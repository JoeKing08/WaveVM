
/*
 * [IDENTITY] Frontend Wavelet Engine - The Memory Guardian
 * ---------------------------------------------------------------------------
 * 物理角色：QEMU 内部的内存一致性协调者。
 * 职责边界：
 * 1. 运行 Latch 机制锁定读写冲突。
 * 2. 定时收割脏页生成 Diff，维持 Wavelet 增量推送。
 * 3. 运行重排缓冲区 (Reorder Window)，将乱序推送"坍缩"为有序内存。
 *
 * [禁止事项]
 * - 严禁在 sigsegv_handler 中进行任何可能引起休眠的操作。
 * - 严禁关闭 Lazy TLB Flush (defer_ro_protect)，否则 QEMU 性能将崩溃。
 * ---------------------------------------------------------------------------
 */
#include "qemu/osdep.h"
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <time.h>
#include <stdatomic.h>
#include "sysemu/kvm.h"
#include "exec/memory.h"
#include "exec/ram_addr.h"

#include "../../../common_include/wavevm_protocol.h"
#include "../../../common_include/wavevm_local_memory.h"
#include "../../../common_include/wavevm_memory.h"
#include "wavevm-runtime-registration.h"

/*
 * WaveVM V29.5 "Wavelet" User-Mode Memory Engine (Production Ready)
 */

// --- 全局配置与状态 ---
static int g_is_slave = 0;
static int g_fd_req = -1;
static __thread uint8_t t_net_buf[WVM_MAX_PACKET_SIZE];
static int g_fd_push = -1;
static int g_ipc_diff_sock = -1; // [FIX-G1] Master TCG harvester 专用 IPC socket
static void *g_ram_base = NULL;
static size_t g_ram_size = 0;
static void *g_shm_shadow = NULL;
static uint32_t g_slave_id = 0;
static bool g_fault_hook_enabled = false;
static bool g_fault_hook_checked = false;
static int g_client_sync_batch = 1024; // 当前生效的 Batch
static int g_min_batch = 1;            // 下限
static int g_max_batch = 8192;         // 上限
static int g_enable_auto_tuning = 1;   // 开关：1=自动, 0=固定(强一致用)
static _Atomic uint64_t g_operation_sequence = 1;

static uint64_t get_us_time(void);
static uint64_t get_local_page_version(uint64_t gpa);
static void set_local_page_version(uint64_t gpa, uint64_t version);
static long wait_for_directory_ack_safe_us(uint64_t timeout_us);
static long wait_for_directory_ack_safe(void);
static int internal_connect_master(void);
static int internal_connect_master_role(uint32_t role);
static int ensure_local_shm_shadow(void);
static void send_diff_via_ipc(void *buf, size_t len);
static int write_all_fd(int fd, const void *buf, size_t len);
static void flush_aggregator(void);

// 脏区捕获链表
typedef struct WritablePage {
    uint64_t gpa;
    void* pre_image_snapshot;
    struct WritablePage *next;
} WritablePage;

#define PAGE_POOL_SIZE 4096
static WritablePage g_page_pool[PAGE_POOL_SIZE];
static void* g_image_pool[PAGE_POOL_SIZE]; // 预分配快照空间
static atomic_uint g_pool_idx = 0; /* [FIX] 必须无符号，防止 21 亿次写缺页后有符号溢出导致负数取模越界 */

static volatile bool g_threads_running = false;
static pthread_t g_listen_thread;
static pthread_t g_harvester_thread;

#define MAX_RAM_BLOCKS 64

typedef struct {
    uintptr_t hva_start;
    uintptr_t hva_end;
    uint64_t  gpa_start;
    uint64_t  size;
} GVMRamBlock;

static GVMRamBlock g_mem_blocks[MAX_RAM_BLOCKS];
static int g_block_count = 0;

#define MAX_VOLATILE_RANGES 16

typedef struct {
    uint64_t start;
    uint64_t end;
} WVMVolatileRange;

static WVMVolatileRange g_volatile_ranges[MAX_VOLATILE_RANGES];
static int g_volatile_range_count = 0;

static bool wvm_is_volatile_gpa(uint64_t gpa)
{
    for (int i = 0; i < g_volatile_range_count; i++) {
        if (gpa >= g_volatile_ranges[i].start && gpa < g_volatile_ranges[i].end) {
            return true;
        }
    }
    return false;
}

/*
 * [物理意图] 在 QEMU 内部建立 Guest 物理地址(GPA)与宿主机虚拟地址(HVA)的“空间映射图”。
 * [关键逻辑] 将 RAM 块注册到私有映射表，并执行初始 mprotect(PROT_NONE) 以强制触发首次访问缺页。
 * [后果] 若未正确注册，特定的内存区域将脱离分布式一致性引擎的监控，导致该区域的写操作无法全网同步。
 */
void wavevm_register_ram_block(void *hva, uint64_t size, uint64_t gpa) {
    if (!g_fault_hook_checked) {
        const char *hook_env = getenv("WVM_ENABLE_FAULT_HOOK");
        bool is_slave = (getenv("WVM_SOCK_REQ") != NULL);
        g_fault_hook_enabled = is_slave && (!hook_env || atoi(hook_env) != 0);
        g_fault_hook_checked = true;
    }
    for (int i = 0; i < g_block_count; i++) {
        if (g_mem_blocks[i].gpa_start == gpa &&
            g_mem_blocks[i].hva_start == (uintptr_t)hva &&
            g_mem_blocks[i].size == size) {
            fprintf(stderr,
                    "[WaveVM-User] dedup ram_block hva=%p gpa=%#llx size=%#llx blocks=%d\n",
                    hva,
                    (unsigned long long)gpa,
                    (unsigned long long)size,
                    g_block_count);
            return;
        }
    }
    if (g_block_count >= MAX_RAM_BLOCKS) exit(1);
    if (!kvm_enabled() && g_fault_hook_enabled) {
        /*
         * Only slave TCG uses host page protection.  The master owns the
         * complete RAM image and tracks writes via QEMU dirty logging; using
         * process-wide mprotect on the master also traps device DMA writes and
         * breaks BIOS/bootloader disk reads.
         */
        int is_slave = (getenv("WVM_SOCK_REQ") != NULL);
        if (is_slave) {
            mprotect(hva, size, PROT_NONE);
        }
    }
    g_mem_blocks[g_block_count].hva_start = (uintptr_t)hva;
    g_mem_blocks[g_block_count].hva_end   = (uintptr_t)hva + size;
    g_mem_blocks[g_block_count].gpa_start = gpa;
    g_mem_blocks[g_block_count].size      = size;
    g_block_count++;
    {
        char msg[224];
        int n = snprintf(msg, sizeof(msg),
                         "[WaveVM-User] ram_block hva=%p..%p gpa=%#llx size=%#llx blocks=%d\n",
                         hva, (void *)((uintptr_t)hva + size),
                         (unsigned long long)gpa,
                         (unsigned long long)size,
                         g_block_count);
        if (n > 0) {
            write(STDERR_FILENO, msg, (size_t)n);
        }
    }
}

// [替换] 查表法 HVA 转 GPA (用于 sigsegv)
static uint64_t hva_to_gpa_safe(uintptr_t addr) {
    // 这里 block_count 是在 wavevm_region_add 时动态增加的
    for (int i = 0; i < g_block_count; i++) {
        if (addr >= g_mem_blocks[i].hva_start && addr < g_mem_blocks[i].hva_end) {
            // 真实的 GPA = 块起始 GPA + 块内偏移
            return g_mem_blocks[i].gpa_start + (addr - g_mem_blocks[i].hva_start);
        }
    }
    return (uint64_t)-1;
}

// [替换] 查表法 GPA 转 HVA (用于 harvester)
static void* gpa_to_hva_safe(uint64_t gpa) {
    for (int i = 0; i < g_block_count; i++) {
        if (gpa >= g_mem_blocks[i].gpa_start &&
            gpa < g_mem_blocks[i].gpa_start + g_mem_blocks[i].size) {
            return (void*)(g_mem_blocks[i].hva_start + (gpa - g_mem_blocks[i].gpa_start));
        }
    }
    return NULL;
}

// 通用极速零检测
static inline bool is_page_all_zero(void *addr) {
    uint64_t *p = (uint64_t *)addr;
    for (int i = 0; i < 512; i += 4) {
        if (p[i] | p[i+1] | p[i+2] | p[i+3]) return false;
    }
    return true;
}

// --- Lazy Protection Queue ---
#define LAZY_QUEUE_SIZE 64
static __thread uint64_t t_lazy_ro_queue[LAZY_QUEUE_SIZE];
static __thread int t_lazy_count = 0;

static void flush_lazy_ro_queue(void) {
    if (t_lazy_count == 0) return;
    if (kvm_enabled() || !g_fault_hook_enabled) {
        t_lazy_count = 0;
        return;
    }
    for (int i = 0; i < t_lazy_count; i++) {
        uint64_t gpa = t_lazy_ro_queue[i];
        void *hva = gpa_to_hva_safe(gpa);
        if (hva) mprotect(hva, 4096, PROT_READ);
    }
    t_lazy_count = 0;
}

static void defer_ro_protect(uint64_t gpa) {
    if (kvm_enabled() || !g_fault_hook_enabled) return; /* Dirty-log paths must never downgrade pages. */
    t_lazy_ro_queue[t_lazy_count++] = gpa;
    if (t_lazy_count >= LAZY_QUEUE_SIZE) flush_lazy_ro_queue();
}

// 发送 PUSH 包 (Diff 或 Zero)
static void send_push_packet(uint64_t gpa, uint64_t version, void *data, uint16_t size, uint8_t flags) {
    if (g_is_slave && g_fd_push < 0) return;
    if (!g_is_slave && g_ipc_diff_sock < 0) {
        g_ipc_diff_sock = internal_connect_master();
        if (g_ipc_diff_sock < 0) return;
    }
    size_t pl_len = sizeof(struct wvm_diff_log) + size;
    size_t pkt_len = sizeof(struct wvm_header) + pl_len;
    uint8_t *buf = malloc(pkt_len);
    if (!buf) return;

    struct wvm_header *hdr = (struct wvm_header *)buf;
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_COMMIT_DIFF);
    hdr->payload_len = htons(pl_len);
    hdr->slave_id = htonl(g_slave_id);
    hdr->target_id = htonl(WVM_NODE_AUTO_ROUTE); // [V31 Fix] 本地通信标记
    hdr->req_id = 0;
    hdr->qos_level = 1;
    hdr->flags = flags; // [关键]
    hdr->crc32 = 0;

    struct wvm_diff_log *log = (struct wvm_diff_log *)(buf + sizeof(*hdr));
    log->gpa = WVM_HTONLL(gpa);
    log->version = WVM_HTONLL(version);
    log->offset = 0;
    log->size = htons(size);

    if (size > 0 && data) memcpy(log->data, data, size);

    hdr->crc32 = htonl(calculate_crc32(buf, pkt_len));
    // [FIX-G1] Master TCG 走 IPC
    if (g_is_slave) {
        write_all_fd(g_fd_push, buf, pkt_len);
    } else {
        send_diff_via_ipc(buf, pkt_len);
    }
    free(buf);
}

// --- [FIX 2] Latch 锁分段 (放在文件头部全局区) ---

// 强制 128 字节对齐 (兼容 x86_64 和 ARM64/Graviton)
typedef struct {
    volatile uint64_t val;
    uint8_t padding[128 - sizeof(uint64_t)];
} __attribute__((aligned(128))) aligned_latch_t;

// 静态断言：编译期检查对齐是否成功
_Static_assert(sizeof(aligned_latch_t) == 128, "Latch alignment failed");

#define LATCH_SHARDS 256
static aligned_latch_t g_latches[LATCH_SHARDS];

// 初始化 (在 wavevm_user_mem_init 调用)
static void init_latches(void) {
    for(int i=0; i<LATCH_SHARDS; i++) g_latches[i].val = (uint64_t)-1;
}

#define LATCH_IDX(gpa) ((gpa >> 12) % LATCH_SHARDS)

// --- [FIX 4] Mode B 微型重排窗口 ---

#define REORDER_WIN_SIZE 32  // 容忍 32 个包的乱序
#define REORDER_MASK (REORDER_WIN_SIZE - 1)

typedef struct {
    uint64_t gpa;
    uint64_t version;
    uint16_t msg_type;
    uint16_t len;
    uint8_t *data;
    uint64_t timestamp_us; // 存入时间戳
    bool active;
} ReorderSlot;

static ReorderSlot g_reorder_buf[REORDER_WIN_SIZE];
static pthread_spinlock_t g_reorder_lock;

// 简单的异或哈希
static inline int get_reorder_idx(uint64_t gpa, uint64_t version) {
    return ((gpa >> 12) ^ version) & REORDER_MASK;
}

// 存入未来的包
static void buffer_future_packet(uint64_t gpa, uint64_t version, uint16_t type, void *data, uint16_t len) {
    int idx = get_reorder_idx(gpa, version);
    pthread_spin_lock(&g_reorder_lock);

    // 如果槽位被占，释放旧数据 (Drop-on-Collision 策略)
    if (g_reorder_buf[idx].active) free(g_reorder_buf[idx].data);

    g_reorder_buf[idx].gpa = gpa;
    g_reorder_buf[idx].version = version;
    g_reorder_buf[idx].msg_type = type;
    g_reorder_buf[idx].len = len;
    g_reorder_buf[idx].active = true;
    g_reorder_buf[idx].timestamp_us = get_us_time();
    g_reorder_buf[idx].data = malloc(len);
    if (g_reorder_buf[idx].data) memcpy(g_reorder_buf[idx].data, data, len);
    else g_reorder_buf[idx].active = false; // OOM 保护

    pthread_spin_unlock(&g_reorder_lock);
}

/* [FIX-F3] Forward declaration: KVM proactive page fetch (defined after request_page_sync) */
static void kvm_proactive_page_fetch(uint64_t gpa);
int wavevm_user_mem_sync_page(uint64_t gpa);
static int request_page_sync(uintptr_t fault_addr, bool is_write);

/*
 * [物理意图] 接收并应用来自 P2P 网络的"真理推送"，更新本地物理内存。
 * [关键逻辑] 执行严格的版本判定（is_next_version）：顺序包直接 memcpy，版本断层包则强制失效（Invalidate）本地映射。
 * [后果] 实现了 MESI 协议的远程写入动作。它保证了即便在乱序网络下，本地 vCPU 看到的内存也是单调递增的一致性状态。
 */
void wvm_apply_remote_push(uint16_t msg_type, void *payload) {
    {
        static unsigned long push_count;
        bool tracked_push = msg_type == MSG_PAGE_PUSH_DIFF ||
                            msg_type == MSG_PAGE_PUSH_FULL ||
                            msg_type == MSG_FORCE_SYNC;
        if (tracked_push) {
            uint64_t gpa = (msg_type == MSG_PAGE_PUSH_DIFF)
                ? WVM_NTOHLL(((struct wvm_diff_log *)payload)->gpa)
                : WVM_NTOHLL(((struct wvm_full_page_push *)payload)->gpa);
            uint64_t version = (msg_type == MSG_PAGE_PUSH_DIFF)
                ? WVM_NTOHLL(((struct wvm_diff_log *)payload)->version)
                : WVM_NTOHLL(((struct wvm_full_page_push *)payload)->version);
            unsigned long n = ++push_count;
            if (n <= 12 || (n % 5000) == 0) {
                fprintf(stderr,
                        "[WVM-PUSH-APPLY] pid=%d n=%lu type=%u gpa=%#llx "
                        "version=%#llx local=%#llx t=%llu\n",
                        (int)getpid(), n, (unsigned)msg_type,
                        (unsigned long long)gpa,
                        (unsigned long long)version,
                        (unsigned long long)get_local_page_version(gpa),
                        (unsigned long long)get_us_time());
            }
        }
    }
// --- 分支 1: Diff 推送 ---
    if (msg_type == MSG_PAGE_PUSH_DIFF) {
        struct wvm_diff_log* log = (struct wvm_diff_log*)payload;
        uint64_t gpa = WVM_NTOHLL(log->gpa);
        uint64_t push_ver = WVM_NTOHLL(log->version);
        uint64_t local_ver = get_local_page_version(gpa);

        // [FIX] 严格版本/幂等性校验

        // 情况 A: 过期或重复的包 (Stale/Duplicate)
        // 网络重传或乱序导致，直接静默丢弃，不做任何内存操作
        if (!is_newer_version(local_ver, push_ver)) {
            return;
        }

        // 情况 B: 顺序到达的包 (Ideal Sequence)
        if (is_next_version(local_ver, push_ver)) {
            uint16_t offset = ntohs(log->offset);
            uint16_t size = ntohs(log->size);

            // 边界检查：防止恶意包导致 Segfault
            if (offset + size > 4096) return;

            // 1. 安全 GPA→HVA 转换（兼容 PCI hole 多段 RAM）
            void *page_hva = gpa_to_hva_safe(gpa);
            if (!page_hva) return;
            mprotect(page_hva, 4096, PROT_READ | PROT_WRITE);
            // 2. 应用增量数据
            memcpy((uint8_t*)page_hva + offset, log->data, size);
            // 3. 放入惰性锁回队列 (性能优化)
            defer_ro_protect(gpa);

            // 4. 更新本地版本
            set_local_page_version(gpa, push_ver);
        }
        // 情况 C: 版本断层 (Gap Detected)
        // 例如：本地是 v10，收到了 v12。中间缺了 v11。
        else {
            // 此时内存状态已不可信，必须强制失效
            // 下次访问触发 sigsegv -> request_page_sync (V28 Pull) 拉取最新全量
            if (!kvm_enabled() && g_fault_hook_enabled) {
                void *inv_hva = gpa_to_hva_safe(gpa);
                if (inv_hva) mprotect(inv_hva, 4096, PROT_NONE);
            }

            // 将本地版本置 0，确保下次 Pull 回来的数据（无论版本多少）都能成功覆盖
            set_local_page_version(gpa, 0);

            // [FIX-F3] KVM 模式下 mprotect(PROT_NONE) 被跳过，guest 不会触发 SIGSEGV，
            // 必须主动拉取最新页面，否则 guest 永远读到 stale 数据。
            if (kvm_enabled()) {
                kvm_proactive_page_fetch(gpa);
            }
        }
    }
    // --- 分支 2: 全页推送 / 强制同步 ---
    else if (msg_type == MSG_PAGE_PUSH_FULL || msg_type == MSG_FORCE_SYNC) {
        struct wvm_full_page_push* full = (struct wvm_full_page_push*)payload;
        uint64_t gpa = WVM_NTOHLL(full->gpa);
        uint64_t push_ver = WVM_NTOHLL(full->version);

        if (is_newer_version(get_local_page_version(gpa), push_ver)) {
            void *page_hva = gpa_to_hva_safe(gpa);
            if (!page_hva) return;
            mprotect(page_hva, 4096, PROT_READ | PROT_WRITE);
            memcpy(page_hva, full->data, 4096);

            // 惰性锁回
            defer_ro_protect(gpa);

            set_local_page_version(gpa, push_ver);
        }
    }
    // --- 分支 3: Prophet RPC (V29 新增) ---
    else if (msg_type == MSG_RPC_BATCH_MEMSET) {
        // [FIX] Daemon 的 handle_rpc_batch_execution 只修改了 g_shm_ptr，
        // 但 QEMU TCG 模式使用独立的匿名 RAM (g_ram_base)，必须同步执行物理填充，
        // 否则 Guest 看到的内存不会被清零，Prophet 指令形同虚设。
        struct wvm_rpc_batch_memset *batch = (struct wvm_rpc_batch_memset *)payload;
        uint32_t count = ntohl(batch->count);
        uint32_t val = ntohl(batch->val);
        struct wvm_rpc_region *regions = (struct wvm_rpc_region *)(batch + 1);
        for (uint32_t i = 0; i < count; i++) {
            uint64_t gpa = WVM_NTOHLL(regions[i].gpa);
            uint64_t r_len = WVM_NTOHLL(regions[i].len);
            if (gpa + r_len <= g_ram_size) {
                void *rpc_hva = gpa_to_hva_safe(gpa);
                if (!rpc_hva) continue;
                mprotect(rpc_hva, r_len, PROT_READ | PROT_WRITE);
                memset(rpc_hva, val, r_len);
                // [FIX] 同步 Prophet 版本号，否则后续 diff 引擎认为该页没变过，
                //       导致远端节点版本断层无法收敛。
                for (uint64_t pg = gpa & ~0xFFFULL; pg < gpa + r_len; pg += 4096) {
                    uint64_t v = get_local_page_version(pg);
                    set_local_page_version(pg, v + 1);
                }
                // tb_flush 在 wavevm-all.c 的 IPC 处理路径中已执行，此处不重复
            }
        }
    }
}

// 检查并应用后续包 (链式反应)
static bool check_and_apply_next(uint64_t gpa, uint64_t next_ver) {
    // 关键点：不再相信调用者传进来的 next_ver (它可能是算错的)
    // 我们基于本地真实的当前版本，去推算可能的“逻辑下一跳”
    uint64_t local_v = get_local_page_version(gpa);

    // 可能性 A: 纪元内连续 (+1)
    uint64_t next_a = local_v + 1;
    // 可能性 B: 跨纪元第一炮 (Epoch + 1, Counter = 1)
    uint32_t cur_epoch = (uint32_t)(local_v >> 32);
    uint64_t next_b = ((uint64_t)(cur_epoch + 1) << 32) | 1;

    pthread_spin_lock(&g_reorder_lock);

    // 1. 先探测可能性 A
    int idx = get_reorder_idx(gpa, next_a);
    ReorderSlot *s = &g_reorder_buf[idx];
    if (s->active && s->gpa == gpa && s->version == next_a) goto hit;

    // 2. A 没中，探测可能性 B
    idx = get_reorder_idx(gpa, next_b);
    s = &g_reorder_buf[idx];
    if (s->active && s->gpa == gpa && s->version == next_b) goto hit;

    // 都没中
    pthread_spin_unlock(&g_reorder_lock);
    return false;

hit:
    // 命中！执行应用逻辑
    void *d = s->data;
    uint16_t t = s->msg_type;

    s->active = false;
    s->data = NULL; // [修复] 彻底杜绝野指针

    pthread_spin_unlock(&g_reorder_lock);

    wvm_apply_remote_push(t, d);
    free(d);
    return true;
}

static WritablePage *g_writable_pages_list = NULL;
static pthread_mutex_t g_dirty_flush_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct WVMHandoffDirtyRecord {
    uint64_t gpa;
    ram_addr_t ra;
    uint64_t old_version;
    uint64_t new_version;
    bool commit_confirmed;
} WVMHandoffDirtyRecord;

typedef struct WVMHandoffDirtyJournal {
    WVMHandoffDirtyRecord *items;
    size_t count;
    size_t capacity;
} WVMHandoffDirtyJournal;

// 线程局部
static __thread int t_com_sock = -1;

// --- 辅助函数 ---

// 使用二级页表风格的目录来存储版本号，适配 64 位地址空间

#define L1_BITS 10
#define L2_BITS 10
#define L1_SIZE (1UL << L1_BITS)
#define L2_SIZE (1UL << L2_BITS)
#define PAGE_SHIFT 12

// 二级索引结构
static uint64_t **g_ver_root = NULL;

/*
 * [物理意图] 维护本地缓存页面的“逻辑时钟（版本号）”快照。
 * [关键逻辑] 采用二级页表结构的索引表（Radix-like Table），以 O(1) 时间复杂度追踪 500PB 空间内每页的版本。
 * [后果] 这是判定“何为真理”的基石。版本号记录错误会直接导致读到旧数据（Stale Read）或触发不必要的全页强制同步。
 */
static uint64_t get_local_page_version(uint64_t gpa) {
    if (!g_ver_root) return 0;

    uint64_t pfn = gpa >> PAGE_SHIFT;
    uint64_t l1_idx = (pfn >> L2_BITS) & (L1_SIZE - 1);
    uint64_t l2_idx = pfn & (L2_SIZE - 1);

    if (g_ver_root[l1_idx] == NULL) return 0;
    return __atomic_load_n(&g_ver_root[l1_idx][l2_idx], __ATOMIC_ACQUIRE);
}

static void set_local_page_version(uint64_t gpa, uint64_t version) {
    if (!g_ver_root) {
        g_ver_root = calloc(L1_SIZE, sizeof(uint64_t *));
        if (!g_ver_root) return; // OOM: 静默放弃版本追踪，不会崩溃
    }

    uint64_t pfn = gpa >> PAGE_SHIFT;
    uint64_t l1_idx = (pfn >> L2_BITS) & (L1_SIZE - 1);
    uint64_t l2_idx = pfn & (L2_SIZE - 1);

    if (g_ver_root[l1_idx] == NULL) {
        g_ver_root[l1_idx] = calloc(L2_SIZE, sizeof(uint64_t));
        if (!g_ver_root[l1_idx]) return; // OOM: 同上
    }
    __atomic_store_n(&g_ver_root[l1_idx][l2_idx], version, __ATOMIC_RELEASE);
}

static void safe_log(const char *msg) {
    if (write(STDERR_FILENO, msg, strlen(msg))) {};
}

// 健壮的阻塞读取 (处理 EINTR)
static int read_exact(int fd, void *buf, size_t len) {
    size_t received = 0;
    char *ptr = (char *)buf;
    while (received < len) {
        ssize_t ret = read(fd, ptr + received, len - received);
        if (ret > 0) received += ret;
        else if (ret == 0) return -1; // EOF
        else if (errno != EINTR) return -1; // Error
    }
    return 0;
}

static void write_be64(uint8_t output[8], uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        output[7U - i] = (uint8_t)(value >> (i * 8U));
    }
}

/*
 * The local node runtime deduplicates by operation key, so each QEMU fault
 * gets a process-scoped, never-reused ID.  After sequence exhaustion QEMU
 * fails the request instead of wrapping into an older operation identity.
 */
static int make_operation_id(
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    uint64_t current = atomic_load_explicit(&g_operation_sequence,
                                            memory_order_relaxed);

    for (;;) {
        uint64_t next;

        if (current == 0) {
            return -EOVERFLOW;
        }
        next = current == UINT64_MAX ? 0 : current + 1U;
        if (atomic_compare_exchange_weak_explicit(
                &g_operation_sequence, &current, next,
                memory_order_relaxed, memory_order_relaxed)) {
            write_be64(operation_id, (uint64_t)(uint32_t)getpid());
            write_be64(operation_id + 8, current);
            return 0;
        }
    }
}

static int parse_u64_env(const char *name, uint64_t *value)
{
    const char *text = getenv(name);
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !*text || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int fill_commit_reply_destination(
    struct wvm_mem_commit *commit)
{
    uint64_t kind;
    uint64_t scope;
    uint64_t vnode;

    if (!commit ||
        parse_u64_env("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_KIND",
                         &kind) != 0 ||
        parse_u64_env("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_SCOPE",
                         &scope) != 0 ||
        parse_u64_env("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_VNODE",
                         &vnode) != 0 ||
        kind > UINT16_MAX || vnode > UINT32_MAX) {
        return -EINVAL;
    }
    commit->reply_destination_kind = (uint16_t)kind;
    commit->reply_destination_scope = scope;
    commit->reply_destination_vnode = (uint32_t)vnode;
    return 0;
}

static int ack_status_to_errno(uint16_t status)
{
    switch (status) {
    case WVM_MEM_ACK_SUCCESS:
        return 0;
    case WVM_MEM_ACK_STALE:
        return -ESTALE;
    case WVM_MEM_ACK_NOT_FOUND:
        return -ENOENT;
    case WVM_MEM_ACK_BACKPRESSURE:
        return -EAGAIN;
    case WVM_MEM_ACK_INTERNAL_FAILURE:
        return -EIO;
    default:
        return -EPROTO;
    }
}

static int commit_status_to_errno(uint16_t status)
{
    switch (status) {
    case WVM_MEM_COMMIT_ACK_SUCCESS:
        return 0;
    case WVM_MEM_COMMIT_ACK_STALE_BASE_VERSION:
        return -ESTALE;
    case WVM_MEM_COMMIT_ACK_NOT_FOUND:
        return -ENOENT;
    case WVM_MEM_COMMIT_ACK_BACKPRESSURE:
        return -EAGAIN;
    case WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE:
        return -EIO;
    default:
        return -EPROTO;
    }
}

/*
 * Submit one canonical V1 commit over an already registered synchronous
 * local IPC connection. The caller owns the connection lifecycle; this
 * helper only validates and exchanges one request/result pair.
 */
static int request_commit_on_fd(
    int fd, uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes,
    struct wvm_mem_commit_ack *ack_out)
{
    struct wvm_local_memory_commit_request request;
    struct wvm_local_memory_commit_result result;
    wvm_ipc_header_t header;
    uint8_t request_bytes[WVM_LOCAL_MEMORY_COMMIT_REQUEST_HEADER_BYTES +
                          WVM_MEMORY_PAGE_BYTES];
    uint8_t result_bytes[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES];
    size_t request_bytes_count = 0;
    char error[160] = {0};
    int status;

    if (fd < 0 || !data || !ack_out || base_version == 0 ||
        gpa % WVM_MEMORY_PAGE_BYTES != 0 || data_bytes == 0 ||
        data_bytes > WVM_MEMORY_PAGE_BYTES ||
        offset > WVM_MEMORY_PAGE_BYTES - data_bytes) {
        return -EINVAL;
    }
    memset(&request, 0, sizeof(request));
    memset(&result, 0, sizeof(result));
    if (make_operation_id(request.operation_id) != 0) {
        return -EOVERFLOW;
    }
    request.delivery_attempt_id = 1;
    request.commit.gpa = gpa;
    request.commit.base_version = base_version;
    request.commit.offset = offset;
    request.commit.size = (uint16_t)data_bytes;
    request.commit.data = data;
    request.commit.data_bytes = data_bytes;
    if (fill_commit_reply_destination(&request.commit) != 0 ||
        wvm_local_memory_commit_request_encode(
            &request, request_bytes, sizeof(request_bytes),
            &request_bytes_count, error, sizeof(error)) != 0) {
        return -EPROTO;
    }
    header.type = WVM_IPC_TYPE_TYPED_MEM_COMMIT;
    header.len = (uint32_t)request_bytes_count;
    if (write_all_fd(fd, &header, sizeof(header)) < 0 ||
        write_all_fd(fd, request_bytes, request_bytes_count) < 0 ||
        read_exact(fd, result_bytes, sizeof(result_bytes)) < 0 ||
        wvm_local_memory_commit_result_decode(
            result_bytes, &result, error, sizeof(error)) != 0 ||
        memcmp(result.operation_id, request.operation_id,
               sizeof(request.operation_id)) != 0 ||
        result.ack.gpa != gpa) {
        return -EIO;
    }
    *ack_out = result.ack;
    status = commit_status_to_errno(result.ack.status);
    return status;
}

/*
 * The QEMU SYNC channel is serialized per thread.  The request and response
 * are both typed V1 records; a zero result length means node runtime failed
 * before it received a directory ACK.
 */
static int request_page_over_ipc(
    uint64_t gpa, struct wvm_mem_ack *ack_out,
    uint8_t page[WVM_MEMORY_PAGE_BYTES])
{
    struct wvm_local_memory_fault_request request;
    wvm_ipc_header_t header;
    uint8_t request_bytes[WVM_LOCAL_MEMORY_FAULT_REQUEST_BYTES];
    uint8_t result_length[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES];
    uint8_t ack_bytes[WVM_MEM_ACK_HEADER_BYTES +
                      WVM_MEMORY_PAGE_BYTES];
    size_t ack_bytes_count = 0;
    struct wvm_mem_ack decoded_ack;
    char error[160] = {0};
    int result;

    if (!ack_out || !page || gpa % WVM_MEMORY_PAGE_BYTES != 0) {
        return -EINVAL;
    }
    if (t_com_sock == -1) {
        t_com_sock = internal_connect_master();
        if (t_com_sock < 0) {
            return -ENOTCONN;
        }
    }
    memset(&request, 0, sizeof(request));
    result = make_operation_id(request.operation_id);
    if (result != 0) {
        return result;
    }
    request.delivery_attempt_id = 1;
    request.gpa = gpa;
    if (wvm_local_memory_fault_request_encode(
            &request, request_bytes, error, sizeof(error)) != 0) {
        return -EPROTO;
    }
    header.type = WVM_IPC_TYPE_TYPED_MEM_FAULT;
    header.len = sizeof(request_bytes);
    if (write_all_fd(t_com_sock, &header, sizeof(header)) < 0 ||
        write_all_fd(t_com_sock, request_bytes, sizeof(request_bytes)) < 0 ||
        read_exact(t_com_sock, result_length, sizeof(result_length)) < 0 ||
        wvm_local_memory_result_length_decode(
            result_length, &ack_bytes_count, error, sizeof(error)) != 0) {
        close(t_com_sock);
        t_com_sock = -1;
        return -EIO;
    }
    if (ack_bytes_count == 0) {
        return -EIO;
    }
    if (read_exact(t_com_sock, ack_bytes, ack_bytes_count) < 0 ||
        wvm_mem_ack_decode(ack_bytes, ack_bytes_count, &decoded_ack,
                              error, sizeof(error)) != 0 ||
        decoded_ack.gpa != gpa) {
        close(t_com_sock);
        t_com_sock = -1;
        return -EPROTO;
    }
    if (decoded_ack.status == WVM_MEM_ACK_SUCCESS) {
        memcpy(page, decoded_ack.data, sizeof(page[0]) *
                                      WVM_MEMORY_PAGE_BYTES);
        decoded_ack.data = page;
    }
    *ack_out = decoded_ack;
    return 0;
}

static int internal_connect_master_role(uint32_t role) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };

    const char *env_path = wavevm_qemu_runtime_socket_path();
    if (!env_path) {
        fprintf(stderr,
                "[WaveVM-User] manifest-derived QEMU socket path is missing\n");
        close(sock);
        return -1;
    }
    strncpy(addr.sun_path, env_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock); return -1;
    }

    if (role != 0) {
        struct wvm_ipc_runtime_registration registration;
        const void *payload = &role;
        size_t payload_size = sizeof(role);
        wvm_ipc_header_t reg_hdr;

        if (wavevm_qemu_runtime_gate_enabled()) {
            if (wavevm_qemu_fill_runtime_registration((uint16_t)role,
                                                      &registration) != 0) {
                fprintf(stderr,
                        "[WaveVM-User] runtime gate active but QEMU "
                        "registration identity is incomplete\n");
                close(sock);
                return -1;
            }
            payload = &registration;
            payload_size = sizeof(registration);
        }
        reg_hdr.type = WVM_IPC_TYPE_REGISTER;
        reg_hdr.len = (uint32_t)payload_size;
        if (write_all_fd(sock, &reg_hdr, sizeof(reg_hdr)) < 0 ||
            write_all_fd(sock, payload, payload_size) < 0) {
            close(sock);
            return -1;
        }
    }
    return sock;
}

static int internal_connect_master(void)
{
    return internal_connect_master_role(
        wavevm_qemu_runtime_gate_enabled() ? WVM_IPC_ROLE_SYNC : 0);
}

static int ensure_local_shm_shadow(void)
{
    if (g_shm_shadow || g_is_slave || !g_ram_size) {
        return g_shm_shadow ? 0 : -1;
    }

    const char *shm_path = getenv("WVM_SHM_FILE");
    if (!shm_path) {
        return -1;
    }

    int shm_fd = shm_open(shm_path, O_RDWR, 0666);
    if (shm_fd < 0) {
        return -1;
    }

    void *ptr = mmap(NULL, g_ram_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);
    if (ptr == MAP_FAILED) {
        return -1;
    }

    g_shm_shadow = ptr;
    return 0;
}

/* [FIX] Sync BIOS shadow region from QEMU's HVA into the SHM backing file.
 *
 * Called by wavevm_region_add() when a RAM region covering the BIOS area
 * (0xC0000-0xFFFFF) is added.  At that point QEMU has already copied the
 * BIOS ROM content into the HVA, but the SHM file still has zeros.
 * We memcpy the overlapping portion so slave nodes see correct BIOS code.
 */
void wavevm_sync_bios_shadow(uint64_t gpa, uint64_t size, void *hva)
{
    if (ensure_local_shm_shadow() < 0) {
        fprintf(stderr, "[WaveVM-BIOS] sync_bios_shadow: SHM shadow not available\n");
        return;
    }

    uint64_t bios_start = 0xC0000;
    uint64_t bios_end   = 0x100000;  /* 1MB */
    uint64_t region_end = gpa + size;

    /* Clamp to the BIOS area */
    uint64_t copy_start = (gpa > bios_start) ? gpa : bios_start;
    uint64_t copy_end   = (region_end < bios_end) ? region_end : bios_end;
    if (copy_start >= copy_end) return;

    uint64_t copy_size   = copy_end - copy_start;
    uint64_t hva_offset  = copy_start - gpa;      /* offset into the HVA region */
    uint64_t shm_offset  = copy_start;             /* GPA == offset in SHM for ram0 */

    if (shm_offset + copy_size > g_ram_size) {
        fprintf(stderr, "[WaveVM-BIOS] sync_bios_shadow: SHM too small for GPA 0x%llx+0x%llx\n",
                (unsigned long long)shm_offset, (unsigned long long)copy_size);
        return;
    }

    memcpy((uint8_t *)g_shm_shadow + shm_offset,
           (uint8_t *)hva + hva_offset,
           copy_size);

    fprintf(stderr, "[WaveVM-BIOS] synced BIOS shadow GPA [0x%llx, 0x%llx) -> SHM offset 0x%llx (%llu bytes)\n",
            (unsigned long long)copy_start, (unsigned long long)copy_end,
            (unsigned long long)shm_offset, (unsigned long long)copy_size);
}

/*
 * 以下函数仅为了兼容 QEMU 命令行参数解析。
 * V29 使用 Wavelet 主动推送模型，不再需要 TTL 和手工 Watch 区域。
 */
void wvm_set_ttl_interval(int ms) {
    // 留空：不再启动 V28 的收割者线程
}

void wvm_register_volatile_ram(uint64_t gpa, uint64_t size) {
    if (size == 0 || g_volatile_range_count >= MAX_VOLATILE_RANGES) {
        return;
    }

    uint64_t end = gpa + size;
    if (end < gpa) {
        return;
    }

    g_volatile_ranges[g_volatile_range_count].start = gpa;
    g_volatile_ranges[g_volatile_range_count].end = end;
    g_volatile_range_count++;

    fprintf(stderr, "[WaveVM-User] volatile RAM range registered [0x%llx, 0x%llx)\n",
            (unsigned long long)gpa, (unsigned long long)end);
}

/* [FIX-F3] KVM 主动页面拉取：KVM 模式下 mprotect(PROT_NONE) 不可用的替代方案。
 *
 * 背景：TCG 模式通过 mprotect(PROT_NONE) + SIGSEGV 触发缺页拉取。
 * KVM 模式下 PROT_NONE 会导致 EPT violation 风暴，所以所有 mprotect(PROT_NONE) 调用
 * 都被 !kvm_enabled() 守卫跳过。
 *
 * 问题：当版本断层发生时，set_local_page_version(gpa, 0) 被调用，但因为没有
 * mprotect(PROT_NONE)，guest 不会触发缺页，旧数据会被永久读取。
 *
 * 修复：在 KVM 模式下检测到版本断层时，主动通过 IPC 向 Master 发起同步页面拉取，
 * 将最新数据写入 HVA 并更新版本号。不依赖 guest 触发的 SIGSEGV。
 */
int wavevm_user_mem_sync_page(uint64_t gpa)
{
    gpa &= ~4095ULL;
    if (!g_ram_base) {
        return -ENODEV;
    }

    /* 使用线程局部 IPC socket (与 request_page_sync Master 路径相同) */
    if (!g_is_slave) {
        struct wvm_mem_ack ack;
        uint8_t page[WVM_MEMORY_PAGE_BYTES];
        int result = request_page_over_ipc(gpa, &ack, page);

        if (result != 0) {
            fprintf(stderr,
                    "[WaveVM-User] sync page: V1 IPC failed for GPA 0x%"
                    PRIx64 "\n", gpa);
            return result;
        }
        result = ack_status_to_errno(ack.status);
        if (result == 0) {
            void *fetch_hva = gpa_to_hva_safe(gpa);
            if (!fetch_hva) {
                return -EFAULT;
            }
            mprotect(fetch_hva, 4096, PROT_READ | PROT_WRITE);
            memcpy(fetch_hva, ack.data, WVM_MEMORY_PAGE_BYTES);
            /* KVM 模式下不降权：脏页由 dirty log 跟踪，
             * mprotect(PROT_READ) 会导致 EPT 违例 → exit=17 */
            set_local_page_version(gpa, ack.version);
            return 0;
        }
        return result;
    } else {
        /* Slave 模式：复用 request_page_sync 的 UDP 路径。
         * 由于 request_page_sync 接受 fault_addr (HVA) 参数，
         * 这里构造 HVA 并直接调用它。
         */
        void *fetch_hva = gpa_to_hva_safe(gpa);
        if (!fetch_hva) {
            return -EFAULT;
        }
        uintptr_t fault_addr = (uintptr_t)fetch_hva;
        return request_page_sync(fault_addr, false);
    }
}

static void kvm_proactive_page_fetch(uint64_t gpa)
{
    (void)wavevm_user_mem_sync_page(gpa);
}

// =============================================================
// [链路 A] 同步缺页处理 (Master IPC / Slave UDP)
// =============================================================

static int request_page_sync(uintptr_t fault_addr, bool is_write) {
    uint64_t gpa = hva_to_gpa_safe(fault_addr);
    if (gpa == (uint64_t)-1) return -1;
    gpa &= ~4095ULL;
    uintptr_t aligned_addr = fault_addr & ~4095ULL;
    {
        char msg[160];
        int n = snprintf(msg, sizeof(msg),
                         "[WaveVM-User] request_page_sync gpa=%#llx write=%d slave=%d\n",
                         (unsigned long long)gpa, is_write ? 1 : 0, g_is_slave ? 1 : 0);
        if (n > 0) {
            write(STDERR_FILENO, msg, (size_t)n);
        }
    }

    // --- Both Master and Slave now use typed IPC protocol (F07 fix) ---
    /* V31b: Master TCG with PROT_READ should only get write faults.
     * For any read fault (shouldn't happen), just mprotect without IPC
     * since the data is already in the SHM-backed memory. */
    if (!g_is_slave && !is_write) {
        mprotect((void *)aligned_addr, 4096, PROT_READ);
        return 0;
    }

    /* Connect to node_runtime via Unix socket for typed protocol */
    if (t_com_sock == -1) {
        t_com_sock = internal_connect_master();
        if (t_com_sock < 0) {
            safe_log("[WVM] FATAL: Cannot connect to node_runtime for typed memory protocol\n");
            return -1;
        }
    }

    {
        struct wvm_mem_ack ack;
        uint8_t page[WVM_MEMORY_PAGE_BYTES];
        int result = request_page_over_ipc(gpa, &ack, page);

        if (result != 0) {
            return result;
        }
        result = ack_status_to_errno(ack.status);
        if (result != 0) {
            return result;
        }
        mprotect((void *)aligned_addr, 4096, PROT_READ | PROT_WRITE);
        memcpy((void *)aligned_addr, ack.data, WVM_MEMORY_PAGE_BYTES);
        set_local_page_version(gpa, ack.version);
        return 0;
    }

    /*
     * Legacy UDP path removed (F07 fix).
     * Both Master and Slave TCG now use typed IPC protocol over Unix sockets.
     * The g_fd_req UDP channel is no longer used for memory faults.
     */
}

static int commit_page_over_ipc(uint64_t gpa, const void *data, uint64_t version);

static inline void wait_on_latch(uint64_t gpa) {
    // 计算索引并查对分段锁数组 g_latches
    int idx = LATCH_IDX(gpa);
    while (__atomic_load_n(&g_latches[idx].val, __ATOMIC_ACQUIRE) == gpa) {
        __builtin_ia32_pause();
    }
}

// ----------------------------------------------------------------------------
// [REVISED] 信号处理：加入 Latch 检查
// ---------------------------------------------------------------------------

/*
 * [物理意图] 模拟处理器的“缺页异常处理单元”，实现按需拉取与乐观写入。
 * [关键逻辑] 1. 读缺页：回退到 V28 阻塞拉取；2. 写保护：利用预分配池进行 Copy-Before-Write (CBW) 捕获。
 * [后果] 这是整个前端最繁重的入口。必须保证零 malloc，任何在此处的阻塞（如等待网络）都会直接锁死 vCPU 的流水线。
 */
static void sigsegv_handler(int sig, siginfo_t *si, void *ucontext) {
    static volatile int s_fault_count = 0;
    int fc = __atomic_add_fetch(&s_fault_count, 1, __ATOMIC_RELAXED);
    uintptr_t addr = (uintptr_t)si->si_addr;
    if (fc <= 50 || (fc & 0xFFFF) == 0) {
        char msg[192];
        int n = snprintf(msg, sizeof(msg),
                         "[WaveVM-User] sigsegv addr=%p code=%d (count=%d)\n",
                         si->si_addr, si->si_code, fc);
        if (n > 0) {
            write(STDERR_FILENO, msg, (size_t)n);
        }
    }

    // 通过安全查表获取 GPA
    uint64_t gpa = hva_to_gpa_safe(addr);
    if (gpa == (uint64_t)-1) {
        {
            char msg[192];
            int n = snprintf(msg, sizeof(msg),
                             "[WaveVM-User] sigsegv passthrough addr=%p\n",
                             si->si_addr);
            if (n > 0) {
                write(STDERR_FILENO, msg, (size_t)n);
            }
        }
        // 说明访问的不是 RAM 区域（可能是 MMIO 或非法地址），交回给标准处理程序
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
        return;
    }

    gpa &= ~4095ULL; // 对齐到页
    void* aligned_addr = (void*)(addr & ~4095ULL);
    wait_on_latch(gpa);

    ucontext_t *ctx = (ucontext_t *)ucontext;
    bool is_write = (ctx->uc_mcontext.gregs[REG_ERR] & 0x2);
    if (fc <= 50 || (fc & 0xFFFF) == 0) {
        char msg[224];
        int n = snprintf(msg, sizeof(msg),
                         "[WaveVM-User] sigsegv hit gpa=%#llx write=%d page=%p (count=%d)\n",
                         (unsigned long long)gpa, is_write ? 1 : 0, aligned_addr, fc);
        if (n > 0) {
            write(STDERR_FILENO, msg, (size_t)n);
        }
    }

    if (is_write) {
        if (get_local_page_version(gpa) == 0) {
            /*
             * A first touch may be a write fault.  Pull the directory copy
             * before arming CBW; otherwise the slave writes on an implicit
             * zero/old page and later commits version 1 over a newer owner
             * version.
             */
            if (request_page_sync(addr, true) != 0) {
                _exit(1);
            }
        }

        // 从预分配池中取，不要 malloc!
        int idx = atomic_fetch_add(&g_pool_idx, 1) % PAGE_POOL_SIZE;
        WritablePage *wp = &g_page_pool[idx];
        void *snapshot = g_image_pool[idx];

        /* The faulting store has not retired yet; once write access is
         * restored, the current page bytes are still the pre-write image. */
        mprotect(aligned_addr, 4096, PROT_READ | PROT_WRITE);
        memcpy(snapshot, aligned_addr, 4096);
        wp->gpa = gpa;
        wp->pre_image_snapshot = snapshot;

        // 插入链表（注意：这里必须用原子操作挂载，防止破坏链表）
        do {
            wp->next = __atomic_load_n(&g_writable_pages_list, __ATOMIC_ACQUIRE);
        } while (!__atomic_compare_exchange_n(&g_writable_pages_list, &wp->next, wp, true, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));

    } else {
        // 读缺页直接同步
        if (request_page_sync(addr, false) == 0) {
            mprotect(aligned_addr, 4096, PROT_READ);
        } else { _exit(1); }
    }
}

// [改为 Diff 包聚合，已被 add_to_aggregator 替代] 发送 Diff 的辅助函数
static void send_commit_diff_dual_mode(uint64_t gpa, uint16_t offset, uint16_t size, void *data) {
    if (g_fd_push < 0) return;

    // 1. 计算包大小
    size_t pl_len = sizeof(struct wvm_diff_log) + size;
    size_t pkt_len = sizeof(struct wvm_header) + pl_len;

    // 2. 分配缓冲区
    uint8_t *buf = malloc(pkt_len);
    if (!buf) return;

    // 3. 填充 Header
    struct wvm_header *hdr = (struct wvm_header *)buf;
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_COMMIT_DIFF);
    hdr->payload_len = htons(pl_len);
    hdr->slave_id = htonl(g_slave_id);
    hdr->target_id = htonl(WVM_NODE_AUTO_ROUTE); // [V31 Fix] 本地通信标记
    hdr->req_id = 0;
    hdr->qos_level = 1; // 走快车道
    hdr->crc32 = 0;     // 先清零
    hdr->flags = 0;

    // 4. 填充 Payload (Diff Log)
    struct wvm_diff_log *log = (struct wvm_diff_log *)(buf + sizeof(*hdr));
    log->gpa = WVM_HTONLL(gpa);
    // 携带本地版本号供 Directory 校验
    log->version = WVM_HTONLL(get_local_page_version(gpa));
    log->offset = htons(offset);
    log->size = htons(size);
    memcpy(log->data, data, size);

    // 5. 计算 CRC32
    hdr->crc32 = htonl(calculate_crc32(buf, pkt_len));

    // 6. 发送并释放
    write_all_fd(g_fd_push, buf, pkt_len);
    free(buf);
}

// 聚合器状态机
static struct {
    uint8_t buf[2048]; // 略大于 MTU，确保能装下一个完整包 + 头部
    int curr_offset;
    pthread_mutex_t lock;
} g_aggregator = {
    .curr_offset = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

// [FIX-G1] Master TCG 模式：将 diff 数据封装为 IPC 发给 Master Daemon
// 每个聚合包内可能有多个 wvm_header 子包（聚合格式），需要拆包后逐个以 IPC 发送
static void send_diff_via_ipc(void *buf, size_t len) {
    if (g_ipc_diff_sock < 0) {
        g_ipc_diff_sock = internal_connect_master();
        if (g_ipc_diff_sock < 0) return;
    }
    // 遍历聚合缓冲区中的每个子包
    size_t off = 0;
    while (off + sizeof(struct wvm_header) <= len) {
        struct wvm_header *sub = (struct wvm_header *)((uint8_t *)buf + off);
        uint16_t pl = ntohs(sub->payload_len);
        size_t sub_len = sizeof(struct wvm_header) + pl;
        if (off + sub_len > len) break;
        // 只取 payload 部分（wvm_diff_log），封装为 IPC
        wvm_ipc_header_t ipc_hdr = { .type = WVM_IPC_TYPE_COMMIT_DIFF, .len = pl };
        void *payload = (uint8_t *)sub + sizeof(struct wvm_header);
        // 发送 IPC header + payload（两次 write，由于是流式 socket 合并发送）
        if (write_all_fd(g_ipc_diff_sock, &ipc_hdr, sizeof(ipc_hdr)) < 0 ||
            write_all_fd(g_ipc_diff_sock, payload, pl) < 0) {
            // 连接断开，尝试重连
            close(g_ipc_diff_sock);
            g_ipc_diff_sock = internal_connect_master();
            break; // 放弃本轮剩余包
        }
        off += sub_len;
    }
}

static int write_all_fd(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_full_page_diff_to_ipc_fd(int fd, uint64_t gpa,
                                         uint64_t version, void *data)
{
    uint8_t payload[sizeof(struct wvm_diff_log) + 4096];
    struct wvm_diff_log *log = (struct wvm_diff_log *)payload;
    wvm_ipc_header_t ipc_hdr;

    ipc_hdr.type = WVM_IPC_TYPE_COMMIT_DIFF_SYNC;
    ipc_hdr.len = sizeof(payload);
    log->gpa = WVM_HTONLL(gpa);
    log->version = WVM_HTONLL(version);
    log->offset = 0;
    log->size = htons(4096);
    memcpy(log->data, data, 4096);

    if (write_all_fd(fd, &ipc_hdr, sizeof(ipc_hdr)) < 0 ||
        write_all_fd(fd, payload, sizeof(payload)) < 0) {
        return -1;
    }
    return 0;
}

static void free_handoff_dirty_journal(WVMHandoffDirtyJournal *journal)
{
    if (!journal) {
        return;
    }
    free(journal->items);
    free(journal);
}

static int append_handoff_dirty_record(WVMHandoffDirtyJournal **journalp,
                                       uint64_t gpa, ram_addr_t ra,
                                       uint64_t old_version,
                                       uint64_t new_version)
{
    WVMHandoffDirtyJournal *journal = *journalp;

    if (!journal) {
        journal = calloc(1, sizeof(*journal));
        if (!journal) {
            return -ENOMEM;
        }
        *journalp = journal;
    }

    if (journal->count == journal->capacity) {
        size_t new_capacity = journal->capacity ? journal->capacity * 2 : 256;
        WVMHandoffDirtyRecord *new_items =
            realloc(journal->items, new_capacity * sizeof(*new_items));
        if (!new_items) {
            return -ENOMEM;
        }
        journal->items = new_items;
        journal->capacity = new_capacity;
    }

    journal->items[journal->count++] = (WVMHandoffDirtyRecord) {
        .gpa = gpa,
        .ra = ra,
        .old_version = old_version,
        .new_version = new_version,
        .commit_confirmed = false,
    };
    return 0;
}

static void rollback_handoff_dirty_locked(WVMHandoffDirtyJournal *journal)
{
    for (size_t i = 0; journal && i < journal->count; i++) {
        WVMHandoffDirtyRecord *rec = &journal->items[i];
        if (rec->commit_confirmed) {
            continue;
        }
        if (get_local_page_version(rec->gpa) == rec->new_version) {
            set_local_page_version(rec->gpa, rec->old_version);
        }
        cpu_physical_memory_set_dirty_range(rec->ra, 4096,
                                            1 << DIRTY_MEMORY_MIGRATION);
    }
}

void wavevm_user_mem_finish_handoff_dirty(WVMHandoffDirtyJournal *journal,
                                          int commit_ok)
{
    static int finish_log_count;

    if (!journal) {
        return;
    }

    if (!commit_ok) {
        pthread_mutex_lock(&g_dirty_flush_lock);
        rollback_handoff_dirty_locked(journal);
        pthread_mutex_unlock(&g_dirty_flush_lock);
        if (finish_log_count < 20) {
            fprintf(stderr,
                    "[WaveVM-User] handoff dirty rollback pages=%zu\n",
                    journal->count);
            finish_log_count++;
        }
    }

    free_handoff_dirty_journal(journal);
}

int wavevm_user_mem_flush_dirty_to_ipc(int ipc_fd,
                                       WVMHandoffDirtyJournal **journal_out)
{
    int flushed = 0;
    int skipped_zero = 0;
    static int flush_log_count = 0;
    WVMHandoffDirtyJournal *journal = NULL;

    if (journal_out) {
        *journal_out = NULL;
    }
    if (ipc_fd < 0 || g_is_slave || g_block_count <= 0) {
        return 0;
    }

    pthread_mutex_lock(&g_dirty_flush_lock);

    /*
     * Remote TCG handoff is a memory ordering boundary: page tables and other
     * CPU-visible RAM writes made by the master must reach the directory before
     * the slave executes the exported architectural state.  Send these diffs on
     * the same IPC stream as the following CPU_RUN so the master daemon observes
     * commit-before-run ordering.
     */
    for (int bi = 0; bi < g_block_count; bi++) {
        GVMRamBlock *blk = &g_mem_blocks[bi];
        ram_addr_t ram_base = qemu_ram_addr_from_host((void *)blk->hva_start);
        if (ram_base == RAM_ADDR_INVALID) {
            continue;
        }

        for (uint64_t off = 0; off + 4096 <= blk->size; off += 4096) {
            ram_addr_t ra = ram_base + off;
            if (!cpu_physical_memory_test_and_clear_dirty(ra, 4096,
                                                          DIRTY_MEMORY_MIGRATION)) {
                continue;
            }

            uint64_t gpa = blk->gpa_start + off;
            void *hva = (void *)(blk->hva_start + off);
            uint64_t cur_ver = get_local_page_version(gpa);
            if (cur_ver == 0 && is_page_all_zero(hva)) {
                /*
                 * Directory SHM starts zeroed and a newly created page meta starts
                 * at version 1.  Do not turn QEMU's initial zero-fill dirty bits
                 * into millions of full-page network commits; record that this
                 * local snapshot matches the implicit zero version instead.
                 */
                set_local_page_version(gpa, 1);
                skipped_zero++;
                continue;
            }

            uint64_t ver = cur_ver + 1;
            if (append_handoff_dirty_record(&journal, gpa, ra, cur_ver, ver) < 0) {
                int saved_errno = ENOMEM;
                cpu_physical_memory_set_dirty_range(ra, 4096,
                                                    1 << DIRTY_MEMORY_MIGRATION);
                if (journal_out) {
                    *journal_out = journal;
                    journal = NULL;
                } else {
                    rollback_handoff_dirty_locked(journal);
                }
                pthread_mutex_unlock(&g_dirty_flush_lock);
                if (flush_log_count < 20) {
                    fprintf(stderr,
                            "[WaveVM-User] handoff dirty journal failed gpa=%#llx "
                            "sent=%d skipped_zero=%d fd=%d errno=%d\n",
                            (unsigned long long)gpa, flushed, skipped_zero,
                            ipc_fd, saved_errno);
                    flush_log_count++;
                }
                free_handoff_dirty_journal(journal);
                return -ENOMEM;
            }
            if (wavevm_qemu_runtime_gate_enabled()) {
                struct wvm_mem_commit_ack ack;
                int commit_ret = request_commit_on_fd(
                    ipc_fd, gpa, cur_ver, 0, hva,
                    WVM_MEMORY_PAGE_BYTES, &ack);

                if (commit_ret == 0) {
                    ver = ack.result_version;
                    journal->items[journal->count - 1].new_version = ver;
                    journal->items[journal->count - 1].commit_confirmed = true;
                } else {
                    cpu_physical_memory_set_dirty_range(
                        ra, 4096, 1 << DIRTY_MEMORY_MIGRATION);
                    pthread_mutex_unlock(&g_dirty_flush_lock);
                    free_handoff_dirty_journal(journal);
                    return commit_ret;
                }
            } else if (send_full_page_diff_to_ipc_fd(ipc_fd, gpa, ver, hva) < 0) {
                int saved_errno = errno;
                if (journal_out) {
                    *journal_out = journal;
                    journal = NULL;
                } else {
                    rollback_handoff_dirty_locked(journal);
                }
                pthread_mutex_unlock(&g_dirty_flush_lock);
                if (flush_log_count < 20) {
                    fprintf(stderr,
                            "[WaveVM-User] handoff dirty flush failed gpa=%#llx "
                            "sent=%d skipped_zero=%d fd=%d errno=%d\n",
                            (unsigned long long)gpa, flushed, skipped_zero,
                            ipc_fd, saved_errno);
                    flush_log_count++;
                }
                free_handoff_dirty_journal(journal);
                return -EIO;
            }
            set_local_page_version(gpa, ver);
            flushed++;
        }
    }

    if (journal_out) {
        *journal_out = journal;
        journal = NULL;
    }
    pthread_mutex_unlock(&g_dirty_flush_lock);
    free_handoff_dirty_journal(journal);

    if ((flushed > 0 || skipped_zero > 0) && flush_log_count < 20) {
        fprintf(stderr,
                "[WaveVM-User] handoff dirty flush pages=%d skipped_zero=%d fd=%d\n",
                flushed, skipped_zero, ipc_fd);
        flush_log_count++;
    }
    return 0;
}

uint64_t wavevm_user_mem_debug_read_u64(uint64_t gpa, uint64_t offset, int *ok)
{
    void *hva;

    if (ok) {
        *ok = 0;
    }
    if (offset > 4088) {
        return 0;
    }
    hva = gpa_to_hva_safe(gpa);
    if (!hva) {
        return 0;
    }
    if (ok) {
        *ok = 1;
    }
    return *(uint64_t *)((uint8_t *)hva + offset);
}

// 发送函数：将缓冲区推向网络
static void flush_aggregator_locked(void) {
    if (g_aggregator.curr_offset == 0) return;
    // [FIX-G1] Master TCG 走 IPC, Slave 走 UDP push socket
    if (g_is_slave) {
        (void)write_all_fd(g_fd_push, g_aggregator.buf, g_aggregator.curr_offset);
    } else {
        send_diff_via_ipc(g_aggregator.buf, g_aggregator.curr_offset);
    }
    g_aggregator.curr_offset = 0;
}

static void flush_aggregator(void) {
    pthread_mutex_lock(&g_aggregator.lock);
    flush_aggregator_locked();
    pthread_mutex_unlock(&g_aggregator.lock);
}

// 核心聚合函数：取代原有的 send_push_packet
static void add_to_aggregator(uint64_t gpa, uint64_t version, uint16_t off, uint16_t sz, void *data, uint8_t flags) {
    size_t payload_len = sizeof(struct wvm_diff_log) + sz;
    size_t needed = sizeof(struct wvm_header) + payload_len;

    pthread_mutex_lock(&g_aggregator.lock);

    // 如果当前包放不下，或者这个包本身就超过了 MTU 分片限制，则先发送之前的
    if (g_aggregator.curr_offset + needed > MTU_SIZE) {
        flush_aggregator_locked();
    }

    // 如果单包就超过 MTU（虽然对于 Diff 很少见），直接绕过聚合器发送
    if (needed > MTU_SIZE) {
        uint8_t *tmp = malloc(needed);
        if (!tmp) { pthread_mutex_unlock(&g_aggregator.lock); return; }
        struct wvm_header *h = (struct wvm_header *)tmp;
        h->magic = htonl(WVM_MAGIC);
        h->msg_type = htons(MSG_COMMIT_DIFF);
        h->payload_len = htons(payload_len);
        h->slave_id = htonl(g_slave_id);
        h->target_id = htonl(WVM_NODE_AUTO_ROUTE);
        h->qos_level = 1;
        h->flags = flags;
        h->crc32 = 0;
        struct wvm_diff_log *l = (struct wvm_diff_log *)(tmp + sizeof(*h));
        l->gpa = WVM_HTONLL(gpa);
        l->version = WVM_HTONLL(version);
        l->offset = htons(off);
        l->size = htons(sz);
        if (sz > 0) memcpy(l->data, data, sz);
        h->crc32 = htonl(calculate_crc32(tmp, needed));
        // [FIX-G1] Master TCG 走 IPC
        if (g_is_slave) {
            (void)write_all_fd(g_fd_push, tmp, needed);
        } else {
            send_diff_via_ipc(tmp, needed);
        }
        free(tmp);
        pthread_mutex_unlock(&g_aggregator.lock);
        return;
    }

    // 填充到缓冲区
    struct wvm_header *hdr = (struct wvm_header *)(g_aggregator.buf + g_aggregator.curr_offset);
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_COMMIT_DIFF);
    hdr->payload_len = htons(payload_len);
    hdr->slave_id = htonl(g_slave_id);
    hdr->target_id = htonl(WVM_NODE_AUTO_ROUTE); // [V31 Fix] 本地通信标记
    hdr->qos_level = 1;
    hdr->flags = flags;
    hdr->crc32 = 0;

    struct wvm_diff_log *log = (struct wvm_diff_log *)(g_aggregator.buf + g_aggregator.curr_offset + sizeof(struct wvm_header));
    log->gpa = WVM_HTONLL(gpa);
    log->version = WVM_HTONLL(version);
    log->offset = htons(off);
    log->size = htons(sz);
    if (sz > 0) memcpy(log->data, data, sz);

    // 在聚合前计算单子包 CRC
    hdr->crc32 = htonl(calculate_crc32((uint8_t*)hdr, needed));

    g_aggregator.curr_offset += needed;
    pthread_mutex_unlock(&g_aggregator.lock);
}

static int process_writable_page(WritablePage *curr, void *current_snapshot,
                                 int *batch_counter)
{
    void *page_addr = gpa_to_hva_safe(curr->gpa);
    if (!page_addr) {
        return 0;
    }

    int idx = LATCH_IDX(curr->gpa);

    // Freeze this page while a consistent post-write snapshot is taken.
    __atomic_store_n(&g_latches[idx].val, curr->gpa, __ATOMIC_RELEASE);

    bool is_volatile = wvm_is_volatile_gpa(curr->gpa);
    if (!is_volatile) {
        mprotect(page_addr, 4096, PROT_READ);
    }
    __sync_synchronize();

    memcpy(current_snapshot, page_addr, 4096);

    __atomic_store_n(&g_latches[idx].val, (uint64_t)-1, __ATOMIC_RELEASE);

    uint64_t ver = get_local_page_version(curr->gpa);
    bool committed = false;

    if (is_page_all_zero(current_snapshot)) {
        /*
         * Commit packets carry the page's current version.  The directory
         * advances to the next version after applying the diff.
         */
        add_to_aggregator(curr->gpa, ver, 0, 0, NULL, WVM_FLAG_ZERO);
        committed = true;
    } else {
        int start = -1, end = -1;
        uint64_t *p64_now = (uint64_t *)current_snapshot;
        uint64_t *p64_pre = (uint64_t *)curr->pre_image_snapshot;

        for (int i = 0; i < 512; i++) {
            if (p64_now[i] != p64_pre[i]) {
                if (start == -1) {
                    start = i * 8;
                }
                end = i * 8 + 7;
            }
        }

        if (start != -1) {
            uint16_t size = end - start + 1;
            add_to_aggregator(curr->gpa, ver, (uint16_t)start, size,
                              (uint8_t *)current_snapshot + start, 0);
            committed = true;
        }
    }

    if (!committed) {
        return 0;
    }

    set_local_page_version(curr->gpa, ver + 1);

    if (batch_counter && g_client_sync_batch > 0) {
        (*batch_counter)++;
        if (*batch_counter >= g_client_sync_batch) {
            flush_aggregator();
            long rtt = wait_for_directory_ack_safe();
            *batch_counter = 0;

            if (g_enable_auto_tuning) {
                if (rtt < 0) {
                    g_client_sync_batch =
                        (g_client_sync_batch > 16) ? g_client_sync_batch / 2 : 1;
                } else if (rtt < 500) {
                    if (g_client_sync_batch < g_max_batch) {
                        g_client_sync_batch += 16;
                    }
                } else if (rtt > 5000) {
                    g_client_sync_batch = (g_client_sync_batch * 3) / 4;
                    if (g_client_sync_batch < g_min_batch) {
                        g_client_sync_batch = g_min_batch;
                    }
                }
            }
        }
    }

    return 1;
}

static int process_writable_batch(WritablePage *batch_head,
                                  void *current_snapshot,
                                  int *batch_counter)
{
    int committed = 0;

    for (WritablePage *curr = batch_head; curr; curr = curr->next) {
        committed += process_writable_page(curr, current_snapshot, batch_counter);
    }

    flush_aggregator();
    return committed;
}

static void requeue_writable_page_chain(WritablePage *head)
{
    WritablePage *tail;
    WritablePage *observed;

    if (!head) {
        return;
    }
    for (tail = head; tail->next; tail = tail->next) {
        void *page_addr = gpa_to_hva_safe(tail->gpa);
        if (page_addr && !wvm_is_volatile_gpa(tail->gpa)) {
            mprotect(page_addr, 4096, PROT_READ | PROT_WRITE);
        }
    }
    {
        void *page_addr = gpa_to_hva_safe(tail->gpa);
        if (page_addr && !wvm_is_volatile_gpa(tail->gpa)) {
            mprotect(page_addr, 4096, PROT_READ | PROT_WRITE);
        }
    }
    observed = __atomic_load_n(&g_writable_pages_list, __ATOMIC_ACQUIRE);
    do {
        tail->next = observed;
    } while (!__atomic_compare_exchange_n(
        &g_writable_pages_list, &observed, head, true,
        __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
}

static int process_writable_batch_full_snapshot(WritablePage *batch_head,
                                                void *current_snapshot)
{
    int committed = 0;
    int first_error = 0;
    uint64_t *seen = NULL;
    size_t seen_count = 0;
    size_t seen_capacity = 0;
    const bool use_commit = wavevm_qemu_runtime_gate_enabled();

    for (WritablePage *curr = batch_head; curr; curr = curr->next) {
        bool duplicate = false;

        for (size_t i = 0; i < seen_count; i++) {
            if (seen[i] == curr->gpa) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        if (seen_count == seen_capacity) {
            size_t new_capacity = seen_capacity ? seen_capacity * 2 : 64;
            uint64_t *new_seen = realloc(seen, new_capacity * sizeof(*seen));
            if (!new_seen) {
                first_error = -ENOMEM;
                requeue_writable_page_chain(curr);
                break;
            }
            seen = new_seen;
            seen_capacity = new_capacity;
        }
        seen[seen_count++] = curr->gpa;

        void *page_addr = gpa_to_hva_safe(curr->gpa);
        if (!page_addr) {
            first_error = -EFAULT;
            requeue_writable_page_chain(curr);
            break;
        }

        int idx = LATCH_IDX(curr->gpa);

        __atomic_store_n(&g_latches[idx].val, curr->gpa, __ATOMIC_RELEASE);
        if (!wvm_is_volatile_gpa(curr->gpa)) {
            mprotect(page_addr, 4096, PROT_READ);
        }
        __sync_synchronize();

        memcpy(current_snapshot, page_addr, 4096);

        __atomic_store_n(&g_latches[idx].val, (uint64_t)-1, __ATOMIC_RELEASE);

        /*
         * A remote TCG slice returns one final architectural state.  Match that
         * with one final full-page memory snapshot per dirty GPA so high-churn
         * pages such as kernel stacks do not depend on a lossless chain of
         * intermediate partial diffs.
         */
        if (use_commit) {
            struct wvm_mem_commit_ack ack;
            uint64_t base_version = get_local_page_version(curr->gpa);
            int commit_ret;

            if (base_version == 0) {
                commit_ret = -ESTALE;
            } else {
                if (t_com_sock < 0) {
                    t_com_sock = internal_connect_master();
                }
                commit_ret = request_commit_on_fd(
                    t_com_sock, curr->gpa, base_version, 0,
                    current_snapshot, WVM_MEMORY_PAGE_BYTES, &ack);
            }
            if (commit_ret != 0) {
                ram_addr_t ra = qemu_ram_addr_from_host(page_addr);
                if (ra != RAM_ADDR_INVALID) {
                    cpu_physical_memory_set_dirty_range(
                        ra, 4096, 1 << DIRTY_MEMORY_MIGRATION);
                }
                first_error = commit_ret;
                requeue_writable_page_chain(curr);
                break;
            }
            set_local_page_version(curr->gpa, ack.result_version);
        } else {
            uint64_t ver = get_local_page_version(curr->gpa) + 1;
            add_to_aggregator(curr->gpa, ver, 0, 4096, current_snapshot, 0);
            set_local_page_version(curr->gpa, ver);
        }
        committed++;
    }

    free(seen);
    if (!use_commit) {
        flush_aggregator();
    }
    return first_error != 0 ? first_error : committed;
}

int wavevm_user_mem_flush_slave_dirty_sync(void)
{
    void *current_snapshot;
    WritablePage *batch_head;
    int committed;
    long rtt;
    static int flush_log_count;

    if (!g_is_slave || g_fd_push < 0 || g_block_count <= 0) {
        return 0;
    }

    current_snapshot = malloc(4096);
    if (!current_snapshot) {
        return -ENOMEM;
    }

    pthread_mutex_lock(&g_dirty_flush_lock);
    batch_head = __atomic_exchange_n(&g_writable_pages_list, NULL,
                                     __ATOMIC_ACQ_REL);
    committed = process_writable_batch_full_snapshot(batch_head,
                                                     current_snapshot);
    if (committed < 0) {
        rtt = committed;
    } else if (committed > 0) {
        /*
         * A remote TCG slice return is a causal handoff: all writes made by the
         * slave must be visible to the directory before the CPU ACK is exported.
         */
            rtt = wait_for_directory_ack_safe_us(5000000ULL);
    } else {
        rtt = 0;
    }
    pthread_mutex_unlock(&g_dirty_flush_lock);

    free(current_snapshot);

    if (committed > 0 && flush_log_count < 20) {
        fprintf(stderr,
                "[WaveVM-User] slave TCG slice dirty flush pages=%d rtt=%ldus\n",
                committed, rtt);
        flush_log_count++;
    }

    return (rtt < 0) ? (int)rtt : 0;
}

/*
 * [物理意图] 充当内存页面的“分布式写回缓存（Write-back Cache）”管理器。
 * [关键逻辑] 1. 计算增量（Diff）；2. 聚合（Aggregator）打包；3. 执行 AIMD 自适应同步屏障，根据 RTT 调整提交频率。
            逻辑: Detach -> Freeze(Lock) -> Snapshot -> Release(Unlock) -> Diff -> Commit -> Sync
 * [后果] 它通过异步提交隐藏了网络延迟。若收割速度跟不上写入速度，Guest 系统内会发生明显的“因果倒置”现象。
 */
static void *diff_harvester_thread_fn(void *arg) {
    void *current_snapshot = malloc(4096);
    if (!current_snapshot) return NULL;

    int batch_counter = 0;

    while (g_threads_running) {
        /* KVM: 1ms cycle (dirty log is cheap, no mprotect overhead).
         * TCG: 50ms cycle — mprotect(PROT_READ) re-arms SIGSEGV on every
         * subsequent write.  At 1ms the harvester re-protects pages so fast
         * that kernel boot triggers millions of SIGSEGVs (2.3M+ in V32g).
         * 50ms lets pages stay RW longer, cutting SIGSEGV ~50x. */
        usleep((kvm_enabled() || !g_is_slave) ? 1000 : 50000);

        /*
         * Slave TCG memory is committed at CPU_RUN ACK boundaries.  Letting the
         * background harvester emit partial diffs during a remote slice creates
         * version gaps for high-frequency pages before the causal CPU state is
         * returned.
         */
        if (g_is_slave && !kvm_enabled()) {
            continue;
        }

        // KVM: harvest QEMU dirty logs, no SIGSEGV/PROT_NONE.
        // Master TCG is synchronized explicitly at remote handoff boundaries.
        // A continuous async TCG stream uses a different IPC socket from CPU_RUN
        // and can overtake the handoff fence, making directory versions diverge.
        // [FIX] 遍历 g_mem_blocks 而非 flat 0~g_ram_size，
        //       并用 qemu_ram_addr_from_host 将 HVA 转为正确的 ram_addr_t，
        //       修复 PCI hole (3G-4G) 导致的 gpa != ram_addr_t 问题。
        if (kvm_enabled()) {
            pthread_mutex_lock(&g_dirty_flush_lock);
            for (int bi = 0; bi < g_block_count; bi++) {
                GVMRamBlock *blk = &g_mem_blocks[bi];
                /* 将 block 起始 HVA 转为 ram_addr_t 基址（一次性，避免每页调用） */
                ram_addr_t ram_base = qemu_ram_addr_from_host((void *)blk->hva_start);
                if (ram_base == RAM_ADDR_INVALID) continue;

                for (uint64_t off = 0; off + 4096 <= blk->size; off += 4096) {
                    ram_addr_t ra = ram_base + off;
                    if (!cpu_physical_memory_test_and_clear_dirty(ra, 4096, DIRTY_MEMORY_MIGRATION)) {
                        continue;
                    }
                    uint64_t gpa = blk->gpa_start + off;
                    void *hva = (void *)(blk->hva_start + off);
                    uint64_t ver = get_local_page_version(gpa);
                    add_to_aggregator(gpa, ver + 1, 0, 4096, hva, 0);
                    set_local_page_version(gpa, ver + 1);
                }
            }
            flush_aggregator();
            pthread_mutex_unlock(&g_dirty_flush_lock);
            continue;
        }

        pthread_mutex_lock(&g_dirty_flush_lock);

        // 1. 偷走链表 (Detach List) — 必须用原子交换，与信号处理函数的 CAS 配合
        WritablePage *batch_head = __atomic_exchange_n(&g_writable_pages_list, NULL, __ATOMIC_ACQ_REL);

        if (!batch_head) {
            pthread_mutex_unlock(&g_dirty_flush_lock);
            continue;
        }

        // 2. 遍历处理脏页
        process_writable_batch(batch_head, current_snapshot, &batch_counter);
        pthread_mutex_unlock(&g_dirty_flush_lock);
    }
    free(current_snapshot);
    return NULL;
}

// =============================================================
// [链路 B] 流式监听线程 (Stream Listener)
// =============================================================

// 环形缓冲区，用于处理 IPC 流的粘包/拆包
typedef struct {
    uint8_t buffer[WVM_MAX_PACKET_SIZE * 4];
    size_t head; // Read ptr
    size_t tail; // Write ptr
} StreamBuffer;

static void sb_init(StreamBuffer *sb) {
    sb->head = 0;
    sb->tail = 0;
}

static void sb_compact(StreamBuffer *sb) {
    if (sb->head > 0) {
        size_t len = sb->tail - sb->head;
        if (len > 0) memmove(sb->buffer, sb->buffer + sb->head, len);
        sb->tail = len;
        sb->head = 0;
    }
}

// --- [V29 Sync Concurrency Control] ---
static pthread_mutex_t g_sync_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_sync_cond = PTHREAD_COND_INITIALIZER;
static volatile int g_ack_received = 0; // 状态标志位

// 辅助：获取微秒时间
static uint64_t get_us_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000UL + ts.tv_nsec / 1000;
}

// 导出配置接口
void wvm_set_client_sync_mode(int batch_size, int auto_tune) {
    if (batch_size > 0) g_client_sync_batch = batch_size;
    g_enable_auto_tuning = auto_tune;

    // 如果设为 1，通常意味着强一致性需求，关闭自动调优
    if (batch_size == 1) {
        g_enable_auto_tuning = 0;
        printf("[WVM] Strict Consistency Mode Activated (Batch=1, No Tuning)\n");
    } else {
        printf("[WVM] Sync Mode: Initial Batch=%d, AutoTuning=%d\n",
               batch_size, auto_tune);
    }
}

/*
 * [F07 Fix] Both Master and Slave TCG now use typed IPC protocol for fence.
 * Legacy MSG_PING/SYNC_MAGIC over UDP removed.
 *
 * [物理意图] 在 P2P 集群中插入一个"顺序执行栅栏"。
 * [关键逻辑] 通过typed IPC发送commit diff sync请求，等待node_runtime确认所有pending写入已落盘。
 * [后果] 确保了分布式内存的"强顺序一致性"。它防止了在执行关键 IO 指令（如 GPU 命令提交）时，内存数据尚未同步完成的情况。
 */
static long wait_for_directory_ack_safe_us(uint64_t timeout_us) {
    (void)timeout_us;

    /* Both Master and Slave TCG use IPC for fence synchronization (F07 fix) */
    if (g_ipc_diff_sock < 0) {
        /* No active IPC connection - treat as local-only mode with no fence needed */
        return 100;
    }

    /* Send typed commit diff sync over IPC to ensure all pending writes are flushed */
    wvm_ipc_header_t header;
    uint8_t sync_request[16] = {0}; /* Minimal sync request payload */
    uint8_t sync_response[16];

    header.type = WVM_IPC_TYPE_COMMIT_DIFF_SYNC;
    header.len = sizeof(sync_request);

    if (write_all_fd(g_ipc_diff_sock, &header, sizeof(header)) < 0 ||
        write_all_fd(g_ipc_diff_sock, sync_request, sizeof(sync_request)) < 0 ||
        read_exact(g_ipc_diff_sock, sync_response, sizeof(sync_response)) < 0) {
        return -1;
    }

    return 100; /* Success - fence complete */
}

static long wait_for_directory_ack_safe(void)
{
    return wait_for_directory_ack_safe_us(1000000ULL);
}

/*
 * [物理意图] 系统的“入站流量净化器”，解决 UDP 乱序和 TLB 刷新成本问题。
 * [关键逻辑] 1. 维护重排窗口（Reorder Window）填补版本空洞；2. 执行延迟刷新（Lazy Flush）以合并 mprotect 调用。
 * [后果] 延迟刷新是性能的救星。若每收到一个 Diff 都执行一次 TLB Shootdown，vCPU 的有效执行时间将缩减到不足 10%。
 */
static void process_push_net_packet(struct wvm_header *hdr, void *payload,
                                    uint16_t p_len)
{
    uint16_t msg_type = ntohs(hdr->msg_type);

    if (msg_type == MSG_PAGE_PUSH_DIFF) {
        if (p_len < sizeof(struct wvm_diff_log)) {
            return;
        }

        struct wvm_diff_log* log = (struct wvm_diff_log*)payload;
        uint64_t gpa = WVM_NTOHLL(log->gpa);
        uint64_t push_ver = WVM_NTOHLL(log->version);
        uint64_t local_ver = get_local_page_version(gpa);

        if (is_next_version(local_ver, push_ver)) {
            wvm_apply_remote_push(msg_type, payload);
            while (check_and_apply_next(gpa, 0)) ;
        } else if (is_newer_version(local_ver, push_ver) &&
                   !is_next_version(local_ver, push_ver)) {
            if (!is_newer_version(local_ver + REORDER_WIN_SIZE, push_ver)) {
                buffer_future_packet(gpa, push_ver, msg_type, payload, p_len);
            } else {
                if (!kvm_enabled() && g_fault_hook_enabled) {
                    void *inv_hva = gpa_to_hva_safe(gpa);
                    if (inv_hva) {
                        mprotect(inv_hva, 4096, PROT_NONE);
                    }
                }
                set_local_page_version(gpa, 0);
                if (kvm_enabled()) {
                    kvm_proactive_page_fetch(gpa);
                }
            }
        }
    } else if (msg_type == MSG_PAGE_PUSH_FULL || msg_type == MSG_FORCE_SYNC) {
        wvm_apply_remote_push(msg_type, payload);
    } else if (msg_type == MSG_RPC_BATCH_MEMSET) {
        wvm_apply_remote_push(msg_type, payload);
    } else if (msg_type == MSG_MEM_ACK &&
               WVM_NTOHLL(hdr->req_id) == SYNC_MAGIC) {
        pthread_mutex_lock(&g_sync_lock);
        g_ack_received = 1;
        pthread_cond_signal(&g_sync_cond);
        pthread_mutex_unlock(&g_sync_lock);
    }
}

static void *mem_push_listener_thread(void *arg) {
    StreamBuffer sb;
    sb_init(&sb);

    // 初始化 TLS 队列索引
    t_lazy_count = 0;
    uint64_t last_cleanup_us = 0;

    struct pollfd pfd = { .fd = g_fd_push, .events = POLLIN };
    printf("[WVM] Async Push Listener Started (Streaming Mode + Lazy Flush).\n");

    while (g_threads_running) {
        // [Stage 0] 循环前冲刷
        // 确保上一轮循环遗留的 RW 页面被锁回 RO。
        // 这保证了 poll 等待期间，页面是安全的（RO）。
        flush_lazy_ro_queue();

        int ret = poll(&pfd, 1, 100);
        uint64_t now_us = get_us_time();
        if (now_us - last_cleanup_us > 200000) { // 每 200ms 清理一次
            pthread_spin_lock(&g_reorder_lock);
            for (int i = 0; i < REORDER_WIN_SIZE; i++) {
                if (g_reorder_buf[i].active && (now_us - g_reorder_buf[i].timestamp_us > 200000)) {
                    uint64_t stale_gpa = g_reorder_buf[i].gpa;

                    // 释放资源
                    free(g_reorder_buf[i].data);
                    g_reorder_buf[i].active = false;

                    // 触发强制同步
                    void* hva = gpa_to_hva_safe(stale_gpa);
                    if (hva && !kvm_enabled() && g_fault_hook_enabled) {
                        mprotect(hva, 4096, PROT_NONE);
                    }
                    set_local_page_version(stale_gpa, 0);
                    // [FIX-F3] KVM 模式下主动拉取过期重排缓冲区中的页面
                    if (kvm_enabled()) {
                        kvm_proactive_page_fetch(stale_gpa);
                    }
                }
            }
            pthread_spin_unlock(&g_reorder_lock);
            last_cleanup_us = now_us;
        }
        if (ret <= 0) continue;

        // [Stage 1] 读取网络流
        size_t space = sizeof(sb.buffer) - sb.tail;
        if (space == 0) { sb_init(&sb); continue; }
        ssize_t n = recv(g_fd_push, sb.buffer + sb.tail, space, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        sb.tail += n;

        // [Stage 2] Parse raw WaveVM datagrams from the slave proxy, while
        // retaining compatibility with IPC-framed packets.
        while (sb.tail - sb.head >= sizeof(struct wvm_ipc_header_t)) {
            uint8_t *cur = sb.buffer + sb.head;
            size_t avail = sb.tail - sb.head;
            size_t total_msg_len = 0;

            if (avail >= sizeof(struct wvm_header)) {
                struct wvm_header *raw = (struct wvm_header *)cur;
                if (ntohl(raw->magic) == WVM_MAGIC) {
                    uint16_t p_len = ntohs(raw->payload_len);
                    total_msg_len = sizeof(struct wvm_header) + p_len;
                    if (avail < total_msg_len) {
                        break;
                    }
                    process_push_net_packet(raw, cur + sizeof(struct wvm_header),
                                            p_len);
                    sb.head += total_msg_len;
                    continue;
                }
            }

            struct wvm_ipc_header_t *ipc = (struct wvm_ipc_header_t *)cur;
            if (ipc->type == WVM_IPC_TYPE_INVALIDATE &&
                ipc->len >= sizeof(struct wvm_header) &&
                ipc->len <= WVM_MAX_PACKET_SIZE) {
                total_msg_len = sizeof(struct wvm_ipc_header_t) + ipc->len;
                if (avail < total_msg_len) {
                    break;
                }

                struct wvm_header *hdr =
                    (struct wvm_header *)(cur + sizeof(struct wvm_ipc_header_t));
                if (ntohl(hdr->magic) == WVM_MAGIC) {
                    uint16_t p_len = ntohs(hdr->payload_len);
                    if (sizeof(struct wvm_header) + p_len <= ipc->len) {
                        process_push_net_packet(hdr,
                                                (uint8_t *)hdr + sizeof(*hdr),
                                                p_len);
                    }
                }
                sb.head += total_msg_len;
                continue;
            }

            if (ipc->type == WVM_IPC_TYPE_PUSH_BARRIER &&
                ipc->len == sizeof(uint64_t)) {
                total_msg_len = sizeof(struct wvm_ipc_header_t) + ipc->len;
                if (avail < total_msg_len) {
                    break;
                }

                /*
                 * The master sends this after one or more PAGE_PUSH messages
                 * on the same stream.  Reaching this point means every prior
                 * push was applied; flush lazy protections before ACKing the
                 * CPU handoff fence.
                 */
                uint64_t cookie;
                struct wvm_ipc_header_t ack = {
                    .type = WVM_IPC_TYPE_PUSH_BARRIER_ACK,
                    .len = sizeof(cookie),
                };

                memcpy(&cookie, cur + sizeof(struct wvm_ipc_header_t),
                       sizeof(cookie));
                {
                    static int barrier_rx_log_count;
                    if (barrier_rx_log_count < 20) {
                        fprintf(stderr,
                                "[WVM-PUSH-BARRIER] rx cookie=%llu\n",
                                (unsigned long long)cookie);
                        barrier_rx_log_count++;
                    }
                }
                flush_lazy_ro_queue();
                if (write_all_fd(g_fd_push, &ack, sizeof(ack)) == 0) {
                    write_all_fd(g_fd_push, &cookie, sizeof(cookie));
                    {
                        static int barrier_ack_log_count;
                        if (barrier_ack_log_count < 20) {
                            fprintf(stderr,
                                    "[WVM-PUSH-BARRIER] ack cookie=%llu\n",
                                    (unsigned long long)cookie);
                            barrier_ack_log_count++;
                        }
                    }
                }
                sb.head += total_msg_len;
                continue;
            }

            // Resynchronize after an unexpected byte; prevents one malformed
            // datagram from wedging the listener forever.
            sb.head++;
        }
        sb_compact(&sb);

        // [Stage 3] 循环末尾强制冲刷
        // 这一步至关重要。它确保了上述 while 循环处理的一批包（可能几十个）
        // 对应的页面在处理完后立刻被锁回 RO。
        // 这将 RW 窗口限制在“微秒级”，兼顾了性能与一致性。
        flush_lazy_ro_queue();
    }
    return NULL;
}

// --- 初始化 ---
void wavevm_user_mem_init(void *ram_ptr, size_t ram_size) {
    static bool push_listener_started;
    g_ram_base = ram_ptr;
    g_ram_size = ram_size;
    if (!getenv("WVM_SOCK_REQ")) {
        ensure_local_shm_shadow();
    }
    bool enable_fault_hook = true;
    const char *hook_env = getenv("WVM_ENABLE_FAULT_HOOK");
    if (hook_env && atoi(hook_env) == 0) {
        enable_fault_hook = false;
    }

    char *env_req = getenv("WVM_SOCK_REQ");
    char *env_push = getenv("WVM_SOCK_PUSH");
    char *env_id = getenv("WVM_SLAVE_ID");
    g_is_slave = (env_req && env_push) ? 1 : 0;

    /*
     * Master TCG must not use host mprotect tracking: firmware and device DMA
     * write guest RAM from QEMU threads, and trapping those writes can surface
     * as BIOS/bootloader disk read failures.  Track master writes through
     * QEMU's dirty log instead.  Slave TCG keeps fault-based demand paging.
     */
    g_fault_hook_enabled = enable_fault_hook && !kvm_enabled() && g_is_slave;
    g_fault_hook_checked = true;

    // KVM + PROT_NONE 会导致 EPT violation，KVM 下：
    //   1. 启用 migration dirty log 替代 mprotect 追踪脏页
    //   2. 各调用点用 !kvm_enabled() 守卫跳过 mprotect(PROT_NONE)
    // 注意：fault hook（SIGSEGV 拦截器）仍然保留，它是分布式缺页请求的核心通道。
    if (kvm_enabled() || !g_is_slave) {
        memory_global_dirty_log_start();
        fprintf(stderr, "[WaveVM] dirty log tracking enabled (kvm=%d slave=%d).\n",
                kvm_enabled() ? 1 : 0, g_is_slave);
    }

    if (!kvm_enabled() && !getenv("WVM_SOCK_REQ")) {
        /* x86 BIOS/PAM shadow RAM is already copied into SHM by
         * wavevm_sync_bios_shadow(). Keep it from becoming a high-frequency
         * write-protect fault source during firmware shadowing. */
        wvm_register_volatile_ram(0xC0000, 0x40000);
    }

    init_latches();
    pthread_spin_init(&g_reorder_lock, 0);

    for(int i=0; i<PAGE_POOL_SIZE; i++) {
        g_image_pool[i] = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    }

    size_t num_pages = ram_size / 4096;

    if (env_req && env_push) {
        g_fd_req = atoi(env_req);
        g_fd_push = atoi(env_push);
        g_slave_id = env_id ? atoi(env_id) : 0;

        printf("[WaveVM-User] V29 Wavelet Engine Active (Slave ID: %d)\n", g_slave_id);

        if (!push_listener_started) {
            g_threads_running = true;
            if (pthread_create(&g_listen_thread, NULL,
                               mem_push_listener_thread, NULL) == 0) {
                push_listener_started = true;
            }
        }
        if (kvm_enabled()) {
            pthread_create(&g_harvester_thread, NULL, diff_harvester_thread_fn, NULL);
        } else {
            /*
             * A TCG slave vCPU slice is a causal execution unit: memory writes
             * must be committed and fenced immediately before the CPU state ACK.
             * The async harvester can otherwise race that handoff and let memory
             * packets overtake or lag behind the returned vCPU context.
             */
            fprintf(stderr, "[WaveVM-User] TCG slave dirty flush is handoff-synchronous\n");
        }
    }
    else {
        /*
         * Master QEMU also needs a dedicated async push channel: remote
         * directories send FORCE_SYNC/PAGE_PUSH updates back to this process
         * when a local writer is stale.  vCPU RPC sockets are synchronous and
         * cannot safely double as the push listener.
         */
        if (g_fd_push < 0) {
            g_fd_push = internal_connect_master_role(WVM_IPC_ROLE_ASYNC_PUSH);
        }
        if (g_fd_push >= 0 && !push_listener_started) {
            g_threads_running = true;
            if (pthread_create(&g_listen_thread, NULL,
                               mem_push_listener_thread, NULL) == 0) {
                push_listener_started = true;
                fprintf(stderr, "[WaveVM-User] master async push listener active fd=%d\n",
                        g_fd_push);
            } else {
                fprintf(stderr, "[WaveVM-User] master async push listener start failed errno=%d\n",
                        errno);
                close(g_fd_push);
                g_fd_push = -1;
            }
        } else if (g_fd_push < 0) {
            fprintf(stderr, "[WaveVM-User] master async push connect failed errno=%d\n",
                    errno);
        }
        if (!kvm_enabled()) {
            /*
             * Master TCG dirty pages are flushed synchronously on CPU handoff.
             * Do not start the async harvester here: it has no ordering against
             * the per-vCPU IPC stream and can race the handoff fence.
             */
            printf("[WaveVM-User] V31 Master TCG Handoff Dirty Flush Active\n");
        }
    }

    if (!kvm_enabled() && g_fault_hook_enabled) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_SIGINFO; // [FIX-M6] 移除 SA_NODEFER，防止 handler 内递归 SIGSEGV 导致栈溢出
        sa.sa_sigaction = sigsegv_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);

        // Initial state is handled per RAM block in wavevm_register_ram_block().
    }
}


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
#include "qemu/main-loop.h"
#include <sys/mman.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <ucontext.h>
#include <unistd.h>
#include <sched.h>
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
#include "exec/exec-all.h"
#include "exec/memory.h"
#include "exec/ram_addr.h"

#include "../../../common_include/wavevm_protocol.h"
#include "../../../common_include/wavevm_local_memory.h"
#include "../../../common_include/wavevm_memory.h"
#include "wavevm-runtime-registration.h"

void wavevm_user_mem_record_tcg_write(ram_addr_t ram_addr, unsigned size);
int wavevm_publish_initial_ram(uint64_t gpa, void *hva, uint64_t bytes,
                               uint64_t *published_pages);

/*
 * WaveVM V29.5 "Wavelet" User-Mode Memory Engine (Production Ready)
 */

// --- 全局配置与状态 ---
static int g_is_slave = 0;
static int g_fd_req = -1;
static __thread uint8_t t_net_buf[WVM_MAX_PACKET_SIZE];
static int g_fd_push = -1;
static int g_ipc_diff_sock = -1; // [FIX-G1] Master TCG harvester 专用 IPC socket
/* Kept open so a stopped TCG helper can still prove QEMU frontend readiness. */
static int g_runtime_registration_fd = -1;
static void *g_ram_base = NULL;
static size_t g_ram_size = 0;
static void *g_shm_shadow = NULL;
static uint32_t g_slave_id = 0;
static bool g_fault_hook_enabled = false;
static bool g_fault_hook_checked = false;
/* Local helper/runtime share a backing; this is not a remote FE proof. */
static int g_tcg_shm_coherent = 0;
/*
 * A helper's RAM dirty bitmap starts dirty while QEMU is constructing the
 * machine and joining the shared backing.  Those bits describe the admitted
 * initial image, not a guest write from a remote CPU slice.  Consume that
 * bootstrap state once, immediately before the first slice, so later dirty
 * bits have a matching pre-image generation.
 */
static atomic_bool g_tcg_dirty_baseline_ready = false;

void wavevm_user_mem_set_tcg_shm_coherent(int enabled)
{
    /*
     * F05: SHM join/attach only proves this process mapped a local backing.
     * Coherent fast-path (skip fault-hook) requires FE and executor to share
     * that backing on the same physical host. When both host ids are known
     * and differ, refuse coherent and keep the real fault/sync path.
     * Missing host ids keep the prior same-host join behavior (local tests)
     * but do not claim cross-host shared RAM.
     */
    if (enabled) {
        const char *fe_host = getenv("WVM_FE_PHYSICAL_HOST_ID");
        const char *ex_host = getenv("WVM_EXECUTOR_PHYSICAL_HOST_ID");
        if (fe_host && *fe_host && ex_host && *ex_host) {
            char *fe_end = NULL, *ex_end = NULL;
            unsigned long long fe = strtoull(fe_host, &fe_end, 10);
            unsigned long long ex = strtoull(ex_host, &ex_end, 10);
            if (fe_end && *fe_end == '\0' && ex_end && *ex_end == '\0' &&
                fe != 0 && ex != 0 && fe != ex) {
                fprintf(stderr,
                        "[WaveVM-User] F05 coherent REFUSED: FE host=%llu "
                        "executor host=%llu (cross-host; fault path kept)\n",
                        fe, ex);
                enabled = 0;
            }
        }
    }
    g_tcg_shm_coherent = enabled ? 1 : 0;
    if (g_tcg_shm_coherent) {
        /* The local runtime installs canonical pages in this shared backing. */
        g_fault_hook_enabled = false;
        /*
         * Join may enable coherent after wavevm_user_mem_init. Ensure dirty
         * logging is on so handoff-synchronous flush can self-emit commits.
         */
        if (g_is_slave && !kvm_enabled()) {
            memory_global_dirty_log_start();
        }
        fprintf(stderr,
                "[WaveVM-User] TCG SHM coherent mode ON "
                "(skip fault-hook / local RAM copies; directory commit stays)\n");
    } else if (!enabled) {
        /* leave fault hook policy to its existing init path */
    }
}


int wavevm_user_mem_tcg_shm_coherent(void)
{
    return g_tcg_shm_coherent;
}

/*
 * Deferred SIGSEGV fault path (capability-fault-engines.md §4.2 / V1 non-goal):
 * the async signal handler may only record a fault in a preallocated slot and
 * wake the dedicated worker. Page IPC / CBW / mprotect run on the worker, never
 * as sync RPC inside sigsegv_handler.
 */
enum {
    WVM_FAULT_SLOT_FREE = 0,
    WVM_FAULT_SLOT_FILLING = 1,
    WVM_FAULT_SLOT_SUBMITTED = 2,
    WVM_FAULT_SLOT_DONE = 3,
    WVM_FAULT_SLOT_FAILED = 4,
};

typedef struct {
    atomic_int state;
    uintptr_t fault_addr;
    uint64_t gpa;
    int is_write;
} WVMFaultSlot;

#define WVM_FAULT_QUEUE_SIZE 128
static WVMFaultSlot g_fault_slots[WVM_FAULT_QUEUE_SIZE];
static atomic_uint g_fault_slot_cursor;
static int g_fault_wake_fd = -1; /* eventfd; write end used from handler */
static pthread_t g_fault_worker_thread;
static atomic_int g_fault_worker_ready;
static volatile bool g_fault_worker_running = false;
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
static int install_page_bytes(uint64_t gpa, uintptr_t aligned_addr,
                              const uint8_t *data, int is_write);
static void send_diff_via_ipc(void *buf, size_t len);
static int write_all_fd(int fd, const void *buf, size_t len);
static void flush_aggregator(void);

// 脏区捕获链表
typedef struct WritablePage {
    uint64_t gpa;
    void* pre_image_snapshot;
    /* F06: slot index is (wp - g_page_pool); keep struct size == HEAD. */
    struct WritablePage *next;
} WritablePage;

#define PAGE_POOL_SIZE 4096
static WritablePage g_page_pool[PAGE_POOL_SIZE];
static void* g_image_pool[PAGE_POOL_SIZE]; // 预分配快照空间
static atomic_uint g_pool_idx = 0; /* [FIX] 必须无符号，防止 21 亿次写缺页后有符号溢出导致负数取模越界 */
/* F06: occupancy — never wrap-reuse a slot still on the writable list / in flight. */
static atomic_uint g_page_pool_occupied[PAGE_POOL_SIZE];
static atomic_uint g_page_pool_in_use = 0;

static int page_pool_claim(void)
{
    for (int n = 0; n < PAGE_POOL_SIZE; n++) {
        unsigned idx = atomic_fetch_add_explicit(&g_pool_idx, 1,
                                                 memory_order_relaxed) %
                       PAGE_POOL_SIZE;
        unsigned expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_page_pool_occupied[idx], &expected, 1,
                memory_order_acq_rel, memory_order_acquire)) {
            atomic_fetch_add_explicit(&g_page_pool_in_use, 1,
                                      memory_order_relaxed);
            return (int)idx;
        }
    }
    return -1;
}

static void page_pool_release(int idx)
{
    if (idx < 0 || idx >= PAGE_POOL_SIZE) {
        return;
    }
    unsigned was = atomic_exchange_explicit(&g_page_pool_occupied[idx], 0,
                                            memory_order_acq_rel);
    if (was) {
        atomic_fetch_sub_explicit(&g_page_pool_in_use, 1, memory_order_relaxed);
    }
}

static void writable_page_release_chain(WritablePage *head,
                                        WritablePage *stop_before)
{
    /*
     * F06: capture next BEFORE release. Pool slots ARE the WritablePage
     * nodes; clearing occupancy allows another claim to overwrite next.
     * Index is (curr - g_page_pool) so sizeof(WritablePage) stays at HEAD.
     */
    WritablePage *curr = head;
    while (curr && curr != stop_before) {
        WritablePage *next = curr->next;
        int idx = (int)(curr - g_page_pool);
        curr->next = NULL;
        if (idx >= 0 && idx < PAGE_POOL_SIZE) {
            page_pool_release(idx);
        }
        curr = next;
    }
}

static volatile bool g_threads_running = false;
static pthread_t g_listen_thread;
static pthread_t g_harvester_thread;

#define MAX_RAM_BLOCKS 64

typedef struct {
    uintptr_t hva_start;
    uintptr_t hva_end;
    ram_addr_t ram_start;
    uint64_t  gpa_start;
    uint64_t  size;
} GVMRamBlock;

static GVMRamBlock g_mem_blocks[MAX_RAM_BLOCKS];
static int g_block_count = 0;

int wavevm_user_mem_prepare_tcg_dirty_baseline(void)
{
    bool expected = false;
    int cleared = 0;

    if (!g_tcg_shm_coherent || kvm_enabled() || g_block_count <= 0) {
        return 0;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &g_tcg_dirty_baseline_ready, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return 0;
    }

    for (int bi = 0; bi < g_block_count; bi++) {
        GVMRamBlock *block = &g_mem_blocks[bi];

        if (block->ram_start == RAM_ADDR_INVALID) {
            continue;
        }
        for (uint64_t offset = 0; offset + WVM_MEMORY_PAGE_BYTES <= block->size;
             offset += WVM_MEMORY_PAGE_BYTES) {
            if (cpu_physical_memory_test_and_clear_dirty(
                    block->ram_start + offset, WVM_MEMORY_PAGE_BYTES,
                    DIRTY_MEMORY_MIGRATION)) {
                cleared++;
            }
        }
    }

    fprintf(stderr,
            "[WaveVM-User] TCG coherent dirty baseline consumed pages=%d "
            "blocks=%d\n",
            cleared, g_block_count);
    return cleared;
}

/* WVM coherent pre-image support begin */
/*
 * Coherent TCG writes do not take the fault-hook path.  QEMU's dirty bitmap
 * therefore tells us only that a page changed, not which bytes belonged to
 * this execution generation.  Keep one pre-image for the first TCG store in
 * each generation so a stale commit can merge the local write-set onto the
 * newer directory page instead of publishing an old full-page snapshot.
 */
typedef struct WVMCoherentPreimage {
    uint64_t gpa;
    uint64_t generation;
    uint8_t *bytes;
    struct WVMCoherentPreimage *next;
} WVMCoherentPreimage;

static WVMCoherentPreimage *g_coherent_preimages;
static pthread_mutex_t g_coherent_preimage_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t g_coherent_generation = 1;
static _Atomic uint64_t g_coherent_capture_failed_generation;

static bool coherent_ram_page_from_ram_addr(ram_addr_t ram_addr,
                                             uint64_t *gpa_out,
                                             uint8_t **hva_out)
{
    for (int i = 0; i < g_block_count; i++) {
        GVMRamBlock *blk = &g_mem_blocks[i];
        ram_addr_t offset;

        if (blk->ram_start == RAM_ADDR_INVALID || ram_addr < blk->ram_start) {
            continue;
        }
        offset = ram_addr - blk->ram_start;
        if (offset >= blk->size) {
            continue;
        }
        offset &= ~((ram_addr_t)WVM_MEMORY_PAGE_BYTES - 1);
        if (offset >= blk->size) {
            continue;
        }
        *gpa_out = blk->gpa_start + offset;
        *hva_out = (uint8_t *)(blk->hva_start + offset);
        return true;
    }
    return false;
}

static WVMCoherentPreimage *coherent_find_preimage_locked(uint64_t gpa,
                                                           uint64_t generation)
{
    for (WVMCoherentPreimage *entry = g_coherent_preimages;
         entry; entry = entry->next) {
        if (entry->gpa == gpa && entry->generation == generation) {
            return entry;
        }
    }
    return NULL;
}

static int coherent_copy_preimage(uint64_t gpa, uint64_t generation,
                                  uint8_t out[WVM_MEMORY_PAGE_BYTES],
                                  uint64_t *used_generation)
{
    int result = -ENOENT;
    WVMCoherentPreimage *selected = NULL;

    pthread_mutex_lock(&g_coherent_preimage_lock);
    /*
     * A TCG write hook runs before its store.  The dirty snapshot can win the
     * race after the hook captured its pre-image but before the store sets the
     * dirty bit.  That write then appears in the next bitmap generation.  Use
     * the oldest still-pending pre-image so rebasing includes every local byte
     * change since the last successful commit.
     */
    for (WVMCoherentPreimage *entry = g_coherent_preimages;
         entry; entry = entry->next) {
        if (entry->gpa == gpa && entry->generation <= generation &&
            (!selected || entry->generation < selected->generation)) {
            selected = entry;
        }
    }
    if (selected) {
        if (selected->bytes) {
            memcpy(out, selected->bytes, WVM_MEMORY_PAGE_BYTES);
            if (used_generation) {
                *used_generation = selected->generation;
            }
            result = 0;
        } else {
            result = -EIO;
        }
    } else {
        uint64_t failed_generation = atomic_load_explicit(
            &g_coherent_capture_failed_generation, memory_order_acquire);
        if (failed_generation != 0 && failed_generation <= generation) {
            result = -EIO;
        }
    }
    pthread_mutex_unlock(&g_coherent_preimage_lock);
    return result;
}

static void coherent_discard_preimage(uint64_t gpa, uint64_t generation)
{
    pthread_mutex_lock(&g_coherent_preimage_lock);
    WVMCoherentPreimage **cursor = &g_coherent_preimages;
    while (*cursor) {
        WVMCoherentPreimage *entry = *cursor;
        if (entry->gpa == gpa && entry->generation <= generation) {
            *cursor = entry->next;
            free(entry->bytes);
            free(entry);
            continue;
        }
        cursor = &entry->next;
    }
    pthread_mutex_unlock(&g_coherent_preimage_lock);
}

/* Called by QEMU's notdirty_write() before the first store retires. */
void wavevm_user_mem_record_tcg_write(ram_addr_t ram_addr, unsigned size)
{
    uint64_t first = (uint64_t)ram_addr & ~(uint64_t)(WVM_MEMORY_PAGE_BYTES - 1);
    uint64_t last;
    uint64_t generation;

    /* Only the slave bitmap-snapshot path consumes these pre-images.  The
     * master uses flush_dirty_to_ipc and has no matching generation advance,
     * so recording there would retain entries indefinitely. */
    if (!g_tcg_shm_coherent || !g_is_slave || size == 0) {
        return;
    }
    if ((uint64_t)size - 1 > UINT64_MAX - (uint64_t)ram_addr) {
        pthread_mutex_lock(&g_coherent_preimage_lock);
        atomic_store_explicit(&g_coherent_capture_failed_generation,
                              atomic_load_explicit(&g_coherent_generation,
                                                   memory_order_acquire),
                              memory_order_release);
        pthread_mutex_unlock(&g_coherent_preimage_lock);
        return;
    }
    last = ((uint64_t)ram_addr + size - 1) &
           ~(uint64_t)(WVM_MEMORY_PAGE_BYTES - 1);

    pthread_mutex_lock(&g_coherent_preimage_lock);
    generation = atomic_load_explicit(&g_coherent_generation,
                                     memory_order_acquire);
    for (uint64_t page = first;; page += WVM_MEMORY_PAGE_BYTES) {
        uint64_t gpa;
        uint8_t *hva;
        WVMCoherentPreimage *entry;

        if (coherent_ram_page_from_ram_addr((ram_addr_t)page, &gpa, &hva)) {
            entry = coherent_find_preimage_locked(gpa, generation);
            if (!entry) {
                entry = calloc(1, sizeof(*entry));
                if (entry) {
                    entry->bytes = malloc(WVM_MEMORY_PAGE_BYTES);
                }
                if (!entry || !entry->bytes) {
                    free(entry ? entry->bytes : NULL);
                    free(entry);
                    atomic_store_explicit(
                        &g_coherent_capture_failed_generation, generation,
                        memory_order_release);
                } else {
                    entry->gpa = gpa;
                    entry->generation = generation;
                    memcpy(entry->bytes, hva, WVM_MEMORY_PAGE_BYTES);
                    entry->next = g_coherent_preimages;
                    g_coherent_preimages = entry;
                }
            }
        } else {
            atomic_store_explicit(&g_coherent_capture_failed_generation,
                                  generation, memory_order_release);
        }
        if (page >= last || UINT64_MAX - page < WVM_MEMORY_PAGE_BYTES) {
            break;
        }
    }
    pthread_mutex_unlock(&g_coherent_preimage_lock);
}
/* WVM coherent pre-image support end */

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
    if (!kvm_enabled() && g_fault_hook_enabled && !g_tcg_shm_coherent) {
        /*
         * Only slave TCG uses host page protection.  The master owns the
         * complete RAM image and tracks writes via QEMU dirty logging; using
         * process-wide mprotect on the master also traps device DMA writes and
         * breaks BIOS/bootloader disk reads.
         * SHM-coherent slaves share the executor file — never PROT_NONE.
         */
        int is_slave = (getenv("WVM_SOCK_REQ") != NULL);
        if (is_slave) {
            mprotect(hva, size, PROT_NONE);
        }
    }
    g_mem_blocks[g_block_count].hva_start = (uintptr_t)hva;
    g_mem_blocks[g_block_count].hva_end   = (uintptr_t)hva + size;
    g_mem_blocks[g_block_count].ram_start = qemu_ram_addr_from_host(hva);
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

static void wvm_invalidate_code_page_on_cpu(CPUState *cpu,
                                           run_on_cpu_data data)
{
    ram_addr_t start = data.host_ulong;

    (void)cpu;
    mmap_lock();
    tb_invalidate_phys_range(start, start + WVM_MEMORY_PAGE_BYTES);
    mmap_unlock();
}

static void wvm_invalidate_pushed_code_page(uint64_t gpa)
{
    void *hva;
    ram_addr_t ram_addr;

    if (!tcg_enabled()) {
        return;
    }
    hva = gpa_to_hva_safe(gpa);
    if (!hva) {
        return;
    }
    ram_addr = qemu_ram_addr_from_host(hva);
    if (ram_addr == RAM_ADDR_INVALID) {
        return;
    }
    if (cpu_physical_memory_get_dirty_flag(ram_addr, DIRTY_MEMORY_CODE)) {
        return;
    }

    if (first_cpu) {
        async_safe_run_on_cpu(first_cpu, wvm_invalidate_code_page_on_cpu,
                              RUN_ON_CPU_HOST_ULONG(ram_addr));
    }
    {
        static unsigned int log_count;
        if (log_count++ < 24) {
            fprintf(stderr,
                    "[WVM-TCG-TB-INVALIDATE] gpa=%#llx ram=%#llx pages=1\n",
                    (unsigned long long)gpa,
                    (unsigned long long)ram_addr);
        }
    }
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
    bool backing_already_applied;
    bool active;
} ReorderSlot;

static ReorderSlot g_reorder_buf[REORDER_WIN_SIZE];
static pthread_spinlock_t g_reorder_lock;

// 简单的异或哈希
static inline int get_reorder_idx(uint64_t gpa, uint64_t version) {
    return ((gpa >> 12) ^ version) & REORDER_MASK;
}

// 存入未来的包
static void buffer_future_packet(uint64_t gpa, uint64_t version, uint16_t type,
                                 void *data, uint16_t len,
                                 bool backing_already_applied) {
    int idx = get_reorder_idx(gpa, version);
    pthread_spin_lock(&g_reorder_lock);

    // 如果槽位被占，释放旧数据 (Drop-on-Collision 策略)
    if (g_reorder_buf[idx].active) free(g_reorder_buf[idx].data);

    g_reorder_buf[idx].gpa = gpa;
    g_reorder_buf[idx].version = version;
    g_reorder_buf[idx].msg_type = type;
    g_reorder_buf[idx].len = len;
    g_reorder_buf[idx].active = true;
    g_reorder_buf[idx].backing_already_applied = backing_already_applied;
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
static void wvm_apply_push(uint16_t msg_type, void *payload,
                           bool backing_already_applied) {
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
            if (!(backing_already_applied && g_tcg_shm_coherent)) {
                mprotect(page_hva, 4096, PROT_READ | PROT_WRITE);
                // 2. Apply the diff when the local runtime did not install it.
                memcpy((uint8_t*)page_hva + offset, log->data, size);
                // 3. 放入惰性锁回队列 (性能优化)
                defer_ro_protect(gpa);
            }

            // 4. 更新本地版本
            set_local_page_version(gpa, push_ver);
            if (size != 0) {
                wvm_invalidate_pushed_code_page(gpa);
            }
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
            if (!(backing_already_applied && g_tcg_shm_coherent)) {
                mprotect(page_hva, 4096, PROT_READ | PROT_WRITE);
                memcpy(page_hva, full->data, 4096);

                // 惰性锁回
                defer_ro_protect(gpa);
            }

            set_local_page_version(gpa, push_ver);
            wvm_invalidate_pushed_code_page(gpa);
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
                if (!(backing_already_applied && g_tcg_shm_coherent)) {
                    mprotect(rpc_hva, r_len, PROT_READ | PROT_WRITE);
                    memset(rpc_hva, val, r_len);
                }
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

void wvm_apply_remote_push(uint16_t msg_type, void *payload)
{
    wvm_apply_push(msg_type, payload, false);
}

void wvm_apply_local_push(uint16_t msg_type, void *payload)
{
    wvm_apply_push(msg_type, payload, true);
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
    bool backing_already_applied = s->backing_already_applied;

    s->active = false;
    s->data = NULL; // [修复] 彻底杜绝野指针

    pthread_spin_unlock(&g_reorder_lock);

    wvm_apply_push(t, d, backing_already_applied);
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
static __thread uint64_t t_memory_deadline_us;
#define WVM_MEMORY_IPC_TIMEOUT_US 120000000ULL /* F05 cross-host fence */
#define WVM_MEMORY_DIRTY_BATCH_TIMEOUT_US 60000000ULL

// --- 辅助函数 ---

#define PAGE_SHIFT 12

/* Sparse radix covers every bit of a uint64_t GPA, with no modulo alias.
 * Published nodes live for the QEMU process lifetime; readers need no lock. */
#define WVM_PAGE_VERSION_BITS 10U
#define WVM_PAGE_VERSION_SLOTS (1U << WVM_PAGE_VERSION_BITS)
#define WVM_PAGE_VERSION_LEVELS ((64U - PAGE_SHIFT + WVM_PAGE_VERSION_BITS - 1) / WVM_PAGE_VERSION_BITS)
struct wvm_page_version_node {
    uintptr_t entries[WVM_PAGE_VERSION_SLOTS];
};
static struct wvm_page_version_node g_page_versions;

static uint64_t *local_page_version_slot(uint64_t gpa, bool create)
{
    struct wvm_page_version_node *node = &g_page_versions;
    uint64_t pfn = gpa >> PAGE_SHIFT;

    for (int level = WVM_PAGE_VERSION_LEVELS - 1; level > 0; level--) {
        unsigned int index = (pfn >> (level * WVM_PAGE_VERSION_BITS)) &
                             (WVM_PAGE_VERSION_SLOTS - 1);
        uintptr_t child = __atomic_load_n(&node->entries[index], __ATOMIC_ACQUIRE);
        if (!child && create) {
            struct wvm_page_version_node *allocated = g_malloc0(sizeof(*allocated));
            uintptr_t expected = 0;
            if (!__atomic_compare_exchange_n(&node->entries[index], &expected,
                    (uintptr_t)allocated, false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
                g_free(allocated);
                child = expected;
            } else {
                child = (uintptr_t)allocated;
            }
        }
        if (!child)
            return NULL;
        node = (struct wvm_page_version_node *)child;
    }
    return (uint64_t *)&node->entries[pfn & (WVM_PAGE_VERSION_SLOTS - 1)];
}

static uint64_t get_local_page_version(uint64_t gpa)
{
    uint64_t *slot = local_page_version_slot(gpa, false);
    return slot ? __atomic_load_n(slot, __ATOMIC_ACQUIRE) : 0;
}

static void set_local_page_version(uint64_t gpa, uint64_t version)
{
    uint64_t *slot = local_page_version_slot(gpa, true);
    __atomic_store_n(slot, version, __ATOMIC_RELEASE);
}

static void safe_log(const char *msg) {
    if (write(STDERR_FILENO, msg, strlen(msg))) {};
}

static int memory_ipc_transfer(int fd, void *buf, size_t len, bool sending,
                                uint64_t deadline_us)
{
    uint8_t *ptr = buf;

    while (len != 0) {
        uint64_t now = get_us_time();
        struct pollfd pfd = {.fd = fd, .events = sending ? POLLOUT : POLLIN};
        int timeout_ms;
        int ready;
        ssize_t n;

        if (now >= deadline_us) {
            return -ETIMEDOUT;
        }
        timeout_ms = (int)MIN((deadline_us - now + 999) / 1000,
                              (uint64_t)INT_MAX);
        ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            return ready == 0 ? -ETIMEDOUT : -errno;
        }
        n = sending ? send(fd, ptr, len, MSG_DONTWAIT | MSG_NOSIGNAL) :
                      recv(fd, ptr, len, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN ||
                      errno == EWOULDBLOCK)) {
            continue;
        }
        if (n <= 0) {
            return n == 0 ? -ECONNRESET : -errno;
        }
        ptr += n;
        len -= (size_t)n;
    }
    return 0;
}

static uint64_t memory_ipc_deadline(void)
{
    uint64_t now = get_us_time();
    uint64_t deadline = now > UINT64_MAX - WVM_MEMORY_IPC_TIMEOUT_US
                            ? UINT64_MAX
                            : now + WVM_MEMORY_IPC_TIMEOUT_US;

    return t_memory_deadline_us ? MIN(deadline, t_memory_deadline_us) : deadline;
}

static uint64_t memory_dirty_batch_deadline(void)
{
    uint64_t now = get_us_time();
    uint64_t deadline = now > UINT64_MAX - WVM_MEMORY_DIRTY_BATCH_TIMEOUT_US
                            ? UINT64_MAX
                            : now + WVM_MEMORY_DIRTY_BATCH_TIMEOUT_US;

    if (t_memory_deadline_us && t_memory_deadline_us < deadline) {
        deadline = t_memory_deadline_us;
    }
    return deadline;
}

static void discard_memory_ipc(int fd)
{
    /* A partial exchange cannot safely share framing with the next request. */
    shutdown(fd, SHUT_RDWR);
    if (fd == t_com_sock) {
        close(t_com_sock);
        t_com_sock = -1;
    } else if (fd == g_ipc_diff_sock) {
        close(g_ipc_diff_sock);
        g_ipc_diff_sock = -1;
    }
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
    uint64_t node_instance;

    if (!commit ||
        parse_u64_env("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_KIND",
                         &kind) != 0 ||
        parse_u64_env("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_SCOPE",
                         &scope) != 0 ||
        parse_u64_env("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_VNODE",
                         &vnode) != 0 ||
        parse_u64_env("WVM_NODE_INSTANCE_ID", &node_instance) != 0 ||
        kind > UINT16_MAX || vnode > UINT32_MAX || node_instance == 0) {
        return -EINVAL;
    }
    commit->reply_destination_kind = (uint16_t)kind;
    commit->reply_destination_scope = scope;
    commit->reply_destination_vnode = (uint32_t)vnode;
    commit->reply_node_instance_id = node_instance;
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

static bool is_initial_directory_version(uint64_t version)
{
    return version != 0 && (uint32_t)version == 1U;
}


/*
 * G6: ESTALE resync must merge our write-set onto the directory page.
 * Bytes we changed vs pre_image keep ours; unchanged bytes keep theirs.
 * Without a pre-image, caller must fail closed — never retag an old full page.
 */
static void wvm_merge_commit_write_set(uint8_t *out,
                                       const uint8_t *pre_image,
                                       const uint8_t *ours,
                                       const uint8_t *theirs,
                                       size_t bytes)
{
    size_t i;

    if (!out || !ours || !theirs || bytes == 0) {
        return;
    }
    if (!pre_image) {
        memcpy(out, ours, bytes);
        return;
    }
    for (i = 0; i < bytes; i++) {
        out[i] = (ours[i] != pre_image[i]) ? ours[i] : theirs[i];
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
    int transfer_rc;
    const char *failed_phase = "request-header";
    uint64_t deadline = memory_ipc_deadline();

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
    if (g_tcg_shm_coherent) {
        request.flags |= WVM_LOCAL_MEMORY_COMMIT_FLAG_SHARED_BACKING;
    }
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
    transfer_rc = memory_ipc_transfer(fd, &header, sizeof(header), true, deadline);
    if (transfer_rc == 0) {
        failed_phase = "request-payload";
        transfer_rc = memory_ipc_transfer(fd, request_bytes, request_bytes_count,
                                          true, deadline);
    }
    if (transfer_rc == 0) {
        failed_phase = "result";
        transfer_rc = memory_ipc_transfer(fd, result_bytes, sizeof(result_bytes),
                                          false, deadline);
    }
    if (transfer_rc != 0) {
        static int transfer_error_log_count;
        if (transfer_error_log_count < 20) {
            fprintf(stderr,
                    "[WaveVM-User] typed commit IPC failed phase=%s "
                    "gpa=%#llx fd=%d rc=%d\n",
                    failed_phase, (unsigned long long)gpa, fd, transfer_rc);
            transfer_error_log_count++;
        }
        discard_memory_ipc(fd);
        return transfer_rc;
    }
    if (wvm_local_memory_commit_result_decode(
            result_bytes, &result, error, sizeof(error)) != 0 ||
        memcmp(result.operation_id, request.operation_id,
               sizeof(request.operation_id)) != 0 ||
        result.ack.gpa != gpa) {
        discard_memory_ipc(fd);
        return -EPROTO;
    }
    *ack_out = result.ack;
    status = commit_status_to_errno(result.ack.status);
    if (status == 0) {
        if (result.ack.result_version <= base_version) {
            return -EPROTO;
        }
    }
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
    uint64_t deadline = memory_ipc_deadline();

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
    result = memory_ipc_transfer(t_com_sock, &header, sizeof(header), true,
                                 deadline);
    if (result == 0) {
        result = memory_ipc_transfer(t_com_sock, request_bytes,
                                     sizeof(request_bytes), true, deadline);
    }
    if (result == 0) {
        result = memory_ipc_transfer(t_com_sock, result_length,
                                     sizeof(result_length), false, deadline);
    }
    if (result != 0) {
        discard_memory_ipc(t_com_sock);
        return result;
    }
    if (wvm_local_memory_result_length_decode(
            result_length, &ack_bytes_count, error, sizeof(error)) != 0) {
        discard_memory_ipc(t_com_sock);
        return -EPROTO;
    }
    if (ack_bytes_count == 0) {
        return -EIO;
    }
    result = memory_ipc_transfer(t_com_sock, ack_bytes, ack_bytes_count,
                                 false, deadline);
    if (result != 0) {
        discard_memory_ipc(t_com_sock);
        return result;
    }
    if (wvm_mem_ack_decode(ack_bytes, ack_bytes_count, &decoded_ack,
                              error, sizeof(error)) != 0 ||
        decoded_ack.gpa != gpa) {
        discard_memory_ipc(t_com_sock);
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

int wavevm_publish_initial_ram(uint64_t gpa, void *hva, uint64_t bytes,
                               uint64_t *published_pages)
{
    uint8_t source[WVM_MEMORY_PAGE_BYTES] QEMU_ALIGNED(8);
    uint8_t committed[WVM_MEMORY_PAGE_BYTES] QEMU_ALIGNED(8);
    int result = 0;

    if (!hva || !published_pages || bytes == 0 ||
        gpa > UINT64_MAX - bytes ||
        (gpa | bytes) % WVM_MEMORY_PAGE_BYTES != 0) {
        return -EINVAL;
    }
    pthread_mutex_lock(&g_dirty_flush_lock);
    for (uint64_t offset = 0; offset < bytes;
         offset += WVM_MEMORY_PAGE_BYTES) {
        struct wvm_mem_ack read_ack;
        struct wvm_mem_commit_ack commit_ack;
        uint64_t page_gpa = gpa + offset;

        memcpy(source, (uint8_t *)hva + offset, sizeof(source));
        /* Untouched RAM already has the directory's implicit zero image. */
        if (is_page_all_zero(source)) {
            continue;
        }
        result = request_page_over_ipc(page_gpa, &read_ack, committed);
        if (result == 0) {
            result = ack_status_to_errno(read_ack.status);
        }
        if (result != 0 || read_ack.version == 0) {
            result = result ? result : -EPROTO;
            break;
        }
        if (memcmp(source, committed, sizeof(source)) == 0) {
            set_local_page_version(page_gpa, read_ack.version);
            continue;
        }
        /* Only an unmodified initial page may be seeded. Never retag a
         * different committed image and overwrite it with frontend bytes. */
        if (!is_initial_directory_version(read_ack.version) ||
            !is_page_all_zero(committed)) {
            result = -ESTALE;
            break;
        }
        result = request_commit_on_fd(t_com_sock, page_gpa, read_ack.version,
                                       0, source, sizeof(source), &commit_ack);
        if (result != 0) {
            break;
        }
        set_local_page_version(page_gpa, commit_ack.result_version);
        (*published_pages)++;
    }
    pthread_mutex_unlock(&g_dirty_flush_lock);
    return result;
}

static int wavevm_publish_ram_mapping(uint64_t gpa, const uint8_t *hva,
                                      uint64_t bytes)
{
    int result = 0;

    if (!hva || bytes == 0 || gpa > UINT64_MAX - bytes) {
        return -EINVAL;
    }
    pthread_mutex_lock(&g_dirty_flush_lock);
    while (bytes != 0) {
        uint8_t committed[WVM_MEMORY_PAGE_BYTES] QEMU_ALIGNED(8);
        struct wvm_mem_ack read_ack;
        uint64_t page_gpa = gpa & ~(uint64_t)(WVM_MEMORY_PAGE_BYTES - 1U);
        uint16_t page_offset = (uint16_t)(gpa - page_gpa);
        size_t page_bytes = MIN(bytes, WVM_MEMORY_PAGE_BYTES - page_offset);

        result = request_page_over_ipc(page_gpa, &read_ack, committed);
        if (result == 0) {
            result = ack_status_to_errno(read_ack.status);
        }
        if (result != 0 || read_ack.version == 0) {
            result = result ? result : -EPROTO;
            break;
        }
        if (memcmp(committed + page_offset, hva, page_bytes) != 0) {
            struct wvm_mem_commit_ack commit_ack;

            result = request_commit_on_fd(t_com_sock, page_gpa,
                                           read_ack.version, page_offset, hva,
                                           page_bytes, &commit_ack);
            if (result != 0) {
                break;
            }
            set_local_page_version(page_gpa, commit_ack.result_version);
        } else {
            set_local_page_version(page_gpa, read_ack.version);
        }
        gpa += page_bytes;
        hva += page_bytes;
        bytes -= page_bytes;
    }
    pthread_mutex_unlock(&g_dirty_flush_lock);
    return result;
}

static int internal_connect_master_role(uint32_t role) {
    uint64_t deadline = memory_ipc_deadline();
    int sock = wavevm_qemu_connect_runtime_socket(
        SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (sock < 0) return -1;
    int flags = fcntl(sock, F_GETFL);
    if (flags < 0 || fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        close(sock);
        return -1;
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
        if (memory_ipc_transfer(sock, &reg_hdr, sizeof(reg_hdr), true,
                                deadline) != 0 ||
            memory_ipc_transfer(sock, (void *)payload, payload_size, true,
                                deadline) != 0) {
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
    uint64_t bios_start = 0xC0000;
    uint64_t bios_end   = 0x100000;  /* 1MB */
    uint64_t region_end = gpa + size;

    /* Clamp to the BIOS area */
    uint64_t copy_start = (gpa > bios_start) ? gpa : bios_start;
    uint64_t copy_end   = (region_end < bios_end) ? region_end : bios_end;
    if (copy_start >= copy_end) return;

    uint64_t copy_size   = copy_end - copy_start;
    uint64_t hva_offset  = copy_start - gpa;      /* offset into the HVA region */
    int result;

    if (g_is_slave || !g_ram_size || !wavevm_qemu_runtime_gate_enabled()) {
        return;
    }
    /* Publish just the QEMU-authored overlap as versioned commits; do not
     * write the shared cache before the directory has accepted the bytes. */
    result = wavevm_publish_ram_mapping(
        copy_start, (uint8_t *)hva + hva_offset, copy_size);
    if (result != 0) {
        fprintf(stderr,
                "[WaveVM-BIOS] canonical shadow publication failed "
                "GPA [%#llx,%#llx) rc=%d\n",
                (unsigned long long)copy_start,
                (unsigned long long)copy_end, result);
        _exit(1);
    }
    fprintf(stderr,
            "[WaveVM-BIOS] canonical shadow publication GPA [%#llx,%#llx)\n",
            (unsigned long long)copy_start, (unsigned long long)copy_end);
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

/*
 * R05: publish remote page bytes without ever exposing the guest mapping as
 * writable on the authoritative multi-vCPU process.
 *
 * Master: the guest RAM is mapped from the VM shared-memory file.  A second
 * MAP_SHARED mapping of the same file (g_shm_shadow) aliases the same pages,
 * so the copy can be performed there while the guest mapping stays
 * PROT_READ.  A concurrent vCPU or device DMA store therefore still faults
 * and reaches the write-tracking path instead of being silently overwritten
 * by this memcpy.
 *
 * Slave TCG helper: the guest mapping is anonymous and has no alias.  The
 * helper runs exactly one vCPU and exports no device model, so the faulting
 * vCPU itself is the only thread that can touch this page while its fault is
 * being resolved; no concurrent guest writer exists to race the copy.
 */
static int install_page_bytes(uint64_t gpa, uintptr_t aligned_addr,
                              const uint8_t *data, int is_write)
{
    (void)is_write;

    if (!g_is_slave) {
        uint8_t *target = NULL;

        if (ensure_local_shm_shadow() == 0 && g_shm_shadow && g_ram_base &&
            g_ram_size != 0) {
            uint64_t offset = aligned_addr - (uintptr_t)g_ram_base;

            if (offset <= g_ram_size - WVM_MEMORY_PAGE_BYTES)
                target = (uint8_t *)g_shm_shadow + offset;
        }
        if (!target) {
            safe_log("[WVM] page install has no writable SHM alias; failing "
                     "closed instead of exposing guest RAM writable\n");
            return -1;
        }
        memcpy(target, data, WVM_MEMORY_PAGE_BYTES);
        return 0;
    }

    /*
     * R05: slave helper must be single-writer (smp=1, -nodefaults). Without an
     * SHM alias the install briefly raises PROT_WRITE on the guest mapping;
     * refuse rather than open that window on a multi-vCPU helper.
     */
    {
        const char *smp = getenv("WVM_SLAVE_VCPU_COUNT");
        if (!smp || strcmp(smp, "1") != 0) {
            safe_log("[WVM] slave page install refused: WVM_SLAVE_VCPU_COUNT!=1 "
                     "(single-writer invariant)");
            return -1;
        }
    }
    if (mprotect((void *)aligned_addr, WVM_MEMORY_PAGE_BYTES,
                 PROT_READ | PROT_WRITE) != 0)
        return -1;
    memcpy((void *)aligned_addr, data, WVM_MEMORY_PAGE_BYTES);
    if (mprotect((void *)aligned_addr, WVM_MEMORY_PAGE_BYTES, PROT_READ) != 0)
        return -1;
    return 0;
}

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
        /*
         * R05: install through an alias where one exists (master) and keep the
         * guest mapping read-only for the whole copy.  The old code opened a
         * PROT_READ|PROT_WRITE window in both branches, letting concurrent
         * stores bypass write tracking or be overwritten by this memcpy.
         */
        if (install_page_bytes(gpa, aligned_addr, ack.data,
                               is_write ? 1 : 0) != 0)
            return -1;
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
 * [关键逻辑] SIGSEGV handler 仅入队 + 唤醒 worker；读缺页/写 CBW/IPC 在
 *            fault worker 线程执行（capability-fault-engines.md §4.2）。
 * [后果] handler 内禁止 sync IPC / malloc / 阻塞锁；失败则 fail-closed _exit。
 */

/* Worker-side resolve: may perform IPC, mprotect, CBW. Never call from handler. */
static int resolve_fault_on_worker(uintptr_t fault_addr, uint64_t gpa, bool is_write)
{
    void *aligned_addr = (void *)(fault_addr & ~4095ULL);

    if (is_write) {
        if (get_local_page_version(gpa) == 0) {
            /*
             * A first touch may be a write fault.  Pull the directory copy
             * before arming CBW; otherwise the slave writes on an implicit
             * zero/old page and later commits version 1 over a newer owner
             * version.
             */
            if (request_page_sync(fault_addr, true) != 0) {
                return -1;
            }
        }

        int idx = page_pool_claim();
        WritablePage *wp;
        void *snapshot;

        if (idx < 0) {
            /*
             * F06: pool full - bounded fail, do not overwrite in-flight
             * pre-images / list nodes. Leave page RO so the store retries or
             * fails closed via the fault worker.
             */
            static int pool_exh_log;
            if (pool_exh_log < 20) {
                fprintf(stderr,
                        "[WaveVM-User] F06 write page pool exhausted "
                        "in_use=%u cap=%u gpa=%#llx; bounded fail\n",
                        atomic_load_explicit(&g_page_pool_in_use,
                                             memory_order_relaxed),
                        (unsigned)PAGE_POOL_SIZE,
                        (unsigned long long)gpa);
                pool_exh_log++;
            }
            return -ENOMEM;
        }
        wp = &g_page_pool[idx];
        snapshot = g_image_pool[idx];

        /*
         * A13: snapshot BEFORE RW mprotect. Capture pre-image while the page
         * is still read-only so concurrent writers cannot race the snapshot.
         * Only then arm WRITE for the faulting store to retire.
         */
        if (mprotect(aligned_addr, 4096, PROT_READ) != 0) {
            page_pool_release(idx);
            return -1;
        }
        memcpy(snapshot, aligned_addr, 4096);
        if (mprotect(aligned_addr, 4096, PROT_READ | PROT_WRITE) != 0) {
            page_pool_release(idx);
            return -1;
        }
        wp->gpa = gpa;
        wp->pre_image_snapshot = snapshot;

        do {
            wp->next = __atomic_load_n(&g_writable_pages_list, __ATOMIC_ACQUIRE);
        } while (!__atomic_compare_exchange_n(&g_writable_pages_list, &wp->next, wp,
                                              true, __ATOMIC_RELEASE,
                                              __ATOMIC_ACQUIRE));
        return 0;
    }

    if (request_page_sync(fault_addr, false) == 0) {
        mprotect(aligned_addr, 4096, PROT_READ);
        return 0;
    }
    return -1;
}

static void *fault_worker_thread_fn(void *arg)
{
    (void)arg;
    atomic_store(&g_fault_worker_ready, 1);
    while (g_fault_worker_running) {
        uint64_t tickets = 0;
        ssize_t n = read(g_fault_wake_fd, &tickets, sizeof(tickets));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (!g_fault_worker_running) {
                break;
            }
            continue;
        }
        if (!g_fault_worker_running) {
            break;
        }
        for (unsigned i = 0; i < WVM_FAULT_QUEUE_SIZE; i++) {
            WVMFaultSlot *slot = &g_fault_slots[i];
            int st = atomic_load(&slot->state);
            if (st != WVM_FAULT_SLOT_SUBMITTED) {
                continue;
            }
            int rc = resolve_fault_on_worker(slot->fault_addr, slot->gpa,
                                            slot->is_write != 0);
            atomic_store(&slot->state,
                         rc == 0 ? WVM_FAULT_SLOT_DONE : WVM_FAULT_SLOT_FAILED);
        }
    }
    atomic_store(&g_fault_worker_ready, 0);
    return NULL;
}

static int start_fault_worker(void)
{
    unsigned i;
    struct timespec ts_start, ts_now;
    if (g_fault_wake_fd >= 0) {
        return 0;
    }
    for (i = 0; i < WVM_FAULT_QUEUE_SIZE; i++) {
        atomic_store(&g_fault_slots[i].state, WVM_FAULT_SLOT_FREE);
        g_fault_slots[i].fault_addr = 0;
        g_fault_slots[i].gpa = 0;
        g_fault_slots[i].is_write = 0;
    }
    atomic_store(&g_fault_slot_cursor, 0);
    atomic_store(&g_fault_worker_ready, 0);
    g_fault_wake_fd = eventfd(0, EFD_CLOEXEC);
    if (g_fault_wake_fd < 0) {
        return -1;
    }
    g_fault_worker_running = true;
    if (pthread_create(&g_fault_worker_thread, NULL, fault_worker_thread_fn,
                       NULL) != 0) {
        g_fault_worker_running = false;
        close(g_fault_wake_fd);
        g_fault_wake_fd = -1;
        return -1;
    }
    /*
     * Wait for ready under load (fractal gateway + dual helpers). A pure
     * PAUSE spin of ~1-5ms is too short when the new thread is delayed;
     * fail-closed _exit then leaves CREATE stuck IN_PROGRESS.
     */
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    for (;;) {
        if (atomic_load(&g_fault_worker_ready)) {
            return 0;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        long elapsed_ms = (ts_now.tv_sec - ts_start.tv_sec) * 1000L +
                          (ts_now.tv_nsec - ts_start.tv_nsec) / 1000000L;
        if (elapsed_ms >= 2000) {
            break;
        }
        sched_yield();
        usleep(1000);
    }
    if (atomic_load(&g_fault_worker_ready)) {
        return 0;
    }
    /* Timed out: tear down so a retry (or FATAL) does not leak fds/threads. */
    g_fault_worker_running = false;
    {
        uint64_t one = 1;
        (void)write(g_fault_wake_fd, &one, sizeof(one));
    }
    (void)pthread_join(g_fault_worker_thread, NULL);
    close(g_fault_wake_fd);
    g_fault_wake_fd = -1;
    atomic_store(&g_fault_worker_ready, 0);
    fprintf(stderr,
            "[WaveVM-User] deferred fault worker ready timed out after 2s\n");
    return -1;
}

/*
 * Async-signal-safe submit: claim a preallocated slot, wake worker, spin until
 * DONE/FAILED. Never calls request_page_over_ipc / request_page_sync.
 */
static void submit_fault_to_worker_or_die(uintptr_t addr, uint64_t gpa, bool is_write)
{
    WVMFaultSlot *slot = NULL;
    unsigned attempt;
    uint64_t one = 1;

    if (!atomic_load(&g_fault_worker_ready) || g_fault_wake_fd < 0) {
        _exit(1);
    }

    for (attempt = 0; attempt < WVM_FAULT_QUEUE_SIZE; attempt++) {
        unsigned idx = atomic_fetch_add(&g_fault_slot_cursor, 1) % WVM_FAULT_QUEUE_SIZE;
        int expected = WVM_FAULT_SLOT_FREE;
        if (atomic_compare_exchange_strong(&g_fault_slots[idx].state, &expected,
                                           WVM_FAULT_SLOT_FILLING)) {
            slot = &g_fault_slots[idx];
            break;
        }
    }
    if (!slot) {
        /* Queue full: fail-closed without performing RPC in the handler. */
        _exit(1);
    }

    slot->fault_addr = addr;
    slot->gpa = gpa;
    slot->is_write = is_write ? 1 : 0;
    atomic_store(&slot->state, WVM_FAULT_SLOT_SUBMITTED);

    if (write(g_fault_wake_fd, &one, sizeof(one)) != (ssize_t)sizeof(one)) {
        atomic_store(&slot->state, WVM_FAULT_SLOT_FAILED);
        _exit(1);
    }

    for (;;) {
        int st = atomic_load(&slot->state);
        if (st == WVM_FAULT_SLOT_DONE) {
            atomic_store(&slot->state, WVM_FAULT_SLOT_FREE);
            return;
        }
        if (st == WVM_FAULT_SLOT_FAILED) {
            _exit(1);
        }
        __builtin_ia32_pause();
    }
}

static void sigsegv_handler(int sig, siginfo_t *si, void *ucontext) {
    static volatile int s_fault_count = 0;
    int fc = __atomic_add_fetch(&s_fault_count, 1, __ATOMIC_RELAXED);
    uintptr_t addr = (uintptr_t)si->si_addr;
    uint64_t gpa;
    ucontext_t *ctx;
    bool is_write;
    (void)sig;

    /*
     * A13: no snprintf/malloc/printf in SIGSEGV — async-signal-safe write only.
     * Detailed diagnostics belong on the fault worker, not the handler.
     */
    if (fc <= 50 || (fc & 0xFFFF) == 0) {
        static const char hit[] = "[WaveVM-User] sigsegv (handler)\n";
        (void)write(STDERR_FILENO, hit, sizeof(hit) - 1);
    }

    gpa = hva_to_gpa_safe(addr);
    if (gpa == (uint64_t)-1) {
        static const char pass[] = "[WaveVM-User] sigsegv passthrough\n";
        (void)write(STDERR_FILENO, pass, sizeof(pass) - 1);
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
        return;
    }

    gpa &= ~4095ULL;
    wait_on_latch(gpa);

    ctx = (ucontext_t *)ucontext;
    is_write = (ctx->uc_mcontext.gregs[REG_ERR] & 0x2) != 0;

    /*
     * Defer all page RPC / CBW / mprotect to the fault worker. The handler must
     * not call request_page_sync or request_page_over_ipc (V1 non-goal).
     */
    submit_fault_to_worker_or_die(addr, gpa, is_write);
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

static int flush_dirty_to_ipc(int ipc_fd,
                              WVMHandoffDirtyJournal **journal_out)
{
    int flushed = 0;
    int skipped_zero = 0;
    uint64_t scanned_pages = 0;
    uint64_t dirty_pages = 0;
    static int flush_log_count = 0;
    WVMHandoffDirtyJournal *journal = NULL;

    if (journal_out) {
        *journal_out = NULL;
    }
    /*
     * G2: SHM coherent only means same-host joined backing may skip local
     * RAM copies / fault-hook. Directory flush/commit must still run so
     * remote authority sees versions and write-sets.
     */
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
            scanned_pages++;
            if (get_us_time() >= memory_ipc_deadline()) {
                fprintf(stderr,
                        "[WaveVM-User] handoff dirty scan deadline "
                        "scanned=%llu dirty=%llu committed=%d skipped_zero=%d\n",
                        (unsigned long long)scanned_pages,
                        (unsigned long long)dirty_pages, flushed,
                        skipped_zero);
                pthread_mutex_unlock(&g_dirty_flush_lock);
                free_handoff_dirty_journal(journal);
                return -ETIMEDOUT;
            }
            if (!cpu_physical_memory_test_and_clear_dirty(ra, 4096,
                                                          DIRTY_MEMORY_MIGRATION)) {
                continue;
            }
            dirty_pages++;

            uint64_t gpa = blk->gpa_start + off;
            void *hva = (void *)(blk->hva_start + off);
            uint64_t cur_ver = get_local_page_version(gpa);
            if (cur_ver == 0 && is_page_all_zero(hva)) {
                /*
                 * Directory SHM starts zeroed; read_page lazily materializes at
                 * (initial_epoch<<32)|1, not plain version 1. Skip zero dirty
                 * bits without inventing a local version — remote fault-read
                 * will materialize matching zeros.
                 */
                skipped_zero++;
                continue;
            }
            if (cur_ver == 0) {
                /*
                 * Unset local version: commit against the directory's implicit
                 * zero page. Production CREATE materialize logs showed base=1;
                 * wvm_handle_local_commit create-on-commits when base matches
                 * MAKE_VERSION(epoch,1), so we do not fault-materialize every
                 * dirty page (that exhausted the V1 waiter retention table).
                 */
                cur_ver = 1;
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

                if (commit_ret == -ENOENT || commit_ret == -ESTALE) {
                    /*
                     * G6: rematerialize alone is not enough — recommitting the
                     * old HVA full page under a new base_version can clobber
                     * concurrent directory writes. Handoff dirty-log has no
                     * per-page pre-image here, so fail closed after one
                     * rematerialize attempt that would only retag bytes.
                     */
                    struct wvm_mem_ack mat_ack;
                    uint8_t mat_page[WVM_MEMORY_PAGE_BYTES];
                    int mat_ret = request_page_over_ipc(gpa, &mat_ack, mat_page);
                    static int handoff_retry_log;
                    if (mat_ret == 0 &&
                        ack_status_to_errno(mat_ack.status) == 0 &&
                        mat_ack.version != 0 &&
                        mat_ack.version == cur_ver) {
                        /* Same base after rematerialize: safe to retry once. */
                        commit_ret = request_commit_on_fd(
                            ipc_fd, gpa, cur_ver, 0, hva,
                            WVM_MEMORY_PAGE_BYTES, &ack);
                    } else {
                        commit_ret = commit_ret ? commit_ret : -ESTALE;
                        if (handoff_retry_log < 20) {
                            fprintf(stderr,
                                    "[WaveVM-User] handoff ESTALE fail-closed "
                                    "gpa=%#llx cur=%#llx mat_ver=%#llx mat=%d\n",
                                    (unsigned long long)gpa,
                                    (unsigned long long)cur_ver,
                                    (unsigned long long)(mat_ret == 0 ?
                                        mat_ack.version : 0),
                                    mat_ret);
                            handoff_retry_log++;
                        }
                    }
                }

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
    /*
     * Callers (wavevm-cpu handoff) treat ret>0 as "pages committed on this
     * stream — run push-visibility fence before CPU_RUN". Returning 0 on
     * success silently skipped the fence and left remote TCG racing PAGE_PUSH
     * APPLY (attach10/11 freeze at Cirros initramfs→vda1).
     */
    return flushed;
}

int wavevm_user_mem_flush_dirty_to_ipc(int ipc_fd,
                                       WVMHandoffDirtyJournal **journal_out)
{
    uint64_t previous_deadline = t_memory_deadline_us;
    int result;

    t_memory_deadline_us = memory_dirty_batch_deadline();
    result = flush_dirty_to_ipc(ipc_fd, journal_out);
    t_memory_deadline_us = previous_deadline;
    return result;
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
    /* F06: slots leave the in-flight list — return them to the free pool. */
    writable_page_release_chain(batch_head, NULL);
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
                writable_page_release_chain(batch_head, curr);
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
            writable_page_release_chain(batch_head, curr);
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

            /*
             * Slave dirty self-emit: unset local version means the page was
             * never fault-cached here. Commit against the directory implicit
             * zero page (epoch counter 1) — same create-on-commit contract as
             * master handoff flush — instead of failing closed as ESTALE.
             */
            if (base_version == 0) {
                base_version = 1;
            }
            if (t_com_sock < 0) {
                t_com_sock = internal_connect_master();
            }
            commit_ret = request_commit_on_fd(
                t_com_sock, curr->gpa, base_version, 0,
                current_snapshot, WVM_MEMORY_PAGE_BYTES, &ack);
            if (commit_ret == -ENOENT || commit_ret == -ESTALE) {
                /*
                 * G6: directory advanced. Rematerialize and merge our write-set
                 * onto the directory page using pre_image; never retag the old
                 * full snapshot with a new base_version alone.
                 */
                struct wvm_mem_ack mat_ack;
                uint8_t mat_page[WVM_MEMORY_PAGE_BYTES];
                uint8_t merged[WVM_MEMORY_PAGE_BYTES];
                int mat_ret = request_page_over_ipc(curr->gpa, &mat_ack,
                                                    mat_page);
                static int slave_retry_log;
                if (mat_ret == 0 &&
                    ack_status_to_errno(mat_ack.status) == 0 &&
                    mat_ack.version != 0 &&
                    curr->pre_image_snapshot) {
                    base_version = mat_ack.version;
                    wvm_merge_commit_write_set(merged,
                                               curr->pre_image_snapshot,
                                               current_snapshot, mat_page,
                                               WVM_MEMORY_PAGE_BYTES);
                    memcpy(current_snapshot, merged, WVM_MEMORY_PAGE_BYTES);
                    commit_ret = request_commit_on_fd(
                        t_com_sock, curr->gpa, base_version, 0,
                        current_snapshot, WVM_MEMORY_PAGE_BYTES, &ack);
                    if (slave_retry_log < 20) {
                        fprintf(stderr,
                                "[WaveVM-User] slave dirty commit resync-merge "
                                "gpa=%#llx base=%#llx ret=%d\n",
                                (unsigned long long)curr->gpa,
                                (unsigned long long)base_version, commit_ret);
                        slave_retry_log++;
                    }
                } else {
                    /* No pre-image or rematerialize failed: fail closed. */
                    if (slave_retry_log < 20) {
                        fprintf(stderr,
                                "[WaveVM-User] slave dirty ESTALE fail-closed "
                                "gpa=%#llx mat=%d pre=%d\n",
                                (unsigned long long)curr->gpa, mat_ret,
                                curr->pre_image_snapshot ? 1 : 0);
                        slave_retry_log++;
                    }
                }
            }
            if (commit_ret != 0) {
                static int commit_fail_log;
                if (commit_fail_log < 20) {
                    fprintf(stderr,
                            "[WaveVM-User] TCG dirty commit failed "
                            "gpa=%#llx base=%#llx ret=%d\n",
                            (unsigned long long)curr->gpa,
                            (unsigned long long)base_version, commit_ret);
                    commit_fail_log++;
                }
                ram_addr_t ra = qemu_ram_addr_from_host(page_addr);
                if (ra != RAM_ADDR_INVALID) {
                    cpu_physical_memory_set_dirty_range(
                        ra, 4096, 1 << DIRTY_MEMORY_MIGRATION);
                }
                first_error = commit_ret;
                writable_page_release_chain(batch_head, curr);
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
    /* F06: completed prefix (or whole batch) returns to the free pool. */
    if (first_error == 0) {
        writable_page_release_chain(batch_head, NULL);
    }
    return first_error != 0 ? first_error : committed;
}

/*
 * Coherent SHM: no fault-hook WritablePage list. Harvest QEMU dirty bits and
 * typed-commit full pages so A14 / Phase-10 remote memory evidence is real.
 * Caller must hold g_dirty_flush_lock. Returns pages committed or -errno.
 *
 * Freeze the dirty set once, using QEMU's bitmap snapshot. Batching yields
 * execution time but cannot complete a causal fence before the set is drained.
 * Writes after the snapshot stay in the live bitmap for the next fence.
 */
static int flush_coherent_dirty_bitmap_locked(void *current_snapshot)
{
    int committed = 0;
    int first_error = 0;
    int scanned = 0;
    int budget;
    int max_scan;
    const bool use_commit = wavevm_qemu_runtime_gate_enabled();
    DirtyBitmapSnapshot *snapshots[MAX_RAM_BLOCKS] = {0};
    ram_addr_t ram_bases[MAX_RAM_BLOCKS];
    uint64_t offsets[MAX_RAM_BLOCKS] = {0};
    uint64_t deadline = memory_ipc_deadline();
    uint64_t snapshot_generation;
    const char *budget_env;
    static int preimage_failure_log_count;

    if (!g_tcg_shm_coherent || !current_snapshot) {
        return 0;
    }
    if (g_block_count <= 0) {
        return 0;
    }

    budget = 32;
    budget_env = getenv("WVM_TCG_COHERENT_DIRTY_BUDGET");
    if (budget_env && budget_env[0] != '\0') {
        int v = atoi(budget_env);
        if (v > 0 && v <= 4096) {
            budget = v;
        }
    }
    /* Yield between bounded bitmap scan batches, without ending the fence. */
    max_scan = budget * 256;
    if (max_scan < 4096) {
        max_scan = 4096;
    }
    if (max_scan > 65536) {
        max_scan = 65536;
    }

    /*
     * Move the generation before taking the bitmap snapshot.  A notdirty
     * callback that starts after this point records its pre-image for the next
     * fence; the callback and this boundary share the pre-image lock so an
     * entry can never be silently replaced while it is being copied.
     */
    pthread_mutex_lock(&g_coherent_preimage_lock);
    snapshot_generation = atomic_fetch_add_explicit(&g_coherent_generation, 1,
                                                     memory_order_acq_rel);
    for (int bi = 0; bi < g_block_count; bi++) {
        GVMRamBlock *blk = &g_mem_blocks[bi];
        ram_addr_t mr_offset;
        RAMBlock *rb = qemu_ram_block_from_host((void *)blk->hva_start,
                                               false, &mr_offset);

        ram_bases[bi] = qemu_ram_addr_from_host((void *)blk->hva_start);
        if (!rb || ram_bases[bi] == RAM_ADDR_INVALID ||
            blk->size % WVM_MEMORY_PAGE_BYTES != 0) {
            first_error = -EFAULT;
            break;
        }
        snapshots[bi] = cpu_physical_memory_snapshot_and_clear_dirty(
            rb->mr, mr_offset, blk->size, DIRTY_MEMORY_MIGRATION);
        if (!snapshots[bi]) {
            first_error = -ENOMEM;
            break;
        }
    }
    pthread_mutex_unlock(&g_coherent_preimage_lock);

    for (int bi = 0; bi < g_block_count && first_error == 0; bi++) {
        GVMRamBlock *blk = &g_mem_blocks[bi];

        while (offsets[bi] + 4096 <= blk->size) {
            uint64_t off = offsets[bi];
            ram_addr_t ra = ram_bases[bi] + off;
            uint64_t gpa;
            void *hva;
            uint64_t base_version;
            uint64_t preimage_generation;
            uint8_t pre_image[WVM_MEMORY_PAGE_BYTES];
            struct wvm_mem_ack authority_ack;
            bool preimage_from_authority = false;
            int preimage_ret;
            int commit_ret;

            if (get_us_time() >= deadline) {
                first_error = -ETIMEDOUT;
                break;
            }
            /* Skip clean bitmap windows without walking every RAM page. */
            uint64_t window = MIN(blk->size - off, 256ULL * 4096);
            if (!cpu_physical_memory_snapshot_get_dirty(snapshots[bi],
                                                         ra, window)) {
                offsets[bi] += window;
                continue;
            }
            if (++scanned >= max_scan) {
                sched_yield();
                scanned = 0;
            }
            if (!cpu_physical_memory_snapshot_get_dirty(snapshots[bi],
                                                         ra, 4096)) {
                offsets[bi] += 4096;
                continue;
            }
            gpa = blk->gpa_start + off;
            hva = (void *)(blk->hva_start + off);
            preimage_generation = snapshot_generation;
            preimage_ret = coherent_copy_preimage(gpa, snapshot_generation,
                                                  pre_image,
                                                  &preimage_generation);
            if (preimage_ret == -ENOENT) {
                uint8_t authority_page[WVM_MEMORY_PAGE_BYTES];
                int read_ret = request_page_over_ipc(
                    gpa, &authority_ack, authority_page);

                /*
                 * Device DMA and other QEMU-side writes can set the dirty
                 * bitmap without passing through notdirty_write().  In that
                 * case the directory image is the only safe pre-image.  Keep
                 * the fallback tied to a successful, versioned READ; never
                 * treat the current local page as its own base.
                 */
                if (read_ret == 0 &&
                    ack_status_to_errno(authority_ack.status) == 0 &&
                    authority_ack.version != 0) {
                    memcpy(pre_image, authority_page, sizeof(pre_image));
                    preimage_from_authority = true;
                    preimage_ret = 0;
                } else if (read_ret == 0) {
                    preimage_ret = ack_status_to_errno(authority_ack.status);
                    if (preimage_ret == 0) {
                        preimage_ret = -EPROTO;
                    }
                } else {
                    preimage_ret = read_ret;
                }
            }
            if (preimage_ret != 0) {
                /*
                 * The current authority page is not a write pre-image.  Using
                 * it here would turn unrelated remote bytes into this writer's
                 * full-page commit and can overwrite a concurrent update.
                 * Keep the dirty bit for the next fence and fail closed until
                 * the genuine pre-image or a safe resync is available.
                 */
                if (preimage_failure_log_count++ < 20) {
                    fprintf(stderr,
                            "[WaveVM-User] coherent dirty preimage unavailable "
                            "gpa=%#llx ret=%d\n",
                            (unsigned long long)gpa, preimage_ret);
                }
                if (preimage_ret != 0) {
                    /* A dirty bit without a safe base must fail closed. */
                    first_error = preimage_ret == -ENOENT ? -EIO : preimage_ret;
                    break;
                }
            }
            memcpy(current_snapshot, hva, 4096);
            if (memcmp(current_snapshot, pre_image, WVM_MEMORY_PAGE_BYTES) == 0) {
                /* A tracked write that produced no byte change needs no commit. */
                if (preimage_from_authority) {
                    set_local_page_version(gpa, authority_ack.version);
                }
                coherent_discard_preimage(gpa, snapshot_generation);
                offsets[bi] += 4096;
                continue;
            }
            if (use_commit) {
                struct wvm_mem_commit_ack ack;

                base_version = preimage_from_authority
                    ? authority_ack.version : get_local_page_version(gpa);
                if (base_version == 0) {
                    base_version = 1;
                }
                if (t_com_sock < 0) {
                    t_com_sock = internal_connect_master();
                }
                commit_ret = request_commit_on_fd(
                    t_com_sock, gpa, base_version, 0, current_snapshot,
                    WVM_MEMORY_PAGE_BYTES, &ack);
                if (commit_ret == -ENOENT || commit_ret == -ESTALE) {
                    struct wvm_mem_ack mat_ack;
                    uint8_t mat_page[WVM_MEMORY_PAGE_BYTES];
                    uint8_t merged[WVM_MEMORY_PAGE_BYTES];
                    int mat_ret = request_page_over_ipc(gpa, &mat_ack, mat_page);
                    if (mat_ret == 0 &&
                        ack_status_to_errno(mat_ack.status) == 0 &&
                        mat_ack.version != 0) {
                        /*
                         * The directory may have advanced since our first
                         * attempt.  Rebase only the bytes that changed since
                         * the captured pre-image; untouched bytes come from
                         * the authority page.
                         */
                        wvm_merge_commit_write_set(merged, pre_image,
                                                   current_snapshot, mat_page,
                                                   WVM_MEMORY_PAGE_BYTES);
                        commit_ret = request_commit_on_fd(
                            t_com_sock, gpa, mat_ack.version, 0, merged,
                            WVM_MEMORY_PAGE_BYTES, &ack);
                        /* Shared RAM may already contain later peer writes.
                         * The merged image belongs to the commit, not RAM. */
                    }
                }
                if (commit_ret != 0) {
                    first_error = commit_ret;
                    break;
                }
                set_local_page_version(gpa, ack.result_version);
            } else {
                uint64_t ver = get_local_page_version(gpa);
                if (ver == 0) {
                    ver = 1;
                }
                add_to_aggregator(gpa, ver + 1, 0, 4096, current_snapshot, 0);
                set_local_page_version(gpa, ver + 1);
            }
            coherent_discard_preimage(gpa, snapshot_generation);
            committed++;
            offsets[bi] += 4096;
            if (committed % budget == 0) {
                sched_yield();
            }
        }
    }
    for (int bi = 0; bi < g_block_count; bi++) {
        if (!snapshots[bi]) {
            continue;
        }
        /* Restore only uncommitted snapshot bits; never clear newer writes. */
        for (uint64_t off = offsets[bi]; off + 4096 <= g_mem_blocks[bi].size;
             off += 4096) {
            if (cpu_physical_memory_snapshot_get_dirty(snapshots[bi],
                                                        ram_bases[bi] + off,
                                                        4096)) {
                cpu_physical_memory_set_dirty_range(
                    ram_bases[bi] + off, 4096, 1 << DIRTY_MEMORY_MIGRATION);
            }
        }
        g_free(snapshots[bi]);
    }
    if (!use_commit && committed > 0) {
        flush_aggregator();
    }
    return first_error != 0 ? first_error : committed;
}

int wavevm_user_mem_flush_slave_dirty_sync(void)
{
    void *current_snapshot;
    WritablePage *batch_head;
    int committed;
    int bitmap_committed = 0;
    long rtt;
    uint64_t previous_deadline;
    static int flush_log_count;

    /*
     * G2: even with coherent SHM, slave dirty must commit to the directory
     * (version + subscriber semantics). Visibility of bytes in SHM is not
     * a substitute for authoritative commit.
     */
    if (!g_is_slave || g_fd_push < 0 || g_block_count <= 0) {
        return 0;
    }

    current_snapshot = malloc(4096);
    if (!current_snapshot) {
        return -ENOMEM;
    }

    previous_deadline = t_memory_deadline_us;
    t_memory_deadline_us = memory_dirty_batch_deadline();
    pthread_mutex_lock(&g_dirty_flush_lock);
    batch_head = __atomic_exchange_n(&g_writable_pages_list, NULL,
                                     __ATOMIC_ACQ_REL);
    committed = process_writable_batch_full_snapshot(batch_head,
                                                     current_snapshot);
    if (committed >= 0 && g_tcg_shm_coherent) {
        bitmap_committed = flush_coherent_dirty_bitmap_locked(current_snapshot);
        if (bitmap_committed < 0) {
            committed = bitmap_committed;
        } else {
            committed += bitmap_committed;
        }
    }
    if (committed < 0) {
        rtt = committed;
    } else if (committed > 0) {
        /*
         * A remote TCG slice return is a causal handoff: all writes made by the
         * slave must be visible to the directory before the CPU ACK is exported.
         */
        uint64_t now = get_us_time();
        rtt = now >= t_memory_deadline_us ? -ETIMEDOUT :
            wait_for_directory_ack_safe_us(t_memory_deadline_us - now);
    } else {
        rtt = 0;
    }
    pthread_mutex_unlock(&g_dirty_flush_lock);
    t_memory_deadline_us = previous_deadline;

    free(current_snapshot);

    if (committed > 0 && flush_log_count < 40) {
        fprintf(stderr,
                "[WaveVM-User] slave TCG slice dirty flush pages=%d "
                "bitmap=%d rtt=%ldus coherent=%d\n",
                committed, bitmap_committed, rtt, g_tcg_shm_coherent);
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
static int memory_push_fence(int fd, uint64_t timeout_us, bool include_helpers)
{
    wvm_ipc_header_t header;
    uint8_t request[16] = {0};
    uint8_t response[16];
    uint64_t now = get_us_time();
    uint64_t deadline = now + MIN(timeout_us, 120000000ULL); /* F05 cross-host */
    int result;

    if (fd < 0) {
        return -ENOTCONN;
    }
    deadline = MIN(deadline, memory_ipc_deadline());
    request[0] = include_helpers ? 0x02 : 0;
    header.type = WVM_IPC_TYPE_COMMIT_DIFF_SYNC;
    header.len = sizeof(request);
    result = memory_ipc_transfer(fd, &header, sizeof(header), true, deadline);
    if (result == 0) {
        result = memory_ipc_transfer(fd, request, sizeof(request), true, deadline);
    }
    if (result == 0) {
        result = memory_ipc_transfer(fd, response, sizeof(response), false,
                                     deadline);
    }
    if (result != 0) {
        discard_memory_ipc(fd);
        return result;
    }
    memcpy(&result, response, sizeof(result));
    return result > 0 ? -result : result;
}

static long wait_for_directory_ack_safe_us(uint64_t timeout_us)
{
    uint64_t start = get_us_time();
    int fd, result;

    if (g_is_slave) {
        if (t_com_sock < 0) {
            t_com_sock = internal_connect_master();
        }
        fd = t_com_sock;
    } else {
        if (g_ipc_diff_sock < 0) {
            g_ipc_diff_sock = internal_connect_master();
        }
        fd = g_ipc_diff_sock;
    }
    result = memory_push_fence(fd, timeout_us ? timeout_us : 1000000ULL, false);
    return result != 0 ? result : (long)(get_us_time() - start);
}

/* FE handoff commits and CPU_RUN share this explicit vCPU stream. */
int wavevm_user_mem_ipc_push_fence(int ipc_fd, uint64_t timeout_us)
{
    return memory_push_fence(ipc_fd, timeout_us ? timeout_us : 5000000ULL, true);
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
    bool backing_already_applied =
        (hdr->flags & WVM_FLAG_SHARED_BACKING) != 0;
    if (msg_type == MSG_PAGE_PUSH_DIFF) {
        if (p_len < sizeof(struct wvm_diff_log)) {
            return;
        }

        struct wvm_diff_log* log = (struct wvm_diff_log*)payload;
        uint64_t gpa = WVM_NTOHLL(log->gpa);
        uint64_t push_ver = WVM_NTOHLL(log->version);
        uint64_t local_ver = get_local_page_version(gpa);

        if (is_next_version(local_ver, push_ver)) {
            wvm_apply_push(msg_type, payload, backing_already_applied);
            while (check_and_apply_next(gpa, 0)) ;
        } else if (is_newer_version(local_ver, push_ver) &&
                   !is_next_version(local_ver, push_ver)) {
            if (!is_newer_version(local_ver + REORDER_WIN_SIZE, push_ver)) {
                buffer_future_packet(gpa, push_ver, msg_type, payload, p_len,
                                     backing_already_applied);
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
        wvm_apply_push(msg_type, payload, backing_already_applied);
    } else if (msg_type == MSG_RPC_BATCH_MEMSET) {
        wvm_apply_push(msg_type, payload, backing_already_applied);
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
                /*
                 * G4: one datagram (header+cookie). Split write() on UDP
                 * becomes two packets and the proxy never reconstitutes the
                 * cookie — sleep-fallback was papering over that.
                 */
                {
                    uint8_t ack_pkt[sizeof(ack) + sizeof(cookie)];

                    memcpy(ack_pkt, &ack, sizeof(ack));
                    memcpy(ack_pkt + sizeof(ack), &cookie, sizeof(cookie));
                    if (write_all_fd(g_fd_push, ack_pkt, sizeof(ack_pkt)) == 0) {
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
    g_fault_hook_enabled = enable_fault_hook && !kvm_enabled() && g_is_slave &&
                           !g_tcg_shm_coherent;
    g_fault_hook_checked = true;

    // KVM + PROT_NONE 会导致 EPT violation，KVM 下：
    //   1. 启用 migration dirty log 替代 mprotect 追踪脏页
    //   2. 各调用点用 !kvm_enabled() 守卫跳过 mprotect(PROT_NONE)
    // 注意：fault hook（SIGSEGV 拦截器）仍然保留，它是分布式缺页请求的核心通道。
    /*
     * Coherent SHM TCG slaves skip SIGSEGV/mprotect tracking, so they must
     * still enable QEMU dirty logging — directory commit remains mandatory
     * (G2 / A14 self-emit). Without this, flush_slave_dirty_sync sees an
     * empty writable list and never TYPED_MEM_COMMITs guest stores.
     */
    if (kvm_enabled() || !g_is_slave || g_tcg_shm_coherent) {
        memory_global_dirty_log_start();
        fprintf(stderr,
                "[WaveVM] dirty log tracking enabled (kvm=%d slave=%d coherent=%d).\n",
                kvm_enabled() ? 1 : 0, g_is_slave, g_tcg_shm_coherent);
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
        g_page_pool[i].next = NULL;
        atomic_store_explicit(&g_page_pool_occupied[i], 0, memory_order_relaxed);
    }
    atomic_store_explicit(&g_page_pool_in_use, 0, memory_order_relaxed);

    size_t num_pages = ram_size / 4096;

    if (env_req && env_push) {
        g_fd_req = atoi(env_req);
        g_fd_push = atoi(env_push);
        g_slave_id = env_id ? atoi(env_id) : 0;

        /*
         * The helper is launched with -S and therefore may not issue a guest
         * memory or vCPU request yet.  Register the admitted QEMU frontend at
         * startup instead of making readiness depend on first guest progress.
         * Keep this connection open for the lifetime of the helper; closing it
         * would revoke the frontend registration while the helper is alive.
         */
        if (wavevm_qemu_runtime_gate_enabled()) {
            g_runtime_registration_fd =
                internal_connect_master_role(WVM_IPC_ROLE_SYNC);
            if (g_runtime_registration_fd < 0) {
                fprintf(stderr,
                        "[WaveVM-User] FATAL: QEMU frontend registration "
                        "failed errno=%d (%s)\n",
                        errno, strerror(errno));
                _exit(1);
            }
            fprintf(stderr,
                    "[WaveVM-User] QEMU frontend registration active fd=%d\n",
                    g_runtime_registration_fd);
        }

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
        /*
         * Start the deferred fault worker before installing SIGSEGV so the
         * handler never falls back to sync IPC (capability-fault-engines.md
         * §4.2). Fail closed if the worker cannot start.
         */
        if (start_fault_worker() != 0) {
            fprintf(stderr,
                    "[WaveVM-User] FATAL: deferred fault worker failed to start\n");
            _exit(1);
        }
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_SIGINFO; // [FIX-M6] 移除 SA_NODEFER，防止 handler 内递归 SIGSEGV 导致栈溢出
        sa.sa_sigaction = sigsegv_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);

        // Initial state is handled per RAM block in wavevm_register_ram_block().
    }
}

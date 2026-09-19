/*
 * [IDENTITY] Master Core - The Distributed Brain
 * ---------------------------------------------------------------------------
 * 物理角色：每个计算节点内的"一致性指挥部"。
 * 职责边界：
 * 1. 维护本地 Pod 视图内的 DHT 寻址，判定 GPA 权属。
 * 2. 运行 Pub/Sub 引擎，管理每个页面的订阅者位图。
 * 3. 判定写冲突：利用乐观锁校验版本号，发起 FORCE_SYNC 修正。
 * 
 * [禁止事项]
 * - 严禁在此处直接操作 Socket 或进行文件 IO。
 * - 严禁修改 HASH_RING_SIZE (4096)，Pod 扩展请修改分层网关配置。
 * - 严禁移除 Latch 或 Lock 机制，否则在高并发写下 Directory 内存将损坏。
 * ---------------------------------------------------------------------------
 */
#include "logic_core.h"
#include "../common_include/wavevm_protocol.h"
#include "../common_include/wavevm_config.h"

#ifdef __KERNEL__
    #include <linux/spinlock.h>
    #include <linux/delay.h>
    #include <linux/string.h>
    #include <linux/printk.h>

    #ifndef UINT32_MAX
    #define UINT32_MAX ((uint32_t)~0U)
    #endif
    #ifndef UINT64_MAX
    #define UINT64_MAX ((uint64_t)~0ULL)
    #endif
    
    typedef spinlock_t pthread_mutex_t;
    #define pthread_mutex_init(l, a) spin_lock_init(l)
    #define pthread_mutex_lock(l)    spin_lock_bh(l)
    #define pthread_mutex_unlock(l)  spin_unlock_bh(l)

    #define pthread_spinlock_t       spinlock_t
    #define pthread_spin_init(l, a)  spin_lock_init(l)
    #define pthread_spin_lock(l)     spin_lock(l)
    #define pthread_spin_unlock(l)   spin_unlock(l)

    #define pthread_rwlock_t         spinlock_t
    #define pthread_rwlock_init(l, a) spin_lock_init(l)
    #define pthread_rwlock_rdlock(l) spin_lock_bh(l)
    #define pthread_rwlock_wrlock(l) spin_lock_bh(l)
    #define pthread_rwlock_unlock(l) spin_unlock_bh(l)
    #define usleep(us)               usleep_range((us), (us) + 100)
    // --------------------

#else
    #include <pthread.h>
    #include <errno.h>
    #include <string.h>
    #include <sys/mman.h>
    #include <stdio.h>
    extern void *g_shm_ptr;
    extern size_t g_shm_size;
#endif

#ifdef __KERNEL__
    #define WVM_LOG_ERR(fmt, ...) printk(KERN_WARNING fmt, ##__VA_ARGS__)
#else
    #define WVM_LOG_ERR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#endif

#ifdef __GNUC__
#define WVM_UNUSED __attribute__((unused))
#else
#define WVM_UNUSED
#endif

#ifdef __KERNEL__
    #include <linux/slab.h>
    #define wvm_malloc(sz) kmalloc(sz, GFP_ATOMIC) 
    #define wvm_free(ptr) kfree(ptr)
#else
    #include <stdlib.h>
    #define wvm_malloc(sz) malloc(sz)
    #define wvm_free(ptr) free(ptr)
#endif

#ifdef __KERNEL__
    #define wvm_alloc_local(sz) kmalloc(sz, GFP_ATOMIC)
    #define wvm_free_local(ptr) kfree(ptr)
#else
    #define wvm_alloc_local(sz) malloc(sz)
    #define wvm_free_local(ptr) free(ptr)
#endif

#ifdef __KERNEL__
    #include <linux/slab.h>
    #define malloc(sz) kmalloc(sz, GFP_ATOMIC)
    #define free(ptr) kfree(ptr)
#endif

#ifdef __KERNEL__
    #include <linux/types.h>
    typedef int atomic_bool;
    typedef int atomic_int;
    typedef long atomic_long;
    #ifndef ATOMIC_VAR_INIT
    #define ATOMIC_VAR_INIT(v) (v)
    #endif
    #define atomic_fetch_add(ptr, v) __sync_fetch_and_add((ptr), (v))
    #define atomic_load(ptr) __atomic_load_n((ptr), __ATOMIC_SEQ_CST)
    #define atomic_store(ptr, v) __atomic_store_n((ptr), (v), __ATOMIC_SEQ_CST)
    #define atomic_exchange(ptr, v) __atomic_exchange_n((ptr), (v), __ATOMIC_SEQ_CST)
#else
    #include <stdatomic.h>
    #include <stdbool.h>
    #include <unistd.h>
#ifndef ATOMIC_VAR_INIT
#define ATOMIC_VAR_INIT(v) (v)
#endif
#endif

// --- 全局状态 ---
struct dsm_driver_ops *g_ops = NULL;
int g_total_nodes = 1;
int g_my_node_id = 0;
int g_ctrl_port = 0; // 这里的定义同时供应给 wavevm_node_master 和 wavevm.ko
uint32_t g_curr_epoch = 0;
#ifndef __KERNEL__
extern int broadcast_push_to_qemu(uint16_t msg_type, void *payload, int len);
extern int broadcast_push_to_qemu_fenced(uint16_t msg_type, void *payload,
                                          int len, uint64_t timeout_us);
extern int wait_local_qemu_push_barrier(uint64_t timeout_us);
#endif

static inline int notify_local_qemu_push(uint16_t msg_type, void *payload, int len)
{
#ifndef __KERNEL__
    return broadcast_push_to_qemu(msg_type, payload, len);
#else
    (void)msg_type;
    (void)payload;
    (void)len;
    return 0;
#endif
}

static inline int notify_local_qemu_push_fenced(uint16_t msg_type, void *payload,
                                                int len, uint64_t timeout_us)
{
#ifndef __KERNEL__
    return broadcast_push_to_qemu_fenced(msg_type, payload, len, timeout_us);
#else
    (void)msg_type;
    (void)payload;
    (void)len;
    (void)timeout_us;
    return 0;
#endif
}

static inline int wait_local_qemu_push_barrier_safe(uint64_t timeout_us)
{
#ifndef __KERNEL__
    return wait_local_qemu_push_barrier(timeout_us);
#else
    (void)timeout_us;
    return 0;
#endif
}

// 哈希环脏标记 (解决 CPU 抖动)
static atomic_bool g_ring_dirty = false;

static struct {
    uint8_t buf[MTU_SIZE + 128]; 
    int curr_offset;
    uint32_t last_gateway_id; 
    pthread_mutex_t lock;
} g_gossip_agg = { .curr_offset = 0 };

#define MAX_LOCAL_VIEW 1024  // 本地感知的邻居上限
#define GOSSIP_INTERVAL_US 60000000 // 60s 心跳一次 (测试压制心跳洪泛)
#define VIEW_SYNC_INTERVAL_US 2000000 // 2秒同步一次全量视图
static uint64_t g_last_view_sync_us WVM_UNUSED = 0;

static void add_gossip_to_aggregator(uint32_t target_node_id, uint8_t state, uint32_t epoch);
static void flush_gossip_aggregator(void);
void handle_rpc_batch_execution(void *payload, uint32_t len);
static void init_broadcast_shards(void);

// --- 指数退避与超时参数 ---
#define INITIAL_RETRY_DELAY_US 50000      // 50ms
#define MAX_RETRY_DELAY_US     500000     // 500ms
#define TOTAL_TIMEOUT_US      20000000    // 20s
/*
 * VCPU_RUN is not a short request/response operation. It represents remote
 * execution until the next CPU exit, so a fixed small RPC timeout can falsely
 * fail a healthy but long-running TCG/KVM run. Keep a long guardrail to avoid
 * permanent hangs, and limit UDP retransmits to the initial delivery window.
 */
#define VCPU_RUN_TIMEOUT_US        (30ULL * 60ULL * 1000000ULL)
#define VCPU_RUN_RETRY_WINDOW_US   5000000ULL
#define VCPU_RUN_MAX_RETRIES       12

// --- 目录表定义 ---
#ifdef __KERNEL__
#define DIR_TABLE_INIT_SIZE (1024 * 4)   // Kernel: fixed, no dynamic growth
#define DIR_TABLE_SIZE      DIR_TABLE_INIT_SIZE
#else
#define DIR_TABLE_INIT_SIZE (1024 * 1024) // User-mode: page-scale table, grows on demand
#endif
#define DIR_MAX_PROBE 128
#define LOCK_SHARDS 65536
#define SMALL_UPDATE_THRESHOLD 1024

#define WVM_CPU_ROUTE_TABLE_SIZE MAX_VCPUS 

// --- 分片广播队列定义 ---
#define NUM_BCAST_WORKERS   8      // 定义8个并行的广播工作线程
#define BCAST_Q_SIZE        16384  // 每个分片队列的大小
#define BCAST_Q_MASK        (BCAST_Q_SIZE - 1)

#define RETRY_TIMEOUT_US 1000 
#define MIN_HOLD_TIME_US 500

// 订阅者位图
typedef struct {
#ifdef __KERNEL__
    unsigned long bits[(WVM_MAX_SLAVES + 63) / 64];
#else
    uint32_t *ids;
    uint32_t count;
    uint32_t cap;
#endif
} copyset_t;

// [辅助宏] 用于操作 64 位复合版本号
#define MAKE_VERSION(epoch, counter) (((uint64_t)(epoch) << 32) | (counter))
#define GET_EPOCH(version) ((uint32_t)((version) >> 32))
#define GET_COUNTER(version) ((uint32_t)((version) & 0xFFFFFFFF))

// 页面元数据
typedef struct {
    uint64_t gpa;
    uint8_t  is_valid; // bool in C
    uint64_t version; // [FIX] 高32位: Epoch, 低32位: Counter
#ifdef __KERNEL__
    uint64_t segment_mask[256]; 
#endif
    copyset_t subscribers;
    uint64_t last_interest_time;
#ifdef __KERNEL__
    uint8_t  base_page_data[4096];
#else
    uint8_t *base_page_data;
#endif
    pthread_mutex_t lock;
} page_meta_t;

/*
 * F12 fix: Global directory table deprecated in favor of per-VM context.
 * These globals remain for backward compatibility during transition but
 * should be accessed through wvm_active_context()->dir_table in new code.
 * TODO Phase 5-7: Remove globals entirely and make all accesses context-aware.
 */
static page_meta_t *g_dir_table = NULL;
static pthread_mutex_t g_dir_table_locks[LOCK_SHARDS];

#ifndef __KERNEL__
static uint8_t *resolve_page_data(page_meta_t *page, uint64_t gpa) {
    if (page->base_page_data) {
        return page->base_page_data;
    }

    if (g_shm_ptr && g_shm_size >= 4096 && gpa <= g_shm_size - 4096) {
        page->base_page_data = (uint8_t*)g_shm_ptr + gpa;
        return page->base_page_data;
    }

    page->base_page_data = wvm_alloc_local(4096);
    if (page->base_page_data) {
        memset(page->base_page_data, 0, 4096);
    }
    return page->base_page_data;
}
#endif

#ifndef __KERNEL__
static uint32_t g_dir_capacity = DIR_TABLE_INIT_SIZE;
static size_t   g_dir_alloc_size = 0; /* mmap size for munmap on grow */
static pthread_mutex_t g_grow_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

// --- 辅助函数 ---
/* 
 * [物理意图] 将 64 位 GPA 空间均匀"粉碎"并映射到 32 位哈希空间。
 * [关键逻辑] 采用非线性散列算法，确保 Guest OS 连续分配的内存页在 DHT 环上能够物理离散分布。
 * [后果] 若此函数失效，内存元数据将产生严重的负载倾斜（Skew），导致个别节点成为全网瓶颈。
 */
static inline uint32_t murmur3_32(uint64_t k) {
    k ^= k >> 33; k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33; return (uint32_t)k;
}

/* 
 * [物理意图] 确定 GPA 对应的分段锁索引，实现万级并发下的"零争用"访问。
 * [关键逻辑] 对页号进行哈希取模，将 500PB 内存映射到 LOCK_SHARDS (65536) 个独立的互斥域中。
 * [后果] 这一步实现了管理平面的并行化，若分段数不足，高频写操作会导致 CPU 产生不必要的 L3 缓存行竞争。
 */
static inline uint32_t get_lock_idx(uint64_t gpa) {
    return murmur3_32(gpa >> WVM_PAGE_SHIFT) % LOCK_SHARDS;
}

/* 
 * [物理意图] 在页面的订阅者名单（Copy-set）中标记一个远程节点的"利害关系"。
 * [关键逻辑] 操作 64 位对齐的位图，记录哪些节点持有该页面的只读缓存，以便在发生写入时发起精准推送。
 * [后果] 这是 Wavelet 协议的核心，它取代了 V28 的盲目广播，将网络流量精确控制在"有需求的节点"之间。
 */
static void copyset_set(copyset_t *cs, uint32_t node_id) {
    if (node_id >= WVM_MAX_SLAVES) return;
#ifdef __KERNEL__
    cs->bits[node_id / 64] |= (1UL << (node_id % 64));
#else
    for (uint32_t i = 0; i < cs->count; i++) {
        if (cs->ids[i] == node_id) return;
    }

    if (cs->count == cs->cap) {
        uint32_t new_cap = cs->cap ? cs->cap * 2 : 4;
        uint32_t *new_ids = realloc(cs->ids, sizeof(*new_ids) * new_cap);
        if (!new_ids) return;
        cs->ids = new_ids;
        cs->cap = new_cap;
    }
    cs->ids[cs->count++] = node_id;
#endif
}

static void register_page_subscriber(page_meta_t *page, uint32_t node_id) {
    if (!page || node_id >= WVM_MAX_SLAVES) return;

    copyset_set(&page->subscribers, node_id);
    page->last_interest_time = g_ops->get_time_us();
#ifdef __KERNEL__
    uint32_t seg_idx = node_id / 64;
    page->segment_mask[seg_idx / 64] |= (1UL << (seg_idx % 64));
#endif
}

/*
 * Placement and route identity are one VM-scoped derived cache.  The
 * accelerator may still expose only one active context per module instance,
 * but the semantic state is no longer a collection of unqualified globals.
 * A later multi-context kernel implementation can register additional
 * instances without changing the lookup contract below.
 */
struct wvm_logic_route_context {
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint32_t cpu_route_table[WVM_CPU_ROUTE_TABLE_SIZE];
    uint32_t memory_route_table[WVM_MEMORY_ROUTE_TABLE_SIZE];
    uint8_t memory_route_valid[WVM_MEMORY_ROUTE_TABLE_SIZE];
    struct {
        uint64_t gpa_start;
        uint64_t bytes;
        uint32_t node_id;
    } memory_range_routes[WVM_MEMORY_ROUTE_TABLE_SIZE];
    size_t memory_range_route_count;
    int memory_range_routes_active;
    struct wvm_route_snapshot_key route_snapshot_key;
    int route_snapshot_bound;
};

/*
 * F12 fix: Global route context deprecated in favor of per-VM context.
 * This global remains for backward compatibility during transition but
 * should be accessed through wvm_active_context()->route_context in new code.
 * TODO Phase 5-7: Remove global entirely and make all accesses context-aware.
 */
static struct wvm_logic_route_context g_logic_route_context;

static struct wvm_logic_route_context *logic_route_context(void)
{
    /* F12 fix: In single-context bootstrap mode, use global.
     * Full per-VM routing requires Phase 5-7 refactor where each
     * context maintains its own route snapshot and directory authority. */
    return &g_logic_route_context;
}

int wvm_logic_bind_route_snapshot(
    const struct wvm_route_snapshot_key *snapshot_key)
{
    struct wvm_logic_route_context *context = logic_route_context();
    char error[128] = {0};
    int key_valid;

    /*
     * The kernel module deliberately does not link the user-space canonical
     * manifest library.  Keep its admission check structural here; user
     * space performs the full canonical validation before calling this API.
     */
#ifdef __KERNEL__
    key_valid = snapshot_key && snapshot_key->scope_key.vm_id != 0 &&
                snapshot_key->scope_key.vm_incarnation != 0 &&
                snapshot_key->scope_key.route_scope_id != 0 &&
                snapshot_key->topology_revision != 0 &&
                snapshot_key->route_generation != 0;
#else
    key_valid = snapshot_key &&
                wvm_route_snapshot_key_validate(snapshot_key, error,
                                                sizeof(error)) == 0;
#endif
    if (!key_valid ||
        (WVM_CURRENT_VM_ID() != 0 &&
         snapshot_key->scope_key.vm_id != WVM_CURRENT_VM_ID())) {
        WVM_LOG_ERR("[Route] rejected route snapshot binding: %s\n",
                    error[0] ? error : "VM namespace mismatch");
        return -1;
    }
    context->vm_id = snapshot_key->scope_key.vm_id;
    context->vm_incarnation = snapshot_key->scope_key.vm_incarnation;
    context->route_snapshot_key = *snapshot_key;
    context->route_snapshot_bound = 1;
    return 0;
}

int wvm_logic_route_snapshot_valid(void)
{
    return logic_route_context()->route_snapshot_bound;
}

int wvm_logic_get_route_snapshot_key(
    struct wvm_route_snapshot_key *snapshot_key)
{
    struct wvm_logic_route_context *context = logic_route_context();

    if (!snapshot_key || !context->route_snapshot_bound) {
        return -1;
    }
    *snapshot_key = context->route_snapshot_key;
    return 0;
}

void wvm_logic_unbind_route_snapshot(void)
{
    struct wvm_logic_route_context *context = logic_route_context();

    memset(&context->route_snapshot_key, 0,
           sizeof(context->route_snapshot_key));
    context->vm_id = 0;
    context->vm_incarnation = 0;
    context->route_snapshot_bound = 0;
}

/* 
 * [物理意图] 建立 vCPU 索引与物理计算节点 ID 之间的静态/动态映射表。
 * [关键逻辑] 用于指导 Master 节点的调度器：当特定的 vCPU 触发陷入时，应该将执行上下文路由给哪个 Slave。
 * [后果] 若此表配置错误，vCPU 将被路由到不存在的节点，导致超级虚拟机的指令流瞬间断裂。
 */
void wvm_set_cpu_mapping(int vcpu_index, uint32_t slave_id) {
    struct wvm_logic_route_context *context = logic_route_context();

    // 这里的边界检查现在是安全的，与全局配置一致
    if (vcpu_index >= 0 && vcpu_index < WVM_CPU_ROUTE_TABLE_SIZE) {
        context->cpu_route_table[vcpu_index] = slave_id;
    }
}

void wvm_clear_cpu_mappings(void) {
    struct wvm_logic_route_context *context = logic_route_context();

    for (int i = 0; i < WVM_CPU_ROUTE_TABLE_SIZE; i++) {
        context->cpu_route_table[i] = WVM_NODE_AUTO_ROUTE;
    }
}

uint32_t wvm_get_cpu_mapping_raw(int vcpu_index) {
    struct wvm_logic_route_context *context = logic_route_context();

    if (vcpu_index >= 0 && vcpu_index < WVM_CPU_ROUTE_TABLE_SIZE) {
        return context->cpu_route_table[vcpu_index];
    }
    return WVM_NODE_AUTO_ROUTE;
}

uint32_t wvm_get_compute_slave_id(int vcpu_index) {
    struct wvm_logic_route_context *context = logic_route_context();

    if (WVM_CURRENT_VM_ID() != 0 && !context->route_snapshot_bound) {
        return WVM_NODE_AUTO_ROUTE;
    }
    if (vcpu_index >= 0 && vcpu_index < WVM_CPU_ROUTE_TABLE_SIZE) {
        uint32_t raw = context->cpu_route_table[vcpu_index];
        // [Fix #3] AUTO_ROUTE 是 sentinel，不能做 ENCODE_ID 操作
        if (raw == WVM_NODE_AUTO_ROUTE) return raw;
        // [Multi-VM] 返回 composite ID
        return WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), raw);
    }
    return WVM_NODE_AUTO_ROUTE;
}

const uint32_t* wvm_get_cpu_route_table(void) {
    return logic_route_context()->cpu_route_table;
}

void wvm_set_memory_mapping(int chunk_index, uint32_t node_id) {
    struct wvm_logic_route_context *context = logic_route_context();

    if (chunk_index >= 0 && chunk_index < WVM_MEMORY_ROUTE_TABLE_SIZE) {
        context->memory_route_table[chunk_index] = node_id;
        context->memory_route_valid[chunk_index] = 1;
    }
}

int wvm_set_memory_range_mapping(uint64_t gpa_start, uint64_t bytes,
                                 uint32_t node_id)
{
    struct wvm_logic_route_context *context = logic_route_context();
    size_t count = context->memory_range_route_count;

    if (bytes == 0 || gpa_start > UINT64_MAX - bytes ||
        node_id == WVM_NODE_AUTO_ROUTE ||
        count >= WVM_MEMORY_ROUTE_TABLE_SIZE) {
        return -1;
    }
    if (count != 0) {
        uint64_t previous_end =
            context->memory_range_routes[count - 1].gpa_start +
            context->memory_range_routes[count - 1].bytes;

        if (previous_end > gpa_start) {
            return -1;
        }
    }
    context->memory_range_routes[count].gpa_start = gpa_start;
    context->memory_range_routes[count].bytes = bytes;
    context->memory_range_routes[count].node_id = node_id;
    context->memory_range_route_count = count + 1;
    context->memory_range_routes_active = 1;
    return 0;
}

void wvm_clear_memory_mappings(void) {
    struct wvm_logic_route_context *context = logic_route_context();

    memset(context->memory_route_valid, 0,
           sizeof(context->memory_route_valid));
    for (int i = 0; i < WVM_MEMORY_ROUTE_TABLE_SIZE; i++) {
        context->memory_route_table[i] = WVM_NODE_AUTO_ROUTE;
    }
    memset(context->memory_range_routes, 0,
           sizeof(context->memory_range_routes));
    context->memory_range_route_count = 0;
    context->memory_range_routes_active = 0;
}

const uint32_t* wvm_get_memory_route_table(void) {
    return logic_route_context()->memory_route_table;
}

/* 
 * [物理意图] 获取特定 GPA 在全网中的最新逻辑时钟（版本号）。
 * [关键逻辑] 直接查询本地 Directory 表，用于在 PUSH 响应中携带真理戳。
 * [后果] 如果获取到的版本号落后，会导致接收端触发版本断层校验失败，进而发起 FORCE_SYNC 全页拉取。
 */
uint64_t wvm_logic_get_page_version(uint64_t gpa) {
    uint32_t lock_idx = get_lock_idx(gpa);
    uint64_t ver = 0;
    pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
    
    // 我们只需要读取版本，不需要创建 meta，如果不存在说明是初始版本 0
    uint64_t page_idx = gpa >> WVM_PAGE_SHIFT;
    uint32_t hash = murmur3_32(page_idx);
#ifdef __KERNEL__
    uint32_t _vcap = DIR_TABLE_SIZE;
#else
    uint32_t _vcap = g_dir_capacity;
#endif
    for (int i = 0; i < DIR_MAX_PROBE; i++) {
        uint32_t cur = (hash + i) % _vcap;
        if (g_dir_table[cur].is_valid && g_dir_table[cur].gpa == gpa) {
            ver = g_dir_table[cur].version;
            break;
        }
        if (!g_dir_table[cur].is_valid) break;
    }
    pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
    return ver;
}

/*
 * [物理意图] 在 Directory 管理表中定位或初始化页面的"户口信息"。
 * [关键逻辑] 使用带线性探测的哈希表，存储页面的版本、订阅位图以及主备份数据。
 * [后果] 这是逻辑核心最重负载的查找点，调用者需持锁。
 */
static page_meta_t* find_or_create_page_meta(uint64_t gpa) {
    uint64_t page_idx = gpa >> WVM_PAGE_SHIFT;
    uint32_t hash = murmur3_32(page_idx);
#ifdef __KERNEL__
    uint32_t cap = DIR_TABLE_SIZE;
#else
    uint32_t cap = g_dir_capacity;
#endif

    for (int i = 0; i < DIR_MAX_PROBE; i++) {
        uint32_t cur = (hash + i) % cap;

        // 找到存在的
        if (g_dir_table[cur].is_valid && g_dir_table[cur].gpa == gpa) {
#ifndef __KERNEL__
            if (!resolve_page_data(&g_dir_table[cur], gpa)) {
                return NULL;
            }
#endif
            return &g_dir_table[cur];
        }

        // 找到空位，新建
        if (!g_dir_table[cur].is_valid) {
            // 清零整个结构体，包括数据页
            memset(&g_dir_table[cur], 0, sizeof(page_meta_t));

            g_dir_table[cur].is_valid = 1;
            g_dir_table[cur].gpa = gpa;
            g_dir_table[cur].version = MAKE_VERSION(g_curr_epoch, 1);
#ifndef __KERNEL__
            if (!resolve_page_data(&g_dir_table[cur], gpa)) {
                memset(&g_dir_table[cur], 0, sizeof(page_meta_t));
                return NULL;
            }
#endif

            // 锁必须初始化，即使是在持锁状态下分配
            pthread_mutex_init(&g_dir_table[cur].lock, NULL);

            return &g_dir_table[cur];
        }
    }

    // 探测链耗尽，需要扩容（user-mode）或报错（kernel）
    if (g_ops && g_ops->log) {
        g_ops->log("[WARN] Directory hash table probe exhausted for GPA %llx (cap=%u)!",
                   (unsigned long long)gpa, cap);
    }
    return NULL;
}

/*
 * Lookup-only companion for commit paths. A dirty commit must never
 * materialize a page as a side effect of an invalid or stale submission.
 * Callers must hold the corresponding directory shard lock.
 */
static page_meta_t *find_page_meta_locked(uint64_t gpa)
{
    uint64_t page_idx = gpa >> WVM_PAGE_SHIFT;
    uint32_t hash = murmur3_32(page_idx);
#ifdef __KERNEL__
    uint32_t cap = DIR_TABLE_SIZE;
#else
    uint32_t cap = g_dir_capacity;
#endif

    for (int i = 0; i < DIR_MAX_PROBE; i++) {
        uint32_t cur = (hash + i) % cap;

        if (!g_dir_table[cur].is_valid) {
            return NULL;
        }
        if (g_dir_table[cur].gpa == gpa) {
            return &g_dir_table[cur];
        }
    }
    return NULL;
}

static void broadcast_to_subscriber_ids(const uint32_t *subscriber_ids,
                                        uint32_t subscriber_count,
                                        uint32_t writer_node_id,
                                        uint16_t msg_type, const void *payload,
                                        int len, uint8_t flags);

#ifndef __KERNEL__
/*
 * 动态扩容目录哈希表。获取所有分片锁后 rehash 到 2 倍容量。
 * 调用前：调用者已释放自己持有的分片锁。
 */
static void dir_table_grow(void) {
    pthread_mutex_lock(&g_grow_lock);

    uint32_t old_cap = g_dir_capacity;
    uint32_t new_cap = old_cap * 2;

    /* 另一个线程可能已经完成扩容 */
    if (g_dir_capacity != old_cap) {
        pthread_mutex_unlock(&g_grow_lock);
        return;
    }

    /* 获取全部分片锁，阻止任何并发查找 */
    for (int i = 0; i < LOCK_SHARDS; i++)
        pthread_mutex_lock(&g_dir_table_locks[i]);

    /* 分配新表 */
    page_meta_t *new_table = (page_meta_t *)g_ops->alloc_large_table(
        sizeof(page_meta_t) * new_cap);
    if (!new_table) {
        if (g_ops && g_ops->log)
            g_ops->log("[CRITICAL] dir_table_grow: alloc failed for %u entries!", new_cap);
        for (int i = LOCK_SHARDS - 1; i >= 0; i--)
            pthread_mutex_unlock(&g_dir_table_locks[i]);
        pthread_mutex_unlock(&g_grow_lock);
        return;
    }
    memset(new_table, 0, sizeof(page_meta_t) * new_cap);

    /* Rehash 所有有效条目 */
    uint32_t migrated = 0;
    for (uint32_t j = 0; j < old_cap; j++) {
        if (!g_dir_table[j].is_valid) continue;

        uint64_t page_idx = g_dir_table[j].gpa >> WVM_PAGE_SHIFT;
        uint32_t hash = murmur3_32(page_idx);
        int placed = 0;

        for (int i = 0; i < DIR_MAX_PROBE * 4; i++) {
            uint32_t cur = (hash + i) % new_cap;
            if (!new_table[cur].is_valid) {
                memcpy(&new_table[cur], &g_dir_table[j], sizeof(page_meta_t));
                /* pthread_mutex_t 不可 memcpy，必须重新初始化 */
                pthread_mutex_init(&new_table[cur].lock, NULL);
                placed = 1;
                migrated++;
                break;
            }
        }

        if (!placed && g_ops && g_ops->log) {
            g_ops->log("[CRITICAL] dir_table_grow: rehash failed for GPA %llx!",
                       (unsigned long long)g_dir_table[j].gpa);
        }
    }

    /* 原子切换 */
    page_meta_t *old_table = g_dir_table;
    size_t old_alloc = g_dir_alloc_size;
    g_dir_table = new_table;
    g_dir_capacity = new_cap;
    g_dir_alloc_size = sizeof(page_meta_t) * new_cap;

    /* 释放所有分片锁（逆序） */
    for (int i = LOCK_SHARDS - 1; i >= 0; i--)
        pthread_mutex_unlock(&g_dir_table_locks[i]);

    /* 释放旧表（alloc_large_table 使用 mmap，必须用 munmap） */
    if (old_alloc > 0)
        munmap(old_table, old_alloc);

    if (g_ops && g_ops->log)
        g_ops->log("[DIR] Grew directory table: %u -> %u entries (%u migrated)",
                   old_cap, new_cap, migrated);

    pthread_mutex_unlock(&g_grow_lock);
}

/*
 * 安全版 find_or_create：探测失败时自动扩容并重试。
 * 调用者必须持有 g_dir_table_locks[lock_idx]。
 * 函数会在扩容时临时释放并重新获取该锁。
 */
static page_meta_t* find_or_create_page_meta_safe(uint64_t gpa, uint32_t lock_idx) {
    page_meta_t *meta = find_or_create_page_meta(gpa);
    if (meta) return meta;

    /* 探测失败，需要扩容 */
    pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
    dir_table_grow();
    pthread_mutex_lock(&g_dir_table_locks[lock_idx]);

    meta = find_or_create_page_meta(gpa);
    if (!meta && g_ops && g_ops->log) {
        g_ops->log("[CRITICAL] Directory still full after growth for GPA %llx!",
                   (unsigned long long)gpa);
    }
    return meta;
}
#endif /* !__KERNEL__ */

/* 跨平台宏：user-mode 用 _safe 版本（支持扩容），kernel 用原始版本 */
#ifdef __KERNEL__
#define DIR_FIND_OR_CREATE(gpa, lock_idx) find_or_create_page_meta(gpa)
#else
#define DIR_FIND_OR_CREATE(gpa, lock_idx) find_or_create_page_meta_safe(gpa, lock_idx)
#endif

// --- 核心接口实现 ---

typedef struct {
    uint32_t node_id;
    struct sockaddr_in addr;
    uint8_t  state;
    uint32_t last_epoch;
    uint64_t last_seen_us;
    uint16_t ctrl_port; 
    pthread_mutex_t lock;
} peer_entry_t;

// 局部拓扑视图：无中心架构的核心
static peer_entry_t g_peer_view[MAX_LOCAL_VIEW];
static int g_peer_count = 0;
static pthread_rwlock_t g_view_lock;

// 自治周期控制
// g_curr_epoch moved earlier to satisfy forward references

static atomic_int g_peers_at_next_epoch = 0; // 观测到处于 E+1 的邻居计数

// [PATCH] 预计算路由表大小
#define HASH_RING_SIZE 4096 
// 这个表存储：Slot -> NodeID 的映射
static uint32_t g_hash_ring_cache[HASH_RING_SIZE];
static pthread_rwlock_t g_ring_lock;

static inline int peer_participates_in_owner_ring(uint8_t state)
{
    /*
     * Configured seeds must participate before they become ACTIVE, otherwise
     * each node temporarily maps every GPA to itself and the directory splits.
     * Liveness, not warm-up state, removes a node from the owner set.
     */
    return state != NODE_STATE_OFFLINE && state != NODE_STATE_DRAINING;
}

/* 
 * [物理意图] 当集群发生节点加减（扩容/宕机）时，在后台重建 P2P 拓扑的逻辑环，复杂度 O(RingSize * PeerCount)，但在后台运行，不阻塞热路径
。
 * [关键逻辑] 采用双缓冲区设计，在写锁保护下仅进行微秒级的指针切换，计算过程则与数据面完全并发。
 * [后果] 这保证了 100 万节点规模下的拓扑变更不会引起 vCPU 的卡顿（Zero-Stall Topology Update）。
 */
static void rebuild_hash_ring_cache(void) {
    // 1. [栈上分配] 或 [堆分配] 临时 Ring，避免持有写锁进行计算
    // 注意：4096 * 4 bytes = 16KB，栈上分配略大但通常可行，稳妥起见用 static 备用 buffer 或 malloc
    uint32_t *temp_ring = malloc(sizeof(uint32_t) * HASH_RING_SIZE);
    if (!temp_ring) return;

    // 2. 获取 View 读锁进行计算 (此时不持有 Ring 锁，不阻塞路由查询)
    pthread_rwlock_rdlock(&g_view_lock);
    
    if (g_peer_count == 0) {
        for(int i=0; i<HASH_RING_SIZE; i++) temp_ring[i] = g_my_node_id;
    } else {
        // 耗时的 O(N*M) 计算在这里进行
        for (int slot = 0; slot < HASH_RING_SIZE; slot++) {
            uint32_t best_node = g_my_node_id;
            uint64_t max_weight = murmur3_32(slot ^ g_my_node_id);
            for (int i = 0; i < g_peer_count; i++) {
                if (!peer_participates_in_owner_ring(g_peer_view[i].state)) continue;
                uint64_t weight = murmur3_32(slot ^ g_peer_view[i].node_id);
                if (weight > max_weight) {
                    max_weight = weight;
                    best_node = g_peer_view[i].node_id;
                }
            }
            temp_ring[slot] = best_node;
        }
    }
    pthread_rwlock_unlock(&g_view_lock); 

    // 3. [关键] 获取 Ring 写锁，仅进行内存拷贝 (memcpy 是微秒级的)
    // 此时才真正发生 STW，但时间极短
    pthread_rwlock_wrlock(&g_ring_lock);
    memcpy(g_hash_ring_cache, temp_ring, sizeof(uint32_t) * HASH_RING_SIZE);
    pthread_rwlock_unlock(&g_ring_lock);
    
    free(temp_ring);
    // if (g_ops->log) g_ops->log("[Swarm] Hash Ring Rebuilt (Zero-Stall).");
}

/* 
 * [物理意图] 在 P2P 哈希环上执行 O(1) 级的"真理定位"。
 * [关键逻辑] 输入 GPA，通过 4096 槽位的预计算哈希环（Consistent Hashing），瞬间找到该内存页的 Directory 节点。
 * [后果] 整个分布式内存的亚微秒级访问完全依赖此函数的计算效率，它规避了昂贵的网络寻址开销。
 */
uint32_t get_owner_node_id(uint64_t gpa) {
    // 将 GPA 映射到 0..4095 的槽位
    // gpa >> 12 (页号) -> 再哈希 -> 取模
    uint32_t slot = murmur3_32(gpa >> WVM_PAGE_SHIFT) % HASH_RING_SIZE;
    
    uint32_t target;
    pthread_rwlock_rdlock(&g_ring_lock);
    target = g_hash_ring_cache[slot];
    pthread_rwlock_unlock(&g_ring_lock);
    
    return target;
}

// 存储切片粒度：64MB (2^26)。
// 物理权衡：过小会导致元数据爆炸，过大会导致负载倾斜。
#define WVM_STORAGE_CHUNK_SHIFT 26

/* 
 * [物理意图] 存储寻址器。将 LBA 映射到 Owner 节点。
 */
uint32_t wvm_get_storage_node_id(uint64_t lba) {
    // LBA (512B) -> Byte Offset -> 64MB Chunk Index
    uint64_t chunk_idx = (lba << 9) >> WVM_STORAGE_CHUNK_SHIFT;
    uint32_t slot = murmur3_32(chunk_idx) % HASH_RING_SIZE;

    uint32_t target;
    pthread_rwlock_rdlock(&g_ring_lock);
    target = g_hash_ring_cache[slot];
    pthread_rwlock_unlock(&g_ring_lock);
    // [Multi-VM] 返回 composite ID
    return WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), target);
}

/* --- 逻辑入口：处理接收到的心跳与视图更新 --- */

#ifdef __KERNEL__
static inline void wvm_notify_kernel_epoch(uint32_t epoch) { (void)epoch; }
#else
extern void wvm_notify_kernel_epoch(uint32_t epoch);
#endif

/* 
 * [物理意图] 接收 Gossip 消息，更新本地对 P2P 邻居的存活状态与纪元（Epoch）认知。
 * [关键逻辑] 实现分布式共识的"观测者模式"，当超过半数邻居进入新纪元时，本地自动推进 Epoch。
 * [后果] 解决了大规模集群中"时钟漂移"问题，确保所有节点的 DHT 路由决策在逻辑时间线上达成最终一致。
 */
void update_local_topology_view(uint32_t src_id, uint32_t src_epoch, uint8_t src_state, struct sockaddr_in *src_addr, uint16_t src_ctrl_port) {
    pthread_rwlock_wrlock(&g_view_lock);
    
    int found = 0;
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peer_view[i].node_id == src_id) {
            g_peer_view[i].last_seen_us = g_ops->get_time_us();
            g_peer_view[i].state = src_state;
            g_peer_view[i].last_epoch = src_epoch;
            if (src_ctrl_port > 0) {
                g_peer_view[i].ctrl_port = src_ctrl_port;
            }
            // 如果地址发生变更（如节点重启更换了物理机），同步更新
            if (src_addr && src_addr->sin_addr.s_addr != 0) {
                g_peer_view[i].addr = *src_addr;
            }
            found = 1;
            break;
        }
    }

    // 发现新邻居：Warm-plug 的入口
    if (!found && g_peer_count < MAX_LOCAL_VIEW) {
        peer_entry_t *new_peer = &g_peer_view[g_peer_count]; // 获取指针
        new_peer->node_id = src_id;
        new_peer->state = src_state;
        new_peer->last_epoch = src_epoch;
        new_peer->last_seen_us = g_ops->get_time_us();
        if (src_addr) new_peer->addr = *src_addr;
        
        // 防止端口为 0。如果传进来是 0 (来自心跳)，默认设为 9001
        new_peer->ctrl_port = (src_ctrl_port > 0) ? src_ctrl_port : 9001;
        
        pthread_mutex_init(&new_peer->lock, NULL);
        if (g_ops->log) g_ops->log("[Swarm] New neighbor discovered: %u", src_id);
        g_peer_count++; // 只有初始化完了再增加计数，防止并发读到半成品
    }

    // Epoch 异步共识：观测者模式推进
    if (src_epoch > g_curr_epoch) {
        atomic_fetch_add(&g_peers_at_next_epoch, 1);
        if (atomic_load(&g_peers_at_next_epoch) > (g_peer_count / 2)) {
            g_curr_epoch = src_epoch;
            atomic_store(&g_peers_at_next_epoch, 0);
            wvm_notify_kernel_epoch(g_curr_epoch);
        }
    }
    
    pthread_rwlock_unlock(&g_view_lock);

    // 仅标记 Dirty，实现惰性重建
    atomic_store(&g_ring_dirty, true);
}

uint8_t  g_my_node_state = NODE_STATE_SHADOW;
static uint64_t g_last_gossip_us = 0;
static uint64_t g_state_start_us = 0;

// 配置参数：严格遵循物理时延
#define HEARTBEAT_TIMEOUT_US 180000000 // 180秒未收到心跳则判定 Fail-in-place (测试)
#define WARMING_DURATION_US  10000000 // 预热态持续10秒，同步元数据
#define GOSSIP_FANOUT        3        // 每次随机向3个邻居扩散

/* --- 核心函数：自治节点状态推进 --- */

/* 
 * [物理意图] 驱动节点的生命周期状态机，实现"优雅上线"与"平滑预热"。
 * [关键逻辑] 节点通过 SHADOW -> WARMING -> ACTIVE 转换，在正式接管内存权属前先同步元数据缓存。
 * [后果] 彻底杜绝了新节点加入时由于"缓存冷启动"导致的瞬间全网性能塌陷（Thundering Herd）。
 */
static void advance_node_lifecycle(void) {
    uint64_t now = g_ops->get_time_us();
    uint64_t duration = now - g_state_start_us;

    switch (g_my_node_state) {
        case NODE_STATE_SHADOW:
            // 影子态：已建立网络连接，开始观测集群 Epoch
            if (g_peer_count > 0) {
                g_my_node_state = NODE_STATE_WARMING;
                g_state_start_us = now;
                if (g_ops->log) g_ops->log("[Lifecycle] Transition to WARMING");
            }
            break;

        case NODE_STATE_WARMING:
            // 预热态：此阶段节点开始拉取元数据，但不承载 Owner 权限
            if (duration > WARMING_DURATION_US) {
                g_my_node_state = NODE_STATE_ACTIVE;
                g_state_start_us = now;
                // 晋升为活跃节点后，一致性哈希会自动将其纳入权重计算
                if (g_ops->log) g_ops->log("[Lifecycle] Transition to ACTIVE. Participating in Owner Set.");
            }
            break;

        case NODE_STATE_ACTIVE:
            // 活跃态：正常工作
            break;

        case NODE_STATE_DRAINING:
            // 排空态：此时不再接受新请求，等待旧事务结束
            break;
    }
}

/* --- 核心逻辑：Fail-in-place 局部判定 --- */

/* 
 * [物理意图] 被动检测 P2P 邻居的健康状况，实现隔离故障（Fail-in-place）。
 * [关键逻辑] 检查上次心跳时间戳，超过 5s 则将其在本地路由表中剔除，不再向其转发请求。
 * [后果] 提供了 P2P 架构的自愈能力，确保个别节点的崩溃不会通过请求堆积拖死整个超级虚拟机。
 */
static void monitor_peer_liveness(void) {
    uint64_t now = g_ops->get_time_us();
    pthread_rwlock_wrlock(&g_view_lock);
    
    for (int i = 0; i < g_peer_count; i++) {
        if (peer_participates_in_owner_ring(g_peer_view[i].state)) {
            if (now - g_peer_view[i].last_seen_us > HEARTBEAT_TIMEOUT_US) {
                // 本地标记失效，不再向其路由请求
                g_peer_view[i].state = NODE_STATE_OFFLINE;
                if (g_ops->log) g_ops->log("[Liveness] Node %u detected OFFLINE (Fail-in-place)", g_peer_view[i].node_id);
            }
        }
    }
    
    pthread_rwlock_unlock(&g_view_lock);
}

/* --- 后台自治线程：驱动心跳与扩散 --- */

/* 
 * [物理意图] 驱动整个 P2P 节点的"自主意识"后台线程。
 * [关键逻辑] 周期性执行：状态机推进、故障探测、以及随机向邻居扩散本地视图（Gossip Fan-out）。
 * [后果] 这是 WaveVM 自治性的动力源，保证了在没有任何中心管理节点的情况下，全网拓扑能自行收敛。
 */
void* autonomous_monitor_thread(void* arg) {
    while (1) {
        uint64_t now = g_ops->get_time_us();
        advance_node_lifecycle();
        monitor_peer_liveness();

        // [V30 FIX] 惰性重建哈希环
        if (atomic_exchange(&g_ring_dirty, false)) {
            rebuild_hash_ring_cache();
        }

        // [V30 FIX] 聚合扩散
        if (now - g_last_gossip_us > GOSSIP_INTERVAL_US) {
            pthread_rwlock_rdlock(&g_view_lock);
            if (g_peer_count > 0) {
                for (int i = 0; i < GOSSIP_FANOUT; i++) {
                    uint32_t ridx = 0;
                    g_ops->get_random(&ridx);
                    peer_entry_t *p = &g_peer_view[ridx % g_peer_count];
                    add_gossip_to_aggregator(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), p->node_id), g_my_node_state, g_curr_epoch);
                }
            }
            pthread_rwlock_unlock(&g_view_lock);
            flush_gossip_aggregator(); // 立即发送
            g_last_gossip_us = now;
        }
        g_ops->cpu_relax();
        usleep(100000); 
    }
    return NULL;
}

/* --- 核心逻辑：向邻居请求视图 --- */

void handle_rpc_batch_execution(void *payload, uint32_t len) { (void)payload; (void)len; }

static void request_view_from_neighbor(uint32_t peer_id) {
    struct wvm_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = htonl(WVM_MAGIC);
    hdr.msg_type = htons(MSG_VIEW_PULL);
    hdr.slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
    hdr.epoch = htonl(g_curr_epoch);
    hdr.payload_len = 0;

    // 发送视图请求
    g_ops->send_packet(&hdr, sizeof(hdr), peer_id);
}

/* --- 核心逻辑：响应邻居的视图请求 --- */

static void handle_view_pull(struct wvm_header *rx_hdr, uint32_t src_id) {
    pthread_rwlock_rdlock(&g_view_lock);
    
    // [无简化实现]：由于 UDP MTU 限制，一次最多发送 32 个条目
    uint32_t count = (g_peer_count > 32) ? 32 : g_peer_count;
    size_t payload_len = sizeof(struct wvm_view_payload) + count * sizeof(struct wvm_view_entry);
    size_t pkt_len = sizeof(struct wvm_header) + payload_len;

    uint8_t *buf = g_ops->alloc_packet(pkt_len, 1); // 原子上下文分配
    if (!buf) {
        pthread_rwlock_unlock(&g_view_lock);
        return;
    }

    struct wvm_header *hdr = (struct wvm_header *)buf;
    // 基础包头填充
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_VIEW_ACK);
    hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
    hdr->payload_len = htons(payload_len);
    hdr->epoch = htonl(g_curr_epoch);
    hdr->node_state = g_my_node_state;

    struct wvm_view_payload *pl = (struct wvm_view_payload *)(buf + sizeof(*hdr));
    pl->entry_count = htonl(count);

    for (uint32_t i = 0; i < count; i++) {
        pl->entries[i].node_id = htonl(g_peer_view[i].node_id);
        pl->entries[i].ip_addr = g_peer_view[i].addr.sin_addr.s_addr;
        pl->entries[i].port    = g_peer_view[i].addr.sin_port;
        pl->entries[i].state   = g_peer_view[i].state;
    }
    pthread_rwlock_unlock(&g_view_lock);

    // [Fix #2] src_id 是裸 node_id（内部逻辑），发包时需要编码为 composite ID
    g_ops->send_packet(buf, pkt_len, WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), src_id));
    g_ops->free_packet(buf);
}

static void handle_view_ack(void *payload, uint16_t payload_len) {
    struct wvm_view_payload *pl = (struct wvm_view_payload *)payload;
    if (payload_len < sizeof(struct wvm_view_payload)) return;
    uint32_t count = ntohl(pl->entry_count);
    // [FIX] 边界检查：确保 count 不超过实际 payload 能容纳的条目数
    uint32_t max_entries = (payload_len - sizeof(struct wvm_view_payload)) / sizeof(struct wvm_view_entry);
    if (count > max_entries) count = max_entries;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t nid = ntohl(pl->entries[i].node_id);
        if (nid == g_my_node_id) continue;

        // 获取 IP 信息
        struct sockaddr_in peer_addr;
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_addr.s_addr = pl->entries[i].ip_addr;
        peer_addr.sin_port = pl->entries[i].port;

        // 直接注入视图，不走中间 fake_hdr 路由
        uint16_t r_ctrl = ntohs(pl->entries[i].ctrl_port); 
        update_local_topology_view(nid, 0, pl->entries[i].state, &peer_addr, r_ctrl);
    }
}

int wvm_core_init(struct dsm_driver_ops *ops, int total_nodes_hint) {
    if (!ops) return -1;
    g_ops = ops;
    
    g_dir_table = (page_meta_t *)g_ops->alloc_large_table(
#ifdef __KERNEL__
        sizeof(page_meta_t) * DIR_TABLE_SIZE);
#else
        sizeof(page_meta_t) * g_dir_capacity);
    g_dir_alloc_size = sizeof(page_meta_t) * g_dir_capacity;
#endif
    if (!g_dir_table) return -ENOMEM;
    
    for (int i = 0; i < LOCK_SHARDS; i++) {
        pthread_mutex_init(&g_dir_table_locks[i], NULL); 
    }

    pthread_mutex_init(&g_gossip_agg.lock, NULL);
    pthread_rwlock_init(&g_view_lock, NULL);
    pthread_rwlock_init(&g_ring_lock, NULL);
    
    init_broadcast_shards();

    wvm_clear_cpu_mappings();
    wvm_clear_memory_mappings();
    
    g_total_nodes = (total_nodes_hint > 0) ? total_nodes_hint : 1;
    return 0;
}

void wvm_set_mem_mapping(int slot, uint32_t value) {
    if (slot == 0) wvm_set_total_nodes((int)value);
    if (slot == 1) wvm_set_my_node_id((int)value);
}

void wvm_set_total_nodes(int count) { 
    if(count > 0) g_total_nodes = count; 
}

void wvm_set_my_node_id(int id) { 
    g_my_node_id = id; 
}

// DHT 路由
uint32_t wvm_get_directory_node_id(uint64_t gpa) {
    struct wvm_logic_route_context *context = logic_route_context();
    uint64_t chunk = gpa >> WVM_ROUTING_SHIFT;
    uint32_t target;

    if (WVM_CURRENT_VM_ID() != 0 && !context->route_snapshot_bound) {
        return WVM_NODE_AUTO_ROUTE;
    }
    if (context->memory_range_routes_active) {
        size_t left = 0;
        size_t right = context->memory_range_route_count;

        while (left < right) {
            size_t middle = left + (right - left) / 2U;
            const uint64_t start =
                context->memory_range_routes[middle].gpa_start;
            const uint64_t bytes =
                context->memory_range_routes[middle].bytes;

            if (gpa < start) {
                right = middle;
            } else if (gpa - start < bytes) {
                return WVM_ENCODE_ID(
                    WVM_CURRENT_VM_ID(),
                    context->memory_range_routes[middle].node_id);
            } else {
                left = middle + 1U;
            }
        }
        /*
         * An admitted range projection is complete for the guest.  Do not
         * silently fall back to topology/DHT inference outside that contract.
         */
        return WVM_NODE_AUTO_ROUTE;
    }
    if (chunk < WVM_MEMORY_ROUTE_TABLE_SIZE &&
        context->memory_route_valid[chunk]) {
        target = context->memory_route_table[chunk];
        if (target != WVM_NODE_AUTO_ROUTE) {
            return WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), target);
        }
    }
    // 在百万节点规模下，即使局部视图不一致，路由结果也能大概率收敛
    // [Multi-VM] 返回 composite ID (vm_id | node_id) 用于网络寻址
    return WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), get_owner_node_id(gpa));
}

// 本地缺页快速路径
int wvm_handle_local_fault_fastpath(uint64_t gpa, void* page_buffer, uint64_t *version_out) {
    uint32_t lock_idx = get_lock_idx(gpa);
    
    // 必须加锁，因为可能有远程写操作正在更新这个页面
    pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
    
    page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);
    if (page) {
        // 直接内存拷贝
        memcpy(page_buffer, page->base_page_data, 4096);
        if (version_out) {
            *version_out = page->version;
        }
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
        return 0; // 成功
    }
    
    pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
    return -1; // 失败
}

int wvm_handle_local_commit(uint64_t gpa, uint64_t base_version,
                               uint16_t offset, const uint8_t *data,
                               size_t data_bytes, uint64_t *result_version)
{
    uint32_t lock_idx;
    page_meta_t *page;
    uint32_t epoch;
    uint32_t counter;

    if (!data || !result_version ||
        (gpa & (WVM_PAGE_BYTES - 1UL)) != 0 ||
        base_version == 0 || data_bytes == 0 ||
        data_bytes > WVM_PAGE_BYTES ||
        offset > WVM_PAGE_BYTES - data_bytes) {
        return -EINVAL;
    }
#ifndef __KERNEL__
    /*
     * A local V1 success must be visible to the live QEMU RAM image. Do not
     * fall back to the legacy heap-backed page allocation here, otherwise the
     * caller could receive a successful ACK for bytes QEMU cannot read.
     */
    if (!g_shm_ptr || g_shm_size < WVM_PAGE_BYTES ||
        gpa > g_shm_size - WVM_PAGE_BYTES) {
        return -EOPNOTSUPP;
    }
#endif

    lock_idx = get_lock_idx(gpa);
    pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
    page = find_page_meta_locked(gpa);
    if (!page) {
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
        return -ENOENT;
    }
    if (page->version != base_version) {
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
        return -ESTALE;
    }

    epoch = GET_EPOCH(page->version);
    counter = GET_COUNTER(page->version);
    if (epoch != g_curr_epoch || counter == UINT32_MAX) {
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
        return epoch != g_curr_epoch ? -ESTALE : -EOVERFLOW;
    }
    memcpy(page->base_page_data + offset, data, data_bytes);
    page->version = MAKE_VERSION(epoch, counter + 1U);
    *result_version = page->version;
    pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
    return 0;
}

int wvm_publish_local_commit(uint64_t gpa, uint64_t result_version,
                                uint16_t offset, const uint8_t *data,
                                size_t data_bytes, uint32_t writer_node_id)
{
    uint32_t *subscriber_ids;
    uint8_t *full_page = NULL;
    uint8_t *payload;
    size_t payload_bytes;
    uint32_t subscriber_count = 0;
    uint32_t lock_idx;
    page_meta_t *page;
    int use_full_page = data_bytes >= SMALL_UPDATE_THRESHOLD;

    if (!data || result_version == 0 ||
        (gpa & (WVM_PAGE_BYTES - 1UL)) != 0 ||
        data_bytes == 0 || data_bytes > WVM_PAGE_BYTES ||
        offset > WVM_PAGE_BYTES - data_bytes) {
        return -EINVAL;
    }

    subscriber_ids = wvm_alloc_local(sizeof(*subscriber_ids) *
                                      WVM_MAX_SLAVES);
    if (!subscriber_ids) {
        return -ENOMEM;
    }
    if (use_full_page) {
        full_page = wvm_alloc_local(WVM_PAGE_BYTES);
        if (!full_page) {
            wvm_free_local(subscriber_ids);
            return -ENOMEM;
        }
    }

    lock_idx = get_lock_idx(gpa);
    pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
    page = find_page_meta_locked(gpa);
    if (!page) {
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
        wvm_free_local(full_page);
        wvm_free_local(subscriber_ids);
        return -ENOENT;
    }
    if (page->version != result_version) {
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
        wvm_free_local(full_page);
        wvm_free_local(subscriber_ids);
        return -ESTALE;
    }
    if (use_full_page) {
        memcpy(full_page, page->base_page_data, WVM_PAGE_BYTES);
    }
#ifdef __KERNEL__
    for (uint32_t node_id = 0;
         node_id < WVM_MAX_SLAVES && subscriber_count < WVM_MAX_SLAVES;
         node_id++) {
        if (page->subscribers.bits[node_id / 64] &
            (1UL << (node_id % 64))) {
            subscriber_ids[subscriber_count++] = node_id;
        }
    }
#else
    subscriber_count = page->subscribers.count;
    if (subscriber_count > WVM_MAX_SLAVES) {
        subscriber_count = WVM_MAX_SLAVES;
    }
    if (subscriber_count != 0) {
        memcpy(subscriber_ids, page->subscribers.ids,
               sizeof(*subscriber_ids) * subscriber_count);
    }
#endif
    /*
     * The writer now owns a valid cached copy. Add it after taking the
     * subscriber snapshot so the current commit is not echoed to its source.
     */
    register_page_subscriber(page, writer_node_id);
    pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);

    if (use_full_page) {
        struct wvm_full_page_push *push;

        payload_bytes = sizeof(*push);
        payload = wvm_alloc_local(payload_bytes);
        if (!payload) {
            wvm_free_local(full_page);
            wvm_free_local(subscriber_ids);
            return -ENOMEM;
        }
        push = (struct wvm_full_page_push *)payload;
        push->gpa = WVM_HTONLL(gpa);
        push->version = WVM_HTONLL(result_version);
        memcpy(push->data, full_page, WVM_PAGE_BYTES);
    } else {
        struct wvm_diff_log *diff;

        payload_bytes = sizeof(*diff) + data_bytes;
        payload = wvm_alloc_local(payload_bytes);
        if (!payload) {
            wvm_free_local(subscriber_ids);
            return -ENOMEM;
        }
        diff = (struct wvm_diff_log *)payload;
        diff->gpa = WVM_HTONLL(gpa);
        diff->version = WVM_HTONLL(result_version);
        diff->offset = htons(offset);
        diff->size = htons((uint16_t)data_bytes);
        memcpy(diff->data, data, data_bytes);
    }

    broadcast_to_subscriber_ids(
        subscriber_ids, subscriber_count, writer_node_id,
        use_full_page ? MSG_PAGE_PUSH_FULL : MSG_PAGE_PUSH_DIFF, payload,
        (int)payload_bytes, 0);

    wvm_free_local(payload);
    wvm_free_local(full_page);
    wvm_free_local(subscriber_ids);
    return 0;
}

// [V29 Optimization] 指针队列，极大降低内存占用
typedef struct {
    uint32_t msg_type;
    uint32_t target_id;
    size_t len;
    void *data_ptr; // [Changed] 只存指针，不再预分配 64KB
    uint8_t flags;
} broadcast_task_t;

// 将队列、头尾指针和锁打包成一个结构体
typedef struct {
    broadcast_task_t    queue[BCAST_Q_SIZE];
    volatile uint64_t   head;
    volatile uint64_t   tail;
    pthread_spinlock_t  lock; // 每个分片队列拥有自己独立的锁
} bcast_queue_shard_t;

// 创建分片队列数组
static bcast_queue_shard_t g_bcast_shards[NUM_BCAST_WORKERS];

static void init_broadcast_shards(void)
{
    for (int i = 0; i < NUM_BCAST_WORKERS; i++) {
        pthread_spin_init(&g_bcast_shards[i].lock, PTHREAD_PROCESS_PRIVATE);
        g_bcast_shards[i].head = 0;
        g_bcast_shards[i].tail = 0;
    }
}

// [V29 Optimization] 多线程消费者：读取指针，发送并释放
void* broadcast_worker_thread(void* arg) {
    long worker_id = (long)arg; // 获取自己的ID
    bcast_queue_shard_t *my_shard = &g_bcast_shards[worker_id]; // 定位到自己的专属队列

    while(1) {
        int work_todo = 0;
        broadcast_task_t task_copy;
        
        // 1. 尝试从自己的分片队列出队
        uint64_t current_head = my_shard->head;
        uint64_t current_tail = my_shard->tail; // 读取 volatile

        if (current_head != current_tail) {
            broadcast_task_t *src = &my_shard->queue[current_head & BCAST_Q_MASK];
            task_copy = *src;
            __sync_synchronize(); 
            my_shard->head = current_head + 1; // 修改自己的head
            work_todo = 1;
        }

        if (work_todo) {
            // 2. 发送逻辑
            size_t pkt_len = sizeof(struct wvm_header) + task_copy.len;
            
            // alloc_packet 用于网络发送的 Buffer (可能来自 Slab/Mempool)
            uint8_t *buffer = g_ops->alloc_packet(pkt_len, 0);
            
            if (buffer) {
                struct wvm_header *hdr = (struct wvm_header *)buffer;
                hdr->magic = htonl(WVM_MAGIC);
                hdr->msg_type = htons(task_copy.msg_type);
                hdr->payload_len = htons(task_copy.len);
                hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
                hdr->target_id = htonl(task_copy.target_id);
                hdr->req_id = 0;
                // 全页推送走慢车道，Diff 走快车道
                hdr->qos_level = (task_copy.msg_type == MSG_PAGE_PUSH_FULL) ? 0 : 1;
                hdr->flags = task_copy.flags; 

                // 拷贝 Payload
                if (task_copy.len > 0 && task_copy.data_ptr) {
                    memcpy(buffer + sizeof(*hdr), task_copy.data_ptr, task_copy.len);
                }
                
                // 计算 CRC 并发送 (由 send_packet 内部处理 CRC，这里只需调用)
                g_ops->send_packet(buffer, pkt_len, task_copy.target_id);
                g_ops->free_packet(buffer);
            }

            // 3. 释放内存
            if (task_copy.data_ptr) {
                #ifdef __KERNEL__
                    kfree(task_copy.data_ptr);
                #else
                    free(task_copy.data_ptr);
                #endif
            }
        } else {
            // 4. 空闲等待
            g_ops->cpu_relax(); 
        }
    }
    return NULL;
}

static void enqueue_broadcast_to_target(uint32_t target_id, uint16_t msg_type,
                                        void *payload, int len, uint8_t flags) {
    if (target_id == (uint32_t)g_my_node_id) return;

    // 分配内存
    void *data_copy = NULL;
    if (len > 0) {
        #ifdef __KERNEL__
            data_copy = kmalloc(len, GFP_ATOMIC);
        #else
            data_copy = malloc(len);
        #endif
        if (!data_copy) return;
        memcpy(data_copy, payload, len);
    }

    // 1. 根据目标ID计算分片索引
    int shard_idx = target_id % NUM_BCAST_WORKERS;
    bcast_queue_shard_t *target_shard = &g_bcast_shards[shard_idx];

    // 2. 锁住目标分片队列
    pthread_spin_lock(&target_shard->lock);
    
    // 3. 检查目标分片队列是否已满
    uint64_t current_tail = target_shard->tail;
    if (current_tail + 1 - target_shard->head >= BCAST_Q_SIZE) {
        pthread_spin_unlock(&target_shard->lock);
        if (data_copy) {
            #ifdef __KERNEL__
                kfree(data_copy);
            #else
                free(data_copy);
            #endif
        }
        return; // Drop-tail
    }

    // 4. 将任务放入目标分片队列
    broadcast_task_t *t = &target_shard->queue[current_tail & BCAST_Q_MASK];
    t->msg_type = msg_type;
    t->target_id = WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), target_id); // [Multi-VM] composite ID for network
    t->len = len;
    t->data_ptr = data_copy;
    t->flags = flags;

    __sync_synchronize();
    target_shard->tail = current_tail + 1; // 更新目标分片队列的tail
    
    pthread_spin_unlock(&target_shard->lock);
}

static void broadcast_to_subscriber_ids(const uint32_t *subscriber_ids,
                                        uint32_t subscriber_count,
                                        uint32_t writer_node_id,
                                        uint16_t msg_type, const void *payload,
                                        int len, uint8_t flags)
{
    if (!subscriber_ids || !payload || len <= 0) {
        return;
    }
    for (uint32_t i = 0; i < subscriber_count; i++) {
        if (subscriber_ids[i] != writer_node_id) {
            enqueue_broadcast_to_target(subscriber_ids[i], msg_type,
                                         (void *)payload, len, flags);
        }
    }
}

/* 
 * [物理意图] 针对特定页面的变动，向全网所有利益相关方精准发射"小波（Wavelet）"更新。
 * [关键逻辑] 遍历订阅者集合，利用多线程分片队列并行发送 Diff 或 Full-Page 包。
 * [后果] 它实现了"读操作本地化"，通过网络带宽换取读时延的消除，是 V30 性能突破的关键。
 */
static void broadcast_to_subscribers(page_meta_t *page, uint16_t msg_type, void *payload, int len, uint8_t flags) {
#ifdef __KERNEL__
    // 遍历订阅者的二级位图
    int seg_mask_count = ((WVM_MAX_SLAVES / 64) + 63) / 64; /* segment_mask 有效元素数 */
    for (int i = 0; i < seg_mask_count; i++) {
        uint64_t mask = page->segment_mask[i];
        if (mask == 0) continue;

        for (int j = 0; j < 64; j++) {
            if ((mask >> j) & 1) {
                uint32_t seg_idx = (i * 64) + j;
                uint64_t sub_bits = page->subscribers.bits[seg_idx];
                
                for (int k = 0; k < 64; k++) {
                    if ((sub_bits >> k) & 1) {
                        uint32_t target_id = (seg_idx * 64) + k;
                        enqueue_broadcast_to_target(target_id, msg_type, payload, len, flags);
                    }
                }
            }
        }
    }
#else
    for (uint32_t i = 0; i < page->subscribers.count; i++) {
        enqueue_broadcast_to_target(page->subscribers.ids[i], msg_type, payload, len, flags);
    }
#endif
}

// [FIX] FORCE_SYNC 限流器状态
static atomic_int  g_force_sync_counter = ATOMIC_VAR_INIT(0);
static atomic_long g_force_sync_last_sec = ATOMIC_VAR_INIT(0);
#define MAX_FORCE_SYNC_PER_SEC 1024 

/* 
 * [物理意图] 当发生严重的版本冲突或逻辑断层时，强制向节点投喂"最终真理"。
 * [关键逻辑] 绕过所有增量优化，直接发送 4KB 全量页面数据并强制更新其版本号。
 * [后果] 这是系统的"最终一致性保险丝"，在网络混沌或极端竞态下保证内存状态不崩溃。
 */
static void force_sync_client(uint64_t gpa, page_meta_t* page, uint32_t client_id) {
    // [FIX] page 可能为 NULL（如 stale-epoch 拒绝路径尚未查表）
    if (!page) {
        // 尝试从目录表中查找
        uint32_t lock_idx = get_lock_idx(gpa);
        pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
        page = DIR_FIND_OR_CREATE(gpa, lock_idx);
        if (!page) {
            pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
            return; // 页面不存在，无法同步
        }
        // 复制版本和数据后立即释放锁
        uint64_t safe_version = page->version;
        uint8_t safe_data[4096];
        memcpy(safe_data, page->base_page_data, 4096);
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);

        // 使用安全副本发送（跳过下方的直接解引用）
        // [FIX] 基于令牌桶思想的秒级节流
        long current_sec = g_ops->get_time_us() / 1000000;
        long last_sec = atomic_load(&g_force_sync_last_sec);
        if (current_sec != last_sec) {
            atomic_store(&g_force_sync_last_sec, current_sec);
            atomic_store(&g_force_sync_counter, 0);
        }
        if (atomic_fetch_add(&g_force_sync_counter, 1) >= MAX_FORCE_SYNC_PER_SEC) return;

        size_t pl_size = sizeof(struct wvm_full_page_push);
        size_t pkt_len = sizeof(struct wvm_header) + pl_size;
        uint8_t *buffer = g_ops->alloc_packet(pkt_len, 1);
        if (!buffer) return;

        struct wvm_header *hdr = (struct wvm_header*)buffer;
        hdr->magic = htonl(WVM_MAGIC);
        hdr->msg_type = htons(MSG_FORCE_SYNC);
        hdr->payload_len = htons(pl_size);
        hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
        hdr->req_id = 0;
        hdr->qos_level = 1;

        struct wvm_full_page_push *push = (struct wvm_full_page_push*)(buffer + sizeof(*hdr));
        push->gpa = WVM_HTONLL(gpa);
        push->version = WVM_HTONLL(safe_version);
        memcpy(push->data, safe_data, 4096);

        g_ops->send_packet(buffer, pkt_len, WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), client_id));
        g_ops->free_packet(buffer);
        return;
    }
    // [FIX] 基于令牌桶思想的秒级节流
    long current_sec = g_ops->get_time_us() / 1000000;
    long last_sec = atomic_load(&g_force_sync_last_sec);

    if (current_sec != last_sec) {
        atomic_store(&g_force_sync_last_sec, current_sec);
        atomic_store(&g_force_sync_counter, 0);
    }

    if (atomic_fetch_add(&g_force_sync_counter, 1) >= MAX_FORCE_SYNC_PER_SEC) {
        // 超出带宽配额，直接丢弃。
        // 客户端因收不到回复，会保持旧版本，下次 COMMIT 依然会失败，实现"天然重试"
        return; 
    }

    size_t pl_size = sizeof(struct wvm_full_page_push);
    size_t pkt_len = sizeof(struct wvm_header) + pl_size;
    
    uint8_t *buffer = g_ops->alloc_packet(pkt_len, 1);
    if (!buffer) return;

    struct wvm_header *hdr = (struct wvm_header*)buffer;
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_FORCE_SYNC);
    hdr->payload_len = htons(pl_size);
    hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
    hdr->req_id = 0;
    hdr->qos_level = 1; // High priority correction

    struct wvm_full_page_push *push = (struct wvm_full_page_push*)(buffer + sizeof(*hdr));
    push->gpa = WVM_HTONLL(gpa);
    // 此时持有页锁，version是安全的
    push->version = WVM_HTONLL(page->version); 
    memcpy(push->data, page->base_page_data, 4096);

    // [Fix #2] client_id 是裸 node_id，发包时需要编码为 composite ID
    g_ops->send_packet(buffer, pkt_len, WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), client_id));
    g_ops->free_packet(buffer);
}

int wvm_handle_page_fault_logic(uint64_t gpa, void *page_buffer, uint64_t *version_out) {
    uint32_t dir_node = wvm_get_directory_node_id(gpa);
    
    // 场景 A: 我就是目录节点 (Local Hit)
    // [Multi-VM] dir_node 是 composite ID，用 WVM_GET_NODEID 比较
    if (WVM_GET_NODEID(dir_node) == (uint32_t)g_my_node_id) {
        uint32_t lock_idx = get_lock_idx(gpa);
        pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
        
        page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);
        int ret = -1;
        
        if (page) {
            // 直接从本地目录内存拷贝
            memcpy(page_buffer, page->base_page_data, 4096);
            if (version_out) *version_out = page->version;
            WVM_LOG_ERR("[Page Fault] local gpa=%#llx ver=%#llx\n",
                        (unsigned long long)gpa,
                        (unsigned long long)page->version);
            
            // 缺页读取会在本地形成缓存副本，后续必须接收该页 push。
            register_page_subscriber(page, g_my_node_id);
            ret = 0;
        }
        
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
        return ret;
    }

    // 场景 B: 远程节点 (Remote Pull)
    // 这是 V28 逻辑的直接复用，但增加了 Version 字段处理
    
    // 1. 分配请求 ID
    // 远程 ACK 是 wvm_mem_ack_payload（含 version + 4KB data），
    // 不能直接把 4KB 页缓冲传给 req_ctx，否则 version 会丢失或发生越界风险。
    struct wvm_mem_ack_payload ack_payload;
    uint64_t rid = g_ops->alloc_req_id(&ack_payload, sizeof(ack_payload));
    if (rid == (uint64_t)-1) return -1;

    // 2. 构造 MSG_MEM_READ 包
    size_t pkt_len = sizeof(struct wvm_header) + 8;
    uint8_t *buffer = g_ops->alloc_packet(pkt_len, 1);
    if (!buffer) { g_ops->free_req_id(rid); return -1; }

    struct wvm_header *hdr = (struct wvm_header *)buffer;
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_MEM_READ);
    hdr->payload_len = htons(8);
    hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
    hdr->target_id = htonl(dir_node);
    hdr->req_id = WVM_HTONLL(rid);
    hdr->qos_level = 1; // 缺页必须走快车道

    uint64_t net_gpa = WVM_HTONLL(gpa);
    memcpy(buffer + sizeof(*hdr), &net_gpa, 8);

    // 3. 发送并等待 (阻塞式)
    uint64_t start_total = g_ops->get_time_us();
    uint64_t last_send = 0;
    
    // 首次发送
    g_ops->send_packet(buffer, pkt_len, dir_node);
    last_send = start_total;
    WVM_LOG_ERR("[Page Fault] remote gpa=%#llx dir=%u rid=%llu\n",
                (unsigned long long)gpa,
                dir_node,
                (unsigned long long)rid);

    int success = 0;
    while (1) {
        // 检查是否完成
        if (g_ops->check_req_status(rid) == 1) {
            success = 1;
            WVM_LOG_ERR("[Page Fault Ack] gpa=%#llx rid=%llu\n",
                        (unsigned long long)gpa,
                        (unsigned long long)rid);
            break;
        }
        
        // 超时重传
        uint64_t now = g_ops->get_time_us();
        if (g_ops->time_diff_us(last_send) > RETRY_TIMEOUT_US) {
            g_ops->send_packet(buffer, pkt_len, dir_node);
            last_send = now;
        }
        
        // 总超时熔断 (5秒)
        if (g_ops->time_diff_us(start_total) > 5000000) break;
        
        g_ops->touch_watchdog();
        g_ops->cpu_relax();
    }

    g_ops->free_packet(buffer);

    if (success) {
        uint64_t ack_gpa = WVM_NTOHLL(ack_payload.gpa);
        if (ack_gpa != gpa) {
            g_ops->free_req_id(rid);
            return -1;
        }
        memcpy(page_buffer, ack_payload.data, 4096);
        if (version_out) {
            *version_out = WVM_NTOHLL(ack_payload.version);
        }
    }
    if (!success) {
        WVM_LOG_ERR("[Page Fault Timeout] gpa=%#llx dir=%u rid=%llu\n",
                    (unsigned long long)gpa,
                    dir_node,
                    (unsigned long long)rid);
    }

    g_ops->free_req_id(rid);
    return success ? 0 : -1;
}

/* 
 * Master 侧 Directory 元数据同步更新
 * 隐患规避：使用宏操作版本号，防止逻辑时钟紊乱；加锁保护，防止并发写冲突。
 */
static void handle_prophet_metadata_update(uint64_t gpa_start, uint64_t len) {
    for (uint64_t off = 0; off < len; off += 4096) {
        uint64_t cur_gpa = gpa_start + off;
        uint32_t lock_idx = get_lock_idx(cur_gpa);
        
        pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
        page_meta_t *page = DIR_FIND_OR_CREATE(cur_gpa, lock_idx);
        if (page) {
            // [严格遵守宏操作]：版本号必须单调连续递增
            uint32_t next_cnt = GET_COUNTER(page->version) + 1;
            page->version = MAKE_VERSION(g_curr_epoch, next_cnt);
            
            // 物理落盘：Master 自己的内存也要清零
            memset(page->base_page_data, 0, 4096);
#ifndef __KERNEL__
            if (g_shm_ptr && cur_gpa + 4096 <= g_shm_size) {
                memset((uint8_t*)g_shm_ptr + cur_gpa, 0, 4096);
            }
#endif
        }
        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
    }
}

/* 
 *  ABI 语义指纹识别器
 * 隐患规避：DF方向检查、整页对齐修剪、最小阈值过滤。
 */
static void wvm_prophet_abi_scanner(wvm_kvm_context_t *ctx) {
    // 1. 方向安全检查：x86 DF位 (Bit 10)。如果 DF=1 (递减)，绝对不加速。
    if (ctx->rflags & (1 << 10)) return;

    // 2. 只有写操作触发的 MMIO/Exception 才具备识别价值
    // 安全门：只加速我们能确定宽度的操作
    uint32_t insn_width = ctx->mmio.len;
    if (insn_width != 1 && insn_width != 2 && insn_width != 4 && insn_width != 8) {
        return;
    }
    uint64_t raw_start = ctx->rdi;
    uint64_t raw_len = ctx->rcx * insn_width; 

    // 3. 对齐修剪：计算 4KB 对齐的加速区间，非对齐部分留给 Guest 跑
    uint64_t aligned_start = (raw_start + 4095) & ~4095ULL;
    uint64_t head_gap = aligned_start - raw_start;
    
    if (raw_len <= head_gap + 4096) return; // 剩余长度不足一页，不加速
    uint64_t acc_len = (raw_len - head_gap) & ~4095ULL;

    // 4. 阈值检查：1MB 以上才触发 Prophet 广播
    if (ctx->rax == 0 && acc_len >= 1048576) {
        // 使用文件中真实存在的广播接口
        struct wvm_rpc_batch_memset batch = { .val = htonl(0), .count = htonl(1) };
        struct wvm_rpc_region region = { .gpa = WVM_HTONLL(aligned_start), .len = WVM_HTONLL(acc_len) };
        // [FIX] broadcast_rpc 要求 header+payload 格式，不能只传裸 payload
        size_t pl_size = sizeof(batch) + sizeof(region);
        uint8_t buf[sizeof(struct wvm_header) + sizeof(batch) + sizeof(region)];
        memset(buf, 0, sizeof(struct wvm_header)); // 清零 header 区域
        memcpy(buf + sizeof(struct wvm_header), &batch, sizeof(batch));
        memcpy(buf + sizeof(struct wvm_header) + sizeof(batch), &region, sizeof(region));

        // 预填 header 基本字段
        struct wvm_header *rpc_hdr = (struct wvm_header *)buf;
        rpc_hdr->magic = htonl(WVM_MAGIC);
        rpc_hdr->msg_type = htons(MSG_RPC_BATCH_MEMSET);
        rpc_hdr->payload_len = htons((uint16_t)pl_size);
        rpc_hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));

        wvm_logic_broadcast_rpc(buf, sizeof(buf), MSG_RPC_BATCH_MEMSET);

        // 同步 Master 侧元数据
        handle_prophet_metadata_update(aligned_start, acc_len);

        // 修正参数不匹配。循环调用，适配 g_ops->invalidate_local(gpa)
        for (uint64_t inv_gpa = aligned_start; inv_gpa < aligned_start + acc_len; inv_gpa += 4096) {
            g_ops->invalidate_local(inv_gpa);
        }

        // 计算残余寄存器状态，防止"字节丢失"
        uint64_t rem_bytes = raw_len - head_gap - acc_len;
        ctx->rdi = aligned_start + acc_len;
        
        // 严禁向上取整！必须向下取整。
        // 如果剩下 3 个字节，rcx 设为 0。
        // Guest 醒来后发现 rcx=0，会结束 REP 循环，剩下那 3 字节由 Guest 
        // 随后的非加速指令完成，或者干脆就不写。这保证了绝不写过界。
        ctx->rcx = rem_bytes / insn_width; 
    }
}

// 核心RPC (带指数退避)
int wvm_rpc_call(uint16_t msg_type, void *payload, int len, uint32_t target_id, void *rx_buffer, int rx_len) {
    { static int __rpc_dbg=0;
      if (__rpc_dbg < 10) {
          WVM_LOG_ERR("[RPC-CALL] msg=%u len=%d target=%u\n",
                      (unsigned)msg_type, len, (unsigned)target_id);
          __rpc_dbg++;
      }
    }
    // 1. 分配接收缓冲区
    // 我们需要一个足够大的缓冲区来接收可能的ACK包头
    uint8_t *net_rx_buf = g_ops->alloc_packet(WVM_MAX_PACKET_SIZE, 0); // Not atomic
    if (!net_rx_buf) return -ENOMEM;

    // 2. 分配请求ID
    uint64_t rid = g_ops->alloc_req_id(net_rx_buf, WVM_MAX_PACKET_SIZE);
    if (rid == (uint64_t)-1) {
        g_ops->free_packet(net_rx_buf);
        return -EBUSY;
    }

    // 3. 构造请求包
    size_t pkt_len = sizeof(struct wvm_header) + len;
    uint8_t *buffer = g_ops->alloc_packet(pkt_len, 0); // Not atomic
    if (!buffer) {
        g_ops->free_req_id(rid);
        g_ops->free_packet(net_rx_buf);
        return -ENOMEM;
    }

    struct wvm_header *hdr = (struct wvm_header *)buffer;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(msg_type);
    hdr->payload_len = htons(len);
    hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id)); // Source ID
    // Preserve logical destination so fractal gateways can route correctly.
    hdr->target_id = htonl(target_id);
    hdr->req_id = WVM_HTONLL(rid);
    hdr->qos_level = 1; // Control messages are fast lane
    if (msg_type == MSG_VCPU_RUN) {
        if (len == (int)sizeof(wvm_tcg_context_t)) {
            hdr->mode_tcg = 1;
        } else if (len >= (int)sizeof(struct wvm_ipc_cpu_run_req)) {
            const struct wvm_ipc_cpu_run_req *run_req =
                (const struct wvm_ipc_cpu_run_req *)payload;
            hdr->mode_tcg = run_req->mode_tcg ? 1 : 0;
        }
    }
    
    if (payload && len > 0) {
        memcpy(buffer + sizeof(*hdr), payload, len);
    }
    
    // 4. 重试循环逻辑
    uint64_t start_total = g_ops->get_time_us();
    uint64_t last_send_time;
    uint64_t current_retry_delay = INITIAL_RETRY_DELAY_US;
    bool retryable = true;
    bool is_vcpu_run = (msg_type == MSG_VCPU_RUN);
    uint64_t total_timeout_us = TOTAL_TIMEOUT_US;
    uint32_t retry_count = 0;
    uint32_t max_retries = UINT32_MAX;
    uint64_t retry_window_us = UINT64_MAX;
    if (is_vcpu_run) {
        /*
         * VCPU_RUN is a long-running transaction. It still needs retransmit for
         * startup UDP readiness/loss, while the slave side provides
         * single-flight execution for duplicate req_ids. Do not retransmit for
         * the whole execution lifetime: duplicates amplify load and can arrive
         * long after the original waiter timed out.
         */
        current_retry_delay = MAX_RETRY_DELAY_US;
        total_timeout_us = VCPU_RUN_TIMEOUT_US;
        max_retries = VCPU_RUN_MAX_RETRIES;
        retry_window_us = VCPU_RUN_RETRY_WINDOW_US;
    }

    // 首次发送
    g_ops->send_packet(buffer, pkt_len, target_id);
    last_send_time = start_total;

    while (g_ops->check_req_status(rid) != 1) {
        // 喂狗
        g_ops->touch_watchdog();

        // 检查总超时
        if (g_ops->time_diff_us(start_total) > total_timeout_us) {
            if (g_ops->log) {
                g_ops->log("[RPC Timeout] Type: %d, Target: %d, RID: %llu", 
                           msg_type, target_id, (unsigned long long)rid);
            }
            g_ops->free_packet(buffer);
            g_ops->free_packet(net_rx_buf);
            g_ops->free_req_id(rid);
            return -ETIMEDOUT;
        }

        // 检查是否需要重试
        if (retryable && g_ops->time_diff_us(last_send_time) > current_retry_delay) {
            if (retry_count >= max_retries ||
                g_ops->time_diff_us(start_total) > retry_window_us) {
                retryable = false;
                continue;
            }

            // 重发
            g_ops->send_packet(buffer, pkt_len, target_id);
            last_send_time = g_ops->get_time_us();
            retry_count++;

            // 指数增加延迟
            current_retry_delay *= 2;
            if (current_retry_delay > MAX_RETRY_DELAY_US) {
                current_retry_delay = MAX_RETRY_DELAY_US;
            }

            // 增加随机抖动 +/- 30%
            uint32_t random_val;
            g_ops->get_random(&random_val);
            uint64_t jitter = current_retry_delay * 3 / 10;
            if (jitter > 0) {
                // random_val is u32, convert to signed offset carefully
                int64_t offset = ((int64_t)random_val % (2 * jitter)) - (int64_t)jitter;
                
                // Ensure delay doesn't go negative or too small
                if ((int64_t)current_retry_delay + offset > 100) {
                    current_retry_delay = (uint64_t)((int64_t)current_retry_delay + offset);
                }
            }
        }
        
        // 短暂休眠让出CPU
        g_ops->yield_cpu_short_time();
    }
    
    // 5. 处理结果
    g_ops->free_packet(buffer); // 释放发送Buffer

    // 从接收Buffer中提取数据
    // [FIX] RX 侧只复制了 payload（不含 header），所以 net_rx_buf 直接就是 payload
    if (rx_buffer && rx_len > 0) {
        /* alloc_req_id 注册了 max_len = WVM_MAX_PACKET_SIZE，
         * RX 回调写入的是纯 payload，长度已由 RX 侧截断到 max_len。
         * 这里直接按 rx_len 复制即可。 */
        memcpy(rx_buffer, net_rx_buf, (size_t)rx_len);
    }

    if (msg_type == MSG_VCPU_RUN && rx_buffer != NULL) {
        struct wvm_ipc_cpu_run_ack *run_ack = (struct wvm_ipc_cpu_run_ack *)rx_buffer;
        
        // 激活！调用你前面定义的 scanner 
        if (run_ack->status == 0 && run_ack->mode_tcg == 0) {
            // 这才是 logic_core 应该有的样子：职责分离
            wvm_prophet_abi_scanner(&run_ack->ctx.kvm);
        }
    }

    g_ops->free_packet(net_rx_buf); // 释放接收Buffer
    g_ops->free_req_id(rid);
    return 0;
}

// 该函数由内核缺页处理程序(wvm_fault_handler)调用，
// 用于告知 Directory 节点："我关注这个页面，请有更新时推给我"。
void wvm_declare_interest_in_neighborhood(uint64_t gpa) {
    // 1. 计算该 GPA 归谁管 (Directory Node)
    uint32_t dir_node = wvm_get_directory_node_id(gpa);
    
    // 如果我自己就是 Directory，不需要网络宣告 (本地 Logic Core 会自动处理)
    // [Multi-VM] dir_node 现在是 composite ID，用 WVM_GET_NODEID 提取裸 ID 比较
    if (WVM_GET_NODEID(dir_node) == (uint32_t)g_my_node_id) return;

    // 2. 分配数据包 (Atomic 上下文安全)
    size_t pkt_len = sizeof(struct wvm_header) + sizeof(uint64_t);
    uint8_t *buffer = g_ops->alloc_packet(pkt_len, 1); 
    
    if (!buffer) {
        // 内存不足时丢弃本次宣告。
        // 这不是致命错误，只会导致本次无法订阅，V28 的拉取机制会兜底。
        return; 
    }

    // 3. 构造协议头
    struct wvm_header *hdr = (struct wvm_header *)buffer;
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_DECLARE_INTEREST);
    hdr->payload_len = htons(sizeof(uint64_t));
    hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id)); // 告诉对方我是谁
    hdr->req_id = 0;                     // 异步消息，不需要 ACK
    hdr->qos_level = 1;                  // 订阅是元数据操作，走 Fast Lane

    // 4. 填充 GPA
    uint64_t net_gpa = WVM_HTONLL(gpa);
    memcpy(buffer + sizeof(*hdr), &net_gpa, sizeof(uint64_t));

    // 5. 发送并释放
    g_ops->send_packet(buffer, pkt_len, dir_node);
    g_ops->free_packet(buffer);
}

static void add_gossip_to_aggregator(uint32_t target_node_id, uint8_t state, uint32_t epoch) {
    struct wvm_heartbeat_payload hb;
    (void)state;
    (void)epoch;

    hb.local_epoch = htonl(g_curr_epoch);
    hb.active_node_count = htonl(g_peer_count);
    hb.load_factor = 0;
    hb.peer_epoch_sum = 0;
    hb.ctrl_port = htons((uint16_t)g_ctrl_port);

    /* Heartbeat packets must be sent as standalone frames so header/CRC/target_id
     * are set consistently by the backend send pipeline. */
    g_ops->send_packet_async(MSG_HEARTBEAT, &hb, sizeof(hb), target_node_id, 1);
}

static void flush_gossip_aggregator() {
    /* No-op: heartbeat aggregation removed; each heartbeat is sent directly. */
}

static void send_commit_ack_if_needed(struct wvm_header *req_hdr,
                                      uint32_t source_node_id,
                                      int ok)
{
    if (!(req_hdr->flags & WVM_FLAG_NEED_ACK) ||
        WVM_NTOHLL(req_hdr->req_id) == 0) {
        return;
    }

    size_t ack_len = sizeof(struct wvm_header) + 1;
    uint8_t *ack_buf = g_ops->alloc_packet(ack_len, 1);
    if (!ack_buf) {
        return;
    }

    struct wvm_header *ack = (struct wvm_header *)ack_buf;
    memset(ack, 0, sizeof(*ack));
    ack->magic = htonl(WVM_MAGIC);
    ack->msg_type = htons(MSG_MEM_ACK);
    ack->payload_len = htons(1);
    ack->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
    ack->target_id = req_hdr->slave_id;
    ack->req_id = req_hdr->req_id;
    ack->qos_level = 1;
    ack->flags = ok ? 0 : WVM_FLAG_ERROR;
    ack->epoch = htonl(g_curr_epoch);
    ack->node_state = g_my_node_state;
    ack_buf[sizeof(*ack)] = ok ? 1 : 0;

    g_ops->send_packet(ack_buf, ack_len, source_node_id);
    g_ops->free_packet(ack_buf);
}

#ifndef __KERNEL__
static void log_commit_sync_decision(const char *reason, struct wvm_header *hdr,
                                     uint32_t source_node_id, uint64_t gpa,
                                     uint64_t commit_version,
                                     uint64_t local_version, uint16_t off,
                                     uint16_t sz, uint16_t pl_len)
{
    static int log_count;
    int is_accept = !strcmp(reason, "accept");

    if (!(hdr->flags & WVM_FLAG_NEED_ACK)) {
        return;
    }
    if (is_accept && __sync_fetch_and_add(&log_count, 1) >= 120) {
        return;
    }
    if (g_ops->log) {
        g_ops->log("[COMMIT_SYNC RX] %s src=%u target=%u gpa=%#llx "
                   "commit=%#llx local=%#llx off=%u sz=%u pl=%u flags=0x%x rid=%llu",
                   reason, (unsigned)source_node_id,
                   (unsigned)ntohl(hdr->target_id),
                   (unsigned long long)gpa,
                   (unsigned long long)commit_version,
                   (unsigned long long)local_version,
                   (unsigned)off, (unsigned)sz, (unsigned)pl_len,
                   (unsigned)hdr->flags,
                   (unsigned long long)WVM_NTOHLL(hdr->req_id));
    }
}
#else
#define log_commit_sync_decision(reason, hdr, source_node_id, gpa, commit_version, local_version, off, sz, pl_len) \
    do { } while (0)
#endif

/* 
 * [物理意图] 分布式内存事务的终极处理器。
 * [关键逻辑] 拦截所有入站消息，根据 MESI 状态机执行：READ(拉取)、DECLARE(订阅)、COMMIT(增量写) 及 Prophet(指令透传)。
 * [后果] 这是系统的"物理法则"执行点，任何逻辑错误都会直接破坏内存强一致性。
 */
void wvm_logic_process_packet(struct wvm_header *hdr, void *payload, uint32_t source_node_id) {
    uint16_t type = ntohs(hdr->msg_type);
    uint32_t src_id_raw = ntohl(hdr->slave_id);
    // [Multi-VM] 解码 composite ID，提取裸 node_id 给内部 DHT 操作
    uint8_t  src_vm_id = WVM_GET_VMID(src_id_raw);
    uint32_t src_id = WVM_GET_NODEID(src_id_raw);
    uint32_t src_epoch = ntohl(hdr->epoch);
    uint8_t  src_state = hdr->node_state;

    // [Multi-VM] 丢弃其他 VM 的包
    if (src_vm_id != WVM_CURRENT_VM_ID()) return;

    if (type == MSG_HEARTBEAT && g_ops && g_ops->log) {
        g_ops->log("[HB LOGIC] src=%u vm=%u state=%u epoch=%u", src_id, src_vm_id, src_state, src_epoch);
    }

    // 1. [核心安全检查] 任何消息都必须透传 Epoch 和 State
    // 如果收到的消息 Epoch 大于本地太远，说明本地视图已严重落后，强制触发视图拉取
    if (src_epoch > g_curr_epoch + 1) {
        request_view_from_neighbor(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), src_id));
    }

    uint16_t r_ctrl_port = 0;
    if (type == MSG_HEARTBEAT) {
        if (ntohs(hdr->payload_len) >= sizeof(struct wvm_heartbeat_payload)) {
            struct wvm_heartbeat_payload *hb = (struct wvm_heartbeat_payload *)payload;
            r_ctrl_port = ntohs(hb->ctrl_port);
        }
    }

    // 2. [自动维护] 无论什么消息类型，只要是自治范围（>=40）或包含有效信息的，都更新拓扑视图
    if (type >= 40 || type == MSG_PING) {
        update_local_topology_view(src_id, src_epoch, src_state, NULL, r_ctrl_port);
    }

    switch(type) {
        case MSG_HEARTBEAT:
            // 视图已在上方更新，无需额外操作
            break;
            
        case MSG_VIEW_PULL:
            handle_view_pull(hdr, src_id);
            break;
            
        case MSG_VIEW_ACK:
            handle_view_ack(payload, ntohs(hdr->payload_len));
            break;

        // --- 1. 处理拉取请求 (Pull) ---
        case MSG_MEM_READ: {
            if (ntohs(hdr->payload_len) < sizeof(uint64_t)) return;
            uint64_t gpa = WVM_NTOHLL(*(uint64_t*)payload);
            
            // 确保我是这个页面的 Directory
            if (WVM_GET_NODEID(wvm_get_directory_node_id(gpa)) != (uint32_t)g_my_node_id) return;
            
            // 构造 MSG_MEM_ACK (包含版本号的 payload)
            size_t pl_size = sizeof(struct wvm_mem_ack_payload);
            size_t pkt_len = sizeof(struct wvm_header) + pl_size;
            uint8_t *buffer = g_ops->alloc_packet(pkt_len, 1);
            if (!buffer) return;

            struct wvm_header *ack = (struct wvm_header*)buffer;
            ack->magic = htonl(WVM_MAGIC);
            ack->msg_type = htons(MSG_MEM_ACK);
            ack->payload_len = htons(pl_size);
            ack->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
            ack->target_id = hdr->slave_id;
            ack->req_id = hdr->req_id; // 必须回传请求ID
            ack->qos_level = 0; // 大包走慢车道

            struct wvm_mem_ack_payload *ack_pl = (struct wvm_mem_ack_payload*)(buffer + sizeof(*ack));
            
            uint32_t lock_idx = get_lock_idx(gpa);
            pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
            
            page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);
            if (page) {
                ack_pl->gpa = WVM_HTONLL(gpa);
                // 关键：填入当前版本号
                ack_pl->version = WVM_HTONLL(page->version);
                memcpy(ack_pl->data, page->base_page_data, 4096);
                register_page_subscriber(page, src_id);
            } else {
                // Should not happen if alloc succeeds, but handle it
                memset(ack_pl, 0, sizeof(*ack_pl));
            }
            
            pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
            
            g_ops->send_packet(buffer, pkt_len, source_node_id);
            g_ops->free_packet(buffer);
            break;
        }

        // --- 2. 处理兴趣宣告 (Pub) ---
        case MSG_DECLARE_INTEREST: {
            if (ntohs(hdr->payload_len) < sizeof(uint64_t)) return;
            uint64_t gpa = WVM_NTOHLL(*(uint64_t*)payload);
            
            if (WVM_GET_NODEID(wvm_get_directory_node_id(gpa)) != (uint32_t)g_my_node_id) return;

            uint32_t lock_idx = get_lock_idx(gpa);
            pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
            
            page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);
            if (page) {
                // 记录订阅者 (使用裸 node_id 索引位图，不能用 composite ID)
                register_page_subscriber(page, src_id);
            }
            
            pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
            break;
        }

        // --- 3. 处理增量提交 (Commit) ---
        case MSG_COMMIT_DIFF: {
            // 安全检查 payload 长度
            uint16_t pl_len = ntohs(hdr->payload_len);
            if (pl_len < sizeof(struct wvm_diff_log)) {
                log_commit_sync_decision("reject-short-payload", hdr, source_node_id,
                                         0, 0, 0, 0, 0, pl_len);
                send_commit_ack_if_needed(hdr, source_node_id, 0);
                return;
            }

            struct wvm_diff_log *log = (struct wvm_diff_log*)payload;
            uint64_t gpa = WVM_NTOHLL(log->gpa);
            uint64_t commit_version = WVM_NTOHLL(log->version);
            uint16_t off = ntohs(log->offset);
            uint16_t sz = ntohs(log->size);

            // 在自治模式下，COMMIT 必须先校验写者的 Epoch
            if (src_epoch < g_curr_epoch) {
                // 拒绝陈旧 Epoch 的提交，通知其 FORCE_SYNC
                force_sync_client(gpa, NULL, src_id);
                log_commit_sync_decision("reject-stale-epoch", hdr, source_node_id,
                                         gpa, commit_version, 0, off, sz, pl_len);
                send_commit_ack_if_needed(hdr, source_node_id, 0);
                return;
            }

            if (sizeof(struct wvm_diff_log) + sz > pl_len || off + sz > 4096) {
                log_commit_sync_decision("reject-bounds", hdr, source_node_id,
                                         gpa, commit_version, 0, off, sz, pl_len);
                send_commit_ack_if_needed(hdr, source_node_id, 0);
                return;
            }

            if (WVM_GET_NODEID(wvm_get_directory_node_id(gpa)) != (uint32_t)g_my_node_id) {
                log_commit_sync_decision("reject-wrong-owner", hdr, source_node_id,
                                         gpa, commit_version, 0, off, sz, pl_len);
                send_commit_ack_if_needed(hdr, source_node_id, 0);
                return;
            }

            uint32_t lock_idx = get_lock_idx(gpa);
            int commit_ok = 0;
            int local_qemu_push_barrier_failed = 0;
            int needs_push_fence = (hdr->flags & WVM_FLAG_NEED_ACK) != 0;

            if (sz == 0) {
                pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
                // [V29.5] Zero Page Commit
                page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);
                if (page) {
                    // 本地清零
                    memset(page->base_page_data, 0, 4096);
#ifndef __KERNEL__
                    if (g_shm_ptr && gpa + 4096 <= g_shm_size) {
                        memset((uint8_t*)g_shm_ptr + gpa, 0, 4096);
                    }
#endif
                    uint32_t local_counter = GET_COUNTER(page->version);
                    page->version = MAKE_VERSION(g_curr_epoch, local_counter + 1);
                    
                    log->version = WVM_HTONLL(page->version);

                    struct wvm_full_page_push local_full;
                    local_full.gpa = WVM_HTONLL(gpa);
                    local_full.version = WVM_HTONLL(page->version);
                    memset(local_full.data, 0, sizeof(local_full.data));
                    if (src_id != (uint32_t)g_my_node_id) {
                        int push_ret = needs_push_fence ?
                            notify_local_qemu_push_fenced(MSG_PAGE_PUSH_FULL,
                                                          &local_full,
                                                          sizeof(local_full),
                                                          5000000ULL) :
                            notify_local_qemu_push(MSG_PAGE_PUSH_FULL,
                                                   &local_full,
                                                   sizeof(local_full));
                        if (push_ret < 0) {
                            local_qemu_push_barrier_failed = 1;
                        }
                    }
                    
                    // 广播零页：Diff类型 + ZeroFlag + 无数据
                    broadcast_to_subscribers(page, MSG_PAGE_PUSH_DIFF, log, sizeof(struct wvm_diff_log), WVM_FLAG_ZERO);
                    /*
                     * A successful commit proves the writer now holds a cached
                     * copy of this page.  Register it after broadcasting this
                     * update so future writers push invalidations/updates back
                     * to it without echoing the writer's own commit.
                     */
                    register_page_subscriber(page, src_id);
                    commit_ok = 1;
                }
                pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
            } else {
                pthread_mutex_lock(&g_dir_table_locks[lock_idx]);

                page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);

                if (!page) {
                    if (g_ops->log) g_ops->log("[Logic] Fatal: Hash Table Full for GPA %llx", gpa);
                    pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
                    log_commit_sync_decision("reject-no-page", hdr, source_node_id,
                                             gpa, commit_version, 0, off, sz, pl_len);
                    send_commit_ack_if_needed(hdr, source_node_id, 0);
                    return; // 防御性退出，防止崩溃
                }

                if (page) {
                    // [FIX] Epoch-Aware 版本校验
                    uint32_t commit_epoch = GET_EPOCH(commit_version);
                    uint32_t commit_counter = GET_COUNTER(commit_version);
                    uint32_t local_epoch = GET_EPOCH(page->version);
                    (void)local_epoch;
                    uint32_t local_counter = GET_COUNTER(page->version);
                    int full_page_overwrite = (off == 0 && sz == 4096);

                    /*
                     * F13 fix: All accepted commits must advance version.
                     * A client-originated full-page commit is not a recovery shortcut;
                     * it must carry the correct base version and satisfy the normal
                     * precondition (memory-consistency.md:237-244).
                     * Lost diffs are recovered by explicit RESYNC, not by accepting
                     * unproven client snapshots.
                     */
                    (void)full_page_overwrite;
                    if (commit_epoch != g_curr_epoch || commit_counter != local_counter) {
                        // 版本冲突！拒绝并强制同步
                        // [FIX-H8] 传 NULL 让 force_sync_client 走安全的重新查找+拷贝路径，
                        // 避免释放锁后解引用 page 指针导致的数据竞争
                        uint64_t local_version = page->version;
                        pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
                        force_sync_client(gpa, NULL, src_id);
                        log_commit_sync_decision("reject-version", hdr, source_node_id,
                                                 gpa, commit_version, local_version,
                                                 off, sz, pl_len);
                        send_commit_ack_if_needed(hdr, source_node_id, 0);
                        return;
                    }
                
                    // 应用 Diff 到主副本
                    memcpy(page->base_page_data + off, log->data, sz);
#ifndef __KERNEL__
                    if (g_shm_ptr && gpa + off + sz <= g_shm_size) {
                        memcpy((uint8_t*)g_shm_ptr + gpa + off, log->data, sz);
                    }
#endif
                    // F13 fix: All commits (full-page or diff) advance version uniformly.
                    page->version = MAKE_VERSION(g_curr_epoch, local_counter + 1);
                
                    // 广播决策
                    if (sz < SMALL_UPDATE_THRESHOLD) {
                        // 小更新：推送 Diff
                        // 需要修改 log 中的 version 为新版本号
                        log->version = WVM_HTONLL(page->version); 

                        if (src_id != (uint32_t)g_my_node_id) {
                            int push_ret = needs_push_fence ?
                                notify_local_qemu_push_fenced(MSG_PAGE_PUSH_DIFF,
                                                              log,
                                                              sizeof(struct wvm_diff_log) + sz,
                                                              5000000ULL) :
                                notify_local_qemu_push(MSG_PAGE_PUSH_DIFF,
                                                       log,
                                                       sizeof(struct wvm_diff_log) + sz);
                            if (push_ret < 0) {
                                local_qemu_push_barrier_failed = 1;
                            }
                        }
                    
                        // 广播 Diff 包
                        broadcast_to_subscribers(page, MSG_PAGE_PUSH_DIFF, log, sizeof(struct wvm_diff_log) + sz, 0);
                        register_page_subscriber(page, src_id);
                    } else {
                        // 大更新：推送全页
                        size_t push_size = sizeof(struct wvm_full_page_push);
            
                        // 参数 1 表示原子分配 (GFP_ATOMIC)，因为当前持有自旋锁
                        uint8_t *temp_buf = g_ops->alloc_packet(push_size, 1);
            
                        if (temp_buf) {
                            struct wvm_full_page_push *p = (struct wvm_full_page_push *)temp_buf;
                
                            p->gpa = WVM_HTONLL(page->gpa);
                            p->version = WVM_HTONLL(page->version);
                            // 第一次拷贝：从 Page Cache 到 临时堆内存
                            memcpy(p->data, page->base_page_data, 4096);

                            if (src_id != (uint32_t)g_my_node_id) {
                                int push_ret = needs_push_fence ?
                                    notify_local_qemu_push_fenced(MSG_PAGE_PUSH_FULL,
                                                                  p,
                                                                  push_size,
                                                                  5000000ULL) :
                                    notify_local_qemu_push(MSG_PAGE_PUSH_FULL,
                                                           p,
                                                           push_size);
                                if (push_ret < 0) {
                                    local_qemu_push_barrier_failed = 1;
                                }
                            }
                
                            // 广播函数内部会进行第二次分配和拷贝 (入队)
                            // 虽然仍有双重拷贝，但避开了栈溢出风险
                            broadcast_to_subscribers(page, MSG_PAGE_PUSH_FULL, p, push_size, 0);
                            register_page_subscriber(page, src_id);
                
                            // 立即释放临时内存
                            g_ops->free_packet(temp_buf);
                        } else {
                            if (g_ops->log) g_ops->log("[Logic] OOM skipping Full Push");
                        }
                    }
                    commit_ok = 1;
                }
                pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
            }
            if (local_qemu_push_barrier_failed) {
                if (g_ops->log) {
                    g_ops->log("[COMMIT_SYNC RX] qemu-push-barrier failed gpa=%#llx src=%u",
                               (unsigned long long)gpa, src_id);
                }
                commit_ok = 0;
            }
            log_commit_sync_decision(commit_ok ? "accept" : "reject-no-commit",
                                     hdr, source_node_id, gpa, commit_version, 0,
                                     off, sz, pl_len);
            send_commit_ack_if_needed(hdr, source_node_id, commit_ok);
            break;
        }

        // 兼容性/强制写入：直接覆盖并推送
        case MSG_MEM_WRITE: {
            // Payload 结构: GPA(8) + Data(4096)
            if (ntohs(hdr->payload_len) < sizeof(uint64_t) + 4096) return;
            
            uint64_t gpa = WVM_NTOHLL(*(uint64_t*)payload);
            void *data_ptr = (uint8_t*)payload + sizeof(uint64_t);
            
            // 1. [Security] 权限检查：只有 Owner 才能接受 Write 并返回 ACK
            if (WVM_GET_NODEID(wvm_get_directory_node_id(gpa)) != (uint32_t)g_my_node_id) {
                // 如果我不是 Owner，这是一个错误路由的包，静默丢弃或记录日志
                // 绝对不能发 ACK，否则客户端会误以为写入成功
                if (g_ops->log) g_ops->log("[Logic] Write on non-owner GPA %llx ignored", gpa);
                return;
            }
            
            uint32_t lock_idx = get_lock_idx(gpa);
            pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
            
            page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);
            int write_success = 0;

            if (page) {
                // 2. [Commit] 先落盘：写入本地内存
                memcpy(page->base_page_data, data_ptr, 4096);
#ifndef __KERNEL__
                if (g_shm_ptr && gpa + 4096 <= g_shm_size) {
                    memcpy((uint8_t*)g_shm_ptr + gpa, data_ptr, 4096);
                }
#endif
                
                // 3. [State] 更新状态：版本号递增
                page->version = MAKE_VERSION(g_curr_epoch, GET_COUNTER(page->version) + 1);
                write_success = 1; // 标记为"已提交"
                
                // 4. [Broadcast] 广播给其他订阅者
                // 注意：这里是在持锁状态下分配内存，使用 wvm_malloc (kmalloc/malloc)
                size_t push_size = sizeof(struct wvm_full_page_push);
                uint8_t *temp_buf = wvm_malloc(push_size); 
                
                if (temp_buf) {
                    struct wvm_full_page_push *p = (struct wvm_full_page_push *)temp_buf;
                    p->gpa = WVM_HTONLL(page->gpa);
                    p->version = WVM_HTONLL(page->version);
                    memcpy(p->data, page->base_page_data, 4096);
                    
                    // 广播函数内部会处理分片队列锁，这里调用是安全的
                    broadcast_to_subscribers(page, MSG_PAGE_PUSH_FULL, p, push_size, 0);
                    
                    wvm_free(temp_buf);
                }
            }
            
            pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);

            // 5. [ACK] 只有在"解锁"且"提交成功"后，才发送 ACK
            // 这保证了当客户端收到 ACK 时，数据一定已经在 Directory 的内存里了
            if (write_success) {
                size_t ack_len = sizeof(struct wvm_header); // ACK 包仅含头部
                uint8_t *ack_buf = g_ops->alloc_packet(ack_len, 1); // Atomic allocation
                
                if (ack_buf) {
                    struct wvm_header *ack_hdr = (struct wvm_header *)ack_buf;
                    ack_hdr->magic = htonl(WVM_MAGIC);
                    ack_hdr->msg_type = htons(MSG_MEM_ACK);
                    ack_hdr->payload_len = 0;
                    ack_hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
                    ack_hdr->target_id = hdr->slave_id;
                    ack_hdr->req_id = hdr->req_id; // 关键：回传请求 ID
                    ack_hdr->qos_level = 1;        // 控制信令走快车道

                    // CRC32 由 send_packet 后端自动计算，此处无需手动填
                    ack_hdr->crc32 = 0;
                    
                    g_ops->send_packet(ack_buf, ack_len, source_node_id);
                    g_ops->free_packet(ack_buf);
                }
            }
            break;
        }

        // --- Prophet 批量指令 (Type 31) ---
        case MSG_RPC_BATCH_MEMSET: {
            uint32_t payload_len = ntohs(hdr->payload_len);
            if (payload_len < sizeof(struct wvm_rpc_batch_memset)) break;

            struct wvm_rpc_batch_memset *batch = (struct wvm_rpc_batch_memset *)payload;
            uint32_t count = ntohl(batch->count);
            
            // 1. 安全检查：防止 Payload 伪造导致 OOB 攻击
            size_t required = sizeof(struct wvm_rpc_batch_memset) + count * sizeof(struct wvm_rpc_region);
            if (payload_len < required) break;

            struct wvm_rpc_region *regions = (struct wvm_rpc_region *)(batch + 1);

            // 2. [关键] 版本一致性维护
            // 在执行物理 memset 之前，必须先更新本地 Directory 表中的版本号
            for (uint32_t i = 0; i < count; i++) {
                uint64_t gpa_start = WVM_NTOHLL(regions[i].gpa);
                uint64_t len = WVM_NTOHLL(regions[i].len);
                
                // 按 4KB 页粒度强制更新本地版本记录
                for (uint64_t cur = gpa_start; cur < gpa_start + len; cur += 4096) {
                    wvm_logic_update_local_version(cur);
                }
            }

            // 3. [执行] 调用后端提供的物理执行接口
            // 逻辑核心不直接操作内存，而是通过 ops 传导
            // 后端执行入口（内核/用户态均由对应实现接管）
            handle_rpc_batch_execution(payload, payload_len);

            // 4. [自治演进] 观测者模式：Prophet 指令也算是一次活跃心跳
            update_local_topology_view(src_id, src_epoch, src_state, NULL, 0);
            break;
        }

        // --- 响应同步探测 PING ---
        case MSG_PING: {
            // 如果 req_id 是 SYNC_MAGIC，说明是 Wavelet 引擎在做同步栅栏
            // Directory 必须立刻回复 MSG_MEM_ACK 且携带同样的 SYNC_MAGIC
            
            size_t ack_len = sizeof(struct wvm_header);
            uint8_t *ack_buf = g_ops->alloc_packet(ack_len, 1); // 原子上下文分配
            
            if (ack_buf) {
                struct wvm_header *ack_hdr = (struct wvm_header *)ack_buf;
                ack_hdr->magic = htonl(WVM_MAGIC);
                ack_hdr->msg_type = htons(MSG_MEM_ACK); // 回复类型
                ack_hdr->payload_len = 0;
                ack_hdr->slave_id = htonl(WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), g_my_node_id));
                ack_hdr->target_id = hdr->slave_id;
                ack_hdr->req_id = hdr->req_id; // 关键：原样回传 SYNC_MAGIC
                ack_hdr->qos_level = 1;        // 必须走快车道，否则 AIMD 会误判延迟
                ack_hdr->epoch = htonl(g_curr_epoch);
                ack_hdr->node_state = g_my_node_state;

                // CRC 重新计算
                ack_hdr->crc32 = 0;
                ack_hdr->crc32 = htonl(calculate_crc32(ack_buf, ack_len));

                // 这里的 source_node_id 是函数的第三个参数
                g_ops->send_packet(ack_buf, ack_len, source_node_id);
                g_ops->free_packet(ack_buf);
            }
            break;
        }

        default:
            break;
    }
}

// [V29 Interface] 本地原子更新版本号
void wvm_logic_update_local_version(uint64_t gpa) {
    uint32_t lock_idx = get_lock_idx(gpa);
    pthread_mutex_lock(&g_dir_table_locks[lock_idx]);
    
    // 仅更新已存在的元数据。若页面未被追踪，说明无 Diff 历史，无需版本号。

    page_meta_t *page = DIR_FIND_OR_CREATE(gpa, lock_idx);
    if (page) {
        // [FIX] Epoch-Aware 版本更新
        uint32_t local_counter = GET_COUNTER(page->version);
        page->version = MAKE_VERSION(g_curr_epoch, local_counter + 1); 
    }
    
    pthread_mutex_unlock(&g_dir_table_locks[lock_idx]);
}

// [V29 Interface] 全网广播 RPC 包
// 基于局部视图进行扩散：
void wvm_logic_broadcast_rpc(void *full_pkt_data, int full_pkt_len, uint16_t msg_type) {
    struct wvm_header *hdr = (struct wvm_header *)full_pkt_data;
    void *payload = (void*)hdr + sizeof(struct wvm_header);
    int payload_len = full_pkt_len - sizeof(struct wvm_header);

    pthread_rwlock_rdlock(&g_view_lock);
    
    // 如果没有发现邻居，仅执行本地，无需广播
    if (g_peer_count == 0) {
        pthread_rwlock_unlock(&g_view_lock);
        return;
    }

    // 遍历局部活跃视图进行扩散
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peer_view[i].state != NODE_STATE_ACTIVE) continue;

        uint32_t target_id = g_peer_view[i].node_id;

        // 定位分片发送队列（复用 V29.5 的高性能分片队列）
        int shard_idx = target_id % NUM_BCAST_WORKERS;
        bcast_queue_shard_t *shard = &g_bcast_shards[shard_idx];

        pthread_spin_lock(&shard->lock);
        if (shard->tail + 1 - shard->head >= BCAST_Q_SIZE) {
            pthread_spin_unlock(&shard->lock);
            continue; // 队列满则跳过，由于是 P2P 扩散，其他节点会有冗余路径
        }

        // 分配并拷贝
        void *data_copy = malloc(payload_len);
        if (data_copy) {
            memcpy(data_copy, payload, payload_len);
            broadcast_task_t *t = &shard->queue[shard->tail & BCAST_Q_MASK];
            t->msg_type = msg_type;
            t->target_id = WVM_ENCODE_ID(WVM_CURRENT_VM_ID(), target_id);
            t->len = payload_len;
            t->data_ptr = data_copy;
            
            // 关键：在 Header 中标记当前 Epoch
            hdr->epoch = g_curr_epoch;
            hdr->node_state = g_my_node_state;

            __sync_synchronize();
            shard->tail++;
        }
        pthread_spin_unlock(&shard->lock);
    }
    pthread_rwlock_unlock(&g_view_lock);
}

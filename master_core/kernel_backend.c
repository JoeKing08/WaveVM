/*
 * [IDENTITY] Kernel Backend - The Bare-Metal Engine
 * ---------------------------------------------------------------------------
 * 物理角色：宿主机内核中的"内存直通总线"。
 * 职责边界：
 * 1. 实现异步缺页等待队列，通过网络中断直接唤醒 vCPU。
 * 2. 实现内核态脏页捕获 (page_mkwrite)，在软中断中完成 Diff 计算。
 * 3. 管理 Radix-Tree 索引，实现对远程 PUSH 的零拷贝应用。
 * 
 * [禁止事项]
 * - 严禁在 sigsegv 路径上使用阻塞型互斥锁 (Mutex)，必须使用 spinlock_irqsave。
 * - 严禁绕过 unmap_mapping_range 直接修改 PTE。
 * ---------------------------------------------------------------------------
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/pseudo_fs.h>
#include <linux/mount.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/nmi.h>      
#include <linux/delay.h>    
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
#include <asm/barrier.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/kthread.h>
#include <linux/wait.h>
#include <asm/byteorder.h>
#include <linux/radix-tree.h>
#include <linux/highmem.h>
#include <linux/random.h>
#include <linux/pagemap.h> 
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/hash.h>

#include "../common_include/wavevm_ioctl.h"
#include "../common_include/wavevm_protocol.h"
#include "unified_driver.h"
#include "logic_core.h" 

#define DRIVER_NAME "wavevm"
#define TX_RING_SIZE 2048
#define TX_SLOT_SIZE 65535
#define MAX_WVM_SLOTS 32

struct wvm_mem_slot {
    uint64_t start_gpa;
    uint64_t size;
    uint64_t host_offset;
    bool active;
};

/* Module-global VM identity removed (baseline §14 / kernel-accelerator.md).
 * Final-path identity comes from the explicit per-context identity only.
 */

/*
 * A01: Task-bound active context (NOT per-CPU). Survives schedule()/CPU
 * migration across sleepable fault/ioctl waits. Hash lock is held only for
 * push/pop — never across sleepable ops or network I/O (no global-serial fix).
 * Sleepable paths also pass ctx explicitly into k_*_ctx helpers.
 */
#define WVM_TASK_CTX_BITS 6
#define WVM_TASK_CTX_SLOTS (1u << WVM_TASK_CTX_BITS)
struct wvm_task_ctx_slot {
	struct task_struct *task;
	struct wvm_kernel_context *ctx;
};
static struct wvm_task_ctx_slot wvm_task_ctx_slots[WVM_TASK_CTX_SLOTS];
static DEFINE_SPINLOCK(wvm_task_ctx_lock);

static int module_service_port = 9000;
module_param(module_service_port, int, 0644);
static int module_local_slave_port = 9001;
module_param(module_local_slave_port, int, 0644);

static struct kmem_cache *wvm_pkt_cache = NULL;

/*
 * Per-VM kernel context boundary.
 *
 * Registry + QUERY_CAPS + BIND advertise/enforce
 * WVM_KERNEL_MAX_CONCURRENT_CONTEXTS after A01–A04 isolation evidence.
 * Data-plane lookups resolve through the bound context; there is no module-
 * global VM identity mirror on the final path.
 */
struct wvm_kernel_context_identity {
    uint32_t vm_id;
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t candidate_manifest_digest[WVM_KERNEL_DIGEST_BYTES];
    uint8_t capability_profile_digest[WVM_KERNEL_DIGEST_BYTES];
    uint8_t activation_fence[WVM_KERNEL_FENCE_BYTES];
    struct wvm_ioctl_route_snapshot_key route_snapshot_key;
};

struct id_pool_t;
struct req_ctx_t;
struct wvm_kernel_transport;

struct wvm_kernel_context {
    struct wvm_kernel_context_identity identity;
    /* A04: node-runtime primary vnode for this context (not g_my_node_id). */
    uint32_t local_vnode_id;
    int active;
    atomic_t refs;
    struct hlist_node hash_node;  /* For registry hash table */
    struct work_struct destroy_work; /* A03: last put from atomic → deferred */
    uint32_t kernel_epoch;
    struct rw_semaphore mapping_sem;
    struct address_space *mapping;
    struct file *priv_file; /* F3: per-context private address_space file */
    int priv_fs_pinned;
    atomic_t mapping_file_refs; /* F3: mmap owners sharing context->mapping */
    atomic_t file_attaches; /* F3: BIND owners; last detach clears route */
    struct wvm_mem_slot mem_slots[MAX_WVM_SLOTS];
    wait_queue_head_t irq_wait_queue;
    atomic_t irq_pending;
    struct id_pool_t __percpu *id_pool;
    struct req_ctx_t *req_ctx;
    size_t req_ctx_count;
    struct radix_tree_root page_tree;
    spinlock_t page_tree_lock;
    struct wvm_kernel_transport *transport;
    struct sockaddr_in gateway_table[WVM_MAX_GATEWAYS];

    /* F12 fix: Per-VM directory table and route context */
    void *dir_table;  /* Per-VM directory authority (replaces g_dir_table) */
    void *dir_locks;  /* Per-VM GPA shard locks (concurrency; not authority) */
    void *route_context;  /* Per-VM routing context (replaces g_logic_route_context) */

    /* Per-context dirty-commit queue (was shared on g_module_transport). */
    struct list_head diff_queue;
    /*
     * R04: commits that exhausted their retry budget.  The unique pre-image is
     * retained here (never silently dropped); the context records the failure
     * so a later teardown/diagnostic can see it.
     */
    struct list_head failed_diffs;
    unsigned int failed_diff_count;
    int diff_failure;
    spinlock_t diff_lock;
};

struct wvm_kernel_file_context {
    int bound;
    struct wvm_kernel_context *context;
    struct address_space *mapping;
    struct wvm_kernel_context_identity identity;
};

static DEFINE_MUTEX(g_context_mutex);

/*
 * Multi-context registry for concurrent VM support.
 * Hash table to handle collisions properly, with reference counting.
 */
#define WVM_CONTEXT_HASH_BITS 4
#define WVM_CONTEXT_HASH_SIZE (1 << WVM_CONTEXT_HASH_BITS)
static DEFINE_HASHTABLE(g_context_registry, WVM_CONTEXT_HASH_BITS);
static int g_active_context_count = 0;

/*
 * Module-wide UDP socket + TX rings (context-tagged slots). Diff queues are
 * per-context. Workers may remain module-wide only with explicit context refs.
 */
static struct wvm_kernel_transport *g_module_transport;
static wait_queue_head_t g_diff_wq;
static atomic_t g_diff_pending;

/* F3: per-context private address_space (miscdevice inode is shared). */
#define WVM_FS_MAGIC 0x57564D41u /* WVMA */
static struct vfsmount *wvm_mnt;
static int wvm_mnt_count;
static DEFINE_MUTEX(wvm_mnt_lock);

static int wvm_init_fs_context(struct fs_context *fc)
{
    struct pseudo_fs_context *ctx = init_pseudo(fc, WVM_FS_MAGIC);
    if (!ctx)
        return -ENOMEM;
    return 0;
}

static const struct file_operations wvm_mem_fops;

static struct file_system_type wvm_fs_type = {
    .name = "wavevm",
    .init_fs_context = wvm_init_fs_context,
    .kill_sb = kill_anon_super,
};


static int wvm_context_ensure_private_mapping(struct wvm_kernel_context *ctx)
{
    struct inode *inode;
    struct file *file;
    int err;

    if (!ctx)
        return -EINVAL;
    if (ctx->priv_file && ctx->mapping)
        return 0;

    mutex_lock(&wvm_mnt_lock);
    if (ctx->priv_file && ctx->mapping) {
        mutex_unlock(&wvm_mnt_lock);
        return 0;
    }

    err = simple_pin_fs(&wvm_fs_type, &wvm_mnt, &wvm_mnt_count);
    if (err) {
        mutex_unlock(&wvm_mnt_lock);
        return err;
    }

    inode = alloc_anon_inode(wvm_mnt->mnt_sb);
    if (IS_ERR(inode)) {
        err = PTR_ERR(inode);
        simple_release_fs(&wvm_mnt, &wvm_mnt_count);
        mutex_unlock(&wvm_mnt_lock);
        return err;
    }
    inode->i_mode = S_IFREG | S_IRUSR | S_IWUSR;
    mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER_MOVABLE);

    file = alloc_file_pseudo(inode, wvm_mnt, "[wavevm_mem]",
                             O_RDWR, &wvm_mem_fops);
    if (IS_ERR(file)) {
        err = PTR_ERR(file);
        iput(inode);
        simple_release_fs(&wvm_mnt, &wvm_mnt_count);
        mutex_unlock(&wvm_mnt_lock);
        return err;
    }
    file->f_mode |= FMODE_CAN_READ | FMODE_CAN_WRITE;
    file->private_data = ctx;
    ctx->priv_file = file;
    ctx->mapping = file->f_mapping;
    ctx->priv_fs_pinned = 1;
    mutex_unlock(&wvm_mnt_lock);
    return 0;
}

static void wvm_context_release_private_mapping(struct wvm_kernel_context *ctx)
{
    if (!ctx)
        return;
    if (ctx->priv_file) {
        /* Drop dangling ctx pointer before async __fput; VMA may still hold
         * a file ref until munmap. Fault path must not UAF after destroy. */
        ctx->priv_file->private_data = NULL;
        fput(ctx->priv_file);
        ctx->priv_file = NULL;
    }
    ctx->mapping = NULL;
    if (ctx->priv_fs_pinned) {
        simple_release_fs(&wvm_mnt, &wvm_mnt_count);
        ctx->priv_fs_pinned = 0;
    }
}


// --- [V29 Wavelet] 内核态脏区捕获与Diff提交结构 ---

// 记录一个正在被写入的页面
struct diff_task_t {
    struct list_head list;
    struct wvm_kernel_context *context;
    struct page *page;      // 目标物理页
    void *pre_image;        // 4KB 快照 (修改前的数据)
    uint64_t gpa;           // Guest Physical Address
    uint64_t timestamp;     // 记录时间，用于防抖
    uint8_t send_retries;   /* R04/A02: bounded resend of unique diff */
};

// --- ID 管理系统 ---
#define BITS_PER_CPU_ID 16
#define MAX_IDS_PER_CPU (1 << BITS_PER_CPU_ID) 
#define CPU_ID_SHIFT    16                     

struct id_pool_t {
    uint32_t *ids;
    uint32_t head;
    uint32_t tail;
    spinlock_t lock;
};

// 请求上下文：增加等待队列以支持异步休眠
struct req_ctx_t {
    void *rx_buffer;
    uint32_t generation;
    uint32_t max_len; // [FIX-G3] 记录 rx_buffer 最大可用长度
    volatile int done;
    wait_queue_head_t wq; // [New] 内核任务在此休眠
    struct task_struct *waiter; // [New] 记录等待的任务 (用于调试或唤醒检查)
};

// [V29 Final Fix] 内核态页面元数据
// 用于在 Radix Tree 中同时存储物理页指针和版本号
typedef struct {
    struct page *page;
    uint64_t version;
    struct rcu_head rcu;
    
    // 内核原生 sk_buff 队列，自带 spinlock，用于缓存乱序到达的包
    struct sk_buff_head reorder_q; 
} kvm_page_meta_t;

// --- QoS 发送队列 ---
struct tx_slot_t {
    struct wvm_kernel_context *context;  /* Per-VM context for this TX */
    int len;
    uint32_t target_id;
    uint8_t data[TX_SLOT_SIZE];
};

struct wvm_tx_ring_t {
    struct tx_slot_t *slots;
    uint32_t head; 
    uint32_t tail; 
    spinlock_t lock;
    atomic_t pending_count;
};

struct wvm_kernel_transport {
    int service_port;
    int local_slave_port;
    struct socket *socket;
    /* gateway_table moved to per-context in wvm_kernel_context */
    struct wvm_tx_ring_t fast_ring;
    struct wvm_tx_ring_t slow_ring;
    struct task_struct *tx_thread;
    wait_queue_head_t tx_wq;
    struct task_struct *committer_thread;
    refcount_t refs; /* contexts + module hold refs */
};

// 定义工作项结构，用于把参数带到 Workqueue 里
struct wvm_inval_work {
    struct work_struct work;
    struct wvm_kernel_context *context;
    uint64_t gpa;
};

/* Forward declaration */
static void wvm_kernel_destroy_context(struct wvm_kernel_context *ctx);
static void wvm_kernel_put_context(struct wvm_kernel_context *ctx);
static void wvm_context_destroy_work_fn(struct work_struct *work);

static u32 wvm_context_hash_key(uint32_t vm_id, uint64_t node_instance_id)
{
    return vm_id ^ (u32)node_instance_id ^ (u32)(node_instance_id >> 32);
}


/*
 * Find and reference an active context by vm_id. Caller must hold g_context_mutex.
 * Returns context with refs incremented, or NULL if not found.
 */
static struct wvm_kernel_context *wvm_kernel_find_context_keyed_locked(
    uint32_t vm_id, uint64_t node_instance_id)
{
    struct wvm_kernel_context *ctx;

    hash_for_each_possible(g_context_registry, ctx, hash_node,
                           wvm_context_hash_key(vm_id, node_instance_id)) {
        if (ctx->active && ctx->identity.vm_id == vm_id &&
            ctx->identity.node_instance_id == node_instance_id) {
            atomic_inc(&ctx->refs);
            return ctx;
        }
    }
    return NULL;
}

/*
 * Find any active context for vm_id. Full-table walk because F11 publishes
 * under composite (vm_id, node_instance_id). Ambiguous multi-match → NULL.
 */
static struct wvm_kernel_context *wvm_kernel_find_context_locked(uint32_t vm_id)
{
    struct wvm_kernel_context *ctx;
    struct wvm_kernel_context *first = NULL;
    int bkt;

    hash_for_each(g_context_registry, bkt, ctx, hash_node) {
        if (!ctx->active || ctx->identity.vm_id != vm_id)
            continue;
        if (first)
            return NULL;
        first = ctx;
    }
    if (first) {
        atomic_inc(&first->refs);
        return first;
    }
    return NULL;
}

/*
 * F11: RCU RX lookup. Prefer (vm_id, physical_node_id) when node_id present;
 * otherwise single active match for vm_id. Softirq-safe.
 */
static struct wvm_kernel_context *wvm_kernel_find_context_rcu(
    uint32_t vm_id, uint32_t physical_node_id)
{
    struct wvm_kernel_context *ctx;
    struct wvm_kernel_context *matched = NULL;
    int bkt;

    rcu_read_lock();
    hash_for_each_rcu(g_context_registry, bkt, ctx, hash_node) {
        if (!ctx->active || ctx->identity.vm_id != vm_id)
            continue;
        if (physical_node_id != 0 &&
            ctx->identity.physical_node_id == physical_node_id) {
            if (atomic_inc_not_zero(&ctx->refs)) {
                rcu_read_unlock();
                return ctx;
            }
            continue;
        }
        if (physical_node_id == 0) {
            if (matched) {
                matched = NULL;
                break;
            }
            matched = ctx;
        }
    }
    if (matched && atomic_inc_not_zero(&matched->refs)) {
        rcu_read_unlock();
        return matched;
    }
    rcu_read_unlock();
    return NULL;
}

static struct wvm_kernel_context *wvm_kernel_find_context(uint32_t vm_id)
{
    struct wvm_kernel_context *ctx;

    mutex_lock(&g_context_mutex);
    ctx = wvm_kernel_find_context_locked(vm_id);
    mutex_unlock(&g_context_mutex);
    return ctx;
}

static void wvm_context_destroy_work_fn(struct work_struct *work)
{
    struct wvm_kernel_context *ctx =
        container_of(work, struct wvm_kernel_context, destroy_work);

    /* Process context: mutex / synchronize_rcu / mapping teardown OK. */
    wvm_kernel_destroy_context(ctx);
}

/*
 * A03: last put must not run sleepable destroy from softirq/atomic (RX path).
 * Defer to workqueue when refs hit 0 outside process context.
 */
static void wvm_kernel_put_context(struct wvm_kernel_context *ctx)
{
    if (!ctx)
        return;
    if (!atomic_dec_and_test(&ctx->refs))
        return;
    if (in_atomic() || irqs_disabled()) {
        INIT_WORK(&ctx->destroy_work, wvm_context_destroy_work_fn);
        schedule_work(&ctx->destroy_work);
        return;
    }
    wvm_kernel_destroy_context(ctx);
}

/*
 * Pure allocator: caller must hold g_context_mutex and handle registry publish.
 * Returns with refcount=1, active=0. Caller is responsible for:
 *   - hash_add(g_context_registry, &ctx->hash_node, vm_id)
 *   - g_active_context_count++
 *   - setting ctx->active = 1 after full initialization
 */
static struct wvm_kernel_context *wvm_kernel_allocate_context(uint32_t vm_id)
{
    struct wvm_kernel_context *ctx;
    int cpu;
    uint32_t i;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return NULL;

    ctx->identity.vm_id = vm_id;
    ctx->local_vnode_id = 0;
    atomic_set(&ctx->refs, 1);
    atomic_set(&ctx->mapping_file_refs, 0);
    atomic_set(&ctx->file_attaches, 0);
    ctx->active = 0;  /* Caller sets to 1 after publish */
    if (!g_module_transport ||
        !refcount_inc_not_zero(&g_module_transport->refs)) {
        kfree(ctx);
        return NULL;
    }
    ctx->transport = g_module_transport;
    INIT_LIST_HEAD(&ctx->diff_queue);
    INIT_LIST_HEAD(&ctx->failed_diffs);
    spin_lock_init(&ctx->diff_lock);
    INIT_RADIX_TREE(&ctx->page_tree, GFP_ATOMIC);
    spin_lock_init(&ctx->page_tree_lock);
    init_rwsem(&ctx->mapping_sem);
    init_waitqueue_head(&ctx->irq_wait_queue);
    atomic_set(&ctx->irq_pending, 0);

    /*
     * Runtime-sized: nr_cpu_ids * MAX_IDS_PER_CPU.
     * The request namespace belongs to each kernel context.
     */
    ctx->req_ctx_count = (size_t)nr_cpu_ids * (size_t)MAX_IDS_PER_CPU;
    ctx->req_ctx = vzalloc(sizeof(struct req_ctx_t) * ctx->req_ctx_count);
    if (!ctx->req_ctx)
        goto fail_ctx;
    for (size_t j = 0; j < ctx->req_ctx_count; j++)
        init_waitqueue_head(&ctx->req_ctx[j].wq);

    ctx->id_pool = alloc_percpu(struct id_pool_t);
    if (!ctx->id_pool)
        goto fail_req_ctx;

    /* F09 fix: populate per-CPU ID pools with usable IDs [0..MAX_IDS_PER_CPU) */
    for_each_online_cpu(cpu) {
        struct id_pool_t *pool = per_cpu_ptr(ctx->id_pool, cpu);
        spin_lock_init(&pool->lock);
        pool->ids = vzalloc(sizeof(uint32_t) * MAX_IDS_PER_CPU);
        if (!pool->ids)
            goto fail_id_pool;
        /* Populate the free list with all valid local IDs */
        for (i = 0; i < MAX_IDS_PER_CPU; i++) {
            pool->ids[i] = i;
        }
        pool->head = 0;
        pool->tail = MAX_IDS_PER_CPU;  /* All IDs available */
    }

    ctx->dir_table = wvm_logic_alloc_dir_table();
    if (!ctx->dir_table)
        goto fail_id_pool;
    ctx->dir_locks = wvm_logic_alloc_dir_locks();
    if (!ctx->dir_locks) {
        wvm_logic_free_dir_table(ctx->dir_table);
        ctx->dir_table = NULL;
        goto fail_id_pool;
    }
    ctx->route_context = wvm_logic_alloc_route_context();
    if (!ctx->route_context) {
        wvm_logic_free_dir_locks(ctx->dir_locks);
        ctx->dir_locks = NULL;
        wvm_logic_free_dir_table(ctx->dir_table);
        ctx->dir_table = NULL;
        goto fail_id_pool;
    }

    /* No registry publish here; caller does hash_add + g_active_context_count++ */
    return ctx;

fail_id_pool:
    for_each_possible_cpu(cpu) {
        struct id_pool_t *pool = per_cpu_ptr(ctx->id_pool, cpu);
        if (pool && pool->ids)
            vfree(pool->ids);
    }
    free_percpu(ctx->id_pool);
fail_req_ctx:
    vfree(ctx->req_ctx);
fail_ctx:
    if (ctx->transport)
        refcount_dec(&ctx->transport->refs);
    kfree(ctx);
    return NULL;
}


static void wvm_drain_context_diff_tasks(struct wvm_kernel_context *ctx)
{
    LIST_HEAD(queued);
    LIST_HEAD(failed);
    struct diff_task_t *task, *tmp;
    int n_queued = 0;

    if (!ctx)
        return;
    spin_lock_bh(&ctx->diff_lock);
    list_splice_init(&ctx->diff_queue, &queued);
    list_splice_init(&ctx->failed_diffs, &failed);
    ctx->failed_diff_count = 0;
    spin_unlock_bh(&ctx->diff_lock);

    /*
     * diff_queue tasks hold a mkwrite context get until completion/drain.
     * failed_diffs retain pre-image only — they must NOT pin ctx->refs, or
     * last-unbind can never reach destroy (circular: destroy drains these).
     */
    list_for_each_entry_safe(task, tmp, &queued, list) {
        list_del(&task->list);
        n_queued++;
        if (task->pre_image)
            vfree(task->pre_image);
        if (task->page)
            put_page(task->page);
        wvm_kernel_put_context(task->context);
        kfree(task);
    }
    list_for_each_entry_safe(task, tmp, &failed, list) {
        list_del(&task->list);
        if (task->pre_image)
            vfree(task->pre_image);
        if (task->page)
            put_page(task->page);
        /* no put_context — permanent-fail path already dropped the get */
        kfree(task);
    }
    if (n_queued)
        atomic_sub(n_queued, &g_diff_pending);
}

static void wvm_kernel_destroy_context(struct wvm_kernel_context *ctx)
{
    int cpu;

    if (!ctx)
        return;

    /* Drop pending wavelet tasks before touching pages / mapping. */
    wvm_drain_context_diff_tasks(ctx);

    mutex_lock(&g_context_mutex);
    if (ctx->active) {
        hash_del_rcu(&ctx->hash_node);  /* F11: RCU-safe removal */
        g_active_context_count--;
        ctx->active = 0;
    }
    mutex_unlock(&g_context_mutex);

    /* F11: Wait for RCU grace period before freeing context.
     * This ensures any concurrent RCU readers in sk_data_ready finish. */
    synchronize_rcu();

    /*
     * Page ownership: fault keeps alloc ref on meta; vm_insert_page adds VMA
     * ref. Write-protect unmap drops VMA refs; meta ref keeps the page alive
     * for re-fault. Unmap first, then put_page(meta->page) + free meta.
     */
    down_write(&ctx->mapping_sem);
    if (ctx->mapping) {
        unmap_mapping_range(ctx->mapping, 0, (~(loff_t)0), 1);
    }
    atomic_set(&ctx->mapping_file_refs, 0);
    up_write(&ctx->mapping_sem);

    /* Clean up id_pool */
    if (ctx->id_pool) {
        for_each_possible_cpu(cpu) {
            struct id_pool_t *pool = per_cpu_ptr(ctx->id_pool, cpu);
            if (pool && pool->ids)
                vfree(pool->ids);
        }
        free_percpu(ctx->id_pool);
        ctx->id_pool = NULL;
    }

    /* Clean up req_ctx */
    if (ctx->req_ctx) {
        vfree(ctx->req_ctx);
        ctx->req_ctx = NULL;
    }

    /* Clean up radix tree: delete slots, put_page meta owns, free meta.
     * Small batches keep stack under frame-size warning. */
    {
        struct radix_tree_iter iter;
        void **slot;
        unsigned long indices_to_delete[16];
        kvm_page_meta_t *metas_to_free[16];
        int count = 0;
        int i;
        int more = 1;

        while (more) {
            count = 0;
            spin_lock(&ctx->page_tree_lock);
            radix_tree_for_each_slot(slot, &ctx->page_tree, &iter, 0) {
                indices_to_delete[count] = iter.index;
                metas_to_free[count] = radix_tree_deref_slot(slot);
                count++;
                if (count >= 16)
                    break;
            }
            for (i = 0; i < count; i++)
                radix_tree_delete(&ctx->page_tree, indices_to_delete[i]);
            more = (count >= 16);
            spin_unlock(&ctx->page_tree_lock);
            for (i = 0; i < count; i++) {
                if (!metas_to_free[i])
                    continue;
                skb_queue_purge(&metas_to_free[i]->reorder_q);
                /* meta owns one page ref (survives write-protect unmap). */
                if (metas_to_free[i]->page)
                    put_page(metas_to_free[i]->page);
                kfree(metas_to_free[i]);
            }
            if (count == 0)
                break;
        }
    }

    if (ctx->dir_table) {
        wvm_logic_free_dir_table(ctx->dir_table);
        ctx->dir_table = NULL;
    }
    if (ctx->dir_locks) {
        wvm_logic_free_dir_locks(ctx->dir_locks);
        ctx->dir_locks = NULL;
    }
    if (ctx->route_context) {
        wvm_logic_free_route_context(ctx->route_context);
        ctx->route_context = NULL;
    }

    if (ctx->transport) {
        refcount_dec(&ctx->transport->refs);
        ctx->transport = NULL;
    }

    wvm_context_release_private_mapping(ctx);
    kfree(ctx);
}

/*
 * A01: Task-bound active context for logic_core / g_ops shims.
 * Sleepable fault paths pass ctx explicitly via k_*_ctx; this table only
 * bridges code that still resolves through wvm_kernel_active_*().
 * Returns WITHOUT taking a ref (caller lifetime covers the op).
 */
static struct wvm_kernel_context *wvm_active_context(void)
{
    struct wvm_kernel_context *ctx = NULL;
    unsigned long flags;
    unsigned slot = hash_ptr(current, WVM_TASK_CTX_BITS);
    unsigned i;

    spin_lock_irqsave(&wvm_task_ctx_lock, flags);
    for (i = 0; i < WVM_TASK_CTX_SLOTS; i++) {
        unsigned idx = (slot + i) & (WVM_TASK_CTX_SLOTS - 1);
        if (wvm_task_ctx_slots[idx].task == current) {
            ctx = wvm_task_ctx_slots[idx].ctx;
            break;
        }
        if (!wvm_task_ctx_slots[idx].task)
            break;
    }
    spin_unlock_irqrestore(&wvm_task_ctx_lock, flags);
    return ctx;
}

static struct wvm_kernel_transport *wvm_active_transport(void)
{
    struct wvm_kernel_context *context = wvm_active_context();

    return context ? context->transport : NULL;
}

static void wvm_set_active_context(struct wvm_kernel_context *ctx)
{
    unsigned long flags;
    unsigned slot = hash_ptr(current, WVM_TASK_CTX_BITS);
    unsigned i;
    int placed = 0;

    spin_lock_irqsave(&wvm_task_ctx_lock, flags);
    for (i = 0; i < WVM_TASK_CTX_SLOTS; i++) {
        unsigned idx = (slot + i) & (WVM_TASK_CTX_SLOTS - 1);
        if (wvm_task_ctx_slots[idx].task == current ||
            !wvm_task_ctx_slots[idx].task) {
            wvm_task_ctx_slots[idx].task = ctx ? current : NULL;
            wvm_task_ctx_slots[idx].ctx = ctx;
            placed = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&wvm_task_ctx_lock, flags);
    if (!placed && ctx)
        pr_warn_ratelimited("wavevm: task-ctx table full; explicit ctx paths required\n");
}

static void wvm_clear_active_context(void)
{
    wvm_set_active_context(NULL);
}

/* A04: prefer context-local vnode over module-global g_my_node_id. */
static uint32_t wvm_ctx_local_vnode(const struct wvm_kernel_context *ctx)
{
    extern int g_my_node_id;

    if (ctx && ctx->local_vnode_id)
        return ctx->local_vnode_id;
    return (uint32_t)g_my_node_id;
}

/*
 * Compat send-target helper. Production nonzero VMs use bare node targets
 * (FULL_VMID on the header via wvm_header_pack_src). Legacy vm_id==0 keeps
 * ENCODE_ID. Never silently truncate a nonzero vm into the 8-bit pack.
 */
static int wvm_wire_encode_id(uint32_t vm_id, uint32_t node_id, uint32_t *out)
{
    if (!out)
        return -EINVAL;
    *out = wvm_wire_target(vm_id, node_id);
    return 0;
}

static struct wvm_kernel_context *wvm_context_for_file(
    const struct wvm_kernel_file_context *file_context)
{
    /*
     * A01 fail-closed: IOCTL/mmap must use the FD's bound context only.
     * Never fall back to the task-active slot — that would let an unbound
     * (or wrong) FD operate on another VM's context.
     */
    if (file_context && file_context->bound && file_context->context)
        return file_context->context;
    return NULL;
}

static struct wvm_kernel_context *wvm_context_from_vma(
    const struct vm_area_struct *vma)
{
    struct file *filp;
    struct wvm_kernel_file_context *file_context;

    if (!vma || !vma->vm_file)
        return NULL;
    filp = vma->vm_file;
    /* Per-context mem file: private_data is the kernel context itself. */
    if (filp->f_op == &wvm_mem_fops)
        return filp->private_data;
    file_context = filp->private_data;
    return wvm_context_for_file(file_context);
}

/*
 * Active-context VM id only. No module-global mirror. Prefer passing
 * context->identity.vm_id explicitly on final TX/RX paths.
 */
uint32_t wvm_kernel_current_vm_id(void)
{
    struct wvm_kernel_context *context = wvm_active_context();

    if (context)
        return READ_ONCE(context->identity.vm_id);
    return 0;
}
EXPORT_SYMBOL_GPL(wvm_kernel_current_vm_id);

void *wvm_kernel_active_dir_table(void)
{
    struct wvm_kernel_context *context = wvm_active_context();

    return context ? context->dir_table : NULL;
}
EXPORT_SYMBOL_GPL(wvm_kernel_active_dir_table);

void *wvm_kernel_active_dir_locks(void)
{
    struct wvm_kernel_context *context = wvm_active_context();

    return context ? context->dir_locks : NULL;
}
EXPORT_SYMBOL_GPL(wvm_kernel_active_dir_locks);

void *wvm_kernel_active_route_context(void)
{
    struct wvm_kernel_context *context = wvm_active_context();

    return context ? context->route_context : NULL;
}
EXPORT_SYMBOL_GPL(wvm_kernel_active_route_context);

static int init_ring(struct wvm_tx_ring_t *ring) {
    ring->slots = vmalloc(sizeof(struct tx_slot_t) * TX_RING_SIZE);
    if (!ring->slots)
        return -ENOMEM;
    ring->head = ring->tail = 0;
    spin_lock_init(&ring->lock);
    atomic_set(&ring->pending_count, 0);
    return 0;
}

static void wvm_transport_stop(struct wvm_kernel_transport *transport)
{
    struct task_struct *tx, *committer;

    if (!transport)
        return;
    /* Drop socket callbacks first so softirq cannot re-enter send paths. */
    if (transport->socket && transport->socket->sk) {
        transport->socket->sk->sk_data_ready = NULL;
        transport->socket->sk->sk_user_data = NULL;
        /* Ensure in-flight softirq RX sees NULL before we tear threads. */
        synchronize_rcu();
    }
    wake_up_interruptible(&transport->tx_wq);
    wake_up_interruptible(&g_diff_wq);
    tx = transport->tx_thread;
    transport->tx_thread = NULL;
    /* kthread_stop on a task that already exited races to NULL deref. */
    if (tx && !IS_ERR_OR_NULL(tx))
        kthread_stop(tx);
    committer = transport->committer_thread;
    transport->committer_thread = NULL;
    if (committer && !IS_ERR_OR_NULL(committer))
        kthread_stop(committer);
    /* Diff tasks live on per-context queues; drained in context destroy. */
    if (transport->fast_ring.slots) {
        vfree(transport->fast_ring.slots);
        transport->fast_ring.slots = NULL;
    }
    if (transport->slow_ring.slots) {
        vfree(transport->slow_ring.slots);
        transport->slow_ring.slots = NULL;
    }
    if (transport->socket) {
        transport->socket->sk->sk_data_ready = NULL;
        transport->socket->sk->sk_user_data = NULL;
        sock_release(transport->socket);
        transport->socket = NULL;
    }
}

// --- 工作线程回调（运行在进程上下文，安全！）---
static void wvm_inval_work_fn(struct work_struct *work) {
    struct wvm_inval_work *iw = container_of(work, struct wvm_inval_work, work);
    struct wvm_kernel_context *context = iw->context;

    /* Prefer per-file mapping when set; fall back to context mapping. */
    down_read(&context->mapping_sem);
    if (context->mapping) {
        loff_t offset = (loff_t)iw->gpa;
        unmap_mapping_range(context->mapping, offset, PAGE_SIZE, 1);
    }
    up_read(&context->mapping_sem);

    /* F3: drop the ref taken in schedule_async_unmap. */
    wvm_kernel_put_context(context);
    kfree(iw);
}

/* Schedulable from atomic context. Holds a context ref across the work. */
static void schedule_async_unmap(struct wvm_kernel_context *context,
                                 uint64_t gpa) {
    struct wvm_inval_work *iw;

    if (!context)
        return;
    iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
    if (!iw) {
        printk(KERN_ERR "[WVM] OOM scheduling unmap for GPA %llx\n", gpa);
        return;
    }
    if (!atomic_inc_not_zero(&context->refs)) {
        kfree(iw);
        return;
    }
    INIT_WORK(&iw->work, wvm_inval_work_fn);
    iw->context = context;
    iw->gpa = gpa;
    schedule_work(&iw->work);
}

// --- 辅助函数 ---
static uint64_t k_get_time_us(void) { return ktime_to_us(ktime_get()); }
static void k_touch_watchdog(void) { touch_nmi_watchdog(); }
static int k_is_atomic_context(void) { return in_atomic() || irqs_disabled(); }
static void k_cpu_relax(void) { cpu_relax(); }
static uint64_t k_time_diff_us(uint64_t start) {
    uint64_t now = k_get_time_us();
    return (now >= start) ? (now - start) : ((uint64_t)(-1) - start + now);
}

static void WVM_PRINTF_LIKE(1, 2) k_log(const char *fmt, ...) {
    struct va_format vaf;
    va_list args;
    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;
    printk(KERN_INFO "[WVM]: %pV\n", &vaf);
    va_end(args);
}

static void k_get_random(uint32_t *val) { get_random_bytes(val, sizeof(uint32_t)); }
static void k_yield_short(void) { if (!in_atomic()) msleep(1); else udelay(50); }

// --- 内存操作 ---
static void* k_alloc_large_table(size_t size) { return vzalloc(size); }
static void k_free_large_table(void *ptr) { vfree(ptr); }
static void* k_alloc_packet(size_t size, int atomic) {
    gfp_t flags = atomic ? GFP_ATOMIC : GFP_KERNEL;
    if (wvm_pkt_cache && size <= (sizeof(struct wvm_header) + 4096)) {
        return kmem_cache_alloc(wvm_pkt_cache, flags);
    }
    return kmalloc(size, flags);
}
static void k_free_packet(void *ptr) {
    if (!ptr) return;
    /*
     * Kernel >= 6.x no longer exposes slab cache pointer in struct page.
     * kfree() can free both kmalloc() and slab objects, and is sufficient here.
     */
    kfree(ptr);
}
static void k_fetch_page(uint64_t gpa, void *buf) {} // Deprecated by logic_core

/* 
 * [物理意图] 从内核索引中“抹除”特定 GPA 的元数据存在。
 * [关键逻辑] 在原子上下文中将页面从 Radix-Tree 中摘除，并使用 kfree_rcu 安全回收乱序缓冲区。
 * [后果] 这是 MESI 协议在内核态落地的第一步，它切断了后续 PUSH 包对该物理页的自动更新链路。
 */
static void k_invalidate_meta_atomic(struct wvm_kernel_context *context,
                                     uint64_t gpa) {
    spin_lock(&context->page_tree_lock);
    kvm_page_meta_t *meta =
        radix_tree_delete(&context->page_tree, gpa >> PAGE_SHIFT);
    spin_unlock(&context->page_tree_lock);
    
    if (meta) {
        // 必须释放队列中所有积压的 skb，否则内存泄漏
        skb_queue_purge(&meta->reorder_q);
        
        // 等待所有 RCU 读者读完后释放结构体
        kfree_rcu(meta, rcu);
    }
}

/* 
 * [物理意图] 实现“零锁竞争”的分布式请求 ID 分配。
 * [关键逻辑] 采用 Per-CPU 变量技术，每个逻辑核拥有独立的 ID 池。利用 Generation 机制检测网络乱序导致的 ABA 冲突。
 * [后果] 这一步是 Mode A 支持百万 TPS 的基石。它消除了传统分布式系统中全局 ID 产生器的串行化瓶颈。
 */
static uint64_t k_alloc_req_id_ctx(struct wvm_kernel_context *context,
                                     void *rx_buffer, uint32_t buffer_size) {
    uint64_t id = (uint64_t)-1;
    unsigned long flags;
    int cpu;
    struct id_pool_t *pool;

    if (!context || !context->id_pool || !context->req_ctx)
        return id;
    cpu = get_cpu();
    pool = this_cpu_ptr(context->id_pool);

    spin_lock_irqsave(&pool->lock, flags);
    if (unlikely(!pool->ids)) goto out;
    if (pool->tail != pool->head) {
        uint32_t raw_idx = pool->ids[pool->head & (MAX_IDS_PER_CPU - 1)];
        pool->head++;
        uint32_t combined_idx = ((uint32_t)cpu << CPU_ID_SHIFT) | raw_idx;
        if (likely((size_t)combined_idx < context->req_ctx_count)) {
            context->req_ctx[combined_idx].generation++;
            if (context->req_ctx[combined_idx].generation == 0)
                context->req_ctx[combined_idx].generation = 1;
            id = ((uint64_t)context->req_ctx[combined_idx].generation << 32) |
                 combined_idx;
            WRITE_ONCE(context->req_ctx[combined_idx].rx_buffer, rx_buffer);
            context->req_ctx[combined_idx].max_len = buffer_size; // [FIX-G3]
            WRITE_ONCE(context->req_ctx[combined_idx].done, 0);
            smp_wmb(); 
        } else { pool->head--; }
    }
out:
    spin_unlock_irqrestore(&pool->lock, flags);
    put_cpu();
    return id;
}

static uint64_t k_alloc_req_id(void *rx_buffer, uint32_t buffer_size)
{
    return k_alloc_req_id_ctx(wvm_active_context(), rx_buffer, buffer_size);
}

static void k_free_req_id_ctx(struct wvm_kernel_context *context, uint64_t full_id)
{
    unsigned long flags;
    uint32_t generation = (uint32_t)(full_id >> 32);
    uint32_t combined_idx = (uint32_t)(full_id & 0xFFFFFFFF);
    int owner_cpu = (combined_idx >> CPU_ID_SHIFT);
    uint32_t raw_idx = combined_idx & (MAX_IDS_PER_CPU - 1);
    struct id_pool_t *pool;

    if (unlikely(!context || !context->id_pool || !context->req_ctx ||
                 (size_t)combined_idx >= context->req_ctx_count ||
                 owner_cpu >= nr_cpu_ids))
        return;
    if (context->req_ctx[combined_idx].generation != generation)
        return;

    xchg(&context->req_ctx[combined_idx].rx_buffer, NULL);
    WRITE_ONCE(context->req_ctx[combined_idx].done, 0);

    pool = per_cpu_ptr(context->id_pool, owner_cpu);
    if (unlikely(!pool->ids))
        return;
    spin_lock_irqsave(&pool->lock, flags);
    pool->ids[pool->tail & (MAX_IDS_PER_CPU - 1)] = raw_idx;
    pool->tail++;
    spin_unlock_irqrestore(&pool->lock, flags);
}

static void k_free_req_id(uint64_t full_id)
{
    k_free_req_id_ctx(wvm_active_context(), full_id);
}

static int k_check_req_status_ctx(struct wvm_kernel_context *context,
                                  uint64_t full_id)
{
    uint32_t combined_idx = (uint32_t)(full_id & 0xFFFFFFFF);

    if (!context || !context->req_ctx ||
        (size_t)combined_idx >= context->req_ctx_count)
        return -1;
    if (READ_ONCE(context->req_ctx[combined_idx].done)) {
        smp_rmb();
        return 1;
    }
    return 0;
}

static int k_check_req_status(uint64_t full_id)
{
    return k_check_req_status_ctx(wvm_active_context(), full_id);
}

// --- 发送逻辑 ---
static void k_set_gateway_ip(uint32_t gw_id, uint32_t ip, uint16_t port) {
    struct wvm_kernel_context *context = wvm_active_context();

    // [Fix #1] 入参可能是 composite ID，先解码为裸 node_id 再索引静态数组
    uint32_t raw_node_id = WVM_GET_NODEID(gw_id);
    if (context && raw_node_id < WVM_MAX_GATEWAYS) {
        context->gateway_table[raw_node_id].sin_family = AF_INET;
        context->gateway_table[raw_node_id].sin_addr.s_addr = ip;
        context->gateway_table[raw_node_id].sin_port = port;
    }
}

static int raw_kernel_send(struct wvm_kernel_context *context,
                           void *data, int len, uint32_t target_id) {
    struct msghdr msg; struct kvec vec; struct sockaddr_in to_addr; int ret;
    struct wvm_kernel_transport *transport =
        context ? context->transport : NULL;
    // [Fix #1] target_id 可能是 composite ID，解码为裸 node_id 索引 gateway_table
    uint32_t raw_id = WVM_GET_NODEID(target_id);
    if (!context || !transport || !transport->socket || raw_id >= WVM_MAX_GATEWAYS ||
        context->gateway_table[raw_id].sin_port == 0) {
        return -ENODEV;
    }

    to_addr = context->gateway_table[raw_id];
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &to_addr;
    msg.msg_namelen = sizeof(to_addr);
    msg.msg_flags = MSG_DONTWAIT;
    vec.iov_base = data;
    vec.iov_len = len;

    ret = kernel_sendmsg(transport->socket, &msg, &vec, 1, len);
    if (ret == -EAGAIN) {
        if (in_atomic() || irqs_disabled()) udelay(5);
    }
    return ret;
}

/* 
 * [物理意图] 模拟处理器的“输出流水线”，负责将内核态产生的 Diff 和 ACK 投射到网络。
 * [关键逻辑] 严格执行优先级调度：Fast Ring（信令）绝对抢占 Slow Ring（全页）。同时将 CRC32 计算卸载到工作线程中。
 * [后果] 保证了系统在“内存洪流”中依然能及时响应心跳与版本确认包，防止了由于网络拥塞导致的误判定节点下线。
 */
static int tx_worker_thread_fn(void *data) {
    struct wvm_kernel_transport *transport = data;
    /* Large TX slots (up to 64KB) cannot live on kernel stack. */
    struct tx_slot_t *slot = kvzalloc(sizeof(*slot), GFP_KERNEL);
    if (!slot || !transport) {
        kvfree(slot);
        return -ENOMEM;
    }
    while (!kthread_should_stop()) {
        wait_event_interruptible(transport->tx_wq,
            atomic_read(&transport->fast_ring.pending_count) > 0 ||
            atomic_read(&transport->slow_ring.pending_count) > 0 ||
            kthread_should_stop());
        
        if (kthread_should_stop()) break;

        // 1. Fast Lane (Priority)
        while (atomic_read(&transport->fast_ring.pending_count) > 0) {
            int found = 0;
            spin_lock_bh(&transport->fast_ring.lock);
            if (transport->fast_ring.head != transport->fast_ring.tail) {
                memcpy(slot,
                       &transport->fast_ring.slots[transport->fast_ring.head],
                       sizeof(*slot));
                transport->fast_ring.head =
                    (transport->fast_ring.head + 1) % TX_RING_SIZE;
                atomic_dec(&transport->fast_ring.pending_count);
                found = 1;
            }
            spin_unlock_bh(&transport->fast_ring.lock);
            
            if (found) {
                // [V29] CRC Calculation offloaded to worker thread
                struct wvm_header *hdr = (struct wvm_header *)slot->data;
                hdr->crc32 = 0;
                hdr->crc32 = htonl(calculate_crc32(slot->data, slot->len));

                raw_kernel_send(slot->context, slot->data, slot->len,
                                slot->target_id);
                /* A03: drop TX-slot get taken at enqueue. */
                if (slot->context)
                    wvm_kernel_put_context(slot->context);
                slot->context = NULL;
                cond_resched();
            }
        }

        // 2. Slow Lane (Quota)
        int quota = 32; 
        while (quota-- > 0 &&
               atomic_read(&transport->slow_ring.pending_count) > 0) {
            int found = 0;
            spin_lock_bh(&transport->slow_ring.lock);
            if (transport->slow_ring.head != transport->slow_ring.tail) {
                memcpy(slot,
                       &transport->slow_ring.slots[transport->slow_ring.head],
                       sizeof(*slot));
                transport->slow_ring.head =
                    (transport->slow_ring.head + 1) % TX_RING_SIZE;
                atomic_dec(&transport->slow_ring.pending_count);
                found = 1;
            }
            spin_unlock_bh(&transport->slow_ring.lock);
            
            if (found) {
                // [V29] CRC Calculation
                struct wvm_header *hdr = (struct wvm_header *)slot->data;
                hdr->crc32 = 0;
                hdr->crc32 = htonl(calculate_crc32(slot->data, slot->len));

                raw_kernel_send(slot->context, slot->data, slot->len,
                                slot->target_id);
                if (slot->context)
                    wvm_kernel_put_context(slot->context);
                slot->context = NULL;
            }
            // Preempt if fast packet arrives
            if (atomic_read(&transport->fast_ring.pending_count) > 0) break;
        }
        k_touch_watchdog();
    }
    kvfree(slot);
    return 0;
}

/* A01: explicit context; A03: TX slot holds a get until worker put. */
static int k_send_packet_ctx(struct wvm_kernel_context *context,
                             void *data, int len, uint32_t target_id)
{
    struct wvm_header *hdr = (struct wvm_header *)data;
    struct wvm_tx_ring_t *ring;
    unsigned long flags;
    uint32_t next;

    if (!context || !context->transport || !data)
        return -ENODEV;

    /* G1: FULL_VMID stashes vm_id in epoch; do not clobber it. */
    if (!(hdr->flags & WVM_FLAG_FULL_VMID))
        hdr->epoch = htonl(READ_ONCE(context->kernel_epoch));
    hdr->node_state = 2;
    hdr->target_id = htonl(target_id);

    hdr->crc32 = 0;
    hdr->crc32 = htonl(calculate_crc32(data, len));
    if (!k_is_atomic_context())
        return raw_kernel_send(context, data, len, target_id);

    ring = (hdr->qos_level == 1) ? &context->transport->fast_ring
                                : &context->transport->slow_ring;
    spin_lock_irqsave(&ring->lock, flags);
    next = (ring->tail + 1) % TX_RING_SIZE;
    if (next != ring->head) {
        if (!atomic_inc_not_zero(&context->refs)) {
            spin_unlock_irqrestore(&ring->lock, flags);
            return -ENODEV;
        }
        ring->slots[ring->tail].context = context;
        ring->slots[ring->tail].len = len;
        ring->slots[ring->tail].target_id = target_id;
        memcpy(ring->slots[ring->tail].data, data, len);
        ring->tail = next;
        atomic_inc(&ring->pending_count);
        wake_up_interruptible(&context->transport->tx_wq);
        spin_unlock_irqrestore(&ring->lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&ring->lock, flags);
    return -EAGAIN;
}

static int k_send_packet(void *data, int len, uint32_t target_id)
{
    return k_send_packet_ctx(wvm_active_context(), data, len, target_id);
}

static void k_send_packet_async(uint16_t msg_type, void *payload, int len,
                                uint32_t target_id, uint8_t qos)
{
    size_t pkt_len = sizeof(struct wvm_header) + len;
    uint8_t *buffer = k_alloc_packet(pkt_len, 1);
    struct wvm_kernel_context *context = wvm_active_context();
    struct wvm_header *hdr;

    if (!buffer)
        return;
    if (!context) {
        k_free_packet(buffer);
        return;
    }

    hdr = (struct wvm_header *)buffer;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(msg_type);
    hdr->payload_len = htons(len);
    if (wvm_header_pack_src(hdr, context->identity.vm_id,
                            wvm_ctx_local_vnode(context)) != 0) {
        k_free_packet(buffer);
        return;
    }
    hdr->req_id = 0;
    hdr->qos_level = qos;
    if (payload && len > 0)
        memcpy(buffer + sizeof(*hdr), payload, len);

    k_send_packet_ctx(context, buffer, pkt_len, target_id);
    k_free_packet(buffer);
}

// 引用外部函数
extern int wvm_handle_local_fault_fastpath(uint64_t gpa, void* page_buffer, uint64_t *version);
extern void wvm_declare_interest_in_neighborhood(uint64_t gpa);

// [NEW IOCTL] 动态注入 Guest 内存布局
static int wvm_set_mem_layout(struct wvm_kernel_context *context,
                              struct wvm_ioctl_mem_layout *layout) {
    if (layout->count > MAX_WVM_SLOTS) return -EINVAL;

    /* Reset old slots first to avoid stale ranges after restart/reconfigure. */
    for (int i = 0; i < MAX_WVM_SLOTS; i++) {
        context->mem_slots[i].active = false;
        context->mem_slots[i].start_gpa = 0;
        context->mem_slots[i].size = 0;
        context->mem_slots[i].host_offset = 0;
    }

    for (int i = 0; i < layout->count; i++) {
        context->mem_slots[i].start_gpa = layout->slots[i].start;
        context->mem_slots[i].size = layout->slots[i].size;
        context->mem_slots[i].active = true;
        printk(KERN_INFO "[WVM] Active RAM Slot %d: GPA 0x%llx - 0x%llx\n", 
               i, context->mem_slots[i].start_gpa,
               context->mem_slots[i].start_gpa + context->mem_slots[i].size);
    }
    return 0;
}

/* 
 * [物理意图] 接管处理器的“缺页异常（EPT Violation）”，实现虚拟化空间的物理坍缩。
 * [关键逻辑] 1. 本地命中路径：直接拷贝 Directory 内容；2. 远程路径：利用 wait_queue 将 vCPU 线程挂起，实现异步网络拉取。
 * [后果] 这是整个项目最高频的入口点。通过异步休眠替代了 V28 的自旋死等，使得物理 CPU 可以在等待内存期间去跑其他任务。
 */
static vm_fault_t wvm_fault_handler(struct vm_fault *vmf) {
    struct wvm_kernel_context *context = wvm_context_from_vma(vmf->vma);
    uint64_t gpa = (uint64_t)vmf->pgoff << PAGE_SHIFT;
    bool is_valid_ram = false;
    vm_fault_t result;

    if (!context)
        return VM_FAULT_SIGBUS;

    /* A01: task-bound active ctx for logic_core; ops use explicit ctx. */
    wvm_set_active_context(context);

    // 严谨的地址合法性检查
    for (int i = 0; i < MAX_WVM_SLOTS; i++) {
        if (context->mem_slots[i].active &&
            gpa >= context->mem_slots[i].start_gpa &&
            gpa < context->mem_slots[i].start_gpa + context->mem_slots[i].size) {
            is_valid_ram = true;
            break;
        }
    }

    if (!is_valid_ram) {
        // 如果 GPA 落在了 PCI Hole 或未映射区域，绝对不能继续
        result = VM_FAULT_SIGBUS;
        goto out;
    }

    /*
     * Re-fault after write-protect unmap: restore the page owned by page_tree.
     * meta holds one ref so the page survives unmap_mapping_range.
     */
    {
        kvm_page_meta_t *existing;

        spin_lock(&context->page_tree_lock);
        existing = radix_tree_lookup(&context->page_tree, gpa >> PAGE_SHIFT);
        if (existing && existing->page) {
            struct page *ep = existing->page;

            get_page(ep);
            spin_unlock(&context->page_tree_lock);
            if (vm_insert_page(vmf->vma, vmf->address, ep) == 0) {
                put_page(ep);
                result = VM_FAULT_NOPAGE;
                goto out;
            }
            put_page(ep);
            result = VM_FAULT_SIGBUS;
            goto out;
        }
        spin_unlock(&context->page_tree_lock);
    }

    uint32_t dir_node = wvm_get_directory_node_id(gpa);
    struct page *page;
    void *page_addr;
    kvm_page_meta_t *meta;
    int ret;
    int treat_local;

    /*
     * F4: AUTO_ROUTE / unbound route is NOT a local-alloc license.
     * Only an explicit local directory owner may take the local first-touch
     * path; directory/data miss there may zero-fill. Range/table miss and
     * unbound snapshot must SIGBUS rather than succeed-with-zeros.
     */
    if (!WVM_IS_VALID_TARGET(dir_node)) {
        result = VM_FAULT_SIGBUS;
        goto out;
    }
    treat_local = (WVM_GET_NODEID(dir_node) == wvm_ctx_local_vnode(context));

    // 1. 分配目标物理页 (HighMem 兼容)
    page = alloc_page(GFP_HIGHUSER_MOVABLE);
    if (unlikely(!page)) {
        result = VM_FAULT_OOM;
        goto out;
    }

    // 2. 为 V29 版本控制分配元数据结构
    meta = kmalloc(sizeof(kvm_page_meta_t), GFP_KERNEL);
    if (unlikely(!meta)) {
        __free_page(page);
        result = VM_FAULT_OOM;
        goto out;
    }
    meta->page = page;
    meta->version = 0;
    // 初始化乱序重排队列头
    skb_queue_head_init(&meta->reorder_q); 

    // ========================================================================
    // 分支 A: 本地缺页 (Local Fault) - 极速路径
    // ========================================================================
    if (treat_local) {
        uint64_t local_version = 0;
        
        // 建立临时内核映射进行拷贝 (原子上下文)
        page_addr = kmap_atomic(page);
        
        /* Local directory owner: miss may first-touch zero; hard errors fail. */
        ret = wvm_handle_local_fault_fastpath(gpa, page_addr, &local_version);
        if (ret < 0) {
            kunmap_atomic(page_addr);
            kfree(meta);
            __free_page(page);
            result = VM_FAULT_SIGBUS;
            goto out;
        }
        if (ret > 0) {
            /* Positive miss/empty → first-touch zero page. */
            memset(page_addr, 0, PAGE_SIZE);
            local_version = 0;
            ret = 0;
        }
        
        kunmap_atomic(page_addr);

        if (ret == 0) {
            // 成功：更新元数据版本
            meta->version = local_version;

            // 插入 VMA
            if (vm_insert_page(vmf->vma, vmf->address, page) != 0) {
                kfree(meta);
                __free_page(page);
                result = VM_FAULT_SIGBUS;
                goto out;
            }

            // 注册到 per-VM 索引树；meta 保留 alloc 引用（写保护 unmap 后仍可复用）
            spin_lock(&context->page_tree_lock);
            radix_tree_insert(&context->page_tree, gpa >> PAGE_SHIFT, meta);
            spin_unlock(&context->page_tree_lock);
            /* Do NOT put_page: meta owns the alloc ref; VMA holds insert ref. */

            // [V29] 宣告兴趣
            wvm_declare_interest_in_neighborhood(gpa);

            result = VM_FAULT_NOPAGE;
            goto out;
        } else {
            // 本地查找失败 (逻辑错误或严重不一致)
            kfree(meta);
            __free_page(page);
            result = VM_FAULT_SIGBUS;
            goto out;
        }
    } 
    
    // ========================================================================
    // 分支 B: 远程缺页 (Remote Fault) - 无限重试版
    // ========================================================================
    else {
        uint64_t rid;
        long timeout_ret;
        
        // 1. 分配跳板缓冲区 (Bounce Buffer)
        size_t ack_payload_size = sizeof(struct wvm_mem_ack_payload);
        void *bounce_buf = kmalloc(ack_payload_size, GFP_KERNEL);
        if (unlikely(!bounce_buf)) {
            kfree(meta);
            __free_page(page);
            result = VM_FAULT_OOM;
            goto out;
        }

        // 2. 分配请求 ID (A01: explicit context)
        rid = k_alloc_req_id_ctx(context, bounce_buf, (uint32_t)ack_payload_size);
        if (rid == (uint64_t)-1) {
            kfree(bounce_buf);
            kfree(meta);
            __free_page(page);
            result = VM_FAULT_SIGBUS;
            goto out;
        }

        // 3. 构造请求包
        uint64_t net_gpa = WVM_HTONLL(gpa);
        size_t pkt_len = sizeof(struct wvm_header) + sizeof(net_gpa);
        
        // --- 重试循环上下文 ---
        unsigned long timeout_jiffies = msecs_to_jiffies(10); // 初始 10ms
        unsigned long max_timeout = msecs_to_jiffies(2000);   // 最大 2s
        
        // 首次发送
        uint8_t *buffer = k_alloc_packet(pkt_len, 1);
        if (likely(buffer)) {
            struct wvm_header *hdr = (struct wvm_header *)buffer;
            memset(hdr, 0, sizeof(*hdr));
            hdr->magic = htonl(WVM_MAGIC);
            hdr->msg_type = htons(MSG_MEM_READ);
            hdr->payload_len = htons(sizeof(net_gpa));
            /* G1: FULL_VMID when vm_id/node exceed 8-bit pack. */
            if (wvm_header_pack_src(hdr, context->identity.vm_id,
                                    wvm_ctx_local_vnode(context)) != 0) {
                k_free_packet(buffer);
                k_free_req_id_ctx(context, rid);
                kfree(bounce_buf);
                kfree(meta);
                __free_page(page);
                result = VM_FAULT_SIGBUS;
                goto out;
            }
            hdr->req_id = WVM_HTONLL(rid);
            hdr->qos_level = 1;
            hdr->crc32 = 0;
            memcpy(buffer + sizeof(*hdr), &net_gpa, sizeof(net_gpa));
            k_send_packet_ctx(context, buffer, pkt_len, dir_node);
            k_free_packet(buffer);
        }

        while (1) {
        // 4. 睡眠等待 — may migrate CPU; do not rely on per-CPU active ctx
        timeout_ret = wait_event_interruptible_timeout(
                context->req_ctx[(uint32_t)rid].wq,
                READ_ONCE(context->req_ctx[(uint32_t)rid].done) == 1,
                timeout_jiffies
            );

            /* A01: re-arm task-bound active ctx after sleep for logic_core. */
            wvm_set_active_context(context);

        // 5. 成功检查
            if (READ_ONCE(context->req_ctx[(uint32_t)rid].done) == 1) {
                break; // 数据到了，跳出
            }

            // 6. 信号中断检查 (防止死锁)
            if (signal_pending(current)) {
                k_log("Page fault interrupted by signal. GPA: %llx", gpa);
                k_free_req_id_ctx(context, rid);
                kfree(bounce_buf);
                kfree(meta);
                __free_page(page);
                result = VM_FAULT_SIGBUS;
                goto out;
            }

            // 7. 超时重发 (指数退避)
            if (timeout_ret == 0) {
                timeout_jiffies *= 2;
                if (timeout_jiffies > max_timeout) timeout_jiffies = max_timeout;
                
                buffer = k_alloc_packet(pkt_len, 1);
                if (buffer) {
                    struct wvm_header *hdr = (struct wvm_header *)buffer;

                    memset(hdr, 0, sizeof(*hdr));
                    hdr->magic = htonl(WVM_MAGIC);
                    hdr->msg_type = htons(MSG_MEM_READ);
                    hdr->payload_len = htons(sizeof(net_gpa));
                    if (wvm_header_pack_src(hdr, context->identity.vm_id,
                                            wvm_ctx_local_vnode(context)) != 0) {
                        k_free_packet(buffer);
                    } else {
                        hdr->req_id = WVM_HTONLL(rid);
                        hdr->qos_level = 1;
                        hdr->crc32 = 0;
                        memcpy(buffer + sizeof(*hdr), &net_gpa, sizeof(net_gpa));
                        k_send_packet_ctx(context, buffer, pkt_len, dir_node);
                        k_free_packet(buffer);
                    }
                }
            }
        }

        // --- 数据处理 ---
        k_free_req_id_ctx(context, rid); 

        // 从 Bounce Buffer 拷贝数据
        struct wvm_mem_ack_payload *ack = (struct wvm_mem_ack_payload *)bounce_buf;
        meta->version = WVM_NTOHLL(ack->version);
        
        page_addr = kmap_atomic(page);
        memcpy(page_addr, ack->data, 4096);
        kunmap_atomic(page_addr);
        
        kfree(bounce_buf);

        if (vm_insert_page(vmf->vma, vmf->address, page) != 0) {
            kfree(meta);
            __free_page(page);
            result = VM_FAULT_SIGBUS;
            goto out;
        }

        spin_lock(&context->page_tree_lock);
        radix_tree_insert(&context->page_tree, gpa >> PAGE_SHIFT, meta);
        spin_unlock(&context->page_tree_lock);
        /* meta owns alloc ref across write-protect unmap cycles. */

        // V29: 宣告兴趣
        wvm_declare_interest_in_neighborhood(gpa);

        result = VM_FAULT_NOPAGE;
        goto out;
    }

out:
    /* A01: clear task-bound active ctx on exit */
    wvm_clear_active_context();
    return result;
}

/* 
 * [物理意图] 内核态“内存小波”生成器，计算物理页的增量变动。
 * [关键逻辑] 在无锁状态下对比“前快照”与“现数据”，生成最小化的 Diff 日志，并通过 COMMIT_DIFF 消息提交给全网。
 * [后果] 实现了极低带宽下的高频内存同步。它只传输变动的比特，使得在千兆网环境下也能模拟出万兆总线的写入吞吐量。
 */
static int committer_thread_fn(void *data) {
    struct wvm_kernel_transport *transport = data;

    if (!transport)
        return -EINVAL;
    while (!kthread_should_stop()) {
        struct diff_task_t *task = NULL;
        struct wvm_kernel_context *ctx;
        struct hlist_node *tmp;
        int bkt;

        wait_event_interruptible(g_diff_wq,
            atomic_read(&g_diff_pending) > 0 || kthread_should_stop());

        if (kthread_should_stop())
            break;

        /* Round-robin: take one task from any live context queue. */
        mutex_lock(&g_context_mutex);
        hash_for_each_safe(g_context_registry, bkt, tmp, ctx, hash_node) {
            if (!ctx->active)
                continue;
            spin_lock_bh(&ctx->diff_lock);
            if (!list_empty(&ctx->diff_queue)) {
                task = list_first_entry(&ctx->diff_queue, struct diff_task_t,
                                        list);
                list_del(&task->list);
                spin_unlock_bh(&ctx->diff_lock);
                atomic_dec(&g_diff_pending);
                /* Hold context across commit work (task already refs it). */
                break;
            }
            spin_unlock_bh(&ctx->diff_lock);
        }
        mutex_unlock(&g_context_mutex);

        if (!task)
            continue;

        // 3. 计算 Diff (Compare current page with pre-image)
        void *current_data = kmap_atomic(task->page);
        
        // --- 优化版 Diff 算法 ---
        int first_diff = -1, last_diff = -1;
        
        // 1. 使用 64位 (8字节) 指针进行快速扫描
        uint64_t *p64_curr = (uint64_t *)current_data;
        uint64_t *p64_pre  = (uint64_t *)task->pre_image;
        int num_words = 4096 / 8; // 512 次循环
        
        for (int i = 0; i < num_words; i++) {
            if (p64_curr[i] != p64_pre[i]) {
                // 发现不同！记录位置
                // 这里的 i 是 8字节的索引，转为字节索引
                int byte_offset = i * 8;
                
                if (first_diff == -1) {
                    first_diff = byte_offset; // 粗略定位到 8字节块
                }
                last_diff = byte_offset + 7;  // 粗略定位到 8字节块末尾
            }
        }
        
        kunmap_atomic(current_data);
        
        // 4. Commit Diff (G7 fail-closed AUTO_ROUTE; local = canonical)
        if (first_diff != -1) {
            uint16_t offset = first_diff;
            uint16_t size = last_diff - first_diff + 1;
            uint32_t dir_node;
            int send_rc = -EAGAIN;
            uint8_t *diff_bytes = NULL;
            kvm_page_meta_t *meta = NULL;
            uint64_t base_version = 0;
            uint64_t result_version = 0;

            /*
             * A02/G7: bind context through directory lookup and commit.
             * Unknown route must NOT be treated as success; confirmed local
             * owner must apply directory version + subscriber publish.
             */
            wvm_set_active_context(task->context);
            dir_node = wvm_get_directory_node_id(task->gpa);

            if (!WVM_IS_VALID_TARGET(dir_node)) {
                wvm_clear_active_context();
                send_rc = -ENODEV;
                goto diff_commit_retain;
            }

            rcu_read_lock();
            meta = radix_tree_lookup(&task->context->page_tree,
                                     task->gpa >> PAGE_SHIFT);
            base_version = meta ? meta->version : 0;
            rcu_read_unlock();

            diff_bytes = kmalloc(size, GFP_KERNEL);
            if (!diff_bytes) {
                wvm_clear_active_context();
                send_rc = -ENOMEM;
                goto diff_commit_retain;
            }
            current_data = kmap_atomic(task->page);
            memcpy(diff_bytes, (uint8_t *)current_data + offset, size);
            kunmap_atomic(current_data);

            if (WVM_GET_NODEID(dir_node) ==
                wvm_ctx_local_vnode(task->context)) {
                if (base_version == 0)
                    base_version = MAKE_VERSION(g_curr_epoch, 1);
                send_rc = wvm_handle_local_commit(task->gpa, base_version,
                                                  offset, diff_bytes, size,
                                                  &result_version);
                if (send_rc == 0) {
                    int pub_rc = wvm_publish_local_commit(
                        task->gpa, result_version, offset, diff_bytes, size,
                        wvm_ctx_local_vnode(task->context));
                    if (pub_rc != 0 && pub_rc != -ENOENT) {
                        pr_warn_ratelimited(
                            "wavevm: local commit publish rc=%d gpa=0x%llx\n",
                            pub_rc, (unsigned long long)task->gpa);
                    }
                    if (meta)
                    spin_lock(&task->context->page_tree_lock);
                    meta = radix_tree_lookup(&task->context->page_tree,
                                             task->gpa >> PAGE_SHIFT);
                    if (meta)
                        meta->version = result_version;
                    spin_unlock(&task->context->page_tree_lock);
                }
                kfree(diff_bytes);
                diff_bytes = NULL;
                wvm_clear_active_context();
                if (send_rc != 0)
                    goto diff_commit_retain;
                /* Local canonical commit succeeded — reprotect below. */
            } else {
                size_t payload_size = sizeof(struct wvm_diff_log) + size;
                size_t pkt_len = sizeof(struct wvm_header) + payload_size;
                uint8_t *buffer = k_alloc_packet(pkt_len, 0);

                if (!buffer) {
                    kfree(diff_bytes);
                    wvm_clear_active_context();
                    send_rc = -ENOMEM;
                    goto diff_commit_retain;
                }
                {
                    struct wvm_header *hdr = (struct wvm_header *)buffer;
                    struct wvm_diff_log *log =
                        (struct wvm_diff_log *)(buffer + sizeof(*hdr));

                    memset(hdr, 0, sizeof(*hdr));
                    hdr->magic = htonl(WVM_MAGIC);
                    hdr->msg_type = htons(MSG_COMMIT_DIFF);
                    hdr->payload_len = htons(payload_size);
                    if (wvm_header_pack_src(hdr, task->context->identity.vm_id,
                                            wvm_ctx_local_vnode(task->context)) != 0) {
                        /* G1: keep pre-image; do not emit lying 8-bit id. */
                        k_free_packet(buffer);
                        kfree(diff_bytes);
                        wvm_clear_active_context();
                        send_rc = -EOPNOTSUPP;
                        goto diff_commit_retain;
                    }
                    hdr->req_id = 0;
                    hdr->qos_level = 1;
                    log->gpa = WVM_HTONLL(task->gpa);
                    log->version = WVM_HTONLL(base_version);
                    log->offset = htons(offset);
                    log->size = htons(size);
                    memcpy((uint8_t *)(log + 1), diff_bytes, size);
                }
                kfree(diff_bytes);
                diff_bytes = NULL;
                send_rc = k_send_packet_ctx(task->context, buffer, pkt_len,
                                            dir_node);
                wvm_clear_active_context();
                k_free_packet(buffer);
                if (send_rc != 0)
                    goto diff_commit_retain;
            }

            if (0) {
diff_commit_retain:
                /*
                 * R04/A02/G7: do not drop the unique pre-image/diff.
                 * Requeue with a bounded retry; page stays dirty.
                 */
                {
                    const uint8_t max_retries = 8;

                    pr_warn_ratelimited(
                        "wavevm: diff commit failed gpa=0x%llx rc=%d "
                        "retry=%u\n",
                        (unsigned long long)task->gpa, send_rc,
                        task->send_retries);
                    if (atomic_read(&task->context->file_attaches) == 0) {
                        if (task->pre_image)
                            vfree(task->pre_image);
                        if (task->page)
                            put_page(task->page);
                        wvm_kernel_put_context(task->context);
                        kfree(task);
                    } else if (task->send_retries < max_retries) {
                        task->send_retries++;
                        spin_lock_bh(&task->context->diff_lock);
                        list_add_tail(&task->list,
                                      &task->context->diff_queue);
                        spin_unlock_bh(&task->context->diff_lock);
                        atomic_inc(&g_diff_pending);
                        wake_up_interruptible(&g_diff_wq);
                    } else {
                        struct wvm_kernel_context *park_ctx = task->context;

                        pr_err_ratelimited(
                            "wavevm: diff commit failed permanently "
                            "gpa=0x%llx rc=%d after %u retries; "
                            "retaining pre-image\n",
                            (unsigned long long)task->gpa, send_rc,
                            task->send_retries);
                        park_ctx->diff_failure = send_rc;
                        spin_lock_bh(&park_ctx->diff_lock);
                        list_add_tail(&task->list, &park_ctx->failed_diffs);
                        park_ctx->failed_diff_count++;
                        spin_unlock_bh(&park_ctx->diff_lock);
                        wvm_kernel_put_context(park_ctx);
                    }
                    continue;
                }
            }
        }

        // 5. [Critical] 重新启用写保护 (Reset cycle)
        // 必须调用 unmap_mapping_range 来清除 PTE 的写权限
        // 这样下一次写入才会再次触发 page_mkwrite
        down_read(&task->context->mapping_sem); // 读锁，允许睡眠
        if (task->context->mapping) {
            unmap_mapping_range(task->context->mapping,
                                (loff_t)task->gpa, PAGE_SIZE, 1);
        }
        up_read(&task->context->mapping_sem);

        // 6. 清理资源
        vfree(task->pre_image);
        put_page(task->page); /* mkwrite get_page */
        wvm_kernel_put_context(task->context); /* mkwrite context ref */
        kfree(task);
    }
    return 0;
}

static vm_fault_t wvm_page_mkwrite(struct vm_fault *vmf) {
    struct wvm_kernel_context *context = wvm_context_from_vma(vmf->vma);
    struct page *page = vmf->page;
    uint64_t gpa = (uint64_t)vmf->pgoff << PAGE_SHIFT;
    struct diff_task_t *task;
    void *vaddr;

    if (!context || !page)
        return VM_FAULT_SIGBUS;

    /*
     * R04: a permanent diff-commit failure retains the only pre-image on
     * failed_diffs. Further guest stores must not open a new write window
     * while that unrecovered failure is outstanding — fail closed so
     * userspace QUERY_DIFF_STATUS / pause can take effect.
     */
    if (READ_ONCE(context->diff_failure) != 0 ||
        READ_ONCE(context->failed_diff_count) != 0)
        return VM_FAULT_SIGBUS;

    /* Must lock when returning VM_FAULT_LOCKED (mm unlocks afterward). */
    lock_page(page);

    task = kmalloc(sizeof(*task), GFP_KERNEL);
    if (!task) {
        unlock_page(page);
        return VM_FAULT_OOM;
    }

    task->pre_image = vmalloc(4096);
    if (!task->pre_image) {
        kfree(task);
        unlock_page(page);
        return VM_FAULT_OOM;
    }

    vaddr = kmap_atomic(page);
    memcpy(task->pre_image, vaddr, 4096);
    kunmap_atomic(vaddr);

    if (!context->transport || !atomic_inc_not_zero(&context->refs)) {
        vfree(task->pre_image);
        kfree(task);
        unlock_page(page);
        return VM_FAULT_SIGBUS;
    }

    task->context = context;
    task->page = page;
    get_page(page);
    task->gpa = gpa;
    task->timestamp = k_get_time_us();
    task->send_retries = 0;

    spin_lock_bh(&context->diff_lock);
    list_add_tail(&task->list, &context->diff_queue);
    spin_unlock_bh(&context->diff_lock);
    atomic_inc(&g_diff_pending);
    wake_up_interruptible(&g_diff_wq);

    return VM_FAULT_LOCKED;
}

// --- 接收处理 ---
extern void wvm_logic_process_packet(struct wvm_header *hdr, void *payload, uint32_t source_id);

// [V29 Core] 尝试应用队列中的乱序包 (链式反应)
// 当收到 v+1 包后，调用此函数检查是否缓存了 v+2, v+3...
static void try_flush_reorder_q(kvm_page_meta_t *meta) {
    struct sk_buff *skb, *tmp;
    bool progress = true;

    // 循环直到无法继续推进版本 (链条断裂)
    while (progress) {
        progress = false;
        
        // 必须加锁，防止软中断并发修改队列
        spin_lock(&meta->reorder_q.lock);
        
        skb_queue_walk_safe(&meta->reorder_q, skb, tmp) {
            // skb->data 存储的是完整的 wvm_header + payload
            struct wvm_header *hdr = (struct wvm_header *)skb->data;
            void *pl = skb->data + sizeof(struct wvm_header);
            
            // 解析包类型与版本号
            uint16_t type = ntohs(hdr->msg_type);
            uint64_t ver = 0;
            void *data_ptr = NULL;
            uint16_t offset = 0;
            uint32_t len = 0;

            if (type == MSG_PAGE_PUSH_DIFF) {
                struct wvm_diff_log *log = (struct wvm_diff_log *)pl;
                ver = WVM_NTOHLL(log->version);
                offset = ntohs(log->offset);
                len = ntohs(log->size);
                data_ptr = log->data;
                // 边界检查
                if (offset + len > 4096) len = 0; 
            } else if (type == MSG_PAGE_PUSH_FULL) {
                struct wvm_full_page_push *full = (struct wvm_full_page_push *)pl;
                ver = WVM_NTOHLL(full->version);
                data_ptr = full->data;
                len = 4096;
            }

            // 命中逻辑：这是我们紧缺的下一个版本
            if (is_next_version(meta->version, ver)) {
                // 1. 从队列摘除 (Unlink)
                __skb_unlink(skb, &meta->reorder_q);
                
                // 2. 应用数据
                // kmap_atomic 可以在自旋锁内使用 (不会睡眠)
                if (len > 0 && data_ptr) {
                    void *vaddr = kmap_atomic(meta->page);
                    memcpy((uint8_t*)vaddr + offset, data_ptr, len);
                    kunmap_atomic(vaddr);
                }
                
                // 3. 更新版本号并标记脏
                meta->version = ver;
                SetPageDirty(meta->page);
                
                // 4. 释放 skb 内存
                kfree_skb(skb);
                
                // 5. 标记进度，跳出遍历，重新开始 (因为链表结构已变)
                progress = true; 
                break; 
            }
            // 过期逻辑：版本号小于等于当前，直接丢弃
            else if (ver <= meta->version) {
                __skb_unlink(skb, &meta->reorder_q);
                kfree_skb(skb);
            }
            // 未来逻辑：ver > meta->version + 1，继续留在队列里等待
        }
        spin_unlock(&meta->reorder_q.lock);
    }
}

/* 
 * [物理意图] 实现“零拷贝”真理更新，将远程推送直接注入 Guest 的物理页。
 * [关键逻辑] 校验版本号：顺序包直接 kmap 写入，乱序包存入 skb_head 队列进行重排。处理完后触发 try_flush 链式应用。
 * [后果] 这是 V30 性能超越 V28 的秘密武器。它在内核底层完成了数据的“无感更新”，Guest 甚至不知道内存已经变了。
 */
static void handle_kernel_push(struct wvm_kernel_context *context,
                                struct wvm_header *hdr, void *payload) {
    if (!context)
        return;
    uint16_t type = ntohs(hdr->msg_type);
    uint8_t flags = hdr->flags; 
    uint64_t gpa, push_version;
    void *data_ptr;
    uint32_t data_len;
    uint16_t offset = 0;

    // --- 1. 解析 Payload ---
    if (type == MSG_PAGE_PUSH_FULL) {
        struct wvm_full_page_push *push = (struct wvm_full_page_push *)payload;
        gpa = WVM_NTOHLL(push->gpa);
        push_version = WVM_NTOHLL(push->version);
        data_ptr = push->data;
        data_len = 4096;
    } else if (type == MSG_PAGE_PUSH_DIFF) {
        struct wvm_diff_log *log = (struct wvm_diff_log *)payload;
        gpa = WVM_NTOHLL(log->gpa);
        push_version = WVM_NTOHLL(log->version);
        offset = ntohs(log->offset);
        data_len = ntohs(log->size);
        data_ptr = log->data;
        if (offset + data_len > 4096) return;
    } else {
        return;
    }

    // --- 2. 核心处理 ---
    rcu_read_lock(); 
    kvm_page_meta_t *meta =
        radix_tree_lookup(&context->page_tree, gpa >> PAGE_SHIFT);
    
    if (meta && meta->page) {
        // [FIX] 幂等性检查：如果包版本 <= 本地版本，静默丢弃
        // 内核态也必须防御重放攻击或网络乱序
        if (!is_newer_version(meta->version, push_version)) {
            rcu_read_unlock();
            return;
        }
        // [场景 A] 顺序到达 (Ideal Case)
        // 如果是全量推送 (Full Push)，或者是连续的 Diff，直接应用
        // 这解决了 Epoch 切换时版本号大跳跃导致的内核死锁问题
        if (is_next_version(meta->version, push_version)) {
            void *vaddr = kmap_atomic(meta->page); 
            if (flags & WVM_FLAG_ZERO) {
                memset(vaddr, 0, 4096);
            } else if (data_len > 0) {
                memcpy((uint8_t*)vaddr + offset, data_ptr, data_len);
            }
            kunmap_atomic(vaddr);
            
            meta->version = push_version;
            SetPageDirty(meta->page);
            try_flush_reorder_q(meta); // 应用后尝试消化队列里的包
        } 
        // [场景 B] 乱序到达 (Future Packet) - 存入队列
        else if (is_newer_version(meta->version, push_version) && !is_next_version(meta->version, push_version)) {
            // 限制队列深度为 8，防止内存耗尽攻击
            if (skb_queue_len(&meta->reorder_q) < 8) {
                // 我们必须分配一个新的 skb 来持久化保存数据
                // 因为当前函数的 payload 指针指向的是临时的网络栈 buffer
                size_t total_len = sizeof(struct wvm_header) + ntohs(hdr->payload_len);
                struct sk_buff *saved_skb = alloc_skb(total_len, GFP_ATOMIC);
                
                if (saved_skb) {
                    // 拷贝完整的 Header + Payload
                    skb_put_data(saved_skb, hdr, total_len); 
                    // 入队 (skb_queue_tail 是并发安全的，但为了和 try_flush 互斥，内部自带锁)
                    skb_queue_tail(&meta->reorder_q, saved_skb);
                }
            }
            // 如果队列满了，丢弃该包，只能等待发送端重传或 V28 兜底
        }
        // [场景 C] 过期包 - 忽略
    }
    rcu_read_unlock(); 
}

/* 
 * [物理意图] 内核态“先知”指令加速器，执行全网同步的物理内存填充。
 * [关键逻辑] 遍历 Radix-Tree 映射的物理页，利用 wmb 内存屏障和 memset 直接操作硬件页，并强制推进逻辑时钟。
 * [后果] 它让分布式虚拟机的“冷启动”与“克隆”速度达到了硬件极限，绕过了所有缓慢的软件协议栈处理路径。
 */
static void handle_kernel_rpc_batch(struct wvm_kernel_context *context,
                                     void *payload, uint32_t payload_len) {
    if (!context)
        return;

    if (payload_len < sizeof(struct wvm_rpc_batch_memset)) return;

    struct wvm_rpc_batch_memset *batch = (struct wvm_rpc_batch_memset *)payload;
    uint32_t count = ntohl(batch->count);
    uint32_t val = ntohl(batch->val); // 通常是 0
    uint8_t fill_byte = (uint8_t)val;

    // 边界检查
    size_t required_len = sizeof(struct wvm_rpc_batch_memset) + count * sizeof(struct wvm_rpc_region);
    if (payload_len < required_len) return;

    struct wvm_rpc_region *regions = (struct wvm_rpc_region *)(batch + 1);

    // 遍历所有内存段
    for (uint32_t i = 0; i < count; i++) {
        uint64_t gpa_start = WVM_NTOHLL(regions[i].gpa);
        uint64_t len = WVM_NTOHLL(regions[i].len);
        uint64_t gpa_end = gpa_start + len;
        uint64_t cur_gpa = gpa_start;

        // 按页遍历 (Page Walk)
        while (cur_gpa < gpa_end) {
            // 计算当前页内的操作范围
            uint64_t page_base = cur_gpa & PAGE_MASK;
            uint64_t page_offset = cur_gpa & ~PAGE_MASK;
            uint64_t bytes_in_page = PAGE_SIZE - page_offset;
            uint64_t remaining = gpa_end - cur_gpa;
            uint64_t op_len = (remaining < bytes_in_page) ? remaining : bytes_in_page;

            rcu_read_lock();
            // 1. 在 Radix Tree 中查找物理页元数据
            kvm_page_meta_t *meta =
                radix_tree_lookup(&context->page_tree, page_base >> PAGE_SHIFT);
            
            if (meta && meta->page) {
                // 2. 建立临时原子映射 (HighMem 兼容)
                void *vaddr = kmap_atomic(meta->page);
                
                // 3. 执行物理内存填充
                memset((uint8_t*)vaddr + page_offset, fill_byte, op_len);
                // [FIX] DMA Fence: 确保数据刷入内存，对设备可见
                wmb(); 
                kunmap_atomic(vaddr);

                // 4. 标记脏页并更新版本号 (逻辑一致性)
                SetPageDirty(meta->page);
                meta->version = MAKE_VERSION(
                    READ_ONCE(context->kernel_epoch),
                    GET_COUNTER(meta->version) + 1);
                
                // 注意：这里不需要广播 Diff，因为 Prophet 的设计假设是
                // 发送端已经广播了 RPC 指令，所有节点都会执行这个操作。
                // 我们只需要更新本地状态即可。
            }
            // 如果 meta 不存在：说明该页尚未被分配/缺页。
            // 对于 memset 0 来说，新分配的页本身就是 0，所以跳过是安全的。
            // 对于 memset 非0，当缺页触发时，会拉取最新数据。
            
            rcu_read_unlock();

            cur_gpa += op_len;
        }
    }
}

/* 
 * [物理意图] 内核态“安全筛网”，负责流量的物理合法性判定与分流。
 * [关键逻辑] 1. 执行强制 CRC32 完整性校验；2. 识别消息类型并根据优先级分发给 Prophet 引擎或逻辑核心。
 * [后果] 这是内核驱动的防火墙。它确保了只有格式正确、且未被篡改的数据包能接触到 Guest 的物理内存。
 */
static void internal_process_single_packet(
    struct wvm_kernel_context *context, struct wvm_header *hdr,
    uint32_t src_ip) {
    struct wvm_kernel_transport *transport =
        context ? context->transport : NULL;
    // 1. [V29 新增] CRC32 强校验
    // 这是 V28 没有的。如果不加，V29 的高可靠性就是空谈。
    uint32_t pkt_len = sizeof(struct wvm_header) + ntohs(hdr->payload_len);
    uint32_t received_crc = ntohl(hdr->crc32);
    
    // 临时清零 CRC 字段进行计算
    hdr->crc32 = 0; 
    uint32_t calculated = calculate_crc32(hdr, pkt_len);
    
    if (calculated != received_crc) {
        // 校验失败，直接静默丢弃，防止污染状态
        // 生产环境可以加一行 printk 但注意频率
        return; 
    }
    
    // 2. 解析通用字段
    void *payload = (void *)hdr + sizeof(struct wvm_header);
    uint16_t type = ntohs(hdr->msg_type);
    
    // 3. [V30 核心修复] 识别 CPU/存储包，内核直接“踢”给本地 Slave 端口
    if (type == MSG_VCPU_RUN || type == MSG_BLOCK_WRITE ||
        type == MSG_BLOCK_READ || type == MSG_BLOCK_FLUSH ||
        type == MSG_BLOCK_TYPED) {
        
        struct sockaddr_in s_addr = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            .sin_port = htons(transport ? transport->local_slave_port : 0)
        };
        struct msghdr msg = { .msg_name = &s_addr, .msg_namelen = sizeof(s_addr), .msg_flags = MSG_DONTWAIT };
        struct kvec vec = { .iov_base = hdr, .iov_len = pkt_len };
        if (transport && transport->socket && s_addr.sin_port != 0)
            kernel_sendmsg(transport->socket, &msg, &vec, 1, pkt_len);
        return;
    }

    // 4. 拦截物理中断包
    // Logic Core 无法处理此消息，必须在内核层直接唤醒 QEMU 等待队列
    if (type == MSG_VFIO_IRQ) {
        if (!context)
            return;
        atomic_set(&context->irq_pending, 1);
        wake_up_interruptible(&context->irq_wait_queue);
        return; 
    }

    // 5. [V29 核心] Prophet 处理
    if (type == MSG_RPC_BATCH_MEMSET) {
        uint32_t payload_len = ntohs(hdr->payload_len);
        handle_kernel_rpc_batch(context, payload, payload_len);
        return; // 处理完毕直接返回，不需要 Logic Core 介入
    }


    // 6. [V29 核心] 拦截主动推送 (Direct Kernel Push)
    // 这是 V29 性能翻倍的关键。必须在内核态直接处理 Diff/Full Push。
    if (type == MSG_PAGE_PUSH_FULL || type == MSG_PAGE_PUSH_DIFF) {
        handle_kernel_push(context, hdr, payload);
        return;
    }

    // 7. [V28 继承] 处理 ACK (唤醒等待线程)
    if (type == MSG_MEM_ACK || type == MSG_VCPU_EXIT) {
        uint64_t rid = WVM_NTOHLL(hdr->req_id);
        if (!context)
            return;
        uint32_t combined_idx = (uint32_t)(rid & 0xFFFFFFFF);
        if (context->req_ctx &&
            (size_t)combined_idx < context->req_ctx_count) {
            struct req_ctx_t *ctx = &context->req_ctx[combined_idx];
            // 检查 Generation 防止 ABA
            if ((rid >> 32) == ctx->generation) {
                if (ctx->rx_buffer) {
                    // V29 的 Payload 包含 Version，结构体变了，但 memcpy 逻辑通用
                    // [FIX-G3] 截断保护：防止恶意/错乱包溢出 rx_buffer
                    size_t copy_len = ntohs(hdr->payload_len);
                    if (copy_len > ctx->max_len)
                        copy_len = ctx->max_len;
                    memcpy(ctx->rx_buffer, payload, copy_len);
                }
                WRITE_ONCE(ctx->done, 1);
                wake_up_interruptible(&ctx->wq); // V29 用 wait_queue 替代了 V28 的自旋
            }
        }
        return;
    }
    
    // 8. [V28 继承] 其他信令转交 Logic Core
    // V29 的 Logic Core 需要知道是谁发的 (Source ID)
    // R04/A01: bind RX context into the implicit WVM_CURRENT_VM_ID() chain.
    {
        uint32_t src_id = ntohl(hdr->slave_id);
        /*
         * R04: this runs from the socket softirq and may interrupt a task that
         * already bound another context (fault/ioctl/committer).  Save and
         * restore the previous binding instead of clearing it unconditionally.
         */
        struct wvm_kernel_context *previous = wvm_active_context();

        wvm_set_active_context(context);
        wvm_logic_process_packet(hdr, payload, src_id);
        wvm_set_active_context(previous);
    }
}

/* 
 * [物理意图] 网卡驱动级别的“数据就绪”回调，执行高PPS解包循环。
 * [关键逻辑] 拦截 Socket 接收队列，对聚合的 UDP 数据包执行循环解构，提取每一个嵌入的 WVM 子包头。
 * [后果] 配合 Gateway 的聚合逻辑，它在内核态实现了“多包合一”的高效处理，极大地减轻了 CPU 软中断的负荷。
 */
static void wavevm_udp_data_ready(struct sock *sk) {
    struct wvm_kernel_transport *transport =
        sk ? (struct wvm_kernel_transport *)sk->sk_user_data : NULL;
    struct sk_buff *skb;

    if (!transport)
        return;
    while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
        // 1. 线性化：确保 skb->data 是连续内存，方便指针操作
        if (skb_is_nonlinear(skb) && skb_linearize(skb) != 0) {
            kfree_skb(skb);
            continue;
        }

        uint32_t offset = 0;
        uint32_t total_len = skb->len;
        struct iphdr *iph = ip_hdr(skb);
        uint32_t src_ip = iph->saddr;

        // 2. 内核态循环解包 (De-aggregation Loop)
        while (offset + sizeof(struct wvm_header) <= total_len) {
            struct wvm_header *hdr = (struct wvm_header *)(skb->data + offset);

            // 魔数校验：防止处理垃圾数据导致 panic
            if (ntohl(hdr->magic) != WVM_MAGIC) break;

            uint16_t p_len = ntohs(hdr->payload_len);
            uint32_t pkt_len = sizeof(struct wvm_header) + p_len;

            // 边界检查
            if (offset + pkt_len > total_len) break;

            // 3. [Multi-VM] 从协议头 target_id 解码 vm_id 并查找对应 context
            // F11 fix: Use RCU lookup in sk_data_ready (softirq context)
            uint32_t target_id = ntohl(hdr->target_id);
            uint32_t vm_id = 0, pkt_node = 0;
            struct wvm_kernel_context *context = NULL;

            {
                wvm_header_unpack_assoc(hdr, target_id, &vm_id, &pkt_node);
                /* Explicit vm_id required; no module-global legacy fallback. */
                if (vm_id != 0)
                    context = wvm_kernel_find_context_rcu(vm_id, pkt_node);
            }

            if (context) {
                // 调用单包处理逻辑 (注意：该函数内部已包含 CRC 校验)
                internal_process_single_packet(context, hdr, src_ip);
                wvm_kernel_put_context(context);  // 释放引用
            }
            // else: 丢弃未知 VM 的包

            // 4. 指针后移
            offset += pkt_len;
        }

        kfree_skb(skb);
    }
}

/* 
 * [物理意图] 物理级映射撤销：强行将 Guest 的硬件 PTE 变为无效。
 * [关键逻辑] 通过 Workqueue 异步触发 unmap_mapping_range，强制冲刷所有物理核心的 TLB 缓存。
 * [后果] 实现了真正的“硬件级失效”。当 Guest 下一次访问该地址时，硬件会产生 EPT 违例并陷入内核，保证不会读到旧数据。
 */
static void k_invalidate_local(uint64_t gpa)
{
    struct wvm_kernel_context *context = wvm_active_context();

    if (!context)
        return;
    k_invalidate_meta_atomic(context, gpa);
    schedule_async_unmap(context, gpa);
    k_log("[Consistency] Invalidate hardware mapping for GPA: %llx", gpa);
}

// --- Driver & Module Init ---
static struct dsm_driver_ops k_ops = {
    .alloc_large_table = k_alloc_large_table,
    .free_large_table = k_free_large_table,
    .alloc_packet = k_alloc_packet,
    .free_packet = k_free_packet,
    .set_gateway_ip = k_set_gateway_ip,
    .send_packet = k_send_packet,
    .fetch_page = k_fetch_page,
    .invalidate_local = k_invalidate_local,
    .log = k_log,
    .is_atomic_context = k_is_atomic_context,
    .touch_watchdog = k_touch_watchdog,
    .alloc_req_id = k_alloc_req_id,
    .free_req_id = k_free_req_id,
    .get_time_us = k_get_time_us,
    .time_diff_us = k_time_diff_us,
    .check_req_status = k_check_req_status,
    .cpu_relax = k_cpu_relax,
    .get_random = k_get_random,
    .yield_cpu_short_time = k_yield_short,
    .send_packet_async = k_send_packet_async
};

static int wvm_bytes_nonzero(const uint8_t *bytes, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (bytes[i] != 0) return 1;
    }
    return 0;
}

static void wvm_context_identity_from_ioctl(
    struct wvm_kernel_context_identity *identity,
    const struct wvm_ioctl_context_bind *request)
{
    memset(identity, 0, sizeof(*identity));
    identity->vm_id = request->vm_id;
    identity->physical_node_id = request->physical_node_id;
    identity->node_instance_id = request->node_instance_id;
    identity->vm_incarnation = request->vm_incarnation;
    identity->manifest_generation = request->manifest_generation;
    memcpy(identity->candidate_manifest_digest,
           request->candidate_manifest_digest,
           sizeof(identity->candidate_manifest_digest));
    memcpy(identity->capability_profile_digest,
           request->capability_profile_digest,
           sizeof(identity->capability_profile_digest));
    memcpy(identity->activation_fence, request->activation_fence,
           sizeof(identity->activation_fence));
    identity->route_snapshot_key = request->route_snapshot_key;
}

static int wvm_context_identity_equal(
    const struct wvm_kernel_context_identity *left,
    const struct wvm_kernel_context_identity *right)
{
    return left->vm_id == right->vm_id &&
           left->physical_node_id == right->physical_node_id &&
           left->node_instance_id == right->node_instance_id &&
           left->vm_incarnation == right->vm_incarnation &&
           left->manifest_generation == right->manifest_generation &&
           memcmp(left->candidate_manifest_digest,
                  right->candidate_manifest_digest,
                  sizeof(left->candidate_manifest_digest)) == 0 &&
           memcmp(left->capability_profile_digest,
                  right->capability_profile_digest,
                  sizeof(left->capability_profile_digest)) == 0 &&
           memcmp(left->activation_fence, right->activation_fence,
                  sizeof(left->activation_fence)) == 0 &&
           left->route_snapshot_key.scope_key.vm_id ==
               right->route_snapshot_key.scope_key.vm_id &&
           left->route_snapshot_key.scope_key.vm_incarnation ==
               right->route_snapshot_key.scope_key.vm_incarnation &&
           left->route_snapshot_key.scope_key.route_scope_id ==
               right->route_snapshot_key.scope_key.route_scope_id &&
           left->route_snapshot_key.topology_revision ==
               right->route_snapshot_key.topology_revision &&
           left->route_snapshot_key.route_generation ==
               right->route_snapshot_key.route_generation &&
           memcmp(left->route_snapshot_key.snapshot_digest,
                  right->route_snapshot_key.snapshot_digest,
                  sizeof(left->route_snapshot_key.snapshot_digest)) == 0;
}

static int wvm_context_request_valid(
    const struct wvm_ioctl_context_bind *request)
{
    if (!request ||
        request->magic != WVM_KERNEL_CONTEXT_MAGIC ||
        request->version != WVM_KERNEL_CONTEXT_ABI_VERSION ||
        request->vm_id == 0 ||
        request->node_instance_id == 0 ||
        request->vm_incarnation == 0 ||
        request->manifest_generation == 0 ||
        !wvm_bytes_nonzero(request->candidate_manifest_digest,
                           WVM_KERNEL_DIGEST_BYTES) ||
        !wvm_bytes_nonzero(request->capability_profile_digest,
                           WVM_KERNEL_DIGEST_BYTES) ||
        !wvm_bytes_nonzero(request->activation_fence,
                           WVM_KERNEL_FENCE_BYTES) ||
        request->route_snapshot_key.scope_key.vm_id != request->vm_id ||
        request->route_snapshot_key.scope_key.vm_incarnation !=
            request->vm_incarnation ||
        request->route_snapshot_key.scope_key.route_scope_id == 0 ||
        request->route_snapshot_key.topology_revision == 0 ||
        request->route_snapshot_key.route_generation == 0 ||
        !wvm_bytes_nonzero(request->route_snapshot_key.snapshot_digest,
                           WVM_KERNEL_DIGEST_BYTES)) {
        return -EINVAL;
    }
    return 0;
}

static int wvm_context_bind_file(
    struct wvm_kernel_file_context *file_context,
    const struct wvm_ioctl_context_bind *request)
{
    struct wvm_kernel_context_identity identity;
    struct wvm_route_snapshot_key route_key;
    struct wvm_kernel_context *ctx = NULL;
    struct wvm_kernel_context *iter;
    int result = 0;
    int created = 0;

    if (!file_context || wvm_context_request_valid(request) != 0) {
        return -EINVAL;
    }
    wvm_context_identity_from_ioctl(&identity, request);
    if (identity.route_snapshot_key.scope_key.vm_id != identity.vm_id ||
        identity.route_snapshot_key.scope_key.vm_incarnation !=
            identity.vm_incarnation) {
        return -EINVAL;
    }
    memset(&route_key, 0, sizeof(route_key));
    route_key.scope_key.vm_id = request->route_snapshot_key.scope_key.vm_id;
    route_key.scope_key.vm_incarnation =
        request->route_snapshot_key.scope_key.vm_incarnation;
    route_key.scope_key.route_scope_id =
        request->route_snapshot_key.scope_key.route_scope_id;
    route_key.topology_revision = request->route_snapshot_key.topology_revision;
    route_key.route_generation = request->route_snapshot_key.route_generation;
    memcpy(route_key.snapshot_digest, request->route_snapshot_key.snapshot_digest,
           sizeof(route_key.snapshot_digest));

    mutex_lock(&g_context_mutex);
    if (file_context->bound) {
        result = wvm_context_identity_equal(&file_context->identity,
                                            &identity) ? 0 : -EBUSY;
        mutex_unlock(&g_context_mutex);
        return result;
    }

    /* F11: exact (vm_id, node_instance_id) first; then scan for same-vm
     * collisions that would share identity incorrectly. */
    ctx = wvm_kernel_find_context_keyed_locked(identity.vm_id,
                                               identity.node_instance_id);
    if (ctx) {
        if (!wvm_context_identity_equal(&ctx->identity, &identity)) {
            wvm_kernel_put_context(ctx);
            mutex_unlock(&g_context_mutex);
            return -EBUSY;
        }
        /* keyed lookup already took a ref; bind path expects to inc once more
         * for attach below only when reusing — drop the lookup ref and let
         * the reuse branch atomic_inc. */
        atomic_dec(&ctx->refs);
    } else {
        int bkt;
        hash_for_each(g_context_registry, bkt, iter, hash_node) {
            if (!iter->active)
                continue;
            if (iter->identity.vm_id == identity.vm_id &&
                iter->identity.node_instance_id != identity.node_instance_id) {
                /* Different compute instance of same VM — allowed. */
                continue;
            }
            if (iter->identity.vm_id == identity.vm_id &&
                iter->identity.node_instance_id == identity.node_instance_id) {
                mutex_unlock(&g_context_mutex);
                return -EBUSY;
            }
        }
    }

    if (!ctx) {
        /* Match QUERY_CAPS advertised max (multi-context after A01–A04). */
        if (g_active_context_count >= WVM_KERNEL_MAX_CONCURRENT_CONTEXTS) {
            mutex_unlock(&g_context_mutex);
            return -ENOSPC;
        }
        ctx = wvm_kernel_allocate_context(identity.vm_id);
        if (!ctx) {
            mutex_unlock(&g_context_mutex);
            return -ENOMEM;
        }
        ctx->identity = identity;
        created = 1;
        /* allocate() starts refs at 1; that hold is the first file attach.
         * Do NOT publish to the registry until route bind succeeds (CC §3-C).
         */
    } else {
        atomic_inc(&ctx->refs);
    }

    file_context->context = ctx;
    file_context->identity = identity;
    file_context->bound = 1;
    mutex_unlock(&g_context_mutex);

    /* Bind route against THIS context before data-plane publish. */
    wvm_set_active_context(ctx);
    if (wvm_logic_bind_route_snapshot(&route_key) != 0) {
        mutex_lock(&g_context_mutex);
        file_context->bound = 0;
        file_context->context = NULL;
        memset(&file_context->identity, 0, sizeof(file_context->identity));
        mutex_unlock(&g_context_mutex);
        wvm_clear_active_context();
        wvm_kernel_put_context(ctx); /* must not skip put / leak */
        return -EINVAL;
    }
    wvm_clear_active_context();

    if (created) {
        mutex_lock(&g_context_mutex);
        /* Publish only after route is ready. */
        hash_add_rcu(g_context_registry, &ctx->hash_node,
                     wvm_context_hash_key(identity.vm_id,
                                          identity.node_instance_id));
        ctx->active = 1;
        g_active_context_count++;
        mutex_unlock(&g_context_mutex);
    }
    atomic_inc(&ctx->file_attaches);
    return 0;
}

static int wvm_context_unbind_file(
    struct wvm_kernel_file_context *file_context,
    const struct wvm_ioctl_context_bind *request)
{
    struct wvm_kernel_context_identity identity;
    struct wvm_kernel_context *ctx;

    if (!file_context || !file_context->bound)
        return 0;
    if (request) {
        if (wvm_context_request_valid(request) != 0)
            return -EINVAL;
        wvm_context_identity_from_ioctl(&identity, request);
        if (!wvm_context_identity_equal(&file_context->identity, &identity))
            return -EPERM;
    }

    mutex_lock(&g_context_mutex);
    ctx = file_context->context;
    file_context->bound = 0;
    file_context->context = NULL;
    memset(&file_context->identity, 0, sizeof(file_context->identity));
    mutex_unlock(&g_context_mutex);

    if (!ctx)
        return 0;

    /*
     * F3: multiple FDs may share one context. Clearing the route on every
     * detach made surviving FDs SIGBUS (AUTO_ROUTE). Only the last BIND
     * owner may unbind the route snapshot; destroy still frees route_context.
     */
    if (atomic_dec_and_test(&ctx->file_attaches)) {
        wvm_set_active_context(ctx);
        wvm_logic_unbind_route_snapshot();
        wvm_clear_active_context();
        /*
         * workerfix3: drop any still-queued mkwrite gets before the file put.
         * (failed_diffs no longer pin refs; queued retries still do.)
         */
        wvm_drain_context_diff_tasks(ctx);
    }

    /* Drop the file's context reference; last put destroys + hash_del. */
    wvm_kernel_put_context(ctx);
    return 0;
}

static int wvm_context_accepts_vm_id(uint32_t vm_id)
{
    struct wvm_kernel_context *ctx;
    int result = -EPERM;

    mutex_lock(&g_context_mutex);
    /* Direct hash lookup without calling find_context (avoids nested lock) */
    hash_for_each_possible(g_context_registry, ctx, hash_node, vm_id) {
        if (ctx->active && ctx->identity.vm_id == vm_id) {
            result = 0;
            break;
        }
    }
    mutex_unlock(&g_context_mutex);
    return result;
}

// [V29] 存储全局 mapping 以便 unmap 使用
static int wvm_open(struct inode *inode, struct file *filp) {
    struct wvm_kernel_file_context *file_context;

    (void)inode;
    file_context = kzalloc(sizeof(*file_context), GFP_KERNEL);
    if (!file_context) return -ENOMEM;
    filp->private_data = file_context;
    return 0;
}

static int wvm_release(struct inode *inode, struct file *filp) {
    struct wvm_kernel_file_context *file_context = filp->private_data;

    (void)inode;
    /*
     * A03: mapping_file_refs + mmap context get are owned by wvm_vma_close.
     * Misc close must not touch them — VMA can outlive this FD.
     * Never NULL context->mapping here: priv_file owns address_space until destroy.
     */
    wvm_context_unbind_file(file_context, NULL);
    kfree(file_context);
    filp->private_data = NULL;

    return 0;
}

static long wvm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    void __user *argp = (void __user *)arg;
    struct wvm_kernel_file_context *file_context = filp->private_data;
    struct wvm_kernel_context *ctx = NULL;
    long ret;

    /* A01: Bind current task to file's VM context (task-local, not per-CPU). */
    if (file_context && file_context->context) {
        ctx = file_context->context;
        wvm_set_active_context(ctx);
    }

    switch (cmd) {
    case IOCTL_WVM_BIND_CONTEXT: {
        struct wvm_ioctl_context_bind request;

        if (copy_from_user(&request, argp, sizeof(request))) {
            ret = -EFAULT;
            goto out;
        }
        ret = wvm_context_bind_file(file_context, &request);
        goto out;
    }
    case IOCTL_WVM_UNBIND_CONTEXT: {
        struct wvm_ioctl_context_bind request;

        if (copy_from_user(&request, argp, sizeof(request))) {
            ret = -EFAULT;
            goto out;
        }
        ret = wvm_context_unbind_file(file_context, &request);
        goto out;
    }
    case IOCTL_WVM_QUERY_CAPS: {
        struct wvm_ioctl_context_caps caps;

        memset(&caps, 0, sizeof(caps));
        caps.magic = WVM_KERNEL_CONTEXT_MAGIC;
        caps.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
        /*
         * Multi-context advertised after A01–A04 isolation evidence.
         * BIND enforces this advertised maximum with -ENOSPC.
         */
        caps.max_concurrent_contexts = WVM_KERNEL_MAX_CONCURRENT_CONTEXTS;
        mutex_lock(&g_context_mutex);
        caps.active_contexts = (uint32_t)g_active_context_count;
        mutex_unlock(&g_context_mutex);
        caps.feature_bits = WVM_KERNEL_CAP_CONTEXT_BIND;
        if (copy_to_user(argp, &caps, sizeof(caps))) {
            ret = -EFAULT;
            goto out;
        }
        ret = 0;
        goto out;
    }
    case IOCTL_WVM_QUERY_DIFF_STATUS: {
        struct wvm_ioctl_diff_status st;
        struct wvm_kernel_context *context = wvm_context_for_file(file_context);
        struct diff_task_t *task;

        memset(&st, 0, sizeof(st));
        st.magic = WVM_KERNEL_DIFF_STATUS_MAGIC;
        st.version = WVM_KERNEL_DIFF_STATUS_VERSION;
        if (!context) {
            ret = -ENOTCONN;
            goto out;
        }
        spin_lock_bh(&context->diff_lock);
        st.last_failure = context->diff_failure;
        st.failed_diff_count = context->failed_diff_count;
        if (!list_empty(&context->failed_diffs)) {
            task = list_first_entry(&context->failed_diffs, struct diff_task_t,
                                   list);
            st.oldest_failed_gpa = task->gpa;
            st.oldest_send_retries = task->send_retries;
        }
        spin_unlock_bh(&context->diff_lock);
        if (copy_to_user(argp, &st, sizeof(st))) {
            ret = -EFAULT;
            goto out;
        }
        ret = 0;
        goto out;
    }
    case IOCTL_SET_GATEWAY: {
        struct wvm_ioctl_gateway gw;
        struct wvm_kernel_context *context = wvm_context_for_file(file_context);
        if (copy_from_user(&gw, argp, sizeof(gw))) {
            ret = -EFAULT;
            goto out;
        }
        if (context && gw.gw_id < WVM_MAX_GATEWAYS) {
            context->gateway_table[gw.gw_id].sin_family = AF_INET;
            context->gateway_table[gw.gw_id].sin_addr.s_addr = gw.ip;
            context->gateway_table[gw.gw_id].sin_port = gw.port;
        }
        break;
    }
    case IOCTL_WVM_REMOTE_RUN: {
        struct wvm_ioctl_remote_run remote_run;
        struct wvm_ipc_cpu_run_req *req = &remote_run.req;
        struct wvm_ipc_cpu_run_ack *ack = &remote_run.ack;
        int rpc_ret;

        if (copy_from_user(&remote_run, argp, sizeof(remote_run))) {
            ret = -EFAULT;
            goto out;
        }

        uint32_t target = req->slave_id;
        if (!WVM_IS_VALID_TARGET(target)) {
            target = wvm_get_compute_slave_id(req->vcpu_index);
        }
        if (!WVM_IS_VALID_TARGET(target)) {
            static int dbg_nodev = 0;
            if (dbg_nodev < 5) {
                uint32_t raw = wvm_get_cpu_mapping_raw(req->vcpu_index);
                printk(KERN_WARNING "[wavevm] REMOTE_RUN cpu=%d raw_route=%u resolved=%u => ENODEV\n",
                       req->vcpu_index, raw, target);
                dbg_nodev++;
            }
            ret = -ENODEV;
            goto out;
        }

        /*
         * Preserve vcpu_index and routing metadata for KVM too.  A compact
         * context payload cannot identify the guest vCPU on the slave.
         */
        memset(ack, 0, sizeof(*ack));
        rpc_ret = wvm_rpc_call(MSG_VCPU_RUN, req, sizeof(*req),
                               target, ack, sizeof(*ack));
        if (rpc_ret < 0) ack->status = rpc_ret;
        if (copy_to_user(argp, &remote_run, sizeof(remote_run))) {
            ret = -EFAULT;
            goto out;
        }
        break;
    }
    case IOCTL_WAIT_IRQ: {
        struct wvm_kernel_context *context =
            wvm_context_for_file(file_context);

        if (wait_event_interruptible(context->irq_wait_queue,
                                     atomic_read(&context->irq_pending) != 0)) {
            ret = -ERESTARTSYS;
            goto out;
        }
        atomic_set(&context->irq_pending, 0);
        uint32_t irq = 16;
        if (copy_to_user(argp, &irq, sizeof(irq))) {
            ret = -EFAULT;
            goto out;
        }
        break;
    }

    case IOCTL_SET_MEM_LAYOUT: {
        struct wvm_ioctl_mem_layout layout;
        struct wvm_kernel_context *layout_ctx;

        if (copy_from_user(&layout, argp, sizeof(layout))) {
            ret = -EFAULT;
            goto out;
        }
        layout_ctx = wvm_context_for_file(file_context);
        if (!layout_ctx) {
            ret = -ENODEV;
            goto out;
        }
        ret = wvm_set_mem_layout(layout_ctx, &layout);
        goto out;
    }

    case IOCTL_UPDATE_MEM_ROUTE: {
        struct wvm_ioctl_route_update head;
        uint32_t *buf;

        // 1. 读取头部元数据
        if (copy_from_user(&head, argp, sizeof(head))) {
            ret = -EFAULT;
            goto out;
        }

        // 安全检查：参数注入通常只有几个整数，限制数量防止滥用
        if (head.count > 1024) {
            ret = -EINVAL;
            goto out;
        }

        // 2. 分配临时缓冲区
        buf = vmalloc(head.count * sizeof(uint32_t));
        if (!buf) {
            ret = -ENOMEM;
            goto out;
        }

        // 3. 读取 Payload (具体的数值)
        if (copy_from_user(buf, (uint8_t*)argp + sizeof(head), head.count * sizeof(uint32_t))) {
            vfree(buf);
            ret = -EFAULT;
            goto out;
        }

        // 4. 传导给 Logic Core; A04: also pin vnode on bound context
        for (int i = 0; i < head.count; i++) {
            uint32_t slot = head.start_index + i;

            // start_index 即 Slot ID; [FIX-M5] keep full uint32_t
            wvm_set_mem_mapping(slot, buf[i]);
            if (ctx && slot == 1)
                WRITE_ONCE(ctx->local_vnode_id, buf[i]);
        }

        vfree(buf);
        break;
    }

    case IOCTL_UPDATE_MEMORY_PLACEMENT: {
        struct wvm_ioctl_route_update head;
        uint32_t *buf;
        size_t bytes;

        if (copy_from_user(&head, argp, sizeof(head))) {
            ret = -EFAULT;
            goto out;
        }
        if (head.count > WVM_MEMORY_ROUTE_TABLE_SIZE ||
            head.start_index >= WVM_MEMORY_ROUTE_TABLE_SIZE ||
            head.start_index + head.count > WVM_MEMORY_ROUTE_TABLE_SIZE) {
            ret = -EINVAL;
            goto out;
        }

        bytes = (size_t)head.count * sizeof(uint32_t);
        if (head.count != 0 && bytes / sizeof(uint32_t) != head.count) {
            ret = -EINVAL;
            goto out;
        }
        buf = vmalloc(bytes);
        if (!buf && bytes != 0) {
            ret = -ENOMEM;
            goto out;
        }
        if (bytes != 0 &&
            copy_from_user(buf, (uint8_t *)argp + sizeof(head), bytes)) {
            vfree(buf);
            ret = -EFAULT;
            goto out;
        }

        for (uint32_t i = 0; i < head.count; i++) {
            wvm_set_memory_mapping(head.start_index + i, buf[i]);
        }
        vfree(buf);
        break;
    }

    case IOCTL_SET_VM_ID: {
        /*
         * Retired from the production path. Manifest-bound
         * IOCTL_WVM_BIND_CONTEXT is the only supported context create/attach.
         * Must goto out: the success epilogue after switch sets ret=0.
         */
        ret = -EOPNOTSUPP;
        goto out;
    }

    // [PATCH] 处理 Epoch 更新
    case IOCTL_UPDATE_EPOCH: {
        uint32_t new_epoch;
        if (copy_from_user(&new_epoch, (void __user *)arg, sizeof(uint32_t))) {
            ret = -EFAULT;
            goto out;
        }
        WRITE_ONCE(wvm_context_for_file(file_context)->kernel_epoch,
                   new_epoch);
        // printk(KERN_INFO "[WVM] Kernel Epoch updated to %u\n", new_epoch);
        break;
    }

    case IOCTL_UPDATE_CPU_ROUTE: {
        struct wvm_ioctl_route_update head;
        uint32_t *buf;
        size_t bytes;

        if (copy_from_user(&head, argp, sizeof(head))) {
            ret = -EFAULT;
            goto out;
        }
        if (head.count > 4096 || head.start_index >= 4096) {
            ret = -EINVAL;
            goto out;
        }
        if (head.start_index + head.count > 4096) {
            ret = -EINVAL;
            goto out;
        }

        bytes = (size_t)head.count * sizeof(uint32_t);
        if (head.count != 0 && bytes / sizeof(uint32_t) != head.count) {
            ret = -EINVAL;
            goto out;
        }
        buf = vmalloc(bytes);
        if (!buf) {
            ret = -ENOMEM;
            goto out;
        }
        if (copy_from_user(buf, (uint8_t *)argp + sizeof(head), head.count * sizeof(uint32_t))) {
            vfree(buf);
            ret = -EFAULT;
            goto out;
        }

        for (uint32_t i = 0; i < head.count; i++) {
            wvm_set_cpu_mapping((int)(head.start_index + i), buf[i]);
        }
        if (head.start_index == 0 && head.count >= 3) {
            printk(KERN_INFO "[wavevm] CPU route table updated: [0]=%u [1]=%u [2]=%u (total chunk=%u)\n",
                   buf[0], buf[1], buf[2], head.count);
        }
        vfree(buf);
        break;
    }

    default:
        ret = -EINVAL;
        goto out;
    }
    ret = 0;

out:
    /* F10 fix: Unbind current task from VM context using per-CPU variable */
    if (ctx) {
        wvm_clear_active_context();
    }
    return ret;
}

static void wvm_vma_close(struct vm_area_struct *vma);

static void wvm_vma_open(struct vm_area_struct *vma);

static const struct vm_operations_struct wvm_vm_ops = {
    .fault = wvm_fault_handler,
    .page_mkwrite = wvm_page_mkwrite,
    .open = wvm_vma_open,   /* R04/A03: fork/VMA-split get */
    .close = wvm_vma_close, /* A03: put mmap context ref */
};

static int wvm_mmap(struct file *filp, struct vm_area_struct *vma) {
    struct wvm_kernel_file_context *file_context = filp->private_data;
    struct wvm_kernel_context *context =
        wvm_context_for_file(file_context);
    struct file *old_file;
    int err;

    if (!context || !file_context || !file_context->bound)
        return -ENODEV;

    /* F3: private address_space per context — same GPA must not share misc inode. */
    err = wvm_context_ensure_private_mapping(context);
    if (err)
        return err;

    /* A03: VMA holds a context ref until vm_ops.close. */
    if (!atomic_inc_not_zero(&context->refs))
        return -ENODEV;

    vma->vm_ops = &wvm_vm_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    /* MIXEDMAP required for vm_insert_page in the fault path. */
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP);
#else
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP;
#endif

    old_file = vma->vm_file;
    vma->vm_file = get_file(context->priv_file);
    fput(old_file);

    down_write(&context->mapping_sem);
    context->mapping = context->priv_file->f_mapping;
    atomic_inc(&context->mapping_file_refs);
    up_write(&context->mapping_sem);
    file_context->mapping = context->mapping;
    return 0;
}

/* R04/A03: fork or VMA split duplicates the VMA — take a matching get. */
static void wvm_vma_open(struct vm_area_struct *vma)
{
    struct wvm_kernel_context *context = wvm_context_from_vma(vma);

    if (!context)
        return;
    if (!atomic_inc_not_zero(&context->refs))
        return;
    down_write(&context->mapping_sem);
    if (context->mapping && vma->vm_file &&
        context->mapping == vma->vm_file->f_mapping)
        atomic_inc(&context->mapping_file_refs);
    up_write(&context->mapping_sem);
}

/* A03: last mapping owner drops the mmap context get on sleepable path. */
static void wvm_vma_close(struct vm_area_struct *vma)
{
    struct wvm_kernel_context *context = wvm_context_from_vma(vma);
    int last_map = 0;

    if (!context)
        return;
    down_write(&context->mapping_sem);
    if (context->mapping && vma->vm_file &&
        context->mapping == vma->vm_file->f_mapping)
        last_map = atomic_dec_and_test(&context->mapping_file_refs);
    up_write(&context->mapping_sem);
    /* Drop queued mkwrite gets when no VMA remains and no FD attach. */
    if (last_map && atomic_read(&context->file_attaches) == 0)
        wvm_drain_context_diff_tasks(context);
    wvm_kernel_put_context(context);
}

static const struct file_operations wvm_mem_fops = {
    /*
     * Intentionally no .owner: alloc_file_pseudo does not fops_get/module_get,
     * but __fput still fops_put/module_put when .owner is set — that underflowed
     * wavevm refcnt to Unloading after context destroy (same-GPA teardown).
     * Module lifetime stays pinned by miscdevice opens + loaded module state.
     */
    /* mmap/ioctl stay on misc fd; this file only supplies a private mapping. */
};

static const struct file_operations wvm_fops = {
    .owner = THIS_MODULE,
    .open = wvm_open,
    .release = wvm_release,
    .mmap = wvm_mmap,
    .unlocked_ioctl = wvm_ioctl,
};

static struct miscdevice wvm_misc = { 
    .minor = MISC_DYNAMIC_MINOR, 
    .name = DRIVER_NAME, 
    .fops = &wvm_fops 
};

static int __init wavevm_init(void) {
    int cpu;
    struct sockaddr_in bind_addr;
    struct wvm_kernel_transport *transport;

    /* Initialize context registry (hash table) */
    hash_init(g_context_registry);
    g_active_context_count = 0;

    transport = kzalloc(sizeof(*transport), GFP_KERNEL);
    if (!transport)
        return -ENOMEM;
    transport->service_port = module_service_port;
    transport->local_slave_port = module_local_slave_port;
    init_waitqueue_head(&transport->tx_wq);
    refcount_set(&transport->refs, 1); /* module holds one ref */
    init_waitqueue_head(&g_diff_wq);
    atomic_set(&g_diff_pending, 0);

    /*
     * Module-wide UDP + TX rings (slots carry context*). Diff queues are
     * per-context. Contexts attach via BIND and take a transport ref.
     */
    g_module_transport = transport;

    size_t slab_size = sizeof(struct wvm_header) + 4096 + sizeof(struct wvm_mem_ack_payload);
    wvm_pkt_cache = kmem_cache_create("wvm_data", slab_size, 0, SLAB_HWCACHE_ALIGN, NULL);

    if (init_ring(&transport->fast_ring) != 0 ||
        init_ring(&transport->slow_ring) != 0)
        goto fail_contexts;

    transport->tx_thread = kthread_run(tx_worker_thread_fn, transport, "wavevm_qos_tx");
    if (IS_ERR(transport->tx_thread)) {
        transport->tx_thread = NULL;
        goto fail_contexts;
    }

    /* Diff committer thread processes all active contexts */
    transport->committer_thread = kthread_run(committer_thread_fn, transport, "wvm_diff_commit");
    if (IS_ERR(transport->committer_thread)) {
        transport->committer_thread = NULL;
        goto fail_contexts;
    }

    if (wvm_core_init(&k_ops, 1) != 0)
        goto fail_contexts;

    if (misc_register(&wvm_misc))
        goto fail_contexts;
    if (sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                         &transport->socket) < 0)
        goto fail_misc;

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(transport->service_port);
    /*
     * kernel_bind() changed its typed sockaddr parameter in newer kernels.
     * The concrete object is always sockaddr_in; void * preserves source
     * compatibility with both the old sockaddr and new sockaddr_unsized APIs.
     */
    kernel_bind(transport->socket, (void *)&bind_addr, sizeof(bind_addr));
    transport->socket->sk->sk_user_data = transport;
    transport->socket->sk->sk_data_ready = wavevm_udp_data_ready;

    k_log("WaveVM V29.5 'Wavelet' Kernel Backend Loaded (Mode A Active, hash-based registry).");
    return 0;

fail_misc:
    misc_deregister(&wvm_misc);
fail_contexts:
    wvm_transport_stop(transport);
    kfree(transport);
    return -ENOMEM;
}

static void __exit wavevm_exit(void) {
    struct wvm_kernel_transport *transport = g_module_transport;
    struct wvm_kernel_context *ctx;
    struct hlist_node *tmp;
    int bkt;

    /* 1. Unpublish device so no new opens race with teardown. */
    misc_deregister(&wvm_misc);

    /* 2. Quiesce RX callbacks before draining async work. */
    if (transport && transport->socket && transport->socket->sk) {
        transport->socket->sk->sk_data_ready = NULL;
        transport->socket->sk->sk_user_data = NULL;
    }

    /* 3. Drain async unmap work while contexts still exist (F3 refs). */
    flush_scheduled_work();
    rcu_barrier();

    /* 4. Destroy remaining contexts. */
    mutex_lock(&g_context_mutex);
    hash_for_each_safe(g_context_registry, bkt, tmp, ctx, hash_node) {
        hash_del_rcu(&ctx->hash_node);
        g_active_context_count--;
        ctx->active = 0;
        mutex_unlock(&g_context_mutex);
        synchronize_rcu();
        wvm_kernel_put_context(ctx);
        mutex_lock(&g_context_mutex);
    }
    mutex_unlock(&g_context_mutex);

    /* 5. Stop kthreads / release socket / rings. */
    g_module_transport = NULL;
    wvm_transport_stop(transport);

    if (wvm_pkt_cache)
        kmem_cache_destroy(wvm_pkt_cache);

    kfree(transport);

    /* Drop pinned pseudo-fs if a destroy raced oddly. */
    while (wvm_mnt_count > 0)
        simple_release_fs(&wvm_mnt, &wvm_mnt_count);
}

module_init(wavevm_init);
module_exit(wavevm_exit);
MODULE_LICENSE("GPL");

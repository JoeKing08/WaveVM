/*
 * Local per-context memory accelerator. Faults and captured diffs complete
 * through the owning user-space runtime; this module has no network,
 * directory, route-planning, or vCPU authority.
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

#define DRIVER_NAME "wavevm"
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

struct wvm_kernel_transport;
struct wvm_kernel_file_context;

struct wvm_kernel_context {
    struct wvm_kernel_context_identity identity;
    /* A04: node-runtime primary vnode for this context (not g_my_node_id). */
    uint32_t local_vnode_id;
    int active;
    atomic_t refs;
    struct hlist_node hash_node;  /* For registry hash table */
    struct work_struct destroy_work; /* A03: last put from atomic → deferred */
    struct rw_semaphore mapping_sem;
    struct address_space *mapping;
    struct file *priv_file; /* F3: per-context private address_space file */
    int priv_fs_pinned;
    atomic_t mapping_file_refs; /* F3: mmap owners sharing context->mapping */
    atomic_t file_attaches; /* F3: BIND owners; last detach clears route */
    struct wvm_mem_slot mem_slots[MAX_WVM_SLOTS];
    struct radix_tree_root page_tree;
    spinlock_t page_tree_lock;

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
    struct mutex memory_lock;
    struct list_head memory_pending;
    wait_queue_head_t memory_wait;
    struct wvm_kernel_file_context *memory_owner;
    uint64_t memory_sequence;
    uint64_t memory_nonce;
    unsigned int memory_pending_count;
    struct wvm_ioctl_memory_config memory_config;
    bool memory_quiescing;
    atomic_t dirty_pending;
    struct pid *authority_pid;
    uint8_t attach_capability[WVM_KERNEL_DIGEST_BYTES];
};

struct wvm_kernel_file_context {
    /* Serializes bind/unbind/mmap/ioctl access to the borrowed context. */
    struct mutex operation_lock;
    int bound;
    bool authority;
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

/* Shared commit workers never hold the registry lock over authority waits. */
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

static int wvm_context_identity_equal(
    const struct wvm_kernel_context_identity *left,
    const struct wvm_kernel_context_identity *right);
static int wvm_context_request_valid(const struct wvm_ioctl_context_bind *request);
static void wvm_context_identity_from_ioctl(
    struct wvm_kernel_context_identity *identity,
    const struct wvm_ioctl_context_bind *request);
static int wvm_memory_invalidate(struct wvm_kernel_context *ctx,
    const struct wvm_ioctl_memory_invalidate *invalidate);

#include "kernel_memory_bridge.h"

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
    struct wvm_ioctl_memory_operation *operation;
    struct wvm_ioctl_memory_operation *intent;
};

// --- ID 管理系统 ---
#define BITS_PER_CPU_ID 16
#define MAX_IDS_PER_CPU (1 << BITS_PER_CPU_ID) 
#define CPU_ID_SHIFT    16                     

// [V29 Final Fix] 内核态页面元数据
// 用于在 Radix Tree 中同时存储物理页指针和版本号
typedef struct {
    struct page *page;
    uint64_t version;
    uint64_t invalid_version;
    bool committing;
    struct rcu_head rcu;
    
    // 内核原生 sk_buff 队列，自带 spinlock，用于缓存乱序到达的包
    struct sk_buff_head reorder_q; 
} kvm_page_meta_t;

static int wvm_memory_invalidate(struct wvm_kernel_context *ctx,
    const struct wvm_ioctl_memory_invalidate *invalidate)
{
    kvm_page_meta_t *meta;
    bool changed = false;

    if (invalidate->gpa % PAGE_SIZE || !invalidate->result_version ||
        invalidate->gpa >= ctx->memory_config.guest_physical_limit)
        return -EINVAL;
    /* Serializes publication with fault's final version check + PTE insert. */
    down_write(&ctx->mapping_sem);
    spin_lock(&ctx->page_tree_lock);
    meta = radix_tree_lookup(&ctx->page_tree, invalidate->gpa >> PAGE_SHIFT);
    if (meta && invalidate->result_version > meta->version &&
        invalidate->result_version > meta->invalid_version) {
        meta->invalid_version = invalidate->result_version;
        changed = true;
    }
    spin_unlock(&ctx->page_tree_lock);
    if (changed && ctx->mapping)
        unmap_mapping_range(ctx->mapping, (loff_t)invalidate->gpa, PAGE_SIZE, 1);
    up_write(&ctx->mapping_sem);
    return 0;
}

struct wvm_kernel_transport {
    struct task_struct *committer_threads[4];
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
            ctx->identity.node_instance_id == node_instance_id &&
            atomic_inc_not_zero(&ctx->refs)) {
            return ctx;
        }
    }
    return NULL;
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
    struct wvm_kernel_context *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

    if (!ctx)
        return NULL;
    if (!try_module_get(THIS_MODULE)) {
        kfree(ctx);
        return NULL;
    }
    ctx->identity.vm_id = vm_id;
    ctx->authority_pid = get_pid(task_tgid(current));
    get_random_bytes(ctx->attach_capability, sizeof(ctx->attach_capability));
    atomic_set(&ctx->refs, 1);
    atomic_set(&ctx->mapping_file_refs, 0);
    atomic_set(&ctx->file_attaches, 0);
    INIT_LIST_HEAD(&ctx->diff_queue);
    INIT_LIST_HEAD(&ctx->failed_diffs);
    spin_lock_init(&ctx->diff_lock);
    mutex_init(&ctx->memory_lock);
    INIT_LIST_HEAD(&ctx->memory_pending);
    init_waitqueue_head(&ctx->memory_wait);
    get_random_bytes(&ctx->memory_nonce, sizeof(ctx->memory_nonce));
    atomic_set(&ctx->dirty_pending, 0);
    INIT_RADIX_TREE(&ctx->page_tree, GFP_ATOMIC);
    spin_lock_init(&ctx->page_tree_lock);
    init_rwsem(&ctx->mapping_sem);
    return ctx;
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
        kfree(task->intent);
        kfree(task->operation);
        kfree(task);
    }
    list_for_each_entry_safe(task, tmp, &failed, list) {
        list_del(&task->list);
        if (task->pre_image)
            vfree(task->pre_image);
        if (task->page)
            put_page(task->page);
        /* no put_context — permanent-fail path already dropped the get */
        kfree(task->intent);
        kfree(task->operation);
        kfree(task);
    }
    if (n_queued)
        atomic_sub(n_queued, &g_diff_pending);
}

static void wvm_kernel_destroy_context(struct wvm_kernel_context *ctx)
{
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

    wvm_context_release_private_mapping(ctx);
    put_pid(ctx->authority_pid);
    kfree(ctx);
    module_put(THIS_MODULE);
}

/* The bound file owns a reference for the duration of each operation. */
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

/*
 * Take an operation-local reference while the caller holds the file's
 * operation_lock. The FD already owns a separate attach reference, but an
 * explicit operation reference makes the lifetime boundary independent of
 * future unbind/release changes and covers blocking ioctls.
 */
static struct wvm_kernel_context *wvm_context_get_for_file(
    const struct wvm_kernel_file_context *file_context)
{
    struct wvm_kernel_context *context = wvm_context_for_file(file_context);

    if (!context || !atomic_inc_not_zero(&context->refs))
        return NULL;
    return context;
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
static int wvm_set_mem_layout(struct wvm_kernel_context *context,
                              struct wvm_ioctl_mem_layout *layout) {
    if (layout->count > MAX_WVM_SLOTS) return -EINVAL;
    if (!READ_ONCE(context->memory_owner)) return -ENOTCONN;
    for (int i = 0; i < layout->count; i++) {
        uint64_t start = layout->slots[i].start, size = layout->slots[i].size;
        bool authorized = false;
        if (!size || (start | size) % PAGE_SIZE ||
            start >= context->memory_config.guest_physical_limit ||
            size > context->memory_config.guest_physical_limit - start)
            return -EINVAL;
        for (int j = 0; j < context->memory_config.range_count; j++) {
            const struct wvm_mem_range *range = &context->memory_config.ranges[j];
            if (start >= range->start && start - range->start < range->size &&
                size <= range->size - (start - range->start)) {
                authorized = true;
                break;
            }
        }
        if (!authorized)
            return -EPERM;
    }

    down_write(&context->mapping_sem);
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
    up_write(&context->mapping_sem);
    return 0;
}

/*
 * [物理意图] 接管处理器的“缺页异常（EPT Violation）”，实现虚拟化空间的物理坍缩。
 * [关键逻辑] 1. 本地命中路径：直接拷贝 Directory 内容；2. 远程路径：利用 wait_queue 将 vCPU 线程挂起，实现异步网络拉取。
 * [后果] 这是整个项目最高频的入口点。通过异步休眠替代了 V28 的自旋死等，使得物理 CPU 可以在等待内存期间去跑其他任务。
 */
static vm_fault_t wvm_fault_handler(struct vm_fault *vmf)
{
    struct wvm_kernel_context *context = wvm_context_from_vma(vmf->vma);
    uint64_t gpa = (uint64_t)vmf->pgoff << PAGE_SHIFT;
    struct wvm_ioctl_memory_operation *operation = NULL;
    kvm_page_meta_t *meta, *existing;
    struct page *page;
    bool valid = false;
    int ret = -EIO;
    unsigned long deadline = jiffies + msecs_to_jiffies(5000);

    if (!context || !READ_ONCE(context->memory_owner) ||
        READ_ONCE(context->memory_quiescing) ||
        READ_ONCE(context->diff_failure))
        return VM_FAULT_SIGBUS;
    down_read(&context->mapping_sem);
    for (int i = 0; i < MAX_WVM_SLOTS; i++) {
        if (context->mem_slots[i].active &&
            gpa >= context->mem_slots[i].start_gpa &&
            gpa - context->mem_slots[i].start_gpa < context->mem_slots[i].size) {
            valid = true;
            break;
        }
    }
    up_read(&context->mapping_sem);
    if (!valid)
        return VM_FAULT_SIGBUS;

    /* Publish a loading cache entry before requesting bytes so concurrent
     * invalidation cannot be lost between the read ACK and cache insertion. */
    meta = kzalloc(sizeof(*meta), GFP_KERNEL);
    page = alloc_page(GFP_HIGHUSER_MOVABLE);
    if (!meta || !page) {
        kfree(meta);
        if (page)
            __free_page(page);
        return VM_FAULT_OOM;
    }
    meta->page = page;
    skb_queue_head_init(&meta->reorder_q);
    spin_lock(&context->page_tree_lock);
    existing = radix_tree_lookup(&context->page_tree, gpa >> PAGE_SHIFT);
    if (existing) {
        get_page(existing->page);
        spin_unlock(&context->page_tree_lock);
        __free_page(page);
        kfree(meta);
        meta = existing;
        page = existing->page;
    } else {
        ret = radix_tree_insert(&context->page_tree, gpa >> PAGE_SHIFT, meta);
        if (!ret)
            get_page(page); /* index owns allocation; fault owns this get */
        spin_unlock(&context->page_tree_lock);
        if (ret) {
            kfree(meta);
            __free_page(page);
            return VM_FAULT_OOM;
        }
    }
retry:
    if (time_after_eq(jiffies, deadline)) {
        ret = -ETIMEDOUT;
        goto out;
    }
    lock_page(page);
    if (READ_ONCE(meta->committing)) {
        long waited;
        unlock_page(page);
        waited = wait_event_interruptible_timeout(context->memory_wait,
            !READ_ONCE(meta->committing) || READ_ONCE(context->diff_failure) ||
            !READ_ONCE(context->memory_owner), deadline - jiffies);
        if (waited <= 0 || READ_ONCE(context->diff_failure) ||
            !READ_ONCE(context->memory_owner)) {
            ret = -EIO;
            goto out;
        }
        goto retry;
    }
    if (!READ_ONCE(meta->version) ||
        READ_ONCE(meta->invalid_version) > READ_ONCE(meta->version)) {
        void *address;

        if (!operation)
            operation = kzalloc(sizeof(*operation), GFP_KERNEL);
        if (!operation) {
            unlock_page(page);
            ret = -ENOMEM;
            goto out;
        }
        memset(operation, 0, sizeof(*operation));
        operation->kind = WVM_KERNEL_MEMORY_READ;
        operation->gpa = gpa;
        ret = wvm_memory_call(context, operation);
        if (ret) {
            unlock_page(page);
            goto out;
        }
        address = kmap_atomic(page);
        memcpy(address, operation->data, PAGE_SIZE);
        kunmap_atomic(address);
        WRITE_ONCE(meta->version, operation->result_version);
    }
    down_read(&context->mapping_sem);
    if (READ_ONCE(context->memory_quiescing)) {
        up_read(&context->mapping_sem);
        unlock_page(page);
        ret = -ESHUTDOWN;
        goto out;
    }
    if (READ_ONCE(meta->invalid_version) > READ_ONCE(meta->version)) {
        up_read(&context->mapping_sem);
        unlock_page(page);
        goto retry;
    }
    ret = vm_insert_page(vmf->vma, vmf->address, page);
    up_read(&context->mapping_sem);
    unlock_page(page);
out:
    put_page(page);
    kfree(operation);
    return ret == 0 || ret == -EBUSY ? VM_FAULT_NOPAGE :
           ret == -ENOMEM ? VM_FAULT_OOM : VM_FAULT_SIGBUS;
}

/* A terminal stale rejection permits a new semantic operation. Preserve the
 * original byte write-set across every rebase; untouched gaps belong to the
 * latest authority snapshot, never to our previous merged proposal. */
static int wvm_rebase_memory_commit(struct diff_task_t *task)
{
    struct wvm_ioctl_memory_operation *read;
    const struct wvm_ioctl_memory_operation *intent;
    int result;

    if (!task->intent) {
        task->intent = kmemdup(task->operation, sizeof(*task->operation), GFP_KERNEL);
        if (!task->intent)
            return -ENOMEM;
    }
    read = kzalloc(sizeof(*read), GFP_KERNEL);
    if (!read)
        return -ENOMEM;
    read->kind = WVM_KERNEL_MEMORY_READ;
    read->gpa = task->gpa;
    result = wvm_memory_call(task->context, read);
    if (result)
        goto out;
    intent = task->intent;
    for (unsigned int i = 0; i < intent->data_bytes; i++) {
        unsigned int offset = intent->offset + i;
        if (intent->data[i] != ((uint8_t *)task->pre_image)[offset])
            read->data[offset] = intent->data[i];
    }
    read->kind = WVM_KERNEL_MEMORY_COMMIT;
    read->base_version = read->result_version;
    read->result_version = 0;
    read->request_id = 0;
    memset(read->operation_id, 0, sizeof(read->operation_id));
    *task->operation = *read;
out:
    kfree(read);
    return result;
}

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

        kvm_page_meta_t *meta;
        int send_rc = 0;

        if (!task->operation) {
            void *current_data;
            int first = -1, last = -1;

            task->operation = kzalloc(sizeof(*task->operation), GFP_KERNEL);
            if (!task->operation) {
                send_rc = -ENOMEM;
                goto diff_commit_retain;
            }
            /* mkwrite returns with the page locked. Waiting here ensures its
             * PTE is installed before we revoke writes and freeze the diff. */
            lock_page(task->page);
            down_read(&task->context->mapping_sem);
            if (task->context->mapping)
                unmap_mapping_range(task->context->mapping,
                                    (loff_t)task->gpa, PAGE_SIZE, 1);
            up_read(&task->context->mapping_sem);
            current_data = kmap_atomic(task->page);
            for (int i = 0; i < PAGE_SIZE; i++) {
                if (((uint8_t *)current_data)[i] !=
                    ((uint8_t *)task->pre_image)[i]) {
                    if (first == -1)
                        first = i;
                    last = i;
                }
            }
            if (first != -1) {
                task->operation->offset = first;
                task->operation->data_bytes = last - first + 1;
                memcpy(task->operation->data, (uint8_t *)current_data + first,
                       task->operation->data_bytes);
            }
            kunmap_atomic(current_data);
            spin_lock(&task->context->page_tree_lock);
            meta = radix_tree_lookup(&task->context->page_tree,
                                     task->gpa >> PAGE_SHIFT);
            task->operation->base_version = meta ? meta->version : 0;
            spin_unlock(&task->context->page_tree_lock);
            task->operation->kind = WVM_KERNEL_MEMORY_COMMIT;
            task->operation->gpa = task->gpa;
            unlock_page(task->page);
        }
        if (task->operation->data_bytes != 0) {
            send_rc = wvm_memory_call(task->context, task->operation);
            if (send_rc == -ESTALE) {
                send_rc = wvm_rebase_memory_commit(task);
                if (!send_rc)
                    send_rc = wvm_memory_call(task->context, task->operation);
            }
            if (send_rc != 0)
                goto diff_commit_retain;
            lock_page(task->page);
            if (task->intent) {
                void *address = kmap_atomic(task->page);
                memcpy(address, task->operation->data, PAGE_SIZE);
                kunmap_atomic(address);
            }
            spin_lock(&task->context->page_tree_lock);
            meta = radix_tree_lookup(&task->context->page_tree,
                                     task->gpa >> PAGE_SHIFT);
            if (meta)
                meta->version = task->operation->result_version;
            spin_unlock(&task->context->page_tree_lock);
            unlock_page(task->page);
        }
        {
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
                        kfree(task->intent);
                        kfree(task->operation);
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
                        wake_up_all(&park_ctx->memory_wait);
                        wvm_kernel_put_context(park_ctx);
                    }
                    continue;
                }
            }
        }

        spin_lock(&task->context->page_tree_lock);
        meta = radix_tree_lookup(&task->context->page_tree,
                                 task->gpa >> PAGE_SHIFT);
        if (meta)
            WRITE_ONCE(meta->committing, false);
        spin_unlock(&task->context->page_tree_lock);
        wake_up_all(&task->context->memory_wait);

        atomic_dec(&task->context->dirty_pending);
        wake_up_all(&task->context->memory_wait);

        // 6. 清理资源
        vfree(task->pre_image);
        put_page(task->page); /* mkwrite get_page */
        wvm_kernel_put_context(task->context); /* mkwrite context ref */
        kfree(task->intent);
        kfree(task->operation);
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

retry:
    /* Must lock when returning VM_FAULT_LOCKED (mm unlocks afterward). */
    lock_page(page);
    {
        kvm_page_meta_t *meta;
        long waited;

        spin_lock(&context->page_tree_lock);
        meta = radix_tree_lookup(&context->page_tree, gpa >> PAGE_SHIFT);
        if (!meta || !READ_ONCE(context->memory_owner) ||
            READ_ONCE(context->memory_quiescing)) {
            spin_unlock(&context->page_tree_lock);
            unlock_page(page);
            return VM_FAULT_SIGBUS;
        }
        if (meta->invalid_version > meta->version && !meta->committing) {
            spin_unlock(&context->page_tree_lock);
            unlock_page(page);
            return VM_FAULT_NOPAGE;
        }
        if (meta->committing) {
            spin_unlock(&context->page_tree_lock);
            unlock_page(page);
            waited = wait_event_interruptible_timeout(context->memory_wait,
                !READ_ONCE(meta->committing) || READ_ONCE(context->diff_failure) ||
                !READ_ONCE(context->memory_owner), msecs_to_jiffies(5000));
            if (waited <= 0 || READ_ONCE(context->diff_failure) ||
                !READ_ONCE(context->memory_owner))
                return VM_FAULT_SIGBUS;
            goto retry;
        }
        /* Reserve after allocations below, while still holding page lock. */
        spin_unlock(&context->page_tree_lock);
    }

    task = kzalloc(sizeof(*task), GFP_KERNEL);
    if (!task) {
        unlock_page(page);
        return VM_FAULT_OOM;
    }

    task->pre_image = vmalloc(4096);
    if (!task->pre_image) {
        kfree(task->intent);
        kfree(task->operation);
        kfree(task);
        unlock_page(page);
        return VM_FAULT_OOM;
    }

    vaddr = kmap_atomic(page);
    memcpy(task->pre_image, vaddr, 4096);
    kunmap_atomic(vaddr);

    if (!atomic_inc_not_zero(&context->refs)) {
        vfree(task->pre_image);
        kfree(task->intent);
        kfree(task->operation);
        kfree(task);
        unlock_page(page);
        return VM_FAULT_SIGBUS;
    }

    task->context = context;
    task->page = page;
    get_page(page);
    task->gpa = gpa;
    task->timestamp = ktime_to_us(ktime_get());
    task->send_retries = 0;
    spin_lock(&context->page_tree_lock);
    {
        kvm_page_meta_t *meta = radix_tree_lookup(&context->page_tree,
                                                 gpa >> PAGE_SHIFT);
        /* Publish the producer and its pending count atomically against STOP.
         * The committer waits for this page lock before revoking its PTE. */
        if (context->memory_quiescing || !READ_ONCE(context->memory_owner)) {
            spin_unlock(&context->page_tree_lock);
            vfree(task->pre_image);
            put_page(page);
            wvm_kernel_put_context(context);
            kfree(task);
            unlock_page(page);
            return VM_FAULT_SIGBUS;
        }
        atomic_inc(&context->dirty_pending);
        if (meta)
            WRITE_ONCE(meta->committing, true);
    }
    spin_unlock(&context->page_tree_lock);

    spin_lock_bh(&context->diff_lock);
    list_add_tail(&task->list, &context->diff_queue);
    spin_unlock_bh(&context->diff_lock);
    atomic_inc(&g_diff_pending);
    wake_up_interruptible(&g_diff_wq);

    return VM_FAULT_LOCKED;
}

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
        request->flags != 0 ||
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
    struct wvm_ioctl_context_bind *request)
{
    struct wvm_kernel_context_identity identity;
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
            mutex_unlock(&g_context_mutex);
            wvm_kernel_put_context(ctx);
            return -EBUSY;
        }
        if (ctx->authority_pid != task_tgid(current) &&
            memcmp(request->attach_capability, ctx->attach_capability,
                   sizeof(ctx->attach_capability)) != 0) {
            mutex_unlock(&g_context_mutex);
            wvm_kernel_put_context(ctx);
            return -EPERM;
        }
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
        /* An external attachment must never create a replacement context. */
        if (wvm_bytes_nonzero(request->attach_capability,
                              sizeof(request->attach_capability))) {
            mutex_unlock(&g_context_mutex);
            return -ENOENT;
        }
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
    }

    file_context->context = ctx;
    file_context->identity = identity;
    file_context->bound = 1;
    file_context->authority = ctx->authority_pid == task_tgid(current);
    memcpy(request->attach_capability, ctx->attach_capability,
           sizeof(request->attach_capability));
    if (created) {
        /* Publish only after route is ready. */
        hash_add_rcu(g_context_registry, &ctx->hash_node,
                     wvm_context_hash_key(identity.vm_id,
                                          identity.node_instance_id));
        ctx->active = 1;
        g_active_context_count++;
    }
    atomic_inc(&ctx->file_attaches);
    mutex_unlock(&g_context_mutex);
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
    file_context->authority = false;
    file_context->context = NULL;
    memset(&file_context->identity, 0, sizeof(file_context->identity));
    mutex_unlock(&g_context_mutex);

    if (!ctx)
        return 0;

    wvm_memory_owner_stop(ctx, file_context);

    /*
     * F3: multiple FDs may share one context. Clearing the route on every
     * detach made surviving FDs SIGBUS (AUTO_ROUTE). Only the last BIND
     * owner may unbind the route snapshot; destroy still frees route_context.
     */
    if (atomic_dec_and_test(&ctx->file_attaches)) {
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

// [V29] 存储全局 mapping 以便 unmap 使用
static int wvm_open(struct inode *inode, struct file *filp) {
    struct wvm_kernel_file_context *file_context;

    (void)inode;
    file_context = kzalloc(sizeof(*file_context), GFP_KERNEL);
    if (!file_context) return -ENOMEM;
    mutex_init(&file_context->operation_lock);
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
    mutex_lock(&file_context->operation_lock);
    wvm_context_unbind_file(file_context, NULL);
    mutex_unlock(&file_context->operation_lock);
    mutex_destroy(&file_context->operation_lock);
    kfree(file_context);
    filp->private_data = NULL;

    return 0;
}

static long wvm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    void __user *argp = (void __user *)arg;
    struct wvm_kernel_file_context *file_context = filp->private_data;
    struct wvm_kernel_context *operation_context;
    long ret;

    if (!file_context)
        return -ENODEV;

    /*
     * DRAIN/DEQUEUE wait for the authority-side worker, while COMPLETE and
     * STOP are the calls that wake or settle those waits.  Holding the FD
     * operation mutex across any of them deadlocks a responder that uses the
     * same authority FD.  Pin the context under the mutex, then let the
     * bridge serialize ownership through memory_lock instead.
     */
    if (cmd == IOCTL_WVM_MEMORY_DEQUEUE ||
        cmd == IOCTL_WVM_MEMORY_COMPLETE ||
        cmd == IOCTL_WVM_MEMORY_STOP ||
        cmd == IOCTL_WVM_MEMORY_DRAIN) {
        mutex_lock(&file_context->operation_lock);
        operation_context = wvm_context_get_for_file(file_context);
        mutex_unlock(&file_context->operation_lock);
        if (!operation_context)
            return -ENOTCONN;
        ret = wvm_memory_bridge_ioctl(file_context, operation_context, cmd,
                                      argp);
        wvm_kernel_put_context(operation_context);
        return ret;
    }
    mutex_lock(&file_context->operation_lock);

    switch (cmd) {
    case IOCTL_WVM_MEMORY_OWNER:
    case IOCTL_WVM_MEMORY_DEQUEUE:
    case IOCTL_WVM_MEMORY_COMPLETE:
    case IOCTL_WVM_MEMORY_STOP:
    case IOCTL_WVM_MEMORY_DRAIN:
    case IOCTL_WVM_MEMORY_INVALIDATE:
    case IOCTL_WVM_MEMORY_QUIESCE:
        operation_context = wvm_context_get_for_file(file_context);
        if (!operation_context) {
            ret = -ENOTCONN;
            goto out;
        }
        ret = wvm_memory_bridge_ioctl(file_context, operation_context, cmd,
                                      argp);
        wvm_kernel_put_context(operation_context);
        goto out;
    case IOCTL_WVM_BIND_CONTEXT: {
        struct wvm_ioctl_context_bind request;

        if (copy_from_user(&request, argp, sizeof(request))) {
            ret = -EFAULT;
            goto out;
        }
        ret = wvm_context_bind_file(file_context, &request);
        if (!ret && copy_to_user(argp, &request, sizeof(request))) {
            wvm_context_unbind_file(file_context, NULL);
            ret = -EFAULT;
        }
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
        struct wvm_kernel_context *context =
            wvm_context_get_for_file(file_context);
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
            wvm_kernel_put_context(context);
            ret = -EFAULT;
            goto out;
        }
        wvm_kernel_put_context(context);
        ret = 0;
        goto out;
    }
    case IOCTL_SET_MEM_LAYOUT: {
        struct wvm_ioctl_mem_layout layout;
        struct wvm_kernel_context *layout_ctx;

        if (copy_from_user(&layout, argp, sizeof(layout))) {
            ret = -EFAULT;
            goto out;
        }
        layout_ctx = wvm_context_get_for_file(file_context);
        if (!layout_ctx) {
            ret = -ENODEV;
            goto out;
        }
        ret = wvm_set_mem_layout(layout_ctx, &layout);
        wvm_kernel_put_context(layout_ctx);
        goto out;
    }

    case IOCTL_SET_GATEWAY:
    case IOCTL_WVM_REMOTE_RUN:
    case IOCTL_WAIT_IRQ:
    case IOCTL_UPDATE_MEM_ROUTE:
    case IOCTL_UPDATE_MEMORY_PLACEMENT:
    case IOCTL_SET_VM_ID:
    case IOCTL_UPDATE_EPOCH:
    case IOCTL_UPDATE_CPU_ROUTE:
        ret = -EOPNOTSUPP;
        goto out;

    default:
        ret = -EINVAL;
        goto out;
    }
    ret = 0;

out:
    mutex_unlock(&file_context->operation_lock);
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
    struct wvm_kernel_context *context;
    struct file *old_file;
    int err;

    if (!file_context)
        return -ENODEV;
    mutex_lock(&file_context->operation_lock);
    context = wvm_context_get_for_file(file_context);
    if (!context || !file_context->bound) {
        err = -ENODEV;
        goto out_unlock;
    }

    /* F3: private address_space per context — same GPA must not share misc inode. */
    err = wvm_context_ensure_private_mapping(context);
    if (err) {
        wvm_kernel_put_context(context);
        goto out_unlock;
    }

    /* The operation reference becomes the VMA reference until vm_ops.close. */

    vma->vm_ops = &wvm_vm_ops;
    /* vm_insert_page uses vm_page_prot directly. The first PTE must be read
     * only, including on a write fault, so page_mkwrite captures a pre-image
     * before Linux grants writes via the VMA's unchanged VM_WRITE permission. */
    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags & ~VM_WRITE);
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
    err = 0;

out_unlock:
    mutex_unlock(&file_context->operation_lock);
    return err;
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

static void wvm_stop_workers(struct wvm_kernel_transport *workers)
{
    if (!workers)
        return;
    for (int i = 0; i < ARRAY_SIZE(workers->committer_threads); i++) {
        if (workers->committer_threads[i])
            kthread_stop(workers->committer_threads[i]);
    }
    kfree(workers);
}

static int __init wavevm_init(void)
{
    struct wvm_kernel_transport *workers;
    int result;

    hash_init(g_context_registry);
    init_waitqueue_head(&g_diff_wq);
    atomic_set(&g_diff_pending, 0);
    workers = kzalloc(sizeof(*workers), GFP_KERNEL);
    if (!workers)
        return -ENOMEM;
    for (int i = 0; i < ARRAY_SIZE(workers->committer_threads); i++) {
        workers->committer_threads[i] = kthread_run(
            committer_thread_fn, workers, "wvm_commit/%d", i);
        if (IS_ERR(workers->committer_threads[i])) {
            result = PTR_ERR(workers->committer_threads[i]);
            workers->committer_threads[i] = NULL;
            wvm_stop_workers(workers);
            return result;
        }
    }
    result = misc_register(&wvm_misc);
    if (result) {
        wvm_stop_workers(workers);
        return result;
    }
    g_module_transport = workers;
    pr_info("wavevm: context-bound local accelerator loaded\n");
    return 0;
}

static void __exit wavevm_exit(void)
{
    misc_deregister(&wvm_misc);
    wvm_stop_workers(g_module_transport);
    g_module_transport = NULL;
}

module_init(wavevm_init);
module_exit(wavevm_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WaveVM per-context local memory accelerator");

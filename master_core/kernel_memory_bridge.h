/* Included after the per-context definitions in kernel_backend.c. */
struct wvm_kernel_memory_pending {
    struct list_head link;
    struct wvm_ioctl_memory_operation operation;
    wait_queue_head_t wait;
    bool delivered;
    bool completed;
};

static void wvm_memory_owner_stop(struct wvm_kernel_context *ctx,
                                  struct wvm_kernel_file_context *owner)
{
    struct wvm_kernel_memory_pending *pending;

    mutex_lock(&ctx->memory_lock);
    if (ctx->memory_owner == owner) {
        ctx->memory_owner = NULL;
        list_for_each_entry(pending, &ctx->memory_pending, link) {
            pending->operation.status = -ESHUTDOWN;
            WRITE_ONCE(pending->completed, true);
            wake_up_all(&pending->wait);
        }
        wake_up_all(&ctx->memory_wait);
    }
    mutex_unlock(&ctx->memory_lock);
}

static int wvm_memory_call(struct wvm_kernel_context *ctx,
                           struct wvm_ioctl_memory_operation *operation)
{
    struct wvm_kernel_memory_pending *pending;
    long waited;
    int result;

    pending = kzalloc(sizeof(*pending), GFP_KERNEL);
    if (!pending)
        return -ENOMEM;
    pending->operation = *operation;
    init_waitqueue_head(&pending->wait);
    mutex_lock(&ctx->memory_lock);
    if (!ctx->memory_owner ||
        ctx->memory_pending_count >= WVM_KERNEL_MEMORY_MAX_PENDING ||
        ctx->memory_sequence == U64_MAX) {
        result = !ctx->memory_owner ? -ENOTCONN : -EAGAIN;
        mutex_unlock(&ctx->memory_lock);
        kfree(pending);
        return result;
    }
    pending->operation.request_id = ++ctx->memory_sequence;
    if (!memchr_inv(pending->operation.operation_id, 0, 16)) {
        memcpy(pending->operation.operation_id, &ctx->memory_nonce, 8);
        memcpy(pending->operation.operation_id + 8, &ctx->memory_sequence, 8);
    }
    /* Retain this semantic identity if the caller retries after a timeout. */
    memcpy(operation->operation_id, pending->operation.operation_id, 16);
    list_add_tail(&pending->link, &ctx->memory_pending);
    ctx->memory_pending_count++;
    wake_up_all(&ctx->memory_wait);
    mutex_unlock(&ctx->memory_lock);

    waited = wait_event_interruptible_timeout(pending->wait,
        READ_ONCE(pending->completed), msecs_to_jiffies(5000));
    mutex_lock(&ctx->memory_lock);
    if (pending->completed) {
        *operation = pending->operation;
        result = operation->status;
    } else {
        result = waited < 0 ? (int)waited : -ETIMEDOUT;
    }
    list_del(&pending->link);
    ctx->memory_pending_count--;
    mutex_unlock(&ctx->memory_lock);
    kfree(pending);
    return result;
}

static bool wvm_memory_queued(struct wvm_kernel_context *ctx)
{
    struct wvm_kernel_memory_pending *pending;
    bool queued = false;

    mutex_lock(&ctx->memory_lock);
    list_for_each_entry(pending, &ctx->memory_pending, link) {
        if (!pending->delivered && !pending->completed) {
            queued = true;
            break;
        }
    }
    mutex_unlock(&ctx->memory_lock);
    return queued;
}

static long wvm_memory_bridge_ioctl(
    struct wvm_kernel_file_context *file_ctx,
    struct wvm_kernel_context *ctx, unsigned int cmd, void __user *argp)
{
    struct wvm_kernel_memory_pending *pending;
    struct wvm_ioctl_memory_operation *operation;
    long result = 0;

    if (!file_ctx || !file_ctx->bound || !ctx)
        return -ENOTCONN;
    if (cmd == IOCTL_WVM_MEMORY_OWNER) {
        struct wvm_ioctl_memory_config config;
        struct wvm_kernel_context_identity identity;

        if (!file_ctx->authority || ctx->authority_pid != task_tgid(current))
            return -EPERM;
        if (copy_from_user(&config, argp, sizeof(config)))
            return -EFAULT;
        if (wvm_context_request_valid(&config.identity) != 0 ||
            !config.guest_physical_limit ||
            config.guest_physical_limit % PAGE_SIZE ||
            !config.range_count || config.range_count > ARRAY_SIZE(config.ranges))
            return -EINVAL;
        for (int i = 0; i < config.range_count; i++) {
            uint64_t start = config.ranges[i].start;
            uint64_t size = config.ranges[i].size;
            if (!size || (start | size) % PAGE_SIZE ||
                start >= config.guest_physical_limit ||
                size > config.guest_physical_limit - start ||
                (i && start < config.ranges[i - 1].start +
                              config.ranges[i - 1].size))
                return -EINVAL;
        }
        wvm_context_identity_from_ioctl(&identity, &config.identity);
        if (!wvm_context_identity_equal(&ctx->identity, &identity))
            return -EPERM;
        down_write(&ctx->mapping_sem);
        mutex_lock(&ctx->memory_lock);
        if (ctx->memory_owner || ctx->memory_config.guest_physical_limit)
            result = -EBUSY;
        else {
            ctx->memory_config = config;
            ctx->local_vnode_id = config.local_vnode;
            for (int i = 0; i < config.range_count; i++) {
                ctx->mem_slots[i].start_gpa = config.ranges[i].start;
                ctx->mem_slots[i].size = config.ranges[i].size;
                ctx->mem_slots[i].active = true;
            }
            /* Executors can fault before a frontend registers a narrower
             * RAM layout. Only the admitted GPA ranges are exposed here. */
            WRITE_ONCE(ctx->memory_owner, file_ctx);
            wake_up_all(&ctx->memory_wait);
        }
        mutex_unlock(&ctx->memory_lock);
        up_write(&ctx->mapping_sem);
        return result;
    }
    if (cmd == IOCTL_WVM_MEMORY_INVALIDATE) {
        struct wvm_ioctl_memory_invalidate invalidate;

        if (READ_ONCE(ctx->memory_owner) != file_ctx ||
            ctx->authority_pid != task_tgid(current))
            return -EPERM;
        if (copy_from_user(&invalidate, argp, sizeof(invalidate)))
            return -EFAULT;
        return wvm_memory_invalidate(ctx, &invalidate);
    }
    if (cmd == IOCTL_WVM_MEMORY_DRAIN) {
        if (!READ_ONCE(ctx->memory_owner))
            return -ENOTCONN;
        result = wait_event_interruptible_timeout(ctx->memory_wait,
            atomic_read(&ctx->dirty_pending) == 0 ||
            READ_ONCE(ctx->diff_failure) ||
            !READ_ONCE(ctx->memory_owner),
            msecs_to_jiffies(5000));
        if (result < 0)
            return result;
        if (READ_ONCE(ctx->diff_failure))
            return -EIO;
        if (!READ_ONCE(ctx->memory_owner))
            return -ESHUTDOWN;
        return result == 0 ? -ETIMEDOUT : 0;
    }
    if (READ_ONCE(ctx->memory_owner) != file_ctx ||
        ctx->authority_pid != task_tgid(current))
        return -EPERM;
    if (cmd == IOCTL_WVM_MEMORY_QUIESCE) {
        down_write(&ctx->mapping_sem);
        spin_lock(&ctx->page_tree_lock);
        WRITE_ONCE(ctx->memory_quiescing, true);
        spin_unlock(&ctx->page_tree_lock);
        if (ctx->mapping)
            unmap_mapping_range(ctx->mapping, 0, 0, 1);
        up_write(&ctx->mapping_sem);
        wake_up_all(&ctx->memory_wait);
        return 0;
    }
    if (cmd == IOCTL_WVM_MEMORY_STOP) {
        wvm_memory_owner_stop(ctx, file_ctx);
        return 0;
    }
    operation = kzalloc(sizeof(*operation), GFP_KERNEL);
    if (!operation)
        return -ENOMEM;
    if (cmd == IOCTL_WVM_MEMORY_DEQUEUE) {
        result = wait_event_interruptible_timeout(ctx->memory_wait,
            READ_ONCE(ctx->memory_owner) != file_ctx || wvm_memory_queued(ctx),
            msecs_to_jiffies(250));
        if (result < 0)
            goto out;
        result = -EAGAIN;
        mutex_lock(&ctx->memory_lock);
        if (ctx->memory_owner != file_ctx) {
            result = -ESHUTDOWN;
        } else {
            list_for_each_entry(pending, &ctx->memory_pending, link) {
                if (pending->delivered || pending->completed)
                    continue;
                *operation = pending->operation;
                /* Copy before claiming: a bad user buffer must not strand it. */
                if (copy_to_user(argp, operation, sizeof(*operation))) {
                    result = -EFAULT;
                } else {
                    pending->delivered = true;
                    result = 0;
                }
                break;
            }
        }
        mutex_unlock(&ctx->memory_lock);
    } else if (cmd == IOCTL_WVM_MEMORY_COMPLETE) {
        if (copy_from_user(operation, argp, sizeof(*operation))) {
            result = -EFAULT;
            goto out;
        }
        result = -ENOENT;
        mutex_lock(&ctx->memory_lock);
        if (ctx->memory_owner != file_ctx) {
            result = -ESHUTDOWN;
            goto unlock;
        }
        list_for_each_entry(pending, &ctx->memory_pending, link) {
            const struct wvm_ioctl_memory_operation *request = &pending->operation;
            if (operation->request_id != request->request_id)
                continue;
            if (pending->completed || !pending->delivered ||
                operation->kind != request->kind ||
                operation->gpa != request->gpa ||
                operation->base_version != request->base_version ||
                memcmp(operation->operation_id, request->operation_id, 16) ||
                (request->kind == WVM_KERNEL_MEMORY_COMMIT &&
                 (operation->offset != request->offset ||
                  operation->data_bytes != request->data_bytes ||
                  memcmp(operation->data, request->data, request->data_bytes))) ||
                operation->status > 0 || operation->reserved != 0 ||
                (operation->status == 0 &&
                 (operation->result_version == 0 ||
                  (operation->kind == WVM_KERNEL_MEMORY_COMMIT &&
                   operation->result_version <= request->base_version) ||
                  (operation->kind == WVM_KERNEL_MEMORY_READ &&
                   operation->data_bytes != WVM_KERNEL_MEMORY_PAGE_BYTES)))) {
                result = -EPROTO;
                break;
            }
            pending->operation = *operation;
            WRITE_ONCE(pending->completed, true);
            wake_up_all(&pending->wait);
            result = 0;
            break;
        }
unlock:
        mutex_unlock(&ctx->memory_lock);
    } else {
        result = -ENOTTY;
    }
out:
    kfree(operation);
    return result;
}

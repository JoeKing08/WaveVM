#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include "kernel_memory.h"
#include "memory_service.h"

static int memory_status(uint16_t status)
{
    switch (status) {
    case WVM_MEM_ACK_SUCCESS: return 0;
    case WVM_MEM_ACK_STALE: return -ESTALE;
    case WVM_MEM_ACK_NOT_FOUND: return -ENOENT;
    case WVM_MEM_ACK_BACKPRESSURE: return -EAGAIN;
    default: return -EIO;
    }
}

int wvm_kernel_memory_execute(struct wvm_ioctl_memory_operation *operation)
{
    char error[192] = {0};
    int result;

    if (!operation)
        return -EINVAL;
    operation->result_version = 0;
    if (operation->gpa % WVM_MEMORY_PAGE_BYTES || operation->reserved ||
        operation->data_bytes > WVM_MEMORY_PAGE_BYTES ||
        operation->offset > WVM_MEMORY_PAGE_BYTES - operation->data_bytes) {
        result = -EINVAL;
    } else if (operation->kind == WVM_KERNEL_MEMORY_READ) {
        struct wvm_mem_ack ack = {0};

        result = wvm_memory_service_global_request_fault(
            operation->gpa, operation->operation_id, 1, &ack,
            operation->data, error, sizeof(error));
        if (result == 0)
            result = memory_status(ack.status);
        if (result == 0 && (ack.gpa != operation->gpa || !ack.version ||
                           ack.data_bytes != WVM_MEMORY_PAGE_BYTES))
            result = -EPROTO;
        if (result == 0) {
            operation->result_version = ack.version;
            operation->data_bytes = WVM_MEMORY_PAGE_BYTES;
        }
    } else if (operation->kind == WVM_KERNEL_MEMORY_COMMIT &&
               operation->base_version && operation->data_bytes) {
        struct wvm_mem_commit_ack ack = {0};

        result = wvm_memory_service_global_request_commit(
            operation->gpa, operation->base_version, operation->offset,
            operation->data, operation->data_bytes, operation->operation_id,
            1, &ack, error, sizeof(error));
        if (result == 0)
            result = memory_status(ack.status);
        if (result == 0 && (ack.gpa != operation->gpa ||
                           ack.result_version <= operation->base_version))
            result = -EPROTO;
        if (result == 0)
            operation->result_version = ack.result_version;
    } else {
        result = -EINVAL;
    }
    operation->status = result;
    return result;
}

static void *memory_worker(void *opaque)
{
    struct wvm_kernel_memory_bridge *bridge = opaque;
    struct wvm_ioctl_memory_operation operation;

    while (!__atomic_load_n(&bridge->stopping, __ATOMIC_ACQUIRE)) {
        memset(&operation, 0, sizeof(operation));
        if (ioctl(bridge->fd, IOCTL_WVM_MEMORY_DEQUEUE, &operation) != 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            __atomic_store_n(&bridge->stopping, 1, __ATOMIC_RELEASE);
            (void)ioctl(bridge->fd, IOCTL_WVM_MEMORY_STOP);
            break;
        }
        (void)wvm_kernel_memory_execute(&operation);
        if (ioctl(bridge->fd, IOCTL_WVM_MEMORY_COMPLETE, &operation) != 0 &&
            errno != ENOENT && errno != ESHUTDOWN) {
            fprintf(stderr, "[kernel-memory] completion failed: %s\n",
                    strerror(errno));
            __atomic_store_n(&bridge->stopping, 1, __ATOMIC_RELEASE);
            (void)ioctl(bridge->fd, IOCTL_WVM_MEMORY_STOP);
            break;
        }
    }
    return NULL;
}

int wvm_kernel_memory_start(struct wvm_kernel_memory_bridge *bridge, int fd,
                            const struct wvm_ioctl_memory_config *config)
{
    int result;

    if (!bridge || fd < 0 || !config)
        return -EINVAL;
    memset(bridge, 0, sizeof(*bridge));
    bridge->fd = fd;
    if (ioctl(fd, IOCTL_WVM_MEMORY_OWNER, config) != 0)
        return -errno;
    for (size_t i = 0; i < WVM_KERNEL_MEMORY_WORKERS; i++) {
        result = pthread_create(&bridge->workers[i], NULL, memory_worker,
                                bridge);
        if (result != 0) {
            (void)wvm_kernel_memory_stop(bridge);
            return -result;
        }
        bridge->worker_count++;
    }
    return 0;
}

int wvm_kernel_memory_stop(struct wvm_kernel_memory_bridge *bridge)
{
    int result = 0;

    if (!bridge || bridge->fd < 0)
        return 0;
    if (ioctl(bridge->fd, IOCTL_WVM_MEMORY_QUIESCE) != 0)
        result = -errno;
    if (ioctl(bridge->fd, IOCTL_WVM_MEMORY_DRAIN) != 0 && !result)
        result = -errno;
    __atomic_store_n(&bridge->stopping, 1, __ATOMIC_RELEASE);
    if (ioctl(bridge->fd, IOCTL_WVM_MEMORY_STOP) != 0 && result == 0)
        result = -errno;
    for (size_t i = 0; i < bridge->worker_count; i++) {
        int joined = pthread_join(bridge->workers[i], NULL);
        if (joined && result == 0)
            result = -joined;
    }
    bridge->worker_count = 0;
    bridge->fd = -1;
    return result;
}

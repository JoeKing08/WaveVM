#ifndef WAVEVM_NODE_RUNTIME_KERNEL_MEMORY_H
#define WAVEVM_NODE_RUNTIME_KERNEL_MEMORY_H

#include <pthread.h>
#include <stddef.h>
#include "../common_include/wavevm_ioctl.h"

#define WVM_KERNEL_MEMORY_WORKERS 4U

struct wvm_kernel_memory_bridge {
    int fd;
    int stopping;
    size_t worker_count;
    pthread_t workers[WVM_KERNEL_MEMORY_WORKERS];
};

int wvm_kernel_memory_execute(struct wvm_ioctl_memory_operation *operation);
int wvm_kernel_memory_start(struct wvm_kernel_memory_bridge *bridge, int fd,
                            const struct wvm_ioctl_memory_config *config);
int wvm_kernel_memory_stop(struct wvm_kernel_memory_bridge *bridge);

#endif

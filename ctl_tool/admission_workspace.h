#ifndef WVM_CTL_ADMISSION_WORKSPACE_H
#define WVM_CTL_ADMISSION_WORKSPACE_H

#include "../common_include/wavevm_coordinator.h"

#define WVM_CTL_ADMISSION_WORKSPACE_BYTES (64U * 1024U * 1024U)

/* Owns transaction output only; published evidence remains independent. */
struct wvm_ctl_admission_buffers {
    void *allocation;
    size_t allocated_bytes;
};

/* Zero-initialize buffers and prepared before first use. Failure preserves
 * the previous workspace and all its bindings. The caller serializes use. */
int wvm_ctl_admission_buffers_reset(
    struct wvm_ctl_admission_buffers *buffers, uint32_t requested_vcpus,
    size_t node_count, size_t member_count, size_t byte_limit,
    struct wvm_coordinator_prepared_vm *prepared,
    struct wvm_coordinator_prepare_options *options,
    struct wvm_activation_record *activation, char *error, size_t error_len);

void wvm_ctl_admission_buffers_destroy(
    struct wvm_ctl_admission_buffers *buffers,
    struct wvm_coordinator_prepared_vm *prepared);

#endif

#ifndef WVM_CTL_ADMISSION_READINESS_H
#define WVM_CTL_ADMISSION_READINESS_H

#include "../common_include/wavevm_control_plane.h"

int wvm_ctl_resume_runtime_readiness(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    size_t member_capacity, uint32_t requested_vcpus,
    wvm_control_plane_readiness_observer_fn observe_ready,
    void *observer_context, char *error, size_t error_len);

#endif

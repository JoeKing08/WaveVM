#ifndef WVM_CTL_ADMISSION_READINESS_H
#define WVM_CTL_ADMISSION_READINESS_H

#include "../common_include/wavevm_control_plane.h"
#include "../common_include/wavevm_admission_transport.h"

int wvm_ctl_probe_runtime_ready(
    struct wvm_control_plane *plane,
    const struct wvm_admission_transaction_record *transaction,
    const struct wvm_control_plane_runtime_manifest_entry *runtime_entry,
    size_t member_capacity, uint32_t max_vcpus,
    struct wvm_admission_transport *transport, char *error,
    size_t error_len);

/* F08: QUIESCE_RUNTIME for one durable runtime entry of a failing VM. */
int wvm_ctl_quiesce_runtime_execution(
    struct wvm_control_plane *plane,
    const struct wvm_admission_transaction_record *transaction,
    const struct wvm_control_plane_runtime_manifest_entry *runtime_entry,
    size_t member_capacity, uint32_t max_vcpus,
    struct wvm_admission_transport *transport, char *error,
    size_t error_len);

int wvm_ctl_resume_runtime_readiness(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    size_t member_capacity, uint32_t requested_vcpus,
    wvm_control_plane_readiness_observer_fn observe_ready,
    void *observer_context, char *error, size_t error_len);

#endif

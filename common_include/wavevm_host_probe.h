#ifndef WAVEVM_HOST_PROBE_H
#define WAVEVM_HOST_PROBE_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_capability.h"

/*
 * Host probe feature bits recorded on execution capability records.
 * AVAILABLE means the probe completed the WaveVM-required operation.
 */
#define WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT (1ULL << 0)
#define WVM_HOST_PROBE_TCG_USERFAULTFD (1ULL << 1)
#define WVM_HOST_PROBE_KVM_API (1ULL << 0)
#define WVM_HOST_PROBE_KVM_DIRTY_LOG (1ULL << 1)
#define WVM_HOST_PROBE_KVM_CREATE_VM (1ULL << 2)

struct wvm_host_probe_result {
    enum wvm_capability_state tcg_state;
    uint64_t tcg_feature_bits;
    uint32_t tcg_abi_version;
    uint16_t tcg_reason_code;

    enum wvm_capability_state kvm_state;
    uint64_t kvm_feature_bits;
    uint32_t kvm_abi_version;
    uint16_t kvm_reason_code;

    enum wvm_capability_state kernel_accel_state;
    uint64_t kernel_accel_feature_bits;
    uint32_t kernel_accel_abi_version;
    uint16_t kernel_accel_reason_code;

    uint64_t observed_at_ms;
    uint8_t probe_operation_id[WVM_IDENTITY_ID_BYTES];
};

/*
 * Bounded local host probes for Minimum capability evidence.
 * Does not mutate global host policy. Safe to call from user process.
 */
int wvm_host_probe_run(struct wvm_host_probe_result *out, char *error,
                       size_t error_len);

/*
 * Fill capability records from a completed probe. Caller owns storage for
 * up to *record_capacity entries; on success *record_count is set.
 * Emits EXECUTION_TCG, MODE_B_MEMORY, VM_ID_U32, and optionally
 * EXECUTION_KVM / KERNEL_ACCELERATION when probed AVAILABLE.
 */
int wvm_host_probe_fill_records(
    const struct wvm_host_probe_result *probe, uint32_t physical_node_id,
    uint64_t node_instance_id, uint64_t provider_instance_id,
    struct wvm_capability_record *records, size_t record_capacity,
    size_t *record_count, char *error, size_t error_len);

#include "wavevm_manifest.h"
#include "wavevm_fault_engine.h"

/*
 * Production probe→profile/exec selection (Minimum).
 * Never selects USERFAULTFD (unimplemented production path); never KVM without
 * dirty-log. fallback_decision: 1=primary, 2=AUTO KVM incomplete→TCG,
 * 3=restricted TCG SIGSEGV.
 */
struct wvm_host_probe_execution_choice {
    enum wvm_manifest_backend backend;
    uint16_t dirty_capture_engine;
    uint16_t read_fault_engine;
    uint16_t invalidation_engine;
    uint16_t fallback_decision;
};

int wvm_host_probe_select_execution(
    enum wvm_manifest_backend_policy policy, int all_tcg, int all_kvm,
    int all_kvm_dirty, int all_tcg_uffd,
    struct wvm_host_probe_execution_choice *out, char *error, size_t error_len);

/*
 * Build a canonical CapabilityReport from probe records and encode it.
 * profile_generation identifies the publication generation for publish-capabilities.
 * Caller owns *bytes_out (malloc); free with free().
 */
int wvm_host_probe_encode_report(
    const struct wvm_capability_record *records, size_t record_count,
    uint64_t profile_generation, uint8_t **bytes_out, size_t *size_out,
    char *error, size_t error_len);

#endif /* WAVEVM_HOST_PROBE_H */

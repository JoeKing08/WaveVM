#ifndef WAVEVM_ADMISSION_STAGE_H
#define WAVEVM_ADMISSION_STAGE_H

/*
 * Canonical participant payloads for the admission transaction.  The
 * envelope message type names the transition; these records carry every
 * authority input the receiving participant must verify before invoking its
 * local reservation or runtime gate.
 */

#include <stddef.h>
#include <stdint.h>

#include "wavevm_lifecycle.h"
#include "wavevm_runtime_dispatch.h"

#define WVM_RECORD_ADMISSION_RESERVATION_STAGE 0x102dU
#define WVM_RECORD_ADMISSION_PARTICIPANT_STAGE 0x102eU

enum wvm_admission_abort_reason {
    WVM_ADMISSION_ABORT_REASON_PRE_ACTIVATION_FAILURE = 1,
};

struct wvm_admission_reservation_stage {
    uint16_t message_type;
    const struct wvm_candidate_vm_manifest *candidate;
    const struct wvm_resource_reservation *reservation;
    const struct wvm_activation_record *activation;
    uint16_t abort_reason;
};

struct wvm_admission_participant_stage {
    uint16_t message_type;
    const struct wvm_candidate_vm_manifest *candidate;
    const struct wvm_node_runtime_manifest *runtime_manifest;
    const struct wvm_activation_record *activation;
    const struct wvm_runtime_dispatch_projection *dispatch_projection;
    uint16_t abort_reason;
};

/*
 * Decoding keeps every nested list in caller-owned bounded storage.  Each
 * reservation requirement receives one fixed-capacity slice from
 * reservation_requirement_leases; the caller must provide enough slices for
 * reservation_requirements.capacity * reservation_requirement_lease_capacity.
 */
struct wvm_admission_candidate_stage_storage {
    struct wvm_vcpu_assignment *vcpu_placements;
    size_t vcpu_placement_capacity;
    struct wvm_memory_chunk_assignment *memory_placements;
    size_t memory_placement_capacity;
    struct wvm_storage_assignment *storage_assignments;
    size_t storage_assignment_capacity;
    struct wvm_required_member *required_members;
    size_t required_member_capacity;
    struct wvm_capability_ref *required_capabilities;
    size_t required_capability_capacity;
    struct wvm_capability_ref *execution_capabilities;
    size_t execution_capability_capacity;
    struct wvm_reservation_requirement *reservation_requirements;
    size_t reservation_requirement_capacity;
    struct wvm_exclusive_lease *reservation_requirement_leases;
    size_t reservation_requirement_lease_capacity;
};

struct wvm_admission_reservation_stage_storage {
    struct wvm_admission_candidate_stage_storage candidate_storage;
    struct wvm_candidate_vm_manifest candidate;
    struct wvm_resource_reservation reservation;
    struct wvm_activation_record activation;
    struct wvm_exclusive_lease *reservation_leases;
    size_t reservation_lease_capacity;
    struct wvm_route_snapshot_key *activation_route_snapshot_keys;
    size_t activation_route_snapshot_key_capacity;
};

struct wvm_admission_participant_stage_storage {
    struct wvm_admission_candidate_stage_storage candidate_storage;
    struct wvm_candidate_vm_manifest candidate;
    struct wvm_node_runtime_manifest runtime_manifest;
    struct wvm_activation_record activation;
    struct wvm_runtime_dispatch_projection dispatch_projection;
    struct wvm_runtime_cpu_dispatch *dispatch_cpu_entries;
    size_t dispatch_cpu_capacity;
    struct wvm_runtime_memory_dispatch *dispatch_memory_entries;
    size_t dispatch_memory_capacity;
    struct wvm_vcpu_assignment *runtime_vcpu_assignments;
    size_t runtime_vcpu_assignment_capacity;
    struct wvm_memory_chunk_assignment *runtime_memory_assignments;
    size_t runtime_memory_assignment_capacity;
    struct wvm_storage_assignment *runtime_storage_assignments;
    size_t runtime_storage_assignment_capacity;
    struct wvm_capability_ref *runtime_capabilities;
    size_t runtime_capability_capacity;
    struct wvm_startup_dependency *runtime_dependencies;
    size_t runtime_dependency_capacity;
    struct wvm_route_snapshot_key *activation_route_snapshot_keys;
    size_t activation_route_snapshot_key_capacity;
};

/*
 * The returned payload is one complete canonical carrier record.  A caller
 * supplies the output storage and owns it through the enclosing envelope
 * submission.
 */
int wvm_admission_reservation_stage_encode(
    const struct wvm_admission_reservation_stage *stage, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_admission_participant_stage_encode(
    const struct wvm_admission_participant_stage *stage, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

/*
 * Decode a complete canonical carrier for MESSAGE_TYPE.  STAGE points only
 * into STORAGE and remains valid until that caller-owned storage is reused.
 */
int wvm_admission_reservation_stage_decode(
    const uint8_t *bytes, size_t encoded_bytes, uint16_t message_type,
    struct wvm_admission_reservation_stage_storage *storage,
    struct wvm_admission_reservation_stage *stage, char *error,
    size_t error_len);

int wvm_admission_participant_stage_decode(
    const uint8_t *bytes, size_t encoded_bytes, uint16_t message_type,
    struct wvm_admission_participant_stage_storage *storage,
    struct wvm_admission_participant_stage *stage, char *error,
    size_t error_len);

#endif /* WAVEVM_ADMISSION_STAGE_H */

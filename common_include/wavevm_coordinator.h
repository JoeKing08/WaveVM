#ifndef WAVEVM_COORDINATOR_H
#define WAVEVM_COORDINATOR_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_cluster.h"

struct wvm_local_reservation_registry;
struct wvm_membership_controller;
struct wvm_membership_controller_capture;

enum wvm_coordinator_id_purpose {
    WVM_COORDINATOR_ID_ADMISSION_TX = 1,
    WVM_COORDINATOR_ID_MANIFEST = 2,
    WVM_COORDINATOR_ID_ACTIVATION_FENCE = 3,
};

struct wvm_coordinator_id_provider {
    void *context;
    int (*allocate_id16)(void *context,
                         enum wvm_coordinator_id_purpose purpose,
                         uint8_t id[WVM_IDENTITY_ID_BYTES], char *error,
                         size_t error_len);
    int (*allocate_route_scope_id)(void *context, uint64_t *route_scope_id,
                                   char *error, size_t error_len);
};

struct wvm_coordinator_transaction {
    uint8_t request_id[WVM_IDENTITY_ID_BYTES];
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t admission_tx_id[WVM_IDENTITY_ID_BYTES];
    uint8_t manifest_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_vm_route_scope_key route_scope_key;
};

struct wvm_coordinator_prepared_route {
    struct wvm_route_snapshot_key route_snapshot_key;
    const struct wvm_required_ack_set *required_ack_set;
};

struct wvm_coordinator_activation_options {
    uint64_t coordinator_instance_id;
    uint64_t durable_decision_sequence;
    uint64_t decided_at;
};

/*
 * Capability and reservation owners provide a coherent immutable evidence
 * view alongside each membership capture. Membership itself is always read
 * from the durable membership controller, never from bootstrap NODE/ROUTE
 * files or a gateway cache.
 */
struct wvm_coordinator_membership_evidence {
    const struct wvm_capability_record *capability_records;
    size_t capability_record_count;
    const struct wvm_resource_reservation *resource_reservations;
    size_t resource_reservation_count;
    uint64_t inventory_revision;
    uint64_t capability_profile_generation;
};

/*
 * The host agent reserves these ports before prepare. The controller binds one
 * immutable launch plan to each selected physical node; launch scripts do not
 * choose per-VM ports or worker counts after admission.
 */
struct wvm_coordinator_node_launch_plan {
    uint32_t physical_node_id;
    uint64_t expected_node_instance_id;
    struct wvm_node_runtime_launch_plan launch_plan;
};

/*
 * Execution-profile selection is a prior capability-control decision. This
 * coordinator verifies that the selected profile is compatible with the
 * canonical request, then binds it immutably into the candidate manifest.
 */
struct wvm_coordinator_prepare_options {
    struct wvm_machine_config guest_machine;
    struct wvm_execution_fault_profile execution_profile;
    uint64_t memory_chunk_bytes;
    uint32_t host_overhead_vcpu_slots;
    uint64_t host_overhead_memory_bytes;
    uint16_t memory_consistency_policy;
    uint32_t guest_numa_nodes;
    uint16_t executor_class;
    uint64_t node_runtime_role_bits;
    uint64_t host_extra_role_bits;
    uint64_t candidate_created_at;
    uint64_t prepared_reservation_expiry_unix_time_ms;
    const struct wvm_coordinator_node_launch_plan *node_launch_plans;
    size_t node_launch_plan_count;
    const struct wvm_admission_node_listener_plan *node_listener_plans;
    size_t node_listener_plan_count;
    uint8_t *placement_plan_bytes;
    size_t placement_plan_bytes_capacity;
    uint8_t *candidate_manifest_bytes;
    size_t candidate_manifest_bytes_capacity;
};

/*
 * Before calling prepare, initialize:
 * - fence.selected_members storage;
 * - placement_plan list buffers;
 * - candidate.required_capabilities storage;
 * - reservations storage;
 * - node_runtime_manifests storage and each local list/dependency capacity.
 *
 * The coordinator fills all counts and immutable fields; it does not own
 * caller memory and performs no network or process launch.
 * Zero-initialize this structure before binding caller storage. The snapshot
 * and admission plan contain heap-owned scratch; release those with
 * wvm_coordinator_prepared_vm_cleanup() before resetting or retiring it.
 */
struct wvm_coordinator_prepared_vm {
    struct wvm_cluster_snapshot cluster_snapshot;
    struct wvm_admission_request admission_request;
    struct wvm_admission_plan admission_plan;
    struct wvm_admission_eligibility_fence fence;
    struct wvm_placement_plan placement_plan;
    size_t placement_plan_bytes;
    struct wvm_candidate_vm_manifest candidate;
    uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t *candidate_manifest_record;
    size_t candidate_manifest_record_capacity;
    size_t candidate_manifest_bytes;
    struct wvm_resource_reservation *reservations;
    size_t reservation_count;
    size_t reservation_capacity;
    /*
     * Optional node-local reservation authorities.  When supplied, prepare,
     * commit, and abort update these registries in the same lifecycle order
     * as the coordinator's derived reservation records.  Leaving this NULL
     * preserves the pure in-memory planning primitive for callers that only
     * need canonical records.
     */
    struct wvm_local_reservation_registry **reservation_registries;
    size_t reservation_registry_count;
    struct wvm_node_runtime_manifest *node_runtime_manifests;
    size_t node_runtime_manifest_count;
    size_t node_runtime_manifest_capacity;
};

/* Release planning scratch only, without aborting or freeing caller buffers. */
void wvm_coordinator_prepared_vm_cleanup(
    struct wvm_coordinator_prepared_vm *prepared_vm);

int wvm_coordinator_begin(
    const struct wvm_vm_request *request,
    struct wvm_vm_namespace_allocator *namespace_allocator,
    const struct wvm_coordinator_id_provider *id_provider,
    struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len);

/*
 * Build the only cluster record input used by production coordinator calls.
 * Capture storage and external evidence remain caller-owned and must stay
 * valid through the immediately following prepare or decision operation.
 */
int wvm_coordinator_capture_current_membership_records(
    const struct wvm_membership_controller *membership_controller,
    struct wvm_membership_controller_capture *membership_capture,
    const struct wvm_coordinator_membership_evidence *evidence,
    struct wvm_cluster_record_set *records_out, char *error, size_t error_len);

int wvm_coordinator_prepare(
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_coordinator_prepare_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len);

/*
 * Capture the current membership authority immediately before planning. This
 * is the production entry point; wvm_coordinator_prepare remains the pure
 * record-level primitive used by deterministic tests and recovery tooling.
 */
int wvm_coordinator_prepare_current_membership(
    const struct wvm_membership_controller *membership_controller,
    struct wvm_membership_controller_capture *membership_capture,
    const struct wvm_coordinator_membership_evidence *evidence,
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_coordinator_prepare_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len);

/*
 * Revalidate the captured proposal against the current canonical records and
 * create one ACTIVATE decision. The caller must preinitialize
 * activation->required_route_snapshot_keys storage with capacity >= 1, then
 * durably persist the returned record before committing any participant.
 */
int wvm_coordinator_decide_activation(
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_coordinator_id_provider *id_provider,
    const struct wvm_coordinator_activation_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_activation_record *activation, char *error, size_t error_len);

/*
 * Recapture membership before validating a prepared eligibility fence. A
 * membership or topology change between prepare and ACTIVATE therefore
 * produces the normal stale-fence rejection instead of consulting a retained
 * mutable controller view.
 */
int wvm_coordinator_decide_activation_current_membership(
    const struct wvm_membership_controller *membership_controller,
    struct wvm_membership_controller_capture *membership_capture,
    const struct wvm_coordinator_membership_evidence *evidence,
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_coordinator_id_provider *id_provider,
    const struct wvm_coordinator_activation_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_activation_record *activation, char *error, size_t error_len);

/*
 * Create the durable pre-activation ABORT decision for one prepared candidate.
 * This never invalidates or tears down an ACTIVATE decision.
 */
int wvm_coordinator_decide_abort(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_activation_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_activation_record *activation, char *error, size_t error_len);

/*
 * Promote locally represented reservations and runtime projections only after
 * the caller has durably persisted a matching ACTIVATE record. Remote
 * participant commit/ACK transport remains outside this in-memory primitive.
 */
int wvm_coordinator_commit_local(
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len);

/*
 * Validate ABORT inputs before contacting participants, without releasing any
 * local resources or clearing runtime projections.
 */
int wvm_coordinator_validate_abort(
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len);

/*
 * Release only PREPARED local records after a matching durable ABORT decision.
 * Remote abort/ACK transport and route-scope retirement remain caller-owned.
 */
int wvm_coordinator_abort_local(
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len);

#endif /* WAVEVM_COORDINATOR_H */

#ifndef WAVEVM_ADMISSION_ORCHESTRATOR_H
#define WAVEVM_ADMISSION_ORCHESTRATOR_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_control_plane.h"

/*
 * These callbacks are transport boundaries.  Each implementation must be
 * idempotent for the identity and manifest passed to it.  A failed prepare or
 * abort callback may have made partial progress, so abort callbacks must also
 * tolerate the item that failed to prepare.
 */
typedef int (*wvm_admission_route_stage_fn)(
    void *context, const struct wvm_coordinator_transaction *coordinator_transaction,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len);

typedef int (*wvm_admission_route_plan_fn)(
    void *context, const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len);

typedef int (*wvm_admission_reservation_stage_fn)(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation, char *error,
    size_t error_len);

/*
 * Commit callbacks receive the exact durable activation decision. This makes
 * the activation fence an explicit transport input rather than permitting a
 * participant to infer it from mutable local state.
 */
typedef int (*wvm_admission_reservation_commit_fn)(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len);

typedef int (*wvm_admission_participant_stage_fn)(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len);

typedef int (*wvm_admission_participant_commit_fn)(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len);

struct wvm_admission_orchestrator_input;

enum wvm_admission_input_phase {
    WVM_ADMISSION_INPUT_PREPARE = 1,
    WVM_ADMISSION_INPUT_ACTIVATION = 2,
};

/*
 * An authority supplies the current membership, capability, inventory, route,
 * and participant projections only for a newly allocated transaction.  A
 * durable replay therefore never reconstructs transient planning state.
 */
typedef int (*wvm_admission_input_prepare_fn)(
    void *context, const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len);

/*
 * Refresh the external capability/inventory/reservation evidence immediately
 * before one membership capture. The provider must replace the evidence view
 * in INPUT with a coherent immutable set for the requested phase. It may not
 * mutate membership state or any already prepared candidate.
 */
typedef int (*wvm_admission_input_refresh_fn)(
    void *context, enum wvm_admission_input_phase phase,
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len);

struct wvm_admission_orchestrator_callbacks {
    wvm_admission_route_plan_fn route_plan;
    wvm_admission_route_stage_fn route_prepare;
    wvm_admission_route_stage_fn route_commit;
    wvm_admission_route_stage_fn route_abort;
    wvm_admission_reservation_stage_fn reservation_prepare;
    wvm_admission_reservation_commit_fn reservation_commit;
    wvm_admission_reservation_stage_fn reservation_abort;
    wvm_admission_participant_stage_fn participant_prepare;
    wvm_admission_participant_commit_fn participant_commit;
    wvm_admission_participant_stage_fn participant_abort;
    wvm_admission_participant_stage_fn participant_ready;
};

/*
 * The control-plane owner installs one complete provider before opening its
 * service. Its storage and transport callbacks remain caller-owned and must
 * describe real registered authorities; an absent binding is a deliberate
 * fail-closed state.
 */
struct wvm_admission_authority {
    wvm_admission_input_prepare_fn prepare_input;
    wvm_admission_input_refresh_fn refresh_input;
    struct wvm_admission_orchestrator_callbacks callbacks;
    void *context;
};

int wvm_admission_authority_validate(
    const struct wvm_admission_authority *authority, char *error,
    size_t error_len);

struct wvm_admission_orchestrator_input {
    struct wvm_control_plane *control_plane;
    struct wvm_vm_namespace_allocator *namespace_allocator;
    const struct wvm_coordinator_id_provider *id_provider;
    const struct wvm_vm_request *request;
    const struct wvm_cluster_record_set *records;
    /*
     * Production callers may provide the live membership authority and its
     * immutable evidence view instead of supplying a pre-captured record set.
     * The orchestrator captures membership before prepare and recaptures it
     * before activation; pure record-level callers continue to use records.
     */
    const struct wvm_membership_controller *membership_controller;
    struct wvm_membership_controller_capture *membership_capture;
    const struct wvm_coordinator_membership_evidence *membership_evidence;
    struct wvm_coordinator_prepared_route *prepared_route;
    const struct wvm_coordinator_prepare_options *prepare_options;
    struct wvm_coordinator_prepared_vm *prepared_vm;
    uint64_t coordinator_instance_id;
    struct wvm_activation_record *activation;
    struct wvm_route_transaction_record *route_transaction;
    struct wvm_route_snapshot_record *route_snapshot;
    const struct wvm_admission_orchestrator_callbacks *callbacks;
    void *callback_context;
    wvm_admission_input_prepare_fn prepare_input;
    void *prepare_input_context;
    wvm_admission_input_refresh_fn refresh_input;
    void *refresh_input_context;
    struct wvm_coordinator_transaction *transaction_out;
    enum wvm_control_plane_submit_result *submit_result_out;
};

/*
 * Execute one create transaction through durable prepare/activate/commit.
 * A replay returns success without invoking transport callbacks.  If any
 * pre-activation stage fails, the function records ABORTING and cleans up
 * only prepared resources; it reaches ABORTED only when cleanup succeeds.
 * Any failure after ACTIVATE is durable leaves ACTIVATION_DECIDED for the
 * recovery/reconciliation path and never issues a pre-activation abort.
 */
int wvm_admission_orchestrator_run(
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len);

struct wvm_admission_recovery_input {
    struct wvm_control_plane *control_plane;
    const struct wvm_coordinator_transaction *transaction;
    struct wvm_coordinator_prepared_vm *prepared_vm;
    struct wvm_route_transaction_record *route_transaction;
    struct wvm_route_snapshot_record *route_snapshot;
    const struct wvm_admission_orchestrator_callbacks *callbacks;
    void *callback_context;
};

/*
 * Resume a durable transaction after process loss. The caller supplies
 * identity-validated in-memory projections reconstructed from the durable
 * candidate/runtime records. The decision and route transaction are reloaded
 * from the open, unfenced journal, never supplied by the caller. The candidate
 * must match its durable digest before any callback runs. ACTIVATION_DECIDED
 * is always resumed forward, while ABORTING is cleaned up toward ABORTED.
 */
int wvm_admission_orchestrator_recover(
    const struct wvm_admission_recovery_input *input, char *error,
    size_t error_len);

#endif /* WAVEVM_ADMISSION_ORCHESTRATOR_H */

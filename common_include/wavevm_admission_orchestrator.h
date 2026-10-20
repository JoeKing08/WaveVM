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
    /* STOP route-retirement request/ACK (not ABORT_*). Optional NULL skips. */
    wvm_admission_route_stage_fn route_retire;
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
     * Non-const: after durable ACTIVATE the production path records VM
     * dependencies via wvm_membership_controller_dependency_acquire and
     * publishes the activated route into the membership controller for
     * gateway-drain predecessor lookup (cluster-membership §5.4).
     */
    struct wvm_membership_controller *membership_controller;
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
    /*
     * Optional: when set, recover_activation / COMMITTED resume idempotently
     * republish membership route + dependency_acquire before readiness opens
     * (cluster-membership §5.4 / runtime-manifest-lifecycle).
     */
    struct wvm_membership_controller *membership_controller;
};

/*
 * Idempotent membership predecessor route + dependency_acquire used by
 * CREATE_VM post-ACTIVATE and by activation recovery. Failure must keep
 * readiness closed.
 */
int wvm_admission_register_membership_route_and_dependencies(
    struct wvm_membership_controller *controller,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_route_transaction_record *route_transaction,
    const struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len);

/*
 * Resume a durable transaction after process loss. The caller supplies
 * identity-validated in-memory projections reconstructed from the durable
 * candidate/runtime records. The decision and route transaction are reloaded
 * from the open, unfenced journal, never supplied by the caller. The candidate
 * must match its durable digest before any callback runs. ACTIVATION_DECIDED
 * is always resumed forward, while ABORTING is cleaned up toward ABORTED.
 * When membership_controller is set, membership route/deps are restored
 * before COMMITTED readiness opens.
 */
int wvm_admission_orchestrator_recover(
    const struct wvm_admission_recovery_input *input, char *error,
    size_t error_len);

/*
 * Mirror of wvm_admission_register_membership_route_and_dependencies for STOP.
 * Releases compute (kind 1) and gateway (kind 2) dependencies for this VM
 * incarnation only. Idempotent for already-absent dependencies. Does not
 * touch another VM's dependency rows.
 */
int wvm_admission_release_membership_dependencies(
    struct wvm_membership_controller *controller,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_route_transaction_record *route_transaction,
    const struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len);

/*
 * Minimum STOP orchestration (runtime-manifest-lifecycle §6.1 / goal §2):
 * RUNNING|STOPPING|RETIRING -> STOPPED with fail-closed cleanup:
 *   1) durable STOPPING
 *   2) route RETIRING (control-plane + optional membership begin_retire)
 *   3) durable RETIRING
 *   4) retire per-VM runtime names (socket/SHM/ready; ENOENT ok)
 *   5) release membership dependencies for this VM only
 *   6) wvm_coordinator_teardown_local (COMMITTED reservation release)
 *   7) route RETIRED then durable STOPPED
 *   8) optional namespace begin_retire + quarantine
 * Does not kill QEMU/executor processes (guest E2E is goal §7) and does not
 * invent HA/RECOVERY_REBIND/MIGRATE. Replay of STOPPED is success.
 */
struct wvm_admission_stop_input {
    struct wvm_control_plane *control_plane;
    const struct wvm_coordinator_transaction *transaction;
    struct wvm_coordinator_prepared_vm *prepared_vm;
    struct wvm_route_transaction_record *route_transaction;
    /* Required for ROUTE_RETIRE ACK when callbacks->route_retire is set. */
    const struct wvm_route_snapshot_record *route_snapshot;
    /*
     * Optional: when set, membership route must be ACTIVATED for this
     * operation_id so begin_retire/retire can run, and compute/gateway deps
     * for this VM incarnation are released.
     */
    struct wvm_membership_controller *membership_controller;
    /* Optional: after STOPPED, begin_retire + quarantine the VM namespace. */
    struct wvm_vm_namespace_allocator *namespace_allocator;
    /*
     * Optional production transport callbacks. When set, STOP issues
     * participant_abort (admitted-child stop) then reservation_abort
     * (COMMITTED lease release) before local name/reservation teardown.
     */
    const struct wvm_admission_orchestrator_callbacks *callbacks;
    void *callback_context;
};

int wvm_admission_orchestrator_stop(
    const struct wvm_admission_stop_input *input, char *error, size_t error_len);

#endif /* WAVEVM_ADMISSION_ORCHESTRATOR_H */

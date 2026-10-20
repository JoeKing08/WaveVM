#include "wavevm_admission_orchestrator.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_membership.h"
#include "wavevm_membership_controller.h"
#include "wavevm_manifest.h"
#include "wavevm_runtime_names.h"
#include "wavevm_coordinator.h"
#include "wavevm_identity.h"
#include "wavevm_sha256.h"

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static int route_snapshot_key_matches(
    const struct wvm_route_snapshot_key *left,
    const struct wvm_route_snapshot_key *right)
{
    return left && right &&
           left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  sizeof(left->snapshot_digest)) == 0;
}

static int callbacks_valid(
    const struct wvm_admission_orchestrator_callbacks *callbacks,
    char *error, size_t error_len)
{
    if (!callbacks) {
        set_error(error, error_len, "callbacks is NULL");
        return -1;
    }
    if (!callbacks->route_plan) {
        set_error(error, error_len, "route_plan is NULL");
        return -1;
    }
    if (!callbacks->route_prepare) {
        set_error(error, error_len, "route_prepare is NULL");
        return -1;
    }
    if (!callbacks->route_commit) {
        set_error(error, error_len, "route_commit is NULL");
        return -1;
    }
    if (!callbacks->route_abort) {
        set_error(error, error_len, "route_abort is NULL");
        return -1;
    }
    if (!callbacks->reservation_prepare) {
        set_error(error, error_len, "reservation_prepare is NULL");
        return -1;
    }
    if (!callbacks->reservation_commit) {
        set_error(error, error_len, "reservation_commit is NULL");
        return -1;
    }
    if (!callbacks->reservation_abort) {
        set_error(error, error_len, "reservation_abort is NULL");
        return -1;
    }
    if (!callbacks->participant_prepare) {
        set_error(error, error_len, "participant_prepare is NULL");
        return -1;
    }
    if (!callbacks->participant_commit) {
        set_error(error, error_len, "participant_commit is NULL");
        return -1;
    }
    if (!callbacks->participant_abort) {
        set_error(error, error_len, "participant_abort is NULL");
        return -1;
    }
    if (!callbacks->participant_ready) {
        set_error(error, error_len, "participant_ready is NULL");
        return -1;
    }
    return 0;
}

int wvm_admission_authority_validate(
    const struct wvm_admission_authority *authority, char *error,
    size_t error_len)
{
    if (!authority || !authority->prepare_input ||
        !authority->refresh_input ||
        callbacks_valid(&authority->callbacks, error, error_len) != 0) {
        set_error(error, error_len,
                  "admission authority binding is incomplete");
        return -1;
    }
    return 0;
}

static int callback_reservations(
    const struct wvm_admission_orchestrator_input *input,
    wvm_admission_reservation_stage_fn callback, char *error, size_t error_len)
{
    size_t i;

    for (i = 0; i < input->prepared_vm->reservation_count; i++) {
        if (callback(input->callback_context, &input->prepared_vm->candidate,
                     &input->prepared_vm->reservations[i], error,
                     error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int callback_participants(
    const struct wvm_admission_orchestrator_input *input,
    wvm_admission_participant_stage_fn callback, char *error, size_t error_len)
{
    size_t i;

    for (i = 0; i < input->prepared_vm->node_runtime_manifest_count; i++) {
        if (callback(input->callback_context, &input->prepared_vm->candidate,
                     &input->prepared_vm->node_runtime_manifests[i], error,
                     error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int callback_reservation_commits(
    const struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    size_t i;

    for (i = 0; i < input->prepared_vm->reservation_count; i++) {
        if (input->callbacks->reservation_commit(
                input->callback_context, &input->prepared_vm->candidate,
                &input->prepared_vm->reservations[i], input->activation,
                error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int callback_participant_commits(
    const struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    size_t i;

    for (i = 0; i < input->prepared_vm->node_runtime_manifest_count; i++) {
        if (input->callbacks->participant_commit(
                input->callback_context, &input->prepared_vm->candidate,
                &input->prepared_vm->node_runtime_manifests[i],
                input->activation, error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}


/*
 * After peer ROUTE_COMMIT and before control-plane ACTIVATED, publish the same
 * route into the membership controller and acquire durable VM dependencies.
 *
 * Specs:
 * - cluster-membership-topology-lifecycle.md §5.4: gateway drain PREPARE needs
 *   exactly one registered dependency for the VM incarnation and an activated
 *   predecessor snapshot in the membership controller.
 * - §4.1 / runtime-manifest-lifecycle: durable ACTIVATE is a post-decision
 *   dependency; drain must see it.
 * - wire-ipc-abi.md §4.2.2: DRAIN PREPARE successor binds that predecessor.
 *
 * dependency_kind values follow existing controller/test convention (nonzero
 * uint16; kind 1 = compute allocation, kind 2 = gateway route). Not the
 * StartupDependency enum.
 */
int wvm_admission_register_membership_route_and_dependencies(
    struct wvm_membership_controller *controller,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_route_transaction_record *route_transaction,
    const struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len)
{
    struct wvm_route_transaction_record preparing;
    struct wvm_membership_dependency dependency;
    size_t i;
    uint16_t route_state = 0;

    if (!controller || !transaction || !route_transaction || !prepared_vm) {
        set_error(error, error_len,
                  "membership dependency registration input is invalid");
        return -1;
    }
    if (transaction->vm_id == 0 || transaction->vm_incarnation == 0 ||
        transaction->manifest_generation == 0) {
        set_error(error, error_len,
                  "membership dependency requires VM identity");
        return -1;
    }

    preparing = *route_transaction;
    preparing.state = WVM_ROUTE_TRANSACTION_PREPARING;
    if (wvm_membership_controller_route_begin(controller, &preparing, error,
                                              error_len) != 0) {
        return -1;
    }
    for (i = 0; i < preparing.required_ack_set.entries.count; i++) {
        if (wvm_membership_controller_route_ack_prepare(
                controller, preparing.operation_id,
                &preparing.required_ack_set.entries.entries[i].member_key,
                error, error_len) != 0) {
            return -1;
        }
    }
    if (wvm_membership_controller_route_commit(controller,
                                               preparing.operation_id, error,
                                               error_len) != 0) {
        return -1;
    }
    if (wvm_membership_controller_route_state(controller, preparing.operation_id,
                                              &route_state, error,
                                              error_len) != 0 ||
        route_state != WVM_ROUTE_TRANSACTION_ACTIVATED) {
        set_error(error, error_len,
                  "membership route did not reach ACTIVATED after CREATE");
        return -1;
    }

    for (i = 0; i < prepared_vm->node_runtime_manifest_count; i++) {
        const struct wvm_node_runtime_manifest *manifest =
            &prepared_vm->node_runtime_manifests[i];

        memset(&dependency, 0, sizeof(dependency));
        dependency.member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        dependency.member_key.role_id = manifest->physical_node_id;
        dependency.member_key.instance_id = manifest->expected_node_instance_id;
        dependency.vm_id = transaction->vm_id;
        dependency.vm_incarnation = transaction->vm_incarnation;
        dependency.manifest_generation = transaction->manifest_generation;
        dependency.dependency_kind = 1; /* compute allocation dependency */
        if (wvm_membership_controller_dependency_acquire(
                controller, &dependency, error, error_len) != 0) {
            return -1;
        }
    }
    for (i = 0; i < route_transaction->required_ack_set.entries.count; i++) {
        const struct wvm_required_ack_entry *ack =
            &route_transaction->required_ack_set.entries.entries[i];

        if (ack->member_key.role_type != WVM_MANIFEST_ROLE_GATEWAY) {
            continue;
        }
        memset(&dependency, 0, sizeof(dependency));
        dependency.member_key = ack->member_key;
        dependency.vm_id = transaction->vm_id;
        dependency.vm_incarnation = transaction->vm_incarnation;
        dependency.manifest_generation = transaction->manifest_generation;
        dependency.dependency_kind = 2; /* gateway route dependency */
        if (wvm_membership_controller_dependency_acquire(
                controller, &dependency, error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int durable_route_state(
    const struct wvm_admission_orchestrator_input *input, uint16_t state,
    char *error, size_t error_len)
{
    input->route_transaction->state = state;
    return wvm_control_plane_record_route_transaction(
        input->control_plane, input->route_transaction, error, error_len);
}

static int abort_pre_activation(
    const struct wvm_admission_orchestrator_input *input,
    struct wvm_coordinator_transaction *transaction, int route_prepared,
    char *error, size_t error_len)
{
    int cleanup_failed = 0;
    char cleanup_error[256] = {0};
    struct wvm_coordinator_activation_options options;

    if (wvm_control_plane_activation_options(
            input->control_plane, input->coordinator_instance_id, &options,
            error, error_len) != 0 ||
        wvm_coordinator_decide_abort(
            transaction, &options, input->prepared_vm,
            input->activation, error, error_len) != 0 ||
        wvm_control_plane_record_activation(
            input->control_plane, transaction, input->activation, error,
            error_len) != 0) {
        return -1;
    }

    if (callback_participants(input, input->callbacks->participant_abort,
                              cleanup_error, sizeof(cleanup_error)) != 0) {
        cleanup_failed = 1;
    }
    if (callback_reservations(input, input->callbacks->reservation_abort,
                              cleanup_error, sizeof(cleanup_error)) != 0) {
        cleanup_failed = 1;
    }
    if (wvm_coordinator_abort_local(transaction, input->prepared_vm,
                                    input->activation, cleanup_error,
                                    sizeof(cleanup_error)) != 0) {
        cleanup_failed = 1;
    }
    if (route_prepared &&
        input->callbacks->route_abort(input->callback_context,
                                       transaction, input->route_transaction,
                                       input->route_snapshot, cleanup_error,
                                       sizeof(cleanup_error)) != 0) {
        cleanup_failed = 1;
    }
    if (!cleanup_failed &&
        durable_route_state(input, WVM_ROUTE_TRANSACTION_ABORTED, cleanup_error,
                            sizeof(cleanup_error)) != 0) {
        cleanup_failed = 1;
    }
    if (!cleanup_failed &&
        wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_ABORTING,
            WVM_LIFECYCLE_ABORTED, cleanup_error, sizeof(cleanup_error)) != 0) {
        cleanup_failed = 1;
    }
    if (cleanup_failed) {
        set_error(error, error_len, "pre-activation cleanup is incomplete: %s",
                  cleanup_error[0] ? cleanup_error : "unknown cleanup error");
        return -1;
    }
    return -1;
}

static int abort_unpersisted_local(
    const struct wvm_admission_orchestrator_input *input,
    struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len)
{
    struct wvm_coordinator_activation_options options;

    if (wvm_control_plane_activation_options(
            input->control_plane, input->coordinator_instance_id, &options,
            error, error_len) != 0 ||
        wvm_coordinator_decide_abort(
            transaction, &options, input->prepared_vm,
            input->activation, error, error_len) != 0 ||
        wvm_coordinator_abort_local(transaction, input->prepared_vm,
                                    input->activation, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

static int abort_identity_transaction(
    const struct wvm_admission_orchestrator_input *input,
    struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len)
{
    char prior[256];
    char cleanup_error[256] = {0};

    if (error && error_len != 0 && error[0] != '\0') {
        (void)snprintf(prior, sizeof(prior), "%s", error);
    } else {
        prior[0] = '\0';
    }
    if (wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_IDENTITY_ALLOCATED,
            WVM_LIFECYCLE_ABORTING, cleanup_error, sizeof(cleanup_error)) != 0 ||
        wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_ABORTING,
            WVM_LIFECYCLE_ABORTED, cleanup_error, sizeof(cleanup_error)) != 0) {
        if (prior[0] != '\0') {
            set_error(error, error_len, "%s (abort cleanup: %s)", prior,
                      cleanup_error[0] ? cleanup_error : "failed");
        } else if (cleanup_error[0] != '\0') {
            set_error(error, error_len, "%s", cleanup_error);
        }
        return -1;
    }
    if (prior[0] != '\0') {
        set_error(error, error_len, "%s", prior);
    }
    return -1;
}

static int identity_input_valid(
    const struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    if (!input || !input->control_plane || !input->namespace_allocator ||
        !input->id_provider || !input->request || !input->transaction_out ||
        !input->submit_result_out) {
        set_error(error, error_len,
                  "admission identity transaction input is invalid");
        return -1;
    }
    return 0;
}

static int prepared_input_valid(
    const struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    if (!input || (input->records && input->membership_controller) ||
        (!input->records &&
         (!input->membership_controller || !input->membership_capture ||
          !input->refresh_input)) ||
        !input->prepared_route ||
        !input->prepare_options || !input->prepared_vm ||
        input->coordinator_instance_id == 0 || !input->activation ||
        !input->route_transaction || !input->route_snapshot) {
        set_error(error, error_len,
                  "admission authority did not supply complete planning input");
        return -1;
    }
    return callbacks_valid(input->callbacks, error, error_len);
}

static int refresh_membership_evidence(
    struct wvm_admission_orchestrator_input *input,
    enum wvm_admission_input_phase phase,
    const struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len)
{
    if (!input || !input->membership_controller) {
        return 0;
    }
    if (!input->refresh_input ||
        input->refresh_input(input->refresh_input_context, phase,
                             input->request, transaction, input, error,
                             error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "admission authority could not refresh evidence");
        }
        return -1;
    }
    if (!input->membership_evidence) {
        set_error(error, error_len,
                  "admission authority returned no membership evidence");
        return -1;
    }
    return 0;
}

static int route_plan_matches_records(
    const struct wvm_cluster_record_set *records,
    const struct wvm_route_snapshot_record *route_snapshot,
    const struct wvm_route_transaction_record *route_transaction, char *error,
    size_t error_len)
{
    if (!records || !route_snapshot || !route_transaction ||
        route_snapshot->membership_revision != records->membership_revision ||
        route_snapshot->route_snapshot_key.topology_revision !=
            records->topology_revision ||
        route_transaction->route_snapshot_key.topology_revision !=
            records->topology_revision) {
        set_error(error, error_len,
                  "admission route plan is stale for captured membership");
        return -1;
    }
    return 0;
}

int wvm_admission_orchestrator_run(
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    enum wvm_control_plane_submit_result submit_result;
    struct wvm_coordinator_transaction *transaction;
    struct wvm_cluster_record_set captured_records;
    struct wvm_coordinator_activation_options activation_options;
    const struct wvm_cluster_record_set *records;
    int route_prepared = 0;
    int candidate_durable = 0;
    int route_durable = 0;

    if (identity_input_valid(input, error, error_len) != 0) {
        return -1;
    }
    transaction = input->transaction_out;
    records = input->records;
    if (wvm_control_plane_begin(
            input->control_plane, input->request, input->namespace_allocator,
            input->id_provider, &submit_result, transaction, error,
            error_len) != 0) {
        return -1;
    }
    *input->submit_result_out = submit_result;
    if (submit_result == WVM_CONTROL_PLANE_SUBMIT_REPLAY) {
        return 0;
    }
    if (!input->prepare_input ||
        input->prepare_input(input->prepare_input_context, input->request,
                             transaction, input, error, error_len) != 0 ||
        prepared_input_valid(input, error, error_len) != 0) {
        return abort_identity_transaction(input, transaction, error, error_len);
    }
    if (refresh_membership_evidence(input, WVM_ADMISSION_INPUT_PREPARE,
                                    transaction, error, error_len) != 0) {
        return abort_identity_transaction(input, transaction, error, error_len);
    }
    if (!records) {
        if (wvm_coordinator_capture_current_membership_records(
                input->membership_controller, input->membership_capture,
                input->membership_evidence, &captured_records, error,
                error_len) != 0) {
            return abort_identity_transaction(input, transaction, error,
                                              error_len);
        }
        records = &captured_records;
    }
    if (input->callbacks->route_plan(
            input->callback_context, transaction, records,
            input->prepared_route, input->route_transaction,
            input->route_snapshot, error, error_len) != 0) {
        return abort_identity_transaction(input, transaction, error, error_len);
    }
    if (route_plan_matches_records(records, input->route_snapshot,
                                   input->route_transaction, error,
                                   error_len) != 0) {
        return abort_identity_transaction(input, transaction, error, error_len);
    }
    if (wvm_coordinator_prepare(
            input->request, transaction, records, input->prepared_route,
            input->prepare_options, input->prepared_vm, error, error_len) != 0) {
        return abort_identity_transaction(input, transaction, error, error_len);
    }
    if (wvm_route_snapshot_record_binds_transaction(
            input->route_snapshot, input->route_transaction, error,
            error_len) != 0 ||
        input->route_transaction->state != WVM_ROUTE_TRANSACTION_PREPARING ||
        !route_snapshot_key_matches(
            &input->route_transaction->route_snapshot_key,
            &input->prepared_vm->candidate.prepared_route_snapshot_key)) {
        if (abort_unpersisted_local(input, transaction, error, error_len) != 0) {
            return -1;
        }
        set_error(error, error_len,
                  "admission route transaction does not match candidate");
        return abort_identity_transaction(input, transaction, error, error_len);
    }
    if (wvm_control_plane_record_candidate(
            input->control_plane, transaction, &input->prepared_vm->candidate,
            error, error_len) != 0) {
        (void)abort_unpersisted_local(input, transaction, NULL, 0);
        return -1;
    }
    candidate_durable = 1;
    if (wvm_control_plane_record_route_transaction(
            input->control_plane, input->route_transaction, error,
            error_len) != 0) {
        (void)wvm_coordinator_abort_local(transaction, input->prepared_vm,
                                          input->activation, NULL, 0);
        return -1;
    }
    route_durable = 1;
    if (wvm_control_plane_record_route_snapshot(
            input->control_plane, input->route_transaction->operation_id,
            input->route_snapshot, error, error_len) != 0) {
        return abort_pre_activation(input, transaction, route_prepared, error,
                                    error_len);
    }
    route_prepared = 1;
    if (input->callbacks->route_prepare(input->callback_context,
                                        transaction, input->route_transaction,
                                        input->route_snapshot, error,
                                        error_len) != 0) {
        return abort_pre_activation(input, transaction, route_prepared, error,
                                    error_len);
    }
    if (wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_PLANNED,
            WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED, error, error_len) != 0 ||
        callback_reservations(input, input->callbacks->reservation_prepare,
                              error, error_len) != 0) {
        return candidate_durable && route_durable
                   ? abort_pre_activation(input, transaction, route_prepared,
                                          error, error_len)
                   : -1;
    }
    if (wvm_control_plane_transition(
            input->control_plane, transaction,
            WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED,
            WVM_LIFECYCLE_RESERVATIONS_PREPARED, error, error_len) != 0 ||
        callback_participants(input, input->callbacks->participant_prepare,
                              error, error_len) != 0 ||
        wvm_control_plane_transition(
            input->control_plane, transaction,
            WVM_LIFECYCLE_RESERVATIONS_PREPARED,
            WVM_LIFECYCLE_PARTICIPANTS_PREPARED, error, error_len) != 0 ||
        (refresh_membership_evidence(input, WVM_ADMISSION_INPUT_ACTIVATION,
                                    transaction, error, error_len) != 0) ||
        wvm_control_plane_activation_options(
            input->control_plane, input->coordinator_instance_id,
            &activation_options, error, error_len) != 0 ||
        (input->membership_controller
             ? wvm_coordinator_decide_activation_current_membership(
                   input->membership_controller, input->membership_capture,
                   input->membership_evidence, input->request, transaction,
                   input->prepared_route, input->id_provider,
                   &activation_options, input->prepared_vm,
                   input->activation, error, error_len)
             : wvm_coordinator_decide_activation(
                   input->request, transaction, records,
                   input->prepared_route, input->id_provider,
                   &activation_options, input->prepared_vm,
                   input->activation, error, error_len)) != 0) {
        return abort_pre_activation(input, transaction, route_prepared, error,
                                    error_len);
    }
    /* A failed write may still have persisted ACTIVATE. Never send ABORT. */
    if (wvm_control_plane_record_activation(input->control_plane, transaction,
                                            input->activation, error,
                                            error_len) != 0) {
        return -1;
    }

    /* From this point the durable activation decision is authoritative. */
    if (wvm_coordinator_commit_local(transaction, input->prepared_vm,
                                     input->activation, error, error_len) != 0 ||
        callback_reservation_commits(input, error, error_len) != 0 ||
        callback_participant_commits(input, error, error_len) != 0) {
        return -1;
    }
    {
        size_t i;

        for (i = 0; i < input->prepared_vm->node_runtime_manifest_count; i++) {
            if (wvm_control_plane_record_runtime_manifest(
                    input->control_plane, transaction,
                    &input->prepared_vm->node_runtime_manifests[i], error,
                    error_len) != 0) {
                return -1;
            }
        }
    }
    if (input->callbacks->route_commit(input->callback_context,
                                        transaction, input->route_transaction,
                                        input->route_snapshot, error,
                                        error_len) != 0) {
        return -1;
    }
    /*
     * Fail-closed: membership predecessor + dependency_acquire must succeed
     * before control-plane ACTIVATED/COMMITTED so gateway drain §5.4 can see
     * the live dependency without an offline seed.
     */
    if (input->membership_controller &&
        wvm_admission_register_membership_route_and_dependencies(
            input->membership_controller, transaction, input->route_transaction,
            input->prepared_vm, error, error_len) != 0) {
        return -1;
    }
    if (durable_route_state(input, WVM_ROUTE_TRANSACTION_ACTIVATED, error,
                            error_len) != 0 ||
        wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_ACTIVATION_DECIDED,
            WVM_LIFECYCLE_COMMITTED, error, error_len) != 0) {
        return -1;
    }
    {
        int ready_status = wvm_control_plane_start_if_participants_ready(
            input->control_plane, transaction,
            &input->prepared_vm->candidate,
            input->prepared_vm->node_runtime_manifests,
            input->prepared_vm->node_runtime_manifest_count,
            input->callbacks->participant_ready, input->callback_context,
            error, error_len);

        if (ready_status != 0) {
            return ready_status == -EAGAIN ? -EAGAIN : -1;
        }
    }
    return 0;
}

int wvm_admission_release_membership_dependencies(
    struct wvm_membership_controller *controller,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_route_transaction_record *route_transaction,
    const struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len)
{
    struct wvm_membership_dependency dependency;
    size_t i;

    if (!controller || !transaction || !route_transaction || !prepared_vm) {
        set_error(error, error_len,
                  "membership dependency release input is invalid");
        return -1;
    }
    if (transaction->vm_id == 0 || transaction->vm_incarnation == 0 ||
        transaction->manifest_generation == 0) {
        set_error(error, error_len,
                  "membership dependency release requires VM identity");
        return -1;
    }

    for (i = 0; i < prepared_vm->node_runtime_manifest_count; i++) {
        const struct wvm_node_runtime_manifest *manifest =
            &prepared_vm->node_runtime_manifests[i];

        memset(&dependency, 0, sizeof(dependency));
        dependency.member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        dependency.member_key.role_id = manifest->physical_node_id;
        dependency.member_key.instance_id = manifest->expected_node_instance_id;
        dependency.vm_id = transaction->vm_id;
        dependency.vm_incarnation = transaction->vm_incarnation;
        dependency.manifest_generation = transaction->manifest_generation;
        dependency.dependency_kind = 1; /* compute allocation dependency */
        if (wvm_membership_controller_dependency_release(
                controller, &dependency, error, error_len) != 0) {
            return -1;
        }
    }
    for (i = 0; i < route_transaction->required_ack_set.entries.count; i++) {
        const struct wvm_required_ack_entry *ack =
            &route_transaction->required_ack_set.entries.entries[i];

        if (ack->member_key.role_type != WVM_MANIFEST_ROLE_GATEWAY) {
            continue;
        }
        memset(&dependency, 0, sizeof(dependency));
        dependency.member_key = ack->member_key;
        dependency.vm_id = transaction->vm_id;
        dependency.vm_incarnation = transaction->vm_incarnation;
        dependency.manifest_generation = transaction->manifest_generation;
        dependency.dependency_kind = 2; /* gateway route dependency */
        if (wvm_membership_controller_dependency_release(
                controller, &dependency, error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int stop_persist_route_state(
    struct wvm_control_plane *plane,
    struct wvm_route_transaction_record *route_transaction, uint16_t state,
    char *error, size_t error_len)
{
    route_transaction->state = state;
    return wvm_control_plane_record_route_transaction(plane, route_transaction,
                                                      error, error_len);
}

static int stop_retire_runtime_names(
    const struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len)
{
    size_t i;

    if (!prepared_vm || !prepared_vm->node_runtime_manifests) {
        set_error(error, error_len, "runtime name retirement lacks manifests");
        return -1;
    }
    for (i = 0; i < prepared_vm->node_runtime_manifest_count; i++) {
        struct wvm_runtime_name_set names;

        if (wvm_runtime_name_set_derive(
                &prepared_vm->node_runtime_manifests[i].local_names, &names,
                error, error_len) != 0 ||
            wvm_runtime_name_set_retire(&names, error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int stop_quarantine_namespace(
    struct wvm_vm_namespace_allocator *allocator,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_route_transaction_record *route_transaction, char *error,
    size_t error_len)
{
    uint8_t retirement_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_sha256_ctx ctx;
    const struct wvm_vm_namespace_record *record;

    if (!allocator) {
        return 0;
    }
    record = wvm_vm_namespace_find(allocator, transaction->vm_id);
    if (!record) {
        set_error(error, error_len, "STOP namespace record was not found");
        return -1;
    }
    if (record->state == WVM_VM_NAMESPACE_QUARANTINED ||
        record->state == WVM_VM_NAMESPACE_FREE) {
        return 0;
    }
    if (record->state == WVM_VM_NAMESPACE_ACTIVE ||
        record->state == WVM_VM_NAMESPACE_ALLOCATED) {
        if (wvm_vm_namespace_begin_retire(allocator, transaction->vm_id,
                                          transaction->vm_incarnation, error,
                                          error_len) != 0) {
            return -1;
        }
    } else if (record->state != WVM_VM_NAMESPACE_RETIRING) {
        set_error(error, error_len,
                  "STOP namespace is not in a retirement-capable state");
        return -1;
    }
    wvm_sha256_init(&ctx);
    wvm_sha256_update(&ctx, transaction->admission_tx_id,
                      sizeof(transaction->admission_tx_id));
    wvm_sha256_update(&ctx, route_transaction->operation_id,
                      sizeof(route_transaction->operation_id));
    wvm_sha256_final(&ctx, retirement_digest);
    return wvm_vm_namespace_quarantine(allocator, transaction->vm_id,
                                       transaction->vm_incarnation,
                                       retirement_digest, 1, error,
                                       error_len);
}

int wvm_admission_orchestrator_stop(
    const struct wvm_admission_stop_input *input, char *error, size_t error_len)
{
    const struct wvm_control_plane_entry *entry;
    enum wvm_lifecycle_state state;
    uint16_t membership_route_state = 0;

    if (!input || !input->control_plane || !input->transaction ||
        !input->prepared_vm || !input->route_transaction) {
        set_error(error, error_len, "STOP input is invalid");
        return -1;
    }
    entry = wvm_control_plane_find_request(input->control_plane,
                                           input->transaction->request_id);
    if (!entry || entry->transaction.vm_id != input->transaction->vm_id ||
        entry->transaction.vm_incarnation !=
            input->transaction->vm_incarnation ||
        memcmp(entry->transaction.admission_tx_id,
               input->transaction->admission_tx_id,
               sizeof(input->transaction->admission_tx_id)) != 0) {
        set_error(error, error_len,
                  "STOP does not match a durable control-plane transaction");
        return -1;
    }
    state = entry->transaction.state;
    if (state == WVM_LIFECYCLE_STOPPED) {
        return 0;
    }
    /*
     * A12: DEGRADED/FAILED must still allow cleanup STOP. Lifecycle matrix
     * already permits DEGRADED/FAILED → STOPPING; entry gate must match.
     */
    if (state != WVM_LIFECYCLE_RUNNING && state != WVM_LIFECYCLE_DEGRADED &&
        state != WVM_LIFECYCLE_FAILED && state != WVM_LIFECYCLE_STOPPING &&
        state != WVM_LIFECYCLE_RETIRING) {
        set_error(error, error_len,
                  "STOP requires RUNNING/DEGRADED/FAILED/STOPPING/RETIRING");
        return -1;
    }

    if (state == WVM_LIFECYCLE_RUNNING || state == WVM_LIFECYCLE_DEGRADED ||
        state == WVM_LIFECYCLE_FAILED) {
        if (wvm_control_plane_transition(
                input->control_plane, input->transaction, state,
                WVM_LIFECYCLE_STOPPING, error, error_len) != 0) {
            return -1;
        }
        state = WVM_LIFECYCLE_STOPPING;
    }

    if (state == WVM_LIFECYCLE_STOPPING) {
        /*
         * §6.1 steps 1–3: after durable STOPPING, stop participants (admitted
         * children) and prepare remote reservation release. Name unlink and
         * local teardown follow route RETIRING below.
         */
        if (input->callbacks) {
            size_t pi;

            if (!input->callbacks->participant_abort) {
                set_error(error, error_len,
                          "STOP callbacks lack participant abort");
                return -1;
            }
            for (pi = 0; pi < input->prepared_vm->node_runtime_manifest_count;
                 pi++) {
                if (input->callbacks->participant_abort(
                        input->callback_context,
                        &input->prepared_vm->candidate,
                        &input->prepared_vm->node_runtime_manifests[pi], error,
                        error_len) != 0) {
                    fprintf(stderr, "orchestrator_stop: participant_abort[%zu] failed: %s\n",
                            pi, (error && error[0]) ? error : "(none)");
                    return -1;
                }
            }
        }
        if (input->route_transaction->state != WVM_ROUTE_TRANSACTION_RETIRING) {
            if (input->route_transaction->state !=
                WVM_ROUTE_TRANSACTION_ACTIVATED) {
                set_error(error, error_len,
                          "STOP route must be ACTIVATED before retirement");
                return -1;
            }
            /*
             * F5: When membership begin_retire will run and RequiredAckSet is
             * non-empty, ROUTE_RETIRE owner ACKs are mandatory. Stream transport
             * validates each ACK carries refs=0 + horizon-complete; those proven
             * values feed begin_retire. Without membership (unit local STOP),
             * control-plane route state alone advances. ABORT_* is not this path.
             */
            {
                size_t ack_count =
                    input->route_transaction->required_ack_set.entries.count;
                uint64_t proven_refs = 0;
                int proven_horizon_complete = 1;
                int collected_owner_acks = 0;

                if (input->membership_controller && ack_count > 0 &&
                    (!input->callbacks || !input->callbacks->route_retire)) {
                    set_error(error, error_len,
                              "STOP requires ROUTE_RETIRE ACK from route "
                              "owners before membership begin_retire");
                    return -1;
                }
                if (input->callbacks && input->callbacks->route_retire) {
                    if (input->callbacks->route_retire(
                            input->callback_context, input->transaction,
                            input->route_transaction, input->route_snapshot,
                            error, error_len) != 0) {
                        fprintf(stderr, "orchestrator_stop: route_retire failed: %s\n",
                                (error && error[0]) ? error : "(none)");
                        return -1;
                    }
                    collected_owner_acks = 1;
                    proven_refs = 0;
                    proven_horizon_complete = 1;
                }
                if (input->membership_controller) {
                    if (ack_count > 0 && !collected_owner_acks) {
                        set_error(error, error_len,
                                  "STOP membership begin_retire lacks owner "
                                  "ROUTE_RETIRE ACK proof");
                        return -1;
                    }
                    if (wvm_membership_controller_route_state(
                            input->membership_controller,
                            input->route_transaction->operation_id,
                            &membership_route_state, error, error_len) != 0) {
                        return -1;
                    }
                    if (membership_route_state ==
                        WVM_ROUTE_TRANSACTION_ACTIVATED) {
                        if (wvm_membership_controller_route_begin_retire(
                                input->membership_controller,
                                input->route_transaction->operation_id,
                                proven_refs, proven_horizon_complete, error,
                                error_len) != 0) {
                            return -1;
                        }
                    } else if (membership_route_state !=
                                   WVM_ROUTE_TRANSACTION_RETIRING &&
                               membership_route_state !=
                                   WVM_ROUTE_TRANSACTION_RETIRED) {
                        set_error(
                            error, error_len,
                            "STOP membership route is not retirement-ready");
                        return -1;
                    }
                }
            }
            if (stop_persist_route_state(
                    input->control_plane, input->route_transaction,
                    WVM_ROUTE_TRANSACTION_RETIRING, error, error_len) != 0) {
                return -1;
            }
        }
        if (wvm_control_plane_transition(
                input->control_plane, input->transaction,
                WVM_LIFECYCLE_STOPPING, WVM_LIFECYCLE_RETIRING, error,
                error_len) != 0) {
            return -1;
        }
        state = WVM_LIFECYCLE_RETIRING;
    }

    if (state != WVM_LIFECYCLE_RETIRING) {
        set_error(error, error_len, "STOP failed to reach RETIRING");
        return -1;
    }

    /*
     * Local names before reservation teardown: teardown_local clears runtime
     * projections including local_names.
     */
    if (stop_retire_runtime_names(input->prepared_vm, error, error_len) != 0) {
        return -1;
    }
    if (input->callbacks) {
        size_t ri;

        if (!input->callbacks->reservation_abort) {
            set_error(error, error_len,
                      "STOP callbacks lack reservation abort");
            return -1;
        }
        for (ri = 0; ri < input->prepared_vm->reservation_count; ri++) {
            if (input->callbacks->reservation_abort(
                    input->callback_context, &input->prepared_vm->candidate,
                    &input->prepared_vm->reservations[ri], error,
                    error_len) != 0) {
                fprintf(stderr, "orchestrator_stop: reservation_abort[%zu] failed: %s\n",
                        ri, (error && error[0]) ? error : "(none)");
                return -1;
            }
        }
    }
    if (input->membership_controller &&
        wvm_admission_release_membership_dependencies(
            input->membership_controller, input->transaction,
            input->route_transaction, input->prepared_vm, error,
            error_len) != 0) {
        return -1;
    }
    if (wvm_coordinator_teardown_local(input->transaction, input->prepared_vm,
                                       error, error_len) != 0) {
        return -1;
    }

    if (input->route_transaction->state != WVM_ROUTE_TRANSACTION_RETIRED) {
        if (input->route_transaction->state !=
            WVM_ROUTE_TRANSACTION_RETIRING) {
            set_error(error, error_len,
                      "STOP route must be RETIRING before final retirement");
            return -1;
        }
        if (input->membership_controller) {
            if (wvm_membership_controller_route_state(
                    input->membership_controller,
                    input->route_transaction->operation_id,
                    &membership_route_state, error, error_len) != 0) {
                return -1;
            }
            if (membership_route_state == WVM_ROUTE_TRANSACTION_RETIRING) {
                if (wvm_membership_controller_route_retire(
                        input->membership_controller,
                        input->route_transaction->operation_id, error,
                        error_len) != 0) {
                    return -1;
                }
            } else if (membership_route_state !=
                       WVM_ROUTE_TRANSACTION_RETIRED) {
                set_error(error, error_len,
                          "STOP membership route did not reach RETIRED");
                return -1;
            }
        }
        if (stop_persist_route_state(input->control_plane,
                                     input->route_transaction,
                                     WVM_ROUTE_TRANSACTION_RETIRED, error,
                                     error_len) != 0) {
            return -1;
        }
    }
    /*
     * Quarantine namespace before durable STOPPED so an interrupted STOP cannot
     * idempotently succeed while leaving the namespace un-quarantined (F12).
     */
    if (stop_quarantine_namespace(input->namespace_allocator,
                                  input->transaction, input->route_transaction,
                                  error, error_len) != 0) {
        return -1;
    }
    if (wvm_control_plane_transition(
            input->control_plane, input->transaction, WVM_LIFECYCLE_RETIRING,
            WVM_LIFECYCLE_STOPPED, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

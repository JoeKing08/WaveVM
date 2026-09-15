#include "wavevm_admission_orchestrator.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_membership.h"

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

    if (wvm_coordinator_decide_abort(
            transaction, input->activation_options, input->prepared_vm,
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
    if (wvm_coordinator_decide_abort(
            transaction, input->activation_options, input->prepared_vm,
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
    if (wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_IDENTITY_ALLOCATED,
            WVM_LIFECYCLE_ABORTING, error, error_len) != 0 ||
        wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_ABORTING,
            WVM_LIFECYCLE_ABORTED, error, error_len) != 0) {
        return -1;
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
        !input->activation_options || !input->activation ||
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
        (input->membership_controller
             ? wvm_coordinator_decide_activation_current_membership(
                   input->membership_controller, input->membership_capture,
                   input->membership_evidence, input->request, transaction,
                   input->prepared_route, input->id_provider,
                   input->activation_options, input->prepared_vm,
                   input->activation, error, error_len)
             : wvm_coordinator_decide_activation(
                   input->request, transaction, records,
                   input->prepared_route, input->id_provider,
                   input->activation_options, input->prepared_vm,
                   input->activation, error, error_len)) != 0 ||
        wvm_control_plane_record_activation(input->control_plane, transaction,
                                            input->activation, error,
                                            error_len) != 0) {
        return abort_pre_activation(input, transaction, route_prepared, error,
                                    error_len);
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
                                        error_len) != 0 ||
        durable_route_state(input, WVM_ROUTE_TRANSACTION_ACTIVATED, error,
                            error_len) != 0 ||
        wvm_control_plane_transition(
            input->control_plane, transaction, WVM_LIFECYCLE_ACTIVATION_DECIDED,
            WVM_LIFECYCLE_COMMITTED, error, error_len) != 0) {
        return -1;
    }
    if (callback_participants(input, input->callbacks->participant_ready,
                              error, error_len) != 0 ||
        wvm_control_plane_start_if_ready(
            input->control_plane, transaction,
            input->prepared_vm->node_runtime_manifests,
            input->prepared_vm->node_runtime_manifest_count, error,
            error_len) != 0) {
        return -1;
    }
    return 0;
}

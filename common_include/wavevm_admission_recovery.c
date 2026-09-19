#include "wavevm_admission_orchestrator.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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

static int recovery_callbacks_valid(
    const struct wvm_admission_orchestrator_callbacks *callbacks,
    char *error, size_t error_len)
{
    if (!callbacks || !callbacks->route_commit || !callbacks->route_abort ||
        !callbacks->reservation_commit || !callbacks->reservation_abort ||
        !callbacks->participant_commit || !callbacks->participant_abort ||
        !callbacks->participant_ready) {
        set_error(error, error_len,
                  "admission recovery callbacks are incomplete");
        return -1;
    }
    return 0;
}

static int recover_reservations(
    const struct wvm_admission_recovery_input *input,
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

static int recover_participants(
    const struct wvm_admission_recovery_input *input,
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

static int recover_reservation_commits(
    const struct wvm_admission_recovery_input *input,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    size_t i;

    for (i = 0; i < input->prepared_vm->reservation_count; i++) {
        if (input->callbacks->reservation_commit(
                input->callback_context, &input->prepared_vm->candidate,
                &input->prepared_vm->reservations[i], activation,
                error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int recover_participant_commits(
    const struct wvm_admission_recovery_input *input,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    size_t i;

    for (i = 0; i < input->prepared_vm->node_runtime_manifest_count; i++) {
        if (input->callbacks->participant_commit(
                input->callback_context, &input->prepared_vm->candidate,
                &input->prepared_vm->node_runtime_manifests[i],
                activation, error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int durable_route_state(
    const struct wvm_admission_recovery_input *input, uint16_t state,
    char *error, size_t error_len)
{
    input->route_transaction->state = state;
    return wvm_control_plane_record_route_transaction(
        input->control_plane, input->route_transaction, error, error_len);
}

static int recovery_input_valid(
    const struct wvm_admission_recovery_input *input, char *error,
    size_t error_len)
{
    if (!input || !input->control_plane ||
        input->control_plane->journal_fd < 0 ||
        input->control_plane->journal_failed || !input->transaction ||
        !input->prepared_vm ||
        !input->route_transaction || !input->route_snapshot ||
        recovery_callbacks_valid(input->callbacks, error, error_len) != 0) {
        set_error(error, error_len, "admission recovery input is invalid");
        return -1;
    }
    return 0;
}

static int reconstruct_durable_route_snapshot(
    const struct wvm_admission_recovery_input *input,
    const struct wvm_admission_transaction_record *transaction, char *error,
    size_t error_len)
{
    uint8_t *bytes;
    const struct wvm_control_plane_route_entry *route;
    size_t encoded_bytes = 0;
    int result = -1;

    route = wvm_control_plane_find_route_transaction(
        input->control_plane, input->route_transaction->operation_id);
    if (!route ||
        wvm_route_transaction_record_decode(
            route->record_bytes, route->record_byte_count,
            input->route_transaction, error, error_len) != 0) {
        set_error(error, error_len, "admission recovery has no durable route transaction");
        return -1;
    }
    bytes = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    if (!bytes) {
        set_error(error, error_len, "cannot allocate route snapshot recovery");
        return -1;
    }
    if (wvm_control_plane_read_route_snapshot(
            input->control_plane, input->route_transaction->operation_id, bytes,
            WVM_CONTROL_PLANE_MAX_RECORD_BYTES, &encoded_bytes, error,
            error_len) == 0 &&
        wvm_route_snapshot_record_decode(bytes, encoded_bytes,
                                         input->route_snapshot, error,
                                         error_len) == 0 &&
        wvm_route_snapshot_record_binds_transaction(
            input->route_snapshot, input->route_transaction, error,
            error_len) == 0 &&
        transaction->has_prepared_route_snapshot_key &&
        input->route_snapshot->route_snapshot_key.scope_key.vm_id ==
            transaction->prepared_route_snapshot_key.scope_key.vm_id &&
        input->route_snapshot->route_snapshot_key.scope_key.vm_incarnation ==
            transaction->prepared_route_snapshot_key.scope_key.vm_incarnation &&
        input->route_snapshot->route_snapshot_key.scope_key.route_scope_id ==
            transaction->prepared_route_snapshot_key.scope_key.route_scope_id &&
        input->route_snapshot->route_snapshot_key.topology_revision ==
            transaction->prepared_route_snapshot_key.topology_revision &&
        input->route_snapshot->route_snapshot_key.route_generation ==
            transaction->prepared_route_snapshot_key.route_generation &&
        memcmp(input->route_snapshot->route_snapshot_key.snapshot_digest,
               transaction->prepared_route_snapshot_key.snapshot_digest,
               WVM_SHA256_DIGEST_BYTES) == 0) {
        result = 0;
    }
    if (result != 0 && error && error_len && error[0] == '\0') {
        set_error(error, error_len, "recovered route does not bind admission transaction");
    }
    free(bytes);
    return result;
}

static int reconstruct_durable_decision(
    const struct wvm_admission_recovery_input *input,
    const struct wvm_admission_transaction_record *transaction,
    struct wvm_activation_record *activation, char *error, size_t error_len)
{
    uint8_t *bytes = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    int result = -1;

    if (!bytes) {
        set_error(error, error_len, "cannot allocate admission decision recovery");
        return -1;
    }
    if (transaction->has_candidate_manifest_digest &&
        wvm_candidate_vm_manifest_encode(
            &input->prepared_vm->candidate, bytes,
            WVM_CONTROL_PLANE_MAX_RECORD_BYTES, &encoded_bytes, digest,
            error, error_len) == 0 &&
        memcmp(digest, transaction->candidate_manifest_digest,
               sizeof(digest)) == 0 &&
        memcmp(digest, input->prepared_vm->candidate_manifest_digest,
               sizeof(digest)) == 0 &&
        wvm_control_plane_read_activation(
            input->control_plane, input->transaction, bytes,
            WVM_CONTROL_PLANE_MAX_RECORD_BYTES, &encoded_bytes, error,
            error_len) == 0 &&
        wvm_activation_record_decode(bytes, encoded_bytes, activation, error,
                                      error_len) == 0) {
        result = 0;
    } else {
        set_error(error, error_len,
                  "admission recovery candidate or decision differs from journal");
    }
    free(bytes);
    return result;
}

static int recover_activation(
    const struct wvm_admission_recovery_input *input,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    size_t i;

    if (activation->decision != WVM_ACTIVATION_ACTIVATE ||
        !activation->has_activation_fence ||
        wvm_coordinator_commit_local(input->transaction, input->prepared_vm,
                                     activation, error, error_len) != 0 ||
        recover_reservation_commits(input, activation, error, error_len) != 0 ||
        recover_participant_commits(input, activation, error, error_len) != 0) {
        return -1;
    }
    for (i = 0; i < input->prepared_vm->node_runtime_manifest_count; i++) {
        if (wvm_control_plane_record_runtime_manifest(
                input->control_plane, input->transaction,
                &input->prepared_vm->node_runtime_manifests[i], error,
                error_len) != 0) {
            return -1;
        }
    }
    if (input->callbacks->route_commit(input->callback_context,
                                       input->transaction,
                                       input->route_transaction,
                                       input->route_snapshot, error,
                                       error_len) != 0 ||
        durable_route_state(input, WVM_ROUTE_TRANSACTION_ACTIVATED, error,
                            error_len) != 0 ||
        wvm_control_plane_transition(
            input->control_plane, input->transaction,
            WVM_LIFECYCLE_ACTIVATION_DECIDED, WVM_LIFECYCLE_COMMITTED, error,
            error_len) != 0 ||
        recover_participants(input, input->callbacks->participant_ready, error,
                             error_len) != 0 ||
        wvm_control_plane_start_if_ready(
            input->control_plane, input->transaction,
            input->prepared_vm->node_runtime_manifests,
            input->prepared_vm->node_runtime_manifest_count, error,
            error_len) != 0) {
        return -1;
    }
    return 0;
}

static int recover_abort(
    const struct wvm_admission_recovery_input *input,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    if (activation->decision != WVM_ACTIVATION_ABORT ||
        activation->has_activation_fence ||
        wvm_coordinator_validate_abort(input->transaction, input->prepared_vm,
                                       activation, error, error_len) != 0 ||
        recover_participants(input, input->callbacks->participant_abort, error,
                             error_len) != 0 ||
        recover_reservations(input, input->callbacks->reservation_abort, error,
                             error_len) != 0 ||
        wvm_coordinator_abort_local(input->transaction, input->prepared_vm,
                                    activation, error, error_len) != 0 ||
        input->callbacks->route_abort(input->callback_context,
                                      input->transaction,
                                      input->route_transaction,
                                      input->route_snapshot, error,
                                      error_len) != 0 ||
        durable_route_state(input, WVM_ROUTE_TRANSACTION_ABORTED, error,
                            error_len) != 0 ||
        wvm_control_plane_transition(
            input->control_plane, input->transaction, WVM_LIFECYCLE_ABORTING,
            WVM_LIFECYCLE_ABORTED, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

int wvm_admission_orchestrator_recover(
    const struct wvm_admission_recovery_input *input, char *error,
    size_t error_len)
{
    const struct wvm_control_plane_entry *entry;
    struct wvm_activation_record activation = {0};
    struct wvm_route_snapshot_key route_key;

    if (recovery_input_valid(input, error, error_len) != 0) {
        return -1;
    }
    entry = wvm_control_plane_find_request(
        input->control_plane, input->transaction->request_id);
    if (!entry || entry->transaction.vm_id != input->transaction->vm_id ||
        entry->transaction.vm_incarnation != input->transaction->vm_incarnation ||
        entry->transaction.manifest_generation !=
            input->transaction->manifest_generation ||
        entry->transaction.route_scope_key.vm_id !=
            input->transaction->route_scope_key.vm_id ||
        entry->transaction.route_scope_key.vm_incarnation !=
            input->transaction->route_scope_key.vm_incarnation ||
        entry->transaction.route_scope_key.route_scope_id !=
            input->transaction->route_scope_key.route_scope_id ||
        memcmp(entry->transaction.manifest_id, input->transaction->manifest_id,
               sizeof(entry->transaction.manifest_id)) != 0 ||
        memcmp(entry->transaction.admission_tx_id,
               input->transaction->admission_tx_id,
               sizeof(entry->transaction.admission_tx_id)) != 0) {
        set_error(error, error_len,
                  "admission recovery transaction identity mismatch");
        return -1;
    }
    if (entry->transaction.state == WVM_LIFECYCLE_RUNNING) {
        return 0;
    }
    activation.required_route_snapshot_keys = &route_key;
    activation.required_route_snapshot_capacity = 1;
    if (reconstruct_durable_decision(input, &entry->transaction, &activation,
                                     error, error_len) != 0 ||
        reconstruct_durable_route_snapshot(input, &entry->transaction,
                                             error, error_len) != 0) {
        return -1;
    }
    if (entry->transaction.state == WVM_LIFECYCLE_COMMITTED) {
        if (wvm_coordinator_commit_local(input->transaction, input->prepared_vm,
                                         &activation, error, error_len) != 0 ||
            recover_participants(input, input->callbacks->participant_ready,
                                 error, error_len) != 0) {
            return -1;
        }
        return wvm_control_plane_start_if_ready(
            input->control_plane, input->transaction,
            input->prepared_vm->node_runtime_manifests,
            input->prepared_vm->node_runtime_manifest_count, error,
            error_len);
    }
    if (entry->transaction.state == WVM_LIFECYCLE_ACTIVATION_DECIDED) {
        return recover_activation(input, &activation, error, error_len);
    }
    if (entry->transaction.state == WVM_LIFECYCLE_ABORTING) {
        return recover_abort(input, &activation, error, error_len);
    }
    set_error(error, error_len,
              "admission recovery cannot resume lifecycle state %d",
              entry->transaction.state);
    return -1;
}

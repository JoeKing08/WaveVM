#include "wavevm_membership_drain_transport.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_envelope.h"
#include "wavevm_control.h"
#include "wavevm_manifest.h"

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static int transport_valid(
    const struct wvm_membership_drain_transport *transport, char *error,
    size_t error_len)
{
    if (!transport || transport->controller_physical_node_id == 0 ||
        transport->controller_instance_id == 0 || !transport->controller ||
        !transport->submit) {
        set_error(error, error_len,
                  "gateway drain route transport is not initialized");
        return -1;
    }
    return 0;
}

/*
 * Peer ROUTE_* envelopes must carry the admitted manifest_generation for the
 * successor VM scope. Resolve it from membership dependencies acquired at
 * CREATE_VM (or equivalent). Conflicting generations for one incarnation
 * fail closed; absence fails closed (no dishonest default).
 */
static int resolve_dependency_manifest_generation(
    const struct wvm_membership_controller *controller, uint32_t vm_id,
    uint64_t vm_incarnation, uint64_t *manifest_generation, char *error,
    size_t error_len)
{
    size_t i;
    uint64_t found = 0;
    int saw = 0;

    if (!controller || !manifest_generation || vm_id == 0 ||
        vm_incarnation == 0) {
        set_error(error, error_len,
                  "gateway drain generation resolve input is invalid");
        return -1;
    }
    for (i = 0; i < controller->dependency_count; i++) {
        const struct wvm_membership_dependency *dependency =
            &controller->dependencies[i];

        if (dependency->vm_id != vm_id ||
            dependency->vm_incarnation != vm_incarnation) {
            continue;
        }
        if (dependency->manifest_generation == 0) {
            set_error(error, error_len,
                      "gateway drain dependency has zero manifest_generation");
            return -1;
        }
        if (saw && dependency->manifest_generation != found) {
            set_error(error, error_len,
                      "gateway drain VM has conflicting dependency "
                      "manifest_generation values");
            return -1;
        }
        found = dependency->manifest_generation;
        saw = 1;
    }
    if (!saw) {
        set_error(error, error_len,
                  "gateway drain successor VM has no membership dependency "
                  "to bind manifest_generation");
        return -1;
    }
    *manifest_generation = found;
    return 0;
}

static int ack_target_valid(const struct wvm_required_ack_entry *ack_entry,
                            char *error, size_t error_len)
{
    if (!ack_entry ||
        wvm_member_key_validate(&ack_entry->member_key, error, error_len) !=
            0 ||
        wvm_endpoint_validate(&ack_entry->endpoint, error, error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "gateway drain RequiredAckSet peer is invalid");
        }
        return -1;
    }
    if (ack_entry->role_type != ack_entry->member_key.role_type) {
        set_error(error, error_len,
                  "gateway drain ACK role does not match member key");
        return -1;
    }
    if (ack_entry->member_key.role_type != WVM_MANIFEST_ROLE_NODE_RUNTIME &&
        ack_entry->member_key.role_type != WVM_MANIFEST_ROLE_GATEWAY) {
        set_error(error, error_len,
                  "gateway drain RequiredAckSet peer role is unsupported");
        return -1;
    }
    return 0;
}

static void stamp_peer_operation_id(
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const struct wvm_required_ack_entry *ack_entry)
{
    operation_id[0] ^= (uint8_t)ack_entry->member_key.role_type;
    operation_id[1] ^= (uint8_t)(ack_entry->member_key.role_id & 0xffU);
}

static int submit_route_stage(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_key *snapshot_key,
    const struct wvm_required_ack_entry *ack_entry, uint16_t message_type,
    uint8_t *payload, size_t payload_bytes, char *error,
    size_t error_len)
{
    struct wvm_admission_transport_target target;
    struct wvm_envelope envelope;
    int status;

    if (transport_valid(transport, error, error_len) != 0 || !controller ||
        !transaction || !snapshot_key ||
        ack_target_valid(ack_entry, error, error_len) != 0 ||
        (!payload && payload_bytes != 0)) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "gateway drain peer route stage input is invalid");
        }
        return -1;
    }

    memset(&target, 0, sizeof(target));
    target.member_key = ack_entry->member_key;
    target.endpoint = ack_entry->endpoint;

    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = message_type;
    envelope.vm_id = snapshot_key->scope_key.vm_id;
    envelope.vm_incarnation = snapshot_key->scope_key.vm_incarnation;
    if (resolve_dependency_manifest_generation(
            controller, snapshot_key->scope_key.vm_id,
            snapshot_key->scope_key.vm_incarnation,
            &envelope.manifest_generation, error, error_len) != 0) {
        return -1;
    }
    envelope.route_scope_id = snapshot_key->scope_key.route_scope_id;
    envelope.topology_revision = snapshot_key->topology_revision;
    envelope.route_generation = snapshot_key->route_generation;
    memcpy(envelope.route_snapshot_digest, snapshot_key->snapshot_digest,
           sizeof(envelope.route_snapshot_digest));
    envelope.origin_physical_node_id = transport->controller_physical_node_id;
    envelope.origin_runtime_instance_id = transport->controller_instance_id;
    envelope.delivery_attempt_id = 1;
    memcpy(envelope.operation_id, transaction->operation_id,
           sizeof(envelope.operation_id));
    stamp_peer_operation_id(envelope.operation_id, ack_entry);
    envelope.payload = payload;
    envelope.payload_bytes = payload_bytes;
    if (payload_bytes != 0) {
        wvm_envelope_semantic_digest(payload, payload_bytes,
                                     envelope.semantic_payload_digest);
    }

    status = transport->submit(transport->context, &target, &envelope, error,
                               error_len);
    if (status != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "gateway drain peer route stage was not durable");
        }
        return status;
    }
    return 0;
}

static int submit_route_prepare(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    uint8_t *payload = NULL;
    size_t payload_bytes = 0;
    uint8_t digest_scratch[WVM_SHA256_DIGEST_BYTES];
    int status;

    if (!snapshot ||
        wvm_route_snapshot_record_binds_transaction(snapshot, transaction,
                                                    error, error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "gateway drain route prepare input is invalid");
        }
        return -1;
    }
    payload = malloc(WVM_ENVELOPE_MAX_LOCAL_PAYLOAD);
    if (!payload) {
        set_error(error, error_len,
                  "cannot allocate gateway drain route prepare payload");
        return -1;
    }
    if (wvm_route_snapshot_record_encode(
            snapshot, payload, WVM_ENVELOPE_MAX_LOCAL_PAYLOAD, &payload_bytes,
            digest_scratch, error, error_len) != 0 ||
        payload_bytes == 0) {
        free(payload);
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "cannot encode successor RouteSnapshot for drain");
        }
        return -1;
    }
    status = submit_route_stage(transport, controller, transaction,
                                &snapshot->route_snapshot_key, ack_entry,
                                WVM_ENVELOPE_MSG_ROUTE_PREPARE, payload,
                                payload_bytes, error, error_len);
    free(payload);
    return status;
}

static int submit_route_commit(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_key *snapshot_key,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    uint8_t payload[256];
    size_t payload_bytes = 0;

    if (!snapshot_key ||
        wvm_route_snapshot_key_encode(snapshot_key, payload, sizeof(payload),
                                      &payload_bytes, error, error_len) != 0 ||
        payload_bytes == 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "cannot encode RouteSnapshotKey for drain COMMIT");
        }
        return -1;
    }
    return submit_route_stage(transport, controller, transaction, snapshot_key,
                              ack_entry, WVM_ENVELOPE_MSG_ROUTE_COMMIT, payload,
                              payload_bytes, error, error_len);
}

static int submit_route_abort(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_key *snapshot_key,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    struct wvm_route_transaction_record aborted;
    uint8_t *payload = NULL;
    size_t payload_bytes = 0;
    int status;

    if (!transaction || !snapshot_key) {
        set_error(error, error_len,
                  "gateway drain route abort input is invalid");
        return -1;
    }
    aborted = *transaction;
    aborted.state = WVM_ROUTE_TRANSACTION_ABORTED;
    payload = malloc(WVM_ENVELOPE_MAX_LOCAL_PAYLOAD);
    if (!payload) {
        set_error(error, error_len,
                  "cannot allocate gateway drain route abort payload");
        return -1;
    }
    if (wvm_route_transaction_record_encode(
            &aborted, payload, WVM_ENVELOPE_MAX_LOCAL_PAYLOAD, &payload_bytes,
            error, error_len) != 0 ||
        payload_bytes == 0) {
        free(payload);
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "cannot encode aborted RouteTransaction for drain");
        }
        return -1;
    }
    status = submit_route_stage(transport, controller, &aborted, snapshot_key,
                                ack_entry, WVM_ENVELOPE_MSG_ROUTE_ABORT,
                                payload, payload_bytes, error, error_len);
    free(payload);
    return status;
}

static int transport_route_prepare(
    void *context, const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    struct wvm_membership_drain_transport *transport = context;

    return submit_route_prepare(transport, transport ? transport->controller : NULL,
                                transaction, snapshot, ack_entry, error,
                                error_len);
}

static int transport_route_commit(
    void *context, const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    struct wvm_membership_drain_transport *transport = context;

    if (!snapshot) {
        set_error(error, error_len, "gateway drain route commit lacks snapshot");
        return -1;
    }
    return submit_route_commit(transport,
                               transport ? transport->controller : NULL,
                               transaction, &snapshot->route_snapshot_key,
                               ack_entry, error, error_len);
}

static int transport_route_abort(
    void *context, const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    struct wvm_membership_drain_transport *transport = context;
    const struct wvm_route_snapshot_key *key;

    if (!transaction) {
        set_error(error, error_len, "gateway drain route abort lacks transaction");
        return -1;
    }
    key = snapshot ? &snapshot->route_snapshot_key
                   : &transaction->route_snapshot_key;
    return submit_route_abort(transport,
                              transport ? transport->controller : NULL,
                              transaction, key, ack_entry, error, error_len);
}

static const struct wvm_membership_controller_route_entry *
find_route_entry(const struct wvm_membership_controller *controller,
                 const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!controller || !operation_id) {
        return NULL;
    }
    for (i = 0; i < controller->route_count; i++) {
        if (memcmp(controller->routes[i].transaction.operation_id, operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &controller->routes[i];
        }
    }
    return NULL;
}

int wvm_membership_drain_transport_init(
    struct wvm_membership_drain_transport *transport,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    struct wvm_membership_controller *controller, void *context,
    wvm_admission_transport_submit_fn submit, char *error, size_t error_len)
{
    if (!transport || controller_physical_node_id == 0 ||
        controller_instance_id == 0 || !controller || !submit) {
        set_error(error, error_len,
                  "gateway drain route transport configuration is invalid");
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    transport->controller_physical_node_id = controller_physical_node_id;
    transport->controller_instance_id = controller_instance_id;
    transport->controller = controller;
    transport->context = context;
    transport->submit = submit;
    return 0;
}

int wvm_membership_drain_transport_bind(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_gateway_drain_request *request, char *error,
    size_t error_len)
{
    if (transport_valid(transport, error, error_len) != 0 || !request) {
        return -1;
    }
    request->route_prepare = transport_route_prepare;
    request->route_commit = transport_route_commit;
    request->route_abort = transport_route_abort;
    request->route_prepare_context = transport;
    return 0;
}

int wvm_membership_drain_transport_collect_prepare_acks(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const struct wvm_membership_gateway_drain_request *request, char *error,
    size_t error_len)
{
    size_t i;
    size_t prepared_count = 0;

    if (transport_valid(transport, error, error_len) != 0 || !controller ||
        !request || !request->gateway_member_key ||
        !request->successor_transaction || !request->successor_snapshot) {
        set_error(error, error_len,
                  "gateway drain ACK collection input is invalid");
        return -1;
    }
    if (wvm_route_snapshot_record_binds_transaction(
            request->successor_snapshot, request->successor_transaction, error,
            error_len) != 0) {
        return -1;
    }

    for (i = 0;
         i < request->successor_transaction->required_ack_set.entries.count;
         i++) {
        const struct wvm_required_ack_entry *ack =
            &request->successor_transaction->required_ack_set.entries.entries[i];

        if (submit_route_prepare(transport, controller,
                                 request->successor_transaction,
                                 request->successor_snapshot, ack, error,
                                 error_len) != 0 ||
            wvm_membership_controller_route_ack_prepare(
                controller, request->successor_transaction->operation_id,
                &ack->member_key, error, error_len) != 0) {
            size_t j;
            char abort_error[256] = {0};

            for (j = 0; j < prepared_count; j++) {
                const struct wvm_required_ack_entry *prepared =
                    &request->successor_transaction->required_ack_set.entries
                         .entries[j];

                (void)submit_route_abort(
                    transport, controller, request->successor_transaction,
                    &request->successor_snapshot->route_snapshot_key, prepared,
                    abort_error, sizeof(abort_error));
            }
            if (wvm_membership_controller_gateway_drain_apply(
                    controller, WVM_GATEWAY_DRAIN_ACTION_ABORT,
                    request->gateway_member_key, NULL, NULL,
                    request->successor_transaction->operation_id,
                    request->expected_membership_revision,
                    request->expected_topology_revision,
                    request->expected_admission_eligibility_revision,
                    abort_error, sizeof(abort_error)) != 0) {
                set_error(error, error_len,
                          "drain peer ACK failed and abort failed: %s",
                          abort_error);
            }
            return -1;
        }
        prepared_count++;
    }
    return 0;
}

int wvm_membership_drain_transport_deliver_commits(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    const struct wvm_membership_controller_route_entry *route;
    size_t i;

    if (transport_valid(transport, error, error_len) != 0 || !controller ||
        !route_operation_id) {
        set_error(error, error_len,
                  "gateway drain commit delivery input is invalid");
        return -1;
    }
    route = find_route_entry(controller, route_operation_id);
    if (!route ||
        route->transaction.state != WVM_ROUTE_TRANSACTION_ACTIVATED) {
        set_error(error, error_len,
                  "gateway drain commit delivery requires an ACTIVATED route");
        return -1;
    }
    for (i = 0; i < route->transaction.required_ack_set.entries.count; i++) {
        const struct wvm_required_ack_entry *ack =
            &route->transaction.required_ack_set.entries.entries[i];

        if (submit_route_commit(transport, controller, &route->transaction,
                                &route->transaction.route_snapshot_key, ack,
                                error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

int wvm_membership_drain_transport_deliver_aborts(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    const struct wvm_membership_controller_route_entry *route;
    size_t i;

    if (transport_valid(transport, error, error_len) != 0 || !controller ||
        !route_operation_id) {
        set_error(error, error_len,
                  "gateway drain abort delivery input is invalid");
        return -1;
    }
    route = find_route_entry(controller, route_operation_id);
    if (!route) {
        set_error(error, error_len,
                  "gateway drain abort delivery names an unknown route");
        return -1;
    }
    for (i = 0; i < route->transaction.required_ack_set.entries.count; i++) {
        const struct wvm_required_ack_entry *ack =
            &route->transaction.required_ack_set.entries.entries[i];

        if (submit_route_abort(transport, controller, &route->transaction,
                               &route->transaction.route_snapshot_key, ack,
                               error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

#include "wavevm_membership_drain_transport.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_envelope.h"
#include "wavevm_control.h"

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
        transport->controller_instance_id == 0 ||
        transport->route_manifest_generation == 0 || !transport->submit) {
        set_error(error, error_len,
                  "gateway drain route transport is not initialized");
        return -1;
    }
    return 0;
}

static int submit_route_prepare(
    struct wvm_membership_drain_transport *transport,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    struct wvm_admission_transport_target target;
    struct wvm_envelope envelope;
    uint8_t *payload = NULL;
    size_t payload_bytes = 0;
    int status;

    if (transport_valid(transport, error, error_len) != 0 || !transaction ||
        !snapshot || !ack_entry ||
        wvm_route_snapshot_record_binds_transaction(snapshot, transaction,
                                                    error, error_len) != 0 ||
        wvm_member_key_validate(&ack_entry->member_key, error, error_len) !=
            0 ||
        wvm_endpoint_validate(&ack_entry->endpoint, error, error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "gateway drain route prepare input is invalid");
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

    payload = malloc(WVM_ENVELOPE_MAX_LOCAL_PAYLOAD);
    if (!payload) {
        set_error(error, error_len,
                  "cannot allocate gateway drain route prepare payload");
        return -1;
    }
    {
        uint8_t digest_scratch[WVM_SHA256_DIGEST_BYTES];

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
    }

    memset(&target, 0, sizeof(target));
    target.member_key = ack_entry->member_key;
    target.endpoint = ack_entry->endpoint;

    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = WVM_ENVELOPE_MSG_ROUTE_PREPARE;
    envelope.vm_id = snapshot->route_snapshot_key.scope_key.vm_id;
    envelope.vm_incarnation =
        snapshot->route_snapshot_key.scope_key.vm_incarnation;
    envelope.manifest_generation = transport->route_manifest_generation;
    envelope.route_scope_id =
        snapshot->route_snapshot_key.scope_key.route_scope_id;
    envelope.topology_revision =
        snapshot->route_snapshot_key.topology_revision;
    envelope.route_generation = snapshot->route_snapshot_key.route_generation;
    memcpy(envelope.route_snapshot_digest,
           snapshot->route_snapshot_key.snapshot_digest,
           sizeof(envelope.route_snapshot_digest));
    envelope.origin_physical_node_id = transport->controller_physical_node_id;
    envelope.origin_runtime_instance_id = transport->controller_instance_id;
    envelope.delivery_attempt_id = 1;
    memcpy(envelope.operation_id, transaction->operation_id,
           sizeof(envelope.operation_id));
    /* Per-peer attempt identity: fold member role bits into last bytes. */
    envelope.operation_id[0] ^= (uint8_t)ack_entry->member_key.role_type;
    envelope.operation_id[1] ^= (uint8_t)(ack_entry->member_key.role_id & 0xffU);
    envelope.payload = payload;
    envelope.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 envelope.semantic_payload_digest);

    status = transport->submit(transport->context, &target, &envelope, error,
                               error_len);
    free(payload);
    if (status != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "gateway drain peer ROUTE_PREPARE was not durable");
        }
        return status;
    }
    return 0;
}

static int transport_route_prepare(
    void *context, const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    return submit_route_prepare(context, transaction, snapshot, ack_entry,
                                error, error_len);
}

int wvm_membership_drain_transport_init(
    struct wvm_membership_drain_transport *transport,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    uint64_t route_manifest_generation, void *context,
    wvm_admission_transport_submit_fn submit, char *error, size_t error_len)
{
    if (!transport || controller_physical_node_id == 0 ||
        controller_instance_id == 0 || route_manifest_generation == 0 ||
        !submit) {
        set_error(error, error_len,
                  "gateway drain route transport configuration is invalid");
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    transport->controller_physical_node_id = controller_physical_node_id;
    transport->controller_instance_id = controller_instance_id;
    transport->route_manifest_generation = route_manifest_generation;
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

        if (submit_route_prepare(transport, request->successor_transaction,
                                 request->successor_snapshot, ack, error,
                                 error_len) != 0 ||
            wvm_membership_controller_route_ack_prepare(
                controller, request->successor_transaction->operation_id,
                &ack->member_key, error, error_len) != 0) {
            char abort_error[256] = {0};

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
    }
    return 0;
}

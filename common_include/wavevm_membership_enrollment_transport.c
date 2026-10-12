#include "wavevm_membership_enrollment_transport.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "wavevm_envelope.h"

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static int transport_valid(
    const struct wvm_membership_enrollment_transport *transport, char *error,
    size_t error_len)
{
    if (!transport || transport->controller_physical_node_id == 0 ||
        transport->controller_instance_id == 0 || !transport->submit) {
        set_error(error, error_len,
                  "cluster enrollment transport is not initialized");
        return -1;
    }
    return 0;
}

static int submit_proof_stage(
    struct wvm_membership_enrollment_transport *transport,
    const struct wvm_cluster_admission_proof *proof,
    const struct wvm_cluster_admission_ack_entry *ack_entry, uint16_t message_type,
    char *error, size_t error_len)
{
    struct wvm_admission_transport_target target;
    struct wvm_envelope envelope;
    uint8_t *payload = NULL;
    size_t payload_bytes = 0;
    int status;

    if (transport_valid(transport, error, error_len) != 0 || !proof ||
        !ack_entry ||
        wvm_cluster_admission_proof_validate(proof, error, error_len) != 0 ||
        wvm_member_key_validate(&ack_entry->member_key, error, error_len) != 0 ||
        wvm_endpoint_validate(&ack_entry->endpoint, error, error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "cluster enrollment stage input is invalid");
        }
        return -1;
    }
    if (ack_entry->role_type != ack_entry->member_key.role_type) {
        set_error(error, error_len,
                  "cluster enrollment ACK role does not match member key");
        return -1;
    }

    payload = malloc(WVM_ENVELOPE_MAX_LOCAL_PAYLOAD);
    if (!payload) {
        set_error(error, error_len,
                  "cannot allocate cluster enrollment payload");
        return -1;
    }
    if (wvm_cluster_admission_proof_encode(proof, payload,
                                          WVM_ENVELOPE_MAX_LOCAL_PAYLOAD,
                                          &payload_bytes, error,
                                          error_len) != 0 ||
        payload_bytes == 0) {
        free(payload);
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "cannot encode cluster admission proof");
        }
        return -1;
    }

    memset(&target, 0, sizeof(target));
    target.member_key = ack_entry->member_key;
    target.endpoint = ack_entry->endpoint;

    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = message_type;
    envelope.origin_physical_node_id = transport->controller_physical_node_id;
    envelope.origin_runtime_instance_id = transport->controller_instance_id;
    envelope.delivery_attempt_id = 1;
    memcpy(envelope.operation_id, proof->operation_id,
           sizeof(envelope.operation_id));
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
                      "cluster enrollment peer stage was not durable");
        }
        return status;
    }
    return 0;
}

static int transport_prepare(
    void *context, const struct wvm_cluster_admission_proof *proof,
    const struct wvm_cluster_admission_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    return submit_proof_stage(context, proof, ack_entry,
                              WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_PREPARE,
                              error, error_len);
}

static int transport_commit(
    void *context, const struct wvm_cluster_admission_proof *proof,
    const struct wvm_cluster_admission_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    return submit_proof_stage(context, proof, ack_entry,
                              WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_COMMIT,
                              error, error_len);
}

static int transport_abort(
    void *context, const struct wvm_cluster_admission_proof *proof,
    const struct wvm_cluster_admission_ack_entry *ack_entry, char *error,
    size_t error_len)
{
    return submit_proof_stage(context, proof, ack_entry,
                              WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_ABORT,
                              error, error_len);
}

int wvm_membership_enrollment_transport_init(
    struct wvm_membership_enrollment_transport *transport,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    void *context, wvm_admission_transport_submit_fn submit, char *error,
    size_t error_len)
{
    if (!transport || controller_physical_node_id == 0 ||
        controller_instance_id == 0 || !submit) {
        set_error(error, error_len,
                  "cluster enrollment transport configuration is invalid");
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    transport->controller_physical_node_id = controller_physical_node_id;
    transport->controller_instance_id = controller_instance_id;
    transport->context = context;
    transport->submit = submit;
    return 0;
}

int wvm_membership_enrollment_transport_bind(
    struct wvm_membership_enrollment_transport *transport,
    struct wvm_membership_cluster_enrollment_request *request, char *error,
    size_t error_len)
{
    if (transport_valid(transport, error, error_len) != 0 || !request) {
        return -1;
    }
    request->prepare = transport_prepare;
    request->commit = transport_commit;
    request->abort = transport_abort;
    request->prepare_context = transport;
    return 0;
}

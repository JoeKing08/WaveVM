#define _POSIX_C_SOURCE 200809L

#include "wavevm_control_transport.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void set_error(char *error, size_t error_len, const char *message)
{
    if (!error || error_len == 0) {
        return;
    }
    (void)snprintf(error, error_len, "%s", message);
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_be64(uint8_t *bytes, uint64_t value)
{
    bytes[0] = (uint8_t)(value >> 56);
    bytes[1] = (uint8_t)(value >> 48);
    bytes[2] = (uint8_t)(value >> 40);
    bytes[3] = (uint8_t)(value >> 32);
    bytes[4] = (uint8_t)(value >> 24);
    bytes[5] = (uint8_t)(value >> 16);
    bytes[6] = (uint8_t)(value >> 8);
    bytes[7] = (uint8_t)value;
}

static uint64_t read_be64(const uint8_t *bytes)
{
    return ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8) | (uint64_t)bytes[7];
}

static int read_full(int fd, uint8_t *bytes, size_t byte_count,
                     size_t *bytes_read, char *error, size_t error_len)
{
    size_t offset = 0;

    if (bytes_read) {
        *bytes_read = 0;
    }
    while (offset < byte_count) {
        ssize_t result = read(fd, bytes + offset, byte_count - offset);

        if (result > 0) {
            offset += (size_t)result;
            continue;
        }
        if (result == 0) {
            if (bytes_read) {
                *bytes_read = offset;
            }
            return 1;
        }
        if (errno == EINTR) {
            continue;
        }
        {
            int saved_errno = errno;
            set_error(error, error_len, "control stream read failed");
            return -saved_errno;
        }
    }
    if (bytes_read) {
        *bytes_read = offset;
    }
    return 0;
}

static int write_full(int fd, const uint8_t *bytes, size_t byte_count,
                      char *error, size_t error_len)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t result = send(fd, bytes + offset, byte_count - offset,
                              MSG_NOSIGNAL);

        if (result > 0) {
            offset += (size_t)result;
            continue;
        }
        if (result == 0) {
            set_error(error, error_len, "control stream write made no progress");
            return -EPIPE;
        }
        if (errno == EINTR) {
            continue;
        }
        {
            int saved_errno = errno;
            set_error(error, error_len, "control stream write failed");
            return -saved_errno;
        }
    }
    return 0;
}

static int admission_request(uint16_t message_type)
{
    switch (message_type) {
    case WVM_ENVELOPE_MSG_PREPARE_RESERVATION:
    case WVM_ENVELOPE_MSG_COMMIT_RESERVATION:
    case WVM_ENVELOPE_MSG_ABORT_RESERVATION:
    case WVM_ENVELOPE_MSG_PREPARE_MANIFEST:
    case WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST:
    case WVM_ENVELOPE_MSG_ABORT_MANIFEST:
    case WVM_ENVELOPE_MSG_ROUTE_PREPARE:
    case WVM_ENVELOPE_MSG_ROUTE_COMMIT:
    case WVM_ENVELOPE_MSG_ROUTE_ABORT:
    case WVM_ENVELOPE_MSG_ROUTE_RETIRE:
        return 1;
    default:
        return 0;
    }
}

static int typed_request(uint16_t message_type)
{
    return message_type == WVM_ENVELOPE_MSG_CREATE_VM ||
           message_type == WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES ||
           message_type == WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE ||
           admission_request(message_type);
}

static int supported_request(uint16_t message_type)
{
    return message_type == WVM_ENVELOPE_MSG_REGISTER_MEMBER ||
           message_type == WVM_ENVELOPE_MSG_REJOIN ||
           message_type == WVM_ENVELOPE_MSG_CORDON ||
           message_type == WVM_ENVELOPE_MSG_DRAIN ||
           typed_request(message_type);
}

static int forwarding_metadata_is_empty(const struct wvm_envelope *envelope)
{
    return envelope && envelope->route.destination_kind == 0 &&
           envelope->route.destination_scope == 0 &&
           envelope->route.destination_vnode_or_endpoint == 0 &&
           envelope->route.hop_limit == 0 && envelope->route.hop_count == 0;
}

static int route_metadata_is_empty(const struct wvm_envelope *envelope)
{
    size_t i;

    if (!envelope || envelope->route_scope_id != 0 ||
        envelope->topology_revision != 0 || envelope->route_generation != 0) {
        return 0;
    }
    for (i = 0; i < sizeof(envelope->route_snapshot_digest); i++) {
        if (envelope->route_snapshot_digest[i] != 0) {
            return 0;
        }
    }
    return forwarding_metadata_is_empty(envelope);
}

static int request_metadata_valid(const struct wvm_envelope *request)
{
    if (!request || request->flags != 0 ||
        !supported_request(request->message_type)) {
        return 0;
    }
    if (admission_request(request->message_type)) {
        return request->vm_id != 0 && forwarding_metadata_is_empty(request);
    }
    return request->vm_id == 0 && route_metadata_is_empty(request);
}

static int send_payload_result(struct wvm_control_stream *transport,
                               const struct wvm_envelope *request,
                               const uint8_t *payload, size_t payload_bytes,
                               char *error, size_t error_len)
{
    struct wvm_envelope response;
    uint8_t frame[WVM_ENVELOPE_HEADER_BYTES +
                  WVM_CONTROL_RESULT_BYTES];
    uint8_t prefix[WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES];
    size_t frame_bytes = 0;

    if (!transport || !request || !payload || payload_bytes == 0 ||
        payload_bytes > WVM_CONTROL_RESULT_BYTES || transport->response_sent) {
        set_error(error, error_len, "control result input is invalid");
        return -EINVAL;
    }
    memset(&response, 0, sizeof(response));
    response.message_type = WVM_ENVELOPE_MSG_CTRL_RESULT;
    response.origin_physical_node_id =
        transport->config.local_physical_node_id;
    response.origin_runtime_instance_id =
        transport->config.local_runtime_instance_id;
    memcpy(response.operation_id, request->operation_id,
           sizeof(response.operation_id));
    response.delivery_attempt_id = request->delivery_attempt_id;
    response.payload = payload;
    response.payload_bytes = payload_bytes;
    if (wvm_envelope_encode(&response, WVM_ENVELOPE_TRANSPORT_LOCAL, frame,
                            sizeof(frame), &frame_bytes, error, error_len) != 0 ||
        frame_bytes > UINT32_MAX) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "control result envelope is invalid");
        }
        return -EPROTO;
    }
    write_be32(prefix, (uint32_t)frame_bytes);
    {
        int result = write_full(transport->config.stream_fd, prefix,
                                sizeof(prefix), error, error_len);
        if (result == 0) {
            result = write_full(transport->config.stream_fd, frame, frame_bytes,
                                error, error_len);
        }
        if (result != 0) {
            return result;
        }
    }
    transport->response_sent = 1;
    return 0;
}

static int send_membership_result(
    struct wvm_control_stream *transport, const struct wvm_envelope *request,
    const struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    uint8_t payload[WVM_MEMBERSHIP_CONTROL_RESULT_BYTES];

    if (!result || wvm_membership_control_result_encode(result, payload) != 0) {
        set_error(error, error_len, "membership control result is invalid");
        return -EINVAL;
    }
    return send_payload_result(transport, request, payload, sizeof(payload),
                               error, error_len);
}

static int send_control_result(struct wvm_control_stream *transport,
                               const struct wvm_envelope *request,
                               const struct wvm_control_result *result,
                               char *error, size_t error_len)
{
    uint8_t payload[WVM_CONTROL_RESULT_BYTES];

    if (!result || wvm_control_result_encode(result, payload) != 0) {
        set_error(error, error_len, "control result is invalid");
        return -EINVAL;
    }
    return send_payload_result(transport, request, payload, sizeof(payload),
                               error, error_len);
}

int wvm_control_transport_init(
    struct wvm_control_stream *transport,
    const struct wvm_control_transport_config *config, char *error,
    size_t error_len)
{
    size_t max_frame_bytes;

    if (!transport || !config || config->stream_fd < 0 ||
        config->local_physical_node_id == 0 ||
        config->local_runtime_instance_id == 0 || !config->authenticate ||
        (!config->apply && !config->control_apply && !config->dispatch)) {
        set_error(error, error_len, "control transport configuration is invalid");
        return -EINVAL;
    }
    max_frame_bytes = config->max_frame_bytes != 0
                          ? config->max_frame_bytes
                          : WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    if (max_frame_bytes < WVM_ENVELOPE_HEADER_BYTES ||
        max_frame_bytes > UINT32_MAX ||
        max_frame_bytes > WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES) {
        set_error(error, error_len, "control transport frame limit is invalid");
        return -EINVAL;
    }
    memset(transport, 0, sizeof(*transport));
    transport->config = *config;
    transport->config.max_frame_bytes = max_frame_bytes;
    return 0;
}

void wvm_control_transport_destroy(struct wvm_control_stream *transport)
{
    if (transport) {
        memset(transport, 0, sizeof(*transport));
        transport->config.stream_fd = -1;
    }
}

int wvm_control_transport_result_sink(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    return send_membership_result(opaque, request, result, error, error_len);
}

int wvm_control_result_encode(const struct wvm_control_result *result,
                              uint8_t bytes[WVM_CONTROL_RESULT_BYTES])
{
    if (!result || !bytes || result->result_flags != 0 ||
        result->status_code > WVM_CONTROL_RESULT_INTERNAL_FAILURE) {
        return -1;
    }
    bytes[0] = (uint8_t)(result->status_code >> 8);
    bytes[1] = (uint8_t)result->status_code;
    bytes[2] = (uint8_t)(result->recorded_state >> 8);
    bytes[3] = (uint8_t)result->recorded_state;
    write_be32(bytes + 4, result->result_flags);
    memcpy(bytes + 8, result->in_reply_to_operation_id,
           sizeof(result->in_reply_to_operation_id));
    memcpy(bytes + 24, result->record_digest, sizeof(result->record_digest));
    write_be64(bytes + 56, result->applied_revision);
    write_be64(bytes + 64, result->expiry_or_retention_deadline);
    write_be32(bytes + 72, result->vm_id);
    write_be64(bytes + 76, result->vm_incarnation);
    write_be64(bytes + 84, result->manifest_generation);
    memcpy(bytes + 92, result->admission_tx_id, sizeof(result->admission_tx_id));
    memcpy(bytes + 108, result->manifest_id, sizeof(result->manifest_id));
    write_be64(bytes + 124, result->route_scope_id);
    return 0;
}

int wvm_control_result_decode(const uint8_t bytes[WVM_CONTROL_RESULT_BYTES],
                              struct wvm_control_result *result)
{
    if (!bytes || !result ||
        ((((uint16_t)bytes[0] << 8) | bytes[1]) >
         WVM_CONTROL_RESULT_INTERNAL_FAILURE) ||
        read_be32(bytes + 4) != 0) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status_code = ((uint16_t)bytes[0] << 8) | bytes[1];
    result->recorded_state = ((uint16_t)bytes[2] << 8) | bytes[3];
    result->result_flags = read_be32(bytes + 4);
    memcpy(result->in_reply_to_operation_id, bytes + 8,
           sizeof(result->in_reply_to_operation_id));
    memcpy(result->record_digest, bytes + 24, sizeof(result->record_digest));
    result->applied_revision = read_be64(bytes + 56);
    result->expiry_or_retention_deadline = read_be64(bytes + 64);
    result->vm_id = read_be32(bytes + 72);
    result->vm_incarnation = read_be64(bytes + 76);
    result->manifest_generation = read_be64(bytes + 84);
    memcpy(result->admission_tx_id, bytes + 92, sizeof(result->admission_tx_id));
    memcpy(result->manifest_id, bytes + 108, sizeof(result->manifest_id));
    result->route_scope_id = read_be64(bytes + 124);
    return 0;
}

int wvm_control_transport_exchange(
    int stream_fd, uint32_t peer_physical_node_id,
    uint64_t peer_runtime_instance_id, const struct wvm_envelope *request,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    uint8_t prefix[WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES];
    uint8_t reply[WVM_ENVELOPE_HEADER_BYTES + WVM_CONTROL_RESULT_BYTES];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_envelope response;
    struct wvm_control_result decoded;
    uint8_t *frame;
    size_t frame_bytes;
    size_t capacity;
    int status;

    if (stream_fd < 0 || peer_physical_node_id == 0 ||
        peer_runtime_instance_id == 0 || !result ||
        !request_metadata_valid(request) ||
        !typed_request(request->message_type) ||
        request->payload_bytes > WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
        set_error(error, error_len, "control exchange input is invalid");
        return -EINVAL;
    }
    capacity = WVM_ENVELOPE_HEADER_BYTES + request->payload_bytes;
    frame = malloc(capacity);
    if (!frame) {
        set_error(error, error_len, "control exchange allocation failed");
        return -ENOMEM;
    }
    status = wvm_envelope_encode(request, WVM_ENVELOPE_TRANSPORT_LOCAL,
                                 frame, capacity, &frame_bytes, error,
                                 error_len);
    if (status != 0) {
        free(frame);
        return -EPROTO;
    }
    write_be32(prefix, (uint32_t)frame_bytes);
    status = write_full(stream_fd, prefix, sizeof(prefix), error, error_len);
    if (status == 0) {
        status = write_full(stream_fd, frame, frame_bytes, error, error_len);
    }
    free(frame);
    if (status != 0) {
        return status;
    }
    status = read_full(stream_fd, prefix, sizeof(prefix), NULL, error, error_len);
    if (status != 0) {
        if (status == 1) {
            set_error(error, error_len, "control reply prefix is truncated");
            return -EPROTO;
        }
        return status;
    }
    frame_bytes = read_be32(prefix);
    if (frame_bytes != sizeof(reply)) {
        set_error(error, error_len, "control reply length is invalid");
        return -EMSGSIZE;
    }
    status = read_full(stream_fd, reply, frame_bytes, NULL, error, error_len);
    if (status != 0) {
        if (status == 1) {
            set_error(error, error_len, "control reply is truncated");
            return -EPROTO;
        }
        return status;
    }
    if (wvm_envelope_decode(reply, frame_bytes, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            &response, error, error_len) != 0 ||
        response.message_type != WVM_ENVELOPE_MSG_CTRL_RESULT ||
        response.flags != 0 || response.vm_id != 0 ||
        !route_metadata_is_empty(&response) ||
        response.origin_physical_node_id != peer_physical_node_id ||
        response.origin_runtime_instance_id != peer_runtime_instance_id ||
        response.delivery_attempt_id != request->delivery_attempt_id ||
        memcmp(response.operation_id, request->operation_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        response.payload_bytes != WVM_CONTROL_RESULT_BYTES ||
        wvm_control_result_decode(response.payload, &decoded) != 0 ||
        memcmp(decoded.in_reply_to_operation_id, request->operation_id,
               WVM_IDENTITY_ID_BYTES) != 0) {
        set_error(error, error_len, "control reply does not match request or peer");
        return -EPROTO;
    }
    if (admission_request(request->message_type) &&
        decoded.status_code == WVM_CONTROL_RESULT_SUCCESS) {
        wvm_envelope_semantic_digest(request->payload, request->payload_bytes,
                                     digest);
        if (decoded.vm_id != request->vm_id ||
            decoded.vm_incarnation != request->vm_incarnation ||
            decoded.manifest_generation != request->manifest_generation ||
            decoded.route_scope_id != request->route_scope_id ||
            memcmp(decoded.record_digest, digest, sizeof(digest)) != 0) {
            set_error(error, error_len, "admission reply does not bind request");
            return -EPROTO;
        }
    }
    *result = decoded;
    return 0;
}

int wvm_control_transport_serve_once(
    struct wvm_control_stream *transport, char *error, size_t error_len)
{
    struct wvm_envelope request;
    struct wvm_member_key actor;
    uint8_t prefix[WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES];
    uint8_t *frame;
    size_t frame_bytes;
    size_t prefix_bytes = 0;
    size_t max_frame_bytes;
    int read_result;
    int dispatch_result;
    int authenticate_result;

    if (!transport || transport->config.stream_fd < 0 ||
        !transport->config.authenticate ||
        (!transport->config.apply && !transport->config.control_apply &&
         !transport->config.dispatch)) {
        set_error(error, error_len, "control transport is not initialized");
        return -EINVAL;
    }
    transport->response_sent = 0;
    read_result = read_full(transport->config.stream_fd, prefix, sizeof(prefix),
                            &prefix_bytes, error, error_len);
    if (read_result == 1) {
        if (prefix_bytes == 0) {
            return WVM_CONTROL_TRANSPORT_EOF;
        }
        set_error(error, error_len, "control stream length prefix is truncated");
        return -EPROTO;
    }
    if (read_result != 0) {
        return read_result;
    }
    frame_bytes = (size_t)read_be32(prefix);
    max_frame_bytes = transport->config.max_frame_bytes;
    if (frame_bytes < WVM_ENVELOPE_HEADER_BYTES ||
        frame_bytes > max_frame_bytes) {
        set_error(error, error_len, "control stream frame length is invalid");
        return -EMSGSIZE;
    }
    frame = malloc(frame_bytes);
    if (!frame) {
        set_error(error, error_len, "control stream frame allocation failed");
        return -ENOMEM;
    }
    read_result = read_full(transport->config.stream_fd, frame, frame_bytes,
                            NULL, error, error_len);
    if (read_result != 0) {
        free(frame);
        if (read_result == 1) {
            set_error(error, error_len, "control stream frame is truncated");
            return -EPROTO;
        }
        return read_result;
    }
    if (wvm_envelope_decode(frame, frame_bytes, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            &request, error, error_len) != 0 ||
        !request_metadata_valid(&request)) {
        free(frame);
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "control stream request is invalid");
        }
        return -EPROTO;
    }
    memset(&actor, 0, sizeof(actor));
    authenticate_result = transport->config.authenticate(
        transport->config.authenticate_opaque, transport->config.stream_fd,
        &actor, error, error_len);
    if (authenticate_result != 0) {
        int response_result;

        if (typed_request(request.message_type)) {
            struct wvm_control_result result;

            memset(&result, 0, sizeof(result));
            result.status_code = WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE;
            memcpy(result.in_reply_to_operation_id, request.operation_id,
                   sizeof(result.in_reply_to_operation_id));
            response_result = send_control_result(transport, &request, &result,
                                                   error, error_len);
        } else {
            struct wvm_membership_control_result result;

            memset(&result, 0, sizeof(result));
            result.status_code = WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE;
            memcpy(result.in_reply_to_operation_id, request.operation_id,
                   sizeof(result.in_reply_to_operation_id));
            response_result = send_membership_result(transport, &request,
                                                     &result, error, error_len);
        }
        free(frame);
        return response_result;
    }
    if (typed_request(request.message_type)) {
        struct wvm_control_result result;

        memset(&result, 0, sizeof(result));
        if (!transport->config.control_apply) {
            result.status_code = WVM_CONTROL_RESULT_UNSUPPORTED;
            memcpy(result.in_reply_to_operation_id, request.operation_id,
                   sizeof(result.in_reply_to_operation_id));
            dispatch_result = send_control_result(transport, &request, &result,
                                                   error, error_len);
        } else {
            dispatch_result = transport->config.control_apply(
                transport->config.control_apply_opaque, &request, &actor,
                &result, error, error_len);
            if (dispatch_result == 0) {
                dispatch_result = send_control_result(transport, &request,
                                                      &result, error, error_len);
            }
        }
        free(frame);
        return dispatch_result == 0 ? WVM_CONTROL_TRANSPORT_ACCEPTED
                                    : dispatch_result;
    }
    if (transport->config.apply) {
        struct wvm_membership_control_result result;

        memset(&result, 0, sizeof(result));
        dispatch_result = transport->config.apply(
            transport->config.apply_opaque, &request, &actor, &result, error,
            error_len);
        if (dispatch_result == 0) {
            dispatch_result = send_membership_result(transport, &request,
                                                     &result, error, error_len);
        }
        free(frame);
        return dispatch_result == 0 ? WVM_CONTROL_TRANSPORT_ACCEPTED
                                    : dispatch_result;
    }
    dispatch_result = transport->config.dispatch(
        transport->config.dispatch_opaque, &request, &actor, error, error_len);
    free(frame);
    if (dispatch_result != 0) {
        return dispatch_result;
    }
    if (!transport->response_sent) {
        set_error(error, error_len,
                  "control dispatcher completed without CTRL_RESULT");
        return -EPROTO;
    }
    return WVM_CONTROL_TRANSPORT_ACCEPTED;
}

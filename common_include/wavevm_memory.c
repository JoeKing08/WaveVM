#include "wavevm_memory.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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

static uint16_t read_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint64_t read_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
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
    size_t i;

    for (i = 0; i < 8; i++) {
        bytes[7U - i] = (uint8_t)(value >> (i * 8U));
    }
}

static int reply_destination_valid(uint16_t kind, uint64_t scope,
                                   uint32_t vnode)
{
    if (vnode == WVM_ENVELOPE_ROUTE_DESTINATION_UNSPECIFIED) {
        return 0;
    }
    return (kind == WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE &&
            scope == 0) ||
           (kind == WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE &&
            scope != 0);
}

static int gpa_valid(uint64_t gpa)
{
    return (gpa & (WVM_MEMORY_PAGE_BYTES - 1U)) == 0;
}

static int ack_status_valid(uint16_t status)
{
    return status <= WVM_MEM_ACK_INTERNAL_FAILURE;
}

static int commit_ack_status_valid(uint16_t status)
{
    return status <= WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
}

static int push_valid(const struct wvm_mem_push *push)
{
    int full;

    if (!push || !gpa_valid(push->gpa) || push->version == 0 ||
        push->directory_physical_node_id == 0 ||
        push->directory_node_instance_id == 0 ||
        (push->flags & ~WVM_MEM_PUSH_FLAG_FULL) != 0) {
        return 0;
    }
    full = (push->flags & WVM_MEM_PUSH_FLAG_FULL) != 0;
    if (full) {
        return push->base_version == 0 && push->offset == 0 &&
               push->size == WVM_MEMORY_PAGE_BYTES &&
               push->data && push->data_bytes == WVM_MEMORY_PAGE_BYTES;
    }
    return push->base_version != 0 && push->size != 0 &&
           push->size <= WVM_MEMORY_PAGE_BYTES &&
           push->offset <= WVM_MEMORY_PAGE_BYTES - push->size &&
           push->data && push->data_bytes == push->size;
}

static int commit_valid(const struct wvm_mem_commit *commit)
{
    return commit && gpa_valid(commit->gpa) && commit->base_version != 0 &&
           commit->reply_node_instance_id != 0 &&
           commit->size != 0 && commit->size <= WVM_MEMORY_PAGE_BYTES &&
           commit->offset <= WVM_MEMORY_PAGE_BYTES - commit->size &&
           reply_destination_valid(commit->reply_destination_kind,
                                   commit->reply_destination_scope,
                                   commit->reply_destination_vnode) &&
           commit->data && commit->data_bytes == commit->size;
}

int wvm_mem_read_encode(const struct wvm_mem_read *read,
                           uint8_t output[WVM_MEM_READ_PAYLOAD_BYTES],
                           char *error, size_t error_len)
{
    if (!read || !output || !gpa_valid(read->gpa) ||
        read->reply_node_instance_id == 0 ||
        !reply_destination_valid(read->reply_destination_kind,
                                 read->reply_destination_scope,
                                 read->reply_destination_vnode)) {
        set_error(error, error_len, "V1 memory read payload is invalid");
        return -1;
    }
    write_be64(output, read->gpa);
    write_be16(output + 8, read->reply_destination_kind);
    write_be16(output + 10, 0);
    write_be64(output + 12, read->reply_destination_scope);
    write_be32(output + 20, read->reply_destination_vnode);
    write_be64(output + 24, read->reply_node_instance_id);
    return 0;
}

int wvm_mem_read_decode(const uint8_t *input, size_t input_bytes,
                           struct wvm_mem_read *read, char *error,
                           size_t error_len)
{
    if (!input || !read || input_bytes != WVM_MEM_READ_PAYLOAD_BYTES ||
        read_be16(input + 10) != 0) {
        set_error(error, error_len, "V1 memory read payload is malformed");
        return -1;
    }
    memset(read, 0, sizeof(*read));
    read->gpa = read_be64(input);
    read->reply_destination_kind = read_be16(input + 8);
    read->reply_destination_scope = read_be64(input + 12);
    read->reply_destination_vnode = read_be32(input + 20);
    read->reply_node_instance_id = read_be64(input + 24);
    if (!gpa_valid(read->gpa) || read->reply_node_instance_id == 0 ||
        !reply_destination_valid(read->reply_destination_kind,
                                 read->reply_destination_scope,
                                 read->reply_destination_vnode)) {
        set_error(error, error_len, "V1 memory read payload is invalid");
        return -1;
    }
    return 0;
}

int wvm_mem_commit_encode(const struct wvm_mem_commit *commit,
                             uint8_t *output, size_t output_capacity,
                             size_t *output_bytes, char *error,
                             size_t error_len)
{
    size_t required_bytes;

    if (!commit_valid(commit) || !output || !output_bytes) {
        set_error(error, error_len, "V1 memory commit payload is invalid");
        return -1;
    }
    required_bytes = WVM_MEM_COMMIT_HEADER_BYTES + commit->size;
    if (output_capacity < required_bytes) {
        set_error(error, error_len, "V1 memory commit output is too small");
        return -1;
    }
    write_be64(output, commit->gpa);
    write_be64(output + 8, commit->base_version);
    write_be16(output + 16, commit->offset);
    write_be16(output + 18, commit->size);
    write_be16(output + 20, commit->reply_destination_kind);
    write_be16(output + 22, 0);
    write_be64(output + 24, commit->reply_destination_scope);
    write_be32(output + 32, commit->reply_destination_vnode);
    write_be64(output + 36, commit->reply_node_instance_id);
    memcpy(output + WVM_MEM_COMMIT_HEADER_BYTES, commit->data,
           commit->size);
    *output_bytes = required_bytes;
    return 0;
}

int wvm_mem_commit_decode(const uint8_t *input, size_t input_bytes,
                             struct wvm_mem_commit *commit, char *error,
                             size_t error_len)
{
    uint16_t size;

    if (!input || !commit || input_bytes < WVM_MEM_COMMIT_HEADER_BYTES ||
        read_be16(input + 22) != 0) {
        set_error(error, error_len, "V1 memory commit payload is malformed");
        return -1;
    }
    size = read_be16(input + 18);
    if (size == 0 ||
        input_bytes != WVM_MEM_COMMIT_HEADER_BYTES + (size_t)size) {
        set_error(error, error_len, "V1 memory commit payload has bad length");
        return -1;
    }
    memset(commit, 0, sizeof(*commit));
    commit->gpa = read_be64(input);
    commit->base_version = read_be64(input + 8);
    commit->offset = read_be16(input + 16);
    commit->size = size;
    commit->reply_destination_kind = read_be16(input + 20);
    commit->reply_destination_scope = read_be64(input + 24);
    commit->reply_destination_vnode = read_be32(input + 32);
    commit->reply_node_instance_id = read_be64(input + 36);
    commit->data = input + WVM_MEM_COMMIT_HEADER_BYTES;
    commit->data_bytes = size;
    if (!commit_valid(commit)) {
        set_error(error, error_len, "V1 memory commit payload is invalid");
        return -1;
    }
    return 0;
}

int wvm_mem_ack_encode(const struct wvm_mem_ack *ack, uint8_t *output,
                          size_t output_capacity, size_t *output_bytes,
                          char *error, size_t error_len)
{
    size_t required_bytes;

    if (!ack || !output || !output_bytes || !gpa_valid(ack->gpa) ||
        !ack_status_valid(ack->status) ||
        ack->directory_physical_node_id == 0 ||
        ack->directory_node_instance_id == 0) {
        set_error(error, error_len, "V1 memory ACK payload is invalid");
        return -1;
    }
    required_bytes = WVM_MEM_ACK_HEADER_BYTES;
    if (ack->status == WVM_MEM_ACK_SUCCESS) {
        if (ack->version == 0 || !ack->data ||
            ack->data_bytes != WVM_MEMORY_PAGE_BYTES) {
            set_error(error, error_len,
                      "successful V1 memory ACK lacks a full page");
            return -1;
        }
        required_bytes += WVM_MEMORY_PAGE_BYTES;
    } else if (ack->version != 0 || ack->data || ack->data_bytes != 0) {
        set_error(error, error_len,
                  "failed V1 memory ACK carries authoritative data");
        return -1;
    }
    if (output_capacity < required_bytes) {
        set_error(error, error_len, "V1 memory ACK output is too small");
        return -1;
    }
    write_be64(output, ack->gpa);
    write_be64(output + 8, ack->version);
    write_be16(output + 16, ack->status);
    write_be16(output + 18, 0);
    write_be32(output + 20, ack->directory_physical_node_id);
    write_be64(output + 24, ack->directory_node_instance_id);
    if (ack->status == WVM_MEM_ACK_SUCCESS) {
        memcpy(output + WVM_MEM_ACK_HEADER_BYTES, ack->data,
               WVM_MEMORY_PAGE_BYTES);
    }
    *output_bytes = required_bytes;
    return 0;
}

int wvm_mem_ack_decode(const uint8_t *input, size_t input_bytes,
                          struct wvm_mem_ack *ack, char *error,
                          size_t error_len)
{
    uint16_t status;

    if (!input || !ack || input_bytes < WVM_MEM_ACK_HEADER_BYTES ||
        read_be16(input + 18) != 0) {
        set_error(error, error_len, "V1 memory ACK payload is malformed");
        return -1;
    }
    status = read_be16(input + 16);
    if (!gpa_valid(read_be64(input)) || !ack_status_valid(status) ||
        read_be32(input + 20) == 0 || read_be64(input + 24) == 0) {
        set_error(error, error_len, "V1 memory ACK payload is invalid");
        return -1;
    }
    memset(ack, 0, sizeof(*ack));
    ack->gpa = read_be64(input);
    ack->version = read_be64(input + 8);
    ack->status = status;
    ack->directory_physical_node_id = read_be32(input + 20);
    ack->directory_node_instance_id = read_be64(input + 24);
    if (status == WVM_MEM_ACK_SUCCESS) {
        if (ack->version == 0 ||
            input_bytes != WVM_MEM_ACK_HEADER_BYTES +
                               WVM_MEMORY_PAGE_BYTES) {
            set_error(error, error_len,
                      "successful V1 memory ACK lacks a full page");
            return -1;
        }
        ack->data = input + WVM_MEM_ACK_HEADER_BYTES;
        ack->data_bytes = WVM_MEMORY_PAGE_BYTES;
    } else if (ack->version != 0 ||
               input_bytes != WVM_MEM_ACK_HEADER_BYTES) {
        set_error(error, error_len,
                  "failed V1 memory ACK carries authoritative data");
        return -1;
    }
    return 0;
}

int wvm_mem_commit_ack_encode(
    const struct wvm_mem_commit_ack *ack,
    uint8_t output[WVM_MEM_COMMIT_ACK_BYTES], char *error,
    size_t error_len)
{
    if (!ack || !output || !gpa_valid(ack->gpa) ||
        !commit_ack_status_valid(ack->status) ||
        ack->directory_physical_node_id == 0 ||
        ack->directory_node_instance_id == 0 ||
        (ack->status == WVM_MEM_COMMIT_ACK_SUCCESS
             ? ack->result_version == 0
             : ack->result_version != 0)) {
        set_error(error, error_len, "V1 memory commit ACK is invalid");
        return -1;
    }
    write_be64(output, ack->gpa);
    write_be64(output + 8, ack->result_version);
    write_be16(output + 16, ack->status);
    write_be16(output + 18, 0);
    write_be32(output + 20, ack->directory_physical_node_id);
    write_be64(output + 24, ack->directory_node_instance_id);
    return 0;
}

int wvm_mem_commit_ack_decode(
    const uint8_t input[WVM_MEM_COMMIT_ACK_BYTES],
    struct wvm_mem_commit_ack *ack, char *error, size_t error_len)
{
    uint16_t status;
    uint64_t result_version;

    if (!input || !ack || read_be16(input + 18) != 0) {
        set_error(error, error_len, "V1 memory commit ACK is malformed");
        return -1;
    }
    status = read_be16(input + 16);
    result_version = read_be64(input + 8);
    if (!gpa_valid(read_be64(input)) || !commit_ack_status_valid(status) ||
        read_be32(input + 20) == 0 || read_be64(input + 24) == 0 ||
        (status == WVM_MEM_COMMIT_ACK_SUCCESS ? result_version == 0
                                                  : result_version != 0)) {
        set_error(error, error_len, "V1 memory commit ACK is invalid");
        return -1;
    }
    memset(ack, 0, sizeof(*ack));
    ack->gpa = read_be64(input);
    ack->result_version = result_version;
    ack->status = status;
    ack->directory_physical_node_id = read_be32(input + 20);
    ack->directory_node_instance_id = read_be64(input + 24);
    return 0;
}

int wvm_mem_push_encode(const struct wvm_mem_push *push, uint8_t *output,
                        size_t output_capacity, size_t *output_bytes,
                        char *error, size_t error_len)
{
    size_t required_bytes;

    if (!push_valid(push) || !output || !output_bytes) {
        set_error(error, error_len, "V1 memory push payload is invalid");
        return -1;
    }
    required_bytes = WVM_MEM_PUSH_HEADER_BYTES + push->data_bytes;
    if (output_capacity < required_bytes) {
        set_error(error, error_len, "V1 memory push output is too small");
        return -1;
    }
    write_be64(output, push->gpa);
    write_be64(output + 8, push->base_version);
    write_be64(output + 16, push->version);
    write_be16(output + 24, push->offset);
    write_be16(output + 26, push->size);
    write_be16(output + 28, push->flags);
    write_be16(output + 30, 0);
    write_be32(output + 32, push->directory_physical_node_id);
    write_be32(output + 36, 0);
    write_be64(output + 40, push->directory_node_instance_id);
    memcpy(output + WVM_MEM_PUSH_HEADER_BYTES, push->data, push->data_bytes);
    *output_bytes = required_bytes;
    return 0;
}

int wvm_mem_push_decode(const uint8_t *input, size_t input_bytes,
                        struct wvm_mem_push *push, char *error,
                        size_t error_len)
{
    uint16_t size;

    if (!input || !push || input_bytes < WVM_MEM_PUSH_HEADER_BYTES ||
        read_be16(input + 30) != 0 || read_be32(input + 36) != 0) {
        set_error(error, error_len, "V1 memory push payload is malformed");
        return -1;
    }
    size = read_be16(input + 26);
    if (size == 0 ||
        input_bytes != WVM_MEM_PUSH_HEADER_BYTES + (size_t)size) {
        set_error(error, error_len, "V1 memory push payload has bad length");
        return -1;
    }
    memset(push, 0, sizeof(*push));
    push->gpa = read_be64(input);
    push->base_version = read_be64(input + 8);
    push->version = read_be64(input + 16);
    push->offset = read_be16(input + 24);
    push->size = size;
    push->flags = read_be16(input + 28);
    push->directory_physical_node_id = read_be32(input + 32);
    push->directory_node_instance_id = read_be64(input + 40);
    push->data = input + WVM_MEM_PUSH_HEADER_BYTES;
    push->data_bytes = size;
    if (!push_valid(push)) {
        set_error(error, error_len, "V1 memory push payload is invalid");
        return -1;
    }
    return 0;
}

int wvm_mem_ack_envelope_build(
    const struct wvm_envelope *request,
    const struct wvm_envelope_route *resolved_reply_route,
    uint64_t response_delivery_attempt_id, const struct wvm_mem_ack *ack,
    uint8_t *payload_output, size_t payload_output_capacity,
    size_t *payload_output_bytes, struct wvm_envelope *response,
    char *error, size_t error_len)
{
    struct wvm_mem_read read;
    size_t encoded_ack_bytes;

    if (!request || !resolved_reply_route || !ack || !payload_output ||
        !payload_output_bytes || !response ||
        request->message_type != WVM_ENVELOPE_MSG_MEM_READ ||
        response_delivery_attempt_id == 0 ||
        wvm_mem_read_decode(request->payload, request->payload_bytes,
                               &read, error, error_len) != 0 ||
        !reply_destination_valid(resolved_reply_route->destination_kind,
                                 resolved_reply_route->destination_scope,
                                 resolved_reply_route
                                     ->destination_vnode_or_endpoint) ||
        resolved_reply_route->hop_limit == 0 ||
        resolved_reply_route->hop_count != 0 ||
        resolved_reply_route->destination_kind !=
            read.reply_destination_kind ||
        resolved_reply_route->destination_scope !=
            read.reply_destination_scope ||
        resolved_reply_route->destination_vnode_or_endpoint !=
            read.reply_destination_vnode ||
        ack->gpa != read.gpa ||
        wvm_mem_ack_encode(ack, payload_output, payload_output_capacity,
                              &encoded_ack_bytes, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "cannot build V1 memory ACK response envelope");
        }
        return -1;
    }

    memset(response, 0, sizeof(*response));
    response->message_type = WVM_ENVELOPE_MSG_MEM_ACK;
    response->vm_id = request->vm_id;
    response->vm_incarnation = request->vm_incarnation;
    response->manifest_generation = request->manifest_generation;
    response->origin_physical_node_id = request->origin_physical_node_id;
    response->origin_runtime_instance_id = request->origin_runtime_instance_id;
    memcpy(response->operation_id, request->operation_id,
           sizeof(response->operation_id));
    response->delivery_attempt_id = response_delivery_attempt_id;
    response->route_scope_id = request->route_scope_id;
    response->topology_revision = request->topology_revision;
    response->route_generation = request->route_generation;
    memcpy(response->route_snapshot_digest, request->route_snapshot_digest,
           sizeof(response->route_snapshot_digest));
    response->route = *resolved_reply_route;
    response->payload = payload_output;
    response->payload_bytes = encoded_ack_bytes;
    *payload_output_bytes = encoded_ack_bytes;
    return 0;
}

int wvm_mem_commit_ack_envelope_build(
    const struct wvm_envelope *request,
    const struct wvm_envelope_route *resolved_reply_route,
    uint64_t response_delivery_attempt_id,
    const struct wvm_mem_commit_ack *ack,
    uint8_t payload_output[WVM_MEM_COMMIT_ACK_BYTES],
    struct wvm_envelope *response, char *error, size_t error_len)
{
    struct wvm_mem_commit commit;

    if (!request || !resolved_reply_route || !ack || !payload_output ||
        !response || request->message_type != WVM_ENVELOPE_MSG_COMMIT_DIFF ||
        response_delivery_attempt_id == 0 ||
        wvm_mem_commit_decode(request->payload, request->payload_bytes,
                                 &commit, error, error_len) != 0 ||
        !reply_destination_valid(resolved_reply_route->destination_kind,
                                 resolved_reply_route->destination_scope,
                                 resolved_reply_route
                                     ->destination_vnode_or_endpoint) ||
        resolved_reply_route->hop_limit == 0 ||
        resolved_reply_route->hop_count != 0 ||
        resolved_reply_route->destination_kind !=
            commit.reply_destination_kind ||
        resolved_reply_route->destination_scope !=
            commit.reply_destination_scope ||
        resolved_reply_route->destination_vnode_or_endpoint !=
            commit.reply_destination_vnode ||
        ack->gpa != commit.gpa ||
        wvm_mem_commit_ack_encode(ack, payload_output, error,
                                     error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "cannot build V1 memory commit ACK envelope");
        }
        return -1;
    }
    memset(response, 0, sizeof(*response));
    response->message_type = WVM_ENVELOPE_MSG_MEM_COMMIT_ACK;
    response->vm_id = request->vm_id;
    response->vm_incarnation = request->vm_incarnation;
    response->manifest_generation = request->manifest_generation;
    response->origin_physical_node_id = request->origin_physical_node_id;
    response->origin_runtime_instance_id = request->origin_runtime_instance_id;
    memcpy(response->operation_id, request->operation_id,
           sizeof(response->operation_id));
    response->delivery_attempt_id = response_delivery_attempt_id;
    response->route_scope_id = request->route_scope_id;
    response->topology_revision = request->topology_revision;
    response->route_generation = request->route_generation;
    memcpy(response->route_snapshot_digest, request->route_snapshot_digest,
           sizeof(response->route_snapshot_digest));
    response->route = *resolved_reply_route;
    response->payload = payload_output;
    response->payload_bytes = WVM_MEM_COMMIT_ACK_BYTES;
    return 0;
}

int wvm_memory_payload_validate(uint16_t message_type,
                                   const uint8_t *payload,
                                   size_t payload_bytes, char *error,
                                   size_t error_len)
{
    struct wvm_mem_read read;
    struct wvm_mem_ack ack;
    struct wvm_mem_commit commit;
    struct wvm_mem_commit_ack commit_ack;
    struct wvm_mem_push push;

    switch (message_type) {
    case WVM_ENVELOPE_MSG_MEM_READ:
        return wvm_mem_read_decode(payload, payload_bytes, &read, error,
                                      error_len);
    case WVM_ENVELOPE_MSG_MEM_ACK:
        return wvm_mem_ack_decode(payload, payload_bytes, &ack, error,
                                     error_len);
    case WVM_ENVELOPE_MSG_COMMIT_DIFF:
        return wvm_mem_commit_decode(payload, payload_bytes, &commit, error,
                                        error_len);
    case WVM_ENVELOPE_MSG_MEM_COMMIT_ACK:
        if (payload_bytes != WVM_MEM_COMMIT_ACK_BYTES) {
            set_error(error, error_len, "V1 memory commit ACK has bad length");
            return -1;
        }
        return wvm_mem_commit_ack_decode(payload, &commit_ack, error,
                                            error_len);
    case WVM_ENVELOPE_MSG_PAGE_PUSH_FULL:
    case WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF:
        if (wvm_mem_push_decode(payload, payload_bytes, &push, error,
                                error_len) != 0) {
            return -1;
        }
        if ((message_type == WVM_ENVELOPE_MSG_PAGE_PUSH_FULL) !=
            ((push.flags & WVM_MEM_PUSH_FLAG_FULL) != 0)) {
            set_error(error, error_len,
                      "V1 memory push type does not match payload flags");
            return -1;
        }
        return 0;
    default:
        return 0;
    }
}

#include "wavevm_vcpu_handoff.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_sha256.h"

enum {
    REQUEST_VERSION_OFFSET = 0,
    REQUEST_BACKEND_OFFSET = 2,
    REQUEST_CONTEXT_SCHEMA_OFFSET = 4,
    REQUEST_FENCE_RESULT_OFFSET = 6,
    REQUEST_VM_ID_OFFSET = 8,
    REQUEST_ORIGIN_PHYSICAL_NODE_OFFSET = 12,
    REQUEST_VCPU_INDEX_OFFSET = 16,
    REQUEST_REPLY_DESTINATION_KIND_OFFSET = 20,
    REQUEST_VM_INCARNATION_OFFSET = 24,
    REQUEST_MANIFEST_GENERATION_OFFSET = 32,
    REQUEST_ORIGIN_RUNTIME_OFFSET = 40,
    REQUEST_DESTINATION_EXECUTOR_OFFSET = 48,
    REQUEST_HANDOFF_SEQUENCE_OFFSET = 56,
    REQUEST_MEMORY_FENCE_OFFSET = 64,
    REQUEST_INTERRUPT_WATERMARK_OFFSET = 72,
    REQUEST_DEVICE_WATERMARK_OFFSET = 80,
    REQUEST_REPLY_DESTINATION_SCOPE_OFFSET = 88,
    REQUEST_REPLY_DESTINATION_VNODE_OFFSET = 96,
    REQUEST_OPERATION_ID_OFFSET = 104,
    REQUEST_CONTEXT_FIELDS_OFFSET = 120,
    REQUEST_CONTEXT_BYTES_OFFSET = 128,
    REQUEST_CONTEXT_DIGEST_OFFSET = 136,
};

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

static int all_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static uint16_t read_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
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

static int backend_valid(uint16_t backend)
{
    return backend == WVM_VCPU_BACKEND_KVM ||
           backend == WVM_VCPU_BACKEND_TCG;
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

static int request_valid(const struct wvm_vcpu_handoff_request *request)
{
    return request &&
           request->protocol_version == WVM_VCPU_HANDOFF_REQUEST_VERSION &&
           backend_valid(request->backend) &&
           request->context_schema_version == WVM_VCPU_CONTEXT_SCHEMA_X86 &&
           request->memory_fence_result == WVM_VCPU_MEMORY_FENCE_SUCCEEDED &&
           request->vm_id != 0 && request->origin_physical_node_id != 0 &&
           request->vm_incarnation != 0 &&
           request->manifest_generation != 0 &&
           request->origin_runtime_instance_id != 0 &&
           request->destination_executor_id != 0 &&
           request->destination_executor_id <= UINT32_MAX &&
           request->destination_executor_id !=
               WVM_ENVELOPE_ROUTE_DESTINATION_UNSPECIFIED &&
           reply_destination_valid(request->reply_destination_kind,
                                   request->reply_destination_scope,
                                   request->reply_destination_vnode) &&
           request->handoff_sequence != 0 && request->memory_fence_id != 0 &&
           !all_zero(request->operation_id, sizeof(request->operation_id)) &&
           (request->context_valid_fields &
            WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE) != 0 &&
           (request->context_valid_fields &
            ~WVM_VCPU_CONTEXT_KNOWN_FIELDS) == 0 &&
           request->context && request->context_bytes != 0 &&
           request->context_bytes <= WVM_VCPU_HANDOFF_MAX_CONTEXT_BYTES;
}

int wvm_vcpu_handoff_request_encode(
    const struct wvm_vcpu_handoff_request *request, uint8_t *output,
    size_t output_capacity, size_t *output_bytes, char *error,
    size_t error_len)
{
    uint8_t context_digest[WVM_SHA256_DIGEST_BYTES];
    size_t required_bytes;

    if (!request_valid(request) || !output || !output_bytes) {
        set_error(error, error_len, "vCPU handoff request is invalid");
        return -1;
    }
    required_bytes = WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES +
                     request->context_bytes;
    if (output_capacity < required_bytes) {
        set_error(error, error_len, "vCPU handoff output is too small");
        return -1;
    }
    memset(output, 0, WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES);
    write_be16(output + REQUEST_VERSION_OFFSET, request->protocol_version);
    write_be16(output + REQUEST_BACKEND_OFFSET, request->backend);
    write_be16(output + REQUEST_CONTEXT_SCHEMA_OFFSET,
               request->context_schema_version);
    write_be16(output + REQUEST_FENCE_RESULT_OFFSET,
               request->memory_fence_result);
    write_be32(output + REQUEST_VM_ID_OFFSET, request->vm_id);
    write_be32(output + REQUEST_ORIGIN_PHYSICAL_NODE_OFFSET,
               request->origin_physical_node_id);
    write_be32(output + REQUEST_VCPU_INDEX_OFFSET, request->vcpu_index);
    write_be16(output + REQUEST_REPLY_DESTINATION_KIND_OFFSET,
               request->reply_destination_kind);
    write_be64(output + REQUEST_VM_INCARNATION_OFFSET,
               request->vm_incarnation);
    write_be64(output + REQUEST_MANIFEST_GENERATION_OFFSET,
               request->manifest_generation);
    write_be64(output + REQUEST_ORIGIN_RUNTIME_OFFSET,
               request->origin_runtime_instance_id);
    write_be64(output + REQUEST_DESTINATION_EXECUTOR_OFFSET,
               request->destination_executor_id);
    write_be64(output + REQUEST_HANDOFF_SEQUENCE_OFFSET,
               request->handoff_sequence);
    write_be64(output + REQUEST_MEMORY_FENCE_OFFSET, request->memory_fence_id);
    write_be64(output + REQUEST_INTERRUPT_WATERMARK_OFFSET,
               request->local_interrupt_watermark);
    write_be64(output + REQUEST_DEVICE_WATERMARK_OFFSET,
               request->device_event_watermark);
    write_be64(output + REQUEST_REPLY_DESTINATION_SCOPE_OFFSET,
               request->reply_destination_scope);
    write_be32(output + REQUEST_REPLY_DESTINATION_VNODE_OFFSET,
               request->reply_destination_vnode);
    memcpy(output + REQUEST_OPERATION_ID_OFFSET, request->operation_id,
           sizeof(request->operation_id));
    write_be64(output + REQUEST_CONTEXT_FIELDS_OFFSET,
               request->context_valid_fields);
    write_be32(output + REQUEST_CONTEXT_BYTES_OFFSET,
               (uint32_t)request->context_bytes);
    wvm_sha256_digest(request->context, request->context_bytes,
                      context_digest);
    memcpy(output + REQUEST_CONTEXT_DIGEST_OFFSET, context_digest,
           sizeof(context_digest));
    memcpy(output + WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES, request->context,
           request->context_bytes);
    *output_bytes = required_bytes;
    return 0;
}

int wvm_vcpu_handoff_request_decode(
    const uint8_t *input, size_t input_bytes,
    struct wvm_vcpu_handoff_request *request, char *error, size_t error_len)
{
    uint8_t context_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t context_bytes;

    if (!input || !request ||
        input_bytes < WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES ||
        read_be16(input + 22) != 0 || read_be32(input + 100) != 0 ||
        read_be32(input + 132) != 0) {
        set_error(error, error_len, "vCPU handoff header is malformed");
        return -1;
    }
    context_bytes = read_be32(input + REQUEST_CONTEXT_BYTES_OFFSET);
    if (context_bytes == 0 || context_bytes > WVM_VCPU_HANDOFF_MAX_CONTEXT_BYTES ||
        input_bytes != WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES +
                           (size_t)context_bytes) {
        set_error(error, error_len, "vCPU handoff context bounds are invalid");
        return -1;
    }

    memset(request, 0, sizeof(*request));
    request->protocol_version = read_be16(input + REQUEST_VERSION_OFFSET);
    request->backend = read_be16(input + REQUEST_BACKEND_OFFSET);
    request->context_schema_version =
        read_be16(input + REQUEST_CONTEXT_SCHEMA_OFFSET);
    request->memory_fence_result = read_be16(input + REQUEST_FENCE_RESULT_OFFSET);
    request->vm_id = read_be32(input + REQUEST_VM_ID_OFFSET);
    request->origin_physical_node_id =
        read_be32(input + REQUEST_ORIGIN_PHYSICAL_NODE_OFFSET);
    request->vcpu_index = read_be32(input + REQUEST_VCPU_INDEX_OFFSET);
    request->reply_destination_kind =
        read_be16(input + REQUEST_REPLY_DESTINATION_KIND_OFFSET);
    request->vm_incarnation = read_be64(input + REQUEST_VM_INCARNATION_OFFSET);
    request->manifest_generation =
        read_be64(input + REQUEST_MANIFEST_GENERATION_OFFSET);
    request->origin_runtime_instance_id =
        read_be64(input + REQUEST_ORIGIN_RUNTIME_OFFSET);
    request->destination_executor_id =
        read_be64(input + REQUEST_DESTINATION_EXECUTOR_OFFSET);
    request->handoff_sequence =
        read_be64(input + REQUEST_HANDOFF_SEQUENCE_OFFSET);
    request->memory_fence_id = read_be64(input + REQUEST_MEMORY_FENCE_OFFSET);
    request->local_interrupt_watermark =
        read_be64(input + REQUEST_INTERRUPT_WATERMARK_OFFSET);
    request->device_event_watermark =
        read_be64(input + REQUEST_DEVICE_WATERMARK_OFFSET);
    request->reply_destination_scope =
        read_be64(input + REQUEST_REPLY_DESTINATION_SCOPE_OFFSET);
    request->reply_destination_vnode =
        read_be32(input + REQUEST_REPLY_DESTINATION_VNODE_OFFSET);
    memcpy(request->operation_id, input + REQUEST_OPERATION_ID_OFFSET,
           sizeof(request->operation_id));
    request->context_valid_fields =
        read_be64(input + REQUEST_CONTEXT_FIELDS_OFFSET);
    request->context = input + WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES;
    request->context_bytes = context_bytes;

    if (!request_valid(request)) {
        set_error(error, error_len, "vCPU handoff request fields are invalid");
        return -1;
    }
    wvm_sha256_digest(request->context, request->context_bytes, context_digest);
    if (memcmp(context_digest, input + REQUEST_CONTEXT_DIGEST_OFFSET,
               sizeof(context_digest)) != 0) {
        set_error(error, error_len, "vCPU handoff context digest mismatch");
        return -1;
    }
    return 0;
}

int wvm_vcpu_handoff_request_validate_envelope(
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    if (!request_valid(request) || !envelope ||
        envelope->message_type != WVM_ENVELOPE_MSG_VCPU_RUN ||
        request->vm_id != envelope->vm_id ||
        request->vm_incarnation != envelope->vm_incarnation ||
        request->manifest_generation != envelope->manifest_generation ||
        request->origin_physical_node_id !=
            envelope->origin_physical_node_id ||
        request->origin_runtime_instance_id !=
            envelope->origin_runtime_instance_id ||
        request->destination_executor_id !=
            envelope->route.destination_vnode_or_endpoint ||
        memcmp(request->operation_id, envelope->operation_id,
               sizeof(request->operation_id)) != 0) {
        set_error(error, error_len,
                  "vCPU handoff does not match its admitted envelope");
        return -1;
    }
    return 0;
}

enum {
    RESULT_VERSION_OFFSET = 0,
    RESULT_STATUS_OFFSET = 2,
    RESULT_EXIT_CLASS_OFFSET = 4,
    RESULT_BACKEND_OFFSET = 6,
    RESULT_VM_ID_OFFSET = 8,
    RESULT_ORIGIN_PHYSICAL_NODE_OFFSET = 12,
    RESULT_VCPU_INDEX_OFFSET = 16,
    RESULT_VM_INCARNATION_OFFSET = 24,
    RESULT_MANIFEST_GENERATION_OFFSET = 32,
    RESULT_ORIGIN_RUNTIME_OFFSET = 40,
    RESULT_HANDOFF_SEQUENCE_OFFSET = 48,
    RESULT_ERROR_GPA_OFFSET = 56,
    RESULT_MEMORY_FENCE_OFFSET = 64,
    RESULT_INTERRUPT_WATERMARK_OFFSET = 72,
    RESULT_DEVICE_WATERMARK_OFFSET = 80,
    RESULT_OPERATION_ID_OFFSET = 88,
    RESULT_CONTEXT_SCHEMA_OFFSET = 104,
    RESULT_CONTEXT_FIELDS_OFFSET = 108,
    RESULT_CONTEXT_BYTES_OFFSET = 116,
    RESULT_CONTEXT_DIGEST_OFFSET = 124,
};

static int exit_class_valid(uint16_t exit_class)
{
    return exit_class <= WVM_VCPU_EXIT_EXECUTOR_ERROR;
}

static int result_valid(const struct wvm_vcpu_handoff_result *result)
{
    if (!result ||
        result->protocol_version != WVM_VCPU_HANDOFF_RESULT_VERSION ||
        result->status > WVM_VCPU_HANDOFF_RESULT_IN_PROGRESS ||
        !exit_class_valid(result->exit_class) || !backend_valid(result->backend) ||
        result->vm_id == 0 || result->origin_physical_node_id == 0 ||
        result->vm_incarnation == 0 || result->manifest_generation == 0 ||
        result->origin_runtime_instance_id == 0 ||
        result->handoff_sequence == 0 ||
        all_zero(result->operation_id, sizeof(result->operation_id)) ||
        result->context_schema_version != WVM_VCPU_CONTEXT_SCHEMA_X86 ||
        (result->context_valid_fields & ~WVM_VCPU_CONTEXT_KNOWN_FIELDS) !=
            0 ||
        result->context_bytes > WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES ||
        (result->context_bytes != 0 && !result->context) ||
        (result->context_bytes == 0 && result->context != NULL)) {
        return 0;
    }
    if (result->status == WVM_VCPU_HANDOFF_RESULT_SUCCESS) {
        return result->exit_class != WVM_VCPU_EXIT_MEMORY_ERROR &&
               result->exit_class != WVM_VCPU_EXIT_EXECUTOR_ERROR &&
               result->context_bytes != 0 &&
               (result->context_valid_fields &
                WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE) != 0;
    }
    if (result->status == WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE) {
        return result->exit_class == WVM_VCPU_EXIT_MEMORY_ERROR &&
               result->context_bytes == 0 &&
               result->context_valid_fields == 0;
    }
    if (result->status == WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE) {
        return result->exit_class == WVM_VCPU_EXIT_EXECUTOR_ERROR &&
               result->context_bytes == 0 &&
               result->context_valid_fields == 0;
    }
    return result->exit_class == WVM_VCPU_EXIT_NONE &&
           result->error_gpa == 0 && result->produced_memory_fence_id == 0 &&
           result->remote_interrupt_watermark == 0 &&
           result->remote_device_watermark == 0 &&
           result->context_bytes == 0 && result->context_valid_fields == 0;
}

int wvm_vcpu_handoff_result_encode(
    const struct wvm_vcpu_handoff_result *result, uint8_t *output,
    size_t output_capacity, size_t *output_bytes, char *error,
    size_t error_len)
{
    uint8_t context_digest[WVM_SHA256_DIGEST_BYTES];
    size_t required_bytes;

    if (!result_valid(result) || !output || !output_bytes) {
        set_error(error, error_len, "vCPU handoff result is invalid");
        return -1;
    }
    required_bytes = WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES +
                     result->context_bytes;
    if (output_capacity < required_bytes) {
        set_error(error, error_len, "vCPU handoff result output is too small");
        return -1;
    }
    memset(output, 0, WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES);
    write_be16(output + RESULT_VERSION_OFFSET, result->protocol_version);
    write_be16(output + RESULT_STATUS_OFFSET, result->status);
    write_be16(output + RESULT_EXIT_CLASS_OFFSET, result->exit_class);
    write_be16(output + RESULT_BACKEND_OFFSET, result->backend);
    write_be32(output + RESULT_VM_ID_OFFSET, result->vm_id);
    write_be32(output + RESULT_ORIGIN_PHYSICAL_NODE_OFFSET,
               result->origin_physical_node_id);
    write_be32(output + RESULT_VCPU_INDEX_OFFSET, result->vcpu_index);
    write_be64(output + RESULT_VM_INCARNATION_OFFSET,
               result->vm_incarnation);
    write_be64(output + RESULT_MANIFEST_GENERATION_OFFSET,
               result->manifest_generation);
    write_be64(output + RESULT_ORIGIN_RUNTIME_OFFSET,
               result->origin_runtime_instance_id);
    write_be64(output + RESULT_HANDOFF_SEQUENCE_OFFSET,
               result->handoff_sequence);
    write_be64(output + RESULT_ERROR_GPA_OFFSET, result->error_gpa);
    write_be64(output + RESULT_MEMORY_FENCE_OFFSET,
               result->produced_memory_fence_id);
    write_be64(output + RESULT_INTERRUPT_WATERMARK_OFFSET,
               result->remote_interrupt_watermark);
    write_be64(output + RESULT_DEVICE_WATERMARK_OFFSET,
               result->remote_device_watermark);
    memcpy(output + RESULT_OPERATION_ID_OFFSET, result->operation_id,
           sizeof(result->operation_id));
    write_be16(output + RESULT_CONTEXT_SCHEMA_OFFSET,
               result->context_schema_version);
    write_be64(output + RESULT_CONTEXT_FIELDS_OFFSET,
               result->context_valid_fields);
    write_be32(output + RESULT_CONTEXT_BYTES_OFFSET,
               (uint32_t)result->context_bytes);
    if (result->context_bytes != 0) {
        wvm_sha256_digest(result->context, result->context_bytes,
                          context_digest);
        memcpy(output + RESULT_CONTEXT_DIGEST_OFFSET, context_digest,
               sizeof(context_digest));
        memcpy(output + WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES, result->context,
               result->context_bytes);
    }
    *output_bytes = required_bytes;
    return 0;
}

int wvm_vcpu_handoff_result_decode(
    const uint8_t *input, size_t input_bytes,
    struct wvm_vcpu_handoff_result *result, char *error, size_t error_len)
{
    uint8_t context_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t context_bytes;

    if (!input || !result ||
        input_bytes < WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES ||
        read_be32(input + 20) != 0 || read_be16(input + 106) != 0 ||
        read_be32(input + 120) != 0 || read_be32(input + 156) != 0) {
        set_error(error, error_len, "vCPU handoff result header is malformed");
        return -1;
    }
    context_bytes = read_be32(input + RESULT_CONTEXT_BYTES_OFFSET);
    if (context_bytes > WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES ||
        input_bytes != WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES +
                           (size_t)context_bytes) {
        set_error(error, error_len, "vCPU handoff result context bounds are invalid");
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->protocol_version = read_be16(input + RESULT_VERSION_OFFSET);
    result->status = read_be16(input + RESULT_STATUS_OFFSET);
    result->exit_class = read_be16(input + RESULT_EXIT_CLASS_OFFSET);
    result->backend = read_be16(input + RESULT_BACKEND_OFFSET);
    result->vm_id = read_be32(input + RESULT_VM_ID_OFFSET);
    result->origin_physical_node_id =
        read_be32(input + RESULT_ORIGIN_PHYSICAL_NODE_OFFSET);
    result->vcpu_index = read_be32(input + RESULT_VCPU_INDEX_OFFSET);
    result->vm_incarnation = read_be64(input + RESULT_VM_INCARNATION_OFFSET);
    result->manifest_generation =
        read_be64(input + RESULT_MANIFEST_GENERATION_OFFSET);
    result->origin_runtime_instance_id =
        read_be64(input + RESULT_ORIGIN_RUNTIME_OFFSET);
    result->handoff_sequence =
        read_be64(input + RESULT_HANDOFF_SEQUENCE_OFFSET);
    result->error_gpa = read_be64(input + RESULT_ERROR_GPA_OFFSET);
    result->produced_memory_fence_id =
        read_be64(input + RESULT_MEMORY_FENCE_OFFSET);
    result->remote_interrupt_watermark =
        read_be64(input + RESULT_INTERRUPT_WATERMARK_OFFSET);
    result->remote_device_watermark =
        read_be64(input + RESULT_DEVICE_WATERMARK_OFFSET);
    memcpy(result->operation_id, input + RESULT_OPERATION_ID_OFFSET,
           sizeof(result->operation_id));
    result->context_schema_version =
        read_be16(input + RESULT_CONTEXT_SCHEMA_OFFSET);
    result->context_valid_fields =
        read_be64(input + RESULT_CONTEXT_FIELDS_OFFSET);
    result->context = context_bytes == 0
                          ? NULL
                          : input + WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES;
    result->context_bytes = context_bytes;

    if (!result_valid(result)) {
        set_error(error, error_len, "vCPU handoff result fields are invalid");
        return -1;
    }
    if (context_bytes != 0) {
        wvm_sha256_digest(result->context, result->context_bytes,
                          context_digest);
        if (memcmp(context_digest, input + RESULT_CONTEXT_DIGEST_OFFSET,
                   sizeof(context_digest)) != 0) {
            set_error(error, error_len,
                      "vCPU handoff result context digest mismatch");
            return -1;
        }
    } else if (!all_zero(input + RESULT_CONTEXT_DIGEST_OFFSET,
                         WVM_SHA256_DIGEST_BYTES)) {
        set_error(error, error_len,
                  "empty vCPU handoff result carries a context digest");
        return -1;
    }
    return 0;
}

int wvm_vcpu_handoff_result_validate_request(
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result, char *error,
    size_t error_len)
{
    if (!request_valid(request) || !result_valid(result) ||
        result->vm_id != request->vm_id ||
        result->vm_incarnation != request->vm_incarnation ||
        result->manifest_generation != request->manifest_generation ||
        result->origin_physical_node_id != request->origin_physical_node_id ||
        result->origin_runtime_instance_id !=
            request->origin_runtime_instance_id ||
        result->vcpu_index != request->vcpu_index ||
        result->handoff_sequence != request->handoff_sequence ||
        result->backend != request->backend ||
        result->context_schema_version != request->context_schema_version ||
        memcmp(result->operation_id, request->operation_id,
               sizeof(result->operation_id)) != 0) {
        set_error(error, error_len,
                  "vCPU handoff result does not match request");
        return -1;
    }
    return 0;
}

int wvm_vcpu_handoff_exit_envelope_build(
    const struct wvm_envelope *request_envelope,
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_envelope_route *resolved_reply_route,
    uint64_t response_delivery_attempt_id,
    const struct wvm_vcpu_handoff_result *result, uint8_t *payload_output,
    size_t payload_output_capacity, size_t *payload_output_bytes,
    struct wvm_envelope *response, char *error, size_t error_len)
{
    size_t encoded_result_bytes;

    if (!request_envelope || !request || !resolved_reply_route || !result ||
        !payload_output || !payload_output_bytes || !response ||
        response_delivery_attempt_id == 0 ||
        wvm_vcpu_handoff_request_validate_envelope(
            request, request_envelope, error, error_len) != 0 ||
        wvm_vcpu_handoff_result_validate_request(request, result, error,
                                                 error_len) != 0 ||
        !reply_destination_valid(resolved_reply_route->destination_kind,
                                 resolved_reply_route->destination_scope,
                                 resolved_reply_route
                                     ->destination_vnode_or_endpoint) ||
        resolved_reply_route->hop_limit == 0 ||
        resolved_reply_route->hop_count != 0 ||
        resolved_reply_route->destination_kind !=
            request->reply_destination_kind ||
        resolved_reply_route->destination_scope !=
            request->reply_destination_scope ||
        resolved_reply_route->destination_vnode_or_endpoint !=
            request->reply_destination_vnode ||
        wvm_vcpu_handoff_result_encode(
            result, payload_output, payload_output_capacity,
            &encoded_result_bytes, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "cannot build typed vCPU exit response envelope");
        }
        return -1;
    }

    memset(response, 0, sizeof(*response));
    response->message_type = WVM_ENVELOPE_MSG_VCPU_EXIT;
    response->vm_id = request_envelope->vm_id;
    response->vm_incarnation = request_envelope->vm_incarnation;
    response->manifest_generation = request_envelope->manifest_generation;
    response->origin_physical_node_id =
        request_envelope->origin_physical_node_id;
    response->origin_runtime_instance_id =
        request_envelope->origin_runtime_instance_id;
    memcpy(response->operation_id, request_envelope->operation_id,
           sizeof(response->operation_id));
    response->delivery_attempt_id = response_delivery_attempt_id;
    response->route_scope_id = request_envelope->route_scope_id;
    response->topology_revision = request_envelope->topology_revision;
    response->route_generation = request_envelope->route_generation;
    memcpy(response->route_snapshot_digest,
           request_envelope->route_snapshot_digest,
           sizeof(response->route_snapshot_digest));
    response->route = *resolved_reply_route;
    response->payload = payload_output;
    response->payload_bytes = encoded_result_bytes;
    *payload_output_bytes = encoded_result_bytes;
    return 0;
}

int wvm_vcpu_handoff_exit_validate_envelope(
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    if (wvm_vcpu_handoff_result_validate_request(request, result, error,
                                                 error_len) != 0 ||
        !envelope || envelope->message_type != WVM_ENVELOPE_MSG_VCPU_EXIT ||
        envelope->vm_id != request->vm_id ||
        envelope->vm_incarnation != request->vm_incarnation ||
        envelope->manifest_generation != request->manifest_generation ||
        envelope->origin_physical_node_id !=
            request->origin_physical_node_id ||
        envelope->origin_runtime_instance_id !=
            request->origin_runtime_instance_id ||
        envelope->route.destination_kind != request->reply_destination_kind ||
        envelope->route.destination_scope != request->reply_destination_scope ||
        envelope->route.destination_vnode_or_endpoint !=
            request->reply_destination_vnode ||
        memcmp(envelope->operation_id, request->operation_id,
               sizeof(envelope->operation_id)) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "typed vCPU exit does not match handoff reply route");
        }
        return -1;
    }
    return 0;
}

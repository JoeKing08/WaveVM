#include "wavevm_local_memory.h"

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

static int all_zero(const uint8_t *bytes, size_t bytes_count)
{
    size_t i;

    for (i = 0; i < bytes_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
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

int wvm_local_memory_fault_request_encode(
    const struct wvm_local_memory_fault_request *request,
    uint8_t output[WVM_LOCAL_MEMORY_FAULT_REQUEST_BYTES], char *error,
    size_t error_len)
{
    if (!request || !output ||
        all_zero(request->operation_id, sizeof(request->operation_id)) ||
        request->delivery_attempt_id == 0 ||
        request->gpa % WVM_MEMORY_PAGE_BYTES != 0) {
        set_error(error, error_len, "local V1 memory fault request is invalid");
        return -1;
    }
    memcpy(output, request->operation_id, sizeof(request->operation_id));
    write_be64(output + 16, request->delivery_attempt_id);
    write_be64(output + 24, request->gpa);
    return 0;
}

int wvm_local_memory_fault_request_decode(
    const uint8_t *input, size_t input_bytes,
    struct wvm_local_memory_fault_request *request, char *error,
    size_t error_len)
{
    if (!input || !request ||
        input_bytes != WVM_LOCAL_MEMORY_FAULT_REQUEST_BYTES ||
        all_zero(input, WVM_IDENTITY_ID_BYTES) ||
        read_be64(input + 16) == 0 ||
        read_be64(input + 24) % WVM_MEMORY_PAGE_BYTES != 0) {
        set_error(error, error_len, "local V1 memory fault request is invalid");
        return -1;
    }
    memset(request, 0, sizeof(*request));
    memcpy(request->operation_id, input, sizeof(request->operation_id));
    request->delivery_attempt_id = read_be64(input + 16);
    request->gpa = read_be64(input + 24);
    return 0;
}

int wvm_local_memory_commit_request_encode(
    const struct wvm_local_memory_commit_request *request,
    uint8_t *output, size_t output_capacity, size_t *output_bytes,
    char *error, size_t error_len)
{
    size_t commit_bytes;

    if (!request || !output || !output_bytes ||
        all_zero(request->operation_id, sizeof(request->operation_id)) ||
        request->delivery_attempt_id == 0 ||
        (request->flags & ~WVM_LOCAL_MEMORY_COMMIT_FLAGS_VALID) != 0 ||
        output_capacity < WVM_IDENTITY_ID_BYTES + 8U + 1U +
                              WVM_MEM_COMMIT_HEADER_BYTES ||
        wvm_mem_commit_encode(
            &request->commit,
            output + WVM_IDENTITY_ID_BYTES + 8U + 1U,
            output_capacity - (WVM_IDENTITY_ID_BYTES + 8U + 1U),
            &commit_bytes, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "local V1 memory commit request is invalid");
        }
        return -1;
    }
    memcpy(output, request->operation_id, WVM_IDENTITY_ID_BYTES);
    write_be64(output + WVM_IDENTITY_ID_BYTES,
               request->delivery_attempt_id);
    output[WVM_IDENTITY_ID_BYTES + 8U] = request->flags;
    *output_bytes = WVM_IDENTITY_ID_BYTES + 8U + 1U + commit_bytes;
    return 0;
}

int wvm_local_memory_commit_request_decode(
    const uint8_t *input, size_t input_bytes,
    struct wvm_local_memory_commit_request *request, char *error,
    size_t error_len)
{
    struct wvm_mem_commit commit;

    if (!input || !request ||
        input_bytes < WVM_IDENTITY_ID_BYTES + 8U + 1U +
                          WVM_MEM_COMMIT_HEADER_BYTES ||
        all_zero(input, WVM_IDENTITY_ID_BYTES) ||
        read_be64(input + WVM_IDENTITY_ID_BYTES) == 0 ||
        (input[WVM_IDENTITY_ID_BYTES + 8U] &
         ~WVM_LOCAL_MEMORY_COMMIT_FLAGS_VALID) != 0 ||
        wvm_mem_commit_decode(
            input + WVM_IDENTITY_ID_BYTES + 8U + 1U,
            input_bytes - (WVM_IDENTITY_ID_BYTES + 8U + 1U),
            &commit, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "local V1 memory commit request is invalid");
        }
        return -1;
    }
    memset(request, 0, sizeof(*request));
    memcpy(request->operation_id, input, WVM_IDENTITY_ID_BYTES);
    request->delivery_attempt_id = read_be64(input + WVM_IDENTITY_ID_BYTES);
    request->flags = input[WVM_IDENTITY_ID_BYTES + 8U];
    request->commit = commit;
    return 0;
}

int wvm_local_memory_commit_result_encode(
    const struct wvm_local_memory_commit_result *result,
    uint8_t output[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES], char *error,
    size_t error_len)
{
    if (!result || !output ||
        all_zero(result->operation_id, sizeof(result->operation_id)) ||
        wvm_mem_commit_ack_encode(
            &result->ack,
            output + WVM_IDENTITY_ID_BYTES, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "local V1 memory commit result is invalid");
        }
        return -1;
    }
    memcpy(output, result->operation_id, WVM_IDENTITY_ID_BYTES);
    return 0;
}

int wvm_local_memory_commit_result_decode(
    const uint8_t input[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES],
    struct wvm_local_memory_commit_result *result, char *error,
    size_t error_len)
{
    struct wvm_mem_commit_ack ack;

    if (!input || !result ||
        all_zero(input, WVM_IDENTITY_ID_BYTES) ||
        wvm_mem_commit_ack_decode(
            input + WVM_IDENTITY_ID_BYTES, &ack, error,
            error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "local V1 memory commit result is invalid");
        }
        return -1;
    }
    memset(result, 0, sizeof(*result));
    memcpy(result->operation_id, input, WVM_IDENTITY_ID_BYTES);
    result->ack = ack;
    return 0;
}

int wvm_local_memory_result_length_encode(
    size_t ack_payload_bytes,
    uint8_t output[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES], char *error,
    size_t error_len)
{
    if (!output ||
        (ack_payload_bytes != 0 &&
         ack_payload_bytes != WVM_MEM_ACK_HEADER_BYTES &&
         ack_payload_bytes !=
             WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES)) {
        set_error(error, error_len, "local V1 memory result length is invalid");
        return -1;
    }
    write_be32(output, (uint32_t)ack_payload_bytes);
    return 0;
}

int wvm_local_memory_result_length_decode(
    const uint8_t input[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES],
    size_t *ack_payload_bytes, char *error, size_t error_len)
{
    uint32_t decoded;

    if (!input || !ack_payload_bytes) {
        set_error(error, error_len, "local V1 memory result length is invalid");
        return -1;
    }
    decoded = read_be32(input);
    if (decoded != 0 && decoded != WVM_MEM_ACK_HEADER_BYTES &&
        decoded != WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES) {
        set_error(error, error_len, "local V1 memory result length is invalid");
        return -1;
    }
    *ack_payload_bytes = decoded;
    return 0;
}

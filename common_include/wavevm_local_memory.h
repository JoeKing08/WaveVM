#ifndef WAVEVM_LOCAL_MEMORY_H
#define WAVEVM_LOCAL_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_identity.h"
#include "wavevm_memory.h"

/*
 * QEMU/executor channels are manifest-bound at registration time. This local
 * record therefore carries the semantic operation key and page request while
 * resolving VM identity and route authority from that admitted connection.
 */
#define WVM_LOCAL_MEMORY_FAULT_REQUEST_BYTES 32U
#define WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES 4U
#define WVM_LOCAL_MEMORY_COMMIT_REQUEST_HEADER_BYTES \
    (WVM_IDENTITY_ID_BYTES + 8U + 1U + WVM_MEM_COMMIT_HEADER_BYTES)
#define WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES \
    (WVM_IDENTITY_ID_BYTES + WVM_MEM_COMMIT_ACK_BYTES)

#define WVM_LOCAL_MEMORY_COMMIT_FLAG_SHARED_BACKING 0x01U
#define WVM_LOCAL_MEMORY_COMMIT_FLAGS_VALID \
    WVM_LOCAL_MEMORY_COMMIT_FLAG_SHARED_BACKING

struct wvm_local_memory_fault_request {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint64_t delivery_attempt_id;
    uint64_t gpa;
};

struct wvm_local_memory_commit_request {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint64_t delivery_attempt_id;
    uint8_t flags;
    struct wvm_mem_commit commit;
};

struct wvm_local_memory_commit_result {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_mem_commit_ack ack;
};

int wvm_local_memory_fault_request_encode(
    const struct wvm_local_memory_fault_request *request,
    uint8_t output[WVM_LOCAL_MEMORY_FAULT_REQUEST_BYTES], char *error,
    size_t error_len);
int wvm_local_memory_fault_request_decode(
    const uint8_t *input, size_t input_bytes,
    struct wvm_local_memory_fault_request *request, char *error,
    size_t error_len);

int wvm_local_memory_commit_request_encode(
    const struct wvm_local_memory_commit_request *request,
    uint8_t *output, size_t output_capacity, size_t *output_bytes,
    char *error, size_t error_len);
int wvm_local_memory_commit_request_decode(
    const uint8_t *input, size_t input_bytes,
    struct wvm_local_memory_commit_request *request, char *error,
    size_t error_len);
int wvm_local_memory_commit_result_encode(
    const struct wvm_local_memory_commit_result *result,
    uint8_t output[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES], char *error,
    size_t error_len);
int wvm_local_memory_commit_result_decode(
    const uint8_t input[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES],
    struct wvm_local_memory_commit_result *result, char *error,
    size_t error_len);

/*
 * A zero result length denotes a local terminal failure before a directory
 * ACK exists. A nonzero length is one exact typed V1 MEM_ACK payload.
 */
int wvm_local_memory_result_length_encode(
    size_t ack_payload_bytes,
    uint8_t output[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES], char *error,
    size_t error_len);
int wvm_local_memory_result_length_decode(
    const uint8_t input[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES],
    size_t *ack_payload_bytes, char *error, size_t error_len);

#endif /* WAVEVM_LOCAL_MEMORY_H */

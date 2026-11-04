#include <stdio.h>
#include <string.h>

#include "wavevm_local_memory.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "local-memory test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_local_memory_fault_request request;
    struct wvm_local_memory_fault_request decoded;
    struct wvm_local_memory_commit_request commit_request;
    struct wvm_local_memory_commit_request decoded_commit_request;
    struct wvm_local_memory_commit_result commit_result;
    struct wvm_local_memory_commit_result decoded_commit_result;
    uint8_t encoded[WVM_LOCAL_MEMORY_FAULT_REQUEST_BYTES];
    uint8_t commit_encoded[WVM_LOCAL_MEMORY_COMMIT_REQUEST_HEADER_BYTES +
                           8U];
    uint8_t commit_result_encoded[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES];
    uint8_t commit_data[3] = {0x31, 0x32, 0x33};
    uint8_t length[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES];
    size_t commit_encoded_bytes = 0;
    size_t ack_payload_bytes = 0;
    char error[128] = {0};

    memset(&request, 0, sizeof(request));
    request.operation_id[15] = 1;
    request.delivery_attempt_id = 7;
    request.gpa = 0x4000;
    if (expect(wvm_local_memory_fault_request_encode(
                   &request, encoded, error, sizeof(error)) == 0 &&
                   wvm_local_memory_fault_request_decode(
                       encoded, sizeof(encoded), &decoded, error,
                       sizeof(error)) == 0 &&
                   memcmp(decoded.operation_id, request.operation_id,
                          sizeof(request.operation_id)) == 0 &&
                   decoded.delivery_attempt_id == request.delivery_attempt_id &&
                   decoded.gpa == request.gpa,
               "round trip typed local fault request") ||
        expect(wvm_local_memory_result_length_encode(
                   WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES,
                   length, error, sizeof(error)) == 0 &&
                   wvm_local_memory_result_length_decode(
                       length, &ack_payload_bytes, error, sizeof(error)) == 0 &&
                   ack_payload_bytes ==
                       WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES,
               "round trip typed local ACK length")) {
        return 1;
    }
    memset(&commit_request, 0, sizeof(commit_request));
    commit_request.operation_id[15] = 2;
    commit_request.delivery_attempt_id = 8;
    commit_request.flags = WVM_LOCAL_MEMORY_COMMIT_FLAG_SHARED_BACKING;
    commit_request.commit.gpa = 0x8000;
    commit_request.commit.base_version = 2;
    commit_request.commit.offset = 5;
    commit_request.commit.size = sizeof(commit_data);
    commit_request.commit.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    commit_request.commit.reply_destination_scope = 7;
    commit_request.commit.reply_destination_vnode = 2;
    commit_request.commit.reply_node_instance_id = 101;
    commit_request.commit.data = commit_data;
    commit_request.commit.data_bytes = sizeof(commit_data);
    if (expect(wvm_local_memory_commit_request_encode(
                   &commit_request, commit_encoded, sizeof(commit_encoded),
                   &commit_encoded_bytes, error, sizeof(error)) == 0 &&
                   wvm_local_memory_commit_request_decode(
                       commit_encoded, commit_encoded_bytes,
                       &decoded_commit_request, error, sizeof(error)) == 0 &&
                   memcmp(decoded_commit_request.operation_id,
                          commit_request.operation_id,
                          sizeof(commit_request.operation_id)) == 0 &&
                   decoded_commit_request.delivery_attempt_id ==
                       commit_request.delivery_attempt_id &&
                   decoded_commit_request.flags == commit_request.flags &&
                   decoded_commit_request.commit.gpa ==
                       commit_request.commit.gpa &&
                   decoded_commit_request.commit.base_version ==
                       commit_request.commit.base_version &&
                   decoded_commit_request.commit.offset ==
                       commit_request.commit.offset &&
                   decoded_commit_request.commit.size ==
                       commit_request.commit.size &&
                   memcmp(decoded_commit_request.commit.data, commit_data,
                          sizeof(commit_data)) == 0,
               "round trip typed local commit request")) {
        return 1;
    }
    memset(&commit_result, 0, sizeof(commit_result));
    memcpy(commit_result.operation_id, commit_request.operation_id,
           sizeof(commit_result.operation_id));
    commit_result.ack.gpa = commit_request.commit.gpa;
    commit_result.ack.result_version = 3;
    commit_result.ack.status = WVM_MEM_COMMIT_ACK_SUCCESS;
    commit_result.ack.directory_physical_node_id = 9;
    commit_result.ack.directory_node_instance_id = 10;
    if (expect(wvm_local_memory_commit_result_encode(
                   &commit_result, commit_result_encoded, error,
                   sizeof(error)) == 0 &&
                   wvm_local_memory_commit_result_decode(
                       commit_result_encoded, &decoded_commit_result, error,
                       sizeof(error)) == 0 &&
                   memcmp(decoded_commit_result.operation_id,
                          commit_result.operation_id,
                          sizeof(commit_result.operation_id)) == 0 &&
                   decoded_commit_result.ack.gpa == commit_result.ack.gpa &&
                   decoded_commit_result.ack.result_version == 3 &&
                   decoded_commit_result.ack.status ==
                       WVM_MEM_COMMIT_ACK_SUCCESS &&
                   decoded_commit_result.ack.directory_physical_node_id == 9 &&
                   decoded_commit_result.ack.directory_node_instance_id == 10,
               "round trip typed local commit result")) {
        return 1;
    }
    request.gpa++;
    if (expect(wvm_local_memory_fault_request_encode(
                   &request, encoded, error, sizeof(error)) != 0,
               "reject unaligned typed local fault") ||
        expect(wvm_local_memory_result_length_encode(
                   WVM_MEM_ACK_HEADER_BYTES + 1U, length, error,
                   sizeof(error)) != 0,
               "reject malformed local ACK length")) {
        return 1;
    }
    commit_request.commit.base_version = 0;
    if (expect(wvm_local_memory_commit_request_encode(
                   &commit_request, commit_encoded, sizeof(commit_encoded),
                   &commit_encoded_bytes, error, sizeof(error)) != 0,
               "reject a local commit without a base version")) {
        return 1;
    }
    puts("local-memory tests: PASS");
    return 0;
}

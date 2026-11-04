#include <stdio.h>
#include <string.h>

#include "wavevm_memory.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "memory test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_mem_read read;
    struct wvm_mem_read decoded_read;
    struct wvm_mem_ack ack;
    struct wvm_mem_ack decoded_ack;
    struct wvm_mem_commit commit;
    struct wvm_mem_commit decoded_commit;
    struct wvm_mem_commit_ack commit_ack;
    struct wvm_mem_commit_ack decoded_commit_ack;
    struct wvm_envelope request;
    struct wvm_envelope response;
    struct wvm_envelope_route resolved_reply_route;
    uint8_t read_bytes[WVM_MEM_READ_PAYLOAD_BYTES];
    uint8_t ack_bytes[WVM_MEM_ACK_HEADER_BYTES +
                      WVM_MEMORY_PAGE_BYTES];
    uint8_t commit_bytes[WVM_MEM_COMMIT_HEADER_BYTES + 64];
    uint8_t commit_ack_bytes[WVM_MEM_COMMIT_ACK_BYTES];
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint8_t frame[WVM_ENVELOPE_HEADER_BYTES +
                  WVM_ENVELOPE_ROUTE_PREFIX_BYTES +
                  WVM_MEM_ACK_HEADER_BYTES +
                  WVM_MEMORY_PAGE_BYTES];
    size_t ack_bytes_count = 0;
    size_t frame_bytes = 0;
    char error[256] = {0};
    size_t i;

    for (i = 0; i < sizeof(page); i++) {
        page[i] = (uint8_t)i;
    }
    memset(&read, 0, sizeof(read));
    read.gpa = 0x4000;
    read.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    read.reply_destination_vnode = 3;
    read.reply_node_instance_id = 101;
    if (expect(wvm_mem_read_encode(&read, read_bytes, error,
                                      sizeof(error)) == 0 &&
                   wvm_mem_read_decode(read_bytes, sizeof(read_bytes),
                                          &decoded_read, error,
                                          sizeof(error)) == 0 &&
                   decoded_read.gpa == read.gpa &&
                   decoded_read.reply_destination_kind ==
                       WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE &&
                   decoded_read.reply_destination_scope == 0 &&
                   decoded_read.reply_destination_vnode == 3 &&
                   decoded_read.reply_node_instance_id == 101,
               "round trip flat memory read reply route")) {
        return 1;
    }

    read.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    read.reply_destination_scope = 99;
    read.reply_destination_vnode = 7;
    if (expect(wvm_mem_read_encode(&read, read_bytes, error,
                                      sizeof(error)) == 0 &&
                   wvm_mem_read_decode(read_bytes, sizeof(read_bytes),
                                          &decoded_read, error,
                                          sizeof(error)) == 0 &&
                   decoded_read.reply_destination_scope == 99 &&
                   decoded_read.reply_destination_vnode == 7,
               "round trip fractal memory read reply route")) {
        return 1;
    }
    read.reply_destination_scope = 0;
    if (expect(wvm_mem_read_encode(&read, read_bytes, error,
                                      sizeof(error)) != 0,
               "reject fractal reply route without scope")) {
        return 1;
    }
    read.reply_destination_scope = 99;
    if (expect(wvm_mem_read_encode(&read, read_bytes, error,
                                      sizeof(error)) == 0,
               "restore fractal memory read") ||
        expect((read_bytes[10] = 1,
                wvm_mem_read_decode(read_bytes, sizeof(read_bytes),
                                       &decoded_read, error,
                                       sizeof(error)) != 0),
               "reject nonzero read reserved bytes")) {
        return 1;
    }
    read_bytes[10] = 0;

    memset(&ack, 0, sizeof(ack));
    ack.gpa = read.gpa;
    ack.version = 12;
    ack.status = WVM_MEM_ACK_SUCCESS;
    ack.directory_physical_node_id = 99;
    ack.directory_node_instance_id = 202;
    ack.data = page;
    ack.data_bytes = sizeof(page);
    if (expect(wvm_mem_ack_encode(&ack, ack_bytes, sizeof(ack_bytes),
                                     &ack_bytes_count, error,
                                     sizeof(error)) == 0 &&
                   ack_bytes_count == sizeof(ack_bytes) &&
                   wvm_mem_ack_decode(ack_bytes, ack_bytes_count,
                                         &decoded_ack, error,
                                         sizeof(error)) == 0 &&
                   decoded_ack.gpa == ack.gpa &&
                   decoded_ack.version == ack.version &&
                   decoded_ack.status == WVM_MEM_ACK_SUCCESS &&
                   decoded_ack.directory_physical_node_id == 99 &&
                   decoded_ack.directory_node_instance_id == 202 &&
                   decoded_ack.data_bytes == sizeof(page) &&
                   memcmp(decoded_ack.data, page, sizeof(page)) == 0 &&
                   wvm_memory_payload_validate(
                       WVM_ENVELOPE_MSG_MEM_ACK, ack_bytes,
                       ack_bytes_count, error, sizeof(error)) == 0,
               "round trip authoritative memory ACK")) {
        return 1;
    }

    memset(&request, 0, sizeof(request));
    request.message_type = WVM_ENVELOPE_MSG_MEM_READ;
    request.vm_id = 256;
    request.vm_incarnation = 7;
    request.manifest_generation = 3;
    request.origin_physical_node_id = 17;
    request.origin_runtime_instance_id = 1001;
    request.operation_id[15] = 9;
    request.delivery_attempt_id = 2;
    request.route_scope_id = 33;
    request.topology_revision = 11;
    request.route_generation = 4;
    memset(request.route_snapshot_digest, 0x8a,
           sizeof(request.route_snapshot_digest));
    request.route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    request.route.destination_scope = 99;
    request.route.destination_vnode_or_endpoint = 7;
    request.route.hop_limit = 8;
    request.payload = read_bytes;
    request.payload_bytes = sizeof(read_bytes);
    memset(&resolved_reply_route, 0, sizeof(resolved_reply_route));
    resolved_reply_route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    resolved_reply_route.destination_scope = 99;
    resolved_reply_route.destination_vnode_or_endpoint = 7;
    resolved_reply_route.hop_limit = 8;
    if (expect(wvm_mem_ack_envelope_build(
                   &request, &resolved_reply_route, 1, &ack, ack_bytes,
                   sizeof(ack_bytes), &ack_bytes_count, &response, error,
                   sizeof(error)) == 0 &&
                   response.message_type == WVM_ENVELOPE_MSG_MEM_ACK &&
                   response.vm_id == request.vm_id &&
                   response.vm_incarnation == request.vm_incarnation &&
                   response.origin_physical_node_id ==
                       request.origin_physical_node_id &&
                   response.origin_runtime_instance_id ==
                       request.origin_runtime_instance_id &&
                   memcmp(response.operation_id, request.operation_id,
                          sizeof(response.operation_id)) == 0 &&
                   response.delivery_attempt_id == 1 &&
                   response.route.destination_kind ==
                       WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE &&
                   response.route.destination_scope == 99 &&
                   response.route.destination_vnode_or_endpoint == 7 &&
                   response.route.hop_count == 0 &&
                   wvm_envelope_encode(
                       &response, WVM_ENVELOPE_TRANSPORT_LOCAL, frame,
                       sizeof(frame), &frame_bytes, error, sizeof(error)) == 0,
               "build ACK with the original operation key and resolved route")) {
        return 1;
    }
    resolved_reply_route.destination_scope = 0;
    if (expect(wvm_mem_ack_envelope_build(
                   &request, &resolved_reply_route, 1, &ack, ack_bytes,
                   sizeof(ack_bytes), &ack_bytes_count, &response, error,
                   sizeof(error)) != 0,
               "reject ACK route that was not snapshot-resolved from read")) {
        return 1;
    }

    ack.status = WVM_MEM_ACK_STALE;
    ack.version = 0;
    ack.data = NULL;
    ack.data_bytes = 0;
    if (expect(wvm_mem_ack_encode(&ack, ack_bytes, sizeof(ack_bytes),
                                     &ack_bytes_count, error,
                                     sizeof(error)) == 0 &&
                   ack_bytes_count == WVM_MEM_ACK_HEADER_BYTES &&
                   wvm_mem_ack_decode(ack_bytes, ack_bytes_count,
                                         &decoded_ack, error,
                                         sizeof(error)) == 0 &&
                   decoded_ack.status == WVM_MEM_ACK_STALE &&
                   decoded_ack.directory_physical_node_id == 99 &&
                   decoded_ack.directory_node_instance_id == 202 &&
                   decoded_ack.data == NULL,
               "round trip terminal memory ACK")) {
        return 1;
    }
    ack.data = page;
    ack.data_bytes = sizeof(page);
    if (expect(wvm_mem_ack_encode(&ack, ack_bytes, sizeof(ack_bytes),
                                     &ack_bytes_count, error,
                                     sizeof(error)) != 0,
               "reject page data on terminal memory ACK")) {
        return 1;
    }

    memset(&commit, 0, sizeof(commit));
    commit.gpa = read.gpa;
    commit.base_version = 12;
    commit.offset = 7;
    commit.size = 64;
    commit.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    commit.reply_destination_scope = 99;
    commit.reply_destination_vnode = 7;
    commit.reply_node_instance_id = 101;
    commit.data = page;
    commit.data_bytes = commit.size;
    if (expect(wvm_mem_commit_encode(
                   &commit, commit_bytes, sizeof(commit_bytes),
                   &ack_bytes_count, error, sizeof(error)) == 0 &&
                   ack_bytes_count == sizeof(commit_bytes) &&
                   wvm_mem_commit_decode(
                       commit_bytes, ack_bytes_count, &decoded_commit, error,
                       sizeof(error)) == 0 &&
                   decoded_commit.gpa == commit.gpa &&
                   decoded_commit.base_version == commit.base_version &&
                   decoded_commit.offset == commit.offset &&
                   decoded_commit.size == commit.size &&
                   decoded_commit.reply_destination_scope == 99 &&
                   decoded_commit.reply_node_instance_id == 101 &&
                   decoded_commit.data_bytes == commit.size &&
                   memcmp(decoded_commit.data, page, commit.size) == 0 &&
                   wvm_memory_payload_validate(
                       WVM_ENVELOPE_MSG_COMMIT_DIFF, commit_bytes,
                       ack_bytes_count, error, sizeof(error)) == 0,
               "round trip versioned V1 memory commit")) {
        return 1;
    }
    commit_bytes[22] = 1;
    if (expect(wvm_mem_commit_decode(
                   commit_bytes, sizeof(commit_bytes), &decoded_commit, error,
                   sizeof(error)) != 0,
               "reject nonzero commit reserved bytes")) {
        return 1;
    }
    commit_bytes[22] = 0;

    memset(&commit_ack, 0, sizeof(commit_ack));
    commit_ack.gpa = commit.gpa;
    commit_ack.result_version = 13;
    commit_ack.status = WVM_MEM_COMMIT_ACK_SUCCESS;
    commit_ack.directory_physical_node_id = 99;
    commit_ack.directory_node_instance_id = 202;
    if (expect(wvm_mem_commit_ack_encode(
                   &commit_ack, commit_ack_bytes, error, sizeof(error)) == 0 &&
                   wvm_mem_commit_ack_decode(
                       commit_ack_bytes, &decoded_commit_ack, error,
                       sizeof(error)) == 0 &&
                   decoded_commit_ack.gpa == commit.gpa &&
                   decoded_commit_ack.result_version == 13 &&
                   decoded_commit_ack.status ==
                       WVM_MEM_COMMIT_ACK_SUCCESS &&
                   wvm_memory_payload_validate(
                       WVM_ENVELOPE_MSG_MEM_COMMIT_ACK, commit_ack_bytes,
                       sizeof(commit_ack_bytes), error, sizeof(error)) == 0,
               "round trip typed V1 commit completion")) {
        return 1;
    }

    request.message_type = WVM_ENVELOPE_MSG_COMMIT_DIFF;
    request.payload = commit_bytes;
    request.payload_bytes = sizeof(commit_bytes);
    memset(&resolved_reply_route, 0, sizeof(resolved_reply_route));
    resolved_reply_route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    resolved_reply_route.destination_scope = 99;
    resolved_reply_route.destination_vnode_or_endpoint = 7;
    resolved_reply_route.hop_limit = 8;
    if (expect(wvm_mem_commit_ack_envelope_build(
                   &request, &resolved_reply_route, 3, &commit_ack,
                   commit_ack_bytes, &response, error, sizeof(error)) == 0 &&
                   response.message_type ==
                       WVM_ENVELOPE_MSG_MEM_COMMIT_ACK &&
                   response.payload_bytes == sizeof(commit_ack_bytes) &&
                   memcmp(response.operation_id, request.operation_id,
                          sizeof(response.operation_id)) == 0 &&
                   response.delivery_attempt_id == 3 &&
                   wvm_envelope_encode(
                       &response, WVM_ENVELOPE_TRANSPORT_LOCAL, frame,
                       sizeof(frame), &frame_bytes, error, sizeof(error)) == 0,
               "build commit ACK with original operation identity")) {
        return 1;
    }

    puts("memory tests: PASS");
    return 0;
}

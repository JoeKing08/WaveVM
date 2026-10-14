#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_control.h"
#include "wavevm_envelope.h"
#include "wavevm_manifest.h"
#include "wavevm_membership_control.h"
#include "wavevm_membership_controller.h"

#include "../../ctl_tool/gateway_drain_successor.h"

#define REQUEST_BYTES 65536U
#define RESPONSE_BYTES \
    (WVM_ENVELOPE_HEADER_BYTES + WVM_MEMBERSHIP_CONTROL_RESULT_BYTES)

/*
 * EXECUTOR DRAIN PREPARE (0x0103): builds one-scope successor via
 * wvm_ctl_gateway_drain_successor_build from membership journal facts, then
 * submits complete GatewayDrainRequest. Caller names departing + successor
 * gateways; builder fails closed rather than inventing topology/members.
 *
 * usage: submit_gateway_drain_prepare SOCKET JOURNAL_SNAP \
 *         DEPART_GW_ID DEPART_INST SUCC_GW_ID SUCC_INST
 */

static int write_full(int fd, const uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t written = write(fd, bytes + offset, byte_count - offset);

        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int read_full(int fd, uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t received = read(fd, bytes + offset, byte_count - offset);

        if (received > 0) {
            offset += (size_t)received;
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static void write_be32(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static uint32_t read_be32(const uint8_t bytes[4])
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static int parse_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (!text || !out) {
        return -1;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0') {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[16];
    struct wvm_membership_controller_route_entry routes[8];
    struct wvm_membership_dependency dependencies[16];
    struct wvm_ctl_gateway_drain_successor successor;
    struct wvm_gateway_drain_request request;
    struct wvm_member_key departing_key;
    struct wvm_member_key successor_key;
    struct wvm_envelope envelope;
    struct wvm_envelope response;
    struct wvm_membership_control_result result;
    struct sockaddr_un address;
    uint8_t payload[REQUEST_BYTES];
    uint8_t request_frame[WVM_ENVELOPE_HEADER_BYTES + REQUEST_BYTES];
    uint8_t response_frame[RESPONSE_BYTES];
    uint8_t prefix[4];
    uint8_t response_prefix[4];
    size_t payload_bytes = 0;
    size_t request_frame_bytes = 0;
    uint32_t response_bytes;
    uint64_t depart_id, depart_inst, succ_id, succ_inst;
    char error[256] = {0};
    size_t path_bytes;
    size_t i;
    int fd = -1;

    if (argc != 7) {
        fprintf(stderr,
                "usage: %s SOCKET JOURNAL DEPART_GW DEPART_INST SUCC_GW "
                "SUCC_INST\n",
                argv[0]);
        return 2;
    }
    if (parse_u64(argv[3], &depart_id) != 0 ||
        parse_u64(argv[4], &depart_inst) != 0 ||
        parse_u64(argv[5], &succ_id) != 0 ||
        parse_u64(argv[6], &succ_inst) != 0) {
        fprintf(stderr, "invalid numeric argument\n");
        return 2;
    }

    wvm_membership_controller_init(&controller, members, 16, routes, 8,
                                   dependencies, 16, NULL, NULL);
    if (wvm_membership_controller_open(&controller, argv[2], error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "journal open: %s\n", error);
        return 1;
    }

    memset(&departing_key, 0, sizeof(departing_key));
    departing_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    departing_key.role_id = (uint32_t)depart_id;
    departing_key.instance_id = depart_inst;
    memset(&successor_key, 0, sizeof(successor_key));
    successor_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    successor_key.role_id = (uint32_t)succ_id;
    successor_key.instance_id = succ_inst;

    if (wvm_ctl_gateway_drain_successor_build(&successor, &controller,
                                              &departing_key, &successor_key,
                                              error, sizeof(error)) != 0) {
        fprintf(stderr, "successor build failed: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }

    memset(&request, 0, sizeof(request));
    request.action = WVM_GATEWAY_DRAIN_ACTION_PREPARE;
    request.target_gateway_member_key = departing_key;
    request.expected_membership_revision = controller.membership_revision;
    request.expected_topology_revision = controller.topology_revision;
    request.expected_admission_eligibility_revision =
        controller.admission_eligibility_revision;
    request.successor_transaction = successor.transaction;
    request.successor_snapshot = successor.snapshot;
    memcpy(request.route_operation_id, successor.transaction.operation_id,
           sizeof(request.route_operation_id));
    wvm_membership_controller_close(&controller);

    if (wvm_gateway_drain_request_encode(&request, payload, sizeof(payload),
                                         &payload_bytes, error,
                                         sizeof(error)) != 0) {
        fprintf(stderr, "encode: %s\n", error);
        return 1;
    }

    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = WVM_ENVELOPE_MSG_DRAIN;
    envelope.origin_physical_node_id = 9001;
    envelope.origin_runtime_instance_id = 9002;
    memcpy(envelope.operation_id, request.route_operation_id,
           sizeof(envelope.operation_id));
    envelope.delivery_attempt_id = 1;
    envelope.payload = payload;
    envelope.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 envelope.semantic_payload_digest);
    if (wvm_envelope_encode(&envelope, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            request_frame, sizeof(request_frame),
                            &request_frame_bytes, error, sizeof(error)) != 0) {
        fprintf(stderr, "encode envelope: %s\n", error);
        return 1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    path_bytes = strlen(argv[1]);
    if (fd < 0 || path_bytes + 1U > sizeof(address.sun_path)) {
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, argv[1], path_bytes + 1U);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_bytes + 1U)) != 0) {
        close(fd);
        return 1;
    }
    write_be32(prefix, (uint32_t)request_frame_bytes);
    if (write_full(fd, prefix, sizeof(prefix)) != 0 ||
        write_full(fd, request_frame, request_frame_bytes) != 0 ||
        read_full(fd, response_prefix, sizeof(response_prefix)) != 0) {
        close(fd);
        return 1;
    }
    response_bytes = read_be32(response_prefix);
    if (response_bytes < WVM_ENVELOPE_HEADER_BYTES ||
        response_bytes > sizeof(response_frame) ||
        read_full(fd, response_frame, response_bytes) != 0 ||
        wvm_envelope_decode(response_frame, response_bytes,
                            WVM_ENVELOPE_TRANSPORT_LOCAL, &response, error,
                            sizeof(error)) != 0 ||
        response.message_type != WVM_ENVELOPE_MSG_CTRL_RESULT ||
        response.payload_bytes != WVM_MEMBERSHIP_CONTROL_RESULT_BYTES ||
        wvm_membership_control_result_decode(response.payload, &result) != 0) {
        close(fd);
        return 1;
    }
    close(fd);
    printf("status=%u recorded_state=%u applied_revision=%llu op=",
           (unsigned)result.status_code, (unsigned)result.recorded_state,
           (unsigned long long)result.applied_revision);
    for (i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
        printf("%02x", request.route_operation_id[i]);
    }
    printf("\n");
    return result.status_code == WVM_MEMBERSHIP_CONTROL_SUCCESS ? 0 : 1;
}

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_control_transport.h"
#include "wavevm_envelope.h"
#include "wavevm_manifest.h"

#define REQUEST_BYTES 16384U
#define RESPONSE_BYTES (WVM_ENVELOPE_HEADER_BYTES + WVM_CONTROL_RESULT_BYTES)

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

int main(int argc, char **argv)
{
    struct wvm_vm_request request;
    struct wvm_envelope envelope;
    struct wvm_envelope response;
    struct wvm_control_result result;
    struct sockaddr_un address;
    uint8_t request_id[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t request_payload[REQUEST_BYTES];
    uint8_t request_frame[WVM_ENVELOPE_HEADER_BYTES + REQUEST_BYTES];
    uint8_t response_frame[RESPONSE_BYTES];
    uint8_t prefix[4];
    uint8_t response_prefix[4];
    size_t request_payload_bytes = 0;
    size_t request_frame_bytes = 0;
    uint32_t response_bytes;
    char error[256] = {0};
    size_t path_bytes;
    int fd = -1;
    int status = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s SOCKET\n", argv[0]);
        return 2;
    }
    request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x71;
    operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x72;
    memset(&request, 0, sizeof(request));
    request.api_version = WVM_CANONICAL_SCHEMA;
    memcpy(request.request_id, request_id, sizeof(request.request_id));
    request.has_display_name = 1;
    snprintf(request.display_name, sizeof(request.display_name), "%s",
             "single-node-create");
    request.requested_vcpus = 1;
    request.requested_memory_bytes = 16ULL * 1024ULL * 1024ULL;
    request.execution_backend_policy = WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG;
    request.accelerator_policy = WVM_MANIFEST_ACCELERATOR_DISABLED;
    request.placement_policy = WVM_MANIFEST_PLACEMENT_COMPACT;
    request.guest_topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
    request.consistency_policy.dirty_batch_size = 1;
    request.consistency_policy.handoff_commit_policy = 1;
    request.consistency_policy.subscriber_delivery_policy = 1;
    request.consistency_policy.max_commit_latency_ms = 1000;
    memset(request.storage_device_plan.qemu_device_configuration_digest, 0x41,
           sizeof(request.storage_device_plan.qemu_device_configuration_digest));
    request.lifecycle_policy.start_policy = 1;
    request.lifecycle_policy.failure_policy = 1;
    request.lifecycle_policy.completion_query_horizon_ms = 1000;
    request.lifecycle_policy.route_retention_horizon_ms = 1000;

    if (wvm_vm_request_encode(&request, request_payload, sizeof(request_payload),
                              &request_payload_bytes, error,
                              sizeof(error)) != 0) {
        fprintf(stderr, "submit CREATE_VM: encode request: %s\n", error);
        return 1;
    }
    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = WVM_ENVELOPE_MSG_CREATE_VM;
    envelope.origin_physical_node_id = 9001;
    envelope.origin_runtime_instance_id = 9002;
    memcpy(envelope.operation_id, operation_id, sizeof(envelope.operation_id));
    envelope.delivery_attempt_id = 1;
    envelope.payload = request_payload;
    envelope.payload_bytes = request_payload_bytes;
    if (wvm_envelope_encode(&envelope, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            request_frame, sizeof(request_frame),
                            &request_frame_bytes, error, sizeof(error)) != 0 ||
        request_frame_bytes > UINT32_MAX) {
        fprintf(stderr, "submit CREATE_VM: encode envelope: %s\n", error);
        return 1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    path_bytes = strlen(argv[1]);
    if (fd < 0 || path_bytes + 1U > sizeof(address.sun_path)) {
        fprintf(stderr, "submit CREATE_VM: cannot open socket\n");
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, argv[1], path_bytes + 1U);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_bytes + 1U)) != 0) {
        fprintf(stderr, "submit CREATE_VM: connect failed\n");
        close(fd);
        return 1;
    }
    write_be32(prefix, (uint32_t)request_frame_bytes);
    if (write_full(fd, prefix, sizeof(prefix)) != 0 ||
        write_full(fd, request_frame, request_frame_bytes) != 0 ||
        read_full(fd, response_prefix, sizeof(response_prefix)) != 0) {
        fprintf(stderr, "submit CREATE_VM: transport failed\n");
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
        response.payload_bytes != WVM_CONTROL_RESULT_BYTES ||
        wvm_control_result_decode(response.payload, &result) != 0) {
        fprintf(stderr, "submit CREATE_VM: decode result: %s\n", error);
        close(fd);
        return 1;
    }
    close(fd);
    printf("status=%u recorded_state=%u vm_id=%u vm_incarnation=%llu "
           "manifest_generation=%llu route_scope_id=%llu\n",
           result.status_code, result.recorded_state, result.vm_id,
           (unsigned long long)result.vm_incarnation,
           (unsigned long long)result.manifest_generation,
           (unsigned long long)result.route_scope_id);
    /*
     * SUCCESS (RUNNING) or IN_PROGRESS (COMMITTED, waiting for live ready)
     * both prove prepare→activate→commit without forging readiness.
     */
    if (result.status_code == WVM_CONTROL_RESULT_SUCCESS ||
        result.status_code == WVM_CONTROL_RESULT_IN_PROGRESS) {
        status = 0;
    }
    return status;
}

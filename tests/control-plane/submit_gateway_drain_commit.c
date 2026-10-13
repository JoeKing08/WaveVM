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

#define REQUEST_BYTES 2048U
#define RESPONSE_BYTES \
    (WVM_ENVELOPE_HEADER_BYTES + WVM_MEMBERSHIP_CONTROL_RESULT_BYTES)

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

/*
 * Submits DRAIN (0x0103) action=COMMIT with no prior PREPARE / no successor.
 * Spec requires PREPARE+successor before COMMIT; this proves the production
 * receiver fail-closes rather than inventing an idle-drain path.
 *
 * usage: submit_gateway_drain_commit SOCKET GATEWAY_ID INSTANCE
 *         MEM_REV TOPO_REV ELIG_REV
 */
int main(int argc, char **argv)
{
    struct wvm_gateway_drain_request request;
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
    uint64_t gateway_id;
    uint64_t instance_id;
    char error[256] = {0};
    size_t path_bytes;
    int fd = -1;

    if (argc != 7 && argc != 8) {
        fprintf(stderr,
                "usage: %s SOCKET GATEWAY_ID INSTANCE MEM TOPO ELIG [OP_HEX]\n",
                argv[0]);
        return 2;
    }
    memset(&request, 0, sizeof(request));
    if (parse_u64(argv[2], &gateway_id) != 0 ||
        parse_u64(argv[3], &instance_id) != 0 ||
        parse_u64(argv[4], &request.expected_membership_revision) != 0 ||
        parse_u64(argv[5], &request.expected_topology_revision) != 0 ||
        parse_u64(argv[6],
                  &request.expected_admission_eligibility_revision) != 0) {
        fprintf(stderr, "invalid numeric argument\n");
        return 2;
    }
    request.action = WVM_GATEWAY_DRAIN_ACTION_COMMIT;
    request.target_gateway_member_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    request.target_gateway_member_key.role_id = (uint32_t)gateway_id;
    request.target_gateway_member_key.instance_id = instance_id;
    if (argc == 8) {
        const char *hex = argv[7];
        size_t i;

        if (strlen(hex) != WVM_IDENTITY_ID_BYTES * 2U) {
            fprintf(stderr, "OP_HEX must be %u hex bytes\n",
                    (unsigned)WVM_IDENTITY_ID_BYTES);
            return 2;
        }
        for (i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
            unsigned value = 0;

            if (sscanf(hex + (i * 2U), "%2x", &value) != 1) {
                fprintf(stderr, "invalid OP_HEX\n");
                return 2;
            }
            request.route_operation_id[i] = (uint8_t)value;
        }
    } else {
        /* Fail-closed fixture without prior PREPARE: unmatched operation id. */
        request.route_operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0xdf;
        request.route_operation_id[WVM_IDENTITY_ID_BYTES - 2] =
            (uint8_t)(gateway_id & 0xffU);
    }

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
    /* Envelope operation ID must differ from PREPARE; route_operation_id in
     * the GatewayDrainRequest payload still names the successor transaction. */
    memcpy(envelope.operation_id, request.route_operation_id,
           sizeof(envelope.operation_id));
    envelope.operation_id[WVM_IDENTITY_ID_BYTES - 1] ^= 0xa5U;
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
    printf("status=%u recorded_state=%u applied_revision=%llu\n",
           (unsigned)result.status_code, (unsigned)result.recorded_state,
           (unsigned long long)result.applied_revision);
    return result.status_code == WVM_MEMBERSHIP_CONTROL_SUCCESS ? 0 : 1;
}

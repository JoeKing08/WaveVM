#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_control_transport.h"
#include "wavevm_envelope.h"

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

/*
 * Usage: submit_stop_vm SOCKET VM_ID VM_INCARNATION MANIFEST_GENERATION
 *        [id_byte=hex]
 */
int main(int argc, char **argv)
{
    struct wvm_envelope envelope;
    struct wvm_envelope response;
    struct wvm_control_result result;
    struct sockaddr_un address;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t request_frame[WVM_ENVELOPE_HEADER_BYTES];
    uint8_t response_frame[RESPONSE_BYTES];
    uint8_t prefix[4];
    uint8_t response_prefix[4];
    size_t request_frame_bytes = 0;
    uint32_t response_bytes;
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    unsigned int id_byte = 0x71;
    char error[256] = {0};
    char *end = NULL;
    int fd;
    size_t path_bytes;

    if (argc < 5 || argc > 6) {
        fprintf(stderr,
                "usage: %s SOCKET VM_ID VM_INCARNATION MANIFEST_GENERATION "
                "[id_byte]\n",
                argv[0]);
        return 1;
    }
    vm_id = (uint32_t)strtoul(argv[2], &end, 10);
    if (!end || *end != '\0' || vm_id == 0) {
        fprintf(stderr, "submit STOP_VM: invalid vm_id\n");
        return 1;
    }
    vm_incarnation = strtoull(argv[3], &end, 10);
    if (!end || *end != '\0' || vm_incarnation == 0) {
        fprintf(stderr, "submit STOP_VM: invalid vm_incarnation\n");
        return 1;
    }
    manifest_generation = strtoull(argv[4], &end, 10);
    if (!end || *end != '\0' || manifest_generation == 0) {
        fprintf(stderr, "submit STOP_VM: invalid manifest_generation\n");
        return 1;
    }
    if (argc == 6) {
        id_byte = (unsigned int)strtoul(argv[5], &end, 16);
        if (!end || *end != '\0' || id_byte == 0 || id_byte > 0xff) {
            fprintf(stderr, "submit STOP_VM: id_byte must be 1..ff hex\n");
            return 1;
        }
    }
    memset(operation_id, (uint8_t)id_byte, sizeof(operation_id));
    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = WVM_ENVELOPE_MSG_STOP_VM;
    envelope.vm_id = vm_id;
    envelope.vm_incarnation = vm_incarnation;
    envelope.manifest_generation = manifest_generation;
    envelope.origin_physical_node_id = 9001;
    envelope.origin_runtime_instance_id = 9002;
    memcpy(envelope.operation_id, operation_id, sizeof(envelope.operation_id));
    envelope.delivery_attempt_id = 1;
    if (wvm_envelope_encode(&envelope, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            request_frame, sizeof(request_frame),
                            &request_frame_bytes, error, sizeof(error)) != 0) {
        fprintf(stderr, "submit STOP_VM: encode envelope: %s\n", error);
        return 1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    path_bytes = strlen(argv[1]);
    if (fd < 0 || path_bytes + 1U > sizeof(address.sun_path)) {
        fprintf(stderr, "submit STOP_VM: cannot open socket\n");
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, argv[1], path_bytes + 1U);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_bytes + 1U)) != 0) {
        fprintf(stderr, "submit STOP_VM: connect failed\n");
        close(fd);
        return 1;
    }
    write_be32(prefix, (uint32_t)request_frame_bytes);
    if (write_full(fd, prefix, sizeof(prefix)) != 0 ||
        write_full(fd, request_frame, request_frame_bytes) != 0 ||
        read_full(fd, response_prefix, sizeof(response_prefix)) != 0) {
        fprintf(stderr, "submit STOP_VM: transport failed\n");
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
        fprintf(stderr, "submit STOP_VM: decode result: %s\n", error);
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
    return 0;
}

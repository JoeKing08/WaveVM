#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_control_transport.h"
#include "wavevm_envelope.h"
#include "wavevm_lifecycle.h"
#include "wavevm_manifest.h"

#define REQUEST_BYTES 16384U
#define RESPONSE_BYTES (WVM_ENVELOPE_HEADER_BYTES + WVM_CONTROL_RESULT_BYTES)

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "ctl CREATE_VM test: %s\n", message);
        return -1;
    }
    return 0;
}

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

static int wait_for_socket(const char *path, int present)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000L};
    struct stat status;
    int attempt;

    for (attempt = 0; attempt < 500; attempt++) {
        int exists = stat(path, &status) == 0;

        if (exists == present) {
            return 0;
        }
        nanosleep(&delay, NULL);
    }
    return -1;
}

static int connect_socket(const char *path)
{
    struct sockaddr_un address;
    size_t path_bytes;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    path_bytes = strlen(path);
    if (path_bytes + 1U > sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, path_bytes + 1U);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_bytes + 1U)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void fill_request(struct wvm_vm_request *request,
                         const uint8_t request_id[WVM_IDENTITY_ID_BYTES],
                         uint32_t requested_vcpus)
{
    memset(request, 0, sizeof(*request));
    request->api_version = WVM_CANONICAL_SCHEMA;
    memcpy(request->request_id, request_id, sizeof(request->request_id));
    request->has_display_name = 1;
    snprintf(request->display_name, sizeof(request->display_name),
             "create-vm-test-%u", requested_vcpus);
    request->requested_vcpus = requested_vcpus;
    request->requested_memory_bytes = 4096;
    request->execution_backend_policy = WVM_MANIFEST_BACKEND_POLICY_AUTO;
    request->accelerator_policy = WVM_MANIFEST_ACCELERATOR_DISABLED;
    request->placement_policy = WVM_MANIFEST_PLACEMENT_COMPACT;
    request->guest_topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
    request->consistency_policy.dirty_batch_size = 1;
    request->consistency_policy.handoff_commit_policy = 1;
    request->consistency_policy.subscriber_delivery_policy = 1;
    request->consistency_policy.max_commit_latency_ms = 1000;
    memset(request->storage_device_plan.qemu_device_configuration_digest, 0x41,
           sizeof(request->storage_device_plan.qemu_device_configuration_digest));
    request->lifecycle_policy.start_policy = 1;
    request->lifecycle_policy.failure_policy = 1;
    request->lifecycle_policy.completion_query_horizon_ms = 1000;
    request->lifecycle_policy.route_retention_horizon_ms = 1000;
}

static int exchange_create_vm(
    const char *socket_path, const struct wvm_vm_request *request,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    struct wvm_control_result *result)
{
    struct wvm_envelope envelope;
    struct wvm_envelope response;
    uint8_t request_payload[REQUEST_BYTES];
    uint8_t request_frame[WVM_ENVELOPE_HEADER_BYTES + REQUEST_BYTES];
    uint8_t response_frame[RESPONSE_BYTES];
    uint8_t prefix[4];
    uint8_t response_prefix[4];
    size_t request_payload_bytes = 0;
    size_t request_frame_bytes = 0;
    uint32_t response_bytes;
    char error[256] = {0};
    int fd = -1;
    int status = -1;

    if (wvm_vm_request_encode(request, request_payload,
                              sizeof(request_payload), &request_payload_bytes,
                              error, sizeof(error)) != 0) {
        fprintf(stderr, "ctl CREATE_VM test: request encode: %s\n", error);
        return -1;
    }
    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = WVM_ENVELOPE_MSG_CREATE_VM;
    envelope.origin_physical_node_id = 17;
    envelope.origin_runtime_instance_id = 101;
    memcpy(envelope.operation_id, operation_id, sizeof(envelope.operation_id));
    envelope.delivery_attempt_id = 1;
    envelope.payload = request_payload;
    envelope.payload_bytes = request_payload_bytes;
    if (wvm_envelope_encode(&envelope, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            request_frame, sizeof(request_frame),
                            &request_frame_bytes, error, sizeof(error)) != 0 ||
        request_frame_bytes > UINT32_MAX) {
        fprintf(stderr, "ctl CREATE_VM test: envelope encode: %s\n", error);
        return -1;
    }
    fd = connect_socket(socket_path);
    if (fd < 0) {
        return -1;
    }
    write_be32(prefix, (uint32_t)request_frame_bytes);
    if (write_full(fd, prefix, sizeof(prefix)) != 0 ||
        write_full(fd, request_frame, request_frame_bytes) != 0 ||
        read_full(fd, response_prefix, sizeof(response_prefix)) != 0) {
        goto out;
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
        wvm_control_result_decode(response.payload, result) != 0 ||
        memcmp(result->in_reply_to_operation_id, operation_id,
               sizeof(result->in_reply_to_operation_id)) != 0) {
        goto out;
    }
    status = 0;
out:
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return status;
}

static pid_t start_daemon(const char *ctl_path, const char *state_directory,
                          const char *socket_path, const char *principal_path)
{
    pid_t child = fork();

    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        execl(ctl_path, ctl_path, "serve", "--state-dir", state_directory,
              "--socket", socket_path, "--local-node-id", "17",
              "--local-instance-id", "101", "--principals", principal_path,
              "--capacity", "8", (char *)NULL);
        _exit(127);
    }
    return child;
}

static int stop_daemon(pid_t child)
{
    int status;

    if (child <= 0 || kill(child, SIGTERM) != 0 ||
        waitpid(child, &status, 0) != child) {
        return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    char state_template[] = "/tmp/wavevm-create-state-XXXXXX";
    char principal_path[128];
    char socket_path[128];
    struct wvm_vm_request request;
    struct wvm_vm_request conflicting_request;
    struct wvm_control_result first_result;
    struct wvm_control_result replay_result;
    struct wvm_control_result conflict_result;
    uint8_t request_id[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t conflict_operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    pid_t child = -1;
    int state_fd = -1;
    FILE *principal = NULL;
    int result = 1;

    memset(&first_result, 0, sizeof(first_result));
    memset(&replay_result, 0, sizeof(replay_result));
    memset(&conflict_result, 0, sizeof(conflict_result));

    if (argc != 2) {
        fprintf(stderr, "usage: %s PATH_TO_WVM_CTL\n", argv[0]);
        return 2;
    }
    state_fd = mkstemp(state_template);
    if (state_fd < 0 || close(state_fd) != 0 || unlink(state_template) != 0 ||
        mkdir(state_template, S_IRWXU) != 0) {
        goto out;
    }
    snprintf(principal_path, sizeof(principal_path), "%s/principals",
             state_template);
    snprintf(socket_path, sizeof(socket_path), "/tmp/wavevm-create-%ld.sock",
             (long)getpid());
    unlink(socket_path);
    principal = fopen(principal_path, "w");
    if (!principal ||
        fprintf(principal, "%lu executor 9001 9002\n",
                (unsigned long)getuid()) < 0 || fclose(principal) != 0) {
        principal = NULL;
        goto out;
    }
    principal = NULL;
    request_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
    operation_id[WVM_IDENTITY_ID_BYTES - 1] = 2;
    conflict_operation_id[WVM_IDENTITY_ID_BYTES - 1] = 3;
    fill_request(&request, request_id, 1);
    child = start_daemon(argv[1], state_template, socket_path, principal_path);
    if (expect(child > 0 && wait_for_socket(socket_path, 1) == 0,
               "start control daemon") != 0 ||
        expect(exchange_create_vm(socket_path, &request, operation_id,
                                   &first_result) == 0,
               "apply first CREATE_VM") != 0 ||
        expect(first_result.status_code ==
                   WVM_CONTROL_RESULT_PRECONDITION_FAILED &&
                   first_result.vm_id == 0 &&
                   first_result.vm_incarnation == 0 &&
                   first_result.manifest_generation == 0 &&
                   first_result.route_scope_id == 0,
               "fail closed without published admission evidence and plans") != 0 ||
        expect(exchange_create_vm(socket_path, &request, operation_id,
                                   &replay_result) == 0 &&
                   memcmp(&first_result, &replay_result,
                          sizeof(first_result)) == 0,
               "replay identical rejected CREATE_VM result") != 0) {
        goto out;
    }
    fill_request(&conflicting_request, request_id, 2);
    expect(exchange_create_vm(socket_path, &conflicting_request,
                              conflict_operation_id, &conflict_result) == 0 &&
                   conflict_result.status_code ==
                       WVM_CONTROL_RESULT_OPERATION_ID_CONFLICT,
               "reject request-id semantic conflict");
    if (conflict_result.status_code != WVM_CONTROL_RESULT_OPERATION_ID_CONFLICT) {
        goto out;
    }
    if (stop_daemon(child) != 0 || wait_for_socket(socket_path, 0) != 0) {
        child = -1;
        goto out;
    }
    child = -1;
    child = start_daemon(argv[1], state_template, socket_path, principal_path);
    if (expect(child > 0 && wait_for_socket(socket_path, 1) == 0,
               "restart control daemon") != 0 ||
        expect(exchange_create_vm(socket_path, &request, operation_id,
                                   &replay_result) == 0 &&
                   memcmp(&first_result, &replay_result,
                          sizeof(first_result)) == 0,
               "replay CREATE_VM after daemon restart") != 0) {
        goto out;
    }
    result = 0;

out:
    if (principal) {
        fclose(principal);
    }
    if (child > 0) {
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
    }
    unlink(socket_path);
    unlink(principal_path);
    unlink(state_template);
    rmdir(state_template);
    return result;
}

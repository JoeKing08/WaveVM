#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_membership_control.h"
#include "wavevm_control_transport.h"

#define MIB (1024ULL * 1024ULL)

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "ctl-service test: %s\n", message);
        return -1;
    }
    return 0;
}

static void sleep_ms(long milliseconds)
{
    struct timespec delay;

    delay.tv_sec = milliseconds / 1000;
    delay.tv_nsec = (milliseconds % 1000) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static int wait_for_path(const char *path, int expected_present)
{
    unsigned int attempt;

    for (attempt = 0; attempt < 200; attempt++) {
        if ((access(path, F_OK) == 0) == expected_present) {
            return 0;
        }
        sleep_ms(5);
    }
    return -1;
}

static int wait_for_exit(pid_t child)
{
    unsigned int attempt;
    int status;

    for (attempt = 0; attempt < 200; attempt++) {
        if (waitpid(child, &status, WNOHANG) == child) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
        }
        sleep_ms(5);
    }
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
    return -1;
}

static pid_t start_service(const char *program, const char *state_directory,
                           const char *socket_path, const char *principal_file)
{
    pid_t child = fork();

    if (child != 0) {
        return child;
    }
    execl(program, program, "serve", "--state-dir", state_directory,
          "--socket", socket_path, "--local-node-id", "900",
          "--local-instance-id", "901", "--principals", principal_file,
          "--capacity", "8", (char *)NULL);
    _exit(127);
}

static int check_pending_membership(const char *journal_path)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[8];
    struct wvm_membership_controller_route_entry routes[8];
    struct wvm_membership_dependency dependencies[8];
    char error[256] = {0};
    int result = -1;

    wvm_membership_controller_init(&controller, members, 8, routes, 8,
                                    dependencies, 8, NULL, NULL);
    if (expect(wvm_membership_controller_open(&controller, journal_path,
                                              error, sizeof(error)) == 0,
               "reopen persisted membership") != 0) {
        goto out;
    }
    if (expect(controller.member_count == 1 && controller.route_count == 0,
               "persist only the registered member, without invented routes") != 0) {
        goto out;
    }
    result = expect(
        members[0].kind == WVM_MEMBERSHIP_COMPUTE &&
            members[0].member_key.role_id == 17 &&
            members[0].member_key.instance_id == 101 &&
            members[0].node.desired_membership_state == WVM_MANIFEST_MEMBER_PENDING &&
            members[0].node.observed_health_state == WVM_MEMBERSHIP_RECOVERING &&
            !members[0].has_activation_route_operation_id,
        "registration and restart cannot activate a member without route commit");
out:
    wvm_membership_controller_close(&controller);
    return result;
}

static void fill_endpoint(struct wvm_endpoint *endpoint)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = 17;
    endpoint->data_port = 19120;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = 19121;
}

static void fill_node(struct wvm_node_record *node)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = 17;
    node->node_instance_id = 101;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint);
    fill_endpoint(&node->sidecar_endpoint);
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = node->physical_node_id;
    node->inventory.node_instance_id = node->node_instance_id;
    node->inventory.failure_domain_id = node->failure_domain_id;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * MIB;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = MIB;
    node->inventory.reserved_gateway_cpu_slots = 1;
    node->inventory.reserved_gateway_memory_bytes = MIB;
    node->inventory.allocatable_vcpu_slots = 6;
    node->inventory.allocatable_memory_bytes = 14 * MIB;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = node->physical_node_id;
    node->capability.node_instance_id = node->node_instance_id;
    node->capability.profile_generation = 1;
    memset(node->capability.profile_digest, 0x21,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
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

static int connect_service(const char *socket_path)
{
    struct sockaddr_un address;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            strlen(socket_path) + 1U)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int exchange_registration(
    const char *socket_path, const uint8_t *payload, size_t payload_bytes,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    struct wvm_membership_control_result *result_out)
{
    struct wvm_envelope request;
    struct wvm_envelope response;
    uint8_t prefix[4];
    uint8_t response_prefix[4];
    uint8_t frame[WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES];
    uint8_t response_frame[WVM_ENVELOPE_HEADER_BYTES +
                           WVM_MEMBERSHIP_CONTROL_RESULT_BYTES];
    size_t frame_bytes = 0;
    uint32_t response_bytes;
    char error[256] = {0};
    int fd;
    int result = -1;

    fd = connect_service(socket_path);
    if (fd < 0) {
        return -1;
    }
    memset(&request, 0, sizeof(request));
    request.message_type = WVM_ENVELOPE_MSG_REGISTER_MEMBER;
    request.origin_physical_node_id = 17;
    request.origin_runtime_instance_id = 101;
    memcpy(request.operation_id, operation_id, sizeof(request.operation_id));
    request.delivery_attempt_id = 1;
    request.payload = payload;
    request.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 request.semantic_payload_digest);
    if (wvm_envelope_encode(&request, WVM_ENVELOPE_TRANSPORT_LOCAL, frame,
                            sizeof(frame), &frame_bytes, error,
                            sizeof(error)) != 0 ||
        frame_bytes > UINT32_MAX) {
        goto out;
    }
    write_be32(prefix, (uint32_t)frame_bytes);
    if (write_full(fd, prefix, sizeof(prefix)) != 0 ||
        write_full(fd, frame, frame_bytes) != 0 ||
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
        response.payload_bytes != WVM_MEMBERSHIP_CONTROL_RESULT_BYTES ||
        wvm_membership_control_result_decode(response.payload, result_out) !=
            0 ||
        memcmp(result_out->in_reply_to_operation_id, operation_id,
               sizeof(result_out->in_reply_to_operation_id)) != 0) {
        goto out;
    }
    result = 0;
out:
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return result;
}

int main(int argc, char **argv)
{
    char temporary_directory[128];
    char state_directory[256];
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char principal_path[256];
    char admission_journal[256];
    char membership_journal[256];
    char membership_control_journal[256];
    struct wvm_node_record node;
    struct wvm_membership_control_result first_result;
    struct wvm_membership_control_result replay_result;
    uint8_t node_bytes[8192];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    size_t node_byte_count = 0;
    char error[256] = {0};
    FILE *principal_file;
    struct stat socket_stat;
    struct stat journal_stat;
    pid_t child = -1;
    int result = 1;

    if (argc != 2 ||
        snprintf(temporary_directory, sizeof(temporary_directory),
                 "/tmp/wavevm-ctl-service-%ld", (long)getpid()) < 0 ||
        mkdir(temporary_directory, S_IRWXU) != 0 ||
        snprintf(state_directory, sizeof(state_directory), "%s/state",
                 temporary_directory) < 0 ||
        snprintf(socket_path, sizeof(socket_path), "%s/control.sock",
                 temporary_directory) < 0 ||
        snprintf(principal_path, sizeof(principal_path), "%s/principals",
                 temporary_directory) < 0 ||
        snprintf(admission_journal, sizeof(admission_journal),
                 "%s/admission.journal", state_directory) < 0 ||
        snprintf(membership_journal, sizeof(membership_journal),
                 "%s/membership.journal", state_directory) < 0 ||
        snprintf(membership_control_journal,
                 sizeof(membership_control_journal),
                 "%s/membership-control.journal", state_directory) < 0 ||
        mkdir(state_directory, S_IRWXU) != 0) {
        return 1;
    }
    principal_file = fopen(principal_path, "w");
    if (!principal_file ||
        fprintf(principal_file, "%lu node-runtime 17 101\n",
                (unsigned long)getuid()) < 0 ||
        fclose(principal_file) != 0) {
        if (principal_file) {
            fclose(principal_file);
        }
        goto out;
    }
    fill_node(&node);
    if (wvm_node_record_encode(&node, node_bytes, sizeof(node_bytes),
                               &node_byte_count, error, sizeof(error)) != 0) {
        goto out;
    }
    operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
    child = start_service(argv[1], state_directory, socket_path, principal_path);
    if (expect(child > 0 && wait_for_path(socket_path, 1) == 0,
               "start control plane with an empty cluster") != 0 ||
        expect(stat(membership_journal, &journal_stat) == 0 &&
                   journal_stat.st_size == 0,
               "startup does not fabricate compute membership") != 0) {
        goto out;
    }
    if (kill(child, SIGTERM) != 0 || wait_for_exit(child) != 0 ||
        expect(wait_for_path(socket_path, 0) == 0,
               "stop empty-cluster daemon") != 0) {
        child = -1;
        goto out;
    }
    child = -1;
    child = start_service(argv[1], state_directory, socket_path, principal_path);
    if (expect(child > 0 && wait_for_path(socket_path, 1) == 0,
               "start manifest-free control-plane daemon") != 0 ||
        expect(stat(membership_journal, &journal_stat) == 0 &&
                   journal_stat.st_size == 0,
               "empty-cluster restart does not fabricate compute membership") != 0 ||
        expect(stat(socket_path, &socket_stat) == 0 &&
                   (socket_stat.st_mode & 0777) == (S_IRUSR | S_IWUSR),
               "publish protected control socket") != 0 ||
        expect(exchange_registration(socket_path, node_bytes, node_byte_count,
                                     operation_id, &first_result) == 0 &&
                   first_result.status_code == WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   first_result.recorded_state == WVM_MANIFEST_MEMBER_PENDING,
               "authenticate Unix peer and persist registration") != 0 ||
        expect(access(admission_journal, F_OK) == 0 &&
                   access(membership_journal, F_OK) == 0 &&
                   access(membership_control_journal, F_OK) == 0,
               "open one durable admission and membership authority") != 0) {
        goto out;
    }
    if (kill(child, SIGTERM) != 0 || wait_for_exit(child) != 0 ||
        expect(wait_for_path(socket_path, 0) == 0,
               "stop daemon and remove listener") != 0) {
        child = -1;
        goto out;
    }
    child = -1;
    if (check_pending_membership(membership_journal) != 0) {
        goto out;
    }
    child = start_service(argv[1], state_directory, socket_path, principal_path);
    if (expect(child > 0 && wait_for_path(socket_path, 1) == 0,
               "restart durable control-plane daemon") != 0 ||
        expect(exchange_registration(socket_path, node_bytes, node_byte_count,
                                     operation_id, &replay_result) == 0 &&
                   memcmp(&first_result, &replay_result,
                          sizeof(first_result)) == 0,
               "replay exact durable registration result") != 0) {
        goto out;
    }
    result = 0;

out:
    if (child > 0) {
        (void)kill(child, SIGTERM);
        if (wait_for_exit(child) != 0) {
            result = 1;
        }
    }
    if (result == 0 && check_pending_membership(membership_journal) != 0) {
        result = 1;
    }
    unlink(socket_path);
    unlink(principal_path);
    unlink(admission_journal);
    unlink(membership_journal);
    unlink(membership_control_journal);
    rmdir(state_directory);
    rmdir(temporary_directory);
    return result;
}

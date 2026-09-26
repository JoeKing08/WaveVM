#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
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

#include "wavevm_control.h"
#include "wavevm_envelope.h"
#include "wavevm_route_delivery.h"
#include "wavevm_runtime_gate.h"
#include "wavevm_control_client.h"
#include "wavevm_tls_control_connector.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "gateway-route-control integration test: %s\n",
                message);
        return -1;
    }
    return 0;
}

static void sleep_ms(long milliseconds)
{
    struct timespec delay;

    delay.tv_sec = milliseconds / 1000L;
    delay.tv_nsec = (milliseconds % 1000L) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 127;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 0;
    endpoint->data_address[3] = 1;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port == UINT16_MAX ? port : port + 1U);
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rule,
                             struct wvm_required_ack_entry *ack,
                             uint64_t generation, uint16_t destination_port,
                             char *error, size_t error_len)
{
    uint8_t encoded[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes = 0;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 701;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 55;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 3;
    snapshot->route_snapshot_key.topology_revision = generation;
    snapshot->route_snapshot_key.route_generation = generation;
    snapshot->membership_revision = generation;
    snapshot->topology_kind = 1;

    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_vnode_or_endpoint = 0;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = (uint32_t)generation;
    rule->next_hop_member.instance_id = 7000U + generation;
    fill_endpoint(&rule->next_hop_endpoint, destination_port);
    rule->hop_limit = 4;

    memset(ack, 0, sizeof(*ack));
    ack->member_key = rule->next_hop_member;
    ack->endpoint = rule->next_hop_endpoint;
    ack->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack->expected_snapshot_key = snapshot->route_snapshot_key;

    snapshot->next_hop_rules.entries = rule;
    snapshot->next_hop_rules.count = 1;
    snapshot->next_hop_rules.capacity = 1;
    snapshot->required_ack_set.entries.entries = ack;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(ack->expected_snapshot_key.snapshot_digest, digest, sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int encode_snapshot(const struct wvm_route_snapshot_record *snapshot,
                           uint8_t *bytes, size_t capacity,
                           size_t *byte_count, char *error, size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    return wvm_route_snapshot_record_encode(snapshot, bytes, capacity,
                                            byte_count, digest, error,
                                            error_len);
}

static int encode_key(const struct wvm_route_snapshot_key *key, uint8_t *bytes,
                      size_t capacity, size_t *byte_count, char *error,
                      size_t error_len)
{
    return wvm_route_snapshot_key_encode(key, bytes, capacity, byte_count,
                                         error, error_len);
}

static int create_runtime_manifest(
    const char *manifest_path, const struct wvm_route_snapshot_key *route_key,
    char *error, size_t error_len)
{
    struct wvm_node_runtime_manifest manifest;
    struct wvm_capability_ref capability;
    struct wvm_local_name_identity name_identity;

    memset(&manifest, 0, sizeof(manifest));
    memset(manifest.candidate_manifest_digest, 0x11,
           sizeof(manifest.candidate_manifest_digest));
    manifest.vm_id = route_key->scope_key.vm_id;
    manifest.vm_incarnation = route_key->scope_key.vm_incarnation;
    manifest.manifest_generation = 9;
    memset(manifest.admission_tx_id, 0x22, sizeof(manifest.admission_tx_id));
    memset(manifest.eligibility_fence_digest, 0x33,
           sizeof(manifest.eligibility_fence_digest));
    manifest.has_activation_fence = 1;
    memset(manifest.activation_fence, 0x44, sizeof(manifest.activation_fence));
    manifest.physical_node_id = 17;
    manifest.expected_node_instance_id = 44;
    manifest.local_role_bits = WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_GATEWAY);
    manifest.required_route_snapshot_key = *route_key;
    memset(manifest.reservation_id, 0x99, sizeof(manifest.reservation_id));

    memset(&name_identity, 0, sizeof(name_identity));
    name_identity.vm_id = manifest.vm_id;
    name_identity.vm_incarnation = manifest.vm_incarnation;
    name_identity.manifest_generation = manifest.manifest_generation;
    name_identity.physical_node_id = manifest.physical_node_id;
    memset(name_identity.manifest_id, 0x66, sizeof(name_identity.manifest_id));
    memcpy(name_identity.admission_tx_id, manifest.admission_tx_id,
           sizeof(name_identity.admission_tx_id));
    if (wvm_local_name_namespace_derive(&name_identity, &manifest.local_names,
                                        error, error_len) != 0) {
        return -1;
    }

    manifest.negotiated_profile.backend = WVM_MANIFEST_BACKEND_TCG;
    manifest.negotiated_profile.context_schema_version = 1;
    manifest.negotiated_profile.dirty_capture_engine = 1;
    manifest.negotiated_profile.read_fault_engine = 1;
    manifest.negotiated_profile.invalidation_engine = 1;
    manifest.negotiated_profile.fallback_decision = 1;
    memset(manifest.negotiated_profile.supported_memory_policies_digest, 0x77,
           sizeof(manifest.negotiated_profile.supported_memory_policies_digest));
    memset(&capability, 0, sizeof(capability));
    capability.physical_node_id = manifest.physical_node_id;
    capability.node_instance_id = manifest.expected_node_instance_id;
    capability.profile_generation = 8;
    memset(capability.profile_digest, 0x88, sizeof(capability.profile_digest));
    manifest.negotiated_profile.per_node_capabilities.entries = &capability;
    manifest.negotiated_profile.per_node_capabilities.count = 1;
    manifest.negotiated_profile.per_node_capabilities.capacity = 1;
    manifest.launch_plan.plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
    manifest.launch_plan.node_runtime_data_port = 19100;
    manifest.launch_plan.node_runtime_control_port = 19121;
    manifest.launch_plan.local_executor_service_port = 19105;
    manifest.launch_plan.local_executor_control_port = 19121;
    manifest.launch_plan.executor_worker_count = 1;
    manifest.launch_plan.vcpu_handoff_record_capacity = 16;
    manifest.launch_plan.sync_batch_size = 1;
    manifest.launch_plan.guest_total_memory_bytes = 4 * 1024 * 1024;
    strcpy(manifest.launch_plan.guest_machine.architecture, "x86_64");
    strcpy(manifest.launch_plan.guest_machine.machine_type, "pc-i440fx-5.2");
    manifest.launch_plan.guest_machine.qemu_compat_version = 502;
    manifest.launch_plan.guest_machine.firmware_policy = 1;
    manifest.launch_plan.consistency_policy.dirty_batch_size = 1;
    manifest.launch_plan.consistency_policy.handoff_commit_policy = 1;
    manifest.launch_plan.consistency_policy.subscriber_delivery_policy = 1;
    manifest.launch_plan.consistency_policy.max_commit_latency_ms = 1000;

    return wvm_runtime_manifest_file_publish(manifest_path, &manifest, error,
                                             error_len);
}

static int bind_udp_loopback(uint16_t requested_port, uint16_t *bound_port)
{
    struct sockaddr_in address;
    socklen_t address_bytes = sizeof(address);
    int fd;

    if (!bound_port) {
        return -1;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(requested_port);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(fd, (struct sockaddr *)&address, &address_bytes) != 0) {
        close(fd);
        return -1;
    }
    *bound_port = ntohs(address.sin_port);
    return fd;
}

static int reserve_udp_port(uint16_t *port_out)
{
    int fd;

    fd = bind_udp_loopback(0, port_out);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int reserve_tcp_port(uint16_t *port_out)
{
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(address.sin_port);
    close(fd);
    return 0;
}

static int wait_for_control_socket(const char *path)
{
    struct stat st;
    struct sockaddr_un address;
    int attempts;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    for (attempts = 0; attempts < 200; attempts++) {
        if (lstat(path, &st) == 0 && S_ISSOCK(st.st_mode) &&
            (st.st_mode & 0777U) == 0600U) {
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);

            if (fd >= 0) {
                int connected = connect(fd, (struct sockaddr *)&address,
                                        sizeof(address));

                close(fd);
                if (connected == 0) {
                    return 0;
                }
            }
        }
        sleep_ms(25);
    }
    return -1;
}

static pid_t start_gateway(const char *gateway_path, const char *manifest_path,
                           const char *poison_route_path,
                           const char *journal_path,
                           const char *control_socket_path,
                           const char *config_path, const char *log_path,
                           uint16_t data_port, uint16_t legacy_control_port,
                           uint16_t tls_control_port, const char *ca_file,
                           const char *certificate_file,
                           const char *private_key_file)
{
    pid_t child;
    char data_port_text[16];
    char control_port_text[16];
    char tls_port_text[16];

    snprintf(data_port_text, sizeof(data_port_text), "%u",
             (unsigned)data_port);
    snprintf(control_port_text, sizeof(control_port_text), "%u",
             (unsigned)legacy_control_port);
    snprintf(tls_port_text, sizeof(tls_port_text), "%u",
             (unsigned)tls_control_port);
    child = fork();
    if (child != 0) {
        return child;
    }
    {
        int log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                          0600);

        if (log_fd < 0) {
            _exit(127);
        }
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }
    setenv("WVM_RUNTIME_GATE_ACTIVE", "1", 1);
    setenv("WVM_RUNTIME_MANIFEST_PATH", manifest_path, 1);
    setenv("WVM_RUNTIME_PHYSICAL_NODE_ID", "17", 1);
    setenv("WVM_NODE_INSTANCE_ID", "44", 1);
    setenv("WVM_GATEWAY_ID", "27", 1);
    setenv("WVM_GATEWAY_INSTANCE_ID", "45", 1);
    setenv("WVM_GATEWAY_ROUTE_JOURNAL_PATH", journal_path, 1);
    setenv("WVM_GATEWAY_CONTROL_SOCKET", control_socket_path, 1);
    setenv("WVM_GATEWAY_CONTROLLER_ROLE", "node-runtime", 1);
    setenv("WVM_GATEWAY_CONTROLLER_ID", "71", 1);
    setenv("WVM_GATEWAY_CONTROLLER_INSTANCE_ID", "72", 1);
    setenv("WVM_GATEWAY_CONTROLLER_PHYSICAL_NODE_ID", "71", 1);
    setenv("WVM_GATEWAY_CONTROLLER_RUNTIME_INSTANCE_ID", "72", 1);
    setenv("WVM_GATEWAY_CONTROL_ADDRESS", "127.0.0.1", 1);
    setenv("WVM_GATEWAY_CONTROL_PORT", tls_port_text, 1);
    setenv("WVM_GATEWAY_CONTROL_CA_FILE", ca_file, 1);
    setenv("WVM_GATEWAY_CONTROL_CERTIFICATE_FILE", certificate_file, 1);
    setenv("WVM_GATEWAY_CONTROL_PRIVATE_KEY_FILE", private_key_file, 1);
    /*
     * The gateway must ignore this unrelated path in active mode and derive
     * the manifest sibling artifact instead.
     */
    setenv("WVM_RUNTIME_ROUTE_SNAPSHOT_PATH", poison_route_path, 1);
    execl(gateway_path, gateway_path, data_port_text, "127.0.0.1", "9",
          config_path, control_port_text, (char *)NULL);
    _exit(127);
}

static void stop_gateway(pid_t child)
{
    int status;
    int attempts;

    if (child <= 0) {
        return;
    }
    kill(child, SIGTERM);
    for (attempts = 0; attempts < 40; attempts++) {
        if (waitpid(child, &status, WNOHANG) == child) {
            return;
        }
        sleep_ms(25);
    }
    kill(child, SIGKILL);
    (void)waitpid(child, &status, 0);
}

static void make_control_request(struct wvm_envelope *request,
                                 uint16_t message_type,
                                 uint8_t operation_tail,
                                 const struct wvm_route_snapshot_key *key,
                                 const uint8_t *payload, size_t payload_bytes)
{
    memset(request, 0, sizeof(*request));
    request->message_type = message_type;
    request->vm_id = 701;
    request->vm_incarnation = 55;
    request->manifest_generation = 9;
    request->origin_physical_node_id = 71;
    request->origin_runtime_instance_id = 72;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    request->delivery_attempt_id = 1;
    request->route_scope_id = key->scope_key.route_scope_id;
    request->topology_revision = key->topology_revision;
    request->route_generation = key->route_generation;
    memcpy(request->route_snapshot_digest, key->snapshot_digest,
           sizeof(request->route_snapshot_digest));
    request->payload = payload;
    request->payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 request->semantic_payload_digest);
}

static int send_control_request(struct wvm_control_stream_client *client,
                                const struct wvm_endpoint *endpoint,
                                const struct wvm_envelope *request,
                                uint16_t expected_state)
{
    const struct wvm_member_key gateway = {
        .role_type = WVM_MANIFEST_ROLE_GATEWAY,
        .role_id = 27,
        .instance_id = 45,
    };
    struct wvm_control_result response;
    char error[256] = {0};
    if (wvm_control_stream_client_exchange(client, &gateway, endpoint,
                                           request, &response, error,
                                           sizeof(error)) != 0 ||
        response.status_code != WVM_CONTROL_RESULT_SUCCESS ||
        response.recorded_state != expected_state ||
        response.applied_revision != request->route_generation) {
        fprintf(stderr, "invalid route control response: %s\n",
                error[0] ? error : "unexpected response");
        return -1;
    }
    return 0;
}

static int reject_wrong_controller(const char *ca_file,
                                   const char *gateway_certificate,
                                   const char *gateway_private_key,
                                   const struct wvm_endpoint *endpoint,
                                   const struct wvm_envelope *request)
{
    const struct wvm_member_key gateway = {
        .role_type = WVM_MANIFEST_ROLE_GATEWAY,
        .role_id = 27,
        .instance_id = 45,
    };
    struct wvm_tls_control_connector tls_state;
    struct wvm_control_stream_connector connector = {0};
    struct wvm_control_stream_client client = {0};
    struct wvm_control_result response = {0};
    char error[256] = {0};
    int result = -1;

    memset(&tls_state, 0, sizeof(tls_state));
    if (wvm_tls_control_connector_bind(
            &tls_state, ca_file, gateway_certificate, gateway_private_key,
            3000, &connector, error, sizeof(error)) == 0 &&
        wvm_control_stream_client_init(&client, &connector, error,
                                       sizeof(error)) == 0 &&
        wvm_control_stream_client_exchange(
            &client, &gateway, endpoint, request, &response, error,
            sizeof(error)) == 0 &&
        response.status_code == WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE) {
        result = 0;
    }
    wvm_control_stream_client_destroy(&client);
    wvm_tls_control_connector_destroy(&tls_state);
    return result;
}

static int expect_forwarded_frame(int receiver_fd, uint16_t gateway_port,
                                  const struct wvm_route_snapshot_key *key,
                                  uint8_t operation_tail)
{
    struct sockaddr_in gateway_address;
    struct pollfd pollfd;
    struct wvm_envelope request;
    struct wvm_envelope forwarded;
    uint8_t frame[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    uint8_t received[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    static const uint8_t payload[] = {0xa1, 0xb2, 0xc3, 0xd4};
    size_t frame_bytes = 0;
    ssize_t received_bytes;
    char error[256] = {0};
    int sender;

    memset(&request, 0, sizeof(request));
    request.message_type = WVM_ENVELOPE_MSG_MEM_READ;
    request.vm_id = key->scope_key.vm_id;
    request.vm_incarnation = key->scope_key.vm_incarnation;
    request.manifest_generation = 9;
    request.origin_physical_node_id = 23;
    request.origin_runtime_instance_id = 99;
    request.operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    request.delivery_attempt_id = 1;
    request.route_scope_id = key->scope_key.route_scope_id;
    request.topology_revision = key->topology_revision;
    request.route_generation = key->route_generation;
    memcpy(request.route_snapshot_digest, key->snapshot_digest,
           sizeof(request.route_snapshot_digest));
    request.route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    request.route.destination_vnode_or_endpoint = 0;
    request.route.hop_limit = 4;
    request.payload = payload;
    request.payload_bytes = sizeof(payload);
    if (wvm_envelope_encode(&request, WVM_ENVELOPE_TRANSPORT_NETWORK,
                               frame, sizeof(frame), &frame_bytes, error,
                               sizeof(error)) != 0) {
        fprintf(stderr, "cannot encode routed V1 frame: %s\n", error);
        return -1;
    }
    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender < 0) {
        return -1;
    }
    memset(&gateway_address, 0, sizeof(gateway_address));
    gateway_address.sin_family = AF_INET;
    gateway_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    gateway_address.sin_port = htons(gateway_port);
    if (sendto(sender, frame, frame_bytes, MSG_NOSIGNAL,
               (struct sockaddr *)&gateway_address,
               sizeof(gateway_address)) != (ssize_t)frame_bytes) {
        close(sender);
        return -1;
    }
    close(sender);
    pollfd.fd = receiver_fd;
    pollfd.events = POLLIN;
    pollfd.revents = 0;
    if (poll(&pollfd, 1, 3000) != 1 || !(pollfd.revents & POLLIN)) {
        return -1;
    }
    received_bytes = recv(receiver_fd, received, sizeof(received), 0);
    if (received_bytes <= 0 ||
        wvm_envelope_decode(received, (size_t)received_bytes,
                               WVM_ENVELOPE_TRANSPORT_NETWORK, &forwarded,
                               error, sizeof(error)) != 0 ||
        forwarded.message_type != request.message_type ||
        forwarded.route.hop_count != 1 ||
        forwarded.route_generation != key->route_generation ||
        memcmp(forwarded.route_snapshot_digest, key->snapshot_digest,
               sizeof(key->snapshot_digest)) != 0 ||
        forwarded.payload_bytes != sizeof(payload) ||
        memcmp(forwarded.payload, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "gateway did not forward admitted V1 frame: %s\n",
                error[0] ? error : "unexpected frame");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char directory[] = "/tmp/wavevm-gateway-control.XXXXXX";
    char manifest_path[512] = {0};
    char manifest_route_path[512] = {0};
    char poison_route_path[512] = {0};
    char journal_path[512] = {0};
    char control_socket_path[512] = {0};
    char config_path[512] = {0};
    char log_path[512] = {0};
    struct wvm_route_snapshot_record initial_snapshot;
    struct wvm_route_snapshot_record successor_snapshot;
    struct wvm_route_snapshot_record poison_snapshot;
    struct wvm_route_rule_record initial_rule;
    struct wvm_route_rule_record successor_rule;
    struct wvm_route_rule_record poison_rule;
    struct wvm_required_ack_entry initial_ack;
    struct wvm_required_ack_entry successor_ack;
    struct wvm_required_ack_entry poison_ack;
    struct wvm_envelope request;
    struct wvm_endpoint gateway_endpoint;
    struct wvm_tls_control_connector tls_state;
    struct wvm_control_stream_connector connector;
    struct wvm_control_stream_client client;
    uint8_t snapshot_bytes[8192];
    uint8_t key_bytes[512];
    size_t snapshot_byte_count = 0;
    size_t key_byte_count = 0;
    uint16_t initial_receiver_port;
    uint16_t successor_receiver_port;
    uint16_t poison_receiver_port;
    uint16_t gateway_port;
    uint16_t legacy_control_port;
    uint16_t tls_control_port;
    char error[256] = {0};
    pid_t gateway = -1;
    int initial_receiver = -1;
    int successor_receiver = -1;
    int poison_receiver = -1;
    int config_fd = -1;
    int legacy_probe = -1;
    int result = 1;
    int client_initialized = 0;

    if (argc != 7) {
        fprintf(stderr, "usage: %s GATEWAY CA GATEWAY_CERT GATEWAY_KEY CONTROLLER_CERT CONTROLLER_KEY\n", argv[0]);
        return 2;
    }
    memset(&tls_state, 0, sizeof(tls_state));
    memset(&connector, 0, sizeof(connector));
    memset(&client, 0, sizeof(client));
    if (!mkdtemp(directory)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest", directory);
    snprintf(poison_route_path, sizeof(poison_route_path), "%s/poison.route",
             directory);
    snprintf(journal_path, sizeof(journal_path), "%s/routes.journal",
             directory);
    snprintf(control_socket_path, sizeof(control_socket_path), "%s/control.sock",
             directory);
    snprintf(config_path, sizeof(config_path), "%s/legacy.conf", directory);
    snprintf(log_path, sizeof(log_path), "%s/gateway.log", directory);

    initial_receiver = bind_udp_loopback(0, &initial_receiver_port);
    successor_receiver = bind_udp_loopback(0, &successor_receiver_port);
    poison_receiver = bind_udp_loopback(0, &poison_receiver_port);
    if (expect(initial_receiver >= 0 && successor_receiver >= 0 &&
                   poison_receiver >= 0,
               "bind V1 route receivers") ||
        expect(reserve_udp_port(&gateway_port) == 0 &&
                   reserve_udp_port(&legacy_control_port) == 0 &&
                   reserve_tcp_port(&tls_control_port) == 0,
               "reserve gateway ports") ||
        finalize_snapshot(&initial_snapshot, &initial_rule, &initial_ack, 1,
                          initial_receiver_port, error, sizeof(error)) != 0 ||
        finalize_snapshot(&successor_snapshot, &successor_rule, &successor_ack,
                          2, successor_receiver_port, error,
                          sizeof(error)) != 0 ||
        finalize_snapshot(&poison_snapshot, &poison_rule, &poison_ack, 9,
                          poison_receiver_port, error, sizeof(error)) != 0 ||
        create_runtime_manifest(manifest_path,
                                &initial_snapshot.route_snapshot_key, error,
                                sizeof(error)) != 0 ||
        wvm_route_snapshot_path_from_manifest(
            manifest_path, manifest_route_path, sizeof(manifest_route_path),
            error, sizeof(error)) != 0 ||
        wvm_route_snapshot_file_publish(manifest_route_path, &initial_snapshot,
                                        error, sizeof(error)) != 0 ||
        wvm_route_snapshot_file_publish(poison_route_path, &poison_snapshot,
                                        error, sizeof(error)) != 0) {
        fprintf(stderr, "gateway fixture setup failed: %s\n", error);
        goto out;
    }
    config_fd = open(config_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (config_fd < 0) {
        perror("open legacy config");
        goto out;
    }
    close(config_fd);
    config_fd = -1;

    fill_endpoint(&gateway_endpoint, gateway_port);
    gateway_endpoint.has_control_address = 1;
    gateway_endpoint.control_address_bytes = 4;
    gateway_endpoint.control_address[0] = 127;
    gateway_endpoint.control_address[3] = 1;
    gateway_endpoint.control_port = tls_control_port;
    if (wvm_tls_control_connector_bind(&tls_state, argv[2], argv[5],
                                       argv[6], 3000, &connector,
                                       error, sizeof(error)) != 0 ||
        wvm_control_stream_client_init(&client, &connector, error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "TLS control test setup failed: %s\n", error);
        goto out;
    }
    client_initialized = 1;

    gateway = start_gateway(argv[1], manifest_path, poison_route_path,
                            journal_path, control_socket_path, config_path,
                            log_path, gateway_port, legacy_control_port,
                            tls_control_port, argv[2], argv[3], argv[4]);
    if (expect(gateway > 0, "fork active gateway") ||
        expect(wait_for_control_socket(control_socket_path) == 0,
               "create authenticated V1 control socket") ||
        expect_forwarded_frame(initial_receiver, gateway_port,
                               &initial_snapshot.route_snapshot_key, 1) != 0) {
        goto out;
    }

    /*
     * A V1 gateway must not bind the old UDP ADD_ROUTE listener. Holding this
     * port proves it did not fall back to that unauthenticated control plane.
     */
    legacy_probe = bind_udp_loopback(legacy_control_port, &legacy_control_port);
    if (expect(legacy_probe >= 0, "leave legacy UDP control disabled")) {
        goto out;
    }
    close(legacy_probe);
    legacy_probe = -1;

    if (encode_snapshot(&successor_snapshot, snapshot_bytes,
                        sizeof(snapshot_bytes), &snapshot_byte_count, error,
                        sizeof(error)) != 0) {
        fprintf(stderr, "encode successor snapshot: %s\n", error);
        goto out;
    }
    make_control_request(&request, WVM_ENVELOPE_MSG_ROUTE_PREPARE, 2,
                         &successor_snapshot.route_snapshot_key,
                         snapshot_bytes, snapshot_byte_count);
    if (expect(reject_wrong_controller(argv[2], argv[3], argv[4],
                                       &gateway_endpoint, &request) == 0,
               "reject gateway certificate as route controller") ||
        expect(send_control_request(&client, &gateway_endpoint, &request, 1) == 0,
               "prepare successor through authenticated TLS") ||
        encode_key(&successor_snapshot.route_snapshot_key, key_bytes,
                   sizeof(key_bytes), &key_byte_count, error,
                   sizeof(error)) != 0) {
        fprintf(stderr, "prepare successor failed: %s\n", error);
        goto out;
    }
    make_control_request(&request, WVM_ENVELOPE_MSG_ROUTE_COMMIT, 3,
                         &successor_snapshot.route_snapshot_key,
                         key_bytes, key_byte_count);
    if (expect(send_control_request(&client, &gateway_endpoint, &request, 2) == 0,
               "commit successor through authenticated TLS")) {
        goto out;
    }

    stop_gateway(gateway);
    gateway = -1;
    gateway = start_gateway(argv[1], manifest_path, poison_route_path,
                            journal_path, control_socket_path, config_path,
                            log_path, gateway_port, legacy_control_port,
                            tls_control_port, argv[2], argv[3], argv[4]);
    if (expect(gateway > 0, "restart gateway with route journal") ||
        expect(wait_for_control_socket(control_socket_path) == 0,
               "restore V1 control socket after replay") ||
        expect_forwarded_frame(successor_receiver, gateway_port,
                               &successor_snapshot.route_snapshot_key, 4) !=
            0) {
        goto out;
    }
    result = 0;
    puts("gateway route-control integration: PASS");
out:
    stop_gateway(gateway);
    if (result != 0) {
        FILE *log = fopen(log_path, "r");
        char line[512];

        if (log) {
            while (fgets(line, sizeof(line), log)) {
                fputs(line, stderr);
            }
            fclose(log);
        }
    }
    if (client_initialized) {
        wvm_control_stream_client_destroy(&client);
    }
    wvm_tls_control_connector_destroy(&tls_state);
    if (legacy_probe >= 0) {
        close(legacy_probe);
    }
    if (config_fd >= 0) {
        close(config_fd);
    }
    if (initial_receiver >= 0) {
        close(initial_receiver);
    }
    if (successor_receiver >= 0) {
        close(successor_receiver);
    }
    if (poison_receiver >= 0) {
        close(poison_receiver);
    }
    unlink(control_socket_path);
    unlink(journal_path);
    unlink(manifest_route_path);
    unlink(manifest_path);
    unlink(poison_route_path);
    unlink(config_path);
    unlink(log_path);
    rmdir(directory);
    return result;
}

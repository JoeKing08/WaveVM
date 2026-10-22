
/*
 * R02: live wavevm_gateway process forwards a real BLOCK_WRITE and BLOCK_ACK.
 *
 * Client -> UDP -> wavevm_gateway (process) -> UDP -> block_service (chunk store)
 *         <- UDP <- wavevm_gateway           <- UDP <- BLOCK_ACK
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
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

#include "block_service.h"
#include "wavevm_block_chunk_store.h"
#include "wavevm_block_wire.h"
#include "wavevm_control.h"
#include "wavevm_manifest.h"
#include "wavevm_runtime_names.h"
#include "wavevm_identity.h"
#include "wavevm_sha256.h"
#include "wavevm_envelope.h"
#include "wavevm_route_delivery.h"
#include "wavevm_runtime_gate.h"

#define VM_ID 701U
#define INCARNATION 55ULL
#define GENERATION 9ULL
#define DEVICE 0U
#define SECTORS 1U
#define BYTES (SECTORS * 512U)
#define STORAGE_VNODE 1U
#define REPLY_VNODE 2U

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "r02-gateway-block: %s\n", msg);
        return -1;
    }
    return 0;
}

static void sleep_ms(long ms)
{
    struct timespec d = {.tv_sec = ms / 1000,
                         .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&d, &d) != 0 && errno == EINTR) {
    }
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint16_t data_port,
                          uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 127;
    endpoint->data_address[3] = 1;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static int bind_udp(uint16_t *port_out)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(addr.sin_port);
    return fd;
}

static int reserve_udp(uint16_t *port_out)
{
    int fd = bind_udp(port_out);
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}

static int reserve_tcp(uint16_t *port_out)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(addr.sin_port);
    close(fd);
    return 0;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rules,
                             struct wvm_required_ack_entry *acks,
                             uint16_t storage_port, uint16_t storage_control_port,
                             uint16_t reply_port, uint16_t reply_control_port,
                             char *error, size_t error_len)
{
    uint8_t encoded[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes = 0;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = VM_ID;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = INCARNATION;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 3;
    snapshot->route_snapshot_key.topology_revision = 1;
    snapshot->route_snapshot_key.route_generation = 1;
    snapshot->membership_revision = 1;
    snapshot->topology_kind = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    memset(rules, 0, 2 * sizeof(*rules));
    rules[0].destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rules[0].destination_scope = 0;
    rules[0].destination_vnode_or_endpoint = STORAGE_VNODE;
    rules[0].next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rules[0].next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rules[0].next_hop_member.role_id = 1;
    rules[0].next_hop_member.instance_id = 33;
    fill_endpoint(&rules[0].next_hop_endpoint, storage_port,
                  storage_control_port);
    rules[0].hop_limit = 4;

    rules[1].destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rules[1].destination_scope = 0;
    rules[1].destination_vnode_or_endpoint = REPLY_VNODE;
    rules[1].next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rules[1].next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rules[1].next_hop_member.role_id = 2;
    rules[1].next_hop_member.instance_id = 4;
    fill_endpoint(&rules[1].next_hop_endpoint, reply_port,
                  reply_control_port);
    rules[1].hop_limit = 4;

    memset(acks, 0, 2 * sizeof(*acks));
    acks[0].member_key = rules[0].next_hop_member;
    acks[0].endpoint = rules[0].next_hop_endpoint;
    acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks[0].expected_snapshot_key = snapshot->route_snapshot_key;
    acks[1].member_key = rules[1].next_hop_member;
    acks[1].endpoint = rules[1].next_hop_endpoint;
    acks[1].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks[1].expected_snapshot_key = snapshot->route_snapshot_key;

    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = 2;
    snapshot->next_hop_rules.capacity = 2;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = 2;
    snapshot->required_ack_set.entries.capacity = 2;

    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0)
        return -1;
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(acks[0].expected_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(acks[1].expected_snapshot_key.snapshot_digest, digest, sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int create_runtime_manifest(const char *manifest_path,
                                   const struct wvm_route_snapshot_key *route_key,
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
    manifest.manifest_generation = GENERATION;
    memset(manifest.admission_tx_id, 0x55, sizeof(manifest.admission_tx_id));
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
                                        error, error_len) != 0)
        return -1;

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
    if (wvm_node_runtime_manifest_validate(&manifest, error, error_len) != 0)
        return -1;
    return wvm_runtime_manifest_file_publish(manifest_path, &manifest, error,
                                             error_len);
}

static int wait_sock(const char *path)
{
    struct stat st;
    struct sockaddr_un address;
    int attempts;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    for (attempts = 0; attempts < 200; attempts++) {
        if (lstat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd >= 0) {
                int ok =
                    connect(fd, (struct sockaddr *)&address, sizeof(address));
                close(fd);
                if (ok == 0)
                    return 0;
            }
        }
        sleep_ms(25);
    }
    return -1;
}

static pid_t start_gateway(const char *gateway_path, const char *manifest_path,
                           const char *poison_path, const char *journal_path,
                           const char *control_socket, const char *config_path,
                           const char *log_path, uint16_t data_port,
                           uint16_t legacy_control, uint16_t tls_control,
                           const char *ca, const char *cert, const char *key)
{
    pid_t child;
    char data_txt[16], ctrl_txt[16], tls_txt[16];

    snprintf(data_txt, sizeof(data_txt), "%u", (unsigned)data_port);
    snprintf(ctrl_txt, sizeof(ctrl_txt), "%u", (unsigned)legacy_control);
    snprintf(tls_txt, sizeof(tls_txt), "%u", (unsigned)tls_control);
    child = fork();
    if (child != 0)
        return child;
    {
        int log_fd =
            open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (log_fd < 0)
            _exit(127);
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }
    setenv("WVM_RUNTIME_GATE_ACTIVE", "1", 1);
    setenv("WVM_GATEWAY_SINGLE_RX", "1", 1);
    setenv("WVM_GATEWAY_DISABLE_REUSEPORT", "1", 1);
    setenv("WVM_GATEWAY_USE_RECVFROM", "1", 1);
    setenv("WVM_RUNTIME_MANIFEST_PATH", manifest_path, 1);
    setenv("WVM_RUNTIME_PHYSICAL_NODE_ID", "17", 1);
    setenv("WVM_NODE_INSTANCE_ID", "44", 1);
    setenv("WVM_GATEWAY_ID", "27", 1);
    setenv("WVM_GATEWAY_INSTANCE_ID", "45", 1);
    setenv("WVM_GATEWAY_ROUTE_JOURNAL_PATH", journal_path, 1);
    setenv("WVM_GATEWAY_CONTROL_SOCKET", control_socket, 1);
    setenv("WVM_GATEWAY_CONTROLLER_ROLE", "node-runtime", 1);
    setenv("WVM_GATEWAY_CONTROLLER_ID", "71", 1);
    setenv("WVM_GATEWAY_CONTROLLER_INSTANCE_ID", "72", 1);
    setenv("WVM_GATEWAY_CONTROLLER_PHYSICAL_NODE_ID", "71", 1);
    setenv("WVM_GATEWAY_CONTROLLER_RUNTIME_INSTANCE_ID", "72", 1);
    setenv("WVM_GATEWAY_CONTROL_ADDRESS", "127.0.0.1", 1);
    setenv("WVM_GATEWAY_CONTROL_PORT", tls_txt, 1);
    setenv("WVM_GATEWAY_CONTROL_CA_FILE", ca, 1);
    setenv("WVM_GATEWAY_CONTROL_CERTIFICATE_FILE", cert, 1);
    setenv("WVM_GATEWAY_CONTROL_PRIVATE_KEY_FILE", key, 1);
    {
        char enrollment_dir[512];
        snprintf(enrollment_dir, sizeof(enrollment_dir), "%s.enrollment",
                 journal_path);
        mkdir(enrollment_dir, 0700);
        setenv("WVM_GATEWAY_ENROLLMENT_STATE_DIR", enrollment_dir, 1);
    }
    setenv("WVM_RUNTIME_ROUTE_SNAPSHOT_PATH", poison_path, 1);
    execl(gateway_path, gateway_path, data_txt, "127.0.0.1", "9", config_path,
          ctrl_txt, (char *)NULL);
    _exit(127);
}

static void stop_gateway(pid_t child)
{
    int status, attempts;
    if (child <= 0)
        return;
    kill(child, SIGTERM);
    for (attempts = 0; attempts < 40; attempts++) {
        if (waitpid(child, &status, WNOHANG) == child)
            return;
        sleep_ms(25);
    }
    kill(child, SIGKILL);
    (void)waitpid(child, &status, 0);
}

struct service_ctx {
    struct wvm_block_service *service;
    int sock;
    uint16_t gateway_port;
    volatile int stop;
};

static int service_send(void *opaque, const struct wvm_envelope *envelope,
                        char *error, size_t error_len)
{
    struct service_ctx *ctx = opaque;
    uint8_t frame[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    size_t frame_bytes = 0;
    struct sockaddr_in gw;

    if (wvm_envelope_encode(envelope, WVM_ENVELOPE_TRANSPORT_NETWORK, frame,
                            sizeof(frame), &frame_bytes, error, error_len) != 0)
        return -1;
    memset(&gw, 0, sizeof(gw));
    gw.sin_family = AF_INET;
    gw.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    gw.sin_port = htons(ctx->gateway_port);
    if (sendto(ctx->sock, frame, frame_bytes, MSG_NOSIGNAL,
               (struct sockaddr *)&gw, sizeof(gw)) != (ssize_t)frame_bytes) {
        snprintf(error, error_len, "service cannot UDP-send ACK to gateway");
        return -1;
    }
    return 0;
}

static int service_resolve(void *opaque, uint16_t destination_kind,
                           uint64_t destination_scope, uint32_t destination_vnode,
                           struct wvm_envelope_route *route, char *error,
                           size_t error_len)
{
    (void)opaque;
    (void)error;
    (void)error_len;
    memset(route, 0, sizeof(*route));
    route->destination_kind = destination_kind;
    route->destination_scope = destination_scope;
    route->destination_vnode_or_endpoint = destination_vnode;
    route->hop_limit = 4;
    return 0;
}

static int execute_block(void *opaque, uint32_t device_index, uint16_t operation,
                         uint32_t flags, uint64_t lba_512, uint32_t sector_count,
                         const uint8_t *data, size_t data_bytes, uint8_t *out,
                         size_t out_capacity, size_t *out_bytes, char *error,
                         size_t error_len)
{
    (void)opaque;
    if (device_index != DEVICE) {
        snprintf(error, error_len, "unexpected device");
        return -1;
    }
    if (operation == WVM_BLOCK_OPERATION_READ)
        return wvm_block_chunk_read(lba_512, sector_count, out, out_capacity,
                                    out_bytes, error, error_len);
    if (operation == WVM_BLOCK_OPERATION_WRITE) {
        int rc = wvm_block_chunk_write(lba_512, sector_count, data, data_bytes,
                                       (flags & WVM_BLOCK_ORDER_FUA) != 0, error,
                                       error_len);
        *out_bytes = 0;
        return rc;
    }
    *out_bytes = 0;
    return wvm_block_chunk_flush_range(lba_512, sector_count, error, error_len);
}

static void *service_main(void *opaque)
{
    struct service_ctx *ctx = opaque;
    uint8_t buf[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    char error[160];

    while (!ctx->stop) {
        struct pollfd p = {.fd = ctx->sock, .events = POLLIN};
        struct wvm_envelope env;
        ssize_t n;

        if (poll(&p, 1, 50) != 1)
            continue;
        n = recv(ctx->sock, buf, sizeof(buf), 0);
        if (n <= 0)
            continue;
        memset(&env, 0, sizeof(env));
        error[0] = '\0';
        if (wvm_envelope_decode(buf, (size_t)n, WVM_ENVELOPE_TRANSPORT_NETWORK,
                                &env, error, sizeof(error)) != 0)
            continue;
        (void)wvm_block_service_dispatch(ctx->service, &env, error,
                                         sizeof(error));
    }
    return NULL;
}

int main(int argc, char **argv)
{
    char directory[] = "/tmp/wavevm-r02-gw-block.XXXXXX";
    char manifest_path[512], poison_path[512], journal_path[512];
    char control_socket[512], config_path[512], log_path[512];
    char manifest_route_path[512], chunk_dir[512];
    char error[256] = {0};
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[2];
    struct wvm_block_service service;
    struct wvm_block_service_config service_config;
    struct service_ctx svc_ctx;
    pthread_t svc_thread;
    uint16_t gateway_port = 0, legacy_control = 0, tls_control = 0;
    uint16_t storage_port = 0, reply_port = 0;
    uint16_t storage_control_port = 0, reply_control_port = 0;
    int storage_fd = -1, reply_fd = -1, config_fd = -1;
    pid_t gateway = -1;
    uint8_t pattern[BYTES], payload[WVM_BLOCK_REQUEST_HEADER_BYTES + BYTES];
    uint8_t frame[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    uint8_t received[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    size_t payload_bytes = 0, frame_bytes = 0;
    struct wvm_envelope request, ack_env;
    struct wvm_block_request block_req;
    struct wvm_block_completion completion;
    const uint8_t *comp_data = NULL;
    size_t comp_data_bytes = 0;
    struct sockaddr_in gw_addr;
    struct pollfd pollfd;
    ssize_t received_bytes;
    int sender = -1;
    size_t i;
    int result = 1;
    int joined = 0;

    if (argc != 7) {
        fprintf(stderr,
                "usage: %s GATEWAY CA GW_CERT GW_KEY CTL_CERT CTL_KEY\n",
                argv[0]);
        return 2;
    }
    if (!mkdtemp(directory)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest", directory);
    snprintf(poison_path, sizeof(poison_path), "%s/poison.route", directory);
    snprintf(journal_path, sizeof(journal_path), "%s/routes.journal", directory);
    snprintf(control_socket, sizeof(control_socket), "%s/control.sock",
             directory);
    snprintf(config_path, sizeof(config_path), "%s/legacy.conf", directory);
    snprintf(log_path, sizeof(log_path), "%s/gateway.log", directory);
    snprintf(chunk_dir, sizeof(chunk_dir), "%s/chunks", directory);

    storage_fd = bind_udp(&storage_port);
    reply_fd = bind_udp(&reply_port);
    if (expect(storage_fd >= 0 && reply_fd >= 0, "bind storage/reply UDP") ||
        expect(reserve_udp(&gateway_port) == 0 &&
                   reserve_udp(&legacy_control) == 0 &&
                   reserve_tcp(&tls_control) == 0,
               "reserve gateway ports") ||
        ((storage_control_port = 10001), (reply_control_port = 10002), 0) ||
        finalize_snapshot(&snapshot, rules, acks, storage_port,
                          storage_control_port, reply_port, reply_control_port,
                          error, sizeof(error)) != 0 ||
        create_runtime_manifest(manifest_path, &snapshot.route_snapshot_key,
                                error, sizeof(error)) != 0 ||
        wvm_route_snapshot_path_from_manifest(manifest_path, manifest_route_path,
                                              sizeof(manifest_route_path), error,
                                              sizeof(error)) != 0 ||
        wvm_route_snapshot_file_publish(manifest_route_path, &snapshot, error,
                                        sizeof(error)) != 0 ||
        wvm_route_snapshot_file_publish(poison_path, &snapshot, error,
                                        sizeof(error)) != 0) {
        fprintf(stderr,
                "r02 fixture: %s (storage=%u/%u reply=%u/%u)\n", error,
                storage_port, storage_control_port, reply_port,
                reply_control_port);
        goto out;
    }
    config_fd = open(config_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (config_fd < 0)
        goto out;
    close(config_fd);
    config_fd = -1;

    if (wvm_block_chunk_store_set_dir(chunk_dir, error, sizeof(error)) != 0) {
        fprintf(stderr, "chunk root: %s\n", error);
        goto out;
    }
    memset(&service_config, 0, sizeof(service_config));
    service_config.vm_id = VM_ID;
    service_config.vm_incarnation = INCARNATION;
    service_config.manifest_generation = GENERATION;
    service_config.execute = execute_block;
    service_config.resolve_route = service_resolve;
    service_config.send_envelope = service_send;
    service_config.opaque = &svc_ctx;
    service_config.local_physical_node_id = 1;
    service_config.local_runtime_instance_id = 33;
    if (wvm_block_service_init(&service, &service_config, error,
                               sizeof(error)) != 0) {
        fprintf(stderr, "block service: %s\n", error);
        goto out;
    }
    svc_ctx.service = &service;
    svc_ctx.sock = storage_fd;
    svc_ctx.gateway_port = gateway_port;
    svc_ctx.stop = 0;
    if (pthread_create(&svc_thread, NULL, service_main, &svc_ctx) != 0)
        goto out;
    joined = 1;

    gateway = start_gateway(argv[1], manifest_path, poison_path, journal_path,
                            control_socket, config_path, log_path, gateway_port,
                            legacy_control, tls_control, argv[2], argv[3],
                            argv[4]);
    if (expect(gateway > 0, "fork wavevm_gateway") ||
        expect(wait_sock(control_socket) == 0, "gateway control socket"))
        goto out;
    /* Workers bind after the control socket; give RX a moment to come up. */
    sleep_ms(500);

    for (i = 0; i < BYTES; i++)
        pattern[i] = (uint8_t)(0x5a ^ i);
    memset(&block_req, 0, sizeof(block_req));
    block_req.payload_version = 1;
    block_req.operation = WVM_BLOCK_OPERATION_WRITE;
    block_req.flags = WVM_BLOCK_ORDER_FUA;
    block_req.lba_512 = 0;
    block_req.sector_count = SECTORS;
    block_req.payload_bytes = BYTES;
    block_req.reply_destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    block_req.reply_destination_scope = 0;
    block_req.reply_destination_vnode = REPLY_VNODE;
    block_req.queue_id = 1;
    block_req.queue_sequence = 1;
    block_req.device_index = DEVICE;
    if (wvm_block_request_encode(&block_req, pattern, BYTES, payload,
                                 sizeof(payload), &payload_bytes, error,
                                 sizeof(error)) != 0) {
        fprintf(stderr, "block encode: %s\n", error);
        goto out;
    }

    memset(&request, 0, sizeof(request));
    request.message_type = WVM_ENVELOPE_MSG_BLOCK_WRITE;
    request.vm_id = VM_ID;
    request.vm_incarnation = INCARNATION;
    request.manifest_generation = GENERATION;
    request.origin_physical_node_id = 3;
    request.origin_runtime_instance_id = 4;
    request.operation_id[15] = 0xB2;
    request.delivery_attempt_id = 1;
    request.route_scope_id =
        snapshot.route_snapshot_key.scope_key.route_scope_id;
    request.topology_revision = snapshot.route_snapshot_key.topology_revision;
    request.route_generation = snapshot.route_snapshot_key.route_generation;
    memcpy(request.route_snapshot_digest,
           snapshot.route_snapshot_key.snapshot_digest,
           sizeof(request.route_snapshot_digest));
    request.route.destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    request.route.destination_vnode_or_endpoint = STORAGE_VNODE;
    request.route.hop_limit = 4;
    request.payload = payload;
    request.payload_bytes = payload_bytes;
    if (wvm_envelope_encode(&request, WVM_ENVELOPE_TRANSPORT_NETWORK, frame,
                            sizeof(frame), &frame_bytes, error,
                            sizeof(error)) != 0) {
        fprintf(stderr, "envelope encode: %s\n", error);
        goto out;
    }

    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender < 0)
        goto out;
    memset(&gw_addr, 0, sizeof(gw_addr));
    gw_addr.sin_family = AF_INET;
    gw_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    gw_addr.sin_port = htons(gateway_port);
    if (sendto(sender, frame, frame_bytes, MSG_NOSIGNAL,
               (struct sockaddr *)&gw_addr, sizeof(gw_addr)) !=
        (ssize_t)frame_bytes) {
        fprintf(stderr, "sendto gateway failed\n");
        goto out;
    }

    pollfd.fd = reply_fd;
    pollfd.events = POLLIN;
    pollfd.revents = 0;
    if (poll(&pollfd, 1, 5000) != 1 || !(pollfd.revents & POLLIN)) {
        fprintf(stderr, "timeout waiting for BLOCK_ACK via gateway\n");
        goto out;
    }
    received_bytes = recv(reply_fd, received, sizeof(received), 0);
    if (received_bytes <= 0 ||
        wvm_envelope_decode(received, (size_t)received_bytes,
                            WVM_ENVELOPE_TRANSPORT_NETWORK, &ack_env, error,
                            sizeof(error)) != 0 ||
        ack_env.message_type != WVM_ENVELOPE_MSG_BLOCK_ACK ||
        ack_env.route.hop_count < 1) {
        fprintf(stderr, "gateway block ACK invalid: %s\n",
                error[0] ? error : "bad frame");
        goto out;
    }
    if (wvm_block_completion_decode(ack_env.payload, ack_env.payload_bytes,
                                    &completion, &comp_data, &comp_data_bytes,
                                    error, sizeof(error)) != 0 ||
        completion.status != WVM_BLOCK_WIRE_SUCCESS) {
        fprintf(stderr, "block completion status=%u err=%s\n",
                completion.status, error);
        goto out;
    }

    result = 0;
    puts("R02 gateway-process block E2E: PASS");

out:
    if (joined) {
        svc_ctx.stop = 1;
        pthread_join(svc_thread, NULL);
        wvm_block_service_destroy(&service);
    }
    stop_gateway(gateway);
    if (sender >= 0)
        close(sender);
    if (storage_fd >= 0)
        close(storage_fd);
    if (reply_fd >= 0)
        close(reply_fd);
    if (result != 0) {
        FILE *log = fopen(log_path, "r");
        char line[512];
        if (log) {
            fprintf(stderr, "--- gateway.log ---\n");
            while (fgets(line, sizeof(line), log))
                fputs(line, stderr);
            fclose(log);
        }
    }
    return result;
}

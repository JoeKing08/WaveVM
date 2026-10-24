/*
 * R1 production typed dispatch vertical slice:
 * admitted fractal route snapshot + live wavevm_gateway process +
 * typed V1 VCPU_RUN (WVM1 handoff) -> gateway_forward -> executor stub ->
 * typed VCPU_EXIT back through gateway.
 *
 * Proves fractal-through-gateway dataplane forward (not Hybrid UDP VCPU_RUN).
 * Guest OS/SSH remains goal §7. Short-exec CREATE smoke stays PASS_COMPONENT_SMOKE.
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

#include "wavevm_control.h"
#include "wavevm_manifest.h"
#include "wavevm_runtime_names.h"
#include "wavevm_identity.h"
#include "wavevm_sha256.h"
#include "wavevm_envelope.h"
#include "wavevm_route_delivery.h"
#include "wavevm_runtime_gate.h"
#include "wavevm_membership.h"
#include "wavevm_vcpu_handoff.h"
#include "wavevm_x86_context.h"
#include "wavevm_protocol.h"

#define VM_ID 802U
#define INCARNATION 66ULL
#define GENERATION 11ULL
#define EXECUTOR_VNODE 1U
#define REPLY_VNODE 2U
#define EXECUTOR_SCOPE 41ULL
#define REPLY_SCOPE 99ULL
#define FENCE_ID 0xF1CEULL
#define HANDOFF_SEQ 7ULL
#define VCPU_INDEX 0U

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "r1-production-dispatch: %s\n", msg);
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

static uint64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

struct udp_emit_ctx {
    int fd;
    struct sockaddr_in dest;
};

static int emit_udp_frame(void *opaque, const uint8_t *frame, size_t frame_bytes,
                          char *error, size_t error_len)
{
    struct udp_emit_ctx *ctx = opaque;
    if (sendto(ctx->fd, frame, frame_bytes, MSG_NOSIGNAL,
               (struct sockaddr *)&ctx->dest, sizeof(ctx->dest)) !=
        (ssize_t)frame_bytes) {
        snprintf(error, error_len, "UDP emit frame failed errno=%d", errno);
        return -1;
    }
    return 0;
}

static int recv_reassemble(int fd, struct wvm_envelope_reassembler *reassembler,
                           struct wvm_envelope_reassembled *out, int timeout_ms,
                           char *error, size_t error_len)
{
    uint8_t buf[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    int waited = 0;

    while (waited < timeout_ms) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        struct wvm_envelope frag;
        int slice = timeout_ms - waited;
        int rc;
        ssize_t n;

        if (slice > 100)
            slice = 100;
        if (poll(&p, 1, slice) != 1) {
            waited += slice;
            continue;
        }
        n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            waited += slice;
            continue;
        }
        memset(&frag, 0, sizeof(frag));
        if (wvm_envelope_decode(buf, (size_t)n, WVM_ENVELOPE_TRANSPORT_NETWORK,
                                &frag, error, error_len) != 0)
            continue;
        if ((frag.flags & WVM_ENVELOPE_FLAG_FRAGMENTED) == 0) {
            uint8_t *copy = NULL;
            memset(out, 0, sizeof(*out));
            out->envelope = frag;
            if (frag.payload_bytes != 0) {
                copy = malloc(frag.payload_bytes);
                if (!copy) {
                    snprintf(error, error_len, "oom unfragmented payload");
                    return -1;
                }
                memcpy(copy, frag.payload, frag.payload_bytes);
                out->payload = copy;
                out->payload_bytes = frag.payload_bytes;
                out->envelope.payload = copy;
            }
            return 0;
        }
        rc = wvm_envelope_reassembler_accept(reassembler, &frag, now_ms(), out,
                                             error, error_len);
        if (rc < 0)
            return -1;
        if (rc == 1)
            return 0;
        waited += slice;
    }
    snprintf(error, error_len, "timeout reassembling logical envelope");
    return -1;
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
                             uint16_t executor_port, uint16_t executor_control,
                             uint16_t reply_port, uint16_t reply_control,
                             char *error, size_t error_len)
{
    uint8_t encoded[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes = 0;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = VM_ID;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = INCARNATION;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 33;
    snapshot->route_snapshot_key.topology_revision = 11;
    snapshot->route_snapshot_key.route_generation = 4;
    snapshot->membership_revision = 3;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    memset(rules, 0, 2 * sizeof(*rules));
    /* Sorted by (kind, scope, vnode): scope 41 then 99. */
    rules[0].destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rules[0].destination_scope = EXECUTOR_SCOPE;
    rules[0].destination_vnode_or_endpoint = EXECUTOR_VNODE;
    rules[0].next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rules[0].next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rules[0].next_hop_member.role_id = 1;
    rules[0].next_hop_member.instance_id = 101;
    fill_endpoint(&rules[0].next_hop_endpoint, executor_port, executor_control);
    rules[0].hop_limit = 4;

    rules[1].destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rules[1].destination_scope = REPLY_SCOPE;
    rules[1].destination_vnode_or_endpoint = REPLY_VNODE;
    rules[1].next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rules[1].next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rules[1].next_hop_member.role_id = 2;
    rules[1].next_hop_member.instance_id = 202;
    fill_endpoint(&rules[1].next_hop_endpoint, reply_port, reply_control);
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

struct executor_ctx {
    int sock;
    uint16_t gateway_port;
    volatile int stop;
    volatile int run_seen;
    volatile uint16_t inbound_hop_count;
    volatile uint64_t seen_fence_id;
};

static void *executor_main(void *opaque)
{
    struct executor_ctx *ctx = opaque;
    struct wvm_envelope_reassembler reassembler;
    struct wvm_envelope_reassembled completed;
    uint8_t payload[WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES +
                    WVM_X86_CONTEXT_WIRE_HEADER_BYTES + sizeof(wvm_tcg_context_t)];
    uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES + sizeof(wvm_tcg_context_t)];
    char error[192];
    wvm_tcg_context_t legacy;
    size_t context_bytes = 0;
    struct udp_emit_ctx emit;

    if (wvm_envelope_reassembler_init(&reassembler) != 0) {
        fprintf(stderr, "executor reassembler init failed\n");
        return NULL;
    }
    memset(&legacy, 0, sizeof(legacy));
    legacy.eip = UINT64_C(0xCAFEBABEDEADBEEF);
    if (wvm_x86_context_encode(
            WVM_VCPU_BACKEND_TCG,
            WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
            &legacy, sizeof(legacy), context, sizeof(context), &context_bytes,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "executor context encode: %s\n", error);
        wvm_envelope_reassembler_destroy(&reassembler);
        return NULL;
    }

    memset(&emit, 0, sizeof(emit));
    emit.fd = ctx->sock;
    emit.dest.sin_family = AF_INET;
    emit.dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    emit.dest.sin_port = htons(ctx->gateway_port);

    while (!ctx->stop) {
        struct wvm_vcpu_handoff_request request;
        struct wvm_vcpu_handoff_result result;
        struct wvm_envelope_route reply_route;
        struct wvm_envelope exit_env;
        size_t payload_bytes = 0;
        struct wvm_envelope run_env;

        memset(&completed, 0, sizeof(completed));
        if (recv_reassemble(ctx->sock, &reassembler, &completed, 200, error,
                            sizeof(error)) != 0) {
            if (ctx->stop)
                break;
            continue;
        }
        run_env = completed.envelope;
        if (run_env.message_type != WVM_ENVELOPE_MSG_VCPU_RUN) {
            wvm_envelope_reassembled_release(&completed);
            continue;
        }
        if (wvm_vcpu_handoff_request_decode(run_env.payload, run_env.payload_bytes,
                                            &request, error,
                                            sizeof(error)) != 0) {
            fprintf(stderr, "executor decode RUN: %s\n", error);
            wvm_envelope_reassembled_release(&completed);
            continue;
        }
        if (wvm_vcpu_handoff_request_validate_envelope(&request, &run_env, error,
                                                       sizeof(error)) != 0) {
            fprintf(stderr, "executor validate RUN: %s\n", error);
            wvm_envelope_reassembled_release(&completed);
            continue;
        }
        ctx->run_seen = 1;
        ctx->inbound_hop_count = run_env.route.hop_count;
        ctx->seen_fence_id = request.memory_fence_id;

        memset(&result, 0, sizeof(result));
        result.protocol_version = WVM_VCPU_HANDOFF_RESULT_VERSION;
        result.status = WVM_VCPU_HANDOFF_RESULT_SUCCESS;
        result.exit_class = WVM_VCPU_EXIT_HALTED;
        result.backend = request.backend;
        result.vm_id = request.vm_id;
        result.origin_physical_node_id = request.origin_physical_node_id;
        result.vcpu_index = request.vcpu_index;
        result.vm_incarnation = request.vm_incarnation;
        result.manifest_generation = request.manifest_generation;
        result.origin_runtime_instance_id = request.origin_runtime_instance_id;
        result.handoff_sequence = request.handoff_sequence;
        result.produced_memory_fence_id = request.memory_fence_id;
        result.remote_interrupt_watermark = request.local_interrupt_watermark;
        result.remote_device_watermark = request.device_event_watermark;
        memcpy(result.operation_id, request.operation_id,
               sizeof(result.operation_id));
        result.context_schema_version = request.context_schema_version;
        result.context_valid_fields = request.context_valid_fields;
        result.context = context;
        result.context_bytes = context_bytes;

        memset(&reply_route, 0, sizeof(reply_route));
        reply_route.destination_kind = request.reply_destination_kind;
        reply_route.destination_scope = request.reply_destination_scope;
        reply_route.destination_vnode_or_endpoint =
            request.reply_destination_vnode;
        reply_route.hop_limit = 4;
        reply_route.hop_count = 0;

        if (wvm_vcpu_handoff_exit_envelope_build(
                &run_env, &request, &reply_route, 1, &result, payload,
                sizeof(payload), &payload_bytes, &exit_env, error,
                sizeof(error)) != 0) {
            fprintf(stderr, "executor build EXIT: %s\n", error);
            wvm_envelope_reassembled_release(&completed);
            continue;
        }
        wvm_envelope_reassembled_release(&completed);
        if (wvm_envelope_emit_network_frames(&exit_env, emit_udp_frame, &emit,
                                             error, sizeof(error)) != 0) {
            fprintf(stderr, "executor emit EXIT frames: %s\n", error);
            continue;
        }
        ctx->stop = 1;
        break;
    }
    wvm_envelope_reassembler_destroy(&reassembler);
    return NULL;
}

int main(int argc, char **argv)
{
    char directory[] = "/tmp/wavevm-r1-gw-dispatch.XXXXXX";
    char manifest_path[512], poison_path[512], journal_path[512];
    char control_socket[512], config_path[512], log_path[512];
    char manifest_route_path[512];
    char error[256] = {0};
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[2];
    struct executor_ctx exec_ctx;
    pthread_t exec_thread;
    uint16_t gateway_port = 0, legacy_control = 0, tls_control = 0;
    uint16_t executor_port = 0, reply_port = 0;
    uint16_t executor_control = 0, reply_control = 0;
    int executor_fd = -1, reply_fd = -1, config_fd = -1, sender = -1;
    pid_t gateway = -1;
    uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES + sizeof(wvm_tcg_context_t)];
    uint8_t payload[WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES +
                    WVM_X86_CONTEXT_WIRE_HEADER_BYTES + sizeof(wvm_tcg_context_t)];
    size_t context_bytes = 0, payload_bytes = 0;
    wvm_tcg_context_t legacy;
    struct wvm_vcpu_handoff_request request;
    struct wvm_vcpu_handoff_result result;
    struct wvm_envelope run_env;
    struct wvm_envelope_reassembler reply_reassembler;
    struct wvm_envelope_reassembled reply_completed;
    struct udp_emit_ctx emit;
    int reply_reassembler_ready = 0;
    int joined = 0;
    int result_code = 1;

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

    executor_fd = bind_udp(&executor_port);
    reply_fd = bind_udp(&reply_port);
    if (expect(executor_fd >= 0 && reply_fd >= 0, "bind executor/reply UDP") ||
        expect(reserve_udp(&gateway_port) == 0 &&
                   reserve_udp(&legacy_control) == 0 &&
                   reserve_tcp(&tls_control) == 0,
               "reserve gateway ports") ||
        ((executor_control = 10011), (reply_control = 10012), 0) ||
        finalize_snapshot(&snapshot, rules, acks, executor_port,
                          executor_control, reply_port, reply_control, error,
                          sizeof(error)) != 0 ||
        create_runtime_manifest(manifest_path, &snapshot.route_snapshot_key,
                                error, sizeof(error)) != 0 ||
        wvm_route_snapshot_path_from_manifest(manifest_path, manifest_route_path,
                                              sizeof(manifest_route_path), error,
                                              sizeof(error)) != 0 ||
        wvm_route_snapshot_file_publish(manifest_route_path, &snapshot, error,
                                        sizeof(error)) != 0 ||
        wvm_route_snapshot_file_publish(poison_path, &snapshot, error,
                                        sizeof(error)) != 0) {
        fprintf(stderr, "r1 fixture: %s\n", error);
        goto out;
    }
    config_fd = open(config_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (config_fd < 0)
        goto out;
    close(config_fd);
    config_fd = -1;

    memset(&exec_ctx, 0, sizeof(exec_ctx));
    exec_ctx.sock = executor_fd;
    exec_ctx.gateway_port = gateway_port;
    if (pthread_create(&exec_thread, NULL, executor_main, &exec_ctx) != 0)
        goto out;
    joined = 1;

    gateway = start_gateway(argv[1], manifest_path, poison_path, journal_path,
                            control_socket, config_path, log_path, gateway_port,
                            legacy_control, tls_control, argv[2], argv[3],
                            argv[4]);
    if (expect(gateway > 0, "fork wavevm_gateway") ||
        expect(wait_sock(control_socket) == 0, "gateway control socket"))
        goto out;
    sleep_ms(500);

    memset(&legacy, 0, sizeof(legacy));
    legacy.eip = UINT64_C(0x1122334455667788);
    if (wvm_x86_context_encode(
            WVM_VCPU_BACKEND_TCG,
            WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
            &legacy, sizeof(legacy), context, sizeof(context), &context_bytes,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "context encode: %s\n", error);
        goto out;
    }

    memset(&request, 0, sizeof(request));
    request.protocol_version = WVM_VCPU_HANDOFF_REQUEST_VERSION;
    request.backend = WVM_VCPU_BACKEND_TCG;
    request.context_schema_version = WVM_VCPU_CONTEXT_SCHEMA_X86;
    request.memory_fence_result = WVM_VCPU_MEMORY_FENCE_SUCCEEDED;
    request.vm_id = VM_ID;
    request.vm_incarnation = INCARNATION;
    request.manifest_generation = GENERATION;
    request.origin_physical_node_id = 18;
    request.origin_runtime_instance_id = 202;
    request.vcpu_index = VCPU_INDEX;
    request.destination_executor_id = EXECUTOR_VNODE;
    request.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    request.reply_destination_scope = REPLY_SCOPE;
    request.reply_destination_vnode = REPLY_VNODE;
    request.handoff_sequence = HANDOFF_SEQ;
    request.memory_fence_id = FENCE_ID;
    request.local_interrupt_watermark = 1;
    request.device_event_watermark = 1;
    request.operation_id[15] = 0xA1;
    request.context_valid_fields =
        WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
        WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE;
    request.context = context;
    request.context_bytes = context_bytes;
    if (wvm_vcpu_handoff_request_encode(&request, payload, sizeof(payload),
                                        &payload_bytes, error,
                                        sizeof(error)) != 0) {
        fprintf(stderr, "handoff encode: %s\n", error);
        goto out;
    }

    memset(&run_env, 0, sizeof(run_env));
    run_env.message_type = WVM_ENVELOPE_MSG_VCPU_RUN;
    run_env.vm_id = VM_ID;
    run_env.vm_incarnation = INCARNATION;
    run_env.manifest_generation = GENERATION;
    run_env.origin_physical_node_id = request.origin_physical_node_id;
    run_env.origin_runtime_instance_id = request.origin_runtime_instance_id;
    memcpy(run_env.operation_id, request.operation_id,
           sizeof(run_env.operation_id));
    run_env.delivery_attempt_id = 1;
    run_env.route_scope_id =
        snapshot.route_snapshot_key.scope_key.route_scope_id;
    run_env.topology_revision = snapshot.route_snapshot_key.topology_revision;
    run_env.route_generation = snapshot.route_snapshot_key.route_generation;
    memcpy(run_env.route_snapshot_digest,
           snapshot.route_snapshot_key.snapshot_digest,
           sizeof(run_env.route_snapshot_digest));
    run_env.route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    run_env.route.destination_scope = EXECUTOR_SCOPE;
    run_env.route.destination_vnode_or_endpoint = EXECUTOR_VNODE;
    run_env.route.hop_limit = 4;
    run_env.payload = payload;
    run_env.payload_bytes = payload_bytes;
    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender < 0)
        goto out;
    memset(&emit, 0, sizeof(emit));
    emit.fd = sender;
    emit.dest.sin_family = AF_INET;
    emit.dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    emit.dest.sin_port = htons(gateway_port);
    if (wvm_envelope_emit_network_frames(&run_env, emit_udp_frame, &emit, error,
                                         sizeof(error)) != 0) {
        fprintf(stderr, "emit RUN frames: %s\n", error);
        goto out;
    }

    if (wvm_envelope_reassembler_init(&reply_reassembler) != 0) {
        fprintf(stderr, "reply reassembler init failed\n");
        goto out;
    }
    reply_reassembler_ready = 1;
    memset(&reply_completed, 0, sizeof(reply_completed));
    if (recv_reassemble(reply_fd, &reply_reassembler, &reply_completed, 5000,
                        error, sizeof(error)) != 0) {
        fprintf(stderr, "timeout/reassemble VCPU_EXIT via gateway: %s\n",
                error);
        goto out;
    }
    if (reply_completed.envelope.message_type != WVM_ENVELOPE_MSG_VCPU_EXIT ||
        reply_completed.envelope.route.hop_count < 1 ||
        reply_completed.envelope.route.destination_kind !=
            WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE ||
        reply_completed.envelope.route.destination_scope != REPLY_SCOPE ||
        reply_completed.envelope.route.destination_vnode_or_endpoint !=
            REPLY_VNODE) {
        fprintf(stderr, "gateway VCPU_EXIT invalid hop=%u kind=%u scope=%llu\n",
                (unsigned)reply_completed.envelope.route.hop_count,
                (unsigned)reply_completed.envelope.route.destination_kind,
                (unsigned long long)reply_completed.envelope.route
                    .destination_scope);
        goto out;
    }
    if (wvm_vcpu_handoff_result_decode(reply_completed.payload,
                                       reply_completed.payload_bytes, &result,
                                       error, sizeof(error)) != 0 ||
        wvm_vcpu_handoff_result_validate_request(&request, &result, error,
                                                 sizeof(error)) != 0 ||
        result.status != WVM_VCPU_HANDOFF_RESULT_SUCCESS ||
        result.produced_memory_fence_id != FENCE_ID) {
        fprintf(stderr, "handoff EXIT mismatch: %s status=%u fence=%llu\n",
                error, (unsigned)result.status,
                (unsigned long long)result.produced_memory_fence_id);
        goto out;
    }
    if (expect(exec_ctx.run_seen == 1, "executor saw VCPU_RUN") ||
        expect(exec_ctx.inbound_hop_count >= 1,
               "executor inbound hop_count advanced by gateway") ||
        expect(exec_ctx.seen_fence_id == FENCE_ID,
               "executor observed memory_fence_id"))
        goto out;

    result_code = 0;
    printf("R1 production typed dispatch gateway E2E: PASS\n");
    printf("  path=admitted_fractal_snapshot->WVM1_VCPU_RUN->gateway_forward"
           "->executor->WVM1_VCPU_EXIT\n");
    printf("  topology=FRACTAL executor_scope=%llu reply_scope=%llu\n",
           (unsigned long long)EXECUTOR_SCOPE,
           (unsigned long long)REPLY_SCOPE);
    printf("  inbound_hop_count=%u exit_hop_count=%u fence_id=0x%llx\n",
           (unsigned)exec_ctx.inbound_hop_count,
           (unsigned)reply_completed.envelope.route.hop_count,
           (unsigned long long)FENCE_ID);

out:
    if (joined) {
        exec_ctx.stop = 1;
        pthread_join(exec_thread, NULL);
    }
    stop_gateway(gateway);
    if (reply_reassembler_ready) {
        wvm_envelope_reassembled_release(&reply_completed);
        wvm_envelope_reassembler_destroy(&reply_reassembler);
    }
    if (sender >= 0)
        close(sender);
    if (executor_fd >= 0)
        close(executor_fd);
    if (reply_fd >= 0)
        close(reply_fd);
    if (result_code != 0) {
        FILE *log = fopen(log_path, "r");
        char line[512];
        if (log) {
            fprintf(stderr, "--- gateway.log ---\n");
            while (fgets(line, sizeof(line), log))
                fputs(line, stderr);
            fclose(log);
        }
    }
    return result_code;
}

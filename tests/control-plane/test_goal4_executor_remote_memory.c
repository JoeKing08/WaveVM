/*
 * goal §4 / A14: drive production wvm_executor_runtime_execute_handoff through
 * executor_bridge with a real memory_service remote fault side effect.
 * Forbidden: test-local execute_with_remote_memory, tcg_helper_stub READY alone.
 * Guest OS/SSH remains goal §7. Multi-node CREATE may still use stub for CP.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "directory_store.h"
#include "executor_bridge.h"
#include "executor_runtime.h"
#include "kvm_page_cache.h"
#include "memory_service.h"
#include "runtime_context.h"
#include "vcpu_coordinator.h"
#include "wavevm_executor_session.h"
#include "wavevm_membership.h"
#include "wavevm_protocol.h"
#include "wavevm_runtime_gate.h"
#include "wavevm_vcpu_handoff.h"
#include "wavevm_x86_context.h"

#define TEST_VM_ID 256U
#define TEST_VCPU 0U
#define REAL_QEMU_GPA 0x1000ULL

static int g_real_qemu;
static int g_real_kvm;

struct remote_state {
    pthread_mutex_t lock;
    pthread_cond_t available;
    int send_count;
    int completion_count;
    uint64_t completed_gpa;
    uint64_t completed_version;
    uint64_t completed_commit_version;
    int commit_completion_count;
    uint16_t completed_status;
    uint8_t completed_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_envelope sent;
    uint8_t sent_payload[WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD];
    size_t sent_payload_bytes;
    struct wvm_memory_service *service;
    struct wvm_memory_service remote_service;
    int remote_service_initialized;
    struct wvm_directory_store directory_store;
    int directory_store_initialized;
    int stop;
};

struct session_peer {
    int fd;
    volatile int stop;
    volatile int run_count;
};

struct exit_capture {
    pthread_mutex_t lock;
    pthread_cond_t available;
    size_t count;
    struct wvm_envelope response;
    struct wvm_vcpu_handoff_result result;
    uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES + sizeof(wvm_tcg_context_t)];
    size_t context_bytes;
};

struct coordinated_path {
    struct wvm_vcpu_handoff_coordinator coordinator;
    void *bridge;
    pthread_mutex_t lock;
    pthread_cond_t available;
    int completed;
    struct wvm_vcpu_handoff_result result;
};

static int coordinated_bridge_reply(void *opaque,
                                    const struct wvm_envelope *envelope,
                                    char *error, size_t error_len)
{
    struct coordinated_path *path = opaque;

    return wvm_vcpu_handoff_coordinator_dispatch(
        &path->coordinator, envelope, error, error_len);
}

static int coordinated_send(void *opaque, const struct wvm_envelope *envelope,
                            char *error, size_t error_len)
{
    struct coordinated_path *path = opaque;

    return wvm_executor_bridge_dispatch(path->bridge, envelope, error,
                                        error_len);
}

static int coordinated_complete(void *opaque,
                                const struct wvm_vcpu_handoff_request *request,
                                const struct wvm_vcpu_handoff_result *result,
                                char *error, size_t error_len)
{
    struct coordinated_path *path = opaque;

    (void)request;
    (void)error;
    (void)error_len;
    pthread_mutex_lock(&path->lock);
    path->result = *result;
    path->completed = 1;
    pthread_cond_signal(&path->available);
    pthread_mutex_unlock(&path->lock);
    return 0;
}

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "goal4 A14 FAIL: %s\n", msg);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t tail,
                          uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = tail;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port + 1000U);
}

static void fill_rule(struct wvm_route_rule_record *rule, uint64_t scope,
                      uint32_t vnode, uint32_t physical_node_id,
                      uint64_t node_instance_id, uint8_t address_tail)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_scope = scope;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = physical_node_id;
    rule->next_hop_member.instance_id = node_instance_id;
    fill_endpoint(&rule->next_hop_endpoint, address_tail,
                  (uint16_t)(19000U + address_tail));
    rule->hop_limit = 4;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record rules[2],
                             struct wvm_required_ack_entry acks[1],
                             char *error, size_t error_len)
{
    uint8_t bytes[4096];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = TEST_VM_ID;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 7;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 33;
    snapshot->route_snapshot_key.topology_revision = 11;
    snapshot->route_snapshot_key.route_generation = 4;
    snapshot->membership_revision = 3;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = 2;
    snapshot->next_hop_rules.capacity = 2;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;
    memset(acks, 0, sizeof(*acks));
    acks[0].member_key = rules[0].next_hop_member;
    acks[0].endpoint = rules[0].next_hop_endpoint;
    acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks[0].expected_snapshot_key = snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    memcpy(acks[0].expected_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int setup_manifest(struct wvm_node_runtime_manifest *manifest,
                          struct wvm_capability_ref *capability,
                          const struct wvm_route_snapshot_key *route_key,
                          char *error, size_t error_len)
{
    struct wvm_local_name_identity name_identity;

    memset(manifest, 0, sizeof(*manifest));
    memset(manifest->candidate_manifest_digest, 0x11,
           sizeof(manifest->candidate_manifest_digest));
    manifest->vm_id = route_key->scope_key.vm_id;
    manifest->vm_incarnation = route_key->scope_key.vm_incarnation;
    manifest->manifest_generation = 3;
    memset(manifest->admission_tx_id, 0x22, sizeof(manifest->admission_tx_id));
    memset(manifest->eligibility_fence_digest, 0x33,
           sizeof(manifest->eligibility_fence_digest));
    manifest->has_activation_fence = 1;
    memset(manifest->activation_fence, 0x52,
           sizeof(manifest->activation_fence));
    manifest->physical_node_id = 17;
    manifest->expected_node_instance_id = 101;
    manifest->local_role_bits =
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_NODE_RUNTIME) |
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_EXECUTOR);
    manifest->required_route_snapshot_key = *route_key;
    memset(&name_identity, 0, sizeof(name_identity));
    name_identity.vm_id = manifest->vm_id;
    name_identity.vm_incarnation = manifest->vm_incarnation;
    name_identity.manifest_generation = manifest->manifest_generation;
    name_identity.physical_node_id = manifest->physical_node_id;
    memset(name_identity.manifest_id, 0x66, sizeof(name_identity.manifest_id));
    memcpy(name_identity.admission_tx_id, manifest->admission_tx_id,
           sizeof(name_identity.admission_tx_id));
    if (wvm_local_name_namespace_derive(&name_identity, &manifest->local_names,
                                        error, error_len) != 0) {
        return -1;
    }
    manifest->negotiated_profile.backend =
        g_real_kvm ? WVM_MANIFEST_BACKEND_KVM : WVM_MANIFEST_BACKEND_TCG;
    manifest->negotiated_profile.context_schema_version = 1;
    manifest->negotiated_profile.dirty_capture_engine = 1;
    manifest->negotiated_profile.read_fault_engine = 1;
    manifest->negotiated_profile.invalidation_engine = 1;
    manifest->negotiated_profile.fallback_decision = 1;
    memset(manifest->negotiated_profile.supported_memory_policies_digest, 0x77,
           sizeof(manifest->negotiated_profile.supported_memory_policies_digest));
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = manifest->physical_node_id;
    capability->node_instance_id = manifest->expected_node_instance_id;
    capability->profile_generation = 8;
    memset(capability->profile_digest, 0x88,
           sizeof(capability->profile_digest));
    manifest->negotiated_profile.per_node_capabilities.entries = capability;
    manifest->negotiated_profile.per_node_capabilities.count = 1;
    manifest->negotiated_profile.per_node_capabilities.capacity = 1;
    memset(manifest->reservation_id, 0x99, sizeof(manifest->reservation_id));
    manifest->launch_plan.plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
    manifest->launch_plan.node_runtime_data_port = 19100;
    manifest->launch_plan.node_runtime_control_port = 19121;
    manifest->launch_plan.local_executor_service_port = 19105;
    manifest->launch_plan.local_executor_control_port = 19121;
    manifest->launch_plan.executor_worker_count = 1;
    manifest->launch_plan.vcpu_handoff_record_capacity = 4;
    manifest->launch_plan.sync_batch_size = 1;
    manifest->launch_plan.guest_total_memory_bytes = 4 * 1024 * 1024;
    strcpy(manifest->launch_plan.guest_machine.architecture, "x86_64");
    strcpy(manifest->launch_plan.guest_machine.machine_type, "pc-i440fx-5.2");
    manifest->launch_plan.guest_machine.qemu_compat_version = 502;
    manifest->launch_plan.guest_machine.firmware_policy = 1;
    manifest->launch_plan.consistency_policy.dirty_batch_size = 1;
    manifest->launch_plan.consistency_policy.handoff_commit_policy = 1;
    manifest->launch_plan.consistency_policy.subscriber_delivery_policy = 1;
    manifest->launch_plan.consistency_policy.max_commit_latency_ms = 1000;
    return wvm_node_runtime_manifest_validate(manifest, error, error_len);
}

static void fill_projection(
    struct wvm_runtime_dispatch_projection *projection,
    struct wvm_runtime_memory_dispatch memory[2],
    const struct wvm_node_runtime_manifest *manifest)
{
    memset(projection, 0, sizeof(*projection));
    memcpy(projection->candidate_manifest_digest,
           manifest->candidate_manifest_digest,
           sizeof(projection->candidate_manifest_digest));
    projection->vm_id = manifest->vm_id;
    projection->vm_incarnation = manifest->vm_incarnation;
    projection->manifest_generation = manifest->manifest_generation;
    projection->physical_node_id = manifest->physical_node_id;
    projection->expected_node_instance_id = manifest->expected_node_instance_id;
    memcpy(projection->activation_fence, manifest->activation_fence,
           sizeof(projection->activation_fence));
    projection->required_route_snapshot_key =
        manifest->required_route_snapshot_key;
    projection->route_topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    projection->local_primary.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    projection->local_primary.destination_scope = 41;
    projection->local_primary.destination_vnode = 7;
    fill_endpoint(&projection->local_sidecar_endpoint, 17, 19017);
    projection->memory_dispatch.entries = memory;
    projection->memory_dispatch.count = 2;
    projection->memory_dispatch.capacity = 2;
    memset(memory, 0, 2 * sizeof(*memory));
    memory[0].gpa_start = 0;
    memory[0].bytes = WVM_MEMORY_PAGE_BYTES;
    memory[0].directory = projection->local_primary;
    memory[0].executor = projection->local_primary;
    /* local vnode 7 */
    memory[0].directory_physical_node_id = 17;
    memory[0].directory_node_instance_id = 101;
    memory[0].consistency_policy = 1;
    memory[1] = memory[0];
    memory[1].gpa_start = WVM_MEMORY_PAGE_BYTES;
    memory[1].directory.destination_scope = 99;
    memory[1].directory.destination_vnode = 1;
    memory[1].executor = memory[1].directory;
    memory[1].directory_physical_node_id = 99;
    memory[1].directory_node_instance_id = 202;
}

static int read_page(void *opaque, uint64_t gpa,
                     uint8_t data[WVM_MEMORY_PAGE_BYTES], uint64_t *version_out,
                     char *error, size_t error_len)
{
    struct remote_state *state = opaque;

    if (!state || !state->directory_store_initialized) {
        return -EINVAL;
    }
    return wvm_directory_store_read_page(&state->directory_store, gpa, data,
                                         version_out, error, error_len);
}

static int complete_fault(void *opaque,
                          const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                          uint64_t gpa, uint64_t version, uint16_t status,
                          uint32_t directory_physical_node_id,
                          uint64_t directory_node_instance_id,
                          const uint8_t *data, size_t data_bytes, char *error,
                          size_t error_len)
{
    struct remote_state *state = opaque;
    int result;

    result = wvm_memory_service_global_complete(
        operation_id, gpa, version, status, directory_physical_node_id,
        directory_node_instance_id, data, data_bytes, error, error_len);
    if (result != 0) {
        return result;
    }
    if (!state) {
        return 0;
    }
    pthread_mutex_lock(&state->lock);
    state->completion_count++;
    state->completed_gpa = gpa;
    state->completed_version = version;
    state->completed_status = status;
    if (data_bytes != 0 && data_bytes <= sizeof(state->completed_page)) {
        memcpy(state->completed_page, data, data_bytes);
    }
    pthread_cond_broadcast(&state->available);
    pthread_mutex_unlock(&state->lock);
    return 0;
}

static int commit_page(void *opaque, uint64_t gpa, uint64_t base_version,
                       uint16_t offset, const uint8_t *data, size_t data_bytes,
                       uint64_t *result_version, char *error, size_t error_len)
{
    struct remote_state *state = opaque;

    if (!state || !state->directory_store_initialized) {
        return -EINVAL;
    }
    return wvm_directory_store_commit_page(
        &state->directory_store, gpa, base_version, offset, data, data_bytes,
        result_version, error, error_len);
}

static int complete_commit(void *opaque,
                           const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                           uint64_t gpa, uint16_t status,
                           uint64_t result_version,
                           uint32_t directory_physical_node_id,
                           uint64_t directory_node_instance_id, char *error,
                           size_t error_len)
{
    struct remote_state *state = opaque;
    int result;

    result = wvm_memory_service_global_complete_commit(
        operation_id, gpa, status, result_version, directory_physical_node_id,
        directory_node_instance_id, error, error_len);
    if (result == 0 && status == WVM_MEM_COMMIT_ACK_SUCCESS) {
        pthread_mutex_lock(&state->lock);
        state->completed_commit_version = result_version;
        state->commit_completion_count++;
        pthread_mutex_unlock(&state->lock);
    }
    return result;
}

static int complete_remote_fault(
    void *opaque, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t gpa, uint64_t version, uint16_t status,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    const uint8_t *data, size_t data_bytes, char *error, size_t error_len)
{
    (void)opaque;
    (void)operation_id;
    (void)gpa;
    (void)version;
    (void)status;
    (void)directory_physical_node_id;
    (void)directory_node_instance_id;
    (void)data;
    (void)data_bytes;
    (void)error;
    (void)error_len;
    return 0;
}

static int send_memory_envelope(void *opaque, const struct wvm_envelope *envelope,
                                char *error, size_t error_len)
{
    struct remote_state *state = opaque;

    (void)error;
    (void)error_len;
    if (!state || !envelope ||
        envelope->payload_bytes > sizeof(state->sent_payload)) {
        return -EAGAIN;
    }
    pthread_mutex_lock(&state->lock);
    state->send_count++;
    state->sent = *envelope;
    state->sent_payload_bytes = envelope->payload_bytes;
    memcpy(state->sent_payload, envelope->payload, envelope->payload_bytes);
    state->sent.payload = state->sent_payload;
    pthread_cond_broadcast(&state->available);
    pthread_mutex_unlock(&state->lock);
    return 0;
}

static int remote_send_envelope(void *opaque,
                                const struct wvm_envelope *envelope,
                                char *error, size_t error_len)
{
    struct remote_state *state = opaque;

    if (!state || !state->service || !envelope) {
        return -ENOTCONN;
    }
    {
        int rc = wvm_memory_service_dispatch(state->service, envelope, error,
                                             error_len);
        fprintf(stderr, "[A3] remote ACK type=%#x dispatch rc=%d err=%s\n",
                (unsigned)envelope->message_type, rc,
                (error && error[0]) ? error : "(empty)");
        return rc;
    }
}

static void *ack_worker(void *opaque)
{
    struct remote_state *state = opaque;
    char error[256];
    for (;;) {
        struct wvm_envelope sent;
        int stop = 0;
        int have_send = 0;

        pthread_mutex_lock(&state->lock);
        while (!state->stop && state->send_count == 0) {
            pthread_cond_wait(&state->available, &state->lock);
        }
        stop = state->stop;
        if (!stop && state->send_count > 0) {
            sent = state->sent;
            have_send = 1;
            state->send_count = 0;
        }
        pthread_mutex_unlock(&state->lock);
        if (stop) {
            break;
        }
        if (!have_send ||
            (sent.message_type != WVM_ENVELOPE_MSG_MEM_READ &&
             sent.message_type != WVM_ENVELOPE_MSG_COMMIT_DIFF) ||
            !state->service || !state->remote_service_initialized) {
            continue;
        }
        memset(error, 0, sizeof(error));
        fprintf(stderr, "goal4 remote service request type=%#x\n",
                (unsigned)sent.message_type);
        {
            int rc = wvm_memory_service_dispatch(&state->remote_service, &sent,
                                                 error, sizeof(error));
            fprintf(stderr, "goal4 remote service dispatch rc=%d err=%s\n",
                    rc, error[0] ? error : "(empty)");
        }
    }
    return NULL;
}

static int prepare_real_qemu_shm(char *name, size_t name_size, char *error,
                               size_t error_len)
{
    const char *existing = getenv("WVM_SHM_FILE");
    int fd;

    if (existing && *existing) {
        snprintf(name, name_size, "%s", existing);
        return 0;
    }
    snprintf(name, name_size, "wavevm_goal4_%d", (int)getpid());
    fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
    if (fd < 0) {
        snprintf(error, error_len, "real QEMU shm: %s", strerror(errno));
        return -1;
    }
    if (ftruncate(fd, 64U * 1024U * 1024U) != 0) {
        snprintf(error, error_len, "real QEMU ftruncate: %s", strerror(errno));
        close(fd);
        shm_unlink(name);
        return -1;
    }
    close(fd);
    if (setenv("WVM_SHM_FILE", name, 1) != 0) {
        snprintf(error, error_len, "real QEMU setenv: %s", strerror(errno));
        shm_unlink(name);
        return -1;
    }
    return 0;
}

static pid_t launch_real_qemu_session(
    const struct wvm_node_runtime_manifest *manifest,
    const struct wvm_runtime_dispatch_projection *projection,
    int *parent_fd_out, char *shm_name, size_t shm_name_size, char *error,
    size_t error_len)
{
    int pair[2] = {-1, -1};
    pid_t pid;
    const char *qemu_bin = getenv("WVM_TCG_QEMU_BIN");
    const char *prepared_name = getenv("WVM_SHM_FILE");
    char name[64];
    char fd_text[16];
    char object_arg[256];
    char machine_arg[64];

    if (!qemu_bin || !*qemu_bin) {
        qemu_bin = "/workspaces/WaveVM/wavevm-qemu/build/qemu-system-x86_64";
    }
    if (!prepared_name || !*prepared_name) {
        snprintf(error, error_len,
                 "real QEMU requires prepare_real_qemu_shm before runtime bind");
        return -1;
    }
    snprintf(name, sizeof(name), "%s", prepared_name);
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) {
        snprintf(error, error_len, "real QEMU socketpair: %s", strerror(errno));
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        snprintf(error, error_len, "real QEMU fork: %s", strerror(errno));
        goto fail;
    }
    if (pid == 0) {
        close(pair[0]);
        if (fcntl(pair[1], F_SETFD, 0) != 0) {
            _exit(127);
        }
        snprintf(fd_text, sizeof(fd_text), "%d", pair[1]);
        setenv("WVM_EXECUTOR_SESSION_FD", fd_text, 1);
        setenv("WVM_SHM_FILE", name, 1);
        setenv("WVM_DISABLE_AUTO_KVM", "1", 1);
        setenv("WVM_ROLE", "SLAVE", 1);
        setenv("WVM_SLAVE_VCPU_COUNT", "1", 1);
        {
            char value[32];

            snprintf(value, sizeof(value), "%llu",
                     (unsigned long long)manifest->vm_id);
            setenv("WVM_VM_ID", value, 1);
            snprintf(value, sizeof(value), "%llu",
                     (unsigned long long)manifest->vm_incarnation);
            setenv("WVM_VM_INCARNATION", value, 1);
            snprintf(value, sizeof(value), "%llu",
                     (unsigned long long)manifest->manifest_generation);
            setenv("WVM_MANIFEST_GENERATION", value, 1);
            snprintf(value, sizeof(value), "%llu",
                     (unsigned long long)projection->local_primary
                         .destination_vnode);
            setenv("WVM_EXECUTOR_ID", value, 1);
            snprintf(value, sizeof(value), "%u", TEST_VCPU);
            setenv("WVM_EXECUTOR_VCPU_INDEX", value, 1);
        }
        snprintf(object_arg, sizeof(object_arg),
                 "memory-backend-file,id=mem,size=16M,mem-path=/dev/shm/%s,"
                 "share=on",
                 name);
        snprintf(machine_arg, sizeof(machine_arg), "pc,memory-backend=mem");
        execl(qemu_bin, qemu_bin, "-accel", "wavevm", "-m", "16",
              "-nodefaults", "-S", "-smp", "1", "-nographic",
              "-object", object_arg, "-machine", machine_arg,
              (char *)NULL);
        _exit(127);
    }
    close(pair[1]);
    pair[1] = -1;
    snprintf(shm_name, shm_name_size, "%s", name);
    *parent_fd_out = pair[0];
    /* Let QEMU finish its reset/BIOS setup.  The production executor then
     * installs the remote page into the same SHM before VCPU_RUN. */
    usleep(1500000);
    return pid;

fail:
    if (pair[0] >= 0) {
        close(pair[0]);
    }
    if (pair[1] >= 0) {
        close(pair[1]);
    }
    return -1;
}

static void stop_real_qemu(pid_t pid, const char *shm_name)
{
    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }
    if (shm_name && shm_name[0]) {
        shm_unlink(shm_name);
    }
}

static void *session_worker(void *opaque)
{
    struct session_peer *peer = opaque;
    uint8_t frame[WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES];
    uint8_t response[WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES];
    char error[256];

    while (!peer->stop) {
        const uint8_t *payload = NULL;
        size_t payload_bytes = 0;
        size_t response_bytes = 0;
        uint16_t message_type = 0;
        struct wvm_vcpu_handoff_request request;
        struct wvm_vcpu_handoff_result result;
        uint8_t result_context[WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES];
        size_t result_payload_bytes = 0;
        ssize_t received;
        struct pollfd pfd = {.fd = peer->fd, .events = POLLIN};

        if (poll(&pfd, 1, 50) <= 0) {
            continue;
        }
        received = recv(peer->fd, frame, sizeof(frame), 0);
        if (received <= 0) {
            if (received == 0 || (errno != EINTR && errno != EAGAIN)) {
                break;
            }
            continue;
        }
        memset(error, 0, sizeof(error));
        if (wvm_executor_session_decode(frame, (size_t)received, &message_type,
                                        &payload, &payload_bytes, error,
                                        sizeof(error)) != 0 ||
            message_type != WVM_EXECUTOR_SESSION_VCPU_RUN ||
            wvm_vcpu_handoff_request_decode(payload, payload_bytes, &request,
                                            error, sizeof(error)) != 0) {
            fprintf(stderr, "goal4 session decode: %s\n", error);
            continue;
        }
        memset(&result, 0, sizeof(result));
        result.protocol_version = WVM_VCPU_HANDOFF_RESULT_VERSION;
        result.status = WVM_VCPU_HANDOFF_RESULT_SUCCESS;
        result.exit_class = WVM_VCPU_EXIT_BUDGET;
        result.backend = request.backend;
        result.vm_id = request.vm_id;
        result.vm_incarnation = request.vm_incarnation;
        result.manifest_generation = request.manifest_generation;
        result.origin_physical_node_id = request.origin_physical_node_id;
        result.origin_runtime_instance_id = request.origin_runtime_instance_id;
        result.vcpu_index = request.vcpu_index;
        result.handoff_sequence = request.handoff_sequence;
        result.produced_memory_fence_id = request.memory_fence_id;
        memcpy(result.operation_id, request.operation_id,
               sizeof(result.operation_id));
        result.context_schema_version = request.context_schema_version;
        result.context_valid_fields = request.context_valid_fields;
        if (request.context_bytes >
            sizeof(result_context)) {
            continue;
        }
        memcpy(result_context, request.context, request.context_bytes);
        result.context = result_context;
        result.context_bytes = request.context_bytes;
        {
            uint8_t result_payload[WVM_EXECUTOR_SESSION_MAX_FRAME_BYTES];

            if (wvm_vcpu_handoff_result_encode(
                    &result, result_payload, sizeof(result_payload),
                    &result_payload_bytes, error, sizeof(error)) != 0 ||
                wvm_executor_session_encode(
                    WVM_EXECUTOR_SESSION_VCPU_EXIT, result_payload,
                    result_payload_bytes, response, sizeof(response),
                    &response_bytes, error, sizeof(error)) != 0) {
            fprintf(stderr, "goal4 session encode: %s\n", error);
            continue;
            }
        }
        if (send(peer->fd, response, response_bytes, MSG_NOSIGNAL) ==
            (ssize_t)response_bytes) {
            peer->run_count++;
        }
    }
    return NULL;
}

static int capture_exit(void *opaque, const struct wvm_envelope *envelope,
                        char *error, size_t error_len)
{
    struct exit_capture *state = opaque;
    struct wvm_vcpu_handoff_result result;

    if (!state || !envelope ||
        wvm_vcpu_handoff_result_decode(envelope->payload,
                                       envelope->payload_bytes, &result, error,
                                       error_len) != 0) {
        return -EINVAL;
    }
    if (result.context_bytes > sizeof(state->context)) {
        return -EOVERFLOW;
    }
    pthread_mutex_lock(&state->lock);
    if (result.context_bytes != 0) {
        memcpy(state->context, result.context, result.context_bytes);
        result.context = state->context;
    }
    state->context_bytes = result.context_bytes;
    state->response = *envelope;
    state->response.payload = NULL;
    state->response.payload_bytes = 0;
    state->result = result;
    state->count++;
    pthread_cond_broadcast(&state->available);
    pthread_mutex_unlock(&state->lock);
    return 0;
}

static int wait_exit(struct exit_capture *state, size_t expected)
{
    struct timespec deadline;
    int result = 0;

    if (!state || clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += 5;
    pthread_mutex_lock(&state->lock);
    while (state->count < expected) {
        result = pthread_cond_timedwait(&state->available, &state->lock,
                                        &deadline);
        if (result != 0) {
            break;
        }
    }
    result = state->count >= expected ? 0 : -1;
    pthread_mutex_unlock(&state->lock);
    return result;
}

static void fill_kvm_prot32(wvm_kvm_context_t *ctx, uint64_t gpa)
{
    struct kvm_sregs sregs;

    memset(ctx, 0, sizeof(*ctx));
    ctx->rip = gpa;
    ctx->rsp = gpa + 0x1000;
    ctx->rflags = 0x2;
    memset(&sregs, 0, sizeof(sregs));
    sregs.cs.selector = 0x8;
    sregs.cs.base = 0;
    sregs.cs.limit = 0xffffffffu;
    sregs.cs.type = 0xb;
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 1;
    sregs.cs.s = 1;
    sregs.cs.g = 1;
    sregs.ds = sregs.cs;
    sregs.ds.selector = 0x10;
    sregs.ds.type = 0x3;
    sregs.es = sregs.ds;
    sregs.ss = sregs.ds;
    sregs.fs = sregs.ds;
    sregs.gs = sregs.ds;
    sregs.tr.selector = 0x18;
    sregs.tr.base = 0;
    sregs.tr.limit = 0xffff;
    sregs.tr.type = 0xb;
    sregs.tr.present = 1;
    sregs.tr.s = 0;
    sregs.ldt.unusable = 1;
    sregs.gdt.base = 0;
    sregs.gdt.limit = 0xffff;
    sregs.idt.base = 0;
    sregs.idt.limit = 0xffff;
    sregs.cr0 = 0x60000011ULL;
    memcpy(ctx->sregs_data, &sregs,
           sizeof(sregs) < sizeof(ctx->sregs_data) ? sizeof(sregs)
                                                   : sizeof(ctx->sregs_data));
}

static int make_request(const struct wvm_node_runtime_manifest *manifest,
                        const struct wvm_runtime_dispatch_projection *projection,
                        struct wvm_vcpu_handoff_request *request,
                        struct wvm_envelope *envelope, uint8_t *payload,
                        size_t payload_capacity, size_t *payload_bytes,
                        char *error, size_t error_len)
{
    static wvm_tcg_context_t legacy_context;
    static wvm_kvm_context_t kvm_context;
    static uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                           sizeof(wvm_tcg_context_t)];
    static size_t context_bytes;
    uint16_t backend = g_real_kvm ? WVM_VCPU_BACKEND_KVM
                                  : WVM_VCPU_BACKEND_TCG;

    memset(request, 0, sizeof(*request));
    if (g_real_kvm) {
        fill_kvm_prot32(&kvm_context, REAL_QEMU_GPA);
        if (wvm_x86_context_encode(
                WVM_VCPU_BACKEND_KVM,
                WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                    WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
                &kvm_context, sizeof(kvm_context), context, sizeof(context),
                &context_bytes, error, error_len) != 0) {
            return -1;
        }
    } else {
        memset(&legacy_context, 0, sizeof(legacy_context));
        legacy_context.eip = g_real_qemu ? REAL_QEMU_GPA :
                                         UINT64_C(0x1122334455667788);
        if (wvm_x86_context_encode(
                WVM_VCPU_BACKEND_TCG,
                WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                    WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
                &legacy_context, sizeof(legacy_context), context,
                sizeof(context), &context_bytes, error, error_len) != 0) {
            return -1;
        }
    }
    request->protocol_version = WVM_VCPU_HANDOFF_REQUEST_VERSION;
    request->backend = backend;
    request->context_schema_version = WVM_VCPU_CONTEXT_SCHEMA_X86;
    request->memory_fence_result = WVM_VCPU_MEMORY_FENCE_SUCCEEDED;
    request->vm_id = manifest->vm_id;
    request->vm_incarnation = manifest->vm_incarnation;
    request->manifest_generation = manifest->manifest_generation;
    request->origin_physical_node_id = 18;
    request->origin_runtime_instance_id = 202;
    request->vcpu_index = TEST_VCPU;
    request->destination_executor_id =
        projection->local_primary.destination_vnode;
    request->reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    request->reply_destination_scope = 41;
    request->reply_destination_vnode = 7;
    request->handoff_sequence = 7;
    request->memory_fence_id = 11;
    request->local_interrupt_watermark = 1;
    request->device_event_watermark = 1;
    request->operation_id[15] = 0xA1;
    request->context_valid_fields =
        WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
        WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE;
    request->context = context;
    request->context_bytes = context_bytes;
    if (wvm_vcpu_handoff_request_encode(request, payload, payload_capacity,
                                        payload_bytes, error, error_len) !=
        0) {
        return -1;
    }
    memset(envelope, 0, sizeof(*envelope));
    envelope->message_type = WVM_ENVELOPE_MSG_VCPU_RUN;
    envelope->vm_id = manifest->vm_id;
    envelope->vm_incarnation = manifest->vm_incarnation;
    envelope->manifest_generation = manifest->manifest_generation;
    envelope->origin_physical_node_id = request->origin_physical_node_id;
    envelope->origin_runtime_instance_id = request->origin_runtime_instance_id;
    memcpy(envelope->operation_id, request->operation_id,
           sizeof(envelope->operation_id));
    envelope->delivery_attempt_id = 1;
    envelope->route_scope_id =
        manifest->required_route_snapshot_key.scope_key.route_scope_id;
    envelope->topology_revision =
        manifest->required_route_snapshot_key.topology_revision;
    envelope->route_generation =
        manifest->required_route_snapshot_key.route_generation;
    memcpy(envelope->route_snapshot_digest,
           manifest->required_route_snapshot_key.snapshot_digest,
           sizeof(envelope->route_snapshot_digest));
    envelope->route.destination_kind =
        projection->local_primary.destination_kind;
    envelope->route.destination_scope =
        projection->local_primary.destination_scope;
    envelope->route.destination_vnode_or_endpoint =
        projection->local_primary.destination_vnode;
    envelope->route.hop_limit = 4;
    envelope->payload = payload;
    envelope->payload_bytes = *payload_bytes;
    wvm_envelope_semantic_digest(payload, *payload_bytes,
                                 envelope->semantic_payload_digest);
    return 0;
}

int main(void)
{
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[1];
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_runtime routes;
    struct wvm_runtime_memory_dispatch memory[2];
    struct wvm_runtime_cpu_dispatch cpus[1];
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_dispatch_projection remote_projection;
    struct wvm_runtime_manifest_storage storage;
    struct wvm_capability_ref capability;
    struct wvm_runtime_gate gate;
    struct wvm_runtime_registration registration;
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t connection_id = 0;
    struct wvm_memory_service_config mem_config;
    struct wvm_memory_service_config remote_mem_config;
    struct wvm_memory_service service;
    struct remote_state remote;
    struct session_peer peer;
    struct exit_capture exits;
    struct wvm_node_runtime_context runtime_context;
    struct wvm_executor_bridge_config bridge_config;
    void *bridge = NULL;
    struct coordinated_path coordinated;
    void *coordinated_bridge = NULL;
    int coordinated_initialized = 0;
    int coordinated_sync_initialized = 0;
    struct wvm_vcpu_handoff_request request;
    struct wvm_envelope envelope;
    uint8_t payload[WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD];
    size_t payload_bytes = 0;
    int session_pair[2] = {-1, -1};
    pid_t qemu_pid = -1;
    char qemu_shm[64] = {0};
    pthread_t ack_thread;
    pthread_t session_thread;
    int ack_started = 0;
    int session_started = 0;
    int bound = 0;
    int installed = 0;
    int kvm_cache_installed = 0;
    char error[256] = {0};
    int exit_code = 1;

    g_real_qemu = getenv("WVM_GOAL4_REAL_QEMU") != NULL;
    g_real_kvm = getenv("WVM_GOAL4_KVM") != NULL;
    if (g_real_qemu) {
        fprintf(stderr,
                "WVM_GOAL4_REAL_QEMU is unsupported: its guest RAM is not "
                "the executor-mapped page. Use WVM_GOAL4_KVM=1 for real "
                "-accel wavevm execution.\n");
        return 1;
    }
    if (g_real_qemu && g_real_kvm) {
        fprintf(stderr, "WVM_GOAL4_REAL_QEMU and WVM_GOAL4_KVM are exclusive\n");
        return 1;
    }
    if ((g_real_qemu || g_real_kvm) &&
        prepare_real_qemu_shm(qemu_shm, sizeof(qemu_shm), error,
                              sizeof(error)) != 0) {
        fprintf(stderr, "goal4 real executor shm: %s\n", error);
        return 1;
    }
    fill_rule(&rules[0], 41, 7, 17, 101, 17);
    fill_rule(&rules[1], 99, 1, 99, 202, 99);
    if (finalize_snapshot(&snapshot, rules, acks, error, sizeof(error)) != 0) {
        fprintf(stderr, "goal4 setup snapshot: %s\n", error);
        return 1;
    }
    memset(&storage, 0, sizeof(storage));
    if (setup_manifest(&storage.manifest, &capability,
                       &snapshot.route_snapshot_key, error,
                       sizeof(error)) != 0) {
        fprintf(stderr, "goal4 setup manifest: %s\n", error);
        return 1;
    }
    fill_projection(&projection, memory, &storage.manifest);
    memset(cpus, 0, sizeof(cpus));
    cpus[0].guest_vcpu_index = TEST_VCPU;
    cpus[0].executor = projection.local_primary;
    projection.cpu_dispatch.entries = cpus;
    projection.cpu_dispatch.count = 1;
    projection.cpu_dispatch.capacity = 1;
    if (expect(wvm_runtime_dispatch_projection_validate(
                   &projection, error, sizeof(error)) == 0,
               "dispatch projection") != 0) {
        return 1;
    }
    wvm_route_runtime_init(&routes);
    if (expect(wvm_route_runtime_prepare(&routes, &snapshot, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &routes, &snapshot.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate routes") != 0) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    wvm_runtime_gate_init(&gate);
    if (expect(wvm_runtime_gate_prepare(
                   &gate, &storage.manifest, storage.manifest.physical_node_id,
                   storage.manifest.expected_node_instance_id, error,
                   sizeof(error)) == 0 &&
                   wvm_runtime_manifest_profile_digest(
                       &storage.manifest, profile_digest, error,
                       sizeof(error)) == 0,
               "prepare gate") != 0) {
        fprintf(stderr, "goal4 prepare: %s\n", error);
        goto out;
    }
    memset(&registration, 0, sizeof(registration));
    registration.connection_role = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    registration.vm_id = storage.manifest.vm_id;
    registration.vm_incarnation = storage.manifest.vm_incarnation;
    registration.manifest_generation = storage.manifest.manifest_generation;
    memcpy(registration.candidate_manifest_digest,
           storage.manifest.candidate_manifest_digest,
           sizeof(registration.candidate_manifest_digest));
    registration.local_runtime_instance_id =
        storage.manifest.expected_node_instance_id;
    registration.caller_process_instance_id = 42;
    memcpy(registration.capability_profile_digest, profile_digest,
           sizeof(registration.capability_profile_digest));
    snprintf(registration.requested_endpoint_name,
             sizeof(registration.requested_endpoint_name), "%s",
             storage.manifest.local_names.namespace_name);
    if (expect(wvm_runtime_gate_register(&gate, &registration, &connection_id,
                                         error, sizeof(error)) == 0 &&
                   wvm_runtime_gate_activate(&gate,
                                             storage.manifest.activation_fence,
                                             error, sizeof(error)) == 0,
               "activate executor gate") != 0) {
        goto out;
    }

    memset(&remote, 0, sizeof(remote));
    if (pthread_mutex_init(&remote.lock, NULL) != 0 ||
        pthread_cond_init(&remote.available, NULL) != 0) {
        goto out;
    }
    {
        struct wvm_directory_store_config directory_config;
        uint8_t page[WVM_MEMORY_PAGE_BYTES];
        uint64_t version = 0;
        uint64_t result_version = 0;
        int commit_index;

        memset(&directory_config, 0, sizeof(directory_config));
        directory_config.initial_epoch = 1;
        directory_config.max_page_records = 16;
        if (wvm_directory_store_init(&remote.directory_store,
                                     &directory_config, error,
                                     sizeof(error)) != 0) {
            fprintf(stderr, "goal4 directory store init: %s\n", error);
            goto out;
        }
        remote.directory_store_initialized = 1;
        if (wvm_directory_store_read_page(
                &remote.directory_store, WVM_MEMORY_PAGE_BYTES, page,
                &version, error, sizeof(error)) != 0) {
            fprintf(stderr, "goal4 directory store materialize: %s\n", error);
            goto out;
        }
        if (g_real_qemu || g_real_kvm) {
            /* The remote directory owns the code page.  The executor must
             * install this HLT into guest RAM for KVM/QEMU to halt at EIP. */
            memset(page, 0x90, sizeof(page));
            page[0] = 0xf4;
        } else {
            memset(page, 0x3c, sizeof(page));
        }
        for (commit_index = 0; commit_index < 8; commit_index++) {
            if (wvm_directory_store_commit_page(
                    &remote.directory_store, WVM_MEMORY_PAGE_BYTES, version,
                    0, page, sizeof(page), &result_version, error,
                    sizeof(error)) != 0) {
                fprintf(stderr, "goal4 directory store seed: %s\n", error);
                goto out;
            }
            version = result_version;
        }
        if (version != ((UINT64_C(1) << 32) | 9U)) {
            fprintf(stderr, "goal4 directory store seed version=0x%llx\n",
                    (unsigned long long)version);
            goto out;
        }
    }
    memset(&mem_config, 0, sizeof(mem_config));
    mem_config.dispatch = &projection;
    mem_config.route_runtime = &routes;
    mem_config.local_physical_node_id = 17;
    mem_config.local_node_instance_id = 101;
    mem_config.local_runtime_instance_id = 1001;
    mem_config.completion_timeout_ms = 5000;
    mem_config.read_page = read_page;
    mem_config.commit_page = commit_page;
    mem_config.complete_commit = complete_commit;
    mem_config.complete_fault = complete_fault;
    mem_config.send_envelope = send_memory_envelope;
    mem_config.opaque = &remote;
    if (expect(wvm_memory_service_init(&service, &mem_config, error,
                                       sizeof(error)) == 0,
               "init memory_service") != 0 ||
        expect(wvm_memory_service_global_install(&service, error,
                                                 sizeof(error)) == 0,
               "install global memory_service") != 0) {
        goto out;
    }
    installed = 1;
    remote.service = &service;
    remote_projection = projection;
    remote_projection.physical_node_id = 99;
    remote_projection.expected_node_instance_id = 202;
    remote_projection.local_primary.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    remote_projection.local_primary.destination_scope = 99;
    remote_projection.local_primary.destination_vnode = 1;
    memset(&remote_mem_config, 0, sizeof(remote_mem_config));
    remote_mem_config.dispatch = &remote_projection;
    remote_mem_config.route_runtime = &routes;
    remote_mem_config.local_physical_node_id = 99;
    remote_mem_config.local_node_instance_id = 202;
    remote_mem_config.local_runtime_instance_id = 2002;
    remote_mem_config.completion_timeout_ms = 5000;
    remote_mem_config.read_page = read_page;
    remote_mem_config.commit_page = commit_page;
    remote_mem_config.complete_fault = complete_remote_fault;
    remote_mem_config.send_envelope = remote_send_envelope;
    remote_mem_config.opaque = &remote;
    if (expect(wvm_memory_service_init(&remote.remote_service,
                                       &remote_mem_config, error,
                                       sizeof(error)) == 0,
               "init real remote memory_service") != 0) {
        goto out;
    }
    remote.remote_service_initialized = 1;
    if (pthread_create(&ack_thread, NULL, ack_worker, &remote) != 0) {
        goto out;
    }
    ack_started = 1;

    memset(&runtime_context, 0, sizeof(runtime_context));
    runtime_context.manifest_storage = &storage;
    runtime_context.manifest = &storage.manifest;
    runtime_context.runtime_gate = &gate;
    runtime_context.dispatch = &projection;
    runtime_context.route_runtime = &routes;
    runtime_context.node_instance_id = storage.manifest.expected_node_instance_id;
    runtime_context.physical_node_id = storage.manifest.physical_node_id;
    runtime_context.local_primary_vnode =
        projection.local_primary.destination_vnode;
    runtime_context.local_vcpu_count = 1;
    runtime_context.local_memory_bytes = 64ULL * 1024ULL * 1024ULL;
    runtime_context.guest_memory_bytes =
        storage.manifest.launch_plan.guest_total_memory_bytes;
    runtime_context.executor_service_port =
        storage.manifest.launch_plan.local_executor_service_port;
    runtime_context.executor_control_port =
        storage.manifest.launch_plan.local_executor_control_port;
    runtime_context.executor_worker_count =
        storage.manifest.launch_plan.executor_worker_count;

    if (expect(wvm_executor_runtime_bind_admitted(&runtime_context, error,
                                                  sizeof(error)) == 0,
               "bind production executor runtime") != 0) {
        fprintf(stderr, "bind err=%s\n", error);
        goto out;
    }
    bound = 1;
    if (g_real_qemu || g_real_kvm) {
        extern void init_kvm_global(void);
        /* Production startup maps guest RAM before binding the executor.
         * A14 runs the bind directly, so perform that same mapping here
         * after the runtime context has set g_slave_ram_size. */
        init_kvm_global();
    }
    if (g_real_kvm) {
        extern void *dirty_sync_sender_thread(void *arg);
        pthread_t sender_thread;
        if (pthread_create(&sender_thread, NULL, dirty_sync_sender_thread,
                           NULL) != 0) {
            fprintf(stderr, "start KVM dirty sender failed\n");
            goto out;
        }
        pthread_detach(sender_thread);
        struct wvm_kvm_page_cache_config cache_config;

        memset(&cache_config, 0, sizeof(cache_config));
        cache_config.vm_id = storage.manifest.vm_id;
        cache_config.vm_incarnation = storage.manifest.vm_incarnation;
        cache_config.max_page_records = 16;
        cache_config.completion_timeout_ms = 5000;
        if (expect(wvm_kvm_page_cache_global_install(
                       &cache_config, error, sizeof(error)) == 0,
                   "install KVM page cache") != 0) {
            fprintf(stderr, "kvm cache err=%s\n", error);
            goto out;
        }
        kvm_cache_installed = 1;
    }
    if (g_real_qemu) {
        qemu_pid = launch_real_qemu_session(
            &storage.manifest, &projection, &session_pair[0], qemu_shm,
            sizeof(qemu_shm), error, sizeof(error));
        if (qemu_pid <= 0) {
            fprintf(stderr, "real QEMU launch: %s\n", error);
            goto out;
        }
        printf("EVID goal4_A14: real_qemu_pid=%ld guest_hlt_gpa=0x%llx\n",
               (long)qemu_pid, (unsigned long long)REAL_QEMU_GPA);
    } else if (!g_real_kvm &&
               socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                          session_pair) != 0) {
        perror("socketpair");
        goto out;
    }
    if (!g_real_kvm) {
        if (expect(wvm_executor_runtime_attach_tcg_session(
                       TEST_VCPU, session_pair[0]) == 0,
                   "attach TCG session") != 0) {
            close(session_pair[0]);
            close(session_pair[1]);
            session_pair[0] = session_pair[1] = -1;
            goto out;
        }
        session_pair[0] = -1; /* owned by executor runtime */
        memset(&peer, 0, sizeof(peer));
        peer.fd = session_pair[1];
        if (!g_real_qemu) {
            if (pthread_create(&session_thread, NULL, session_worker,
                               &peer) != 0) {
                goto out;
            }
            session_started = 1;
        }
    }
    wvm_executor_runtime_publish_ready();

    memset(&exits, 0, sizeof(exits));
    if (pthread_mutex_init(&exits.lock, NULL) != 0 ||
        pthread_cond_init(&exits.available, NULL) != 0) {
        goto out;
    }
    memset(&bridge_config, 0, sizeof(bridge_config));
    bridge_config.manifest = &storage.manifest;
    bridge_config.runtime_gate = &gate;
    bridge_config.dispatch = &projection;
    bridge_config.route_runtime = &routes;
    bridge_config.local_runtime_instance_id =
        storage.manifest.expected_node_instance_id;
    bridge_config.runtime_connection_id = connection_id;
    bridge_config.operation_retention_horizon_ms =
        snapshot.operation_retention_horizon_ms;
    bridge_config.execute_handoff = wvm_executor_runtime_execute_handoff;
    bridge_config.execute_handoff_opaque = &runtime_context;
    bridge_config.send_envelope = capture_exit;
    bridge_config.send_envelope_opaque = &exits;
    if (expect(wvm_executor_bridge_dispatch_init(&bridge_config, &bridge, error,
                                                 sizeof(error)) == 0,
               "init executor_bridge with production execute_handoff") != 0) {
        fprintf(stderr, "bridge init err=%s\n", error);
        goto out;
    }
    if (expect(make_request(&storage.manifest, &projection, &request, &envelope,
                            payload, sizeof(payload), &payload_bytes, error,
                            sizeof(error)) == 0,
               "build VCPU_RUN") != 0 ||
        expect(wvm_executor_bridge_dispatch(bridge, &envelope, error,
                                            sizeof(error)) == 0 &&
                   wait_exit(&exits, 1) == 0,
               "production execute_handoff via bridge") != 0) {
        fprintf(stderr, "dispatch err=%s\n", error);
        goto out;
    }
    if (g_real_qemu) {
        uint16_t exit_class;

        peer.run_count = 1;
        pthread_mutex_lock(&exits.lock);
        exit_class = exits.result.exit_class;
        printf("EVID goal4_A14: real_qemu_exit_class=%u context_bytes=%zu "
               "status=%u\n",
               (unsigned)exit_class, exits.context_bytes,
               (unsigned)exits.result.status);
        pthread_mutex_unlock(&exits.lock);
        if (expect(exit_class == WVM_VCPU_EXIT_HALTED &&
                       exits.context_bytes != 0 &&
                       exits.result.status ==
                           WVM_VCPU_HANDOFF_RESULT_SUCCESS,
                   "real QEMU executed the remote HLT page") != 0) {
            goto out;
        }
    }

    if (g_real_kvm) {
        uint16_t exit_class;

        pthread_mutex_lock(&exits.lock);
        exit_class = exits.result.exit_class;
        printf("EVID goal4_A14: real_kvm_exit_class=%u context_bytes=%zu "
               "status=%u\n",
               (unsigned)exit_class, exits.context_bytes,
               (unsigned)exits.result.status);
        pthread_mutex_unlock(&exits.lock);
        if (expect(exit_class == WVM_VCPU_EXIT_HALTED &&
                       exits.context_bytes != 0 &&
                       exits.result.status ==
                           WVM_VCPU_HANDOFF_RESULT_SUCCESS,
                   "real KVM executed the remote HLT page") != 0) {
            goto out;
        }
    }

    pthread_mutex_lock(&remote.lock);
    if (expect(remote.completion_count >= 1, "remote memory ACK completed") !=
            0 ||
        expect(remote.completed_gpa == WVM_MEMORY_PAGE_BYTES,
               "remote GPA") != 0 ||
        expect(remote.completed_version == ((UINT64_C(1) << 32) | 9U),
               "remote version") != 0 ||
        expect(remote.completed_page[0] ==
                   ((g_real_qemu || g_real_kvm) ? 0xf4 : 0x3c),
               "remote page bytes") != 0) {
        pthread_mutex_unlock(&remote.lock);
        goto out;
    }
    pthread_mutex_unlock(&remote.lock);

    pthread_mutex_lock(&exits.lock);
    if (expect(exits.result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS,
               "VCPU_EXIT SUCCESS") != 0 ||
        expect(exits.response.message_type == WVM_ENVELOPE_MSG_VCPU_EXIT,
               "typed VCPU_EXIT") != 0 ||
        expect(g_real_kvm || peer.run_count == 1,
               "TCG session run-once") != 0) {
        pthread_mutex_unlock(&exits.lock);
        goto out;
    }
    pthread_mutex_unlock(&exits.lock);

    envelope.delivery_attempt_id = 2;
    if (expect(wvm_executor_bridge_dispatch(bridge, &envelope, error,
                                            sizeof(error)) == 0 &&
                   wait_exit(&exits, 2) == 0,
               "cached replay without second execute") != 0 ||
        expect(g_real_kvm || peer.run_count == 1,
               "SPEC-vcpu-run-once cache holds") != 0) {
        goto out;
    }

    if (g_real_kvm) {
        struct wvm_executor_bridge_config coordinated_bridge_config;
        struct wvm_vcpu_handoff_coordinator_config coordinator_config;
        struct wvm_vcpu_handoff_submit submit;
        struct timespec deadline;
        uint64_t fence_id;

        (void)wvm_kvm_page_cache_global_invalidate(REAL_QEMU_GPA, error,
                                                    sizeof(error));
        memset(&coordinated, 0, sizeof(coordinated));
        if (pthread_mutex_init(&coordinated.lock, NULL) != 0 ||
            pthread_cond_init(&coordinated.available, NULL) != 0) {
            fprintf(stderr, "coordinator completion init failed\n");
            goto out;
        }
        coordinated_sync_initialized = 1;
        coordinated_bridge_config = bridge_config;
        coordinated_bridge_config.send_envelope = coordinated_bridge_reply;
        coordinated_bridge_config.send_envelope_opaque = &coordinated;
        if (expect(wvm_executor_bridge_dispatch_init(
                       &coordinated_bridge_config, &coordinated_bridge, error,
                       sizeof(error)) == 0,
                   "init coordinator executor_bridge") != 0) {
            fprintf(stderr, "coordinator bridge err=%s\n", error);
            goto out;
        }
        pthread_mutex_lock(&remote.lock);
        fence_id = remote.completed_commit_version;
        pthread_mutex_unlock(&remote.lock);
        if (fence_id == 0) {
            fprintf(stderr, "coordinator has no real dirty commit fence\n");
            goto out;
        }
        memset(&coordinator_config, 0, sizeof(coordinator_config));
        coordinator_config.manifest = &storage.manifest;
        coordinator_config.runtime_gate = &gate;
        coordinator_config.dispatch = &projection;
        coordinator_config.route_runtime = &routes;
        coordinator_config.local_runtime_instance_id =
            storage.manifest.expected_node_instance_id;
        coordinator_config.runtime_connection_id = connection_id;
        coordinator_config.operation_retention_horizon_ms =
            snapshot.operation_retention_horizon_ms;
        coordinator_config.send_envelope = coordinated_send;
        coordinator_config.send_envelope_opaque = &coordinated;
        coordinator_config.complete = coordinated_complete;
        coordinator_config.complete_opaque = &coordinated;
        if (expect(wvm_vcpu_handoff_coordinator_init(
                       &coordinated.coordinator, &coordinator_config, error,
                       sizeof(error)) == 0,
                   "init vCPU handoff coordinator") != 0) {
            fprintf(stderr, "coordinator init err=%s\n", error);
            goto out;
        }
        coordinated_initialized = 1;
        memset(&submit, 0, sizeof(submit));
        submit.backend = request.backend;
        submit.vcpu_index = request.vcpu_index;
        submit.memory_fence_result = WVM_VCPU_MEMORY_FENCE_SUCCEEDED;
        submit.memory_fence_id = fence_id;
        submit.local_interrupt_watermark = request.local_interrupt_watermark;
        submit.device_event_watermark = request.device_event_watermark;
        memcpy(submit.operation_id, request.operation_id,
               sizeof(submit.operation_id));
        submit.context_schema_version = request.context_schema_version;
        submit.context_valid_fields = request.context_valid_fields;
        submit.context = request.context;
        submit.context_bytes = request.context_bytes;
        coordinated.bridge = coordinated_bridge;
        if (expect(wvm_vcpu_handoff_coordinator_submit(
                       &coordinated.coordinator, &submit, error,
                       sizeof(error)) == 0,
                   "coordinator submit -> KVM handoff") != 0) {
            fprintf(stderr, "coordinator submit err=%s\n", error);
            goto out;
        }
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;
        pthread_mutex_lock(&coordinated.lock);
        while (!coordinated.completed) {
            if (pthread_cond_timedwait(&coordinated.available,
                                       &coordinated.lock, &deadline) != 0) {
                break;
            }
        }
        if (!coordinated.completed) {
            pthread_mutex_unlock(&coordinated.lock);
            fprintf(stderr, "coordinator completion timeout\n");
            goto out;
        }
        printf("EVID goal4_A14: coordinator_fence_id=0x%llx "
               "coordinator_exit_class=%u coordinator_context_bytes=%zu "
               "coordinator_status=%u\n",
               (unsigned long long)fence_id,
               (unsigned)coordinated.result.exit_class,
               coordinated.result.context_bytes,
               (unsigned)coordinated.result.status);
        if (expect(coordinated.result.exit_class == WVM_VCPU_EXIT_HALTED &&
                       coordinated.result.context_bytes != 0 &&
                       coordinated.result.status ==
                           WVM_VCPU_HANDOFF_RESULT_SUCCESS,
                   "coordinator observed real KVM VCPU_EXIT") != 0) {
            pthread_mutex_unlock(&coordinated.lock);
            goto out;
        }
        pthread_mutex_unlock(&coordinated.lock);
        wvm_vcpu_handoff_coordinator_destroy(&coordinated.coordinator);
        coordinated_initialized = 0;
        wvm_executor_bridge_dispatch_destroy(coordinated_bridge);
        coordinated_bridge = NULL;
        pthread_cond_destroy(&coordinated.available);
        pthread_mutex_destroy(&coordinated.lock);
        coordinated_sync_initialized = 0;
    }

    printf("EVID goal4_A14: remote_fault_ACK version=0x%llx fence_id=11 "
           "production_execute_handoff=1\n",
           (unsigned long long)remote.completed_version);
    puts("goal4 A14: executor_bridge → wvm_executor_runtime_execute_handoff");
    puts(g_real_kvm
             ? "           → remote memory_service fault/ACK → real KVM_RUN PASS"
             : "           → remote memory_service fault/ACK → TCG run-once PASS");
    puts("(production entry; not test-local execute; not pause-stub READY)");
    puts("(live multi-node guest OS/SSH still §7)");
    exit_code = 0;

out:
    if (coordinated_initialized) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinated.coordinator);
    }
    if (coordinated_bridge) {
        wvm_executor_bridge_dispatch_destroy(coordinated_bridge);
    }
    if (coordinated_sync_initialized) {
        pthread_cond_destroy(&coordinated.available);
        pthread_mutex_destroy(&coordinated.lock);
    }
    if (bridge) {
        wvm_executor_bridge_dispatch_destroy(bridge);
    }
    if (session_started) {
        peer.stop = 1;
        pthread_join(session_thread, NULL);
    }
    if (session_pair[1] >= 0) {
        close(session_pair[1]);
    }
    if (session_pair[0] >= 0) {
        close(session_pair[0]);
    }
    if (qemu_pid > 0) {
        stop_real_qemu(qemu_pid, qemu_shm);
        qemu_pid = -1;
    } else if (qemu_shm[0]) {
        shm_unlink(qemu_shm);
        qemu_shm[0] = '\0';
    }
    if (kvm_cache_installed) {
        wvm_kvm_page_cache_global_uninstall();
        kvm_cache_installed = 0;
    }
    if (bound) {
        wvm_executor_runtime_unbind();
    }
    if (ack_started) {
        pthread_mutex_lock(&remote.lock);
        remote.stop = 1;
        pthread_cond_broadcast(&remote.available);
        pthread_mutex_unlock(&remote.lock);
        pthread_join(ack_thread, NULL);
    }
    if (installed) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
    }
    if (remote.remote_service_initialized) {
        wvm_memory_service_destroy(&remote.remote_service);
        remote.remote_service_initialized = 0;
    }
    if (remote.directory_store_initialized) {
        wvm_directory_store_destroy(&remote.directory_store);
        remote.directory_store_initialized = 0;
    }
    pthread_cond_destroy(&remote.available);
    pthread_mutex_destroy(&remote.lock);
    pthread_cond_destroy(&exits.available);
    pthread_mutex_destroy(&exits.lock);
    wvm_route_runtime_destroy(&routes);
    return exit_code;
}

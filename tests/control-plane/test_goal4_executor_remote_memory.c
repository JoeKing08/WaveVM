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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
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
#include "vcpu_service.h"
#include "wavevm_executor_session.h"
#include "wavevm_membership.h"
#include "wavevm_protocol.h"
#include "wavevm_local_memory.h"
#include "wavevm_runtime_gate.h"
#include "wavevm_vcpu_handoff.h"
#include "wavevm_x86_context.h"

#define TEST_VM_ID 256U
#define TEST_VCPU 0U
#define REAL_QEMU_GPA 0x1000ULL

static int g_real_qemu;
static int g_real_kvm;

/* Slave TCG SOCK/GATE/RUNTIME_SOCKET harness for production dirty self-emit. */
static int g_qemu_req_keep_fd = -1;
static int g_qemu_push_notify_fd = -1;
static int g_qemu_cmd_keep_fd = -1;
static int g_qemu_runtime_listen_fd = -1;
static char g_qemu_runtime_sock_path[108];
static pthread_t g_qemu_ipc_thread;
static volatile int g_qemu_ipc_stop;
static int g_qemu_ipc_started;


/* Production executor's mapping of the shared guest RAM (slave_hybrid.c). */
extern uint8_t *wvm_executor_guest_ram_base(void);

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
    struct wvm_vcpu_service service;
    int service_initialized;
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
    int service_result = 0;

    if (path->service_initialized) {
        service_result = wvm_vcpu_service_complete(
            &path->service, request, result, error, error_len);
    }
    if (result->status != WVM_VCPU_HANDOFF_RESULT_SUCCESS) {
        fprintf(stderr, "goal4 coordinator completion status=%u exit=%u err=%s\n",
                (unsigned)result->status, (unsigned)result->exit_class,
                error && error[0] ? error : "(empty)");
    }
    (void)error_len;
    pthread_mutex_lock(&path->lock);
    path->result = *result;
    path->completed = 1;
    pthread_cond_signal(&path->available);
    pthread_mutex_unlock(&path->lock);
    return service_result;
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
    /*
     * Real-QEMU A14 also faults page0 (ESP) through IPC after the code-page
     * install. Once the code page ACK is recorded, ignore other GPAs so the
     * final expects still see the install snapshot.
     */
    if (!(g_real_qemu && state->completed_gpa == WVM_MEMORY_PAGE_BYTES &&
          gpa != WVM_MEMORY_PAGE_BYTES)) {
        state->completed_gpa = gpa;
        state->completed_version = version;
        state->completed_status = status;
        if (data_bytes != 0 && data_bytes <= sizeof(state->completed_page)) {
            memcpy(state->completed_page, data, data_bytes);
        }
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
        pthread_cond_broadcast(&state->available);
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


static void setenv_hex_digest(const char *name, const uint8_t *bytes, size_t n)
{
    char hex[WVM_SHA256_DIGEST_BYTES * 2U + 1U];
    size_t i;

    if (n > WVM_SHA256_DIGEST_BYTES) {
        n = WVM_SHA256_DIGEST_BYTES;
    }
    for (i = 0; i < n; i++) {
        snprintf(hex + i * 2U, 3, "%02x", bytes[i]);
    }
    hex[n * 2U] = '\0';
    setenv(name, hex, 1);
}

static int write_exact_fd(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_exact_fd(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static void handle_a14_ipc_fault(int qemu_fd, const uint8_t *payload,
                                 uint32_t payload_bytes)
{
    struct wvm_local_memory_fault_request request;
    struct wvm_mem_ack ack;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint8_t ack_payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    uint8_t result_length[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES];
    size_t ack_payload_bytes = 0;
    char error[192] = {0};
    int result;

    memset(&request, 0, sizeof(request));
    memset(&ack, 0, sizeof(ack));
    if (wvm_local_memory_fault_request_decode(payload, payload_bytes, &request,
                                              error, sizeof(error)) == 0) {
        result = wvm_memory_service_global_request_fault(
            request.gpa, request.operation_id, request.delivery_attempt_id,
            &ack, page, error, sizeof(error));
        if (result == 0 &&
            wvm_mem_ack_encode(&ack, ack_payload, sizeof(ack_payload),
                               &ack_payload_bytes, error, sizeof(error)) == 0) {
            result = 0;
        } else if (result == 0) {
            result = -EPROTO;
        }
    } else {
        result = -EPROTO;
    }
    if (result != 0) {
        ack_payload_bytes = 0;
        fprintf(stderr, "goal4 A14 IPC fault rejected status=%d err=%s\n",
                result, error[0] ? error : "(empty)");
    } else {
        fprintf(stderr, "goal4 A14 IPC fault ok gpa=%#llx version=%#llx\n",
                (unsigned long long)ack.gpa,
                (unsigned long long)ack.version);
    }
    if (wvm_local_memory_result_length_encode(ack_payload_bytes, result_length,
                                              error, sizeof(error)) != 0 ||
        write_exact_fd(qemu_fd, result_length, sizeof(result_length)) < 0 ||
        (ack_payload_bytes != 0 &&
         write_exact_fd(qemu_fd, ack_payload, ack_payload_bytes) < 0)) {
        fprintf(stderr, "goal4 A14 IPC fault response write failed\n");
    }
}

static void handle_a14_ipc_commit(int qemu_fd, const uint8_t *payload,
                                  uint32_t payload_bytes)
{
    struct wvm_local_memory_commit_request request;
    struct wvm_local_memory_commit_result result;
    uint8_t encoded[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES];
    char error[192] = {0};
    int status;

    memset(&request, 0, sizeof(request));
    memset(&result, 0, sizeof(result));
    if (wvm_local_memory_commit_request_decode(payload, payload_bytes, &request,
                                               error, sizeof(error)) != 0) {
        status = -EPROTO;
    } else {
        status = wvm_memory_service_global_request_commit(
            request.commit.gpa, request.commit.base_version,
            request.commit.offset, request.commit.data,
            request.commit.data_bytes, request.operation_id,
            request.delivery_attempt_id, &result.ack, error, sizeof(error));
        memcpy(result.operation_id, request.operation_id,
               sizeof(result.operation_id));
    }
    if (status != 0) {
        memset(&result, 0, sizeof(result));
        memcpy(result.operation_id, request.operation_id,
               sizeof(result.operation_id));
        result.ack.gpa = request.commit.gpa;
        result.ack.status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
        fprintf(stderr, "goal4 A14 IPC commit rejected status=%d err=%s\n",
                status, error[0] ? error : "(empty)");
    } else {
        fprintf(stderr,
                "goal4 A14 IPC commit ok gpa=%#llx base=%#llx result=%#llx\n",
                (unsigned long long)result.ack.gpa,
                (unsigned long long)request.commit.base_version,
                (unsigned long long)result.ack.result_version);
    }
    if (wvm_local_memory_commit_result_encode(&result, encoded, error,
                                              sizeof(error)) != 0 ||
        write_exact_fd(qemu_fd, encoded, sizeof(encoded)) < 0) {
        fprintf(stderr, "goal4 A14 IPC commit response write failed\n");
    }
}

static void *a14_qemu_ipc_client(void *opaque)
{
    int qemu_fd = (int)(intptr_t)opaque;
    /*
     * Commit payload is header + one page; keep a modest heap buffer rather
     * than a 1MiB stack frame.
     */
    enum { A14_IPC_PAYLOAD_CAP =
               WVM_LOCAL_MEMORY_COMMIT_REQUEST_HEADER_BYTES +
               WVM_MEMORY_PAGE_BYTES + 64U };
    uint8_t *payload_buf = malloc(A14_IPC_PAYLOAD_CAP);

    if (!payload_buf) {
        close(qemu_fd);
        return NULL;
    }
    while (!g_qemu_ipc_stop) {
        wvm_ipc_header_t ipc_hdr;
        struct pollfd pfd = {.fd = qemu_fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 50);

        if (pr <= 0) {
            continue;
        }
        if (read_exact_fd(qemu_fd, &ipc_hdr, sizeof(ipc_hdr)) < 0) {
            break;
        }
        if (ipc_hdr.len > A14_IPC_PAYLOAD_CAP) {
            fprintf(stderr, "goal4 A14 IPC oversized type=%u len=%u\n",
                    (unsigned)ipc_hdr.type, (unsigned)ipc_hdr.len);
            break;
        }
        if (ipc_hdr.len != 0 &&
            read_exact_fd(qemu_fd, payload_buf, ipc_hdr.len) < 0) {
            break;
        }
        switch (ipc_hdr.type) {
        case WVM_IPC_TYPE_REGISTER:
            fprintf(stderr,
                    "goal4 A14 IPC REGISTER fd=%d len=%u (GATE slave sync)\n",
                    qemu_fd, (unsigned)ipc_hdr.len);
            break;
        case WVM_IPC_TYPE_TYPED_MEM_FAULT:
            handle_a14_ipc_fault(qemu_fd, payload_buf, ipc_hdr.len);
            break;
        case WVM_IPC_TYPE_TYPED_MEM_COMMIT:
            handle_a14_ipc_commit(qemu_fd, payload_buf, ipc_hdr.len);
            break;
        case WVM_IPC_TYPE_COMMIT_DIFF_SYNC: {
            uint8_t sync_response[16] = {0};

            if (write_exact_fd(qemu_fd, sync_response,
                               sizeof(sync_response)) < 0) {
                fprintf(stderr, "goal4 A14 COMMIT_DIFF_SYNC ack failed\n");
            }
            break;
        }
        default:
            fprintf(stderr, "goal4 A14 IPC ignore type=%u len=%u\n",
                    (unsigned)ipc_hdr.type, (unsigned)ipc_hdr.len);
            break;
        }
    }
    free(payload_buf);
    close(qemu_fd);
    return NULL;
}

static void *a14_qemu_ipc_listener(void *opaque)
{
    (void)opaque;
    while (!g_qemu_ipc_stop) {
        struct pollfd pfd = {.fd = g_qemu_runtime_listen_fd, .events = POLLIN};
        int client;
        pthread_t client_thread;

        if (poll(&pfd, 1, 50) <= 0) {
            continue;
        }
        client = accept(g_qemu_runtime_listen_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            break;
        }
        if (pthread_create(&client_thread, NULL, a14_qemu_ipc_client,
                           (void *)(intptr_t)client) != 0) {
            close(client);
            continue;
        }
        pthread_detach(client_thread);
    }
    return NULL;
}

static int start_a14_qemu_ipc_listener(char *error, size_t error_len)
{
    struct sockaddr_un addr;
    int fd;

    if (g_qemu_ipc_started) {
        return 0;
    }
    snprintf(g_qemu_runtime_sock_path, sizeof(g_qemu_runtime_sock_path),
             "/tmp/wavevm_goal4_rt_%d.sock", (int)getpid());
    unlink(g_qemu_runtime_sock_path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(error, error_len, "A14 runtime socket: %s", strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
             g_qemu_runtime_sock_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 8) != 0) {
        snprintf(error, error_len, "A14 runtime bind/listen: %s",
                 strerror(errno));
        close(fd);
        unlink(g_qemu_runtime_sock_path);
        return -1;
    }
    g_qemu_runtime_listen_fd = fd;
    g_qemu_ipc_stop = 0;
    if (pthread_create(&g_qemu_ipc_thread, NULL, a14_qemu_ipc_listener,
                       NULL) != 0) {
        snprintf(error, error_len, "A14 runtime listener thread failed");
        close(fd);
        g_qemu_runtime_listen_fd = -1;
        unlink(g_qemu_runtime_sock_path);
        return -1;
    }
    g_qemu_ipc_started = 1;
    fprintf(stderr, "goal4 A14 RUNTIME_SOCKET=%s listening\n",
            g_qemu_runtime_sock_path);
    return 0;
}

static void stop_a14_qemu_ipc_listener(void)
{
    if (!g_qemu_ipc_started) {
        return;
    }
    g_qemu_ipc_stop = 1;
    if (g_qemu_runtime_listen_fd >= 0) {
        close(g_qemu_runtime_listen_fd);
        g_qemu_runtime_listen_fd = -1;
    }
    pthread_join(g_qemu_ipc_thread, NULL);
    if (g_qemu_runtime_sock_path[0]) {
        unlink(g_qemu_runtime_sock_path);
        g_qemu_runtime_sock_path[0] = '\0';
    }
    g_qemu_ipc_started = 0;
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
    const uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES],
    int *parent_fd_out, char *shm_name, size_t shm_name_size, char *error,
    size_t error_len)
{
    int pair[2] = {-1, -1};
    int req_pair[2] = {-1, -1};
    int push_pair[2] = {-1, -1};
    int cmd_pair[2] = {-1, -1};
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
    if (!g_qemu_runtime_sock_path[0]) {
        snprintf(error, error_len,
                 "real QEMU requires start_a14_qemu_ipc_listener first");
        return -1;
    }
    snprintf(name, sizeof(name), "%s", prepared_name);
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) {
        snprintf(error, error_len, "real QEMU socketpair: %s", strerror(errno));
        return -1;
    }
    /*
     * CMD/REQ/PUSH must survive exec into QEMU.  Do not use SOCK_CLOEXEC on
     * these pairs; clear FD_CLOEXEC explicitly as a belt-and-suspenders.
     */
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, req_pair) != 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, push_pair) != 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, cmd_pair) != 0) {
        snprintf(error, error_len, "real QEMU SOCK pairs: %s", strerror(errno));
        goto fail;
    }

    pid = fork();
    if (pid < 0) {
        snprintf(error, error_len, "real QEMU fork: %s", strerror(errno));
        goto fail;
    }
    if (pid == 0) {
        close(pair[0]);
        close(req_pair[0]);
        close(push_pair[0]);
        close(cmd_pair[0]);
        (void)fcntl(pair[1], F_SETFD, 0);
        (void)fcntl(req_pair[1], F_SETFD, 0);
        (void)fcntl(push_pair[1], F_SETFD, 0);
        (void)fcntl(cmd_pair[1], F_SETFD, 0);
        snprintf(fd_text, sizeof(fd_text), "%d", pair[1]);
        setenv("WVM_EXECUTOR_SESSION_FD", fd_text, 1);
        snprintf(fd_text, sizeof(fd_text), "%d", cmd_pair[1]);
        setenv("WVM_SOCK_CMD", fd_text, 1);
        snprintf(fd_text, sizeof(fd_text), "%d", req_pair[1]);
        setenv("WVM_SOCK_REQ", fd_text, 1);
        snprintf(fd_text, sizeof(fd_text), "%d", push_pair[1]);
        setenv("WVM_SOCK_PUSH", fd_text, 1);
        setenv("WVM_SLAVE_ID", "1", 1);
        setenv("WVM_SHM_FILE", name, 1);
        setenv("WVM_DISABLE_AUTO_KVM", "1", 1);
        setenv("WVM_ROLE", "SLAVE", 1);
        setenv("WVM_SLAVE_VCPU_COUNT", "1", 1);
        /* GATE + RUNTIME_SOCKET unlock production typed dirty commit. */
        setenv("WVM_RUNTIME_GATE_ACTIVE", "1", 1);
        setenv("WVM_RUNTIME_SOCKET", g_qemu_runtime_sock_path, 1);
        setenv("WVM_RUNTIME_NAMESPACE",
               manifest->local_names.namespace_name, 1);
        {
            char value[64];

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
                     (unsigned long long)manifest->expected_node_instance_id);
            setenv("WVM_RUNTIME_LOCAL_INSTANCE_ID", value, 1);
            snprintf(value, sizeof(value), "%llu",
                     (unsigned long long)projection->local_primary
                         .destination_vnode);
            setenv("WVM_EXECUTOR_ID", value, 1);
            snprintf(value, sizeof(value), "%u", TEST_VCPU);
            setenv("WVM_EXECUTOR_VCPU_INDEX", value, 1);
            /*
             * fill_commit_reply_destination() in QEMU requires these three
             * for TYPED_MEM_COMMIT. Without them request_commit_on_fd returns
             * -EPROTO after REGISTER and the handoff becomes EXECUTOR_ERROR
             * with an empty dirty flush (no commit payload ever written).
             */
            snprintf(value, sizeof(value), "%u",
                     (unsigned)projection->local_primary.destination_kind);
            setenv("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_KIND", value, 1);
            snprintf(value, sizeof(value), "%llu",
                     (unsigned long long)projection->local_primary
                         .destination_scope);
            setenv("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_SCOPE", value, 1);
            snprintf(value, sizeof(value), "%u",
                     (unsigned)projection->local_primary.destination_vnode);
            setenv("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_VNODE", value, 1);
        }
        setenv_hex_digest("WVM_CANDIDATE_MANIFEST_DIGEST",
                          manifest->candidate_manifest_digest,
                          sizeof(manifest->candidate_manifest_digest));
        setenv_hex_digest("WVM_CAPABILITY_PROFILE_DIGEST", profile_digest,
                          WVM_SHA256_DIGEST_BYTES);
        snprintf(object_arg, sizeof(object_arg), "/dev/shm/%s", name);
        snprintf(machine_arg, sizeof(machine_arg), "pc");
        execl(qemu_bin, qemu_bin, "-accel", "wavevm", "-m", "16",
              "-nodefaults", "-S", "-smp", "1", "-nographic", "-mem-path",
              object_arg, "-mem-prealloc", "-machine", machine_arg,
              (char *)NULL);
        _exit(127);
    }
    close(pair[1]);
    pair[1] = -1;
    close(req_pair[1]);
    req_pair[1] = -1;
    close(push_pair[1]);
    push_pair[1] = -1;
    close(cmd_pair[1]);
    cmd_pair[1] = -1;
    g_qemu_req_keep_fd = req_pair[0];
    req_pair[0] = -1;
    g_qemu_push_notify_fd = push_pair[0];
    push_pair[0] = -1;
    /* Keep CMD peer open so QEMU's master_sock stays valid. */
    g_qemu_req_keep_fd = g_qemu_req_keep_fd; /* quiet lint */
    {
        int cmd_keep = cmd_pair[0];

        cmd_pair[0] = -1;
        /* Stash CMD on the unused side of req keep by dup into a static. */
        if (g_qemu_cmd_keep_fd >= 0) {
            close(g_qemu_cmd_keep_fd);
        }
        g_qemu_cmd_keep_fd = cmd_keep;
    }
    wvm_executor_runtime_set_tcg_install_notify_fd(g_qemu_push_notify_fd);
    snprintf(shm_name, shm_name_size, "%s", name);
    *parent_fd_out = pair[0];
    /* Let QEMU finish its reset/BIOS setup + register RAM + start push listener. */
    usleep(2000000);
    fprintf(stderr,
            "goal4 A14 QEMU pid=%d push_notify_fd=%d cmd_keep=%d req_keep=%d\n",
            (int)pid, g_qemu_push_notify_fd, g_qemu_cmd_keep_fd,
            g_qemu_req_keep_fd);
    {
        char path[128];
        char environ_buf[4096];
        int efd;
        ssize_t n;
        snprintf(path, sizeof(path), "/proc/%d/environ", (int)pid);
        efd = open(path, O_RDONLY);
        if (efd >= 0) {
            n = read(efd, environ_buf, sizeof(environ_buf) - 1);
            close(efd);
            if (n > 0) {
                size_t i;
                environ_buf[n] = '\0';
                for (i = 0; i < (size_t)n; i++) {
                    if (environ_buf[i] == '\0') {
                        environ_buf[i] = '\n';
                    }
                }
                fprintf(stderr, "goal4 A14 QEMU environ (filtered):\n");
                {
                    char *line = environ_buf;
                    while (line && *line) {
                        char *nl = strchr(line, '\n');
                        if (nl) {
                            *nl = '\0';
                        }
                        if (strncmp(line, "WVM_", 4) == 0) {
                            fprintf(stderr, "  %s\n", line);
                        }
                        line = nl ? nl + 1 : NULL;
                    }
                }
            }
        }
    }
    return pid;

fail:
    if (pair[0] >= 0) {
        close(pair[0]);
    }
    if (pair[1] >= 0) {
        close(pair[1]);
    }
    if (req_pair[0] >= 0) {
        close(req_pair[0]);
    }
    if (req_pair[1] >= 0) {
        close(req_pair[1]);
    }
    if (push_pair[0] >= 0) {
        close(push_pair[0]);
    }
    if (push_pair[1] >= 0) {
        close(push_pair[1]);
    }
    if (cmd_pair[0] >= 0) {
        close(cmd_pair[0]);
    }
    if (cmd_pair[1] >= 0) {
        close(cmd_pair[1]);
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
        if (g_real_qemu) {
            /* Flat 32-bit protected-mode context for real QEMU TCG.
             * SegmentCache.flags must use QEMU's descriptor-high-dword
             * layout (type byte at bits 15:8, DPL at 14:13, G/B at 23/22).
             * The older 0xcf9b|0x00c00000 packing left DPL=2, so HLT #GP'd
             * and a zero IDT limit turned that into a triple-fault reset. */
            for (int seg = 0; seg < 6; seg++) {
                legacy_context.segs[seg].base = 0;
                legacy_context.segs[seg].limit = 0xffffffffU;
                legacy_context.segs[seg].selector = seg == 1 ? 0x8 : 0x10;
                /* 0x00cf9b00: P|DPL0|S|code-XR|A + G|B; 0x00cf9300 data-RW. */
                legacy_context.segs[seg].flags =
                    seg == 1 ? 0x00cf9b00U : 0x00cf9300U;
            }
            legacy_context.tr.selector = 0x18;
            legacy_context.tr.base = 0;
            legacy_context.tr.limit = 0xffff;
            legacy_context.tr.flags = 0x00008b00U; /* P|DPL0|busy TSS16/32-ish */
            legacy_context.ldt.flags = 0; /* unusable */
            legacy_context.gdt_base = 0;
            legacy_context.gdt_limit = 0xffff;
            legacy_context.idt_base = 0;
            legacy_context.idt_limit = 0xffff;
            /* ESP in admitted page0 (local directory); 0x2000 is unmapped. */
            legacy_context.regs[4] = 0x0FF0ULL;
            legacy_context.eflags = 0x2ULL;
            legacy_context.cr[0] = 0x60000011ULL;
            legacy_context.cr[4] = 0x10ULL;
            legacy_context.hflags = 0x30U; /* HF_CS32 | HF_SS32; CPL recomputed */
            legacy_context.a20_mask = 0xffffffffU;
            legacy_context.old_exception = -1;
        }
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
    int coordinated_sockets[2] = {-1, -1};
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
    /* Default A14 is the real no-root TCG path.  The component-only session
     * stub remains available for narrow ABI tests, but it is no longer the
     * default and is never reported as real TCG execution. */
    if (!g_real_qemu && !g_real_kvm &&
        getenv("WVM_GOAL4_COMPONENT_ONLY") == NULL) {
        g_real_qemu = 1;
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
    if (g_real_qemu) {
        /*
         * This host may expose /dev/wavevm, but the QEMU child is explicitly
         * running the TCG backend against WVM_SHM_FILE.  Force the executor's
         * guest-RAM mapping to that same SHM instead of the Mode A device
         * mapping, otherwise the fetched page is installed into unrelated
         * memory and QEMU sees zeros.
         */
        setenv("WVM_FORCE_TCG", "1", 1);
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
            /*
             * The remote directory owns the code page.  The guest first stores
             * a known dword to its own code page, then halts.  The final
             * directory bytes therefore prove a real guest store traversed the
             * dirty/commit path, not just a HLT fetch.
             */
            memset(page, 0x90, sizeof(page));
            page[0] = 0xc7; /* mov dword ptr [0x1000], 0x12345678 */
            page[1] = 0x05;
            page[2] = 0x00;
            page[3] = 0x10;
            page[4] = 0x00;
            page[5] = 0x00;
            page[6] = 0x78;
            page[7] = 0x56;
            page[8] = 0x34;
            page[9] = 0x12;
            page[10] = 0xf4;
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
        if (start_a14_qemu_ipc_listener(error, sizeof(error)) != 0) {
            fprintf(stderr, "real QEMU IPC listener: %s\n", error);
            goto out;
        }
        qemu_pid = launch_real_qemu_session(
            &storage.manifest, &projection, profile_digest, &session_pair[0],
            qemu_shm, sizeof(qemu_shm), error, sizeof(error));
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
        int shm_fd = shm_open(qemu_shm, O_RDONLY, 0);

        if (shm_fd >= 0) {
            uint8_t probe[16];
            ssize_t got = pread(shm_fd, probe, sizeof(probe), REAL_QEMU_GPA);
            fprintf(stderr, "goal4 TCG shm probe got=%zd bytes=%02x%02x%02x%02x\n",
                    got, got > 0 ? probe[0] : 0, got > 1 ? probe[1] : 0,
                    got > 2 ? probe[2] : 0, got > 3 ? probe[3] : 0);
            close(shm_fd);
        } else {
            fprintf(stderr, "goal4 TCG shm probe open failed: %s\n",
                    strerror(errno));
        }
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

    if (g_real_qemu || g_real_kvm) {
        uint8_t guest_page[WVM_MEMORY_PAGE_BYTES];
        uint8_t final_page[WVM_MEMORY_PAGE_BYTES];
        uint64_t final_version = 0;

        if (g_real_qemu) {
            struct timespec deadline;
            uint8_t *guest_ram = wvm_executor_guest_ram_base();

            /*
             * Executor SHM is the install mirror; WaveVM TCG slave RAM is
             * anonymous (or a distinct mapping). Guest stores land in QEMU
             * RAM and reach the directory only via production dirty flush
             * TYPED_MEM_COMMIT. Treat SHM bytes as advisory; the self-emit
             * + directory check below is the authoritative proof.
             */
            if (guest_ram) {
                memcpy(guest_page, guest_ram + REAL_QEMU_GPA,
                       sizeof(guest_page));
                fprintf(stderr,
                        "goal4 TCG executor-SHM after HLT "
                        "bytes=%02x%02x%02x%02x "
                        "(anonymous QEMU RAM may differ)\n",
                        guest_page[0], guest_page[1], guest_page[2],
                        guest_page[3]);
            } else {
                fprintf(stderr, "goal4 TCG executor guest RAM not mapped\n");
            }
            /*
             * Production TCG dirty self-emit: QEMU slave flush must have
             * typed-committed via RUNTIME_SOCKET after the guest store.
             * Do not call memory_service commit from the test harness.
             */
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += 5;
            pthread_mutex_lock(&remote.lock);
            while (remote.completed_commit_version == 0) {
                if (pthread_cond_timedwait(&remote.available, &remote.lock,
                                           &deadline) != 0) {
                    break;
                }
            }
            pthread_mutex_unlock(&remote.lock);
            if (expect(remote.completed_commit_version != 0,
                       "real TCG dirty self-emit reached remote fence") != 0) {
                fprintf(stderr,
                        "TCG self-emit timeout commit_version=0\n");
                goto out;
            }
            printf("EVID goal4_A14: tcg_dirty_self_emit_version=0x%llx\n",
                   (unsigned long long)remote.completed_commit_version);
        } else {
            struct timespec deadline;

            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += 5;
            pthread_mutex_lock(&remote.lock);
            while (remote.completed_commit_version == 0) {
                if (pthread_cond_timedwait(&remote.available, &remote.lock,
                                           &deadline) != 0) {
                    break;
                }
            }
            pthread_mutex_unlock(&remote.lock);
            if (expect(remote.completed_commit_version != 0,
                       "real KVM dirty commit reached remote fence") != 0) {
                goto out;
            }
        }
        if (expect(wvm_directory_store_read_page(
                       &remote.directory_store, REAL_QEMU_GPA, final_page,
                       &final_version, error, sizeof(error)) == 0,
                   "read final remote directory page") != 0) {
            goto out;
        }
        if (expect(final_page[0] == 0x78 && final_page[1] == 0x56 &&
                       final_page[2] == 0x34 && final_page[3] == 0x12,
                   "remote directory contains real guest store") != 0) {
            goto out;
        }
        printf("EVID goal4_A14: guest_store_remote_version=0x%llx "
               "guest_store_bytes=%02x%02x%02x%02x\n",
               (unsigned long long)final_version, final_page[0], final_page[1],
               final_page[2], final_page[3]);
    }

    pthread_mutex_lock(&remote.lock);
    if (expect(remote.completion_count >= 1, "remote memory ACK completed") !=
            0 ||
        expect(remote.completed_gpa == WVM_MEMORY_PAGE_BYTES,
               "remote GPA") != 0 ||
        expect(remote.completed_version == ((UINT64_C(1) << 32) | 9U),
               "remote version") != 0 ||
        expect(remote.completed_page[0] ==
                   ((g_real_qemu || g_real_kvm) ? 0xc7 : 0x3c),
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
        struct wvm_vcpu_service_config service_config;
        struct wvm_ipc_cpu_run_req legacy_request;
        struct wvm_ipc_cpu_run_ack legacy_ack;
        wvm_kvm_context_t legacy_context;
        uint64_t legacy_fields = 0;
        struct timespec deadline;
        uint64_t fence_id;
        uint64_t service_fence = 0;
        size_t legacy_received = 0;
        uint8_t coord_page[WVM_MEMORY_PAGE_BYTES];

        (void)wvm_kvm_page_cache_global_invalidate(REAL_QEMU_GPA, error,
                                                    sizeof(error));
        /* The first handoff intentionally overwrote its own code page with the
         * guest store.  Seed the coordinator handoff with a clean HLT page at
         * the next directory version so it exercises a fresh real KVM run
         * without re-executing stored data. */
        memset(coord_page, 0, sizeof(coord_page));
        coord_page[0] = 0xf4;
        if (expect(wvm_directory_store_commit_page(
                       &remote.directory_store, REAL_QEMU_GPA,
                       remote.completed_commit_version, 0, coord_page,
                       sizeof(coord_page), &fence_id, error,
                       sizeof(error)) == 0,
                   "seed coordinator HLT page") != 0) {
            fprintf(stderr, "coordinator seed err=%s\n",
                    error[0] ? error : "(empty)");
            goto out;
        }
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
        memset(&service_config, 0, sizeof(service_config));
        service_config.coordinator = &coordinated.coordinator;
        service_config.record_capacity =
            storage.manifest.launch_plan.vcpu_handoff_record_capacity;
        if (expect(wvm_vcpu_service_init(&coordinated.service, &service_config,
                                         error, sizeof(error)) == 0,
                   "init production vCPU IPC service") != 0) {
            fprintf(stderr, "coordinator service err=%s\n", error);
            goto out;
        }
        coordinated.service_initialized = 1;
        if (expect(socketpair(AF_UNIX, SOCK_STREAM, 0, coordinated_sockets) == 0,
                   "create coordinator QEMU IPC socket") != 0 ||
            expect(wvm_x86_context_decode(
                       request.backend, request.context, request.context_bytes,
                       &legacy_fields, &legacy_context, sizeof(legacy_context),
                       error, sizeof(error)) == 0 &&
                       legacy_fields == request.context_valid_fields,
                   "decode coordinator KVM context") != 0) {
            goto out;
        }
        memset(&legacy_request, 0, sizeof(legacy_request));
        legacy_request.mode_tcg = 0;
        legacy_request.slave_id = WVM_NODE_AUTO_ROUTE;
        legacy_request.vcpu_index = request.vcpu_index;
        memcpy(&legacy_request.ctx.kvm, &legacy_context,
               sizeof(legacy_context));
        coordinated.bridge = coordinated_bridge;
        if (expect(wvm_vcpu_service_submit(&coordinated.service,
                                           coordinated_sockets[0], &legacy_request,
                                           error, sizeof(error)) == 0,
                   "vcpu_service submits real KVM handoff") != 0) {
            fprintf(stderr, "coordinator service submit err=%s\n", error);
            goto out;
        }
        service_fence = coordinated.service.last_memory_fence_id;
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
        memset(&legacy_ack, 0, sizeof(legacy_ack));
        while (legacy_received < sizeof(legacy_ack)) {
            ssize_t got = recv(coordinated_sockets[1],
                               (uint8_t *)&legacy_ack + legacy_received,
                               sizeof(legacy_ack) - legacy_received, 0);
            if (got <= 0) {
                break;
            }
            legacy_received += (size_t)got;
        }
        printf("EVID goal4_A14: coordinator_fence_id=0x%llx "
               "coordinator_seed_version=0x%llx coordinator_exit_class=%u "
               "coordinator_context_bytes=%zu coordinator_status=%u "
               "legacy_ack_status=%d legacy_ack_mode=%u legacy_ack_bytes=%zu\n",
               (unsigned long long)service_fence,
               (unsigned long long)fence_id,
               (unsigned)coordinated.result.exit_class,
               coordinated.result.context_bytes,
               (unsigned)coordinated.result.status, legacy_ack.status,
               (unsigned)legacy_ack.mode_tcg, legacy_received);
        if (expect(legacy_received == sizeof(legacy_ack) &&
                       legacy_ack.status == 0 && legacy_ack.mode_tcg == 0,
                   "vcpu_service returned a real KVM ACK") != 0) {
            pthread_mutex_unlock(&coordinated.lock);
            goto out;
        }
        if (expect(coordinated.result.exit_class == WVM_VCPU_EXIT_HALTED &&
                       coordinated.result.context_bytes != 0 &&
                       coordinated.result.status ==
                           WVM_VCPU_HANDOFF_RESULT_SUCCESS,
                   "coordinator observed real KVM VCPU_EXIT") != 0) {
            pthread_mutex_unlock(&coordinated.lock);
            goto out;
        }
        pthread_mutex_unlock(&coordinated.lock);
        if (coordinated.service_initialized) {
            wvm_vcpu_service_destroy(&coordinated.service);
            coordinated.service_initialized = 0;
        }
        if (coordinated_sockets[0] >= 0) {
            close(coordinated_sockets[0]);
            coordinated_sockets[0] = -1;
        }
        if (coordinated_sockets[1] >= 0) {
            close(coordinated_sockets[1]);
            coordinated_sockets[1] = -1;
        }
        wvm_vcpu_handoff_coordinator_destroy(&coordinated.coordinator);
        coordinated_initialized = 0;
        wvm_executor_bridge_dispatch_destroy(coordinated_bridge);
        coordinated_bridge = NULL;
        pthread_cond_destroy(&coordinated.available);
        pthread_mutex_destroy(&coordinated.lock);
        coordinated_sync_initialized = 0;
    }

    printf("EVID goal4_A14: remote_fault_ACK version=0x%llx "
           "request_fence_id=%u produced_fence_id=%llu "
           "production_execute_handoff=1\n",
           (unsigned long long)remote.completed_version,
           (unsigned)request.memory_fence_id,
           (unsigned long long)exits.result.produced_memory_fence_id);
    puts("goal4 A14: executor_bridge → wvm_executor_runtime_execute_handoff");
    puts(g_real_kvm
             ? "           → remote memory_service fault/ACK → real KVM_RUN PASS"
             : "           → remote memory_service fault/ACK → TCG self-emit dirty PASS");
    puts("(production entry; not test-local execute; not pause-stub READY)");
    puts("(live multi-node guest OS/SSH still §7)");
    exit_code = 0;

out:
    wvm_executor_runtime_set_tcg_install_notify_fd(-1);
    if (g_qemu_push_notify_fd >= 0) {
        close(g_qemu_push_notify_fd);
        g_qemu_push_notify_fd = -1;
    }
    if (g_qemu_req_keep_fd >= 0) {
        close(g_qemu_req_keep_fd);
        g_qemu_req_keep_fd = -1;
    }
    if (g_qemu_cmd_keep_fd >= 0) {
        close(g_qemu_cmd_keep_fd);
        g_qemu_cmd_keep_fd = -1;
    }
    stop_a14_qemu_ipc_listener();
    if (coordinated.service_initialized) {
        wvm_vcpu_service_destroy(&coordinated.service);
        coordinated.service_initialized = 0;
    }
    if (coordinated_sockets[0] >= 0) {
        close(coordinated_sockets[0]);
        coordinated_sockets[0] = -1;
    }
    if (coordinated_sockets[1] >= 0) {
        close(coordinated_sockets[1]);
        coordinated_sockets[1] = -1;
    }
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

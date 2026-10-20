/*
 * goal §4 / A14: drive production wvm_executor_runtime_execute_handoff through
 * executor_bridge with a real memory_service remote fault side effect.
 * Forbidden: test-local execute_with_remote_memory, tcg_helper_stub READY alone.
 * Guest OS/SSH remains goal §7. Multi-node CREATE may still use stub for CP.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "executor_bridge.h"
#include "executor_runtime.h"
#include "memory_service.h"
#include "runtime_context.h"
#include "wavevm_executor_session.h"
#include "wavevm_membership.h"
#include "wavevm_protocol.h"
#include "wavevm_runtime_gate.h"
#include "wavevm_vcpu_handoff.h"
#include "wavevm_x86_context.h"

#define TEST_VM_ID 256U
#define TEST_VCPU 0U

struct remote_state {
    pthread_mutex_t lock;
    pthread_cond_t available;
    int send_count;
    int completion_count;
    uint64_t completed_gpa;
    uint64_t completed_version;
    uint16_t completed_status;
    uint8_t completed_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_envelope sent;
    uint8_t sent_payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    size_t sent_payload_bytes;
    struct wvm_memory_service *service;
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
    manifest->negotiated_profile.backend = WVM_MANIFEST_BACKEND_TCG;
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
    (void)opaque;
    (void)gpa;
    (void)error;
    (void)error_len;
    memset(data, 0xa5, WVM_MEMORY_PAGE_BYTES);
    *version_out = 7;
    return 0;
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
    (void)opaque;
    (void)gpa;
    (void)offset;
    (void)data;
    (void)data_bytes;
    (void)error;
    (void)error_len;
    *result_version = base_version + 1;
    return 0;
}

static int complete_commit(void *opaque,
                           const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                           uint64_t gpa, uint16_t status,
                           uint64_t result_version,
                           uint32_t directory_physical_node_id,
                           uint64_t directory_node_instance_id, char *error,
                           size_t error_len)
{
    (void)opaque;
    (void)operation_id;
    (void)gpa;
    (void)status;
    (void)result_version;
    (void)directory_physical_node_id;
    (void)directory_node_instance_id;
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

static void *ack_worker(void *opaque)
{
    struct remote_state *state = opaque;
    uint8_t remote_page[WVM_MEMORY_PAGE_BYTES];
    char error[256];

    memset(remote_page, 0x3c, sizeof(remote_page));
    for (;;) {
        struct wvm_envelope sent;
        struct wvm_mem_ack ack;
        struct wvm_envelope_route reply_route;
        struct wvm_envelope response;
        uint8_t ack_payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
        size_t ack_payload_bytes = 0;
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
        if (!have_send || sent.message_type != WVM_ENVELOPE_MSG_MEM_READ ||
            !state->service) {
            continue;
        }
        memset(&ack, 0, sizeof(ack));
        ack.gpa = WVM_MEMORY_PAGE_BYTES;
        ack.version = 9;
        ack.status = WVM_MEM_ACK_SUCCESS;
        ack.directory_physical_node_id = 99;
        ack.directory_node_instance_id = 202;
        ack.data = remote_page;
        ack.data_bytes = sizeof(remote_page);
        memset(&reply_route, 0, sizeof(reply_route));
        reply_route.destination_kind =
            WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
        reply_route.destination_scope = 41;
        reply_route.destination_vnode_or_endpoint = 7;
        reply_route.hop_limit = 4;
        memset(error, 0, sizeof(error));
        if (wvm_mem_ack_envelope_build(
                &sent, &reply_route, 2, &ack, ack_payload, sizeof(ack_payload),
                &ack_payload_bytes, &response, error, sizeof(error)) != 0 ||
            wvm_memory_service_dispatch(state->service, &response, error,
                                        sizeof(error)) != 0) {
            fprintf(stderr, "goal4 ack_worker: %s\n", error);
        }
    }
    return NULL;
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

static int make_request(const struct wvm_node_runtime_manifest *manifest,
                        const struct wvm_runtime_dispatch_projection *projection,
                        struct wvm_vcpu_handoff_request *request,
                        struct wvm_envelope *envelope, uint8_t *payload,
                        size_t payload_capacity, size_t *payload_bytes,
                        char *error, size_t error_len)
{
    static wvm_tcg_context_t legacy_context;
    static uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                           sizeof(legacy_context)];
    static size_t context_bytes;

    memset(request, 0, sizeof(*request));
    memset(&legacy_context, 0, sizeof(legacy_context));
    legacy_context.eip = UINT64_C(0x1122334455667788);
    if (wvm_x86_context_encode(
            WVM_VCPU_BACKEND_TCG,
            WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
            &legacy_context, sizeof(legacy_context), context, sizeof(context),
            &context_bytes, error, error_len) != 0) {
        return -1;
    }
    request->protocol_version = WVM_VCPU_HANDOFF_REQUEST_VERSION;
    request->backend = WVM_VCPU_BACKEND_TCG;
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
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_manifest_storage storage;
    struct wvm_capability_ref capability;
    struct wvm_runtime_gate gate;
    struct wvm_runtime_registration registration;
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t connection_id = 0;
    struct wvm_memory_service_config mem_config;
    struct wvm_memory_service service;
    struct remote_state remote;
    struct session_peer peer;
    struct exit_capture exits;
    struct wvm_node_runtime_context runtime_context;
    struct wvm_executor_bridge_config bridge_config;
    void *bridge = NULL;
    struct wvm_vcpu_handoff_request request;
    struct wvm_envelope envelope;
    uint8_t payload[WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD];
    size_t payload_bytes = 0;
    int session_pair[2] = {-1, -1};
    pthread_t ack_thread;
    pthread_t session_thread;
    int ack_started = 0;
    int session_started = 0;
    int bound = 0;
    int installed = 0;
    char error[256] = {0};
    int exit_code = 1;

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
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, session_pair) !=
        0) {
        perror("socketpair");
        goto out;
    }
    if (expect(wvm_executor_runtime_attach_tcg_session(TEST_VCPU,
                                                      session_pair[0]) == 0,
               "attach TCG session") != 0) {
        close(session_pair[0]);
        close(session_pair[1]);
        session_pair[0] = session_pair[1] = -1;
        goto out;
    }
    session_pair[0] = -1; /* owned by executor runtime */
    memset(&peer, 0, sizeof(peer));
    peer.fd = session_pair[1];
    if (pthread_create(&session_thread, NULL, session_worker, &peer) != 0) {
        goto out;
    }
    session_started = 1;
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

    pthread_mutex_lock(&remote.lock);
    if (expect(remote.completion_count >= 1, "remote memory ACK completed") !=
            0 ||
        expect(remote.completed_gpa == WVM_MEMORY_PAGE_BYTES,
               "remote GPA") != 0 ||
        expect(remote.completed_version == 9, "remote version") != 0 ||
        expect(remote.completed_page[0] == 0x3c, "remote page bytes") != 0) {
        pthread_mutex_unlock(&remote.lock);
        goto out;
    }
    pthread_mutex_unlock(&remote.lock);

    pthread_mutex_lock(&exits.lock);
    if (expect(exits.result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS,
               "VCPU_EXIT SUCCESS") != 0 ||
        expect(exits.response.message_type == WVM_ENVELOPE_MSG_VCPU_EXIT,
               "typed VCPU_EXIT") != 0 ||
        expect(peer.run_count == 1, "TCG session run-once") != 0) {
        pthread_mutex_unlock(&exits.lock);
        goto out;
    }
    pthread_mutex_unlock(&exits.lock);

    envelope.delivery_attempt_id = 2;
    if (expect(wvm_executor_bridge_dispatch(bridge, &envelope, error,
                                            sizeof(error)) == 0 &&
                   wait_exit(&exits, 2) == 0,
               "cached replay without second execute") != 0 ||
        expect(peer.run_count == 1, "SPEC-vcpu-run-once cache holds") != 0) {
        goto out;
    }

    puts("goal4 A14: executor_bridge → wvm_executor_runtime_execute_handoff");
    puts("           → remote memory_service fault/ACK → TCG run-once PASS");
    puts("(production entry; not test-local execute; not pause-stub READY)");
    puts("(live multi-node guest OS/SSH still §7)");
    exit_code = 0;

out:
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
    pthread_cond_destroy(&remote.available);
    pthread_mutex_destroy(&remote.lock);
    pthread_cond_destroy(&exits.available);
    pthread_mutex_destroy(&exits.lock);
    wvm_route_runtime_destroy(&routes);
    return exit_code;
}

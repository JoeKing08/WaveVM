/*
 * goal §4 / A14: typed execute_handoff whose side effect is a real
 * memory_service remote fault → ACK (not tcg_helper_stub pause-as-READY,
 * not a local marker-only stub). Companion shell also runs
 * test_memory_service + test_executor_bridge. Guest OS/SSH remains §7.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "memory_service.h"
#include "wavevm_membership.h"
#include "wavevm_protocol.h"
#include "wavevm_vcpu_handoff.h"

struct remote_state {
    pthread_mutex_t lock;
    int send_count;
    int completion_count;
    uint64_t completed_gpa;
    uint64_t completed_version;
    uint16_t completed_status;
    uint8_t completed_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_envelope sent;
    uint8_t sent_payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    size_t sent_payload_bytes;
    int execute_called;
};

struct exec_ctx {
    struct remote_state *state;
    struct wvm_memory_service *service;
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
    snapshot->route_snapshot_key.scope_key.vm_id = 256;
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

static void fill_projection(
    struct wvm_runtime_dispatch_projection *projection,
    struct wvm_runtime_memory_dispatch memory[2],
    const struct wvm_route_snapshot_key *route_key)
{
    memset(projection, 0, sizeof(*projection));
    memset(projection->candidate_manifest_digest, 0x51,
           sizeof(projection->candidate_manifest_digest));
    projection->vm_id = 256;
    projection->vm_incarnation = 7;
    projection->manifest_generation = 3;
    projection->physical_node_id = 17;
    projection->expected_node_instance_id = 101;
    memset(projection->activation_fence, 0x52,
           sizeof(projection->activation_fence));
    projection->required_route_snapshot_key = *route_key;
    projection->route_topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    projection->local_primary.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    projection->local_primary.destination_scope = 41;
    projection->local_primary.destination_vnode = 0;
    fill_endpoint(&projection->local_sidecar_endpoint, 17, 19017);
    projection->memory_dispatch.entries = memory;
    projection->memory_dispatch.count = 2;
    projection->memory_dispatch.capacity = 2;
    memset(memory, 0, 2 * sizeof(*memory));
    memory[0].gpa_start = 0;
    memory[0].bytes = WVM_MEMORY_PAGE_BYTES;
    memory[0].directory = projection->local_primary;
    memory[0].executor = projection->local_primary;
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

    (void)operation_id;
    (void)directory_physical_node_id;
    (void)directory_node_instance_id;
    (void)error;
    (void)error_len;
    if (!state || (status == WVM_MEM_ACK_SUCCESS &&
                   (!data || data_bytes != WVM_MEMORY_PAGE_BYTES))) {
        return -EINVAL;
    }
    pthread_mutex_lock(&state->lock);
    state->completion_count++;
    state->completed_gpa = gpa;
    state->completed_version = version;
    state->completed_status = status;
    if (data_bytes != 0) {
        memcpy(state->completed_page, data, data_bytes);
    }
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

static int send_envelope(void *opaque, const struct wvm_envelope *envelope,
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
    pthread_mutex_unlock(&state->lock);
    return 0;
}

/* Production-shaped execute_handoff: remote memory fault as the side effect. */
static int execute_with_remote_memory(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    struct wvm_vcpu_handoff_result *result, uint8_t *result_context,
    size_t result_context_capacity, char *error, size_t error_len)
{
    struct exec_ctx *ctx = opaque;
    uint8_t op[WVM_IDENTITY_ID_BYTES];

    if (!ctx || !ctx->state || !ctx->service || !request || !result ||
        !result_context || result_context_capacity < 64) {
        if (error && error_len) {
            snprintf(error, error_len, "execute_with_remote_memory bad input");
        }
        return -1;
    }
    ctx->state->execute_called = 1;
    memset(op, 0, sizeof(op));
    op[15] = 0xA1;
    if (wvm_memory_service_request_fault(ctx->service, WVM_MEMORY_PAGE_BYTES,
                                         op, 1, error, error_len) != 0) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status = WVM_VCPU_HANDOFF_RESULT_SUCCESS;
    result->handoff_sequence = request->handoff_sequence;
    result->produced_memory_fence_id = request->memory_fence_id;
    result->context_valid_fields = request->context_valid_fields;
    memset(result_context, 0, result_context_capacity);
    result_context[0] = 0xA5;
    result->context = result_context;
    result->context_bytes = 64;
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
    struct wvm_memory_service_config config;
    struct wvm_memory_service service;
    struct remote_state state;
    struct exec_ctx exec;
    struct wvm_vcpu_handoff_request request;
    struct wvm_vcpu_handoff_result result;
    uint8_t result_context[256];
    uint8_t remote_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_mem_ack ack;
    struct wvm_envelope_route reply_route;
    struct wvm_envelope response;
    uint8_t ack_payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    size_t ack_payload_bytes = 0;
    char error[256] = {0};

    memset(remote_page, 0x3c, sizeof(remote_page));
    fill_rule(&rules[0], 41, 0, 17, 101, 17);
    fill_rule(&rules[1], 99, 1, 99, 202, 99);
    if (finalize_snapshot(&snapshot, rules, acks, error, sizeof(error)) != 0) {
        fprintf(stderr, "goal4 setup: %s\n", error);
        return 1;
    }
    fill_projection(&projection, memory, &snapshot.route_snapshot_key);
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
    memset(&state, 0, sizeof(state));
    if (pthread_mutex_init(&state.lock, NULL) != 0) {
        return 1;
    }
    memset(&config, 0, sizeof(config));
    config.dispatch = &projection;
    config.route_runtime = &routes;
    config.local_physical_node_id = 17;
    config.local_node_instance_id = 101;
    config.local_runtime_instance_id = 1001;
    config.completion_timeout_ms = 5000;
    config.read_page = read_page;
    config.commit_page = commit_page;
    config.complete_commit = complete_commit;
    config.complete_fault = complete_fault;
    config.send_envelope = send_envelope;
    config.opaque = &state;
    if (expect(wvm_memory_service_init(&service, &config, error,
                                       sizeof(error)) == 0,
               "init memory_service") != 0) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    exec.state = &state;
    exec.service = &service;
    memset(&request, 0, sizeof(request));
    request.backend = WVM_VCPU_BACKEND_TCG;
    request.handoff_sequence = 7;
    request.memory_fence_id = 11;
    request.memory_fence_result = WVM_VCPU_MEMORY_FENCE_SUCCEEDED;
    request.context_valid_fields = 1;
    request.destination_executor_id = 1;
    request.vm_id = 256;
    request.vm_incarnation = 7;
    request.manifest_generation = 3;

    if (expect(execute_with_remote_memory(&exec, &request, &result,
                                          result_context, sizeof(result_context),
                                          error, sizeof(error)) == 0,
               "execute_handoff returns 0") != 0 ||
        expect(state.execute_called == 1, "execute invoked") != 0 ||
        expect(result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS, "SUCCESS") !=
            0 ||
        expect(result_context[0] == 0xA5, "result context") != 0 ||
        expect(state.send_count == 1, "remote MEM_READ sent") != 0 ||
        expect(state.sent.message_type == WVM_ENVELOPE_MSG_MEM_READ,
               "MEM_READ") != 0) {
        fprintf(stderr, "err=%s\n", error);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
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
    reply_route.destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    reply_route.destination_scope = 41;
    reply_route.destination_vnode_or_endpoint = 0;
    reply_route.hop_limit = 4;
    if (expect(wvm_mem_ack_envelope_build(
                   &state.sent, &reply_route, 2, &ack, ack_payload,
                   sizeof(ack_payload), &ack_payload_bytes, &response, error,
                   sizeof(error)) == 0 &&
                   wvm_memory_service_dispatch(&service, &response, error,
                                               sizeof(error)) == 0 &&
                   state.completion_count == 1 &&
                   state.completed_gpa == WVM_MEMORY_PAGE_BYTES &&
                   state.completed_version == 9 &&
                   memcmp(state.completed_page, remote_page,
                          sizeof(remote_page)) == 0,
               "remote ACK completes memory side effect") != 0) {
        fprintf(stderr, "ack err=%s completion=%d\n", error,
                state.completion_count);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    wvm_memory_service_destroy(&service);
    wvm_route_runtime_destroy(&routes);
    pthread_mutex_destroy(&state.lock);
    puts("goal4 A14: execute_handoff → memory_service remote fault/ACK PASS");
    puts("(not pause-stub READY; live multi-node guest OS still §7)");
    return 0;
}

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "executor_bridge.h"
#include "wavevm_membership.h"
#include "wavevm_protocol.h"
#include "wavevm_vcpu_handoff.h"
#include "wavevm_x86_context.h"

#define TEST_VM_ID 42U

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "executor bridge test: %s\n", message);
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

static void fill_rule(struct wvm_route_rule_record *rule, uint32_t vnode,
                      uint8_t endpoint_tail, uint16_t port)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = endpoint_tail;
    rule->next_hop_member.instance_id = 1000U + endpoint_tail;
    fill_endpoint(&rule->next_hop_endpoint, endpoint_tail, port);
    rule->hop_limit = 4;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rules,
                             struct wvm_required_ack_entry *acks, char *error,
                             size_t error_len)
{
    uint8_t encoded[16384];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    size_t i;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = TEST_VM_ID;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 4;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 9;
    snapshot->route_snapshot_key.topology_revision = 2;
    snapshot->route_snapshot_key.route_generation = 3;
    snapshot->membership_revision = 2;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = 2;
    snapshot->next_hop_rules.capacity = 2;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;
    for (i = 0; i < snapshot->required_ack_set.entries.count; i++) {
        acks[i].member_key = rules[0].next_hop_member;
        acks[i].endpoint = rules[0].next_hop_endpoint;
        acks[i].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        acks[i].expected_snapshot_key = snapshot->route_snapshot_key;
    }
    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    for (i = 0; i < snapshot->required_ack_set.entries.count; i++) {
        memcpy(acks[i].expected_snapshot_key.snapshot_digest, digest,
               sizeof(digest));
    }
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
    manifest->manifest_generation = 1;
    memset(manifest->admission_tx_id, 0x22, sizeof(manifest->admission_tx_id));
    memset(manifest->eligibility_fence_digest, 0x33,
           sizeof(manifest->eligibility_fence_digest));
    manifest->has_activation_fence = 1;
    memset(manifest->activation_fence, 0x44,
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
    manifest->launch_plan.vcpu_handoff_record_capacity = 1;
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
    projection->route_topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    projection->local_primary.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    projection->local_primary.destination_vnode = 7;
    fill_endpoint(&projection->local_sidecar_endpoint, 17, 19017);
}

struct send_state {
    pthread_mutex_t lock;
    pthread_cond_t available;
    size_t count;
    struct wvm_envelope response;
    struct wvm_vcpu_handoff_result result;
    uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                    sizeof(wvm_tcg_context_t)];
    size_t context_bytes;
};

struct executor_stub {
    pthread_mutex_t lock;
    pthread_cond_t entered;
    pthread_cond_t release;
    unsigned int received;
    unsigned int entered_count;
    int valid;
    int block;
    int released;
};

static int capture_response(void *opaque, const struct wvm_envelope *envelope,
                            char *error, size_t error_len)
{
    struct send_state *state = opaque;
    struct wvm_vcpu_handoff_result result;

    if (!state || !envelope ||
        wvm_vcpu_handoff_result_decode(envelope->payload,
                                       envelope->payload_bytes,
                                       &result, error, error_len) !=
            0) {
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

static int wait_for_response(struct send_state *state, size_t expected)
{
    struct timespec deadline;
    int result = 0;

    if (!state || clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += 2;
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

static int executor_stub_execute(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    struct wvm_vcpu_handoff_result *result, uint8_t *result_context,
    size_t result_context_capacity, char *error, size_t error_len)
{
    struct executor_stub *stub = opaque;
    wvm_tcg_context_t context;
    uint64_t fields = 0;
    size_t encoded_bytes = 0;

    if (!stub || !request || !result || !result_context ||
        result_context_capacity < WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES ||
        request->backend != WVM_VCPU_BACKEND_TCG ||
        request->vcpu_index != 3 ||
        wvm_x86_context_decode(
            request->backend, request->context, request->context_bytes,
            &fields, &context, sizeof(context), error, error_len) != 0 ||
        fields != request->context_valid_fields ||
        context.eip != UINT64_C(0x1122334455667788)) {
        if (stub) {
            pthread_mutex_lock(&stub->lock);
            stub->valid = 0;
            pthread_mutex_unlock(&stub->lock);
        }
        return -EPROTO;
    }
    pthread_mutex_lock(&stub->lock);
    if (stub->block) {
        stub->entered_count++;
        pthread_cond_broadcast(&stub->entered);
        while (!stub->released) {
            pthread_cond_wait(&stub->release, &stub->lock);
        }
    }
    pthread_mutex_unlock(&stub->lock);
    context.eip += 4;
    if (wvm_x86_context_encode(
            request->backend, request->context_valid_fields, &context,
            sizeof(context), result_context, result_context_capacity,
            &encoded_bytes, error, error_len) != 0) {
        return -EPROTO;
    }
    memset(result, 0, sizeof(*result));
    result->protocol_version = WVM_VCPU_HANDOFF_RESULT_VERSION;
    result->status = WVM_VCPU_HANDOFF_RESULT_SUCCESS;
    result->exit_class = WVM_VCPU_EXIT_BUDGET;
    result->backend = request->backend;
    result->vm_id = request->vm_id;
    result->vm_incarnation = request->vm_incarnation;
    result->manifest_generation = request->manifest_generation;
    result->origin_physical_node_id = request->origin_physical_node_id;
    result->origin_runtime_instance_id = request->origin_runtime_instance_id;
    result->vcpu_index = request->vcpu_index;
    result->handoff_sequence = request->handoff_sequence;
    result->produced_memory_fence_id = request->memory_fence_id + 1U;
    memcpy(result->operation_id, request->operation_id,
           sizeof(result->operation_id));
    result->context_schema_version = request->context_schema_version;
    result->context_valid_fields = request->context_valid_fields;
    result->context = result_context;
    result->context_bytes = encoded_bytes;
    pthread_mutex_lock(&stub->lock);
    stub->received++;
    pthread_mutex_unlock(&stub->lock);
    return 0;
}

static int make_request(const struct wvm_node_runtime_manifest *manifest,
                        const struct wvm_runtime_dispatch_projection *projection,
                        uint32_t vcpu_index, uint8_t operation_tail,
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
    request->vcpu_index = vcpu_index;
    request->destination_executor_id =
        projection->local_primary.destination_vnode;
    request->reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    request->reply_destination_vnode = 9;
    request->handoff_sequence = 1;
    request->memory_fence_id = 10;
    request->local_interrupt_watermark = 11;
    request->device_event_watermark = 12;
    request->operation_id[15] = operation_tail;
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
    struct wvm_node_runtime_manifest manifest;
    struct wvm_capability_ref capability;
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_gate gate;
    struct wvm_runtime_registration registration;
    struct wvm_route_runtime routes;
    struct wvm_executor_bridge_config config;
    struct wvm_vcpu_handoff_request request;
    struct wvm_envelope envelope;
    struct send_state sent;
    struct executor_stub stub;
    struct wvm_envelope response;
    struct wvm_vcpu_handoff_result result;
    wvm_tcg_context_t returned_context;
    uint8_t payload[WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES +
                    WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                    sizeof(wvm_tcg_context_t)];
    uint8_t result_context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                           sizeof(wvm_tcg_context_t)];
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    size_t payload_bytes = 0;
    uint64_t connection_id = 0;
    uint64_t decoded_fields = 0;
    unsigned int stub_received = 0;
    int stub_valid = 0;
    int sent_initialized = 0;
    int stub_initialized = 0;
    int exit_code = 1;
    void *bridge = NULL;
    char error[256] = {0};

    fill_rule(&rules[0], 7, 17, 19017);
    fill_rule(&rules[1], 9, 18, 19018);
    if (expect(finalize_snapshot(&snapshot, rules, acks, error,
                                 sizeof(error)) == 0,
               "build route snapshot") ||
        expect(setup_manifest(&manifest, &capability,
                              &snapshot.route_snapshot_key, error,
                              sizeof(error)) == 0,
               "build admitted manifest")) {
        return 1;
    }
    fill_projection(&projection, &manifest);
    if (expect(wvm_runtime_dispatch_projection_validate(
                   &projection, error, sizeof(error)) == 0,
               "build admitted dispatch projection")) {
        return 1;
    }
    wvm_route_runtime_init(&routes);
    if (expect(wvm_route_runtime_prepare(&routes, &snapshot, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &routes, &snapshot.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate route snapshot")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    wvm_runtime_gate_init(&gate);
    if (expect(wvm_runtime_gate_prepare(&gate, &manifest,
                                        manifest.physical_node_id,
                                        manifest.expected_node_instance_id,
                                        error, sizeof(error)) == 0 &&
                   wvm_runtime_manifest_profile_digest(
                       &manifest, profile_digest, error, sizeof(error)) == 0,
               "prepare admitted runtime gate")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&registration, 0, sizeof(registration));
    registration.connection_role = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    registration.vm_id = manifest.vm_id;
    registration.vm_incarnation = manifest.vm_incarnation;
    registration.manifest_generation = manifest.manifest_generation;
    memcpy(registration.candidate_manifest_digest,
           manifest.candidate_manifest_digest,
           sizeof(registration.candidate_manifest_digest));
    registration.local_runtime_instance_id = manifest.expected_node_instance_id;
    registration.caller_process_instance_id = 501;
    memcpy(registration.capability_profile_digest, profile_digest,
           sizeof(registration.capability_profile_digest));
    snprintf(registration.requested_endpoint_name,
             sizeof(registration.requested_endpoint_name), "%s",
             manifest.local_names.namespace_name);
    if (expect(wvm_runtime_gate_register(&gate, &registration, &connection_id,
                                         error, sizeof(error)) == 0 &&
                   wvm_runtime_gate_activate(&gate, manifest.activation_fence,
                                             error, sizeof(error)) == 0,
               "register and activate runtime gate")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&sent, 0, sizeof(sent));
    if (expect(pthread_mutex_init(&sent.lock, NULL) == 0,
               "initialize typed result lock")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(pthread_cond_init(&sent.available, NULL) == 0,
               "initialize typed result condition")) {
        pthread_mutex_destroy(&sent.lock);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    sent_initialized = 1;
    memset(&stub, 0, sizeof(stub));
    stub.valid = 1;
    if (expect(pthread_mutex_init(&stub.lock, NULL) == 0,
               "initialize typed executor stub") ||
        expect(pthread_cond_init(&stub.entered, NULL) == 0,
               "initialize stub entered condition") ||
        expect(pthread_cond_init(&stub.release, NULL) == 0,
               "initialize stub release condition")) {
        pthread_mutex_destroy(&stub.lock);
        pthread_cond_destroy(&sent.available);
        pthread_mutex_destroy(&sent.lock);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    stub_initialized = 1;
    memset(&config, 0, sizeof(config));
    config.manifest = &manifest;
    config.runtime_gate = &gate;
    config.dispatch = &projection;
    config.route_runtime = &routes;
    config.local_runtime_instance_id = manifest.expected_node_instance_id;
    config.runtime_connection_id = connection_id;
    config.operation_retention_horizon_ms =
        snapshot.operation_retention_horizon_ms;
    config.execute_handoff = executor_stub_execute;
    config.execute_handoff_opaque = &stub;
    config.send_envelope = capture_response;
    config.send_envelope_opaque = &sent;
    if (expect(wvm_executor_bridge_dispatch_init(&config, &bridge, error,
                                                 sizeof(error)) == 0,
               "initialize admitted executor bridge") ||
        expect(make_request(&manifest, &projection, 3, 1, &request, &envelope,
                            payload, sizeof(payload), &payload_bytes, error,
                            sizeof(error)) == 0,
               "build first typed handoff") ||
        expect(wvm_executor_bridge_dispatch(bridge, &envelope, error,
                                            sizeof(error)) == 0 &&
                   wait_for_response(&sent, 1) == 0,
               "execute typed handoff through the typed local executor ABI")) {
        goto out;
    }
    pthread_mutex_lock(&sent.lock);
    response = sent.response;
    result = sent.result;
    if (sent.context_bytes > sizeof(result_context)) {
        pthread_mutex_unlock(&sent.lock);
        expect(0, "copy first typed exit context");
        goto out;
    }
    memcpy(result_context, sent.context, sent.context_bytes);
    result.context = result_context;
    pthread_mutex_unlock(&sent.lock);
    if (expect(response.message_type == WVM_ENVELOPE_MSG_VCPU_EXIT &&
                   response.route.destination_vnode_or_endpoint == 9 &&
                   response.route.hop_limit == 4 &&
                   result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS &&
                   result.exit_class == WVM_VCPU_EXIT_BUDGET &&
                   result.produced_memory_fence_id != 0 &&
                   wvm_vcpu_handoff_exit_validate_envelope(
                       &request, &result, &response, error,
                       sizeof(error)) == 0 &&
                   wvm_x86_context_decode(
                       WVM_VCPU_BACKEND_TCG, result.context,
                       result.context_bytes, &decoded_fields,
                       &returned_context, sizeof(returned_context), error,
                       sizeof(error)) == 0 &&
                   decoded_fields == request.context_valid_fields &&
                   returned_context.eip ==
                       UINT64_C(0x112233445566778c),
               "return completed typed TCG exit through explicit reply route")) {
        goto out;
    }

    envelope.delivery_attempt_id = 2;
    if (expect(wvm_executor_bridge_dispatch(bridge, &envelope, error,
                                            sizeof(error)) == 0 &&
                   wait_for_response(&sent, 2) == 0,
               "replay the cached typed exit without re-execution")) {
        goto out;
    }
    pthread_mutex_lock(&stub.lock);
    stub_received = stub.received;
    stub_valid = stub.valid;
    pthread_mutex_unlock(&stub.lock);
    pthread_mutex_lock(&sent.lock);
    response = sent.response;
    result = sent.result;
    pthread_mutex_unlock(&sent.lock);
    if (expect(stub_valid && stub_received == 1 &&
                   response.delivery_attempt_id == 3 &&
                   result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS &&
                   wvm_vcpu_handoff_exit_validate_envelope(
                       &request, &result, &response, error,
                       sizeof(error)) == 0,
               "replay the completed typed exit without another execution")) {
        goto out;
    }

    if (expect(make_request(&manifest, &projection, 4, 2, &request, &envelope,
                            payload, sizeof(payload), &payload_bytes, error,
                            sizeof(error)) == 0 &&
                   wvm_executor_bridge_dispatch(bridge, &envelope, error,
                                                sizeof(error)) == 0 &&
                   wait_for_response(&sent, 3) == 0,
               "return explicit backpressure when admitted cache is full")) {
        goto out;
    }
    pthread_mutex_lock(&sent.lock);
    response = sent.response;
    result = sent.result;
    pthread_mutex_unlock(&sent.lock);
    if (expect(response.delivery_attempt_id == 2 &&
                   result.status == WVM_VCPU_HANDOFF_RESULT_BACKPRESSURE &&
                   result.exit_class == WVM_VCPU_EXIT_NONE &&
                   wvm_vcpu_handoff_exit_validate_envelope(
                       &request, &result, &response, error,
                       sizeof(error)) == 0,
               "preserve explicit typed backpressure semantics")) {
        goto out;
    }

    request.destination_executor_id = 8;
    if (expect(wvm_vcpu_handoff_request_encode(
                   &request, payload, sizeof(payload), &payload_bytes, error,
                   sizeof(error)) == 0,
               "encode nonlocal typed handoff")) {
        goto out;
    }
    envelope.payload_bytes = payload_bytes;
    envelope.route.destination_vnode_or_endpoint = 8;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 envelope.semantic_payload_digest);
    if (expect(wvm_executor_bridge_dispatch(bridge, &envelope, error,
                                            sizeof(error)) == -EPERM,
               "reject a handoff not targeting the local executor")) {
        goto out;
    }

    {
        struct wvm_executor_bridge_config drain_config = config;
        void *drain_bridge = NULL;
        struct timespec deadline;
        int entered = 0;

        stub.block = 1;
        stub.released = 0;
        stub.entered_count = 0;
        if (expect(wvm_executor_bridge_dispatch_init(
                       &drain_config, &drain_bridge, error,
                       sizeof(error)) == 0,
                   "initialize in-flight drain bridge") ||
            expect(make_request(&manifest, &projection, 3, 3, &request,
                                &envelope, payload, sizeof(payload),
                                &payload_bytes, error, sizeof(error)) == 0,
                   "build in-flight drain handoff") ||
            expect(wvm_executor_bridge_dispatch(drain_bridge, &envelope, error,
                                                sizeof(error)) == 0,
                   "enqueue in-flight drain handoff")) {
            wvm_executor_bridge_dispatch_destroy(drain_bridge);
            goto out;
        }
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;
        pthread_mutex_lock(&stub.lock);
        while (stub.entered_count == 0) {
            if (pthread_cond_timedwait(&stub.entered, &stub.lock,
                                       &deadline) != 0) {
                break;
            }
        }
        entered = stub.entered_count != 0;
        pthread_mutex_unlock(&stub.lock);
        if (expect(entered, "executor entered the in-flight handoff") ||
            expect(wvm_executor_bridge_dispatch_drain(
                       drain_bridge, 100, error, sizeof(error)) == -ETIMEDOUT,
                   "drain reports timeout while executor is in flight")) {
            pthread_mutex_lock(&stub.lock);
            stub.released = 1;
            pthread_cond_broadcast(&stub.release);
            pthread_mutex_unlock(&stub.lock);
            wvm_executor_bridge_dispatch_destroy(drain_bridge);
            goto out;
        }
        pthread_mutex_lock(&stub.lock);
        stub.released = 1;
        pthread_cond_broadcast(&stub.release);
        pthread_mutex_unlock(&stub.lock);
        if (expect(wvm_executor_bridge_dispatch_drain(
                       drain_bridge, 5000, error, sizeof(error)) == 0,
                   "drain waits for the in-flight executor to finish") ||
            expect(wait_for_response(&sent, 4) == 0,
                   "in-flight drain handoff completed")) {
            wvm_executor_bridge_dispatch_destroy(drain_bridge);
            goto out;
        }
        wvm_executor_bridge_dispatch_destroy(drain_bridge);
        stub.block = 0;
        puts("EVID executor_bridge_drain: in_flight_timeout=1 drained=1");
    }

    exit_code = 0;
out:
    wvm_executor_bridge_dispatch_destroy(bridge);
    if (stub_initialized) {
        pthread_cond_destroy(&stub.release);
        pthread_cond_destroy(&stub.entered);
        pthread_mutex_destroy(&stub.lock);
    }
    if (sent_initialized) {
        pthread_cond_destroy(&sent.available);
        pthread_mutex_destroy(&sent.lock);
    }
    wvm_route_runtime_destroy(&routes);
    if (exit_code == 0) {
        puts("executor bridge tests: PASS");
    }
    return exit_code;
}

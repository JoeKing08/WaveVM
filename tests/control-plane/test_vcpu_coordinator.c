#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "vcpu_coordinator.h"
#include "wavevm_membership.h"
#include "wavevm_protocol.h"
#include "wavevm_x86_context.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "vCPU coordinator test: %s\n", message);
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
                             struct wvm_route_rule_record rules[2],
                             struct wvm_required_ack_entry acks[1],
                             uint64_t route_generation, char *error,
                             size_t error_len)
{
    uint8_t encoded[16384];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 256;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 4;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 9;
    snapshot->route_snapshot_key.topology_revision = 2;
    snapshot->route_snapshot_key.route_generation = route_generation;
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
    acks[0].member_key = rules[0].next_hop_member;
    acks[0].endpoint = rules[0].next_hop_endpoint;
    acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks[0].expected_snapshot_key = snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
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
    manifest->negotiated_profile.context_schema_version =
        WVM_VCPU_CONTEXT_SCHEMA_X86;
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
    struct wvm_runtime_cpu_dispatch cpu_entries[2],
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
    memset(cpu_entries, 0, 2 * sizeof(*cpu_entries));
    cpu_entries[0].guest_vcpu_index = 3;
    cpu_entries[0].executor.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    cpu_entries[0].executor.destination_vnode = 11;
    cpu_entries[1].guest_vcpu_index = 4;
    cpu_entries[1].executor.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    cpu_entries[1].executor.destination_vnode = 11;
    projection->cpu_dispatch.entries = cpu_entries;
    projection->cpu_dispatch.count = 2;
    projection->cpu_dispatch.capacity = 2;
}

struct send_state {
    size_t count;
    struct wvm_envelope envelope;
    struct wvm_vcpu_handoff_request request;
};

struct completion_state {
    size_t count;
    struct wvm_vcpu_handoff_request request;
    struct wvm_vcpu_handoff_result result;
};

static int capture_send(void *opaque, const struct wvm_envelope *envelope,
                        char *error, size_t error_len)
{
    struct send_state *state = opaque;

    if (!state || !envelope ||
        wvm_vcpu_handoff_request_decode(
            envelope->payload, envelope->payload_bytes, &state->request, error,
            error_len) != 0) {
        return -EINVAL;
    }
    state->envelope = *envelope;
    state->count++;
    return 0;
}

static int capture_completion(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result, char *error,
    size_t error_len)
{
    struct completion_state *state = opaque;

    (void)error;
    (void)error_len;
    if (!state || !request || !result) {
        return -EINVAL;
    }
    state->request = *request;
    state->result = *result;
    state->count++;
    return 0;
}

static void fill_submit(struct wvm_vcpu_handoff_submit *submit,
                        uint32_t vcpu_index, uint8_t operation_tail,
                        const uint8_t *context, size_t context_bytes)
{
    memset(submit, 0, sizeof(*submit));
    submit->backend = WVM_VCPU_BACKEND_TCG;
    submit->vcpu_index = vcpu_index;
    submit->memory_fence_id = 10;
    submit->local_interrupt_watermark = 11;
    submit->device_event_watermark = 12;
    submit->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    submit->context_schema_version = WVM_VCPU_CONTEXT_SCHEMA_X86;
    submit->context_valid_fields =
        WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
        WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE;
    submit->context = context;
    submit->context_bytes = context_bytes;
}

static int build_success_exit(
    const struct send_state *sent, uint64_t remote_watermark,
    const uint8_t *context, size_t context_bytes, uint8_t *payload,
    size_t payload_capacity, struct wvm_envelope *exit_envelope, char *error,
    size_t error_len)
{
    struct wvm_vcpu_handoff_result result;
    struct wvm_envelope_route reply_route;
    size_t payload_bytes;

    if (!sent || !payload || !exit_envelope) {
        return -1;
    }
    memset(&result, 0, sizeof(result));
    result.protocol_version = WVM_VCPU_HANDOFF_RESULT_VERSION;
    result.status = WVM_VCPU_HANDOFF_RESULT_SUCCESS;
    result.exit_class = WVM_VCPU_EXIT_BUDGET;
    result.backend = sent->request.backend;
    result.vm_id = sent->request.vm_id;
    result.vm_incarnation = sent->request.vm_incarnation;
    result.manifest_generation = sent->request.manifest_generation;
    result.origin_physical_node_id = sent->request.origin_physical_node_id;
    result.origin_runtime_instance_id = sent->request.origin_runtime_instance_id;
    result.vcpu_index = sent->request.vcpu_index;
    result.handoff_sequence = sent->request.handoff_sequence;
    result.produced_memory_fence_id = sent->request.memory_fence_id + 1U;
    result.remote_interrupt_watermark = remote_watermark;
    result.remote_device_watermark = sent->request.device_event_watermark + 1U;
    memcpy(result.operation_id, sent->request.operation_id,
           sizeof(result.operation_id));
    result.context_schema_version = sent->request.context_schema_version;
    result.context_valid_fields =
        WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
        WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE;
    result.context = context;
    result.context_bytes = context_bytes;
    memset(&reply_route, 0, sizeof(reply_route));
    reply_route.destination_kind = sent->request.reply_destination_kind;
    reply_route.destination_scope = sent->request.reply_destination_scope;
    reply_route.destination_vnode_or_endpoint =
        sent->request.reply_destination_vnode;
    reply_route.hop_limit = 4;
    return wvm_vcpu_handoff_exit_envelope_build(
        &sent->envelope, &sent->request, &reply_route, 2, &result, payload,
        payload_capacity, &payload_bytes, exit_envelope, error, error_len);
}

int main(void)
{
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[1];
    struct wvm_route_snapshot_record snapshot;
    struct wvm_node_runtime_manifest manifest;
    struct wvm_capability_ref capability;
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_cpu_dispatch cpu_entries[2];
    struct wvm_runtime_gate gate;
    struct wvm_runtime_registration registration;
    struct wvm_route_runtime routes;
    struct wvm_vcpu_handoff_coordinator_config config;
    struct wvm_vcpu_handoff_coordinator coordinator;
    struct wvm_vcpu_handoff_submit submit;
    struct send_state sent;
    struct completion_state completed;
    struct wvm_envelope exit_envelope;
    wvm_tcg_context_t exported_context;
    wvm_tcg_context_t completed_context;
    uint8_t submit_context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                           sizeof(exported_context)];
    uint8_t result_context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                           sizeof(completed_context)];
    uint8_t exit_payload[WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES +
                         sizeof(result_context)];
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    size_t submit_context_bytes = 0;
    size_t result_context_bytes = 0;
    uint64_t connection_id = 0;
    char error[256] = {0};

    memset(&exported_context, 0x31, sizeof(exported_context));
    exported_context.eip = UINT64_C(0x1122334455667788);
    memset(&completed_context, 0x72, sizeof(completed_context));
    completed_context.eip = UINT64_C(0x8877665544332211);
    fill_rule(&rules[0], 7, 17, 19017);
    fill_rule(&rules[1], 11, 18, 19018);
    if (expect(finalize_snapshot(&snapshot, rules, acks, 3, error,
                                 sizeof(error)) == 0,
               "build route snapshot") ||
        expect(setup_manifest(&manifest, &capability,
                              &snapshot.route_snapshot_key, error,
                              sizeof(error)) == 0,
               "build admitted manifest")) {
        return 1;
    }
    fill_projection(&projection, cpu_entries, &manifest);
    if (expect(wvm_runtime_dispatch_projection_validate(
                   &projection, error, sizeof(error)) == 0,
               "build admitted CPU placement projection")) {
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
               "prepare runtime gate")) {
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
               "activate runtime gate")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&sent, 0, sizeof(sent));
    memset(&completed, 0, sizeof(completed));
    memset(&config, 0, sizeof(config));
    config.manifest = &manifest;
    config.runtime_gate = &gate;
    config.dispatch = &projection;
    config.route_runtime = &routes;
    config.local_runtime_instance_id = manifest.expected_node_instance_id;
    config.runtime_connection_id = connection_id;
    config.operation_retention_horizon_ms =
        snapshot.operation_retention_horizon_ms;
    config.send_envelope = capture_send;
    config.send_envelope_opaque = &sent;
    config.complete = capture_completion;
    config.complete_opaque = &completed;
    if (expect(wvm_vcpu_handoff_coordinator_init(
                   &coordinator, &config, error, sizeof(error)) == 0,
               "initialize admitted vCPU coordinator")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_x86_context_encode(
                   WVM_VCPU_BACKEND_TCG,
                   WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                       WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
                   &exported_context, sizeof(exported_context), submit_context,
                   sizeof(submit_context), &submit_context_bytes, error,
                   sizeof(error)) == 0,
               "encode admitted TCG context")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    fill_submit(&submit, 3, 1, submit_context, submit_context_bytes);
    if (expect(wvm_vcpu_handoff_coordinator_submit(
                   &coordinator, &submit, error, sizeof(error)) == 0 &&
                   sent.count == 1 &&
                   sent.envelope.message_type == WVM_ENVELOPE_MSG_VCPU_RUN &&
                   sent.envelope.route.destination_vnode_or_endpoint == 11 &&
                   sent.request.destination_executor_id == 11 &&
                   sent.request.reply_destination_vnode == 7 &&
                   sent.request.handoff_sequence == 1,
               "compile VCPU_RUN from admitted CPU placement")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_vcpu_handoff_coordinator_submit(
                   &coordinator, &submit, error, sizeof(error)) == 0 &&
                   sent.count == 2 &&
                   sent.envelope.delivery_attempt_id == 2 &&
                   sent.request.handoff_sequence == 1,
               "retry identical operation without creating another sequence")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    fill_submit(&submit, 3, 2, submit_context, submit_context_bytes);
    if (expect(wvm_vcpu_handoff_coordinator_submit(
                   &coordinator, &submit, error, sizeof(error)) == -EALREADY,
               "reject a second operation while one vCPU is remote in flight")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    submit.backend = WVM_VCPU_BACKEND_KVM;
    if (expect(wvm_vcpu_handoff_coordinator_submit(
                   &coordinator, &submit, error, sizeof(error)) == -EINVAL,
               "reject a handoff backend outside the admitted profile")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_x86_context_encode(
                   WVM_VCPU_BACKEND_TCG,
                   WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                       WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
                   &completed_context, sizeof(completed_context),
                   result_context, sizeof(result_context),
                   &result_context_bytes, error, sizeof(error)) == 0 &&
                   build_success_exit(&sent, 13, result_context,
                                  result_context_bytes, exit_payload,
                                  sizeof(exit_payload), &exit_envelope, error,
                                  sizeof(error)) == 0 &&
                   wvm_vcpu_handoff_coordinator_dispatch(
                       &coordinator, &exit_envelope, error, sizeof(error)) == 0 &&
                   completed.count == 1 &&
                   completed.result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS &&
                   completed.request.handoff_sequence == 1,
               "complete one matching VCPU_EXIT exactly once")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(wvm_vcpu_handoff_coordinator_dispatch(
                   &coordinator, &exit_envelope, error, sizeof(error)) == 0 &&
                   completed.count == 1,
               "accept an exact duplicate exit idempotently") ||
        expect(build_success_exit(&sent, 99, result_context,
                                  result_context_bytes, exit_payload,
                                  sizeof(exit_payload), &exit_envelope, error,
                                  sizeof(error)) == 0 &&
                   wvm_vcpu_handoff_coordinator_dispatch(
                       &coordinator, &exit_envelope, error, sizeof(error)) ==
                       -EPROTO &&
                   completed.count == 1,
               "reject a conflicting duplicate exit")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    fill_submit(&submit, 3, 2, submit_context, submit_context_bytes);
    if (expect(wvm_vcpu_handoff_coordinator_submit(
                   &coordinator, &submit, error, sizeof(error)) == 0 &&
                   sent.count == 3 &&
                   sent.request.handoff_sequence == 2,
               "advance only after the previous vCPU completion")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    /* Drain sequence-2 so the reroute oracle starts from a clean lane. */
    if (expect(build_success_exit(&sent, 13, result_context,
                                  result_context_bytes, exit_payload,
                                  sizeof(exit_payload), &exit_envelope, error,
                                  sizeof(error)) == 0 &&
                   wvm_vcpu_handoff_coordinator_dispatch(
                       &coordinator, &exit_envelope, error, sizeof(error)) ==
                       0,
               "complete sequence-2 before reroute oracle")) {
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    /*
     * RM-P7-op-identity-across-reroute: drop VCPU_EXIT across G→G+1, refresh
     * forwarding key on retry, then complete exactly once; lookup returns cache.
     */
    {
        struct wvm_route_snapshot_record gen4;
        struct wvm_route_rule_record gen4_rules[2];
        struct wvm_required_ack_entry gen4_acks[1];
        struct wvm_vcpu_handoff_request looked_request;
        struct wvm_vcpu_handoff_result looked_result;
        uint8_t op_tail = 7;
        uint64_t sequence_before;
        size_t completed_before = completed.count;

        fill_rule(&gen4_rules[0], 7, 17, 19117);
        fill_rule(&gen4_rules[1], 11, 21, 19121);
        if (finalize_snapshot(&gen4, gen4_rules, gen4_acks, 4, error,
                              sizeof(error)) != 0) {
            fprintf(stderr, "vCPU coordinator gen4 setup: %s\n", error);
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }
        gen4.has_predecessor_snapshot_key = 1;
        gen4.predecessor_snapshot_key = manifest.required_route_snapshot_key;

        fill_submit(&submit, 3, op_tail, submit_context, submit_context_bytes);
        {
            int submit_rc = wvm_vcpu_handoff_coordinator_submit(
                &coordinator, &submit, error, sizeof(error));
            if (expect(submit_rc == 0 && sent.count == 4,
                       "submit semantic op under generation 3")) {
                fprintf(stderr, "submit gen3 rc=%d count=%zu err=%s\n",
                        submit_rc, sent.count, error);
                wvm_vcpu_handoff_coordinator_destroy(&coordinator);
                wvm_route_runtime_destroy(&routes);
                return 1;
            }
        }
        sequence_before = sent.request.handoff_sequence;
        if (expect(sent.envelope.route_generation == 3,
                   "initial emit uses generation 3")) {
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }

        /* Install G+1 and update admitted projection (control-plane reroute). */
        if (expect(wvm_route_runtime_prepare(&routes, &gen4, error,
                                             sizeof(error)) == 0 &&
                       wvm_route_runtime_activate(
                           &routes, &gen4.route_snapshot_key, error,
                           sizeof(error)) == 0,
                   "activate route generation 4")) {
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }
        projection.required_route_snapshot_key = gen4.route_snapshot_key;
        manifest.required_route_snapshot_key = gen4.route_snapshot_key;

        /* Lost VCPU_EXIT: retry same operation_id; forwarding key refreshes. */
        if (expect(wvm_vcpu_handoff_coordinator_submit(
                       &coordinator, &submit, error, sizeof(error)) == 0 &&
                       sent.count == 5 &&
                       sent.envelope.route_generation == 4 &&
                       sent.envelope.delivery_attempt_id == 2 &&
                       sent.request.handoff_sequence == sequence_before &&
                       memcmp(sent.envelope.operation_id, submit.operation_id,
                              sizeof(submit.operation_id)) == 0,
                   "reroute retry refreshes generation; keeps op identity")) {
            fprintf(stderr,
                    "reroute retry: gen=%llu attempt=%llu seq=%llu err=%s\n",
                    (unsigned long long)sent.envelope.route_generation,
                    (unsigned long long)sent.envelope.delivery_attempt_id,
                    (unsigned long long)sent.request.handoff_sequence, error);
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }

        if (expect(build_success_exit(&sent, 13, result_context,
                                      result_context_bytes, exit_payload,
                                      sizeof(exit_payload), &exit_envelope,
                                      error, sizeof(error)) == 0 &&
                       wvm_vcpu_handoff_coordinator_dispatch(
                           &coordinator, &exit_envelope, error,
                           sizeof(error)) == 0 &&
                       completed.count == completed_before + 1,
                   "one completion after dropped-exit reroute")) {
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }
        if (expect(wvm_vcpu_handoff_coordinator_lookup_completed(
                       &coordinator, 3, submit.operation_id, &looked_request,
                       &looked_result, error, sizeof(error)) == 0 &&
                       looked_result.status ==
                           WVM_VCPU_HANDOFF_RESULT_SUCCESS &&
                       looked_request.handoff_sequence == sequence_before,
                   "lookup returns cached result under same operation_id") ||
            expect(wvm_vcpu_handoff_coordinator_submit(
                       &coordinator, &submit, error, sizeof(error)) ==
                       -EALREADY,
                   "resubmit of completed op does not mint a new sequence")) {
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }
    }

    wvm_vcpu_handoff_coordinator_destroy(&coordinator);
    wvm_route_runtime_destroy(&routes);
    puts("vCPU coordinator tests: PASS");
    puts("NOTE: RM-P7 op-identity across reroute (G→G+1 + cache lookup).");
    return 0;
}

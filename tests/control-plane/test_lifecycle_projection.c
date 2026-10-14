#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_cluster.h"
#include "wavevm_lifecycle.h"
#include "wavevm_membership.h"
#include "wavevm_runtime_delivery.h"
#include "wavevm_runtime_dispatch.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "lifecycle-projection test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_id(uint8_t id[WVM_IDENTITY_ID_BYTES], uint8_t value)
{
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = value;
}

static void fill_capability(struct wvm_capability_ref *capability,
                            uint32_t physical_node_id,
                            uint64_t node_instance_id, uint8_t digest_byte)
{
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = physical_node_id;
    capability->node_instance_id = node_instance_id;
    capability->profile_generation = 13;
    memset(capability->profile_digest, digest_byte,
           sizeof(capability->profile_digest));
}

static int build_candidate(struct wvm_candidate_vm_manifest *candidate,
                           struct wvm_reservation_requirement requirements[2],
                           struct wvm_vcpu_assignment vcpus[2],
                           struct wvm_memory_chunk_assignment memory[2],
                           struct wvm_capability_ref capabilities[2],
                           struct wvm_required_member members[2],
                           uint8_t candidate_digest[WVM_SHA256_DIGEST_BYTES],
                           char *error, size_t error_len)
{
    struct wvm_placement_plan plan;
    struct wvm_local_name_identity local_identity;
    uint8_t plan_bytes[4096];
    uint8_t candidate_bytes[8192];
    uint8_t plan_digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    memset(requirements, 0, 2 * sizeof(*requirements));
    fill_id(requirements[0].reservation_id, 0x10);
    requirements[0].physical_node_id = 17;
    requirements[0].node_instance_id = 101;
    requirements[0].inventory_revision = 23;
    requirements[0].guest_vcpu_slots = 1;
    requirements[0].guest_memory_bytes = 2 * 1024 * 1024;
    requirements[0].overhead_vcpu_slots = 1;
    requirements[0].overhead_memory_bytes = 1024 * 1024;
    fill_id(requirements[1].reservation_id, 0x20);
    requirements[1].physical_node_id = 99;
    requirements[1].node_instance_id = 202;
    requirements[1].inventory_revision = 23;
    requirements[1].guest_vcpu_slots = 1;
    requirements[1].guest_memory_bytes = 2 * 1024 * 1024;

    memset(vcpus, 0, 2 * sizeof(*vcpus));
    vcpus[0].executor_physical_node_id = 17;
    vcpus[0].backend = WVM_MANIFEST_BACKEND_TCG;
    vcpus[0].executor_class = 1;
    fill_id(vcpus[0].reservation_id, 0x10);
    vcpus[1] = vcpus[0];
    vcpus[1].guest_vcpu_index = 1;
    vcpus[1].executor_physical_node_id = 99;
    vcpus[1].executor_slot = 1;
    fill_id(vcpus[1].reservation_id, 0x20);

    memset(memory, 0, 2 * sizeof(*memory));
    memory[0].bytes = 2 * 1024 * 1024;
    memory[0].directory_physical_node_id = 17;
    memory[0].executor_physical_node_id = 17;
    memory[0].consistency_policy = 1;
    fill_id(memory[0].reservation_id, 0x10);
    memory[1] = memory[0];
    memory[1].gpa_start = 2 * 1024 * 1024;
    memory[1].directory_physical_node_id = 99;
    memory[1].executor_physical_node_id = 99;
    fill_id(memory[1].reservation_id, 0x20);

    memset(&plan, 0, sizeof(plan));
    fill_id(plan.admission_tx_id, 0x42);
    memset(plan.eligibility_fence_digest, 0x51,
           sizeof(plan.eligibility_fence_digest));
    plan.inventory_revision = 23;
    plan.membership_revision = 7;
    plan.topology_revision = 11;
    plan.capability_profile_generation = 13;
    plan.host_node = 17;
    plan.vcpu_assignments.entries = vcpus;
    plan.vcpu_assignments.count = 2;
    plan.memory_assignments.entries = memory;
    plan.memory_assignments.count = 2;
    plan.reservation_requirements.entries = requirements;
    plan.reservation_requirements.count = 2;
    plan.guest_topology.topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
    plan.guest_topology.guest_numa_nodes = 1;
    plan.route_scope_key.vm_id = 256;
    plan.route_scope_key.vm_incarnation = 1;
    plan.route_scope_key.route_scope_id = 1;
    if (wvm_placement_plan_encode(&plan, plan_bytes, sizeof(plan_bytes),
                                  &encoded_bytes, plan_digest, error,
                                  error_len) != 0) {
        return -1;
    }

    fill_capability(&capabilities[0], 17, 101, 0x61);
    fill_capability(&capabilities[1], 99, 202, 0x62);
    memset(members, 0, 2 * sizeof(*members));
    members[0].member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    members[0].member_key.role_id = 17;
    members[0].member_key.instance_id = 1001;
    members[0].physical_node_id = 17;
    members[0].failure_domain_id = 1;
    members[0].capability = capabilities[0];
    members[0].required_state = WVM_MANIFEST_MEMBER_ACTIVE;
    members[1] = members[0];
    members[1].member_key.role_id = 99;
    members[1].member_key.instance_id = 1002;
    members[1].physical_node_id = 99;
    members[1].failure_domain_id = 2;
    members[1].capability = capabilities[1];

    memset(candidate, 0, sizeof(*candidate));
    fill_id(candidate->manifest_id, 0x01);
    candidate->manifest_schema_version = 1;
    candidate->vm_id = 256;
    candidate->vm_incarnation = 1;
    candidate->manifest_generation = 1;
    fill_id(candidate->request_id, 0x02);
    memcpy(candidate->admission_tx_id, plan.admission_tx_id,
           sizeof(candidate->admission_tx_id));
    memcpy(candidate->eligibility_fence_digest, plan.eligibility_fence_digest,
           sizeof(candidate->eligibility_fence_digest));
    candidate->candidate_created_at = 1;
    strcpy(candidate->guest_machine.architecture, "x86_64");
    strcpy(candidate->guest_machine.machine_type, "pc-i440fx-5.2");
    candidate->guest_machine.qemu_compat_version = 502;
    candidate->guest_machine.firmware_policy = 1;
    candidate->guest_topology = plan.guest_topology;
    candidate->execution_plan.backend = WVM_MANIFEST_BACKEND_TCG;
    candidate->execution_plan.context_schema_version = 1;
    candidate->execution_plan.dirty_capture_engine = 1;
    candidate->execution_plan.read_fault_engine = 1;
    candidate->execution_plan.invalidation_engine = 1;
    candidate->execution_plan.per_node_capabilities.entries = capabilities;
    candidate->execution_plan.per_node_capabilities.count = 2;
    memset(candidate->execution_plan.supported_memory_policies_digest, 0x71,
           sizeof(candidate->execution_plan.supported_memory_policies_digest));
    candidate->execution_plan.fallback_decision = 1;
    candidate->consistency_policy.dirty_batch_size = 1;
    candidate->consistency_policy.handoff_commit_policy = 1;
    candidate->consistency_policy.subscriber_delivery_policy = 1;
    candidate->consistency_policy.max_commit_latency_ms = 1000;
    memset(candidate->storage_device_plan.qemu_device_configuration_digest,
           0x81,
           sizeof(candidate->storage_device_plan.qemu_device_configuration_digest));
    candidate->host_node = 17;
    candidate->vcpu_placements.entries = vcpus;
    candidate->vcpu_placements.count = 2;
    candidate->memory_placements.entries = memory;
    candidate->memory_placements.count = 2;
    candidate->required_members.entries = members;
    candidate->required_members.count = 2;
    candidate->required_capabilities.entries = capabilities;
    candidate->required_capabilities.count = 2;
    candidate->reservation_requirements.entries = requirements;
    candidate->reservation_requirements.count = 2;
    candidate->route_scope_key = plan.route_scope_key;
    candidate->prepared_route_snapshot_key.scope_key = plan.route_scope_key;
    candidate->prepared_route_snapshot_key.topology_revision = 11;
    candidate->prepared_route_snapshot_key.route_generation = 1;
    memset(candidate->prepared_route_snapshot_key.snapshot_digest, 0x91,
           sizeof(candidate->prepared_route_snapshot_key.snapshot_digest));
    memcpy(candidate->plan_digest, plan_digest, sizeof(candidate->plan_digest));
    memset(&local_identity, 0, sizeof(local_identity));
    local_identity.vm_id = candidate->vm_id;
    local_identity.vm_incarnation = candidate->vm_incarnation;
    local_identity.manifest_generation = candidate->manifest_generation;
    local_identity.physical_node_id = candidate->host_node;
    memcpy(local_identity.manifest_id, candidate->manifest_id,
           sizeof(local_identity.manifest_id));
    memcpy(local_identity.admission_tx_id, candidate->admission_tx_id,
           sizeof(local_identity.admission_tx_id));
    if (wvm_local_name_namespace_derive(&local_identity,
                                        &candidate->local_name_namespace,
                                        error, error_len) != 0) {
        return -1;
    }
    candidate->lifecycle_policy.start_policy = 1;
    candidate->lifecycle_policy.failure_policy = 1;
    candidate->lifecycle_policy.completion_query_horizon_ms = 5000;
    candidate->lifecycle_policy.route_retention_horizon_ms = 6000;
    candidate->namespace_abi = WVM_MANIFEST_NAMESPACE_U32;
    if (wvm_candidate_vm_manifest_encode(candidate, candidate_bytes,
                                         sizeof(candidate_bytes), &encoded_bytes,
                                         candidate_digest, error, error_len) !=
        0) {
        return -1;
    }
    memcpy(candidate->manifest_digest, candidate_digest,
           sizeof(candidate->manifest_digest));
    return 0;
}

static void fill_dispatch_endpoint(struct wvm_endpoint *endpoint,
                                   uint8_t last_octet, uint16_t data_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 10;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(data_port + 100);
}

static void fill_dispatch_node(struct wvm_node_record *node,
                               uint32_t physical_node_id,
                               uint64_t node_instance_id,
                               uint32_t local_vnode_first, uint64_t pod_id)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = physical_node_id;
    node->node_instance_id = node_instance_id;
    node->failure_domain_id = physical_node_id;
    fill_dispatch_endpoint(&node->control_endpoint,
                           (uint8_t)physical_node_id, 18000);
    fill_dispatch_endpoint(&node->sidecar_endpoint,
                           (uint8_t)physical_node_id, 19000);
    node->role_bits = 1;
    node->local_vnode_first = local_vnode_first;
    node->local_vnode_count = 1;
    node->pod_id = pod_id;
    node->inventory.physical_node_id = physical_node_id;
    node->inventory.node_instance_id = node_instance_id;
    node->inventory.failure_domain_id = node->failure_domain_id;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * 1024 * 1024;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = 1024 * 1024;
    node->inventory.allocatable_vcpu_slots = 7;
    node->inventory.allocatable_memory_bytes = 15 * 1024 * 1024;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = physical_node_id;
    node->capability.node_instance_id = node_instance_id;
    node->capability.profile_generation = 1;
    memset(node->capability.profile_digest, (int)local_vnode_first + 1,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = 1;
    node->membership_revision = 1;
    node->topology_revision = 1;
    wvm_node_record_init_single_host_defaults(node);
}

static void fill_dispatch_route_rule(struct wvm_route_rule_record *rule,
                                     uint64_t scope, uint32_t vnode,
                                     const struct wvm_node_record *node)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_scope = scope;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = node->physical_node_id;
    rule->next_hop_member.instance_id = node->node_instance_id;
    rule->next_hop_endpoint = node->sidecar_endpoint;
    rule->hop_limit = 8;
}

static void fill_dispatch_ack(struct wvm_required_ack_entry *ack,
                              const struct wvm_node_record *node,
                              const struct wvm_route_snapshot_key *key)
{
    memset(ack, 0, sizeof(*ack));
    ack->member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack->member_key.role_id = node->physical_node_id;
    ack->member_key.instance_id = node->node_instance_id;
    ack->endpoint = node->sidecar_endpoint;
    ack->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack->expected_snapshot_key = *key;
}

static int test_runtime_dispatch_projection(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    struct wvm_node_record nodes[2];
    struct wvm_cluster_record_set records;
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[2];
    struct wvm_route_snapshot_record snapshot;
    struct wvm_runtime_cpu_dispatch cpu_entries[2];
    struct wvm_runtime_memory_dispatch memory_entries[2];
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_cpu_dispatch decoded_cpu_entries[2];
    struct wvm_runtime_memory_dispatch decoded_memory_entries[2];
    struct wvm_runtime_dispatch_projection decoded;
    struct wvm_runtime_dispatch_storage loaded;
    struct wvm_runtime_manifest_storage delivered_manifest;
    struct wvm_route_snapshot_file_storage delivered_route;
    struct wvm_runtime_delivery_request delivery;
    struct wvm_candidate_vm_manifest delivery_candidate;
    struct wvm_node_runtime_manifest delivery_runtime;
    struct wvm_route_snapshot_record delivery_snapshot;
    struct wvm_required_ack_entry delivery_acks[2];
    struct wvm_candidate_vm_manifest wrong_candidate;
    struct wvm_node_runtime_manifest wrong_runtime;
    uint8_t bytes[4096];
    uint8_t route_bytes[4096];
    uint8_t candidate_bytes[16384];
    uint8_t route_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t candidate_digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    char manifest_path[] = "/tmp/wavevm-runtime-dispatch.XXXXXX";
    char route_path[WVM_ROUTE_DELIVERY_PATH_MAX];
    char dispatch_path[WVM_RUNTIME_DISPATCH_PATH_MAX];
    int fd;

    fill_dispatch_node(&nodes[0], 17, 101, 0, 41);
    fill_dispatch_node(&nodes[1], 99, 202, 1, 99);
    memset(&records, 0, sizeof(records));
    records.nodes = nodes;
    records.node_count = 2;
    records.inventory_revision = 1;
    records.membership_revision = 1;
    records.topology_revision = 1;
    records.admission_eligibility_revision = 1;
    records.capability_profile_generation = 1;

    fill_dispatch_route_rule(&rules[0], 0, 0, &nodes[0]);
    fill_dispatch_route_rule(&rules[1], 0, 1, &nodes[1]);
    fill_dispatch_ack(&acks[0], &nodes[0],
                      &candidate->prepared_route_snapshot_key);
    fill_dispatch_ack(&acks[1], &nodes[1],
                      &candidate->prepared_route_snapshot_key);
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.route_snapshot_key = candidate->prepared_route_snapshot_key;
    snapshot.membership_revision = 1;
    snapshot.topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    snapshot.next_hop_rules.entries = rules;
    snapshot.next_hop_rules.count = 2;
    snapshot.next_hop_rules.capacity = 2;
    snapshot.required_ack_set.entries.entries = acks;
    snapshot.required_ack_set.entries.count = 2;
    snapshot.required_ack_set.entries.capacity = 2;
    snapshot.operation_retention_horizon_ms = 5000;
    snapshot.retirement_policy = 1;

    memset(&projection, 0, sizeof(projection));
    projection.cpu_dispatch.entries = cpu_entries;
    projection.cpu_dispatch.capacity = 2;
    projection.memory_dispatch.entries = memory_entries;
    projection.memory_dispatch.capacity = 2;
    if (expect(wvm_runtime_dispatch_projection_build(
                   candidate, runtime_manifest, &records, &snapshot,
                   &projection, error, error_len) == 0 &&
                   projection.route_topology_kind == WVM_ROUTE_TOPOLOGY_FLAT &&
                   projection.local_primary.destination_kind ==
                       WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE &&
                   projection.local_primary.destination_scope == 0 &&
                   projection.local_primary.destination_vnode == 0 &&
                   projection.cpu_dispatch.count == 2 &&
                   projection.memory_dispatch.count == 2 &&
                   projection.memory_dispatch.entries[1].gpa_start ==
                       2 * 1024 * 1024 &&
                   projection.memory_dispatch.entries[1]
                           .directory_physical_node_id == 99 &&
                   projection.memory_dispatch.entries[1]
                           .directory_node_instance_id == 202,
               "build manifest-bound dispatch projection")) {
        return -1;
    }

    memset(&decoded, 0, sizeof(decoded));
    decoded.cpu_dispatch.entries = decoded_cpu_entries;
    decoded.cpu_dispatch.capacity = 2;
    decoded.memory_dispatch.entries = decoded_memory_entries;
    decoded.memory_dispatch.capacity = 2;
    if (expect(wvm_runtime_dispatch_projection_encode(
                   &projection, bytes, sizeof(bytes), &encoded_bytes, error,
                   error_len) == 0 &&
                   wvm_runtime_dispatch_projection_decode(
                       bytes, encoded_bytes, &decoded, error, error_len) == 0 &&
                   decoded.memory_dispatch.count == 2 &&
                   decoded.cpu_dispatch.entries[1].executor.destination_kind ==
                       WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE &&
                   decoded.cpu_dispatch.entries[1].executor.destination_scope ==
                       0 &&
                   decoded.cpu_dispatch.entries[1].executor.destination_vnode ==
                       1 &&
                   decoded.memory_dispatch.entries[1]
                           .directory_physical_node_id == 99 &&
                   decoded.memory_dispatch.entries[1]
                           .directory_node_instance_id == 202,
               "round trip dispatch projection")) {
        return -1;
    }

    /*
     * The runtime projection is the typed boundary between placement and
     * routing. A fractal route must retain its Pod scope at every placement;
     * it must never be reconstructed from a raw vnode in a legacy table.
     */
    snapshot.topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    rules[0].destination_scope = nodes[0].pod_id;
    rules[1].destination_scope = nodes[1].pod_id;
    if (expect(wvm_runtime_dispatch_projection_build(
                   candidate, runtime_manifest, &records, &snapshot,
                   &projection, error, error_len) == 0 &&
                   projection.route_topology_kind ==
                       WVM_ROUTE_TOPOLOGY_FRACTAL &&
                   projection.local_primary.destination_kind ==
                       WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE &&
                   projection.local_primary.destination_scope == 41 &&
                   projection.local_primary.destination_vnode == 0 &&
                   projection.cpu_dispatch.entries[1].executor
                           .destination_kind ==
                       WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE &&
                   projection.cpu_dispatch.entries[1].executor
                           .destination_scope == 99 &&
                   projection.cpu_dispatch.entries[1].executor
                           .destination_vnode == 1 &&
                   projection.memory_dispatch.entries[1].directory
                           .destination_scope == 99 &&
                   projection.memory_dispatch.entries[1].executor
                           .destination_scope == 99 &&
                   projection.memory_dispatch.entries[1]
                           .directory_physical_node_id == 99 &&
                   projection.memory_dispatch.entries[1]
                           .directory_node_instance_id == 202 &&
                   wvm_runtime_dispatch_find_cpu(&projection, 1) ==
                       &projection.cpu_dispatch.entries[1] &&
                   wvm_runtime_dispatch_find_memory(
                       &projection, 2 * 1024 * 1024) ==
                       &projection.memory_dispatch.entries[1] &&
                   wvm_runtime_dispatch_find_memory(
                       &projection, 4 * 1024 * 1024) == NULL,
               "build scoped fractal dispatch projection")) {
        return -1;
    }
    memset(&decoded, 0, sizeof(decoded));
    decoded.cpu_dispatch.entries = decoded_cpu_entries;
    decoded.cpu_dispatch.capacity = 2;
    decoded.memory_dispatch.entries = decoded_memory_entries;
    decoded.memory_dispatch.capacity = 2;
    if (expect(wvm_runtime_dispatch_projection_encode(
                   &projection, bytes, sizeof(bytes), &encoded_bytes, error,
                   error_len) == 0 &&
                   wvm_runtime_dispatch_projection_decode(
                       bytes, encoded_bytes, &decoded, error, error_len) == 0 &&
                   decoded.route_topology_kind ==
                       WVM_ROUTE_TOPOLOGY_FRACTAL &&
                   decoded.local_primary.destination_scope == 41 &&
                   decoded.cpu_dispatch.entries[1].executor
                           .destination_scope == 99 &&
                   decoded.memory_dispatch.entries[1].directory
                           .destination_scope == 99 &&
                   decoded.memory_dispatch.entries[1].executor
                           .destination_scope == 99 &&
                   decoded.memory_dispatch.entries[1]
                           .directory_physical_node_id == 99 &&
                   decoded.memory_dispatch.entries[1]
                           .directory_node_instance_id == 202,
               "round trip scoped fractal dispatch projection")) {
        return -1;
    }
    snapshot.topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    rules[0].destination_scope = 0;
    rules[1].destination_scope = 0;

    fd = mkstemp(manifest_path);
    if (fd < 0) {
        perror("mkstemp runtime dispatch");
        return -1;
    }
    close(fd);
    unlink(manifest_path);
    wvm_runtime_dispatch_storage_init(&loaded);
    if (expect(wvm_runtime_dispatch_path_from_manifest(
                   manifest_path, dispatch_path, sizeof(dispatch_path), error,
                   error_len) == 0 &&
                   wvm_runtime_dispatch_file_publish(
                       dispatch_path, &projection, error, error_len) == 0 &&
                   wvm_runtime_dispatch_file_load(
                       dispatch_path, &loaded, error, error_len) == 0 &&
                   loaded.projection.expected_node_instance_id == 101 &&
                   loaded.projection.local_sidecar_endpoint.data_port == 19000,
               "atomically publish and load dispatch projection")) {
        wvm_runtime_dispatch_storage_free(&loaded);
        unlink(dispatch_path);
        return -1;
    }
    wvm_runtime_dispatch_storage_free(&loaded);
    unlink(dispatch_path);

    /*
     * The earlier projection fixture uses a synthetic snapshot digest because
     * projection validation checks binding shape.  File publication also
     * verifies the canonical snapshot self-digest, so derive a complete
     * candidate/runtime/snapshot bundle for the delivery path.
     */
    delivery_snapshot = snapshot;
    memcpy(delivery_acks, acks, sizeof(delivery_acks));
    delivery_snapshot.required_ack_set.entries.entries = delivery_acks;
    memset(delivery_snapshot.route_snapshot_key.snapshot_digest, 0,
           sizeof(delivery_snapshot.route_snapshot_key.snapshot_digest));
    delivery_acks[0].expected_snapshot_key =
        delivery_snapshot.route_snapshot_key;
    delivery_acks[1].expected_snapshot_key =
        delivery_snapshot.route_snapshot_key;
    if (wvm_route_snapshot_record_encode(
            &delivery_snapshot, route_bytes, sizeof(route_bytes),
            &encoded_bytes, route_digest, error, error_len) != 0) {
        fprintf(stderr, "derive delivery route snapshot: %s\n",
                error[0] ? error : "unknown error");
        return -1;
    }
    memcpy(delivery_snapshot.route_snapshot_key.snapshot_digest, route_digest,
           sizeof(route_digest));
    memcpy(delivery_acks[0].expected_snapshot_key.snapshot_digest, route_digest,
           sizeof(route_digest));
    memcpy(delivery_acks[1].expected_snapshot_key.snapshot_digest, route_digest,
           sizeof(route_digest));

    delivery_candidate = *candidate;
    delivery_candidate.prepared_route_snapshot_key =
        delivery_snapshot.route_snapshot_key;
    memset(delivery_candidate.manifest_digest, 0,
           sizeof(delivery_candidate.manifest_digest));
    if (wvm_candidate_vm_manifest_encode(
            &delivery_candidate, candidate_bytes, sizeof(candidate_bytes),
            &encoded_bytes, candidate_digest, error, error_len) != 0) {
        fprintf(stderr, "derive delivery candidate: %s\n",
                error[0] ? error : "unknown error");
        return -1;
    }
    memcpy(delivery_candidate.manifest_digest, candidate_digest,
           sizeof(candidate_digest));
    delivery_runtime = *runtime_manifest;
    memcpy(delivery_runtime.candidate_manifest_digest, candidate_digest,
           sizeof(candidate_digest));
    delivery_runtime.required_route_snapshot_key =
        delivery_snapshot.route_snapshot_key;

    memset(&delivery, 0, sizeof(delivery));
    delivery.candidate = &delivery_candidate;
    delivery.runtime_manifest = &delivery_runtime;
    delivery.cluster_records = &records;
    delivery.route_snapshot = &delivery_snapshot;
    delivery.runtime_manifest_path = manifest_path;
    wvm_runtime_manifest_storage_init(&delivered_manifest);
    wvm_route_snapshot_file_storage_init(&delivered_route);
    wvm_runtime_dispatch_storage_init(&loaded);
    if (wvm_runtime_delivery_publish(&delivery, error, error_len) != 0) {
        fprintf(stderr, "runtime delivery first publish: %s\n",
                error[0] ? error : "unknown error");
        wvm_runtime_dispatch_storage_free(&loaded);
        wvm_runtime_manifest_storage_free(&delivered_manifest);
        wvm_route_snapshot_file_storage_free(&delivered_route);
        unlink(manifest_path);
        unlink(route_path);
        unlink(dispatch_path);
        return -1;
    }
    if (expect(wvm_route_snapshot_path_from_manifest(
                       manifest_path, route_path, sizeof(route_path), error,
                       error_len) == 0 &&
                   wvm_runtime_manifest_load_file(
                       manifest_path, &delivered_manifest, error,
                       error_len) == 0 &&
                   wvm_route_snapshot_file_load(
                       route_path, &delivered_route, error, error_len) == 0 &&
                   wvm_runtime_dispatch_file_load(
                       dispatch_path, &loaded, error, error_len) == 0 &&
                   delivered_manifest.manifest.vm_id == delivery_candidate.vm_id &&
                   memcmp(delivered_route.snapshot.route_snapshot_key
                              .snapshot_digest,
                          delivery_candidate.prepared_route_snapshot_key
                              .snapshot_digest,
                          WVM_SHA256_DIGEST_BYTES) == 0 &&
                   loaded.projection.vm_id == delivery_candidate.vm_id &&
                   loaded.projection.cpu_dispatch.count == 2 &&
                   loaded.projection.memory_dispatch.count == 2 &&
                   wvm_runtime_delivery_publish(&delivery, error,
                                                error_len) == 0,
               "atomically publish and replay complete runtime bundle")) {
        wvm_runtime_dispatch_storage_free(&loaded);
        wvm_runtime_manifest_storage_free(&delivered_manifest);
        wvm_route_snapshot_file_storage_free(&delivered_route);
        unlink(manifest_path);
        unlink(route_path);
        unlink(dispatch_path);
        return -1;
    }
    wvm_runtime_dispatch_storage_free(&loaded);
    wvm_runtime_manifest_storage_free(&delivered_manifest);
    wvm_route_snapshot_file_storage_free(&delivered_route);
    unlink(manifest_path);
    unlink(route_path);
    unlink(dispatch_path);

    wrong_candidate = *candidate;
    wrong_candidate.manifest_digest[0] ^= 0xff;
    if (expect(wvm_runtime_dispatch_projection_build(
                   &wrong_candidate, runtime_manifest, &records, &snapshot,
                   &projection, error, error_len) != 0,
               "reject candidate digest mismatch")) {
        return -1;
    }
    wrong_runtime = *runtime_manifest;
    wrong_runtime.expected_node_instance_id++;
    if (expect(wvm_runtime_dispatch_projection_build(
                   candidate, &wrong_runtime, &records, &snapshot, &projection,
                   error, error_len) != 0,
               "reject node instance mismatch")) {
        return -1;
    }
    rules[1].destination_vnode_or_endpoint = 2;
    if (expect(wvm_runtime_dispatch_projection_build(
                   candidate, runtime_manifest, &records, &snapshot,
                   &projection, error, error_len) != 0,
               "reject missing exact route")) {
        return -1;
    }

    return 0;
}

int main(void)
{
    struct wvm_candidate_vm_manifest candidate;
    struct wvm_reservation_requirement requirements[2];
    struct wvm_reservation_requirement invalid_requirement;
    struct wvm_vcpu_assignment vcpus[2];
    struct wvm_memory_chunk_assignment memory[2];
    struct wvm_capability_ref capabilities[2];
    struct wvm_required_member members[2];
    struct wvm_resource_reservation reservation;
    struct wvm_activation_record activation;
    struct wvm_activation_record decoded_activation;
    struct wvm_route_snapshot_key required_snapshots[1];
    struct wvm_route_snapshot_key decoded_snapshots[1];
    struct wvm_vcpu_assignment local_vcpus[2];
    struct wvm_vcpu_assignment decoded_local_vcpus[2];
    struct wvm_memory_chunk_assignment local_memory[2];
    struct wvm_memory_chunk_assignment decoded_local_memory[2];
    struct wvm_node_runtime_manifest runtime_manifest;
    struct wvm_node_runtime_manifest decoded_runtime_manifest;
    struct wvm_resource_reservation decoded_reservation;
    struct wvm_capability_ref decoded_capabilities[2];
    struct wvm_startup_dependency dependency;
    struct wvm_startup_dependency decoded_dependency;
    struct wvm_startup_dependency dependencies[1];
    struct wvm_startup_dependency decoded_dependencies[1];
    struct wvm_lifecycle_transaction transaction;
    struct wvm_admission_transaction_record admission_record;
    struct wvm_admission_transaction_record decoded_admission_record;
    uint8_t candidate_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t activation_fence[WVM_IDENTITY_ID_BYTES];
    uint8_t participant_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t bytes[16384];
    size_t encoded_bytes;
    char error[256] = {0};

    if (expect(build_candidate(&candidate, requirements, vcpus, memory,
                               capabilities, members, candidate_digest, error,
                               sizeof(error)) == 0,
               "build candidate")) {
        return 1;
    }
    memset(&admission_record, 0, sizeof(admission_record));
    admission_record.request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x02;
    memset(admission_record.request_digest, 0x31,
           sizeof(admission_record.request_digest));
    admission_record.vm_id = candidate.vm_id;
    admission_record.vm_incarnation = candidate.vm_incarnation;
    admission_record.manifest_generation = candidate.manifest_generation;
    memcpy(admission_record.admission_tx_id, candidate.admission_tx_id,
           sizeof(admission_record.admission_tx_id));
    memcpy(admission_record.manifest_id, candidate.manifest_id,
           sizeof(admission_record.manifest_id));
    admission_record.route_scope_key = candidate.route_scope_key;
    admission_record.state = WVM_LIFECYCLE_PLANNED;
    admission_record.has_candidate_manifest_digest = 1;
    memcpy(admission_record.candidate_manifest_digest, candidate_digest,
           sizeof(admission_record.candidate_manifest_digest));
    admission_record.has_prepared_route_snapshot_key = 1;
    admission_record.prepared_route_snapshot_key =
        candidate.prepared_route_snapshot_key;
    admission_record.transaction_sequence = 1;
    if (expect(wvm_admission_transaction_record_encode(
                   &admission_record, bytes, sizeof(bytes), &encoded_bytes,
                   error, sizeof(error)) == 0 &&
                   wvm_admission_transaction_record_decode(
                       bytes, encoded_bytes, &decoded_admission_record, error,
                       sizeof(error)) == 0 &&
                   decoded_admission_record.has_prepared_route_snapshot_key &&
                   decoded_admission_record
                           .prepared_route_snapshot_key.route_generation ==
                       candidate.prepared_route_snapshot_key.route_generation &&
                   memcmp(decoded_admission_record.prepared_route_snapshot_key
                              .snapshot_digest,
                          candidate.prepared_route_snapshot_key.snapshot_digest,
                          WVM_SHA256_DIGEST_BYTES) == 0,
               "round trip candidate-bound prepared route snapshot key")) {
        return 1;
    }
    admission_record.has_prepared_route_snapshot_key = 0;
    if (expect(wvm_admission_transaction_record_validate(
                   &admission_record, error, sizeof(error)) != 0,
               "reject candidate digest without prepared route snapshot key")) {
        return 1;
    }
    invalid_requirement = requirements[0];
    invalid_requirement.guest_vcpu_slots++;
    if (expect(wvm_resource_reservation_derive(
                   &invalid_requirement, &candidate, candidate_digest,
                   &reservation, 1000, error, sizeof(error)) != 0,
               "reject non-candidate reservation requirement") ||
        expect(wvm_resource_reservation_derive(
                   &requirements[0], &candidate, candidate_digest,
                   &reservation, 1000, error, sizeof(error)) == 0,
               "derive prepared reservation")) {
        return 1;
    }
    memset(&decoded_reservation, 0, sizeof(decoded_reservation));
    if (expect(wvm_resource_reservation_encode(
                   &reservation, bytes, sizeof(bytes), &encoded_bytes, error,
                   sizeof(error)) == 0,
               "encode prepared reservation") ||
        expect(wvm_resource_reservation_decode(
                   bytes, encoded_bytes, &decoded_reservation, error,
                   sizeof(error)) == 0,
               "decode prepared reservation") ||
        expect(memcmp(decoded_reservation.reservation_id, reservation.reservation_id,
                      sizeof(reservation.reservation_id)) == 0 &&
                   decoded_reservation.state == WVM_RESERVATION_PREPARED,
               "round trip prepared reservation")) {
        return 1;
    }

    required_snapshots[0] = candidate.prepared_route_snapshot_key;
    fill_id(activation_fence, 0x77);
    memset(participant_digest, 0xa1, sizeof(participant_digest));
    if (expect(wvm_activation_record_decide(
                   &activation, &candidate, candidate_digest, activation_fence,
                   99, participant_digest, required_snapshots, 1, 1,
                   WVM_ACTIVATION_ACTIVATE, 1, 2000, error,
                   sizeof(error)) == 0,
               "decide activation") ||
        expect(wvm_resource_reservation_commit(&reservation, &activation, error,
                                               sizeof(error)) == 0,
               "commit reservation")) {
        return 1;
    }
    memset(&decoded_activation, 0, sizeof(decoded_activation));
    decoded_activation.required_route_snapshot_keys = decoded_snapshots;
    decoded_activation.required_route_snapshot_capacity = 1;
    if (expect(wvm_activation_record_encode(
                   &activation, bytes, sizeof(bytes), &encoded_bytes, error,
                   sizeof(error)) == 0,
               "encode activation record") ||
        expect(wvm_activation_record_decode(
                   bytes, encoded_bytes, &decoded_activation, error,
                   sizeof(error)) == 0,
               "decode activation record") ||
        expect(decoded_activation.decision == WVM_ACTIVATION_ACTIVATE &&
                   decoded_activation.required_route_snapshot_count == 1 &&
                   memcmp(decoded_activation.activation_fence, activation_fence,
                          sizeof(activation_fence)) == 0,
               "round trip activation record")) {
        return 1;
    }

    memset(&runtime_manifest, 0, sizeof(runtime_manifest));
    runtime_manifest.local_vcpu_assignments.entries = local_vcpus;
    runtime_manifest.local_vcpu_assignments.count = 2;
    runtime_manifest.local_vcpu_assignments.capacity = 2;
    runtime_manifest.local_memory_assignments.entries = local_memory;
    runtime_manifest.local_memory_assignments.count = 2;
    runtime_manifest.local_memory_assignments.capacity = 2;
    runtime_manifest.startup_dependencies.entries = dependencies;
    runtime_manifest.startup_dependencies.capacity = 1;
    runtime_manifest.launch_plan.plan_version =
        WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
    runtime_manifest.launch_plan.node_runtime_data_port = 19100;
    runtime_manifest.launch_plan.node_runtime_control_port = 19121;
    runtime_manifest.launch_plan.local_executor_service_port = 19105;
    runtime_manifest.launch_plan.local_executor_control_port = 19121;
    runtime_manifest.launch_plan.executor_worker_count = 1;
    runtime_manifest.launch_plan.vcpu_handoff_record_capacity = 16;
    runtime_manifest.launch_plan.sync_batch_size = 1;
    runtime_manifest.launch_plan.guest_total_memory_bytes =
        4 * 1024 * 1024;
    runtime_manifest.launch_plan.guest_machine = candidate.guest_machine;
    runtime_manifest.launch_plan.consistency_policy =
        candidate.consistency_policy;
    if (expect(wvm_node_runtime_manifest_project(
                   &candidate, candidate_digest, &reservation, &activation,
                   &runtime_manifest.launch_plan, 1, &runtime_manifest, error,
                   sizeof(error)) == 0,
               "project node runtime manifest") ||
        expect(runtime_manifest.has_activation_fence,
               "project committed activation fence") ||
        expect(runtime_manifest.local_vcpu_assignments.count == 1,
               "filter local vCPU assignments") ||
        expect(runtime_manifest.local_memory_assignments.count == 1,
               "filter local memory assignments") ||
        expect(runtime_manifest.local_vcpu_assignments.entries[0]
                       .executor_physical_node_id == 17,
               "project local vCPU node") ||
        expect(runtime_manifest.local_memory_assignments.entries[0]
                       .executor_physical_node_id == 17,
               "project local memory node")) {
        return 1;
    }
    memset(&dependency, 0, sizeof(dependency));
    dependency.dependency_kind = WVM_STARTUP_DEPENDENCY_REQUIRED_MEMBER;
    dependency.member_key = members[1].member_key;
    dependency.required_state = WVM_MANIFEST_MEMBER_ACTIVE;
    if (expect(wvm_startup_dependency_encode(
                   &dependency, bytes, sizeof(bytes), &encoded_bytes, error,
                   sizeof(error)) == 0,
               "encode startup dependency") ||
        expect(wvm_startup_dependency_decode(
                   bytes, encoded_bytes, &decoded_dependency, error,
                   sizeof(error)) == 0,
               "decode startup dependency")) {
        return 1;
    }
    dependencies[0] = decoded_dependency;
    runtime_manifest.startup_dependencies.count = 1;
    memset(&decoded_runtime_manifest, 0, sizeof(decoded_runtime_manifest));
    decoded_runtime_manifest.local_vcpu_assignments.entries = decoded_local_vcpus;
    decoded_runtime_manifest.local_vcpu_assignments.capacity = 2;
    decoded_runtime_manifest.local_memory_assignments.entries =
        decoded_local_memory;
    decoded_runtime_manifest.local_memory_assignments.capacity = 2;
    decoded_runtime_manifest.negotiated_profile.per_node_capabilities.entries =
        decoded_capabilities;
    decoded_runtime_manifest.negotiated_profile.per_node_capabilities.capacity =
        2;
    decoded_runtime_manifest.startup_dependencies.entries = decoded_dependencies;
    decoded_runtime_manifest.startup_dependencies.capacity = 1;
    if (expect(wvm_node_runtime_manifest_encode(
                   &runtime_manifest, bytes, sizeof(bytes), &encoded_bytes,
                   error, sizeof(error)) == 0,
               "encode node runtime manifest") ||
        expect(wvm_node_runtime_manifest_decode(
                   bytes, encoded_bytes, &decoded_runtime_manifest, error,
                   sizeof(error)) == 0,
               "decode node runtime manifest") ||
        expect(decoded_runtime_manifest.local_vcpu_assignments.count == 1 &&
                   decoded_runtime_manifest.local_memory_assignments.count == 1 &&
                   decoded_runtime_manifest.startup_dependencies.count == 1 &&
                   decoded_runtime_manifest.launch_plan
                           .local_executor_service_port == 19105 &&
                   decoded_runtime_manifest.launch_plan
                           .guest_total_memory_bytes == 4 * 1024 * 1024 &&
                   memcmp(decoded_runtime_manifest.candidate_manifest_digest,
                          candidate_digest, sizeof(candidate_digest)) == 0,
               "round trip node runtime manifest")) {
        return 1;
    }
    if (test_runtime_dispatch_projection(&candidate, &runtime_manifest, error,
                                         sizeof(error)) != 0) {
        return 1;
    }

    if (expect(wvm_resource_reservation_begin_release(&reservation, error,
                                                       sizeof(error)) == 0,
               "begin committed reservation release") ||
        expect(wvm_resource_reservation_release(&reservation, error,
                                                sizeof(error)) == 0,
               "complete reservation release") ||
        expect(reservation.state == WVM_RESERVATION_RELEASED,
               "reservation is released")) {
        return 1;
    }

    if (expect(wvm_lifecycle_transaction_init(&transaction, &candidate,
                                              candidate_digest, error,
                                              sizeof(error)) == 0,
               "initialize lifecycle transaction") ||
        expect(wvm_lifecycle_transition(
                   &transaction, WVM_LIFECYCLE_PLANNED,
                   WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED, error,
                   sizeof(error)) == 0,
               "advance planned transaction") ||
        expect(wvm_lifecycle_transition(&transaction,
                                        WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED,
                                        WVM_LIFECYCLE_RUNNING, error,
                                        sizeof(error)) != 0,
               "reject lifecycle state skip") ||
        expect(wvm_lifecycle_transition(
                   &transaction, WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED,
                   WVM_LIFECYCLE_ABORTING, error, sizeof(error)) == 0,
               "abort pre-activation transaction") ||
        expect(wvm_lifecycle_transition(&transaction, WVM_LIFECYCLE_ABORTING,
                                        WVM_LIFECYCLE_ABORTED, error,
                                        sizeof(error)) == 0,
               "complete transaction abort")) {
        return 1;
    }

    puts("lifecycle-projection tests: PASS");
    return 0;
}

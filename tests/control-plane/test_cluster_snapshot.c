#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_canonical.h"
#include "wavevm_cluster.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "cluster-snapshot test: %s\n", message);
        return -1;
    }
    return 0;
}

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 10;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_capability(struct wvm_capability_record *record,
                            uint16_t capability_id, uint32_t node_id,
                            uint64_t node_instance, uint64_t provider)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = node_id;
    record->node_instance_id = node_instance;
    record->provider_instance_id = provider;
    record->state = WVM_CAPABILITY_AVAILABLE;
    record->abi_version = 1;
    record->observed_at = 1;
    record->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] =
        (uint8_t)provider;
}

static int fill_node(struct wvm_node_record *node, uint32_t node_id,
                     uint64_t instance, uint64_t failure_domain,
                     struct wvm_capability_record *capabilities,
                     size_t capability_count, uint32_t *gateway_ids,
                     size_t gateway_id_count)
{
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];

    memset(node, 0, sizeof(*node));
    node->physical_node_id = node_id;
    node->node_instance_id = instance;
    node->failure_domain_id = failure_domain;
    fill_endpoint(&node->control_endpoint, (uint8_t)node_id,
                  (uint16_t)(9000 + node_id), (uint16_t)(9100 + node_id));
    fill_endpoint(&node->sidecar_endpoint, (uint8_t)node_id,
                  (uint16_t)(9200 + node_id), (uint16_t)(9300 + node_id));
    node->role_bits = 1;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = node_id;
    node->inventory.node_instance_id = instance;
    node->inventory.failure_domain_id = failure_domain;
    node->inventory.inventory_revision = 7;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * 1024 * 1024;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = 1024 * 1024;
    node->inventory.reserved_gateway_cpu_slots = gateway_id_count ? 1 : 0;
    node->inventory.reserved_gateway_memory_bytes =
        gateway_id_count ? 1024 * 1024 : 0;
    node->inventory.hosted_gateway_role_ids = gateway_ids;
    node->inventory.hosted_gateway_role_id_count = gateway_id_count;
    node->inventory.hosted_gateway_role_id_capacity = gateway_id_count;
    node->inventory.allocatable_vcpu_slots = gateway_id_count ? 6 : 7;
    node->inventory.allocatable_memory_bytes =
        gateway_id_count ? 14 * 1024 * 1024 : 15 * 1024 * 1024;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = node_id;
    node->capability.node_instance_id = instance;
    node->capability.profile_generation = 9;
    if (wvm_capability_profile_digest(node_id, instance, 9, capabilities,
                                      capability_count, profile_digest, NULL,
                                      0) != 0) {
        return -1;
    }
    memcpy(node->capability.profile_digest, profile_digest,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = 1;
    node->membership_revision = 5;
    node->topology_revision = 6;
    return 0;
}

int main(void)
{
    struct wvm_capability_record capabilities[6];
    struct wvm_node_record nodes[2];
    struct wvm_gateway_record gateway;
    struct wvm_cluster_record_set records;
    struct wvm_cluster_snapshot snapshot;
    struct wvm_admission_request request;
    struct wvm_admission_plan plan;
    struct wvm_cluster_snapshot constrained_snapshot;
    struct wvm_host_constraint constraints[1];
    struct wvm_host_constraint_list constraint_list;
    struct wvm_required_ack_entry ack_entries[1];
    struct wvm_required_ack_entry decoded_ack_entries[1];
    struct wvm_required_ack_set ack_set;
    struct wvm_required_ack_set decoded_ack_set;
    struct wvm_required_member selected_members[3];
    struct wvm_admission_eligibility_fence fence;
    uint32_t gateway_ids[1] = {3};
    uint8_t admission_tx_id[WVM_ADMISSION_ID_BYTES] = {0};
    char error[256] = {0};

    fill_capability(&capabilities[0], WVM_CAPABILITY_ID_EXECUTION_KVM, 17, 101,
                    1);
    fill_capability(&capabilities[1], WVM_CAPABILITY_ID_EXECUTION_TCG, 17, 101,
                    2);
    fill_capability(&capabilities[2], WVM_CAPABILITY_ID_MODE_B_MEMORY, 17, 101,
                    3);
    fill_capability(&capabilities[3], WVM_CAPABILITY_ID_EXECUTION_KVM, 99, 202,
                    1);
    fill_capability(&capabilities[4], WVM_CAPABILITY_ID_EXECUTION_TCG, 99, 202,
                    2);
    fill_capability(&capabilities[5], WVM_CAPABILITY_ID_MODE_B_MEMORY, 99, 202,
                    3);
    if (expect(fill_node(&nodes[0], 17, 101, 1, capabilities, 3, gateway_ids,
                         1) == 0 &&
                   fill_node(&nodes[1], 99, 202, 2, capabilities + 3, 3, NULL,
                             0) ==
                       0,
               "derive node capability profiles")) {
        return 1;
    }

    memset(&gateway, 0, sizeof(gateway));
    gateway.gateway_id = 3;
    gateway.gateway_instance_id = 301;
    gateway.hosting_physical_node_id = 17;
    gateway.failure_domain_id = 1;
    fill_endpoint(&gateway.endpoint, 17, 9400, 9401);
    gateway.role_bits = 1;
    gateway.desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    gateway.observed_health_state = 1;
    gateway.membership_revision = 5;
    gateway.topology_revision = 6;

    memset(&records, 0, sizeof(records));
    records.nodes = nodes;
    records.node_count = 2;
    records.gateways = &gateway;
    records.gateway_count = 1;
    records.capability_records = capabilities;
    records.capability_record_count = 6;
    records.inventory_revision = 10;
    records.membership_revision = 5;
    records.topology_revision = 6;
    records.admission_eligibility_revision = 7;
    records.capability_profile_generation = 9;
    if (expect(wvm_cluster_snapshot_build(&records, &snapshot, error,
                                          sizeof(error)) == 0,
               "build canonical cluster snapshot") ||
        expect(snapshot.admission.node_count == 2 &&
                   snapshot.admission.nodes[0].physical_node_id == 17 &&
                   snapshot.admission.nodes[0].backend_capabilities ==
                       (WVM_ADMISSION_BACKEND_CAP_KVM |
                        WVM_ADMISSION_BACKEND_CAP_TCG),
               "derive Mode B backend eligibility") ||
        expect(snapshot.admission.nodes[0].runtime_capabilities ==
                   WVM_ADMISSION_RUNTIME_CAP_MODE_B_MEMORY,
               "derive independent Mode B memory eligibility")) {
        return 1;
    }
    memset(constraints, 0, sizeof(constraints));
    constraints[0].constraint_kind =
        WVM_MANIFEST_HOST_CONSTRAINT_PHYSICAL_NODE;
    constraints[0].comparison_operator = WVM_MANIFEST_HOST_CONSTRAINT_EQUALS;
    strcpy(constraints[0].subject, "id");
    strcpy(constraints[0].value, "17");
    constraint_list.entries = constraints;
    constraint_list.count = 1;
    constraint_list.capacity = 1;
    if (expect(wvm_cluster_snapshot_apply_host_constraints(
                   &records, &snapshot, &constraint_list, &constrained_snapshot,
                   error, sizeof(error)) == 0,
               "apply canonical physical-node constraint") ||
        expect(constrained_snapshot.admission.nodes[0].membership_state ==
                   WVM_ADMISSION_MEMBER_ACTIVE &&
                   constrained_snapshot.admission.nodes[1].membership_state ==
                       WVM_ADMISSION_MEMBER_CORDONED,
               "cordon nodes outside constrained participant set")) {
        return 1;
    }

    {
        struct wvm_cluster_snapshot previous = constrained_snapshot;
        struct wvm_cluster_snapshot untouched;
        struct wvm_cluster_snapshot sentinel;
        uint32_t saved_kind = constraints[0].constraint_kind;

        memset(&untouched, 0xa5, sizeof(untouched));
        sentinel = untouched;
        constraints[0].constraint_kind = 0;
        if (expect(wvm_cluster_snapshot_apply_host_constraints(
                       &records, &snapshot, &constraint_list, &untouched,
                       error, sizeof(error)) != 0 &&
                       memcmp(&untouched, &sentinel, sizeof(untouched)) == 0,
                   "invalid constraint leaves uninitialized output untouched") ||
            expect(wvm_cluster_snapshot_apply_host_constraints(
                       &records, &snapshot, &constraint_list,
                       &constrained_snapshot, error, sizeof(error)) != 0 &&
                       memcmp(&constrained_snapshot, &previous,
                              sizeof(previous)) == 0,
                   "failed constraint preserves previous snapshot")) {
            return 1;
        }
        constraints[0].constraint_kind = saved_kind;
        if (expect(wvm_cluster_snapshot_apply_host_constraints(
                       &records, &snapshot, &constraint_list, &snapshot,
                       error, sizeof(error)) != 0 &&
                       snapshot.admission.nodes[1].membership_state ==
                           WVM_ADMISSION_MEMBER_ACTIVE,
                   "reject in-place constraint without changing source")) {
            return 1;
        }
    }

    memset(&request, 0, sizeof(request));
    request.vm_id = 256;
    request.vm_incarnation = 1;
    request.manifest_generation = 1;
    request.backend = WVM_ADMISSION_BACKEND_TCG;
    request.placement_policy = WVM_ADMISSION_PLACEMENT_SPREAD;
    request.requested_vcpu_slots = 2;
    request.requested_memory_bytes = 4 * 1024 * 1024;
    request.memory_chunk_bytes = 2 * 1024 * 1024;
    request.host_overhead_vcpu_slots = 1;
    request.host_overhead_memory_bytes = 1024 * 1024;
    admission_tx_id[WVM_ADMISSION_ID_BYTES - 1] = 0x42;
    if (expect(wvm_admission_plan_propose(&snapshot.admission, &request,
                                          admission_tx_id, &plan, error,
                                          sizeof(error)) == 0,
               "propose from canonical snapshot")) {
        return 1;
    }

    memset(ack_entries, 0, sizeof(ack_entries));
    ack_entries[0].member_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    ack_entries[0].member_key.role_id = 3;
    ack_entries[0].member_key.instance_id = 301;
    ack_entries[0].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    ack_entries[0].endpoint = gateway.endpoint;
    ack_entries[0].expected_snapshot_key.scope_key.vm_id = request.vm_id;
    ack_entries[0].expected_snapshot_key.scope_key.vm_incarnation =
        request.vm_incarnation;
    ack_entries[0].expected_snapshot_key.scope_key.route_scope_id = 1;
    ack_entries[0].expected_snapshot_key.topology_revision = 6;
    ack_entries[0].expected_snapshot_key.route_generation = 1;
    memset(ack_entries[0].expected_snapshot_key.snapshot_digest, 0x61,
           sizeof(ack_entries[0].expected_snapshot_key.snapshot_digest));
    memset(&ack_set, 0, sizeof(ack_set));
    ack_set.entries.entries = ack_entries;
    ack_set.entries.count = 1;
    ack_set.entries.capacity = 1;
    memset(ack_set.entries_digest, 0, sizeof(ack_set.entries_digest));
    {
        uint8_t ack_bytes[1024];
        size_t ack_bytes_used;

        if (wvm_required_ack_set_encode(&ack_set, ack_bytes, sizeof(ack_bytes),
                                        &ack_bytes_used, error,
                                        sizeof(error)) != 0) {
            return 1;
        }
        memset(&decoded_ack_set, 0, sizeof(decoded_ack_set));
        decoded_ack_set.entries.entries = decoded_ack_entries;
        decoded_ack_set.entries.capacity = 1;
        if (wvm_required_ack_set_decode(ack_bytes, ack_bytes_used,
                                        &decoded_ack_set, error,
                                        sizeof(error)) != 0) {
            return 1;
        }
    }

    memset(&fence, 0, sizeof(fence));
    fence.selected_members.entries = selected_members;
    fence.selected_members.capacity = 3;
    if (expect(wvm_cluster_admission_fence_build(
                   &records, &snapshot, &request, &plan,
                   &ack_entries[0].expected_snapshot_key.scope_key,
                   &decoded_ack_set,
                   &fence, error, sizeof(error)) == 0,
               "build admission eligibility fence") ||
        expect(fence.selected_members.count == 3 &&
                   fence.selected_members.entries[0].member_key.role_type ==
                       WVM_MANIFEST_ROLE_NODE_RUNTIME &&
                   !bytes_are_zero(fence.fence_digest,
                                   sizeof(fence.fence_digest)),
               "select plan and route participants")) {
        return 1;
    }

    {
        struct wvm_cluster_snapshot untouched;
        struct wvm_cluster_snapshot before;

        memset(&untouched, 0xa5, sizeof(untouched));
        memcpy(&before, &untouched, sizeof(before));
        nodes[0].membership_revision++;
        if (expect(wvm_cluster_snapshot_build(&records, &untouched, error,
                                              sizeof(error)) != 0 &&
                       memcmp(&untouched, &before, sizeof(untouched)) == 0,
                   "invalid record cannot free an uninitialized output")) {
            return 1;
        }
        memcpy(&before, &snapshot, sizeof(before));
        if (expect(wvm_cluster_snapshot_build(&records, &snapshot, error,
                                              sizeof(error)) != 0 &&
                       memcmp(&snapshot, &before, sizeof(snapshot)) == 0,
                   "invalid record preserves the previous snapshot") ||
            expect(wvm_admission_snapshot_validate(&snapshot.admission, error,
                                                    sizeof(error)) == 0,
                   "previous snapshot remains usable after build failure")) {
            return 1;
        }
        nodes[0].membership_revision--;
    }

    capabilities[5].state = WVM_CAPABILITY_UNAVAILABLE;
    capabilities[5].reason_code = 1;
    if (expect(wvm_cluster_snapshot_build(&records, &snapshot, error,
                                          sizeof(error)) != 0,
               "reject stale capability profile digest") ||
        expect(wvm_admission_snapshot_validate(&snapshot.admission, error,
                                                sizeof(error)) == 0,
               "post-allocation failure preserves the previous snapshot")) {
        return 1;
    }

    free(plan.reservations);
    wvm_admission_snapshot_cleanup(&constrained_snapshot.admission);
    wvm_admission_snapshot_cleanup(&snapshot.admission);
    puts("cluster-snapshot tests: PASS");
    return 0;
}

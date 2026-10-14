#include <stdio.h>
#include <string.h>

#include "wavevm_control.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "control-membership-record test: %s\n", message);
        return -1;
    }
    return 0;
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

static void fill_capability(struct wvm_capability_ref *capability,
                            uint32_t node_id, uint64_t instance,
                            uint8_t digest_byte)
{
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = node_id;
    capability->node_instance_id = instance;
    capability->profile_generation = 7;
    memset(capability->profile_digest, digest_byte,
           sizeof(capability->profile_digest));
}

static void fill_node(struct wvm_node_record *node, uint32_t gateway_ids[1])
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = 17;
    node->node_instance_id = 101;
    node->failure_domain_id = 1;
    fill_endpoint(&node->control_endpoint, 17, 9000, 9001);
    fill_endpoint(&node->sidecar_endpoint, 17, 9100, 9101);
    node->role_bits = 1;
    node->local_vnode_first = 0;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = 17;
    node->inventory.node_instance_id = 101;
    node->inventory.failure_domain_id = 1;
    node->inventory.inventory_revision = 3;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * 1024 * 1024;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = 1024 * 1024;
    node->inventory.reserved_gateway_cpu_slots = 1;
    node->inventory.reserved_gateway_memory_bytes = 1024 * 1024;
    node->inventory.hosted_gateway_role_ids = gateway_ids;
    node->inventory.hosted_gateway_role_id_count = 1;
    node->inventory.hosted_gateway_role_id_capacity = 1;
    gateway_ids[0] = 3;
    node->inventory.allocatable_vcpu_slots = 6;
    node->inventory.allocatable_memory_bytes = 14 * 1024 * 1024;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    fill_capability(&node->capability, 17, 101, 0x20);
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = 1;
    node->membership_revision = 4;
    node->topology_revision = 5;
    wvm_node_record_init_single_host_defaults(node);
}

int main(void)
{
    struct wvm_node_record node;
    struct wvm_node_record decoded_node;
    struct wvm_gateway_record gateway;
    struct wvm_gateway_record decoded_gateway;
    uint32_t node_gateway_ids[1];
    uint32_t decoded_node_gateway_ids[1];
    uint32_t gateway_parents[1] = {1};
    uint32_t gateway_children[1] = {2};
    uint32_t decoded_gateway_parents[1];
    uint32_t decoded_gateway_children[1];
    struct wvm_route_snapshot_key route_key;
    struct wvm_required_ack_entry ack_entries[1];
    struct wvm_required_ack_entry decoded_ack_entries[1];
    struct wvm_required_ack_set ack_set;
    struct wvm_required_ack_set decoded_ack_set;
    struct wvm_required_member selected_members[1];
    struct wvm_required_member decoded_selected_members[1];
    struct wvm_admission_eligibility_fence fence;
    struct wvm_admission_eligibility_fence decoded_fence;
    struct wvm_route_transaction_record transaction;
    struct wvm_route_transaction_record decoded_transaction;
    uint8_t bytes[8192];
    uint8_t ack_bytes[4096];
    uint8_t fence_digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    size_t ack_encoded_bytes;
    char error[256] = {0};

    fill_node(&node, node_gateway_ids);
    if (expect(wvm_node_record_encode(&node, bytes, sizeof(bytes),
                                      &encoded_bytes, error,
                                      sizeof(error)) == 0,
               "encode node record")) {
        return 1;
    }
    memset(&decoded_node, 0, sizeof(decoded_node));
    decoded_node.inventory.hosted_gateway_role_ids = decoded_node_gateway_ids;
    decoded_node.inventory.hosted_gateway_role_id_capacity = 1;
    if (expect(wvm_node_record_decode(bytes, encoded_bytes, &decoded_node,
                                      error, sizeof(error)) == 0,
               "decode node record") ||
        expect(decoded_node.inventory.allocatable_vcpu_slots == 6,
               "preserve allocatable CPU capacity") ||
        expect(decoded_node.inventory.hosted_gateway_role_ids[0] == 3,
               "decode hosted gateway list")) {
        return 1;
    }

    memset(&gateway, 0, sizeof(gateway));
    gateway.gateway_id = 3;
    gateway.gateway_instance_id = 301;
    gateway.hosting_physical_node_id = 17;
    gateway.failure_domain_id = 1;
    fill_endpoint(&gateway.endpoint, 17, 9200, 9201);
    gateway.role_bits = 2;
    gateway.parent_gateway_ids = gateway_parents;
    gateway.parent_gateway_id_count = 1;
    gateway.parent_gateway_id_capacity = 1;
    gateway.child_gateway_ids = gateway_children;
    gateway.child_gateway_id_count = 1;
    gateway.child_gateway_id_capacity = 1;
    gateway.desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    gateway.observed_health_state = 1;
    gateway.membership_revision = 4;
    gateway.topology_revision = 5;
    if (expect(wvm_gateway_record_encode(&gateway, bytes, sizeof(bytes),
                                         &encoded_bytes, error,
                                         sizeof(error)) == 0,
               "encode gateway record")) {
        return 1;
    }
    memset(&decoded_gateway, 0, sizeof(decoded_gateway));
    decoded_gateway.parent_gateway_ids = decoded_gateway_parents;
    decoded_gateway.parent_gateway_id_capacity = 1;
    decoded_gateway.child_gateway_ids = decoded_gateway_children;
    decoded_gateway.child_gateway_id_capacity = 1;
    if (expect(wvm_gateway_record_decode(bytes, encoded_bytes, &decoded_gateway,
                                         error, sizeof(error)) == 0,
               "decode gateway record") ||
        expect(decoded_gateway.child_gateway_ids[0] == 2,
               "decode gateway child")) {
        return 1;
    }

    memset(&route_key, 0, sizeof(route_key));
    route_key.scope_key.vm_id = 256;
    route_key.scope_key.vm_incarnation = 1;
    route_key.scope_key.route_scope_id = 1;
    route_key.topology_revision = 5;
    route_key.route_generation = 1;
    memset(route_key.snapshot_digest, 0x41, sizeof(route_key.snapshot_digest));
    memset(ack_entries, 0, sizeof(ack_entries));
    ack_entries[0].member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack_entries[0].member_key.role_id = 17;
    ack_entries[0].member_key.instance_id = 1001;
    ack_entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack_entries[0].expected_snapshot_key = route_key;
    fill_endpoint(&ack_entries[0].endpoint, 17, 9000, 9001);
    memset(&ack_set, 0, sizeof(ack_set));
    ack_set.entries.entries = ack_entries;
    ack_set.entries.count = 1;
    ack_set.entries.capacity = 1;
    if (expect(wvm_required_ack_set_encode(&ack_set, ack_bytes,
                                           sizeof(ack_bytes), &ack_encoded_bytes,
                                           error, sizeof(error)) == 0,
               "encode route ACK set")) {
        return 1;
    }
    memset(&decoded_ack_set, 0, sizeof(decoded_ack_set));
    decoded_ack_set.entries.entries = decoded_ack_entries;
    decoded_ack_set.entries.capacity = 1;
    if (expect(wvm_required_ack_set_decode(ack_bytes, ack_encoded_bytes,
                                           &decoded_ack_set, error,
                                           sizeof(error)) == 0,
               "decode route ACK set")) {
        return 1;
    }

    memset(selected_members, 0, sizeof(selected_members));
    selected_members[0].member_key = ack_entries[0].member_key;
    selected_members[0].physical_node_id = 17;
    selected_members[0].failure_domain_id = 1;
    fill_capability(&selected_members[0].capability, 17, 101, 0x20);
    selected_members[0].required_state = WVM_MANIFEST_MEMBER_ACTIVE;
    memset(&fence, 0, sizeof(fence));
    memset(fence.admission_tx_id, 0, sizeof(fence.admission_tx_id));
    fence.admission_tx_id[15] = 0x44;
    fence.membership_revision = 4;
    fence.topology_revision = 5;
    fence.admission_eligibility_revision = 6;
    fence.inventory_revision = 3;
    fence.capability_profile_generation = 7;
    fence.selected_members.entries = selected_members;
    fence.selected_members.count = 1;
    fence.selected_members.capacity = 1;
    fence.required_route_scope_key = route_key.scope_key;
    memcpy(fence.required_ack_set_digest, decoded_ack_set.entries_digest,
           sizeof(fence.required_ack_set_digest));
    if (expect(wvm_admission_eligibility_fence_encode(
                   &fence, bytes, sizeof(bytes), &encoded_bytes, fence_digest,
                   error, sizeof(error)) == 0,
               "encode admission fence")) {
        return 1;
    }
    memset(&decoded_fence, 0, sizeof(decoded_fence));
    decoded_fence.selected_members.entries = decoded_selected_members;
    decoded_fence.selected_members.capacity = 1;
    if (expect(wvm_admission_eligibility_fence_decode(
                   bytes, encoded_bytes, &decoded_fence, error,
                   sizeof(error)) == 0,
               "decode admission fence") ||
        expect(memcmp(decoded_fence.fence_digest, fence_digest,
                      sizeof(fence_digest)) == 0,
               "validate admission fence digest")) {
        return 1;
    }

    memset(&transaction, 0, sizeof(transaction));
    transaction.operation_id[15] = 0x55;
    transaction.route_snapshot_key = route_key;
    transaction.required_ack_set = decoded_ack_set;
    transaction.operation_retention_horizon_ms = 5000;
    transaction.state = 1;
    if (expect(wvm_route_transaction_record_encode(
                   &transaction, bytes, sizeof(bytes), &encoded_bytes, error,
                   sizeof(error)) == 0,
               "encode route transaction")) {
        return 1;
    }
    memset(&decoded_transaction, 0, sizeof(decoded_transaction));
    decoded_transaction.required_ack_set.entries.entries = decoded_ack_entries;
    decoded_transaction.required_ack_set.entries.capacity = 1;
    if (expect(wvm_route_transaction_record_decode(
                   bytes, encoded_bytes, &decoded_transaction, error,
                   sizeof(error)) == 0,
               "decode route transaction") ||
        expect(decoded_transaction.required_ack_set.entries.count == 1,
               "decode transaction ACK set")) {
        return 1;
    }

    puts("control-membership-record tests: PASS");
    return 0;
}

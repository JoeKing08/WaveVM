#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "wavevm_control.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "physical-host-aggregate test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint32_t node_id,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 10;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = (uint8_t)(node_id >> 8);
    endpoint->data_address[3] = (uint8_t)node_id;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_node(struct wvm_node_record *node, uint32_t node_id,
                      uint64_t instance_id, uint64_t host_id, uint16_t data_port,
                      uint16_t control_port, uint32_t registered_vcpu,
                      uint32_t allocatable_vcpu, const char *namespace_name)
{
    uint32_t reserved_vcpu;
    uint64_t registered_memory = 16ULL * 1024ULL * 1024ULL;
    uint64_t allocatable_memory = 8ULL * 1024ULL * 1024ULL;
    uint64_t reserved_memory;

    memset(node, 0, sizeof(*node));
    if (allocatable_vcpu > registered_vcpu) {
        allocatable_vcpu = registered_vcpu;
    }
    reserved_vcpu = registered_vcpu - allocatable_vcpu;
    if (allocatable_memory > registered_memory) {
        allocatable_memory = registered_memory;
    }
    reserved_memory = registered_memory - allocatable_memory;
    node->physical_node_id = node_id;
    node->node_instance_id = instance_id;
    node->failure_domain_id = 1;
    fill_endpoint(&node->control_endpoint, node_id, data_port, control_port);
    fill_endpoint(&node->sidecar_endpoint, node_id, (uint16_t)(data_port + 10U),
                  (uint16_t)(control_port + 10U));
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_first = 0;
    node->local_vnode_count = 8;
    node->inventory.physical_node_id = node_id;
    node->inventory.node_instance_id = instance_id;
    node->inventory.failure_domain_id = 1;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = registered_vcpu;
    node->inventory.registered_memory_bytes = registered_memory;
    node->inventory.reserved_host_cpu_slots = reserved_vcpu;
    node->inventory.reserved_host_memory_bytes = reserved_memory;
    node->inventory.allocatable_vcpu_slots = allocatable_vcpu;
    node->inventory.allocatable_memory_bytes = allocatable_memory;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = node_id;
    node->capability.node_instance_id = instance_id;
    node->capability.profile_generation = 1;
    memset(node->capability.profile_digest, 0x21,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = 1;
    node->membership_revision = 1;
    node->topology_revision = 1;
    node->physical_host_id = host_id;
    snprintf(node->node_instance_namespace.namespace_name,
             sizeof(node->node_instance_namespace.namespace_name), "%s",
             namespace_name);
    memset(node->node_instance_namespace.derivation_salt_digest, 0xa5,
           sizeof(node->node_instance_namespace.derivation_salt_digest));
    node->node_instance_namespace.name_generation = 1;
}

int main(void)
{
    struct wvm_node_record nodes[2];
    struct wvm_node_record decoded;
    uint8_t bytes[4096];
    size_t encoded = 0;
    char error[256] = {0};

    fill_node(&nodes[0], 17, 101, 9001, 19100, 19101, 8, 4, "ni-host9001-a");
    fill_node(&nodes[1], 18, 102, 9001, 19200, 19201, 8, 4, "ni-host9001-b");

    if (expect(wvm_node_record_encode(&nodes[0], bytes, sizeof(bytes), &encoded,
                                      error, sizeof(error)) == 0,
               "encode node with physical_host_id + namespace") ||
        expect(wvm_node_record_decode(bytes, encoded, &decoded, error,
                                      sizeof(error)) == 0,
               "decode node with physical_host_id + namespace") ||
        expect(decoded.physical_host_id == 9001 &&
                   strcmp(decoded.node_instance_namespace.namespace_name,
                          "ni-host9001-a") == 0,
               "round-trip preserves host identity")) {
        return 1;
    }

    if (expect(wvm_physical_host_aggregate_validate(nodes, 2, error,
                                                    sizeof(error)) == 0,
               "same-host dual instance with split allocatable fits host budget")) {
        fprintf(stderr, " unexpected error: %s\n", error);
        return 1;
    }

    /* Keep inventory identity: reserved + allocatable == registered. */
    nodes[1].inventory.allocatable_vcpu_slots = 5;
    nodes[1].inventory.reserved_host_cpu_slots = 3; /* 4+5 > host registered 8 */
    if (expect(wvm_physical_host_aggregate_validate(nodes, 2, error,
                                                    sizeof(error)) != 0,
               "fail-closed: allocatable sum must not exceed registered host") ||
        expect(strstr(error, "double-count") != NULL ||
                   strstr(error, "exceeds registered") != NULL,
               "error names double-count / host budget")) {
        fprintf(stderr, " got error: %s\n", error);
        return 1;
    }

    nodes[1].inventory.allocatable_vcpu_slots = 4;
    nodes[1].inventory.reserved_host_cpu_slots = 4;
    nodes[1].inventory.registered_vcpu_slots = 16; /* disagree on host budget */
    nodes[1].inventory.reserved_host_cpu_slots = 12;
    if (expect(wvm_physical_host_aggregate_validate(nodes, 2, error,
                                                    sizeof(error)) != 0,
               "fail-closed: same-host registered capacity must agree")) {
        fprintf(stderr, " got error: %s\n", error);
        return 1;
    }

    nodes[1].inventory.registered_vcpu_slots = 8;
    nodes[1].inventory.reserved_host_cpu_slots = 4;
    nodes[1].inventory.allocatable_vcpu_slots = 4;
    strcpy(nodes[1].node_instance_namespace.namespace_name, "ni-host9001-a");
    if (expect(wvm_physical_host_aggregate_validate(nodes, 2, error,
                                                    sizeof(error)) != 0,
               "fail-closed: same-host namespaces must be distinct")) {
        fprintf(stderr, " got error: %s\n", error);
        return 1;
    }

    strcpy(nodes[1].node_instance_namespace.namespace_name, "ni-host9001-b");
    nodes[1].control_endpoint.data_port = 19100; /* collide with node 0 data */
    if (expect(wvm_physical_host_aggregate_validate(nodes, 2, error,
                                                    sizeof(error)) != 0,
               "fail-closed: same-host listener ports must be distinct")) {
        fprintf(stderr, " got error: %s\n", error);
        return 1;
    }

    puts("physical-host-aggregate tests: PASS");
    puts("NOTE: durable NodeRecord physical_host_id + NodeInstanceNamespace");
    puts("      encode/decode and same-host aggregate fail-closed accounting.");
    puts("      Does not claim dual agent vertical or guest E2E.");
    return 0;
}

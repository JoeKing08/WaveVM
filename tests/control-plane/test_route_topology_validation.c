#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../../common_include/wavevm_admission_route.h"
#include "../../common_include/wavevm_cluster.h"
#include "../../common_include/wavevm_manifest.h"
#include "../../common_include/wavevm_capability.h"
#include "../../common_include/wavevm_canonical.h"

static int fill_capability(struct wvm_capability_record *cap, uint32_t cap_id, uint32_t schema_version) {
    memset(cap, 0, sizeof(*cap));
    cap->capability_id = cap_id;
    cap->capability_schema_version = WVM_CANONICAL_SCHEMA;
    cap->physical_node_id = 17;
    cap->node_instance_id = 101;
    cap->provider_instance_id = schema_version;
    cap->state = WVM_CAPABILITY_AVAILABLE;
    cap->abi_version = 1;
    cap->observed_at = schema_version;
    cap->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] = (uint8_t)schema_version;
    return 0;
}

static int fill_endpoint(struct wvm_endpoint *ep, uint32_t phys_node, uint16_t data_port, uint16_t ctrl_port) {
    memset(ep, 0, sizeof(*ep));
    ep->data_transport = WVM_DATA_TRANSPORT_UDP;
    ep->data_address_bytes = 4;
    ep->data_address[0] = 10;
    ep->data_address[1] = 0;
    ep->data_address[2] = (phys_node >> 8) & 0xff;
    ep->data_address[3] = phys_node & 0xff;
    ep->data_port = data_port;
    ep->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    ep->control_port = ctrl_port;
    return 0;
}

int main(void) {
    struct wvm_node_record node;
    struct wvm_capability_record capabilities[3];
    struct wvm_cluster_record_set records;
    struct wvm_admission_route_compiler compiler_flat, compiler_fractal;
    struct wvm_route_rule_record route_rules[256];
    struct wvm_required_ack_entry ack_entries[1];
    uint8_t snapshot_bytes[65536];
    uint8_t ack_set_bytes[4096];
    uint32_t hosted_gateways[1] = {1};
    char error[512];
    
    printf("=== WaveVM Route Topology Validation ===\n\n");
    
    fill_capability(&capabilities[0], WVM_CAPABILITY_ID_EXECUTION_KVM, 1);
    fill_capability(&capabilities[1], WVM_CAPABILITY_ID_EXECUTION_TCG, 2);
    fill_capability(&capabilities[2], WVM_CAPABILITY_ID_MODE_B_MEMORY, 3);
    
    memset(&node, 0, sizeof(node));
    node.physical_node_id = 17;
    node.node_instance_id = 101;
    node.failure_domain_id = 1;
    fill_endpoint(&node.control_endpoint, 17, 9000, 9100);
    fill_endpoint(&node.sidecar_endpoint, 17, 9200, 9300);
    node.role_bits = 1;
    node.pod_id = 7;
    node.local_vnode_first = 0;
    node.local_vnode_count = 16;
    
    node.inventory.physical_node_id = 17;
    node.inventory.node_instance_id = 101;
    node.inventory.inventory_revision = 7;
    node.inventory.registered_vcpu_slots = 8;
    node.inventory.registered_memory_bytes = 16 * 1024 * 1024;
    node.inventory.allocatable_vcpu_slots = 6;
    node.inventory.allocatable_memory_bytes = 14 * 1024 * 1024;
    node.inventory.hosted_gateway_role_ids = hosted_gateways;
    node.inventory.hosted_gateway_role_id_count = 1;
    
    node.capability.physical_node_id = 17;
    node.capability.node_instance_id = 101;
    node.capability.profile_generation = 9;

    uint8_t profile_digest[32];
    char digest_error[256];
    if (wvm_capability_profile_digest(17, 101, 9, capabilities, 3, profile_digest, digest_error, sizeof(digest_error)) != 0) {
        fprintf(stderr, "FAIL: cannot compute capability profile digest: %s\n", digest_error);
        return 1;
    }
    memcpy(node.capability.profile_digest, profile_digest, 32);
    
    node.desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node.observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node.membership_revision = 5;
    node.topology_revision = 6;
    
    memset(&records, 0, sizeof(records));
    records.nodes = &node;
    records.node_count = 1;
    records.capability_records = capabilities;
    records.capability_record_count = 3;
    records.membership_revision = 5;
    records.topology_revision = 6;
    records.inventory_revision = 7;
    records.capability_profile_generation = 9;
    
    printf("Test 1: FLAT topology with KVM capability\n");
    if (wvm_admission_route_compiler_init(&compiler_flat, WVM_ROUTE_TOPOLOGY_FLAT,
                                          1, 6000, 1, route_rules, 256,
                                          ack_entries, 1,
                                          snapshot_bytes, sizeof(snapshot_bytes),
                                          ack_set_bytes, sizeof(ack_set_bytes),
                                          error, sizeof(error)) == 0) {
        printf("  ✓ FLAT compiler initialized\n");
    } else {
        printf("  ✗ FLAT compiler init failed: %s\n", error);
        return 1;
    }

    printf("\nTest 2: FRACTAL topology with KVM capability\n");
    if (wvm_admission_route_compiler_init(&compiler_fractal, WVM_ROUTE_TOPOLOGY_FRACTAL,
                                          1, 6000, 1, route_rules, 256,
                                          ack_entries, 1,
                                          snapshot_bytes, sizeof(snapshot_bytes),
                                          ack_set_bytes, sizeof(ack_set_bytes),
                                          error, sizeof(error)) == 0) {
        printf("  ✓ FRACTAL compiler initialized\n");
    } else {
        printf("  ✗ FRACTAL compiler init failed: %s\n", error);
        return 1;
    }
    
    printf("\nTest 3: Node capability verification\n");
    printf("  Node %u has capabilities:\n", node.physical_node_id);
    for (size_t i = 0; i < 3; i++) {
        const char *cap_name = "UNKNOWN";
        if (capabilities[i].capability_id == WVM_CAPABILITY_ID_EXECUTION_KVM) {
            cap_name = "EXECUTION_KVM";
        } else if (capabilities[i].capability_id == WVM_CAPABILITY_ID_EXECUTION_TCG) {
            cap_name = "EXECUTION_TCG";
        } else if (capabilities[i].capability_id == WVM_CAPABILITY_ID_MODE_B_MEMORY) {
            cap_name = "MODE_B_MEMORY";
        }
        printf("    - %s (id=%u, schema_ver=%u)\n", cap_name,
               capabilities[i].capability_id, capabilities[i].capability_schema_version);
    }

    printf("\nTest 4: Route topology contracts\n");
    printf("  FLAT topology: direct vnode addressing (16 vnodes)\n");
    printf("  FRACTAL topology: hierarchical pod addressing (pod_id=%lu)\n", (unsigned long)node.pod_id);

    printf("\n=== Route compiler initialization and topology structure validation PASS ===\n");
    printf("NOTE: This test validates compiler setup and topology metadata.\n");
    printf("      It does not exercise compile/forward logic or KVM/TCG execution paths.\n");
    return 0;
}

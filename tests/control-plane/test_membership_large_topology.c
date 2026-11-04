#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_admission_route.h"
#include "wavevm_canonical.h"
#include "wavevm_capability.h"
#include "wavevm_cluster.h"
#include "wavevm_host_probe.h"
#include "wavevm_membership_controller.h"
#include "wavevm_route_runtime.h"

#define NODE_COUNT 2U
#define NODE_VNODES 2050U
#define TOTAL_VNODES (NODE_COUNT * NODE_VNODES)
#define ROUTE_CAPACITY (TOTAL_VNODES + 4U)

static int fail(const char *where, const char *error)
{
    fprintf(stderr, "large-topology: %s: %s\n", where,
            error && error[0] ? error : "failed");
    return 1;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t host,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = host;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_capability(struct wvm_capability_record *record,
                            uint32_t node_id, uint64_t instance,
                            uint16_t capability_id, uint64_t provider)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = node_id;
    record->node_instance_id = instance;
    record->provider_instance_id = provider;
    record->state = WVM_CAPABILITY_AVAILABLE;
    record->abi_version = 1;
    if (capability_id == WVM_CAPABILITY_ID_EXECUTION_TCG)
        record->feature_bits = WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT;
    else if (capability_id == WVM_CAPABILITY_ID_MODE_B_MEMORY)
        record->feature_bits = 1;
    record->observed_at = provider;
    record->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] =
        (uint8_t)provider;
}

static int prepare_controller_records(
    enum wvm_route_topology_kind topology,
    struct wvm_membership_controller *controller,
    struct wvm_membership_controller_member_entry members[3],
    struct wvm_capability_record capabilities[NODE_COUNT * 4U],
    struct wvm_membership_controller_capture *capture,
    struct wvm_node_record captured_nodes[NODE_COUNT],
    struct wvm_gateway_record *captured_gateways,
    uint32_t *captured_hosted_gateways,
    struct wvm_cluster_record_set *records, char *error, size_t error_len)
{
    struct wvm_node_record nodes[NODE_COUNT];
    struct wvm_gateway_record gateway;
    uint32_t *hosted_gateway_ids;
    size_t cap_index = 0;

    memset(nodes, 0, sizeof(nodes));
    memset(&gateway, 0, sizeof(gateway));
    memset(members, 0, 3U * sizeof(*members));
    memset(capabilities, 0, NODE_COUNT * 4U * sizeof(*capabilities));
    wvm_membership_controller_init(controller, members, 3, NULL, 0, NULL, 0,
                                   NULL, NULL);
    controller->membership_revision = 5;
    controller->topology_revision = 6;
    controller->admission_eligibility_revision = 7;

    for (size_t i = 0; i < NODE_COUNT; i++) {
        const uint32_t node_id = i == 0 ? 17U : 19U;
        const uint64_t instance = i == 0 ? 101U : 102U;
        const uint8_t address = i == 0 ? 17U : 19U;
        uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
        uint64_t provider_base = 100U + i * 10U;

        nodes[i].physical_node_id = node_id;
        nodes[i].node_instance_id = instance;
        nodes[i].failure_domain_id = i + 1U;
        fill_endpoint(&nodes[i].control_endpoint, address,
                      (uint16_t)(19100U + i * 100U),
                      (uint16_t)(19101U + i * 100U));
        fill_endpoint(&nodes[i].sidecar_endpoint, address,
                      (uint16_t)(19200U + i * 100U),
                      (uint16_t)(19201U + i * 100U));
        nodes[i].role_bits = 1;
        nodes[i].pod_id = topology == WVM_ROUTE_TOPOLOGY_FRACTAL ?
                              11U + i : 0U;
        nodes[i].local_vnode_first = topology == WVM_ROUTE_TOPOLOGY_FRACTAL ?
                                         0U : (uint32_t)i * NODE_VNODES;
        nodes[i].local_vnode_count = NODE_VNODES;
        nodes[i].inventory.physical_node_id = node_id;
        nodes[i].inventory.node_instance_id = instance;
        nodes[i].inventory.failure_domain_id = i + 1U;
        nodes[i].inventory.inventory_revision = 3;
        nodes[i].inventory.registered_vcpu_slots = 8;
        nodes[i].inventory.registered_memory_bytes = 32U * 1024U * 1024U;
        nodes[i].inventory.reserved_host_cpu_slots = 1;
        nodes[i].inventory.reserved_host_memory_bytes = 1024U * 1024U;
        if (i == 0) {
            nodes[i].inventory.reserved_gateway_cpu_slots = 1;
            nodes[i].inventory.reserved_gateway_memory_bytes = 1024U * 1024U;
            hosted_gateway_ids = calloc(1, sizeof(*hosted_gateway_ids));
            if (!hosted_gateway_ids)
                return fail("allocate gateway host relation", NULL);
            hosted_gateway_ids[0] = 7;
            nodes[i].inventory.hosted_gateway_role_ids = hosted_gateway_ids;
            nodes[i].inventory.hosted_gateway_role_id_count = 1;
            nodes[i].inventory.hosted_gateway_role_id_capacity = 1;
        }
        nodes[i].inventory.allocatable_vcpu_slots =
            8U - nodes[i].inventory.reserved_host_cpu_slots -
            nodes[i].inventory.reserved_gateway_cpu_slots;
        nodes[i].inventory.allocatable_memory_bytes =
            nodes[i].inventory.registered_memory_bytes -
            nodes[i].inventory.reserved_host_memory_bytes -
            nodes[i].inventory.reserved_gateway_memory_bytes;
        memset(nodes[i].inventory.storage_capabilities_digest, 0x31,
               WVM_SHA256_DIGEST_BYTES);
        memset(nodes[i].inventory.accelerator_fault_capabilities_digest, 0x32,
               WVM_SHA256_DIGEST_BYTES);
        memset(nodes[i].inventory.exclusive_resource_inventory_digest, 0x33,
               WVM_SHA256_DIGEST_BYTES);
        nodes[i].desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
        nodes[i].observed_health_state = WVM_MEMBERSHIP_HEALTHY;
        nodes[i].membership_revision = 5;
        nodes[i].topology_revision = 6;
        wvm_node_record_init_single_host_defaults(&nodes[i]);

        fill_capability(&capabilities[cap_index++], node_id, instance,
                        WVM_CAPABILITY_ID_EXECUTION_KVM, provider_base + 1U);
        fill_capability(&capabilities[cap_index++], node_id, instance,
                        WVM_CAPABILITY_ID_EXECUTION_TCG, provider_base + 2U);
        fill_capability(&capabilities[cap_index++], node_id, instance,
                        WVM_CAPABILITY_ID_MODE_B_MEMORY, provider_base + 3U);
        fill_capability(&capabilities[cap_index++], node_id, instance,
                        WVM_CAPABILITY_ID_VM_ID_U32, provider_base + 4U);
        nodes[i].capability.physical_node_id = node_id;
        nodes[i].capability.node_instance_id = instance;
        nodes[i].capability.profile_generation = 9;
        if (wvm_capability_profile_digest(
                node_id, instance, 9, &capabilities[cap_index - 4U], 4,
                profile_digest, error, error_len) != 0) {
            free(nodes[0].inventory.hosted_gateway_role_ids);
            return -1;
        }
        memcpy(nodes[i].capability.profile_digest, profile_digest,
               sizeof(profile_digest));

        members[i].kind = WVM_MEMBERSHIP_COMPUTE;
        members[i].member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        members[i].member_key.role_id = node_id;
        members[i].member_key.instance_id = instance;
        members[i].node = nodes[i];
    }

    gateway.gateway_id = 7;
    gateway.gateway_instance_id = 701;
    gateway.hosting_physical_node_id = 17;
    gateway.failure_domain_id = 1;
    fill_endpoint(&gateway.endpoint, 17, 19500, 19501);
    gateway.role_bits = 1;
    gateway.desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    gateway.observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    gateway.membership_revision = 5;
    gateway.topology_revision = 6;
    members[2].kind = WVM_MEMBERSHIP_GATEWAY;
    members[2].member_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    members[2].member_key.role_id = gateway.gateway_id;
    members[2].member_key.instance_id = gateway.gateway_instance_id;
    members[2].gateway = gateway;

    controller->member_count = 3;

    memset(capture, 0, sizeof(*capture));
    capture->nodes = captured_nodes;
    capture->node_capacity = NODE_COUNT;
    capture->gateways = captured_gateways;
    capture->gateway_capacity = 1;
    capture->hosted_gateway_role_ids = captured_hosted_gateways;
    capture->hosted_gateway_role_id_capacity = 1;

    if (wvm_membership_controller_capture_current_cluster_records(
            controller, capture, capabilities, NODE_COUNT * 4U, NULL, 0, 3,
            9, records, error, error_len) != 0) {
        wvm_membership_controller_close(controller);
        return -1;
    }
    return 0;
}

static int run_case(enum wvm_route_topology_kind topology)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[3];
    struct wvm_capability_record capabilities[NODE_COUNT * 4U];
    struct wvm_membership_controller_capture capture;
    struct wvm_node_record captured_nodes[NODE_COUNT];
    struct wvm_gateway_record captured_gateways[1];
    uint32_t captured_hosted_gateways[1];
    struct wvm_cluster_record_set records;
    struct wvm_cluster_snapshot cluster = {0};
    struct wvm_admission_request request = {0};
    struct wvm_admission_plan admission = {0};
    struct wvm_admission_route_compiler compiler;
    struct wvm_route_rule_record *rules = NULL;
    struct wvm_required_ack_entry acknowledgements[4];
    uint8_t *snapshot_bytes = NULL;
    uint8_t ack_bytes[65536];
    struct wvm_coordinator_transaction transaction = {0};
    struct wvm_coordinator_prepared_route prepared_route = {0};
    struct wvm_route_transaction_record route_transaction = {0};
    struct wvm_route_snapshot_record route_snapshot = {0};
    struct wvm_route_runtime runtime;
    struct wvm_route_runtime_next_hop hop_a, hop_b;
    char error[256] = {0};
    int controller_initialized = 0;
    int runtime_initialized = 0;
    int result = -1;

    if (prepare_controller_records(
            topology, &controller, members, capabilities, &capture,
            captured_nodes, captured_gateways, captured_hosted_gateways,
            &records, error, sizeof(error)) != 0) {
        fail("capture membership records", error);
        return -1;
    }
    controller_initialized = 1;
    if (capture.node_count != NODE_COUNT || capture.gateway_count != 1 ||
        wvm_cluster_snapshot_build(&records, &cluster, error,
                                   sizeof(error)) != 0) {
        fail("build captured admission snapshot", error);
        goto out;
    }

    request.vm_id = 700;
    request.vm_incarnation = 1;
    request.manifest_generation = 1;
    request.backend = WVM_ADMISSION_BACKEND_TCG;
    request.placement_policy = WVM_ADMISSION_PLACEMENT_COMPACT;
    request.requested_vcpu_slots = 2;
    request.requested_memory_bytes = 2U * 1024U * 1024U;
    request.memory_chunk_bytes = 1024U * 1024U;
    request.host_overhead_vcpu_slots = 1;
    request.host_overhead_memory_bytes = 1024U * 1024U;
    transaction.vm_id = request.vm_id;
    transaction.vm_incarnation = request.vm_incarnation;
    transaction.manifest_generation = request.manifest_generation;
    transaction.admission_tx_id[WVM_IDENTITY_ID_BYTES - 1] =
        (uint8_t)topology;
    transaction.route_scope_key.vm_id = request.vm_id;
    transaction.route_scope_key.vm_incarnation = request.vm_incarnation;
    transaction.route_scope_key.route_scope_id = 99;
    {
        uint8_t admission_id[WVM_ADMISSION_ID_BYTES] = {0};
        admission_id[WVM_ADMISSION_ID_BYTES - 1] = (uint8_t)topology;
        if (wvm_admission_plan_propose(&cluster.admission, &request,
                                       admission_id, &admission, error,
                                       sizeof(error)) != 0) {
            fail("admission plan", error);
            goto out;
        }
    }

    rules = calloc(ROUTE_CAPACITY, sizeof(*rules));
    snapshot_bytes = malloc(8U * 1024U * 1024U);
    if (!rules || !snapshot_bytes ||
        wvm_admission_route_compiler_init(
            &compiler, topology, 1, 6000, 1, rules, ROUTE_CAPACITY,
            acknowledgements, 4, snapshot_bytes, 8U * 1024U * 1024U,
            ack_bytes, sizeof(ack_bytes), error, sizeof(error)) != 0 ||
        wvm_admission_route_compile(
            &compiler, &transaction, &records, &prepared_route,
            &route_transaction, &route_snapshot, error, sizeof(error)) != 0) {
        fail("compile captured route snapshot", error);
        goto out;
    }
    if ((topology == WVM_ROUTE_TOPOLOGY_FLAT &&
         route_snapshot.next_hop_rules.count != TOTAL_VNODES) ||
        (topology == WVM_ROUTE_TOPOLOGY_FRACTAL &&
         route_snapshot.next_hop_rules.count != TOTAL_VNODES + 2U)) {
        fail("route count over old flat bound", NULL);
        goto out;
    }

    wvm_route_runtime_init(&runtime);
    runtime_initialized = 1;
    if (wvm_route_runtime_prepare(&runtime, &route_snapshot, error,
                                  sizeof(error)) != 0 ||
        wvm_route_runtime_activate(&runtime,
                                   &route_snapshot.route_snapshot_key, error,
                                   sizeof(error)) != 0) {
        fail("activate captured route snapshot", error);
        goto out;
    }
    if (topology == WVM_ROUTE_TOPOLOGY_FLAT) {
        if (wvm_route_runtime_lookup_destination(
                &runtime, &route_snapshot.route_snapshot_key,
                WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, 4095, &hop_a,
                error, sizeof(error)) != 0 ||
            wvm_route_runtime_lookup_destination(
                &runtime, &route_snapshot.route_snapshot_key,
                WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, 4096, &hop_b,
                error, sizeof(error)) != 0) {
            fail("resolve flat vnodes across 4096", error);
            goto out;
        }
        if (hop_a.next_hop_member.role_type != WVM_MANIFEST_ROLE_GATEWAY ||
            hop_b.next_hop_member.role_type != WVM_MANIFEST_ROLE_GATEWAY ||
            hop_a.next_hop_member.role_id != 7 ||
            hop_b.next_hop_member.role_id != 7) {
            fail("flat boundary routes through the captured gateway", NULL);
            goto out;
        }
    } else if (wvm_route_runtime_lookup_destination(
                   &runtime, &route_snapshot.route_snapshot_key,
                   WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE, 11,
                   NODE_VNODES - 1U, &hop_a, error, sizeof(error)) != 0 ||
               wvm_route_runtime_lookup_destination(
                   &runtime, &route_snapshot.route_snapshot_key,
                   WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE, 12,
                   NODE_VNODES - 1U, &hop_b, error, sizeof(error)) != 0 ||
               hop_a.next_hop_member.role_id != 17 ||
               hop_b.next_hop_member.role_id != 19) {
        fail("resolve overlapping vnode IDs by Pod scope", error);
        goto out;
    }
    result = 0;
    printf("large-topology: %s capture=%zu admission=PASS routes=%zu lookup=PASS\n",
           topology == WVM_ROUTE_TOPOLOGY_FLAT ? "flat" : "fractal",
           capture.node_count, route_snapshot.next_hop_rules.count);

out:
    if (runtime_initialized)
        wvm_route_runtime_destroy(&runtime);
    free(admission.reservations);
    wvm_admission_snapshot_cleanup(&cluster.admission);
    free(rules);
    free(snapshot_bytes);
    if (controller_initialized)
        wvm_membership_controller_close(&controller);
    return result;
}

int main(void)
{
    if (run_case(WVM_ROUTE_TOPOLOGY_FLAT) != 0 ||
        run_case(WVM_ROUTE_TOPOLOGY_FRACTAL) != 0)
        return 1;
    puts("large-topology acceptance: PASS");
    return 0;
}

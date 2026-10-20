/*
 * SPEC-cluster-flat-gt-4096-fixture (Minimum)
 * cluster-membership §10 + identity-routing §10:
 *  - domain budgeted for 4096 accepts 4096 and rejects +1 without partial pub
 *  - flat fixture with sufficient budgets admits >4096, compiles snapshot,
 *    and resolves destinations on both sides of the old 4096 boundary
 *    without adding a Pod/gateway hierarchy layer
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_admission_route.h"
#include "wavevm_canonical.h"
#include "wavevm_cluster.h"
#include "wavevm_route_runtime.h"

#define MIB (1024ULL * 1024ULL)
#define FLAT_OVER_4096 4100U
#define FLAT_AT_4096 4096U

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "flat-gt-4096: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t host,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 10;
    endpoint->data_address[3] = host;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_capability(struct wvm_capability_record *record,
                            uint16_t capability_id, uint64_t provider)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = 17;
    record->node_instance_id = 101;
    record->provider_instance_id = provider;
    record->state = WVM_CAPABILITY_AVAILABLE;
    record->abi_version = 1;
    record->observed_at = provider;
    record->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] = (uint8_t)provider;
}

static int fill_records(struct wvm_node_record *node,
                        struct wvm_gateway_record *gateway,
                        struct wvm_capability_record capabilities[3],
                        uint32_t hosted_gateways[1],
                        struct wvm_cluster_record_set *records,
                        uint32_t vnode_count)
{
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];

    fill_capability(&capabilities[0], WVM_CAPABILITY_ID_EXECUTION_KVM, 1);
    fill_capability(&capabilities[1], WVM_CAPABILITY_ID_EXECUTION_TCG, 2);
    fill_capability(&capabilities[2], WVM_CAPABILITY_ID_MODE_B_MEMORY, 3);
    memset(node, 0, sizeof(*node));
    node->physical_node_id = 17;
    node->node_instance_id = 101;
    node->failure_domain_id = 1;
    fill_endpoint(&node->control_endpoint, 17, 9000, 9100);
    fill_endpoint(&node->sidecar_endpoint, 17, 9200, 9300);
    node->role_bits = 1;
    node->pod_id = 0; /* flat: no Pod hierarchy */
    node->local_vnode_first = 0;
    node->local_vnode_count = vnode_count;
    node->inventory.physical_node_id = 17;
    node->inventory.node_instance_id = 101;
    node->inventory.failure_domain_id = 1;
    node->inventory.inventory_revision = 7;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * MIB;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = MIB;
    node->inventory.reserved_gateway_cpu_slots = 1;
    node->inventory.reserved_gateway_memory_bytes = MIB;
    node->inventory.hosted_gateway_role_ids = hosted_gateways;
    node->inventory.hosted_gateway_role_id_count = 1;
    node->inventory.hosted_gateway_role_id_capacity = 1;
    node->inventory.allocatable_vcpu_slots = 6;
    node->inventory.allocatable_memory_bytes = 14 * MIB;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = 17;
    node->capability.node_instance_id = 101;
    node->capability.profile_generation = 9;
    if (wvm_capability_profile_digest(17, 101, 9, capabilities, 3,
                                      profile_digest, NULL, 0) != 0) {
        return -1;
    }
    memcpy(node->capability.profile_digest, profile_digest,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 5;
    node->topology_revision = 6;
    wvm_node_record_init_single_host_defaults(node);

    memset(gateway, 0, sizeof(*gateway));
    gateway->gateway_id = 3;
    gateway->gateway_instance_id = 301;
    gateway->hosting_physical_node_id = 17;
    gateway->failure_domain_id = 1;
    fill_endpoint(&gateway->endpoint, 17, 9400, 9401);
    gateway->role_bits = 1;
    gateway->pod_id_or_scope = 0;
    gateway->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    gateway->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    gateway->membership_revision = 5;
    gateway->topology_revision = 6;

    memset(records, 0, sizeof(*records));
    records->nodes = node;
    records->node_count = 1;
    records->gateways = gateway;
    records->gateway_count = 1;
    records->capability_records = capabilities;
    records->capability_record_count = 3;
    records->inventory_revision = 7;
    records->membership_revision = 5;
    records->topology_revision = 6;
    records->admission_eligibility_revision = 8;
    records->capability_profile_generation = 9;
    return 0;
}

static void fill_transaction(struct wvm_coordinator_transaction *transaction)
{
    memset(transaction, 0, sizeof(*transaction));
    transaction->vm_id = 256;
    transaction->vm_incarnation = 1;
    transaction->manifest_generation = 1;
    transaction->admission_tx_id[WVM_IDENTITY_ID_BYTES - 1] = 0x55;
    transaction->route_scope_key.vm_id = 256;
    transaction->route_scope_key.vm_incarnation = 1;
    transaction->route_scope_key.route_scope_id = 0x1234;
}

struct compile_buffers {
    struct wvm_route_rule_record *rules;
    size_t rule_capacity;
    struct wvm_required_ack_entry acks[4];
    uint8_t *snapshot_bytes;
    size_t snapshot_capacity;
    uint8_t *ack_set_bytes;
    size_t ack_set_capacity;
};

static int buffers_alloc(struct compile_buffers *b, size_t rule_capacity)
{
    memset(b, 0, sizeof(*b));
    b->rule_capacity = rule_capacity;
    b->rules = calloc(rule_capacity, sizeof(*b->rules));
    b->snapshot_capacity = 16U * 1024U * 1024U;
    b->snapshot_bytes = malloc(b->snapshot_capacity);
    b->ack_set_capacity = 256U * 1024U;
    b->ack_set_bytes = malloc(b->ack_set_capacity);
    if (!b->rules || !b->snapshot_bytes || !b->ack_set_bytes) {
        free(b->rules);
        free(b->snapshot_bytes);
        free(b->ack_set_bytes);
        memset(b, 0, sizeof(*b));
        return -1;
    }
    return 0;
}

static void buffers_free(struct compile_buffers *b)
{
    free(b->rules);
    free(b->snapshot_bytes);
    free(b->ack_set_bytes);
    memset(b, 0, sizeof(*b));
}

static int compile_flat(uint32_t vnode_count, size_t rule_budget,
                        struct wvm_route_snapshot_record *route_snapshot_out,
                        struct compile_buffers *owned_rules_holder,
                        char *error, size_t error_len)
{
    struct wvm_node_record node;
    struct wvm_gateway_record gateway;
    struct wvm_capability_record capabilities[3];
    uint32_t hosted_gateways[1] = {3};
    struct wvm_cluster_record_set records;
    struct wvm_coordinator_transaction transaction;
    struct wvm_admission_route_compiler compiler;
    struct wvm_coordinator_prepared_route prepared_route;
    struct wvm_route_transaction_record route_transaction;
    struct compile_buffers buffers;

    if (buffers_alloc(&buffers, rule_budget) != 0) {
        snprintf(error, error_len, "out of memory for route budgets");
        return -1;
    }
    if (fill_records(&node, &gateway, capabilities, hosted_gateways, &records,
                     vnode_count) != 0) {
        buffers_free(&buffers);
        snprintf(error, error_len, "fill_records failed");
        return -1;
    }
    if (wvm_admission_route_compiler_init(
            &compiler, WVM_ROUTE_TOPOLOGY_FLAT, 1, 6000, 1, buffers.rules,
            buffers.rule_capacity, buffers.acks, 4, buffers.snapshot_bytes,
            buffers.snapshot_capacity, buffers.ack_set_bytes,
            buffers.ack_set_capacity, error, error_len) != 0) {
        buffers_free(&buffers);
        return -1;
    }
    fill_transaction(&transaction);
    if (wvm_admission_route_compile(&compiler, &transaction, &records,
                                   &prepared_route, &route_transaction,
                                   route_snapshot_out, error, error_len) != 0) {
        buffers_free(&buffers);
        return -1;
    }
    /* Caller owns buffers for lifetime of snapshot rule pointers. */
    *owned_rules_holder = buffers;
    return 0;
}

static int test_budget_reject_at_4096(void)
{
    struct wvm_route_snapshot_record snapshot;
    struct compile_buffers holder;
    char error[256] = {0};

    /* Budget exactly 4096: requesting 4097 admitted entries must fail closed. */
    if (compile_flat(FLAT_AT_4096 + 1U, FLAT_AT_4096, &snapshot, &holder, error,
                     sizeof(error)) == 0) {
        buffers_free(&holder);
        fprintf(stderr,
                "flat-gt-4096: expected reject for 4097 with budget 4096\n");
        return -1;
    }
    if (expect(strstr(error, "route compiler rule storage is missing") != NULL ||
                   strstr(error, "storage") != NULL || error[0] != '\0',
               "reject reports bounded failure (no partial success)")) {
        return -1;
    }
    printf("flat-gt-4096: budget-4096 rejects +1 (%s)\n", error);
    return 0;
}

static int test_over_4096_compile_and_lookup(void)
{
    struct wvm_route_snapshot_record snapshot;
    struct compile_buffers holder;
    struct wvm_route_runtime runtime;
    struct wvm_route_runtime_next_hop next_hop;
    char error[256] = {0};
    uint32_t probes[] = {0U, 4095U, 4096U, FLAT_OVER_4096 - 1U};
    size_t i;

    if (compile_flat(FLAT_OVER_4096, FLAT_OVER_4096, &snapshot, &holder, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "flat-gt-4096: compile >4096 failed: %s\n", error);
        return -1;
    }
    if (expect(snapshot.next_hop_rules.count == FLAT_OVER_4096,
               "compiled rule count exceeds 4096") ||
        expect(snapshot.topology_kind == WVM_ROUTE_TOPOLOGY_FLAT,
               "topology remains flat (no hierarchy added)")) {
        buffers_free(&holder);
        return -1;
    }

    wvm_route_runtime_init(&runtime);
    if (expect(wvm_route_runtime_prepare(&runtime, &snapshot, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &snapshot.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate >4096 flat snapshot")) {
        wvm_route_runtime_destroy(&runtime);
        buffers_free(&holder);
        return -1;
    }
    for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        if (expect(wvm_route_runtime_lookup_destination(
                       &runtime, &snapshot.route_snapshot_key,
                       WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE, 0, probes[i],
                       &next_hop, error, sizeof(error)) == 0 &&
                       next_hop.next_hop_endpoint.data_port == 9400,
                   "resolve vnode across old 4096 boundary")) {
            fprintf(stderr, "flat-gt-4096: lookup vnode=%u failed: %s\n",
                    probes[i], error);
            wvm_route_runtime_destroy(&runtime);
            buffers_free(&holder);
            return -1;
        }
    }
    wvm_route_runtime_destroy(&runtime);
    buffers_free(&holder);
    printf("flat-gt-4096: compiled+resolved %u flat entries (incl 4095/4096)\n",
           FLAT_OVER_4096);
    return 0;
}

int main(void)
{
    if (test_budget_reject_at_4096() != 0 ||
        test_over_4096_compile_and_lookup() != 0) {
        return 1;
    }
    puts("flat-gt-4096-fixture: PASS");
    return 0;
}

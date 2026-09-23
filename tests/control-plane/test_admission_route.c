#include <stdio.h>
#include <string.h>

#include "wavevm_admission_route.h"
#include "wavevm_admission_transport.h"
#include "wavevm_canonical.h"
#include "wavevm_cluster.h"

#define MIB (1024ULL * 1024ULL)

struct transport_capture {
    unsigned call_count;
    uint16_t message_types[3];
    uint8_t operation_ids[3][WVM_IDENTITY_ID_BYTES];
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "admission-route test: %s\n", message);
        return -1;
    }
    return 0;
}

static int resolve_node(void *opaque, uint32_t node_id, uint64_t instance_id,
                        struct wvm_admission_transport_target *target,
                        char *error, size_t error_len)
{
    (void)opaque;
    (void)node_id;
    (void)instance_id;
    (void)target;
    (void)error;
    (void)error_len;
    return -1;
}

static int submit_route_stage(
    void *opaque, const struct wvm_admission_transport_target *target,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    struct transport_capture *capture = opaque;
    struct wvm_envelope decoded;
    uint8_t frame[65536];
    size_t frame_bytes = 0;

    if (!capture || !target || !envelope || capture->call_count >= 3 ||
        target->member_key.role_type != WVM_MANIFEST_ROLE_GATEWAY ||
        wvm_envelope_encode(envelope, WVM_ENVELOPE_TRANSPORT_LOCAL, frame,
                            sizeof(frame), &frame_bytes, error, error_len) !=
            0 ||
        wvm_envelope_decode(frame, frame_bytes, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            &decoded, error, error_len) != 0 ||
        decoded.message_type != envelope->message_type ||
        decoded.vm_id != envelope->vm_id ||
        decoded.route_scope_id != envelope->route_scope_id ||
        memcmp(decoded.semantic_payload_digest, envelope->semantic_payload_digest,
               sizeof(decoded.semantic_payload_digest)) != 0) {
        return -1;
    }
    capture->message_types[capture->call_count] = envelope->message_type;
    memcpy(capture->operation_ids[capture->call_count], envelope->operation_id,
           sizeof(envelope->operation_id));
    capture->call_count++;
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
                        struct wvm_cluster_record_set *records)
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
    node->pod_id = 7;
    node->local_vnode_first = 0;
    node->local_vnode_count = 16;
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

    memset(gateway, 0, sizeof(*gateway));
    gateway->gateway_id = 3;
    gateway->gateway_instance_id = 301;
    gateway->hosting_physical_node_id = 17;
    gateway->failure_domain_id = 1;
    fill_endpoint(&gateway->endpoint, 17, 9400, 9401);
    gateway->role_bits = 1;
    gateway->pod_id_or_scope = 7;
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

int main(void)
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
    struct wvm_route_snapshot_record route_snapshot;
    struct wvm_route_rule_record route_rules[16];
    struct wvm_required_ack_entry ack_entries[1];
    uint8_t snapshot_bytes[65536];
    uint8_t ack_set_bytes[4096];
    struct wvm_admission_transport transport;
    struct wvm_admission_orchestrator_callbacks callbacks;
    struct transport_capture capture;
    char error[256] = {0};

    if (expect(fill_records(&node, &gateway, capabilities, hosted_gateways,
                            &records) == 0,
               "build canonical route inputs") ||
        expect(wvm_admission_route_compiler_init(
                   &compiler, WVM_ROUTE_TOPOLOGY_FLAT, 1, 6000, 1, route_rules,
                   16, ack_entries, 1, snapshot_bytes, sizeof(snapshot_bytes),
                   ack_set_bytes, sizeof(ack_set_bytes), error,
                   sizeof(error)) == 0,
               "initialize flat route compiler")) {
        return 1;
    }
    fill_transaction(&transaction);
    if (wvm_admission_route_compile(
            &compiler, &transaction, &records, &prepared_route,
            &route_transaction, &route_snapshot, error, sizeof(error)) != 0) {
        fprintf(stderr, "admission-route test: compile flat route snapshot: %s\n",
                error);
        return 1;
    }
    if (expect(1, "compile flat route snapshot") ||
        expect(compiler.route_rule_count == 16 &&
                   route_snapshot.topology_kind == WVM_ROUTE_TOPOLOGY_FLAT,
               "compile every active flat vnode") ||
        expect(wvm_route_snapshot_record_validate(&route_snapshot, error,
                                                  sizeof(error)) == 0 &&
                   wvm_route_transaction_record_validate(&route_transaction,
                                                         error,
                                                         sizeof(error)) == 0,
               "validate compiled flat records") ||
        expect(wvm_route_snapshot_record_binds_transaction(
                   &route_snapshot, &route_transaction, error,
                   sizeof(error)) == 0,
               "bind compiled route transaction")) {
        return 1;
    }

    memset(&capture, 0, sizeof(capture));
    if (expect(wvm_admission_transport_init(
                   &transport, 17, 500, &capture, resolve_node,
                   submit_route_stage, error, sizeof(error)) ==
                   0,
               "initialize route control transport") ||
        expect(wvm_admission_transport_callbacks(
                   &transport, &callbacks, error, sizeof(error)) == 0 &&
                   callbacks.route_plan == NULL,
               "build stage transport callbacks")) {
        return 1;
    }
    if (callbacks.route_prepare(&transport, &transaction, &route_transaction,
                                &route_snapshot, error, sizeof(error)) != 0) {
        fprintf(stderr, "admission-route test: route prepare: %s\n", error);
        return 1;
    }
    if (callbacks.route_commit(&transport, &transaction, &route_transaction,
                               &route_snapshot, error, sizeof(error)) != 0) {
        fprintf(stderr, "admission-route test: route commit: %s\n", error);
        return 1;
    }
    if (callbacks.route_abort(&transport, &transaction, &route_transaction,
                              &route_snapshot, error, sizeof(error)) != 0) {
        fprintf(stderr, "admission-route test: route abort: %s\n", error);
        return 1;
    }
    if (expect(capture.call_count == 3 &&
                   capture.message_types[0] == WVM_ENVELOPE_MSG_ROUTE_PREPARE &&
                   capture.message_types[1] == WVM_ENVELOPE_MSG_ROUTE_COMMIT &&
                   capture.message_types[2] == WVM_ENVELOPE_MSG_ROUTE_ABORT &&
                   memcmp(capture.operation_ids[0], capture.operation_ids[1],
                          WVM_IDENTITY_ID_BYTES) != 0 &&
                   memcmp(capture.operation_ids[1], capture.operation_ids[2],
                          WVM_IDENTITY_ID_BYTES) != 0,
               "use distinct idempotent operation IDs for route stages")) {
        return 1;
    }

    if (expect(wvm_admission_route_compiler_init(
                   &compiler, WVM_ROUTE_TOPOLOGY_FRACTAL, 1, 6000, 1,
                   route_rules, 16, ack_entries, 1, snapshot_bytes,
                   sizeof(snapshot_bytes), ack_set_bytes, sizeof(ack_set_bytes),
                   error, sizeof(error)) == 0,
               "initialize fractal route compiler") ||
        expect(wvm_admission_route_compile(
                   &compiler, &transaction, &records, &prepared_route,
                   &route_transaction, &route_snapshot, error,
                   sizeof(error)) == 0,
               "compile fractal route snapshot") ||
        expect(compiler.route_rule_count == 1 &&
                   route_snapshot.next_hop_rules.entries[0].destination_scope ==
                       7,
               "compile one prefix per active pod") ||
        expect(wvm_route_snapshot_record_validate(&route_snapshot, error,
                                                  sizeof(error)) == 0,
               "validate compiled fractal records")) {
        return 1;
    }

    gateway.observed_health_state = WVM_MEMBERSHIP_UNREACHABLE;
    if (expect(wvm_admission_route_compile(
                   &compiler, &transaction, &records, &prepared_route,
                   &route_transaction, &route_snapshot, error,
                   sizeof(error)) != 0,
               "reject route compilation without healthy gateway")) {
        return 1;
    }
    puts("admission-route tests: PASS");
    return 0;
}

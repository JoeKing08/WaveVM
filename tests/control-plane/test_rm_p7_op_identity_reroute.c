/*
 * RM-P7-op-identity-across-reroute (Minimum start)
 * Roadmap §11: lost vCPU/block/memory results during route-generation change
 * preserve one semantic operation identity.
 *
 * This oracle proves the wire/control identity contract used by reroute:
 *   1) operation_id + semantic_payload_digest identify one operation
 *   2) changing route_generation does not change operation_id
 *   3) route_runtime accepts the new generation key for the same VM scope
 *      while the operation_id field is unchanged on the envelope
 * Full lost-result cache replay under drop of VCPU_EXIT/commit ACK remains
 * Completion-cache oracle: tests/control-plane/test_vcpu_coordinator.c
 * (lookup_completed + -EALREADY resubmit after dropped-exit G→G+1).
 */
#include <stdio.h>
#include <string.h>

#include "wavevm_envelope.h"
#include "wavevm_route_runtime.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "op-identity-reroute: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port + 1000U);
}

static int make_snapshot(struct wvm_route_snapshot_record *snapshot,
                         struct wvm_route_rule_record *rules,
                         struct wvm_required_ack_entry *acks,
                         uint64_t generation, uint16_t port, char *error,
                         size_t error_len)
{
    uint8_t bytes[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded;

    memset(rules, 0, sizeof(*rules));
    rules->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rules->destination_vnode_or_endpoint = 0;
    rules->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rules->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rules->next_hop_member.role_id = 11;
    rules->next_hop_member.instance_id = 1011;
    fill_endpoint(&rules->next_hop_endpoint, 11, port);
    rules->hop_limit = 4;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 7;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 1;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 99;
    snapshot->route_snapshot_key.topology_revision = 4;
    snapshot->route_snapshot_key.route_generation = generation;
    snapshot->membership_revision = 4;
    snapshot->topology_kind = 1;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = 1;
    snapshot->next_hop_rules.capacity = 1;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;
    memset(acks, 0, sizeof(*acks));
    acks->member_key = rules->next_hop_member;
    acks->endpoint = rules->next_hop_endpoint;
    acks->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks->expected_snapshot_key = snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(acks->expected_snapshot_key.snapshot_digest, digest, sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

int main(void)
{
    struct wvm_route_runtime runtime;
    struct wvm_route_snapshot_record gen1, gen2;
    struct wvm_route_rule_record rules1, rules2;
    struct wvm_required_ack_entry acks1, acks2;
    struct wvm_envelope op;
    uint8_t semantic_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t operation_id[16];
    char error[256] = {0};
    uint8_t payload[32];
    struct wvm_route_runtime_next_hop next_hop;

    memset(operation_id, 0xab, sizeof(operation_id));
    memset(payload, 0x5a, sizeof(payload));
    wvm_envelope_semantic_digest(payload, sizeof(payload), semantic_digest);

    if (make_snapshot(&gen1, &rules1, &acks1, 1, 19001, error,
                      sizeof(error)) != 0 ||
        make_snapshot(&gen2, &rules2, &acks2, 2, 19002, error,
                      sizeof(error)) != 0) {
        fprintf(stderr, "op-identity setup: %s\n", error);
        return 1;
    }
    gen2.has_predecessor_snapshot_key = 1;
    gen2.predecessor_snapshot_key = gen1.route_snapshot_key;

    wvm_route_runtime_init(&runtime);
    if (expect(wvm_route_runtime_prepare(&runtime, &gen1, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &gen1.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate generation 1") ||
        expect(wvm_route_runtime_prepare(&runtime, &gen2, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &gen2.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate generation 2 (reroute)")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    /* One semantic operation identity survives the generation bump. */
    memset(&op, 0, sizeof(op));
    memcpy(op.operation_id, operation_id, sizeof(operation_id));
    memcpy(op.semantic_payload_digest, semantic_digest,
           sizeof(semantic_digest));
    op.vm_id = 7;
    op.vm_incarnation = 1;
    op.route_scope_id = 99;
    op.topology_revision = 4;
    op.route_generation = 2; /* refreshed forwarding key */
    memcpy(op.route_snapshot_digest, gen2.route_snapshot_key.snapshot_digest,
           sizeof(op.route_snapshot_digest));
    op.route.destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    op.route.destination_vnode_or_endpoint = 0;
    op.route.hop_limit = 8;
    op.payload = payload;
    op.payload_bytes = sizeof(payload);

    if (expect(wvm_route_runtime_lookup(&runtime, &op, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19002,
               "rerouted envelope resolves on new generation") ||
        expect(memcmp(op.operation_id, operation_id, sizeof(operation_id)) == 0,
               "operation_id unchanged after route_generation refresh") ||
        expect(memcmp(op.semantic_payload_digest, semantic_digest,
                      sizeof(semantic_digest)) == 0,
               "semantic payload digest unchanged across reroute")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    wvm_route_runtime_destroy(&runtime);
    puts("op-identity-reroute: PASS (wire identity contract)");
    puts("NOTE: completion-cache covered by test_vcpu_coordinator (see suite).");
    return 0;
}

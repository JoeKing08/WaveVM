/*
 * SPEC-cluster-min-vm-a-b-shared-gateway
 * cluster-membership §10 / runtime-manifest §10 / identity-routing §10:
 * VM A route-scope retirement while VM B shares a gateway leaves B's
 * current and predecessor snapshots intact (including overlapping raw
 * vnode IDs).
 */
#include <stdio.h>
#include <string.h>

#include "wavevm_route_runtime.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "shared-gateway-retire: %s\n", message);
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

static void fill_gateway_rule(struct wvm_route_rule_record *rule, uint32_t vnode,
                              uint8_t gw_tail, uint16_t gw_port)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    rule->next_hop_member.role_id = 901;
    rule->next_hop_member.instance_id = 902;
    fill_endpoint(&rule->next_hop_endpoint, gw_tail, gw_port);
    rule->hop_limit = 2;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rules,
                             size_t rule_count,
                             struct wvm_required_ack_entry *acks,
                             size_t ack_count, uint32_t vm_id,
                             uint64_t incarnation, uint64_t route_scope_id,
                             uint64_t topology_revision,
                             uint64_t route_generation, char *error,
                             size_t error_len)
{
    uint8_t bytes[16384];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    size_t i;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = vm_id;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = incarnation;
    snapshot->route_snapshot_key.scope_key.route_scope_id = route_scope_id;
    snapshot->route_snapshot_key.topology_revision = topology_revision;
    snapshot->route_snapshot_key.route_generation = route_generation;
    snapshot->membership_revision = topology_revision;
    snapshot->topology_kind = 1;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = rule_count;
    snapshot->next_hop_rules.capacity = rule_count;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = ack_count;
    snapshot->required_ack_set.entries.capacity = ack_count;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    for (i = 0; i < ack_count; i++) {
        memset(&acks[i], 0, sizeof(acks[i]));
        acks[i].member_key = rules[0].next_hop_member;
        acks[i].endpoint = rules[0].next_hop_endpoint;
        acks[i].role_type = WVM_MANIFEST_ROLE_GATEWAY;
        acks[i].expected_snapshot_key = snapshot->route_snapshot_key;
    }
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    for (i = 0; i < ack_count; i++) {
        memcpy(acks[i].expected_snapshot_key.snapshot_digest, digest,
               sizeof(digest));
    }
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static void envelope_for(struct wvm_envelope *envelope,
                         const struct wvm_route_snapshot_key *key,
                         uint32_t vnode)
{
    memset(envelope, 0, sizeof(*envelope));
    envelope->vm_id = key->scope_key.vm_id;
    envelope->vm_incarnation = key->scope_key.vm_incarnation;
    envelope->route_scope_id = key->scope_key.route_scope_id;
    envelope->topology_revision = key->topology_revision;
    envelope->route_generation = key->route_generation;
    memcpy(envelope->route_snapshot_digest, key->snapshot_digest,
           sizeof(envelope->route_snapshot_digest));
    envelope->route.destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    envelope->route.destination_vnode_or_endpoint = vnode;
    envelope->route.hop_limit = 8;
}

int main(void)
{
    struct wvm_route_runtime runtime;
    struct wvm_route_snapshot_record snap_a_gen1;
    struct wvm_route_snapshot_record snap_a_gen2;
    struct wvm_route_snapshot_record snap_b_gen1;
    struct wvm_route_snapshot_record snap_b_gen2;
    struct wvm_route_rule_record rules_a1[1];
    struct wvm_route_rule_record rules_a2[1];
    struct wvm_route_rule_record rules_b1[1];
    struct wvm_route_rule_record rules_b2[1];
    struct wvm_required_ack_entry acks_a1[1];
    struct wvm_required_ack_entry acks_a2[1];
    struct wvm_required_ack_entry acks_b1[1];
    struct wvm_required_ack_entry acks_b2[1];
    struct wvm_envelope env_a;
    struct wvm_envelope env_b;
    struct wvm_route_runtime_next_hop next_hop;
    struct wvm_route_snapshot_key key_out;
    char error[256] = {0};
    /* Shared gateway endpoint (same role_id/instance/port). Overlapping raw
     * vnode 0 for both VMs — namespace must keep them distinct. */
    const uint16_t shared_gw_port = 19401;
    const uint8_t shared_gw_tail = 50;

    fill_gateway_rule(&rules_a1[0], 0, shared_gw_tail, shared_gw_port);
    fill_gateway_rule(&rules_a2[0], 0, shared_gw_tail, shared_gw_port);
    fill_gateway_rule(&rules_b1[0], 0, shared_gw_tail, shared_gw_port);
    fill_gateway_rule(&rules_b2[0], 0, shared_gw_tail, shared_gw_port);

    if (finalize_snapshot(&snap_a_gen1, rules_a1, 1, acks_a1, 1, 11, 1, 100, 4,
                          1, error, sizeof(error)) != 0 ||
        finalize_snapshot(&snap_a_gen2, rules_a2, 1, acks_a2, 1, 11, 1, 100, 4,
                          2, error, sizeof(error)) != 0 ||
        finalize_snapshot(&snap_b_gen1, rules_b1, 1, acks_b1, 1, 22, 1, 200, 4,
                          1, error, sizeof(error)) != 0 ||
        finalize_snapshot(&snap_b_gen2, rules_b2, 1, acks_b2, 1, 22, 1, 200, 4,
                          2, error, sizeof(error)) != 0) {
        fprintf(stderr, "shared-gateway-retire setup: %s\n", error);
        return 1;
    }
    snap_a_gen2.has_predecessor_snapshot_key = 1;
    snap_a_gen2.predecessor_snapshot_key = snap_a_gen1.route_snapshot_key;
    snap_b_gen2.has_predecessor_snapshot_key = 1;
    snap_b_gen2.predecessor_snapshot_key = snap_b_gen1.route_snapshot_key;

    wvm_route_runtime_init(&runtime);

    /* Activate A gen1, B gen1, then advance both to gen2 so each has a
     * predecessor retained on the shared gateway consumer. */
    if (expect(wvm_route_runtime_prepare(&runtime, &snap_a_gen1, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &snap_a_gen1.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate VM A gen1") ||
        expect(wvm_route_runtime_prepare(&runtime, &snap_b_gen1, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &snap_b_gen1.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate VM B gen1") ||
        expect(wvm_route_runtime_prepare(&runtime, &snap_a_gen2, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &snap_a_gen2.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate VM A gen2") ||
        expect(wvm_route_runtime_prepare(&runtime, &snap_b_gen2, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &snap_b_gen2.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate VM B gen2")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    envelope_for(&env_b, &snap_b_gen2.route_snapshot_key, 0);
    if (expect(wvm_route_runtime_lookup(&runtime, &env_b, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == shared_gw_port,
               "VM B resolves via shared gateway before A retire") ||
        expect(wvm_route_runtime_predecessor_key(
                   &runtime, &snap_b_gen2.route_snapshot_key.scope_key,
                   &key_out) == 0 &&
                   memcmp(&key_out, &snap_b_gen1.route_snapshot_key,
                          sizeof(key_out)) == 0,
               "VM B predecessor retained before A retire")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    /* Retire predecessor before active (runtime fail-closed otherwise). */
    if (expect(wvm_route_runtime_retire(&runtime, &snap_a_gen1.route_snapshot_key,
                                        error, sizeof(error)) == 0,
               "retire VM A predecessor snapshot") ||
        expect(wvm_route_runtime_retire(&runtime, &snap_a_gen2.route_snapshot_key,
                                        error, sizeof(error)) == 0,
               "retire VM A current snapshot")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    envelope_for(&env_a, &snap_a_gen2.route_snapshot_key, 0);
    if (expect(wvm_route_runtime_lookup(&runtime, &env_a, &next_hop, error,
                                        sizeof(error)) != 0,
               "VM A current rejected after retirement") ||
        expect(!wvm_route_runtime_has_snapshot(&runtime,
                                               &snap_a_gen2.route_snapshot_key) &&
                   !wvm_route_runtime_has_snapshot(
                       &runtime, &snap_a_gen1.route_snapshot_key),
               "VM A snapshots gone") ||
        expect(wvm_route_runtime_lookup(&runtime, &env_b, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == shared_gw_port,
               "VM B current intact after A retirement") ||
        expect(wvm_route_runtime_current_key(
                   &runtime, &snap_b_gen2.route_snapshot_key.scope_key,
                   &key_out) == 0 &&
                   memcmp(&key_out, &snap_b_gen2.route_snapshot_key,
                          sizeof(key_out)) == 0,
               "VM B current key unchanged") ||
        expect(wvm_route_runtime_predecessor_key(
                   &runtime, &snap_b_gen2.route_snapshot_key.scope_key,
                   &key_out) == 0 &&
                   memcmp(&key_out, &snap_b_gen1.route_snapshot_key,
                          sizeof(key_out)) == 0,
               "VM B predecessor unchanged after A retirement") ||
        expect(wvm_route_runtime_has_snapshot(&runtime,
                                              &snap_b_gen1.route_snapshot_key) &&
                   wvm_route_runtime_has_snapshot(
                       &runtime, &snap_b_gen2.route_snapshot_key),
               "VM B current+predecessor snapshots still present")) {
        wvm_route_runtime_destroy(&runtime);
        return 1;
    }

    wvm_route_runtime_destroy(&runtime);
    puts("shared-gateway-retire: PASS");
    puts("NOTE: overlapping raw vnode 0; shared gateway 901:902.");
    return 0;
}

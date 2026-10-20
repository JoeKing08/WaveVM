/*
 * RM-P8-mode-a-same-semantics-as-b (focused Minimum oracle)
 * Roadmap §12: Mode A passes the same semantic tests as Mode B; only
 * capability/performance differ. NOT goal §6 matrix.
 */
#include <stdio.h>
#include <string.h>

#include "wavevm_identity.h"
#include "wavevm_manifest.h"
#include "wavevm_reservation_runtime.h"
#include "wavevm_route_runtime.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "mode-ab-shared-semantics: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_id(uint8_t id[WVM_IDENTITY_ID_BYTES], uint8_t value)
{
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = value;
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

static void fill_rule(struct wvm_route_rule_record *rule, uint32_t vnode,
                      uint8_t tail, uint16_t port)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = tail;
    rule->next_hop_member.instance_id = 1000U + tail;
    fill_endpoint(&rule->next_hop_endpoint, tail, port);
    rule->hop_limit = 4;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rules,
                             struct wvm_required_ack_entry *acks,
                             uint32_t vm_id, uint64_t incarnation,
                             uint16_t port, char *error, size_t error_len)
{
    uint8_t bytes[16384];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    fill_rule(&rules[0], 0, (uint8_t)(vm_id & 0xff), port);
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = vm_id;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = incarnation;
    snapshot->route_snapshot_key.scope_key.route_scope_id = vm_id * 10U;
    snapshot->route_snapshot_key.topology_revision = 4;
    snapshot->route_snapshot_key.route_generation = 1;
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
    memset(&acks[0], 0, sizeof(acks[0]));
    acks[0].member_key = rules[0].next_hop_member;
    acks[0].endpoint = rules[0].next_hop_endpoint;
    acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks[0].expected_snapshot_key = snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(acks[0].expected_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int prepare_one(struct wvm_local_reservation_registry *registry,
                       struct wvm_resource_reservation *res,
                       struct wvm_exclusive_lease *leases, uint8_t id,
                       uint32_t vm_id, int mode_a)
{
    enum wvm_reservation_runtime_result result;
    char error[128];
    size_t n = 0;

    memset(res, 0, sizeof(*res));
    memset(leases, 0, sizeof(*leases) * 3);
    fill_id(res->reservation_id, id);
    fill_id(res->plan_digest, (uint8_t)(id + 1));
    fill_id(res->candidate_manifest_digest, (uint8_t)(id + 2));
    fill_id(res->admission_tx_id, (uint8_t)(id + 3));
    fill_id(res->eligibility_fence_digest, (uint8_t)(id + 4));
    res->vm_id = vm_id;
    res->vm_incarnation = 1;
    res->physical_node_id = 17;
    res->node_instance_id = 9;
    res->inventory_revision = 4;
    res->guest_vcpu_slots = 1;
    res->guest_memory_bytes = 4096;
    res->overhead_memory_bytes = 0;
    res->state = WVM_RESERVATION_PREPARED;
    res->has_prepared_expiry = 1;
    res->prepared_expiry_unix_time_ms = 1000;

    leases[n].lease_kind = WVM_EXCLUSIVE_LEASE_KIND_NODE_RUNTIME_DATA_UDP;
    leases[n].lease_generation = 1;
    snprintf(leases[n].lease_name, sizeof(leases[n].lease_name),
             "udp:any:node-runtime-data:%u", (unsigned)(17000 + vm_id));
    n++;
    leases[n].lease_kind = WVM_EXCLUSIVE_LEASE_KIND_LOCAL_EXECUTOR_SERVICE_UDP;
    leases[n].lease_generation = 1;
    snprintf(leases[n].lease_name, sizeof(leases[n].lease_name),
             "udp:loopback:local-executor-service:%u",
             (unsigned)(18000 + vm_id));
    n++;
    if (mode_a) {
        leases[n].lease_kind = WVM_EXCLUSIVE_LEASE_KIND_KERNEL_CONTEXT;
        leases[n].lease_generation = 1;
        /* Fixed gate name: second Mode A on same node must collide. */
        snprintf(leases[n].lease_name, sizeof(leases[n].lease_name),
                 "kernel-context");
        n++;
    }
    res->exclusive_leases.entries = leases;
    res->exclusive_leases.count = n;
    res->exclusive_leases.capacity = n;
    return wvm_local_reservation_prepare(registry, res, &result, error,
                                         sizeof(error)) == 0 &&
           result == WVM_RESERVATION_RUNTIME_NEW;
}

static int test_capacity_semantics(void)
{
    struct wvm_admission_node node;
    struct wvm_resource_reservation stored[8];
    struct wvm_local_reservation_registry registry;
    struct wvm_resource_reservation r_b1, r_b2, r_a1, r_a2;
    struct wvm_exclusive_lease leases_b1[3], leases_b2[3];
    struct wvm_exclusive_lease leases_a1[3], leases_a2[3];
    enum wvm_reservation_runtime_result result;
    char error[128];

    memset(&node, 0, sizeof(node));
    node.physical_node_id = 17;
    node.node_instance_id = 9;
    node.inventory_revision = 4;
    node.allocatable_vcpu_slots = 8;
    node.allocatable_memory_bytes = 65536;
    if (wvm_local_reservation_registry_init(&registry, &node, stored, 8, error,
                                            sizeof(error)) != 0) {
        return -1;
    }
    if (expect(prepare_one(&registry, &r_b1, leases_b1, 1, 101, 0),
               "Mode B VM1 prepare") ||
        expect(prepare_one(&registry, &r_b2, leases_b2, 2, 102, 0),
               "Mode B VM2 prepare") ||
        expect(registry.prepared_vcpu_slots == 2,
               "Mode B accounts guest vCPU identically")) {
        wvm_local_reservation_registry_destroy(&registry);
        return -1;
    }
    wvm_local_reservation_abort(&registry, &r_b1, &result, error, sizeof(error));
    wvm_local_reservation_abort(&registry, &r_b2, &result, error, sizeof(error));
    if (expect(prepare_one(&registry, &r_a1, leases_a1, 3, 201, 1),
               "Mode A VM1 prepare") ||
        expect(!prepare_one(&registry, &r_a2, leases_a2, 4, 202, 1),
               "Mode A VM2 rejected on fixed kernel-context lease") ||
        expect(registry.prepared_vcpu_slots == 1,
               "Mode A accounts only the admitted VM's guest vCPU")) {
        wvm_local_reservation_registry_destroy(&registry);
        return -1;
    }
    wvm_local_reservation_registry_destroy(&registry);
    return 0;
}

static int test_route_namespace_semantics(void)
{
    struct wvm_route_runtime runtime;
    struct wvm_route_snapshot_record snap_a, snap_b;
    struct wvm_route_rule_record rules_a[1], rules_b[1];
    struct wvm_required_ack_entry acks_a[1], acks_b[1];
    struct wvm_envelope env;
    struct wvm_route_runtime_next_hop next_hop;
    char error[256];

    if (finalize_snapshot(&snap_a, rules_a, acks_a, 11, 1, 19111, error,
                          sizeof(error)) != 0 ||
        finalize_snapshot(&snap_b, rules_b, acks_b, 22, 1, 19222, error,
                          sizeof(error)) != 0) {
        fprintf(stderr, "mode-ab route setup: %s\n", error);
        return -1;
    }
    wvm_route_runtime_init(&runtime);
    if (expect(wvm_route_runtime_prepare(&runtime, &snap_a, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &snap_a.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate scope A") ||
        expect(wvm_route_runtime_prepare(&runtime, &snap_b, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime, &snap_b.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate scope B")) {
        wvm_route_runtime_destroy(&runtime);
        return -1;
    }
    memset(&env, 0, sizeof(env));
    env.vm_id = 11;
    env.vm_incarnation = 1;
    env.route_scope_id = snap_a.route_snapshot_key.scope_key.route_scope_id;
    env.topology_revision = 4;
    env.route_generation = 1;
    memcpy(env.route_snapshot_digest,
           snap_a.route_snapshot_key.snapshot_digest,
           sizeof(env.route_snapshot_digest));
    env.route.destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    env.route.destination_vnode_or_endpoint = 0;
    env.route.hop_limit = 8;
    if (expect(wvm_route_runtime_lookup(&runtime, &env, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19111,
               "raw vnode 0 resolves in VM 11 namespace")) {
        wvm_route_runtime_destroy(&runtime);
        return -1;
    }
    env.vm_id = 22;
    env.route_scope_id = snap_b.route_snapshot_key.scope_key.route_scope_id;
    memcpy(env.route_snapshot_digest, snap_b.route_snapshot_key.snapshot_digest,
           sizeof(env.route_snapshot_digest));
    if (expect(wvm_route_runtime_lookup(&runtime, &env, &next_hop, error,
                                        sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19222,
               "same raw vnode 0 resolves distinctly in VM 22")) {
        wvm_route_runtime_destroy(&runtime);
        return -1;
    }
    wvm_route_runtime_destroy(&runtime);
    return 0;
}

static int test_identity_semantics(void)
{
    struct wvm_vm_namespace_allocator allocator;
    struct wvm_vm_namespace_record records[8];
    uint32_t vm_a = 0, vm_b = 0;
    uint64_t inc_a = 0, inc_b = 0;
    char error[128];

    wvm_vm_namespace_allocator_init(&allocator, records, 8, 1);
    if (expect(wvm_vm_namespace_allocate(&allocator, WVM_NAMESPACE_ABI_U32, &vm_a,
                                         &inc_a, error, sizeof(error)) == 0,
               "allocate Mode A namespace") ||
        expect(wvm_vm_namespace_allocate(&allocator, WVM_NAMESPACE_ABI_U32, &vm_b,
                                         &inc_b, error, sizeof(error)) == 0,
               "allocate Mode B namespace") ||
        expect(vm_a != vm_b, "distinct vm_id for Mode A vs Mode B scopes") ||
        expect(inc_a == 1 && inc_b == 1,
               "incarnation starts at 1 for both modes")) {
        return -1;
    }
    return 0;
}

int main(void)
{
    if (test_capacity_semantics() != 0 || test_route_namespace_semantics() != 0 ||
        test_identity_semantics() != 0) {
        return 1;
    }
    puts("mode-ab-shared-semantics: PASS");
    puts("NOTE: CP shared-oracle only (capacity/route/identity).");
    puts("NOTE: memory semantic equivalence (page version/commit/dirty/resync/fence)");
    puts("NOTE: requires guest-visible paths — GUEST-BLOCKED, not claimed COMPLETE.");
    return 0;
}

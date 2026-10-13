#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_control.h"
#include "wavevm_manifest.h"
#include "wavevm_membership_controller.h"
#include "wavevm_sha256.h"

/*
 * Offline durable predecessor route + dependency for gateway 换血 fixtures.
 * Spec §5.4: PREPARE requires exactly one registered dependency for the VM
 * incarnation and an activated predecessor snapshot. CREATE_VM does not yet
 * call dependency_acquire; this seeds the same controller facts the production
 * path would record. ctl must be stopped (exclusive journal lock).
 *
 * usage: seed_gateway_drain_route JOURNAL \\
 *          DEPART_GW_ID DEPART_INST SUCC_GW_ID SUCC_INST \\
 *          NODE_ID NODE_INST VM_ID
 */

static int build_ack_set(struct wvm_required_ack_set *ack_set,
                         struct wvm_required_ack_entry entries[2],
                         struct wvm_required_ack_entry decoded[2],
                         const struct wvm_route_snapshot_key *route_key,
                         const struct wvm_member_key *node_member,
                         const struct wvm_endpoint *node_endpoint,
                         const struct wvm_member_key *gateway_member,
                         const struct wvm_endpoint *gateway_endpoint,
                         char *error, size_t error_len)
{
    struct wvm_required_ack_set source;
    uint8_t bytes[4096];
    size_t encoded_bytes = 0;

    memset(entries, 0, 2 * sizeof(*entries));
    entries[0].member_key = *node_member;
    entries[0].endpoint = *node_endpoint;
    entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    entries[0].expected_snapshot_key = *route_key;
    entries[1].member_key = *gateway_member;
    entries[1].endpoint = *gateway_endpoint;
    entries[1].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    entries[1].expected_snapshot_key = *route_key;
    memset(&source, 0, sizeof(source));
    source.entries.entries = entries;
    source.entries.count = 2;
    source.entries.capacity = 2;
    if (wvm_required_ack_set_encode(&source, bytes, sizeof(bytes),
                                    &encoded_bytes, error, error_len) != 0) {
        return -1;
    }
    memset(ack_set, 0, sizeof(*ack_set));
    ack_set->entries.entries = decoded;
    ack_set->entries.capacity = 2;
    return wvm_required_ack_set_decode(bytes, encoded_bytes, ack_set, error,
                                       error_len);
}

static const struct wvm_membership_controller_member_entry *find_member(
    const struct wvm_membership_controller *controller, uint16_t role_type,
    uint32_t role_id, uint64_t instance_id)
{
    size_t i;

    for (i = 0; i < controller->member_count; i++) {
        const struct wvm_membership_controller_member_entry *entry =
            &controller->members[i];

        if (entry->member_key.role_type == role_type &&
            entry->member_key.role_id == role_id &&
            entry->member_key.instance_id == instance_id) {
            return entry;
        }
    }
    return NULL;
}

static const struct wvm_endpoint *member_endpoint(
    const struct wvm_membership_controller_member_entry *entry)
{
    if (!entry) {
        return NULL;
    }
    if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
        return &entry->node.control_endpoint;
    }
    return &entry->gateway.endpoint;
}

int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[16];
    struct wvm_membership_controller_route_entry routes[8];
    struct wvm_membership_dependency dependencies[16];
    struct wvm_route_snapshot_key predecessor_key;
    struct wvm_route_transaction_record transaction;
    struct wvm_required_ack_set ack_set;
    struct wvm_required_ack_entry ack_entries[2];
    struct wvm_required_ack_entry decoded_acks[2];
    struct wvm_membership_dependency dependency;
    const struct wvm_membership_controller_member_entry *departing;
    const struct wvm_membership_controller_member_entry *node;
    const struct wvm_endpoint *departing_ep;
    const struct wvm_endpoint *node_ep;
    uint32_t depart_id;
    uint64_t depart_inst;
    uint32_t succ_id;
    uint64_t succ_inst;
    uint32_t node_id;
    uint64_t node_inst;
    uint32_t vm_id;
    char error[256] = {0};

    if (argc != 9) {
        fprintf(stderr,
                "usage: %s JOURNAL DEPART_GW DEPART_INST SUCC_GW SUCC_INST "
                "NODE NODE_INST VM_ID\n",
                argv[0]);
        return 2;
    }
    depart_id = (uint32_t)strtoul(argv[2], NULL, 10);
    depart_inst = (uint64_t)strtoull(argv[3], NULL, 10);
    succ_id = (uint32_t)strtoul(argv[4], NULL, 10);
    succ_inst = (uint64_t)strtoull(argv[5], NULL, 10);
    node_id = (uint32_t)strtoul(argv[6], NULL, 10);
    node_inst = (uint64_t)strtoull(argv[7], NULL, 10);
    vm_id = (uint32_t)strtoul(argv[8], NULL, 10);
    (void)succ_id;
    (void)succ_inst;

    wvm_membership_controller_init(&controller, members, 16, routes, 8,
                                   dependencies, 16, NULL, NULL);
    if (wvm_membership_controller_open(&controller, argv[1], error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "open: %s\n", error);
        return 1;
    }
    departing = find_member(&controller, WVM_MANIFEST_ROLE_GATEWAY, depart_id,
                            depart_inst);
    node = find_member(&controller, WVM_MANIFEST_ROLE_NODE_RUNTIME, node_id,
                       node_inst);
    departing_ep = member_endpoint(departing);
    node_ep = member_endpoint(node);
    if (!departing || !node || !departing_ep || !node_ep ||
        departing->gateway.desired_membership_state !=
            WVM_MANIFEST_MEMBER_ACTIVE ||
        node->node.desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE) {
        fprintf(stderr, "departing gateway or node not ACTIVE in journal\n");
        wvm_membership_controller_close(&controller);
        return 1;
    }

    memset(&predecessor_key, 0, sizeof(predecessor_key));
    predecessor_key.scope_key.vm_id = vm_id;
    predecessor_key.scope_key.vm_incarnation = 1;
    predecessor_key.scope_key.route_scope_id = 1;
    predecessor_key.topology_revision = controller.topology_revision;
    predecessor_key.route_generation = 1;
    memset(predecessor_key.snapshot_digest, 0x5a,
           sizeof(predecessor_key.snapshot_digest));

    if (build_ack_set(&ack_set, ack_entries, decoded_acks, &predecessor_key,
                      &node->member_key, node_ep, &departing->member_key,
                      departing_ep, error, sizeof(error)) != 0) {
        fprintf(stderr, "ack set: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }
    memset(&transaction, 0, sizeof(transaction));
    transaction.operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x41;
    transaction.operation_id[WVM_IDENTITY_ID_BYTES - 2] =
        (uint8_t)(vm_id & 0xffU);
    transaction.route_snapshot_key = predecessor_key;
    transaction.required_ack_set = ack_set;
    transaction.operation_retention_horizon_ms = 5000;
    transaction.state = WVM_ROUTE_TRANSACTION_PREPARING;

    if (wvm_membership_controller_route_begin(&controller, &transaction, error,
                                              sizeof(error)) != 0 ||
        wvm_membership_controller_route_ack_prepare(
            &controller, transaction.operation_id, &node->member_key, error,
            sizeof(error)) != 0 ||
        wvm_membership_controller_route_ack_prepare(
            &controller, transaction.operation_id, &departing->member_key,
            error, sizeof(error)) != 0 ||
        wvm_membership_controller_route_commit(
            &controller, transaction.operation_id, error, sizeof(error)) != 0) {
        fprintf(stderr, "predecessor route: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }

    memset(&dependency, 0, sizeof(dependency));
    dependency.member_key = departing->member_key;
    dependency.vm_id = vm_id;
    dependency.vm_incarnation = 1;
    dependency.manifest_generation = 1;
    dependency.dependency_kind = 2;
    if (wvm_membership_controller_dependency_acquire(&controller, &dependency,
                                                     error, sizeof(error)) !=
        0) {
        fprintf(stderr, "dependency: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }

    printf("seeded_predecessor vm=%u topo=%llu mem=%llu elig=%llu\n", vm_id,
           (unsigned long long)controller.topology_revision,
           (unsigned long long)controller.membership_revision,
           (unsigned long long)controller.admission_eligibility_revision);
    wvm_membership_controller_close(&controller);
    return 0;
}

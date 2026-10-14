#include <stdio.h>
#include <string.h>

#include "wavevm_membership.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "membership-route test: %s\n", message);
        return -1;
    }
    return 0;
}

static struct wvm_membership_member make_member(
    uint32_t physical_node_id, uint64_t node_instance_id)
{
    struct wvm_membership_member member;

    memset(&member, 0, sizeof(member));
    member.kind = WVM_MEMBERSHIP_COMPUTE;
    member.member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    member.member_key.role_id = physical_node_id;
    member.member_key.instance_id = node_instance_id + 1000;
    member.hosting_physical_node_id = physical_node_id;
    member.failure_domain_id = physical_node_id;
    member.capability.physical_node_id = physical_node_id;
    member.capability.node_instance_id = node_instance_id;
    member.capability.profile_generation = 1;
    memset(member.capability.profile_digest, (int)physical_node_id,
           sizeof(member.capability.profile_digest));
    member.desired_state = WVM_MANIFEST_MEMBER_PENDING;
    member.health_state = WVM_MEMBERSHIP_HEALTHY;
    return member;
}

int main(void)
{
    struct wvm_membership_member members[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_registry registry;
    struct wvm_membership_member member1 = make_member(17, 101);
    struct wvm_membership_member member2 = make_member(99, 202);
    struct wvm_membership_dependency dependency;
    struct wvm_route_ack_entry acks[2];
    struct wvm_route_rule rules[2];
    struct wvm_route_ack_set ack_set;
    struct wvm_route_snapshot snapshot;
    struct wvm_route_transaction transaction;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t ack_digest[WVM_SHA256_DIGEST_BYTES];
    char error[256] = {0};

    wvm_membership_registry_init(&registry, members,
                                 sizeof(members) / sizeof(members[0]));
    wvm_membership_registry_set_dependencies(
        &registry, dependencies, sizeof(dependencies) / sizeof(dependencies[0]));
    if (expect(wvm_membership_register(&registry, &member1, error,
                                       sizeof(error)) == 0,
               "register node one") ||
        expect(wvm_membership_register(&registry, &member2, error,
                                       sizeof(error)) == 0,
               "register node two") ||
        expect(wvm_membership_begin_validation(&registry, &member1.member_key,
                                               error, sizeof(error)) == 0,
               "validate node one") ||
        expect(wvm_membership_prepare(&registry, &member1.member_key, error,
                                      sizeof(error)) == 0,
               "prepare node one") ||
        expect(wvm_membership_mark_health(&registry, &member1.member_key,
                                          WVM_MEMBERSHIP_HEALTHY, error,
                                          sizeof(error)) == 0,
               "health node one") ||
        expect(wvm_membership_activate(&registry, &member1.member_key, error,
                                       sizeof(error)) != 0,
               "reject direct node one activation") ||
        expect(wvm_membership_begin_validation(&registry, &member2.member_key,
                                               error, sizeof(error)) == 0,
               "begin node two validation") ||
        expect(wvm_membership_prepare(&registry, &member2.member_key, error,
                                      sizeof(error)) == 0,
               "prepare node two") ||
        expect(wvm_membership_mark_health(&registry, &member2.member_key,
                                          WVM_MEMBERSHIP_HEALTHY, error,
                                          sizeof(error)) == 0,
               "health node two")) {
        return 1;
    }

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.key.scope_key.vm_id = 256;
    snapshot.key.scope_key.vm_incarnation = 1;
    snapshot.key.scope_key.route_scope_id = 1;
    snapshot.key.topology_revision = registry.topology_revision;
    snapshot.key.route_generation = 1;
    memset(snapshot.key.snapshot_digest, 0x31,
           sizeof(snapshot.key.snapshot_digest));
    snapshot.membership_revision = registry.membership_revision;
    snapshot.topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    rules[0].destination_kind = 1;
    rules[0].destination_scope = 0;
    rules[0].destination_vnode_or_endpoint = 1;
    rules[0].next_hop_kind = 1;
    rules[0].next_hop_member = member1.member_key;
    rules[0].hop_limit = 4;
    rules[1] = rules[0];
    rules[1].destination_vnode_or_endpoint = 2;
    rules[1].next_hop_member = member2.member_key;
    snapshot.rules = rules;
    snapshot.rule_count = 2;
    snapshot.rule_capacity = 2;
    memset(acks, 0, sizeof(acks));
    acks[0].member_key = member1.member_key;
    acks[0].expected_snapshot_key = snapshot.key;
    acks[1].member_key = member2.member_key;
    acks[1].expected_snapshot_key = snapshot.key;
    memset(ack_digest, 0x41, sizeof(ack_digest));
    ack_set.entries = acks;
    ack_set.count = 2;
    ack_set.capacity = 2;
    memcpy(ack_set.entries_digest, ack_digest, sizeof(ack_digest));
    snapshot.required_ack_set = &ack_set;
    snapshot.operation_retention_horizon_ms = 1000;
    snapshot.retirement_policy = 1;
    operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;

    if (expect(wvm_route_snapshot_validate(&snapshot, &registry, error,
                                           sizeof(error)) != 0,
               "reject prepared members outside route transaction") ||
        expect(wvm_route_transaction_begin(
                   &transaction, operation_id, &snapshot, NULL, acks,
                   sizeof(acks) / sizeof(acks[0]), 2, ack_digest, error,
                   sizeof(error)) == 0,
               "begin transaction") ||
        expect(wvm_route_transaction_ack_prepare(&transaction,
                                                 &member1.member_key,
                                                 &snapshot.key, error,
                                                 sizeof(error)) == 0,
               "ack node one") ||
        expect(wvm_route_transaction_commit(&transaction, &registry, error,
                                            sizeof(error)) != 0,
               "reject incomplete ACK set") ||
        expect(wvm_route_transaction_ack_prepare(&transaction,
                                                 &member2.member_key,
                                                 &snapshot.key, error,
                                                 sizeof(error)) == 0,
               "ack node two") ||
        expect(wvm_route_transaction_commit(&transaction, &registry, error,
                                            sizeof(error)) == 0,
               "commit full ACK set") ||
        expect(wvm_membership_activate_with_route(
                   &registry, &member1.member_key, &transaction, error,
                   sizeof(error)) == 0,
               "activate node one through committed route") ||
        expect(wvm_membership_activate_with_route(
                   &registry, &member2.member_key, &transaction, error,
                   sizeof(error)) == 0,
               "activate node two through committed route") ||
        expect(wvm_membership_activate_with_route(
                   &registry, &member2.member_key, &transaction, error,
                   sizeof(error)) == 0,
               "replay route-authorized activation") ||
        expect(wvm_route_transaction_begin_retire(&transaction, 1, 1, error,
                                                  sizeof(error)) != 0,
               "retain snapshot with active operation") ||
        expect(wvm_route_transaction_begin_retire(&transaction, 0, 1, error,
                                                  sizeof(error)) == 0,
               "begin retirement") ||
        expect(wvm_route_transaction_retire(&transaction, error,
                                            sizeof(error)) == 0,
               "retire snapshot")) {
        return 1;
    }

    memset(&dependency, 0, sizeof(dependency));
    dependency.member_key = member2.member_key;
    dependency.vm_id = 256;
    dependency.vm_incarnation = 1;
    dependency.manifest_generation = 1;
    dependency.dependency_kind = 1;
    {
        struct wvm_membership_dependency mode_b_vm_a = dependency;
        struct wvm_membership_dependency mode_b_vm_b = dependency;

        mode_b_vm_a.vm_id = 256;
        mode_b_vm_a.dependency_kind = 1; /* Mode B compute placement */
        mode_b_vm_b.vm_id = 257;
        mode_b_vm_b.dependency_kind = 1;
        if (expect(wvm_membership_dependency_acquire(
                       &registry, &mode_b_vm_a, error, sizeof(error)) == 0 &&
                       wvm_membership_dependency_acquire(
                           &registry, &mode_b_vm_b, error, sizeof(error)) == 0 &&
                       members[1].active_dependency_count == 2,
                   "acquire two Mode B VM dependencies on one compute") ||
            expect(wvm_membership_begin_drain(&registry, &member2.member_key,
                                              error, sizeof(error)) != 0,
                   "reject compute drain while two Mode B deps exist") ||
            expect(wvm_membership_dependency_release(
                       &registry, &mode_b_vm_a, error, sizeof(error)) == 0 &&
                       members[1].active_dependency_count == 1,
                   "teardown of Mode B VM A does not clear VM B dependency") ||
            expect(wvm_membership_begin_drain(&registry, &member2.member_key,
                                              error, sizeof(error)) != 0,
                   "reject drain while the other Mode B VM dependency remains") ||
            expect(wvm_membership_dependency_release(
                       &registry, &mode_b_vm_b, error, sizeof(error)) == 0 &&
                       members[1].active_dependency_count == 0,
                   "release remaining Mode B VM B dependency") ||
            expect(wvm_membership_begin_drain(&registry, &member2.member_key,
                                              error, sizeof(error)) == 0,
                   "drain compute after both Mode B deps released") ||
            expect(wvm_membership_remove(&registry, &member2.member_key, error,
                                         sizeof(error)) == 0,
                   "remove compute after dual-VM drain")) {
            return 1;
        }
    }

    puts("membership-route tests: PASS");
    puts("NOTE: dual Mode B VM deps — drain fail-closed until both released;");
    puts("      one VM teardown must not clear the other dependency.");
    return 0;
}

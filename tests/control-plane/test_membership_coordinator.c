#define _XOPEN_SOURCE 700

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_membership_coordinator.h"

#define MIB (1024ULL * 1024ULL)

struct prepare_capture {
    unsigned int calls;
    unsigned int fail_on_call;
    unsigned int commit_calls;
    unsigned int fail_on_commit_call;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "membership-coordinator test: %s\n", message);
        return -1;
    }
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authorize(void *context,
                     enum wvm_membership_controller_authorization_action action,
                     const struct wvm_member_key *actor,
                     const struct wvm_member_key *subject, char *error,
                     size_t error_len)
{
    (void)context;
    (void)action;
    (void)error;
    (void)error_len;
    return member_key_equal(actor, subject) ? 0 : -1;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_capability(struct wvm_capability_ref *capability,
                            uint32_t node_id, uint64_t instance)
{
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = node_id;
    capability->node_instance_id = instance;
    capability->profile_generation = 1;
    memset(capability->profile_digest, 0x21,
           sizeof(capability->profile_digest));
}

static void fill_node(struct wvm_node_record *node)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = 18;
    node->node_instance_id = 102;
    node->failure_domain_id = 4;
    fill_endpoint(&node->control_endpoint, 18, 19200, 19201);
    fill_endpoint(&node->sidecar_endpoint, 18, 19220, 19221);
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_first = 16;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = node->physical_node_id;
    node->inventory.node_instance_id = node->node_instance_id;
    node->inventory.failure_domain_id = node->failure_domain_id;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * MIB;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = 1 * MIB;
    node->inventory.allocatable_vcpu_slots = 7;
    node->inventory.allocatable_memory_bytes = 15 * MIB;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    fill_capability(&node->capability, node->physical_node_id,
                    node->node_instance_id);
}

static void fill_gateway(struct wvm_gateway_record *gateway)
{
    memset(gateway, 0, sizeof(*gateway));
    gateway->gateway_id = 7;
    gateway->gateway_instance_id = 701;
    gateway->hosting_physical_node_id = 17;
    gateway->failure_domain_id = 3;
    fill_endpoint(&gateway->endpoint, 17, 19120, 19121);
    gateway->role_bits = 1;
    gateway->pod_id_or_scope = 1;
}

static void node_key(const struct wvm_node_record *node,
                     struct wvm_member_key *key)
{
    memset(key, 0, sizeof(*key));
    key->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    key->role_id = node->physical_node_id;
    key->instance_id = node->node_instance_id;
}

static void gateway_key(const struct wvm_gateway_record *gateway,
                        struct wvm_member_key *key)
{
    memset(key, 0, sizeof(*key));
    key->role_type = WVM_MANIFEST_ROLE_GATEWAY;
    key->role_id = gateway->gateway_id;
    key->instance_id = gateway->gateway_instance_id;
}

static int build_ack_set(struct wvm_required_ack_set *ack_set,
                         struct wvm_required_ack_entry *entries,
                         struct wvm_required_ack_entry *decoded_entries,
                         size_t entry_count,
                         const struct wvm_route_snapshot_key *route_key,
                         const struct wvm_member_key *first_member,
                         const struct wvm_endpoint *first_endpoint,
                         const struct wvm_member_key *second_member,
                         const struct wvm_endpoint *second_endpoint,
                         char *error, size_t error_len)
{
    struct wvm_required_ack_set source;
    uint8_t bytes[4096];
    size_t encoded_bytes;

    memset(entries, 0, entry_count * sizeof(*entries));
    entries[0].member_key = *first_member;
    entries[0].endpoint = *first_endpoint;
    entries[0].role_type = first_member->role_type;
    entries[0].expected_snapshot_key = *route_key;
    if (entry_count == 2) {
        entries[1].member_key = *second_member;
        entries[1].endpoint = *second_endpoint;
        entries[1].role_type = second_member->role_type;
        entries[1].expected_snapshot_key = *route_key;
    }
    memset(&source, 0, sizeof(source));
    source.entries.entries = entries;
    source.entries.count = entry_count;
    source.entries.capacity = entry_count;
    if (wvm_required_ack_set_encode(&source, bytes, sizeof(bytes),
                                    &encoded_bytes, error, error_len) != 0) {
        return -1;
    }
    memset(ack_set, 0, sizeof(*ack_set));
    ack_set->entries.entries = decoded_entries;
    ack_set->entries.capacity = entry_count;
    return wvm_required_ack_set_decode(bytes, encoded_bytes, ack_set, error,
                                       error_len);
}

static void build_route_key(struct wvm_route_snapshot_key *key,
                            uint64_t topology_revision,
                            uint64_t route_generation, uint8_t digest)
{
    memset(key, 0, sizeof(*key));
    key->scope_key.vm_id = 256;
    key->scope_key.vm_incarnation = 1;
    key->scope_key.route_scope_id = 1;
    key->topology_revision = topology_revision;
    key->route_generation = route_generation;
    memset(key->snapshot_digest, digest, sizeof(key->snapshot_digest));
}

static void build_transaction(struct wvm_route_transaction_record *transaction,
                              uint8_t operation_tail,
                              const struct wvm_route_snapshot_key *route_key,
                              const struct wvm_required_ack_set *ack_set)
{
    memset(transaction, 0, sizeof(*transaction));
    transaction->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    transaction->route_snapshot_key = *route_key;
    transaction->required_ack_set = *ack_set;
    transaction->operation_retention_horizon_ms = 5000;
    transaction->state = WVM_ROUTE_TRANSACTION_PREPARING;
}

static int build_join_snapshot(
    struct wvm_route_snapshot_record *snapshot,
    struct wvm_route_rule_record *rule,
    struct wvm_required_ack_entry snapshot_ack_entries[2],
    struct wvm_required_ack_entry transaction_ack_entries[2],
    struct wvm_required_ack_entry decoded_transaction_ack_entries[2],
    struct wvm_required_ack_set *ack_set,
    uint64_t topology_revision, uint64_t membership_revision,
    const struct wvm_member_key *node_member,
    const struct wvm_endpoint *node_endpoint,
    const struct wvm_member_key *gateway_member,
    const struct wvm_endpoint *gateway_endpoint, char *error,
    size_t error_len)
{
    uint8_t encoded[8192];
    size_t encoded_bytes;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 256;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 1;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 1;
    snapshot->route_snapshot_key.topology_revision = topology_revision;
    snapshot->route_snapshot_key.route_generation = 2;
    snapshot->membership_revision = membership_revision;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    rule->next_hop_member = *gateway_member;
    rule->next_hop_endpoint = *gateway_endpoint;
    rule->hop_limit = 4;
    snapshot->next_hop_rules.entries = rule;
    snapshot->next_hop_rules.count = 1;
    snapshot->next_hop_rules.capacity = 1;
    memset(snapshot_ack_entries, 0, 2 * sizeof(*snapshot_ack_entries));
    snapshot_ack_entries[0].member_key = *node_member;
    snapshot_ack_entries[0].endpoint = *node_endpoint;
    snapshot_ack_entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    snapshot_ack_entries[0].expected_snapshot_key = snapshot->route_snapshot_key;
    snapshot_ack_entries[1].member_key = *gateway_member;
    snapshot_ack_entries[1].endpoint = *gateway_endpoint;
    snapshot_ack_entries[1].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    snapshot_ack_entries[1].expected_snapshot_key = snapshot->route_snapshot_key;
    snapshot->required_ack_set.entries.entries = snapshot_ack_entries;
    snapshot->required_ack_set.entries.count = 2;
    snapshot->required_ack_set.entries.capacity = 2;
    if (wvm_route_snapshot_record_encode(
            snapshot, encoded, sizeof(encoded), &encoded_bytes, NULL, error,
            error_len) != 0 ||
        wvm_route_snapshot_record_decode(encoded, encoded_bytes, snapshot,
                                         error, error_len) != 0) {
        return -1;
    }
    return build_ack_set(ack_set, transaction_ack_entries,
                         decoded_transaction_ack_entries, 2,
                         &snapshot->route_snapshot_key, node_member,
                         node_endpoint, gateway_member, gateway_endpoint,
                         error, error_len);
}

static int build_gateway_successor_transaction(
    struct wvm_route_transaction_record *transaction,
    struct wvm_route_snapshot_record *snapshot,
    struct wvm_route_rule_record *rule,
    struct wvm_required_ack_entry snapshot_ack_entries[2],
    struct wvm_required_ack_entry transaction_ack_entries[2],
    struct wvm_required_ack_entry decoded_transaction_ack_entries[2],
    struct wvm_required_ack_set *ack_set,
    struct wvm_required_ack_entry optional_departure_entries[1],
    uint64_t topology_revision, uint64_t membership_revision,
    uint64_t route_generation, uint8_t operation_tail,
    const struct wvm_route_snapshot_key *predecessor_key,
    const struct wvm_member_key *node_member,
    const struct wvm_endpoint *node_endpoint,
    const struct wvm_member_key *departing_gateway_member,
    const struct wvm_endpoint *departing_gateway_endpoint,
    const struct wvm_member_key *successor_gateway_member,
    const struct wvm_endpoint *successor_gateway_endpoint, char *error,
    size_t error_len)
{
    uint8_t encoded[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key = predecessor_key->scope_key;
    snapshot->route_snapshot_key.topology_revision = topology_revision;
    snapshot->route_snapshot_key.route_generation = route_generation;
    snapshot->membership_revision = membership_revision;
    snapshot->topology_kind = 1;
    snapshot->has_predecessor_snapshot_key = 1;
    snapshot->predecessor_snapshot_key = *predecessor_key;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    rule->next_hop_member = *successor_gateway_member;
    rule->next_hop_endpoint = *successor_gateway_endpoint;
    rule->hop_limit = 4;
    snapshot->next_hop_rules.entries = rule;
    snapshot->next_hop_rules.count = 1;
    snapshot->next_hop_rules.capacity = 1;

    memset(snapshot_ack_entries, 0, 2 * sizeof(*snapshot_ack_entries));
    snapshot_ack_entries[0].member_key = *node_member;
    snapshot_ack_entries[0].endpoint = *node_endpoint;
    snapshot_ack_entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    snapshot_ack_entries[0].expected_snapshot_key =
        snapshot->route_snapshot_key;
    snapshot_ack_entries[1].member_key = *successor_gateway_member;
    snapshot_ack_entries[1].endpoint = *successor_gateway_endpoint;
    snapshot_ack_entries[1].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    snapshot_ack_entries[1].expected_snapshot_key =
        snapshot->route_snapshot_key;
    snapshot->required_ack_set.entries.entries = snapshot_ack_entries;
    snapshot->required_ack_set.entries.count = 2;
    snapshot->required_ack_set.entries.capacity = 2;
    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(snapshot_ack_entries[0].expected_snapshot_key.snapshot_digest,
           digest, sizeof(digest));
    memcpy(snapshot_ack_entries[1].expected_snapshot_key.snapshot_digest,
           digest, sizeof(digest));
    if (wvm_route_snapshot_record_validate(snapshot, error, error_len) != 0 ||
        build_ack_set(ack_set, transaction_ack_entries,
                      decoded_transaction_ack_entries, 2,
                      &snapshot->route_snapshot_key, node_member, node_endpoint,
                      successor_gateway_member, successor_gateway_endpoint,
                      error, error_len) != 0) {
        return -1;
    }
    memset(transaction, 0, sizeof(*transaction));
    transaction->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    transaction->route_snapshot_key = snapshot->route_snapshot_key;
    transaction->has_predecessor_snapshot_key = 1;
    transaction->predecessor_snapshot_key = *predecessor_key;
    transaction->required_ack_set = *ack_set;
    memset(optional_departure_entries, 0,
           sizeof(*optional_departure_entries));
    optional_departure_entries[0].member_key = *departing_gateway_member;
    optional_departure_entries[0].endpoint = *departing_gateway_endpoint;
    optional_departure_entries[0].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    optional_departure_entries[0].expected_snapshot_key = *predecessor_key;
    transaction->optional_departure_drain_set.entries =
        optional_departure_entries;
    transaction->optional_departure_drain_set.count = 1;
    transaction->optional_departure_drain_set.capacity = 1;
    transaction->operation_retention_horizon_ms = 5000;
    transaction->state = WVM_ROUTE_TRANSACTION_PREPARING;
    return wvm_route_transaction_record_validate(transaction, error, error_len);
}

static int route_prepare(void *context,
                         const struct wvm_route_transaction_record *transaction,
                         const struct wvm_route_snapshot_record *snapshot,
                         const struct wvm_required_ack_entry *ack_entry,
                         char *error, size_t error_len)
{
    struct prepare_capture *capture = context;

    if (wvm_route_snapshot_record_binds_transaction(
            snapshot, transaction, error, error_len) != 0 ||
        memcmp(ack_entry->expected_snapshot_key.snapshot_digest,
               snapshot->route_snapshot_key.snapshot_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        return -1;
    }
    capture->calls++;
    if (capture->fail_on_call == capture->calls) {
        snprintf(error, error_len, "simulated participant prepare failure");
        return -1;
    }
    return 0;
}

static int route_commit(void *context,
                        const struct wvm_route_transaction_record *transaction,
                        const struct wvm_route_snapshot_record *snapshot,
                        const struct wvm_required_ack_entry *ack_entry,
                        char *error, size_t error_len)
{
    struct prepare_capture *capture = context;

    if (wvm_route_snapshot_record_binds_transaction(
            snapshot, transaction, error, error_len) != 0 ||
        memcmp(ack_entry->expected_snapshot_key.snapshot_digest,
               snapshot->route_snapshot_key.snapshot_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        return -1;
    }
    capture->commit_calls++;
    if (capture->fail_on_commit_call == capture->commit_calls) {
        snprintf(error, error_len, "simulated participant commit failure");
        return -1;
    }
    return 0;
}

static int activate_gateway(struct wvm_membership_controller *controller,
                            const struct wvm_gateway_record *gateway,
                            const struct wvm_member_key *gateway_member,
                            char *error, size_t error_len)
{
    struct wvm_route_snapshot_key route_key;
    struct wvm_required_ack_entry ack_entries[1];
    struct wvm_required_ack_entry decoded_ack_entries[1];
    struct wvm_required_ack_set ack_set;
    struct wvm_route_transaction_record transaction;

    if (wvm_membership_controller_register_gateway(
            controller, gateway_member, gateway, error, error_len) != 0 ||
        wvm_membership_controller_begin_validation(controller, gateway_member,
                                                   error, error_len) != 0 ||
        wvm_membership_controller_report_self_health(
            controller, gateway_member, WVM_MEMBERSHIP_HEALTHY, error,
            error_len) != 0 ||
        wvm_membership_controller_prepare_member(controller, gateway_member,
                                                  error, error_len) != 0) {
        return -1;
    }
    build_route_key(&route_key, controller->topology_revision, 1, 0x51);
    if (build_ack_set(&ack_set, ack_entries, decoded_ack_entries, 1, &route_key,
                      gateway_member, &gateway->endpoint, NULL, NULL, error,
                      error_len) != 0) {
        return -1;
    }
    build_transaction(&transaction, (uint8_t)(0x40 + gateway->gateway_id),
                      &route_key, &ack_set);
    if (wvm_membership_controller_route_begin(controller, &transaction, error,
                                              error_len) != 0 ||
        wvm_membership_controller_route_ack_prepare(
            controller, transaction.operation_id, gateway_member, error,
            error_len) != 0 ||
        wvm_membership_controller_route_commit(
            controller, transaction.operation_id, error, error_len) != 0 ||
        wvm_membership_controller_activate_member(
            controller, gateway_member, transaction.operation_id, error,
            error_len) != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    char journal_path[] = "/tmp/wavevm-membership-coordinator.XXXXXX";
    struct wvm_membership_controller_member_entry members[8];
    struct wvm_membership_controller_member_entry recovered_members[8];
    struct wvm_membership_controller_route_entry routes[8];
    struct wvm_membership_controller_route_entry recovered_routes[8];
    struct wvm_membership_dependency dependencies[8];
    struct wvm_membership_dependency recovered_dependencies[8];
    struct wvm_membership_controller controller;
    struct wvm_membership_controller recovered_controller;
    struct wvm_gateway_record gateway;
    struct wvm_gateway_record successor_gateway;
    struct wvm_node_record node;
    struct wvm_member_key gateway_member;
    struct wvm_member_key successor_gateway_member;
    struct wvm_member_key node_member;
    struct wvm_route_snapshot_record join_snapshot;
    struct wvm_route_rule_record join_rule;
    struct wvm_required_ack_entry join_snapshot_ack_entries[2];
    struct wvm_required_ack_entry ack_entries[2];
    struct wvm_required_ack_entry decoded_ack_entries[2];
    struct wvm_required_ack_set ack_set;
    struct wvm_route_transaction_record failed_transaction;
    struct wvm_route_transaction_record successful_transaction;
    struct wvm_route_snapshot_key predecessor_route_key;
    struct wvm_route_snapshot_record failed_successor_snapshot;
    struct wvm_route_snapshot_record committed_successor_snapshot;
    struct wvm_route_rule_record failed_successor_rule;
    struct wvm_route_rule_record committed_successor_rule;
    struct wvm_required_ack_entry failed_snapshot_ack_entries[2];
    struct wvm_required_ack_entry committed_snapshot_ack_entries[2];
    struct wvm_required_ack_entry failed_transaction_ack_entries[2];
    struct wvm_required_ack_entry committed_transaction_ack_entries[2];
    struct wvm_required_ack_entry decoded_failed_transaction_ack_entries[2];
    struct wvm_required_ack_entry decoded_committed_transaction_ack_entries[2];
    struct wvm_required_ack_set failed_successor_ack_set;
    struct wvm_required_ack_set committed_successor_ack_set;
    struct wvm_required_ack_entry failed_optional_departure_entries[1];
    struct wvm_required_ack_entry committed_optional_departure_entries[1];
    struct wvm_route_transaction_record failed_successor_transaction;
    struct wvm_route_transaction_record committed_successor_transaction;
    struct wvm_membership_controller_member_status member_status;
    struct wvm_membership_compute_drain_request compute_drain;
    struct wvm_membership_gateway_drain_request gateway_drain;
    struct wvm_membership_dependency dependency;
    struct wvm_membership_join_request join_request;
    struct prepare_capture capture;
    const struct wvm_membership_controller_member_entry *entry;
    uint16_t route_state;
    char error[256] = {0};
    int fd;
    int join_result;

    fd = mkstemp(journal_path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);
    fill_gateway(&gateway);
    successor_gateway = gateway;
    successor_gateway.gateway_id = 8;
    successor_gateway.gateway_instance_id = 801;
    fill_endpoint(&successor_gateway.endpoint, 19, 19320, 19321);
    fill_node(&node);
    gateway_key(&gateway, &gateway_member);
    gateway_key(&successor_gateway, &successor_gateway_member);
    node_key(&node, &node_member);
    wvm_membership_controller_init(&controller, members, 8, routes, 8,
                                   dependencies, 8, authorize, NULL);
    if (expect(wvm_membership_controller_open(&controller, journal_path, error,
                                              sizeof(error)) == 0,
               "open membership controller") ||
        expect(activate_gateway(&controller, &gateway, &gateway_member, error,
                                sizeof(error)) == 0,
               "activate existing route participant")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    if (expect(activate_gateway(&controller, &successor_gateway,
                                &successor_gateway_member, error,
                                sizeof(error)) == 0,
               "activate successor gateway")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    if (expect(build_join_snapshot(
                   &join_snapshot, &join_rule, join_snapshot_ack_entries,
                   ack_entries, decoded_ack_entries, &ack_set,
                   controller.topology_revision + 1,
                   controller.membership_revision + 1, &node_member,
                   &node.control_endpoint, &gateway_member, &gateway.endpoint,
                   error, sizeof(error)) == 0,
               "build join route snapshot and RequiredAckSet")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }
    build_transaction(&failed_transaction, 0x42,
                      &join_snapshot.route_snapshot_key, &ack_set);
    memset(&join_request, 0, sizeof(join_request));
    join_request.member_kind = WVM_MEMBERSHIP_COMPUTE;
    join_request.authenticated_actor = &node_member;
    join_request.node = &node;
    join_request.route_transaction = &failed_transaction;
    join_request.route_snapshot = &join_snapshot;
    join_request.route_prepare = route_prepare;
    join_request.route_commit = route_commit;
    join_request.route_prepare_context = &capture;
    capture.calls = 0;
    capture.fail_on_call = 2;
    if (expect(wvm_membership_coordinator_join(&controller, &join_request,
                                               error, sizeof(error)) != 0,
               "abort join after a participant rejects prepare") ||
        expect(wvm_membership_controller_route_state(
                   &controller, failed_transaction.operation_id, &route_state,
                   error, sizeof(error)) == 0 &&
                   route_state == WVM_ROUTE_TRANSACTION_ABORTED,
               "failed join records an aborted route") ||
        expect((entry = wvm_membership_controller_find(&controller, &node_member)) !=
                   NULL &&
                   entry->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_PREPARED,
               "failed join leaves the node non-schedulable")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    build_transaction(&successful_transaction, 0x43,
                      &join_snapshot.route_snapshot_key, &ack_set);
    join_request.route_transaction = &successful_transaction;
    capture.calls = 0;
    capture.fail_on_call = 0;
    capture.commit_calls = 0;
    capture.fail_on_commit_call = 2;
    if (expect(wvm_membership_coordinator_join(&controller, &join_request,
                                               error, sizeof(error)) != 0,
               "join waits for every consumer commit ACK") ||
        expect(wvm_membership_controller_route_state(
                   &controller, successful_transaction.operation_id,
                   &route_state, error, sizeof(error)) == 0 &&
                   route_state == WVM_ROUTE_TRANSACTION_ACTIVATED,
               "controller route remains committed for retry") ||
        expect((entry = wvm_membership_controller_find(&controller,
                                                       &node_member)) != NULL &&
                   entry->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_PREPARED,
               "commit failure leaves joining member non-schedulable")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }
    error[0] = '\0';
    capture.commit_calls = 0;
    capture.fail_on_commit_call = 0;
    join_result = wvm_membership_coordinator_join(&controller, &join_request,
                                                   error, sizeof(error));
    if (join_result != 0) {
        fprintf(stderr, "membership-coordinator join error: %s\n", error);
    }
    if (expect(join_result == 0,
               "join completes after every participant ACK") ||
        expect((entry = wvm_membership_controller_find(&controller, &node_member)) !=
                   NULL &&
                   entry->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE &&
                   entry->has_activation_route_operation_id &&
                   memcmp(entry->activation_route_operation_id,
                          successful_transaction.operation_id,
                          WVM_IDENTITY_ID_BYTES) == 0,
               "active member retains its committed route authorization")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    memset(&dependency, 0, sizeof(dependency));
    dependency.member_key = node_member;
    dependency.vm_id = 256;
    dependency.vm_incarnation = 1;
    dependency.manifest_generation = 1;
    dependency.dependency_kind = 2;
    memset(&compute_drain, 0, sizeof(compute_drain));
    compute_drain.member_key = node_member;
    if (expect(wvm_membership_controller_dependency_acquire(
                   &controller, &dependency, error, sizeof(error)) == 0,
               "record gateway dependency before drain") ||
        expect(wvm_membership_coordinator_drain_compute(
                   &controller, &compute_drain, error, sizeof(error)) != 0,
               "reject compute drain while a VM dependency exists") ||
        expect(wvm_membership_controller_dependency_release(
                   &controller, &dependency, error, sizeof(error)) == 0,
               "release compute drain test dependency")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    predecessor_route_key = successful_transaction.route_snapshot_key;
    memset(&dependency, 0, sizeof(dependency));
    dependency.member_key = gateway_member;
    dependency.vm_id = predecessor_route_key.scope_key.vm_id;
    dependency.vm_incarnation = predecessor_route_key.scope_key.vm_incarnation;
    dependency.manifest_generation = 1;
    dependency.dependency_kind = 2;
    memset(&gateway_drain, 0, sizeof(gateway_drain));
    gateway_drain.gateway_member_key = &gateway_member;
    gateway_drain.expected_membership_revision = controller.membership_revision;
    gateway_drain.expected_topology_revision = controller.topology_revision;
    gateway_drain.expected_admission_eligibility_revision =
        controller.admission_eligibility_revision;
    gateway_drain.route_prepare = route_prepare;
    gateway_drain.route_prepare_context = &capture;
    if (expect(wvm_membership_controller_dependency_acquire(
                   &controller, &dependency, error, sizeof(error)) == 0,
               "record gateway drain dependency") ||
        expect(build_gateway_successor_transaction(
                   &failed_successor_transaction, &failed_successor_snapshot,
                   &failed_successor_rule, failed_snapshot_ack_entries,
                   failed_transaction_ack_entries,
                   decoded_failed_transaction_ack_entries,
                   &failed_successor_ack_set, failed_optional_departure_entries,
                   controller.topology_revision + 1U,
                   controller.membership_revision, 3, 0x44,
                   &predecessor_route_key, &node_member, &node.control_endpoint,
                   &gateway_member, &gateway.endpoint, &successor_gateway_member,
                   &successor_gateway.endpoint, error, sizeof(error)) == 0,
               "build failed gateway successor") ||
        expect((gateway_drain.successor_transaction =
                    &failed_successor_transaction,
                gateway_drain.successor_snapshot = &failed_successor_snapshot,
                capture.calls = 0, capture.fail_on_call = 1,
                wvm_membership_coordinator_drain_gateway(
                    &controller, &gateway_drain, error, sizeof(error)) != 0),
               "abort gateway drain after participant prepare failure") ||
        expect(capture.calls == 1 &&
                   wvm_membership_controller_route_state(
                       &controller, failed_successor_transaction.operation_id,
                       &route_state, error, sizeof(error)) == 0 &&
                   route_state == WVM_ROUTE_TRANSACTION_ABORTED,
               "failed gateway drain is durably aborted")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    gateway_drain.expected_membership_revision = controller.membership_revision;
    gateway_drain.expected_topology_revision = controller.topology_revision;
    gateway_drain.expected_admission_eligibility_revision =
        controller.admission_eligibility_revision;
    if (expect(build_gateway_successor_transaction(
                   &committed_successor_transaction,
                   &committed_successor_snapshot, &committed_successor_rule,
                   committed_snapshot_ack_entries,
                   committed_transaction_ack_entries,
                   decoded_committed_transaction_ack_entries,
                   &committed_successor_ack_set,
                   committed_optional_departure_entries,
                   controller.topology_revision + 1U,
                   controller.membership_revision, 4, 0x45,
                   &predecessor_route_key, &node_member, &node.control_endpoint,
                   &gateway_member, &gateway.endpoint, &successor_gateway_member,
                   &successor_gateway.endpoint, error, sizeof(error)) == 0,
               "build committed gateway successor") ||
        expect((gateway_drain.successor_transaction =
                    &committed_successor_transaction,
                gateway_drain.successor_snapshot = &committed_successor_snapshot,
                capture.calls = 0, capture.fail_on_call = 0,
                wvm_membership_coordinator_drain_gateway(
                    &controller, &gateway_drain, error, sizeof(error)) == 0),
               "commit gateway drain after all participant ACKs") ||
        expect(capture.calls == 2 &&
                   wvm_membership_coordinator_drain_gateway(
                       &controller, &gateway_drain, error, sizeof(error)) == 0 &&
                   capture.calls == 2,
               "replay committed gateway drain without re-preparing") ||
        expect(wvm_membership_coordinator_remove_gateway(
                   &controller, &gateway_member, error, sizeof(error)) != 0,
               "retain drained gateway while dependency exists")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    if (expect(wvm_membership_controller_dependency_release(
                   &controller, &dependency, error, sizeof(error)) == 0,
               "release gateway drain dependency") ||
        expect(wvm_membership_coordinator_remove_gateway(
                   &controller, &gateway_member, error, sizeof(error)) == 0,
               "remove dependency-free drained gateway") ||
        expect(wvm_membership_coordinator_remove_gateway(
                   &controller, &gateway_member, error, sizeof(error)) == 0,
               "replay gateway removal") ||
        expect(wvm_membership_controller_member_status(
                   &controller, &gateway_member, &member_status, error,
                   sizeof(error)) == 0 &&
                   member_status.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_REMOVED,
               "gateway removal state is observable through a copy")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    if (expect(wvm_membership_coordinator_remove_compute(
                   &controller, &compute_drain, error, sizeof(error)) == 0,
               "drain and remove dependency-free compute member") ||
        expect(wvm_membership_coordinator_remove_compute(
                   &controller, &compute_drain, error, sizeof(error)) == 0,
               "replay compute removal")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }
    wvm_membership_controller_close(&controller);

    wvm_membership_controller_init(&recovered_controller, recovered_members, 8,
                                   recovered_routes, 8, recovered_dependencies,
                                   8, authorize, NULL);
    if (expect(wvm_membership_controller_open(&recovered_controller,
                                              journal_path, error,
                                              sizeof(error)) == 0,
               "recover membership controller") ||
        expect((entry = wvm_membership_controller_find(&recovered_controller,
                                                        &node_member)) != NULL &&
                   entry->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_REMOVED,
               "recover removed compute member") ||
        expect((entry = wvm_membership_controller_find(
                    &recovered_controller, &gateway_member)) != NULL &&
                   entry->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_REMOVED,
               "recover removed gateway member") ||
        expect((entry = wvm_membership_controller_find(
                    &recovered_controller, &successor_gateway_member)) != NULL &&
                   entry->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE,
               "recover surviving gateway member") ||
        expect(wvm_membership_controller_route_state(
                   &recovered_controller, failed_successor_transaction.operation_id,
                   &route_state, error, sizeof(error)) == 0 &&
                   route_state == WVM_ROUTE_TRANSACTION_ABORTED &&
                   wvm_membership_controller_route_state(
                       &recovered_controller,
                       committed_successor_transaction.operation_id,
                       &route_state, error, sizeof(error)) == 0 &&
                   route_state == WVM_ROUTE_TRANSACTION_ACTIVATED &&
                   !recovered_controller.gateway_drain.active,
               "recover gateway drain abort and commit decisions")) {
        wvm_membership_controller_close(&recovered_controller);
        unlink(journal_path);
        return 1;
    }
    wvm_membership_controller_close(&recovered_controller);
    unlink(journal_path);
    puts("membership-coordinator tests: PASS");
    return 0;
}

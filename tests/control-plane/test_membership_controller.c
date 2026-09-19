#define _XOPEN_SOURCE 700

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_coordinator.h"
#include "wavevm_membership_controller.h"

#define MIB (1024ULL * 1024ULL)

struct authorization_context {
    unsigned int calls;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "membership-controller test: %s\n", message);
        return -1;
    }
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authorize(void *context,
                     enum wvm_membership_controller_authorization_action action,
                     const struct wvm_member_key *actor,
                     const struct wvm_member_key *subject, char *error,
                     size_t error_len)
{
    struct authorization_context *authorization = context;

    (void)action;
    (void)error;
    (void)error_len;
    if (!member_key_equal(actor, subject)) {
        return -1;
    }
    authorization->calls++;
    return 0;
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
                            uint32_t node_id, uint64_t instance,
                            uint8_t digest)
{
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = node_id;
    capability->node_instance_id = instance;
    capability->profile_generation = 1;
    memset(capability->profile_digest, digest,
           sizeof(capability->profile_digest));
}

static void fill_capability_record(struct wvm_capability_record *record,
                                   uint16_t capability_id,
                                   uint64_t provider_instance_id)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = 17;
    record->node_instance_id = 101;
    record->provider_instance_id = provider_instance_id;
    record->state = WVM_CAPABILITY_AVAILABLE;
    record->abi_version = 1;
    record->observed_at = 1;
    record->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] =
        (uint8_t)provider_instance_id;
}

static void fill_node(struct wvm_node_record *node, uint32_t *gateway_ids,
                      size_t gateway_id_count)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = 17;
    node->node_instance_id = 101;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint, 17, 19100, 19101);
    fill_endpoint(&node->sidecar_endpoint, 17, 19120, 19121);
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_first = 0;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = node->physical_node_id;
    node->inventory.node_instance_id = node->node_instance_id;
    node->inventory.failure_domain_id = node->failure_domain_id;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * MIB;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = 1 * MIB;
    node->inventory.reserved_gateway_cpu_slots = 1;
    node->inventory.reserved_gateway_memory_bytes = 1 * MIB;
    node->inventory.hosted_gateway_role_ids = gateway_ids;
    node->inventory.hosted_gateway_role_id_count = gateway_id_count;
    node->inventory.hosted_gateway_role_id_capacity = gateway_id_count;
    node->inventory.allocatable_vcpu_slots = 6;
    node->inventory.allocatable_memory_bytes = 14 * MIB;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    fill_capability(&node->capability, node->physical_node_id,
                    node->node_instance_id, 0x21);
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
}

static void fill_gateway(struct wvm_gateway_record *gateway,
                         uint32_t *parent_gateway_ids,
                         size_t parent_gateway_id_count,
                         uint32_t *child_gateway_ids,
                         size_t child_gateway_id_count)
{
    memset(gateway, 0, sizeof(*gateway));
    gateway->gateway_id = 7;
    gateway->gateway_instance_id = 701;
    gateway->hosting_physical_node_id = 17;
    gateway->failure_domain_id = 3;
    fill_endpoint(&gateway->endpoint, 17, 19120, 19121);
    gateway->role_bits = 1;
    gateway->pod_id_or_scope = 1;
    gateway->parent_gateway_ids = parent_gateway_ids;
    gateway->parent_gateway_id_count = parent_gateway_id_count;
    gateway->parent_gateway_id_capacity = parent_gateway_id_count;
    gateway->child_gateway_ids = child_gateway_ids;
    gateway->child_gateway_id_count = child_gateway_id_count;
    gateway->child_gateway_id_capacity = child_gateway_id_count;
    gateway->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    gateway->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    gateway->membership_revision = 1;
    gateway->topology_revision = 1;
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
                         struct wvm_required_ack_entry entries[2],
                         struct wvm_required_ack_entry decoded_entries[2],
                         const struct wvm_route_snapshot_key *route_key,
                         const struct wvm_member_key *node_member,
                         const struct wvm_endpoint *node_endpoint,
                         const struct wvm_member_key *gateway_member,
                         const struct wvm_endpoint *gateway_endpoint,
                         char *error, size_t error_len)
{
    uint8_t bytes[4096];
    size_t encoded_bytes;
    struct wvm_required_ack_set source;

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
    ack_set->entries.entries = decoded_entries;
    ack_set->entries.capacity = 2;
    return wvm_required_ack_set_decode(bytes, encoded_bytes, ack_set, error,
                                       error_len);
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

    if (!transaction || !snapshot || !rule || !snapshot_ack_entries ||
        !transaction_ack_entries || !decoded_transaction_ack_entries ||
        !ack_set || !optional_departure_entries || !predecessor_key ||
        !node_member || !node_endpoint || !departing_gateway_member ||
        !departing_gateway_endpoint || !successor_gateway_member ||
        !successor_gateway_endpoint) {
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = predecessor_key->scope_key.vm_id;
    snapshot->route_snapshot_key.scope_key.vm_incarnation =
        predecessor_key->scope_key.vm_incarnation;
    snapshot->route_snapshot_key.scope_key.route_scope_id =
        predecessor_key->scope_key.route_scope_id;
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
    rule->destination_vnode_or_endpoint = 0;
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
                      decoded_transaction_ack_entries,
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
    memset(optional_departure_entries, 0, sizeof(*optional_departure_entries));
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

int main(void)
{
    char journal_path[] = "/tmp/wavevm-membership-controller.XXXXXX";
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_member_entry recovered_members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_controller_route_entry recovered_routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_dependency recovered_dependencies[4];
    struct wvm_membership_controller controller;
    struct wvm_membership_controller recovered_controller;
    struct authorization_context authorization = {0};
    struct wvm_node_record node;
    struct wvm_node_record changed_node;
    struct wvm_gateway_record gateway;
    struct wvm_gateway_record child_gateway;
    struct wvm_capability_record capabilities[3];
    struct wvm_cluster_record_set records;
    struct wvm_cluster_snapshot cluster_snapshot;
    struct wvm_coordinator_membership_evidence evidence;
    struct wvm_node_record snapshot_nodes[4];
    struct wvm_gateway_record snapshot_gateways[4];
    struct wvm_node_record captured_nodes[4];
    struct wvm_gateway_record captured_gateways[4];
    uint32_t captured_hosted_gateway_ids[4];
    uint32_t captured_gateway_parent_ids[4];
    uint32_t captured_gateway_child_ids[4];
    struct wvm_membership_controller_capture capture;
    struct wvm_membership_controller_member_status member_status;
    struct wvm_membership_controller_member_status saved_status;
    struct wvm_member_key node_member;
    struct wvm_member_key gateway_member;
    struct wvm_member_key child_gateway_member;
    struct wvm_member_key unauthorized_member;
    struct wvm_route_snapshot_key route_key;
    struct wvm_route_snapshot_key child_route_key;
    struct wvm_required_ack_entry ack_entries[2];
    struct wvm_required_ack_entry decoded_ack_entries[2];
    struct wvm_required_ack_set ack_set;
    struct wvm_route_transaction_record transaction;
    struct wvm_required_ack_entry child_ack_entries[2];
    struct wvm_required_ack_entry decoded_child_ack_entries[2];
    struct wvm_required_ack_set child_ack_set;
    struct wvm_route_transaction_record child_transaction;
    struct wvm_route_snapshot_record aborted_successor_snapshot;
    struct wvm_route_snapshot_record committed_successor_snapshot;
    struct wvm_route_rule_record aborted_successor_rule;
    struct wvm_route_rule_record committed_successor_rule;
    struct wvm_required_ack_entry aborted_snapshot_ack_entries[2];
    struct wvm_required_ack_entry committed_snapshot_ack_entries[2];
    struct wvm_required_ack_entry aborted_transaction_ack_entries[2];
    struct wvm_required_ack_entry committed_transaction_ack_entries[2];
    struct wvm_required_ack_entry decoded_aborted_transaction_ack_entries[2];
    struct wvm_required_ack_entry decoded_committed_transaction_ack_entries[2];
    struct wvm_required_ack_set aborted_successor_ack_set;
    struct wvm_required_ack_set committed_successor_ack_set;
    struct wvm_required_ack_entry aborted_optional_departure_entries[1];
    struct wvm_required_ack_entry committed_optional_departure_entries[1];
    struct wvm_route_transaction_record aborted_successor_transaction;
    struct wvm_route_transaction_record committed_successor_transaction;
    struct wvm_membership_dependency dependency;
    struct wvm_membership_dependency gateway_dependency;
    uint32_t gateway_ids[2] = {7, 8};
    uint32_t gateway_parent_ids[1] = {7};
    uint32_t gateway_child_ids[1] = {8};
    uint8_t capability_profile_digest[WVM_SHA256_DIGEST_BYTES];
    size_t node_count;
    size_t gateway_count;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t eligibility_revision;
    char error[256] = {0};
    int fd;

    fd = mkstemp(journal_path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    fill_node(&node, gateway_ids, 2);
    fill_gateway(&gateway, NULL, 0, gateway_child_ids, 1);
    fill_gateway(&child_gateway, gateway_parent_ids, 1, NULL, 0);
    child_gateway.gateway_id = 8;
    child_gateway.gateway_instance_id = 801;
    fill_endpoint(&child_gateway.endpoint, 17, 19122, 19123);
    fill_capability_record(&capabilities[0], WVM_CAPABILITY_ID_EXECUTION_KVM,
                           1);
    fill_capability_record(&capabilities[1], WVM_CAPABILITY_ID_EXECUTION_TCG,
                           2);
    fill_capability_record(&capabilities[2],
                           WVM_CAPABILITY_ID_MODE_B_MEMORY, 3);
    if (wvm_capability_profile_digest(
            node.physical_node_id, node.node_instance_id, 1, capabilities, 3,
            capability_profile_digest, error, sizeof(error)) != 0) {
        fprintf(stderr, "membership-controller test setup: %s\n", error);
        unlink(journal_path);
        return 1;
    }
    memcpy(node.capability.profile_digest, capability_profile_digest,
           sizeof(node.capability.profile_digest));
    node_key(&node, &node_member);
    gateway_key(&gateway, &gateway_member);
    gateway_key(&child_gateway, &child_gateway_member);
    unauthorized_member = node_member;
    unauthorized_member.instance_id++;

    wvm_membership_controller_init(
        &controller, members, 4, routes, 4, dependencies, 4, authorize,
        &authorization);
    if (expect(wvm_membership_controller_open(&controller, journal_path, error,
                                              sizeof(error)) == 0,
               "open empty membership controller") ||
        expect(wvm_membership_controller_register_node(
                   &controller, &unauthorized_member, &node, error,
                   sizeof(error)) != 0,
               "reject unauthenticated node identity") ||
        expect(wvm_membership_controller_register_node(
                   &controller, &node_member, &node, error, sizeof(error)) ==
                   0,
               "register node as pending") ||
        expect((changed_node = node,
                changed_node.control_endpoint.data_port++,
                wvm_membership_controller_register_node(
                    &controller, &node_member, &changed_node, error,
                    sizeof(error)) != 0),
               "reject changed registration under the same node instance") ||
        expect(wvm_membership_controller_register_gateway(
                   &controller, &gateway_member, &gateway, error,
                   sizeof(error)) == 0,
               "register parent gateway as pending") ||
        expect(wvm_membership_controller_register_gateway(
                   &controller, &child_gateway_member, &child_gateway, error,
                   sizeof(error)) == 0,
               "register child gateway as pending") ||
        expect(wvm_membership_controller_find(&controller, &node_member)
                       ->node.desired_membership_state ==
                   WVM_MANIFEST_MEMBER_PENDING &&
                   wvm_membership_controller_find(&controller, &node_member)
                           ->node.observed_health_state ==
                       WVM_MEMBERSHIP_RECOVERING,
               "registration normalizes desired and health state")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    if (expect(wvm_membership_controller_member_status(
                   &controller, &node_member, &member_status, error,
                   sizeof(error)) == 0 &&
                   memcmp(&member_status.endpoint, &node.control_endpoint,
                          sizeof(member_status.endpoint)) == 0,
               "copy endpoint without capturing hosted gateway lists") ||
        expect(wvm_membership_controller_member_status(
                   &controller, &gateway_member, &member_status, error,
                   sizeof(error)) == 0 &&
                   memcmp(&member_status.endpoint, &gateway.endpoint,
                          sizeof(member_status.endpoint)) == 0,
               "copy gateway endpoint without capturing parent/child lists")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }
    saved_status = member_status;
    {
        struct wvm_member_key stale_key = node_member;

        stale_key.instance_id++;
        if (expect(wvm_membership_controller_member_status(
                       &controller, &stale_key, &member_status, error,
                       sizeof(error)) != 0 &&
                       memcmp(&saved_status, &member_status, sizeof(member_status)) == 0,
                   "stale instance lookup cannot return a replacement endpoint")) {
            wvm_membership_controller_close(&controller);
            unlink(journal_path);
            return 1;
        }
    }

    if (expect(wvm_membership_controller_begin_validation(
                   &controller, &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_begin_validation(
                       &controller, &gateway_member, error, sizeof(error)) ==
                       0 &&
                   wvm_membership_controller_begin_validation(
                       &controller, &child_gateway_member, error,
                       sizeof(error)) == 0,
               "move every route participant into validation") ||
        expect(wvm_membership_controller_report_self_health(
                   &controller, &node_member, WVM_MEMBERSHIP_HEALTHY, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_controller_report_self_health(
                       &controller, &gateway_member, WVM_MEMBERSHIP_HEALTHY,
                       error, sizeof(error)) == 0 &&
                   wvm_membership_controller_report_self_health(
                       &controller, &child_gateway_member,
                       WVM_MEMBERSHIP_HEALTHY, error, sizeof(error)) == 0,
               "accept authenticated healthy reports") ||
        expect(wvm_membership_controller_prepare_member(
                   &controller, &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_prepare_member(
                       &controller, &gateway_member, error, sizeof(error)) ==
                       0 &&
                   wvm_membership_controller_prepare_member(
                       &controller, &child_gateway_member, error,
                       sizeof(error)) == 0,
               "prepare members before route commit")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    memset(&route_key, 0, sizeof(route_key));
    route_key.scope_key.vm_id = 256;
    route_key.scope_key.vm_incarnation = 1;
    route_key.scope_key.route_scope_id = 1;
    route_key.topology_revision = controller.topology_revision;
    route_key.route_generation = 1;
    memset(route_key.snapshot_digest, 0x5a, sizeof(route_key.snapshot_digest));
    if (expect(build_ack_set(&ack_set, ack_entries, decoded_ack_entries,
                             &route_key, &node_member,
                             &node.control_endpoint, &gateway_member,
                             &gateway.endpoint, error, sizeof(error)) == 0,
               "build canonical route ACK set")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }
    memset(&transaction, 0, sizeof(transaction));
    transaction.operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x41;
    transaction.route_snapshot_key = route_key;
    transaction.required_ack_set = ack_set;
    transaction.operation_retention_horizon_ms = 5000;
    transaction.state = WVM_ROUTE_TRANSACTION_PREPARING;
    if (expect(wvm_membership_controller_route_begin(
                   &controller, &transaction, error, sizeof(error)) == 0,
               "persist route prepare transaction") ||
        expect(wvm_membership_controller_route_ack_prepare(
                   &controller, transaction.operation_id, &node_member, error,
                   sizeof(error)) == 0,
               "persist first route ACK") ||
        expect(wvm_membership_controller_route_commit(
                   &controller, transaction.operation_id, error,
                   sizeof(error)) != 0,
               "reject route commit with incomplete ACK set") ||
        expect(wvm_membership_controller_route_ack_prepare(
                   &controller, transaction.operation_id, &gateway_member,
                   error, sizeof(error)) == 0 &&
                   wvm_membership_controller_route_commit(
                       &controller, transaction.operation_id, error,
                       sizeof(error)) == 0,
               "commit route after every required ACK") ||
        expect(wvm_membership_controller_activate_member(
                   &controller, &node_member, transaction.operation_id, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_controller_activate_member(
                       &controller, &gateway_member, transaction.operation_id,
                       error, sizeof(error)) == 0,
               "activate members only through committed route transaction")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    child_route_key = route_key;
    child_route_key.scope_key.vm_id = 257;
    child_route_key.route_generation = 1;
    memset(child_route_key.snapshot_digest, 0x5b,
           sizeof(child_route_key.snapshot_digest));
    if (expect(build_ack_set(&child_ack_set, child_ack_entries,
                             decoded_child_ack_entries, &child_route_key,
                             &node_member, &node.control_endpoint,
                             &child_gateway_member, &child_gateway.endpoint,
                             error, sizeof(error)) == 0,
               "build route authorization for the successor gateway") ||
        expect((memset(&child_transaction, 0, sizeof(child_transaction)),
                child_transaction.operation_id[WVM_IDENTITY_ID_BYTES - 1] =
                    0x42,
                child_transaction.route_snapshot_key = child_route_key,
                child_transaction.required_ack_set = child_ack_set,
                child_transaction.operation_retention_horizon_ms = 5000,
                child_transaction.state = WVM_ROUTE_TRANSACTION_PREPARING,
                wvm_membership_controller_route_begin(
                    &controller, &child_transaction, error, sizeof(error)) ==
                    0 &&
                wvm_membership_controller_route_ack_prepare(
                    &controller, child_transaction.operation_id, &node_member,
                    error, sizeof(error)) == 0 &&
                wvm_membership_controller_route_ack_prepare(
                    &controller, child_transaction.operation_id,
                    &child_gateway_member, error, sizeof(error)) == 0 &&
                wvm_membership_controller_route_commit(
                    &controller, child_transaction.operation_id, error,
                    sizeof(error)) == 0 &&
                wvm_membership_controller_activate_member(
                    &controller, &child_gateway_member,
                    child_transaction.operation_id, error, sizeof(error)) == 0),
               "activate the replacement gateway through a committed route")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }
    memset(&capture, 0, sizeof(capture));
    capture.nodes = captured_nodes;
    capture.node_capacity = sizeof(captured_nodes) / sizeof(captured_nodes[0]);
    capture.gateways = captured_gateways;
    capture.gateway_capacity =
        sizeof(captured_gateways) / sizeof(captured_gateways[0]);
    capture.hosted_gateway_role_ids = captured_hosted_gateway_ids;
    capture.hosted_gateway_role_id_capacity =
        sizeof(captured_hosted_gateway_ids) /
        sizeof(captured_hosted_gateway_ids[0]);
    capture.gateway_parent_ids = captured_gateway_parent_ids;
    capture.gateway_parent_id_capacity =
        sizeof(captured_gateway_parent_ids) /
        sizeof(captured_gateway_parent_ids[0]);
    capture.gateway_child_ids = captured_gateway_child_ids;
    capture.gateway_child_id_capacity =
        sizeof(captured_gateway_child_ids) /
        sizeof(captured_gateway_child_ids[0]);
    memset(&evidence, 0, sizeof(evidence));
    evidence.capability_records = capabilities;
    evidence.capability_record_count = 3;
    evidence.inventory_revision = 1;
    evidence.capability_profile_generation = 1;
    if (expect(wvm_coordinator_capture_current_membership_records(
                   &controller, &capture, &evidence, &records, error,
                   sizeof(error)) == 0 &&
                   wvm_cluster_snapshot_build(&records, &cluster_snapshot,
                                              error, sizeof(error)) == 0 &&
                   records.membership_revision ==
                       controller.membership_revision &&
                   records.topology_revision == controller.topology_revision &&
                   capture.node_count == 1 && capture.gateway_count == 2 &&
                   capture.hosted_gateway_role_id_count == 2 &&
                   capture.gateway_parent_id_count == 1 &&
                   capture.gateway_child_id_count == 1 &&
                   captured_nodes[0].inventory.hosted_gateway_role_ids ==
                       captured_hosted_gateway_ids &&
                   captured_nodes[0].inventory.hosted_gateway_role_ids !=
                       wvm_membership_controller_find(&controller, &node_member)
                           ->node.inventory.hosted_gateway_role_ids &&
                   captured_gateways[0].child_gateway_ids ==
                       captured_gateway_child_ids &&
                   captured_gateways[0].child_gateway_ids !=
                       wvm_membership_controller_find(
                           &controller, &gateway_member)
                           ->gateway.child_gateway_ids &&
                   captured_gateways[1].parent_gateway_ids ==
                       captured_gateway_parent_ids &&
                   captured_gateways[1].parent_gateway_ids !=
                       wvm_membership_controller_find(
                           &controller, &child_gateway_member)
                           ->gateway.parent_gateway_ids &&
                   cluster_snapshot.admission.node_count == 1 &&
                   cluster_snapshot.active_gateway_count == 2,
               "capture immutable member graph for admission snapshot")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    memset(&gateway_dependency, 0, sizeof(gateway_dependency));
    gateway_dependency.member_key = gateway_member;
    gateway_dependency.vm_id = route_key.scope_key.vm_id;
    gateway_dependency.vm_incarnation = route_key.scope_key.vm_incarnation;
    gateway_dependency.manifest_generation = 1;
    gateway_dependency.dependency_kind = 2;
    if (expect(wvm_membership_controller_dependency_acquire(
                   &controller, &gateway_dependency, error, sizeof(error)) ==
                   0,
               "record the single route scope using the departing gateway") ||
        expect(wvm_membership_controller_begin_drain(
                   &controller, &gateway_member, error, sizeof(error)) != 0,
               "reject generic gateway drain without successor publication") ||
        expect(build_gateway_successor_transaction(
                   &aborted_successor_transaction, &aborted_successor_snapshot,
                   &aborted_successor_rule, aborted_snapshot_ack_entries,
                   aborted_transaction_ack_entries,
                   decoded_aborted_transaction_ack_entries,
                   &aborted_successor_ack_set,
                   aborted_optional_departure_entries,
                   controller.topology_revision + 1U,
                   controller.membership_revision, 3, 0x43, &route_key,
                   &node_member, &node.control_endpoint, &gateway_member,
                   &gateway.endpoint, &child_gateway_member,
                   &child_gateway.endpoint, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_gateway_drain_begin(
                       &controller, &gateway_member,
                       &aborted_successor_transaction,
                       &aborted_successor_snapshot, error, sizeof(error)) ==
                       0,
               "reserve successor topology before gateway drain") ||
        expect(wvm_membership_controller_begin_drain(
                   &controller, &node_member, error, sizeof(error)) != 0,
               "reject concurrent topology mutation during gateway drain") ||
        expect(wvm_membership_controller_route_ack_prepare(
                   &controller, aborted_successor_transaction.operation_id,
                   &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_route_commit(
                       &controller, aborted_successor_transaction.operation_id,
                       error, sizeof(error)) != 0,
               "reject generic publication of a prepared drain successor") ||
        expect(wvm_membership_controller_gateway_drain_abort(
                   &controller, aborted_successor_transaction.operation_id,
                   error, sizeof(error)) == 0 &&
                   wvm_membership_controller_gateway_drain_abort(
                       &controller, aborted_successor_transaction.operation_id,
                       error, sizeof(error)) == 0 &&
                   !controller.gateway_drain.active &&
                   controller.routes[2].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ABORTED &&
                   wvm_membership_controller_route_ack_prepare(
                       &controller, aborted_successor_transaction.operation_id,
                       &child_gateway_member, error, sizeof(error)) != 0,
               "abort drain durably before successor publication")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    if (expect(build_gateway_successor_transaction(
                   &committed_successor_transaction,
                   &committed_successor_snapshot, &committed_successor_rule,
                   committed_snapshot_ack_entries,
                   committed_transaction_ack_entries,
                   decoded_committed_transaction_ack_entries,
                   &committed_successor_ack_set,
                   committed_optional_departure_entries,
                   controller.topology_revision + 1U,
                   controller.membership_revision, 4, 0x44, &route_key,
                   &node_member, &node.control_endpoint, &gateway_member,
                   &gateway.endpoint, &child_gateway_member,
                   &child_gateway.endpoint, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_gateway_drain_begin(
                       &controller, &gateway_member,
                       &committed_successor_transaction,
                       &committed_successor_snapshot, error, sizeof(error)) ==
                       0 &&
                   wvm_membership_controller_route_ack_prepare(
                       &controller, committed_successor_transaction.operation_id,
                       &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_route_ack_prepare(
                       &controller, committed_successor_transaction.operation_id,
                       &child_gateway_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_route_commit(
                       &controller, committed_successor_transaction.operation_id,
                       error, sizeof(error)) != 0 &&
                   wvm_membership_controller_gateway_drain_commit(
                       &controller, committed_successor_transaction.operation_id,
                       error, sizeof(error)) == 0 &&
                   wvm_membership_controller_gateway_drain_commit(
                       &controller, committed_successor_transaction.operation_id,
                       error, sizeof(error)) == 0,
               "atomically publish successor route and gateway drain") ||
        expect(!controller.gateway_drain.active &&
                   controller.routes[3].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ACTIVATED &&
                   controller.routes[3].required_ack_states[0].activated &&
                   controller.routes[3].required_ack_states[1].activated &&
                   wvm_membership_controller_find(&controller, &gateway_member)
                           ->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_DRAINING &&
                   wvm_membership_controller_remove(
                       &controller, &gateway_member, error, sizeof(error)) !=
                       0,
               "retain gateway until predecessor dependency releases")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    memset(&dependency, 0, sizeof(dependency));
    dependency.member_key = node_member;
    dependency.vm_id = 256;
    dependency.vm_incarnation = 1;
    dependency.manifest_generation = 1;
    dependency.dependency_kind = 1;
    if (expect(wvm_membership_controller_dependency_acquire(
                   &controller, &dependency, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_cordon(
                       &controller, &node_member, error, sizeof(error)) == 0,
               "cordon active node with a recorded dependency") ||
        expect(wvm_membership_controller_begin_drain(
                   &controller, &node_member, error, sizeof(error)) != 0,
               "reject drain while a VM dependency exists") ||
        expect(wvm_membership_controller_dependency_release(
                   &controller, &dependency, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_begin_drain(
                       &controller, &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_remove(
                       &controller, &node_member, error, sizeof(error)) == 0,
               "remove node only after dependency release") ||
        expect(wvm_membership_controller_mark_monitor_health(
                   &controller, &gateway_member, WVM_MEMBERSHIP_UNREACHABLE,
                   error, sizeof(error)) == 0,
               "record monitor-only unreachable evidence")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    if (expect(wvm_membership_controller_snapshot(
                   &controller, snapshot_nodes, 4, &node_count,
                   snapshot_gateways, 4, &gateway_count, &membership_revision,
                   &topology_revision, &eligibility_revision, error,
                   sizeof(error)) == 0 &&
                   node_count == 1 && gateway_count == 2 &&
                   snapshot_nodes[0].desired_membership_state ==
                       WVM_MANIFEST_MEMBER_REMOVED &&
                   snapshot_gateways[0].observed_health_state ==
                       WVM_MEMBERSHIP_UNREACHABLE &&
                   membership_revision == controller.membership_revision &&
                   topology_revision == controller.topology_revision &&
                   eligibility_revision ==
                       controller.admission_eligibility_revision,
               "materialize current controller-owned membership records")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }
    wvm_membership_controller_close(&controller);

    fd = open(journal_path, O_WRONLY | O_APPEND);
    if (fd < 0 || write(fd, "WVM", 3) != 3) {
        perror("append torn membership journal tail");
        if (fd >= 0) {
            close(fd);
        }
        unlink(journal_path);
        return 1;
    }
    close(fd);

    wvm_membership_controller_init(
        &recovered_controller, recovered_members, 4, recovered_routes, 4,
        recovered_dependencies, 4, authorize, &authorization);
    if (expect(wvm_membership_controller_open(
                   &recovered_controller, journal_path, error,
                   sizeof(error)) == 0,
               "recover completed membership journal and trim torn tail") ||
        expect(wvm_membership_controller_find(&recovered_controller,
                                              &node_member)
                       ->node.desired_membership_state ==
                   WVM_MANIFEST_MEMBER_REMOVED &&
                   wvm_membership_controller_find(&recovered_controller,
                                                  &gateway_member)
                           ->gateway.observed_health_state ==
                       WVM_MEMBERSHIP_UNREACHABLE &&
                   recovered_controller.routes[0].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ACTIVATED &&
                   recovered_controller.routes[2].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ABORTED &&
                   recovered_controller.routes[3].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ACTIVATED &&
                   !recovered_controller.gateway_drain.active,
               "recover state, health, and committed route transaction")) {
        wvm_membership_controller_close(&recovered_controller);
        unlink(journal_path);
        return 1;
    }

    wvm_membership_controller_close(&recovered_controller);
    unlink(journal_path);
    puts("membership-controller tests: PASS");
    return 0;
}

#define _XOPEN_SOURCE 700

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_membership_control.h"

#define MIB (1024ULL * 1024ULL)

struct authorization_context {
    unsigned int calls;
};

struct management_authorization_context {
    unsigned int calls;
    int allow;
};

struct membership_authorization_context {
    unsigned int calls;
    int allow;
    enum wvm_membership_control_membership_action last_action;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "membership-control test: %s\n", message);
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

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
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
    node->capability.physical_node_id = node->physical_node_id;
    node->capability.node_instance_id = node->node_instance_id;
    node->capability.profile_generation = 1;
    memset(node->capability.profile_digest, 0x21,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
    wvm_node_record_init_single_host_defaults(node);
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
    gateway->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    gateway->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    gateway->membership_revision = 1;
    gateway->topology_revision = 1;
}

static void fill_child_gateway(struct wvm_gateway_record *gateway,
                               uint32_t parent_gateway_ids[1])
{
    fill_gateway(gateway);
    gateway->gateway_id = 8;
    gateway->gateway_instance_id = 801;
    parent_gateway_ids[0] = 7;
    gateway->parent_gateway_ids = parent_gateway_ids;
    gateway->parent_gateway_id_count = 1;
    gateway->parent_gateway_id_capacity = 1;
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

static void make_request(struct wvm_envelope *request, uint16_t message_type,
                         uint8_t operation_tail, uint32_t origin_node,
                         uint64_t origin_instance, const uint8_t *payload,
                         size_t payload_bytes)
{
    memset(request, 0, sizeof(*request));
    request->message_type = message_type;
    request->origin_physical_node_id = origin_node;
    request->origin_runtime_instance_id = origin_instance;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                    request->semantic_payload_digest);
}

static int encode_rejoin(const uint8_t *member_record,
                         size_t member_record_bytes,
                         const struct wvm_member_key *prior_member,
                         uint8_t output[8192], size_t *output_bytes,
                         char *error, size_t error_len)
{
    uint8_t recovery_evidence[WVM_SHA256_DIGEST_BYTES];

    /* R08: use production encoder — do not keep a test-local wire layout. */
    memset(recovery_evidence, 0x7e, sizeof(recovery_evidence));
    return wvm_membership_rejoin_request_encode(
        member_record, member_record_bytes, prior_member, recovery_evidence,
        output, 8192, output_bytes, error, error_len);
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

static int authorize_management(
    void *context, enum wvm_gateway_drain_action action,
    const struct wvm_member_key *actor,
    const struct wvm_member_key *target_gateway, char *error, size_t error_len)
{
    struct management_authorization_context *authorization = context;

    (void)action;
    (void)actor;
    (void)target_gateway;
    (void)error;
    (void)error_len;
    authorization->calls++;
    return authorization->allow ? 0 : -1;
}

static int authorize_membership(
    void *context, enum wvm_membership_control_membership_action action,
    const struct wvm_member_key *actor,
    const struct wvm_member_key *target_member, char *error,
    size_t error_len)
{
    struct membership_authorization_context *authorization = context;

    (void)actor;
    (void)target_member;
    (void)error;
    (void)error_len;
    authorization->calls++;
    authorization->last_action = action;
    return authorization->allow ? 0 : -1;
}

static int make_drain_envelope(
    struct wvm_envelope *envelope, uint8_t *payload, size_t payload_capacity,
    size_t *payload_bytes, uint8_t envelope_operation_tail,
    enum wvm_gateway_drain_action action,
    const struct wvm_member_key *executor_member,
    const struct wvm_member_key *target_gateway_member,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t expected_membership_revision, uint64_t expected_topology_revision,
    uint64_t expected_admission_eligibility_revision,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot,
    char *error, size_t error_len)
{
    struct wvm_gateway_drain_request request;

    if (!envelope || !payload || !payload_bytes || !executor_member ||
        !target_gateway_member || !route_operation_id) {
        return -1;
    }
    memset(&request, 0, sizeof(request));
    request.action = action;
    request.target_gateway_member_key = *target_gateway_member;
    request.expected_membership_revision = expected_membership_revision;
    request.expected_topology_revision = expected_topology_revision;
    request.expected_admission_eligibility_revision =
        expected_admission_eligibility_revision;
    memcpy(request.route_operation_id, route_operation_id,
           sizeof(request.route_operation_id));
    if (action == WVM_GATEWAY_DRAIN_ACTION_PREPARE) {
        if (!successor_transaction || !successor_snapshot) {
            return -1;
        }
        request.successor_transaction = *successor_transaction;
        request.successor_snapshot = *successor_snapshot;
    }
    if (wvm_gateway_drain_request_encode(
            &request, payload, payload_capacity, payload_bytes, error,
            error_len) != 0) {
        return -1;
    }
    make_request(envelope, WVM_ENVELOPE_MSG_DRAIN,
                 envelope_operation_tail, executor_member->role_id,
                 executor_member->instance_id, payload, *payload_bytes);
    return 0;
}

static int make_cordon_envelope(
    struct wvm_envelope *envelope, uint8_t *payload, size_t payload_capacity,
    size_t *payload_bytes, uint8_t envelope_operation_tail,
    const struct wvm_member_key *executor_member,
    const struct wvm_member_key *target_member,
    uint64_t expected_membership_revision, uint64_t expected_topology_revision,
    uint64_t expected_admission_eligibility_revision, uint16_t reason_code,
    char *error, size_t error_len)
{
    struct wvm_member_cordon_request request;

    if (!envelope || !payload || !payload_bytes || !executor_member ||
        !target_member) {
        return -1;
    }
    memset(&request, 0, sizeof(request));
    request.target_member_key = *target_member;
    request.expected_membership_revision = expected_membership_revision;
    request.expected_topology_revision = expected_topology_revision;
    request.expected_admission_eligibility_revision =
        expected_admission_eligibility_revision;
    request.reason_code = reason_code;
    if (wvm_member_cordon_request_encode(
            &request, payload, payload_capacity, payload_bytes, error,
            error_len) != 0) {
        return -1;
    }
    make_request(envelope, WVM_ENVELOPE_MSG_CORDON,
                 envelope_operation_tail, executor_member->role_id,
                 executor_member->instance_id, payload, *payload_bytes);
    return 0;
}

static int corrupt_nested_transaction_record_type(uint8_t *bytes,
                                                  size_t byte_count)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int next;

    if (!bytes || wvm_canonical_record_parse(bytes, byte_count, &record) != 0) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) > 0) {
        if (field.tag == 6 &&
            field.value_bytes >= WVM_CANONICAL_RECORD_HEADER_BYTES) {
            ((uint8_t *)field.value)[2] = 0x7f;
            return 0;
        }
    }
    return -1;
}

int main(void)
{
    char membership_journal[] = "/tmp/wavevm-membership-authority.XXXXXX";
    char control_journal[] = "/tmp/wavevm-membership-control.XXXXXX";
    char unprivileged_control_journal[] =
        "/tmp/wavevm-membership-unprivileged.XXXXXX";
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_member_entry recovered_members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_controller_route_entry recovered_routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_dependency recovered_dependencies[4];
    struct wvm_membership_control_operation operations[12];
    struct wvm_membership_control_operation recovered_operations[12];
    struct wvm_membership_control_operation unprivileged_operations[2];
    struct wvm_membership_controller controller;
    struct wvm_membership_controller recovered_controller;
    struct wvm_membership_control control;
    struct wvm_membership_control recovered_control;
    struct wvm_membership_control unprivileged_control;
    struct authorization_context authorization = {0};
    struct management_authorization_context management_authorization = {0, 0};
    struct membership_authorization_context membership_authorization = {0, 1, 0};
    struct wvm_node_record node;
    struct wvm_gateway_record gateway;
    struct wvm_gateway_record child_gateway;
    struct wvm_member_key node_member;
    struct wvm_member_key gateway_member;
    struct wvm_member_key child_gateway_member;
    struct wvm_member_key executor_member;
    struct wvm_member_key prior_gateway_member;
    struct wvm_member_key forged_member;
    struct wvm_envelope request;
    struct wvm_membership_control_result first_result;
    struct wvm_membership_control_result replay_result;
    struct wvm_membership_control_result decoded_result;
    struct wvm_membership_control_result drain_prepare_result;
    struct wvm_membership_control_result drain_abort_result;
    struct wvm_membership_control_result drain_commit_result;
    struct wvm_membership_control_result cordon_result;
    struct wvm_membership_control_result cordon_retry_result;
    struct wvm_membership_control_result node_cordon_result;
    struct wvm_route_snapshot_key predecessor_key;
    struct wvm_route_snapshot_key child_route_key;
    struct wvm_required_ack_entry predecessor_ack_entries[2];
    struct wvm_required_ack_entry decoded_predecessor_ack_entries[2];
    struct wvm_required_ack_set predecessor_ack_set;
    struct wvm_route_transaction_record predecessor_transaction;
    struct wvm_required_ack_entry child_ack_entries[2];
    struct wvm_required_ack_entry decoded_child_ack_entries[2];
    struct wvm_required_ack_set child_ack_set;
    struct wvm_route_transaction_record child_transaction;
    struct wvm_required_ack_entry committed_snapshot_ack_entries[2];
    struct wvm_required_ack_entry committed_transaction_ack_entries[2];
    struct wvm_required_ack_entry decoded_committed_transaction_ack_entries[2];
    struct wvm_required_ack_set committed_successor_ack_set;
    struct wvm_required_ack_entry committed_optional_departure_entries[1];
    struct wvm_route_transaction_record committed_successor_transaction;
    struct wvm_route_snapshot_record committed_successor_snapshot;
    struct wvm_route_rule_record committed_successor_rule;
    struct wvm_membership_dependency gateway_dependency;
    struct wvm_envelope drain_envelope;
    struct wvm_envelope cordon_envelope;
    uint32_t gateway_ids[2] = {7, 8};
    uint32_t gateway_child_ids[1] = {8};
    uint32_t child_gateway_parent_ids[1];
    uint8_t node_bytes[8192];
    uint8_t gateway_bytes[8192];
    uint8_t rejoin_bytes[8192];
    uint8_t drain_bytes[32768];
    uint8_t malformed_drain_bytes[32768];
    uint8_t cordon_bytes[1024];
    uint8_t result_bytes[WVM_MEMBERSHIP_CONTROL_RESULT_BYTES];
    size_t node_byte_count;
    size_t gateway_byte_count;
    size_t rejoin_byte_count;
    size_t drain_byte_count;
    size_t cordon_byte_count;
    uint64_t cordon_membership_revision;
    uint64_t cordon_topology_revision;
    uint64_t cordon_eligibility_revision;
    uint64_t drain_eligibility_revision;
    uint64_t retained_membership_revision;
    char error[256] = {0};
    int fd;

    fd = mkstemp(membership_journal);
    if (fd < 0) {
        perror("mkstemp membership journal");
        return 1;
    }
    close(fd);
    fd = mkstemp(control_journal);
    if (fd < 0) {
        perror("mkstemp control journal");
        unlink(membership_journal);
        return 1;
    }
    close(fd);
    fd = mkstemp(unprivileged_control_journal);
    if (fd < 0) {
        perror("mkstemp unprivileged control journal");
        unlink(control_journal);
        unlink(membership_journal);
        return 1;
    }
    close(fd);

    fill_node(&node, gateway_ids, 2);
    fill_gateway(&gateway);
    gateway.child_gateway_ids = gateway_child_ids;
    gateway.child_gateway_id_count = 1;
    gateway.child_gateway_id_capacity = 1;
    fill_child_gateway(&child_gateway, child_gateway_parent_ids);
    node_key(&node, &node_member);
    gateway_key(&gateway, &gateway_member);
    gateway_key(&child_gateway, &child_gateway_member);
    memset(&executor_member, 0, sizeof(executor_member));
    executor_member.role_type = WVM_MANIFEST_ROLE_EXECUTOR;
    executor_member.role_id = node.physical_node_id;
    executor_member.instance_id = 901;
    prior_gateway_member = gateway_member;
    prior_gateway_member.instance_id--;
    wvm_membership_controller_init(&controller, members, 4, routes, 4,
                                   dependencies, 4, authorize, &authorization);
    wvm_membership_control_init(&control, &controller, operations, 12);
    wvm_membership_control_init(&unprivileged_control, &controller,
                                unprivileged_operations, 2);
    if (expect(wvm_membership_control_set_management_authorizer(
                   &control, authorize_management,
                   &management_authorization) == 0,
               "install gateway drain management authorizer") ||
        expect(wvm_membership_control_set_membership_authorizer(
                   &control, authorize_membership,
                   &membership_authorization) == 0,
               "install membership management authorizer") ||
        expect(wvm_membership_controller_open(&controller, membership_journal,
                                              error, sizeof(error)) == 0,
               "open membership authority") ||
        expect(wvm_membership_control_open(&control, control_journal, error,
                                           sizeof(error)) == 0,
               "open membership control") ||
        expect(wvm_node_record_encode(&node, node_bytes, sizeof(node_bytes),
                                      &node_byte_count, error,
                                      sizeof(error)) == 0,
               "encode node registration")) {
        goto fail;
    }
    make_request(&request, WVM_ENVELOPE_MSG_REGISTER_MEMBER, 1,
                 node.physical_node_id, node.node_instance_id, node_bytes,
                 node_byte_count);
    if (expect(wvm_membership_control_apply(&control, &request, &node_member,
                                            &first_result, error,
                                            sizeof(error)) == 0 &&
                   first_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   first_result.recorded_state ==
                       WVM_MANIFEST_MEMBER_PENDING &&
                   first_result.applied_revision ==
                       controller.membership_revision &&
                   first_result.applied_revision != 0 &&
                   !bytes_are_zero(first_result.record_digest,
                                   sizeof(first_result.record_digest)),
               "register node through authenticated V1 receiver") ||
        expect(wvm_membership_controller_find(&controller, &node_member)
                       ->node.desired_membership_state ==
                   WVM_MANIFEST_MEMBER_PENDING,
               "authority owns normalized registration state") ||
        expect(wvm_membership_control_result_encode(&first_result, result_bytes) ==
                       0 &&
                   wvm_membership_control_result_decode(result_bytes,
                                                        &decoded_result) == 0 &&
                   memcmp(&first_result, &decoded_result,
                          sizeof(first_result)) == 0,
               "fixed ControlResult round trip") ||
        expect(wvm_membership_control_apply(&control, &request, &node_member,
                                            &replay_result, error,
                                            sizeof(error)) == 0 &&
                   memcmp(&first_result, &replay_result,
                          sizeof(first_result)) == 0 &&
                   controller.membership_revision ==
                       first_result.applied_revision,
               "same operation replays without a second membership change")) {
        goto fail;
    }

    request.semantic_payload_digest[0] ^= 0xff;
    if (expect(wvm_membership_control_apply(&control, &request, &node_member,
                                            &replay_result, error,
                                            sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_INVALID_ENVELOPE,
               "reject mismatched semantic digest before mutation")) {
        goto fail;
    }
    request.semantic_payload_digest[0] ^= 0xff;
    request.payload = gateway_bytes;
    request.payload_bytes = 1;
    wvm_envelope_semantic_digest(request.payload, request.payload_bytes,
                                    request.semantic_payload_digest);
    if (expect(wvm_membership_control_apply(&control, &request, &node_member,
                                            &replay_result, error,
                                            sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_OPERATION_ID_CONFLICT,
               "reject operation-ID reuse under a different digest")) {
        goto fail;
    }

    forged_member = node_member;
    forged_member.instance_id++;
    make_request(&request, WVM_ENVELOPE_MSG_REGISTER_MEMBER, 2,
                 node.physical_node_id, node.node_instance_id, node_bytes,
                 node_byte_count);
    if (expect(wvm_membership_control_apply(&control, &request, &forged_member,
                                            &replay_result, error,
                                            sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE,
               "reject a transport principal that differs from the payload") ||
        expect(controller.member_count == 1,
               "forged registration does not change membership")) {
        goto fail;
    }

    if (expect(wvm_gateway_record_encode(&gateway, gateway_bytes,
                                         sizeof(gateway_bytes),
                                         &gateway_byte_count, error,
                                         sizeof(error)) == 0 &&
                   encode_rejoin(gateway_bytes, gateway_byte_count,
                                 &prior_gateway_member, rejoin_bytes,
                                 &rejoin_byte_count, error,
                                 sizeof(error)) == 0,
               "encode rejoin request") ||
        expect((make_request(&request, WVM_ENVELOPE_MSG_REJOIN, 3,
                             gateway.hosting_physical_node_id,
                             gateway.gateway_instance_id, rejoin_bytes,
                             rejoin_byte_count),
                wvm_membership_control_apply(&control, &request,
                                              &gateway_member, &replay_result,
                                              error, sizeof(error)) == 0) &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   replay_result.recorded_state ==
                       WVM_MANIFEST_MEMBER_VALIDATING,
               "rejoin reaches validating only after durable registration") ||
        expect(wvm_membership_controller_find(&controller, &gateway_member)
                       ->gateway.desired_membership_state ==
                   WVM_MANIFEST_MEMBER_VALIDATING,
               "rejoin does not activate a member")) {
        goto fail;
    }

    if (expect(wvm_membership_controller_register_gateway(
                   &controller, &child_gateway_member, &child_gateway, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_controller_begin_validation(
                       &controller, &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_begin_validation(
                       &controller, &child_gateway_member, error,
                       sizeof(error)) == 0 &&
                   wvm_membership_controller_report_self_health(
                       &controller, &node_member, WVM_MEMBERSHIP_HEALTHY, error,
                       sizeof(error)) == 0 &&
                   wvm_membership_controller_report_self_health(
                       &controller, &gateway_member, WVM_MEMBERSHIP_HEALTHY,
                       error, sizeof(error)) == 0 &&
                   wvm_membership_controller_report_self_health(
                       &controller, &child_gateway_member,
                       WVM_MEMBERSHIP_HEALTHY, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_prepare_member(
                       &controller, &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_prepare_member(
                       &controller, &gateway_member, error, sizeof(error)) ==
                       0 &&
                   wvm_membership_controller_prepare_member(
                       &controller, &child_gateway_member, error,
                       sizeof(error)) == 0,
               "prepare every registered route participant")) {
        goto fail;
    }

    memset(&predecessor_key, 0, sizeof(predecessor_key));
    predecessor_key.scope_key.vm_id = 256;
    predecessor_key.scope_key.vm_incarnation = 1;
    predecessor_key.scope_key.route_scope_id = 1;
    predecessor_key.topology_revision = controller.topology_revision;
    predecessor_key.route_generation = 1;
    memset(predecessor_key.snapshot_digest, 0x5a,
           sizeof(predecessor_key.snapshot_digest));
    if (expect(build_ack_set(&predecessor_ack_set, predecessor_ack_entries,
                             decoded_predecessor_ack_entries, &predecessor_key,
                             &node_member, &node.control_endpoint,
                             &gateway_member, &gateway.endpoint, error,
                             sizeof(error)) == 0 &&
                   (memset(&predecessor_transaction, 0,
                           sizeof(predecessor_transaction)),
                    predecessor_transaction.operation_id
                        [WVM_IDENTITY_ID_BYTES - 1] = 0x41,
                    predecessor_transaction.route_snapshot_key =
                        predecessor_key,
                    predecessor_transaction.required_ack_set =
                        predecessor_ack_set,
                    predecessor_transaction.operation_retention_horizon_ms =
                        5000,
                    predecessor_transaction.state =
                        WVM_ROUTE_TRANSACTION_PREPARING,
                    wvm_membership_controller_route_begin(
                        &controller, &predecessor_transaction, error,
                        sizeof(error)) == 0) &&
                   wvm_membership_controller_route_ack_prepare(
                       &controller, predecessor_transaction.operation_id,
                       &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_route_ack_prepare(
                       &controller, predecessor_transaction.operation_id,
                       &gateway_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_route_commit(
                       &controller, predecessor_transaction.operation_id, error,
                       sizeof(error)) == 0 &&
                   wvm_membership_controller_activate_member(
                       &controller, &node_member,
                       predecessor_transaction.operation_id, error,
                       sizeof(error)) == 0 &&
                   wvm_membership_controller_activate_member(
                       &controller, &gateway_member,
                       predecessor_transaction.operation_id, error,
                       sizeof(error)) == 0,
               "activate the predecessor route through the controller")) {
        goto fail;
    }

    child_route_key = predecessor_key;
    child_route_key.scope_key.vm_id = 257;
    memset(child_route_key.snapshot_digest, 0x5b,
           sizeof(child_route_key.snapshot_digest));
    if (expect(build_ack_set(&child_ack_set, child_ack_entries,
                             decoded_child_ack_entries, &child_route_key,
                             &node_member, &node.control_endpoint,
                             &child_gateway_member, &child_gateway.endpoint,
                             error, sizeof(error)) == 0 &&
                   (memset(&child_transaction, 0, sizeof(child_transaction)),
                    child_transaction.operation_id[WVM_IDENTITY_ID_BYTES - 1] =
                        0x42,
                    child_transaction.route_snapshot_key = child_route_key,
                    child_transaction.required_ack_set = child_ack_set,
                    child_transaction.operation_retention_horizon_ms = 5000,
                    child_transaction.state = WVM_ROUTE_TRANSACTION_PREPARING,
                    wvm_membership_controller_route_begin(
                        &controller, &child_transaction, error,
                        sizeof(error)) == 0) &&
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
                       child_transaction.operation_id, error, sizeof(error)) ==
                       0,
               "activate the successor gateway route")) {
        goto fail;
    }

    memset(&gateway_dependency, 0, sizeof(gateway_dependency));
    gateway_dependency.member_key = gateway_member;
    gateway_dependency.vm_id = predecessor_key.scope_key.vm_id;
    gateway_dependency.vm_incarnation =
        predecessor_key.scope_key.vm_incarnation;
    gateway_dependency.manifest_generation = 1;
    gateway_dependency.dependency_kind = 2;
    if (expect(wvm_membership_controller_dependency_acquire(
                   &controller, &gateway_dependency, error, sizeof(error)) ==
                   0,
               "record gateway route dependency")) {
        goto fail;
    }

    if (expect(wvm_membership_control_open(&unprivileged_control,
                                           unprivileged_control_journal, error,
                                           sizeof(error)) == 0 &&
                   build_gateway_successor_transaction(
                       &committed_successor_transaction,
                       &committed_successor_snapshot,
                       &committed_successor_rule,
                       committed_snapshot_ack_entries,
                       committed_transaction_ack_entries,
                       decoded_committed_transaction_ack_entries,
                       &committed_successor_ack_set,
                       committed_optional_departure_entries,
                       controller.topology_revision + 1U,
                       controller.membership_revision, 2, 0x44,
                       &predecessor_key, &node_member, &node.control_endpoint,
                       &gateway_member, &gateway.endpoint,
                       &child_gateway_member, &child_gateway.endpoint, error,
                       sizeof(error)) == 0 &&
                   make_drain_envelope(
                       &drain_envelope, drain_bytes, sizeof(drain_bytes),
                       &drain_byte_count, 0x30,
                       WVM_GATEWAY_DRAIN_ACTION_PREPARE, &executor_member,
                       &gateway_member,
                       committed_successor_transaction.operation_id,
                       controller.membership_revision, controller.topology_revision,
                       controller.admission_eligibility_revision,
                       &committed_successor_transaction,
                       &committed_successor_snapshot, error, sizeof(error)) ==
                       0 &&
                   wvm_membership_control_apply(
                       &unprivileged_control, &drain_envelope, &executor_member,
                       &replay_result, error, sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE &&
                   !controller.gateway_drain.active,
               "fail closed without a management authorizer")) {
        goto fail;
    }
    wvm_membership_control_close(&unprivileged_control);

    management_authorization.allow = 0;
    if (expect(wvm_membership_control_apply(
                   &control, &drain_envelope, &executor_member, &replay_result,
                   error, sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE &&
                   management_authorization.calls != 0,
               "reject a management callback decision") ||
        expect(wvm_membership_control_apply(
                   &control, &drain_envelope, &gateway_member, &replay_result,
                   error, sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE,
               "reject a gateway self-authorization attempt")) {
        goto fail;
    }
    management_authorization.allow = 1;

    memcpy(malformed_drain_bytes, drain_bytes, drain_byte_count);
    if (expect(corrupt_nested_transaction_record_type(
                   malformed_drain_bytes, drain_byte_count) == 0 &&
                   (make_request(&request, WVM_ENVELOPE_MSG_DRAIN, 0x31,
                                 executor_member.role_id,
                                 executor_member.instance_id,
                                 malformed_drain_bytes, drain_byte_count),
                    wvm_membership_control_apply(
                        &control, &request, &executor_member, &replay_result,
                        error, sizeof(error)) == 0) &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_INVALID_RECORD &&
                   !controller.gateway_drain.active,
               "reject a malformed nested successor record")) {
        goto fail;
    }

    drain_eligibility_revision = controller.admission_eligibility_revision;
    if (expect(make_drain_envelope(
                   &drain_envelope, drain_bytes, sizeof(drain_bytes),
                   &drain_byte_count, 0x32,
                   WVM_GATEWAY_DRAIN_ACTION_PREPARE, &executor_member,
                   &gateway_member, committed_successor_transaction.operation_id,
                   controller.membership_revision, controller.topology_revision,
                   controller.admission_eligibility_revision + 1U,
                   &committed_successor_transaction,
                   &committed_successor_snapshot, error, sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &drain_envelope, &executor_member,
                       &replay_result, error, sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_PRECONDITION_FAILED &&
                   !controller.gateway_drain.active,
               "reject a stale drain revision fence")) {
        goto fail;
    }

    if (expect(make_drain_envelope(
                   &drain_envelope, drain_bytes, sizeof(drain_bytes),
                   &drain_byte_count, 0x33,
                   WVM_GATEWAY_DRAIN_ACTION_PREPARE, &executor_member,
                   &gateway_member, committed_successor_transaction.operation_id,
                   controller.membership_revision, controller.topology_revision,
                   drain_eligibility_revision,
                   &committed_successor_transaction,
                   &committed_successor_snapshot, error, sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &drain_envelope, &executor_member,
                       &drain_prepare_result, error, sizeof(error)) == 0 &&
                   drain_prepare_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   controller.gateway_drain.active,
               "prepare gateway drain through the authenticated receiver")) {
        goto fail;
    }

    if (expect(make_drain_envelope(
                   &drain_envelope, drain_bytes, sizeof(drain_bytes),
                   &drain_byte_count, 0x34,
                   WVM_GATEWAY_DRAIN_ACTION_ABORT, &executor_member,
                   &gateway_member, committed_successor_transaction.operation_id,
                   controller.membership_revision, controller.topology_revision,
                   drain_eligibility_revision, NULL, NULL, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &drain_envelope, &executor_member,
                       &drain_abort_result, error, sizeof(error)) == 0 &&
                   drain_abort_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   !controller.gateway_drain.active &&
                   controller.admission_eligibility_revision ==
                       drain_eligibility_revision + 1U &&
                   controller.routes[2].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ABORTED,
               "abort the prepared gateway drain")) {
        goto fail;
    }
    if (expect(wvm_membership_control_apply(
                   &control, &drain_envelope, &executor_member, &replay_result,
                   error, sizeof(error)) == 0 &&
                   memcmp(&drain_abort_result, &replay_result,
                          sizeof(drain_abort_result)) == 0,
               "replay the durable drain abort result")) {
        goto fail;
    }

    drain_eligibility_revision = controller.admission_eligibility_revision;
    if (expect(build_gateway_successor_transaction(
                   &committed_successor_transaction,
                   &committed_successor_snapshot, &committed_successor_rule,
                   committed_snapshot_ack_entries,
                   committed_transaction_ack_entries,
                   decoded_committed_transaction_ack_entries,
                   &committed_successor_ack_set,
                   committed_optional_departure_entries,
                   controller.topology_revision + 1U,
                   controller.membership_revision, 3, 0x45, &predecessor_key,
                   &node_member, &node.control_endpoint, &gateway_member,
                   &gateway.endpoint, &child_gateway_member,
                   &child_gateway.endpoint, error, sizeof(error)) == 0 &&
                   make_drain_envelope(
                       &drain_envelope, drain_bytes, sizeof(drain_bytes),
                       &drain_byte_count, 0x35,
                       WVM_GATEWAY_DRAIN_ACTION_PREPARE, &executor_member,
                       &gateway_member,
                       committed_successor_transaction.operation_id,
                       controller.membership_revision, controller.topology_revision,
                       drain_eligibility_revision,
                       &committed_successor_transaction,
                       &committed_successor_snapshot, error, sizeof(error)) ==
                       0 &&
                   wvm_membership_control_apply(
                       &control, &drain_envelope, &executor_member,
                       &drain_prepare_result, error, sizeof(error)) == 0 &&
                   drain_prepare_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   wvm_membership_controller_route_ack_prepare(
                       &controller, committed_successor_transaction.operation_id,
                       &node_member, error, sizeof(error)) == 0 &&
                   wvm_membership_controller_route_ack_prepare(
                       &controller, committed_successor_transaction.operation_id,
                       &child_gateway_member, error, sizeof(error)) == 0 &&
                   make_drain_envelope(
                       &drain_envelope, drain_bytes, sizeof(drain_bytes),
                       &drain_byte_count, 0x36,
                       WVM_GATEWAY_DRAIN_ACTION_COMMIT, &executor_member,
                       &gateway_member,
                       committed_successor_transaction.operation_id,
                       controller.membership_revision, controller.topology_revision,
                       drain_eligibility_revision, NULL, NULL,
                       error, sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &drain_envelope, &executor_member,
                       &drain_commit_result, error, sizeof(error)) == 0 &&
                   drain_commit_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   !controller.gateway_drain.active &&
                   controller.routes[3].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ACTIVATED &&
                   wvm_membership_controller_find(&controller, &gateway_member)
                           ->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_DRAINING,
               "commit the successor route and drain atomically")) {
        goto fail;
    }
    if (expect(wvm_membership_control_apply(
                   &control, &drain_envelope, &executor_member, &replay_result,
                   error, sizeof(error)) == 0 &&
                   memcmp(&drain_commit_result, &replay_result,
                          sizeof(drain_commit_result)) == 0,
               "replay the durable drain commit result")) {
        goto fail;
    }

    if (expect(wvm_membership_control_set_management_authorizer(
                   &unprivileged_control, authorize_management,
                   &management_authorization) == 0 &&
                   wvm_membership_control_open(
                       &unprivileged_control, unprivileged_control_journal,
                       error, sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &unprivileged_control, &drain_envelope, &executor_member,
                       &replay_result, error, sizeof(error)) == 0 &&
                   memcmp(&drain_commit_result, &replay_result,
                          sizeof(drain_commit_result)) == 0,
               "recover a controller-only durable drain commit")) {
        goto fail;
    }
    wvm_membership_control_close(&unprivileged_control);

    cordon_membership_revision = controller.membership_revision;
    cordon_topology_revision = controller.topology_revision;
    cordon_eligibility_revision =
        controller.admission_eligibility_revision;
    if (expect(make_cordon_envelope(
                   &cordon_envelope, cordon_bytes, sizeof(cordon_bytes),
                   &cordon_byte_count, 0x50, &executor_member, &node_member,
                   cordon_membership_revision, cordon_topology_revision,
                   cordon_eligibility_revision, 0x0101, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_control_open(
                       &unprivileged_control, unprivileged_control_journal,
                       error, sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &unprivileged_control, &cordon_envelope, &executor_member,
                       &replay_result, error, sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE &&
                   controller.membership_revision ==
                       cordon_membership_revision &&
                   wvm_membership_controller_find(&controller, &node_member)
                           ->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE,
               "fail closed without a membership authorizer")) {
        goto fail;
    }
    wvm_membership_control_close(&unprivileged_control);

    if (expect(wvm_membership_control_apply(
                   &control, &cordon_envelope, &executor_member, &cordon_result,
                   error, sizeof(error)) == 0 &&
                   cordon_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   cordon_result.recorded_state ==
                       WVM_MANIFEST_MEMBER_CORDONED &&
                   cordon_result.applied_revision ==
                       cordon_membership_revision + 1U &&
                   controller.membership_revision ==
                       cordon_result.applied_revision &&
                   controller.topology_revision == cordon_topology_revision &&
                   controller.admission_eligibility_revision ==
                       cordon_eligibility_revision + 1U &&
                   membership_authorization.calls != 0 &&
                   membership_authorization.last_action ==
                       WVM_MEMBERSHIP_CONTROL_MEMBERSHIP_ACTION_CORDON,
               "cordon a compute member through the fenced receiver")) {
        goto fail;
    }
    node_cordon_result = cordon_result;
    if (expect(make_cordon_envelope(
                   &cordon_envelope, cordon_bytes, sizeof(cordon_bytes),
                   &cordon_byte_count, 0x51, &executor_member, &node_member,
                   cordon_membership_revision, cordon_topology_revision,
                   cordon_eligibility_revision, 0x0101, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &cordon_envelope, &executor_member,
                       &cordon_retry_result, error, sizeof(error)) == 0 &&
                   cordon_retry_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   cordon_retry_result.applied_revision ==
                       cordon_result.applied_revision &&
                   controller.membership_revision ==
                       cordon_result.applied_revision &&
                   wvm_membership_controller_find(&controller, &node_member)
                           ->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_CORDONED,
               "retry a cordon after the controller journal commit")) {
        goto fail;
    }

    if (expect(make_cordon_envelope(
                   &cordon_envelope, cordon_bytes, sizeof(cordon_bytes),
                   &cordon_byte_count, 0x52, &executor_member,
                   &child_gateway_member, controller.membership_revision,
                   controller.topology_revision,
                   controller.admission_eligibility_revision, 0x0102, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &cordon_envelope, &gateway_member,
                       &replay_result, error, sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE &&
                   wvm_membership_controller_find(
                       &controller, &child_gateway_member)
                           ->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE,
               "reject a non-executor cordon actor")) {
        goto fail;
    }
    membership_authorization.allow = 0;
    if (expect(make_cordon_envelope(
                   &cordon_envelope, cordon_bytes, sizeof(cordon_bytes),
                   &cordon_byte_count, 0x53, &executor_member,
                   &child_gateway_member, controller.membership_revision,
                   controller.topology_revision,
                   controller.admission_eligibility_revision, 0x0102, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &cordon_envelope, &executor_member,
                       &replay_result, error, sizeof(error)) == 0 &&
                   replay_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE &&
                   wvm_membership_controller_find(
                       &controller, &child_gateway_member)
                           ->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE,
               "reject a membership authorizer denial")) {
        goto fail;
    }
    membership_authorization.allow = 1;
    if (expect(make_cordon_envelope(
                   &cordon_envelope, cordon_bytes, sizeof(cordon_bytes),
                   &cordon_byte_count, 0x54, &executor_member,
                   &child_gateway_member, controller.membership_revision,
                   controller.topology_revision,
                   controller.admission_eligibility_revision, 0x0102, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &control, &cordon_envelope, &executor_member,
                       &cordon_result, error, sizeof(error)) == 0 &&
                   cordon_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   cordon_result.recorded_state ==
                       WVM_MANIFEST_MEMBER_CORDONED &&
                   wvm_membership_controller_find(
                       &controller, &child_gateway_member)
                           ->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_CORDONED,
               "cordon a gateway member through the same receiver")) {
        goto fail;
    }

    retained_membership_revision = controller.membership_revision;

    wvm_membership_control_close(&control);
    fd = open(control_journal, O_WRONLY | O_APPEND);
    if (fd < 0 || write(fd, "WVM", 3) != 3) {
        perror("append torn membership-control tail");
        if (fd >= 0) {
            close(fd);
        }
        goto fail_authority_only;
    }
    close(fd);
    wvm_membership_controller_close(&controller);

    wvm_membership_controller_init(
        &recovered_controller, recovered_members, 4, recovered_routes, 4,
        recovered_dependencies, 4, authorize, &authorization);
    wvm_membership_control_init(&recovered_control, &recovered_controller,
                                recovered_operations, 12);
    if (expect(wvm_membership_control_set_management_authorizer(
                   &recovered_control, authorize_management,
                   &management_authorization) == 0,
               "restore management authorizer before control recovery") ||
        expect(wvm_membership_controller_open(&recovered_controller,
                                              membership_journal, error,
                                              sizeof(error)) == 0,
               "recover membership authority") ||
        expect(wvm_membership_control_open(&recovered_control, control_journal,
                                           error, sizeof(error)) == 0,
               "recover operation result journal after torn tail")) {
        goto fail_recovered;
    }
    make_request(&request, WVM_ENVELOPE_MSG_REGISTER_MEMBER, 1,
                 node.physical_node_id, node.node_instance_id, node_bytes,
                 node_byte_count);
    if (expect(wvm_membership_control_apply(&recovered_control, &request,
                                            &node_member, &replay_result,
                                            error, sizeof(error)) == 0 &&
                   memcmp(&first_result, &replay_result,
                          sizeof(first_result)) == 0 &&
                   recovered_controller.membership_revision ==
                       retained_membership_revision,
               "recover and replay the original durable result")) {
        goto fail_recovered;
    }
    if (expect(wvm_membership_control_apply(
                   &recovered_control, &drain_envelope, &executor_member,
                   &replay_result, error, sizeof(error)) == 0 &&
                   memcmp(&drain_commit_result, &replay_result,
                          sizeof(drain_commit_result)) == 0 &&
                   !recovered_controller.gateway_drain.active &&
                   recovered_controller.routes[3].transaction.state ==
                       WVM_ROUTE_TRANSACTION_ACTIVATED &&
                   wvm_membership_controller_find(
                       &recovered_controller, &node_member)
                           ->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_CORDONED &&
                   wvm_membership_controller_find(
                       &recovered_controller, &child_gateway_member)
                           ->gateway.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_CORDONED,
               "recover and replay the committed drain result")) {
        goto fail_recovered;
    }
    if (expect(make_cordon_envelope(
                   &cordon_envelope, cordon_bytes, sizeof(cordon_bytes),
                   &cordon_byte_count, 0x50, &executor_member, &node_member,
                   cordon_membership_revision, cordon_topology_revision,
                   cordon_eligibility_revision, 0x0101, error,
                   sizeof(error)) == 0 &&
                   wvm_membership_control_apply(
                       &recovered_control, &cordon_envelope, &executor_member,
                       &replay_result, error, sizeof(error)) == 0 &&
                   memcmp(&node_cordon_result, &replay_result,
                          sizeof(node_cordon_result)) == 0 &&
                   recovered_controller.membership_revision ==
                       retained_membership_revision,
               "recover and replay the durable cordon result")) {
        goto fail_recovered;
    }

    wvm_membership_control_close(&unprivileged_control);
    wvm_membership_control_close(&recovered_control);
    wvm_membership_controller_close(&recovered_controller);
    unlink(unprivileged_control_journal);
    unlink(control_journal);
    unlink(membership_journal);
    puts("membership-control tests: PASS");
    return 0;

fail_recovered:
    wvm_membership_control_close(&recovered_control);
    wvm_membership_controller_close(&recovered_controller);
    unlink(unprivileged_control_journal);
    unlink(control_journal);
    unlink(membership_journal);
    return 1;

fail:
    wvm_membership_control_close(&unprivileged_control);
    wvm_membership_control_close(&control);
fail_authority_only:
    wvm_membership_control_close(&unprivileged_control);
    wvm_membership_controller_close(&controller);
    unlink(unprivileged_control_journal);
    unlink(control_journal);
    unlink(membership_journal);
    return 1;
}

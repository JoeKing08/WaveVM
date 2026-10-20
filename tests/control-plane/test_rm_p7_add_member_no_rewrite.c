/*
 * RM-P7-add-member-no-rewrite:
 * Adding a cluster member must not rewrite an ACTIVATED VM route.
 */
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_membership_controller.h"

#define MIB (1024ULL * 1024ULL)

struct authorization_context {
    unsigned int calls;
};

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
    if (!member_key_equal(actor, subject))
        return -1;
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

static void fill_node(struct wvm_node_record *node, uint32_t *gateway_ids,
                      size_t gateway_id_count, uint32_t physical_node_id,
                      uint32_t instance_id)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = physical_node_id;
    node->node_instance_id = instance_id;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint, (uint8_t)physical_node_id, 19100,
                  19101);
    fill_endpoint(&node->sidecar_endpoint, (uint8_t)physical_node_id, 19120,
                  19121);
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_first = 0;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = physical_node_id;
    node->inventory.node_instance_id = instance_id;
    node->inventory.failure_domain_id = 3;
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
    fill_capability(&node->capability, physical_node_id, instance_id, 0x21);
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
                                    &encoded_bytes, error, error_len) != 0)
        return -1;
    memset(ack_set, 0, sizeof(*ack_set));
    ack_set->entries.entries = decoded;
    ack_set->entries.capacity = 2;
    return wvm_required_ack_set_decode(bytes, encoded_bytes, ack_set, error,
                                       error_len);
}

int main(void)
{
    char journal_path[] = "/tmp/wvm-rm-p7-add-member.XXXXXX";
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_controller controller;
    struct authorization_context authorization = {0};
    struct wvm_node_record node_a, node_b;
    struct wvm_gateway_record gateway;
    struct wvm_member_key key_a, key_b, key_gw;
    struct wvm_route_snapshot_key route_key;
    struct wvm_required_ack_entry ack_entries[2], decoded_ack[2];
    struct wvm_required_ack_set ack_set;
    struct wvm_route_transaction_record transaction;
    uint8_t op_id[WVM_IDENTITY_ID_BYTES];
    uint8_t digest_before[WVM_SHA256_DIGEST_BYTES];
    uint32_t gen_before;
    uint64_t topo_before, memb_before;
    size_t route_count_before;
    char error[256];
    int fd;
    const struct wvm_membership_controller_route_entry *route_after;
    const struct wvm_membership_controller_member_entry *member_b;
    uint32_t gw_ids_a[] = {7};
    uint32_t gw_ids_b[] = {7};
    size_t i;

    fd = mkstemp(journal_path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    fill_node(&node_a, gw_ids_a, 1, 17, 101);
    fill_node(&node_b, gw_ids_b, 1, 18, 102);
    fill_gateway(&gateway);


    memset(&key_a, 0, sizeof(key_a));
    key_a.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    key_a.role_id = 17;
    key_a.instance_id = 101;
    memset(&key_b, 0, sizeof(key_b));
    key_b.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    key_b.role_id = 18;
    key_b.instance_id = 102;
    memset(&key_gw, 0, sizeof(key_gw));
    key_gw.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    key_gw.role_id = 7;
    key_gw.instance_id = 701;

    wvm_membership_controller_init(&controller, members, 4, routes, 4,
                                   dependencies, 4, authorize, &authorization);
    if (wvm_membership_controller_open(&controller, journal_path, error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "open: %s\n", error);
        unlink(journal_path);
        return 1;
    }

    printf("add-member-no-rewrite: register A+gateway\n");
    if (wvm_membership_controller_register_node(&controller, &key_a, &node_a,
                                                error, sizeof(error)) != 0 ||
        wvm_membership_controller_register_gateway(&controller, &key_gw,
                                                   &gateway, error,
                                                   sizeof(error)) != 0) {
        fprintf(stderr, "register: %s\n", error);
        goto fail;
    }
    if (wvm_membership_controller_begin_validation(&controller, &key_a, error,
                                                   sizeof(error)) != 0 ||
        wvm_membership_controller_begin_validation(&controller, &key_gw, error,
                                                   sizeof(error)) != 0 ||
        wvm_membership_controller_report_self_health(
            &controller, &key_a, WVM_MEMBERSHIP_HEALTHY, error,
            sizeof(error)) != 0 ||
        wvm_membership_controller_report_self_health(
            &controller, &key_gw, WVM_MEMBERSHIP_HEALTHY, error,
            sizeof(error)) != 0 ||
        wvm_membership_controller_prepare_member(&controller, &key_a, error,
                                                 sizeof(error)) != 0 ||
        wvm_membership_controller_prepare_member(&controller, &key_gw, error,
                                                 sizeof(error)) != 0) {
        fprintf(stderr, "prepare A+GW: %s\n", error);
        goto fail;
    }

    memset(&route_key, 0, sizeof(route_key));
    route_key.scope_key.vm_id = 9001;
    route_key.scope_key.vm_incarnation = 1;
    route_key.scope_key.route_scope_id = 1;
    route_key.topology_revision = controller.topology_revision;
    route_key.route_generation = 1;
    memset(route_key.snapshot_digest, 0x5a, sizeof(route_key.snapshot_digest));

    if (build_ack_set(&ack_set, ack_entries, decoded_ack, &route_key, &key_a,
                      &node_a.control_endpoint, &key_gw, &gateway.endpoint,
                      error, sizeof(error)) != 0) {
        fprintf(stderr, "ack set: %s\n", error);
        goto fail;
    }

    memset(op_id, 0, sizeof(op_id));
    op_id[WVM_IDENTITY_ID_BYTES - 1] = 0x41;
    memset(&transaction, 0, sizeof(transaction));
    memcpy(transaction.operation_id, op_id, sizeof(op_id));
    transaction.route_snapshot_key = route_key;
    transaction.required_ack_set = ack_set;
    transaction.operation_retention_horizon_ms = 5000;
    transaction.state = WVM_ROUTE_TRANSACTION_PREPARING;

    printf("add-member-no-rewrite: activate VM route on A+GW\n");
    if (wvm_membership_controller_route_begin(&controller, &transaction, error,
                                              sizeof(error)) != 0 ||
        wvm_membership_controller_route_ack_prepare(&controller, op_id, &key_a,
                                                    error, sizeof(error)) != 0 ||
        wvm_membership_controller_route_ack_prepare(&controller, op_id, &key_gw,
                                                    error, sizeof(error)) != 0 ||
        wvm_membership_controller_route_commit(&controller, op_id, error,
                                               sizeof(error)) != 0 ||
        wvm_membership_controller_activate_member(&controller, &key_a, op_id,
                                                  error, sizeof(error)) != 0 ||
        wvm_membership_controller_activate_member(&controller, &key_gw, op_id,
                                                  error, sizeof(error)) != 0) {
        fprintf(stderr, "activate: %s\n", error);
        goto fail;
    }

    gen_before = route_key.route_generation;
    memcpy(digest_before, route_key.snapshot_digest, sizeof(digest_before));
    topo_before = controller.topology_revision;
    memb_before = controller.membership_revision;
    route_count_before = controller.route_count;

    printf("add-member-no-rewrite: register B (new member)\n");
    if (wvm_membership_controller_register_node(&controller, &key_b, &node_b,
                                                error, sizeof(error)) != 0) {
        fprintf(stderr, "register B: %s\n", error);
        goto fail;
    }

    if (controller.route_count != route_count_before) {
        fprintf(stderr, "FAIL: route_count changed %zu -> %zu\n",
                route_count_before, controller.route_count);
        goto fail;
    }
    route_after = NULL;
    for (i = 0; i < controller.route_count; i++) {
        if (memcmp(controller.routes[i].transaction.operation_id, op_id,
                   sizeof(op_id)) == 0) {
            route_after = &controller.routes[i];
            break;
        }
    }
    if (!route_after) {
        fprintf(stderr, "FAIL: activated route disappeared after join\n");
        goto fail;
    }
    if (route_after->transaction.route_snapshot_key.route_generation !=
            gen_before ||
        memcmp(route_after->transaction.route_snapshot_key.snapshot_digest,
               digest_before, sizeof(digest_before)) != 0 ||
        route_after->transaction.state != WVM_ROUTE_TRANSACTION_ACTIVATED) {
        fprintf(stderr, "FAIL: ACTIVATED route rewritten after join\n");
        goto fail;
    }
    if (controller.topology_revision < topo_before ||
        controller.membership_revision < memb_before) {
        fprintf(stderr, "FAIL: revisions went backwards\n");
        goto fail;
    }

    member_b = wvm_membership_controller_find(&controller, &key_b);
    if (!member_b ||
        member_b->node.desired_membership_state !=
            WVM_MANIFEST_MEMBER_PENDING) {
        fprintf(stderr, "FAIL: new member not PENDING after register\n");
        goto fail;
    }
    if (wvm_membership_controller_activate_member(&controller, &key_b, op_id,
                                                  error, sizeof(error)) == 0) {
        fprintf(stderr,
                "FAIL: B activated on pre-join route without rewrite txn\n");
        goto fail;
    }

    printf("PASS RM-P7-add-member-no-rewrite "
           "(join leaves ACTIVATED route gen=%u digest intact; "
           "B stays PENDING; cannot activate on old op)\n",
           gen_before);
    wvm_membership_controller_close(&controller);
    unlink(journal_path);
    return 0;

fail:
    wvm_membership_controller_close(&controller);
    unlink(journal_path);
    return 1;
}

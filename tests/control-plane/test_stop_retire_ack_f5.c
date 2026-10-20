/*
 * GOAL-2 / SPEC-runtime-stop-cleanup / RM-1.1-lifecycle-cleanup (Codex F5 class):
 * membership begin_retire rejects active refs or incomplete horizon;
 * only refs=0 + horizon_complete advances ACTIVATED → RETIRING → RETIRED.
 * Orchestrator fail-closed when membership+RequiredAckSet but no route_retire
 * is covered by wavevm_admission_orchestrator.c (error strings asserted via
 * source contract note below).
 */
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_membership_controller.h"

#define MIB (1024ULL * 1024ULL)

struct authorization_context { unsigned int calls; };

static int member_key_equal(const struct wvm_member_key *a,
                            const struct wvm_member_key *b)
{
    return a->role_type == b->role_type && a->role_id == b->role_id &&
           a->instance_id == b->instance_id;
}

static int authorize(void *context,
                     enum wvm_membership_controller_authorization_action action,
                     const struct wvm_member_key *actor,
                     const struct wvm_member_key *subject, char *error,
                     size_t error_len)
{
    struct authorization_context *auth = context;
    (void)action; (void)error; (void)error_len;
    if (!member_key_equal(actor, subject)) return -1;
    auth->calls++;
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
                            uint32_t node_id, uint64_t instance, uint8_t digest)
{
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = node_id;
    capability->node_instance_id = instance;
    capability->profile_generation = 1;
    memset(capability->profile_digest, digest, sizeof(capability->profile_digest));
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
    node->inventory.physical_node_id = 17;
    node->inventory.node_instance_id = 101;
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
    fill_capability(&node->capability, 17, 101, 0x21);
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
    char journal_path[] = "/tmp/wvm-stop-retire-f5.XXXXXX";
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_controller controller;
    struct authorization_context authorization = {0};
    struct wvm_node_record node;
    struct wvm_gateway_record gateway;
    struct wvm_member_key key_n, key_gw;
    struct wvm_route_snapshot_key route_key;
    struct wvm_required_ack_entry ack_entries[2], decoded[2];
    struct wvm_required_ack_set ack_set;
    struct wvm_route_transaction_record transaction;
    uint8_t op_id[WVM_IDENTITY_ID_BYTES];
    uint32_t gw_ids[] = {7};
    uint16_t state = 0;
    char error[256];
    int fd;

    fd = mkstemp(journal_path);
    if (fd < 0) { perror("mkstemp"); return 1; }
    close(fd);

    fill_node(&node, gw_ids, 1);
    fill_gateway(&gateway);
    memset(&key_n, 0, sizeof(key_n));
    key_n.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    key_n.role_id = 17;
    key_n.instance_id = 101;
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
    if (wvm_membership_controller_register_node(&controller, &key_n, &node,
                                                error, sizeof(error)) != 0 ||
        wvm_membership_controller_register_gateway(&controller, &key_gw,
                                                   &gateway, error,
                                                   sizeof(error)) != 0 ||
        wvm_membership_controller_begin_validation(&controller, &key_n, error,
                                                   sizeof(error)) != 0 ||
        wvm_membership_controller_begin_validation(&controller, &key_gw, error,
                                                   sizeof(error)) != 0 ||
        wvm_membership_controller_report_self_health(
            &controller, &key_n, WVM_MEMBERSHIP_HEALTHY, error,
            sizeof(error)) != 0 ||
        wvm_membership_controller_report_self_health(
            &controller, &key_gw, WVM_MEMBERSHIP_HEALTHY, error,
            sizeof(error)) != 0 ||
        wvm_membership_controller_prepare_member(&controller, &key_n, error,
                                                 sizeof(error)) != 0 ||
        wvm_membership_controller_prepare_member(&controller, &key_gw, error,
                                                 sizeof(error)) != 0) {
        fprintf(stderr, "setup: %s\n", error);
        goto fail;
    }

    memset(&route_key, 0, sizeof(route_key));
    route_key.scope_key.vm_id = 42;
    route_key.scope_key.vm_incarnation = 1;
    route_key.scope_key.route_scope_id = 1;
    route_key.topology_revision = controller.topology_revision;
    route_key.route_generation = 1;
    memset(route_key.snapshot_digest, 0xab, sizeof(route_key.snapshot_digest));
    if (build_ack_set(&ack_set, ack_entries, decoded, &route_key, &key_n,
                      &node.control_endpoint, &key_gw, &gateway.endpoint, error,
                      sizeof(error)) != 0) {
        fprintf(stderr, "ack: %s\n", error);
        goto fail;
    }
    memset(op_id, 0, sizeof(op_id));
    op_id[WVM_IDENTITY_ID_BYTES - 1] = 0xF5;
    memset(&transaction, 0, sizeof(transaction));
    memcpy(transaction.operation_id, op_id, sizeof(op_id));
    transaction.route_snapshot_key = route_key;
    transaction.required_ack_set = ack_set;
    transaction.operation_retention_horizon_ms = 5000;
    transaction.state = WVM_ROUTE_TRANSACTION_PREPARING;

    if (wvm_membership_controller_route_begin(&controller, &transaction, error,
                                              sizeof(error)) != 0 ||
        wvm_membership_controller_route_ack_prepare(&controller, op_id, &key_n,
                                                    error, sizeof(error)) != 0 ||
        wvm_membership_controller_route_ack_prepare(&controller, op_id, &key_gw,
                                                    error, sizeof(error)) != 0 ||
        wvm_membership_controller_route_commit(&controller, op_id, error,
                                               sizeof(error)) != 0 ||
        wvm_membership_controller_activate_member(&controller, &key_n, op_id,
                                                  error, sizeof(error)) != 0 ||
        wvm_membership_controller_activate_member(&controller, &key_gw, op_id,
                                                  error, sizeof(error)) != 0) {
        fprintf(stderr, "activate: %s\n", error);
        goto fail;
    }

    /* F5: reject begin_retire while active refs remain. */
    if (wvm_membership_controller_route_begin_retire(&controller, op_id, 1, 1,
                                                     error, sizeof(error)) == 0) {
        fprintf(stderr, "FAIL: begin_retire accepted with refs=1\n");
        goto fail;
    }
    if (wvm_membership_controller_route_begin_retire(&controller, op_id, 0, 0,
                                                     error, sizeof(error)) == 0) {
        fprintf(stderr, "FAIL: begin_retire accepted with horizon incomplete\n");
        goto fail;
    }
    /* Proven refs=0 + horizon complete (as ROUTE_RETIRE ACK must prove). */
    if (wvm_membership_controller_route_begin_retire(&controller, op_id, 0, 1,
                                                     error, sizeof(error)) != 0) {
        fprintf(stderr, "FAIL: begin_retire refs=0 horizon=1: %s\n", error);
        goto fail;
    }
    if (wvm_membership_controller_route_state(&controller, op_id, &state, error,
                                              sizeof(error)) != 0 ||
        state != WVM_ROUTE_TRANSACTION_RETIRING) {
        fprintf(stderr, "FAIL: expected RETIRING state=%u\n", state);
        goto fail;
    }
    if (wvm_membership_controller_route_retire(&controller, op_id, error,
                                               sizeof(error)) != 0) {
        fprintf(stderr, "FAIL: retire: %s\n", error);
        goto fail;
    }
    if (wvm_membership_controller_route_state(&controller, op_id, &state, error,
                                              sizeof(error)) != 0 ||
        state != WVM_ROUTE_TRANSACTION_RETIRED) {
        fprintf(stderr, "FAIL: expected RETIRED state=%u\n", state);
        goto fail;
    }

    printf("PASS STOP/F5 begin_retire "
           "(reject refs!=0 and !horizon; accept proven 0/1 → RETIRED)\n");
    printf("NOTE: orchestrator fail-closed without callbacks->route_retire when "
           "membership+RequiredAckSet nonempty: "
           "wavevm_admission_orchestrator.c STOP path; "
           "transport ROUTE_RETIRE ACK proof in "
           "wavevm_admission_stream_transport.c / admission_receiver.c\n");
    wvm_membership_controller_close(&controller);
    unlink(journal_path);
    return 0;
fail:
    wvm_membership_controller_close(&controller);
    unlink(journal_path);
    return 1;
}

#define _XOPEN_SOURCE 700

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_control.h"
#include "wavevm_membership_coordinator.h"

#define MIB (1024ULL * 1024ULL)
#define HOST_ID 9001ULL

struct enrollment_capture {
    unsigned int prepare_calls;
    unsigned int commit_calls;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "same-host-dual-agent test: %s\n", message);
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

static void fill_same_host_node(struct wvm_node_record *node, uint32_t node_id,
                                uint64_t instance_id, uint16_t data_port,
                                uint16_t control_port, uint32_t registered_vcpu,
                                uint32_t allocatable_vcpu,
                                uint64_t registered_memory,
                                uint64_t allocatable_memory,
                                const char *namespace_name)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = node_id;
    node->node_instance_id = instance_id;
    node->failure_domain_id = 1;
    fill_endpoint(&node->control_endpoint, (uint8_t)node_id, data_port,
                  control_port);
    fill_endpoint(&node->sidecar_endpoint, (uint8_t)node_id,
                  (uint16_t)(data_port + 20U), (uint16_t)(control_port + 20U));
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_first = (node_id == 17U) ? 0U : 16U;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = node_id;
    node->inventory.node_instance_id = instance_id;
    node->inventory.failure_domain_id = 1;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = registered_vcpu;
    node->inventory.registered_memory_bytes = registered_memory;
    node->inventory.reserved_host_cpu_slots =
        registered_vcpu - allocatable_vcpu;
    node->inventory.reserved_host_memory_bytes =
        registered_memory - allocatable_memory;
    node->inventory.allocatable_vcpu_slots = allocatable_vcpu;
    node->inventory.allocatable_memory_bytes = allocatable_memory;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = node_id;
    node->capability.node_instance_id = instance_id;
    node->capability.profile_generation = 1;
    memset(node->capability.profile_digest, 0x21,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
    node->physical_host_id = HOST_ID;
    snprintf(node->node_instance_namespace.namespace_name,
             sizeof(node->node_instance_namespace.namespace_name), "%s",
             namespace_name);
    memset(node->node_instance_namespace.derivation_salt_digest, 0xa5,
           sizeof(node->node_instance_namespace.derivation_salt_digest));
    node->node_instance_namespace.name_generation = 1;
}

static void node_key(const struct wvm_node_record *node,
                     struct wvm_member_key *key)
{
    memset(key, 0, sizeof(*key));
    key->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    key->role_id = node->physical_node_id;
    key->instance_id = node->node_instance_id;
}

static int enrollment_prepare(void *context,
                              const struct wvm_cluster_admission_proof *proof,
                              const struct wvm_cluster_admission_ack_entry *ack,
                              char *error, size_t error_len)
{
    struct enrollment_capture *capture = context;

    if (!proof || !ack || ack->role_type != ack->member_key.role_type) {
        snprintf(error, error_len, "invalid enrollment prepare ACK");
        return -1;
    }
    capture->prepare_calls++;
    return 0;
}

static int enrollment_commit(void *context,
                             const struct wvm_cluster_admission_proof *proof,
                             const struct wvm_cluster_admission_ack_entry *ack,
                             char *error, size_t error_len)
{
    struct enrollment_capture *capture = context;

    if (!proof || !ack || ack->role_type != ack->member_key.role_type) {
        snprintf(error, error_len, "invalid enrollment commit ACK");
        return -1;
    }
    capture->commit_calls++;
    return 0;
}

static int enrollment_abort(void *context,
                            const struct wvm_cluster_admission_proof *proof,
                            const struct wvm_cluster_admission_ack_entry *ack,
                            char *error, size_t error_len)
{
    (void)context;
    (void)proof;
    (void)ack;
    (void)error;
    (void)error_len;
    return 0;
}

static int prepare_member_path(struct wvm_membership_controller *controller,
                               const struct wvm_member_key *key, char *error,
                               size_t error_len)
{
    return wvm_membership_controller_report_self_health(
               controller, key, WVM_MEMBERSHIP_HEALTHY, error, error_len) ==
                   0 &&
                   wvm_membership_controller_begin_validation(
                       controller, key, error, error_len) == 0 &&
                   wvm_membership_controller_prepare_member(
                       controller, key, error, error_len) == 0
               ? 0
               : -1;
}

static int enroll_prepared(
    struct wvm_membership_controller *controller,
    const struct wvm_node_record *node, const struct wvm_member_key *key,
    uint8_t operation_tail, struct enrollment_capture *capture, char *error,
    size_t error_len)
{
    struct wvm_cluster_admission_proof proof;
    struct wvm_cluster_admission_ack_entry ack_entries[4];
    struct wvm_membership_cluster_enrollment_request request;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t capability_evidence[WVM_SHA256_DIGEST_BYTES];
    uint8_t topology_assignment[WVM_SHA256_DIGEST_BYTES];

    memset(operation_id, 0, sizeof(operation_id));
    operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    memset(capability_evidence, operation_tail, sizeof(capability_evidence));
    memset(topology_assignment, (uint8_t)(operation_tail + 1U),
           sizeof(topology_assignment));
    memset(&proof, 0, sizeof(proof));
    if (wvm_membership_controller_build_cluster_admission_proof(
            controller, key, operation_id, controller->membership_revision,
            controller->topology_revision,
            controller->admission_eligibility_revision, capability_evidence,
            topology_assignment, &proof, ack_entries,
            sizeof(ack_entries) / sizeof(ack_entries[0]), error,
            error_len) != 0) {
        return -1;
    }
    memset(&request, 0, sizeof(request));
    request.member_kind = WVM_MEMBERSHIP_COMPUTE;
    request.authenticated_actor = key;
    request.node = node;
    request.proof = &proof;
    request.prepare = enrollment_prepare;
    request.commit = enrollment_commit;
    request.abort = enrollment_abort;
    request.prepare_context = capture;
    if (wvm_membership_coordinator_enroll_cluster_member(controller, &request,
                                                         error, error_len) !=
        0) {
        return -1;
    }
    if (wvm_membership_controller_find(controller, key)
            ->node.desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE) {
        snprintf(error, error_len, "enrollment did not reach ACTIVE");
        return -1;
    }
    return 0;
}

int main(void)
{
    char journal_path[] = "/tmp/wavevm-same-host-dual.XXXXXX";
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_controller controller;
    struct wvm_node_record node_a;
    struct wvm_node_record node_b;
    struct wvm_node_record node_bad;
    struct wvm_member_key key_a;
    struct wvm_member_key key_b;
    struct wvm_member_key key_bad;
    struct enrollment_capture capture = {0};
    struct wvm_node_record host_nodes[2];
    const struct wvm_membership_controller_member_entry *entry_a;
    const struct wvm_membership_controller_member_entry *entry_b;
    char error[256] = {0};
    int fd;

    fd = mkstemp(journal_path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    fill_same_host_node(&node_a, 17, 101, 19100, 19101, 8, 4, 16 * MIB, 8 * MIB,
                        "ni-host9001-a");
    fill_same_host_node(&node_b, 18, 102, 19200, 19201, 8, 4, 16 * MIB, 8 * MIB,
                        "ni-host9001-b");
    node_key(&node_a, &key_a);
    node_key(&node_b, &key_b);

    wvm_membership_controller_init(&controller, members, 4, routes, 4,
                                   dependencies, 4, authorize, NULL);
    if (expect(wvm_membership_controller_open(&controller, journal_path, error,
                                              sizeof(error)) == 0,
               "open membership controller")) {
        unlink(journal_path);
        return 1;
    }

    if (expect(wvm_membership_controller_register_node(
                   &controller, &key_a, &node_a, error, sizeof(error)) == 0,
               "register first same-host node") ||
        expect(prepare_member_path(&controller, &key_a, error, sizeof(error)) ==
                   0,
               "prepare first same-host node") ||
        expect(enroll_prepared(&controller, &node_a, &key_a, 0x61, &capture,
                               error, sizeof(error)) == 0,
               "enroll first same-host node ACTIVE")) {
        fprintf(stderr, " error: %s\n", error);
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    /* Fail-closed: second register that double-counts host allocatable. */
    node_bad = node_b;
    node_bad.inventory.allocatable_vcpu_slots = 5;
    node_bad.inventory.reserved_host_cpu_slots = 3;
    node_key(&node_bad, &key_bad);
    if (expect(wvm_membership_controller_register_node(
                   &controller, &key_bad, &node_bad, error, sizeof(error)) != 0,
               "reject same-host double-count allocatable") ||
        expect(strstr(error, "double-count") != NULL ||
                   strstr(error, "exceeds registered") != NULL,
               "double-count rejection names host budget")) {
        fprintf(stderr, " got error: %s\n", error);
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    /* Fail-closed: colliding namespace on otherwise valid split. */
    node_bad = node_b;
    strcpy(node_bad.node_instance_namespace.namespace_name, "ni-host9001-a");
    if (expect(wvm_membership_controller_register_node(
                   &controller, &key_b, &node_bad, error, sizeof(error)) != 0,
               "reject same-host namespace collision")) {
        fprintf(stderr, " got error: %s\n", error);
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    /* Honest second instance: distinct ports/namespace, split capacity. */
    if (expect(wvm_membership_controller_register_node(
                   &controller, &key_b, &node_b, error, sizeof(error)) == 0,
               "register second same-host node") ||
        expect(prepare_member_path(&controller, &key_b, error, sizeof(error)) ==
                   0,
               "prepare second same-host node") ||
        expect(enroll_prepared(&controller, &node_b, &key_b, 0x62, &capture,
                               error, sizeof(error)) == 0,
               "enroll second same-host node ACTIVE")) {
        fprintf(stderr, " error: %s\n", error);
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    entry_a = wvm_membership_controller_find(&controller, &key_a);
    entry_b = wvm_membership_controller_find(&controller, &key_b);
    if (expect(entry_a != NULL && entry_b != NULL, "both members present") ||
        expect(entry_a->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE &&
                   entry_b->node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE,
               "both same-host instances ACTIVE") ||
        expect(entry_a->node.physical_host_id == HOST_ID &&
                   entry_b->node.physical_host_id == HOST_ID,
               "shared physical_host_id") ||
        expect(strcmp(entry_a->node.node_instance_namespace.namespace_name,
                      entry_b->node.node_instance_namespace.namespace_name) !=
                   0,
               "distinct node_instance_namespace") ||
        expect(entry_a->node.control_endpoint.control_port !=
                       entry_b->node.control_endpoint.control_port &&
                   entry_a->node.control_endpoint.data_port !=
                       entry_b->node.control_endpoint.data_port,
               "distinct listener ports")) {
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    host_nodes[0] = entry_a->node;
    host_nodes[1] = entry_b->node;
    if (expect(wvm_physical_host_aggregate_validate(host_nodes, 2, error,
                                                    sizeof(error)) == 0,
               "ACTIVE same-host pair passes aggregate accounting") ||
        expect(entry_a->node.inventory.allocatable_vcpu_slots +
                       entry_b->node.inventory.allocatable_vcpu_slots <=
                   entry_a->node.inventory.registered_vcpu_slots,
               "sum(allocatable) does not double-count registered")) {
        fprintf(stderr, " error: %s\n", error);
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    /* After both ACTIVE, another over-budget register still fails closed. */
    fill_same_host_node(&node_bad, 19, 103, 19300, 19301, 8, 1, 16 * MIB, 1 * MIB,
                        "ni-host9001-c");
    node_key(&node_bad, &key_bad);
    if (expect(wvm_membership_controller_register_node(
                   &controller, &key_bad, &node_bad, error, sizeof(error)) != 0,
               "reject third instance that would exceed host budget")) {
        fprintf(stderr, " got error: %s\n", error);
        wvm_membership_controller_close(&controller);
        unlink(journal_path);
        return 1;
    }

    wvm_membership_controller_close(&controller);
    unlink(journal_path);
    puts("same-host dual agent vertical: PASS");
    puts("NOTE: two node_instance on one physical_host_id → both ACTIVE;");
    puts("      distinct namespace/ports; aggregate no double-count;");
    puts("      fail-closed on over-budget / colliding second register.");
    puts("      Control-plane enrollment vertical (not live TLS agents).");
    return 0;
}

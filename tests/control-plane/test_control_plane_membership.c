#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_control_plane.h"
#include "wavevm_canonical.h"

#define MIB (1024ULL * 1024ULL)

struct authorization_context {
    unsigned int calls;
};

struct result_context {
    unsigned int calls;
    struct wvm_membership_control_result result;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "control-plane membership test: %s\n", message);
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

static int authorize_self(
    void *context, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    struct authorization_context *authorization = context;

    (void)action;
    (void)error;
    (void)error_len;
    if (!authorization || !member_key_equal(actor, subject)) {
        return -1;
    }
    authorization->calls++;
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = 17;
    endpoint->data_port = 19120;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = 19121;
}

static void fill_node(struct wvm_node_record *node)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = 17;
    node->node_instance_id = 101;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint);
    fill_endpoint(&node->sidecar_endpoint);
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

static int result_sink(void *context, const struct wvm_envelope *request,
                       const struct wvm_membership_control_result *result,
                       char *error, size_t error_len)
{
    struct result_context *capture = context;

    (void)error;
    (void)error_len;
    if (!capture || !request || !result ||
        memcmp(request->operation_id, result->in_reply_to_operation_id,
               sizeof(request->operation_id)) != 0) {
        return -1;
    }
    capture->calls++;
    capture->result = *result;
    return 0;
}

static void make_register_request(struct wvm_envelope *request,
                                  const uint8_t *payload, size_t payload_bytes)
{
    memset(request, 0, sizeof(*request));
    request->message_type = WVM_ENVELOPE_MSG_REGISTER_MEMBER;
    request->origin_physical_node_id = 17;
    request->origin_runtime_instance_id = 101;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 request->semantic_payload_digest);
}

static void configure_owner(
    struct wvm_control_plane *plane,
    struct wvm_control_plane_entry entries[1],
    struct wvm_membership_controller_member_entry members[2],
    struct wvm_membership_controller_route_entry routes[2],
    struct wvm_membership_dependency dependencies[2],
    struct wvm_membership_control_operation operations[2],
    const char *membership_path, const char *control_path,
    struct authorization_context *authorization,
    struct result_context *results)
{
    struct wvm_control_plane_membership_config config;

    memset(&config, 0, sizeof(config));
    config.members = members;
    config.member_capacity = 2;
    config.routes = routes;
    config.route_capacity = 2;
    config.dependencies = dependencies;
    config.dependency_capacity = 2;
    config.operations = operations;
    config.operation_capacity = 2;
    config.membership_journal_path = membership_path;
    config.control_journal_path = control_path;
    config.authorize = authorize_self;
    config.authorize_context = authorization;
    config.result_sink = result_sink;
    config.result_sink_context = results;
    wvm_control_plane_init(plane, entries, 1);
    (void)wvm_control_plane_configure_membership(plane, &config, NULL, 0);
}

int main(void)
{
    char admission_path[128];
    char membership_path[128];
    char control_path[128];
    struct wvm_control_plane plane;
    struct wvm_control_plane recovered;
    struct wvm_control_plane_entry entries[1];
    struct wvm_control_plane_entry recovered_entries[1];
    struct wvm_vm_namespace_record namespace_records[4];
    struct wvm_vm_namespace_record recovered_namespace_records[4];
    struct wvm_vm_namespace_allocator namespace_allocator;
    struct wvm_vm_namespace_allocator recovered_namespace_allocator;
    struct wvm_membership_controller_member_entry members[2];
    struct wvm_membership_controller_member_entry recovered_members[2];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_controller_route_entry recovered_routes[2];
    struct wvm_membership_dependency dependencies[2];
    struct wvm_membership_dependency recovered_dependencies[2];
    struct wvm_membership_control_operation operations[2];
    struct wvm_membership_control_operation recovered_operations[2];
    struct wvm_node_record node;
    struct wvm_member_key actor;
    struct wvm_envelope request;
    struct authorization_context authorization = {0};
    struct authorization_context recovered_authorization = {0};
    struct result_context results = {0};
    struct result_context recovered_results = {0};
    uint8_t node_bytes[8192];
    size_t node_byte_count = 0;
    char error[256] = {0};
    uint16_t first_state;
    uint64_t first_revision;

    if (snprintf(admission_path, sizeof(admission_path),
                 "/tmp/wavevm-owner-admission-%ld", (long)getpid()) < 0 ||
        snprintf(membership_path, sizeof(membership_path),
                 "/tmp/wavevm-owner-membership-%ld", (long)getpid()) < 0 ||
        snprintf(control_path, sizeof(control_path),
                 "/tmp/wavevm-owner-control-%ld", (long)getpid()) < 0) {
        return 1;
    }
    unlink(admission_path);
    unlink(membership_path);
    unlink(control_path);

    fill_node(&node);
    memset(&actor, 0, sizeof(actor));
    actor.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    actor.role_id = node.physical_node_id;
    actor.instance_id = node.node_instance_id;
    if (expect(wvm_node_record_encode(&node, node_bytes, sizeof(node_bytes),
                                      &node_byte_count, error,
                                      sizeof(error)) == 0,
               "encode canonical registration") != 0) {
        return 1;
    }
    make_register_request(&request, node_bytes, node_byte_count);

    configure_owner(&plane, entries, members, routes, dependencies, operations,
                    membership_path, control_path, &authorization, &results);
    wvm_vm_namespace_allocator_init(&namespace_allocator, namespace_records,
                                    sizeof(namespace_records) /
                                        sizeof(namespace_records[0]),
                                    1);
    if (expect(plane.membership_configured,
               "configure one membership owner") != 0 ||
        expect(wvm_control_plane_open_membership(&plane, error,
                                                 sizeof(error)) == 0,
               "open owner journals") != 0 ||
        expect(wvm_control_plane_open(&plane, admission_path,
                                      &namespace_allocator, error,
                                      sizeof(error)) == 0,
               "open admission journal with same membership authority") != 0 ||
        expect(wvm_control_plane_membership_dispatch(
                   &plane, &request, &actor, error, sizeof(error)) == 0,
               "dispatch registration through owner") != 0 ||
        expect(results.calls == 1 &&
                   results.result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   results.result.recorded_state ==
                       WVM_MANIFEST_MEMBER_PENDING,
               "deliver typed registration result") != 0 ||
        expect(authorization.calls == 1,
               "use controller authorization from owner") != 0) {
        wvm_control_plane_close(&plane);
        unlink(admission_path);
        unlink(membership_path);
        unlink(control_path);
        return 1;
    }
    first_state = results.result.recorded_state;
    first_revision = results.result.applied_revision;
    wvm_control_plane_close(&plane);

    configure_owner(&recovered, recovered_entries, recovered_members,
                    recovered_routes, recovered_dependencies,
                    recovered_operations, membership_path, control_path,
                    &recovered_authorization, &recovered_results);
    wvm_vm_namespace_allocator_init(
        &recovered_namespace_allocator, recovered_namespace_records,
        sizeof(recovered_namespace_records) /
            sizeof(recovered_namespace_records[0]),
        1);
    if (expect(wvm_control_plane_open_membership(&recovered, error,
                                                 sizeof(error)) == 0,
               "recover owner journals") != 0 ||
        expect(wvm_control_plane_open(&recovered, admission_path,
                                      &recovered_namespace_allocator, error,
                                      sizeof(error)) == 0,
               "recover admission journal with membership authority") != 0 ||
        expect(wvm_control_plane_membership_dispatch(
                   &recovered, &request, &actor, error, sizeof(error)) == 0,
               "replay registration through recovered owner") != 0 ||
        expect(recovered_results.calls == 1 &&
                   recovered_results.result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   recovered_results.result.recorded_state == first_state &&
                   recovered_results.result.applied_revision == first_revision,
               "recovered owner returns the durable replay result") != 0 ||
        expect(recovered_authorization.calls == 0,
               "replay does not re-authorize or mutate membership") != 0) {
        wvm_control_plane_close(&recovered);
        unlink(admission_path);
        unlink(membership_path);
        unlink(control_path);
        return 1;
    }
    if (expect(wvm_membership_controller_find(
                   &recovered.membership_controller, &actor) != NULL,
               "recovered owner retains registered member") != 0) {
        wvm_control_plane_close(&recovered);
        unlink(admission_path);
        unlink(membership_path);
        unlink(control_path);
        return 1;
    }
    wvm_control_plane_close(&recovered);
    unlink(admission_path);
    unlink(membership_path);
    unlink(control_path);
    return 0;
}

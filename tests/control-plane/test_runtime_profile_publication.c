#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "runtime_profile_publication.h"

#define MIB (1024ULL * 1024ULL)

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "runtime-profile-publication test: %s\n", message);
        return -1;
    }
    return 0;
}

static int authorize(
    void *context, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    (void)context;
    (void)action;
    (void)error;
    (void)error_len;
    return actor->role_type == subject->role_type &&
                   actor->role_id == subject->role_id &&
                   actor->instance_id == subject->instance_id
               ? 0
               : -1;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint16_t data_port,
                          uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 127;
    endpoint->data_address[3] = 1;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_node(struct wvm_node_record *node, uint32_t node_id,
                      uint64_t instance_id, uint16_t port_base)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = node_id;
    node->node_instance_id = instance_id;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint, port_base, port_base + 1U);
    fill_endpoint(&node->sidecar_endpoint, port_base + 2U, port_base + 3U);
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_count = 8;
    node->inventory.physical_node_id = node_id;
    node->inventory.node_instance_id = instance_id;
    node->inventory.failure_domain_id = 3;
    node->inventory.inventory_revision = 3;
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
    node->capability.physical_node_id = node_id;
    node->capability.node_instance_id = instance_id;
    node->capability.profile_generation = 5;
    memset(node->capability.profile_digest, 0x21,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
}

static void fill_profile(struct wvm_node_runtime_profile *profile,
                         const struct wvm_node_record *node,
                         uint16_t data_ports[2], uint16_t service_ports[2])
{
    memset(profile, 0, sizeof(*profile));
    profile->physical_node_id = node->physical_node_id;
    profile->node_instance_id = node->node_instance_id;
    profile->inventory_revision = node->inventory.inventory_revision;
    profile->capability_profile_generation =
        node->capability.profile_generation;
    profile->runtime_profile_generation = 7;
    profile->node_runtime_control_port = data_ports[0] - 2U;
    profile->local_executor_control_port = data_ports[0] - 1U;
    profile->executor_worker_count = 4;
    profile->sync_batch_size = 64;
    profile->vcpu_handoff_record_capacity = 128;
    profile->node_runtime_data_ports = data_ports;
    profile->node_runtime_data_port_count = 2;
    profile->local_executor_service_ports = service_ports;
    profile->local_executor_service_port_count = 2;
}

static int encode_request(const struct wvm_node_runtime_profile *profile,
                          uint8_t *bytes, size_t capacity,
                          struct wvm_envelope *request, char *error,
                          size_t error_len)
{
    size_t encoded_bytes;

    if (wvm_node_runtime_profile_encode(profile, bytes, capacity,
                                        &encoded_bytes, error,
                                        error_len) != 0) {
        return -1;
    }
    memset(request, 0, sizeof(*request));
    request->message_type = WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE;
    request->origin_physical_node_id = profile->physical_node_id;
    request->origin_runtime_instance_id = profile->node_instance_id;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
    request->delivery_attempt_id = 1;
    request->payload = bytes;
    request->payload_bytes = encoded_bytes;
    wvm_envelope_semantic_digest(bytes, encoded_bytes,
                                 request->semantic_payload_digest);
    return 0;
}

static void fill_actor(struct wvm_member_key *actor,
                       const struct wvm_node_record *node)
{
    memset(actor, 0, sizeof(*actor));
    actor->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    actor->role_id = node->physical_node_id;
    actor->instance_id = node->node_instance_id;
}

int main(void)
{
    char state_directory[] = "/tmp/wavevm-runtime-profile-publication.XXXXXX";
    char path[512];
    char error[256] = {0};
    struct wvm_membership_controller_member_entry members[2];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_dependency dependencies[2];
    struct wvm_membership_controller controller;
    struct wvm_node_record node1, node2, capture_nodes[2];
    struct wvm_gateway_record capture_gateways[1];
    struct wvm_membership_controller_capture capture = {0};
    struct wvm_node_runtime_profile profile1, profile2, loaded = {0};
    struct wvm_ctl_runtime_profile_set set = {0};
    struct wvm_member_key actor1, actor2, stale_actor;
    struct wvm_envelope request;
    struct wvm_control_result result;
    uint16_t data1[2] = {19102, 19103};
    uint16_t service1[2] = {19110, 19111};
    uint16_t data2[2] = {19202, 19203};
    uint16_t service2[2] = {19210, 19211};
    uint8_t bytes[4096];
    int rc = 1;

    if (!mkdtemp(state_directory) ||
        snprintf(path, sizeof(path), "%s/membership.journal",
                 state_directory) >= (int)sizeof(path)) {
        return 1;
    }
    fill_node(&node1, 17, 101, 18100);
    fill_node(&node2, 9, 202, 18200);
    fill_profile(&profile1, &node1, data1, service1);
    fill_profile(&profile2, &node2, data2, service2);
    fill_actor(&actor1, &node1);
    fill_actor(&actor2, &node2);
    wvm_membership_controller_init(&controller, members, 2, routes, 2,
                                   dependencies, 2, authorize, NULL);
    if (expect(wvm_membership_controller_open(
                   &controller, path, error, sizeof(error)) == 0,
               "open membership authority") ||
        expect(wvm_membership_controller_register_node(
                   &controller, &actor1, &node1, error, sizeof(error)) == 0,
               "register first publisher") ||
        expect(wvm_membership_controller_register_node(
                   &controller, &actor2, &node2, error, sizeof(error)) == 0,
               "register second publisher") ||
        expect(encode_request(&profile1, bytes, sizeof(bytes), &request,
                              error, sizeof(error)) == 0,
               "encode first publication") ||
        expect(wvm_ctl_publish_runtime_profile(
                   state_directory, &controller, &request, &actor1, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_SUCCESS &&
                   result.applied_revision == 7,
               "publish an authenticated profile")) {
        goto out_controller;
    }

    stale_actor = actor1;
    stale_actor.instance_id++;
    profile1.node_instance_id = stale_actor.instance_id;
    if (expect(encode_request(&profile1, bytes, sizeof(bytes), &request,
                              error, sizeof(error)) == 0,
               "encode stale-instance publication")) {
        goto out_controller;
    }
    request.origin_runtime_instance_id = stale_actor.instance_id;
    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_publish_runtime_profile(
                   state_directory, &controller, &request, &stale_actor,
                   &result, error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_STALE_INSTANCE,
               "reject a stale node instance")) {
        goto out_controller;
    }
    profile1.node_instance_id = node1.node_instance_id;

    profile1.inventory_revision++;
    memset(error, 0, sizeof(error));
    if (expect(encode_request(&profile1, bytes, sizeof(bytes), &request,
                              error, sizeof(error)) == 0,
               "encode stale-inventory publication") ||
        expect(wvm_ctl_publish_runtime_profile(
                   state_directory, &controller, &request, &actor1, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_PRECONDITION_FAILED,
               "reject a stale inventory revision")) {
        goto out_controller;
    }
    profile1.inventory_revision--;
    profile1.capability_profile_generation++;
    memset(error, 0, sizeof(error));
    if (expect(encode_request(&profile1, bytes, sizeof(bytes), &request,
                              error, sizeof(error)) == 0,
               "encode stale-capability publication") ||
        expect(wvm_ctl_publish_runtime_profile(
                   state_directory, &controller, &request, &actor1, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_PRECONDITION_FAILED,
               "reject a stale capability generation")) {
        goto out_controller;
    }
    profile1.capability_profile_generation--;

    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_load_runtime_profile(
                   state_directory, &node1, &loaded, error,
                   sizeof(error)) == 0,
               "reload the accepted durable profile") ||
        expect(loaded.runtime_profile_generation == 7 &&
                   loaded.physical_node_id == node1.physical_node_id,
               "preserve accepted profile after rejected updates") ||
        expect(encode_request(&profile2, bytes, sizeof(bytes), &request,
                              error, sizeof(error)) == 0,
               "encode second publication") ||
        expect(wvm_ctl_publish_runtime_profile(
                   state_directory, &controller, &request, &actor2, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_SUCCESS,
               "publish second profile")) {
        goto out_controller;
    }

    capture.nodes = capture_nodes;
    capture.node_capacity = 2;
    capture.gateways = capture_gateways;
    capture.gateway_capacity = 1;
    memset(error, 0, sizeof(error));
    if (expect(wvm_membership_controller_capture(
                   &controller, &capture, error, sizeof(error)) == 0 &&
                   capture.node_count == 2,
               "capture both registered nodes") ||
        expect(wvm_ctl_load_runtime_profile_set(
                   state_directory, &capture, &set, error, sizeof(error)) == 0 &&
                   set.profile_count == 2,
               "load one complete runtime-profile set")) {
        goto out_controller;
    }

    snprintf(path, sizeof(path), "%s/runtime-profile-%u.record",
             state_directory, node2.physical_node_id);
    unlink(path);
    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_load_runtime_profile_set(
                   state_directory, &capture, &set, error, sizeof(error)) != 0 &&
                   set.profile_count == 2,
               "missing profile does not replace the prior complete set")) {
        goto out_controller;
    }
    if (expect(encode_request(&profile2, bytes, sizeof(bytes), &request,
                              error, sizeof(error)) == 0,
               "re-encode second publication") ||
        expect(wvm_ctl_publish_runtime_profile(
                   state_directory, &controller, &request, &actor2, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_SUCCESS,
               "restore second durable profile")) {
        goto out_controller;
    }
    capture.nodes[0].inventory.inventory_revision++;
    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_load_runtime_profile_set(
                   state_directory, &capture, &set, error, sizeof(error)) != 0 &&
                   set.profile_count == 2,
               "stale profile does not replace the prior complete set")) {
        goto out_controller;
    }
    rc = 0;

out_controller:
    wvm_ctl_runtime_profile_set_destroy(&set);
    wvm_node_runtime_profile_destroy(&loaded);
    wvm_membership_controller_close(&controller);
    snprintf(path, sizeof(path), "%s/runtime-profile-9.record",
             state_directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/runtime-profile-17.record",
             state_directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/membership.journal", state_directory);
    unlink(path);
    rmdir(state_directory);
    if (rc == 0) {
        puts("runtime-profile-publication tests: PASS");
    } else if (error[0]) {
        fprintf(stderr, "runtime-profile-publication test detail: %s\n",
                error);
    }
    return rc;
}

#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "capability_publication.h"
#include "wavevm_canonical.h"

#define MIB (1024ULL * 1024ULL)

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "capability-publication test: %s\n", message);
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

static void fill_capability(struct wvm_capability_record *record)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = WVM_CAPABILITY_ID_EXECUTION_TCG;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = 17;
    record->node_instance_id = 101;
    record->provider_instance_id = 301;
    record->state = WVM_CAPABILITY_AVAILABLE;
    record->abi_version = 1;
    record->feature_bits = 1;
    record->observed_at = 1000;
    record->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
}

static int fill_node(struct wvm_node_record *node,
                     const struct wvm_capability_report *report, char *error,
                     size_t error_len)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = report->records[0].physical_node_id;
    node->node_instance_id = report->records[0].node_instance_id;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint, 19100, 19101);
    fill_endpoint(&node->sidecar_endpoint, 19120, 19121);
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_count = 8;
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
    node->capability.physical_node_id = node->physical_node_id;
    node->capability.node_instance_id = node->node_instance_id;
    node->capability.profile_generation = report->profile_generation;
    if (wvm_capability_profile_digest(
            node->physical_node_id, node->node_instance_id,
            report->profile_generation, report->records, report->record_count,
            node->capability.profile_digest, error, error_len) != 0) {
        return -1;
    }
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
    return 0;
}

static int encode_request(const struct wvm_capability_report *report,
                          uint8_t *bytes, size_t capacity,
                          struct wvm_envelope *request, char *error,
                          size_t error_len)
{
    size_t encoded_bytes;

    if (wvm_capability_report_encode(report, bytes, capacity, &encoded_bytes,
                                     error, error_len) != 0) {
        return -1;
    }
    memset(request, 0, sizeof(*request));
    request->message_type = WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES;
    request->origin_physical_node_id = report->records[0].physical_node_id;
    request->origin_runtime_instance_id = report->records[0].node_instance_id;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
    request->delivery_attempt_id = 1;
    request->payload = bytes;
    request->payload_bytes = encoded_bytes;
    wvm_envelope_semantic_digest(bytes, encoded_bytes,
                                 request->semantic_payload_digest);
    return 0;
}

int main(void)
{
    char state_directory[] = "/tmp/wavevm-capability-publication.XXXXXX";
    char journal_path[512];
    char error[256] = {0};
    struct wvm_membership_controller_member_entry members[2];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_dependency dependencies[2];
    struct wvm_membership_controller controller;
    struct wvm_capability_record capability;
    struct wvm_capability_record capability2;
    struct wvm_capability_report report;
    struct wvm_capability_report report2;
    struct wvm_capability_report loaded = {0};
    struct wvm_ctl_capability_evidence evidence = {0};
    struct wvm_node_record node;
    struct wvm_node_record node2;
    struct wvm_node_record capture_nodes[2];
    struct wvm_gateway_record capture_gateways[1];
    struct wvm_membership_controller_capture capture = {0};
    struct wvm_member_key actor;
    struct wvm_member_key actor2;
    struct wvm_member_key stale_actor;
    struct wvm_envelope request;
    struct wvm_control_result result;
    uint8_t bytes[4096];
    int rc = 1;

    if (!mkdtemp(state_directory)) {
        perror("mkdtemp");
        return 1;
    }
    if (snprintf(journal_path, sizeof(journal_path), "%s/membership.journal",
                 state_directory) >= (int)sizeof(journal_path)) {
        goto out_directory;
    }
    fill_capability(&capability);
    memset(&report, 0, sizeof(report));
    report.profile_generation = 3;
    report.records = &capability;
    report.record_count = 1;
    if (fill_node(&node, &report, error, sizeof(error)) != 0) {
        goto out_directory;
    }
    memset(&actor, 0, sizeof(actor));
    actor.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    actor.role_id = node.physical_node_id;
    actor.instance_id = node.node_instance_id;

    wvm_membership_controller_init(&controller, members, 2, routes, 2,
                                   dependencies, 2, authorize, NULL);
    if (expect(wvm_membership_controller_open(
                   &controller, journal_path, error, sizeof(error)) == 0,
               "open membership authority") ||
        expect(wvm_membership_controller_register_node(
                   &controller, &actor, &node, error, sizeof(error)) == 0,
               "register capability publisher") ||
        expect(encode_request(&report, bytes, sizeof(bytes), &request, error,
                              sizeof(error)) == 0,
               "encode publication request") ||
        expect(wvm_ctl_publish_capabilities(
                   state_directory, &controller, &request, &actor, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_SUCCESS &&
                   result.applied_revision == report.profile_generation,
               "publish matching registered capability profile")) {
        goto out_controller;
    }

    stale_actor = actor;
    stale_actor.instance_id++;
    request.origin_runtime_instance_id = stale_actor.instance_id;
    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_publish_capabilities(
                   state_directory, &controller, &request, &stale_actor,
                   &result, error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_STALE_INSTANCE,
               "reject a stale node instance")) {
        goto out_controller;
    }

    capability.feature_bits++;
    memset(error, 0, sizeof(error));
    if (expect(encode_request(&report, bytes, sizeof(bytes), &request, error,
                              sizeof(error)) == 0,
               "encode mismatched profile") ||
        expect(wvm_ctl_publish_capabilities(
                   state_directory, &controller, &request, &actor, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_PRECONDITION_FAILED,
               "reject a report with the wrong profile digest")) {
        goto out_controller;
    }
    capability.feature_bits--;

    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_load_capabilities(
                   state_directory, &node.capability, &loaded, error,
                   sizeof(error)) == 0,
               "load durable capability publication after restart") ||
        expect(loaded.profile_generation == report.profile_generation &&
                   loaded.record_count == 1 &&
                   loaded.records[0].physical_node_id == node.physical_node_id &&
                   loaded.records[0].node_instance_id == node.node_instance_id &&
                   loaded.records[0].feature_bits == 1,
               "preserve the accepted profile across reload")) {
        goto out_controller;
    }

    capability2 = capability;
    capability2.physical_node_id = 9;
    capability2.node_instance_id = 202;
    capability2.provider_instance_id = 302;
    capability2.probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] = 2;
    memset(&report2, 0, sizeof(report2));
    report2.profile_generation = report.profile_generation;
    report2.records = &capability2;
    report2.record_count = 1;
    if (fill_node(&node2, &report2, error, sizeof(error)) != 0) {
        goto out_controller;
    }
    node2.control_endpoint.data_port = 19200;
    node2.control_endpoint.control_port = 19201;
    node2.sidecar_endpoint.data_port = 19220;
    node2.sidecar_endpoint.control_port = 19221;
    memset(&actor2, 0, sizeof(actor2));
    actor2.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    actor2.role_id = node2.physical_node_id;
    actor2.instance_id = node2.node_instance_id;
    memset(error, 0, sizeof(error));
    if (expect(wvm_membership_controller_register_node(
                   &controller, &actor2, &node2, error, sizeof(error)) == 0,
               "register a second capability publisher") ||
        expect(encode_request(&report2, bytes, sizeof(bytes), &request, error,
                              sizeof(error)) == 0,
               "encode the second publication request") ||
        expect(wvm_ctl_publish_capabilities(
                   state_directory, &controller, &request, &actor2, &result,
                   error, sizeof(error)) == 0 &&
                   result.status_code == WVM_CONTROL_RESULT_SUCCESS,
               "publish the second registered capability profile")) {
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
               "capture both registered compute nodes") ||
        expect(wvm_ctl_load_capability_evidence(
                   state_directory, &capture, &evidence, error,
                   sizeof(error)) == 0,
               "aggregate durable reports for one membership capture") ||
        expect(evidence.record_count == 2 &&
                   evidence.inventory_revision == 1 &&
                   evidence.profile_generation == report.profile_generation &&
                   evidence.records[0].physical_node_id == 9 &&
                   evidence.records[1].physical_node_id == 17,
               "sort the aggregate by canonical capability key")) {
        goto out_controller;
    }

    capture.nodes[1].capability.profile_generation++;
    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_load_capability_evidence(
                   state_directory, &capture, &evidence, error,
                   sizeof(error)) != 0 && evidence.record_count == 2,
               "reject mixed profile generations without replacing evidence")) {
        goto out_controller;
    }
    capture.nodes[1].capability.profile_generation--;
    capture.nodes[1].inventory.inventory_revision++;
    memset(error, 0, sizeof(error));
    if (expect(wvm_ctl_load_capability_evidence(
                   state_directory, &capture, &evidence, error,
                   sizeof(error)) != 0 && evidence.record_count == 2,
               "reject mixed inventory revisions without replacing evidence")) {
        goto out_controller;
    }
    rc = 0;

out_controller:
    wvm_ctl_capability_evidence_destroy(&evidence);
    wvm_capability_report_destroy(&loaded);
    wvm_membership_controller_close(&controller);
out_directory:
    snprintf(journal_path, sizeof(journal_path),
             "%s/capabilities-9.record", state_directory);
    unlink(journal_path);
    snprintf(journal_path, sizeof(journal_path),
             "%s/capabilities-17.record", state_directory);
    unlink(journal_path);
    snprintf(journal_path, sizeof(journal_path), "%s/membership.journal",
             state_directory);
    unlink(journal_path);
    rmdir(state_directory);
    if (rc == 0) {
        puts("capability-publication tests: PASS");
    } else if (error[0]) {
        fprintf(stderr, "capability-publication test detail: %s\n", error);
    }
    return rc;
}

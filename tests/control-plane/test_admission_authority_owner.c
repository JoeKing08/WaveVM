#include <stdio.h>
#include <string.h>

#include "wavevm_admission_authority_owner.h"
#include "wavevm_canonical.h"

struct workspace_state {
    unsigned resets;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "admission-authority-owner test: %s\n", message);
        return -1;
    }
    return 0;
}

static int reset_workspace(
    void *context, const struct wvm_vm_request *request,
    struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_activation_record *activation,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len)
{
    struct workspace_state *state = context;

    (void)error;
    (void)error_len;
    if (!state || !request || !prepared_route || !prepared_vm ||
        !activation || !route_transaction || !route_snapshot) {
        return -1;
    }
    memset(prepared_route, 0, sizeof(*prepared_route));
    memset(prepared_vm, 0, sizeof(*prepared_vm));
    memset(activation, 0, sizeof(*activation));
    memset(route_transaction, 0, sizeof(*route_transaction));
    memset(route_snapshot, 0, sizeof(*route_snapshot));
    state->resets++;
    return 0;
}

static int resolve_node(void *context, uint32_t physical_node_id,
                        uint64_t node_instance_id,
                        struct wvm_admission_transport_target *target,
                        char *error, size_t error_len)
{
    (void)context;
    (void)physical_node_id;
    (void)node_instance_id;
    (void)target;
    (void)error;
    (void)error_len;
    return -1;
}

static int submit(void *context,
                  const struct wvm_admission_transport_target *target,
                  const struct wvm_envelope *envelope, char *error,
                  size_t error_len)
{
    (void)context;
    (void)target;
    (void)envelope;
    (void)error;
    (void)error_len;
    return -1;
}

static void fill_machine(struct wvm_machine_config *machine)
{
    memset(machine, 0, sizeof(*machine));
    strcpy(machine->architecture, "x86_64");
    strcpy(machine->machine_type, "pc-i440fx-5.2");
    machine->qemu_compat_version = 502;
    machine->firmware_policy = 1;
}

static void fill_launch(struct wvm_coordinator_node_launch_plan *launch)
{
    memset(launch, 0, sizeof(*launch));
    launch->physical_node_id = 17;
    launch->expected_node_instance_id = 101;
    launch->launch_plan.plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
    launch->launch_plan.node_runtime_data_port = 19100;
    launch->launch_plan.node_runtime_control_port = 19121;
    launch->launch_plan.local_executor_service_port = 19105;
    launch->launch_plan.local_executor_control_port = 19121;
    launch->launch_plan.executor_worker_count = 1;
    launch->launch_plan.vcpu_handoff_record_capacity = 16;
    launch->launch_plan.sync_batch_size = 1;
    launch->launch_plan.guest_total_memory_bytes = 4096;
    fill_machine(&launch->launch_plan.guest_machine);
    launch->launch_plan.consistency_policy.dirty_batch_size = 1;
    launch->launch_plan.consistency_policy.handoff_commit_policy = 1;
    launch->launch_plan.consistency_policy.subscriber_delivery_policy = 1;
    launch->launch_plan.consistency_policy.max_commit_latency_ms = 1000;
}

static void fill_listener(struct wvm_admission_node_listener_plan *listener,
                          const struct wvm_coordinator_node_launch_plan *launch,
                          struct wvm_exclusive_lease leases[2])
{
    memset(listener, 0, sizeof(*listener));
    listener->physical_node_id = launch->physical_node_id;
    listener->expected_node_instance_id = launch->expected_node_instance_id;
    listener->node_runtime_data_port =
        launch->launch_plan.node_runtime_data_port;
    listener->local_executor_service_port =
        launch->launch_plan.local_executor_service_port;
    listener->lease_generation = 1;
    listener->lease_entries = leases;
    listener->lease_capacity = 2;
}

static void fill_capability(struct wvm_capability_record *capability)
{
    memset(capability, 0, sizeof(*capability));
    capability->capability_id = WVM_CAPABILITY_ID_EXECUTION_TCG;
    capability->capability_schema_version = WVM_CANONICAL_SCHEMA;
    capability->physical_node_id = 17;
    capability->node_instance_id = 101;
    capability->provider_instance_id = 301;
    capability->state = WVM_CAPABILITY_AVAILABLE;
    capability->abi_version = 1;
    capability->observed_at = 1000;
    capability->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
}

int main(void)
{
    struct wvm_membership_controller membership_controller;
    struct wvm_membership_controller_capture membership_capture;
    struct wvm_admission_evidence_owner evidence_owner;
    struct wvm_admission_evidence_owner unpublished_evidence_owner;
    struct wvm_admission_plan_provider plan_provider;
    struct wvm_admission_plan_provider unpublished_plan_provider;
    struct wvm_admission_route_compiler route_compiler;
    struct wvm_admission_route_compiler unpublished_route_compiler;
    struct wvm_admission_transport transport;
    struct wvm_admission_authority_owner_config config;
    struct wvm_admission_authority_owner_config unpublished_config;
    struct wvm_admission_authority_owner owner;
    struct wvm_capability_record source_capabilities[1];
    struct wvm_capability_record stored_capabilities[1];
    struct wvm_capability_record unpublished_capabilities[1];
    struct wvm_resource_reservation stored_reservations[1];
    struct wvm_node_record records_nodes[1];
    struct wvm_cluster_record_set records;
    struct wvm_coordinator_node_launch_plan source_launch[1];
    struct wvm_coordinator_node_launch_plan stored_launch[1];
    struct wvm_coordinator_node_launch_plan unpublished_launch[1];
    struct wvm_admission_node_listener_plan source_listener[1];
    struct wvm_admission_node_listener_plan stored_listener[1];
    struct wvm_admission_node_listener_plan unpublished_listener[1];
    struct wvm_exclusive_lease leases[2];
    struct wvm_coordinator_prepare_options options;
    struct wvm_coordinator_prepared_route prepared_route;
    struct wvm_coordinator_prepared_vm prepared_vm;
    struct wvm_activation_record activation;
    struct wvm_route_transaction_record route_transaction;
    struct wvm_route_snapshot_record route_snapshot;
    struct wvm_route_rule_record route_rules[16];
    struct wvm_required_ack_entry route_ack_entries[1];
    uint8_t route_snapshot_bytes[65536];
    uint8_t route_ack_set_bytes[4096];
    struct wvm_vm_request request;
    struct wvm_coordinator_transaction transaction;
    struct wvm_admission_orchestrator_input input;
    struct workspace_state workspace = {0};
    struct wvm_node_record capture_nodes[1];
    struct wvm_gateway_record capture_gateways[1];
    char error[256] = {0};

    memset(&membership_controller, 0, sizeof(membership_controller));
    memset(&membership_capture, 0, sizeof(membership_capture));
    memset(records_nodes, 0, sizeof(records_nodes));
    records_nodes[0].physical_node_id = 17;
    records_nodes[0].node_instance_id = 101;
    memset(&records, 0, sizeof(records));
    records.nodes = records_nodes;
    records.node_count = 1;
    records.membership_revision = 11;
    records.topology_revision = 12;
    records.admission_eligibility_revision = 13;
    records.inventory_revision = 7;
    membership_capture.nodes = capture_nodes;
    membership_capture.node_capacity = 1;
    membership_capture.gateways = capture_gateways;
    membership_capture.gateway_capacity = 1;
    fill_capability(source_capabilities);
    fill_launch(source_launch);
    fill_listener(source_listener, source_launch, leases);
    memset(&options, 0, sizeof(options));
    if (expect(wvm_admission_evidence_owner_init(
                   &evidence_owner, stored_capabilities, 1,
                   stored_reservations, 1, error, sizeof(error)) == 0 &&
                   wvm_admission_evidence_owner_publish(
                       &evidence_owner, source_capabilities, 1, NULL, 0, 7,
                       9, error, sizeof(error)) == 0 &&
                   wvm_admission_plan_provider_init(
                       &plan_provider, stored_launch, 1, stored_listener, 1,
                       error, sizeof(error)) == 0 &&
                   wvm_admission_plan_provider_publish(
                       &plan_provider, &records, source_launch, 1,
                       source_listener, 1, error, sizeof(error)) == 0 &&
                   wvm_admission_plan_provider_set_options_template(
                       &plan_provider, &options, error, sizeof(error)) == 0,
               "publish immutable evidence and complete launch plan") ||
        expect(wvm_admission_transport_init(
                   &transport, 17, 500, NULL, resolve_node, submit,
                   error, sizeof(error)) == 0,
               "initialize caller-owned admission transport")) {
        return 1;
    }
    if (expect(wvm_admission_route_compiler_init(
                   &route_compiler, WVM_ROUTE_TOPOLOGY_FLAT, 1, 6000, 1,
                   route_rules, 16, route_ack_entries, 1,
                   route_snapshot_bytes, sizeof(route_snapshot_bytes),
                   route_ack_set_bytes, sizeof(route_ack_set_bytes), error,
                   sizeof(error)) == 0,
               "initialize caller-owned route compiler")) {
        return 1;
    }

    memset(&config, 0, sizeof(config));
    config.membership_controller = &membership_controller;
    config.membership_capture = &membership_capture;
    config.evidence_owner = &evidence_owner;
    config.plan_provider = &plan_provider;
    config.route_compiler = &route_compiler;
    config.transport = &transport;
    config.prepared_route = &prepared_route;
    config.prepared_vm = &prepared_vm;
    config.activation = &activation;
    config.route_transaction = &route_transaction;
    config.route_snapshot = &route_snapshot;
    config.workspace_context = &workspace;
    config.reset_workspace = reset_workspace;

    if (expect(wvm_admission_evidence_owner_init(
                   &unpublished_evidence_owner, unpublished_capabilities, 1,
                   stored_reservations, 1, error, sizeof(error)) == 0,
               "initialize an unpublished evidence owner") ||
        expect(wvm_admission_plan_provider_init(
                   &unpublished_plan_provider, unpublished_launch, 1,
                   unpublished_listener, 1, error, sizeof(error)) == 0,
               "initialize an unpublished plan provider")) {
        return 1;
    }
    unpublished_config = config;
    unpublished_config.evidence_owner = &unpublished_evidence_owner;
    memset(&owner, 0, sizeof(owner));
    memset(error, 0, sizeof(error));
    if (expect(wvm_admission_authority_owner_init(
                   &owner, &unpublished_config, error, sizeof(error)) == 0,
               "bind configured but unpublished evidence")) {
        return 1;
    }
    memset(&input, 0, sizeof(input));
    memset(error, 0, sizeof(error));
    if (expect(owner.authority.prepare_input(
                   owner.authority.context, &request, &transaction, &input,
                   error, sizeof(error)) != 0,
               "fail closed before evidence publication") ||
        expect(workspace.resets == 1,
               "refresh caller-owned workspace before publication validation")) {
        return 1;
    }
    unpublished_config = config;
    unpublished_config.plan_provider = &unpublished_plan_provider;
    memset(&owner, 0, sizeof(owner));
    memset(error, 0, sizeof(error));
    if (expect(wvm_admission_authority_owner_init(
                   &owner, &unpublished_config, error, sizeof(error)) == 0,
               "bind configured but unpublished launch plan")) {
        return 1;
    }
    unpublished_config = config;
    memset(&unpublished_route_compiler, 0, sizeof(unpublished_route_compiler));
    unpublished_config.route_compiler = &unpublished_route_compiler;
    memset(&owner, 0, sizeof(owner));
    memset(error, 0, sizeof(error));
    if (expect(wvm_admission_authority_owner_init(
                   &owner, &unpublished_config, error, sizeof(error)) != 0,
               "reject an unconfigured route compiler")) {
        return 1;
    }
    memset(&owner, 0, sizeof(owner));
    if (expect(wvm_admission_authority_owner_init(
                   &owner, &config, error, sizeof(error)) == 0 &&
                   wvm_admission_authority_owner_binding(&owner) != NULL &&
                   wvm_admission_authority_validate(
                       wvm_admission_authority_owner_binding(&owner), error,
                       sizeof(error)) == 0,
               "compose a complete admission authority from published owners")) {
        return 1;
    }

    memset(&input, 0, sizeof(input));
    memset(&request, 0, sizeof(request));
    memset(&transaction, 0, sizeof(transaction));
    if (expect(owner.authority.prepare_input(
                   owner.authority.context, &request, &transaction, &input,
                   error, sizeof(error)) == 0 && workspace.resets == 2 &&
                   input.membership_controller == &membership_controller &&
                   input.membership_capture == &membership_capture &&
                   input.prepared_route == &prepared_route &&
                   input.prepared_vm == &prepared_vm &&
                   input.coordinator_instance_id ==
                       transport.controller_instance_id &&
                   input.activation == &activation &&
                   input.route_transaction == &route_transaction &&
                   input.route_snapshot == &route_snapshot &&
                   input.prepare_options == &plan_provider.options_template,
               "prepare input resets and binds only caller-owned workspace") ||
        expect(owner.authority.refresh_input(
                   owner.authority.context, WVM_ADMISSION_INPUT_PREPARE,
                   &request, &transaction, &input, error, sizeof(error)) ==
                   0 &&
                   input.membership_evidence == &evidence_owner.evidence_view,
               "refresh input binds immutable evidence publication")) {
        return 1;
    }

    records.topology_revision++;
    memset(error, 0, sizeof(error));
    if (expect(owner.authority.callbacks.route_plan(
                   owner.authority.context, &transaction, &records,
                   &prepared_route, &route_transaction, &route_snapshot,
                   error, sizeof(error)) != 0,
               "reject a plan publication stale for the membership capture")) {
        return 1;
    }

    memset(&transport, 0, sizeof(transport));
    memset(&owner, 0, sizeof(owner));
    memset(error, 0, sizeof(error));
    if (expect(wvm_admission_authority_owner_init(
                   &owner, &config, error, sizeof(error)) != 0,
               "reject an authority owner without a valid transport")) {
        return 1;
    }

    puts("admission-authority-owner tests: PASS");
    return 0;
}

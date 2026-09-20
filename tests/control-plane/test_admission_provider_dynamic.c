#include <stdio.h>
#include <string.h>

#include "wavevm_admission_provider.h"
#include "wavevm_admission_orchestrator.h"
#include "wavevm_membership_controller.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "dynamic admission-provider test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_node(struct wvm_node_record *node, uint32_t node_id,
                      uint64_t instance_id)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = node_id;
    node->node_instance_id = instance_id;
    node->inventory.physical_node_id = node_id;
    node->inventory.node_instance_id = instance_id;
    node->inventory.inventory_revision = 5;
    node->capability.physical_node_id = node_id;
    node->capability.node_instance_id = instance_id;
    node->capability.profile_generation = 7;
    memset(node->capability.profile_digest, 0x31,
           sizeof(node->capability.profile_digest));
}

static void fill_profile(struct wvm_node_runtime_profile *profile,
                         const struct wvm_node_record *node,
                         uint16_t data_ports[2], uint16_t service_ports[2])
{
    memset(profile, 0, sizeof(*profile));
    profile->physical_node_id = node->physical_node_id;
    profile->node_instance_id = node->node_instance_id;
    profile->inventory_revision = node->inventory.inventory_revision;
    profile->capability_profile_generation = node->capability.profile_generation;
    profile->runtime_profile_generation = 9;
    profile->node_runtime_control_port = data_ports[0] - 2U;
    profile->local_executor_control_port = service_ports[0] - 2U;
    profile->executor_worker_count = 2;
    profile->sync_batch_size = 8;
    profile->vcpu_handoff_record_capacity = 32;
    profile->node_runtime_data_ports = data_ports;
    profile->node_runtime_data_port_count = 2;
    profile->local_executor_service_ports = service_ports;
    profile->local_executor_service_port_count = 2;
}

int main(void)
{
    struct wvm_node_record nodes[2];
    struct wvm_membership_controller_capture capture = {0};
    struct wvm_cluster_record_set records = {0};
    struct wvm_node_runtime_profile profiles[2];
    struct wvm_coordinator_node_launch_plan launches[2];
    struct wvm_admission_node_listener_plan listeners[2];
    struct wvm_exclusive_lease leases[6];
    struct wvm_admission_plan_provider provider;
    struct wvm_coordinator_prepare_options template_options;
    struct wvm_admission_orchestrator_input input;
    struct wvm_vm_request request;
    struct wvm_coordinator_transaction transaction;
    uint16_t data_ports[2][2] = {{19102, 19103}, {19202, 19203}};
    uint16_t service_ports[2][2] = {{19110, 19111}, {19210, 19211}};
    char error[256] = {0};

    fill_node(&nodes[0], 17, 101);
    fill_node(&nodes[1], 19, 102);
    fill_profile(&profiles[0], &nodes[0], data_ports[0], service_ports[0]);
    fill_profile(&profiles[1], &nodes[1], data_ports[1], service_ports[1]);
    capture.nodes = nodes;
    capture.node_capacity = 2;
    capture.node_count = 2;
    capture.membership_revision = 11;
    capture.topology_revision = 12;
    capture.admission_eligibility_revision = 13;
    records.nodes = nodes;
    records.node_count = 2;
    records.membership_revision = capture.membership_revision;
    records.topology_revision = capture.topology_revision;
    records.admission_eligibility_revision =
        capture.admission_eligibility_revision;
    records.inventory_revision = 5;

    if (expect(wvm_admission_plan_provider_init_with_lease_storage(
                   &provider, launches, 2, listeners, 2, leases, 6, error,
                   sizeof(error)) == 0,
               "initialize dynamic provider") ||
        expect(wvm_admission_plan_provider_publish_runtime_profiles(
                   &provider, &capture, profiles, 2, error, sizeof(error)) ==
                   0,
               "publish complete runtime profile set") ||
        expect(wvm_admission_plan_provider_validate(
                   &provider, &records, error, sizeof(error)) == 0,
               "validate dynamic profile set")) {
        return 1;
    }

    memset(&template_options, 0, sizeof(template_options));
    strcpy(template_options.guest_machine.architecture, "x86_64");
    strcpy(template_options.guest_machine.machine_type, "pc-i440fx-5.2");
    template_options.guest_machine.qemu_compat_version = 502;
    template_options.guest_machine.firmware_policy = 1;
    template_options.execution_profile.kernel_accelerator_bits = 1;
    template_options.memory_consistency_policy = 1;
    if (expect(wvm_admission_plan_provider_set_options_template(
                   &provider, &template_options, error, sizeof(error)) == 0,
               "publish non-per-node options template")) {
        return 1;
    }
    memset(&request, 0, sizeof(request));
    request.requested_memory_bytes = 8192;
    request.consistency_policy.dirty_batch_size = 3;
    request.consistency_policy.handoff_commit_policy = 4;
    request.consistency_policy.subscriber_delivery_policy = 5;
    request.consistency_policy.max_commit_latency_ms = 6;
    memset(&transaction, 0, sizeof(transaction));
    transaction.admission_tx_id[0] = 0x42;
    memset(&input, 0, sizeof(input));
    if (expect(wvm_admission_plan_provider_prepare_input(
                   &provider, &request, &transaction, &input, error,
                   sizeof(error)) == 0,
               "generate per-transaction launch plans") ||
        expect(input.prepare_options == &provider.prepared_options,
               "bind generated options rather than static template") ||
        expect(provider.node_launch_plan_count == 2 &&
                   provider.node_listener_plan_count == 2,
               "generate one plan per profile") ||
        expect(launches[0].launch_plan.guest_total_memory_bytes == 8192 &&
                   launches[0].launch_plan.consistency_policy.dirty_batch_size ==
                       3,
               "copy VM memory and consistency policy") ||
        expect(listeners[0].lease_generation != 0 &&
                   listeners[0].lease_entries == leases,
               "bind transaction lease storage") ||
        expect(listeners[0].node_runtime_data_port !=
                   listeners[1].node_runtime_data_port,
               "select node-specific listener ports")) {
        return 1;
    }
    puts("dynamic admission-provider tests: PASS");
    return 0;
}

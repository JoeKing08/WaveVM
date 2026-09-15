#include <stdio.h>
#include <string.h>

#include "wavevm_admission_provider.h"
#include "wavevm_admission_orchestrator.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "admission-provider test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_machine(struct wvm_machine_config *machine)
{
    memset(machine, 0, sizeof(*machine));
    strcpy(machine->architecture, "x86_64");
    strcpy(machine->machine_type, "pc-i440fx-5.2");
    machine->qemu_compat_version = 502;
    machine->firmware_policy = 1;
}

static void fill_launch(struct wvm_coordinator_node_launch_plan *launch,
                        uint32_t node_id, uint64_t instance_id,
                        uint16_t offset)
{
    memset(launch, 0, sizeof(*launch));
    launch->physical_node_id = node_id;
    launch->expected_node_instance_id = instance_id;
    launch->launch_plan.plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
    launch->launch_plan.node_runtime_data_port = (uint16_t)(19100 + offset);
    launch->launch_plan.node_runtime_control_port =
        (uint16_t)(19121 + offset);
    launch->launch_plan.local_executor_service_port =
        (uint16_t)(19105 + offset);
    launch->launch_plan.local_executor_control_port =
        (uint16_t)(19121 + offset);
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
                          struct wvm_exclusive_lease *leases)
{
    memset(listener, 0, sizeof(*listener));
    listener->physical_node_id = launch->physical_node_id;
    listener->expected_node_instance_id = launch->expected_node_instance_id;
    listener->node_runtime_data_port =
        launch->launch_plan.node_runtime_data_port;
    listener->local_executor_service_port =
        launch->launch_plan.local_executor_service_port;
    listener->lease_generation = launch->expected_node_instance_id;
    listener->lease_entries = leases;
    listener->lease_capacity = 2;
}

int main(void)
{
    struct wvm_node_record nodes[2];
    struct wvm_cluster_record_set records;
    struct wvm_coordinator_node_launch_plan source_launch[2];
    struct wvm_admission_node_listener_plan source_listener[2];
    struct wvm_exclusive_lease leases[2][2];
    struct wvm_coordinator_node_launch_plan stored_launch[2];
    struct wvm_admission_node_listener_plan stored_listener[2];
    struct wvm_admission_plan_provider provider;
    struct wvm_coordinator_prepare_options options;
    char error[256] = {0};

    memset(nodes, 0, sizeof(nodes));
    nodes[0].physical_node_id = 17;
    nodes[0].node_instance_id = 101;
    nodes[1].physical_node_id = 19;
    nodes[1].node_instance_id = 102;
    memset(&records, 0, sizeof(records));
    records.nodes = nodes;
    records.node_count = 2;
    records.inventory_revision = 10;
    records.membership_revision = 11;
    records.topology_revision = 12;
    records.admission_eligibility_revision = 13;
    fill_launch(&source_launch[0], 17, 101, 0);
    fill_launch(&source_launch[1], 19, 102, 100);
    fill_listener(&source_listener[0], &source_launch[0], leases[0]);
    fill_listener(&source_listener[1], &source_launch[1], leases[1]);
    {
        struct wvm_admission_node_listener_plan listener = source_listener[0];

        source_listener[0] = source_listener[1];
        source_listener[1] = listener;
    }
    if (expect(wvm_admission_plan_provider_init(
                   &provider, stored_launch, 2, stored_listener, 2, error,
                   sizeof(error)) == 0,
               "initialize provider") ||
        expect(wvm_admission_plan_provider_publish(
                   &provider, &records, source_launch, 2, source_listener, 2,
                   error, sizeof(error)) == 0,
               "publish complete controller plan set") ||
        expect(wvm_admission_plan_provider_validate(
                   &provider, &records, error, sizeof(error)) == 0,
               "validate published plan set")) {
        return 1;
    }
    memset(&options, 0, sizeof(options));
    if (expect(wvm_admission_plan_provider_set_options_template(
                   &provider, &options, error, sizeof(error)) == 0,
               "publish controller options template") ||
        expect(wvm_admission_plan_provider_bind_options(
                   &provider, &options, error, sizeof(error)) == 0 &&
                   options.node_launch_plans == stored_launch &&
                   options.node_listener_plans == stored_listener &&
                   options.node_launch_plan_count == 2 &&
                   options.node_listener_plan_count == 2,
               "bind controller plans into coordinator options")) {
        return 1;
    }
    {
        struct wvm_admission_orchestrator_input input;
        struct wvm_vm_request request;
        struct wvm_coordinator_transaction transaction;

        memset(&input, 0, sizeof(input));
        memset(&request, 0, sizeof(request));
        memset(&transaction, 0, sizeof(transaction));
        if (expect(wvm_admission_plan_provider_prepare_input(
                       &provider, &request, &transaction, &input, error,
                       sizeof(error)) == 0 &&
                       input.prepare_options == &provider.options_template,
                   "provide the bound template to the orchestrator")) {
            return 1;
        }
    }
    records.inventory_revision++;
    if (expect(wvm_admission_plan_provider_validate(
                   &provider, &records, error, sizeof(error)) != 0,
               "reject a changed inventory revision")) {
        return 1;
    }
    nodes[1].node_instance_id++;
    if (expect(wvm_admission_plan_provider_validate(
                   &provider, &records, error, sizeof(error)) != 0,
               "reject a changed node instance") ||
        expect(wvm_admission_plan_provider_publish(
                   &provider, &records, source_launch, 1, source_listener, 2,
                   error, sizeof(error)) != 0,
               "reject incomplete publication")) {
        return 1;
    }
    puts("admission-provider tests: PASS");
    return 0;
}

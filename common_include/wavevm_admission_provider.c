#include "wavevm_admission_provider.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_admission_orchestrator.h"

static void set_error(char *error, size_t error_len, const char *format, ...)
{
    va_list arguments;

    if (!error || error_len == 0) {
        return;
    }
    va_start(arguments, format);
    vsnprintf(error, error_len, format, arguments);
    va_end(arguments);
}

static int node_identity_equal(uint32_t left_node, uint64_t left_instance,
                               uint32_t right_node, uint64_t right_instance)
{
    return left_node == right_node && left_instance == right_instance;
}

static int provider_storage_valid(
    const struct wvm_admission_plan_provider *provider, char *error,
    size_t error_len)
{
    if (!provider || !provider->initialized || !provider->node_launch_plans ||
        provider->node_launch_plan_capacity == 0 ||
        !provider->node_listener_plans ||
        provider->node_listener_plan_capacity == 0) {
        set_error(error, error_len,
                  "admission plan provider storage is invalid");
        return -1;
    }
    if (provider->node_launch_plan_count >
            provider->node_launch_plan_capacity ||
        provider->node_listener_plan_count >
            provider->node_listener_plan_capacity) {
        set_error(error, error_len,
                  "admission plan provider counts exceed storage");
        return -1;
    }
    return 0;
}

static int find_node(const struct wvm_cluster_record_set *records,
                     uint32_t physical_node_id, uint64_t node_instance_id)
{
    size_t i;

    for (i = 0; i < records->node_count; i++) {
        if (node_identity_equal(records->nodes[i].physical_node_id,
                                records->nodes[i].node_instance_id,
                                physical_node_id, node_instance_id)) {
            return (int)i;
        }
    }
    return -1;
}

static int launch_plan_index(
    const struct wvm_coordinator_node_launch_plan *plans, size_t count,
    uint32_t physical_node_id, uint64_t node_instance_id)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (node_identity_equal(plans[i].physical_node_id,
                                plans[i].expected_node_instance_id,
                                physical_node_id, node_instance_id)) {
            return (int)i;
        }
    }
    return -1;
}

static int listener_plan_index(
    const struct wvm_admission_node_listener_plan *plans, size_t count,
    uint32_t physical_node_id, uint64_t node_instance_id)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (node_identity_equal(plans[i].physical_node_id,
                                plans[i].expected_node_instance_id,
                                physical_node_id, node_instance_id)) {
            return (int)i;
        }
    }
    return -1;
}

static int launch_plan_validate(
    const struct wvm_coordinator_node_launch_plan *plan, char *error,
    size_t error_len)
{
    if (!plan || plan->physical_node_id == 0 ||
        plan->expected_node_instance_id == 0 ||
        wvm_node_runtime_launch_plan_validate(&plan->launch_plan, error,
                                              error_len) != 0) {
        set_error(error, error_len,
                  "controller launch plan has invalid node identity or body");
        return -1;
    }
    return 0;
}

static int listener_plan_validate(
    const struct wvm_admission_node_listener_plan *plan, char *error,
    size_t error_len)
{
    if (!plan || plan->physical_node_id == 0 ||
        plan->expected_node_instance_id == 0 ||
        plan->node_runtime_data_port == 0 ||
        plan->local_executor_service_port == 0 ||
        plan->node_runtime_data_port == plan->local_executor_service_port ||
        (plan->kernel_accelerator_required != 0 &&
         plan->kernel_accelerator_required != 1) ||
        plan->lease_generation == 0 || !plan->lease_entries ||
        plan->lease_capacity < 2) {
        set_error(error, error_len,
                  "controller listener plan has invalid identity or lease storage");
        return -1;
    }
    return 0;
}

static int plan_set_validate(
    const struct wvm_admission_plan_provider *provider,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_node_launch_plan *launch_plans,
    size_t launch_count,
    const struct wvm_admission_node_listener_plan *listener_plans,
    size_t listener_count, char *error, size_t error_len)
{
    size_t i;

    if (provider_storage_valid(provider, error, error_len) != 0 || !records ||
        !records->nodes || records->node_count == 0 ||
        records->node_count != launch_count ||
        records->node_count != listener_count || !launch_plans ||
        !listener_plans || launch_count == 0 ||
        launch_count > provider->node_launch_plan_capacity ||
        listener_count > provider->node_listener_plan_capacity ||
        records->inventory_revision == 0 ||
        records->membership_revision == 0 || records->topology_revision == 0 ||
        records->admission_eligibility_revision == 0) {
        set_error(error, error_len,
                  "controller plan set does not cover a complete membership capture");
        return -1;
    }
    for (i = 0; i < launch_count; i++) {
        const struct wvm_coordinator_node_launch_plan *launch =
            &launch_plans[i];
        const struct wvm_admission_node_listener_plan *listener;
        int node_index;
        int listener_index;
        size_t j;

        if (launch_plan_validate(launch, error, error_len) != 0 ||
            launch_plan_index(launch_plans, i, launch->physical_node_id,
                              launch->expected_node_instance_id) >= 0 ||
            (node_index = find_node(records, launch->physical_node_id,
                                    launch->expected_node_instance_id)) < 0) {
            set_error(error, error_len,
                      "controller launch plans contain a duplicate or unknown node");
            return -1;
        }
        for (j = 0; j < i; j++) {
            if (records->nodes[j].physical_node_id ==
                launch->physical_node_id) {
                set_error(error, error_len,
                          "membership capture contains a duplicate node ID");
                return -1;
            }
        }
        listener_index = listener_plan_index(
            listener_plans, listener_count, launch->physical_node_id,
            launch->expected_node_instance_id);
        if (listener_index < 0) {
            set_error(error, error_len,
                      "controller launch plan has no matching listener plan");
            return -1;
        }
        listener = &listener_plans[listener_index];
        if (listener_plan_validate(listener, error, error_len) != 0 ||
            listener->node_runtime_data_port !=
                launch->launch_plan.node_runtime_data_port ||
            listener->local_executor_service_port !=
                launch->launch_plan.local_executor_service_port ||
            records->nodes[node_index].physical_node_id !=
                launch->physical_node_id) {
            set_error(error, error_len,
                      "controller launch and listener plans do not bind node identity");
            return -1;
        }
    }
    for (i = 0; i < listener_count; i++) {
        if (listener_plan_validate(&listener_plans[i], error, error_len) != 0 ||
            listener_plan_index(listener_plans, i,
                                listener_plans[i].physical_node_id,
                                listener_plans[i].expected_node_instance_id) >=
                0 ||
            launch_plan_index(launch_plans, launch_count,
                              listener_plans[i].physical_node_id,
                              listener_plans[i].expected_node_instance_id) <
                0) {
            set_error(error, error_len,
                      "controller listener plans contain an unknown node");
            return -1;
        }
    }
    return 0;
}

int wvm_admission_plan_provider_init(
    struct wvm_admission_plan_provider *provider,
    struct wvm_coordinator_node_launch_plan *node_launch_plans,
    size_t node_launch_plan_capacity,
    struct wvm_admission_node_listener_plan *node_listener_plans,
    size_t node_listener_plan_capacity, char *error, size_t error_len)
{
    if (!provider || !node_launch_plans || node_launch_plan_capacity == 0 ||
        !node_listener_plans || node_listener_plan_capacity == 0) {
        set_error(error, error_len,
                  "admission plan provider initialization is invalid");
        return -1;
    }
    memset(provider, 0, sizeof(*provider));
    provider->node_launch_plans = node_launch_plans;
    provider->node_launch_plan_capacity = node_launch_plan_capacity;
    provider->node_listener_plans = node_listener_plans;
    provider->node_listener_plan_capacity = node_listener_plan_capacity;
    provider->initialized = 1;
    return 0;
}

int wvm_admission_plan_provider_publish(
    struct wvm_admission_plan_provider *provider,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_node_launch_plan *node_launch_plans,
    size_t node_launch_plan_count,
    const struct wvm_admission_node_listener_plan *node_listener_plans,
    size_t node_listener_plan_count, char *error, size_t error_len)
{
    if (plan_set_validate(provider, records, node_launch_plans,
                          node_launch_plan_count, node_listener_plans,
                          node_listener_plan_count, error, error_len) != 0) {
        return -1;
    }
    memmove(provider->node_launch_plans, node_launch_plans,
            node_launch_plan_count * sizeof(*provider->node_launch_plans));
    memmove(provider->node_listener_plans, node_listener_plans,
            node_listener_plan_count * sizeof(*provider->node_listener_plans));
    provider->node_launch_plan_count = node_launch_plan_count;
    provider->node_listener_plan_count = node_listener_plan_count;
    provider->inventory_revision = records->inventory_revision;
    provider->membership_revision = records->membership_revision;
    provider->topology_revision = records->topology_revision;
    provider->admission_eligibility_revision =
        records->admission_eligibility_revision;
    provider->published = 1;
    return 0;
}

int wvm_admission_plan_provider_validate(
    const struct wvm_admission_plan_provider *provider,
    const struct wvm_cluster_record_set *records, char *error,
    size_t error_len)
{
    if (!provider || !provider->published ||
        plan_set_validate(provider, records, provider->node_launch_plans,
                          provider->node_launch_plan_count,
                          provider->node_listener_plans,
                          provider->node_listener_plan_count, error,
                          error_len) != 0 ||
        provider->inventory_revision != records->inventory_revision ||
        provider->membership_revision != records->membership_revision ||
        provider->topology_revision != records->topology_revision ||
        provider->admission_eligibility_revision !=
            records->admission_eligibility_revision) {
        set_error(error, error_len,
                  "controller launch plan publication is stale");
        return -1;
    }
    return 0;
}

int wvm_admission_plan_provider_set_options_template(
    struct wvm_admission_plan_provider *provider,
    const struct wvm_coordinator_prepare_options *options, char *error,
    size_t error_len)
{
    if (!provider || !provider->published || !options ||
        provider_storage_valid(provider, error, error_len) != 0) {
        set_error(error, error_len,
                  "cannot publish an incomplete controller options template");
        return -1;
    }
    provider->options_template = *options;
    provider->options_template_published = 1;
    if (wvm_admission_plan_provider_bind_options(
            provider, &provider->options_template, error, error_len) != 0) {
        provider->options_template_published = 0;
        memset(&provider->options_template, 0,
               sizeof(provider->options_template));
        return -1;
    }
    return 0;
}

int wvm_admission_plan_provider_bind_options(
    const struct wvm_admission_plan_provider *provider,
    struct wvm_coordinator_prepare_options *options, char *error,
    size_t error_len)
{
    if (!provider || !provider->published || !options ||
        provider_storage_valid(provider, error, error_len) != 0 ||
        provider->node_launch_plan_count == 0 ||
        provider->node_listener_plan_count == 0) {
        set_error(error, error_len,
                  "cannot bind unpublished controller launch plans");
        return -1;
    }
    options->node_launch_plans = provider->node_launch_plans;
    options->node_launch_plan_count = provider->node_launch_plan_count;
    options->node_listener_plans = provider->node_listener_plans;
    options->node_listener_plan_count = provider->node_listener_plan_count;
    return 0;
}

int wvm_admission_plan_provider_prepare_input(
    void *context, const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    struct wvm_admission_plan_provider *provider = context;

    if (!provider || !request || !transaction || !input ||
        !provider->options_template_published ||
        provider_storage_valid(provider, error, error_len) != 0) {
        set_error(error, error_len,
                  "controller prepare-input provider is not configured");
        return -1;
    }
    input->prepare_options = &provider->options_template;
    return wvm_admission_plan_provider_bind_options(
        provider, &provider->options_template, error, error_len);
}

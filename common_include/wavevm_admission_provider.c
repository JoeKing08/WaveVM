#include "wavevm_admission_provider.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_admission_orchestrator.h"
#include "wavevm_membership_controller.h"

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

static uint64_t transaction_generation(
    const struct wvm_coordinator_transaction *transaction)
{
    uint64_t value = UINT64_C(1469598103934665603);
    size_t i;

    for (i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
        value ^= transaction->admission_tx_id[i];
        value *= UINT64_C(1099511628211);
    }
    return value == 0 ? 1 : value;
}

static size_t transaction_port_index(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_node_runtime_profile *profile, size_t count,
    uint32_t salt)
{
    uint64_t value = transaction_generation(transaction);

    if (count == 0) {
        return 0;
    }

    value ^= (uint64_t)profile->physical_node_id * UINT64_C(0x9e3779b1);
    value ^= profile->node_instance_id + UINT64_C(0x9e3779b97f4a7c15);
    value ^= (uint64_t)salt * UINT64_C(0x517cc1b727220a95);
    return (size_t)(value % count);
}

static int find_profile(
    const struct wvm_admission_plan_provider *provider, uint32_t physical_node_id,
    uint64_t node_instance_id)
{
    size_t i;

    for (i = 0; i < provider->runtime_profile_count; i++) {
        if (node_identity_equal(provider->runtime_profiles[i].physical_node_id,
                                provider->runtime_profiles[i].node_instance_id,
                                physical_node_id, node_instance_id)) {
            return (int)i;
        }
    }
    return -1;
}

static int runtime_profile_set_validate(
    const struct wvm_admission_plan_provider *provider,
    const struct wvm_membership_controller_capture *capture,
    const struct wvm_node_runtime_profile *profiles, size_t profile_count,
    char *error, size_t error_len)
{
    size_t i;

    if (!provider || !capture || !capture->nodes || capture->node_count == 0 ||
        capture->node_count > capture->node_capacity ||
        !profiles || profile_count != capture->node_count ||
        profile_count > provider->node_launch_plan_capacity ||
        profile_count > provider->node_listener_plan_capacity ||
        profile_count > SIZE_MAX / 3U ||
        !provider->lease_storage ||
        provider->lease_storage_capacity < profile_count * 3U ||
        capture->membership_revision == 0 || capture->topology_revision == 0 ||
        capture->admission_eligibility_revision == 0) {
        set_error(error, error_len,
                  "runtime profile publication does not cover membership");
        return -1;
    }
    for (i = 0; i < profile_count; i++) {
        const struct wvm_node_runtime_profile *profile = &profiles[i];
        size_t j;
        int found = 0;

        if (wvm_node_runtime_profile_validate(profile, error, error_len) != 0) {
            return -1;
        }
        for (j = 0; j < capture->node_count; j++) {
            const struct wvm_node_record *node = &capture->nodes[j];

            if (!node_identity_equal(profile->physical_node_id,
                                     profile->node_instance_id,
                                     node->physical_node_id,
                                     node->node_instance_id)) {
                continue;
            }
            if (profile->inventory_revision !=
                    node->inventory.inventory_revision ||
                profile->capability_profile_generation !=
                    node->capability.profile_generation) {
                set_error(error, error_len,
                          "runtime profile evidence is stale for node %u",
                          profile->physical_node_id);
                return -1;
            }
            found = 1;
            break;
        }
        if (!found) {
            set_error(error, error_len,
                      "runtime profile names an unknown node %u",
                      profile->physical_node_id);
            return -1;
        }
        for (j = 0; j < i; j++) {
            if (node_identity_equal(profile->physical_node_id,
                                    profile->node_instance_id,
                                    profiles[j].physical_node_id,
                                    profiles[j].node_instance_id)) {
                set_error(error, error_len,
                          "runtime profile publication contains duplicates");
                return -1;
            }
        }
    }
    for (i = 0; i < capture->node_count; i++) {
        for (size_t j = 0; j < profile_count; j++) {
            if (node_identity_equal(capture->nodes[i].physical_node_id,
                                    capture->nodes[i].node_instance_id,
                                    profiles[j].physical_node_id,
                                    profiles[j].node_instance_id)) {
                goto next_node;
            }
        }
        set_error(error, error_len,
                  "membership node %u has no runtime profile",
                  capture->nodes[i].physical_node_id);
        return -1;
next_node:
        ;
    }
    return 0;
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

int wvm_admission_plan_provider_init_with_lease_storage(
    struct wvm_admission_plan_provider *provider,
    struct wvm_coordinator_node_launch_plan *node_launch_plans,
    size_t node_launch_plan_capacity,
    struct wvm_admission_node_listener_plan *node_listener_plans,
    size_t node_listener_plan_capacity,
    struct wvm_exclusive_lease *lease_storage,
    size_t lease_storage_capacity, char *error, size_t error_len)
{
    if (!lease_storage || lease_storage_capacity == 0 ||
        node_launch_plan_capacity > SIZE_MAX / 3U ||
        lease_storage_capacity < node_launch_plan_capacity * 3U) {
        set_error(error, error_len,
                  "admission lease storage is too small for runtime profiles");
        return -1;
    }
    if (wvm_admission_plan_provider_init(
            provider, node_launch_plans, node_launch_plan_capacity,
            node_listener_plans, node_listener_plan_capacity, error,
            error_len) != 0) {
        return -1;
    }
    provider->lease_storage = lease_storage;
    provider->lease_storage_capacity = lease_storage_capacity;
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
    provider->runtime_profiles = NULL;
    provider->runtime_profile_count = 0;
    provider->runtime_profiles_published = 0;
    provider->published = 1;
    return 0;
}

int wvm_admission_plan_provider_publish_runtime_profiles(
    struct wvm_admission_plan_provider *provider,
    const struct wvm_membership_controller_capture *capture,
    const struct wvm_node_runtime_profile *profiles, size_t profile_count,
    char *error, size_t error_len)
{
    if (!provider || !provider->initialized ||
        runtime_profile_set_validate(provider, capture, profiles,
                                     profile_count, error, error_len) != 0) {
        return -1;
    }
    provider->runtime_profiles = profiles;
    provider->runtime_profile_count = profile_count;
    provider->membership_revision = capture->membership_revision;
    provider->topology_revision = capture->topology_revision;
    provider->admission_eligibility_revision =
        capture->admission_eligibility_revision;
    provider->runtime_profiles_published = 1;
    provider->published = 1;
    return 0;
}

int wvm_admission_plan_provider_validate(
    const struct wvm_admission_plan_provider *provider,
    const struct wvm_cluster_record_set *records, char *error,
    size_t error_len)
{
    size_t i;

    if (!provider || !provider->published || !records || !records->nodes ||
        records->node_count == 0 ||
        provider->membership_revision != records->membership_revision ||
        provider->topology_revision != records->topology_revision ||
        provider->admission_eligibility_revision !=
            records->admission_eligibility_revision) {
        set_error(error, error_len,
                  "controller launch plan publication is stale");
        return -1;
    }
    if (provider->runtime_profiles_published) {
        if (provider->runtime_profile_count != records->node_count) {
            set_error(error, error_len,
                      "runtime profile publication is incomplete");
            return -1;
        }
        for (i = 0; i < records->node_count; i++) {
            int profile_index = find_profile(
                provider, records->nodes[i].physical_node_id,
                records->nodes[i].node_instance_id);

            if (profile_index < 0 ||
                provider->runtime_profiles[profile_index].inventory_revision !=
                    records->nodes[i].inventory.inventory_revision ||
                provider->runtime_profiles[profile_index]
                        .capability_profile_generation !=
                    records->nodes[i].capability.profile_generation) {
                set_error(error, error_len,
                          "runtime profile publication is stale for node %u",
                          records->nodes[i].physical_node_id);
                return -1;
            }
        }
        return 0;
    }
    if (provider->inventory_revision != records->inventory_revision ||
        plan_set_validate(provider, records, provider->node_launch_plans,
                          provider->node_launch_plan_count,
                          provider->node_listener_plans,
                          provider->node_listener_plan_count, error,
                          error_len) != 0) {
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
    if (!provider || !options ||
        provider_storage_valid(provider, error, error_len) != 0) {
        set_error(error, error_len,
                  "cannot publish an incomplete controller options template");
        return -1;
    }
    provider->options_template = *options;
    provider->options_template_published = 1;
    if (provider->published && !provider->runtime_profiles_published &&
        wvm_admission_plan_provider_bind_options(
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

static int build_runtime_profile_plans(
    struct wvm_admission_plan_provider *provider,
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len)
{
    size_t i;
    uint64_t lease_generation;
    int kernel_accelerator_required;

    if (!provider || !request || !transaction ||
        !provider->runtime_profiles_published || !provider->runtime_profiles ||
        provider->runtime_profile_count == 0 ||
        provider->runtime_profile_count > provider->node_launch_plan_capacity ||
        provider->runtime_profile_count > provider->node_listener_plan_capacity ||
        !provider->lease_storage ||
        provider->runtime_profile_count > SIZE_MAX / 3U) {
        set_error(error, error_len,
                  "runtime profile plan generation is not configured");
        return -1;
    }
    lease_generation = transaction_generation(transaction);
    kernel_accelerator_required =
        provider->options_template.execution_profile.kernel_accelerator_bits != 0;
    for (i = 0; i < provider->runtime_profile_count; i++) {
        const struct wvm_node_runtime_profile *profile =
            &provider->runtime_profiles[i];
        struct wvm_coordinator_node_launch_plan *launch =
            &provider->node_launch_plans[i];
        struct wvm_admission_node_listener_plan *listener =
            &provider->node_listener_plans[i];
        size_t data_index = transaction_port_index(
            transaction, profile, profile->node_runtime_data_port_count, 1U);
        size_t service_index = transaction_port_index(
            transaction, profile, profile->local_executor_service_port_count,
            2U);

        memset(launch, 0, sizeof(*launch));
        launch->physical_node_id = profile->physical_node_id;
        launch->expected_node_instance_id = profile->node_instance_id;
        launch->launch_plan.plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
        launch->launch_plan.node_runtime_data_port =
            profile->node_runtime_data_ports[data_index];
        launch->launch_plan.node_runtime_control_port =
            profile->node_runtime_control_port;
        launch->launch_plan.local_executor_service_port =
            profile->local_executor_service_ports[service_index];
        launch->launch_plan.local_executor_control_port =
            profile->local_executor_control_port;
        launch->launch_plan.executor_worker_count = profile->executor_worker_count;
        launch->launch_plan.vcpu_handoff_record_capacity =
            profile->vcpu_handoff_record_capacity;
        launch->launch_plan.sync_batch_size = profile->sync_batch_size;
        launch->launch_plan.guest_total_memory_bytes =
            request->requested_memory_bytes;
        launch->launch_plan.guest_machine = provider->options_template.guest_machine;
        launch->launch_plan.consistency_policy = request->consistency_policy;

        memset(listener, 0, sizeof(*listener));
        listener->physical_node_id = profile->physical_node_id;
        listener->expected_node_instance_id = profile->node_instance_id;
        listener->node_runtime_data_port =
            launch->launch_plan.node_runtime_data_port;
        listener->local_executor_service_port =
            launch->launch_plan.local_executor_service_port;
        listener->kernel_accelerator_required = kernel_accelerator_required;
        listener->lease_generation = lease_generation;
        listener->lease_entries = provider->lease_storage + i * 3U;
        listener->lease_capacity = 3;
    }
    provider->node_launch_plan_count = provider->runtime_profile_count;
    provider->node_listener_plan_count = provider->runtime_profile_count;
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
    if (provider->runtime_profiles_published) {
        provider->prepared_options = provider->options_template;
        if (build_runtime_profile_plans(provider, request, transaction, error,
                                        error_len) != 0 ||
            wvm_admission_plan_provider_bind_options(
                provider, &provider->prepared_options, error, error_len) != 0) {
            return -1;
        }
        input->prepare_options = &provider->prepared_options;
        return 0;
    }
    input->prepare_options = &provider->options_template;
    return wvm_admission_plan_provider_bind_options(
        provider, &provider->options_template, error, error_len);
}

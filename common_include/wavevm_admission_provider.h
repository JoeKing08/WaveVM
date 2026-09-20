#ifndef WAVEVM_ADMISSION_PROVIDER_H
#define WAVEVM_ADMISSION_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission.h"
#include "wavevm_cluster.h"
#include "wavevm_coordinator.h"
#include "wavevm_runtime_profile.h"

struct wvm_admission_orchestrator_input;
struct wvm_membership_controller_capture;

/*
 * Controller-owned launch material for every registered compute node. The
 * provider does not derive ports or runtime limits; a controller publishes
 * those values after validating the corresponding node instance.
 */
struct wvm_admission_plan_provider {
    struct wvm_coordinator_node_launch_plan *node_launch_plans;
    size_t node_launch_plan_capacity;
    size_t node_launch_plan_count;
    struct wvm_admission_node_listener_plan *node_listener_plans;
    size_t node_listener_plan_capacity;
    size_t node_listener_plan_count;
    struct wvm_exclusive_lease *lease_storage;
    size_t lease_storage_capacity;
    const struct wvm_node_runtime_profile *runtime_profiles;
    size_t runtime_profile_count;
    uint64_t inventory_revision;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t admission_eligibility_revision;
    struct wvm_coordinator_prepare_options options_template;
    struct wvm_coordinator_prepare_options prepared_options;
    int initialized;
    int published;
    int runtime_profiles_published;
    int options_template_published;
};

int wvm_admission_plan_provider_init(
    struct wvm_admission_plan_provider *provider,
    struct wvm_coordinator_node_launch_plan *node_launch_plans,
    size_t node_launch_plan_capacity,
    struct wvm_admission_node_listener_plan *node_listener_plans,
    size_t node_listener_plan_capacity, char *error, size_t error_len);

/* Variant used by the production owner: lease storage is caller-owned and
 * has room for the maximum three leases per admitted node. */
int wvm_admission_plan_provider_init_with_lease_storage(
    struct wvm_admission_plan_provider *provider,
    struct wvm_coordinator_node_launch_plan *node_launch_plans,
    size_t node_launch_plan_capacity,
    struct wvm_admission_node_listener_plan *node_listener_plans,
    size_t node_listener_plan_capacity,
    struct wvm_exclusive_lease *lease_storage,
    size_t lease_storage_capacity, char *error, size_t error_len);

/*
 * Publish one complete plan set against one captured membership record set.
 * Nested lease storage is retained by reference and must remain stable until
 * the next publication or provider destruction.
 */
int wvm_admission_plan_provider_publish(
    struct wvm_admission_plan_provider *provider,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_node_launch_plan *node_launch_plans,
    size_t node_launch_plan_count,
    const struct wvm_admission_node_listener_plan *node_listener_plans,
    size_t node_listener_plan_count, char *error, size_t error_len);

/* Publish the immutable node-static runtime evidence. Per-VM plans are
 * generated from this reference during prepare_input. */
int wvm_admission_plan_provider_publish_runtime_profiles(
    struct wvm_admission_plan_provider *provider,
    const struct wvm_membership_controller_capture *capture,
    const struct wvm_node_runtime_profile *profiles, size_t profile_count,
    char *error, size_t error_len);

int wvm_admission_plan_provider_validate(
    const struct wvm_admission_plan_provider *provider,
    const struct wvm_cluster_record_set *records, char *error,
    size_t error_len);

/* Copy the controller's non-per-node policy and output storage bindings. */
int wvm_admission_plan_provider_set_options_template(
    struct wvm_admission_plan_provider *provider,
    const struct wvm_coordinator_prepare_options *options, char *error,
    size_t error_len);

/* Bind the published controller material into an existing prepare policy. */
int wvm_admission_plan_provider_bind_options(
    const struct wvm_admission_plan_provider *provider,
    struct wvm_coordinator_prepare_options *options, char *error,
    size_t error_len);

/* Signature-compatible prepare-input owner for the admission orchestrator. */
int wvm_admission_plan_provider_prepare_input(
    void *context, const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len);

#endif /* WAVEVM_ADMISSION_PROVIDER_H */

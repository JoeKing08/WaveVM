#include "admission_recovery.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common_include/wavevm_admission.h"
#include "../common_include/wavevm_lifecycle.h"
#include "../common_include/wavevm_manifest.h"
#include "../common_include/wavevm_membership_controller.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "runtime_profile_publication.h"
#include "../common_include/wavevm_control_transport.h"

struct runtime_lists {
    struct wvm_vcpu_assignment *vcpus;
    struct wvm_memory_chunk_assignment *memory;
    struct wvm_storage_assignment *storage;
    struct wvm_capability_ref *capabilities;
    struct wvm_startup_dependency *dependencies;
};

struct recovery_projection {
    struct wvm_coordinator_prepared_vm prepared_vm;
    struct wvm_resource_reservation *reservations;
    struct wvm_node_runtime_manifest *manifests;
    struct runtime_lists *runtime_lists;
    struct wvm_vcpu_assignment *vcpus;
    struct wvm_memory_chunk_assignment *memory;
    struct wvm_storage_assignment *storage;
    struct wvm_required_member *members;
    struct wvm_capability_ref *capabilities;
    struct wvm_capability_ref *execution_capabilities;
    struct wvm_reservation_requirement *requirements;
    struct wvm_exclusive_lease *leases;
    uint8_t *candidate_record;
    size_t candidate_record_bytes;
    size_t candidate_record_capacity;
    struct wvm_route_rule_record *route_rules;
    struct wvm_required_ack_entry *route_acks;
    struct wvm_required_ack_entry *route_tx_acks;
    struct wvm_required_ack_entry *route_tx_drain;
    struct wvm_route_transaction_record route_transaction;
    struct wvm_route_snapshot_record route_snapshot;
    size_t runtime_count;
    size_t member_capacity;
    uint32_t max_vcpus;
};

static void projection_destroy(struct recovery_projection *projection)
{
    size_t i;

    if (!projection) {
        return;
    }
    for (i = 0; i < projection->runtime_count; i++) {
        free(projection->runtime_lists[i].vcpus);
        free(projection->runtime_lists[i].memory);
        free(projection->runtime_lists[i].storage);
        free(projection->runtime_lists[i].capabilities);
        free(projection->runtime_lists[i].dependencies);
    }
    free(projection->runtime_lists);
    free(projection->manifests);
    free(projection->reservations);
    free(projection->vcpus);
    free(projection->memory);
    free(projection->storage);
    free(projection->members);
    free(projection->capabilities);
    free(projection->execution_capabilities);
    free(projection->requirements);
    free(projection->leases);
    free(projection->candidate_record);
    free(projection->route_rules);
    free(projection->route_acks);
    free(projection->route_tx_acks);
    free(projection->route_tx_drain);
    memset(projection, 0, sizeof(*projection));
}

#define ALLOC_LIST(field, count)                                            \
    do {                                                                    \
        (field) = calloc((count) ? (count) : 1U, sizeof(*(field)));         \
        if (!(field)) {                                                     \
            goto allocation_failed;                                        \
        }                                                                   \
    } while (0)

static int candidate_storage_init(struct recovery_projection *projection,
                                  size_t members, uint32_t vcpus)
{
    struct wvm_candidate_vm_manifest *candidate =
        &projection->prepared_vm.candidate;
    size_t i;
    size_t lease_count;

    if (members == 0 || members > SIZE_MAX / 3U || vcpus == 0) {
        return -1;
    }
    lease_count = members * 3U;
    ALLOC_LIST(projection->vcpus, vcpus);
    ALLOC_LIST(projection->memory, members);
    ALLOC_LIST(projection->storage, members);
    ALLOC_LIST(projection->members, members);
    ALLOC_LIST(projection->capabilities, members);
    ALLOC_LIST(projection->execution_capabilities, members);
    ALLOC_LIST(projection->requirements, members);
    ALLOC_LIST(projection->leases, lease_count);
    candidate->vcpu_placements.entries = projection->vcpus;
    candidate->vcpu_placements.capacity = vcpus;
    candidate->memory_placements.entries = projection->memory;
    candidate->memory_placements.capacity = members;
    candidate->storage_device_plan.assignments.entries = projection->storage;
    candidate->storage_device_plan.assignments.capacity = members;
    candidate->required_members.entries = projection->members;
    candidate->required_members.capacity = members;
    candidate->required_capabilities.entries = projection->capabilities;
    candidate->required_capabilities.capacity = members;
    candidate->execution_plan.per_node_capabilities.entries =
        projection->execution_capabilities;
    candidate->execution_plan.per_node_capabilities.capacity = members;
    candidate->reservation_requirements.entries = projection->requirements;
    candidate->reservation_requirements.capacity = members;
    for (i = 0; i < members; i++) {
        projection->requirements[i].exclusive_leases.entries =
            projection->leases + i * 3U;
        projection->requirements[i].exclusive_leases.capacity = 3;
    }
    return 0;

allocation_failed:
    return -1;
}

static int runtime_storage_init(struct recovery_projection *projection,
                                size_t index, size_t members, uint32_t vcpus)
{
    struct wvm_node_runtime_manifest *manifest = &projection->manifests[index];
    struct runtime_lists *lists = &projection->runtime_lists[index];

    ALLOC_LIST(lists->vcpus, vcpus);
    ALLOC_LIST(lists->memory, members);
    ALLOC_LIST(lists->storage, members);
    ALLOC_LIST(lists->capabilities, members);
    ALLOC_LIST(lists->dependencies, members);
    manifest->local_vcpu_assignments.entries = lists->vcpus;
    manifest->local_vcpu_assignments.capacity = vcpus;
    manifest->local_memory_assignments.entries = lists->memory;
    manifest->local_memory_assignments.capacity = members;
    manifest->local_storage_assignments.entries = lists->storage;
    manifest->local_storage_assignments.capacity = members;
    manifest->negotiated_profile.per_node_capabilities.entries =
        lists->capabilities;
    manifest->negotiated_profile.per_node_capabilities.capacity = members;
    manifest->startup_dependencies.entries = lists->dependencies;
    manifest->startup_dependencies.capacity = members;
    return 0;

allocation_failed:
    return -1;
}

static int lifecycle_needs_recover(enum wvm_lifecycle_state state)
{
    return state == WVM_LIFECYCLE_ACTIVATION_DECIDED ||
           state == WVM_LIFECYCLE_COMMITTED || state == WVM_LIFECYCLE_ABORTING;
}

static int backend_to_admission(enum wvm_manifest_backend backend,
                                enum wvm_admission_backend *out)
{
    if (backend == WVM_MANIFEST_BACKEND_KVM) {
        *out = WVM_ADMISSION_BACKEND_KVM;
        return 0;
    }
    if (backend == WVM_MANIFEST_BACKEND_TCG) {
        *out = WVM_ADMISSION_BACKEND_TCG;
        return 0;
    }
    return -1;
}

static int find_route_operation_for_snapshot(
    const struct wvm_control_plane *plane,
    const struct wvm_route_snapshot_key *snapshot_key,
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES], size_t ack_capacity,
    char *error, size_t error_len)
{
    struct wvm_required_ack_entry *acks = NULL;
    struct wvm_required_ack_entry *drain = NULL;
    size_t i;
    int found = 0;
    int status = -1;

    if (!plane || !snapshot_key || !operation_id || ack_capacity == 0) {
        if (error && error_len) {
            snprintf(error, error_len, "route snapshot lookup input is invalid");
        }
        return -1;
    }
    acks = calloc(ack_capacity, sizeof(*acks));
    drain = calloc(ack_capacity, sizeof(*drain));
    if (!acks || !drain) {
        if (error && error_len) {
            snprintf(error, error_len, "cannot allocate route lookup scratch");
        }
        free(acks);
        free(drain);
        return -1;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        struct wvm_route_transaction_record decoded;
        const struct wvm_control_plane_route_entry *entry =
            &plane->route_entries[i];
        char decode_error[256];

        if (!entry->record_bytes || entry->record_byte_count == 0) {
            continue;
        }
        memset(&decoded, 0, sizeof(decoded));
        decoded.required_ack_set.entries.entries = acks;
        decoded.required_ack_set.entries.capacity = ack_capacity;
        decoded.optional_departure_drain_set.entries = drain;
        decoded.optional_departure_drain_set.capacity = ack_capacity;
        decode_error[0] = '\0';
        if (wvm_route_transaction_record_decode(
                entry->record_bytes, entry->record_byte_count, &decoded,
                decode_error, sizeof(decode_error)) != 0) {
            continue;
        }
        if (decoded.route_snapshot_key.scope_key.vm_id ==
                snapshot_key->scope_key.vm_id &&
            decoded.route_snapshot_key.scope_key.vm_incarnation ==
                snapshot_key->scope_key.vm_incarnation &&
            decoded.route_snapshot_key.scope_key.route_scope_id ==
                snapshot_key->scope_key.route_scope_id &&
            decoded.route_snapshot_key.topology_revision ==
                snapshot_key->topology_revision &&
            decoded.route_snapshot_key.route_generation ==
                snapshot_key->route_generation &&
            memcmp(decoded.route_snapshot_key.snapshot_digest,
                   snapshot_key->snapshot_digest,
                   WVM_SHA256_DIGEST_BYTES) == 0) {
            if (found) {
                if (error && error_len) {
                    snprintf(error, error_len,
                             "route snapshot maps to multiple operations");
                }
                goto out;
            }
            memcpy(operation_id, decoded.operation_id, WVM_IDENTITY_ID_BYTES);
            found = 1;
        }
    }
    if (!found) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "route snapshot has no durable route operation");
        }
        goto out;
    }
    status = 0;
out:
    free(acks);
    free(drain);
    return status;
}

static int bind_plan_and_admission_request(
    struct recovery_projection *projection,
    const struct wvm_coordinator_transaction *transaction,
    uint64_t membership_revision, uint64_t topology_revision, char *error,
    size_t error_len)
{
    struct wvm_coordinator_prepared_vm *prepared = &projection->prepared_vm;
    struct wvm_candidate_vm_manifest *candidate = &prepared->candidate;
    struct wvm_placement_plan *plan = &prepared->placement_plan;
    struct wvm_admission_request *admission = &prepared->admission_request;
    const struct wvm_reservation_requirement *host_requirement = NULL;
    size_t i;
    enum wvm_admission_backend backend;

    if (backend_to_admission(candidate->execution_plan.backend, &backend) != 0) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "recovery candidate has unsupported execution backend");
        }
        return -1;
    }
    for (i = 0; i < candidate->reservation_requirements.count; i++) {
        const struct wvm_reservation_requirement *requirement =
            &candidate->reservation_requirements.entries[i];

        if (requirement->physical_node_id == candidate->host_node) {
            host_requirement = requirement;
            break;
        }
    }
    if (!host_requirement) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "recovery candidate lacks host reservation requirement");
        }
        return -1;
    }

    memset(admission, 0, sizeof(*admission));
    admission->vm_id = transaction->vm_id;
    admission->vm_incarnation = transaction->vm_incarnation;
    admission->manifest_generation = transaction->manifest_generation;
    admission->backend = backend;
    admission->placement_policy = WVM_ADMISSION_PLACEMENT_COMPACT;
    admission->requested_vcpu_slots = (uint32_t)candidate->vcpu_placements.count;
    if (admission->requested_vcpu_slots == 0) {
        if (error && error_len) {
            snprintf(error, error_len, "recovery candidate has no vCPU placement");
        }
        return -1;
    }
    admission->requested_memory_bytes = 0;
    for (i = 0; i < candidate->memory_placements.count; i++) {
        admission->requested_memory_bytes +=
            candidate->memory_placements.entries[i].bytes;
    }
    admission->memory_chunk_bytes =
        candidate->memory_placements.count > 0
            ? candidate->memory_placements.entries[0].bytes
            : WVM_ADMISSION_PAGE_BYTES;
    if (admission->memory_chunk_bytes == 0 ||
        admission->memory_chunk_bytes % WVM_ADMISSION_PAGE_BYTES != 0) {
        admission->memory_chunk_bytes = WVM_ADMISSION_PAGE_BYTES;
    }
    admission->host_overhead_vcpu_slots = host_requirement->overhead_vcpu_slots;
    admission->host_overhead_memory_bytes =
        host_requirement->overhead_memory_bytes;
    if (admission->host_overhead_vcpu_slots == 0 &&
        admission->host_overhead_memory_bytes == 0) {
        admission->host_overhead_memory_bytes = WVM_ADMISSION_PAGE_BYTES;
    }

    memset(plan, 0, sizeof(*plan));
    memcpy(plan->plan_digest, candidate->plan_digest, sizeof(plan->plan_digest));
    memcpy(plan->admission_tx_id, candidate->admission_tx_id,
           sizeof(plan->admission_tx_id));
    memcpy(plan->eligibility_fence_digest, candidate->eligibility_fence_digest,
           sizeof(plan->eligibility_fence_digest));
    plan->inventory_revision = host_requirement->inventory_revision;
    plan->membership_revision =
        membership_revision != 0 ? membership_revision : 1;
    plan->topology_revision = topology_revision != 0 ? topology_revision : 1;
    plan->capability_profile_generation = 1;
    for (i = 0; i < candidate->required_capabilities.count; i++) {
        uint64_t generation =
            candidate->required_capabilities.entries[i].profile_generation;
        if (generation > plan->capability_profile_generation) {
            plan->capability_profile_generation = generation;
        }
    }
    plan->host_node = candidate->host_node;
    plan->vcpu_assignments = candidate->vcpu_placements;
    plan->memory_assignments = candidate->memory_placements;
    plan->storage_assignments = candidate->storage_device_plan.assignments;
    plan->reservation_requirements = candidate->reservation_requirements;
    plan->guest_topology = candidate->guest_topology;
    plan->route_scope_key = candidate->route_scope_key;
    return 0;
}

static size_t recovery_port_index(
    const struct wvm_coordinator_transaction *transaction, size_t count,
    uint32_t salt)
{
    uint64_t value;
    size_t i;

    if (count == 0) {
        return 0;
    }
    if (transaction->vm_id != 0) {
        return (size_t)(((uint64_t)transaction->vm_id + (uint64_t)salt - 1U) %
                        count);
    }
    value = UINT64_C(1469598103934665603);
    for (i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
        value ^= transaction->admission_tx_id[i];
        value *= UINT64_C(1099511628211);
    }
    if (value == 0) {
        value = 1;
    }
    value ^= (uint64_t)salt * UINT64_C(0x517cc1b727220a95);
    return (size_t)(value % count);
}

static const struct wvm_node_runtime_profile *find_recovery_profile(
    const struct wvm_node_runtime_profile *profiles, size_t profile_count,
    uint32_t physical_node_id, uint64_t node_instance_id)
{
    size_t i;

    for (i = 0; i < profile_count; i++) {
        if (profiles[i].physical_node_id == physical_node_id &&
            profiles[i].node_instance_id == node_instance_id) {
            return &profiles[i];
        }
    }
    return NULL;
}

static int synthesize_launch_plan_from_profile(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_node_runtime_profile *profile,
    struct wvm_coordinator_node_launch_plan *launch, char *error,
    size_t error_len)
{
    uint64_t total_memory = 0;
    size_t i;
    size_t data_index;
    size_t service_index;

    if (!candidate || !transaction || !profile || !launch) {
        if (error && error_len) {
            snprintf(error, error_len, "launch plan synthesis input is invalid");
        }
        return -1;
    }
    for (i = 0; i < candidate->memory_placements.count; i++) {
        const uint64_t bytes = candidate->memory_placements.entries[i].bytes;

        if (bytes == 0 || bytes > UINT64_MAX - total_memory) {
            if (error && error_len) {
                snprintf(error, error_len,
                         "recovery candidate memory total is invalid");
            }
            return -1;
        }
        total_memory += bytes;
    }
    if (profile->node_runtime_data_port_count == 0 ||
        profile->local_executor_service_port_count == 0 ||
        !profile->node_runtime_data_ports ||
        !profile->local_executor_service_ports) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "runtime profile lacks listener port pools for node %u",
                     profile->physical_node_id);
        }
        return -1;
    }
    data_index = recovery_port_index(
        transaction, profile->node_runtime_data_port_count, 1U);
    service_index = recovery_port_index(
        transaction, profile->local_executor_service_port_count, 2U);
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
    launch->launch_plan.guest_total_memory_bytes = total_memory;
    launch->launch_plan.guest_machine = candidate->guest_machine;
    launch->launch_plan.consistency_policy = candidate->consistency_policy;
    if (wvm_node_runtime_launch_plan_validate(&launch->launch_plan, error,
                                              error_len) != 0) {
        return -1;
    }
    return 0;
}

/*
 * ACTIVATION_DECIDED may lack durable runtime manifests (crash between
 * record_activation and record_runtime_manifest). Rebuild prepare-style
 * projections from durable candidate + on-disk runtime profiles → launch
 * plans, matching live prepare port binding. commit_local then stamps the
 * activation fence. Missing profiles fail closed.
 */
static int project_runtime_manifests_from_launch_plans(
    const struct wvm_coordinator_transaction *transaction,
    struct recovery_projection *projection, const char *state_directory,
    const struct wvm_membership_controller_capture *membership_capture,
    char *error, size_t error_len)
{
    struct wvm_ctl_runtime_profile_set profiles = {0};
    size_t i;
    int status = -1;

    if (!transaction || !projection || !state_directory || !membership_capture) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "ACTIVATION_DECIDED recovery lacks launch-plan inputs");
        }
        return -1;
    }
    projection->runtime_count =
        projection->prepared_vm.candidate.reservation_requirements.count;
    if (projection->runtime_count == 0) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "recovery candidate has no reservation requirements");
        }
        return -1;
    }
    if (wvm_ctl_load_runtime_profile_set(state_directory, membership_capture,
                                         &profiles, error, error_len) != 0) {
        return -1;
    }

    ALLOC_LIST(projection->manifests, projection->runtime_count);
    ALLOC_LIST(projection->runtime_lists, projection->runtime_count);
    ALLOC_LIST(projection->reservations, projection->runtime_count);
    for (i = 0; i < projection->runtime_count; i++) {
        const struct wvm_reservation_requirement *requirement =
            &projection->prepared_vm.candidate.reservation_requirements
                 .entries[i];
        const struct wvm_node_runtime_profile *profile;
        struct wvm_coordinator_node_launch_plan launch;
        uint64_t local_role_bits =
            WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_NODE_RUNTIME) |
            WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_EXECUTOR);

        if (runtime_storage_init(projection, i, projection->member_capacity,
                                 projection->max_vcpus) != 0) {
            goto allocation_failed;
        }
        profile = find_recovery_profile(
            profiles.profiles, profiles.profile_count,
            requirement->physical_node_id, requirement->node_instance_id);
        if (!profile) {
            if (error && error_len) {
                snprintf(error, error_len,
                         "no durable runtime profile for recovery node %u",
                         requirement->physical_node_id);
            }
            goto out;
        }
        if (synthesize_launch_plan_from_profile(
                &projection->prepared_vm.candidate, transaction, profile,
                &launch, error, error_len) != 0) {
            goto out;
        }
        if (requirement->physical_node_id ==
            projection->prepared_vm.candidate.host_node) {
            local_role_bits |=
                WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_QEMU_FRONTEND);
        }
        if (wvm_resource_reservation_derive(
                requirement, &projection->prepared_vm.candidate,
                projection->prepared_vm.candidate_manifest_digest,
                &projection->reservations[i], 1, error, error_len) != 0 ||
            wvm_node_runtime_manifest_project(
                &projection->prepared_vm.candidate,
                projection->prepared_vm.candidate_manifest_digest,
                &projection->reservations[i], NULL, &launch.launch_plan,
                local_role_bits, &projection->manifests[i], error,
                error_len) != 0) {
            goto out;
        }
    }
    projection->prepared_vm.reservations = projection->reservations;
    projection->prepared_vm.reservation_count = projection->runtime_count;
    projection->prepared_vm.reservation_capacity = projection->runtime_count;
    projection->prepared_vm.node_runtime_manifests = projection->manifests;
    projection->prepared_vm.node_runtime_manifest_count =
        projection->runtime_count;
    projection->prepared_vm.node_runtime_manifest_capacity =
        projection->runtime_count;
    fprintf(stderr,
            "wvm_ctl: ACTIVATION_DECIDED recovery projected %zu runtime "
            "manifest(s) from launch plans\n",
            projection->runtime_count);
    status = 0;
    goto out;

allocation_failed:
    if (error && error_len) {
        snprintf(error, error_len,
                 "cannot allocate recovery launch-plan projection");
    }
out:
    wvm_ctl_runtime_profile_set_destroy(&profiles);
    return status;
}

static int load_runtime_manifests(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    enum wvm_lifecycle_state lifecycle_state,
    struct recovery_projection *projection, const char *state_directory,
    const struct wvm_membership_controller_capture *membership_capture,
    char *error, size_t error_len)
{
    uint8_t *record = NULL;
    size_t record_bytes;
    size_t i;
    int status = -1;
    char durable_error[512];

    projection->runtime_count =
        projection->prepared_vm.candidate.reservation_requirements.count;
    if (projection->runtime_count == 0) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "recovery candidate has no reservation requirements");
        }
        return -1;
    }
    ALLOC_LIST(projection->manifests, projection->runtime_count);
    ALLOC_LIST(projection->runtime_lists, projection->runtime_count);
    ALLOC_LIST(projection->reservations, projection->runtime_count);
    record = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    if (!record) {
        goto allocation_failed;
    }
    durable_error[0] = '\0';
    for (i = 0; i < projection->runtime_count; i++) {
        const struct wvm_reservation_requirement *requirement =
            &projection->prepared_vm.candidate.reservation_requirements
                 .entries[i];

        if (runtime_storage_init(projection, i, projection->member_capacity,
                                 projection->max_vcpus) != 0) {
            goto allocation_failed;
        }
        if (wvm_control_plane_read_runtime_manifest(
                plane, transaction, requirement->physical_node_id,
                requirement->node_instance_id, record,
                WVM_CONTROL_PLANE_MAX_RECORD_BYTES, &record_bytes,
                durable_error, sizeof(durable_error)) != 0 ||
            wvm_node_runtime_manifest_decode(
                record, record_bytes, &projection->manifests[i], durable_error,
                sizeof(durable_error)) != 0) {
            size_t allocated = i + 1U;
            size_t j;

            /* Incomplete durable set: only ACTIVATION_DECIDED may rebuild. */
            free(record);
            record = NULL;
            for (j = 0; j < allocated; j++) {
                free(projection->runtime_lists[j].vcpus);
                free(projection->runtime_lists[j].memory);
                free(projection->runtime_lists[j].storage);
                free(projection->runtime_lists[j].capabilities);
                free(projection->runtime_lists[j].dependencies);
                memset(&projection->runtime_lists[j], 0,
                       sizeof(projection->runtime_lists[j]));
            }
            free(projection->runtime_lists);
            free(projection->manifests);
            free(projection->reservations);
            projection->runtime_lists = NULL;
            projection->manifests = NULL;
            projection->reservations = NULL;
            projection->runtime_count = 0;
            if (lifecycle_state == WVM_LIFECYCLE_ACTIVATION_DECIDED) {
                return project_runtime_manifests_from_launch_plans(
                    transaction, projection, state_directory,
                    membership_capture, error, error_len);
            }
            if (error && error_len) {
                snprintf(error, error_len, "%s",
                         durable_error[0]
                             ? durable_error
                             : "durable runtime manifest missing");
            }
            return -1;
        }
        if (wvm_resource_reservation_derive(
                requirement, &projection->prepared_vm.candidate,
                projection->prepared_vm.candidate_manifest_digest,
                &projection->reservations[i],
                /* Expiry only for PREPARED; commit_local accepts matching
                 * activation anyway. Use a non-zero placeholder. */
                1, error, error_len) != 0) {
            goto out;
        }
    }
    projection->prepared_vm.reservations = projection->reservations;
    projection->prepared_vm.reservation_count = projection->runtime_count;
    projection->prepared_vm.reservation_capacity = projection->runtime_count;
    projection->prepared_vm.node_runtime_manifests = projection->manifests;
    projection->prepared_vm.node_runtime_manifest_count =
        projection->runtime_count;
    projection->prepared_vm.node_runtime_manifest_capacity =
        projection->runtime_count;
    status = 0;
    goto out;

allocation_failed:
    if (error && error_len) {
        snprintf(error, error_len, "cannot allocate recovery runtime projection");
    }
out:
    free(record);
    return status;
}

static int recover_one_entry(
    struct wvm_control_plane *plane,
    struct wvm_membership_controller *membership_controller,
    const struct wvm_admission_authority *authority, const char *state_directory,
    const struct wvm_membership_controller_capture *membership_capture,
    const struct wvm_control_plane_entry *entry, size_t member_capacity,
    uint32_t max_vcpus, size_t route_rule_capacity, size_t route_ack_capacity,
    char *error, size_t error_len)
{
    struct recovery_projection projection = {0};
    struct wvm_coordinator_transaction transaction;
    struct wvm_admission_recovery_input recovery_input;
    uint8_t *record = NULL;
    size_t record_bytes;
    uint64_t membership_revision = 0;
    uint64_t topology_revision = 0;
    uint64_t eligibility_revision = 0;
    size_t node_count = 0;
    size_t gateway_count = 0;
    int status = -1;
    int ready_status;

    projection.member_capacity = member_capacity;
    projection.max_vcpus = max_vcpus;
    memset(&transaction, 0, sizeof(transaction));
    memcpy(transaction.request_id, entry->transaction.request_id,
           sizeof(transaction.request_id));
    transaction.vm_id = entry->transaction.vm_id;
    transaction.vm_incarnation = entry->transaction.vm_incarnation;
    transaction.manifest_generation = entry->transaction.manifest_generation;
    memcpy(transaction.admission_tx_id, entry->transaction.admission_tx_id,
           sizeof(transaction.admission_tx_id));
    memcpy(transaction.manifest_id, entry->transaction.manifest_id,
           sizeof(transaction.manifest_id));
    transaction.route_scope_key = entry->transaction.route_scope_key;

    if (!entry->transaction.has_candidate_manifest_digest ||
        !entry->transaction.has_prepared_route_snapshot_key) {
        if (error && error_len) {
            snprintf(error, error_len,
                     "mid-flight admission lacks durable candidate/route key");
        }
        return -1;
    }
    if (!authority ||
        wvm_admission_authority_validate(authority, error, error_len) != 0) {
        if (error && error_len && error[0] == '\0') {
            snprintf(error, error_len, "admission authority is incomplete");
        }
        return -1;
    }

    record = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    if (!record ||
        candidate_storage_init(&projection, member_capacity, max_vcpus) != 0) {
        if (error && error_len) {
            snprintf(error, error_len, "cannot allocate recovery candidate storage");
        }
        goto out;
    }
    projection.candidate_record = record;
    projection.candidate_record_capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
    record = NULL;
    if (wvm_control_plane_read_candidate(
            plane, &transaction, projection.candidate_record,
            projection.candidate_record_capacity, &record_bytes, error,
            error_len) != 0 ||
        wvm_candidate_vm_manifest_decode(
            projection.candidate_record, record_bytes,
            &projection.prepared_vm.candidate, error, error_len) != 0) {
        goto out;
    }
    {
        uint8_t reencode_digest[WVM_SHA256_DIGEST_BYTES];
        size_t reencode_bytes = 0;

        if (wvm_candidate_vm_manifest_encode(
                &projection.prepared_vm.candidate, projection.candidate_record,
                projection.candidate_record_capacity, &reencode_bytes,
                reencode_digest, error, error_len) != 0) {
            goto out;
        }
        if (memcmp(reencode_digest, entry->transaction.candidate_manifest_digest,
                   sizeof(reencode_digest)) != 0) {
            if (error && error_len) {
                snprintf(error, error_len,
                         "recovered candidate digest differs from durable journal");
            }
            goto out;
        }
        memcpy(projection.prepared_vm.candidate.manifest_digest, reencode_digest,
               sizeof(reencode_digest));
        memcpy(projection.prepared_vm.candidate_manifest_digest, reencode_digest,
               sizeof(reencode_digest));
        projection.candidate_record_bytes = reencode_bytes;
        projection.prepared_vm.candidate_manifest_record =
            projection.candidate_record;
        projection.prepared_vm.candidate_manifest_record_capacity =
            projection.candidate_record_capacity;
        projection.prepared_vm.candidate_manifest_bytes = reencode_bytes;
    }

    /* Serve startup is single-threaded before the control listener starts. */
    membership_revision = membership_controller->membership_revision;
    topology_revision = membership_controller->topology_revision;
    eligibility_revision = membership_controller->admission_eligibility_revision;
    if (membership_revision == 0) {
        membership_revision = 1;
    }
    if (topology_revision == 0) {
        topology_revision = 1;
    }
    (void)eligibility_revision;
    (void)node_count;
    (void)gateway_count;
    if (bind_plan_and_admission_request(&projection, &transaction,
                                       membership_revision, topology_revision,
                                       error, error_len) != 0) {
        goto out;
    }
    if (load_runtime_manifests(plane, &transaction, entry->transaction.state,
                               &projection, state_directory, membership_capture,
                               error, error_len) != 0) {
        goto out;
    }

    ALLOC_LIST(projection.route_rules, route_rule_capacity);
    ALLOC_LIST(projection.route_acks, route_ack_capacity);
    ALLOC_LIST(projection.route_tx_acks, route_ack_capacity);
    ALLOC_LIST(projection.route_tx_drain, route_ack_capacity);
    memset(&projection.route_snapshot, 0, sizeof(projection.route_snapshot));
    projection.route_snapshot.next_hop_rules.entries = projection.route_rules;
    projection.route_snapshot.next_hop_rules.capacity = route_rule_capacity;
    projection.route_snapshot.required_ack_set.entries.entries =
        projection.route_acks;
    projection.route_snapshot.required_ack_set.entries.capacity =
        route_ack_capacity;
    memset(&projection.route_transaction, 0,
           sizeof(projection.route_transaction));
    projection.route_transaction.required_ack_set.entries.entries =
        projection.route_tx_acks;
    projection.route_transaction.required_ack_set.entries.capacity =
        route_ack_capacity;
    projection.route_transaction.optional_departure_drain_set.entries =
        projection.route_tx_drain;
    projection.route_transaction.optional_departure_drain_set.capacity =
        route_ack_capacity;
    if (find_route_operation_for_snapshot(
            plane, &entry->transaction.prepared_route_snapshot_key,
            projection.route_transaction.operation_id, route_ack_capacity, error,
            error_len) != 0) {
        goto out;
    }

    memset(&recovery_input, 0, sizeof(recovery_input));
    recovery_input.control_plane = plane;
    recovery_input.transaction = &transaction;
    recovery_input.prepared_vm = &projection.prepared_vm;
    recovery_input.route_transaction = &projection.route_transaction;
    recovery_input.route_snapshot = &projection.route_snapshot;
    recovery_input.callbacks = &authority->callbacks;
    recovery_input.callback_context = authority->context;
    recovery_input.membership_controller = membership_controller;

    ready_status =
        wvm_admission_orchestrator_recover(&recovery_input, error, error_len);
    if (ready_status == 0 || ready_status == -EAGAIN) {
        /*
         * orchestrator_recover fail-closed republishes membership route +
         * dependency_acquire before readiness when membership_controller is
         * set (COMMITTED / ACTIVATION_DECIDED). Log that path for cold-start
         * vertical evidence; do not invent a second acquire here.
         */
        if (membership_controller) {
            fprintf(stderr,
                    "wvm_ctl: mid-flight recovery republished membership "
                    "route+dependencies for vm_id=%u incarnation=%llu "
                    "generation=%llu (ready_status=%d)\n",
                    (unsigned)transaction.vm_id,
                    (unsigned long long)transaction.vm_incarnation,
                    (unsigned long long)transaction.manifest_generation,
                    ready_status);
        }
        status = 0;
        if (error && error_len) {
            error[0] = '\0';
        }
    }
    goto out;

allocation_failed:
    if (error && error_len) {
        snprintf(error, error_len, "cannot allocate admission recovery scratch");
    }
out:
    free(record);
    projection_destroy(&projection);
    return status;
}

int wvm_ctl_recover_midflight_admissions(
    struct wvm_control_plane *plane,
    struct wvm_membership_controller *membership_controller,
    const struct wvm_admission_authority *authority, const char *state_directory,
    const struct wvm_membership_controller_capture *membership_capture,
    size_t member_capacity, uint32_t max_vcpus, size_t route_rule_capacity,
    size_t route_ack_capacity, char *error, size_t error_len)
{
    size_t i;

    if (!plane || plane->journal_fd < 0 || plane->journal_failed ||
        !membership_controller || !authority || !state_directory ||
        !membership_capture || member_capacity == 0 || max_vcpus == 0 ||
        route_rule_capacity == 0 || route_ack_capacity == 0) {
        if (error && error_len) {
            snprintf(error, error_len, "admission recovery scan input is invalid");
        }
        return -1;
    }
    for (i = 0; i < plane->entry_count; i++) {
        const struct wvm_control_plane_entry *entry = &plane->entries[i];
        char entry_error[512];

        if (!lifecycle_needs_recover(entry->transaction.state)) {
            continue;
        }
        entry_error[0] = '\0';
        fprintf(stderr,
                "wvm_ctl: recovering mid-flight admission vm_id=%u "
                "incarnation=%llu state=%u\n",
                entry->transaction.vm_id,
                (unsigned long long)entry->transaction.vm_incarnation,
                (unsigned)entry->transaction.state);
        if (recover_one_entry(plane, membership_controller, authority,
                              state_directory, membership_capture, entry,
                              member_capacity, max_vcpus, route_rule_capacity,
                              route_ack_capacity, entry_error,
                              sizeof(entry_error)) != 0) {
            fprintf(stderr,
                    "wvm_ctl: admission recovery fail-closed for vm_id=%u: %s\n",
                    entry->transaction.vm_id,
                    entry_error[0] ? entry_error : "unknown error");
            if (error && error_len) {
                snprintf(error, error_len, "%s",
                         entry_error[0] ? entry_error
                                        : "admission recovery failed");
            }
            return -1;
        }
    }
    fprintf(stderr, "wvm_ctl: mid-flight admission recovery scan complete\n");
    if (error && error_len) {
        error[0] = '\0';
    }
    return 0;
}

static const struct wvm_control_plane_entry *find_entry_by_vm_identity(
    const struct wvm_control_plane *plane, uint32_t vm_id,
    uint64_t vm_incarnation, uint64_t manifest_generation)
{
    size_t i;
    const struct wvm_control_plane_entry *found = NULL;

    if (!plane || vm_id == 0 || vm_incarnation == 0) {
        return NULL;
    }
    for (i = 0; i < plane->entry_count; i++) {
        const struct wvm_control_plane_entry *entry = &plane->entries[i];

        if (entry->transaction.vm_id != vm_id ||
            entry->transaction.vm_incarnation != vm_incarnation) {
            continue;
        }
        if (manifest_generation != 0 &&
            entry->transaction.manifest_generation != manifest_generation) {
            continue;
        }
        if (found) {
            return NULL; /* ambiguous */
        }
        found = entry;
    }
    return found;
}

static int load_route_transaction_for_snapshot(
    const struct wvm_control_plane *plane,
    const struct wvm_route_snapshot_key *snapshot_key,
    struct wvm_route_transaction_record *route_out,
    struct wvm_required_ack_entry *acks, size_t ack_capacity,
    struct wvm_required_ack_entry *drain, size_t drain_capacity, char *error,
    size_t error_len)
{
    size_t i;
    int found = 0;

    if (!plane || !snapshot_key || !route_out || !acks || ack_capacity == 0) {
        if (error && error_len) {
            snprintf(error, error_len, "STOP route load input is invalid");
        }
        return -1;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        struct wvm_route_transaction_record decoded;
        const struct wvm_control_plane_route_entry *entry =
            &plane->route_entries[i];
        char decode_error[256];

        if (!entry->record_bytes || entry->record_byte_count == 0) {
            continue;
        }
        memset(&decoded, 0, sizeof(decoded));
        decoded.required_ack_set.entries.entries = acks;
        decoded.required_ack_set.entries.capacity = ack_capacity;
        decoded.optional_departure_drain_set.entries = drain;
        decoded.optional_departure_drain_set.capacity = drain_capacity;
        decode_error[0] = '\0';
        if (wvm_route_transaction_record_decode(
                entry->record_bytes, entry->record_byte_count, &decoded,
                decode_error, sizeof(decode_error)) != 0) {
            continue;
        }
        if (decoded.route_snapshot_key.scope_key.vm_id ==
                snapshot_key->scope_key.vm_id &&
            decoded.route_snapshot_key.scope_key.vm_incarnation ==
                snapshot_key->scope_key.vm_incarnation &&
            decoded.route_snapshot_key.scope_key.route_scope_id ==
                snapshot_key->scope_key.route_scope_id &&
            decoded.route_snapshot_key.topology_revision ==
                snapshot_key->topology_revision &&
            decoded.route_snapshot_key.route_generation ==
                snapshot_key->route_generation &&
            memcmp(decoded.route_snapshot_key.snapshot_digest,
                   snapshot_key->snapshot_digest,
                   WVM_SHA256_DIGEST_BYTES) == 0) {
            if (found) {
                if (error && error_len) {
                    snprintf(error, error_len,
                             "STOP route snapshot is ambiguous");
                }
                return -1;
            }
            *route_out = decoded;
            /* Prefer durable entry state if present. */
            route_out->state = entry->state ? entry->state : decoded.state;
            found = 1;
        }
    }
    if (!found) {
        if (error && error_len) {
            snprintf(error, error_len, "STOP route transaction was not found");
        }
        return -1;
    }
    return 0;
}

int wvm_ctl_stop_vm(
    struct wvm_control_plane *plane,
    struct wvm_vm_namespace_allocator *namespace_allocator,
    struct wvm_membership_controller *membership_controller,
    const struct wvm_admission_authority *authority,
    const char *state_directory,
    const struct wvm_membership_controller_capture *membership_capture,
    uint32_t vm_id, uint64_t vm_incarnation, uint64_t manifest_generation,
    size_t member_capacity, uint32_t max_vcpus, size_t route_rule_capacity,
    size_t route_ack_capacity, struct wvm_control_result *result, char *error,
    size_t error_len)
{
    const struct wvm_control_plane_entry *entry;
    struct recovery_projection projection = {0};
    struct wvm_coordinator_transaction transaction;
    struct wvm_admission_stop_input stop_input;
    struct wvm_activation_record activation;
    struct wvm_route_snapshot_key activation_keys[4];
    uint8_t *activation_bytes = NULL;
    size_t activation_byte_count = 0;
    uint8_t *candidate_record = NULL;
    size_t record_bytes = 0;
    size_t i;
    int status = -1;

    (void)route_rule_capacity;
    if (!result) {
        if (error && error_len) {
            snprintf(error, error_len, "STOP_VM result storage is missing");
        }
        return -EINVAL;
    }
    memset(result, 0, sizeof(*result));
    result->status_code = WVM_CONTROL_RESULT_INTERNAL_FAILURE;
    if (!plane || !namespace_allocator || vm_id == 0 || vm_incarnation == 0) {
        result->status_code = WVM_CONTROL_RESULT_INVALID_REQUEST;
        return 0;
    }
    entry = find_entry_by_vm_identity(plane, vm_id, vm_incarnation,
                                      manifest_generation);
    if (!entry) {
        result->status_code = WVM_CONTROL_RESULT_NOT_FOUND;
        if (error && error_len) {
            snprintf(error, error_len,
                     "STOP_VM target VM was not found in durable control plane");
        }
        return 0;
    }
    result->vm_id = entry->transaction.vm_id;
    result->vm_incarnation = entry->transaction.vm_incarnation;
    result->manifest_generation = entry->transaction.manifest_generation;
    result->route_scope_id = entry->transaction.route_scope_key.route_scope_id;
    result->recorded_state = (uint16_t)entry->transaction.state;
    memcpy(result->admission_tx_id, entry->transaction.admission_tx_id,
           sizeof(result->admission_tx_id));
    memcpy(result->manifest_id, entry->transaction.manifest_id,
           sizeof(result->manifest_id));
    if (entry->transaction.state == WVM_LIFECYCLE_STOPPED) {
        result->status_code = WVM_CONTROL_RESULT_SUCCESS;
        return 0;
    }
    if (entry->transaction.state != WVM_LIFECYCLE_RUNNING &&
        entry->transaction.state != WVM_LIFECYCLE_STOPPING &&
        entry->transaction.state != WVM_LIFECYCLE_RETIRING) {
        result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
        if (error && error_len) {
            snprintf(error, error_len,
                     "STOP_VM requires RUNNING/STOPPING/RETIRING (state=%u)",
                     (unsigned)entry->transaction.state);
        }
        return 0;
    }
    if (!entry->transaction.has_candidate_manifest_digest ||
        !entry->transaction.has_prepared_route_snapshot_key ||
        !entry->transaction.has_activation_record_digest) {
        result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
        if (error && error_len) {
            snprintf(error, error_len,
                     "STOP_VM lacks durable candidate/route/activation");
        }
        return 0;
    }

    memset(&transaction, 0, sizeof(transaction));
    memcpy(transaction.request_id, entry->transaction.request_id,
           sizeof(transaction.request_id));
    transaction.vm_id = entry->transaction.vm_id;
    transaction.vm_incarnation = entry->transaction.vm_incarnation;
    transaction.manifest_generation = entry->transaction.manifest_generation;
    memcpy(transaction.admission_tx_id, entry->transaction.admission_tx_id,
           sizeof(transaction.admission_tx_id));
    memcpy(transaction.manifest_id, entry->transaction.manifest_id,
           sizeof(transaction.manifest_id));
    transaction.route_scope_key = entry->transaction.route_scope_key;

    projection.member_capacity = member_capacity;
    projection.max_vcpus = max_vcpus;
    candidate_record = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    activation_bytes = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    if (!candidate_record || !activation_bytes ||
        candidate_storage_init(&projection, member_capacity, max_vcpus) != 0) {
        if (error && error_len) {
            snprintf(error, error_len, "cannot allocate STOP projection");
        }
        goto out;
    }
    projection.candidate_record = candidate_record;
    projection.candidate_record_capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
    candidate_record = NULL;
    if (wvm_control_plane_read_candidate(
            plane, &transaction, projection.candidate_record,
            projection.candidate_record_capacity, &record_bytes, error,
            error_len) != 0 ||
        wvm_candidate_vm_manifest_decode(
            projection.candidate_record, record_bytes,
            &projection.prepared_vm.candidate, error, error_len) != 0) {
        goto out;
    }
    {
        uint8_t reencode_digest[WVM_SHA256_DIGEST_BYTES];
        size_t reencode_bytes = 0;

        if (wvm_candidate_vm_manifest_encode(
                &projection.prepared_vm.candidate, projection.candidate_record,
                projection.candidate_record_capacity, &reencode_bytes,
                reencode_digest, error, error_len) != 0) {
            goto out;
        }
        if (memcmp(reencode_digest, entry->transaction.candidate_manifest_digest,
                   sizeof(reencode_digest)) != 0) {
            if (error && error_len) {
                snprintf(error, error_len,
                         "STOP candidate digest differs from durable journal");
            }
            goto out;
        }
        memcpy(projection.prepared_vm.candidate.manifest_digest, reencode_digest,
               sizeof(reencode_digest));
        memcpy(projection.prepared_vm.candidate_manifest_digest, reencode_digest,
               sizeof(reencode_digest));
        projection.candidate_record_bytes = reencode_bytes;
        projection.prepared_vm.candidate_manifest_record =
            projection.candidate_record;
        projection.prepared_vm.candidate_manifest_record_capacity =
            projection.candidate_record_capacity;
        projection.prepared_vm.candidate_manifest_bytes = reencode_bytes;
    }
    if (bind_plan_and_admission_request(
            &projection, &transaction,
            membership_controller ? membership_controller->membership_revision
                                  : 1,
            membership_controller ? membership_controller->topology_revision : 1,
            error, error_len) != 0) {
        goto out;
    }
    if (load_runtime_manifests(plane, &transaction, entry->transaction.state,
                               &projection, state_directory, membership_capture,
                               error, error_len) != 0) {
        goto out;
    }

    memset(&activation, 0, sizeof(activation));
    activation.required_route_snapshot_keys = activation_keys;
    activation.required_route_snapshot_capacity =
        sizeof(activation_keys) / sizeof(activation_keys[0]);
    if (wvm_control_plane_read_activation(
            plane, &transaction, activation_bytes,
            WVM_CONTROL_PLANE_MAX_RECORD_BYTES, &activation_byte_count, error,
            error_len) != 0 ||
        wvm_activation_record_decode(activation_bytes, activation_byte_count,
                                     &activation, error, error_len) != 0 ||
        activation.decision != WVM_ACTIVATION_ACTIVATE) {
        if (error && error_len && error[0] == '\0') {
            snprintf(error, error_len, "STOP lacks durable ACTIVATE decision");
        }
        goto out;
    }
    for (i = 0; i < projection.prepared_vm.reservation_count; i++) {
        if (projection.prepared_vm.reservations[i].state !=
                WVM_RESERVATION_COMMITTED &&
            wvm_resource_reservation_commit(
                &projection.prepared_vm.reservations[i], &activation, error,
                error_len) != 0) {
            goto out;
        }
    }

    projection.route_acks = calloc(route_ack_capacity, sizeof(*projection.route_acks));
    projection.route_tx_acks =
        calloc(route_ack_capacity, sizeof(*projection.route_tx_acks));
    projection.route_tx_drain =
        calloc(route_ack_capacity, sizeof(*projection.route_tx_drain));
    if (!projection.route_acks || !projection.route_tx_acks ||
        !projection.route_tx_drain) {
        if (error && error_len) {
            snprintf(error, error_len, "cannot allocate STOP route ack storage");
        }
        goto out;
    }
    memset(&projection.route_transaction, 0, sizeof(projection.route_transaction));
    if (load_route_transaction_for_snapshot(
            plane, &entry->transaction.prepared_route_snapshot_key,
            &projection.route_transaction, projection.route_tx_acks,
            route_ack_capacity, projection.route_tx_drain, route_ack_capacity,
            error, error_len) != 0) {
        goto out;
    }

    memset(&stop_input, 0, sizeof(stop_input));
    stop_input.control_plane = plane;
    stop_input.transaction = &transaction;
    stop_input.prepared_vm = &projection.prepared_vm;
    stop_input.route_transaction = &projection.route_transaction;
    stop_input.membership_controller = membership_controller;
    stop_input.namespace_allocator = namespace_allocator;
    if (authority) {
        stop_input.callbacks = &authority->callbacks;
        stop_input.callback_context = authority->context;
    }
    if (wvm_admission_orchestrator_stop(&stop_input, error, error_len) != 0) {
        result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
        goto out;
    }
    entry = wvm_control_plane_find_request(plane, transaction.request_id);
    if (!entry || entry->transaction.state != WVM_LIFECYCLE_STOPPED) {
        result->status_code = WVM_CONTROL_RESULT_INTERNAL_FAILURE;
        if (error && error_len) {
            snprintf(error, error_len, "STOP_VM did not reach durable STOPPED");
        }
        goto out;
    }
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    result->recorded_state = (uint16_t)entry->transaction.state;
    result->applied_revision = entry->transaction.transaction_sequence;
    status = 0;
    if (error && error_len) {
        error[0] = '\0';
    }
out:
    free(activation_bytes);
    free(candidate_record);
    projection_destroy(&projection);
    return status == 0 ? 0 : (result->status_code == WVM_CONTROL_RESULT_INTERNAL_FAILURE ? -EIO : 0);
}

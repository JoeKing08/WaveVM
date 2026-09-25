#include "admission_readiness.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct runtime_lists {
    struct wvm_vcpu_assignment *vcpus;
    struct wvm_memory_chunk_assignment *memory;
    struct wvm_storage_assignment *storage;
    struct wvm_capability_ref *capabilities;
    struct wvm_startup_dependency *dependencies;
};

struct replay_projection {
    struct wvm_candidate_vm_manifest candidate;
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
    size_t runtime_count;
};

static void projection_destroy(struct replay_projection *projection)
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
    free(projection->vcpus);
    free(projection->memory);
    free(projection->storage);
    free(projection->members);
    free(projection->capabilities);
    free(projection->execution_capabilities);
    free(projection->requirements);
    free(projection->leases);
    memset(projection, 0, sizeof(*projection));
}

#define ALLOC_LIST(field, count)                                            \
    do {                                                                    \
        (field) = calloc((count) ? (count) : 1U, sizeof(*(field)));         \
        if (!(field)) {                                                     \
            goto allocation_failed;                                        \
        }                                                                   \
    } while (0)

static int candidate_storage_init(struct replay_projection *projection,
                                  size_t members, uint32_t vcpus)
{
    struct wvm_candidate_vm_manifest *candidate = &projection->candidate;
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

static int runtime_storage_init(struct replay_projection *projection,
                                size_t index, size_t members,
                                uint32_t vcpus)
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

int wvm_ctl_resume_runtime_readiness(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    size_t member_capacity, uint32_t requested_vcpus,
    wvm_control_plane_readiness_observer_fn observe_ready,
    void *observer_context, char *error, size_t error_len)
{
    struct replay_projection projection = {0};
    uint8_t *record = NULL;
    size_t record_bytes;
    size_t i;
    int status = -1;

    if (!plane || !transaction || !observe_ready || member_capacity == 0 ||
        requested_vcpus == 0) {
        if (error && error_len) {
            snprintf(error, error_len, "runtime replay input is invalid");
        }
        return -1;
    }
    record = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    if (!record || candidate_storage_init(&projection, member_capacity,
                                          requested_vcpus) != 0) {
        goto allocation_failed;
    }
    if (wvm_control_plane_read_candidate(
            plane, transaction, record, WVM_CONTROL_PLANE_MAX_RECORD_BYTES,
            &record_bytes, error, error_len) != 0 ||
        wvm_candidate_vm_manifest_decode(
            record, record_bytes, &projection.candidate, error, error_len) != 0 ||
        projection.candidate.reservation_requirements.count == 0) {
        goto out;
    }
    projection.runtime_count =
        projection.candidate.reservation_requirements.count;
    ALLOC_LIST(projection.manifests, projection.runtime_count);
    ALLOC_LIST(projection.runtime_lists, projection.runtime_count);
    for (i = 0; i < projection.runtime_count; i++) {
        const struct wvm_reservation_requirement *requirement =
            &projection.candidate.reservation_requirements.entries[i];

        if (runtime_storage_init(&projection, i, member_capacity,
                                 requested_vcpus) != 0) {
            goto allocation_failed;
        }
        if (wvm_control_plane_read_runtime_manifest(
                plane, transaction, requirement->physical_node_id,
                requirement->node_instance_id, record,
                WVM_CONTROL_PLANE_MAX_RECORD_BYTES, &record_bytes, error,
                error_len) != 0 ||
            wvm_node_runtime_manifest_decode(
                record, record_bytes, &projection.manifests[i], error,
                error_len) != 0) {
            goto out;
        }
    }
    status = wvm_control_plane_start_if_participants_ready(
        plane, transaction, &projection.candidate, projection.manifests,
        projection.runtime_count, observe_ready, observer_context, error,
        error_len);
    goto out;

allocation_failed:
    if (error && error_len) {
        snprintf(error, error_len, "cannot allocate runtime replay projection");
    }
out:
    free(record);
    projection_destroy(&projection);
    return status;
}

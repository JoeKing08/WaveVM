#include "admission_workspace.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../common_include/wavevm_envelope.h"

enum buffer_index {
    SELECTED_MEMBERS,
    VCPUS,
    MEMORY,
    REQUIREMENTS,
    CAPABILITIES,
    RESERVATIONS,
    RUNTIMES,
    LOCAL_VCPUS,
    LOCAL_MEMORY,
    DEPENDENCIES,
    ACTIVATION_ROUTES,
    PLACEMENT_BYTES,
    CANDIDATE_BYTES,
    BUFFER_COUNT
};

struct buffer_layout {
    size_t count;
    size_t stride;
    size_t offset;
};

int wvm_ctl_admission_buffers_reset(
    struct wvm_ctl_admission_buffers *buffers, uint32_t requested_vcpus,
    size_t node_count, size_t member_count, size_t byte_limit,
    struct wvm_coordinator_prepared_vm *prepared,
    struct wvm_coordinator_prepare_options *options,
    struct wvm_activation_record *activation, char *error, size_t error_len)
{
    struct buffer_layout layout[BUFFER_COUNT] = {
        {member_count, sizeof(struct wvm_required_member), 0},
        {requested_vcpus, sizeof(struct wvm_vcpu_assignment), 0},
        {node_count, sizeof(struct wvm_memory_chunk_assignment), 0},
        {node_count, sizeof(struct wvm_reservation_requirement), 0},
        {member_count, sizeof(struct wvm_capability_ref), 0},
        {node_count, sizeof(struct wvm_resource_reservation), 0},
        {node_count, sizeof(struct wvm_node_runtime_manifest), 0},
        {requested_vcpus, sizeof(struct wvm_vcpu_assignment), 0},
        {node_count, sizeof(struct wvm_memory_chunk_assignment), 0},
        {member_count, sizeof(struct wvm_startup_dependency), 0},
        {1, sizeof(struct wvm_route_snapshot_key), 0},
        {WVM_ENVELOPE_MAX_LOCAL_PAYLOAD, 1, 0},
        {WVM_ENVELOPE_MAX_LOCAL_PAYLOAD, 1, 0},
    };
    uint8_t *allocation;
    void *parts[BUFFER_COUNT];
    size_t total = 0;
    size_t i;

    if (!buffers || !prepared || !options || !activation ||
        !requested_vcpus || !node_count || node_count > member_count ||
        member_count > UINT32_MAX || !byte_limit) {
        if (error && error_len) {
            snprintf(error, error_len, "invalid admission workspace dimensions");
        }
        return -1;
    }
    /* Projection currently requires full candidate-list capacity per runtime.
     * Bound the complete allocation before allocating any of these lists. */
    for (i = LOCAL_VCPUS; i <= DEPENDENCIES; i++) {
        if (layout[i].count > SIZE_MAX / node_count) {
            goto capacity;
        }
        layout[i].count *= node_count;
    }
    for (i = 0; i < BUFFER_COUNT; i++) {
        size_t alignment = _Alignof(max_align_t);
        size_t padding = (alignment - total % alignment) % alignment;

        if (padding > byte_limit - total) {
            goto capacity;
        }
        total += padding;
        layout[i].offset = total;
        if (layout[i].count > (byte_limit - total) / layout[i].stride) {
            goto capacity;
        }
        total += layout[i].count * layout[i].stride;
    }
    allocation = calloc(total, 1);
    if (!allocation) {
        if (error && error_len) {
            snprintf(error, error_len, "cannot allocate admission workspace");
        }
        return -1;
    }
    for (i = 0; i < BUFFER_COUNT; i++) {
        parts[i] = allocation + layout[i].offset;
    }

    wvm_ctl_admission_buffers_destroy(buffers, prepared);
    buffers->allocation = allocation;
    buffers->allocated_bytes = total;
    prepared->fence.selected_members.entries = parts[SELECTED_MEMBERS];
    prepared->fence.selected_members.capacity = member_count;
    prepared->placement_plan.vcpu_assignments.entries = parts[VCPUS];
    prepared->placement_plan.vcpu_assignments.capacity = requested_vcpus;
    prepared->placement_plan.memory_assignments.entries = parts[MEMORY];
    prepared->placement_plan.memory_assignments.capacity = node_count;
    prepared->placement_plan.reservation_requirements.entries = parts[REQUIREMENTS];
    prepared->placement_plan.reservation_requirements.capacity = node_count;
    prepared->candidate.required_capabilities.entries = parts[CAPABILITIES];
    prepared->candidate.required_capabilities.capacity = member_count;
    prepared->reservations = parts[RESERVATIONS];
    prepared->reservation_capacity = node_count;
    prepared->node_runtime_manifests = parts[RUNTIMES];
    prepared->node_runtime_manifest_capacity = node_count;
    for (i = 0; i < node_count; i++) {
        struct wvm_node_runtime_manifest *runtime =
            &prepared->node_runtime_manifests[i];

        runtime->local_vcpu_assignments.entries =
            (struct wvm_vcpu_assignment *)parts[LOCAL_VCPUS] +
            i * requested_vcpus;
        runtime->local_vcpu_assignments.capacity = requested_vcpus;
        runtime->local_memory_assignments.entries =
            (struct wvm_memory_chunk_assignment *)parts[LOCAL_MEMORY] +
            i * node_count;
        runtime->local_memory_assignments.capacity = node_count;
        runtime->startup_dependencies.entries =
            (struct wvm_startup_dependency *)parts[DEPENDENCIES] +
            i * member_count;
        runtime->startup_dependencies.capacity = member_count;
    }
    options->placement_plan_bytes = parts[PLACEMENT_BYTES];
    options->placement_plan_bytes_capacity = WVM_ENVELOPE_MAX_LOCAL_PAYLOAD;
    options->candidate_manifest_bytes = parts[CANDIDATE_BYTES];
    options->candidate_manifest_bytes_capacity = WVM_ENVELOPE_MAX_LOCAL_PAYLOAD;
    memset(activation, 0, sizeof(*activation));
    activation->required_route_snapshot_keys = parts[ACTIVATION_ROUTES];
    activation->required_route_snapshot_capacity = 1;
    return 0;

capacity:
    if (error && error_len) {
        snprintf(error, error_len, "admission workspace exceeds byte budget");
    }
    return -1;
}

void wvm_ctl_admission_buffers_destroy(
    struct wvm_ctl_admission_buffers *buffers,
    struct wvm_coordinator_prepared_vm *prepared)
{
    if (!buffers || !prepared) {
        return;
    }
    wvm_coordinator_prepared_vm_cleanup(prepared);
    memset(prepared, 0, sizeof(*prepared));
    free(buffers->allocation);
    memset(buffers, 0, sizeof(*buffers));
}

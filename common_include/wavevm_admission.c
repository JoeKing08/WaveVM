#include "wavevm_admission.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_sha256.h"

int wvm_admission_snapshot_init(struct wvm_admission_snapshot *snapshot,
                                uint32_t initial_capacity)
{
    if (!snapshot || initial_capacity == 0) {
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->nodes = calloc(initial_capacity, sizeof(struct wvm_admission_node));
    if (!snapshot->nodes) {
        return -1;
    }
    snapshot->node_capacity = initial_capacity;
    snapshot->node_count = 0;
    return 0;
}

void wvm_admission_snapshot_cleanup(struct wvm_admission_snapshot *snapshot)
{
    if (snapshot && snapshot->nodes) {
        free(snapshot->nodes);
        snapshot->nodes = NULL;
        snapshot->node_capacity = 0;
        snapshot->node_count = 0;
    }
}

int wvm_admission_snapshot_copy(const struct wvm_admission_snapshot *src,
                                struct wvm_admission_snapshot *dst)
{
    struct wvm_admission_snapshot copy;

    if (!src || !dst || src->node_count > src->node_capacity ||
        (src->node_count != 0 &&
         (!src->nodes || sizeof(*src->nodes) > SIZE_MAX / src->node_count))) {
        return -1;
    }
    if (src == dst) {
        return 0;
    }
    copy = *src;
    copy.nodes = NULL;
    copy.node_capacity = src->node_count;
    if (src->node_count > 0) {
        copy.nodes = malloc(src->node_count * sizeof(*copy.nodes));
        if (!copy.nodes) {
            return -1;
        }
        memcpy(copy.nodes, src->nodes, src->node_count * sizeof(*copy.nodes));
    }
    *dst = copy;
    return 0;
}

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static int valid_member_state(enum wvm_admission_member_state state)
{
    return state >= WVM_ADMISSION_MEMBER_PENDING &&
           state <= WVM_ADMISSION_MEMBER_FAILED;
}

static int valid_health_state(enum wvm_admission_health_state state)
{
    return state >= WVM_ADMISSION_HEALTHY &&
           state <= WVM_ADMISSION_RECOVERING;
}

static int valid_backend(enum wvm_admission_backend backend)
{
    return backend == WVM_ADMISSION_BACKEND_KVM ||
           backend == WVM_ADMISSION_BACKEND_TCG;
}

static uint32_t backend_capability(enum wvm_admission_backend backend)
{
    return backend == WVM_ADMISSION_BACKEND_KVM
               ? WVM_ADMISSION_BACKEND_CAP_KVM
               : WVM_ADMISSION_BACKEND_CAP_TCG;
}

static int node_index_by_id(const struct wvm_admission_snapshot *snapshot,
                            uint32_t physical_node_id)
{
    uint32_t i;

    for (i = 0; i < snapshot->node_count; i++) {
        if (snapshot->nodes[i].physical_node_id == physical_node_id) {
            return (int)i;
        }
    }
    return -1;
}

static int id_is_zero(const uint8_t id[WVM_ADMISSION_ID_BYTES])
{
    uint32_t i;

    for (i = 0; i < WVM_ADMISSION_ID_BYTES; i++) {
        if (id[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int digest_is_zero(const uint8_t digest[WVM_SHA256_DIGEST_BYTES])
{
    size_t i;

    for (i = 0; i < WVM_SHA256_DIGEST_BYTES; i++) {
        if (digest[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int node_is_active_and_healthy(const struct wvm_admission_node *node)
{
    return node && node->membership_state == WVM_ADMISSION_MEMBER_ACTIVE &&
           node->health_state == WVM_ADMISSION_HEALTHY;
}

static int node_is_executor_eligible(
    const struct wvm_admission_node *node,
    enum wvm_admission_backend backend)
{
    return node_is_active_and_healthy(node) &&
           (node->backend_capabilities & backend_capability(backend)) != 0;
}

static int node_is_memory_eligible(const struct wvm_admission_node *node)
{
    return node_is_active_and_healthy(node) &&
           (node->runtime_capabilities &
            WVM_ADMISSION_RUNTIME_CAP_MODE_B_MEMORY) != 0;
}

static int node_available_capacity(const struct wvm_admission_node *node,
                                   uint32_t *vcpu_slots,
                                   uint64_t *memory_bytes)
{
    uint64_t consumed_memory;
    uint64_t consumed_cpu;

    if (!node || !vcpu_slots || !memory_bytes ||
        node->prepared_vcpu_slots > node->allocatable_vcpu_slots ||
        node->committed_vcpu_slots >
            node->allocatable_vcpu_slots - node->prepared_vcpu_slots ||
        node->prepared_memory_bytes > node->allocatable_memory_bytes ||
        node->committed_memory_bytes >
            node->allocatable_memory_bytes - node->prepared_memory_bytes) {
        return -1;
    }
    consumed_cpu = (uint64_t)node->prepared_vcpu_slots +
                   node->committed_vcpu_slots;
    consumed_memory = node->prepared_memory_bytes + node->committed_memory_bytes;
    *vcpu_slots = (uint32_t)(node->allocatable_vcpu_slots - consumed_cpu);
    *memory_bytes = node->allocatable_memory_bytes - consumed_memory;
    return 0;
}

static int fraction_compare(uint64_t left_numerator,
                            uint64_t left_denominator,
                            uint64_t right_numerator,
                            uint64_t right_denominator)
{
    __uint128_t left;
    __uint128_t right;

    if (left_denominator == 0 || right_denominator == 0) {
        return left_denominator == right_denominator ? 0
                                                     : (left_denominator == 0 ? 1 : -1);
    }
    left = (__uint128_t)left_numerator * right_denominator;
    right = (__uint128_t)right_numerator * left_denominator;
    return left < right ? -1 : (left > right ? 1 : 0);
}

static int projected_max_utilization_compare(
    uint64_t left_cpu_used, uint64_t left_cpu_capacity,
    uint64_t left_memory_used, uint64_t left_memory_capacity,
    uint64_t right_cpu_used, uint64_t right_cpu_capacity,
    uint64_t right_memory_used, uint64_t right_memory_capacity)
{
    int left_cpu_is_max = fraction_compare(left_cpu_used, left_cpu_capacity,
                                           left_memory_used,
                                           left_memory_capacity) >= 0;
    int right_cpu_is_max = fraction_compare(right_cpu_used, right_cpu_capacity,
                                            right_memory_used,
                                            right_memory_capacity) >= 0;

    return fraction_compare(left_cpu_is_max ? left_cpu_used : left_memory_used,
                            left_cpu_is_max ? left_cpu_capacity
                                            : left_memory_capacity,
                            right_cpu_is_max ? right_cpu_used
                                             : right_memory_used,
                            right_cpu_is_max ? right_cpu_capacity
                                             : right_memory_capacity);
}

int wvm_admission_snapshot_validate(const struct wvm_admission_snapshot *snapshot,
                                    char *error, size_t error_len)
{
    uint32_t i;

    if (!snapshot || snapshot->node_count == 0 ||
        snapshot->inventory_revision == 0 ||
        snapshot->membership_revision == 0 || snapshot->topology_revision == 0 ||
        snapshot->capability_profile_generation == 0) {
        set_error(error, error_len, "admission snapshot has invalid metadata");
        return -1;
    }

    if (snapshot->node_count > snapshot->node_capacity) {
        set_error(error, error_len,
                  "admission snapshot node_count %u exceeds capacity %u",
                  snapshot->node_count, snapshot->node_capacity);
        return -1;
    }

    for (i = 0; i < snapshot->node_count; i++) {
        const struct wvm_admission_node *node = &snapshot->nodes[i];
        uint64_t reserved_memory;
        uint32_t available_vcpu;
        uint64_t available_memory;

        if (node->physical_node_id == 0 || node->node_instance_id == 0 ||
            node->inventory_revision == 0 ||
            !valid_member_state(node->membership_state) ||
            !valid_health_state(node->health_state) ||
            (node->backend_capabilities &
             ~(WVM_ADMISSION_BACKEND_CAP_KVM |
               WVM_ADMISSION_BACKEND_CAP_TCG)) ||
            (node->runtime_capabilities &
             ~WVM_ADMISSION_RUNTIME_CAP_MODE_B_MEMORY)) {
            set_error(error, error_len,
                      "admission snapshot has invalid node metadata at index %u",
                      i);
            return -1;
        }
        if (node_index_by_id(snapshot, node->physical_node_id) != (int)i) {
            set_error(error, error_len,
                      "admission snapshot has duplicate physical node id %u",
                      node->physical_node_id);
            return -1;
        }
        if (node->reserved_host_vcpu_slots > node->registered_vcpu_slots ||
            node->reserved_gateway_vcpu_slots >
                node->registered_vcpu_slots - node->reserved_host_vcpu_slots) {
            set_error(error, error_len,
                      "admission snapshot over-reserves CPU on node %u",
                      node->physical_node_id);
            return -1;
        }
        if (node->allocatable_vcpu_slots != node->registered_vcpu_slots -
                                                node->reserved_host_vcpu_slots -
                                                node->reserved_gateway_vcpu_slots) {
            set_error(error, error_len,
                      "admission snapshot has inconsistent CPU capacity on node %u",
                      node->physical_node_id);
            return -1;
        }

        if (node->reserved_host_memory_bytes > node->registered_memory_bytes) {
            set_error(error, error_len,
                      "admission snapshot over-reserves memory on node %u",
                      node->physical_node_id);
            return -1;
        }
        reserved_memory = node->reserved_host_memory_bytes;
        if (node->reserved_gateway_memory_bytes >
            node->registered_memory_bytes - reserved_memory) {
            set_error(error, error_len,
                      "admission snapshot over-reserves memory on node %u",
                      node->physical_node_id);
            return -1;
        }
        reserved_memory += node->reserved_gateway_memory_bytes;
        if (node->allocatable_memory_bytes !=
            node->registered_memory_bytes - reserved_memory ||
            node_available_capacity(node, &available_vcpu, &available_memory) !=
                0) {
            set_error(error, error_len,
                      "admission snapshot has inconsistent available capacity on node %u",
                      node->physical_node_id);
            return -1;
        }
        (void)available_vcpu;
        (void)available_memory;
    }

    return 0;
}

int wvm_admission_request_validate(const struct wvm_admission_request *request,
                                   char *error, size_t error_len)
{
    if (!request || request->vm_id == 0 || request->vm_incarnation == 0 ||
        request->manifest_generation == 0 || !valid_backend(request->backend) ||
        (request->placement_policy != WVM_ADMISSION_PLACEMENT_COMPACT &&
         request->placement_policy != WVM_ADMISSION_PLACEMENT_SPREAD) ||
        request->requested_vcpu_slots == 0 ||
        request->requested_memory_bytes == 0 ||
        request->requested_memory_bytes % WVM_ADMISSION_PAGE_BYTES != 0 ||
        request->memory_chunk_bytes == 0 ||
        request->memory_chunk_bytes % WVM_ADMISSION_PAGE_BYTES != 0 ||
        request->host_overhead_memory_bytes % WVM_ADMISSION_PAGE_BYTES != 0 ||
        (request->host_overhead_vcpu_slots == 0 &&
         request->host_overhead_memory_bytes == 0)) {
        set_error(error, error_len, "admission request has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_admission_plan_validate(const struct wvm_admission_snapshot *snapshot,
                                const struct wvm_admission_request *request,
                                const struct wvm_admission_plan *plan,
                                char *error, size_t error_len)
{
    uint64_t total_guest_cpu = 0;
    uint64_t total_guest_memory = 0;
    uint64_t total_host_cpu = 0;
    uint64_t total_host_memory = 0;
    int host_seen = 0;
    uint32_t i;

    if (wvm_admission_snapshot_validate(snapshot, error, error_len) != 0 ||
        wvm_admission_request_validate(request, error, error_len) != 0) {
        return -1;
    }
    if (!plan || plan->reservation_count == 0 ||
        plan->reservation_count > snapshot->node_count ||
        id_is_zero(plan->admission_tx_id) ||
        plan->membership_revision != snapshot->membership_revision ||
        plan->topology_revision != snapshot->topology_revision ||
        plan->capability_profile_generation !=
            snapshot->capability_profile_generation ||
        node_index_by_id(snapshot, plan->host_physical_node_id) < 0) {
        set_error(error, error_len, "admission plan has invalid metadata");
        return -1;
    }

    for (i = 0; i < plan->reservation_count; i++) {
        const struct wvm_admission_reservation *reservation =
            &plan->reservations[i];
        const struct wvm_admission_node *node;
        int node_index;
        uint64_t reserved_cpu;
        uint64_t reserved_memory;
        uint32_t available_cpu;
        uint64_t available_memory;
        uint32_t j;

        node_index = node_index_by_id(snapshot, reservation->physical_node_id);
        if (node_index < 0) {
            set_error(error, error_len, "admission plan names unknown node %u",
                      reservation->physical_node_id);
            return -1;
        }
        node = &snapshot->nodes[node_index];
        if (reservation->expected_node_instance_id != node->node_instance_id ||
            reservation->expected_inventory_revision != node->inventory_revision) {
            set_error(error, error_len,
                      "admission plan has stale instance or inventory on node %u",
                      reservation->physical_node_id);
            return -1;
        }
        if (!node_is_active_and_healthy(node) ||
            (reservation->guest_vcpu_slots != 0 &&
             !node_is_executor_eligible(node, request->backend)) ||
            (reservation->guest_memory_bytes != 0 &&
             !node_is_memory_eligible(node)) ||
            (reservation->physical_node_id == plan->host_physical_node_id &&
             !node_is_executor_eligible(node, request->backend)) ||
            node_available_capacity(node, &available_cpu, &available_memory) !=
                0) {
            set_error(error, error_len, "admission plan uses ineligible node %u",
                      reservation->physical_node_id);
            return -1;
        }
        if (reservation->guest_memory_bytes % WVM_ADMISSION_PAGE_BYTES != 0 ||
            reservation->host_overhead_memory_bytes %
                    WVM_ADMISSION_PAGE_BYTES != 0) {
            set_error(error, error_len,
                      "admission plan has unaligned memory reservation on node %u",
                      reservation->physical_node_id);
            return -1;
        }
        for (j = 0; j < i; j++) {
            if (plan->reservations[j].physical_node_id ==
                reservation->physical_node_id) {
                set_error(error, error_len, "admission plan duplicates node %u",
                          reservation->physical_node_id);
                return -1;
            }
            if (plan->reservations[j].physical_node_id >
                reservation->physical_node_id) {
                set_error(error, error_len,
                          "admission plan reservations are not ordered by node id");
                return -1;
            }
        }

        reserved_cpu = (uint64_t)reservation->guest_vcpu_slots +
                       reservation->host_overhead_vcpu_slots;
        reserved_memory = reservation->guest_memory_bytes;
        if (reservation->host_overhead_memory_bytes >
            UINT64_MAX - reserved_memory) {
            set_error(error, error_len,
                      "admission plan overflows memory reservation on node %u",
                      reservation->physical_node_id);
            return -1;
        }
        reserved_memory += reservation->host_overhead_memory_bytes;
        if (reserved_cpu > available_cpu || reserved_memory > available_memory) {
            set_error(error, error_len,
                      "admission plan exceeds currently available capacity on node %u",
                      reservation->physical_node_id);
            return -1;
        }

        if (reservation->physical_node_id == plan->host_physical_node_id) {
            host_seen = 1;
        } else if (reservation->host_overhead_vcpu_slots != 0 ||
                   reservation->host_overhead_memory_bytes != 0) {
            set_error(error, error_len,
                      "admission plan assigns host overhead to non-host node %u",
                      reservation->physical_node_id);
            return -1;
        }

        total_guest_cpu += reservation->guest_vcpu_slots;
        if (reservation->guest_memory_bytes > UINT64_MAX - total_guest_memory ||
            reservation->host_overhead_memory_bytes >
                UINT64_MAX - total_host_memory) {
            set_error(error, error_len, "admission plan total memory overflows");
            return -1;
        }
        total_guest_memory += reservation->guest_memory_bytes;
        total_host_cpu += reservation->host_overhead_vcpu_slots;
        total_host_memory += reservation->host_overhead_memory_bytes;
    }

    if (!host_seen || total_guest_cpu != request->requested_vcpu_slots ||
        total_guest_memory != request->requested_memory_bytes ||
        total_host_cpu != request->host_overhead_vcpu_slots ||
        total_host_memory != request->host_overhead_memory_bytes) {
        set_error(error, error_len,
                  "admission plan does not completely cover normalized request");
        return -1;
    }
    return 0;
}

static void sort_node_indices(const struct wvm_admission_snapshot *snapshot,
                              uint32_t *indices, uint32_t capacity)
{
    uint32_t i;

    if (snapshot->node_count > capacity) {
        return;
    }

    for (i = 0; i < snapshot->node_count; i++) {
        uint32_t value = i;
        uint32_t insert_at = i;

        while (insert_at != 0 &&
               snapshot->nodes[indices[insert_at - 1]].physical_node_id >
                   snapshot->nodes[value].physical_node_id) {
            indices[insert_at] = indices[insert_at - 1];
            insert_at--;
        }
        indices[insert_at] = value;
    }
}

static int select_host_node(const struct wvm_admission_snapshot *snapshot,
                            const struct wvm_admission_request *request,
                            const uint32_t *indices)
{
    int best = -1;
    uint32_t i;

    for (i = 0; i < snapshot->node_count; i++) {
        const struct wvm_admission_node *node = &snapshot->nodes[indices[i]];
        uint32_t available_cpu;
        uint64_t available_memory;
        int comparison;

        if (!node_is_executor_eligible(node, request->backend) ||
            node_available_capacity(node, &available_cpu, &available_memory) !=
                0 ||
            request->host_overhead_vcpu_slots > available_cpu ||
            request->host_overhead_memory_bytes > available_memory) {
            continue;
        }
        if (best < 0) {
            best = (int)indices[i];
            continue;
        }

        if (request->placement_policy == WVM_ADMISSION_PLACEMENT_COMPACT) {
            const struct wvm_admission_node *current = &snapshot->nodes[best];
            uint32_t current_cpu;
            uint64_t current_memory;
            uint32_t node_remaining_cpu;
            uint64_t node_remaining_memory;
            uint32_t current_remaining_cpu;
            uint64_t current_remaining_memory;

            (void)node_available_capacity(current, &current_cpu, &current_memory);
            node_remaining_cpu =
                available_cpu - request->host_overhead_vcpu_slots;
            node_remaining_memory =
                available_memory - request->host_overhead_memory_bytes;
            current_remaining_cpu =
                current_cpu - request->host_overhead_vcpu_slots;
            current_remaining_memory =
                current_memory - request->host_overhead_memory_bytes;
            comparison = node_remaining_cpu > current_remaining_cpu
                             ? 1
                             : (node_remaining_cpu < current_remaining_cpu
                                    ? -1
                                    : (node_remaining_memory >
                                               current_remaining_memory
                                           ? 1
                                           : (node_remaining_memory <
                                                      current_remaining_memory
                                                  ? -1
                                                  : 0)));
            if (comparison > 0 ||
                (comparison == 0 &&
                 node->physical_node_id < current->physical_node_id)) {
                best = (int)indices[i];
            }
        } else {
            const struct wvm_admission_node *current = &snapshot->nodes[best];
            uint32_t current_cpu;
            uint64_t current_memory;

            (void)node_available_capacity(current, &current_cpu, &current_memory);
            comparison = projected_max_utilization_compare(
                node->committed_vcpu_slots + node->prepared_vcpu_slots +
                    request->host_overhead_vcpu_slots,
                node->allocatable_vcpu_slots,
                node->committed_memory_bytes + node->prepared_memory_bytes +
                    request->host_overhead_memory_bytes,
                node->allocatable_memory_bytes,
                current->committed_vcpu_slots + current->prepared_vcpu_slots +
                    request->host_overhead_vcpu_slots,
                current->allocatable_vcpu_slots,
                current->committed_memory_bytes + current->prepared_memory_bytes +
                    request->host_overhead_memory_bytes,
                current->allocatable_memory_bytes);
            if (comparison < 0 ||
                (comparison == 0 &&
                 node->physical_node_id < current->physical_node_id)) {
                best = (int)indices[i];
            }
        }
    }
    return best;
}

static int select_assignment_node(
    const struct wvm_admission_snapshot *snapshot,
    const struct wvm_admission_request *request,
    const uint32_t *indices,
    const uint32_t *guest_vcpus,
    const uint64_t *guest_memory, int host_index,
    int memory_assignment, uint64_t memory_bytes)
{
    int best = -1;
    uint32_t i;

    for (i = 0; i < snapshot->node_count; i++) {
        const uint32_t node_index = indices[i];
        const struct wvm_admission_node *node = &snapshot->nodes[node_index];
        uint32_t available_cpu;
        uint64_t available_memory;
        uint64_t cpu_used;
        uint64_t memory_used;
        int selected;

        if (!(memory_assignment ? node_is_memory_eligible(node)
                                : node_is_executor_eligible(
                                      node, request->backend)) ||
            node_available_capacity(node, &available_cpu, &available_memory) !=
                0) {
            continue;
        }
        cpu_used = guest_vcpus[node_index] +
                   (node_index == (uint32_t)host_index
                        ? request->host_overhead_vcpu_slots
                        : 0);
        memory_used = guest_memory[node_index] +
                      (node_index == (uint32_t)host_index
                           ? request->host_overhead_memory_bytes
                           : 0);
        if ((!memory_assignment && cpu_used >= available_cpu) ||
            (memory_assignment &&
             (memory_used > available_memory ||
              memory_bytes > available_memory - memory_used))) {
            continue;
        }
        selected = cpu_used != 0 || memory_used != 0;
        if (best < 0) {
            best = (int)node_index;
            continue;
        }

        if (request->placement_policy == WVM_ADMISSION_PLACEMENT_COMPACT) {
            const struct wvm_admission_node *current = &snapshot->nodes[best];
            uint32_t current_available_cpu;
            uint64_t current_available_memory;
            uint64_t current_cpu_used;
            uint64_t current_memory_used;
            int current_selected;

            (void)node_available_capacity(current, &current_available_cpu,
                                          &current_available_memory);
            current_cpu_used = guest_vcpus[best] +
                               ((uint32_t)best == (uint32_t)host_index
                                    ? request->host_overhead_vcpu_slots
                                    : 0);
            current_memory_used = guest_memory[best] +
                                  ((uint32_t)best == (uint32_t)host_index
                                       ? request->host_overhead_memory_bytes
                                       : 0);
            current_selected = current_cpu_used != 0 || current_memory_used != 0;
            if (selected > current_selected ||
                (selected == current_selected &&
                 ((!memory_assignment &&
                   available_cpu - cpu_used > current_available_cpu - current_cpu_used) ||
                  (memory_assignment &&
                   available_memory - memory_used >
                       current_available_memory - current_memory_used)) ) ||
                (selected == current_selected &&
                 ((!memory_assignment &&
                   available_cpu - cpu_used == current_available_cpu - current_cpu_used) ||
                  (memory_assignment &&
                   available_memory - memory_used ==
                       current_available_memory - current_memory_used)) &&
                 node->physical_node_id < current->physical_node_id)) {
                best = (int)node_index;
            }
        } else {
            const struct wvm_admission_node *current = &snapshot->nodes[best];
            uint32_t current_available_cpu;
            uint64_t current_available_memory;
            uint64_t current_cpu_used;
            uint64_t current_memory_used;
            int comparison;

            (void)node_available_capacity(current, &current_available_cpu,
                                          &current_available_memory);
            current_cpu_used = guest_vcpus[best] +
                               ((uint32_t)best == (uint32_t)host_index
                                    ? request->host_overhead_vcpu_slots
                                    : 0);
            current_memory_used = guest_memory[best] +
                                  ((uint32_t)best == (uint32_t)host_index
                                       ? request->host_overhead_memory_bytes
                                       : 0);
            comparison = projected_max_utilization_compare(
                cpu_used + (memory_assignment ? 0U : 1U), available_cpu,
                memory_used + (memory_assignment ? memory_bytes : 0U),
                available_memory,
                current_cpu_used + (memory_assignment ? 0U : 1U),
                current_available_cpu,
                current_memory_used + (memory_assignment ? memory_bytes : 0U),
                current_available_memory);
            if (comparison < 0 ||
                (comparison == 0 &&
                 node->physical_node_id < current->physical_node_id)) {
                best = (int)node_index;
            }
        }
    }
    return best;
}

int wvm_admission_plan_propose(
    const struct wvm_admission_snapshot *snapshot,
    const struct wvm_admission_request *request,
    const uint8_t admission_tx_id[WVM_ADMISSION_ID_BYTES],
    struct wvm_admission_plan *plan, char *error, size_t error_len)
{
    struct wvm_admission_plan proposed = {0};
    struct wvm_admission_plan *output = plan;
    uint32_t *indices = NULL;
    uint32_t *guest_vcpus = NULL;
    uint64_t *guest_memory = NULL;
    int host_index;
    uint32_t remaining_vcpus;
    uint64_t remaining_memory;
    uint32_t i;
    int ret = -1;

    if (wvm_admission_snapshot_validate(snapshot, error, error_len) != 0 ||
        wvm_admission_request_validate(request, error, error_len) != 0 ||
        !admission_tx_id || id_is_zero(admission_tx_id) || !plan) {
        set_error(error, error_len, "cannot propose admission plan");
        return -1;
    }

    /* Publish only a complete result; failure must not free caller storage. */
    plan = &proposed;
    indices = calloc(snapshot->node_count, sizeof(*indices));
    guest_vcpus = calloc(snapshot->node_count, sizeof(*guest_vcpus));
    guest_memory = calloc(snapshot->node_count, sizeof(*guest_memory));
    if (!indices || !guest_vcpus || !guest_memory) {
        set_error(error, error_len, "failed to allocate working arrays");
        goto out;
    }

    sort_node_indices(snapshot, indices, snapshot->node_count);
    host_index = select_host_node(snapshot, request, indices);
    if (host_index < 0) {
        set_error(error, error_len,
                  "no eligible node can reserve the required host overhead");
        goto out;
    }

    remaining_vcpus = request->requested_vcpu_slots;
    while (remaining_vcpus != 0) {
        int node_index = select_assignment_node(snapshot, request, indices,
                                                guest_vcpus, guest_memory,
                                                host_index, 0, 0);

        if (node_index < 0) {
            set_error(error, error_len,
                      "insufficient eligible CPU capacity for VM request");
            goto out;
        }
        guest_vcpus[node_index]++;
        remaining_vcpus--;
    }

    remaining_memory = request->requested_memory_bytes;
    while (remaining_memory != 0) {
        uint64_t chunk = remaining_memory;
        int node_index;

        if (chunk > request->memory_chunk_bytes) {
            chunk = request->memory_chunk_bytes;
        }
        node_index = select_assignment_node(snapshot, request, indices,
                                            guest_vcpus, guest_memory,
                                            host_index, 1, chunk);
        if (node_index < 0) {
            set_error(error, error_len,
                      "insufficient eligible memory capacity for VM request");
            goto out;
        }
        guest_memory[node_index] += chunk;
        remaining_memory -= chunk;
    }

    memset(plan, 0, sizeof(*plan));
    memcpy(plan->admission_tx_id, admission_tx_id, sizeof(plan->admission_tx_id));
    plan->membership_revision = snapshot->membership_revision;
    plan->topology_revision = snapshot->topology_revision;
    plan->capability_profile_generation = snapshot->capability_profile_generation;
    plan->host_physical_node_id = snapshot->nodes[host_index].physical_node_id;
    plan->reservation_capacity = snapshot->node_count;
    plan->reservations = calloc(plan->reservation_capacity,
                                sizeof(*plan->reservations));
    if (!plan->reservations) {
        set_error(error, error_len, "failed to allocate reservation array");
        goto out;
    }
    for (i = 0; i < snapshot->node_count; i++) {
        const uint32_t node_index = indices[i];
        const struct wvm_admission_node *node = &snapshot->nodes[node_index];
        struct wvm_admission_reservation *reservation;

        if (guest_vcpus[node_index] == 0 && guest_memory[node_index] == 0 &&
            node_index != (uint32_t)host_index) {
            continue;
        }
        reservation = &plan->reservations[plan->reservation_count++];
        reservation->physical_node_id = node->physical_node_id;
        reservation->expected_node_instance_id = node->node_instance_id;
        reservation->expected_inventory_revision = node->inventory_revision;
        reservation->guest_vcpu_slots = guest_vcpus[node_index];
        reservation->guest_memory_bytes = guest_memory[node_index];
        if (node_index == (uint32_t)host_index) {
            reservation->host_overhead_vcpu_slots =
                request->host_overhead_vcpu_slots;
            reservation->host_overhead_memory_bytes =
                request->host_overhead_memory_bytes;
        }
    }
    ret = wvm_admission_plan_validate(snapshot, request, plan, error, error_len);

out:
    free(indices);
    free(guest_vcpus);
    free(guest_memory);
    if (ret == 0) {
        *output = proposed;
    } else {
        free(proposed.reservations);
    }
    return ret;
}

static int placement_options_validate(
    const struct wvm_admission_placement_options *options, char *error,
    size_t error_len)
{
    struct wvm_guest_topology topology;

    if (!options || options->memory_consistency_policy == 0 ||
        options->executor_class == 0 ||
        (options->kernel_accelerator_required != 0 &&
         options->kernel_accelerator_required != 1) ||
        wvm_vm_route_scope_key_validate(&options->route_scope_key, error,
                                        error_len) != 0) {
        set_error(error, error_len, "admission placement options are invalid");
        return -1;
    }
    memset(&topology, 0, sizeof(topology));
    topology.topology_policy = options->guest_topology_policy;
    topology.guest_numa_nodes = options->guest_numa_nodes;
    if (wvm_guest_topology_validate(&topology, error, error_len) != 0) {
        set_error(error, error_len, "admission guest topology is invalid");
        return -1;
    }
    return 0;
}

static int listener_plan_matches(
    const struct wvm_admission_node_listener_plan *plan,
    uint32_t physical_node_id, uint64_t node_instance_id)
{
    return plan && plan->physical_node_id == physical_node_id &&
           plan->expected_node_instance_id == node_instance_id;
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
        plan->lease_capacity <
            (plan->kernel_accelerator_required ? 3U : 2U)) {
        set_error(error, error_len, "node listener lease plan is invalid");
        return -1;
    }
    return 0;
}

static const struct wvm_admission_node_listener_plan *find_listener_plan(
    const struct wvm_admission_placement_options *options,
    uint32_t physical_node_id, uint64_t node_instance_id, char *error,
    size_t error_len)
{
    const struct wvm_admission_node_listener_plan *found = NULL;
    size_t i;

    if (!options || !options->listener_plans ||
        options->listener_plan_count == 0) {
        set_error(error, error_len, "placement listener plans are missing");
        return NULL;
    }
    for (i = 0; i < options->listener_plan_count; i++) {
        const struct wvm_admission_node_listener_plan *plan =
            &options->listener_plans[i];

        if (listener_plan_validate(plan, error, error_len) != 0) {
            return NULL;
        }
        if (!listener_plan_matches(plan, physical_node_id, node_instance_id)) {
            continue;
        }
        if (found) {
            set_error(error, error_len,
                      "placement has duplicate listener plans for node %u",
                      physical_node_id);
            return NULL;
        }
        found = plan;
    }
    if (!found) {
        set_error(error, error_len,
                  "placement has no listener plan for node %u instance %llu",
                  physical_node_id, (unsigned long long)node_instance_id);
    }
    return found;
}

static int derive_listener_leases(
    const struct wvm_admission_node_listener_plan *plan, char *error,
    size_t error_len)
{
    int written;

    if (listener_plan_validate(plan, error, error_len) != 0) {
        return -1;
    }
    memset(plan->lease_entries, 0,
           plan->lease_capacity * sizeof(*plan->lease_entries));
    plan->lease_entries[0].lease_kind =
        WVM_EXCLUSIVE_LEASE_KIND_NODE_RUNTIME_DATA_UDP;
    plan->lease_entries[0].lease_generation = plan->lease_generation;
    written = snprintf(plan->lease_entries[0].lease_name,
                       sizeof(plan->lease_entries[0].lease_name),
                       "udp:any:node-runtime-data:%u",
                       (unsigned)plan->node_runtime_data_port);
    if (written < 0 || (size_t)written >=
                           sizeof(plan->lease_entries[0].lease_name)) {
        set_error(error, error_len, "node runtime listener lease name is too long");
        return -1;
    }
    plan->lease_entries[1].lease_kind =
        WVM_EXCLUSIVE_LEASE_KIND_LOCAL_EXECUTOR_SERVICE_UDP;
    plan->lease_entries[1].lease_generation = plan->lease_generation;
    written = snprintf(plan->lease_entries[1].lease_name,
                       sizeof(plan->lease_entries[1].lease_name),
                       "udp:loopback:local-executor-service:%u",
                       (unsigned)plan->local_executor_service_port);
    if (written < 0 || (size_t)written >=
                           sizeof(plan->lease_entries[1].lease_name)) {
        set_error(error, error_len, "executor listener lease name is too long");
        return -1;
    }
    if (plan->kernel_accelerator_required) {
        plan->lease_entries[2].lease_kind =
            WVM_EXCLUSIVE_LEASE_KIND_KERNEL_CONTEXT;
        plan->lease_entries[2].lease_generation = plan->lease_generation;
        written = snprintf(plan->lease_entries[2].lease_name,
                           sizeof(plan->lease_entries[2].lease_name),
                           "kernel-context");
        if (written < 0 || (size_t)written >=
                               sizeof(plan->lease_entries[2].lease_name)) {
            set_error(error, error_len, "kernel context lease name is too long");
            return -1;
        }
    }
    return 0;
}

static void derive_reservation_id(
    const uint8_t admission_tx_id[WVM_ADMISSION_ID_BYTES],
    uint32_t physical_node_id, uint8_t reservation_id[WVM_IDENTITY_ID_BYTES])
{
    static const char domain[] = "wavevm/reservation-requirement/v1";
    struct wvm_sha256_ctx context;
    uint8_t node_bytes[4];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    node_bytes[0] = (uint8_t)(physical_node_id >> 24);
    node_bytes[1] = (uint8_t)(physical_node_id >> 16);
    node_bytes[2] = (uint8_t)(physical_node_id >> 8);
    node_bytes[3] = (uint8_t)physical_node_id;
    wvm_sha256_init(&context);
    wvm_sha256_update(&context, domain, sizeof(domain) - 1U);
    wvm_sha256_update(&context, admission_tx_id, WVM_ADMISSION_ID_BYTES);
    wvm_sha256_update(&context, node_bytes, sizeof(node_bytes));
    wvm_sha256_final(&context, digest);
    memcpy(reservation_id, digest, WVM_IDENTITY_ID_BYTES);
    if (id_is_zero(reservation_id)) {
        reservation_id[WVM_IDENTITY_ID_BYTES - 1U] = 1;
    }
}

static int requirement_index_by_node(
    const struct wvm_reservation_requirement_list *requirements,
    uint32_t physical_node_id)
{
    size_t i;

    for (i = 0; i < requirements->count; i++) {
        if (requirements->entries[i].physical_node_id == physical_node_id) {
            return (int)i;
        }
    }
    return -1;
}

static void sort_requirements_by_id(struct wvm_reservation_requirement *entries,
                                    size_t count)
{
    size_t i;

    for (i = 1; i < count; i++) {
        struct wvm_reservation_requirement value = entries[i];
        size_t insert_at = i;

        while (insert_at != 0 &&
               memcmp(entries[insert_at - 1].reservation_id, value.reservation_id,
                      WVM_IDENTITY_ID_BYTES) > 0) {
            entries[insert_at] = entries[insert_at - 1];
            insert_at--;
        }
        entries[insert_at] = value;
    }
}

int wvm_admission_placement_plan_build(
    const struct wvm_admission_snapshot *snapshot,
    const struct wvm_admission_request *request,
    const struct wvm_admission_plan *admission_plan,
    const uint8_t eligibility_fence_digest[WVM_SHA256_DIGEST_BYTES],
    const struct wvm_admission_placement_options *options,
    struct wvm_placement_plan *placement_plan, char *error,
    size_t error_len)
{
    struct wvm_vcpu_assignment_list vcpus;
    struct wvm_memory_chunk_assignment_list memory;
    struct wvm_storage_assignment_list storage;
    struct wvm_reservation_requirement_list requirements;
    uint64_t remaining_memory;
    uint64_t gpa_start = 0;
    size_t required_memory_assignments = 0;
    size_t i;
    size_t vcpu_index = 0;
    size_t memory_index = 0;

    if (wvm_admission_plan_validate(snapshot, request, admission_plan, error,
                                    error_len) != 0 ||
        !eligibility_fence_digest || digest_is_zero(eligibility_fence_digest) ||
        placement_options_validate(options, error, error_len) != 0 ||
        !placement_plan) {
        set_error(error, error_len, "cannot build placement plan");
        return -1;
    }

    remaining_memory = request->requested_memory_bytes;
    while (remaining_memory != 0) {
        const uint64_t chunk = remaining_memory > request->memory_chunk_bytes
                                   ? request->memory_chunk_bytes
                                   : remaining_memory;

        required_memory_assignments++;
        remaining_memory -= chunk;
    }
    vcpus = placement_plan->vcpu_assignments;
    memory = placement_plan->memory_assignments;
    storage = placement_plan->storage_assignments;
    requirements = placement_plan->reservation_requirements;
    /*
     * The caller owns the backing buffers, but each build owns its output
     * contents. Retaining a previous count would append into stale output and
     * can overrun an otherwise correctly sized reusable buffer.
     */
    vcpus.count = 0;
    memory.count = 0;
    storage.count = 0;
    requirements.count = 0;
    if (!vcpus.entries || vcpus.capacity < request->requested_vcpu_slots ||
        !memory.entries || memory.capacity < required_memory_assignments ||
        requirements.capacity < admission_plan->reservation_count ||
        (requirements.capacity != 0 && !requirements.entries)) {
        set_error(error, error_len, "placement plan output buffers are too small");
        return -1;
    }

    memset(placement_plan, 0, sizeof(*placement_plan));
    placement_plan->vcpu_assignments = vcpus;
    placement_plan->memory_assignments = memory;
    placement_plan->storage_assignments = storage;
    placement_plan->reservation_requirements = requirements;
    placement_plan->inventory_revision = snapshot->inventory_revision;
    placement_plan->membership_revision = snapshot->membership_revision;
    placement_plan->topology_revision = snapshot->topology_revision;
    placement_plan->capability_profile_generation =
        snapshot->capability_profile_generation;
    memcpy(placement_plan->admission_tx_id, admission_plan->admission_tx_id,
           sizeof(placement_plan->admission_tx_id));
    memcpy(placement_plan->eligibility_fence_digest, eligibility_fence_digest,
           sizeof(placement_plan->eligibility_fence_digest));
    placement_plan->host_node = admission_plan->host_physical_node_id;
    placement_plan->route_scope_key = options->route_scope_key;
    placement_plan->guest_topology.topology_policy =
        options->guest_topology_policy;
    placement_plan->guest_topology.guest_numa_nodes = options->guest_numa_nodes;

    for (i = 0; i < admission_plan->reservation_count; i++) {
        const struct wvm_admission_reservation *reservation =
            &admission_plan->reservations[i];
        struct wvm_reservation_requirement *requirement =
            &placement_plan->reservation_requirements
                 .entries[placement_plan->reservation_requirements.count++];
        const struct wvm_admission_node_listener_plan *listener_plan;

        derive_reservation_id(admission_plan->admission_tx_id,
                              reservation->physical_node_id,
                              requirement->reservation_id);
        requirement->physical_node_id = reservation->physical_node_id;
        requirement->node_instance_id = reservation->expected_node_instance_id;
        requirement->inventory_revision = reservation->expected_inventory_revision;
        requirement->guest_vcpu_slots = reservation->guest_vcpu_slots;
        requirement->guest_memory_bytes = reservation->guest_memory_bytes;
        requirement->overhead_vcpu_slots = reservation->host_overhead_vcpu_slots;
        requirement->overhead_memory_bytes =
            reservation->host_overhead_memory_bytes;
        listener_plan = find_listener_plan(
            options, reservation->physical_node_id,
            reservation->expected_node_instance_id, error, error_len);
        if (!listener_plan || derive_listener_leases(listener_plan, error,
                                                     error_len) != 0) {
            return -1;
        }
        if (listener_plan->kernel_accelerator_required !=
            options->kernel_accelerator_required) {
            set_error(error, error_len,
                      "listener accelerator requirement does not match profile");
            return -1;
        }
        requirement->exclusive_leases.entries = listener_plan->lease_entries;
        requirement->exclusive_leases.count =
            listener_plan->kernel_accelerator_required ? 3 : 2;
        requirement->exclusive_leases.capacity = listener_plan->lease_capacity;
    }
    sort_requirements_by_id(placement_plan->reservation_requirements.entries,
                            placement_plan->reservation_requirements.count);

    for (i = 0; i < admission_plan->reservation_count; i++) {
        const struct wvm_admission_reservation *reservation =
            &admission_plan->reservations[i];
        const int requirement_index = requirement_index_by_node(
            &placement_plan->reservation_requirements,
            reservation->physical_node_id);
        const struct wvm_reservation_requirement *requirement;
        uint32_t local_vcpu;
        uint64_t local_memory;

        if (requirement_index < 0) {
            set_error(error, error_len, "placement reservation lookup failed");
            return -1;
        }
        requirement =
            &placement_plan->reservation_requirements.entries[requirement_index];
        for (local_vcpu = 0; local_vcpu < reservation->guest_vcpu_slots;
             local_vcpu++) {
            struct wvm_vcpu_assignment *assignment =
                &placement_plan->vcpu_assignments.entries[vcpu_index];

            memset(assignment, 0, sizeof(*assignment));
            assignment->guest_vcpu_index = (uint32_t)vcpu_index;
            assignment->executor_physical_node_id = reservation->physical_node_id;
            assignment->backend = (enum wvm_manifest_backend)request->backend;
            assignment->executor_class = options->executor_class;
            assignment->executor_slot = local_vcpu;
            memcpy(assignment->reservation_id, requirement->reservation_id,
                   sizeof(assignment->reservation_id));
            vcpu_index++;
        }

        local_memory = reservation->guest_memory_bytes;
        while (local_memory != 0) {
            const uint64_t chunk =
                local_memory > request->memory_chunk_bytes
                    ? request->memory_chunk_bytes
                    : local_memory;
            struct wvm_memory_chunk_assignment *assignment =
                &placement_plan->memory_assignments.entries[memory_index];

            memset(assignment, 0, sizeof(*assignment));
            assignment->gpa_start = gpa_start;
            assignment->bytes = chunk;
            assignment->directory_physical_node_id = reservation->physical_node_id;
            assignment->executor_physical_node_id = reservation->physical_node_id;
            assignment->consistency_policy = options->memory_consistency_policy;
            memcpy(assignment->reservation_id, requirement->reservation_id,
                   sizeof(assignment->reservation_id));
            gpa_start += chunk;
            local_memory -= chunk;
            memory_index++;
        }
    }
    placement_plan->vcpu_assignments.count = vcpu_index;
    placement_plan->memory_assignments.count = memory_index;
    placement_plan->storage_assignments.count = 0;

    if (vcpu_index != request->requested_vcpu_slots ||
        gpa_start != request->requested_memory_bytes) {
        set_error(error, error_len,
                  "placement plan does not cover the normalized request");
        return -1;
    }
    return wvm_placement_plan_validate(placement_plan, error, error_len);
}

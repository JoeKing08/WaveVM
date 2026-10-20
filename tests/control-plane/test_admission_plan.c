#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_admission.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "admission-plan test: %s\n", message);
        return -1;
    }
    return 0;
}

static struct wvm_admission_node make_node(uint32_t id, uint64_t instance,
                                           uint64_t inventory_revision,
                                           uint32_t vcpus, uint64_t memory)
{
    struct wvm_admission_node node;

    memset(&node, 0, sizeof(node));
    node.physical_node_id = id;
    node.node_instance_id = instance;
    node.inventory_revision = inventory_revision;
    node.membership_state = WVM_ADMISSION_MEMBER_ACTIVE;
    node.health_state = WVM_ADMISSION_HEALTHY;
    node.backend_capabilities =
        WVM_ADMISSION_BACKEND_CAP_KVM | WVM_ADMISSION_BACKEND_CAP_TCG;
    node.runtime_capabilities = WVM_ADMISSION_RUNTIME_CAP_MODE_B_MEMORY;
    node.registered_vcpu_slots = vcpus + 1;
    node.registered_memory_bytes = memory + WVM_ADMISSION_PAGE_BYTES;
    node.reserved_host_vcpu_slots = 1;
    node.reserved_host_memory_bytes = WVM_ADMISSION_PAGE_BYTES;
    node.allocatable_vcpu_slots = vcpus;
    node.allocatable_memory_bytes = memory;
    return node;
}

static void fill_valid_plan(struct wvm_admission_plan *plan)
{
    memset(plan, 0, sizeof(*plan));
    plan->reservations = calloc(2, sizeof(struct wvm_admission_reservation));
    if (!plan->reservations) {
        return;
    }
    plan->reservation_capacity = 2;
    plan->admission_tx_id[WVM_ADMISSION_ID_BYTES - 1] = 1;
    plan->membership_revision = 7;
    plan->topology_revision = 11;
    plan->capability_profile_generation = 13;
    plan->host_physical_node_id = 17;
    plan->reservation_count = 2;

    plan->reservations[0].physical_node_id = 17;
    plan->reservations[0].expected_node_instance_id = 101;
    plan->reservations[0].expected_inventory_revision = 19;
    plan->reservations[0].guest_vcpu_slots = 2;
    plan->reservations[0].guest_memory_bytes = 4 * 1024 * 1024;
    plan->reservations[0].host_overhead_vcpu_slots = 1;
    plan->reservations[0].host_overhead_memory_bytes = 1 * 1024 * 1024;

    plan->reservations[1].physical_node_id = 99;
    plan->reservations[1].expected_node_instance_id = 202;
    plan->reservations[1].expected_inventory_revision = 23;
    plan->reservations[1].guest_vcpu_slots = 1;
    plan->reservations[1].guest_memory_bytes = 4 * 1024 * 1024;
}

static void fill_kvm_memory_only_plan(struct wvm_admission_plan *plan)
{
    memset(plan, 0, sizeof(*plan));
    plan->reservations = calloc(2, sizeof(struct wvm_admission_reservation));
    if (!plan->reservations) {
        return;
    }
    plan->reservation_capacity = 2;
    plan->admission_tx_id[WVM_ADMISSION_ID_BYTES - 1] = 1;
    plan->membership_revision = 7;
    plan->topology_revision = 11;
    plan->capability_profile_generation = 13;
    plan->host_physical_node_id = 17;
    plan->reservation_count = 2;

    plan->reservations[0].physical_node_id = 17;
    plan->reservations[0].expected_node_instance_id = 101;
    plan->reservations[0].expected_inventory_revision = 19;
    plan->reservations[0].guest_vcpu_slots = 3;
    plan->reservations[0].guest_memory_bytes = 4 * 1024 * 1024;
    plan->reservations[0].host_overhead_vcpu_slots = 1;
    plan->reservations[0].host_overhead_memory_bytes = 1 * 1024 * 1024;

    plan->reservations[1].physical_node_id = 99;
    plan->reservations[1].expected_node_instance_id = 202;
    plan->reservations[1].expected_inventory_revision = 23;
    plan->reservations[1].guest_memory_bytes = 4 * 1024 * 1024;
}

static void cleanup_plan(struct wvm_admission_plan *plan)
{
    if (plan && plan->reservations) {
        free(plan->reservations);
        plan->reservations = NULL;
        plan->reservation_capacity = 0;
    }
}

int main(void)
{
    struct wvm_admission_snapshot snapshot;
    struct wvm_admission_request request;
    struct wvm_admission_plan plan;
    struct wvm_admission_plan proposed_plan;
    struct wvm_admission_plan untouched_plan;
    struct wvm_admission_plan untouched_before;
    struct wvm_admission_plan proposed_before;
    struct wvm_admission_placement_options options;
    struct wvm_vcpu_assignment vcpu_assignments[3];
    struct wvm_memory_chunk_assignment memory_assignments[4];
    struct wvm_reservation_requirement reservation_requirements[2];
    struct wvm_admission_node_listener_plan listener_plans[2];
    struct wvm_exclusive_lease listener_leases[2][3];
    struct wvm_placement_plan placement_plan;
    uint8_t admission_tx_id[WVM_ADMISSION_ID_BYTES] = {0};
    uint8_t eligibility_fence_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t placement_bytes[8192];
    uint8_t placement_digest[WVM_SHA256_DIGEST_BYTES];
    size_t placement_bytes_used;
    char error[256] = {0};

    /* Initialize snapshot with capacity for 2 nodes */
    if (wvm_admission_snapshot_init(&snapshot, 2) != 0) {
        puts("FAIL: failed to initialize snapshot");
        return 1;
    }
    snapshot.inventory_revision = 29;
    snapshot.membership_revision = 7;
    snapshot.topology_revision = 11;
    snapshot.capability_profile_generation = 13;
    snapshot.node_count = 2;
    snapshot.nodes[0] = make_node(17, 101, 19, 3, 8 * 1024 * 1024);
    snapshot.nodes[1] = make_node(99, 202, 23, 2, 8 * 1024 * 1024);

    {
        struct wvm_admission_snapshot copy = {0};
        struct wvm_admission_snapshot invalid = snapshot;
        struct wvm_admission_node *source_nodes = snapshot.nodes;
        struct wvm_admission_snapshot previous;

        if (expect(wvm_admission_snapshot_copy(&snapshot, &snapshot) == 0 &&
                       snapshot.nodes == source_nodes,
                   "self-copy preserves snapshot allocation") ||
            expect(wvm_admission_snapshot_copy(&snapshot, &copy) == 0 &&
                       copy.nodes != source_nodes &&
                       memcmp(copy.nodes, source_nodes,
                              snapshot.node_count * sizeof(*source_nodes)) == 0,
                   "snapshot copy owns independent node storage")) {
            return 1;
        }
        previous = copy;
        invalid.node_count = invalid.node_capacity + 1;
        if (expect(wvm_admission_snapshot_copy(&invalid, &copy) != 0 &&
                       memcmp(&copy, &previous, sizeof(copy)) == 0,
                   "invalid count leaves destination snapshot unchanged")) {
            return 1;
        }
        invalid = snapshot;
        invalid.nodes = NULL;
        if (expect(wvm_admission_snapshot_copy(&invalid, &copy) != 0 &&
                       memcmp(&copy, &previous, sizeof(copy)) == 0,
                   "missing source storage leaves destination unchanged")) {
            return 1;
        }
        wvm_admission_snapshot_cleanup(&copy);
    }

    memset(&request, 0, sizeof(request));
    request.vm_id = 256;
    request.vm_incarnation = 1;
    request.manifest_generation = 1;
    request.backend = WVM_ADMISSION_BACKEND_TCG;
    request.placement_policy = WVM_ADMISSION_PLACEMENT_SPREAD;
    request.requested_vcpu_slots = 3;
    request.requested_memory_bytes = 8 * 1024 * 1024;
    request.memory_chunk_bytes = 2 * 1024 * 1024;
    request.host_overhead_vcpu_slots = 1;
    request.host_overhead_memory_bytes = 1 * 1024 * 1024;

    fill_valid_plan(&plan);
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) == 0,
               "accept a complete, revision-pinned TCG plan")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    admission_tx_id[WVM_ADMISSION_ID_BYTES - 1] = 0x44;
    if (expect(wvm_admission_plan_propose(&snapshot, &request, admission_tx_id,
                                          &proposed_plan, error,
                                          sizeof(error)) == 0,
               "generate a deterministic reservation plan") ||
        expect(proposed_plan.host_physical_node_id == 17,
               "choose an explicit compact host") ||
        expect(proposed_plan.reservation_count == 2,
               "use both nodes when local CPU capacity is insufficient") ||
        expect(proposed_plan.reservations[0].physical_node_id == 17 &&
                   proposed_plan.reservations[1].physical_node_id == 99,
               "emit reservations in stable node order")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    memset(&options, 0, sizeof(options));
    options.memory_consistency_policy = 1;
    options.guest_topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
    options.guest_numa_nodes = 1;
    options.executor_class = 1;
    options.kernel_accelerator_required = 0;
    options.route_scope_key.vm_id = request.vm_id;
    options.route_scope_key.vm_incarnation = request.vm_incarnation;
    options.route_scope_key.route_scope_id = 1;
    memset(listener_plans, 0, sizeof(listener_plans));
    memset(listener_leases, 0, sizeof(listener_leases));
    listener_plans[0].physical_node_id = 17;
    listener_plans[0].expected_node_instance_id = 101;
    listener_plans[0].node_runtime_data_port = 19100;
    listener_plans[0].local_executor_service_port = 19105;
    listener_plans[0].lease_generation = 101;
    listener_plans[0].lease_entries = listener_leases[0];
    listener_plans[0].lease_capacity = 3;
    listener_plans[1].physical_node_id = 99;
    listener_plans[1].expected_node_instance_id = 202;
    listener_plans[1].node_runtime_data_port = 19200;
    listener_plans[1].local_executor_service_port = 19205;
    listener_plans[1].lease_generation = 202;
    listener_plans[1].lease_entries = listener_leases[1];
    listener_plans[1].lease_capacity = 3;
    options.listener_plans = listener_plans;
    options.listener_plan_count = 2;
    memset(eligibility_fence_digest, 0x5a, sizeof(eligibility_fence_digest));
    memset(&placement_plan, 0, sizeof(placement_plan));
    placement_plan.vcpu_assignments.entries = vcpu_assignments;
    placement_plan.vcpu_assignments.capacity =
        sizeof(vcpu_assignments) / sizeof(vcpu_assignments[0]);
    placement_plan.memory_assignments.entries = memory_assignments;
    placement_plan.memory_assignments.capacity =
        sizeof(memory_assignments) / sizeof(memory_assignments[0]);
    placement_plan.reservation_requirements.entries = reservation_requirements;
    placement_plan.reservation_requirements.capacity =
        sizeof(reservation_requirements) / sizeof(reservation_requirements[0]);
    if (expect(wvm_admission_placement_plan_build(
                   &snapshot, &request, &proposed_plan, eligibility_fence_digest,
                   &options, &placement_plan, error, sizeof(error)) == 0,
               "materialize canonical placement assignments") ||
        expect(placement_plan.vcpu_assignments.count == 3 &&
                   placement_plan.memory_assignments.count == 4,
               "cover every requested CPU and memory chunk") ||
        expect(placement_plan.host_node == proposed_plan.host_physical_node_id,
               "preserve selected host") ||
        expect(placement_plan.reservation_requirements.entries[0]
                       .exclusive_leases.count == 2,
               "reserve the two actual node listeners") ||
        expect(wvm_placement_plan_encode(
                   &placement_plan, placement_bytes, sizeof(placement_bytes),
                   &placement_bytes_used, placement_digest, error,
                   sizeof(error)) == 0,
               "encode the generated placement plan")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    options.kernel_accelerator_required = 1;
    listener_plans[0].kernel_accelerator_required = 1;
    listener_plans[1].kernel_accelerator_required = 1;
    if (expect(wvm_admission_placement_plan_build(
                   &snapshot, &request, &proposed_plan, eligibility_fence_digest,
                   &options, &placement_plan, error, sizeof(error)) == 0 &&
                   placement_plan.reservation_requirements.entries[0]
                           .exclusive_leases.count == 3 &&
                   placement_plan.reservation_requirements.entries[0]
                           .exclusive_leases.entries[2].lease_kind ==
                       WVM_EXCLUSIVE_LEASE_KIND_KERNEL_CONTEXT &&
                   strcmp(placement_plan.reservation_requirements.entries[0]
                              .exclusive_leases.entries[2].lease_name,
                          "kernel-context") == 0,
               "kernel profile reserves fixed kernel-context lease (gate closed)")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }
    options.kernel_accelerator_required = 0;
    listener_plans[0].kernel_accelerator_required = 0;
    listener_plans[1].kernel_accelerator_required = 0;

    snapshot.nodes[1].committed_vcpu_slots = 2;
    memset(&untouched_plan, 0xa5, sizeof(untouched_plan));
    memcpy(&untouched_before, &untouched_plan, sizeof(untouched_before));
    if (expect(wvm_admission_plan_propose(&snapshot, &request, admission_tx_id,
                                          &untouched_plan, error,
                                          sizeof(error)) != 0 &&
                   memcmp(&untouched_plan, &untouched_before,
                          sizeof(untouched_plan)) == 0,
               "failed proposal leaves uninitialized output untouched")) {
        return 1;
    }
    memcpy(&proposed_before, &proposed_plan, sizeof(proposed_before));
    if (expect(wvm_admission_plan_propose(&snapshot, &request, admission_tx_id,
                                          &proposed_plan, error,
                                          sizeof(error)) != 0,
               "reject a request that collides with committed capacity") ||
        expect(memcmp(&proposed_before, &proposed_plan,
                      sizeof(proposed_plan)) == 0,
               "failed proposal preserves the existing owned result")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }
    snapshot.nodes[1].committed_vcpu_slots = 0;
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &proposed_plan,
                                           error, sizeof(error)) == 0,
               "previous plan remains usable after proposal failure")) {
        return 1;
    }

    plan.reservations[1].expected_inventory_revision++;
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) != 0,
               "reject stale inventory revision")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    cleanup_plan(&plan);
    fill_valid_plan(&plan);
    plan.reservations[1].host_overhead_memory_bytes = WVM_ADMISSION_PAGE_BYTES;
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) != 0,
               "reject host overhead on a non-host")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    cleanup_plan(&plan);
    fill_valid_plan(&plan);
    snapshot.nodes[1].membership_state = WVM_ADMISSION_MEMBER_CORDONED;
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) != 0,
               "reject cordoned member")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    snapshot.nodes[1].membership_state = WVM_ADMISSION_MEMBER_ACTIVE;
    snapshot.nodes[1].backend_capabilities = WVM_ADMISSION_BACKEND_CAP_KVM;
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) != 0,
               "reject backend-incompatible member")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    snapshot.nodes[1].backend_capabilities =
        WVM_ADMISSION_BACKEND_CAP_KVM | WVM_ADMISSION_BACKEND_CAP_TCG;
    snapshot.nodes[0] = make_node(17, 101, 19, 4, 8 * 1024 * 1024);
    snapshot.nodes[1].backend_capabilities = 0;
    request.backend = WVM_ADMISSION_BACKEND_KVM;
    cleanup_plan(&plan);
    fill_kvm_memory_only_plan(&plan);
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) == 0,
               "allow a Mode B memory-only participant without KVM") ||
        expect(wvm_admission_placement_plan_build(
                   &snapshot, &request, &plan, eligibility_fence_digest,
                   &options, &placement_plan, error, sizeof(error)) == 0 &&
                   placement_plan.vcpu_assignments.count == 3 &&
                   placement_plan.memory_assignments.count == 4,
               "materialize homogeneous KVM CPU and memory-only placement")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }
    snapshot.nodes[1].runtime_capabilities = 0;
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) != 0,
               "reject a memory participant without Mode B memory service")) {
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }
    snapshot.nodes[1].runtime_capabilities =
        WVM_ADMISSION_RUNTIME_CAP_MODE_B_MEMORY;
    snapshot.nodes[1].backend_capabilities =
        WVM_ADMISSION_BACKEND_CAP_KVM | WVM_ADMISSION_BACKEND_CAP_TCG;
    request.backend = WVM_ADMISSION_BACKEND_TCG;
    request.vm_id = 0;
    if (expect(wvm_admission_plan_validate(&snapshot, &request, &plan, error,
                                           sizeof(error)) != 0,
               "reject legacy VM namespace in V1 admission")) {
        cleanup_plan(&plan);
        wvm_admission_snapshot_cleanup(&snapshot);
        return 1;
    }

    /*
     * RM-P7-origin-not-host: request origin (node 99) does not implicitly
     * become QEMU host_node. Only node 17 can reserve host overhead.
     */
    {
        struct wvm_admission_snapshot origin_snapshot;
        struct wvm_admission_request origin_request;
        struct wvm_admission_plan origin_plan;
        uint8_t origin_tx[WVM_ADMISSION_ID_BYTES];
        char origin_error[128];

        if (wvm_admission_snapshot_init(&origin_snapshot, 2) != 0) {
            puts("FAIL: origin snapshot init");
            cleanup_plan(&plan);
            cleanup_plan(&proposed_plan);
            wvm_admission_snapshot_cleanup(&snapshot);
            return 1;
        }
        origin_snapshot.inventory_revision = 29;
        origin_snapshot.membership_revision = 7;
        origin_snapshot.topology_revision = 11;
        origin_snapshot.capability_profile_generation = 13;
        origin_snapshot.node_count = 2;
        /* Origin-like node first: eligible for guest work but cannot host. */
        origin_snapshot.nodes[0] = make_node(99, 202, 23, 2, 8 * 1024 * 1024);
        origin_snapshot.nodes[1] = make_node(17, 101, 19, 8, 32 * 1024 * 1024);
        memset(&origin_request, 0, sizeof(origin_request));
        origin_request.vm_id = 42;
        origin_request.vm_incarnation = 1;
        origin_request.manifest_generation = 1;
        origin_request.backend = WVM_ADMISSION_BACKEND_TCG;
        origin_request.placement_policy = WVM_ADMISSION_PLACEMENT_COMPACT;
        origin_request.requested_vcpu_slots = 1;
        origin_request.requested_memory_bytes = 4 * 1024 * 1024;
        origin_request.memory_chunk_bytes = 4 * 1024 * 1024;
        origin_request.host_overhead_vcpu_slots = 3; /* exceeds node 99 (2) */
        origin_request.host_overhead_memory_bytes = 1 * 1024 * 1024;
        memset(origin_tx, 0, sizeof(origin_tx));
        origin_tx[WVM_ADMISSION_ID_BYTES - 1] = 9;
        memset(&origin_plan, 0, sizeof(origin_plan));
        if (expect(wvm_admission_plan_propose(&origin_snapshot, &origin_request,
                                              origin_tx, &origin_plan,
                                              origin_error,
                                              sizeof(origin_error)) == 0,
                   "propose despite origin node lacking host capacity") ||
            expect(origin_plan.host_physical_node_id == 17,
                   "host_node is capacity-selected 17, not origin 99") ||
            expect(origin_plan.host_physical_node_id != 99,
                   "request origin 99 is not implicit host_node")) {
            fprintf(stderr, "origin-not-host: %s\n", origin_error);
            cleanup_plan(&origin_plan);
            wvm_admission_snapshot_cleanup(&origin_snapshot);
            cleanup_plan(&plan);
            cleanup_plan(&proposed_plan);
            wvm_admission_snapshot_cleanup(&snapshot);
            return 1;
        }
        cleanup_plan(&origin_plan);
        wvm_admission_snapshot_cleanup(&origin_snapshot);
    }

    /*
     * Codex A06: capacity must be sum(ceil(per_node/chunk)), not ceil(total/chunk).
     * Nodes 5+5 MiB with 4 MiB chunks → 2+2=4 slots; ceil(10/4)=3.
     * capacity=3 must fail closed; capacity=4 must emit exactly 4 memory slots.
     */
    {
        struct wvm_admission_plan a06_plan;
        struct wvm_admission_reservation a06_reservations[2];
        struct wvm_admission_request a06_request;
        struct wvm_admission_placement_options a06_options;
        struct wvm_placement_plan a06_placement;
        struct wvm_vcpu_assignment a06_vcpus[8];
        struct wvm_memory_chunk_assignment a06_memory_short[3];
        struct wvm_memory_chunk_assignment a06_memory_ok[4];
        struct wvm_reservation_requirement a06_reqs[4];
        struct wvm_admission_node_listener_plan a06_listeners[2];
        struct wvm_exclusive_lease a06_leases[2][3];
        uint8_t a06_fence[WVM_SHA256_DIGEST_BYTES];
        char a06_error[256];

        memset(&a06_plan, 0, sizeof(a06_plan));
        memset(a06_reservations, 0, sizeof(a06_reservations));
        memset(&a06_request, 0, sizeof(a06_request));
        a06_request.vm_id = 65;
        a06_request.vm_incarnation = 1;
        a06_request.manifest_generation = 1;
        a06_request.backend = WVM_ADMISSION_BACKEND_TCG;
        a06_request.placement_policy = WVM_ADMISSION_PLACEMENT_SPREAD;
        a06_request.requested_vcpu_slots = 2;
        a06_request.requested_memory_bytes = 10ULL * 1024ULL * 1024ULL;
        a06_request.memory_chunk_bytes = 4ULL * 1024ULL * 1024ULL;
        a06_request.host_overhead_vcpu_slots = 1;
        a06_request.host_overhead_memory_bytes = WVM_ADMISSION_PAGE_BYTES;
        a06_plan.host_physical_node_id = 17;
        a06_plan.membership_revision = snapshot.membership_revision;
        a06_plan.topology_revision = snapshot.topology_revision;
        a06_plan.capability_profile_generation =
            snapshot.capability_profile_generation;
        a06_plan.reservation_count = 2;
        a06_plan.reservation_capacity = 2;
        a06_plan.reservations = a06_reservations;
        a06_reservations[0].physical_node_id = 17;
        a06_reservations[0].expected_node_instance_id = 101;
        a06_reservations[0].expected_inventory_revision = 19;
        a06_reservations[0].guest_vcpu_slots = 1;
        a06_reservations[0].guest_memory_bytes = 5ULL * 1024ULL * 1024ULL;
        a06_reservations[0].host_overhead_vcpu_slots = 1;
        a06_reservations[0].host_overhead_memory_bytes = WVM_ADMISSION_PAGE_BYTES;
        a06_reservations[1].physical_node_id = 99;
        a06_reservations[1].expected_node_instance_id = 202;
        a06_reservations[1].expected_inventory_revision = 23;
        a06_reservations[1].guest_vcpu_slots = 1;
        a06_reservations[1].guest_memory_bytes = 5ULL * 1024ULL * 1024ULL;
        memset(a06_plan.admission_tx_id, 0x0a, sizeof(a06_plan.admission_tx_id));

        memset(&a06_options, 0, sizeof(a06_options));
        a06_options.memory_consistency_policy = 1;
        a06_options.guest_topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
        a06_options.guest_numa_nodes = 1;
        a06_options.executor_class = 1;
        a06_options.route_scope_key.vm_id = a06_request.vm_id;
        a06_options.route_scope_key.vm_incarnation = a06_request.vm_incarnation;
        a06_options.route_scope_key.route_scope_id = 1;
        memset(a06_listeners, 0, sizeof(a06_listeners));
        memset(a06_leases, 0, sizeof(a06_leases));
        a06_listeners[0].physical_node_id = 17;
        a06_listeners[0].expected_node_instance_id = 101;
        a06_listeners[0].node_runtime_data_port = 19100;
        a06_listeners[0].local_executor_service_port = 19105;
        a06_listeners[0].lease_generation = 101;
        a06_listeners[0].lease_entries = a06_leases[0];
        a06_listeners[0].lease_capacity = 3;
        a06_listeners[1].physical_node_id = 99;
        a06_listeners[1].expected_node_instance_id = 202;
        a06_listeners[1].node_runtime_data_port = 19200;
        a06_listeners[1].local_executor_service_port = 19205;
        a06_listeners[1].lease_generation = 202;
        a06_listeners[1].lease_entries = a06_leases[1];
        a06_listeners[1].lease_capacity = 3;
        a06_options.listener_plans = a06_listeners;
        a06_options.listener_plan_count = 2;
        memset(a06_fence, 0x5a, sizeof(a06_fence));
        memset(&a06_placement, 0, sizeof(a06_placement));
        a06_placement.vcpu_assignments.entries = a06_vcpus;
        a06_placement.vcpu_assignments.capacity =
            sizeof(a06_vcpus) / sizeof(a06_vcpus[0]);
        a06_placement.memory_assignments.entries = a06_memory_short;
        a06_placement.memory_assignments.capacity = 3; /* ceil(total/chunk)=3 */
        a06_placement.reservation_requirements.entries = a06_reqs;
        a06_placement.reservation_requirements.capacity =
            sizeof(a06_reqs) / sizeof(a06_reqs[0]);
        a06_error[0] = '\0';
        if (expect(wvm_admission_placement_plan_build(
                       &snapshot, &a06_request, &a06_plan, a06_fence,
                       &a06_options, &a06_placement, a06_error,
                       sizeof(a06_error)) != 0,
                   "A06 fail-closed when capacity < sum(ceil(per_node/chunk))")) {
            fprintf(stderr, "A06 short-capacity: %s\n", a06_error);
            cleanup_plan(&plan);
            cleanup_plan(&proposed_plan);
            wvm_admission_snapshot_cleanup(&snapshot);
            return 1;
        }
        a06_placement.memory_assignments.entries = a06_memory_ok;
        a06_placement.memory_assignments.capacity = 4;
        a06_error[0] = '\0';
        if (expect(wvm_admission_placement_plan_build(
                       &snapshot, &a06_request, &a06_plan, a06_fence,
                       &a06_options, &a06_placement, a06_error,
                       sizeof(a06_error)) == 0 &&
                       a06_placement.memory_assignments.count == 4,
                   "A06 succeeds with capacity==sum(ceil(per_node/chunk))")) {
            fprintf(stderr, "A06 adequate-capacity: %s count=%zu\n", a06_error,
                    a06_placement.memory_assignments.count);
            cleanup_plan(&plan);
            cleanup_plan(&proposed_plan);
            wvm_admission_snapshot_cleanup(&snapshot);
            return 1;
        }
    }

    cleanup_plan(&plan);
    cleanup_plan(&proposed_plan);
    wvm_admission_snapshot_cleanup(&snapshot);
    puts("admission-plan tests: PASS");
    puts("NOTE: RM-P7-origin-not-host oracle included.");
    puts("NOTE: Codex A06 sum(ceil(per_node/chunk)) capacity oracle included.");
    return 0;
}

#include <stdio.h>
#include <string.h>

#include "wavevm_reservation_runtime.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "reservation-runtime test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_id(uint8_t id[WVM_IDENTITY_ID_BYTES], uint8_t value)
{
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = value;
}

static void fill_reservation(struct wvm_resource_reservation *reservation,
                             uint8_t id, uint32_t node_id)
{
    memset(reservation, 0, sizeof(*reservation));
    fill_id(reservation->reservation_id, id);
    fill_id(reservation->plan_digest, id + 10);
    fill_id(reservation->candidate_manifest_digest, id + 20);
    fill_id(reservation->admission_tx_id, id + 30);
    fill_id(reservation->eligibility_fence_digest, id + 40);
    reservation->vm_id = 100 + id;
    reservation->vm_incarnation = 1;
    reservation->physical_node_id = node_id;
    reservation->node_instance_id = 9;
    reservation->inventory_revision = 4;
    reservation->guest_vcpu_slots = 2;
    reservation->guest_memory_bytes = 4096;
    reservation->overhead_memory_bytes = 4096;
    reservation->state = WVM_RESERVATION_PREPARED;
    reservation->exclusive_leases.count = 1;
    reservation->exclusive_leases.capacity = 1;
}

int main(void)
{
    struct wvm_admission_node node;
    struct wvm_admission_node other_node;
    struct wvm_resource_reservation stored[5];
    struct wvm_resource_reservation other_stored[2];
    struct wvm_resource_reservation first;
    struct wvm_resource_reservation conflicting;
    struct wvm_resource_reservation distinct;
    struct wvm_resource_reservation other_node_reservation;
    struct wvm_resource_reservation mode_b_first;
    struct wvm_resource_reservation mode_b_second;
    struct wvm_resource_reservation replay_mismatch;
    struct wvm_exclusive_lease first_lease;
    struct wvm_exclusive_lease conflict_lease;
    struct wvm_exclusive_lease distinct_lease;
    struct wvm_local_reservation_registry registry;
    struct wvm_local_reservation_registry other_registry;
    struct wvm_activation_record activation;
    enum wvm_reservation_runtime_result result;
    char error[256] = {0};

    memset(&node, 0, sizeof(node));
    node.physical_node_id = 17;
    node.node_instance_id = 9;
    node.inventory_revision = 4;
    node.allocatable_vcpu_slots = 4;
    node.allocatable_memory_bytes = 16384;

    other_node = node;
    other_node.physical_node_id = 18;

    memset(&first_lease, 0, sizeof(first_lease));
    first_lease.lease_kind = WVM_EXCLUSIVE_LEASE_KIND_KERNEL_CONTEXT;
    first_lease.lease_generation = 1;
    strcpy(first_lease.lease_name, "kernel-context");
    fill_reservation(&first, 1, 17);
    first.exclusive_leases.entries = &first_lease;
    first.has_prepared_expiry = 1;
    first.prepared_expiry_unix_time_ms = 10;

    memset(&conflict_lease, 0, sizeof(conflict_lease));
    conflict_lease.lease_kind = WVM_EXCLUSIVE_LEASE_KIND_KERNEL_CONTEXT;
    conflict_lease.lease_generation = 2;
    strcpy(conflict_lease.lease_name, "kernel-context");
    fill_reservation(&conflicting, 2, 17);
    conflicting.exclusive_leases.entries = &conflict_lease;
    conflicting.has_prepared_expiry = 1;
    conflicting.prepared_expiry_unix_time_ms = 20;

    memset(&other_node_reservation, 0, sizeof(other_node_reservation));
    fill_reservation(&other_node_reservation, 4, 18);
    other_node_reservation.exclusive_leases.entries = &conflict_lease;
    other_node_reservation.has_prepared_expiry = 1;
    other_node_reservation.prepared_expiry_unix_time_ms = 40;

    fill_reservation(&mode_b_first, 5, 17);
    mode_b_first.guest_vcpu_slots = 1;
    mode_b_first.guest_memory_bytes = 4096;
    mode_b_first.overhead_memory_bytes = 0;
    mode_b_first.exclusive_leases.entries = NULL;
    mode_b_first.exclusive_leases.count = 0;
    mode_b_first.exclusive_leases.capacity = 0;
    mode_b_first.has_prepared_expiry = 1;
    mode_b_first.prepared_expiry_unix_time_ms = 50;

    fill_reservation(&mode_b_second, 6, 17);
    mode_b_second.guest_vcpu_slots = 1;
    mode_b_second.guest_memory_bytes = 4096;
    mode_b_second.overhead_memory_bytes = 0;
    mode_b_second.exclusive_leases.entries = NULL;
    mode_b_second.exclusive_leases.count = 0;
    mode_b_second.exclusive_leases.capacity = 0;
    mode_b_second.has_prepared_expiry = 1;
    mode_b_second.prepared_expiry_unix_time_ms = 60;

    memset(&distinct_lease, 0, sizeof(distinct_lease));
    distinct_lease.lease_kind = 1;
    distinct_lease.lease_generation = 9;
    strcpy(distinct_lease.lease_name, "vm-103-qemu");
    fill_reservation(&distinct, 3, 17);
    distinct.exclusive_leases.entries = &distinct_lease;
    distinct.has_prepared_expiry = 1;
    distinct.prepared_expiry_unix_time_ms = 30;

    replay_mismatch = first;
    replay_mismatch.exclusive_leases.entries = &conflict_lease;

    if (expect(wvm_local_reservation_registry_init(
                   &registry, &node, stored, 5, error, sizeof(error)) == 0,
               "initialize registry") ||
        expect(wvm_local_reservation_prepare(
                   &registry, &first, &result, error, sizeof(error)) == 0 &&
                   result == WVM_RESERVATION_RUNTIME_NEW,
               "prepare first reservation") ||
        expect(wvm_local_reservation_prepare(
                   &registry, &first, &result, error, sizeof(error)) == 0 &&
                   result == WVM_RESERVATION_RUNTIME_REPLAY,
               "replay identical prepare") ||
        expect(wvm_local_reservation_prepare(
                   &registry, &replay_mismatch, &result, error, sizeof(error)) != 0,
               "reject replay with a different lease generation") ||
        expect(wvm_local_reservation_prepare(
                   &registry, &conflicting, &result, error, sizeof(error)) != 0,
               "reject a second single-context kernel reservation") ||
        expect(wvm_local_reservation_prepare(
                   &registry, &distinct, &result, error, sizeof(error)) == 0 &&
                   result == WVM_RESERVATION_RUNTIME_NEW,
               "allow a distinct lease resource")) {
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }
    if (expect(wvm_local_reservation_abort(
                   &registry, &distinct, &result, error,
                   sizeof(error)) == 0,
               "release distinct reservation before reuse checks")) {
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }
    if (wvm_local_reservation_registry_init(
            &other_registry, &other_node, other_stored, 2, error,
            sizeof(error)) != 0) {
        fprintf(stderr,
                "reservation-runtime test: initialize second node registry\n");
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }
    if (expect(wvm_local_reservation_prepare(
                   &other_registry, &other_node_reservation, &result, error,
                   sizeof(error)) == 0 &&
                   result == WVM_RESERVATION_RUNTIME_NEW,
               "allow the same kernel context lease on a different node") ||
        expect(wvm_local_reservation_prepare(
                   &registry, &mode_b_first, &result, error, sizeof(error)) ==
                   0 &&
                   result == WVM_RESERVATION_RUNTIME_NEW,
               "allow a Mode B reservation without a kernel context lease") ||
        expect(wvm_local_reservation_prepare(
                   &registry, &mode_b_second, &result, error, sizeof(error)) ==
                   0 &&
                   result == WVM_RESERVATION_RUNTIME_NEW,
               "allow multiple Mode B reservations on one node")) {
        wvm_local_reservation_registry_destroy(&other_registry);
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }
    if (expect(wvm_local_reservation_abort(
                   &registry, &mode_b_first, &result, error,
                   sizeof(error)) == 0,
               "release first Mode B reservation") ||
        expect(wvm_local_reservation_abort(
                   &registry, &mode_b_second, &result, error,
                   sizeof(error)) == 0,
               "release second Mode B reservation")) {
        wvm_local_reservation_registry_destroy(&other_registry);
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }

    memset(&activation, 0, sizeof(activation));
    fill_id(activation.admission_tx_id, 31);
    fill_id(activation.candidate_manifest_digest, 21);
    fill_id(activation.activation_fence, 41);
    activation.coordinator_instance_id = 1;
    fill_id(activation.required_participant_set_digest, 51);
    activation.decision = WVM_ACTIVATION_ACTIVATE;
    activation.durable_decision_sequence = 1;
    activation.decided_at = 1;
    {
        struct wvm_route_snapshot_key route_key;

        memset(&route_key, 0, sizeof(route_key));
        route_key.scope_key.vm_id = first.vm_id;
        route_key.scope_key.vm_incarnation = first.vm_incarnation;
        route_key.scope_key.route_scope_id = 1;
        route_key.topology_revision = 1;
        route_key.route_generation = 1;
        memset(route_key.snapshot_digest, 1, sizeof(route_key.snapshot_digest));
        activation.required_route_snapshot_keys = &route_key;
        activation.required_route_snapshot_count = 1;
        activation.required_route_snapshot_capacity = 1;
        if (expect(wvm_local_reservation_commit(
                       &registry, &first, &activation, &result,
                       error, sizeof(error)) != 0,
                   "reject mismatched activation") ||
            expect(wvm_local_reservation_abort(
                       &registry, &first, &result, error,
                       sizeof(error)) == 0,
                   "release the first kernel context lease") ||
            expect(wvm_local_reservation_prepare(
                       &registry, &conflicting, &result, error,
                       sizeof(error)) == 0 &&
                       result == WVM_RESERVATION_RUNTIME_NEW,
                   "reuse the kernel context lease after release") ||
            expect(wvm_local_reservation_abort(
                       &registry, &conflicting, &result, error,
                       sizeof(error)) == 0,
                   "release the reused kernel context lease") ||
            expect(wvm_local_reservation_reap_expired(&registry, 100) == 0,
                   "do not reap released reservation")) {
            wvm_local_reservation_registry_destroy(&other_registry);
            wvm_local_reservation_registry_destroy(&registry);
            return 1;
        }
    }
    wvm_local_reservation_registry_destroy(&other_registry);
    wvm_local_reservation_registry_destroy(&registry);
    puts("reservation-runtime tests: PASS");
    return 0;
}

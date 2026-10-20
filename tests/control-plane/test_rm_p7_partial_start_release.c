/*
 * RM-P7-partial-start-release:
 * Failure after a prepare step releases exactly resources created by that step.
 */
#include <stdio.h>
#include <string.h>

#include "wavevm_reservation_runtime.h"

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "partial-start-release: %s\n", msg);
        return 1;
    }
    return 0;
}

static void fill_id(uint8_t id[WVM_IDENTITY_ID_BYTES], uint8_t value)
{
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = value;
}

static void fill_mode_b(struct wvm_resource_reservation *r, uint8_t id,
                        uint32_t vcpu, uint64_t mem)
{
    memset(r, 0, sizeof(*r));
    fill_id(r->reservation_id, id);
    fill_id(r->plan_digest, id + 10);
    fill_id(r->candidate_manifest_digest, id + 20);
    fill_id(r->admission_tx_id, id + 30);
    fill_id(r->eligibility_fence_digest, id + 40);
    r->vm_id = 200 + id;
    r->vm_incarnation = 1;
    r->physical_node_id = 17;
    r->node_instance_id = 9;
    r->inventory_revision = 4;
    r->guest_vcpu_slots = vcpu;
    r->guest_memory_bytes = mem;
    r->overhead_memory_bytes = 0;
    r->state = WVM_RESERVATION_PREPARED;
    r->exclusive_leases.entries = NULL;
    r->exclusive_leases.count = 0;
    r->exclusive_leases.capacity = 0;
    r->has_prepared_expiry = 1;
    r->prepared_expiry_unix_time_ms = 1000 + id;
}

int main(void)
{
    struct wvm_admission_node node;
    struct wvm_resource_reservation stored[4];
    struct wvm_resource_reservation first, second;
    struct wvm_local_reservation_registry registry;
    enum wvm_reservation_runtime_result result;
    char error[256] = {0};

    memset(&node, 0, sizeof(node));
    node.physical_node_id = 17;
    node.node_instance_id = 9;
    node.inventory_revision = 4;
    node.allocatable_vcpu_slots = 8;
    node.allocatable_memory_bytes = 32768;

    fill_mode_b(&first, 1, 2, 4096);
    fill_mode_b(&second, 2, 2, 4096);

    if (wvm_local_reservation_registry_init(&registry, &node, stored, 4, error,
                                            sizeof(error)) != 0) {
        fprintf(stderr, "init: %s\n", error);
        return 1;
    }

    /* Unknown abort (never prepared) must not invent capacity use. */
    {
        struct wvm_resource_reservation ghost;
        fill_mode_b(&ghost, 9, 2, 4096);
        if (expect(wvm_local_reservation_abort(&registry, &ghost, &result, error,
                                               sizeof(error)) == 0,
                   "unknown abort installs tombstone") ||
            expect(registry.prepared_vcpu_slots == 0 &&
                       registry.prepared_memory_bytes == 0 &&
                       registry.committed_vcpu_slots == 0,
                   "no capacity consumed before prepare")) {
            wvm_local_reservation_registry_destroy(&registry);
            return 1;
        }
    }

    if (expect(wvm_local_reservation_prepare(&registry, &first, &result, error,
                                             sizeof(error)) == 0 &&
                   result == WVM_RESERVATION_RUNTIME_NEW,
               "prepare first") ||
        expect(registry.prepared_vcpu_slots == 2 &&
                   registry.prepared_memory_bytes == 4096,
               "prepare consumed exact first-step resources")) {
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }

    if (expect(wvm_local_reservation_abort(&registry, &first, &result, error,
                                           sizeof(error)) == 0,
               "abort after prepare step") ||
        expect(registry.prepared_vcpu_slots == 0 &&
                   registry.prepared_memory_bytes == 0,
               "prepare-step failure released exactly those resources")) {
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }

    /* Fresh IDs after tombstone of id=1. */
    fill_mode_b(&first, 3, 2, 4096);
    fill_mode_b(&second, 4, 2, 4096);
    if (expect(wvm_local_reservation_prepare(&registry, &first, &result, error,
                                             sizeof(error)) == 0 &&
                   wvm_local_reservation_prepare(&registry, &second, &result,
                                                 error, sizeof(error)) == 0,
               "prepare two steps") ||
        expect(registry.prepared_vcpu_slots == 4 &&
                   registry.prepared_memory_bytes == 8192,
               "two prepares accumulate")) {
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }

    if (expect(wvm_local_reservation_abort(&registry, &first, &result, error,
                                           sizeof(error)) == 0,
               "abort only first step") ||
        expect(registry.prepared_vcpu_slots == 2 &&
                   registry.prepared_memory_bytes == 4096,
               "only first-step resources released") ||
        expect(wvm_local_reservation_abort(&registry, &second, &result, error,
                                           sizeof(error)) == 0 &&
                   registry.prepared_vcpu_slots == 0 &&
                   registry.prepared_memory_bytes == 0,
               "second-step abort restores remainder")) {
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }

    if (expect(wvm_local_reservation_abort(&registry, &second, &result, error,
                                           sizeof(error)) == 0,
               "idempotent abort replay after partial cleanup")) {
        wvm_local_reservation_registry_destroy(&registry);
        return 1;
    }

    wvm_local_reservation_registry_destroy(&registry);
    puts("PASS RM-P7-partial-start-release "
         "(exact step release; selective; idempotent)");
    puts("NOTE: also test_create_vm_recover.sh A-D + coordinator abort→RELEASED");
    return 0;
}

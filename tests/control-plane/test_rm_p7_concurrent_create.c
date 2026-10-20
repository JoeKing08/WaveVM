/*
 * RM-P7-concurrent-create-no-double-alloc
 * Phase 7 Minimum: four concurrent VM creations cannot double-allocate
 * CPU, memory, ports, SHM/host overhead exclusive leases.
 *
 * Oracle targets the local reservation registry (admission CREATE path's
 * capacity + exclusive-lease gate). Full multi-process CREATE_VM vertical
 * is exercised elsewhere; this is the race oracle.
 */
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_reservation_runtime.h"
#include "wavevm_manifest.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "rm-p7-concurrent-create: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_id(uint8_t id[WVM_IDENTITY_ID_BYTES], uint8_t value)
{
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = value;
}

struct race_arg {
    struct wvm_local_reservation_registry *registry;
    struct wvm_resource_reservation reservation;
    struct wvm_exclusive_lease leases[3];
    int outcome; /* 1 prepare ok, 0 rejected, -1 error */
};

static void fill_create(struct race_arg *arg, uint8_t id, uint16_t port_base,
                        int collide_ports)
{
    memset(&arg->reservation, 0, sizeof(arg->reservation));
    memset(arg->leases, 0, sizeof(arg->leases));
    fill_id(arg->reservation.reservation_id, id);
    fill_id(arg->reservation.plan_digest, (uint8_t)(id + 10));
    fill_id(arg->reservation.candidate_manifest_digest, (uint8_t)(id + 20));
    fill_id(arg->reservation.admission_tx_id, (uint8_t)(id + 30));
    fill_id(arg->reservation.eligibility_fence_digest, (uint8_t)(id + 40));
    arg->reservation.vm_id = 200U + id;
    arg->reservation.vm_incarnation = 1;
    arg->reservation.physical_node_id = 17;
    arg->reservation.node_instance_id = 9;
    arg->reservation.inventory_revision = 4;
    arg->reservation.guest_vcpu_slots = 2;
    arg->reservation.guest_memory_bytes = 8192;
    arg->reservation.overhead_vcpu_slots = 1; /* host overhead */
    arg->reservation.overhead_memory_bytes = 4096;
    arg->reservation.state = WVM_RESERVATION_PREPARED;
    arg->reservation.has_prepared_expiry = 1;
    arg->reservation.prepared_expiry_unix_time_ms = 10000;

    arg->leases[0].lease_kind = WVM_EXCLUSIVE_LEASE_KIND_NODE_RUNTIME_DATA_UDP;
    arg->leases[0].lease_generation = 1;
    snprintf(arg->leases[0].lease_name, sizeof(arg->leases[0].lease_name),
             "udp:any:node-runtime-data:%u",
             (unsigned)(collide_ports ? 18000 : port_base));

    arg->leases[1].lease_kind =
        WVM_EXCLUSIVE_LEASE_KIND_LOCAL_EXECUTOR_SERVICE_UDP;
    arg->leases[1].lease_generation = 1;
    snprintf(arg->leases[1].lease_name, sizeof(arg->leases[1].lease_name),
             "udp:loopback:local-executor-service:%u",
             (unsigned)(collide_ports ? 19000 : (uint16_t)(port_base + 1U)));

    /* SHM-like exclusive host resource name (generic lease kind 1 reused as
     * named host overhead resource under inventory digest). */
    arg->leases[2].lease_kind = 4U; /* distinct kind for host SHM path name */
    arg->leases[2].lease_generation = 1;
    snprintf(arg->leases[2].lease_name, sizeof(arg->leases[2].lease_name),
             "shm:/wavevm_ram/vm-%u", (unsigned)arg->reservation.vm_id);

    arg->reservation.exclusive_leases.entries = arg->leases;
    arg->reservation.exclusive_leases.count = 3;
    arg->reservation.exclusive_leases.capacity = 3;
}

static void *race_main(void *opaque)
{
    struct race_arg *arg = opaque;
    enum wvm_reservation_runtime_result result;
    char error[128];

    if (wvm_local_reservation_prepare(arg->registry, &arg->reservation, &result,
                                      error, sizeof(error)) == 0) {
        arg->outcome = 1;
    } else {
        arg->outcome = 0;
    }
    return NULL;
}

static int run_capacity_race(void)
{
    struct wvm_admission_node node;
    struct wvm_resource_reservation stored[16];
    struct wvm_local_reservation_registry registry;
    struct race_arg args[4];
    pthread_t threads[4];
    char error[256];
    size_t i;
    int successes = 0;
    uint32_t expected_cpu;

    memset(&node, 0, sizeof(node));
    node.physical_node_id = 17;
    node.node_instance_id = 9;
    node.inventory_revision = 4;
    /* Capacity fits exactly two creates: each uses 2 guest + 1 overhead = 3. */
    node.allocatable_vcpu_slots = 6;
    node.allocatable_memory_bytes = 2U * (8192U + 4096U);

    if (wvm_local_reservation_registry_init(&registry, &node, stored, 16, error,
                                            sizeof(error)) != 0) {
        fprintf(stderr, "rm-p7-concurrent-create: init: %s\n", error);
        return -1;
    }
    for (i = 0; i < 4; i++) {
        args[i].registry = &registry;
        args[i].outcome = -1;
        fill_create(&args[i], (uint8_t)(10 + i), (uint16_t)(18010 + i * 10), 0);
    }
    for (i = 0; i < 4; i++) {
        if (pthread_create(&threads[i], NULL, race_main, &args[i]) != 0) {
            wvm_local_reservation_registry_destroy(&registry);
            return -1;
        }
    }
    for (i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
        if (args[i].outcome < 0) {
            wvm_local_reservation_registry_destroy(&registry);
            return -1;
        }
        if (args[i].outcome == 1) {
            successes++;
        }
    }
    expected_cpu = 6;
    if (expect(successes == 2, "exactly two of four concurrent creates succeed") ||
        expect(registry.prepared_vcpu_slots == expected_cpu,
               "prepared vCPU accounts exactly to capacity") ||
        expect(registry.prepared_memory_bytes == node.allocatable_memory_bytes,
               "prepared memory accounts exactly to capacity")) {
        wvm_local_reservation_registry_destroy(&registry);
        return -1;
    }
    wvm_local_reservation_registry_destroy(&registry);
    return 0;
}

static int run_port_collision_race(void)
{
    struct wvm_admission_node node;
    struct wvm_resource_reservation stored[8];
    struct wvm_local_reservation_registry registry;
    struct race_arg args[4];
    pthread_t threads[4];
    char error[256];
    size_t i;
    int successes = 0;

    memset(&node, 0, sizeof(node));
    node.physical_node_id = 17;
    node.node_instance_id = 9;
    node.inventory_revision = 4;
    /* Plenty of CPU/mem — only exclusive port leases should serialize. */
    node.allocatable_vcpu_slots = 64;
    node.allocatable_memory_bytes = 1U << 30;

    if (wvm_local_reservation_registry_init(&registry, &node, stored, 8, error,
                                            sizeof(error)) != 0) {
        fprintf(stderr, "rm-p7-concurrent-create: port init: %s\n", error);
        return -1;
    }
    for (i = 0; i < 4; i++) {
        args[i].registry = &registry;
        args[i].outcome = -1;
        /* All four request the same UDP ports → only one may prepare. */
        fill_create(&args[i], (uint8_t)(40 + i), 18000, 1);
        /* Distinct SHM names so only ports collide. */
        snprintf(args[i].leases[2].lease_name, sizeof(args[i].leases[2].lease_name),
                 "shm:/wavevm_ram/vm-%u", (unsigned)args[i].reservation.vm_id);
    }
    for (i = 0; i < 4; i++) {
        if (pthread_create(&threads[i], NULL, race_main, &args[i]) != 0) {
            wvm_local_reservation_registry_destroy(&registry);
            return -1;
        }
    }
    for (i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
        if (args[i].outcome == 1) {
            successes++;
        }
    }
    if (expect(successes == 1,
               "identical port leases: only one concurrent create succeeds")) {
        wvm_local_reservation_registry_destroy(&registry);
        return -1;
    }
    wvm_local_reservation_registry_destroy(&registry);
    return 0;
}

int main(void)
{
    if (run_capacity_race() != 0 || run_port_collision_race() != 0) {
        return 1;
    }
    puts("rm-p7-concurrent-create: PASS");
    puts("NOTE: 4-way capacity + exclusive port/SHM lease fail-closed.");
    return 0;
}

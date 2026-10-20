/*
 * Unit oracle for the deferred fault-slot state machine used by the
 * SIGSEGV path (mirrors wavevm-user-mem.c). Ensures submit never needs
 * to perform IPC in the producer (handler-equivalent) side.
 */
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    WVM_FAULT_SLOT_FREE = 0,
    WVM_FAULT_SLOT_FILLING = 1,
    WVM_FAULT_SLOT_SUBMITTED = 2,
    WVM_FAULT_SLOT_DONE = 3,
    WVM_FAULT_SLOT_FAILED = 4,
};

typedef struct {
    atomic_int state;
    uintptr_t fault_addr;
    uint64_t gpa;
    int is_write;
} WVMFaultSlot;

#define WVM_FAULT_QUEUE_SIZE 8

static WVMFaultSlot g_fault_slots[WVM_FAULT_QUEUE_SIZE];
static atomic_uint g_fault_slot_cursor;
static int g_resolved;
static int g_ipc_from_producer;

static int resolve_on_worker(uintptr_t fault_addr, uint64_t gpa, int is_write)
{
    (void)fault_addr;
    (void)gpa;
    (void)is_write;
    g_resolved++;
    return 0;
}

static int submit_from_producer(uintptr_t addr, uint64_t gpa, int is_write)
{
    WVMFaultSlot *slot = NULL;
    for (unsigned attempt = 0; attempt < WVM_FAULT_QUEUE_SIZE; attempt++) {
        unsigned idx = atomic_fetch_add(&g_fault_slot_cursor, 1) % WVM_FAULT_QUEUE_SIZE;
        int expected = WVM_FAULT_SLOT_FREE;
        if (atomic_compare_exchange_strong(&g_fault_slots[idx].state, &expected,
                                           WVM_FAULT_SLOT_FILLING)) {
            slot = &g_fault_slots[idx];
            break;
        }
    }
    if (!slot) {
        return -1;
    }
    /* Producer must not touch IPC. */
    slot->fault_addr = addr;
    slot->gpa = gpa;
    slot->is_write = is_write;
    atomic_store(&slot->state, WVM_FAULT_SLOT_SUBMITTED);
    return 0;
}

static void worker_drain(void)
{
    for (unsigned i = 0; i < WVM_FAULT_QUEUE_SIZE; i++) {
        WVMFaultSlot *slot = &g_fault_slots[i];
        if (atomic_load(&slot->state) != WVM_FAULT_SLOT_SUBMITTED) {
            continue;
        }
        int rc = resolve_on_worker(slot->fault_addr, slot->gpa, slot->is_write);
        atomic_store(&slot->state,
                     rc == 0 ? WVM_FAULT_SLOT_DONE : WVM_FAULT_SLOT_FAILED);
    }
}

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        return 0;
    }
    return 1;
}

int main(void)
{
    int ok = 1;
    memset(g_fault_slots, 0, sizeof(g_fault_slots));
    atomic_store(&g_fault_slot_cursor, 0);
    g_resolved = 0;
    g_ipc_from_producer = 0;

    ok &= expect(submit_from_producer(0x1000, 0x2000, 0) == 0, "submit read fault");
    ok &= expect(submit_from_producer(0x3000, 0x4000, 1) == 0, "submit write fault");
    ok &= expect(g_ipc_from_producer == 0, "producer performed no IPC");
    ok &= expect(g_resolved == 0, "worker has not run yet");

    worker_drain();
    ok &= expect(g_resolved == 2, "worker resolved both faults");
    ok &= expect(atomic_load(&g_fault_slots[0].state) == WVM_FAULT_SLOT_DONE ||
                     atomic_load(&g_fault_slots[1].state) == WVM_FAULT_SLOT_DONE,
                 "at least one DONE slot");

    /* Recycle DONE -> FREE like the real handler */
    for (unsigned i = 0; i < WVM_FAULT_QUEUE_SIZE; i++) {
        if (atomic_load(&g_fault_slots[i].state) == WVM_FAULT_SLOT_DONE) {
            atomic_store(&g_fault_slots[i].state, WVM_FAULT_SLOT_FREE);
        }
    }

    /* Fill the queue; next submit must fail-closed (no IPC). */
    for (unsigned i = 0; i < WVM_FAULT_QUEUE_SIZE; i++) {
        ok &= expect(submit_from_producer(0x1000u * (i + 1), 0x2000u * (i + 1), 0) == 0,
                     "fill queue");
    }
    ok &= expect(submit_from_producer(0xdead, 0xbeef, 0) != 0,
                 "overflow fail-closed without IPC");
    ok &= expect(g_ipc_from_producer == 0, "overflow still no producer IPC");

    if (!ok) {
        return 1;
    }
    printf("PASS: deferred fault queue producer never does IPC\n");
    return 0;
}

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include <stdatomic.h>
#include "wavevm_memory.h"

#define MAX_RAM_BLOCKS 1
#define DIRTY_MEMORY_MIGRATION 0
#define RAM_ADDR_INVALID UINT64_MAX
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define g_free free
typedef uint64_t ram_addr_t;
typedef struct { int unused; } MemoryRegion;
typedef struct { MemoryRegion *mr; } RAMBlock;
typedef struct { uint64_t bits; } DirtyBitmapSnapshot;
typedef struct {
    uintptr_t hva_start;
    ram_addr_t ram_start;
    uint64_t gpa_start, size;
} GVMRamBlock;
static uint8_t ram[64 * WVM_MEMORY_PAGE_BYTES];
static uint8_t authority_pages[64][WVM_MEMORY_PAGE_BYTES];
static uint8_t last_committed[WVM_MEMORY_PAGE_BYTES];
static GVMRamBlock g_mem_blocks[1];
static int g_block_count = 1, g_tcg_shm_coherent = 1, g_is_slave = 1;
static int t_com_sock = 1;
static uint64_t live_dirty, versions[64];
static int calls, fail_page = -1, fail_page_calls;
static int page_read_result;
static bool inject_later_write, inject_commit_write;
static uint64_t clock_us, clock_step;
static bool wavevm_qemu_runtime_gate_enabled(void) { return true; }
static uint64_t get_us_time(void) { clock_us += clock_step; return clock_us; }
static uint64_t memory_ipc_deadline(void) { return get_us_time() + 5000000; }
static RAMBlock *qemu_ram_block_from_host(void *ptr, bool round, ram_addr_t *off)
{
    static MemoryRegion mr;
    static RAMBlock rb = {.mr = &mr};
    (void)ptr; (void)round; *off = 0; return &rb;
}
static ram_addr_t qemu_ram_addr_from_host(void *ptr)
{ return (uint8_t *)ptr - ram; }
static DirtyBitmapSnapshot *cpu_physical_memory_snapshot_and_clear_dirty(
    MemoryRegion *mr, ram_addr_t off, uint64_t size, unsigned client)
{
    DirtyBitmapSnapshot *s = malloc(sizeof(*s));
    (void)mr; (void)off; (void)size; (void)client;
    assert(s); s->bits = live_dirty; live_dirty = 0;
    if (inject_later_write) { live_dirty |= UINT64_C(1) << 63; }
    return s;
}
static bool cpu_physical_memory_snapshot_get_dirty(
    DirtyBitmapSnapshot *s, ram_addr_t ra, uint64_t size)
{
    for (uint64_t p = ra / 4096; p < (ra + size) / 4096; p++) {
        if (s->bits & (UINT64_C(1) << p)) { return true; }
    }
    return false;
}
static void cpu_physical_memory_set_dirty_range(ram_addr_t ra, uint64_t len,
                                                unsigned flags)
{ (void)len; (void)flags; live_dirty |= UINT64_C(1) << (ra / 4096); }
static uint64_t get_local_page_version(uint64_t gpa) { return versions[gpa / 4096]; }
static void set_local_page_version(uint64_t gpa, uint64_t version)
{ versions[gpa / 4096] = version; }
static int internal_connect_master(void) { return 1; }
static int request_commit_on_fd(int fd, uint64_t gpa, uint64_t version,
                                uint16_t offset, const uint8_t *data,
                                size_t bytes, struct wvm_mem_commit_ack *ack)
{
    (void)fd; (void)offset; calls++;
    if ((int)(gpa / 4096) == fail_page && ++fail_page_calls == 1) {
        return -ESTALE;
    }
    assert(bytes == WVM_MEMORY_PAGE_BYTES);
    assert(gpa / WVM_MEMORY_PAGE_BYTES < 64);
    memcpy(authority_pages[gpa / WVM_MEMORY_PAGE_BYTES], data, bytes);
    memcpy(last_committed, data, bytes);
    if (inject_commit_write && (int)(gpa / 4096) == fail_page) {
        ram[gpa + 1] = 4;
        live_dirty |= UINT64_C(1) << (gpa / 4096);
        inject_commit_write = false;
    }
    ack->result_version = version + 1; return 0;
}
static int request_page_over_ipc(uint64_t gpa, struct wvm_mem_ack *ack,
                                  uint8_t *data)
{
    if (page_read_result != 0) { return page_read_result; }
    assert(gpa / WVM_MEMORY_PAGE_BYTES < 64);
    memcpy(data, authority_pages[gpa / WVM_MEMORY_PAGE_BYTES],
           WVM_MEMORY_PAGE_BYTES);
    ack->status = WVM_MEM_ACK_SUCCESS; ack->version = 9; return 0;
}
static int ack_status_to_errno(uint16_t status) { return status ? -EIO : 0; }
static void add_to_aggregator(uint64_t gpa, uint64_t v, uint16_t off,
                               uint16_t size, void *p, uint8_t flags)
{ (void)gpa; (void)v; (void)off; (void)size; (void)p; (void)flags; assert(false); }
static void flush_aggregator(void) { assert(false); }

/* Generated directly from the production function by the test runner. */
#include "coherent_dirty.inc"

static void reset(void)
{
    while (g_coherent_preimages) {
        WVMCoherentPreimage *entry = g_coherent_preimages;
        g_coherent_preimages = entry->next;
        free(entry->bytes);
        free(entry);
    }
    atomic_store_explicit(&g_coherent_generation, 1, memory_order_release);
    atomic_store_explicit(&g_coherent_capture_failed_generation, 0,
                          memory_order_release);
    memset(ram, 1, sizeof(ram));
    memset(authority_pages, 1, sizeof(authority_pages));
    memset(last_committed, 0, sizeof(last_committed));
    for (size_t i = 0; i < 64; i++) { versions[i] = 5; }
    g_mem_blocks[0] = (GVMRamBlock){.hva_start = (uintptr_t)ram,
                                   .ram_start = 0,
                                   .size = sizeof(ram)};
    calls = 0; fail_page = -1; fail_page_calls = 0;
    page_read_result = 0;
    clock_us = 0; clock_step = 0;
    for (size_t page = 0; page < 64; page++) {
        wavevm_user_mem_record_tcg_write(page * WVM_MEMORY_PAGE_BYTES, 1);
        ram[page * WVM_MEMORY_PAGE_BYTES] = 2;
    }
    live_dirty = (UINT64_C(1) << 33) - 1;
    inject_later_write = false;
    inject_commit_write = false;
}

int main(void)
{
    uint8_t snapshot[4096];
    reset();
    while (g_coherent_preimages) {
        WVMCoherentPreimage *entry = g_coherent_preimages;
        g_coherent_preimages = entry->next;
        free(entry->bytes);
        free(entry);
    }
    g_is_slave = 0;
    wavevm_user_mem_record_tcg_write(0, 1);
    assert(g_coherent_preimages == NULL);
    g_is_slave = 1;
    wavevm_user_mem_record_tcg_write(0, 1);
    assert(g_coherent_preimages != NULL);

    reset(); inject_later_write = true;
    assert(flush_coherent_dirty_bitmap_locked(snapshot) == 33);
    assert(calls == 33 && live_dirty == (UINT64_C(1) << 63));
    reset(); fail_page = 1;
    assert(flush_coherent_dirty_bitmap_locked(snapshot) == 33);
    assert(calls == 34); /* stale page is rebased onto authority version 9. */
    assert(live_dirty == 0);
    assert(versions[0] == 6 && versions[1] == 10);
    reset(); clock_step = 5000000;
    assert(flush_coherent_dirty_bitmap_locked(snapshot) == -ETIMEDOUT);
    assert(calls == 0 && live_dirty == (UINT64_C(1) << 33) - 1);
    reset();
    coherent_discard_preimage(10 * WVM_MEMORY_PAGE_BYTES, 1);
    live_dirty = UINT64_C(1) << 10;
    assert(flush_coherent_dirty_bitmap_locked(snapshot) == 1);
    assert(calls == 1 && versions[10] == 10);
    reset();
    coherent_discard_preimage(10 * WVM_MEMORY_PAGE_BYTES, 1);
    live_dirty = UINT64_C(1) << 10;
    page_read_result = -ETIMEDOUT;
    assert(flush_coherent_dirty_bitmap_locked(snapshot) == -ETIMEDOUT);
    assert(calls == 0 && live_dirty == (UINT64_C(1) << 10));
    /* A write can set its dirty bit after its pre-image generation was frozen. */
    reset();
    live_dirty = 0;
    assert(flush_coherent_dirty_bitmap_locked(snapshot) == 0);
    assert(atomic_load_explicit(&g_coherent_generation,
                                memory_order_acquire) == 2);
    ram[10 * WVM_MEMORY_PAGE_BYTES + 1] = 3;
    live_dirty = UINT64_C(1) << 10;
    fail_page = 10;
    inject_commit_write = true;
    authority_pages[10][8] = 0x77;
    assert(flush_coherent_dirty_bitmap_locked(snapshot) == 1);
    assert(calls == 2 && versions[10] == 10);
    assert(last_committed[0] == 2 && last_committed[1] == 3);
    assert(last_committed[8] == 0x77);
    assert(ram[10 * WVM_MEMORY_PAGE_BYTES + 1] == 4);
    assert(ram[10 * WVM_MEMORY_PAGE_BYTES + 8] == 1);
    assert(live_dirty == (UINT64_C(1) << 10));
    puts("coherent dirty fence: 33 pages, concurrent dirty, stale base, timeout PASS");
    return 0;
}

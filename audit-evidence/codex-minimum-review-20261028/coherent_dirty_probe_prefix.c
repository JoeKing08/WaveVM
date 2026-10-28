#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WVM_MEMORY_PAGE_BYTES 4096
#define DIRTY_MEMORY_MIGRATION 0
#define RAM_ADDR_INVALID UINT64_MAX
typedef uint64_t ram_addr_t;
typedef struct { uintptr_t hva_start; uint64_t gpa_start; uint64_t size; } GVMRamBlock;
struct wvm_mem_commit_ack { uint64_t result_version; };
struct wvm_mem_ack { uint32_t status; uint64_t version; };
static bool g_tcg_shm_coherent = true;
static int g_block_count = 1;
static GVMRamBlock g_mem_blocks[1];
static int t_com_sock = 1;
static uint8_t local_ram[33][4096], directory_ram[33][4096];
static uint64_t local_versions[33], directory_versions[33];
static bool dirty[33];
static int commits;
static bool wavevm_qemu_runtime_gate_enabled(void) { return true; }
static ram_addr_t qemu_ram_addr_from_host(void *p) { return (uint8_t *)p - &local_ram[0][0]; }
static uint64_t get_local_page_version(uint64_t gpa) { return local_versions[gpa / 4096]; }
static void set_local_page_version(uint64_t gpa, uint64_t v) { local_versions[gpa / 4096] = v; }
static bool is_page_all_zero(void *p) {
    uint8_t *b = p;
    for (int i = 0; i < 4096; i++) if (b[i]) return false;
    return true;
}
static bool cpu_physical_memory_test_and_clear_dirty(ram_addr_t ra, int len, int kind) {
    (void)len; (void)kind;
    bool was_dirty = dirty[ra / 4096];
    dirty[ra / 4096] = false;
    return was_dirty;
}
static void cpu_physical_memory_set_dirty_range(ram_addr_t ra, int len, int flags) {
    (void)len; (void)flags; dirty[ra / 4096] = true;
}
static int internal_connect_master(void) { return 1; }
static int ack_status_to_errno(uint32_t status) { return status ? -EIO : 0; }
static int request_commit_on_fd(int fd, uint64_t gpa, uint64_t base, int flags,
                                const void *page, size_t bytes,
                                struct wvm_mem_commit_ack *ack) {
    size_t i = gpa / 4096;
    (void)fd; (void)flags;
    if (base != directory_versions[i]) return -ESTALE;
    memcpy(directory_ram[i], page, bytes);
    ack->result_version = ++directory_versions[i];
    commits++;
    return 0;
}
static int request_page_over_ipc(uint64_t gpa, struct wvm_mem_ack *ack, uint8_t *page) {
    size_t i = gpa / 4096;
    ack->status = 0;
    ack->version = directory_versions[i];
    memcpy(page, directory_ram[i], 4096);
    return 0;
}
static void add_to_aggregator(uint64_t gpa, uint64_t v, int off, int len, void *data, int f) {
    (void)gpa; (void)v; (void)off; (void)len; (void)data; (void)f;
}
static void flush_aggregator(void) {}

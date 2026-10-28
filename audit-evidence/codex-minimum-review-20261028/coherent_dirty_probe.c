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
static int flush_coherent_dirty_bitmap_locked(void *current_snapshot)
{
    int committed = 0;
    int first_error = 0;
    int scanned = 0;
    int budget;
    int max_scan;
    const bool use_commit = wavevm_qemu_runtime_gate_enabled();
    static int cursor_bi;
    static uint64_t cursor_off;
    const char *budget_env;
    int bi_start;
    int passes;

    if (!g_tcg_shm_coherent || !current_snapshot) {
        return 0;
    }
    if (g_block_count <= 0) {
        return 0;
    }

    budget = 32;
    budget_env = getenv("WVM_TCG_COHERENT_DIRTY_BUDGET");
    if (budget_env && budget_env[0] != '\0') {
        int v = atoi(budget_env);
        if (v > 0 && v <= 4096) {
            budget = v;
        }
    }
    /* Scan at most this many pages of bitmap per call (clean checks are cheap
     * but still O(RAM) if unbounded — 8k pages ≈ 32MiB window). */
    max_scan = budget * 256;
    if (max_scan < 4096) {
        max_scan = 4096;
    }
    if (max_scan > 65536) {
        max_scan = 65536;
    }

    if (cursor_bi < 0 || cursor_bi >= g_block_count) {
        cursor_bi = 0;
        cursor_off = 0;
    }

    bi_start = cursor_bi;
    passes = 0;
    while (committed < budget && scanned < max_scan && first_error == 0 &&
           passes < g_block_count + 1) {
        GVMRamBlock *blk = &g_mem_blocks[cursor_bi];
        ram_addr_t ram_base = qemu_ram_addr_from_host((void *)blk->hva_start);
        uint64_t off = cursor_off;

        if (ram_base == RAM_ADDR_INVALID || blk->size < 4096) {
            cursor_bi = (cursor_bi + 1) % g_block_count;
            cursor_off = 0;
            passes++;
            if (cursor_bi == bi_start && cursor_off == 0) {
                break;
            }
            continue;
        }

        while (off + 4096 <= blk->size && committed < budget &&
               scanned < max_scan && first_error == 0) {
            ram_addr_t ra = ram_base + off;
            uint64_t gpa;
            void *hva;
            uint64_t base_version;
            int commit_ret;

            scanned++;
            if (!cpu_physical_memory_test_and_clear_dirty(
                    ra, 4096, DIRTY_MEMORY_MIGRATION)) {
                off += 4096;
                continue;
            }
            gpa = blk->gpa_start + off;
            hva = (void *)(blk->hva_start + off);
            if (get_local_page_version(gpa) == 0 && is_page_all_zero(hva)) {
                /* Match master handoff: skip implicit zero dirty bits. */
                off += 4096;
                continue;
            }
            memcpy(current_snapshot, hva, 4096);
            if (use_commit) {
                struct wvm_mem_commit_ack ack;

                base_version = get_local_page_version(gpa);
                if (base_version == 0) {
                    base_version = 1;
                }
                if (t_com_sock < 0) {
                    t_com_sock = internal_connect_master();
                }
                commit_ret = request_commit_on_fd(
                    t_com_sock, gpa, base_version, 0, current_snapshot,
                    WVM_MEMORY_PAGE_BYTES, &ack);
                if (commit_ret == -ENOENT || commit_ret == -ESTALE) {
                    struct wvm_mem_ack mat_ack;
                    uint8_t mat_page[WVM_MEMORY_PAGE_BYTES];
                    int mat_ret = request_page_over_ipc(gpa, &mat_ack, mat_page);
                    if (mat_ret == 0 &&
                        ack_status_to_errno(mat_ack.status) == 0 &&
                        mat_ack.version != 0) {
                        base_version = mat_ack.version;
                        /*
                         * No fault-hook pre-image under coherent SHM: commit
                         * the post-store full page against rematerialized base
                         * (create/replace). Prefer fail-closed over silent skip.
                         */
                        commit_ret = request_commit_on_fd(
                            t_com_sock, gpa, base_version, 0, current_snapshot,
                            WVM_MEMORY_PAGE_BYTES, &ack);
                    }
                }
                if (commit_ret != 0) {
                    cpu_physical_memory_set_dirty_range(
                        ra, 4096, 1 << DIRTY_MEMORY_MIGRATION);
                    first_error = commit_ret;
                    break;
                }
                set_local_page_version(gpa, ack.result_version);
            } else {
                uint64_t ver = get_local_page_version(gpa);
                if (ver == 0) {
                    ver = 1;
                }
                add_to_aggregator(gpa, ver + 1, 0, 4096, current_snapshot, 0);
                set_local_page_version(gpa, ver + 1);
            }
            committed++;
            off += 4096;
        }

        if (off + 4096 > blk->size) {
            cursor_bi = (cursor_bi + 1) % g_block_count;
            cursor_off = 0;
            passes++;
        } else {
            cursor_off = off;
        }
        if (cursor_bi == bi_start && cursor_off == 0 && passes > 0) {
            break;
        }
    }
    if (!use_commit && committed > 0) {
        flush_aggregator();
    }
    return first_error != 0 ? first_error : committed;
}

int main(int argc, char **argv) {
    uint8_t snapshot[4096];
    int remaining = 0;
    bool stale = argc > 1 && strcmp(argv[1], "stale") == 0;
    g_mem_blocks[0].hva_start = (uintptr_t)&local_ram[0][0];
    g_mem_blocks[0].size = (stale ? 1 : 33) * 4096;
    for (int i = 0; i < (stale ? 1 : 33); i++) {
        local_versions[i] = directory_versions[i] = 1;
        dirty[i] = true;
        local_ram[i][0] = 1;
    }
    if (stale) {
        directory_versions[0] = 2;
        directory_ram[0][1] = 1;
    }
    int rc = flush_coherent_dirty_bitmap_locked(snapshot);
    for (int i = 0; i < 33; i++) remaining += dirty[i];
    printf("probe=%s return=%d commits=%d remaining_dirty=%d directory_x=%u directory_y=%u\n",
           stale ? "stale" : "budget", rc, commits, remaining,
           directory_ram[0][0], directory_ram[0][1]);
    if (stale) return directory_ram[0][1] == 0 ? 0 : 1;
    return rc == 32 && remaining == 1 ? 0 : 1;
}

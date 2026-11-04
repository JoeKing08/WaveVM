#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../master_core/logic_core.c"

void *g_shm_ptr;
size_t g_shm_size;

static int check_page(const uint8_t *page, const uint8_t patch[3])
{
    for (size_t i = 0; i < WVM_PAGE_BYTES; i++) {
        uint8_t expected = i >= 7 && i < 10 ? patch[i - 7] : 0;

        if (page[i] != expected) {
            fprintf(stderr, "page mismatch at offset %zu: got=%02x expected=%02x\n",
                    i, page[i], expected);
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    const uint64_t gpa = WVM_PAGE_BYTES;
    const uint8_t patch[3] = {0x11, 0x22, 0x33};
    uint8_t page[WVM_PAGE_BYTES];
    uint64_t version = 0;
    uint64_t next_version = 0;
    uint32_t lock_idx;

    g_dir_capacity = 4096;
    g_dir_table = calloc(g_dir_capacity, sizeof(*g_dir_table));
    g_dir_alloc_size = g_dir_capacity * sizeof(*g_dir_table);
    g_shm_ptr = calloc(1, 2 * WVM_PAGE_BYTES);
    g_shm_size = 2 * WVM_PAGE_BYTES;
    if (!g_dir_table || !g_shm_ptr) {
        fputs("test allocation failed\n", stderr);
        return 1;
    }
    lock_idx = get_lock_idx(gpa);
    pthread_mutex_init(&g_dir_table_locks[lock_idx], NULL);

    memset((uint8_t *)g_shm_ptr + gpa, 0xa5, WVM_PAGE_BYTES);
    if (wvm_handle_local_fault_fastpath(gpa, page, &version) != 0 ||
        version != 1) {
        fputs("failed to materialize committed zero page\n", stderr);
        return 1;
    }
    for (size_t i = 0; i < sizeof(page); i++) {
        if (page[i] != 0) {
            fputs("mutable SHM was exposed as committed directory data\n", stderr);
            return 1;
        }
    }

    memset((uint8_t *)g_shm_ptr + gpa, 0x5a, WVM_PAGE_BYTES);
    if (wvm_handle_local_fault_fastpath(gpa, page, &version) != 0 ||
        version != 1) {
        fputs("uncommitted SHM mutation changed directory version\n", stderr);
        return 1;
    }
    for (size_t i = 0; i < sizeof(page); i++) {
        if (page[i] != 0) {
            fputs("uncommitted SHM mutation changed directory image\n", stderr);
            return 1;
        }
    }

    if (wvm_handle_local_commit(gpa, version, 7, patch, sizeof(patch), 0,
                                &next_version) != 0 ||
        next_version != version + 1) {
        fputs("versioned directory commit failed\n", stderr);
        return 1;
    }
    memset((uint8_t *)g_shm_ptr + gpa, 0xc3, WVM_PAGE_BYTES);
    if (wvm_handle_local_fault_fastpath(gpa, page, &version) != 0 ||
        version != next_version || check_page(page, patch) != 0) {
        fputs("committed directory image changed with mutable SHM\n", stderr);
        return 1;
    }

    {
        const uint8_t shared_patch[3] = {0x44, 0x55, 0x66};

        memset((uint8_t *)g_shm_ptr + gpa, 0x44, WVM_PAGE_BYTES);
        memcpy((uint8_t *)g_shm_ptr + gpa + 20, shared_patch,
               sizeof(shared_patch));
        if (wvm_handle_local_commit(gpa, version, 20, shared_patch,
                                    sizeof(shared_patch), 1,
                                    &next_version) != 0) {
            fputs("shared-backing directory commit failed\n", stderr);
            return 1;
        }
        for (size_t i = 0; i < WVM_PAGE_BYTES; i++) {
            uint8_t expected = i >= 20 && i < 23 ? shared_patch[i - 20] : 0x44;

            if (((uint8_t *)g_shm_ptr)[gpa + i] != expected) {
                fputs("shared-backing commit rewrote live guest RAM\n", stderr);
                return 1;
            }
        }
        memset((uint8_t *)g_shm_ptr + gpa, 0xc3, WVM_PAGE_BYTES);
        if (wvm_handle_local_fault_fastpath(gpa, page, &version) != 0 ||
            version != next_version) {
            fputs("shared-backing commit image/version missing\n", stderr);
            return 1;
        }
        for (size_t i = 0; i < WVM_PAGE_BYTES; i++) {
            uint8_t expected = i >= 7 && i < 10 ? patch[i - 7] :
                               i >= 20 && i < 23 ? shared_patch[i - 20] : 0;

            if (page[i] != expected) {
                fputs("shared-backing commit did not update directory image\n",
                      stderr);
                return 1;
            }
        }
    }
    if (wvm_handle_local_commit(gpa, version - 1, 0, patch, sizeof(patch), 0,
                                &next_version) != -ESTALE) {
        fputs("stale directory commit was not rejected\n", stderr);
        return 1;
    }

    puts("committed directory image isolation: PASS");
    return 0;
}

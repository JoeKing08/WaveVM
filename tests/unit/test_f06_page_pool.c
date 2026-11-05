#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct WritablePage {
    uint64_t gpa;
    void *pre_image_snapshot;
    struct WritablePage *next;
} WritablePage;

#include "f06_pool.inc"

int main(void)
{
    int idxs[PAGE_POOL_SIZE];
    int i;

    /* Init like wavevm_user_mem_init */
    for (i = 0; i < PAGE_POOL_SIZE; i++) {
        g_page_pool[i].next = NULL;
        atomic_store_explicit(&g_page_pool_occupied[i], 0, memory_order_relaxed);
    }
    atomic_store_explicit(&g_page_pool_in_use, 0, memory_order_relaxed);
    atomic_store_explicit(&g_pool_idx, 0, memory_order_relaxed);

    /* Occupy entire pool */
    for (i = 0; i < PAGE_POOL_SIZE; i++) {
        idxs[i] = page_pool_claim();
        assert(idxs[i] >= 0 && idxs[i] < PAGE_POOL_SIZE);
        g_page_pool[idxs[i]].gpa = (uint64_t)i * 4096;
    }
    assert(atomic_load(&g_page_pool_in_use) == (unsigned)PAGE_POOL_SIZE);

    /* 4097th claim must fail bounded (no wrap overwrite) */
    assert(page_pool_claim() == -1);
    assert(atomic_load(&g_page_pool_in_use) == (unsigned)PAGE_POOL_SIZE);
    puts("EVID F06 pool_exhaust claim_fail_at_4097 in_use=4096");

    /* Flood beyond: many more fails stay bounded */
    for (i = 0; i < 128; i++) {
        assert(page_pool_claim() == -1);
    }
    puts("EVID F06 write_fault_flood_beyond_cap bounded_fail=128");

    /* Release one → reclaim same capacity without overwrite of others */
    {
        int freed = idxs[0];
        int before = atomic_load(&g_page_pool_in_use);
        page_pool_release(freed);
        assert(atomic_load(&g_page_pool_in_use) == (unsigned)(before - 1));
        int again = page_pool_claim();
        assert(again == freed || again >= 0);
        assert(atomic_load(&g_page_pool_in_use) == (unsigned)PAGE_POOL_SIZE);
        /* Still full */
        assert(page_pool_claim() == -1);
        puts("EVID F06 occupy_return_reclaim slot_ok");
    }

    /* Release all occupied slots (simulates writable_page_release_chain). */
    for (i = 0; i < PAGE_POOL_SIZE; i++) {
        if (atomic_load(&g_page_pool_occupied[i])) {
            page_pool_release(i);
        }
    }
    assert(atomic_load(&g_page_pool_in_use) == 0);
    puts("EVID F06 full_return in_use=0");

    puts("F06 page-pool unit: PASS");
    return 0;
}

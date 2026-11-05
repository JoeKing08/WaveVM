#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Stubs for extracted wavevm_user_mem_set_tcg_shm_coherent */
static int g_tcg_shm_coherent = 0;
static bool g_fault_hook_enabled = true;
static int g_is_slave = 1;
static int dirty_log_starts = 0;
static int kvm_enabled(void) { return 0; }
static void memory_global_dirty_log_start(void) { dirty_log_starts++; }

#include "f05_coherent.inc"

static void clear_hosts(void)
{
    unsetenv("WVM_FE_PHYSICAL_HOST_ID");
    unsetenv("WVM_EXECUTOR_PHYSICAL_HOST_ID");
}

int main(void)
{
    /* Same host: coherent allowed */
    clear_hosts();
    setenv("WVM_FE_PHYSICAL_HOST_ID", "7", 1);
    setenv("WVM_EXECUTOR_PHYSICAL_HOST_ID", "7", 1);
    g_tcg_shm_coherent = 0;
    g_fault_hook_enabled = true;
    dirty_log_starts = 0;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 1);
    assert(g_fault_hook_enabled == false);
    assert(dirty_log_starts == 1);
    assert(wavevm_user_mem_tcg_shm_coherent() == 1);
    puts("EVID F05 same_host_coherent_allowed fe=7 ex=7");

    /* Cross-host mismatch: refuse coherent, keep fault path */
    clear_hosts();
    setenv("WVM_FE_PHYSICAL_HOST_ID", "1", 1);
    setenv("WVM_EXECUTOR_PHYSICAL_HOST_ID", "2", 1);
    g_tcg_shm_coherent = 1;
    g_fault_hook_enabled = true;
    dirty_log_starts = 0;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 0);
    assert(g_fault_hook_enabled == true); /* refuse path must not disable hook */
    assert(dirty_log_starts == 0);
    assert(wavevm_user_mem_tcg_shm_coherent() == 0);
    puts("EVID F05 cross_host_coherent_refused fe=1 ex=2 fault_hook_kept=1");

    /* Missing host ids: prior same-host join behavior (allow) */
    clear_hosts();
    g_tcg_shm_coherent = 0;
    g_fault_hook_enabled = true;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 1);
    puts("EVID F05 missing_host_ids_keep_prior_join_behavior coherent=1");

    /* Explicit disable still works */
    clear_hosts();
    wavevm_user_mem_set_tcg_shm_coherent(0);
    assert(g_tcg_shm_coherent == 0);
    puts("EVID F05 explicit_disable coherent=0");

    /* Placement export contract (source-level strings exist in agents) —
     * runtime env parseability for cross-host refuse already proven above. */
    puts("F05 coherent-host-scope unit: PASS");
    return 0;
}

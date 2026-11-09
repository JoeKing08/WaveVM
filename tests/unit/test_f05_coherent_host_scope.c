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
    unsetenv("WVM_SHM_FILE");
    unsetenv("WVM_FE_SHM_FILE");
}

static void set_same_host_backing(void)
{
    setenv("WVM_FE_PHYSICAL_HOST_ID", "7", 1);
    setenv("WVM_EXECUTOR_PHYSICAL_HOST_ID", "7", 1);
    setenv("WVM_SHM_FILE", "/wavevm_ram_n02", 1);
    setenv("WVM_FE_SHM_FILE", "/wavevm_ram_n02", 1);
}

int main(void)
{
    /* Same host + matching backing: coherent allowed */
    clear_hosts();
    set_same_host_backing();
    g_tcg_shm_coherent = 0;
    g_fault_hook_enabled = true;
    dirty_log_starts = 0;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 1);
    assert(g_fault_hook_enabled == false);
    assert(dirty_log_starts == 1);
    assert(wavevm_user_mem_tcg_shm_coherent() == 1);
    puts("EVID N02 same_host_same_backing_coherent_allowed fe=7 ex=7");

    /* Cross-host mismatch: refuse coherent, keep fault path */
    clear_hosts();
    setenv("WVM_FE_PHYSICAL_HOST_ID", "1", 1);
    setenv("WVM_EXECUTOR_PHYSICAL_HOST_ID", "2", 1);
    setenv("WVM_SHM_FILE", "/wavevm_ram_n02", 1);
    setenv("WVM_FE_SHM_FILE", "/wavevm_ram_n02", 1);
    g_tcg_shm_coherent = 1;
    g_fault_hook_enabled = true;
    dirty_log_starts = 0;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 0);
    assert(g_fault_hook_enabled == true);
    assert(dirty_log_starts == 0);
    assert(wavevm_user_mem_tcg_shm_coherent() == 0);
    puts("EVID N02 cross_host_coherent_refused fe=1 ex=2 fault_hook_kept=1");

    /* N02: missing host ids must REFUSE (was prior allow) */
    clear_hosts();
    setenv("WVM_SHM_FILE", "/wavevm_ram_n02", 1);
    setenv("WVM_FE_SHM_FILE", "/wavevm_ram_n02", 1);
    g_tcg_shm_coherent = 0;
    g_fault_hook_enabled = true;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 0);
    assert(g_fault_hook_enabled == true);
    puts("EVID N02 missing_host_ids_refuse coherent=0");

    /* N02: invalid host id (zero) refuse */
    clear_hosts();
    setenv("WVM_FE_PHYSICAL_HOST_ID", "0", 1);
    setenv("WVM_EXECUTOR_PHYSICAL_HOST_ID", "0", 1);
    setenv("WVM_SHM_FILE", "/wavevm_ram_n02", 1);
    setenv("WVM_FE_SHM_FILE", "/wavevm_ram_n02", 1);
    g_tcg_shm_coherent = 0;
    g_fault_hook_enabled = true;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 0);
    puts("EVID N02 zero_host_ids_refuse coherent=0");

    /* N02: same host, different backing refuse */
    clear_hosts();
    setenv("WVM_FE_PHYSICAL_HOST_ID", "7", 1);
    setenv("WVM_EXECUTOR_PHYSICAL_HOST_ID", "7", 1);
    setenv("WVM_SHM_FILE", "/wavevm_ram_exec", 1);
    setenv("WVM_FE_SHM_FILE", "/wavevm_ram_fe", 1);
    g_tcg_shm_coherent = 0;
    g_fault_hook_enabled = true;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 0);
    puts("EVID N02 same_host_different_backing_refuse coherent=0");

    /* N02: missing FE shm identity refuse */
    clear_hosts();
    setenv("WVM_FE_PHYSICAL_HOST_ID", "7", 1);
    setenv("WVM_EXECUTOR_PHYSICAL_HOST_ID", "7", 1);
    setenv("WVM_SHM_FILE", "/wavevm_ram_n02", 1);
    g_tcg_shm_coherent = 0;
    g_fault_hook_enabled = true;
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 0);
    puts("EVID N02 missing_fe_shm_refuse coherent=0");

    /* Explicit disable still works */
    clear_hosts();
    set_same_host_backing();
    wavevm_user_mem_set_tcg_shm_coherent(1);
    assert(g_tcg_shm_coherent == 1);
    wavevm_user_mem_set_tcg_shm_coherent(0);
    assert(g_tcg_shm_coherent == 0);
    puts("EVID N02 explicit_disable coherent=0");

    puts("F05/N02 coherent-host-scope unit: PASS");
    return 0;
}

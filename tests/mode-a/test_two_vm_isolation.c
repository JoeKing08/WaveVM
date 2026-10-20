/*
 * Mode A Two-VM Isolation Test
 *
 * Verifies that two VMs using Mode A (kernel accelerator) maintain complete
 * isolation using the existing IOCTL_WVM_BIND_CONTEXT interface.
 *
 * Test procedure:
 * 1. Open two file descriptors to /dev/wavevm
 * 2. Bind each fd to a distinct VM identity via IOCTL_WVM_BIND_CONTEXT
 * 3. Set up memory layouts for each VM with distinct GPA ranges
 * 4. mmap and fault pages for each VM
 * 5. Verify that faults are routed to the correct context
 * 6. Verify that memory mappings remain isolated
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>

#include "../../common_include/wavevm_ioctl.h"

#define TEST_VM1_IDENTITY 1001
#define TEST_VM2_IDENTITY 1002
#define TEST_NODE_ID 1
#define TEST_GPA_BASE_1 0x100000000ULL
#define TEST_GPA_BASE_2 0x200000000ULL
#define TEST_MEMORY_SIZE (16 * 4096)  /* 16 pages = 64KB */

static int g_dev_fd1 = -1;
static int g_dev_fd2 = -1;
static void *g_vm1_mapping = NULL;
static void *g_vm2_mapping = NULL;

static void cleanup_test(void)
{
    if (g_vm1_mapping && g_vm1_mapping != MAP_FAILED) {
        munmap(g_vm1_mapping, TEST_MEMORY_SIZE);
    }
    if (g_vm2_mapping && g_vm2_mapping != MAP_FAILED) {
        munmap(g_vm2_mapping, TEST_MEMORY_SIZE);
    }
    if (g_dev_fd1 >= 0) {
        struct wvm_ioctl_context_bind unbind = {0};
        unbind.magic = WVM_KERNEL_CONTEXT_MAGIC;
        unbind.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
        unbind.vm_id = TEST_VM1_IDENTITY;
        ioctl(g_dev_fd1, IOCTL_WVM_UNBIND_CONTEXT, &unbind);
        close(g_dev_fd1);
    }
    if (g_dev_fd2 >= 0) {
        struct wvm_ioctl_context_bind unbind = {0};
        unbind.magic = WVM_KERNEL_CONTEXT_MAGIC;
        unbind.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
        unbind.vm_id = TEST_VM2_IDENTITY;
        ioctl(g_dev_fd2, IOCTL_WVM_UNBIND_CONTEXT, &unbind);
        close(g_dev_fd2);
    }
}

static int bind_vm_context(int fd, uint32_t vm_id, const char *vm_name)
{
    struct wvm_ioctl_context_bind bind = {0};

    bind.magic = WVM_KERNEL_CONTEXT_MAGIC;
    bind.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    bind.flags = 0;
    bind.vm_id = vm_id;
    bind.physical_node_id = TEST_NODE_ID;
    bind.node_instance_id = 1; /* F11 ABI v3 */
    bind.vm_incarnation = 1;
    bind.manifest_generation = 1;

    /* Generate fake but distinct digests for each VM */
    memset(bind.candidate_manifest_digest, vm_id & 0xFF, WVM_KERNEL_DIGEST_BYTES);
    memset(bind.capability_profile_digest, (vm_id >> 8) & 0xFF, WVM_KERNEL_DIGEST_BYTES);
    memset(bind.activation_fence, vm_id & 0xFF, WVM_KERNEL_FENCE_BYTES);

    bind.route_snapshot_key.scope_key.vm_id = vm_id;
    bind.route_snapshot_key.scope_key.vm_incarnation = 1;
    bind.route_snapshot_key.scope_key.route_scope_id = 1;
    bind.route_snapshot_key.topology_revision = 1;
    bind.route_snapshot_key.route_generation = 1;
    memset(bind.route_snapshot_key.snapshot_digest, vm_id & 0xFF, WVM_KERNEL_DIGEST_BYTES);

    if (ioctl(fd, IOCTL_WVM_BIND_CONTEXT, &bind) < 0) {
        fprintf(stderr, "Failed to bind context for VM %u (%s): %s\n",
                vm_id, vm_name, strerror(errno));
        return -1;
    }

    printf("[OK] Bound fd %d to VM %u (%s)\n", fd, vm_id, vm_name);
    return 0;
}

static int set_memory_layout(int fd, uint64_t gpa_base, uint64_t size, const char *vm_name)
{
    struct wvm_ioctl_mem_layout layout = {0};

    layout.count = 1;
    layout.slots[0].start = gpa_base;
    layout.slots[0].size = size;

    if (ioctl(fd, IOCTL_SET_MEM_LAYOUT, &layout) < 0) {
        fprintf(stderr, "Failed to set memory layout for %s: %s\n",
                vm_name, strerror(errno));
        return -1;
    }

    printf("[OK] Set memory layout for %s: GPA 0x%lx, size 0x%lx\n",
           vm_name, gpa_base, size);
    return 0;
}

static int test_context_isolation(void)
{
    printf("\n=== Test 1: Context Binding Isolation ===\n");

    /* Query capabilities */
    struct wvm_ioctl_context_caps caps = {0};
    if (ioctl(g_dev_fd1, IOCTL_WVM_QUERY_CAPS, &caps) < 0) {
        fprintf(stderr, "Failed to query capabilities: %s\n", strerror(errno));
        return -1;
    }

    printf("[INFO] Kernel capabilities:\n");
    printf("  Magic: 0x%x (expected 0x%x)\n", caps.magic, WVM_KERNEL_CONTEXT_MAGIC);
    printf("  Version: %u (expected %u)\n", caps.version, WVM_KERNEL_CONTEXT_ABI_VERSION);
    printf("  Max concurrent contexts: %u\n", caps.max_concurrent_contexts);
    printf("  Active contexts: %u\n", caps.active_contexts);
    printf("  Feature bits: 0x%lx\n", caps.feature_bits);

    if (caps.magic != WVM_KERNEL_CONTEXT_MAGIC) {
        fprintf(stderr, "[FAIL] Invalid kernel magic\n");
        return -1;
    }

    if (!(caps.feature_bits & WVM_KERNEL_CAP_CONTEXT_BIND)) {
        fprintf(stderr, "[FAIL] Kernel does not support context binding\n");
        return -1;
    }

    printf("[OK] Kernel supports context binding\n");

    /* Verify that we have two bound contexts */
    if (ioctl(g_dev_fd2, IOCTL_WVM_QUERY_CAPS, &caps) < 0) {
        fprintf(stderr, "Failed to query capabilities from fd2: %s\n", strerror(errno));
        return -1;
    }

    /*
     * Gate restored: QUERY_CAPS must advertise SINGLE_CONTEXT with max=1
     * until A01-A04 isolation evidence reopens multi-context Mode A.
     */
    if (!(caps.feature_bits & WVM_KERNEL_CAP_SINGLE_CONTEXT) ||
        caps.max_concurrent_contexts != 1U) {
        fprintf(stderr,
                "[FAIL] single-context gate not advertised (feature_bits=%llx max=%u)\n",
                (unsigned long long)caps.feature_bits,
                caps.max_concurrent_contexts);
        return 1;
    }
    printf("[OK] single-context gate advertised (active=%u max=%u)\n",
           caps.active_contexts, caps.max_concurrent_contexts);

    return 0;
}

static int test_memory_isolation(void)
{
    printf("\n=== Test 2: Memory Mapping Isolation ===\n");

    /* Map memory for VM1 */
    g_vm1_mapping = mmap(NULL, TEST_MEMORY_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED, g_dev_fd1, TEST_GPA_BASE_1);
    if (g_vm1_mapping == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap VM1 memory: %s\n", strerror(errno));
        return -1;
    }
    printf("[OK] Mapped VM1 memory at %p (GPA 0x%llx)\n",
           g_vm1_mapping, (unsigned long long)TEST_GPA_BASE_1);

    /* Map memory for VM2 */
    g_vm2_mapping = mmap(NULL, TEST_MEMORY_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED, g_dev_fd2, TEST_GPA_BASE_2);
    if (g_vm2_mapping == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap VM2 memory: %s\n", strerror(errno));
        return -1;
    }
    printf("[OK] Mapped VM2 memory at %p (GPA 0x%llx)\n",
           g_vm2_mapping, (unsigned long long)TEST_GPA_BASE_2);

    /* Verify mappings are distinct in virtual address space */
    if (g_vm1_mapping == g_vm2_mapping) {
        fprintf(stderr, "[FAIL] VM1 and VM2 mappings overlap in VA space!\n");
        return -1;
    }
    printf("[OK] VM1 and VM2 have distinct virtual address mappings\n");

    return 0;
}

static int test_fault_isolation(void)
{
    printf("\n=== Test 3: Page Fault Isolation ===\n");

    /* Write distinct patterns to each VM's memory */
    volatile uint32_t *vm1_mem = (volatile uint32_t *)g_vm1_mapping;
    volatile uint32_t *vm2_mem = (volatile uint32_t *)g_vm2_mapping;

    printf("[INFO] Writing test pattern to VM1 memory...\n");
    for (int i = 0; i < TEST_MEMORY_SIZE / sizeof(uint32_t); i++) {
        vm1_mem[i] = 0xDEAD0000 | i;
    }
    printf("[OK] VM1 memory written (pattern: 0xDEAD****)\n");

    printf("[INFO] Writing test pattern to VM2 memory...\n");
    for (int i = 0; i < TEST_MEMORY_SIZE / sizeof(uint32_t); i++) {
        vm2_mem[i] = 0xBEEF0000 | i;
    }
    printf("[OK] VM2 memory written (pattern: 0xBEEF****)\n");

    /* Verify patterns remain isolated */
    printf("[INFO] Verifying VM1 pattern integrity...\n");
    for (int i = 0; i < TEST_MEMORY_SIZE / sizeof(uint32_t); i++) {
        uint32_t expected = 0xDEAD0000 | i;
        if (vm1_mem[i] != expected) {
            fprintf(stderr, "[FAIL] VM1 memory corrupted at offset %d: "
                    "got 0x%x, expected 0x%x\n",
                    i, vm1_mem[i], expected);
            return -1;
        }
    }
    printf("[OK] VM1 pattern intact (no corruption from VM2)\n");

    printf("[INFO] Verifying VM2 pattern integrity...\n");
    for (int i = 0; i < TEST_MEMORY_SIZE / sizeof(uint32_t); i++) {
        uint32_t expected = 0xBEEF0000 | i;
        if (vm2_mem[i] != expected) {
            fprintf(stderr, "[FAIL] VM2 memory corrupted at offset %d: "
                    "got 0x%x, expected 0x%x\n",
                    i, vm2_mem[i], expected);
            return -1;
        }
    }
    printf("[OK] VM2 pattern intact (no corruption from VM1)\n");

    return 0;
}


static int test_teardown_isolation(void)
{
    struct wvm_ioctl_context_caps caps = {0};
    struct wvm_ioctl_context_bind unbind = {0};

    printf("\n=== Test 4: Teardown Isolation ===\n");

    unbind.magic = WVM_KERNEL_CONTEXT_MAGIC;
    unbind.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    unbind.vm_id = TEST_VM1_IDENTITY;
    unbind.physical_node_id = TEST_NODE_ID;
    unbind.node_instance_id = 1; /* F11 ABI v3 */
    unbind.vm_incarnation = 1;
    unbind.manifest_generation = 1;
    memset(unbind.candidate_manifest_digest, TEST_VM1_IDENTITY & 0xFF,
           WVM_KERNEL_DIGEST_BYTES);
    memset(unbind.capability_profile_digest, (TEST_VM1_IDENTITY >> 8) & 0xFF,
           WVM_KERNEL_DIGEST_BYTES);
    memset(unbind.activation_fence, TEST_VM1_IDENTITY & 0xFF,
           WVM_KERNEL_FENCE_BYTES);
    unbind.route_snapshot_key.scope_key.vm_id = TEST_VM1_IDENTITY;
    unbind.route_snapshot_key.scope_key.vm_incarnation = 1;
    unbind.route_snapshot_key.scope_key.route_scope_id = 1;
    unbind.route_snapshot_key.topology_revision = 1;
    unbind.route_snapshot_key.route_generation = 1;
    memset(unbind.route_snapshot_key.snapshot_digest, TEST_VM1_IDENTITY & 0xFF,
           WVM_KERNEL_DIGEST_BYTES);

    if (ioctl(g_dev_fd1, IOCTL_WVM_UNBIND_CONTEXT, &unbind) < 0) {
        fprintf(stderr, "[FAIL] Unbind VM1: %s\n", strerror(errno));
        return -1;
    }
    close(g_dev_fd1);
    g_dev_fd1 = -1;
    printf("[OK] Unbound and closed VM1 fd\n");

    if (ioctl(g_dev_fd2, IOCTL_WVM_QUERY_CAPS, &caps) < 0) {
        fprintf(stderr, "[FAIL] QUERY_CAPS after VM1 teardown: %s\n",
                strerror(errno));
        return -1;
    }
    if (caps.active_contexts < 1) {
        fprintf(stderr,
                "[FAIL] VM2 context destroyed by VM1 teardown (active=%u)\n",
                caps.active_contexts);
        return -1;
    }
    printf("[OK] VM2 context still active after VM1 teardown (active=%u)\n",
           caps.active_contexts);

    {
        volatile uint32_t *vm2_mem = (volatile uint32_t *)g_vm2_mapping;
        if (vm2_mem[0] != (0xBEEF0000u | 0u)) {
            fprintf(stderr, "[FAIL] VM2 page corrupted after VM1 teardown\n");
            return -1;
        }
    }
    printf("[OK] VM2 memory intact after sibling teardown\n");
    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;

    printf("WaveVM Mode A Two-VM Isolation Test\n");
    printf("====================================\n");
    printf("Using existing BIND_CONTEXT interface\n\n");

    /* Open two file descriptors to /dev/wavevm */
    g_dev_fd1 = open("/dev/wavevm", O_RDWR);
    if (g_dev_fd1 < 0) {
        fprintf(stderr, "Failed to open /dev/wavevm for VM1: %s\n", strerror(errno));
        fprintf(stderr, "Ensure kernel module is loaded: sudo insmod master_core/wavevm.ko\n");
        return 1;
    }
    printf("[OK] Opened /dev/wavevm for VM1 (fd=%d)\n", g_dev_fd1);

    g_dev_fd2 = open("/dev/wavevm", O_RDWR);
    if (g_dev_fd2 < 0) {
        fprintf(stderr, "Failed to open /dev/wavevm for VM2: %s\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }
    printf("[OK] Opened /dev/wavevm for VM2 (fd=%d)\n", g_dev_fd2);

    /* Gate closed: first bind OK; second Mode A bind must be rejected. */
    if (bind_vm_context(g_dev_fd1, TEST_VM1_IDENTITY, "VM1") < 0) {
        ret = 1;
        goto cleanup;
    }
    if (bind_vm_context(g_dev_fd2, TEST_VM2_IDENTITY, "VM2") == 0) {
        fprintf(stderr,
                "[FAIL] second Mode A bind succeeded while gate is closed\n");
        ret = 1;
        goto cleanup;
    }
    printf("[OK] second Mode A bind rejected (gate closed)\n");

    if (test_context_isolation() < 0) {
        ret = 1;
        goto cleanup;
    }

    printf("\n====================================\n");
    printf("Mode A second-VM gate CLOSED (caps+BIND): PASS\n");
    printf("Dual isolation body deferred until A01-A04 close.\n");
    printf("====================================\n");

cleanup:
    cleanup_test();
    return ret;
}

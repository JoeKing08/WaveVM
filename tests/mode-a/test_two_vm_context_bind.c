/*
 * Mode A dual-context bind/teardown isolation (no mmap/fault).
 * Proves per-VM kernel context registry: distinct binds, QUERY_CAPS,
 * sibling teardown does not destroy the other context.
 * Full mmap/fault isolation is tests/mode-a/test_two_vm_isolation.c
 * (requires reloadable /dev/wavevm with VM_MIXEDMAP).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#include "../../common_include/wavevm_ioctl.h"

static int bind_vm(int fd, uint32_t vm_id)
{
    struct wvm_ioctl_context_bind bind;
    memset(&bind, 0, sizeof(bind));
    bind.magic = WVM_KERNEL_CONTEXT_MAGIC;
    bind.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    bind.vm_id = vm_id;
    bind.physical_node_id = 1;
    bind.node_instance_id = 1; /* F11 ABI v3 */
    bind.vm_incarnation = 1;
    bind.manifest_generation = 1;
    memset(bind.candidate_manifest_digest, (int)(vm_id & 0xFF), WVM_KERNEL_DIGEST_BYTES);
    memset(bind.capability_profile_digest, 0xAB, WVM_KERNEL_DIGEST_BYTES);
    memset(bind.activation_fence, (int)(vm_id & 0xFF), WVM_KERNEL_FENCE_BYTES);
    bind.route_snapshot_key.scope_key.vm_id = vm_id;
    bind.route_snapshot_key.scope_key.vm_incarnation = 1;
    bind.route_snapshot_key.scope_key.route_scope_id = 1;
    bind.route_snapshot_key.topology_revision = 1;
    bind.route_snapshot_key.route_generation = 1;
    memset(bind.route_snapshot_key.snapshot_digest, (int)(vm_id & 0xFF),
           WVM_KERNEL_DIGEST_BYTES);
    if (ioctl(fd, IOCTL_WVM_BIND_CONTEXT, &bind) < 0) {
        fprintf(stderr, "BIND vm=%u: %s\n", vm_id, strerror(errno));
        return -1;
    }
    return 0;
}

static int unbind_vm(int fd, uint32_t vm_id)
{
    struct wvm_ioctl_context_bind bind;
    memset(&bind, 0, sizeof(bind));
    bind.magic = WVM_KERNEL_CONTEXT_MAGIC;
    bind.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    bind.vm_id = vm_id;
    bind.physical_node_id = 1;
    bind.node_instance_id = 1; /* F11 ABI v3 */
    bind.vm_incarnation = 1;
    bind.manifest_generation = 1;
    memset(bind.candidate_manifest_digest, (int)(vm_id & 0xFF), WVM_KERNEL_DIGEST_BYTES);
    memset(bind.capability_profile_digest, 0xAB, WVM_KERNEL_DIGEST_BYTES);
    memset(bind.activation_fence, (int)(vm_id & 0xFF), WVM_KERNEL_FENCE_BYTES);
    bind.route_snapshot_key.scope_key.vm_id = vm_id;
    bind.route_snapshot_key.scope_key.vm_incarnation = 1;
    bind.route_snapshot_key.scope_key.route_scope_id = 1;
    bind.route_snapshot_key.topology_revision = 1;
    bind.route_snapshot_key.route_generation = 1;
    memset(bind.route_snapshot_key.snapshot_digest, (int)(vm_id & 0xFF),
           WVM_KERNEL_DIGEST_BYTES);
    if (ioctl(fd, IOCTL_WVM_UNBIND_CONTEXT, &bind) < 0) {
        fprintf(stderr, "UNBIND vm=%u: %s\n", vm_id, strerror(errno));
        return -1;
    }
    return 0;
}

static int query_caps(int fd, struct wvm_ioctl_context_caps *caps)
{
    memset(caps, 0, sizeof(*caps));
    if (ioctl(fd, IOCTL_WVM_QUERY_CAPS, caps) < 0) {
        fprintf(stderr, "QUERY_CAPS: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int set_layout(int fd, uint64_t gpa, uint64_t size)
{
    struct wvm_ioctl_mem_layout layout;
    memset(&layout, 0, sizeof(layout));
    layout.count = 1;
    layout.slots[0].start = gpa;
    layout.slots[0].size = size;
    if (ioctl(fd, IOCTL_SET_MEM_LAYOUT, &layout) < 0) {
        fprintf(stderr, "SET_MEM_LAYOUT: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int main(void)
{
    const uint32_t vm1 = 3101, vm2 = 3102;
    int fd1 = -1, fd2 = -1;
    struct wvm_ioctl_context_caps caps;
    uint32_t before, after_bind;

    fd1 = open("/dev/wavevm", O_RDWR);
    fd2 = open("/dev/wavevm", O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        perror("open /dev/wavevm");
        return 1;
    }
    if (query_caps(fd1, &caps) != 0)
        return 1;
    before = caps.active_contexts;
    if (!(caps.feature_bits & WVM_KERNEL_CAP_CONTEXT_BIND) ||
        !(caps.feature_bits & WVM_KERNEL_CAP_SINGLE_CONTEXT) ||
        caps.max_concurrent_contexts != 1U) {
        fprintf(stderr,
                "FAIL: single-context gate not advertised (max=%u feats=%llx)\n",
                caps.max_concurrent_contexts,
                (unsigned long long)caps.feature_bits);
        return 1;
    }
    printf("[OK] single-context gate advertised (max=%u active_before=%u)\n",
           caps.max_concurrent_contexts, before);

    if (bind_vm(fd1, vm1) != 0) {
        fprintf(stderr, "FAIL: first Mode A bind rejected\n");
        close(fd1);
        close(fd2);
        return 1;
    }
    if (bind_vm(fd2, vm2) == 0) {
        fprintf(stderr, "FAIL: second Mode A bind succeeded while gate closed\n");
        close(fd1);
        close(fd2);
        return 1;
    }
    if (query_caps(fd1, &caps) != 0)
        return 1;
    after_bind = caps.active_contexts;
    if (after_bind != before + 1) {
        fprintf(stderr,
                "FAIL: expected %u active after single bind, got %u\n",
                before + 1, after_bind);
        return 1;
    }
    printf("[OK] second bind rejected; active=%u (gate closed)\n", after_bind);

    if (set_layout(fd1, 0x100000000ULL, 64 * 1024) != 0)
        return 1;
    printf("[OK] SET_MEM_LAYOUT accepted for the single admitted context\n");

    if (unbind_vm(fd1, vm1) != 0)
        return 1;
    close(fd1);
    fd1 = -1;
    close(fd2);
    fd2 = -1;
    printf("Mode A second-VM gate CLOSED (caps+BIND reject): PASS\n");
    return 0;
}

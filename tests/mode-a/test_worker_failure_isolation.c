/*
 * SPEC-kernel-accel-acceptance-two-vm — concurrent detach/destroy isolation
 * (acceptance §10 worker-failure class). Cannot SIGKILL module TX kthreads
 * from userspace; stresses async faults vs peer destroy + mutual destroy.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <stdatomic.h>

#include "../../common_include/wavevm_ioctl.h"

#define SAME_GPA        0x100000000ULL
#define MEM_SIZE        (16 * 4096)
#define VM_KEEP         2101U
#define VM_PEER         2102U

static sigjmp_buf g_jmp;
static void on_sigbus(int sig)
{
    (void)sig;
    siglongjmp(g_jmp, 1);
}

static void fill_bind(struct wvm_ioctl_context_bind *b, uint32_t vm,
                      uint64_t inst, uint8_t tag)
{
    memset(b, 0, sizeof(*b));
    b->magic = WVM_KERNEL_CONTEXT_MAGIC;
    b->version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    b->vm_id = vm;
    b->physical_node_id = 1;
    b->node_instance_id = inst;
    b->vm_incarnation = 1;
    b->manifest_generation = 1;
    memset(b->candidate_manifest_digest, tag, WVM_KERNEL_DIGEST_BYTES);
    memset(b->capability_profile_digest, 0xAB, WVM_KERNEL_DIGEST_BYTES);
    memset(b->activation_fence, tag, WVM_KERNEL_FENCE_BYTES);
    b->route_snapshot_key.scope_key.vm_id = vm;
    b->route_snapshot_key.scope_key.vm_incarnation = 1;
    b->route_snapshot_key.scope_key.route_scope_id = 1;
    b->route_snapshot_key.topology_revision = 1;
    b->route_snapshot_key.route_generation = 1;
    memset(b->route_snapshot_key.snapshot_digest, tag, WVM_KERNEL_DIGEST_BYTES);
}

static int open_bind(uint32_t vm, uint64_t inst, uint8_t tag)
{
    int fd = open("/dev/wavevm", O_RDWR);
    struct wvm_ioctl_context_bind b;
    if (fd < 0) {
        perror("open /dev/wavevm");
        return -1;
    }
    fill_bind(&b, vm, inst, tag);
    if (ioctl(fd, IOCTL_WVM_BIND_CONTEXT, &b) < 0) {
        fprintf(stderr, "BIND vm=%u: %s\n", vm, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
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

static void *map_gpa(int fd, uint64_t gpa, size_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                   (off_t)gpa);
    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return NULL;
    }
    return p;
}

static void unbind_close(int fd, uint32_t vm, uint64_t inst, uint8_t tag)
{
    struct wvm_ioctl_context_bind b;
    if (fd < 0)
        return;
    fill_bind(&b, vm, inst, tag);
    ioctl(fd, IOCTL_WVM_UNBIND_CONTEXT, &b);
    close(fd);
}

struct stress_arg {
    volatile uint32_t *pages;
    size_t nwords;
    atomic_int *stop;
    atomic_int *faults;
    atomic_int *errors;
};

static void *stress_fault_thread(void *arg)
{
    struct stress_arg *s = arg;
    size_t i;
    while (!atomic_load(s->stop)) {
        if (sigsetjmp(g_jmp, 1) != 0) {
            atomic_fetch_add(s->errors, 1);
            break;
        }
        for (i = 0; i < s->nwords; i++) {
            s->pages[i] = (uint32_t)i ^ 0xA5A5A5A5u;
            (void)s->pages[i];
        }
        atomic_fetch_add(s->faults, 1);
    }
    return NULL;
}

static int test_concurrent_detach_destroy(void)
{
    int fd_keep = -1, fd_peer = -1;
    void *map_keep = NULL, *map_peer = NULL;
    atomic_int stop, faults, errors;
    struct stress_arg sarg;
    pthread_t thr;
    int i, rc = -1;
    struct wvm_ioctl_context_caps caps;

    printf("\n=== Concurrent peer destroy under keep-VM faults ===\n");
    atomic_init(&stop, 0);
    atomic_init(&faults, 0);
    atomic_init(&errors, 0);

    fd_keep = open_bind(VM_KEEP, 1, 0xA1);
    fd_peer = open_bind(VM_PEER, 1, 0xB2);
    if (fd_keep < 0 || fd_peer < 0)
        goto out;
    if (set_layout(fd_keep, SAME_GPA, MEM_SIZE) < 0 ||
        set_layout(fd_peer, SAME_GPA, MEM_SIZE) < 0)
        goto out;
    map_keep = map_gpa(fd_keep, SAME_GPA, MEM_SIZE);
    map_peer = map_gpa(fd_peer, SAME_GPA, MEM_SIZE);
    if (!map_keep || !map_peer)
        goto out;

    if (sigsetjmp(g_jmp, 1) == 0) {
        memset(map_keep, 0x11, MEM_SIZE);
        memset(map_peer, 0x22, MEM_SIZE);
    } else {
        fprintf(stderr, "[FAIL] SIGBUS priming\n");
        goto out;
    }

    sarg.pages = (volatile uint32_t *)map_keep;
    sarg.nwords = MEM_SIZE / sizeof(uint32_t);
    sarg.stop = &stop;
    sarg.faults = &faults;
    sarg.errors = &errors;
    if (pthread_create(&thr, NULL, stress_fault_thread, &sarg) != 0) {
        perror("pthread_create");
        goto out;
    }

    for (i = 0; i < 12; i++) {
        usleep(1500);
        munmap(map_peer, MEM_SIZE);
        map_peer = NULL;
        unbind_close(fd_peer, VM_PEER, 1, 0xB2);
        fd_peer = -1;
        usleep(1500);
        fd_peer = open_bind(VM_PEER, 1, 0xB2);
        if (fd_peer < 0 || set_layout(fd_peer, SAME_GPA, MEM_SIZE) < 0) {
            fprintf(stderr, "[FAIL] re-BIND peer cycle %d\n", i);
            atomic_store(&stop, 1);
            pthread_join(thr, NULL);
            goto out;
        }
        map_peer = map_gpa(fd_peer, SAME_GPA, MEM_SIZE);
        if (!map_peer) {
            atomic_store(&stop, 1);
            pthread_join(thr, NULL);
            goto out;
        }
        if (sigsetjmp(g_jmp, 1) == 0)
            memset(map_peer, 0x22, 64);
        else {
            fprintf(stderr, "[FAIL] SIGBUS writing re-bound peer\n");
            atomic_store(&stop, 1);
            pthread_join(thr, NULL);
            goto out;
        }
    }

    atomic_store(&stop, 1);
    pthread_join(thr, NULL);

    if (atomic_load(&errors) != 0) {
        fprintf(stderr, "[FAIL] keep-VM errors=%d (possible UAF/SIGBUS)\n",
                atomic_load(&errors));
        goto out;
    }
    if (atomic_load(&faults) < 1) {
        fprintf(stderr, "[FAIL] no fault loops\n");
        goto out;
    }
    if (sigsetjmp(g_jmp, 1) != 0) {
        fprintf(stderr, "[FAIL] SIGBUS reading keep after churn\n");
        goto out;
    }
    (void)((volatile uint32_t *)map_keep)[0];

    memset(&caps, 0, sizeof(caps));
    if (ioctl(fd_keep, IOCTL_WVM_QUERY_CAPS, &caps) < 0) {
        fprintf(stderr, "[FAIL] QUERY_CAPS: %s\n", strerror(errno));
        goto out;
    }
    if (caps.active_contexts < 1) {
        fprintf(stderr, "[FAIL] keep context gone active=%u\n",
                caps.active_contexts);
        goto out;
    }
    if (!(caps.feature_bits & WVM_KERNEL_CAP_CONTEXT_BIND)) {
        fprintf(stderr, "[FAIL] CONTEXT_BIND bit lost\n");
        goto out;
    }

    printf("[OK] peer destroy×12 under faults (loops=%d)\n",
           atomic_load(&faults));
    rc = 0;
out:
    if (map_keep)
        munmap(map_keep, MEM_SIZE);
    if (map_peer)
        munmap(map_peer, MEM_SIZE);
    if (fd_keep >= 0)
        unbind_close(fd_keep, VM_KEEP, 1, 0xA1);
    if (fd_peer >= 0)
        unbind_close(fd_peer, VM_PEER, 1, 0xB2);
    return rc;
}

static int test_mutual_destroy(void)
{
    int a = -1, b = -1;
    void *ma = NULL, *mb = NULL;
    int i;
    struct wvm_ioctl_context_caps caps;

    printf("\n=== Mutual destroy churn ===\n");
    for (i = 0; i < 10; i++) {
        a = open_bind(VM_KEEP, 1, 0xA1);
        b = open_bind(VM_PEER, 1, 0xB2);
        if (a < 0 || b < 0)
            return -1;
        if (set_layout(a, SAME_GPA, MEM_SIZE) < 0 ||
            set_layout(b, SAME_GPA, MEM_SIZE) < 0)
            return -1;
        ma = map_gpa(a, SAME_GPA, MEM_SIZE);
        mb = map_gpa(b, SAME_GPA, MEM_SIZE);
        if (!ma || !mb)
            return -1;
        if (sigsetjmp(g_jmp, 1) == 0) {
            memset(ma, 0xAA, 128);
            memset(mb, 0xBB, 128);
        } else {
            fprintf(stderr, "[FAIL] SIGBUS mutual prime\n");
            return -1;
        }
        munmap(ma, MEM_SIZE);
        munmap(mb, MEM_SIZE);
        unbind_close(a, VM_KEEP, 1, 0xA1);
        unbind_close(b, VM_PEER, 1, 0xB2);
        a = b = -1;
        ma = mb = NULL;
    }
    a = open_bind(VM_KEEP, 1, 0xA1);
    if (a < 0)
        return -1;
    memset(&caps, 0, sizeof(caps));
    if (ioctl(a, IOCTL_WVM_QUERY_CAPS, &caps) < 0 ||
        caps.active_contexts < 1) {
        fprintf(stderr, "[FAIL] post-mutual QUERY_CAPS\n");
        unbind_close(a, VM_KEEP, 1, 0xA1);
        return -1;
    }
    unbind_close(a, VM_KEEP, 1, 0xA1);
    printf("[OK] mutual destroy×10; fresh BIND OK\n");
    return 0;
}

int main(void)
{
    struct sigaction sa;
    int failed = 0;
    struct wvm_ioctl_context_caps caps;
    int fd;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigbus;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    printf("WaveVM Mode A worker-failure-class isolation\n");
    fd = open("/dev/wavevm", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    memset(&caps, 0, sizeof(caps));
    if (ioctl(fd, IOCTL_WVM_QUERY_CAPS, &caps) < 0 ||
        !(caps.feature_bits & WVM_KERNEL_CAP_CONTEXT_BIND)) {
        fprintf(stderr, "need CONTEXT_BIND /dev/wavevm (gate may be SINGLE_CONTEXT)\n");
        close(fd);
        return 1;
    }
    close(fd);

    if (test_concurrent_detach_destroy() != 0)
        failed++;
    if (test_mutual_destroy() != 0)
        failed++;

    if (failed) {
        printf("\nWORKER-FAILURE ISOLATION: FAIL (%d)\n", failed);
        return 1;
    }
    printf("\nWORKER-FAILURE ISOLATION: ALL PASS\n");
    printf("NOTE: module TX kthread kill not injected; concurrent "
           "detach/destroy + survivor integrity covered. Verify dmesg clean.\n");
    return 0;
}

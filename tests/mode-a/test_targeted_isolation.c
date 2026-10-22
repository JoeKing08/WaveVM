/*
 * Targeted Mode A isolation acceptance (roadmap §12 / cross-review C):
 *  1) Same GPA on two VMs — no mapping/state collision
 *  2) Multi-FD same VM — sibling FD survives peer close
 *  3) In-flight async teardown — close/unbind while faults continue
 *
 * Gate lift requires ALL three PASS. Distinct-GPA tests alone are insufficient.
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
#define VM_A            2001U
#define VM_B            2002U
#define VM_MULTI        2003U

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_got_sigbus;

static void on_sigbus(int sig)
{
    (void)sig;
    g_got_sigbus = 1;
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
        fprintf(stderr, "BIND vm=%u inst=%llu: %s\n", vm,
                (unsigned long long)inst, strerror(errno));
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
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)gpa);
    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap GPA 0x%llx: %s\n",
                (unsigned long long)gpa, strerror(errno));
        return NULL;
    }
    return p;
}

static int unbind_close(int fd, uint32_t vm, uint64_t inst, uint8_t tag)
{
    struct wvm_ioctl_context_bind b;
    if (fd < 0)
        return 0;
    fill_bind(&b, vm, inst, tag);
    ioctl(fd, IOCTL_WVM_UNBIND_CONTEXT, &b);
    close(fd);
    return 0;
}

/* ---- 1) Same GPA isolation ---- */
static int test_same_gpa(void)
{
    int fd_a = -1, fd_b = -1;
    void *map_a = NULL, *map_b = NULL;
    uint32_t *pa, *pb;
    size_t i, nwords;
    int rc = -1;

    printf("\n=== Targeted 1: Same GPA two-VM isolation ===\n");
    fd_a = open_bind(VM_A, 1, 0xA1);
    fd_b = open_bind(VM_B, 1, 0xB2);
    if (fd_a < 0 || fd_b < 0)
        goto out;
    if (set_layout(fd_a, SAME_GPA, MEM_SIZE) < 0 ||
        set_layout(fd_b, SAME_GPA, MEM_SIZE) < 0)
        goto out;
    map_a = map_gpa(fd_a, SAME_GPA, MEM_SIZE);
    map_b = map_gpa(fd_b, SAME_GPA, MEM_SIZE);
    if (!map_a || !map_b)
        goto out;

    nwords = MEM_SIZE / sizeof(uint32_t);
    pa = (uint32_t *)map_a;
    pb = (uint32_t *)map_b;

    g_got_sigbus = 0;
    if (sigsetjmp(g_jmp, 1) == 0) {
        for (i = 0; i < nwords; i++)
            pa[i] = 0xA1000000u ^ (uint32_t)i;
    } else {
        fprintf(stderr, "[FAIL] SIGBUS writing VM_A same-GPA mapping\n");
        goto out;
    }
    if (sigsetjmp(g_jmp, 1) == 0) {
        for (i = 0; i < nwords; i++)
            pb[i] = 0xB2000000u ^ (uint32_t)i;
    } else {
        fprintf(stderr, "[FAIL] SIGBUS writing VM_B same-GPA mapping\n");
        goto out;
    }

    for (i = 0; i < nwords; i++) {
        if (pa[i] != (0xA1000000u ^ (uint32_t)i)) {
            fprintf(stderr,
                    "[FAIL] VM_A corrupted at %zu: got 0x%x (VM_B bleed?)\n",
                    i, pa[i]);
            goto out;
        }
        if (pb[i] != (0xB2000000u ^ (uint32_t)i)) {
            fprintf(stderr,
                    "[FAIL] VM_B corrupted at %zu: got 0x%x (VM_A bleed?)\n",
                    i, pb[i]);
            goto out;
        }
    }
    printf("[OK] Same GPA 0x%llx: VM_A and VM_B patterns isolated\n",
           (unsigned long long)SAME_GPA);

    /* Teardown A; B must remain intact */
    munmap(map_a, MEM_SIZE);
    map_a = NULL;
    unbind_close(fd_a, VM_A, 1, 0xA1);
    fd_a = -1;

    for (i = 0; i < nwords; i++) {
        if (pb[i] != (0xB2000000u ^ (uint32_t)i)) {
            fprintf(stderr,
                    "[FAIL] VM_B corrupted after VM_A teardown at %zu: 0x%x\n",
                    i, pb[i]);
            goto out;
        }
    }
    printf("[OK] VM_B intact after sibling same-GPA teardown\n");
    rc = 0;
out:
    if (map_a)
        munmap(map_a, MEM_SIZE);
    if (map_b)
        munmap(map_b, MEM_SIZE);
    if (fd_a >= 0)
        unbind_close(fd_a, VM_A, 1, 0xA1);
    if (fd_b >= 0)
        unbind_close(fd_b, VM_B, 1, 0xB2);
    return rc;
}

/* ---- 2) Multi-FD same VM ---- */
static int test_multi_fd_same_vm(void)
{
    int fd1 = -1, fd2 = -1;
    void *m1 = NULL, *m2 = NULL;
    uint32_t *p1, *p2;
    size_t i, nwords;
    struct wvm_ioctl_context_caps caps;
    int rc = -1;

    printf("\n=== Targeted 2: Multi-FD same VM ===\n");
    fd1 = open_bind(VM_MULTI, 1, 0xC3);
    if (fd1 < 0)
        goto out;
    /* Second FD attaches to same (vm, node_instance) identity */
    fd2 = open("/dev/wavevm", O_RDWR);
    if (fd2 < 0) {
        perror("open fd2");
        goto out;
    }
    {
        struct wvm_ioctl_context_bind b;
        fill_bind(&b, VM_MULTI, 1, 0xC3);
        if (ioctl(fd2, IOCTL_WVM_BIND_CONTEXT, &b) < 0) {
            fprintf(stderr, "BIND second FD same identity: %s\n",
                    strerror(errno));
            goto out;
        }
    }
    if (set_layout(fd1, SAME_GPA, MEM_SIZE) < 0)
        goto out;
    /* layout is per-context; fd2 shares context — mmap both */
    m1 = map_gpa(fd1, SAME_GPA, MEM_SIZE);
    m2 = map_gpa(fd2, SAME_GPA, MEM_SIZE);
    if (!m1 || !m2)
        goto out;

    nwords = MEM_SIZE / sizeof(uint32_t);
    p1 = (uint32_t *)m1;
    p2 = (uint32_t *)m2;
    if (sigsetjmp(g_jmp, 1) == 0) {
        for (i = 0; i < nwords; i++)
            p1[i] = 0xC3000000u ^ (uint32_t)i;
    } else {
        fprintf(stderr, "[FAIL] SIGBUS on multi-FD write via fd1\n");
        goto out;
    }
    /* Both FDs map same context pages for same GPA — p2 should see p1 data
     * OR have independent PTEs that still don't crash sibling. Accept either
     * coherent shared view or isolated PTE view, but sibling must survive. */
    for (i = 0; i < nwords; i++) {
        if (p1[i] != (0xC3000000u ^ (uint32_t)i)) {
            fprintf(stderr, "[FAIL] fd1 pattern lost at %zu\n", i);
            goto out;
        }
    }

    /* Close fd1 (detach one mapping owner); fd2 must remain usable */
    munmap(m1, MEM_SIZE);
    m1 = NULL;
    unbind_close(fd1, VM_MULTI, 1, 0xC3);
    fd1 = -1;

    memset(&caps, 0, sizeof(caps));
    caps.magic = WVM_KERNEL_CONTEXT_MAGIC;
    caps.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    if (ioctl(fd2, IOCTL_WVM_QUERY_CAPS, &caps) < 0) {
        fprintf(stderr, "[FAIL] QUERY_CAPS on surviving FD: %s\n",
                strerror(errno));
        goto out;
    }
    if (caps.active_contexts < 1) {
        fprintf(stderr, "[FAIL] context destroyed by sibling FD close (active=%u)\n",
                caps.active_contexts);
        goto out;
    }

    if (sigsetjmp(g_jmp, 1) == 0) {
        for (i = 0; i < nwords; i++)
            p2[i] = 0xC3FFFFFFU ^ (uint32_t)i;
        for (i = 0; i < nwords; i++) {
            if (p2[i] != (0xC3FFFFFFU ^ (uint32_t)i)) {
                fprintf(stderr, "[FAIL] surviving FD write verify at %zu\n", i);
                goto out;
            }
        }
    } else {
        fprintf(stderr, "[FAIL] SIGBUS on surviving FD after sibling close\n");
        goto out;
    }
    printf("[OK] Multi-FD same VM: sibling FD survived peer close+unmap\n");
    rc = 0;
out:
    if (m1)
        munmap(m1, MEM_SIZE);
    if (m2)
        munmap(m2, MEM_SIZE);
    if (fd1 >= 0)
        unbind_close(fd1, VM_MULTI, 1, 0xC3);
    if (fd2 >= 0)
        unbind_close(fd2, VM_MULTI, 1, 0xC3);
    return rc;
}

/* ---- 3) In-flight async teardown ---- */
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
            s->pages[i] = (uint32_t)i ^ 0xD4D4D4D4u;
            (void)s->pages[i];
        }
        atomic_fetch_add(s->faults, 1);
    }
    return NULL;
}

static int test_inflight_async_teardown(void)
{
    int fd_keep = -1, fd_peer = -1;
    void *map_keep = NULL, *map_peer = NULL;
    atomic_int stop, faults, errors;
    struct stress_arg sarg;
    pthread_t thr;
    int i, rc = -1;
    struct wvm_ioctl_context_caps caps;

    printf("\n=== Targeted 3: In-flight async teardown ===\n");
    atomic_init(&stop, 0);
    atomic_init(&faults, 0);
    atomic_init(&errors, 0);

    fd_keep = open_bind(VM_A, 1, 0xA1);
    fd_peer = open_bind(VM_B, 1, 0xB2);
    if (fd_keep < 0 || fd_peer < 0)
        goto out;
    if (set_layout(fd_keep, SAME_GPA, MEM_SIZE) < 0 ||
        set_layout(fd_peer, SAME_GPA, MEM_SIZE) < 0)
        goto out;
    map_keep = map_gpa(fd_keep, SAME_GPA, MEM_SIZE);
    map_peer = map_gpa(fd_peer, SAME_GPA, MEM_SIZE);
    if (!map_keep || !map_peer)
        goto out;

    /* Prime both mappings */
    if (sigsetjmp(g_jmp, 1) == 0) {
        memset(map_keep, 0x11, MEM_SIZE);
        memset(map_peer, 0x22, MEM_SIZE);
    } else {
        fprintf(stderr, "[FAIL] SIGBUS priming maps\n");
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

    /* While keep-VM faults, repeatedly tear down peer and re-bind */
    for (i = 0; i < 8; i++) {
        usleep(2000);
        munmap(map_peer, MEM_SIZE);
        map_peer = NULL;
        unbind_close(fd_peer, VM_B, 1, 0xB2);
        fd_peer = -1;
        usleep(2000);
        fd_peer = open_bind(VM_B, 1, 0xB2);
        if (fd_peer < 0) {
            fprintf(stderr, "[FAIL] re-BIND peer during stress\n");
            atomic_store(&stop, 1);
            pthread_join(thr, NULL);
            goto out;
        }
        if (set_layout(fd_peer, SAME_GPA, MEM_SIZE) < 0) {
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
            memset(map_peer, 0x22 + (i & 0xf), MEM_SIZE);
        else {
            fprintf(stderr, "[FAIL] SIGBUS peer remmap during stress\n");
            atomic_store(&stop, 1);
            pthread_join(thr, NULL);
            goto out;
        }
    }

    atomic_store(&stop, 1);
    pthread_join(thr, NULL);

    if (atomic_load(&errors) != 0) {
        fprintf(stderr, "[FAIL] keep-VM took SIGBUS/errors during peer churn (%d)\n",
                atomic_load(&errors));
        goto out;
    }
    if (atomic_load(&faults) < 1) {
        fprintf(stderr, "[FAIL] stress thread made no progress\n");
        goto out;
    }

    memset(&caps, 0, sizeof(caps));
    caps.magic = WVM_KERNEL_CONTEXT_MAGIC;
    caps.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    if (ioctl(fd_keep, IOCTL_WVM_QUERY_CAPS, &caps) < 0 ||
        caps.active_contexts < 1) {
        fprintf(stderr, "[FAIL] keep context lost after async teardown churn\n");
        goto out;
    }

    /* Final integrity of keep mapping */
    {
        uint32_t *p = (uint32_t *)map_keep;
        size_t n = MEM_SIZE / sizeof(uint32_t);
        size_t j;
        for (j = 0; j < n; j++) {
            if (p[j] != ((uint32_t)j ^ 0xD4D4D4D4u)) {
                fprintf(stderr, "[FAIL] keep map corrupted at %zu after churn\n",
                        j);
                goto out;
            }
        }
    }
    printf("[OK] In-flight teardown: keep-VM survived %d peer churn cycles (%d fault loops)\n",
           8, atomic_load(&faults));
    rc = 0;
out:
    atomic_store(&stop, 1);
    if (map_keep)
        munmap(map_keep, MEM_SIZE);
    if (map_peer)
        munmap(map_peer, MEM_SIZE);
    if (fd_keep >= 0)
        unbind_close(fd_keep, VM_A, 1, 0xA1);
    if (fd_peer >= 0)
        unbind_close(fd_peer, VM_B, 1, 0xB2);
    return rc;
}

int main(void)
{
    struct sigaction sa;
    int failed = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigbus;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    printf("WaveVM targeted Mode A isolation (same GPA / multi-FD / async teardown)\n");
    printf("ABI v%u\n", WVM_KERNEL_CONTEXT_ABI_VERSION);

    if (test_same_gpa() != 0)
        failed++;
    if (test_multi_fd_same_vm() != 0)
        failed++;
    if (test_inflight_async_teardown() != 0)
        failed++;

    if (failed) {
        printf("\nTARGETED ISOLATION: FAIL (%d case(s))\n", failed);
        printf("Do not claim multi-context until this evidence passes.\n");
        return 1;
    }
    printf("\nTARGETED ISOLATION: ALL PASS\n");
    printf("Isolation evidence OK (same-GPA / multi-FD / async teardown).\n");
    return 0;
}

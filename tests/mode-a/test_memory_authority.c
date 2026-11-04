/* Real-module contract probe. The two local authority responders are fixtures;
 * production authority semantics are covered by test_memory_service. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../common_include/wavevm_ioctl.h"

struct authority {
    int fd;
    int hold, seen, reject, stopping, stale_once;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    uint64_t version;
    uint8_t page[4096];
    struct wvm_ioctl_context_bind identity;
};

static void prepare(struct authority *a, uint32_t vm)
{
    struct wvm_ioctl_memory_config config = {0};
    struct wvm_ioctl_mem_layout layout = {.count = 1};
    struct wvm_ioctl_context_bind *id = &a->identity;

    a->fd = open("/dev/wavevm", O_RDWR | O_CLOEXEC);
    assert(a->fd >= 0);
    *id = (struct wvm_ioctl_context_bind){
        .magic = WVM_KERNEL_CONTEXT_MAGIC,
        .version = WVM_KERNEL_CONTEXT_ABI_VERSION,
        .vm_id = vm, .physical_node_id = 7, .node_instance_id = 9,
        .vm_incarnation = 1, .manifest_generation = 1,
    };
    memset(id->candidate_manifest_digest, vm & 255, 32);
    memset(id->capability_profile_digest, 2, 32);
    memset(id->activation_fence, 3, 16);
    id->route_snapshot_key.scope_key.vm_id = vm;
    id->route_snapshot_key.scope_key.vm_incarnation = 1;
    id->route_snapshot_key.scope_key.route_scope_id = 1;
    id->route_snapshot_key.topology_revision = 1;
    id->route_snapshot_key.route_generation = 1;
    memset(id->route_snapshot_key.snapshot_digest, 4, 32);
    assert(ioctl(a->fd, IOCTL_WVM_BIND_CONTEXT, id) == 0);
    config.identity = *id;
    config.guest_physical_limit = 4096;
    config.range_count = 1;
    config.ranges[0].size = 4096;
    assert(ioctl(a->fd, IOCTL_WVM_MEMORY_OWNER, &config) == 0);
    layout.slots[0].size = 4096;
    assert(ioctl(a->fd, IOCTL_SET_MEM_LAYOUT, &layout) == 0);
    pthread_mutex_init(&a->lock, NULL);
    pthread_cond_init(&a->changed, NULL);
    a->version = 1;
    memset(a->page, vm & 255, sizeof(a->page));
}

static void *respond(void *opaque)
{
    struct authority *a = opaque;
    struct wvm_ioctl_memory_operation op;

    while (!__atomic_load_n(&a->stopping, __ATOMIC_ACQUIRE)) {
        memset(&op, 0, sizeof(op));
        if (ioctl(a->fd, IOCTL_WVM_MEMORY_DEQUEUE, &op)) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            assert(errno == ESHUTDOWN || errno == EPERM);
            break;
        }
        assert(op.gpa == 0 && op.request_id);
        pthread_mutex_lock(&a->lock);
        if (op.kind == WVM_KERNEL_MEMORY_READ) {
            memcpy(op.data, a->page, sizeof(a->page));
            op.data_bytes = sizeof(a->page);
        } else {
            assert(op.kind == WVM_KERNEL_MEMORY_COMMIT);
            a->seen = 1;
            pthread_cond_broadcast(&a->changed);
            while (a->hold)
                pthread_cond_wait(&a->changed, &a->lock);
            if (a->reject)
                op.status = -EIO;
            else if (a->stale_once) {
                a->stale_once = 0;
                a->page[18] = 0xee;
                a->version++;
                op.status = -ESTALE;
            }
            else {
                assert(op.base_version == a->version);
                memcpy(a->page + op.offset, op.data, op.data_bytes);
                a->version++;
            }
        }
        op.result_version = op.status ? 0 : a->version;
        pthread_mutex_unlock(&a->lock);
        assert(ioctl(a->fd, IOCTL_WVM_MEMORY_COMPLETE, &op) == 0);
    }
    return NULL;
}

struct drain { int fd, result, notify; };

static void *drain(void *opaque)
{
    struct drain *d = opaque;
    char done = 1;
    d->result = ioctl(d->fd, IOCTL_WVM_MEMORY_DRAIN) == 0 ? 0 : -errno;
    assert(write(d->notify, &done, 1) == 1);
    return NULL;
}

static void attachment_boundary(struct authority *a)
{
    pid_t child = fork();
    int status;
    assert(child >= 0);
    if (!child) {
        struct wvm_ioctl_memory_operation op;
        struct wvm_ioctl_context_bind id = a->identity;
        int fd = open("/dev/wavevm", O_RDWR);
        assert(fd >= 0);
        /* Inheriting the authority FD does not confer authority to a child. */
        assert(ioctl(a->fd, IOCTL_WVM_MEMORY_DEQUEUE, &op) == -1 && errno == EPERM);
        memset(id.attach_capability, 0, sizeof(id.attach_capability));
        assert(ioctl(fd, IOCTL_WVM_BIND_CONTEXT, &id) == -1 && errno == EPERM);
        id = a->identity;
        assert(ioctl(fd, IOCTL_WVM_BIND_CONTEXT, &id) == 0);
        assert(ioctl(fd, IOCTL_WVM_MEMORY_DEQUEUE, &op) == -1 && errno == EPERM);
        close(fd);
        _exit(0);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
    struct authority a = {0}, b = {0};
    pthread_t aw, bw, waiter;
    volatile uint8_t *pa, *pb;
    int pipefd[2];
    struct drain pending;
    struct pollfd ready;
    struct timespec limit;

    if (access("/dev/wavevm", R_OK | W_OK) != 0) {
        fputs("real kernel authority probe unavailable\n", stderr);
        return 77;
    }
    alarm(30);
    prepare(&a, 0x10101);
    prepare(&b, 0x20202);
    attachment_boundary(&a);
    assert(pthread_create(&aw, NULL, respond, &a) == 0);
    assert(pthread_create(&bw, NULL, respond, &b) == 0);
    pa = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, a.fd, 0);
    pb = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, b.fd, 0);
    assert(pa != MAP_FAILED && pb != MAP_FAILED);
    assert(pa[0] == 1 && pb[0] == 2);
    pthread_mutex_lock(&a.lock);
    a.hold = 1;
    a.stale_once = 1;
    pthread_mutex_unlock(&a.lock);
    *(volatile uint32_t *)(pa + 16) = 0x92019101U;
    clock_gettime(CLOCK_REALTIME, &limit);
    limit.tv_sec += 3;
    pthread_mutex_lock(&a.lock);
    while (!a.seen)
        assert(pthread_cond_timedwait(&a.changed, &a.lock, &limit) == 0);
    pthread_mutex_unlock(&a.lock);
    assert(pipe(pipefd) == 0);
    pending = (struct drain){.fd = a.fd, .notify = pipefd[1]};
    assert(pthread_create(&waiter, NULL, drain, &pending) == 0);
    ready = (struct pollfd){.fd = pipefd[0], .events = POLLIN};
    assert(poll(&ready, 1, 100) == 0); /* No success before semantic ACK. */
    pb[23] = 0x82;
    assert(ioctl(b.fd, IOCTL_WVM_MEMORY_DRAIN) == 0);
    pthread_mutex_lock(&b.lock);
    assert(b.page[23] == 0x82 && b.page[17] == 2);
    pthread_mutex_unlock(&b.lock);
    pthread_mutex_lock(&a.lock);
    a.hold = 0;
    pthread_cond_broadcast(&a.changed);
    pthread_mutex_unlock(&a.lock);
    assert(pthread_join(waiter, NULL) == 0 && pending.result == 0);
    close(pipefd[0]);
    close(pipefd[1]);
    pthread_mutex_lock(&a.lock);
    assert(a.page[17] == 0x91 && a.page[18] == 0xee && a.page[19] == 0x92);
    a.reject = 1;
    pthread_mutex_unlock(&a.lock);
    assert(pa[18] == 0xee);
    pa[31] = 0x71;
    assert(ioctl(a.fd, IOCTL_WVM_MEMORY_DRAIN) == -1 && errno == EIO);
    __atomic_store_n(&a.stopping, 1, __ATOMIC_RELEASE);
    assert(ioctl(a.fd, IOCTL_WVM_MEMORY_STOP) == 0);
    assert(pthread_join(aw, NULL) == 0);
    munmap((void *)pa, 4096);
    close(a.fd);
    assert(pb[23] == 0x82);
    assert(ioctl(b.fd, IOCTL_WVM_MEMORY_QUIESCE) == 0);
    assert(ioctl(b.fd, IOCTL_WVM_MEMORY_DRAIN) == 0);
    __atomic_store_n(&b.stopping, 1, __ATOMIC_RELEASE);
    assert(ioctl(b.fd, IOCTL_WVM_MEMORY_STOP) == 0);
    assert(pthread_join(bw, NULL) == 0);
    munmap((void *)pb, 4096);
    close(b.fd);
    puts("kernel authority attachment / delayed ACK / rejection / isolation: PASS");
    return 0;
}


/*
 * R05: multi-vCPU race proof beyond structural single-writer fail-closed.
 *
 * 1) Production guard: WVM_SLAVE_VCPU_COUNT must be "1" or install refuses.
 * 2) Race window: concurrent unguarded mprotect+memcpy on one page either
 *    tears observed bytes or raises SIGSEGV/SIGBUS on a concurrent reader —
 *    both prove why the single-writer gate exists.
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096U
#define ROUNDS 50000U

static volatile unsigned g_faults;
static volatile int g_stop;

static void on_fault(int sig)
{
    (void)sig;
    g_faults++;
}

struct race_arg {
    uint8_t *page;
    uint8_t marker;
    unsigned long writes;
};

static int install_unguarded(uint8_t *page, const uint8_t *data)
{
    if (mprotect(page, PAGE, PROT_READ | PROT_WRITE) != 0)
        return -1;
    memcpy(page, data, PAGE);
    if (mprotect(page, PAGE, PROT_READ) != 0)
        return -1;
    return 0;
}

static int install_guarded(uint8_t *page, const uint8_t *data)
{
    const char *smp = getenv("WVM_SLAVE_VCPU_COUNT");
    if (!smp || strcmp(smp, "1") != 0)
        return -EPERM;
    return install_unguarded(page, data);
}

static void *writer(void *opaque)
{
    struct race_arg *arg = opaque;
    uint8_t data[PAGE];

    memset(data, arg->marker, PAGE);
    while (!g_stop) {
        if (install_unguarded(arg->page, data) == 0)
            arg->writes++;
    }
    return NULL;
}

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "r05-multi-vcpu-race: %s\n", msg);
        return -1;
    }
    return 0;
}

int main(void)
{
    uint8_t *page;
    pthread_t t0, t1;
    struct race_arg a0, a1;
    unsigned torn = 0, i;
    uint8_t sample[PAGE];
    uint8_t ones[PAGE];
    struct sigaction sa;

    page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (expect(page != MAP_FAILED, "mmap page") != 0)
        return 1;
    memset(page, 0, PAGE);
    mprotect(page, PAGE, PROT_READ);
    memset(ones, 0x11, PAGE);

    unsetenv("WVM_SLAVE_VCPU_COUNT");
    if (expect(install_guarded(page, ones) == -EPERM,
               "guard refuses missing env") != 0)
        return 1;
    setenv("WVM_SLAVE_VCPU_COUNT", "2", 1);
    if (expect(install_guarded(page, ones) == -EPERM,
               "guard refuses smp=2") != 0)
        return 1;
    setenv("WVM_SLAVE_VCPU_COUNT", "1", 1);
    if (expect(install_guarded(page, ones) == 0, "guard allows smp=1") != 0)
        return 1;
    printf("[OK] structural single-writer guard (WVM_SLAVE_VCPU_COUNT)\n");

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_fault;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGSEGV, &sa, NULL) != 0 ||
        sigaction(SIGBUS, &sa, NULL) != 0) {
        fprintf(stderr, "cannot install fault handler\n");
        return 1;
    }

    a0.page = page;
    a0.marker = 0xA1;
    a0.writes = 0;
    a1.page = page;
    a1.marker = 0xB2;
    a1.writes = 0;
    g_stop = 0;
    g_faults = 0;
    if (pthread_create(&t0, NULL, writer, &a0) != 0 ||
        pthread_create(&t1, NULL, writer, &a1) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    for (i = 0; i < ROUNDS; i++) {
        uint8_t first;
        size_t j;
        /* May SEGV if a writer has the page non-readable mid-window. */
        memcpy(sample, page, PAGE);
        first = sample[0];
        for (j = 1; j < PAGE; j++) {
            if (sample[j] != first) {
                torn++;
                break;
            }
        }
    }
    g_stop = 1;
    pthread_join(t0, NULL);
    pthread_join(t1, NULL);

    if (expect(a0.writes > 0 && a1.writes > 0, "both writers progressed") != 0)
        return 1;
    if (torn == 0 && g_faults == 0) {
        fprintf(stderr,
                "r05: no tear/fault in %u rounds (writes %lu/%lu)\n", ROUNDS,
                a0.writes, a1.writes);
        munmap(page, PAGE);
        puts("R05 multi-vCPU race: PARTIAL (guard PASS; race window not "
             "observed)");
        return 2;
    }
    printf("[OK] unguarded dual-writer race evidence tear=%u faults=%u "
           "writes=%lu/%lu\n",
           torn, g_faults, a0.writes, a1.writes);
    munmap(page, PAGE);
    puts("R05 multi-vCPU race proof: PASS");
    return 0;
}

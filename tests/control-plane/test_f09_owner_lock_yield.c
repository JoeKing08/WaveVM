/*
 * F09: production owner lock must yield across admission network waits so a
 * delayed participant does not block unrelated lifecycle/health work.
 * This directed oracle mirrors ctl_tool control_owner_before/after_network.
 * Conflicting reservation atomicity: tests/control-plane/test_rm_p7_concurrent_create.
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>

struct owner_lock_state {
    pthread_mutex_t lock;
    int lock_held;
    pthread_t lock_owner;
    unsigned yield_depth;
};

static void owner_lock(struct owner_lock_state *s)
{
    pthread_mutex_lock(&s->lock);
    s->lock_owner = pthread_self();
    s->lock_held = 1;
}

static void owner_unlock(struct owner_lock_state *s)
{
    s->lock_held = 0;
    pthread_mutex_unlock(&s->lock);
}

static void before_network(struct owner_lock_state *s)
{
    if (!s->lock_held || !pthread_equal(s->lock_owner, pthread_self())) {
        return;
    }
    s->yield_depth++;
    if (s->yield_depth == 1U) {
        s->lock_held = 0;
        pthread_mutex_unlock(&s->lock);
    }
}

static void after_network(struct owner_lock_state *s)
{
    if (s->yield_depth == 0U) {
        return;
    }
    if (s->yield_depth == 1U) {
        pthread_mutex_lock(&s->lock);
        s->lock_owner = pthread_self();
        s->lock_held = 1;
    }
    s->yield_depth--;
}

struct health_arg {
    struct owner_lock_state *owner;
    atomic_int got_lock_during_delay;
    atomic_int started;
    atomic_int delay_active; /* only count acquisitions while RPC delayed */
};

static void *health_thread(void *arg)
{
    struct health_arg *h = arg;
    struct timespec start, now;

    atomic_store(&h->started, 1);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (pthread_mutex_trylock(&h->owner->lock) == 0) {
            if (atomic_load(&h->delay_active)) {
                atomic_store(&h->got_lock_during_delay, 1);
            }
            pthread_mutex_unlock(&h->owner->lock);
            return NULL;
        }
        if (!atomic_load(&h->delay_active) &&
            atomic_load(&h->got_lock_during_delay) == 0) {
            /* delay ended without us ever holding the lock during it */
            clock_gettime(CLOCK_MONOTONIC, &now);
            long ms = (long)((now.tv_sec - start.tv_sec) * 1000L +
                             (now.tv_nsec - start.tv_nsec) / 1000000L);
            if (ms > 100) {
                return NULL;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ms = (long)((now.tv_sec - start.tv_sec) * 1000L +
                         (now.tv_nsec - start.tv_nsec) / 1000000L);
        if (ms > 2000) {
            return NULL;
        }
        usleep(1000);
    }
}

static void delayed_rpc(unsigned delay_ms)
{
    usleep(delay_ms * 1000U);
}

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "test_f09_owner_lock_yield: FAIL %s\n", msg);
        return 1;
    }
    return 0;
}

int main(void)
{
    struct owner_lock_state owner;
    struct health_arg health;
    pthread_t tid;
    int failures = 0;

    memset(&owner, 0, sizeof(owner));
    memset(&health, 0, sizeof(health));
    pthread_mutex_init(&owner.lock, NULL);
    health.owner = &owner;

    /* With yield: health must acquire during delayed RPC. */
    owner_lock(&owner);
    if (pthread_create(&tid, NULL, health_thread, &health) != 0) {
        fprintf(stderr, "spawn failed\n");
        return 1;
    }
    while (!atomic_load(&health.started)) {
        usleep(1000);
    }
    atomic_store(&health.delay_active, 1);
    before_network(&owner);
    delayed_rpc(400);
    after_network(&owner);
    atomic_store(&health.delay_active, 0);
    owner_unlock(&owner);
    pthread_join(tid, NULL);
    failures += expect(atomic_load(&health.got_lock_during_delay) == 1,
                       "health acquired owner lock during yielded RPC");

    /* Without yield: health must stay blocked for the whole delay. */
    atomic_store(&health.got_lock_during_delay, 0);
    atomic_store(&health.started, 0);
    atomic_store(&health.delay_active, 0);
    owner_lock(&owner);
    if (pthread_create(&tid, NULL, health_thread, &health) != 0) {
        return 1;
    }
    while (!atomic_load(&health.started)) {
        usleep(1000);
    }
    atomic_store(&health.delay_active, 1);
    delayed_rpc(400);
    atomic_store(&health.delay_active, 0);
    owner_unlock(&owner);
    pthread_join(tid, NULL);
    failures += expect(atomic_load(&health.got_lock_during_delay) == 0,
                       "without yield, health blocked for entire delay");

    pthread_mutex_destroy(&owner.lock);
    if (failures) {
        fprintf(stderr, "test_f09_owner_lock_yield: %d failure(s)\n", failures);
        return 1;
    }
    puts("test_f09_owner_lock_yield: PASS");
    return 0;
}

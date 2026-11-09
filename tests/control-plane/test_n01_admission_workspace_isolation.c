/*
 * N01: concurrent CREATE must not share one resettable admission workspace.
 *
 * Directed oracle (mirrors ctl_tool/main.c lease + reset refuse):
 *   - Thread A acquires workspace lease, marks a prepared buffer, yields
 *     (simulates F09 network wait without holding owner lock).
 *   - Thread B tries acquire -> fail-closed busy.
 *   - Thread B reset attempt while A holds -> refused; A's marker intact.
 *   - After A releases, B can acquire and reset.
 *
 * This does not restore a global owner lock across RPCs (F09 still holds).
 */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>

struct fake_workspace {
    int tx_held;
    pthread_t tx_holder;
    uint32_t tx_vm_id;
    uint64_t tx_vm_inc;
    unsigned marker;
    unsigned reset_count;
    unsigned refused_reset;
};

struct owner_lock {
    pthread_mutex_t lock;
    int lock_held;
    pthread_t lock_owner;
    unsigned yield_depth;
};

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "test_n01_admission_workspace_isolation: FAIL %s\n", msg);
        return 1;
    }
    return 0;
}

static int try_acquire(struct fake_workspace *ws)
{
    if (ws->tx_held) {
        if (pthread_equal(ws->tx_holder, pthread_self())) {
            return 0;
        }
        return -1; /* busy */
    }
    ws->tx_held = 1;
    ws->tx_holder = pthread_self();
    ws->tx_vm_id = 0;
    ws->tx_vm_inc = 0;
    return 0;
}

static void release_ws(struct fake_workspace *ws)
{
    if (!ws->tx_held || !pthread_equal(ws->tx_holder, pthread_self())) {
        return;
    }
    ws->tx_held = 0;
    ws->tx_vm_id = 0;
    ws->tx_vm_inc = 0;
}

static int reset_ws(struct fake_workspace *ws, unsigned new_marker)
{
    if (ws->tx_held && !pthread_equal(ws->tx_holder, pthread_self())) {
        ws->refused_reset++;
        return -1;
    }
    ws->marker = new_marker;
    ws->reset_count++;
    return 0;
}

static void owner_lock(struct owner_lock *o)
{
    pthread_mutex_lock(&o->lock);
    o->lock_owner = pthread_self();
    o->lock_held = 1;
}

static void owner_unlock(struct owner_lock *o)
{
    o->lock_held = 0;
    pthread_mutex_unlock(&o->lock);
}

static void before_network(struct owner_lock *o)
{
    if (!o->lock_held || !pthread_equal(o->lock_owner, pthread_self())) {
        return;
    }
    o->yield_depth++;
    if (o->yield_depth == 1U) {
        o->lock_held = 0;
        pthread_mutex_unlock(&o->lock);
    }
}

static void after_network(struct owner_lock *o)
{
    if (o->yield_depth == 0U) {
        return;
    }
    if (o->yield_depth == 1U) {
        pthread_mutex_lock(&o->lock);
        o->lock_owner = pthread_self();
        o->lock_held = 1;
    }
    o->yield_depth--;
}

struct thread_arg {
    struct fake_workspace *ws;
    struct owner_lock *owner;
    atomic_int a_holding_during_yield;
    atomic_int b_acquire_busy;
    atomic_int b_reset_refused;
    atomic_int b_saw_marker;
    atomic_int phase; /* 0 init, 1 A yielded, 2 B done probing, 3 A done */
};

static void *thread_a(void *arg)
{
    struct thread_arg *t = arg;

    owner_lock(t->owner);
    if (try_acquire(t->ws) != 0) {
        owner_unlock(t->owner);
        return NULL;
    }
    if (reset_ws(t->ws, 0xA11U) != 0) {
        release_ws(t->ws);
        owner_unlock(t->owner);
        return NULL;
    }
    t->ws->tx_vm_id = 42;
    t->ws->tx_vm_inc = 7;
    /* F09 yield: drop owner lock while keeping workspace lease. */
    before_network(t->owner);
    atomic_store(&t->a_holding_during_yield, 1);
    /* Wait until B finished probing. */
    while (atomic_load(&t->phase) < 2) {
        usleep(1000);
    }
    after_network(t->owner);
    /* Marker must still be A's. */
    atomic_store(&t->b_saw_marker, (int)t->ws->marker);
    release_ws(t->ws);
    owner_unlock(t->owner);
    atomic_store(&t->phase, 3);
    return NULL;
}

static void *thread_b(void *arg)
{
    struct thread_arg *t = arg;

    /* Wait until A has yielded with lease held. */
    while (!atomic_load(&t->a_holding_during_yield)) {
        usleep(1000);
    }
    owner_lock(t->owner);
    if (try_acquire(t->ws) != 0) {
        atomic_store(&t->b_acquire_busy, 1);
    }
    if (reset_ws(t->ws, 0xB22U) != 0) {
        atomic_store(&t->b_reset_refused, 1);
    }
    owner_unlock(t->owner);
    atomic_store(&t->phase, 2);
    /* After A releases, B should be able to acquire+reset. */
    while (atomic_load(&t->phase) < 3) {
        usleep(1000);
    }
    owner_lock(t->owner);
    if (try_acquire(t->ws) == 0 && reset_ws(t->ws, 0xB22U) == 0) {
        atomic_fetch_or(&t->b_saw_marker, 0); /* keep prior */
        /* reuse b_saw_marker high bit? store final marker separately via reset_count check below */
        t->ws->tx_vm_id = 99;
        release_ws(t->ws);
    }
    owner_unlock(t->owner);
    return NULL;
}

int main(void)
{
    struct fake_workspace ws;
    struct owner_lock owner;
    struct thread_arg arg;
    pthread_t ta, tb;
    int failed = 0;

    memset(&ws, 0, sizeof(ws));
    memset(&owner, 0, sizeof(owner));
    memset(&arg, 0, sizeof(arg));
    pthread_mutex_init(&owner.lock, NULL);
    arg.ws = &ws;
    arg.owner = &owner;

    if (pthread_create(&ta, NULL, thread_a, &arg) != 0 ||
        pthread_create(&tb, NULL, thread_b, &arg) != 0) {
        fprintf(stderr, "test_n01: cannot create threads\n");
        return 1;
    }
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    failed |= expect(atomic_load(&arg.b_acquire_busy) == 1,
                     "B must see workspace busy while A holds lease across yield");
    failed |= expect(atomic_load(&arg.b_reset_refused) == 1,
                     "B reset must be refused while A holds lease");
    failed |= expect(atomic_load(&arg.b_saw_marker) == (int)0xA11U,
                     "A marker must survive B's concurrent attempt");
    failed |= expect(ws.refused_reset >= 1U, "at least one refused reset");
    failed |= expect(ws.reset_count >= 2U,
                     "A reset + B post-release reset must both succeed");
    failed |= expect(ws.marker == 0xB22U, "B must reset after A release");
    failed |= expect(ws.tx_held == 0, "workspace lease released at end");

    pthread_mutex_destroy(&owner.lock);
    if (failed) {
        return 1;
    }
    fprintf(stdout, "test_n01_admission_workspace_isolation: PASS\n");
    fprintf(stdout,
            "busy=%d refused_reset=%u resets=%u final_marker=0x%X\n",
            atomic_load(&arg.b_acquire_busy), ws.refused_reset, ws.reset_count,
            ws.marker);
    return 0;
}

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
static pthread_mutex_t g_push_barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_push_barrier_cond = PTHREAD_COND_INITIALIZER;
static uint64_t g_push_barrier_next = 1;
static uint64_t g_push_barrier_active_cookie = 0;
static int g_push_barrier_expect = 0;
static int g_push_barrier_got = 0;

static void mark_push_barrier_done(uint64_t cookie)
{
    pthread_mutex_lock(&g_push_barrier_lock);
    if (cookie == g_push_barrier_active_cookie && g_push_barrier_expect > 0) {
        g_push_barrier_got++;
        pthread_cond_broadcast(&g_push_barrier_cond);
    }
    pthread_mutex_unlock(&g_push_barrier_lock);
}

static uint64_t push_barrier_begin(int expect_count)
{
    uint64_t cookie;

    pthread_mutex_lock(&g_push_barrier_lock);
    cookie = g_push_barrier_next++;
    g_push_barrier_active_cookie = cookie;
    g_push_barrier_expect = expect_count > 0 ? expect_count : 1;
    g_push_barrier_got = 0;
    pthread_mutex_unlock(&g_push_barrier_lock);
    return cookie;
}

static int wait_for_push_barrier_cookie(uint64_t cookie, uint64_t timeout_us)
{
    struct timespec ts;

    if (timeout_us == 0) {
        timeout_us = 5000000ULL;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t)(timeout_us / 1000000ULL);
    ts.tv_nsec += (long)((timeout_us % 1000000ULL) * 1000ULL);
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g_push_barrier_lock);
    while (!(g_push_barrier_active_cookie == cookie &&
             g_push_barrier_got >= g_push_barrier_expect)) {
        int rc = pthread_cond_timedwait(&g_push_barrier_cond,
                                        &g_push_barrier_lock, &ts);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&g_push_barrier_lock);
            return -ETIMEDOUT;
        }
    }
    pthread_mutex_unlock(&g_push_barrier_lock);
    return 0;
}
int main(void) { uint64_t c = push_barrier_begin(2); mark_push_barrier_done(c); mark_push_barrier_done(c); int rc = wait_for_push_barrier_cookie(c, 1000); printf("same_helper_duplicate_acks=2 required_helpers=2 fence_rc=%d\n", rc); return rc == 0 ? 0 : 1; }

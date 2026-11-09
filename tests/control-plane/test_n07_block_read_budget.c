#include <pthread.h>
#include <stdio.h>
#include <string.h>

/*
 * N07 oracle: two concurrent READ reserves against a budget that fits only one
 * must yield at most one success when holds are accounted before execute.
 */
struct budget {
    pthread_mutex_t lock;
    size_t retained;
    size_t reserved;
    size_t limit;
};

struct arg {
    struct budget *b;
    size_t need;
    int got;
};

static int try_reserve(struct budget *b, size_t need)
{
    pthread_mutex_lock(&b->lock);
    if (b->retained + b->reserved + need > b->limit) {
        pthread_mutex_unlock(&b->lock);
        return -1;
    }
    b->reserved += need;
    pthread_mutex_unlock(&b->lock);
    return 0;
}

static void *worker(void *opaque)
{
    struct arg *a = opaque;
    a->got = try_reserve(a->b, a->need) == 0;
    return NULL;
}

int main(void)
{
    struct budget b;
    struct arg a1, a2;
    pthread_t t1, t2;
    int ok = 0;

    memset(&b, 0, sizeof(b));
    pthread_mutex_init(&b.lock, NULL);
    b.limit = 4096;
    a1.b = a2.b = &b;
    a1.need = a2.need = 4096;
    a1.got = a2.got = 0;
    pthread_create(&t1, NULL, worker, &a1);
    pthread_create(&t2, NULL, worker, &a2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    ok = (a1.got + a2.got) == 1;
    if (!ok) {
        fprintf(stderr,
                "test_n07_block_read_budget: FAIL got=%d+%d reserved=%zu\n",
                a1.got, a2.got, b.reserved);
        return 1;
    }
    printf("test_n07_block_read_budget: PASS winners=%d reserved=%zu\n",
           a1.got + a2.got, b.reserved);
    return 0;
}

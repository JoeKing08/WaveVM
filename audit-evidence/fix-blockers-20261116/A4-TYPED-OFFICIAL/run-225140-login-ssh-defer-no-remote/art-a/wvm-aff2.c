#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
int main(void)
{
    cpu_set_t s;
    struct timespec ts, te;
    CPU_ZERO(&s);
    CPU_SET(2, &s);
    if (sched_setaffinity(0, sizeof(s), &s) != 0) {
        fprintf(stderr, "aff 2 failed errno=%d\n", errno);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts);
    volatile unsigned long i = 0;
    do {
        for (int k = 0; k < 10000000; k++) i++;
        clock_gettime(CLOCK_MONOTONIC, &te);
    } while ((te.tv_sec - ts.tv_sec) + (te.tv_nsec - ts.tv_nsec) / 1e9 < 5.0);
    printf("burn-cpu2-sec=5 iters=%lu\n", i);
    fflush(stdout);
    return 0;
}

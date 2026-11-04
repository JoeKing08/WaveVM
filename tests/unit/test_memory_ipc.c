#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
static uint64_t get_us_time(void)
{
    struct timespec ts;
    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}
#include "memory_ipc.inc"

int main(void)
{
    int pair[2];
    char received[8] = {0};
    char *large = calloc(1, 1024 * 1024);
    int small_buffer = 4096;
    uint64_t start;

    assert(large && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(write(pair[1], "abc", 3) == 3);
    start = get_us_time();
    assert(memory_ipc_transfer(pair[0], received, 8, false, start + 30000) ==
           -ETIMEDOUT);
    assert(!memcmp(received, "abc", 3));
    assert(get_us_time() - start < 500000);
    assert(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &small_buffer,
                      sizeof(small_buffer)) == 0);
    start = get_us_time();
    assert(memory_ipc_transfer(pair[0], large, 1024 * 1024, true,
                                start + 30000) == -ETIMEDOUT);
    assert(get_us_time() - start < 500000);
    close(pair[1]);
    assert(memory_ipc_transfer(pair[0], received, 8, false,
                                get_us_time() + 30000) == -ECONNRESET);
    close(pair[0]);
    free(large);
    return 0;
}

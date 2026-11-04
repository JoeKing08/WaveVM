#define _GNU_SOURCE
#include <assert.h>

/* Include the production tracker, not a copy of its completion algorithm. */
#include "../../slave_daemon/slave_hybrid.c"

int main(void)
{
    push_barrier_peer_t peers[2] = {
        {.endpoint = {.sin_family = AF_INET,
                      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                      .sin_port = htons(30001)}},
        {.endpoint = {.sin_family = AF_INET,
                      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                      .sin_port = htons(30002)}},
    };
    push_barrier_peer_t other_peer = {.endpoint = peers[0].endpoint};
    push_barrier_t first = {.peers = peers, .peer_count = 2};
    push_barrier_t second = {.peers = &other_peer, .peer_count = 1};
    struct sockaddr_in stranger = peers[1].endpoint;

    assert(push_barrier_begin(&first) == 0);
    assert(push_barrier_begin(&second) == 0);
    mark_push_barrier_done(first.cookie, &peers[0].endpoint);
    mark_push_barrier_done(first.cookie, &peers[0].endpoint);
    stranger.sin_port = htons(30003);
    mark_push_barrier_done(first.cookie, &stranger);
    assert(first.remaining == 1);
    assert(second.remaining == 1);
    assert(wait_for_push_barrier_cookie(&first, 1000) == -ETIMEDOUT);
    mark_push_barrier_done(second.cookie, &other_peer.endpoint);
    assert(wait_for_push_barrier_cookie(&second, 1000) == 0);
    push_barrier_end(&second);
    mark_push_barrier_done(first.cookie, &peers[1].endpoint);
    assert(wait_for_push_barrier_cookie(&first, 1000) == 0);
    push_barrier_end(&first);
    assert(g_push_barriers == NULL);
    puts("helper barrier: duplicate/unknown ACK, missing peer, concurrent fences PASS");
    return 0;
}

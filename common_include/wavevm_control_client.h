#ifndef WAVEVM_CONTROL_CLIENT_H
#define WAVEVM_CONTROL_CLIENT_H

/*
 * Caller-owned authenticated control client.  This is deliberately separate
 * from the data-plane transport: endpoint selection belongs here, while the
 * framing and result binding remain in wavevm_control_transport.
 */

#include <stddef.h>
#include <stdint.h>

#include "wavevm_control.h"
#include "wavevm_control_transport.h"

typedef int (*wvm_control_stream_open_fn)(
    void *opaque, const struct wvm_endpoint *endpoint, int *stream_fd,
    char *error, size_t error_len);

typedef int (*wvm_control_stream_authenticate_peer_fn)(
    void *opaque, int stream_fd, const struct wvm_member_key *expected_peer,
    char *error, size_t error_len);

struct wvm_control_stream_connector {
    void *opaque;
    wvm_control_stream_open_fn open_unix_stream;
    wvm_control_stream_open_fn open_tls_tcp;
    wvm_control_stream_open_fn open_quic_stream;
    wvm_control_stream_authenticate_peer_fn authenticate_peer;
    uint32_t timeout_ms;
};

struct wvm_control_stream_client {
    struct wvm_control_stream_connector connector;
    int initialized;
};

int wvm_control_stream_client_init(
    struct wvm_control_stream_client *client,
    const struct wvm_control_stream_connector *connector, char *error,
    size_t error_len);

void wvm_control_stream_client_destroy(
    struct wvm_control_stream_client *client);

/* Select, authenticate, exchange one request, and close the owned stream. */
int wvm_control_stream_client_exchange(
    struct wvm_control_stream_client *client,
    const struct wvm_member_key *expected_peer,
    const struct wvm_endpoint *endpoint, const struct wvm_envelope *request,
    struct wvm_control_result *result, char *error, size_t error_len);

#endif /* WAVEVM_CONTROL_CLIENT_H */

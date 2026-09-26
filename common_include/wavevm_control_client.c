#define _POSIX_C_SOURCE 200809L

#include "wavevm_control_client.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static int callback_failure(int result)
{
    return result < 0 ? result : -EACCES;
}

static int set_socket_timeout(int stream_fd, uint32_t timeout_ms,
                              char *error, size_t error_len)
{
    struct timeval timeout;

    timeout.tv_sec = (time_t)(timeout_ms / 1000U);
    timeout.tv_usec = (suseconds_t)((timeout_ms % 1000U) * 1000U);
    if (setsockopt(stream_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0 ||
        setsockopt(stream_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "cannot configure control stream timeout: %s",
                           strerror(errno));
        }
        return -errno;
    }
    return 0;
}

static wvm_control_stream_open_fn select_open_callback(
    const struct wvm_control_stream_connector *connector,
    enum wvm_control_transport transport, char *error, size_t error_len)
{
    if (!connector) {
        set_error(error, error_len, "control stream connector is missing");
        return NULL;
    }
    switch (transport) {
    case WVM_CONTROL_TRANSPORT_UNIX_STREAM:
        if (!connector->open_unix_stream) {
            set_error(error, error_len,
                      "Unix control stream connector is not configured");
            return NULL;
        }
        return connector->open_unix_stream;
    case WVM_CONTROL_TRANSPORT_TLS_TCP:
        if (!connector->open_tls_tcp) {
            set_error(error, error_len,
                      "TLS/TCP control stream connector is not configured");
            return NULL;
        }
        return connector->open_tls_tcp;
    case WVM_CONTROL_TRANSPORT_QUIC_STREAM:
        if (!connector->open_quic_stream) {
            set_error(error, error_len,
                      "QUIC control stream connector is not configured");
            return NULL;
        }
        return connector->open_quic_stream;
    default:
        set_error(error, error_len, "control endpoint transport is invalid");
        return NULL;
    }
}

static wvm_control_stream_authenticate_peer_fn select_authenticate_callback(
    const struct wvm_control_stream_connector *connector,
    enum wvm_control_transport transport, void **opaque, char *error,
    size_t error_len)
{
    if (!connector || !opaque) {
        set_error(error, error_len, "control authenticator is missing");
        return NULL;
    }
    switch (transport) {
    case WVM_CONTROL_TRANSPORT_UNIX_STREAM:
        *opaque = connector->authenticate_unix_opaque
                      ? connector->authenticate_unix_opaque
                      : connector->opaque;
        break;
    case WVM_CONTROL_TRANSPORT_TLS_TCP:
        *opaque = connector->authenticate_tls_opaque
                      ? connector->authenticate_tls_opaque
                      : connector->opaque;
        break;
    case WVM_CONTROL_TRANSPORT_QUIC_STREAM:
        *opaque = connector->authenticate_quic_opaque
                      ? connector->authenticate_quic_opaque
                      : connector->opaque;
        break;
    default:
        set_error(error, error_len, "control endpoint transport is invalid");
        return NULL;
    }
    if (!connector->authenticate_peer && !connector->authenticate_unix &&
        !connector->authenticate_tls && !connector->authenticate_quic) {
        set_error(error, error_len,
                  "authenticated control stream connector is incomplete");
        return NULL;
    }
    switch (transport) {
    case WVM_CONTROL_TRANSPORT_UNIX_STREAM:
        return connector->authenticate_unix
                   ? connector->authenticate_unix
                   : connector->authenticate_peer;
    case WVM_CONTROL_TRANSPORT_TLS_TCP:
        return connector->authenticate_tls
                   ? connector->authenticate_tls
                   : connector->authenticate_peer;
    case WVM_CONTROL_TRANSPORT_QUIC_STREAM:
        return connector->authenticate_quic
                   ? connector->authenticate_quic
                   : connector->authenticate_peer;
    default:
        return NULL;
    }
}

static wvm_control_stream_exchange_fn select_exchange_callback(
    const struct wvm_control_stream_connector *connector,
    enum wvm_control_transport transport, void **opaque)
{
    if (!connector || !opaque) {
        return NULL;
    }
    switch (transport) {
    case WVM_CONTROL_TRANSPORT_TLS_TCP:
        *opaque = connector->exchange_tls_opaque
                      ? connector->exchange_tls_opaque
                      : connector->opaque;
        return connector->exchange_tls_tcp;
    case WVM_CONTROL_TRANSPORT_QUIC_STREAM:
        *opaque = connector->exchange_quic_opaque
                      ? connector->exchange_quic_opaque
                      : connector->opaque;
        return connector->exchange_quic_stream;
    default:
        return NULL;
    }
}

int wvm_control_stream_client_init(
    struct wvm_control_stream_client *client,
    const struct wvm_control_stream_connector *connector, char *error,
    size_t error_len)
{
    if (!client || !connector ||
        (!connector->authenticate_peer && !connector->authenticate_unix &&
         !connector->authenticate_tls && !connector->authenticate_quic)) {
        set_error(error, error_len,
                  "authenticated control stream client is incomplete");
        return -EINVAL;
    }
    memset(client, 0, sizeof(*client));
    client->connector = *connector;
    if (client->connector.timeout_ms == 0) {
        client->connector.timeout_ms = 10000U;
    }
    client->initialized = 1;
    return 0;
}

void wvm_control_stream_client_destroy(
    struct wvm_control_stream_client *client)
{
    if (client) {
        memset(client, 0, sizeof(*client));
    }
}

int wvm_control_stream_client_exchange(
    struct wvm_control_stream_client *client,
    const struct wvm_member_key *expected_peer,
    const struct wvm_endpoint *endpoint, const struct wvm_envelope *request,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    wvm_control_stream_open_fn open_stream;
    wvm_control_stream_authenticate_peer_fn authenticate_peer;
    wvm_control_stream_exchange_fn exchange_stream;
    void *callback_opaque;
    int stream_fd = -1;
    int status;

    if (!client || !client->initialized || !expected_peer || !endpoint ||
        !request || !result ||
        wvm_member_key_validate(expected_peer, error, error_len) != 0 ||
        wvm_endpoint_validate(endpoint, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "control stream exchange input is invalid");
        }
        return -EINVAL;
    }
    open_stream = select_open_callback(&client->connector,
                                       endpoint->control_transport, error,
                                       error_len);
    if (!open_stream) {
        return -EOPNOTSUPP;
    }
    status = open_stream(client->connector.opaque, endpoint, &stream_fd, error,
                         error_len);
    if (status != 0 || stream_fd < 0) {
        if (stream_fd >= 0) {
            close(stream_fd);
        }
        if (status == 0) {
            set_error(error, error_len,
                      "control stream connector returned no stream");
            return -EPROTO;
        }
        return callback_failure(status);
    }
    status = set_socket_timeout(stream_fd, client->connector.timeout_ms, error,
                                error_len);
    if (status == 0) {
        authenticate_peer = select_authenticate_callback(
            &client->connector, endpoint->control_transport, &callback_opaque,
            error, error_len);
        if (!authenticate_peer) {
            status = -EINVAL;
        } else {
            status = authenticate_peer(callback_opaque, stream_fd, expected_peer,
                                       error, error_len);
        }
        if (status != 0) {
            status = callback_failure(status);
        }
    }
    if (status == 0) {
        exchange_stream = select_exchange_callback(
            &client->connector, endpoint->control_transport, &callback_opaque);
        if (exchange_stream) {
            status = exchange_stream(callback_opaque, expected_peer, endpoint,
                                     request, result, error, error_len);
        } else {
            status = wvm_control_transport_exchange(
                stream_fd, expected_peer->role_id, expected_peer->instance_id,
                request, result, error, error_len);
        }
    }
    shutdown(stream_fd, SHUT_RDWR);
    close(stream_fd);
    return status;
}

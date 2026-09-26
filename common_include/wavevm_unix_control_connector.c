#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "wavevm_unix_control_connector.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static int open_unix_stream(void *opaque, const struct wvm_endpoint *endpoint,
                            int *stream_fd, char *error, size_t error_len)
{
    struct sockaddr_un address;
    size_t path_bytes;
    int fd;

    (void)opaque;
    if (!endpoint || !stream_fd ||
        endpoint->control_transport != WVM_CONTROL_TRANSPORT_UNIX_STREAM ||
        !endpoint->has_control_socket_path) {
        set_error(error, error_len, "Unix control endpoint is incomplete");
        return -EINVAL;
    }
    path_bytes = strlen(endpoint->control_socket_path);
    if (path_bytes == 0 || path_bytes >= sizeof(address.sun_path) ||
        endpoint->control_socket_path[0] != '/') {
        set_error(error, error_len, "Unix control socket path is invalid");
        return -EINVAL;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len, "Unix control socket failed: %s",
                           strerror(errno));
        }
        return -errno;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, endpoint->control_socket_path, path_bytes + 1U);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_bytes + 1U)) != 0) {
        int saved_errno = errno;

        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "Unix control connect failed: %s",
                           strerror(saved_errno));
        }
        close(fd);
        return -saved_errno;
    }
    *stream_fd = fd;
    return 0;
}

static int authenticate_unix_peer(
    void *opaque, int stream_fd, const struct wvm_member_key *expected_peer,
    char *error, size_t error_len)
{
    struct wvm_unix_control_connector *connector = opaque;
    struct wvm_unix_peer_credentials credentials;
    struct ucred kernel_credentials;
    socklen_t credentials_bytes = sizeof(kernel_credentials);

    if (!connector || !connector->authorize_peer || stream_fd < 0 ||
        !expected_peer) {
        set_error(error, error_len,
                  "Unix control peer authorization is not configured");
        return -EINVAL;
    }
    memset(&kernel_credentials, 0, sizeof(kernel_credentials));
    if (getsockopt(stream_fd, SOL_SOCKET, SO_PEERCRED, &kernel_credentials,
                   &credentials_bytes) != 0) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "cannot obtain Unix peer credentials: %s",
                           strerror(errno));
        }
        return -errno;
    }
    if (credentials_bytes != sizeof(kernel_credentials) ||
        kernel_credentials.pid <= 0) {
        set_error(error, error_len, "Unix peer credentials are malformed");
        return -EACCES;
    }
    credentials.process_id = kernel_credentials.pid;
    credentials.user_id = kernel_credentials.uid;
    credentials.group_id = kernel_credentials.gid;
    return connector->authorize_peer(connector->authorize_opaque,
                                     expected_peer, &credentials, error,
                                     error_len);
}

int wvm_unix_control_connector_bind(
    struct wvm_unix_control_connector *unix_connector,
    wvm_unix_control_authorize_peer_fn authorize_peer, void *authorize_opaque,
    uint32_t timeout_ms, struct wvm_control_stream_connector *connector,
    char *error, size_t error_len)
{
    if (!unix_connector || !authorize_peer || !connector) {
        set_error(error, error_len, "Unix control connector is incomplete");
        return -EINVAL;
    }
    unix_connector->authorize_peer = authorize_peer;
    unix_connector->authorize_opaque = authorize_opaque;
    memset(connector, 0, sizeof(*connector));
    connector->opaque = unix_connector;
    connector->open_unix_stream = open_unix_stream;
    connector->authenticate_peer = authenticate_unix_peer;
    connector->authenticate_unix = authenticate_unix_peer;
    connector->authenticate_unix_opaque = unix_connector;
    connector->timeout_ms = timeout_ms;
    return 0;
}

#define _GNU_SOURCE

#include "wavevm_control_owner.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

struct wvm_control_owner_client {
    struct wvm_control_owner *owner;
    int fd;
    int tls;
    SSL *ssl;
    pthread_t thread;
    int done;
    struct wvm_control_owner_client *next;
};

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static void set_errno_error(char *error, size_t error_len, const char *prefix)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s: %s", prefix,
                       strerror(errno));
    }
}

static ssize_t owner_ssl_read(void *opaque, void *buffer, size_t bytes)
{
    return SSL_read((SSL *)opaque, buffer, (int)bytes);
}

static ssize_t owner_ssl_write(void *opaque, const void *buffer, size_t bytes)
{
    return SSL_write((SSL *)opaque, buffer, (int)bytes);
}

static int owner_is_stopping(struct wvm_control_owner *owner)
{
    int stopping;

    pthread_mutex_lock(&owner->lock);
    stopping = owner->stopping;
    pthread_mutex_unlock(&owner->lock);
    return stopping;
}

static void owner_reap_completed(struct wvm_control_owner *owner)
{
    struct wvm_control_owner_client *client;
    struct wvm_control_owner_client **cursor;

    for (;;) {
        client = NULL;
        pthread_mutex_lock(&owner->lock);
        cursor = &owner->clients;
        while (*cursor) {
            if ((*cursor)->done) {
                client = *cursor;
                *cursor = client->next;
                break;
            }
            cursor = &(*cursor)->next;
        }
        pthread_mutex_unlock(&owner->lock);
        if (!client) {
            return;
        }
        (void)pthread_join(client->thread, NULL);
        free(client);
    }
}

static void *owner_client_main(void *opaque)
{
    struct wvm_control_owner_client *client = opaque;
    struct wvm_control_owner *owner = client->owner;
    struct wvm_control_transport_config transport_config;
    struct wvm_control_stream transport;
    char error[256] = {0};

    memset(&transport, 0, sizeof(transport));
    memset(&transport_config, 0, sizeof(transport_config));
    transport_config.stream_fd = client->fd;
    transport_config.max_frame_bytes = owner->config.max_frame_bytes;
    transport_config.local_physical_node_id =
        owner->config.local_physical_node_id;
    transport_config.local_runtime_instance_id =
        owner->config.local_runtime_instance_id;
    transport_config.authenticate = owner->config.authenticate;
    transport_config.authenticate_io = client->tls
                                          ? owner->config.authenticate_io
                                          : NULL;
    transport_config.authenticate_opaque = owner->config.authenticate_opaque;
    transport_config.apply = owner->config.apply;
    transport_config.apply_opaque = owner->config.apply_opaque;
    transport_config.control_apply = owner->config.control_apply;
    transport_config.control_apply_opaque = owner->config.control_apply_opaque;
    transport_config.admission_apply = owner->config.admission_apply;
    transport_config.admission_apply_opaque =
        owner->config.admission_apply_opaque;
    transport_config.dispatch = owner->config.dispatch;
    transport_config.dispatch_opaque = owner->config.dispatch_opaque;

    if (client->tls) {
        struct wvm_control_io io;

        client->ssl = SSL_new(owner->tls_context);
        if (!client->ssl || SSL_set_fd(client->ssl, client->fd) != 1 ||
            SSL_accept(client->ssl) != 1) {
            if (client->ssl) {
                SSL_free(client->ssl);
                client->ssl = NULL;
            }
            goto close_client;
        }
        io.opaque = client->ssl;
        io.read = owner_ssl_read;
        io.write = owner_ssl_write;
        transport_config.io = io;
    }

    if (wvm_control_transport_init(&transport, &transport_config, error,
                                   sizeof(error)) == 0) {
        for (;;) {
            int result = wvm_control_transport_serve_once(
                &transport, error, sizeof(error));

            if (result != WVM_CONTROL_TRANSPORT_ACCEPTED) {
                break;
            }
        }
    }
    wvm_control_transport_destroy(&transport);
close_client:
    if (client->ssl) {
        (void)SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    shutdown(client->fd, SHUT_RDWR);
    close(client->fd);

    pthread_mutex_lock(&owner->lock);
    client->done = 1;
    pthread_cond_broadcast(&owner->clients_changed);
    pthread_mutex_unlock(&owner->lock);
    return NULL;
}

static int owner_add_client(struct wvm_control_owner *owner, int client_fd,
                            int tls,
                            char *error, size_t error_len)
{
    struct wvm_control_owner_client *client;

    client = calloc(1, sizeof(*client));
    if (!client) {
        set_error(error, error_len, "control owner client allocation failed");
        close(client_fd);
        return -ENOMEM;
    }
    client->owner = owner;
    client->fd = client_fd;
    client->tls = tls;
    client->ssl = NULL;
    pthread_mutex_lock(&owner->lock);
    if (owner->stopping) {
        pthread_mutex_unlock(&owner->lock);
        close(client_fd);
        free(client);
        return -ESHUTDOWN;
    }
    client->next = owner->clients;
    owner->clients = client;
    pthread_mutex_unlock(&owner->lock);
    {
        int thread_result = pthread_create(&client->thread, NULL,
                                           owner_client_main, client);
        struct wvm_control_owner_client **cursor;

        if (thread_result == 0) {
            return 0;
        }

        pthread_mutex_lock(&owner->lock);
        cursor = &owner->clients;
        while (*cursor && *cursor != client) {
            cursor = &(*cursor)->next;
        }
        if (*cursor == client) {
            *cursor = client->next;
        }
        pthread_mutex_unlock(&owner->lock);
        close(client_fd);
        free(client);
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "control owner client thread failed: %s",
                           strerror(thread_result));
        }
        return -thread_result;
    }
}

static void *owner_listener_main(void *opaque)
{
    struct wvm_control_owner *owner = opaque;
    struct pollfd descriptors[3];

    for (;;) {
        int poll_result;

        owner_reap_completed(owner);
        memset(descriptors, 0, sizeof(descriptors));
        descriptors[0].fd = owner->listener_fd;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = owner->network_listener_fd;
        descriptors[1].events = POLLIN;
        descriptors[2].fd = owner->stop_read_fd;
        descriptors[2].events = POLLIN;
        poll_result = poll(descriptors, 3, -1);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if ((descriptors[2].revents & (POLLIN | POLLHUP | POLLERR)) != 0 ||
            owner_is_stopping(owner)) {
            break;
        }
        if ((descriptors[0].revents & POLLIN) != 0) {
            int client_fd = accept4(owner->listener_fd, NULL, NULL,
                                    SOCK_CLOEXEC);

            if (client_fd >= 0) {
                char error[256] = {0};

                (void)owner_add_client(owner, client_fd, 0, error,
                                        sizeof(error));
            } else if (errno != EINTR && owner_is_stopping(owner)) {
                break;
            }
        }
        if ((descriptors[1].revents & POLLIN) != 0 &&
            owner->network_listener_fd >= 0) {
            int client_fd = accept4(owner->network_listener_fd, NULL, NULL,
                                    SOCK_CLOEXEC);

            if (client_fd >= 0) {
                char error[256] = {0};

                (void)owner_add_client(owner, client_fd, 1, error,
                                        sizeof(error));
            }
        }
    }
    owner_reap_completed(owner);
    return NULL;
}

static int create_listener(const struct wvm_control_owner *owner,
                           char *error, size_t error_len)
{
    struct sockaddr_un address;
    struct stat existing;
    size_t path_bytes;
    socklen_t address_length;
    int listener_fd;
    int bound;

    listener_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener_fd < 0) {
        set_errno_error(error, error_len, "control owner socket failed");
        return -errno;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    path_bytes = strlen(owner->socket_path) + 1U;
    memcpy(address.sun_path, owner->socket_path, path_bytes);
    address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                 path_bytes);
    bound = bind(listener_fd, (const struct sockaddr *)&address, address_length);
    if (bound != 0 && errno == EADDRINUSE &&
        lstat(owner->socket_path, &existing) == 0 &&
        S_ISSOCK(existing.st_mode) && existing.st_uid == geteuid()) {
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

        if (probe >= 0) {
            int connected = connect(probe, (const struct sockaddr *)&address,
                                    address_length);
            int probe_error = errno;

            close(probe);
            if (connected != 0 && probe_error == ECONNREFUSED &&
                unlink(owner->socket_path) == 0) {
                bound = bind(listener_fd, (const struct sockaddr *)&address,
                             address_length);
            }
        }
    }
    if (bound != 0 ||
        chmod(owner->socket_path, owner->config.socket_mode) != 0 ||
        listen(listener_fd, owner->config.listen_backlog) != 0) {
        int saved_errno = errno;

        set_errno_error(error, error_len, "control owner bind/listen failed");
        close(listener_fd);
        return -saved_errno;
    }
    return listener_fd;
}

static int create_network_listener(const struct wvm_control_owner *owner,
                                   char *error, size_t error_len)
{
    const struct wvm_endpoint *endpoint = &owner->network_endpoint;
    struct sockaddr_storage address;
    socklen_t address_len;
    int family;
    int listener;
    int reuse = 1;

    if (endpoint->control_address_bytes == 4) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;

        memset(&address, 0, sizeof(address));
        ipv4->sin_family = AF_INET;
        memcpy(&ipv4->sin_addr, endpoint->control_address, 4);
        ipv4->sin_port = htons(endpoint->control_port);
        address_len = sizeof(*ipv4);
        family = AF_INET;
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;

        memset(&address, 0, sizeof(address));
        ipv6->sin6_family = AF_INET6;
        memcpy(&ipv6->sin6_addr, endpoint->control_address, 16);
        ipv6->sin6_port = htons(endpoint->control_port);
        address_len = sizeof(*ipv6);
        family = AF_INET6;
    }
    listener = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse,
                                    sizeof(reuse)) != 0 ||
        bind(listener, (const struct sockaddr *)&address, address_len) != 0 ||
        listen(listener, owner->config.listen_backlog) != 0) {
        int saved_errno = errno;

        if (listener >= 0) {
            close(listener);
        }
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "TLS control owner bind/listen failed: %s",
                           strerror(saved_errno));
        }
        return -saved_errno;
    }
    return listener;
}

static SSL_CTX *create_tls_context(const struct wvm_control_owner *owner,
                                   char *error, size_t error_len)
{
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());

    if (!context ||
        SSL_CTX_use_certificate_chain_file(context,
                                           owner->config.tls_certificate_file) !=
            1 ||
        SSL_CTX_use_PrivateKey_file(context, owner->config.tls_private_key_file,
                                    SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_load_verify_locations(context, owner->config.tls_ca_file, NULL) !=
            1 ||
        SSL_CTX_check_private_key(context) != 1) {
        if (context) {
            SSL_CTX_free(context);
        }
        if (error && error_len != 0) {
            unsigned long code = ERR_get_error();
            char reason[160] = {0};

            if (code != 0) {
                ERR_error_string_n(code, reason, sizeof(reason));
            }
            (void)snprintf(error, error_len, "TLS control owner identity failed%s%s",
                           reason[0] ? ": " : "", reason);
        }
        return NULL;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    return context;
}

int wvm_control_owner_init(struct wvm_control_owner *owner,
                           const struct wvm_control_owner_config *config,
                           char *error, size_t error_len)
{
    size_t path_bytes;

    if (!owner || !config || !config->socket_path ||
        config->socket_path[0] == '\0' || config->socket_mode == 0 ||
        config->listen_backlog <= 0 || config->local_physical_node_id == 0 ||
        config->local_runtime_instance_id == 0 ||
        (!config->authenticate && !config->authenticate_io) ||
        (!config->apply && !config->control_apply &&
         !config->admission_apply && !config->dispatch)) {
        set_error(error, error_len, "control owner configuration is invalid");
        return -EINVAL;
    }
    if (config->network_endpoint &&
        (config->network_endpoint->control_transport !=
             WVM_CONTROL_TRANSPORT_TLS_TCP ||
         !config->network_endpoint->has_control_address ||
         !config->tls_ca_file || !config->tls_certificate_file ||
         !config->tls_private_key_file ||
         wvm_endpoint_validate(config->network_endpoint, error, error_len) != 0)) {
        set_error(error, error_len, "TLS control owner endpoint is invalid");
        return -EINVAL;
    }
    if (config->network_endpoint && !config->authenticate_io) {
        set_error(error, error_len,
                  "TLS control owner requires certificate identity authentication");
        return -EINVAL;
    }
    path_bytes = strlen(config->socket_path);
    if (path_bytes + 1U > WVM_CONTROL_OWNER_SOCKET_PATH_MAX) {
        set_error(error, error_len, "control owner socket path is too long");
        return -ENAMETOOLONG;
    }
    memset(owner, 0, sizeof(*owner));
    owner->listener_fd = -1;
    owner->network_listener_fd = -1;
    owner->stop_read_fd = -1;
    owner->stop_write_fd = -1;
    memcpy(owner->socket_path, config->socket_path, path_bytes + 1U);
    owner->config = *config;
    if (config->network_endpoint) {
        owner->network_endpoint = *config->network_endpoint;
        owner->config.network_endpoint = &owner->network_endpoint;
    }
    owner->config.socket_path = owner->socket_path;
    if (pthread_mutex_init(&owner->lock, NULL) != 0) {
        set_error(error, error_len, "control owner mutex initialization failed");
        return -1;
    }
    owner->lock_initialized = 1;
    if (pthread_cond_init(&owner->clients_changed, NULL) != 0) {
        pthread_mutex_destroy(&owner->lock);
        owner->lock_initialized = 0;
        set_error(error, error_len,
                  "control owner condition initialization failed");
        return -1;
    }
    return 0;
}

int wvm_control_owner_start(struct wvm_control_owner *owner, char *error,
                            size_t error_len)
{
    int stop_fds[2] = {-1, -1};
    int listener_fd;

    if (!owner || !owner->lock_initialized) {
        set_error(error, error_len, "control owner is not initialized");
        return -EINVAL;
    }
    pthread_mutex_lock(&owner->lock);
    if (owner->started) {
        pthread_mutex_unlock(&owner->lock);
        set_error(error, error_len, "control owner is already running");
        return -EALREADY;
    }
    pthread_mutex_unlock(&owner->lock);
    listener_fd = create_listener(owner, error, error_len);
    if (listener_fd < 0 || pipe2(stop_fds, O_CLOEXEC) != 0) {
        int saved_errno = errno;

        if (listener_fd >= 0) {
            close(listener_fd);
        }
        if (stop_fds[0] >= 0) {
            close(stop_fds[0]);
            close(stop_fds[1]);
        }
        errno = saved_errno;
        return listener_fd < 0 ? listener_fd : -saved_errno;
    }
    owner->listener_fd = listener_fd;
    if (owner->config.network_endpoint) {
        owner->tls_context = create_tls_context(owner, error, error_len);
        if (!owner->tls_context) {
            close(listener_fd);
            unlink(owner->socket_path);
            return -EACCES;
        }
        owner->network_listener_fd =
            create_network_listener(owner, error, error_len);
        if (owner->network_listener_fd < 0) {
            SSL_CTX_free(owner->tls_context);
            owner->tls_context = NULL;
            close(listener_fd);
            unlink(owner->socket_path);
            return owner->network_listener_fd;
        }
    }
    owner->stop_read_fd = stop_fds[0];
    owner->stop_write_fd = stop_fds[1];
    pthread_mutex_lock(&owner->lock);
    owner->stopping = 0;
    owner->started = 1;
    pthread_mutex_unlock(&owner->lock);
    {
        int thread_result = pthread_create(&owner->listener_thread, NULL,
                                           owner_listener_main, owner);

        if (thread_result == 0) {
            return 0;
        }
        pthread_mutex_lock(&owner->lock);
        owner->started = 0;
        owner->stopping = 0;
        pthread_mutex_unlock(&owner->lock);
        close(owner->listener_fd);
        if (owner->network_listener_fd >= 0) {
            close(owner->network_listener_fd);
            owner->network_listener_fd = -1;
        }
        if (owner->tls_context) {
            SSL_CTX_free(owner->tls_context);
            owner->tls_context = NULL;
        }
        close(owner->stop_read_fd);
        close(owner->stop_write_fd);
        owner->listener_fd = -1;
        owner->stop_read_fd = -1;
        owner->stop_write_fd = -1;
        unlink(owner->socket_path);
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "control owner listener thread failed: %s",
                           strerror(thread_result));
        }
        return -thread_result;
    }
}

int wvm_control_owner_stop(struct wvm_control_owner *owner, char *error,
                           size_t error_len)
{
    struct wvm_control_owner_client *client;

    (void)error;
    (void)error_len;
    if (!owner || !owner->lock_initialized) {
        set_error(error, error_len, "control owner is not initialized");
        return -EINVAL;
    }
    pthread_mutex_lock(&owner->lock);
    if (!owner->started) {
        pthread_mutex_unlock(&owner->lock);
        return 0;
    }
    owner->stopping = 1;
    pthread_mutex_unlock(&owner->lock);
    if (owner->stop_write_fd >= 0) {
        uint8_t wake = 1;
        ssize_t wake_result = write(owner->stop_write_fd, &wake, sizeof(wake));

        (void)wake_result;
    }
    (void)pthread_join(owner->listener_thread, NULL);
    close(owner->listener_fd);
    owner->listener_fd = -1;
    if (owner->network_listener_fd >= 0) {
        close(owner->network_listener_fd);
        owner->network_listener_fd = -1;
    }
    if (owner->tls_context) {
        SSL_CTX_free(owner->tls_context);
        owner->tls_context = NULL;
    }
    pthread_mutex_lock(&owner->lock);
    for (client = owner->clients; client; client = client->next) {
        (void)shutdown(client->fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&owner->lock);
    for (;;) {
        pthread_mutex_lock(&owner->lock);
        client = owner->clients;
        if (client) {
            owner->clients = client->next;
        }
        pthread_mutex_unlock(&owner->lock);
        if (!client) {
            break;
        }
        (void)pthread_join(client->thread, NULL);
        free(client);
    }
    close(owner->stop_read_fd);
    close(owner->stop_write_fd);
    owner->stop_read_fd = -1;
    owner->stop_write_fd = -1;
    unlink(owner->socket_path);
    pthread_mutex_lock(&owner->lock);
    owner->started = 0;
    owner->stopping = 0;
    pthread_mutex_unlock(&owner->lock);
    return 0;
}

void wvm_control_owner_destroy(struct wvm_control_owner *owner)
{
    if (!owner) {
        return;
    }
    if (owner->lock_initialized) {
        (void)wvm_control_owner_stop(owner, NULL, 0);
        pthread_cond_destroy(&owner->clients_changed);
        pthread_mutex_destroy(&owner->lock);
    }
    if (owner->tls_context) {
        SSL_CTX_free(owner->tls_context);
    }
    memset(owner, 0, sizeof(*owner));
    owner->listener_fd = -1;
    owner->stop_read_fd = -1;
    owner->stop_write_fd = -1;
}

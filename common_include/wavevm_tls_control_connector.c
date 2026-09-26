#define _POSIX_C_SOURCE 200809L

#include "wavevm_tls_control_connector.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static void set_ssl_error(char *error, size_t error_len, const char *prefix)
{
    unsigned long code = ERR_get_error();
    char reason[160];

    if (!error || error_len == 0) {
        return;
    }
    if (code != 0) {
        ERR_error_string_n(code, reason, sizeof(reason));
        (void)snprintf(error, error_len, "%s: %s", prefix, reason);
    } else {
        (void)snprintf(error, error_len, "%s", prefix);
    }
}

static int endpoint_socket(const struct wvm_endpoint *endpoint,
                           struct sockaddr_storage *address,
                           socklen_t *address_len, int *family, char *error,
                           size_t error_len)
{
    if (!endpoint || !address || !address_len || !family ||
        !endpoint->has_control_address || endpoint->control_port == 0 ||
        (endpoint->control_address_bytes != 4 &&
         endpoint->control_address_bytes != 16)) {
        set_error(error, error_len, "TLS control endpoint address is invalid");
        return -EINVAL;
    }
    memset(address, 0, sizeof(*address));
    if (endpoint->control_address_bytes == 4) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;

        ipv4->sin_family = AF_INET;
        memcpy(&ipv4->sin_addr, endpoint->control_address, 4);
        ipv4->sin_port = htons(endpoint->control_port);
        *address_len = sizeof(*ipv4);
        *family = AF_INET;
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address;

        ipv6->sin6_family = AF_INET6;
        memcpy(&ipv6->sin6_addr, endpoint->control_address, 16);
        ipv6->sin6_port = htons(endpoint->control_port);
        *address_len = sizeof(*ipv6);
        *family = AF_INET6;
    }
    return 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *address,
                                socklen_t address_len, uint32_t timeout_ms,
                                char *error, size_t error_len)
{
    struct pollfd descriptor;
    int flags;
    int poll_result;
    int socket_error = 0;
    socklen_t socket_error_len = sizeof(socket_error);

    if (timeout_ms == 0) {
        timeout_ms = 10000U;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "cannot configure TLS control connect timeout: %s",
                           strerror(errno));
        }
        return -errno;
    }
    if (connect(fd, address, address_len) == 0) {
        (void)fcntl(fd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS && errno != EINTR) {
        int saved_errno = errno;

        (void)fcntl(fd, F_SETFL, flags);
        if (error && error_len != 0) {
            (void)snprintf(error, error_len, "TLS control connect failed: %s",
                           strerror(saved_errno));
        }
        return -saved_errno;
    }
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.fd = fd;
    descriptor.events = POLLOUT;
    do {
        poll_result = poll(&descriptor, 1, (int)timeout_ms);
    } while (poll_result < 0 && errno == EINTR);
    if (poll_result == 0) {
        (void)fcntl(fd, F_SETFL, flags);
        set_error(error, error_len, "TLS control connect timed out");
        return -ETIMEDOUT;
    }
    if (poll_result < 0) {
        int saved_errno = errno;

        (void)fcntl(fd, F_SETFL, flags);
        if (error && error_len != 0) {
            (void)snprintf(error, error_len, "TLS control connect poll failed: %s",
                           strerror(saved_errno));
        }
        return -saved_errno;
    }
    if ((descriptor.revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) == 0 ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_len) != 0 ||
        socket_error != 0) {
        int saved_errno = socket_error != 0 ? socket_error : errno;

        (void)fcntl(fd, F_SETFL, flags);
        if (saved_errno == 0) {
            saved_errno = EIO;
        }
        if (error && error_len != 0) {
            (void)snprintf(error, error_len, "TLS control connect failed: %s",
                           strerror(saved_errno));
        }
        return -saved_errno;
    }
    if (fcntl(fd, F_SETFL, flags) != 0) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "cannot restore TLS control socket flags: %s",
                           strerror(errno));
        }
        return -errno;
    }
    return 0;
}

static int open_tls_tcp(void *opaque, const struct wvm_endpoint *endpoint,
                        int *stream_fd, char *error, size_t error_len)
{
    const struct wvm_tls_control_connector *connector = opaque;
    struct sockaddr_storage address;
    socklen_t address_len;
    int family;
    int fd;
    int status;

    if (!connector || !stream_fd ||
        endpoint_socket(endpoint, &address, &address_len, &family,
                                      error, error_len) != 0) {
        return -EINVAL;
    }
    fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len, "TLS control socket failed: %s",
                           strerror(errno));
        }
        return -errno;
    }
    status = connect_with_timeout(fd, (const struct sockaddr *)&address,
                                  address_len, connector->timeout_ms, error,
                                  error_len);
    if (status != 0) {
        close(fd);
        return status;
    }
    *stream_fd = fd;
    return 0;
}

static int member_name(const struct wvm_member_key *member, char *name,
                       size_t name_len)
{
    const char *role;

    if (!member || !name || name_len == 0) {
        return -1;
    }
    switch (member->role_type) {
    case WVM_MANIFEST_ROLE_NODE_RUNTIME: role = "node-runtime"; break;
    case WVM_MANIFEST_ROLE_GATEWAY: role = "gateway"; break;
    case WVM_MANIFEST_ROLE_EXECUTOR: role = "executor"; break;
    default: return -1;
    }
    if (snprintf(name, name_len, "%s:%u:%llu", role, member->role_id,
                 (unsigned long long)member->instance_id) < 0) {
        return -1;
    }
    return name[0] == '\0' || strlen(name) >= name_len ? -1 : 0;
}

static int parse_member_name(const char *name, struct wvm_member_key *member)
{
    const char *separator;
    const char *instance_text;
    char role[32];
    char *end;
    unsigned long role_id;
    unsigned long long instance_id;

    if (!name || !member) {
        return -1;
    }
    separator = strchr(name, ':');
    if (!separator || (size_t)(separator - name) >= sizeof(role)) {
        return -1;
    }
    memcpy(role, name, (size_t)(separator - name));
    role[separator - name] = '\0';
    instance_text = strchr(separator + 1, ':');
    if (!instance_text || instance_text == separator + 1 ||
        instance_text[1] == '\0') {
        return -1;
    }
    errno = 0;
    role_id = strtoul(separator + 1, &end, 10);
    if (errno != 0 || end != instance_text || role_id == 0 ||
        role_id > UINT32_MAX) {
        return -1;
    }
    errno = 0;
    instance_id = strtoull(instance_text + 1, &end, 10);
    if (errno != 0 || *end != '\0' || instance_id == 0) {
        return -1;
    }
    memset(member, 0, sizeof(*member));
    if (strcmp(role, "node-runtime") == 0) {
        member->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    } else if (strcmp(role, "gateway") == 0) {
        member->role_type = WVM_MANIFEST_ROLE_GATEWAY;
    } else if (strcmp(role, "executor") == 0) {
        member->role_type = WVM_MANIFEST_ROLE_EXECUTOR;
    } else {
        return -1;
    }
    member->role_id = (uint32_t)role_id;
    member->instance_id = (uint64_t)instance_id;
    return 0;
}

int wvm_tls_control_peer_identity(
    const struct wvm_control_io *io, struct wvm_member_key *member,
    char *error, size_t error_len)
{
    SSL *ssl;
    X509 *certificate;
    X509_NAME *subject;
    char common_name[256];
    int common_name_bytes;

    if (!io || !io->opaque || !member) {
        set_error(error, error_len, "TLS peer identity stream is incomplete");
        return -EINVAL;
    }
    ssl = io->opaque;
    if (SSL_get_verify_result(ssl) != X509_V_OK ||
        (certificate = SSL_get1_peer_certificate(ssl)) == NULL) {
        set_error(error, error_len, "TLS peer certificate is not trusted");
        return -EACCES;
    }
    subject = X509_get_subject_name(certificate);
    common_name_bytes = subject
                            ? X509_NAME_get_text_by_NID(
                                  subject, NID_commonName, common_name,
                                  (int)sizeof(common_name))
                            : -1;
    X509_free(certificate);
    if (common_name_bytes < 0 ||
        (size_t)common_name_bytes >= sizeof(common_name) ||
        parse_member_name(common_name, member) != 0 ||
        wvm_member_key_validate(member, error, error_len) != 0) {
        set_error(error, error_len, "TLS peer certificate identity is invalid");
        return -EACCES;
    }
    return 0;
}

static int authenticate_tls(void *opaque, int stream_fd,
                            const struct wvm_member_key *expected_peer,
                            char *error, size_t error_len)
{
    struct wvm_tls_control_connector *connector = opaque;
    SSL_CTX *context;
    SSL *ssl;
    X509 *certificate;
    X509_NAME *subject;
    char expected_name[128];
    char common_name[256];
    int common_name_bytes;

    if (!connector || !expected_peer || stream_fd < 0 || !connector->ssl_context ||
        member_name(expected_peer, expected_name, sizeof(expected_name)) != 0) {
        set_error(error, error_len, "TLS control authentication is incomplete");
        return -EINVAL;
    }
    context = connector->ssl_context;
    ssl = SSL_new(context);
    if (!ssl || SSL_set_fd(ssl, stream_fd) != 1) {
        if (ssl) {
            SSL_free(ssl);
        }
        set_ssl_error(error, error_len, "cannot initialize TLS control stream");
        return -EPROTO;
    }
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        set_ssl_error(error, error_len, "TLS control handshake failed");
        return -EACCES;
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK ||
        (certificate = SSL_get1_peer_certificate(ssl)) == NULL) {
        SSL_free(ssl);
        set_error(error, error_len, "TLS control peer certificate is not trusted");
        return -EACCES;
    }
    subject = X509_get_subject_name(certificate);
    common_name_bytes = subject
                            ? X509_NAME_get_text_by_NID(
                                  subject, NID_commonName, common_name,
                                  (int)sizeof(common_name))
                            : -1;
    X509_free(certificate);
    if (common_name_bytes < 0 || (size_t)common_name_bytes >= sizeof(common_name) ||
        strcmp(common_name, expected_name) != 0) {
        SSL_free(ssl);
        set_error(error, error_len,
                  "TLS control peer identity does not match member key");
        return -EACCES;
    }
    connector->active_ssl = ssl;
    connector->active_fd = stream_fd;
    return 0;
}

static ssize_t tls_read(void *opaque, void *buffer, size_t bytes)
{
    SSL *ssl = opaque;

    return ssl ? SSL_read(ssl, buffer, (int)bytes) : -1;
}

static ssize_t tls_write(void *opaque, const void *buffer, size_t bytes)
{
    SSL *ssl = opaque;

    return ssl ? SSL_write(ssl, buffer, (int)bytes) : -1;
}

static int exchange_tls(void *opaque, const struct wvm_member_key *expected_peer,
                        const struct wvm_endpoint *endpoint,
                        const struct wvm_envelope *request,
                        struct wvm_control_result *result, char *error,
                        size_t error_len)
{
    struct wvm_tls_control_connector *connector = opaque;
    SSL *ssl;
    struct wvm_control_io io;
    int status;

    (void)endpoint;
    if (!connector || !expected_peer || !request || !result ||
        !connector->active_ssl || connector->active_fd < 0) {
        set_error(error, error_len, "TLS control exchange is not authenticated");
        return -EINVAL;
    }
    ssl = connector->active_ssl;
    io.opaque = ssl;
    io.read = tls_read;
    io.write = tls_write;
    status = wvm_control_transport_exchange_io(
        &io, expected_peer->role_id, expected_peer->instance_id, request, result,
        error, error_len);
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    connector->active_ssl = NULL;
    connector->active_fd = -1;
    return status;
}

int wvm_tls_control_connector_bind(
    struct wvm_tls_control_connector *tls_connector, const char *ca_file,
    const char *certificate_file, const char *private_key_file,
    uint32_t timeout_ms, struct wvm_control_stream_connector *connector,
    char *error, size_t error_len)
{
    SSL_CTX *context;

    if (!tls_connector || !ca_file || !certificate_file || !private_key_file ||
        !connector || ca_file[0] == '\0' || certificate_file[0] == '\0' ||
        private_key_file[0] == '\0') {
        set_error(error, error_len, "TLS control connector configuration is incomplete");
        return -EINVAL;
    }
    memset(tls_connector, 0, sizeof(*tls_connector));
    tls_connector->active_fd = -1;
    tls_connector->timeout_ms = timeout_ms;
    context = SSL_CTX_new(TLS_client_method());
    if (!context || SSL_CTX_load_verify_locations(context, ca_file, NULL) != 1 ||
        SSL_CTX_use_certificate_chain_file(context, certificate_file) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, private_key_file, SSL_FILETYPE_PEM) !=
            1 ||
        SSL_CTX_check_private_key(context) != 1) {
        if (context) {
            SSL_CTX_free(context);
        }
        set_ssl_error(error, error_len, "cannot configure TLS control identity");
        return -EACCES;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    tls_connector->ssl_context = context;
    connector->open_tls_tcp = open_tls_tcp;
    connector->opaque = tls_connector;
    connector->authenticate_tls = authenticate_tls;
    connector->authenticate_tls_opaque = tls_connector;
    connector->exchange_tls_tcp = exchange_tls;
    connector->exchange_tls_opaque = tls_connector;
    connector->timeout_ms = timeout_ms;
    return 0;
}

void wvm_tls_control_connector_destroy(
    struct wvm_tls_control_connector *tls_connector)
{
    if (!tls_connector) {
        return;
    }
    if (tls_connector->active_ssl) {
        SSL_free(tls_connector->active_ssl);
    }
    if (tls_connector->ssl_context) {
        SSL_CTX_free(tls_connector->ssl_context);
    }
    memset(tls_connector, 0, sizeof(*tls_connector));
    tls_connector->active_fd = -1;
}

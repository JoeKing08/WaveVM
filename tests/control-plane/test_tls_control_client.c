#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "wavevm_admission_stream_transport.h"
#include "wavevm_control_transport.h"
#include "wavevm_tls_control_connector.h"

struct server_context {
    const char *certificate_file;
    const char *private_key_file;
    const char *ca_file;
    struct wvm_member_key peer;
    int listener_fd;
    int result;
    char error[256];
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "TLS control client test: %s\n", message);
        return -1;
    }
    return 0;
}

static ssize_t ssl_read(void *opaque, void *buffer, size_t bytes)
{
    return SSL_read((SSL *)opaque, buffer, (int)bytes);
}

static ssize_t ssl_write(void *opaque, const void *buffer, size_t bytes)
{
    return SSL_write((SSL *)opaque, buffer, (int)bytes);
}

static int authenticate_server(void *opaque, int stream_fd,
                               struct wvm_member_key *actor, char *error,
                               size_t error_len)
{
    struct server_context *context = opaque;

    (void)stream_fd;
    (void)error;
    (void)error_len;
    if (!context || !actor) {
        return -EINVAL;
    }
    *actor = context->peer;
    return 0;
}

static int apply_stage(void *opaque, const struct wvm_envelope *request,
                       const struct wvm_member_key *actor,
                       struct wvm_control_result *result, char *error,
                       size_t error_len)
{
    struct server_context *context = opaque;

    (void)error;
    (void)error_len;
    if (!context || !request || !actor || !result ||
        memcmp(actor, &context->peer, sizeof(*actor)) != 0) {
        return -EACCES;
    }
    memset(result, 0, sizeof(*result));
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    memcpy(result->in_reply_to_operation_id, request->operation_id,
           sizeof(result->in_reply_to_operation_id));
    memcpy(result->record_digest, request->semantic_payload_digest,
           sizeof(result->record_digest));
    result->vm_id = request->vm_id;
    result->vm_incarnation = request->vm_incarnation;
    result->manifest_generation = request->manifest_generation;
    result->route_scope_id = request->route_scope_id;
    return 0;
}

static void *serve_tls(void *opaque)
{
    struct server_context *context = opaque;
    SSL_CTX *ssl_context = NULL;
    SSL *ssl = NULL;
    struct wvm_control_transport_config config;
    struct wvm_control_stream transport;
    struct wvm_control_io io;
    struct sockaddr_storage address;
    socklen_t address_bytes = sizeof(address);
    int client_fd = -1;

    client_fd = accept(context->listener_fd, NULL, NULL);
    if (client_fd < 0) {
        snprintf(context->error, sizeof(context->error), "accept failed");
        context->result = -1;
        return NULL;
    }
    ssl_context = SSL_CTX_new(TLS_server_method());
    if (!ssl_context ||
        SSL_CTX_use_certificate_file(ssl_context, context->certificate_file,
                                      SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ssl_context, context->private_key_file,
                                    SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_load_verify_locations(ssl_context, context->ca_file, NULL) !=
            1 ||
        SSL_CTX_check_private_key(ssl_context) != 1) {
        snprintf(context->error, sizeof(context->error),
                 "cannot configure TLS server");
        context->result = -1;
        goto out;
    }
    SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    ssl = SSL_new(ssl_context);
    if (!ssl || SSL_set_fd(ssl, client_fd) != 1 || SSL_accept(ssl) != 1) {
        snprintf(context->error, sizeof(context->error),
                 "TLS server handshake failed");
        context->result = -1;
        goto out;
    }
    memset(&config, 0, sizeof(config));
    config.stream_fd = client_fd;
    config.local_physical_node_id = context->peer.role_id;
    config.local_runtime_instance_id = context->peer.instance_id;
    config.authenticate = authenticate_server;
    config.authenticate_opaque = context;
    config.admission_apply = apply_stage;
    config.admission_apply_opaque = context;
    io.opaque = ssl;
    io.read = ssl_read;
    io.write = ssl_write;
    config.io = io;
    if (wvm_control_transport_init(&transport, &config, context->error,
                                   sizeof(context->error)) != 0 ||
        wvm_control_transport_serve_once(&transport, context->error,
                                          sizeof(context->error)) !=
            WVM_CONTROL_TRANSPORT_ACCEPTED) {
        context->result = -1;
        goto out;
    }
    context->result = 0;
out:
    if (ssl) {
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (client_fd >= 0) {
        close(client_fd);
    }
    if (ssl_context) {
        SSL_CTX_free(ssl_context);
    }
    (void)getsockname(context->listener_fd, (struct sockaddr *)&address,
                      &address_bytes);
    return NULL;
}

static void fill_request(struct wvm_envelope *request)
{
    static const uint8_t payload[] = {0x21, 0x22};

    memset(request, 0, sizeof(*request));
    request->message_type = WVM_ENVELOPE_MSG_PREPARE_MANIFEST;
    request->origin_physical_node_id = 700;
    request->origin_runtime_instance_id = 701;
    request->vm_id = 256;
    request->vm_incarnation = 2;
    request->manifest_generation = 3;
    request->route_scope_id = 4;
    request->topology_revision = 5;
    request->route_generation = 6;
    memset(request->route_snapshot_digest, 0x44,
           sizeof(request->route_snapshot_digest));
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1U] = 7;
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = sizeof(payload);
    wvm_envelope_semantic_digest(payload, sizeof(payload),
                                 request->semantic_payload_digest);
}

int main(int argc, char **argv)
{
    struct server_context server;
    struct wvm_tls_control_connector tls_connector;
    struct wvm_control_stream_connector connector;
    struct wvm_control_stream_client client;
    struct wvm_admission_stream_transport admission_transport;
    struct wvm_admission_transport_target target;
    struct wvm_endpoint endpoint;
    struct wvm_envelope request;
    struct wvm_control_result result;
    struct sockaddr_in address;
    socklen_t address_bytes = sizeof(address);
    pthread_t thread;
    char error[256] = {0};
    int listener = -1;
    int status = 1;

    signal(SIGPIPE, SIG_IGN);

    if (argc != 4) {
        fprintf(stderr, "usage: %s CA CERT KEY\n", argv[0]);
        return 2;
    }
    memset(&server, 0, sizeof(server));
    server.certificate_file = argv[2];
    server.private_key_file = argv[3];
    server.ca_file = argv[1];
    server.peer.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    server.peer.role_id = 900;
    server.peer.instance_id = 901;
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &address_bytes) != 0) {
        close(listener);
        return 1;
    }
    server.listener_fd = listener;
    if (pthread_create(&thread, NULL, serve_tls, &server) != 0) {
        close(listener);
        return 1;
    }
    memset(&connector, 0, sizeof(connector));
    if (wvm_tls_control_connector_bind(&tls_connector, argv[1], argv[2], argv[3],
                                       2000, &connector, error,
                                       sizeof(error)) != 0) {
        goto out_thread;
    }
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint.data_address_bytes = 4;
    endpoint.data_address[0] = 127;
    endpoint.data_address[3] = 1;
    endpoint.data_port = 19000;
    endpoint.control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint.has_control_address = 1;
    endpoint.control_address_bytes = 4;
    endpoint.control_address[0] = 127;
    endpoint.control_address[3] = 1;
    endpoint.control_port = ntohs(address.sin_port);
    memset(&target, 0, sizeof(target));
    target.member_key = server.peer;
    target.endpoint = endpoint;
    fill_request(&request);
    if (wvm_control_stream_client_init(&client, &connector, error,
                                       sizeof(error)) != 0 ||
        wvm_admission_stream_transport_init(&admission_transport, &connector,
                                            error, sizeof(error)) != 0 ||
        wvm_admission_stream_transport_submit(
            &admission_transport, &target, &request, error, sizeof(error)) != 0 ||
        expect(server.result == 0, "authenticated TLS exchange completed") != 0) {
        goto out_client;
    }
    memset(&result, 0, sizeof(result));
    status = 0;
out_client:
    wvm_admission_stream_transport_destroy(&admission_transport);
    wvm_control_stream_client_destroy(&client);
    wvm_tls_control_connector_destroy(&tls_connector);
out_thread:
    (void)pthread_join(thread, NULL);
    close(listener);
    if (status != 0) {
        fprintf(stderr, "TLS control client test: %s%s\n", error,
                server.error[0] ? server.error : "");
    }
    return status;
}

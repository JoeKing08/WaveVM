#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_admission_node_service.h"
#include "wavevm_admission_stream_transport.h"
#include "wavevm_tls_control_connector.h"

struct authentication_context {
    struct wvm_member_key controller;
};

static int member_equal(const struct wvm_member_key *left,
                        const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authenticate_unix(void *opaque, int stream_fd,
                             struct wvm_member_key *actor, char *error,
                             size_t error_len)
{
    struct authentication_context *context = opaque;
    struct ucred credentials;
    socklen_t bytes = sizeof(credentials);

    (void)error;
    (void)error_len;
    if (!context || !actor ||
        getsockopt(stream_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &bytes) !=
            0 ||
        credentials.uid != getuid()) {
        return -EACCES;
    }
    *actor = context->controller;
    return 0;
}

static int authenticate_tls(void *opaque, int stream_fd,
                            const struct wvm_control_io *io,
                            struct wvm_member_key *actor, char *error,
                            size_t error_len)
{
    struct authentication_context *context = opaque;
    struct wvm_member_key peer;

    (void)stream_fd;
    if (!context || !actor ||
        wvm_tls_control_peer_identity(io, &peer, error, error_len) != 0 ||
        !member_equal(&peer, &context->controller)) {
        return -EACCES;
    }
    *actor = peer;
    return 0;
}

static void fill_request(struct wvm_envelope *request)
{
    static const uint8_t payload[] = {0x01};

    memset(request, 0, sizeof(*request));
    request->message_type = WVM_ENVELOPE_MSG_PREPARE_MANIFEST;
    request->origin_physical_node_id = 701;
    request->origin_runtime_instance_id = 702;
    request->vm_id = 9001;
    request->vm_incarnation = 1;
    request->manifest_generation = 1;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1U] = 1;
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = sizeof(payload);
    wvm_envelope_semantic_digest(payload, sizeof(payload),
                                 request->semantic_payload_digest);
}

int main(int argc, char **argv)
{
    struct wvm_admission_node_service service;
    struct wvm_admission_node_service_config config;
    struct authentication_context authentication;
    struct wvm_tls_control_connector connector_state;
    struct wvm_control_stream_connector connector;
    struct wvm_admission_stream_transport transport;
    struct wvm_admission_transport_target target;
    struct wvm_endpoint endpoint;
    struct wvm_envelope request;
    struct in_addr address;
    char socket_path[] = "/tmp/wavevm-tls-admission.XXXXXX";
    char error[256] = {0};
    int directory_fd;
    int transport_initialized = 0;
    int service_initialized = 0;
    int status = 1;

    if (argc != 7 || inet_pton(AF_INET, "127.0.0.1", &address) != 1) {
        return 2;
    }
    directory_fd = mkstemp(socket_path);
    if (directory_fd < 0) {
        return 1;
    }
    close(directory_fd);
    unlink(socket_path);
    memset(&authentication, 0, sizeof(authentication));
    authentication.controller.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    authentication.controller.role_id = 701;
    authentication.controller.instance_id = 702;
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint.data_address_bytes = 4;
    endpoint.data_port = 1;
    endpoint.control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint.has_control_address = 1;
    endpoint.control_address_bytes = 4;
    memcpy(endpoint.data_address, &address, 4);
    memcpy(endpoint.control_address, &address, 4);
    endpoint.control_port = (uint16_t)strtoul(argv[1], NULL, 10);
    memset(&config, 0, sizeof(config));
    config.socket_path = socket_path;
    config.socket_mode = S_IRUSR | S_IWUSR;
    config.listen_backlog = 4;
    config.local_physical_node_id = 801;
    config.local_runtime_instance_id = 802;
    config.max_frame_bytes = WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    config.network_endpoint = &endpoint;
    config.tls_ca_file = argv[2];
    config.tls_certificate_file = argv[3];
    config.tls_private_key_file = argv[4];
    config.authenticate = authenticate_unix;
    config.authenticate_io = authenticate_tls;
    config.authenticate_opaque = &authentication;
    config.receiver.controller_member_key = authentication.controller;
    config.receiver.controller_physical_node_id = 701;
    config.receiver.controller_runtime_instance_id = 702;
    config.receiver.local_physical_node_id = 801;
    config.receiver.local_node_instance_id = 802;
    if (wvm_admission_node_service_init(&service, &config, error,
                                        sizeof(error)) != 0 ||
        wvm_admission_node_service_start(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "TLS admission node service: %s\n", error);
        goto out;
    }
    service_initialized = 1;
    memset(&connector, 0, sizeof(connector));
    if (wvm_tls_control_connector_bind(&connector_state, argv[2], argv[5],
                                       argv[6], 2000, &connector, error,
                                       sizeof(error)) != 0 ||
        wvm_admission_stream_transport_init(&transport, &connector, error,
                                            sizeof(error)) != 0) {
        goto stop;
    }
    transport_initialized = 1;
    memset(&target, 0, sizeof(target));
    target.member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    target.member_key.role_id = 801;
    target.member_key.instance_id = 802;
    target.endpoint = endpoint;
    fill_request(&request);
    if (wvm_admission_stream_transport_submit(&transport, &target, &request,
                                               error, sizeof(error)) != -EACCES) {
        fprintf(stderr, "TLS admission node service: unexpected result: %s\n",
                error);
        goto stop;
    }
    status = 0;
stop:
    if (transport_initialized) {
        wvm_admission_stream_transport_destroy(&transport);
    }
    wvm_tls_control_connector_destroy(&connector_state);
    if (service_initialized) {
        (void)wvm_admission_node_service_stop(&service, error, sizeof(error));
        wvm_admission_node_service_destroy(&service);
    }
out:
    unlink(socket_path);
    return status;
}

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stddef.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_admission_stream_transport.h"
#include "wavevm_control_client.h"
#include "wavevm_unix_control_connector.h"

struct server_context {
    struct wvm_control_stream *transport;
    const struct wvm_member_key *expected_peer;
    uint16_t recorded_state;
    int result;
    char error[256];
};

struct connector_context {
    int client_fd;
    unsigned int open_calls;
    unsigned int authenticate_calls;
    int reject_peer;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "control client test: %s\n", message);
        return -1;
    }
    return 0;
}

static void *serve_one(void *opaque)
{
    struct server_context *context = opaque;

    context->result = wvm_control_transport_serve_once(
        context->transport, context->error, sizeof(context->error));
    return NULL;
}

static int authenticate_server(void *opaque, int stream_fd,
                               struct wvm_member_key *actor, char *error,
                               size_t error_len)
{
    const struct server_context *context = opaque;

    (void)stream_fd;
    (void)error;
    (void)error_len;
    if (!context || !context->expected_peer || !actor) {
        return -1;
    }
    *actor = *context->expected_peer;
    return 0;
}

static int apply_stage(void *opaque, const struct wvm_envelope *request,
                       const struct wvm_member_key *actor,
                       struct wvm_control_result *result, char *error,
                       size_t error_len)
{
    const struct server_context *context = opaque;
    const struct wvm_member_key *expected =
        context ? context->expected_peer : NULL;

    (void)error;
    (void)error_len;
    if (!expected || !request || !actor || !result ||
        actor->role_type != expected->role_type ||
        actor->role_id != expected->role_id ||
        actor->instance_id != expected->instance_id) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    result->recorded_state = context->recorded_state;
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

static int open_socketpair_peer(void *opaque, const struct wvm_endpoint *endpoint,
                                int *stream_fd, char *error, size_t error_len)
{
    struct connector_context *context = opaque;

    (void)error;
    (void)error_len;
    if (!context || !endpoint || !stream_fd ||
        endpoint->control_transport != WVM_CONTROL_TRANSPORT_UNIX_STREAM ||
        context->client_fd < 0) {
        return -1;
    }
    *stream_fd = dup(context->client_fd);
    if (*stream_fd < 0) {
        return -errno;
    }
    context->open_calls++;
    return 0;
}

static int authenticate_peer(void *opaque, int stream_fd,
                             const struct wvm_member_key *expected_peer,
                             char *error, size_t error_len)
{
    struct connector_context *context = opaque;

    (void)stream_fd;
    (void)error;
    (void)error_len;
    if (!context || !expected_peer) {
        return -1;
    }
    context->authenticate_calls++;
    return context->reject_peer ? -1 : 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint,
                          enum wvm_control_transport transport)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 127;
    endpoint->data_address[3] = 1;
    endpoint->data_port = 19000;
    endpoint->control_transport = transport;
    endpoint->control_port = 19001;
    if (transport == WVM_CONTROL_TRANSPORT_UNIX_STREAM) {
        endpoint->has_control_socket_path = 1;
        snprintf(endpoint->control_socket_path,
                 sizeof(endpoint->control_socket_path),
                 "/tmp/wavevm-control-client.sock");
    }
}

static void fill_request(struct wvm_envelope *request)
{
    static const uint8_t payload[] = {0x11, 0x22, 0x33};

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
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = 9;
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = sizeof(payload);
    wvm_envelope_semantic_digest(payload, sizeof(payload),
                                 request->semantic_payload_digest);
}

static int run_authenticated_exchange(uint16_t message_type,
                                      uint16_t recorded_state,
                                      int expected_submit_result)
{
    struct wvm_member_key peer = {
        .role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME,
        .role_id = 900,
        .instance_id = 901,
    };
    struct connector_context connector_context = {-1, 0, 0, 0};
    struct wvm_control_stream_connector connector = {0};
    struct wvm_control_stream_client client;
    struct wvm_admission_stream_transport admission_transport;
    struct wvm_admission_transport_target target;
    struct wvm_control_transport_config server_config = {0};
    struct wvm_control_stream server_transport;
    struct server_context server = {0};
    struct wvm_envelope request;
    struct wvm_endpoint endpoint;
    pthread_t thread;
    int sockets[2] = {-1, -1};
    int admission_initialized = 0;
    char error[256] = {0};
    int status = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return -1;
    }
    connector_context.client_fd = sockets[1];
    connector.opaque = &connector_context;
    connector.open_unix_stream = open_socketpair_peer;
    connector.authenticate_peer = authenticate_peer;
    connector.timeout_ms = 1000;
    server_config.stream_fd = sockets[0];
    server_config.local_physical_node_id = peer.role_id;
    server_config.local_runtime_instance_id = peer.instance_id;
    server_config.authenticate = authenticate_server;
    server.expected_peer = &peer;
    server.recorded_state = recorded_state;
    server_config.authenticate_opaque = &server;
    server_config.admission_apply = apply_stage;
    server_config.admission_apply_opaque = &server;
    fill_endpoint(&endpoint, WVM_CONTROL_TRANSPORT_UNIX_STREAM);
    fill_request(&request);
    request.message_type = message_type;
    if (wvm_control_transport_init(&server_transport, &server_config, error,
                                   sizeof(error)) != 0 ||
        wvm_control_stream_client_init(&client, &connector, error,
                                       sizeof(error)) != 0) {
        goto out;
    }
    server.transport = &server_transport;
    memset(&target, 0, sizeof(target));
    target.member_key = peer;
    target.endpoint = endpoint;
    if (wvm_admission_stream_transport_init(
            &admission_transport, &connector, error, sizeof(error)) != 0) {
        goto out_client;
    }
    admission_initialized = 1;
    if (pthread_create(&thread, NULL, serve_one, &server) != 0) {
        goto out_client;
    }
    {
        int submit_result = wvm_admission_stream_transport_submit(
            &admission_transport, &target, &request, error, sizeof(error));
        int join_result = pthread_join(thread, NULL);

        if (submit_result != expected_submit_result || join_result != 0 ||
            expect(server.result == WVM_CONTROL_TRANSPORT_ACCEPTED,
                   "server accepts authenticated stream request") != 0 ||
            expect(connector_context.open_calls == 1 &&
                       connector_context.authenticate_calls == 1,
                   "client opens and authenticates the admission stream") != 0) {
            goto out_client;
        }
    }
    wvm_admission_stream_transport_destroy(&admission_transport);
    admission_initialized = 0;
    status = 0;
out_client:
    if (admission_initialized) {
        wvm_admission_stream_transport_destroy(&admission_transport);
    }
    wvm_control_stream_client_destroy(&client);
out:
    if (status != 0 && error[0] != '\0') {
        fprintf(stderr, "control client test: %s\n", error);
    }
    close(sockets[0]);
    close(sockets[1]);
    return status;
}

static int test_authenticated_exchange(void)
{
    return run_authenticated_exchange(WVM_ENVELOPE_MSG_PREPARE_MANIFEST, 0,
                                      0) == 0 &&
                   run_authenticated_exchange(
                       WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY,
                       WVM_LIFECYCLE_COMMITTED, 0) == 0 &&
                   run_authenticated_exchange(
                       WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY,
                       WVM_LIFECYCLE_PARTICIPANTS_PREPARED, -EPROTO) == 0
               ? 0
               : -1;
}

static int test_fail_closed_connector_selection(void)
{
    struct connector_context context = {-1, 0, 0, 0};
    struct wvm_control_stream_connector connector = {
        .opaque = &context,
        .open_unix_stream = open_socketpair_peer,
        .authenticate_peer = authenticate_peer,
    };
    struct wvm_control_stream_client client;
    struct wvm_member_key peer = {
        .role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME,
        .role_id = 900,
        .instance_id = 901,
    };
    struct wvm_endpoint endpoint;
    struct wvm_envelope request;
    struct wvm_control_result result;
    char error[256] = {0};

    fill_endpoint(&endpoint, WVM_CONTROL_TRANSPORT_TLS_TCP);
    fill_request(&request);
    memset(&result, 0xa5, sizeof(result));
    if (wvm_control_stream_client_init(&client, &connector, error,
                                       sizeof(error)) != 0 ||
        expect(wvm_control_stream_client_exchange(
                   &client, &peer, &endpoint, &request, &result, error,
                   sizeof(error)) == -EOPNOTSUPP,
               "missing TLS connector fails closed") != 0 ||
        expect(context.open_calls == 0,
               "unsupported connector does not open a raw stream") != 0) {
        wvm_control_stream_client_destroy(&client);
        return -1;
    }
    wvm_control_stream_client_destroy(&client);
    return 0;
}

static int authorize_current_user(void *opaque,
                                  const struct wvm_member_key *expected_peer,
                                  const struct wvm_unix_peer_credentials *peer,
                                  char *error, size_t error_len)
{
    const struct wvm_member_key *allowed = opaque;

    (void)error;
    (void)error_len;
    return allowed && expected_peer && peer &&
                   allowed->role_type == expected_peer->role_type &&
                   allowed->role_id == expected_peer->role_id &&
                   allowed->instance_id == expected_peer->instance_id &&
                   peer->user_id == getuid() && peer->process_id > 0
               ? 0
               : -EACCES;
}

static int test_real_unix_connector_and_peer_credentials(void)
{
    struct wvm_unix_control_connector unix_connector;
    struct wvm_control_stream_connector connector;
    struct wvm_member_key peer = {
        .role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME,
        .role_id = 900,
        .instance_id = 901,
    };
    struct wvm_endpoint endpoint;
    struct wvm_endpoint decoded_endpoint;
    struct wvm_endpoint invalid_endpoint;
    struct sockaddr_un address;
    uint8_t encoded_endpoint[512];
    size_t encoded_endpoint_bytes = 0;
    char directory[] = "/tmp/wavevm-control-client.XXXXXX";
    int listener = -1;
    int client = -1;
    int accepted = -1;
    char error[256] = {0};
    int status = -1;

    if (!mkdtemp(directory)) {
        return -1;
    }
    fill_endpoint(&endpoint, WVM_CONTROL_TRANSPORT_UNIX_STREAM);
    if (snprintf(endpoint.control_socket_path,
                 sizeof(endpoint.control_socket_path), "%s/peer.sock",
                 directory) < 0 ||
        wvm_endpoint_validate(&endpoint, error, sizeof(error)) != 0 ||
        wvm_endpoint_encode(&endpoint, encoded_endpoint,
                            sizeof(encoded_endpoint),
                            &encoded_endpoint_bytes, error, sizeof(error)) != 0 ||
        wvm_endpoint_decode(encoded_endpoint, encoded_endpoint_bytes,
                            &decoded_endpoint, error, sizeof(error)) != 0 ||
        !decoded_endpoint.has_control_socket_path ||
        strcmp(decoded_endpoint.control_socket_path,
               endpoint.control_socket_path) != 0 ||
        wvm_unix_control_connector_bind(&unix_connector,
                                       authorize_current_user, &peer, 1000,
                                       &connector, error, sizeof(error)) != 0) {
        goto out;
    }
    invalid_endpoint = endpoint;
    invalid_endpoint.has_control_socket_path = 0;
    invalid_endpoint.control_socket_path[0] = '\0';
    if (expect(wvm_endpoint_validate(&invalid_endpoint, error, sizeof(error)) !=
                   0,
               "Unix endpoints require an explicit socket path") != 0) {
        goto out;
    }
    invalid_endpoint = endpoint;
    invalid_endpoint.control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    if (expect(wvm_endpoint_validate(&invalid_endpoint, error, sizeof(error)) !=
                   0,
               "network endpoints reject Unix socket paths") != 0) {
        goto out;
    }
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        goto out;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s",
             endpoint.control_socket_path);
    if (bind(listener, (const struct sockaddr *)&address,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                         strlen(address.sun_path) + 1U)) != 0 ||
        listen(listener, 1) != 0 ||
        connector.open_unix_stream(connector.opaque, &endpoint, &client,
                                   error, sizeof(error)) != 0) {
        goto out;
    }
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0 ||
        connector.authenticate_peer(connector.opaque, client, &peer, error,
                                     sizeof(error)) != 0 ||
        expect(connector.authenticate_peer(
                   connector.opaque, client,
                   &(struct wvm_member_key){
                       .role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME,
                       .role_id = 900,
                       .instance_id = 902,
                   },
                   error, sizeof(error)) != 0,
               "Unix peer credentials reject an unexpected member instance") !=
            0) {
        goto out;
    }
    status = 0;
out:
    if (accepted >= 0) {
        close(accepted);
    }
    if (client >= 0) {
        close(client);
    }
    if (listener >= 0) {
        close(listener);
    }
    unlink(endpoint.control_socket_path);
    rmdir(directory);
    if (status != 0 && error[0] != '\0') {
        fprintf(stderr, "control client test: %s\n", error);
    }
    return status;
}

int main(void)
{
    if (test_authenticated_exchange() != 0 ||
        test_fail_closed_connector_selection() != 0 ||
        test_real_unix_connector_and_peer_credentials() != 0) {
        return 1;
    }
    puts("control client tests: PASS");
    return 0;
}

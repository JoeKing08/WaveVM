#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "wavevm_control_plane.h"
#include "wavevm_control_transport.h"

#define MIB (1024ULL * 1024ULL)

struct authorization_context {
    unsigned int calls;
};

struct authentication_context {
    struct wvm_member_key actor;
    unsigned int calls;
    int reject;
};

struct serve_context {
    struct wvm_control_stream *transport;
    int result;
    char error[256];
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "control transport test: %s\n", message);
        return -1;
    }
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authorize_self(
    void *context, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    struct authorization_context *authorization = context;

    (void)action;
    (void)error;
    (void)error_len;
    if (!authorization || !member_key_equal(actor, subject)) {
        return -1;
    }
    authorization->calls++;
    return 0;
}

static int authenticate_actor(void *opaque, int stream_fd,
                              struct wvm_member_key *actor, char *error,
                              size_t error_len)
{
    struct authentication_context *context = opaque;

    (void)stream_fd;
    (void)error;
    (void)error_len;
    if (!context || !actor || context->reject) {
        return -1;
    }
    *actor = context->actor;
    context->calls++;
    return 0;
}

static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static int write_bytes_fragmented(int fd, const uint8_t *bytes, size_t count)
{
    size_t offset = 0;

    while (offset < count) {
        ssize_t written = write(fd, bytes + offset, 1);

        if (written == 1) {
            offset++;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int read_bytes(int fd, uint8_t *bytes, size_t count)
{
    size_t offset = 0;

    while (offset < count) {
        ssize_t read_count = read(fd, bytes + offset, count - offset);

        if (read_count > 0) {
            offset += (size_t)read_count;
        } else if (read_count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int send_request(int fd, const struct wvm_envelope *request,
                        char *error, size_t error_len);
static int receive_result(int fd, struct wvm_membership_control_result *result,
                          char *error, size_t error_len);

static void *serve_one_request(void *opaque)
{
    struct serve_context *context = opaque;

    context->result = wvm_control_transport_serve_once(
        context->transport, context->error, sizeof(context->error));
    return NULL;
}

static int start_serve(struct serve_context *context, pthread_t *thread,
                       struct wvm_control_stream *transport)
{
    if (!context || !thread || !transport) {
        return -1;
    }
    memset(context, 0, sizeof(*context));
    context->transport = transport;
    return pthread_create(thread, NULL, serve_one_request, context);
}

static int exchange_request(
    struct wvm_control_stream *transport, int client_fd,
    const struct wvm_envelope *request,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    struct serve_context server;
    pthread_t thread;
    int join_result;

    if (start_serve(&server, &thread, transport) != 0) {
        return -1;
    }
    if (send_request(client_fd, request, error, error_len) != 0 ||
        receive_result(client_fd, result, error, error_len) != 0) {
        shutdown(client_fd, SHUT_RDWR);
        (void)pthread_join(thread, NULL);
        return -1;
    }
    join_result = pthread_join(thread, NULL);
    if (join_result != 0 || server.result != WVM_CONTROL_TRANSPORT_ACCEPTED) {
        if (error && error_len != 0 && error[0] == '\0') {
            snprintf(error, error_len, "%s",
                     server.error[0] != '\0'
                         ? server.error
                         : "control stream server rejected request");
        }
        return -1;
    }
    return 0;
}

static int exchange_raw_frame(struct wvm_control_stream *transport,
                              int client_fd, const uint8_t *prefix,
                              const uint8_t *frame, size_t frame_bytes)
{
    struct serve_context server;
    pthread_t thread;
    int join_result;

    if (start_serve(&server, &thread, transport) != 0 ||
        write_bytes_fragmented(client_fd, prefix,
                               WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES) !=
            0 ||
        (frame_bytes != 0 &&
         write_bytes_fragmented(client_fd, frame, frame_bytes) != 0)) {
        return -1;
    }
    join_result = pthread_join(thread, NULL);
    return join_result == 0 ? server.result : -1;
}

static int send_request(int fd, const struct wvm_envelope *request,
                        char *error, size_t error_len)
{
    uint8_t frame[WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES];
    uint8_t prefix[WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES];
    size_t frame_bytes = 0;

    if (wvm_envelope_encode(request, WVM_ENVELOPE_TRANSPORT_LOCAL, frame,
                            sizeof(frame), &frame_bytes, error, error_len) != 0 ||
        frame_bytes > UINT32_MAX) {
        return -1;
    }
    write_be32(prefix, (uint32_t)frame_bytes);
    return write_bytes_fragmented(fd, prefix, sizeof(prefix)) != 0 ||
                   write_bytes_fragmented(fd, frame, frame_bytes) != 0
               ? -1
               : 0;
}

static int receive_result(int fd, struct wvm_membership_control_result *result,
                          char *error, size_t error_len)
{
    uint8_t prefix[WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES];
    uint8_t frame[WVM_ENVELOPE_HEADER_BYTES +
                  WVM_MEMBERSHIP_CONTROL_RESULT_BYTES];
    struct wvm_envelope response;
    uint32_t frame_bytes;

    if (read_bytes(fd, prefix, sizeof(prefix)) != 0) {
        return -1;
    }
    frame_bytes = read_be32(prefix);
    if (frame_bytes > sizeof(frame) || frame_bytes < WVM_ENVELOPE_HEADER_BYTES ||
        read_bytes(fd, frame, frame_bytes) != 0 ||
        wvm_envelope_decode(frame, frame_bytes, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            &response, error, error_len) != 0 ||
        response.message_type != WVM_ENVELOPE_MSG_CTRL_RESULT ||
        response.vm_id != 0 ||
        response.payload_bytes != WVM_MEMBERSHIP_CONTROL_RESULT_BYTES ||
        wvm_membership_control_result_decode(response.payload, result) != 0) {
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = 17;
    endpoint->data_port = 19120;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = 19121;
}

static void fill_node(struct wvm_node_record *node)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = 17;
    node->node_instance_id = 101;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint);
    fill_endpoint(&node->sidecar_endpoint);
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = node->physical_node_id;
    node->inventory.node_instance_id = node->node_instance_id;
    node->inventory.failure_domain_id = node->failure_domain_id;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * MIB;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = 1 * MIB;
    node->inventory.reserved_gateway_cpu_slots = 1;
    node->inventory.reserved_gateway_memory_bytes = 1 * MIB;
    node->inventory.allocatable_vcpu_slots = 6;
    node->inventory.allocatable_memory_bytes = 14 * MIB;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = node->physical_node_id;
    node->capability.node_instance_id = node->node_instance_id;
    node->capability.profile_generation = 1;
    memset(node->capability.profile_digest, 0x21,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
}

static void make_register_request(struct wvm_envelope *request,
                                  const uint8_t *payload, size_t payload_bytes,
                                  uint8_t operation_id)
{
    memset(request, 0, sizeof(*request));
    request->message_type = WVM_ENVELOPE_MSG_REGISTER_MEMBER;
    request->origin_physical_node_id = 17;
    request->origin_runtime_instance_id = 101;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_id;
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = payload_bytes;
}

static int configure_owner(
    struct wvm_control_plane *plane, struct wvm_control_plane_entry *entries,
    struct wvm_membership_controller_member_entry *members,
    struct wvm_membership_controller_route_entry *routes,
    struct wvm_membership_dependency *dependencies,
    struct wvm_membership_control_operation *operations,
    const char *membership_path, const char *control_path,
    struct authorization_context *authorization, char *error, size_t error_len)
{
    struct wvm_control_plane_membership_config config;

    memset(&config, 0, sizeof(config));
    config.members = members;
    config.member_capacity = 2;
    config.routes = routes;
    config.route_capacity = 2;
    config.dependencies = dependencies;
    config.dependency_capacity = 2;
    config.operations = operations;
    config.operation_capacity = 4;
    config.membership_journal_path = membership_path;
    config.control_journal_path = control_path;
    config.authorize = authorize_self;
    config.authorize_context = authorization;
    config.result_sink = NULL;
    config.result_sink_context = NULL;
    wvm_control_plane_init(plane, entries, 1);
    if (wvm_control_plane_configure_membership(plane, &config, error,
                                                error_len) != 0 ||
        wvm_control_plane_open_membership(plane, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

struct typed_apply_context {
    unsigned int calls;
    uint16_t status;
};

/* Transport fixture only; no participant persistence is simulated here. */
static int apply_typed_request(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *actor, struct wvm_control_result *result,
    char *error, size_t error_len)
{
    struct typed_apply_context *context = opaque;

    (void)actor;
    (void)error;
    (void)error_len;
    context->calls++;
    memset(result, 0, sizeof(*result));
    result->status_code = context->status;
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

static void fill_stage_request(struct wvm_envelope *request, uint16_t type);

static int test_admission_dispatch_owner(void)
{
    struct authentication_context authentication = {0};
    struct typed_apply_context ordinary = {0};
    struct typed_apply_context admission = {0};
    struct wvm_control_transport_config config = {0};
    struct wvm_control_stream transport;
    struct wvm_envelope request;
    struct wvm_control_result result;
    struct serve_context server;
    pthread_t thread;
    int sockets[2] = {-1, -1};
    char error[256] = {0};
    int status = -1;

    authentication.actor.role_type = WVM_MANIFEST_ROLE_EXECUTOR;
    authentication.actor.role_id = 41;
    authentication.actor.instance_id = 42;
    admission.status = WVM_CONTROL_RESULT_SUCCESS;
    ordinary.status = WVM_CONTROL_RESULT_SUCCESS;
    fill_stage_request(&request, WVM_ENVELOPE_MSG_PREPARE_MANIFEST);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return -1;
    }
    config.stream_fd = sockets[0];
    config.local_physical_node_id = 900;
    config.local_runtime_instance_id = 901;
    config.authenticate = authenticate_actor;
    config.authenticate_opaque = &authentication;
    config.control_apply = apply_typed_request;
    config.control_apply_opaque = &ordinary;
    config.admission_apply = apply_typed_request;
    config.admission_apply_opaque = &admission;
    if (wvm_control_transport_init(&transport, &config, error,
                                   sizeof(error)) != 0 ||
        start_serve(&server, &thread, &transport) != 0 ||
        wvm_control_transport_exchange(sockets[1], 900, 901, &request,
                                       &result, error, sizeof(error)) != 0 ||
        pthread_join(thread, NULL) != 0 ||
        expect(result.status_code == WVM_CONTROL_RESULT_SUCCESS,
               "admission stage returns receiver result") ||
        expect(admission.calls == 1 && ordinary.calls == 0,
               "admission stage uses its dedicated owner")) {
        goto out;
    }
    transport.config.admission_apply = NULL;
    if (start_serve(&server, &thread, &transport) != 0 ||
        wvm_control_transport_exchange(sockets[1], 900, 901, &request,
                                       &result, error, sizeof(error)) != 0 ||
        pthread_join(thread, NULL) != 0 ||
        expect(result.status_code == WVM_CONTROL_RESULT_UNSUPPORTED,
               "missing admission owner fails closed") ||
        expect(admission.calls == 1 && ordinary.calls == 0,
               "missing admission owner does not fall through")) {
        goto out;
    }
    status = 0;
out:
    wvm_control_transport_destroy(&transport);
    close(sockets[0]);
    close(sockets[1]);
    if (status != 0 && error[0] != '\0') {
        fprintf(stderr, "control transport test: %s\n", error);
    }
    return status;
}

static void fill_stage_request(struct wvm_envelope *request, uint16_t type)
{
    static const uint8_t payload[] = {1, 2, 3};

    make_register_request(request, payload, sizeof(payload), 7);
    request->message_type = type;
    if (type != WVM_ENVELOPE_MSG_CREATE_VM) {
        request->vm_id = 256;
        request->vm_incarnation = 2;
        request->manifest_generation = 3;
        request->route_scope_id = 4;
        request->topology_revision = 5;
        request->route_generation = 6;
        memset(request->route_snapshot_digest, 0x27,
               sizeof(request->route_snapshot_digest));
    }
    wvm_envelope_semantic_digest(payload, sizeof(payload),
                                 request->semantic_payload_digest);
}

static int test_typed_exchange(void)
{
    const uint16_t types[] = {
        WVM_ENVELOPE_MSG_CREATE_VM,
        WVM_ENVELOPE_MSG_PREPARE_RESERVATION,
        WVM_ENVELOPE_MSG_COMMIT_RESERVATION,
        WVM_ENVELOPE_MSG_ABORT_RESERVATION,
        WVM_ENVELOPE_MSG_PREPARE_MANIFEST,
        WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST,
        WVM_ENVELOPE_MSG_ABORT_MANIFEST,
        WVM_ENVELOPE_MSG_ROUTE_PREPARE,
        WVM_ENVELOPE_MSG_ROUTE_COMMIT,
        WVM_ENVELOPE_MSG_ROUTE_ABORT,
        WVM_ENVELOPE_MSG_ROUTE_RETIRE,
    };
    struct authentication_context authentication = {0};
    struct typed_apply_context applied = {0};
    struct wvm_control_transport_config config = {0};
    struct wvm_control_stream transport;
    struct wvm_envelope request;
    struct wvm_control_result result;
    struct serve_context server;
    pthread_t thread;
    int sockets[2];
    int status = -1;
    size_t i;
    char error[256] = {0};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return -1;
    }
    config.stream_fd = sockets[0];
    config.local_physical_node_id = 900;
    config.local_runtime_instance_id = 901;
    config.authenticate = authenticate_actor;
    config.authenticate_opaque = &authentication;
    config.control_apply = apply_typed_request;
    config.control_apply_opaque = &applied;
    config.admission_apply = apply_typed_request;
    config.admission_apply_opaque = &applied;
    if (wvm_control_transport_init(&transport, &config, error, sizeof(error))) {
        goto out;
    }
    for (i = 0; i < sizeof(types) / sizeof(types[0]) + 3; i++) {
        size_t count = sizeof(types) / sizeof(types[0]);
        uint16_t expected_status = WVM_CONTROL_RESULT_SUCCESS;
        unsigned int previous_calls = applied.calls;
        int exchange_status;

        fill_stage_request(&request, types[i < count ? i : 1]);
        if (i == count) {
            applied.status = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
            expected_status = applied.status;
        } else if (i == count + 1) {
            authentication.reject = 1;
            expected_status = WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE;
        } else if (i == count + 2) {
            authentication.reject = 0;
            transport.config.control_apply = NULL;
            transport.config.admission_apply = NULL;
            transport.config.apply = wvm_control_plane_membership_apply;
            expected_status = WVM_CONTROL_RESULT_UNSUPPORTED;
        }
        if (start_serve(&server, &thread, &transport) != 0) {
            goto out;
        }
        exchange_status = wvm_control_transport_exchange(
            sockets[1], 900, 901, &request, &result, error, sizeof(error));
        if (exchange_status != 0) {
            shutdown(sockets[1], SHUT_RDWR);
        }
        if (pthread_join(thread, NULL) != 0 ||
            expect(exchange_status == 0 && server.result == 0 &&
                       result.status_code == expected_status,
                   "typed stream preserves stage reply or semantic rejection") ||
            expect(applied.calls == previous_calls + (i <= count ? 1U : 0U),
                   "unauthenticated or unsupported stages never reach apply")) {
            goto out;
        }
    }
    /* A completed apply must not kill the process if its client disconnects. */
    transport.config.control_apply = apply_typed_request;
    transport.config.admission_apply = apply_typed_request;
    if (send_request(sockets[1], &request, error, sizeof(error)) != 0 ||
        shutdown(sockets[1], SHUT_RD) != 0 ||
        expect(wvm_control_transport_serve_once(&transport, error,
                                                 sizeof(error)) == -EPIPE,
               "reply to disconnected client returns EPIPE, not SIGPIPE")) {
        goto out;
    }
    status = 0;
out:
    close(sockets[0]);
    close(sockets[1]);
    return status;
}

static int test_reply_validation(void)
{
    int variant;

    for (variant = 0; variant < 13; variant++) {
        struct wvm_envelope request;
        struct wvm_envelope response = {0};
        struct wvm_control_result result;
        struct wvm_control_result untouched;
        struct typed_apply_context context = {0};
        uint8_t payload[WVM_CONTROL_RESULT_BYTES];
        uint8_t frame[WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES +
                      WVM_ENVELOPE_HEADER_BYTES + WVM_CONTROL_RESULT_BYTES];
        size_t frame_bytes = 0;
        size_t sent_bytes;
        int sockets[2];
        int status;
        int expected = -EPROTO;
        char error[256] = {0};

        fill_stage_request(&request, WVM_ENVELOPE_MSG_PREPARE_RESERVATION);
        apply_typed_request(&context, &request, NULL, &result, NULL, 0);
        response.message_type = WVM_ENVELOPE_MSG_CTRL_RESULT;
        response.origin_physical_node_id = 900;
        response.origin_runtime_instance_id = 901;
        response.delivery_attempt_id = request.delivery_attempt_id;
        memcpy(response.operation_id, request.operation_id,
               sizeof(response.operation_id));
        switch (variant) {
        case 0: response.origin_physical_node_id++; break;
        case 1: response.origin_runtime_instance_id++; break;
        case 2: response.operation_id[0]++; break;
        case 3: response.delivery_attempt_id++; break;
        case 4: result.in_reply_to_operation_id[0]++; break;
        case 5: result.vm_id++; break;
        case 6: result.vm_incarnation++; break;
        case 7: result.manifest_generation++; break;
        case 8: result.route_scope_id++; break;
        case 9: result.record_digest[0]++; break;
        }
        if (wvm_control_result_encode(&result, payload) != 0) {
            return -1;
        }
        response.payload = payload;
        response.payload_bytes = sizeof(payload);
        if (wvm_envelope_encode(&response, WVM_ENVELOPE_TRANSPORT_LOCAL,
                                frame + 4, sizeof(frame) - 4, &frame_bytes,
                                error, sizeof(error)) != 0 ||
            socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
            return -1;
        }
        write_be32(frame, (uint32_t)frame_bytes);
        sent_bytes = frame_bytes + 4;
        if (variant == 10) {
            write_be32(frame, UINT32_MAX);
            sent_bytes = 4;
            expected = -EMSGSIZE;
        } else if (variant == 11) {
            sent_bytes--;
        } else if (variant == 12) {
            sent_bytes = 2;
        }
        if (send(sockets[0], frame, sent_bytes, MSG_NOSIGNAL) !=
                (ssize_t)sent_bytes || shutdown(sockets[0], SHUT_WR) != 0) {
            close(sockets[0]);
            close(sockets[1]);
            return -1;
        }
        memset(&result, 0xa5, sizeof(result));
        untouched = result;
        status = wvm_control_transport_exchange(
            sockets[1], 900, 901, &request, &result, error, sizeof(error));
        close(sockets[0]);
        close(sockets[1]);
        if (expect(status == expected &&
                       memcmp(&result, &untouched, sizeof(result)) == 0,
                   "reject mismatched, oversized or truncated reply unchanged")) {
            return -1;
        }
    }
    return 0;
}

static int test_exchange_io_failure(void)
{
    struct wvm_envelope request;
    struct wvm_control_result result;
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 20000};
    int sockets[2];
    int status;

    fill_stage_request(&request, WVM_ENVELOPE_MSG_PREPARE_MANIFEST);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return -1;
    }
    if (setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    status = wvm_control_transport_exchange(sockets[1], 900, 901, &request,
                                            &result, NULL, 0);
    close(sockets[0]);
    if (expect(status == -EAGAIN || status == -EWOULDBLOCK,
               "request without reply fails at caller's socket timeout") ||
        expect(wvm_control_transport_exchange(sockets[1], 900, 901, &request,
                                               &result, NULL, 0) == -EPIPE,
               "closed peer fails without SIGPIPE")) {
        close(sockets[1]);
        return -1;
    }
    close(sockets[1]);
    return 0;
}

int main(void)
{
    char membership_path[128];
    char control_path[128];
    char error[256] = {0};
    struct wvm_control_plane plane;
    struct wvm_control_plane_entry entries[1];
    struct wvm_membership_controller_member_entry members[2];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_dependency dependencies[2];
    struct wvm_membership_control_operation operations[4];
    struct wvm_node_record node;
    struct wvm_member_key actor;
    struct authentication_context authentication;
    struct wvm_control_stream transport;
    struct wvm_control_transport_config transport_config;
    struct wvm_envelope request;
    struct wvm_membership_control_result first_result;
    struct wvm_membership_control_result replay_result;
    struct wvm_membership_control_result rejected_result;
    uint8_t node_bytes[8192];
    uint8_t malformed_frame[WVM_ENVELOPE_HEADER_BYTES];
    uint8_t malformed_prefix[WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES];
    size_t node_byte_count = 0;
    int sockets[2] = {-1, -1};
    struct authorization_context authorization = {0};
    int result = 1;

    signal(SIGPIPE, SIG_DFL);
    if (test_admission_dispatch_owner() != 0 ||
        test_typed_exchange() != 0 || test_reply_validation() != 0 ||
        test_exchange_io_failure() != 0) {
        return 1;
    }
    memset(&plane, 0, sizeof(plane));
    memset(&transport, 0, sizeof(transport));
    if (snprintf(membership_path, sizeof(membership_path),
                 "/tmp/wavevm-control-transport-membership-%ld",
                 (long)getpid()) < 0 ||
        snprintf(control_path, sizeof(control_path),
                 "/tmp/wavevm-control-transport-control-%ld", (long)getpid()) <
            0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return 1;
    }
    unlink(membership_path);
    unlink(control_path);
    fill_node(&node);
    memset(&actor, 0, sizeof(actor));
    actor.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    actor.role_id = node.physical_node_id;
    actor.instance_id = node.node_instance_id;
    if (expect(wvm_node_record_encode(&node, node_bytes, sizeof(node_bytes),
                                      &node_byte_count, error,
                                      sizeof(error)) == 0,
               "encode canonical registration") != 0) {
        goto cleanup;
    }
    memset(&authentication, 0, sizeof(authentication));
    authentication.actor = actor;
    memset(&transport_config, 0, sizeof(transport_config));
    transport_config.stream_fd = sockets[0];
    transport_config.local_physical_node_id = 900;
    transport_config.local_runtime_instance_id = 901;
    transport_config.authenticate = authenticate_actor;
    transport_config.authenticate_opaque = &authentication;
    transport_config.apply = wvm_control_plane_membership_apply;
    transport_config.apply_opaque = &plane;
    if (expect(wvm_control_transport_init(&transport, &transport_config, error,
                                          sizeof(error)) == 0,
               "initialize reliable control stream") != 0 ||
        expect(configure_owner(&plane, entries, members, routes, dependencies,
                               operations, membership_path, control_path,
                               &authorization, error, sizeof(error)) == 0,
               "open authoritative membership owner") != 0) {
        goto cleanup;
    }
    make_register_request(&request, node_bytes, node_byte_count, 1);
    if (expect(exchange_request(&transport, sockets[1], &request,
                                &first_result, error, sizeof(error)) == 0,
               "apply fragmented registration through stream") != 0 ||
        expect(
                   first_result.status_code == WVM_MEMBERSHIP_CONTROL_SUCCESS,
               "decode successful CTRL_RESULT") != 0 ||
        expect(authentication.calls == 1 && authorization.calls == 1,
               "authenticate and authorize registration once") != 0) {
        goto cleanup;
    }
    if (expect(exchange_request(&transport, sockets[1], &request,
                                &replay_result, error, sizeof(error)) == 0,
               "replay registration through stream") != 0 ||
        expect(
                   memcmp(&first_result, &replay_result,
                          sizeof(first_result)) == 0,
               "replay the identical typed result") != 0 ||
        expect(authorization.calls == 1,
               "do not mutate membership on operation replay") != 0) {
        goto cleanup;
    }
    authentication.reject = 1;
    make_register_request(&request, node_bytes, node_byte_count, 2);
    if (expect(exchange_request(&transport, sockets[1], &request,
                                &rejected_result, error, sizeof(error)) == 0,
               "return typed authentication rejection") != 0 ||
        expect(
                   rejected_result.status_code ==
                       WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE,
               "decode unauthorized CTRL_RESULT") != 0 ||
        expect(authorization.calls == 1,
               "reject unauthenticated actor before owner dispatch") != 0) {
        goto cleanup;
    }
    write_be32(malformed_prefix,
               (uint32_t)(transport.config.max_frame_bytes + 1U));
    if (expect(exchange_raw_frame(&transport, sockets[1], malformed_prefix,
                                  NULL, 0) == -EMSGSIZE,
               "send oversized control length prefix") != 0 ||
        expect(authorization.calls == 1,
               "reject oversized frame before owner dispatch") != 0) {
        goto cleanup;
    }
    memset(malformed_frame, 0, sizeof(malformed_frame));
    write_be32(malformed_prefix, (uint32_t)sizeof(malformed_frame));
    if (expect(exchange_raw_frame(&transport, sockets[1], malformed_prefix,
                                  malformed_frame,
                                  sizeof(malformed_frame)) == -EPROTO,
               "send malformed control envelope") != 0 ||
        expect(authorization.calls == 1,
               "reject malformed envelope before owner dispatch") != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    wvm_control_plane_close_membership(&plane);
    wvm_control_transport_destroy(&transport);
    if (sockets[0] >= 0) {
        close(sockets[0]);
    }
    if (sockets[1] >= 0) {
        close(sockets[1]);
    }
    unlink(membership_path);
    unlink(control_path);
    if (result != 0 && error[0] != '\0') {
        fprintf(stderr, "control transport test: %s\n", error);
    }
    return result;
}

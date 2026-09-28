#define _XOPEN_SOURCE 700

#include <errno.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_control_plane.h"
#include "wavevm_control_service.h"
#include "wavevm_tls_control_connector.h"

#define MIB (1024ULL * 1024ULL)

struct authorization_context {
    struct wvm_member_key actor;
    unsigned int transport_calls;
    unsigned int membership_calls;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "control-service test: %s\n", message);
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

static int authenticate_actor(void *opaque, int stream_fd,
                              struct wvm_member_key *actor, char *error,
                              size_t error_len)
{
    struct authorization_context *context = opaque;

    (void)stream_fd;
    (void)error;
    (void)error_len;
    if (!context || !actor) {
        return -1;
    }
    *actor = context->actor;
    context->transport_calls++;
    return 0;
}

static int authorize_self(
    void *opaque, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    struct authorization_context *context = opaque;

    (void)action;
    (void)error;
    (void)error_len;
    if (!context || !member_key_equal(actor, subject) ||
        !member_key_equal(actor, &context->actor)) {
        return -1;
    }
    context->membership_calls++;
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
    node->inventory.reserved_host_memory_bytes = MIB;
    node->inventory.reserved_gateway_cpu_slots = 1;
    node->inventory.reserved_gateway_memory_bytes = MIB;
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

static ssize_t stream_read(void *opaque, void *bytes, size_t byte_count)
{
    return read(*(int *)opaque, bytes, byte_count);
}

static ssize_t stream_write(void *opaque, const void *bytes,
                            size_t byte_count)
{
    return write(*(int *)opaque, bytes, byte_count);
}

static ssize_t tls_read(void *opaque, void *bytes, size_t byte_count)
{
    return SSL_read(opaque, bytes, (int)byte_count);
}

static ssize_t tls_write(void *opaque, const void *bytes, size_t byte_count)
{
    return SSL_write(opaque, bytes, (int)byte_count);
}

static int connect_service(const char *socket_path)
{
    struct sockaddr_un address;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            strlen(socket_path) + 1U)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_tls_service(uint16_t port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
        connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static SSL_CTX *make_client_context(const char *ca, const char *certificate,
                                    const char *key)
{
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());

    if (!context) {
        return NULL;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(context, ca, NULL) != 1 ||
        SSL_CTX_use_certificate_file(context, certificate,
                                     SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) {
        SSL_CTX_free(context);
        return NULL;
    }
    return context;
}

static int exchange_registration(
    const char *socket_path, uint16_t port, SSL_CTX *tls_context,
    const uint8_t *payload, size_t payload_bytes,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    struct wvm_membership_control_result *result_out)
{
    struct wvm_envelope request;
    struct wvm_control_io io;
    char error[256] = {0};
    int fd;
    SSL *ssl = NULL;
    int status = -1;

    fd = tls_context ? connect_tls_service(port) : connect_service(socket_path);
    if (fd < 0) {
        return -1;
    }
    if (tls_context) {
        ssl = SSL_new(tls_context);
        if (!ssl || SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1 ||
            SSL_get_verify_result(ssl) != X509_V_OK) {
            goto out;
        }
    }
    memset(&request, 0, sizeof(request));
    request.message_type = WVM_ENVELOPE_MSG_REGISTER_MEMBER;
    request.origin_physical_node_id = 17;
    request.origin_runtime_instance_id = 101;
    memcpy(request.operation_id, operation_id, sizeof(request.operation_id));
    request.delivery_attempt_id = 1;
    request.payload = payload;
    request.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 request.semantic_payload_digest);
    io.opaque = ssl ? (void *)ssl : (void *)&fd;
    io.read = ssl ? tls_read : stream_read;
    io.write = ssl ? tls_write : stream_write;
    status = wvm_control_transport_membership_exchange_io(
        &io, 900, 901, &request, result_out, error, sizeof(error));
out:
    shutdown(fd, SHUT_RDWR);
    SSL_free(ssl);
    close(fd);
    return status;
}

static int authenticate_cert(void *opaque, int stream_fd,
                             const struct wvm_control_io *io,
                             struct wvm_member_key *actor, char *error,
                             size_t error_len)
{
    (void)opaque;
    (void)stream_fd;
    return wvm_tls_control_peer_identity(io, actor, error, error_len);
}

int main(int argc, char **argv)
{
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char membership_path[128];
    char control_path[128];
    struct wvm_control_plane plane;
    struct wvm_control_plane_entry entries[2];
    struct wvm_membership_controller_member_entry members[2];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_dependency dependencies[2];
    struct wvm_membership_control_operation operations[4];
    struct wvm_control_plane_membership_config membership_config;
    struct wvm_control_service_config service_config;
    struct wvm_control_service service;
    struct wvm_endpoint tls_endpoint;
    struct wvm_tls_control_connector membership_connector;
    struct wvm_control_stream_connector connector_callbacks;
    struct wvm_member_key controller_member;
    struct wvm_envelope membership_request;
    SSL_CTX *correct_client = NULL;
    SSL_CTX *wrong_client = NULL;
    struct authorization_context authorization;
    struct wvm_node_record node;
    struct wvm_membership_control_result first_result;
    struct wvm_membership_control_result replay_result;
    uint8_t node_bytes[8192];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    size_t node_byte_count = 0;
    char error[256] = {0};
    struct stat socket_stat;
    int result = 1;
    int membership_connector_bound = 0;
    unsigned long port_value = 0;

    if (argc != 1 && argc != 9) {
        return 2;
    }
    if (argc == 9) {
        struct sigaction ignore_pipe = {.sa_handler = SIG_IGN};
        char *end = NULL;

        sigemptyset(&ignore_pipe.sa_mask);
        if (sigaction(SIGPIPE, &ignore_pipe, NULL) != 0) {
            return 1;
        }
        memset(&membership_connector, 0, sizeof(membership_connector));
        memset(&connector_callbacks, 0, sizeof(connector_callbacks));
        memset(&controller_member, 0, sizeof(controller_member));
        controller_member.role_type = WVM_MANIFEST_ROLE_EXECUTOR;
        controller_member.role_id = 900;
        controller_member.instance_id = 901;
        port_value = strtoul(argv[1], &end, 10);
        if (!end || *end != '\0' || port_value == 0 ||
            port_value > UINT16_MAX) {
            return 2;
        }
        correct_client = make_client_context(argv[2], argv[5], argv[6]);
        wrong_client = make_client_context(argv[2], argv[7], argv[8]);
        if (!correct_client || !wrong_client) {
            goto out;
        }
    }

    snprintf(socket_path, sizeof(socket_path), "/tmp/wavevm-service-%ld.sock",
             (long)getpid());
    snprintf(membership_path, sizeof(membership_path),
             "/tmp/wavevm-service-membership-%ld", (long)getpid());
    snprintf(control_path, sizeof(control_path),
             "/tmp/wavevm-service-control-%ld", (long)getpid());
    unlink(socket_path);
    unlink(membership_path);
    unlink(control_path);
    memset(&authorization, 0, sizeof(authorization));
    authorization.actor.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    authorization.actor.role_id = 17;
    authorization.actor.instance_id = 101;
    fill_node(&node);
    if (wvm_node_record_encode(&node, node_bytes, sizeof(node_bytes),
                               &node_byte_count, error, sizeof(error)) != 0) {
        goto out;
    }
    memset(&membership_config, 0, sizeof(membership_config));
    membership_config.members = members;
    membership_config.member_capacity = 2;
    membership_config.routes = routes;
    membership_config.route_capacity = 2;
    membership_config.dependencies = dependencies;
    membership_config.dependency_capacity = 2;
    membership_config.operations = operations;
    membership_config.operation_capacity = 4;
    membership_config.membership_journal_path = membership_path;
    membership_config.control_journal_path = control_path;
    membership_config.authorize = authorize_self;
    membership_config.authorize_context = &authorization;
    wvm_control_plane_init(&plane, entries, 2);
    if (wvm_control_plane_configure_membership(&plane, &membership_config,
                                               error, sizeof(error)) != 0 ||
        wvm_control_plane_open_membership(&plane, error, sizeof(error)) != 0) {
        goto close_plane;
    }
    memset(&service_config, 0, sizeof(service_config));
    service_config.plane = &plane;
    service_config.socket_path = socket_path;
    service_config.socket_mode = S_IRUSR | S_IWUSR;
    service_config.listen_backlog = 4;
    service_config.local_physical_node_id = 900;
    service_config.local_runtime_instance_id = 901;
    service_config.authenticate = authenticate_actor;
    service_config.authenticate_opaque = &authorization;
    if (argc == 9) {
        memset(&tls_endpoint, 0, sizeof(tls_endpoint));
        tls_endpoint.data_transport = WVM_DATA_TRANSPORT_UDP;
        tls_endpoint.data_address_bytes = 4;
        tls_endpoint.data_address[0] = 127;
        tls_endpoint.data_address[3] = 1;
        tls_endpoint.data_port = 1;
        tls_endpoint.control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
        tls_endpoint.has_control_address = 1;
        tls_endpoint.control_address_bytes = 4;
        tls_endpoint.control_address[0] = 127;
        tls_endpoint.control_address[3] = 1;
        tls_endpoint.control_port = (uint16_t)port_value;
        service_config.network_endpoint = &tls_endpoint;
        service_config.tls_ca_file = argv[2];
        service_config.tls_certificate_file = argv[3];
        service_config.tls_private_key_file = argv[4];
        service_config.authenticate_io = authenticate_cert;
    }
    if (wvm_control_service_init(&service, &service_config, error,
                                 sizeof(error)) != 0 ||
        wvm_control_service_start(&service, error, sizeof(error)) != 0 ||
        expect(stat(socket_path, &socket_stat) == 0,
               "start protected control-plane listener") != 0) {
        goto destroy_service;
    }
    operation_id[WVM_IDENTITY_ID_BYTES - 1] = 1;
    if (expect(exchange_registration(socket_path, (uint16_t)port_value,
                                     correct_client, node_bytes,
                                     node_byte_count,
                                     operation_id, &first_result) == 0,
               "apply membership request through control service") != 0 ||
        expect(first_result.status_code == WVM_MEMBERSHIP_CONTROL_SUCCESS &&
                   first_result.recorded_state == WVM_MANIFEST_MEMBER_PENDING,
               "return durable typed result") != 0 ||
        expect(wvm_membership_controller_find(&plane.membership_controller,
                                              &authorization.actor) != NULL,
               "update authoritative membership state") != 0 ||
        expect(authorization.transport_calls == (argc == 9 ? 0U : 1U) &&
                   authorization.membership_calls == 1,
               "authenticate stream and authorize first operation") != 0 ||
        expect(wvm_control_service_stop(&service, error, sizeof(error)) == 0,
               "stop only the listener") != 0 ||
        expect(stat(socket_path, &socket_stat) != 0 && errno == ENOENT,
               "remove listener while retaining the durable plane") != 0 ||
        expect(plane.membership_open,
               "listener shutdown keeps membership authority open") != 0 ||
        expect(wvm_control_service_start(&service, error, sizeof(error)) == 0,
               "restart listener against same open plane") != 0 ||
        expect(exchange_registration(socket_path, 0, NULL, node_bytes,
                                     node_byte_count,
                                     operation_id, &replay_result) == 0,
               "replay membership request through restarted listener") != 0 ||
        expect(memcmp(&first_result, &replay_result, sizeof(first_result)) ==
                   0,
               "replay exact durable control result") != 0 ||
        expect(authorization.transport_calls == (argc == 9 ? 1U : 2U) &&
                   authorization.membership_calls == 1,
               "replay reauthenticates transport without mutating authority") !=
                   0) {
        goto destroy_service;
    }
    if (argc == 9) {
        memset(&membership_request, 0, sizeof(membership_request));
        membership_request.message_type = WVM_ENVELOPE_MSG_REGISTER_MEMBER;
        membership_request.origin_physical_node_id = 17;
        membership_request.origin_runtime_instance_id = 101;
        memcpy(membership_request.operation_id, operation_id,
               sizeof(operation_id));
        membership_request.delivery_attempt_id = 1;
        membership_request.payload = node_bytes;
        membership_request.payload_bytes = node_byte_count;
        wvm_envelope_semantic_digest(node_bytes, node_byte_count,
                                     membership_request.semantic_payload_digest);
        if (expect(wvm_tls_control_connector_bind(
                       &membership_connector, argv[2], argv[5], argv[6],
                       2000, &connector_callbacks, error, sizeof(error)) == 0,
                   "bind authenticated membership client") != 0) {
            goto destroy_service;
        }
        membership_connector_bound = 1;
        if (expect(wvm_tls_control_membership_exchange(
                       &membership_connector, &controller_member,
                       900, 901, &tls_endpoint, &membership_request, &replay_result,
                       error, sizeof(error)) == 0 &&
                       memcmp(&first_result, &replay_result,
                              sizeof(first_result)) == 0,
                   "membership TLS client replays durable result") != 0) {
            goto destroy_service;
        }
        controller_member.instance_id = 902;
        if (expect(wvm_tls_control_membership_exchange(
                       &membership_connector, &controller_member,
                       900, 901, &tls_endpoint, &membership_request, &replay_result,
                       error, sizeof(error)) == -EACCES,
                   "membership TLS client rejects wrong controller identity") != 0) {
            goto destroy_service;
        }
        operation_id[WVM_IDENTITY_ID_BYTES - 1] = 2;
        if (expect(exchange_registration(socket_path, (uint16_t)port_value,
                                         wrong_client, node_bytes,
                                         node_byte_count, operation_id,
                                         &replay_result) == 0 &&
                       replay_result.status_code ==
                           WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE,
                   "certificate identity cannot register another member") != 0) {
            goto destroy_service;
        }
    }
    result = 0;

destroy_service:
    if (membership_connector_bound) {
        wvm_tls_control_connector_destroy(&membership_connector);
    }
    wvm_control_service_destroy(&service);
close_plane:
    wvm_control_plane_close(&plane);
out:
    SSL_CTX_free(correct_client);
    SSL_CTX_free(wrong_client);
    unlink(socket_path);
    unlink(membership_path);
    unlink(control_path);
    if (result != 0 && error[0] != '\0') {
        fprintf(stderr, "control-service test: %s\n", error);
    }
    return result;
}

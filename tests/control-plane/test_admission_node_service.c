#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_admission_node_service.h"
#include "wavevm_canonical.h"
#include "wavevm_control_transport.h"

struct authentication_context {
    struct wvm_member_key actor;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "admission-node-service test: %s\n", message);
        return -1;
    }
    return 0;
}

static int authenticate_controller(void *opaque, int stream_fd,
                                   struct wvm_member_key *actor, char *error,
                                   size_t error_len)
{
    struct authentication_context *context = opaque;

    (void)stream_fd;
    (void)error;
    (void)error_len;
    if (!context || !actor) {
        return -1;
    }
    *actor = context->actor;
    return 0;
}

static int connect_retry(const char *path)
{
    struct sockaddr_un address;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000L};
    int attempt;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (!path || strlen(path) >= sizeof(address.sun_path)) {
        return -1;
    }
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    for (attempt = 0; attempt < 200; attempt++) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

        if (fd >= 0 && connect(fd, (const struct sockaddr *)&address,
                               (socklen_t)(offsetof(struct sockaddr_un,
                                                    sun_path) +
                                           strlen(path) + 1U)) == 0) {
            return fd;
        }
        if (fd >= 0) {
            close(fd);
        }
        nanosleep(&delay, NULL);
    }
    return -1;
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

static int fill_route_request(struct wvm_envelope *request, uint8_t *payload,
                              size_t payload_capacity, char *error,
                              size_t error_len)
{
    struct wvm_route_snapshot_record snapshot = {0};
    struct wvm_route_rule_record rule = {0};
    struct wvm_required_ack_entry ack = {0};
    struct wvm_endpoint endpoint = {0};
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t payload_bytes;

    endpoint.data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint.data_address_bytes = 4;
    endpoint.data_address[0] = 192;
    endpoint.data_address[1] = 0;
    endpoint.data_address[2] = 2;
    endpoint.data_address[3] = 10;
    endpoint.data_port = 19001;
    endpoint.control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint.control_port = 20001;
    snapshot.route_snapshot_key.scope_key.vm_id = 9001;
    snapshot.route_snapshot_key.scope_key.vm_incarnation = 1;
    snapshot.route_snapshot_key.scope_key.route_scope_id = 3;
    snapshot.route_snapshot_key.topology_revision = 1;
    snapshot.route_snapshot_key.route_generation = 1;
    snapshot.membership_revision = 1;
    snapshot.topology_kind = 1;
    snapshot.operation_retention_horizon_ms = 5000;
    snapshot.retirement_policy = 1;
    rule.destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule.next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule.next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule.next_hop_member.role_id = 801;
    rule.next_hop_member.instance_id = 802;
    rule.next_hop_endpoint = endpoint;
    rule.hop_limit = 4;
    ack.member_key = rule.next_hop_member;
    ack.endpoint = endpoint;
    ack.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack.expected_snapshot_key = snapshot.route_snapshot_key;
    snapshot.next_hop_rules.entries = &rule;
    snapshot.next_hop_rules.count = 1;
    snapshot.next_hop_rules.capacity = 1;
    snapshot.required_ack_set.entries.entries = &ack;
    snapshot.required_ack_set.entries.count = 1;
    snapshot.required_ack_set.entries.capacity = 1;
    if (wvm_route_snapshot_record_encode(&snapshot, payload, payload_capacity,
                                         &payload_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot.route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(ack.expected_snapshot_key.snapshot_digest, digest, sizeof(digest));
    if (wvm_route_snapshot_record_validate(&snapshot, error, error_len) != 0 ||
        wvm_route_snapshot_record_encode(&snapshot, payload, payload_capacity,
                                         &payload_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    fill_request(request);
    request->message_type = WVM_ENVELOPE_MSG_ROUTE_PREPARE;
    request->route_scope_id = snapshot.route_snapshot_key.scope_key.route_scope_id;
    request->topology_revision = snapshot.route_snapshot_key.topology_revision;
    request->route_generation = snapshot.route_snapshot_key.route_generation;
    memcpy(request->route_snapshot_digest,
           snapshot.route_snapshot_key.snapshot_digest,
           sizeof(request->route_snapshot_digest));
    request->payload = payload;
    request->payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 request->semantic_payload_digest);
    return 0;
}

int main(int argc, char **argv)
{
    struct wvm_admission_node_service service;
    struct wvm_admission_node_service_config config;
    struct authentication_context authentication;
    struct wvm_envelope request;
    struct wvm_control_result result;
    char directory[] = "/tmp/wavevm-admission-node-service.XXXXXX";
    char socket_path[256];
    char error[256] = {0};
    uint8_t route_payload[8192];
    int fd = -1;
    int status = 1;

    if (argc == 5 &&
        (strcmp(argv[1], "--client") == 0 ||
         strcmp(argv[1], "--unauthorized-client") == 0 ||
         strcmp(argv[1], "--route-client") == 0)) {
        char *end;
        unsigned long node_id;
        unsigned long long instance_id;
        int route_client = strcmp(argv[1], "--route-client") == 0;
        uint16_t expected_status = route_client
                                       ? WVM_CONTROL_RESULT_SUCCESS
                                       : strcmp(argv[1], "--client") == 0
                                             ? WVM_CONTROL_RESULT_PRECONDITION_FAILED
                                             : WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE;

        errno = 0;
        node_id = strtoul(argv[3], &end, 10);
        if (errno != 0 || *end != '\0' || node_id == 0 || node_id > UINT32_MAX) {
            return 2;
        }
        errno = 0;
        instance_id = strtoull(argv[4], &end, 10);
        if (errno != 0 || *end != '\0' || instance_id == 0) {
            return 2;
        }
        if (route_client) {
            if (fill_route_request(&request, route_payload,
                                   sizeof(route_payload), error,
                                   sizeof(error)) != 0) {
                fprintf(stderr, "admission-node-service route fixture: %s\n", error);
                return 1;
            }
        } else {
            fill_request(&request);
        }
        fd = connect_retry(argv[2]);
        if (fd < 0) {
            return 1;
        }
        memset(&result, 0, sizeof(result));
        status = wvm_control_transport_exchange(
                     fd, (uint32_t)node_id, (uint64_t)instance_id,
                     &request, &result, error, sizeof(error)) == 0 &&
                 result.status_code == expected_status &&
                 (!route_client || result.recorded_state == 1) &&
                 memcmp(result.in_reply_to_operation_id, request.operation_id,
                        sizeof(request.operation_id)) == 0 ? 0 : 1;
        if (status != 0) {
            fprintf(stderr, "admission-node-service client: %s\n",
                    error[0] ? error : "unexpected participant result");
        }
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return status;
    }
    if (argc != 1) {
        return 2;
    }

    if (!mkdtemp(directory) ||
        snprintf(socket_path, sizeof(socket_path), "%s/admission.sock",
                 directory) < 0) {
        return 1;
    }
    memset(&authentication, 0, sizeof(authentication));
    authentication.actor.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    authentication.actor.role_id = 701;
    authentication.actor.instance_id = 702;
    memset(&config, 0, sizeof(config));
    config.socket_path = socket_path;
    config.socket_mode = S_IRUSR | S_IWUSR;
    config.listen_backlog = 4;
    config.local_physical_node_id = 801;
    config.local_runtime_instance_id = 802;
    config.max_frame_bytes = WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    config.authenticate = authenticate_controller;
    config.authenticate_opaque = &authentication;
    config.receiver.controller_member_key = authentication.actor;
    config.receiver.controller_physical_node_id = 701;
    config.receiver.controller_runtime_instance_id = 702;
    config.receiver.local_physical_node_id = 801;
    config.receiver.local_node_instance_id = 802;

    if (wvm_admission_node_service_init(&service, &config, error,
                                        sizeof(error)) != 0 ||
        wvm_admission_node_service_start(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "admission-node-service test: %s\n",
                error[0] ? error : "service setup failed");
        goto out;
    }
    fill_request(&request);
    fd = connect_retry(socket_path);
    if (expect(fd >= 0, "connect to node-level admission listener") != 0) {
        goto stop;
    }
    memset(&result, 0, sizeof(result));
    if (expect(wvm_control_transport_exchange(
                   fd, config.local_physical_node_id,
                   config.local_runtime_instance_id, &request, &result, error,
                   sizeof(error)) == 0,
               "receive typed admission result") != 0 ||
        expect(result.status_code == WVM_CONTROL_RESULT_PRECONDITION_FAILED,
               "listener dispatches to receiver instead of unsupported") != 0 ||
        expect(memcmp(result.in_reply_to_operation_id, request.operation_id,
                      sizeof(request.operation_id)) == 0,
               "receiver result remains bound to request") != 0) {
        goto close;
    }
    status = 0;
close:
    shutdown(fd, SHUT_RDWR);
    close(fd);
stop:
    if (wvm_admission_node_service_stop(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "admission-node-service test: cannot stop service: %s\n",
                error[0] ? error : "unknown error");
        status = 1;
    }
    wvm_admission_node_service_destroy(&service);
out:
    unlink(socket_path);
    rmdir(directory);
    return status;
}

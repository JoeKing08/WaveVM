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

int main(void)
{
    struct wvm_admission_node_service service;
    struct wvm_admission_node_service_config config;
    struct authentication_context authentication;
    struct wvm_envelope request;
    struct wvm_control_result result;
    char directory[] = "/tmp/wavevm-admission-node-service.XXXXXX";
    char socket_path[256];
    char error[256] = {0};
    int fd = -1;
    int status = 1;

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

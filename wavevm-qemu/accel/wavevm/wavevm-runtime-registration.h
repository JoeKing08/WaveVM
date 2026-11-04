#pragma once

#include "qemu/osdep.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../../../common_include/wavevm_manifest.h"
#include "../../../common_include/wavevm_config.h"
#include "../../../common_include/wavevm_protocol.h"
#include "../../../common_include/wavevm_ioctl.h"

static inline int wavevm_qemu_runtime_gate_enabled(void)
{
    const char *value = getenv("WVM_RUNTIME_GATE_ACTIVE");

    return value && value[0] != '\0' && strcmp(value, "0") != 0;
}

static inline const char *wavevm_qemu_runtime_socket_path(void)
{
    const char *path = getenv("WVM_RUNTIME_SOCKET");

    if (!path || path[0] == '\0') {
        path = getenv("WVM_ENV_SOCK_PATH");
    }
    return path && path[0] != '\0' ? path : NULL;
}

/*
 * The node runtime creates this socket in its master role, while an admitted
 * executor may launch the QEMU frontend first. Registration waits for the
 * manifest-derived endpoint within a bounded deadline instead of falling back
 * to an unbound endpoint or using a fixed readiness sleep.
 */
static inline int wavevm_qemu_connect_runtime_socket(int socket_type)
{
    const char *path = wavevm_qemu_runtime_socket_path();
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    const int64_t deadline = g_get_monotonic_time() + 5000000;
    int last_error = ENOENT;

    if (!path || strlen(path) >= sizeof(address.sun_path)) {
        errno = EINVAL;
        fprintf(stderr, "[WaveVM] runtime socket path invalid: %s\n",
                path ? path : "<unset>");
        return -1;
    }
    memcpy(address.sun_path, path, strlen(path) + 1U);

    for (;;) {
        int fd = socket(AF_UNIX, socket_type, 0);
        int result;

        if (fd < 0) {
            return -1;
        }
        result = connect(fd, (struct sockaddr *)&address, sizeof(address));
        if (result == 0) {
            return fd;
        }
        last_error = errno;
        if (last_error == EINPROGRESS) {
            struct pollfd ready = {.fd = fd, .events = POLLOUT};
            int64_t remaining = deadline - g_get_monotonic_time();
            int poll_result;
            int socket_error = 0;
            socklen_t socket_error_bytes = sizeof(socket_error);

            if (remaining <= 0) {
                close(fd);
                errno = ETIMEDOUT;
                return -1;
            }
            poll_result = poll(&ready, 1,
                               (int)((remaining + 999) / 1000));
            if (poll_result > 0 &&
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                           &socket_error_bytes) == 0) {
                last_error = socket_error;
                if (last_error == 0) {
                    return fd;
                }
            } else if (poll_result == 0) {
                last_error = ETIMEDOUT;
            } else {
                last_error = errno;
            }
        }
        close(fd);
        if (last_error != ENOENT && last_error != ECONNREFUSED &&
            last_error != EAGAIN && last_error != EWOULDBLOCK &&
            last_error != ETIMEDOUT && last_error != EINTR) {
            errno = last_error;
            fprintf(stderr,
                    "[WaveVM] runtime socket connect failed path=%s errno=%d (%s)\n",
                    path, last_error, strerror(last_error));
            return -1;
        }
        if (g_get_monotonic_time() >= deadline) {
            errno = last_error == 0 ? ETIMEDOUT : last_error;
            fprintf(stderr,
                    "[WaveVM] runtime socket connect timed out path=%s errno=%d (%s)\n",
                    path, errno, strerror(errno));
            return -1;
        }
        g_usleep(10000);
    }
}

static inline int wavevm_qemu_parse_u64_env(const char *name,
                                            uint64_t *value)
{
    const char *text = getenv(name);
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !*text || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0) {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static inline int wavevm_qemu_parse_hex_env(
    const char *name, uint8_t *bytes, size_t byte_count)
{
    const char *text = getenv(name);
    size_t i;

    if (!text || strlen(text) != byte_count * 2U || !bytes) {
        return -1;
    }
    for (i = 0; i < byte_count; i++) {
        unsigned int byte;

        if (sscanf(text + i * 2U, "%2x", &byte) != 1 || byte > 0xffU) {
            return -1;
        }
        bytes[i] = (uint8_t)byte;
    }
    return 0;
}

static inline int wavevm_qemu_fill_runtime_registration(
    uint16_t ipc_role, struct wvm_ipc_runtime_registration *registration)
{
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint64_t local_runtime_instance_id;
    uint64_t value;
    const char *namespace_name;

    if (!registration ||
        wavevm_qemu_parse_u64_env("WVM_VM_ID", &value) != 0 ||
        value > UINT32_MAX) {
        return -1;
    }
    memset(registration, 0, sizeof(*registration));
    registration->magic = WVM_IPC_REGISTRATION_MAGIC;
    registration->version = WVM_IPC_REGISTRATION_VERSION;
    registration->ipc_role = ipc_role;
    registration->connection_role = WVM_MANIFEST_ROLE_QEMU_FRONTEND;
    registration->vm_id = (uint32_t)value;
    if (wavevm_qemu_parse_u64_env("WVM_VM_INCARNATION", &vm_incarnation) != 0 ||
        wavevm_qemu_parse_u64_env("WVM_MANIFEST_GENERATION",
                                  &manifest_generation) != 0 ||
        wavevm_qemu_parse_hex_env("WVM_CANDIDATE_MANIFEST_DIGEST",
                                  registration->candidate_manifest_digest,
                                  sizeof(registration->candidate_manifest_digest)) !=
            0 ||
        wavevm_qemu_parse_u64_env("WVM_RUNTIME_LOCAL_INSTANCE_ID",
                                  &local_runtime_instance_id) != 0 ||
        wavevm_qemu_parse_hex_env("WVM_CAPABILITY_PROFILE_DIGEST",
                                  registration->capability_profile_digest,
                                  sizeof(registration->capability_profile_digest)) !=
            0) {
        return -1;
    }
    registration->vm_incarnation = vm_incarnation;
    registration->manifest_generation = manifest_generation;
    registration->local_runtime_instance_id = local_runtime_instance_id;
    registration->caller_process_instance_id = (uint64_t)getpid();
    namespace_name = getenv("WVM_RUNTIME_NAMESPACE");
    if (!namespace_name || !*namespace_name ||
        strlen(namespace_name) >= sizeof(registration->requested_endpoint_name)) {
        return -1;
    }
    memcpy(registration->requested_endpoint_name, namespace_name,
           strlen(namespace_name) + 1U);
    return 0;
}

static inline int wavevm_qemu_query_kernel_caps(
    int dev_fd, struct wvm_ioctl_context_caps *caps)
{
    if (dev_fd < 0 || !caps) return -EINVAL;
    memset(caps, 0, sizeof(*caps));
    if (ioctl(dev_fd, IOCTL_WVM_QUERY_CAPS, caps) < 0) {
        return -errno;
    }
    if (caps->magic != WVM_KERNEL_CONTEXT_MAGIC ||
        caps->version != WVM_KERNEL_CONTEXT_ABI_VERSION ||
        caps->max_concurrent_contexts == 0 ||
        !(caps->feature_bits & WVM_KERNEL_CAP_CONTEXT_BIND)) {
        return -ENOTSUP;
    }
    return 0;
}

static inline bool wavevm_qemu_kernel_accel_usable(void)
{
    struct wvm_ioctl_context_caps caps;
    int dev_fd;
    int result;

    dev_fd = open("/dev/wavevm", O_RDWR);
    if (dev_fd < 0) return false;
    result = wavevm_qemu_query_kernel_caps(dev_fd, &caps);
    close(dev_fd);
    return result == 0;
}

static inline int wavevm_qemu_attachment_transfer(
    int fd, void *buffer, size_t bytes, bool sending, int64_t deadline)
{
    uint8_t *cursor = buffer;

    while (bytes) {
        int64_t remaining = deadline - g_get_monotonic_time();
        struct pollfd ready = {.fd = fd, .events = sending ? POLLOUT : POLLIN};
        ssize_t count;
        int result;

        if (remaining <= 0)
            return -ETIMEDOUT;
        result = poll(&ready, 1, (int)((remaining + 999) / 1000));
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (!result)
            return -ETIMEDOUT;
        count = sending ? send(fd, cursor, bytes, MSG_DONTWAIT | MSG_NOSIGNAL) :
                          recv(fd, cursor, bytes, MSG_DONTWAIT);
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -errno;
        }
        if (!count)
            return -ECONNRESET;
        cursor += count;
        bytes -= count;
    }
    return 0;
}

/* Obtain an attach-only capability through this VM's admitted local runtime.
 * A fresh channel leaves the vCPU and memory response streams undisturbed. */
static inline int wavevm_qemu_get_kernel_attachment(uint8_t capability[32])
{
    struct wvm_ipc_runtime_registration registration;
    struct wvm_ipc_kernel_attachment response;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    wvm_ipc_header_t header;
    const char *path = wavevm_qemu_runtime_socket_path();
    int64_t deadline = g_get_monotonic_time() + 5000000;
    int fd, result;

    if (!path || strlen(path) >= sizeof(address.sun_path) ||
        wavevm_qemu_fill_runtime_registration(WVM_IPC_ROLE_SYNC,
                                              &registration) != 0)
        return -EINVAL;
    memcpy(address.sun_path, path, strlen(path) + 1);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    if (result < 0 && errno == EINPROGRESS) {
        struct pollfd ready = {.fd = fd, .events = POLLOUT};
        int error = 0;
        socklen_t bytes = sizeof(error);

        do {
            int64_t remaining = deadline - g_get_monotonic_time();
            result = remaining <= 0 ? 0 :
                poll(&ready, 1, (int)((remaining + 999) / 1000));
        } while (result < 0 && errno == EINTR);
        if (result <= 0) {
            result = result == 0 ? -ETIMEDOUT : -errno;
            goto out;
        }
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &bytes) != 0) {
            result = -errno;
            goto out;
        }
        result = -error;
    } else if (result < 0) {
        result = -errno;
    }
    if (result < 0)
        goto out;
    header = (wvm_ipc_header_t){WVM_IPC_TYPE_REGISTER, sizeof(registration)};
    result = wavevm_qemu_attachment_transfer(fd, &header, sizeof(header), true,
                                             deadline);
    if (!result)
        result = wavevm_qemu_attachment_transfer(fd, &registration,
                    sizeof(registration), true, deadline);
    header = (wvm_ipc_header_t){WVM_IPC_TYPE_KERNEL_ATTACHMENT, 0};
    if (!result)
        result = wavevm_qemu_attachment_transfer(fd, &header, sizeof(header),
                                                 true, deadline);
    if (!result)
        result = wavevm_qemu_attachment_transfer(fd, &response,
                                                 sizeof(response), false,
                                                 deadline);
    if (!result) {
        static const uint8_t zero[32];

        if (response.status || !memcmp(response.capability, zero, sizeof(zero)))
            result = response.status < 0 ? response.status : -EPROTO;
        else
            memcpy(capability, response.capability, sizeof(response.capability));
    }
out:
    close(fd);
    return result;
}

/* Mode A attaches to the runtime-owned context for the same manifest. */
static inline int wavevm_qemu_bind_kernel_context(int dev_fd)
{
    struct wvm_ioctl_context_bind request;
    uint64_t value;

    if (!wavevm_qemu_runtime_gate_enabled()) return -EPERM;
    if (dev_fd < 0 ||
        wavevm_qemu_parse_u64_env("WVM_VM_ID", &value) != 0 ||
        value == 0 || value > UINT32_MAX) {
        return -EINVAL;
    }

    memset(&request, 0, sizeof(request));
    request.magic = WVM_KERNEL_CONTEXT_MAGIC;
    request.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    request.vm_id = (uint32_t)value;
    if (wavevm_qemu_parse_u64_env("WVM_RUNTIME_PHYSICAL_NODE_ID",
                                  &value) != 0 ||
        value > UINT32_MAX) {
        return -EINVAL;
    }
    request.physical_node_id = (uint32_t)value;
    /* F11/s23g5: kernel rejects node_instance_id==0 (ABI v3). Prefer
     * WVM_NODE_INSTANCE_ID, fall back to WVM_RUNTIME_LOCAL_INSTANCE_ID. */
    if (wavevm_qemu_parse_u64_env("WVM_NODE_INSTANCE_ID", &value) != 0) {
        if (wavevm_qemu_parse_u64_env("WVM_RUNTIME_LOCAL_INSTANCE_ID",
                                      &value) != 0 ||
            value == 0) {
            return -EINVAL;
        }
    } else if (value == 0) {
        return -EINVAL;
    }
    request.node_instance_id = value;
    if (wavevm_qemu_parse_u64_env("WVM_VM_INCARNATION",
                                  &request.vm_incarnation) != 0 ||
        wavevm_qemu_parse_u64_env("WVM_MANIFEST_GENERATION",
                                  &request.manifest_generation) != 0 ||
        wavevm_qemu_parse_hex_env(
            "WVM_CANDIDATE_MANIFEST_DIGEST",
            request.candidate_manifest_digest,
            sizeof(request.candidate_manifest_digest)) != 0 ||
        wavevm_qemu_parse_hex_env(
            "WVM_CAPABILITY_PROFILE_DIGEST",
            request.capability_profile_digest,
            sizeof(request.capability_profile_digest)) != 0 ||
        wavevm_qemu_parse_hex_env("WVM_ACTIVATION_FENCE",
                                  request.activation_fence,
                                  sizeof(request.activation_fence)) != 0) {
        return -EINVAL;
    }
    if (wavevm_qemu_parse_u64_env("WVM_ROUTE_SCOPE_ID", &value) != 0 ||
        value == 0) {
        return -EINVAL;
    }
    request.route_snapshot_key.scope_key.route_scope_id = value;
    if (wavevm_qemu_parse_u64_env("WVM_TOPOLOGY_REVISION", &value) != 0 ||
        value == 0) {
        return -EINVAL;
    }
    request.route_snapshot_key.topology_revision = value;
    if (wavevm_qemu_parse_u64_env("WVM_ROUTE_GENERATION", &value) != 0 ||
        value == 0 ||
        wavevm_qemu_parse_hex_env(
            "WVM_ROUTE_SNAPSHOT_DIGEST",
            request.route_snapshot_key.snapshot_digest,
            sizeof(request.route_snapshot_key.snapshot_digest)) != 0) {
        return -EINVAL;
    }
    request.route_snapshot_key.route_generation = value;
    request.route_snapshot_key.scope_key.vm_id = request.vm_id;
    request.route_snapshot_key.scope_key.vm_incarnation =
        request.vm_incarnation;

    {
        int result = wavevm_qemu_get_kernel_attachment(request.attach_capability);
        if (result)
            return result;
    }
    if (ioctl(dev_fd, IOCTL_WVM_BIND_CONTEXT, &request) < 0) {
        return -errno;
    }
    return 0;
}

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

/*
 * Mode A is admitted from the same manifest as the user-space runtime.  The
 * kernel module currently exposes one context per physical module instance;
 * binding here makes that limitation explicit instead of allowing a second
 * VM to overwrite module-global state.
 */
static inline int wavevm_qemu_bind_kernel_context(int dev_fd)
{
    struct wvm_ioctl_context_bind request;
    uint64_t value;

    if (!wavevm_qemu_runtime_gate_enabled()) return 0;
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

    if (ioctl(dev_fd, IOCTL_WVM_BIND_CONTEXT, &request) < 0) {
        return -errno;
    }
    return 0;
}

/*
 * s23g7: Mode A FE BIND creates a *separate* kernel context from the node
 * daemon. Dual-yes KVM often runs the sidecar as Mode B (bits==0), so the
 * child never IOCTL_UPDATE_CPU_ROUTE / SET_GATEWAY into the FE fd.
 * Without FE-local inject, REMOTE_RUN stays on AUTO_ROUTE => ENODEV and
 * remote_done only accumulates via HALT-WAKE false counts.
 *
 * Populate bare vnode routes for vCPUs >= split and the sidecar gateway
 * from launch.env (PRIMARY_DESTINATION_VNODE + EXECUTOR_SERVICE_PORT).
 * Returns 0 on success / nothing-to-do; negative -errno on ioctl failure.
 */
static inline int wavevm_qemu_inject_fe_compute_routes(int dev_fd, int vcpus,
                                                      int local_split)
{
    uint64_t vnode_u = 0;
    uint64_t port_u = 0;
    uint32_t vnode;
    uint16_t port_n;
    uint32_t ip_n;
    int remote_cpus;
    size_t buf_size;
    struct wvm_ioctl_route_update *payload;
    struct wvm_ioctl_gateway gw;
    int i;
    int mapped = 0;

    if (dev_fd < 0) {
        return -EINVAL;
    }
    if (vcpus <= 0) {
        vcpus = 1;
    }
    if (local_split < 0) {
        local_split = 0;
    }
    if (local_split > vcpus) {
        local_split = vcpus;
    }
    remote_cpus = vcpus - local_split;
    if (remote_cpus <= 0) {
        fprintf(stderr,
                "[WaveVM-QEMU] FE compute routes: split=%d vcpus=%d "
                "(no remote vCPUs; skip inject)\n",
                local_split, vcpus);
        return 0;
    }
    if (wavevm_qemu_parse_u64_env(
            "WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_VNODE", &vnode_u) != 0 ||
        vnode_u == 0 || vnode_u >= WVM_MAX_GATEWAYS) {
        fprintf(stderr,
                "[WaveVM-QEMU] FE compute routes: missing/invalid "
                "WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_VNODE\n");
        return -EINVAL;
    }
    vnode = (uint32_t)vnode_u;
    /*
     * Mode A FE BIND cutover (s23g13 / charter): point SET_GATEWAY at the
     * Hybrid executor service port — same endpoint Mode B uses for local
     * handoff. Kernel :9000 <-> Hybrid is the Mode A acceleration of that
     * contract (wire-ipc §7 / kernel-accelerator §5.2).
     *
     * Do NOT prefer WVM_RUNTIME_LOCAL_PORT (V30 sidecar) here: that wraps
     * Mode A REMOTE_RUN in the old Mode B forward shell (kernel->V30->Hybrid
     * hairpin). Joe rejected 「旧版本套上新版本」; V30 demux cannot be the
     * formal Mode A BIND fix. Fall back to LOCAL_PORT only if executor port
     * is absent (exceptional).
     */
    if (wavevm_qemu_parse_u64_env("WVM_EXECUTOR_SERVICE_PORT", &port_u) != 0 ||
        port_u == 0 || port_u > 65535) {
        if (wavevm_qemu_parse_u64_env("WVM_RUNTIME_LOCAL_PORT",
                                      &port_u) != 0 ||
            port_u == 0 || port_u > 65535) {
            fprintf(stderr,
                    "[WaveVM-QEMU] FE compute routes: missing executor port "
                    "(WVM_EXECUTOR_SERVICE_PORT / WVM_RUNTIME_LOCAL_PORT)\n");
            return -EINVAL;
        }
    }
    port_n = htons((uint16_t)port_u);
    ip_n = htonl(0x7f000001u); /* 127.0.0.1 — same-host executor endpoint */

    memset(&gw, 0, sizeof(gw));
    gw.gw_id = vnode; /* bare node_id index into gateway_table */
    gw.ip = ip_n;
    gw.port = port_n;
    if (ioctl(dev_fd, IOCTL_SET_GATEWAY, &gw) < 0) {
        fprintf(stderr,
                "[WaveVM-QEMU] FE SET_GATEWAY vnode=%u port=%u failed: %s\n",
                vnode, (unsigned)port_u, strerror(errno));
        return -errno;
    }

    buf_size = sizeof(*payload) + (size_t)vcpus * sizeof(uint32_t);
    payload = calloc(1, buf_size);
    if (!payload) {
        return -ENOMEM;
    }
    payload->start_index = 0;
    payload->count = (uint32_t)vcpus;
    for (i = 0; i < vcpus; i++) {
        if (i >= local_split) {
            payload->entries[i] = vnode; /* bare vnode */
            mapped++;
        } else {
            payload->entries[i] = WVM_NODE_AUTO_ROUTE;
        }
    }
    if (ioctl(dev_fd, IOCTL_UPDATE_CPU_ROUTE, payload) < 0) {
        fprintf(stderr,
                "[WaveVM-QEMU] FE UPDATE_CPU_ROUTE failed: %s\n",
                strerror(errno));
        free(payload);
        return -errno;
    }
    free(payload);
    fprintf(stderr,
            "[WaveVM-QEMU] FE compute routes injected: split=%d vcpus=%d "
            "mapped=%d vnode=%u gw=127.0.0.1:%u\n",
            local_split, vcpus, mapped, vnode, (unsigned)port_u);
    return 0;
}

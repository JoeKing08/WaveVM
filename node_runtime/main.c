#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>

#include "executor_bridge.h"
#include "executor_runtime.h"
#include "ingress.h"
#include "memory_service.h"
#include "runtime_context.h"
#include "vcpu_coordinator.h"
#include "vcpu_service.h"
#include "../common_include/wavevm_executor_abi.h"
#include "../common_include/wavevm_runtime_names.h"
#include "../common_include/wavevm_route_delivery.h"
#include "../common_include/wavevm_route_runtime.h"
#include "../common_include/wavevm_runtime_dispatch.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../master_core/logic_core.h"

int wavevm_master_runtime_main(
    const struct wvm_node_runtime_context *runtime);
int wavevm_executor_runtime_main(
    const struct wvm_node_runtime_context *runtime);
extern volatile sig_atomic_t g_shutdown_requested;
int wavevm_admission_agent_main(int argc, char **argv);

struct role_launch {
    const struct wvm_node_runtime_context *runtime;
};

struct memory_network_context {
    int sidecar_fd;
    struct sockaddr_in sidecar_address;
};

static void export_hex_env(const char *name, const uint8_t *bytes,
                           size_t byte_count)
{
    char *text;
    size_t i;

    text = calloc(byte_count * 2U + 1U, 1);
    if (!text) {
        fprintf(stderr, "[node-runtime] cannot export %s\n", name);
        return;
    }
    for (i = 0; i < byte_count; i++) {
        snprintf(text + i * 2U, 3, "%02x", bytes[i]);
    }
    if (setenv(name, text, 1) != 0) {
        fprintf(stderr, "[node-runtime] cannot set %s: %s\n", name,
                strerror(errno));
    }
    free(text);
}

static int export_runtime_identity(
    const struct wvm_node_runtime_manifest *manifest,
    uint64_t node_instance_id, int physical_node_id)
{
    char value[64];
    struct wvm_runtime_name_set names;
    char error[256] = {0};

    if (!manifest ||
        wvm_runtime_name_set_derive(&manifest->local_names, &names, error,
                                    sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] cannot derive local runtime namespace\n");
        return -1;
    }
    /*
     * The legacy adapter uses WVM_INSTANCE_ID and WVM_SHM_FILE for local
     * socket/SHM names. Derive both from the admitted namespace so a gated
     * launch cannot silently fall back to instance 0 or /wavevm_ram.
     */
    if (setenv("WVM_INSTANCE_ID", manifest->local_names.namespace_name, 1) !=
            0 ||
        setenv("WVM_SHM_FILE", names.shm_name, 1) != 0 ||
        setenv("WVM_ENV_SOCK_PATH", names.runtime_socket, 1) != 0 ||
        setenv("WVM_RUNTIME_SOCKET", names.runtime_socket, 1) != 0 ||
        setenv("WVM_RUNTIME_WORKER_SOCKET", names.worker_socket, 1) != 0 ||
        setenv("WVM_RUNTIME_MONITOR_SOCKET", names.monitor_socket, 1) != 0 ||
        setenv("WVM_RUNTIME_READY_FILE", names.ready_file, 1) != 0 ||
        setenv("WVM_RUNTIME_LOG_DIR", names.log_directory, 1) != 0 ||
        setenv("WVM_RUNTIME_TMP_DIR", names.temporary_directory, 1) != 0 ||
        setenv("WVM_LOCAL_EXECUTOR_SOCKET", names.executor_socket, 1) != 0) {
        fprintf(stderr, "[node-runtime] cannot export local namespace: %s\n",
                strerror(errno));
        return -1;
    }
    snprintf(value, sizeof(value), "%u", manifest->vm_id);
    setenv("WVM_VM_ID", value, 1);
    snprintf(value, sizeof(value), "%" PRIu64, manifest->vm_incarnation);
    setenv("WVM_VM_INCARNATION", value, 1);
    snprintf(value, sizeof(value), "%" PRIu64, manifest->manifest_generation);
    setenv("WVM_MANIFEST_GENERATION", value, 1);
    snprintf(value, sizeof(value), "%" PRIu64, node_instance_id);
    setenv("WVM_RUNTIME_LOCAL_INSTANCE_ID", value, 1);
    snprintf(value, sizeof(value), "%d", physical_node_id);
    setenv("WVM_RUNTIME_PHYSICAL_NODE_ID", value, 1);
    setenv("WVM_RUNTIME_NAMESPACE", manifest->local_names.namespace_name, 1);
    export_hex_env("WVM_CANDIDATE_MANIFEST_DIGEST",
                   manifest->candidate_manifest_digest,
                   sizeof(manifest->candidate_manifest_digest));
    if (manifest->has_activation_fence) {
        export_hex_env("WVM_ACTIVATION_FENCE", manifest->activation_fence,
                       sizeof(manifest->activation_fence));
    }
    return 0;
}

static int derive_runtime_profile_digest(
    const struct wvm_node_runtime_manifest *manifest,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES])
{
    char error[256] = {0};

    if (wvm_runtime_manifest_profile_digest(manifest, digest, error,
                                            sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] cannot derive profile digest: %s\n",
                error[0] ? error : "invalid capability profile");
        return -1;
    }
    return 0;
}

static void *run_master_role(void *opaque)
{
    struct role_launch *launch = opaque;
    int result = wavevm_master_runtime_main(launch->runtime);

    return (void *)(intptr_t)result;
}

static void *run_executor_role(void *opaque)
{
    struct role_launch *launch = opaque;
    int result = wavevm_executor_runtime_main(launch->runtime);

    return (void *)(intptr_t)result;
}

static int parse_u64(const char *text, uint64_t *value)
{
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

static int sum_local_memory_bytes(
    const struct wvm_node_runtime_manifest *manifest, uint64_t *total_out)
{
    uint64_t total = 0;
    size_t i;

    if (!manifest || !total_out) {
        return -1;
    }
    for (i = 0; i < manifest->local_memory_assignments.count; i++) {
        const uint64_t bytes =
            manifest->local_memory_assignments.entries[i].bytes;

        if (bytes == 0 || bytes > UINT64_MAX - total) {
            return -1;
        }
        total += bytes;
    }
    *total_out = total;
    return 0;
}

static int route_key_equal(const struct wvm_route_snapshot_key *left,
                           const struct wvm_route_snapshot_key *right)
{
    return left && right &&
           left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int read_authoritative_local_page(
    void *opaque, uint64_t gpa, uint8_t data[WVM_MEMORY_PAGE_BYTES],
    uint64_t *version_out, char *error, size_t error_len)
{
    int result;

    (void)opaque;
    if (!data || !version_out) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "local V1 directory read is invalid");
        }
        return -EINVAL;
    }
    /*
     * This is a typed read-only adapter over the existing authoritative
     * directory page table. The page data points at the live WVM_SHM_FILE
     * mapping used by the local QEMU frontend; V1 ingress never reinterprets
     * a V1 payload as a legacy packet or invokes legacy network routing.
     */
    result = wvm_handle_local_fault_fastpath(gpa, data, version_out);
    if (result != 0 && error && error_len != 0) {
        snprintf(error, error_len,
                 "local V1 directory cannot read GPA %#" PRIx64, gpa);
    }
    return result;
}

static int commit_authoritative_local_page(
    void *opaque, uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes, uint64_t *result_version,
    char *error, size_t error_len)
{
    int result;

    (void)opaque;
    if (!data || !result_version) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "local V1 directory commit is invalid");
        }
        return -EINVAL;
    }
    result = wvm_handle_local_commit(
        gpa, base_version, offset, data, data_bytes, result_version);
    if (result != 0 && error && error_len != 0) {
        snprintf(error, error_len,
                 "local V1 directory cannot commit GPA %#" PRIx64, gpa);
    }
    return result;
}

static int publish_authoritative_local_page(
    void *opaque, uint64_t gpa, uint64_t result_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes, uint32_t writer_physical_node_id,
    char *error, size_t error_len)
{
    int result;

    (void)opaque;
    if (!data) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "local V1 directory publish is invalid");
        }
        return -EINVAL;
    }
    result = wvm_publish_local_commit(
        gpa, result_version, offset, data, data_bytes,
        writer_physical_node_id);
    if (result != 0 && error && error_len != 0) {
        snprintf(error, error_len,
                 "local V1 directory cannot publish GPA %#" PRIx64, gpa);
    }
    return result;
}

static int send_sidecar_frame(void *opaque, const uint8_t *frame,
                                 size_t frame_bytes, char *error,
                                 size_t error_len)
{
    struct memory_network_context *context = opaque;
    ssize_t sent;

    if (!context || context->sidecar_fd < 0 || !frame || frame_bytes == 0) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "local V1 sidecar transport is inactive");
        }
        return -ENOTCONN;
    }
    sent = sendto(context->sidecar_fd, frame, frame_bytes, MSG_DONTWAIT,
                  (const struct sockaddr *)&context->sidecar_address,
                  sizeof(context->sidecar_address));
    if (sent == (ssize_t)frame_bytes) {
        return 0;
    }
    if (error && error_len != 0) {
        snprintf(error, error_len, "local V1 sidecar send failed: %s",
                 sent < 0 ? strerror(errno) : "short datagram");
    }
    if (sent < 0) {
        return errno == EAGAIN || errno == EWOULDBLOCK ? -EAGAIN : -errno;
    }
    return -EIO;
}

static int send_runtime_envelope(void *opaque,
                                 const struct wvm_envelope *envelope,
                                 char *error, size_t error_len)
{
    return wvm_envelope_emit_network_frames(
        envelope, send_sidecar_frame, opaque, error, error_len);
}

static int complete_memory_fault(
    void *opaque, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t gpa, uint64_t version, uint16_t status,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    const uint8_t *data, size_t data_bytes, char *error, size_t error_len)
{
    (void)opaque;
    return wvm_memory_service_global_complete(
        operation_id, gpa, version, status, directory_physical_node_id,
        directory_node_instance_id, data, data_bytes, error, error_len);
}

static int complete_memory_commit(
    void *opaque, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t gpa, uint16_t status, uint64_t result_version,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    char *error, size_t error_len)
{
    (void)opaque;
    return wvm_memory_service_global_complete_commit(
        operation_id, gpa, status, result_version,
        directory_physical_node_id, directory_node_instance_id, error,
        error_len);
}

static int init_memory_network_context(
    struct memory_network_context *context,
    const struct wvm_runtime_dispatch_projection *dispatch, char *error,
    size_t error_len)
{
    const struct wvm_endpoint *endpoint;

    if (!context || !dispatch) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "local V1 sidecar context is invalid");
        }
        return -EINVAL;
    }
    endpoint = &dispatch->local_sidecar_endpoint;
    if (endpoint->data_transport != WVM_DATA_TRANSPORT_UDP ||
        endpoint->data_address_bytes != 4 || endpoint->data_port == 0) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "local V1 sidecar endpoint is not IPv4/UDP");
        }
        return -EPROTONOSUPPORT;
    }
    memset(context, 0, sizeof(*context));
    context->sidecar_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (context->sidecar_fd < 0) {
        if (error && error_len != 0) {
            snprintf(error, error_len, "cannot create V1 sidecar socket: %s",
                     strerror(errno));
        }
        return -errno;
    }
    context->sidecar_address.sin_family = AF_INET;
    memcpy(&context->sidecar_address.sin_addr.s_addr, endpoint->data_address,
           sizeof(context->sidecar_address.sin_addr.s_addr));
    context->sidecar_address.sin_port = htons(endpoint->data_port);
    return 0;
}

static void destroy_memory_network_context(
    struct memory_network_context *context)
{
    if (!context) {
        return;
    }
    if (context->sidecar_fd >= 0) {
        close(context->sidecar_fd);
    }
    memset(context, 0, sizeof(*context));
    context->sidecar_fd = -1;
}

static int runtime_dispatch_matches_manifest(
    const struct wvm_runtime_dispatch_projection *dispatch,
    const struct wvm_node_runtime_manifest *manifest,
    uint64_t node_instance_id, uint32_t physical_node_id, char *error,
    size_t error_len)
{
    if (!dispatch || !manifest ||
        wvm_runtime_dispatch_projection_validate(dispatch, error,
                                                 error_len) != 0 ||
        memcmp(dispatch->candidate_manifest_digest,
               manifest->candidate_manifest_digest,
               sizeof(dispatch->candidate_manifest_digest)) != 0 ||
        dispatch->vm_id != manifest->vm_id ||
        dispatch->vm_incarnation != manifest->vm_incarnation ||
        dispatch->manifest_generation != manifest->manifest_generation ||
        dispatch->physical_node_id != physical_node_id ||
        dispatch->expected_node_instance_id != node_instance_id ||
        memcmp(dispatch->activation_fence, manifest->activation_fence,
               sizeof(dispatch->activation_fence)) != 0 ||
        !route_key_equal(&dispatch->required_route_snapshot_key,
                         &manifest->required_route_snapshot_key)) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "runtime dispatch does not match admitted manifest");
        }
        return -1;
    }
    return 0;
}

static int prepare_runtime_gate(const char *manifest_path,
                                uint64_t node_instance_id,
                                struct wvm_runtime_manifest_storage *storage,
                                struct wvm_runtime_gate *gate,
                                char *route_snapshot_path,
                                size_t route_snapshot_path_capacity,
                                char *dispatch_path,
                                size_t dispatch_path_capacity,
                                struct wvm_runtime_dispatch_storage
                                    *dispatch_storage,
                                struct wvm_route_runtime *route_runtime,
                                uint64_t *completion_timeout_ms)
{
    struct wvm_route_snapshot_file_storage route_storage;
    char error[256] = {0};

    if (!completion_timeout_ms) {
        return -1;
    }
    *completion_timeout_ms = 0;
    wvm_route_snapshot_file_storage_init(&route_storage);
    wvm_runtime_manifest_storage_init(storage);
    wvm_runtime_dispatch_storage_init(dispatch_storage);
    wvm_route_runtime_init(route_runtime);
    if (wvm_runtime_manifest_load_file(manifest_path, storage, error,
                                       sizeof(error)) != 0 ||
        storage->manifest.physical_node_id > INT_MAX ||
        wvm_runtime_gate_prepare(gate, &storage->manifest,
                                 storage->manifest.physical_node_id,
                                 node_instance_id,
                                 error, sizeof(error)) != 0 ||
        wvm_runtime_gate_activate(gate, storage->manifest.activation_fence,
                                  error, sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] manifest gate rejected startup: %s\n",
                error[0] ? error : "invalid runtime manifest");
        wvm_runtime_manifest_storage_free(storage);
        wvm_route_snapshot_file_storage_free(&route_storage);
        wvm_runtime_dispatch_storage_free(dispatch_storage);
        wvm_route_runtime_destroy(route_runtime);
        return -1;
    }
    if (wvm_route_snapshot_path_from_manifest(
            manifest_path, route_snapshot_path, route_snapshot_path_capacity,
            error, sizeof(error)) != 0 ||
        wvm_route_snapshot_file_load(route_snapshot_path, &route_storage, error,
                                     sizeof(error)) != 0 ||
        wvm_route_snapshot_file_matches(
            &route_storage,
            &storage->manifest.required_route_snapshot_key, error,
            sizeof(error)) != 0) {
        fprintf(stderr,
                "[node-runtime] admitted route snapshot rejected: %s\n",
                error[0] ? error : "route snapshot identity mismatch");
        wvm_runtime_manifest_storage_free(storage);
        wvm_route_snapshot_file_storage_free(&route_storage);
        wvm_runtime_dispatch_storage_free(dispatch_storage);
        wvm_route_runtime_destroy(route_runtime);
        return -1;
    }
    if (wvm_route_runtime_prepare(route_runtime, &route_storage.snapshot,
                                  error, sizeof(error)) != 0 ||
        wvm_route_runtime_activate(
            route_runtime, &storage->manifest.required_route_snapshot_key,
            error, sizeof(error)) != 0) {
        fprintf(stderr,
                "[node-runtime] immutable route runtime rejected startup: %s\n",
                error[0] ? error : "route snapshot activation failed");
        wvm_runtime_manifest_storage_free(storage);
        wvm_route_snapshot_file_storage_free(&route_storage);
        wvm_runtime_dispatch_storage_free(dispatch_storage);
        wvm_route_runtime_destroy(route_runtime);
        return -1;
    }
    *completion_timeout_ms =
        route_storage.snapshot.operation_retention_horizon_ms;
    if (*completion_timeout_ms == 0) {
        fprintf(stderr,
                "[node-runtime] route snapshot has no operation retention "
                "horizon\n");
        wvm_runtime_manifest_storage_free(storage);
        wvm_route_snapshot_file_storage_free(&route_storage);
        wvm_runtime_dispatch_storage_free(dispatch_storage);
        wvm_route_runtime_destroy(route_runtime);
        return -1;
    }
    if (wvm_runtime_dispatch_path_from_manifest(
            manifest_path, dispatch_path, dispatch_path_capacity, error,
            sizeof(error)) != 0 ||
        wvm_runtime_dispatch_file_load(dispatch_path, dispatch_storage, error,
                                       sizeof(error)) != 0 ||
        runtime_dispatch_matches_manifest(
            &dispatch_storage->projection, &storage->manifest,
            node_instance_id, storage->manifest.physical_node_id, error,
            sizeof(error)) != 0) {
        fprintf(stderr,
                "[node-runtime] admitted runtime dispatch rejected: %s\n",
                error[0] ? error : "runtime dispatch identity mismatch");
        wvm_runtime_manifest_storage_free(storage);
        wvm_route_snapshot_file_storage_free(&route_storage);
        wvm_runtime_dispatch_storage_free(dispatch_storage);
        wvm_route_runtime_destroy(route_runtime);
        return -1;
    }
    wvm_route_snapshot_file_storage_free(&route_storage);
    return 0;
}

static int parse_required_options(int argc, char **argv, const char **manifest,
                                  uint64_t *node_instance_id,
                                  int *print_launch_env)
{
    int i;
    int have_manifest = 0;
    int have_instance = 0;
    int have_print_env = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc) {
            if (have_manifest) {
                return -1;
            }
            *manifest = argv[++i];
            have_manifest = 1;
        } else if (strcmp(argv[i], "--node-instance") == 0 &&
                   i + 1 < argc &&
                   parse_u64(argv[++i], node_instance_id) == 0) {
            if (have_instance) {
                return -1;
            }
            have_instance = 1;
        } else if (strcmp(argv[i], "--print-launch-env") == 0) {
            if (have_print_env) {
                return -1;
            }
            have_print_env = 1;
        } else {
            return -1;
        }
    }
    if (print_launch_env) {
        *print_launch_env = have_print_env;
    }
    return have_manifest && have_instance ? 0 : -1;
}

static void print_shell_export(const char *name)
{
    const char *value = getenv(name);
    const char *cursor;

    if (!value) {
        return;
    }
    printf("export %s='", name);
    for (cursor = value; *cursor != '\0'; cursor++) {
        if (*cursor == '\'') {
            fputs("'\\''", stdout);
        } else {
            putchar((unsigned char)*cursor);
        }
    }
    puts("'");
}

static void print_launch_environment(void)
{
    static const char *const names[] = {
        "WVM_RUNTIME_MANIFEST_PATH",
        "WVM_RUNTIME_ROUTE_SNAPSHOT_PATH",
        "WVM_RUNTIME_DISPATCH_PATH",
        "WVM_NODE_INSTANCE_ID",
        "WVM_RUNTIME_GATE_ACTIVE",
        "WVM_INSTANCE_ID",
        "WVM_RUNTIME_NAMESPACE",
        "WVM_SHM_FILE",
        "WVM_ENV_SOCK_PATH",
        "WVM_RUNTIME_SOCKET",
        "WVM_RUNTIME_WORKER_SOCKET",
        "WVM_RUNTIME_MONITOR_SOCKET",
        "WVM_RUNTIME_READY_FILE",
        "WVM_RUNTIME_LOG_DIR",
        "WVM_RUNTIME_TMP_DIR",
        "WVM_LOCAL_EXECUTOR_SOCKET",
        "WVM_VM_ID",
        "WVM_VM_INCARNATION",
        "WVM_MANIFEST_GENERATION",
        "WVM_RUNTIME_LOCAL_INSTANCE_ID",
        "WVM_RUNTIME_PHYSICAL_NODE_ID",
        "WVM_CANDIDATE_MANIFEST_DIGEST",
        "WVM_ACTIVATION_FENCE",
        "WVM_ROUTE_SCOPE_ID",
        "WVM_TOPOLOGY_REVISION",
        "WVM_ROUTE_GENERATION",
        "WVM_ROUTE_SNAPSHOT_DIGEST",
        "WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_KIND",
        "WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_SCOPE",
        "WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_VNODE",
        "WVM_CAPABILITY_PROFILE_DIGEST",
        "WVM_EXECUTOR_SERVICE_PORT",
        "WVM_RUNTIME_LOCAL_PORT",
        "WVM_TCG_QEMU_MACHINE",
        "WVM_TCG_QEMU_MEM_MB",
    };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        print_shell_export(names[i]);
    }
}

/*
 * One process image owns both logical roles. The master role remains the
 * node-runtime semantic coordinator; the slave role remains its local
 * executor manager. They are started on separate threads and retain their
 * existing asynchronous queues instead of forwarding through a new global
 * lock.
 *
 * Invocation:
 *   wavevm_node_runtime --manifest FILE --node-instance N
 */
static int run_runtime_main(int argc, char **argv)
{
    const char *manifest_path = NULL;
    uint64_t node_instance_id = 0;
    int print_launch_env = 0;
    int physical_node_id;
    pthread_t master_thread;
    pthread_t executor_thread;
    struct role_launch master_launch;
    struct role_launch executor_launch;
    struct wvm_node_runtime_context runtime_context;
    struct wvm_runtime_manifest_storage storage;
    struct wvm_runtime_gate gate;
    char route_snapshot_path[WVM_ROUTE_DELIVERY_PATH_MAX];
    char dispatch_path[WVM_RUNTIME_DISPATCH_PATH_MAX];
    struct wvm_runtime_dispatch_storage dispatch_storage;
    struct wvm_route_runtime route_runtime;
    struct wvm_memory_service memory_service;
    struct wvm_vcpu_handoff_coordinator vcpu_coordinator;
    struct wvm_vcpu_service vcpu_service;
    struct memory_network_context memory_network;
    uint8_t capability_profile_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t completion_timeout_ms = 0;
    uint64_t runtime_connection_id = 0;
    void *master_result = NULL;
    void *executor_result = NULL;
    void *executor_dispatch_opaque = NULL;
    char instance_text[32];
    char guest_memory_mb_text[32];

    if (parse_required_options(argc, argv, &manifest_path,
                               &node_instance_id, &print_launch_env) != 0) {
        fprintf(stderr,
                "Usage: %s --manifest FILE --node-instance N "
                "[--print-launch-env]\n",
                argv[0]);
        return 2;
    }
    memset(&memory_service, 0, sizeof(memory_service));
    memset(&vcpu_coordinator, 0, sizeof(vcpu_coordinator));
    memset(&vcpu_service, 0, sizeof(vcpu_service));
    memset(&memory_network, 0, sizeof(memory_network));
    memory_network.sidecar_fd = -1;
    wvm_runtime_gate_init(&gate);
    if (prepare_runtime_gate(manifest_path, node_instance_id, &storage, &gate,
                             route_snapshot_path,
                             sizeof(route_snapshot_path), dispatch_path,
                             sizeof(dispatch_path), &dispatch_storage,
                             &route_runtime, &completion_timeout_ms) != 0) {
        return 1;
    }
    physical_node_id = (int)storage.manifest.physical_node_id;
    {
        uint64_t local_memory_bytes;
        char name_error[256] = {0};

        if (physical_node_id <= 0 ||
            sum_local_memory_bytes(&storage.manifest, &local_memory_bytes) !=
                0 ||
            local_memory_bytes == 0 ||
            storage.manifest.launch_plan.guest_total_memory_bytes == 0 ||
            storage.manifest.launch_plan.guest_total_memory_bytes %
                    (1024ULL * 1024ULL) !=
                0) {
            fprintf(stderr,
                    "[node-runtime] admitted manifest has no usable local "
                    "resource context\n");
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
        memset(&runtime_context, 0, sizeof(runtime_context));
        runtime_context.manifest_path = manifest_path;
        runtime_context.route_snapshot_path = route_snapshot_path;
        runtime_context.dispatch_path = dispatch_path;
        runtime_context.manifest_storage = &storage;
        runtime_context.dispatch_storage = &dispatch_storage;
        if (wvm_runtime_name_set_derive(
                &storage.manifest.local_names, &runtime_context.names,
                name_error, sizeof(name_error)) != 0) {
            fprintf(stderr,
                    "[node-runtime] cannot derive runtime names: %s\n",
                    name_error[0] ? name_error : "invalid local namespace");
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
        runtime_context.manifest = &storage.manifest;
        runtime_context.dispatch = &dispatch_storage.projection;
        runtime_context.runtime_gate = &gate;
        runtime_context.route_runtime = &route_runtime;
        runtime_context.node_instance_id = node_instance_id;
        runtime_context.physical_node_id = (uint32_t)physical_node_id;
        runtime_context.local_primary_vnode =
            dispatch_storage.projection.local_primary.destination_vnode;
        runtime_context.local_vcpu_count =
            (uint32_t)storage.manifest.local_vcpu_assignments.count;
        runtime_context.local_memory_bytes = local_memory_bytes;
        runtime_context.guest_memory_bytes =
            storage.manifest.launch_plan.guest_total_memory_bytes;
        runtime_context.node_runtime_data_port =
            storage.manifest.launch_plan.node_runtime_data_port;
        runtime_context.node_runtime_control_port =
            storage.manifest.launch_plan.node_runtime_control_port;
        runtime_context.executor_service_port =
            storage.manifest.launch_plan.local_executor_service_port;
        runtime_context.executor_control_port =
            storage.manifest.launch_plan.local_executor_control_port;
        runtime_context.executor_worker_count =
            storage.manifest.launch_plan.executor_worker_count;
        runtime_context.sync_batch_size =
            storage.manifest.launch_plan.sync_batch_size;
        if (snprintf(guest_memory_mb_text, sizeof(guest_memory_mb_text),
                     "%" PRIu64,
                     (uint64_t)(runtime_context.guest_memory_bytes /
                                (1024ULL * 1024ULL))) < 0) {
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
    }
    snprintf(instance_text, sizeof(instance_text), "%llu",
             (unsigned long long)node_instance_id);
    setenv("WVM_RUNTIME_MANIFEST_PATH", manifest_path, 1);
    setenv("WVM_RUNTIME_ROUTE_SNAPSHOT_PATH", route_snapshot_path, 1);
    setenv("WVM_RUNTIME_DISPATCH_PATH", dispatch_path, 1);
    setenv("WVM_NODE_INSTANCE_ID", instance_text, 1);
    setenv("WVM_RUNTIME_GATE_ACTIVE", "1", 1);
    if (export_runtime_identity(&storage.manifest, node_instance_id,
                                physical_node_id) != 0) {
        wvm_runtime_manifest_storage_free(&storage);
        wvm_runtime_dispatch_storage_free(&dispatch_storage);
        wvm_route_runtime_destroy(&route_runtime);
        return 1;
    }
    {
        char value[64];

        snprintf(value, sizeof(value), "%" PRIu64,
                 storage.manifest.required_route_snapshot_key.scope_key
                     .route_scope_id);
        setenv("WVM_ROUTE_SCOPE_ID", value, 1);
        snprintf(value, sizeof(value), "%" PRIu64,
                 storage.manifest.required_route_snapshot_key.topology_revision);
        setenv("WVM_TOPOLOGY_REVISION", value, 1);
        snprintf(value, sizeof(value), "%" PRIu64,
                 storage.manifest.required_route_snapshot_key.route_generation);
        setenv("WVM_ROUTE_GENERATION", value, 1);
        export_hex_env("WVM_ROUTE_SNAPSHOT_DIGEST",
                       storage.manifest.required_route_snapshot_key
                           .snapshot_digest,
                       sizeof(storage.manifest.required_route_snapshot_key
                                  .snapshot_digest));
        snprintf(value, sizeof(value), "%u",
                 (unsigned)dispatch_storage.projection.local_primary
                     .destination_kind);
        setenv("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_KIND", value, 1);
        snprintf(value, sizeof(value), "%" PRIu64,
                 dispatch_storage.projection.local_primary.destination_scope);
        setenv("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_SCOPE", value, 1);
        snprintf(value, sizeof(value), "%u",
                 (unsigned)dispatch_storage.projection.local_primary
                     .destination_vnode);
        setenv("WVM_RUNTIME_LOCAL_PRIMARY_DESTINATION_VNODE", value, 1);
    }
    if (derive_runtime_profile_digest(&storage.manifest,
                                      capability_profile_digest) != 0) {
        wvm_runtime_manifest_storage_free(&storage);
        wvm_runtime_dispatch_storage_free(&dispatch_storage);
        wvm_route_runtime_destroy(&route_runtime);
        return 1;
    }
    export_hex_env("WVM_CAPABILITY_PROFILE_DIGEST", capability_profile_digest,
                   sizeof(capability_profile_digest));
    {
        struct wvm_runtime_registration registration;
        char error[256] = {0};

        memset(&registration, 0, sizeof(registration));
        registration.connection_role = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        registration.vm_id = storage.manifest.vm_id;
        registration.vm_incarnation = storage.manifest.vm_incarnation;
        registration.manifest_generation = storage.manifest.manifest_generation;
        memcpy(registration.candidate_manifest_digest,
               storage.manifest.candidate_manifest_digest,
               sizeof(registration.candidate_manifest_digest));
        registration.local_runtime_instance_id = node_instance_id;
        registration.caller_process_instance_id = (uint64_t)getpid();
        memcpy(registration.capability_profile_digest, capability_profile_digest,
               sizeof(registration.capability_profile_digest));
        snprintf(registration.requested_endpoint_name,
                 sizeof(registration.requested_endpoint_name), "%s",
                 storage.manifest.local_names.namespace_name);
        if (wvm_runtime_gate_register(&gate, &registration,
                                      &runtime_connection_id, error,
                                      sizeof(error)) != 0) {
            fprintf(stderr,
                    "[node-runtime] cannot register admitted local caller: %s\n",
                    error[0] ? error : "runtime gate rejected registration");
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
    }

    fprintf(stderr,
            "[node-runtime] admitted vm=%u incarnation=%" PRIu64
            " generation=%" PRIu64 " physical_node=%d\n",
            storage.manifest.vm_id, storage.manifest.vm_incarnation,
            storage.manifest.manifest_generation, physical_node_id);

    {
        struct wvm_executor_bridge_config bridge_config;
        struct wvm_vcpu_handoff_coordinator_config vcpu_config;
        struct wvm_memory_service_config memory_config;
        struct wvm_ingress_config ingress_config;
        char error[256] = {0};

        uint16_t executor_service_port =
            storage.manifest.launch_plan.local_executor_service_port;
        uint16_t node_runtime_port =
            storage.manifest.launch_plan.node_runtime_data_port;
        snprintf(instance_text, sizeof(instance_text), "%u",
                 (unsigned)executor_service_port);
        setenv("WVM_EXECUTOR_SERVICE_PORT", instance_text, 1);
        snprintf(instance_text, sizeof(instance_text), "%u",
                 (unsigned)node_runtime_port);
        setenv("WVM_RUNTIME_LOCAL_PORT", instance_text, 1);
        setenv("WVM_TCG_QEMU_MACHINE",
               storage.manifest.launch_plan.guest_machine.machine_type, 1);
        setenv("WVM_TCG_QEMU_MEM_MB", guest_memory_mb_text, 1);
        if (print_launch_env) {
            print_launch_environment();
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 0;
        }
        if (init_memory_network_context(
                &memory_network, &dispatch_storage.projection, error,
                sizeof(error)) != 0) {
            fprintf(stderr,
                    "[node-runtime] cannot initialize local sidecar "
                    "transport: %s\n",
                    error[0] ? error : "invalid sidecar endpoint");
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
        memset(&bridge_config, 0, sizeof(bridge_config));
        bridge_config.manifest = &storage.manifest;
        bridge_config.runtime_gate = &gate;
        bridge_config.dispatch = &dispatch_storage.projection;
        bridge_config.route_runtime = &route_runtime;
        bridge_config.local_runtime_instance_id = node_instance_id;
        bridge_config.runtime_connection_id = runtime_connection_id;
        bridge_config.operation_retention_horizon_ms = completion_timeout_ms;
        bridge_config.execute_handoff =
            wvm_executor_runtime_execute_handoff;
        bridge_config.execute_handoff_opaque = &runtime_context;
        bridge_config.send_envelope = send_runtime_envelope;
        bridge_config.send_envelope_opaque = &memory_network;
        if (wvm_executor_bridge_dispatch_init(
                &bridge_config, &executor_dispatch_opaque, error,
                sizeof(error)) != 0) {
            fprintf(stderr, "[node-runtime] cannot initialize executor bridge: %s\n",
                    error[0] ? error : "invalid typed executor boundary");
            destroy_memory_network_context(&memory_network);
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
        memset(&memory_config, 0, sizeof(memory_config));
        memory_config.dispatch = &dispatch_storage.projection;
        memory_config.route_runtime = &route_runtime;
        memory_config.local_physical_node_id = (uint32_t)physical_node_id;
        memory_config.local_node_instance_id = node_instance_id;
        memory_config.local_runtime_instance_id = node_instance_id;
        memory_config.completion_timeout_ms = completion_timeout_ms;
        memory_config.read_page = read_authoritative_local_page;
        memory_config.commit_page = commit_authoritative_local_page;
        memory_config.publish_commit = publish_authoritative_local_page;
        memory_config.complete_commit = complete_memory_commit;
        memory_config.complete_fault = complete_memory_fault;
        memory_config.send_envelope = send_runtime_envelope;
        memory_config.opaque = &memory_network;
        if (wvm_memory_service_init(&memory_service, &memory_config, error,
                                       sizeof(error)) != 0 ||
            wvm_memory_service_global_install(&memory_service, error,
                                                 sizeof(error)) != 0) {
            fprintf(stderr,
                    "[node-runtime] cannot initialize V1 memory service: %s\n",
                    error[0] ? error : "invalid V1 memory state");
            wvm_memory_service_destroy(&memory_service);
            wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
            destroy_memory_network_context(&memory_network);
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
        memset(&vcpu_config, 0, sizeof(vcpu_config));
        vcpu_config.manifest = &storage.manifest;
        vcpu_config.runtime_gate = &gate;
        vcpu_config.dispatch = &dispatch_storage.projection;
        vcpu_config.route_runtime = &route_runtime;
        vcpu_config.local_runtime_instance_id = node_instance_id;
        vcpu_config.runtime_connection_id = runtime_connection_id;
        vcpu_config.operation_retention_horizon_ms = completion_timeout_ms;
        vcpu_config.send_envelope = send_runtime_envelope;
        vcpu_config.send_envelope_opaque = &memory_network;
        vcpu_config.complete = wvm_vcpu_service_complete;
        vcpu_config.complete_opaque = &vcpu_service;
        if (wvm_vcpu_handoff_coordinator_init(
                &vcpu_coordinator, &vcpu_config, error, sizeof(error)) != 0) {
            fprintf(stderr,
                    "[node-runtime] cannot initialize vCPU handoff "
                    "coordinator: %s\n",
                    error[0] ? error : "invalid admitted vCPU state");
            wvm_memory_service_global_uninstall(&memory_service);
            wvm_memory_service_destroy(&memory_service);
            wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
            destroy_memory_network_context(&memory_network);
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
        {
            struct wvm_vcpu_service_config vcpu_service_config;

            memset(&vcpu_service_config, 0, sizeof(vcpu_service_config));
            vcpu_service_config.coordinator = &vcpu_coordinator;
            vcpu_service_config.record_capacity =
                storage.manifest.launch_plan.vcpu_handoff_record_capacity;
            if (wvm_vcpu_service_init(&vcpu_service, &vcpu_service_config,
                                      error, sizeof(error)) != 0 ||
                wvm_vcpu_service_global_install(&vcpu_service, error,
                                                sizeof(error)) != 0) {
                fprintf(stderr,
                        "[node-runtime] cannot initialize local vCPU "
                        "service: %s\n",
                        error[0] ? error : "invalid admitted vCPU state");
                wvm_vcpu_service_global_uninstall(&vcpu_service);
                wvm_vcpu_service_destroy(&vcpu_service);
                wvm_vcpu_handoff_coordinator_destroy(&vcpu_coordinator);
                wvm_memory_service_global_uninstall(&memory_service);
                wvm_memory_service_destroy(&memory_service);
                wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
                destroy_memory_network_context(&memory_network);
                wvm_runtime_manifest_storage_free(&storage);
                wvm_runtime_dispatch_storage_free(&dispatch_storage);
                wvm_route_runtime_destroy(&route_runtime);
                return 1;
            }
        }
        memset(&ingress_config, 0, sizeof(ingress_config));
        ingress_config.manifest = &storage.manifest;
        ingress_config.runtime_gate = &gate;
        ingress_config.runtime_connection_id = runtime_connection_id;
        ingress_config.memory_dispatch = wvm_memory_service_dispatch;
        ingress_config.memory_dispatch_opaque = &memory_service;
        ingress_config.vcpu_dispatch = wvm_executor_bridge_dispatch;
        ingress_config.vcpu_dispatch_opaque = executor_dispatch_opaque;
        ingress_config.vcpu_result_dispatch =
            wvm_vcpu_handoff_coordinator_dispatch;
        ingress_config.vcpu_result_dispatch_opaque = &vcpu_coordinator;
        if (wvm_ingress_global_init(&ingress_config, error,
                                       sizeof(error)) != 0) {
            fprintf(stderr, "[node-runtime] cannot initialize V1 ingress: %s\n",
                    error[0] ? error : "invalid admitted ingress state");
            wvm_vcpu_service_global_uninstall(&vcpu_service);
            wvm_vcpu_service_destroy(&vcpu_service);
            wvm_memory_service_global_uninstall(&memory_service);
            wvm_memory_service_destroy(&memory_service);
            wvm_vcpu_handoff_coordinator_destroy(&vcpu_coordinator);
            wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
            destroy_memory_network_context(&memory_network);
            wvm_runtime_manifest_storage_free(&storage);
            wvm_runtime_dispatch_storage_free(&dispatch_storage);
            wvm_route_runtime_destroy(&route_runtime);
            return 1;
        }
    }

    executor_launch.runtime = &runtime_context;
    if (pthread_create(&executor_thread, NULL, run_executor_role,
                       &executor_launch) != 0) {
        perror("[node-runtime] cannot start local executor role");
        wvm_vcpu_service_global_uninstall(&vcpu_service);
        wvm_vcpu_service_destroy(&vcpu_service);
        wvm_memory_service_global_uninstall(&memory_service);
        wvm_memory_service_destroy(&memory_service);
        wvm_vcpu_handoff_coordinator_destroy(&vcpu_coordinator);
        wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
        destroy_memory_network_context(&memory_network);
        wvm_runtime_manifest_storage_free(&storage);
        wvm_runtime_dispatch_storage_free(&dispatch_storage);
        wvm_route_runtime_destroy(&route_runtime);
        return 1;
    }

    /*
     * The executor must publish a usable local listener before the semantic
     * coordinator can accept a vCPU handoff. This is a lifecycle gate, not a
     * timing workaround: failure is reported by the executor startup state.
     */
    if (wvm_executor_runtime_wait_ready() != 0) {
        fprintf(stderr,
                "[node-runtime] local executor did not reach ready state\n");
        g_shutdown_requested = 1;
        pthread_join(executor_thread, &executor_result);
        wvm_vcpu_service_global_uninstall(&vcpu_service);
        wvm_vcpu_service_destroy(&vcpu_service);
        wvm_memory_service_global_uninstall(&memory_service);
        wvm_memory_service_destroy(&memory_service);
        wvm_vcpu_handoff_coordinator_destroy(&vcpu_coordinator);
        wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
        destroy_memory_network_context(&memory_network);
        wvm_runtime_manifest_storage_free(&storage);
        wvm_runtime_dispatch_storage_free(&dispatch_storage);
        wvm_route_runtime_destroy(&route_runtime);
        return 1;
    }

    master_launch.runtime = &runtime_context;
    if (pthread_create(&master_thread, NULL, run_master_role,
                       &master_launch) != 0) {
        perror("[node-runtime] cannot start node-runtime coordinator role");
        g_shutdown_requested = 1;
        pthread_join(executor_thread, &executor_result);
        wvm_vcpu_service_global_uninstall(&vcpu_service);
        wvm_vcpu_service_destroy(&vcpu_service);
        wvm_memory_service_global_uninstall(&memory_service);
        wvm_memory_service_destroy(&memory_service);
        wvm_vcpu_handoff_coordinator_destroy(&vcpu_coordinator);
        wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
        destroy_memory_network_context(&memory_network);
        wvm_runtime_manifest_storage_free(&storage);
        wvm_runtime_dispatch_storage_free(&dispatch_storage);
        wvm_route_runtime_destroy(&route_runtime);
        return 1;
    }

    pthread_join(master_thread, &master_result);
    g_shutdown_requested = 1;
    pthread_join(executor_thread, &executor_result);
    wvm_vcpu_service_global_uninstall(&vcpu_service);
    wvm_vcpu_service_destroy(&vcpu_service);
    wvm_memory_service_global_uninstall(&memory_service);
    wvm_memory_service_destroy(&memory_service);
    wvm_vcpu_handoff_coordinator_destroy(&vcpu_coordinator);
    wvm_executor_bridge_dispatch_destroy(executor_dispatch_opaque);
    destroy_memory_network_context(&memory_network);
    wvm_runtime_manifest_storage_free(&storage);
    wvm_runtime_dispatch_storage_free(&dispatch_storage);
    wvm_route_runtime_destroy(&route_runtime);
    return (int)(intptr_t)master_result;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "agent") == 0) {
        return wavevm_admission_agent_main(argc, argv);
    }
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        uint64_t parent_pid;
        char *runtime_argv[6];

        if (argc != 8 || strcmp(argv[2], "--parent-pid") != 0 ||
            strcmp(argv[4], "--manifest") != 0 ||
            strcmp(argv[6], "--node-instance") != 0 ||
            parse_u64(argv[3], &parent_pid) != 0 ||
            prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
            (uint64_t)getppid() != parent_pid) {
            fprintf(stderr, "[node-runtime] child is not bound to its agent\n");
            return 2;
        }
        runtime_argv[0] = argv[0];
        runtime_argv[1] = argv[4];
        runtime_argv[2] = argv[5];
        runtime_argv[3] = argv[6];
        runtime_argv[4] = argv[7];
        runtime_argv[5] = NULL;
        return run_runtime_main(5, runtime_argv);
    }
    return run_runtime_main(argc, argv);
}

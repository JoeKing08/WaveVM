/*
 * [IDENTITY] Main Wrapper - The Identity Mapper
 * ---------------------------------------------------------------------------
 * 物理角色：Daemon 的启动引擎与"身份翻译官"。
 * 职责边界：
 * 1. 解析 swarm_config，将物理资源容量、DHT 权重和 VM placement 分离。
 * 2. 初始化共享内存后端，建立 QEMU 与 Daemon 的 IPC 桥梁。
 * 3. 启动自治监控线程 (Gossip)，驱动节点生命周期演进。
 * 
 * [禁止事项]
 * - 严禁在未显式配置 dht_slots 时改变兼容的 RAM/4GB DHT slot 规则。
 * - 严禁在 QEMU 建立连接前提前释放资源。
 * ---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>

#include "logic_core.h"
#include "../common_include/wavevm_protocol.h"
#include "../common_include/wavevm_ioctl.h"
#include "../common_include/wavevm_config.h"
#include "../common_include/wavevm_resources.h"
#include "../common_include/wavevm_membership.h"
#include "../common_include/wavevm_route_delivery.h"
#include "../common_include/wavevm_runtime_dispatch.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../common_include/wavevm_runtime_names.h"
#include "../common_include/wavevm_local_memory.h"
#include "../common_include/wavevm_memory.h"
#include "../node_runtime/memory_service.h"
#include "../node_runtime/vcpu_service.h"

// --- 全局状态 ---
extern struct dsm_driver_ops u_ops;
extern int user_backend_init(int my_node_id, int port);
void *g_shm_ptr = NULL;
size_t g_shm_size = 0;
int g_dev_fd = -1;
extern int g_my_node_id;
uint8_t g_my_vm_id = 0;  // Multi-VM: 默认 0，向后兼容
static struct wvm_resource_plan g_resource_plan;
static int g_resource_plan_ready = 0;
static struct wvm_runtime_manifest_storage g_runtime_storage;
static struct wvm_runtime_gate g_runtime_gate;
static int g_runtime_gate_active = 0;
static struct wvm_runtime_dispatch_storage g_runtime_dispatch_storage;
static int g_runtime_dispatch_active = 0;
static int g_runtime_dispatch_kernel_memory_cache = 0;
static pthread_mutex_t g_runtime_gate_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_runtime_operation_sequence = 1;
volatile sig_atomic_t g_shutdown_requested = 0;

#define MAX_QEMU_CLIENTS 8

static void request_shutdown(int signal_number)
{
    (void)signal_number;
    g_shutdown_requested = 1;
}

static int install_shutdown_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = request_shutdown;
    sigemptyset(&action.sa_mask);
    /* Do not use SA_RESTART: accept() must return so the main thread owns
     * the lifecycle teardown instead of leaving readiness published forever. */
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        return -1;
    }
    return 0;
}

static int parse_runtime_u64(const char *text, uint64_t *value)
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

static int parse_legacy_vm_id(const char *text, uint8_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (!text || !*text || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > UINT8_MAX) {
        return -1;
    }
    *value = (uint8_t)parsed;
    return 0;
}

static int runtime_gate_enabled_by_environment(void)
{
    const char *value = getenv("WVM_RUNTIME_GATE_ACTIVE");

    return value && value[0] != '\0' && strcmp(value, "0") != 0;
}

static int runtime_route_key_equal(const struct wvm_route_snapshot_key *left,
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

static int init_runtime_dispatch_from_environment(void)
{
    const char *dispatch_path;
    const struct wvm_runtime_dispatch_projection *dispatch;
    char error[256] = {0};

    if (!runtime_gate_enabled_by_environment()) {
        return 0;
    }
    dispatch_path = getenv("WVM_RUNTIME_DISPATCH_PATH");
    if (!dispatch_path || !g_runtime_storage.manifest.has_activation_fence) {
        fprintf(stderr,
                "[RuntimeDispatch] active runtime is missing dispatch input\n");
        return -1;
    }

    wvm_runtime_dispatch_storage_init(&g_runtime_dispatch_storage);
    if (wvm_runtime_dispatch_file_load(dispatch_path,
                                       &g_runtime_dispatch_storage, error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "[RuntimeDispatch] cannot load dispatch: %s\n",
                error[0] ? error : "invalid dispatch artifact");
        wvm_runtime_dispatch_storage_free(&g_runtime_dispatch_storage);
        return -1;
    }
    dispatch = &g_runtime_dispatch_storage.projection;
    if (memcmp(dispatch->candidate_manifest_digest,
               g_runtime_storage.manifest.candidate_manifest_digest,
               sizeof(dispatch->candidate_manifest_digest)) != 0 ||
        dispatch->vm_id != g_runtime_storage.manifest.vm_id ||
        dispatch->vm_incarnation != g_runtime_storage.manifest.vm_incarnation ||
        dispatch->manifest_generation !=
            g_runtime_storage.manifest.manifest_generation ||
        dispatch->physical_node_id !=
            g_runtime_storage.manifest.physical_node_id ||
        dispatch->expected_node_instance_id !=
            g_runtime_storage.manifest.expected_node_instance_id ||
        memcmp(dispatch->activation_fence,
               g_runtime_storage.manifest.activation_fence,
               sizeof(dispatch->activation_fence)) != 0 ||
        !runtime_route_key_equal(
            &dispatch->required_route_snapshot_key,
            &g_runtime_storage.manifest.required_route_snapshot_key)) {
        fprintf(stderr,
                "[RuntimeDispatch] dispatch does not match admitted manifest\n");
        wvm_runtime_dispatch_storage_free(&g_runtime_dispatch_storage);
        return -1;
    }
    g_runtime_dispatch_active = 1;
    return 0;
}

static int runtime_dispatch_populate_legacy_memory_cache(
    const struct wvm_runtime_dispatch_projection *dispatch)
{
    const uint64_t legacy_chunk_bytes = UINT64_C(1) << WVM_ROUTING_SHIFT;
    size_t i;

    if (!dispatch ||
        dispatch->route_topology_kind != WVM_ROUTE_TOPOLOGY_FLAT) {
        return 0;
    }
    for (i = 0; i < dispatch->memory_dispatch.count; i++) {
        const struct wvm_runtime_memory_dispatch *entry =
            &dispatch->memory_dispatch.entries[i];
        uint64_t first_chunk;
        uint64_t chunk_count;

        if (entry->gpa_start % legacy_chunk_bytes != 0 ||
            entry->bytes % legacy_chunk_bytes != 0 ||
            entry->directory.destination_kind !=
                WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE ||
            entry->directory.destination_scope != 0) {
            return 0;
        }
        first_chunk = entry->gpa_start / legacy_chunk_bytes;
        chunk_count = entry->bytes / legacy_chunk_bytes;
        if (first_chunk >= WVM_MEMORY_ROUTE_TABLE_SIZE ||
            chunk_count > WVM_MEMORY_ROUTE_TABLE_SIZE - first_chunk) {
            return 0;
        }
    }
    for (i = 0; i < dispatch->memory_dispatch.count; i++) {
        const struct wvm_runtime_memory_dispatch *entry =
            &dispatch->memory_dispatch.entries[i];
        uint64_t first_chunk = entry->gpa_start / legacy_chunk_bytes;
        uint64_t chunk_count = entry->bytes / legacy_chunk_bytes;
        uint64_t chunk;

        for (chunk = 0; chunk < chunk_count; chunk++) {
            wvm_set_memory_mapping((int)(first_chunk + chunk),
                                   entry->directory.destination_vnode);
        }
    }
    return 1;
}

static int runtime_dispatch_legacy_vnode_count(
    const struct wvm_runtime_dispatch_projection *dispatch,
    uint32_t *count_out)
{
    uint32_t maximum;
    size_t i;

    if (!dispatch || !count_out ||
        dispatch->route_topology_kind != WVM_ROUTE_TOPOLOGY_FLAT ||
        dispatch->local_primary.destination_kind !=
            WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE ||
        dispatch->local_primary.destination_scope != 0) {
        return -1;
    }
    maximum = dispatch->local_primary.destination_vnode;
    for (i = 0; i < dispatch->cpu_dispatch.count; i++) {
        const struct wvm_runtime_route_destination *destination =
            &dispatch->cpu_dispatch.entries[i].executor;

        if (destination->destination_kind !=
                WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE ||
            destination->destination_scope != 0) {
            return -1;
        }
        if (destination->destination_vnode > maximum) {
            maximum = destination->destination_vnode;
        }
    }
    for (i = 0; i < dispatch->memory_dispatch.count; i++) {
        const struct wvm_runtime_memory_dispatch *entry =
            &dispatch->memory_dispatch.entries[i];

        if (entry->directory.destination_kind !=
                WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE ||
            entry->directory.destination_scope != 0 ||
            entry->executor.destination_kind !=
                WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE ||
            entry->executor.destination_scope != 0) {
            return -1;
        }
        if (entry->directory.destination_vnode > maximum) {
            maximum = entry->directory.destination_vnode;
        }
        if (entry->executor.destination_vnode > maximum) {
            maximum = entry->executor.destination_vnode;
        }
    }
    if (maximum == UINT32_MAX) {
        return -1;
    }
    *count_out = maximum + 1U;
    return 0;
}

static int apply_runtime_dispatch(void)
{
    const struct wvm_runtime_dispatch_projection *dispatch;
    uint32_t sidecar_ip = 0;
    uint32_t legacy_vnode_count;
    size_t i;

    if (!g_runtime_dispatch_active) {
        return -1;
    }
    dispatch = &g_runtime_dispatch_storage.projection;

    /*
     * A fractal route has no lossless representation in the legacy logic-core
     * arrays: the pod/scope is part of the destination identity.  The local
     * node-runtime services already consume the typed projection, so the only
     * compatibility state needed here is the local sidecar endpoint.  Keep
     * the legacy route cache entirely out of this path instead of flattening a
     * scoped destination into a raw vnode.
     */
    if (dispatch->route_topology_kind == WVM_ROUTE_TOPOLOGY_FRACTAL) {
        memcpy(&sidecar_ip, dispatch->local_sidecar_endpoint.data_address,
               sizeof(sidecar_ip));
        if (!u_ops.set_gateway_ip ||
            dispatch->local_primary.destination_vnode >= WVM_MAX_GATEWAYS ||
            dispatch->local_sidecar_endpoint.data_port == 0) {
            return -1;
        }
        u_ops.set_gateway_ip(
            WVM_ENCODE_ID(g_my_vm_id,
                          dispatch->local_primary.destination_vnode),
            sidecar_ip, htons(dispatch->local_sidecar_endpoint.data_port));
        return 0;
    }
    if (runtime_dispatch_legacy_vnode_count(dispatch, &legacy_vnode_count) !=
        0) {
        /*
         * The legacy logic-core route arrays have no Pod/scope dimension.
         * Do not flatten a fractal admitted route into raw vnode IDs.
         */
        return -1;
    }
    memcpy(&sidecar_ip, dispatch->local_sidecar_endpoint.data_address,
           sizeof(sidecar_ip));

    /*
     * The node runtime has exactly one fabric peer: its local sidecar.  Each
     * compatibility target entry deliberately resolves to that peer; the
     * immutable route snapshot remains the cross-node routing authority.
     */
    for (i = 0; i < legacy_vnode_count; i++) {
        u_ops.set_gateway_ip(WVM_ENCODE_ID(g_my_vm_id, (uint32_t)i),
                             sidecar_ip,
                             htons(dispatch->local_sidecar_endpoint.data_port));
    }

    wvm_set_mem_mapping(0, legacy_vnode_count);
    wvm_clear_cpu_mappings();
    wvm_clear_memory_mappings();
    for (i = 0; i < dispatch->cpu_dispatch.count; i++) {
        if (wvm_get_cpu_mapping_raw(
                (int)dispatch->cpu_dispatch.entries[i].guest_vcpu_index) !=
            WVM_NODE_AUTO_ROUTE) {
            return -1;
        }
        wvm_set_cpu_mapping(
            (int)dispatch->cpu_dispatch.entries[i].guest_vcpu_index,
            dispatch->cpu_dispatch.entries[i].executor.destination_vnode);
    }
    for (i = 0; i < dispatch->memory_dispatch.count; i++) {
        const struct wvm_runtime_memory_dispatch *entry =
            &dispatch->memory_dispatch.entries[i];

        if (wvm_set_memory_range_mapping(entry->gpa_start, entry->bytes,
                                         entry->directory.destination_vnode) !=
            0) {
            return -1;
        }
    }
    g_runtime_dispatch_kernel_memory_cache =
        runtime_dispatch_populate_legacy_memory_cache(dispatch);
    return 0;
}

static int runtime_dispatch_local_reservation(uint32_t *local_vcpus,
                                              uint64_t *local_memory_bytes)
{
    const struct wvm_memory_chunk_assignment_list *memory;
    uint64_t bytes = 0;
    size_t i;

    if (!g_runtime_dispatch_active || !local_vcpus || !local_memory_bytes) {
        return -1;
    }
    memory = &g_runtime_storage.manifest.local_memory_assignments;
    for (i = 0; i < memory->count; i++) {
        if (bytes > UINT64_MAX - memory->entries[i].bytes) {
            return -1;
        }
        bytes += memory->entries[i].bytes;
    }
    *local_vcpus =
        (uint32_t)g_runtime_storage.manifest.local_vcpu_assignments.count;
    *local_memory_bytes = bytes;
    return 0;
}

static int init_runtime_gate_from_environment(int physical_node_id)
{
    const char *manifest_path;
    const char *node_instance_text;
    struct wvm_route_snapshot_file_storage route_storage;
    char route_path[WVM_ROUTE_DELIVERY_PATH_MAX];
    uint64_t node_instance_id;
    char error[256] = {0};

    if (!runtime_gate_enabled_by_environment()) {
        return 0;
    }
    manifest_path = getenv("WVM_RUNTIME_MANIFEST_PATH");
    node_instance_text = getenv("WVM_NODE_INSTANCE_ID");
    if (!manifest_path ||
        parse_runtime_u64(node_instance_text, &node_instance_id) != 0) {
        fprintf(stderr,
                "[RuntimeGate] active but manifest path/node instance is "
                "missing\n");
        return -1;
    }

    wvm_route_snapshot_file_storage_init(&route_storage);
    wvm_runtime_manifest_storage_init(&g_runtime_storage);
    wvm_runtime_gate_init(&g_runtime_gate);
    if (wvm_runtime_manifest_load_file(manifest_path, &g_runtime_storage,
                                       error, sizeof(error)) != 0 ||
        g_runtime_storage.manifest.vm_id != g_my_vm_id ||
        wvm_runtime_gate_prepare(&g_runtime_gate, &g_runtime_storage.manifest,
                                 (uint32_t)physical_node_id, node_instance_id,
                                 error, sizeof(error)) != 0 ||
        wvm_runtime_gate_activate(&g_runtime_gate,
                                  g_runtime_storage.manifest.activation_fence,
                                  error, sizeof(error)) != 0) {
        fprintf(stderr, "[RuntimeGate] master role rejected manifest: %s\n",
                error[0] ? error : "manifest VM identity mismatch");
        wvm_runtime_manifest_storage_free(&g_runtime_storage);
        wvm_route_snapshot_file_storage_free(&route_storage);
        return -1;
    }
    if (wvm_route_snapshot_path_from_manifest(
            manifest_path, route_path, sizeof(route_path), error,
            sizeof(error)) != 0 ||
        wvm_route_snapshot_file_load(route_path, &route_storage, error,
                                     sizeof(error)) != 0 ||
        wvm_route_snapshot_file_matches(
            &route_storage,
            &g_runtime_storage.manifest.required_route_snapshot_key, error,
            sizeof(error)) != 0) {
        fprintf(stderr, "[RuntimeGate] master role rejected route snapshot: %s\n",
                error[0] ? error : "route snapshot identity mismatch");
        wvm_runtime_manifest_storage_free(&g_runtime_storage);
        wvm_route_snapshot_file_storage_free(&route_storage);
        return -1;
    }
    setenv("WVM_RUNTIME_ROUTE_SNAPSHOT_PATH", route_path, 1);
    wvm_route_snapshot_file_storage_free(&route_storage);
    g_runtime_gate_active = 1;
    if (init_runtime_dispatch_from_environment() != 0) {
        g_runtime_gate_active = 0;
        wvm_runtime_manifest_storage_free(&g_runtime_storage);
        return -1;
    }
    return 0;
}

static int runtime_gate_register_qemu(
    const struct wvm_ipc_runtime_registration *wire_registration,
    uint64_t *connection_id_out)
{
    struct wvm_runtime_registration registration;
    char error[256] = {0};
    int result;

    if (!wire_registration ||
        wire_registration->magic != WVM_IPC_REGISTRATION_MAGIC ||
        wire_registration->version != WVM_IPC_REGISTRATION_VERSION ||
        wire_registration->connection_role != WVM_MANIFEST_ROLE_QEMU_FRONTEND) {
        return -1;
    }
    memset(&registration, 0, sizeof(registration));
    registration.connection_role =
        (enum wvm_manifest_role_type)wire_registration->connection_role;
    registration.vm_id = wire_registration->vm_id;
    registration.vm_incarnation = wire_registration->vm_incarnation;
    registration.manifest_generation = wire_registration->manifest_generation;
    memcpy(registration.candidate_manifest_digest,
           wire_registration->candidate_manifest_digest,
           sizeof(registration.candidate_manifest_digest));
    registration.local_runtime_instance_id =
        wire_registration->local_runtime_instance_id;
    registration.caller_process_instance_id =
        wire_registration->caller_process_instance_id;
    memcpy(registration.capability_profile_digest,
           wire_registration->capability_profile_digest,
           sizeof(registration.capability_profile_digest));
    memcpy(registration.requested_endpoint_name,
           wire_registration->requested_endpoint_name,
           sizeof(registration.requested_endpoint_name));

    pthread_mutex_lock(&g_runtime_gate_lock);
    result = wvm_runtime_gate_register(&g_runtime_gate, &registration,
                                       connection_id_out, error,
                                       sizeof(error));
    pthread_mutex_unlock(&g_runtime_gate_lock);
    if (result != 0) {
        fprintf(stderr, "[RuntimeGate] QEMU registration rejected: %s\n",
                error[0] ? error : "identity mismatch");
    }
    return result;
}

static int runtime_gate_authorize_connection(uint64_t connection_id)
{
    struct wvm_runtime_operation operation;
    uint64_t operation_id;
    char error[256] = {0};
    int result;

    if (!g_runtime_gate_active) {
        return 0;
    }
    memset(&operation, 0, sizeof(operation));
    operation_id = __sync_fetch_and_add(&g_runtime_operation_sequence, 1);
    if (operation_id == 0) {
        operation_id = 1;
    }
    operation.connection_id = connection_id;
    operation.vm_id = g_runtime_storage.manifest.vm_id;
    operation.vm_incarnation = g_runtime_storage.manifest.vm_incarnation;
    operation.manifest_generation =
        g_runtime_storage.manifest.manifest_generation;
    memcpy(operation.candidate_manifest_digest,
           g_runtime_storage.manifest.candidate_manifest_digest,
           sizeof(operation.candidate_manifest_digest));
    operation.route_snapshot_key =
        g_runtime_storage.manifest.required_route_snapshot_key;
    memcpy(operation.activation_fence,
           g_runtime_storage.manifest.activation_fence,
           sizeof(operation.activation_fence));
    memcpy(operation.operation_id, &operation_id, sizeof(operation_id));

    pthread_mutex_lock(&g_runtime_gate_lock);
    result = wvm_runtime_gate_authorize(&g_runtime_gate, &operation, error,
                                        sizeof(error));
    pthread_mutex_unlock(&g_runtime_gate_lock);
    if (result != 0) {
        fprintf(stderr, "[RuntimeGate] IPC operation rejected: %s\n",
                error[0] ? error : "authorization failure");
    }
    return result;
}

static int bind_kernel_context_from_manifest(uint32_t physical_node_id)
{
    struct wvm_ioctl_context_bind request;
    uint8_t profile_digest[WVM_KERNEL_DIGEST_BYTES];
    char error[256] = {0};

    if (g_dev_fd < 0 || !g_runtime_gate_active) return 0;
    if (!g_runtime_storage.manifest.has_activation_fence ||
        wvm_runtime_manifest_profile_digest(&g_runtime_storage.manifest,
                                            profile_digest, error,
                                            sizeof(error)) != 0) {
        fprintf(stderr,
                "[KernelContext] manifest has no valid activation/profile "
                "identity: %s\n",
                error[0] ? error : "invalid manifest");
        return -1;
    }

    memset(&request, 0, sizeof(request));
    request.magic = WVM_KERNEL_CONTEXT_MAGIC;
    request.version = WVM_KERNEL_CONTEXT_ABI_VERSION;
    request.vm_id = g_runtime_storage.manifest.vm_id;
    request.physical_node_id = physical_node_id;
    request.vm_incarnation = g_runtime_storage.manifest.vm_incarnation;
    request.manifest_generation =
        g_runtime_storage.manifest.manifest_generation;
    memcpy(request.candidate_manifest_digest,
           g_runtime_storage.manifest.candidate_manifest_digest,
           sizeof(request.candidate_manifest_digest));
    memcpy(request.capability_profile_digest, profile_digest,
           sizeof(request.capability_profile_digest));
    memcpy(request.activation_fence,
           g_runtime_storage.manifest.activation_fence,
           sizeof(request.activation_fence));
    request.route_snapshot_key.scope_key.vm_id =
        g_runtime_storage.manifest.required_route_snapshot_key.scope_key.vm_id;
    request.route_snapshot_key.scope_key.vm_incarnation =
        g_runtime_storage.manifest.required_route_snapshot_key.scope_key
            .vm_incarnation;
    request.route_snapshot_key.scope_key.route_scope_id =
        g_runtime_storage.manifest.required_route_snapshot_key.scope_key
            .route_scope_id;
    request.route_snapshot_key.topology_revision =
        g_runtime_storage.manifest.required_route_snapshot_key.topology_revision;
    request.route_snapshot_key.route_generation =
        g_runtime_storage.manifest.required_route_snapshot_key.route_generation;
    memcpy(request.route_snapshot_key.snapshot_digest,
           g_runtime_storage.manifest.required_route_snapshot_key
               .snapshot_digest,
           sizeof(request.route_snapshot_key.snapshot_digest));

    if (ioctl(g_dev_fd, IOCTL_WVM_BIND_CONTEXT, &request) < 0) {
        fprintf(stderr,
                "[KernelContext] manifest-bound Mode A context rejected: "
                "errno=%d (%s)\n",
                errno, strerror(errno));
        return -1;
    }
    fprintf(stderr,
            "[KernelContext] bound VM=%u incarnation=%" PRIu64
            " node=%u (single-context Mode A gate)\n",
            request.vm_id, request.vm_incarnation, request.physical_node_id);
    return 0;
}

static void inject_cpu_route_table(void) {
    if (g_dev_fd < 0) return;
    const uint32_t *table = wvm_get_cpu_route_table();
    if (!table) return;

    const uint32_t chunk_size = 1024;
    size_t buf_size = sizeof(struct wvm_ioctl_route_update) + chunk_size * sizeof(uint32_t);
    struct wvm_ioctl_route_update *payload = malloc(buf_size);
    if (!payload) {
        fprintf(stderr, "[CPU-ROUTE] malloc failed\n");
        return;
    }

    for (uint32_t i = 0; i < WVM_CPU_ROUTE_TABLE_SIZE; i += chunk_size) {
        uint32_t count = chunk_size;
        if (i + count > WVM_CPU_ROUTE_TABLE_SIZE) count = WVM_CPU_ROUTE_TABLE_SIZE - i;

        payload->start_index = i;
        payload->count = count;
        memcpy(payload->entries, &table[i], count * sizeof(uint32_t));

        if (ioctl(g_dev_fd, IOCTL_UPDATE_CPU_ROUTE, payload) < 0) {
            fprintf(stderr, "[CPU-ROUTE] inject failed at %u (errno=%d)\n", i, errno);
            free(payload);
            return;
        }
    }

    fprintf(stderr, "[CPU-ROUTE] injected %u entries\n", (unsigned)WVM_CPU_ROUTE_TABLE_SIZE);
    free(payload);
}

static void inject_memory_route_table(void) {
    const uint32_t *table;
    const uint32_t chunk_size = 1024;
    size_t buf_size;
    struct wvm_ioctl_route_update *payload;

    if (g_dev_fd < 0) return;
    table = wvm_get_memory_route_table();
    if (!table) return;

    buf_size = sizeof(*payload) + chunk_size * sizeof(uint32_t);
    payload = malloc(buf_size);
    if (!payload) {
        fprintf(stderr, "[MEM-ROUTE] malloc failed\n");
        return;
    }

    for (uint32_t i = 0; i < WVM_MEMORY_ROUTE_TABLE_SIZE; i += chunk_size) {
        uint32_t count = chunk_size;

        if (i + count > WVM_MEMORY_ROUTE_TABLE_SIZE) {
            count = WVM_MEMORY_ROUTE_TABLE_SIZE - i;
        }
        payload->start_index = i;
        payload->count = count;
        memcpy(payload->entries, &table[i], count * sizeof(uint32_t));
        if (ioctl(g_dev_fd, IOCTL_UPDATE_MEMORY_PLACEMENT, payload) < 0) {
            fprintf(stderr, "[MEM-ROUTE] inject failed at %u (errno=%d)\n",
                    i, errno);
            free(payload);
            return;
        }
    }

    fprintf(stderr, "[MEM-ROUTE] injected %u entries\n",
            (unsigned)WVM_MEMORY_ROUTE_TABLE_SIZE);
    free(payload);
}

static void inject_mem_global(uint32_t slot, uint32_t value) {
    size_t buf_size = sizeof(struct wvm_ioctl_route_update) + sizeof(uint32_t);
    struct wvm_ioctl_route_update *payload;

    if (g_dev_fd < 0) return;
    payload = malloc(buf_size);
    if (!payload) {
        fprintf(stderr, "[MEM-GLOBAL] malloc failed\n");
        return;
    }
    payload->start_index = slot;
    payload->count = 1;
    payload->entries[0] = value;
    if (ioctl(g_dev_fd, IOCTL_UPDATE_MEM_ROUTE, payload) < 0) {
        fprintf(stderr, "[MEM-GLOBAL] inject slot %u failed (errno=%d)\n",
                slot, errno);
    }
    free(payload);
}

static void inject_vm_id(uint8_t vm_id) {
    if (g_dev_fd < 0) return;
    if (ioctl(g_dev_fd, IOCTL_SET_VM_ID, &vm_id) < 0) {
        fprintf(stderr, "[VM-ID] inject failed (errno=%d)\n", errno);
    }
}
#define NUM_BCAST_WORKERS 8

/* [FIX-G2] 坚如磐石的循环读取，处理 Partial Read 和 EINTR */
static ssize_t read_exact(int fd, void *buf, size_t len) {
    size_t received = 0;
    char *ptr = (char *)buf;
    while (received < len) {
        ssize_t ret = read(fd, ptr + received, len - received);
        if (ret > 0) {
            received += ret;
        } else if (ret == 0) {
            return -1; // EOF: 对端关闭
        } else {
            if (errno == EINTR) continue; // 信号中断，重试
            return -1; // 真正的错误
        }
    }
    return (ssize_t)received;
}

/* [FIX] 循环写，处理 partial write 和 EINTR，避免 IPC 流错位 */
static ssize_t write_exact(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    const char *ptr = (const char *)buf;
    while (sent < len) {
        ssize_t ret = write(fd, ptr + sent, len - sent);
        if (ret > 0) {
            sent += ret;
        } else if (ret == 0) {
            return -1;
        } else {
            if (errno == EINTR) continue;
            return -1;
        }
    }
    return (ssize_t)sent;
}

static int g_qemu_clients[8];
static int g_client_count = 0;
static pthread_mutex_t g_client_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_push_barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_push_barrier_cond = PTHREAD_COND_INITIALIZER;
static uint64_t g_push_barrier_next = 1;
static uint64_t g_push_barrier_done = 0;

extern void* broadcast_worker_thread(void* arg);
extern void* autonomous_monitor_thread(void* arg);
int g_sync_batch_size = 64;
void handle_ipc_rpc_passthrough(int qemu_fd, void *data, uint32_t len) { (void)qemu_fd; (void)data; (void)len; }

void load_swarm_config(const char *filename) {
    char error[256] = {0};
    const struct wvm_resource_vm *vm;

    if (!g_resource_plan_ready) {
        if (wvm_resource_plan_load(filename, &g_resource_plan, error,
                                   sizeof(error)) != 0) {
            fprintf(stderr, "[Config] %s\n", error);
            exit(1);
        }
        g_resource_plan_ready = 1;
    }

    printf("[Config] DHT Ring Size: %u Virtual Nodes (from %u Physical).\n",
           g_resource_plan.total_vnodes, g_resource_plan.node_count);
    for (uint32_t i = 0; i < g_resource_plan.node_count; i++) {
        const struct wvm_resource_node *node = &g_resource_plan.nodes[i];

        for (uint32_t slot = 0; slot < node->dht_slots; slot++) {
            uint32_t vnode = node->vnode_start + slot;
            u_ops.set_gateway_ip(WVM_ENCODE_ID(g_my_vm_id, vnode),
                                 inet_addr(node->ip), htons(node->port));
        }
    }
    wvm_set_mem_mapping(0, g_resource_plan.total_vnodes);

    wvm_clear_cpu_mappings();
    wvm_clear_memory_mappings();
    vm = wvm_resource_plan_get_vm(&g_resource_plan, g_my_vm_id);
    if (g_resource_plan.vm_count > 0 && !vm) {
        fprintf(stderr, "[Config] VM %u has no resource reservation\n",
                (unsigned)g_my_vm_id);
        exit(1);
    }

    if (vm) {
        for (uint32_t vcpu = 0; vcpu < vm->vcpu_count; vcpu++) {
            wvm_set_cpu_mapping((int)vcpu, vm->vcpu_nodes[vcpu]);
        }
        for (uint32_t chunk = 0; chunk < vm->memory_chunk_count; chunk++) {
            wvm_set_memory_mapping((int)chunk, vm->memory_nodes[chunk]);
        }
        printf("[Config] VM %u placement: %u vCPUs, %u x 1GiB memory chunks (%s).\n",
               (unsigned)g_my_vm_id, vm->vcpu_count,
               vm->memory_chunk_count,
               vm->policy == WVM_RESOURCE_POLICY_COMPACT ? "compact" : "spread");
        return;
    }

    /*
     * No new VM request: retain the historic core-weighted table exactly so
     * existing deployments and old VM directives keep their former routing.
     */
    int current_vcpu = 0;
    for (uint32_t i = 0; i < g_resource_plan.node_count; i++) {
        const struct wvm_resource_node *node = &g_resource_plan.nodes[i];

        for (uint32_t core = 0;
             core < node->cpu_capacity &&
             current_vcpu < WVM_CPU_ROUTE_TABLE_SIZE;
             core++) {
            wvm_set_cpu_mapping(current_vcpu++, node->vnode_start);
        }
    }
    for (uint32_t cursor = 0;
         current_vcpu < WVM_CPU_ROUTE_TABLE_SIZE;
         cursor = (cursor + 1) % g_resource_plan.node_count) {
        wvm_set_cpu_mapping(current_vcpu++,
                            g_resource_plan.nodes[cursor].vnode_start);
    }
    printf("[Config] CPU Routing Table Initialized (legacy core-weighted mode).\n");
}

/*
 * The QEMU SYNC channel is the only local fault boundary.  It carries a
 * typed V1 request into the admitted node runtime and receives one exact
 * typed MEM_ACK payload in return.  The old legacy fault IPC is deliberately
 * not translated here: it cannot carry operation identity or authority.
 */
static void handle_ipc_fault(int qemu_fd, const uint8_t *payload,
                                uint32_t payload_bytes)
{
    struct wvm_local_memory_fault_request request;
    struct wvm_mem_ack ack;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint8_t ack_payload[WVM_MEM_ACK_HEADER_BYTES +
                        WVM_MEMORY_PAGE_BYTES];
    uint8_t result_length[WVM_LOCAL_MEMORY_RESULT_LENGTH_BYTES];
    size_t ack_payload_bytes = 0;
    char error[192] = {0};
    int result;

    memset(&request, 0, sizeof(request));
    memset(&ack, 0, sizeof(ack));
    if (wvm_local_memory_fault_request_decode(
            payload, payload_bytes, &request, error, sizeof(error)) == 0) {
        result = wvm_memory_service_global_request_fault(
            request.gpa, request.operation_id, request.delivery_attempt_id,
            &ack, page, error, sizeof(error));
        if (result == 0 &&
            wvm_mem_ack_encode(&ack, ack_payload, sizeof(ack_payload),
                                  &ack_payload_bytes, error,
                                  sizeof(error)) == 0) {
            result = 0;
        } else if (result == 0) {
            result = -EPROTO;
        }
    } else {
        result = -EPROTO;
    }

    if (result != 0) {
        ack_payload_bytes = 0;
        fprintf(stderr,
                "[IPC V1 Fault] rejected fd=%d status=%d reason=%s\n",
                qemu_fd, result, error[0] ? error : "invalid local request");
    }
    if (wvm_local_memory_result_length_encode(
            ack_payload_bytes, result_length, error, sizeof(error)) != 0 ||
        write_exact(qemu_fd, result_length, sizeof(result_length)) < 0 ||
        (ack_payload_bytes != 0 &&
         write_exact(qemu_fd, ack_payload, ack_payload_bytes) < 0)) {
        fprintf(stderr, "[IPC V1 Fault] response write failed fd=%d\n",
                qemu_fd);
    }
}

static void handle_ipc_commit(int qemu_fd, const uint8_t *payload,
                                 uint32_t payload_bytes)
{
    struct wvm_local_memory_commit_request request;
    struct wvm_local_memory_commit_result result;
    uint8_t encoded[WVM_LOCAL_MEMORY_COMMIT_RESULT_BYTES];
    char error[192] = {0};
    int status;

    memset(&request, 0, sizeof(request));
    memset(&result, 0, sizeof(result));
    if (wvm_local_memory_commit_request_decode(
            payload, payload_bytes, &request, error, sizeof(error)) != 0) {
        status = -EPROTO;
    } else {
        status = wvm_memory_service_global_request_commit(
            request.commit.gpa, request.commit.base_version,
            request.commit.offset, request.commit.data,
            request.commit.data_bytes, request.operation_id,
            request.delivery_attempt_id, &result.ack, error, sizeof(error));
        memcpy(result.operation_id, request.operation_id,
               sizeof(result.operation_id));
    }
    if (status != 0) {
        memset(&result, 0, sizeof(result));
        memcpy(result.operation_id, request.operation_id,
               sizeof(result.operation_id));
        result.ack.gpa = request.commit.gpa;
        result.ack.status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
        fprintf(stderr,
                "[IPC V1 Commit] rejected fd=%d status=%d reason=%s\n",
                qemu_fd, status, error[0] ? error : "invalid local request");
    }
    if (wvm_local_memory_commit_result_encode(
            &result, encoded, error, sizeof(error)) != 0 ||
        write_exact(qemu_fd, encoded, sizeof(encoded)) < 0) {
        fprintf(stderr, "[IPC V1 Commit] response write failed fd=%d\n",
                qemu_fd);
    }
}

static void handle_ipc_cpu_run(int qemu_fd,
                               const struct wvm_ipc_cpu_run_req *req)
{
    struct wvm_ipc_cpu_run_ack ack;
    char error[192] = {0};
    int result;

    /*
     * This point is reached only after drain_pending_commits() succeeds on
     * the same QEMU IPC connection. The node-runtime service therefore owns
     * the following typed memory fence and the exact asynchronous reply path.
     */
    result = wvm_vcpu_service_global_submit(qemu_fd, req, error,
                                             sizeof(error));
    if (result == 0) {
        return;
    }
    memset(&ack, 0, sizeof(ack));
    ack.status = result;
    ack.mode_tcg = req->mode_tcg;
    fprintf(stderr,
            "[IPC VCPU_RUN] rejected fd=%d vcpu=%u mode=%u status=%d reason=%s\n",
            qemu_fd, req->vcpu_index, req->mode_tcg, result,
            error[0] ? error : "typed vCPU service unavailable");
    (void)write_exact(qemu_fd, &ack, sizeof(ack));
}

#define WVM_COMMIT_SYNC_WINDOW     512  /* F05: larger in-flight over TS */
#define WVM_COMMIT_SYNC_TIMEOUT_US 5000000ULL
#define WVM_COMMIT_SYNC_RETRY_US   50000ULL

struct pending_commit_sync {
    int active;
    uint64_t rid;
    uint8_t ack_status;
    uint8_t *pkt;
    size_t pkt_len;
    uint32_t dir_node;
    uint64_t gpa;
    uint64_t start_us;
    uint64_t last_send_us;
};

struct pending_commit_queue {
    struct pending_commit_sync entries[WVM_COMMIT_SYNC_WINDOW];
    unsigned head;
    unsigned count;
};

/*
 * F05: bulk handoff flush (~tens of thousands of COMMIT_DIFF_SYNC) must not
 * starve the empty push-fence on the same vcpu fd. Overflow holds remote syncs
 * the window cannot accept yet; fence/CPU_RUN drain overflow+window before
 * proceeding.
 */
struct overflow_commit {
    uint8_t *payload;
    uint32_t len;
    uint32_t dir_node;
    struct overflow_commit *next;
};

struct commit_overflow_list {
    struct overflow_commit *head;
    struct overflow_commit *tail;
    unsigned count;
};

static void release_pending_commit(struct pending_commit_sync *entry)
{
    if (!entry->active) {
        return;
    }
    if (entry->pkt) {
        u_ops.free_packet(entry->pkt);
    }
    if (entry->rid != (uint64_t)-1) {
        u_ops.free_req_id(entry->rid);
    }
    memset(entry, 0, sizeof(*entry));
}

static int send_pending_commit(struct pending_commit_sync *entry)
{
    int ret = u_ops.send_packet(entry->pkt, (int)entry->pkt_len, entry->dir_node);
    if (ret == 0) {
        entry->last_send_us = u_ops.get_time_us();
    }
    return ret;
}


static int wait_oldest_pending_commit(struct pending_commit_queue *queue,
                                      uint64_t *fail_gpa);

static void cancel_commit_overflow(struct commit_overflow_list *overflow)
{
    while (overflow->head) {
        struct overflow_commit *node = overflow->head;
        overflow->head = node->next;
        free(node->payload);
        free(node);
        if (overflow->count > 0) {
            overflow->count--;
        }
    }
    overflow->tail = NULL;
    overflow->count = 0;
}

static int overflow_push_commit(struct commit_overflow_list *overflow,
                                struct wvm_diff_log *log, uint32_t len,
                                uint32_t dir_node)
{
    struct overflow_commit *node = calloc(1, sizeof(*node));
    if (!node) {
        return -ENOMEM;
    }
    node->payload = malloc(len);
    if (!node->payload) {
        free(node);
        return -ENOMEM;
    }
    memcpy(node->payload, log, len);
    node->len = len;
    node->dir_node = dir_node;
    if (overflow->tail) {
        overflow->tail->next = node;
    } else {
        overflow->head = node;
    }
    overflow->tail = node;
    overflow->count++;
    return 0;
}

/* Non-blocking poll of FIFO head: 0 ok, <0 error/timeout, -EAGAIN pending. */
static int poll_oldest_pending_commit(struct pending_commit_queue *queue,
                                      uint64_t *fail_gpa)
{
    struct pending_commit_sync *entry;
    int status;

    if (queue->count == 0) {
        return 0;
    }

    entry = &queue->entries[queue->head];
    status = u_ops.check_req_status(entry->rid);
    if (status == 1) {
        int ret = entry->ack_status == 1 ? 0 : -EIO;
        static int ack_log_count;
        if (ret == 0 && ack_log_count < 20) {
            fprintf(stderr,
                    "[IPC COMMIT_SYNC] ack gpa=%#llx dir=%u rid=%llu\n",
                    (unsigned long long)entry->gpa,
                    (unsigned)entry->dir_node,
                    (unsigned long long)entry->rid);
            ack_log_count++;
        }
        if (ret < 0) {
            fprintf(stderr,
                    "[IPC COMMIT_SYNC] nack gpa=%#llx dir=%u rid=%llu\n",
                    (unsigned long long)entry->gpa,
                    (unsigned)entry->dir_node,
                    (unsigned long long)entry->rid);
            if (fail_gpa) {
                *fail_gpa = entry->gpa;
            }
        }
        release_pending_commit(entry);
        queue->head = (queue->head + 1) % WVM_COMMIT_SYNC_WINDOW;
        queue->count--;
        return ret;
    }

    if (u_ops.time_diff_us(entry->start_us) >= WVM_COMMIT_SYNC_TIMEOUT_US) {
        fprintf(stderr, "[IPC COMMIT_SYNC] timeout gpa=%#llx dir=%u rid=%llu\n",
                (unsigned long long)entry->gpa,
                (unsigned)entry->dir_node,
                (unsigned long long)entry->rid);
        if (fail_gpa) {
            *fail_gpa = entry->gpa;
        }
        release_pending_commit(entry);
        queue->head = (queue->head + 1) % WVM_COMMIT_SYNC_WINDOW;
        queue->count--;
        return -ETIMEDOUT;
    }

    if (u_ops.time_diff_us(entry->last_send_us) > WVM_COMMIT_SYNC_RETRY_US) {
        send_pending_commit(entry);
    }
    return -EAGAIN;
}

static int enqueue_commit_diff_sync_prepared(struct pending_commit_queue *queue,
                                             struct wvm_diff_log *log, uint32_t len,
                                             uint32_t dir_node)
{
    struct pending_commit_sync *entry;
    unsigned idx;

    if (queue->count >= WVM_COMMIT_SYNC_WINDOW) {
        return -EAGAIN;
    }

    idx = (queue->head + queue->count) % WVM_COMMIT_SYNC_WINDOW;
    entry = &queue->entries[idx];
    memset(entry, 0, sizeof(*entry));
    entry->rid = (uint64_t)-1;
    entry->dir_node = dir_node;
    entry->gpa = WVM_NTOHLL(log->gpa);
    entry->start_us = u_ops.get_time_us();

    entry->rid = u_ops.alloc_req_id(&entry->ack_status, sizeof(entry->ack_status));
    if (entry->rid == (uint64_t)-1) {
        return -EBUSY;
    }

    entry->pkt_len = sizeof(struct wvm_header) + len;
    entry->pkt = u_ops.alloc_packet(entry->pkt_len, 0);
    if (!entry->pkt) {
        u_ops.free_req_id(entry->rid);
        entry->rid = (uint64_t)-1;
        return -ENOMEM;
    }

    struct wvm_header *hdr = (struct wvm_header *)entry->pkt;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(MSG_COMMIT_DIFF);
    hdr->payload_len = htons((uint16_t)len);
    hdr->slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
    hdr->target_id = htonl(dir_node);
    hdr->req_id = WVM_HTONLL(entry->rid);
    hdr->qos_level = 1;
    hdr->flags = WVM_FLAG_NEED_ACK;
    hdr->epoch = htonl(g_curr_epoch);
    hdr->node_state = g_my_node_state;
    memcpy(entry->pkt + sizeof(*hdr), log, len);

    entry->active = 1;
    if (send_pending_commit(entry) < 0) {
        release_pending_commit(entry);
        return -EIO;
    }

    queue->count++;
    return 0;
}

static void fill_window_from_overflow(struct pending_commit_queue *queue,
                                      struct commit_overflow_list *overflow)
{
    while (overflow->head && queue->count < WVM_COMMIT_SYNC_WINDOW) {
        struct overflow_commit *node = overflow->head;
        int ret = enqueue_commit_diff_sync_prepared(
            queue, (struct wvm_diff_log *)node->payload, node->len, node->dir_node);
        if (ret == -EAGAIN) {
            break;
        }
        overflow->head = node->next;
        if (!overflow->head) {
            overflow->tail = NULL;
        }
        if (overflow->count > 0) {
            overflow->count--;
        }
        free(node->payload);
        free(node);
        if (ret < 0) {
            fprintf(stderr,
                    "[IPC COMMIT_SYNC] overflow enqueue failed ret=%d left=%u\n",
                    ret, overflow->count);
            /* keep draining what we can */
        }
    }
}

static int pump_pending_commits(struct pending_commit_queue *queue,
                                struct commit_overflow_list *overflow,
                                uint64_t *fail_gpa)
{
    int progressed = 0;
    int last_err = 0;

    for (;;) {
        int ret;

        fill_window_from_overflow(queue, overflow);
        if (queue->count == 0) {
            return last_err;
        }
        ret = poll_oldest_pending_commit(queue, fail_gpa);
        if (ret == -EAGAIN) {
            fill_window_from_overflow(queue, overflow);
            return last_err;
        }
        if (ret < 0) {
            last_err = ret;
            fill_window_from_overflow(queue, overflow);
            return ret;
        }
        progressed = 1;
        fill_window_from_overflow(queue, overflow);
        (void)progressed;
    }
}

static int drain_commits_with_overflow(struct pending_commit_queue *queue,
                                       struct commit_overflow_list *overflow,
                                       uint64_t *fail_gpa)
{
    fill_window_from_overflow(queue, overflow);
    while (queue->count > 0 || overflow->count > 0) {
        int pret = pump_pending_commits(queue, overflow, fail_gpa);
        if (pret < 0 && pret != -EAGAIN) {
            return pret;
        }
        if (queue->count == 0 && overflow->count == 0) {
            return 0;
        }
        if (queue->count > 0) {
            int wret = wait_oldest_pending_commit(queue, fail_gpa);
            if (wret < 0) {
                return wret;
            }
        }
        fill_window_from_overflow(queue, overflow);
    }
    return 0;
}

static int wait_oldest_pending_commit(struct pending_commit_queue *queue,
                                      uint64_t *fail_gpa)
{
    if (queue->count == 0) {
        return 0;
    }

    struct pending_commit_sync *entry = &queue->entries[queue->head];
    uint64_t last_wait_log_us = entry->start_us;
    while (u_ops.time_diff_us(entry->start_us) < WVM_COMMIT_SYNC_TIMEOUT_US) {
        if (u_ops.check_req_status(entry->rid) == 1) {
            int ret = entry->ack_status == 1 ? 0 : -EIO;
            static int ack_log_count;
            if (ret == 0 && ack_log_count < 20) {
                fprintf(stderr,
                        "[IPC COMMIT_SYNC] ack gpa=%#llx dir=%u rid=%llu\n",
                        (unsigned long long)entry->gpa,
                        (unsigned)entry->dir_node,
                        (unsigned long long)entry->rid);
                ack_log_count++;
            }
            if (ret < 0) {
                fprintf(stderr,
                        "[IPC COMMIT_SYNC] nack gpa=%#llx dir=%u rid=%llu\n",
                        (unsigned long long)entry->gpa,
                        (unsigned)entry->dir_node,
                        (unsigned long long)entry->rid);
                if (fail_gpa) {
                    *fail_gpa = entry->gpa;
                }
            }
            release_pending_commit(entry);
            queue->head = (queue->head + 1) % WVM_COMMIT_SYNC_WINDOW;
            queue->count--;
            return ret;
        }

        if (u_ops.time_diff_us(last_wait_log_us) > 1000000ULL) {
            static int slow_wait_log_count;
            if (slow_wait_log_count < 20) {
                fprintf(stderr,
                        "[IPC COMMIT_SYNC] waiting gpa=%#llx dir=%u rid=%llu elapsed_us=%llu\n",
                        (unsigned long long)entry->gpa,
                        (unsigned)entry->dir_node,
                        (unsigned long long)entry->rid,
                        (unsigned long long)u_ops.time_diff_us(entry->start_us));
                slow_wait_log_count++;
            }
            last_wait_log_us = u_ops.get_time_us();
        }

        if (u_ops.time_diff_us(entry->last_send_us) > WVM_COMMIT_SYNC_RETRY_US) {
            send_pending_commit(entry);
        }
        u_ops.yield_cpu_short_time();
    }

    fprintf(stderr, "[IPC COMMIT_SYNC] timeout gpa=%#llx dir=%u rid=%llu\n",
            (unsigned long long)entry->gpa,
            (unsigned)entry->dir_node,
            (unsigned long long)entry->rid);
    if (fail_gpa) {
        *fail_gpa = entry->gpa;
    }
    release_pending_commit(entry);
    queue->head = (queue->head + 1) % WVM_COMMIT_SYNC_WINDOW;
    queue->count--;
    return -ETIMEDOUT;
}

static int drain_pending_commits(struct pending_commit_queue *queue,
                                 uint64_t *fail_gpa)
{
    while (queue->count > 0) {
        int ret = wait_oldest_pending_commit(queue, fail_gpa);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

static void cancel_pending_commits(struct pending_commit_queue *queue)
{
    while (queue->count > 0) {
        struct pending_commit_sync *entry = &queue->entries[queue->head];
        release_pending_commit(entry);
        queue->head = (queue->head + 1) % WVM_COMMIT_SYNC_WINDOW;
        queue->count--;
    }
}

static int enqueue_commit_diff_sync(struct pending_commit_queue *queue,
                                    struct commit_overflow_list *overflow,
                                    struct wvm_diff_log *log, uint32_t len,
                                    uint32_t dir_node)
{
    int ret;

    (void)pump_pending_commits(queue, overflow, NULL);

    ret = enqueue_commit_diff_sync_prepared(queue, log, len, dir_node);
    if (ret != -EAGAIN) {
        return ret;
    }

    {
        static int full_log_count;
        if (full_log_count < 20) {
            fprintf(stderr,
                    "[IPC COMMIT_SYNC] window full, overflow count=%u win=%u\n",
                    overflow->count, queue->count);
            full_log_count++;
        }
    }
    return overflow_push_commit(overflow, log, len, dir_node);
}

static void mark_push_barrier_done(uint64_t cookie)
{
    pthread_mutex_lock(&g_push_barrier_lock);
    if (cookie > g_push_barrier_done) {
        g_push_barrier_done = cookie;
    }
    static int push_barrier_ack_log_count;
    if (push_barrier_ack_log_count < 20) {
        fprintf(stderr, "[PUSH-BARRIER-ACK] cookie=%llu done=%llu\n",
                (unsigned long long)cookie,
                (unsigned long long)g_push_barrier_done);
        push_barrier_ack_log_count++;
    }
    pthread_cond_broadcast(&g_push_barrier_cond);
    pthread_mutex_unlock(&g_push_barrier_lock);
}

static int broadcast_push_to_qemu_locked(uint16_t msg_type, void* payload, int len)
{
    wvm_ipc_header_t ipc_hdr;
    int sent = 0;

    if (g_client_count <= 0) {
        return 0;
    }

    ipc_hdr.type = WVM_IPC_TYPE_INVALIDATE;
    ipc_hdr.len = sizeof(struct wvm_header) + len;

    uint8_t *buffer = malloc(sizeof(ipc_hdr) + ipc_hdr.len);
    if (!buffer) {
        return 0;
    }

    memcpy(buffer, &ipc_hdr, sizeof(ipc_hdr));
    struct wvm_header *hdr = (struct wvm_header *)(buffer + sizeof(ipc_hdr));
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = htonl(WVM_MAGIC);
    hdr->msg_type = htons(msg_type);
    hdr->payload_len = htons((uint16_t)len);
    hdr->slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
    hdr->target_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
    hdr->qos_level = (msg_type == MSG_PAGE_PUSH_FULL || msg_type == MSG_FORCE_SYNC) ? 0 : 1;
    hdr->epoch = htonl(g_curr_epoch);
    hdr->node_state = g_my_node_state;
    memcpy((void *)hdr + sizeof(*hdr), payload, len);

    for (int i = 0; i < g_client_count; i++) {
        if (write_exact(g_qemu_clients[i], buffer,
                        sizeof(ipc_hdr) + ipc_hdr.len) >= 0) {
            sent++;
        }
    }
    free(buffer);
    return sent;
}

static int send_push_barrier_locked(uint64_t *cookie_out)
{
    wvm_ipc_header_t ipc_hdr = {
        .type = WVM_IPC_TYPE_PUSH_BARRIER,
        .len = sizeof(uint64_t),
    };
    uint64_t cookie;

    if (g_client_count <= 0) {
        return 0;
    }

    pthread_mutex_lock(&g_push_barrier_lock);
    cookie = g_push_barrier_next++;
    pthread_mutex_unlock(&g_push_barrier_lock);

    /*
     * Caller must hold g_client_lock so no other PAGE_PUSH can be inserted
     * between this commit's push and the fence marker.
     */
    if (write_exact(g_qemu_clients[0], &ipc_hdr, sizeof(ipc_hdr)) < 0 ||
        write_exact(g_qemu_clients[0], &cookie, sizeof(cookie)) < 0) {
        return -EIO;
    }

    static int push_barrier_send_log_count;
    if (push_barrier_send_log_count < 20) {
        fprintf(stderr, "[PUSH-BARRIER] send cookie=%llu fd=%d clients=%d\n",
                (unsigned long long)cookie, g_qemu_clients[0], g_client_count);
        push_barrier_send_log_count++;
    }

    if (cookie_out) {
        *cookie_out = cookie;
    }
    return 0;
}

static int wait_for_push_barrier_cookie(uint64_t cookie, uint64_t timeout_us)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_us / 1000000ULL;
    ts.tv_nsec += (long)((timeout_us % 1000000ULL) * 1000ULL);
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g_push_barrier_lock);
    while (g_push_barrier_done < cookie) {
        int rc = pthread_cond_timedwait(&g_push_barrier_cond,
                                        &g_push_barrier_lock, &ts);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&g_push_barrier_lock);
            return -ETIMEDOUT;
        }
    }
    pthread_mutex_unlock(&g_push_barrier_lock);
    return 0;
}

/* Strong def in slave_hybrid.c (node_runtime). Sleep-fallback OK. */
__attribute__((weak))
int wavevm_proxy_barrier_local_helpers(uint64_t timeout_us)
{
    (void)timeout_us;
    return 0;
}

int wait_local_qemu_push_barrier(uint64_t timeout_us)
{
    pthread_mutex_lock(&g_client_lock);
    if (g_client_count <= 0) {
        pthread_mutex_unlock(&g_client_lock);
        return 0;
    }

    uint64_t cookie = 0;
    int ret = send_push_barrier_locked(&cookie);
    pthread_mutex_unlock(&g_client_lock);
    if (ret < 0) {
        return ret;
    }

    return wait_for_push_barrier_cookie(cookie, timeout_us);
}

int broadcast_push_to_qemu_fenced(uint16_t msg_type, void* payload, int len,
                                  uint64_t timeout_us)
{
    uint64_t cookie = 0;
    int ret;
    int sent;

    pthread_mutex_lock(&g_client_lock);
    sent = broadcast_push_to_qemu_locked(msg_type, payload, len);
    if (sent <= 0) {
        pthread_mutex_unlock(&g_client_lock);
        return sent;
    }

    ret = send_push_barrier_locked(&cookie);
    pthread_mutex_unlock(&g_client_lock);
    if (ret < 0) {
        return ret;
    }

    ret = wait_for_push_barrier_cookie(cookie, timeout_us);
    if (ret < 0) {
        return ret;
    }
    return sent;
}

int broadcast_push_to_qemu(uint16_t msg_type, void* payload, int len) {
    pthread_mutex_lock(&g_client_lock);
    int sent = broadcast_push_to_qemu_locked(msg_type, payload, len);
    pthread_mutex_unlock(&g_client_lock);
    return sent;
}

void broadcast_raw_packet_to_qemu(const void *packet, size_t len) {
    wvm_ipc_header_t ipc_hdr;
    ipc_hdr.type = WVM_IPC_TYPE_INVALIDATE;
    ipc_hdr.len = (uint32_t)len;

    pthread_mutex_lock(&g_client_lock);
    for (int i = 0; i < g_client_count; i++) {
        if (write_exact(g_qemu_clients[i], &ipc_hdr, sizeof(ipc_hdr)) < 0 ||
            write_exact(g_qemu_clients[i], packet, len) < 0) {
            fprintf(stderr, "[IPC] raw packet forward failed fd=%d errno=%d\n",
                    g_qemu_clients[i], errno);
        }
    }
    pthread_mutex_unlock(&g_client_lock);
}

void broadcast_irq_to_qemu(void) {
    wvm_ipc_header_t ipc_hdr;
    ipc_hdr.type = WVM_IPC_TYPE_IRQ;
    ipc_hdr.len = 0;
    
    pthread_mutex_lock(&g_client_lock);
    for (int i = 0; i < g_client_count; i++) {
        write_exact(g_qemu_clients[i], &ipc_hdr, sizeof(ipc_hdr));
    }
    pthread_mutex_unlock(&g_client_lock);
}

/* 
 * [物理意图] 维护 QEMU 前端与 Backend 守护进程之间的“生命脐带”。
 * [关键逻辑] 处理本地 IPC 请求，将 vCPU 的 COMMIT_DIFF 任务异步分发至分布式总线。
 * [后果] 这是本地算力与全局总线的交汇点。若此处的循环发生阻塞，vCPU 将产生明显的物理卡顿。
 */
void* client_handler(void *socket_desc) {
    int qemu_fd = *(int*)socket_desc;
    free(socket_desc);
    fprintf(stderr, "[IPC] client connected fd=%d\n", qemu_fd);

    int is_push_client = 0;
    uint64_t runtime_connection_id = 0;

    wvm_ipc_header_t ipc_hdr;
    uint8_t payload_buf[WVM_MAX_PACKET_SIZE];
    struct pending_commit_queue commit_queue = {0};
    struct commit_overflow_list commit_overflow = {0};

    while (1) {
        // [FIX-G2] 使用 read_exact 处理 partial read
        ssize_t hdr_n = read_exact(qemu_fd, &ipc_hdr, sizeof(ipc_hdr));
        if (hdr_n < 0) {
            fprintf(stderr, "[IPC] header read failed fd=%d errno=%d\n",
                    qemu_fd, errno);
            break;
        }
        if (ipc_hdr.len > sizeof(payload_buf)) {
            fprintf(stderr, "[IPC] payload too large fd=%d type=%u len=%u max=%zu\n",
                    qemu_fd, (unsigned)ipc_hdr.type, (unsigned)ipc_hdr.len, sizeof(payload_buf));
            // Payload too large, drain and ignore
            char drain[1024];
            size_t remaining = ipc_hdr.len;
            while(remaining > 0) {
                ssize_t n = read(qemu_fd, drain, (remaining > sizeof(drain)) ? sizeof(drain) : remaining);
                if (n <= 0) break;
                remaining -= n;
            }
            continue;
        }
        
        // [FIX-G2] 使用 read_exact 处理 partial read
        ssize_t payload_n = read_exact(qemu_fd, payload_buf, ipc_hdr.len);
        if (payload_n < 0) {
            fprintf(stderr, "[IPC] payload read failed fd=%d type=%u need=%u errno=%d\n",
                    qemu_fd, (unsigned)ipc_hdr.type, (unsigned)ipc_hdr.len, errno);
            break;
        }

        if (g_runtime_gate_active &&
            ipc_hdr.type != WVM_IPC_TYPE_REGISTER &&
            runtime_connection_id == 0) {
            fprintf(stderr,
                    "[RuntimeGate] rejecting unregistered IPC fd=%d type=%u\n",
                    qemu_fd, (unsigned)ipc_hdr.type);
            break;
        }
        if (g_runtime_gate_active &&
            ipc_hdr.type != WVM_IPC_TYPE_REGISTER &&
            runtime_gate_authorize_connection(runtime_connection_id) != 0) {
            break;
        }

        switch (ipc_hdr.type) {
            case WVM_IPC_TYPE_REGISTER: {
                uint32_t role = 0;

                if (g_runtime_gate_active) {
                    if (runtime_connection_id != 0) {
                        fprintf(stderr,
                                "[IPC] duplicate registration on fd=%d\n",
                                qemu_fd);
                        break;
                    }
                    if (ipc_hdr.len !=
                            sizeof(struct wvm_ipc_runtime_registration)) {
                        fprintf(stderr,
                                "[IPC] manifest-bound registration failed "
                                "fd=%d len=%u\n",
                                qemu_fd, (unsigned)ipc_hdr.len);
                        break;
                    }
                    role = ((const struct wvm_ipc_runtime_registration *)
                                payload_buf)->ipc_role;
                    if (role != WVM_IPC_ROLE_ASYNC_PUSH &&
                        role != WVM_IPC_ROLE_SYNC) {
                        fprintf(stderr,
                                "[IPC] invalid manifest-bound channel role "
                                "fd=%d role=%u\n",
                                qemu_fd, (unsigned)role);
                        break;
                    }
                    if (runtime_gate_register_qemu(
                            (const struct wvm_ipc_runtime_registration *)
                                payload_buf,
                            &runtime_connection_id) != 0) {
                        fprintf(stderr,
                                "[IPC] manifest-bound registration failed "
                                "fd=%d len=%u\n",
                                qemu_fd, (unsigned)ipc_hdr.len);
                        break;
                    }
                    fprintf(stderr,
                            "[IPC] fd=%d registered against runtime "
                            "connection=%" PRIu64 "\n",
                            qemu_fd, runtime_connection_id);
                } else {
                    if (ipc_hdr.len != sizeof(uint32_t)) {
                        fprintf(stderr,
                                "[IPC] invalid registration fd=%d len=%u\n",
                                qemu_fd, (unsigned)ipc_hdr.len);
                        break;
                    }
                    memcpy(&role, payload_buf, sizeof(role));
                }
                if (role == WVM_IPC_ROLE_ASYNC_PUSH) {
                    pthread_mutex_lock(&g_client_lock);
                    if (!is_push_client && g_client_count < (int)(sizeof(g_qemu_clients) /
                                                                   sizeof(g_qemu_clients[0]))) {
                        g_qemu_clients[g_client_count++] = qemu_fd;
                        is_push_client = 1;
                        fprintf(stderr,
                                "[IPC] fd=%d registered as async push client count=%d\n",
                                qemu_fd, g_client_count);
                    } else if (!is_push_client) {
                        fprintf(stderr, "[IPC] WARN: async push slots full fd=%d\n", qemu_fd);
                    }
                    pthread_mutex_unlock(&g_client_lock);
                } else {
                    fprintf(stderr, "[IPC] fd=%d registered as sync role=%u\n",
                            qemu_fd, (unsigned)role);
                }
                break;
            }
            case WVM_IPC_TYPE_PUSH_BARRIER_ACK: {
                if (ipc_hdr.len == sizeof(uint64_t)) {
                    uint64_t cookie;
                    memcpy(&cookie, payload_buf, sizeof(cookie));
                    mark_push_barrier_done(cookie);
                }
                break;
            }
            case WVM_IPC_TYPE_TYPED_MEM_FAULT:
                handle_ipc_fault(qemu_fd, payload_buf, ipc_hdr.len);
                break;
            case WVM_IPC_TYPE_TYPED_MEM_COMMIT:
                handle_ipc_commit(qemu_fd, payload_buf, ipc_hdr.len);
                break;
            case WVM_IPC_TYPE_CPU_RUN: {
                struct wvm_ipc_cpu_run_req *req =
                    (struct wvm_ipc_cpu_run_req*)payload_buf;
                static int cpu_run_rx_log_count;
                if (cpu_run_rx_log_count < 20) {
                    fprintf(stderr,
                            "[IPC CPU_RUN RX] fd=%d vcpu=%u mode=%u pending=%u overflow=%u\n",
                            qemu_fd, req->vcpu_index, req->mode_tcg,
                            commit_queue.count, commit_overflow.count);
                }

                uint64_t fail_gpa = 0;
                int ret = drain_commits_with_overflow(&commit_queue,
                                                      &commit_overflow,
                                                      &fail_gpa);
                if (ret < 0) {
                    struct wvm_ipc_cpu_run_ack ack = {0};
                    ack.status = ret;
                    ack.mode_tcg = req->mode_tcg;
                    ack.error_gpa = fail_gpa;
                    write_exact(qemu_fd, &ack, sizeof(ack));
                    break;
                }
                if (cpu_run_rx_log_count < 20) {
                    fprintf(stderr,
                            "[IPC CPU_RUN RX] fd=%d drain done vcpu=%u pending=%u overflow=%u\n",
                            qemu_fd, req->vcpu_index, commit_queue.count,
                            commit_overflow.count);
                    cpu_run_rx_log_count++;
                }
                handle_ipc_cpu_run(qemu_fd, req);
                break;
            }
            case WVM_IPC_TYPE_COMMIT_DIFF:
            case WVM_IPC_TYPE_COMMIT_DIFF_SYNC: {
                /*
                 * len==16 empty payload is the QEMU push-visibility fence.
                 * Must reply 16 bytes; drain COMMIT_DIFF_SYNC backlog first.
                 */
                if (ipc_hdr.type == WVM_IPC_TYPE_COMMIT_DIFF_SYNC &&
                    ipc_hdr.len == 16) {
                    uint8_t fence_resp[16] = {0};
                    int br;
                    int hr = 0;
                    int dr;
                    uint64_t fail_gpa = 0;
                    int need_helpers = (payload_buf[0] == 0x02);
                    static int fence_log_count;
                    if (fence_log_count < 40) {
                        fprintf(stderr,
                                "[IPC FENCE] begin fd=%d pending=%u overflow=%u "
                                "helpers=%d\n",
                                qemu_fd, commit_queue.count,
                                commit_overflow.count, need_helpers);
                    }
                    dr = drain_commits_with_overflow(&commit_queue,
                                                     &commit_overflow,
                                                     &fail_gpa);
                    br = wait_local_qemu_push_barrier(120000000ULL); /* F05 */
                    if (need_helpers) {
                        hr = wavevm_proxy_barrier_local_helpers(120000000ULL);
                    }
                    if (dr != 0 || br != 0 || hr != 0) {
                        int err = dr != 0 ? dr : (br != 0 ? br : hr);
                        if (err > 0) {
                            err = -err;
                        }
                        memcpy(fence_resp, &err, sizeof(err));
                    }
                    if (fence_log_count < 40) {
                        fprintf(stderr,
                                "[IPC FENCE] push-barrier done br=%d helpers=%d "
                                "hr=%d dr=%d fail_gpa=%#llx pending=%u "
                                "overflow=%u fd=%d\n",
                                br, need_helpers, hr, dr,
                                (unsigned long long)fail_gpa,
                                commit_queue.count, commit_overflow.count,
                                qemu_fd);
                        fence_log_count++;
                    }
                    if (write_exact(qemu_fd, fence_resp, sizeof(fence_resp)) < 0) {
                        fprintf(stderr,
                                "[IPC FENCE] reply failed fd=%d errno=%d\n",
                                qemu_fd, errno);
                    }
                    break;
                }
                // This is the new IPC type for V29
                struct wvm_diff_log* log = (struct wvm_diff_log*)payload_buf;
                uint32_t dir_node = wvm_get_directory_node_id(WVM_NTOHLL(log->gpa));
                if (WVM_GET_NODEID(dir_node) == (uint32_t)g_my_node_id) {
                    /*
                     * Local directory commits must be applied before later IPC
                     * messages on the same QEMU connection, especially TCG
                     * CPU_RUN handoff.  Queueing through async send lets the
                     * remote vCPU pull a just-written page table before the
                     * directory copy is updated.
                     */
                    struct wvm_header hdr = {0};
                    hdr.magic = htonl(WVM_MAGIC);
                    hdr.msg_type = htons(MSG_COMMIT_DIFF);
                    hdr.payload_len = htons((uint16_t)ipc_hdr.len);
                    hdr.slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
                    hdr.target_id = htonl(dir_node);
                    hdr.epoch = htonl(g_curr_epoch);
                    hdr.node_state = g_my_node_state;
                    wvm_logic_process_packet(&hdr, log,
                                             WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
                } else if (ipc_hdr.type == WVM_IPC_TYPE_COMMIT_DIFF_SYNC) {
                    int ret = enqueue_commit_diff_sync(&commit_queue, &commit_overflow, log, ipc_hdr.len,
                                                       dir_node);
                    if (ret < 0) {
                        fprintf(stderr,
                                "[IPC COMMIT_SYNC] failed gpa=%#llx dir=%u ret=%d\n",
                                (unsigned long long)WVM_NTOHLL(log->gpa),
                                (unsigned)dir_node, ret);
                    }
                } else {
                    // Send MSG_COMMIT_DIFF to the correct directory node
                    u_ops.send_packet_async(MSG_COMMIT_DIFF, log, ipc_hdr.len, dir_node, 1);
                }
                break;
            }
            case WVM_IPC_TYPE_RPC_PASSTHROUGH: { // Type 99
                extern void handle_ipc_rpc_passthrough(int qemu_fd, void *data, uint32_t len);
                handle_ipc_rpc_passthrough(qemu_fd, payload_buf, ipc_hdr.len);
                break;
            }
            case WVM_IPC_TYPE_BLOCK_IO: {
                // 结构体必须与 QEMU 端严格对齐 (Packed 13 Bytes)
                struct wvm_ipc_block_req {
                    uint64_t lba;
                    uint32_t len;
                    uint8_t  is_write;
                    uint8_t  data[0];
                } __attribute__((packed));
                struct wvm_ipc_block_req *req = (void*)payload_buf;
                uint32_t target = wvm_get_storage_node_id(req->lba);
                
                size_t blk_size = sizeof(struct wvm_block_payload) + (req->is_write ? req->len : 0);
                size_t pkt_len = sizeof(struct wvm_header) + blk_size;
                
                // [FIX] 1. 分配 RX Buffer 接收远端真实数据
                size_t rx_buf_size = sizeof(struct wvm_block_payload) + req->len;
                uint8_t *rx_buf = malloc(rx_buf_size);
                uint64_t rid = u_ops.alloc_req_id(rx_buf, (uint32_t)rx_buf_size);
                
                uint8_t *pkt = u_ops.alloc_packet(pkt_len, 0);
                if (pkt && rid != (uint64_t)-1) {
                    struct wvm_header *h = (struct wvm_header *)pkt;
                    h->magic = htonl(WVM_MAGIC);
                    h->msg_type = htons(req->is_write ? MSG_BLOCK_WRITE : MSG_BLOCK_READ);
                    h->payload_len = htons(blk_size);
                    h->slave_id = htonl(WVM_ENCODE_ID(g_my_vm_id, g_my_node_id));
                    h->req_id = WVM_HTONLL(rid); // [FIX] 必须赋予请求ID才能收到ACK
                    h->qos_level = 1; 
                    
                    struct wvm_block_payload *p = (void*)(pkt + sizeof(*h));
                    p->lba = WVM_HTONLL(req->lba);
                    p->count = htonl(req->len / 512);
                    if (req->is_write) memcpy(p->data, req->data, req->len);
                    
                    h->crc32 = 0;
                    h->crc32 = htonl(calculate_crc32(pkt, pkt_len));
                    
                    // 2. 发送请求
                    u_ops.send_packet(pkt, pkt_len, target);
                    
                    // [FIX] 3. 阻塞等待远端存储节点回包
                    uint64_t t_start = u_ops.get_time_us();
                    int success = 0;
                    while (u_ops.time_diff_us(t_start) < 5000000) { // 5秒超时
                        if (u_ops.check_req_status(rid) == 1) {
                            // --- 完美闭环：检查硬件级坏道/写入错误 ---
                            struct wvm_header *rx_hdr = (struct wvm_header *)rx_buf;
                            if (rx_hdr->flags & WVM_FLAG_ERROR) {
                                fprintf(stderr, "[Storage] Remote Slave reported physical IO error on LBA!\n");
                                success = 0; // 物理落盘失败，向 QEMU 报告错误
                            } else {
                                success = 1; // 真正意义上的安全落盘
                            }
                            break;
                        }
                        usleep(100);
                    }
                    
                    // [FIX] 4. 向 QEMU 发送 ACK 唤醒 vCPU
                    uint8_t ack_byte = success ? 1 : 0;
                    write_exact(qemu_fd, &ack_byte, 1);
                    
                    // 如果是读操作，把远端拿回来的数据塞回给 QEMU
                    if (success && !req->is_write) {
                        struct wvm_block_payload *rx_p = (struct wvm_block_payload *)rx_buf;
                        write_exact(qemu_fd, rx_p->data, req->len);
                    }
                } else {
                    // 内存不足，直接回复失败，防止 QEMU 死锁
                    uint8_t ack_byte = 0;
                    write_exact(qemu_fd, &ack_byte, 1);
                }
                
                if (pkt) u_ops.free_packet(pkt);
                if (rid != (uint64_t)-1) u_ops.free_req_id(rid);
                free(rx_buf);
                break;
            }
            default:
                fprintf(stderr, "[IPC] unknown type fd=%d type=%u len=%u\n",
                        qemu_fd, (unsigned)ipc_hdr.type, (unsigned)ipc_hdr.len);
                break;
        }
    }
    if (drain_commits_with_overflow(&commit_queue, &commit_overflow, NULL) < 0) {
        cancel_pending_commits(&commit_queue);
        cancel_commit_overflow(&commit_overflow);
    } else {
        cancel_commit_overflow(&commit_overflow);
    }
    fprintf(stderr, "[IPC] client disconnected fd=%d\n", qemu_fd);
    close(qemu_fd);

    if (g_runtime_gate_active && runtime_connection_id != 0) {
        char error[256] = {0};

        pthread_mutex_lock(&g_runtime_gate_lock);
        if (wvm_runtime_gate_revoke(&g_runtime_gate, runtime_connection_id,
                                    error, sizeof(error)) != 0) {
            fprintf(stderr, "[RuntimeGate] revoke failed fd=%d: %s\n", qemu_fd,
                    error[0] ? error : "unknown error");
        }
        pthread_mutex_unlock(&g_runtime_gate_lock);
    }
    
    // 移除客户端并压缩数组，防止 Slot 耗尽
    if (is_push_client) {
        pthread_mutex_lock(&g_client_lock);
        for (int i = 0; i < g_client_count; i++) {
            if (g_qemu_clients[i] == qemu_fd) {
                // 将最后一个元素移到当前空位（无序数组删除法，效率 O(1)）
                if (i != g_client_count - 1) {
                    g_qemu_clients[i] = g_qemu_clients[g_client_count - 1];
                }
                g_client_count--;
                break;
            }
        }
        pthread_mutex_unlock(&g_client_lock);
    }
    
    return NULL;
}

/* 
 * [物理意图] 在无中心网络中注入“初始火种（Bootstrap Seeds）”。
 * [关键逻辑] 从配置中提取非本机的节点 IP，将其状态设为 SHADOW 并挂载到局部视图中，触发初始的 VIEW_PULL 请求。
 * [后果] 这是 P2P 网络的启动原点。若无此函数，节点将陷入“孤岛效应”，无法通过 Gossip 发现任何邻居。
 */
void load_initial_seeds(const char *config_file) {
    (void)config_file;

    if (!g_resource_plan_ready) {
        return;
    }

    for (uint32_t i = 0; i < g_resource_plan.node_count; i++) {
        const struct wvm_resource_node *node = &g_resource_plan.nodes[i];
        struct sockaddr_in seed = {0};

        seed.sin_family = AF_INET;
        seed.sin_addr.s_addr = inet_addr(node->ip);
        seed.sin_port = htons(node->port);
        for (uint32_t slot = 0; slot < node->dht_slots; slot++) {
            uint32_t vnode = node->vnode_start + slot;

            if (vnode == (uint32_t)g_my_node_id) {
                continue;
            }
            update_local_topology_view(vnode, 0, NODE_STATE_SHADOW, &seed, 0);
        }
    }
}

// --- Main Entry ---
int main(int argc, char **argv) {
    // Prevent process-wide termination on EPIPE when a peer disconnects.
    signal(SIGPIPE, SIG_IGN);
    if (install_shutdown_handlers() != 0) {
        perror("[Lifecycle] cannot install shutdown handlers");
        return 1;
    }

    // 参数检查
    if (argc < 7) {
        fprintf(stderr, "Usage: %s <RAM_MB> <LOCAL_PORT> <SWARM_CONFIG> <MY_PHYS_ID> <CTRL_PORT> <SLAVE_PORT> [SYNC_BATCH] [VM_ID]\n", argv[0]);
        return 1;
    }

    g_dev_fd = open("/dev/wavevm", O_RDWR);
    if (g_dev_fd < 0) {
        // 如果是纯用户态模式，这可能不是致命的，但在 Mode A 下是致命的。
        // 打印警告即可，方便调试
        perror("[Warning] Failed to open /dev/wavevm (Kernel Mode disabled?)");
    }


    // 1. 基础参数解析
    size_t ram_mb = (size_t)atol(argv[1]);
    g_shm_size = ram_mb * 1024 * 1024;
    int local_port = atoi(argv[2]);
    const char *config_file = argv[3];
    int my_phys_id = atoi(argv[4]); // 用户传入的是物理 ID (配置文件行号)
    g_ctrl_port = atoi(argv[5]);
    extern int g_slave_forward_port; 
    g_slave_forward_port = atoi(argv[6]);
    // 可选参数：批量同步大小
    if (argc >= 8) {
        extern int g_sync_batch_size;
        g_sync_batch_size = atoi(argv[7]);
    }
    // 可选参数：VM ID (Multi-VM 资源池化)
    if (argc >= 9 &&
        parse_legacy_vm_id(argv[8], &g_my_vm_id) != 0) {
        fprintf(stderr,
                "[VM-ID] legacy data-plane header supports VM IDs only in "
                "[0, %u]; U32 dispatch is not implemented here\n",
                UINT8_MAX);
        return 1;
    }
    if (init_runtime_gate_from_environment(my_phys_id) != 0) {
        return 1;
    }
    if (g_runtime_gate_active &&
        wvm_logic_bind_route_snapshot(
            &g_runtime_storage.manifest.required_route_snapshot_key) != 0) {
        fprintf(stderr, "[Route] admitted manifest route snapshot rejected\n");
        return 1;
    }
    if (bind_kernel_context_from_manifest((uint32_t)my_phys_id) != 0) {
        return 1;
    }

    printf("[*] WaveVM Swarm V30.0 'Wavelet' Node Daemon (PhysID: %d, VM: %u)\n", my_phys_id, (unsigned)g_my_vm_id);

    /*
     * Resolve identity before starting backend RX threads.  Physical IDs are
     * placement keys; admitted launches derive packet routing and the local
     * sidecar from their immutable runtime dispatch projection.  The static
     * resource plan remains available only for ungated legacy startup.
     */
    int my_virtual_id;
    uint32_t my_local_cores;
    uint64_t required_memory_bytes;
    uint32_t total_vnodes;
    int legacy_route_enabled = 1;

    if (g_runtime_gate_active) {
        const struct wvm_runtime_dispatch_projection *dispatch =
            &g_runtime_dispatch_storage.projection;

        my_virtual_id = (int)dispatch->local_primary.destination_vnode;
        legacy_route_enabled =
            dispatch->route_topology_kind == WVM_ROUTE_TOPOLOGY_FLAT;
        total_vnodes = 0;
        if (legacy_route_enabled &&
            runtime_dispatch_legacy_vnode_count(dispatch, &total_vnodes) != 0) {
            fprintf(stderr,
                    "[-] Failed to derive admitted flat route cache size\n");
            return 1;
        }
        if (setenv("WVM_RUNTIME_LEGACY_ROUTE_MODE",
                   legacy_route_enabled ? "flat" : "typed", 1) != 0) {
            fprintf(stderr,
                    "[-] Failed to publish admitted route mode: %s\n",
                    strerror(errno));
            return 1;
        }
        if (runtime_dispatch_local_reservation(&my_local_cores,
                                               &required_memory_bytes) != 0 ||
            user_backend_init(my_virtual_id, local_port) != 0) {
            fprintf(stderr,
                    "[-] Failed to initialize admitted user backend.\n");
            return 1;
        }
    } else {
        char error[256] = {0};
        const struct wvm_resource_node *my_node;

        if (wvm_resource_plan_load(config_file, &g_resource_plan, error,
                                   sizeof(error)) != 0) {
            fprintf(stderr, "[Config] %s\n", error);
            return 1;
        }
        g_resource_plan_ready = 1;
        my_node = wvm_resource_plan_find_node(&g_resource_plan, my_phys_id);
        if (!my_node) {
            fprintf(stderr, "[Fatal] My Physical ID %d not found in config file!\n",
                    my_phys_id);
            return 1;
        }
        my_virtual_id = (int)my_node->vnode_start;
        my_local_cores = my_node->cpu_capacity;
        required_memory_bytes = my_node->memory_mb * 1024U * 1024U;
        total_vnodes = g_resource_plan.total_vnodes;
        if (user_backend_init((int)my_node->vnode_start, local_port) != 0) {
            fprintf(stderr, "[-] Failed to init user backend.\n");
            return 1;
        }
    }

    // 2. Initialize user backend after topology identity has been resolved.
    if (!g_runtime_gate_active && !g_resource_plan_ready) {
        fprintf(stderr, "[-] Failed to init user backend.\n");
        return 1;
    }
    
    // 3. 初始化逻辑核心 (Logic Core)
    // 此时 Total Nodes 尚未知，传 0 作为提示
    if (wvm_core_init(&u_ops, 0) != 0) {
        fprintf(stderr, "[-] Logic Core init failed.\n");
        return 1;
    }
    
    // 4. Initialize routing only from the active authority for this launch.
    if (g_runtime_gate_active) {
        if (apply_runtime_dispatch() != 0) {
            fprintf(stderr,
                    "[-] Failed to apply admitted runtime dispatch.\n");
            return 1;
        }
    } else {
        load_swarm_config(config_file);
    }

    // 5. 启动 V29.5 核心推送引擎的多线程广播线程
    printf("[+] Starting %d Wavelet Broadcast Engines...\n", NUM_BCAST_WORKERS);
    for (long i = 0; i < NUM_BCAST_WORKERS; i++) { // 使用 long 避免指针转换警告
        pthread_t bcast_tid;
        // 将线程ID (0 to 7)作为参数传入
        if (pthread_create(&bcast_tid, NULL, broadcast_worker_thread, (void*)i) != 0) {
            perror("[-] Failed to start broadcast worker thread");
            exit(1);
        }
        pthread_detach(bcast_tid);
    }
    printf("[+] All Wavelet Broadcast Engines started.\n");

    // 6. Validate the local reservation after routing has been initialized.
    if (!g_runtime_gate_active) {
        const struct wvm_resource_vm *my_vm =
            wvm_resource_plan_get_vm(&g_resource_plan, g_my_vm_id);

        if (my_vm) {
            my_local_cores =
                wvm_resource_plan_local_vcpus(&g_resource_plan, g_my_vm_id,
                                               my_phys_id);
            required_memory_bytes =
                wvm_resource_plan_local_memory_mb(&g_resource_plan, g_my_vm_id,
                                                  my_phys_id) *
                1024U * 1024U;
        }
    }
    if ((uint64_t)g_shm_size < required_memory_bytes) {
        fprintf(stderr, "\n[FATAL] Resource Mismatch!\n");
        fprintf(stderr, "  Local reservation requires:          %llu bytes\n",
                (unsigned long long)required_memory_bytes);
        fprintf(stderr, "  Launch arg provided:                 %lu MB\n",
                ram_mb);
        return 1;
    }
    printf("[Check] Resource verified: Alloc %lu MB >= Reservation %llu bytes.\n",
           ram_mb, (unsigned long long)required_memory_bytes);

    // 7. 将真实的虚拟 ID 注入 Logic Core
    // Logic Core 将根据此 ID 判断是否拥有某个 GPA 的管理权 (Directory Owner)
    wvm_set_my_node_id(my_virtual_id);
    printf("[Init] Identity Mapped: PhysID %d -> VirtualID %d (Primary)\n", my_phys_id, my_virtual_id);
    // Mode A owns a separate Logic Core instance inside wavevm.ko.
    if (!g_runtime_gate_active || legacy_route_enabled) {
        inject_vm_id(g_my_vm_id);
        inject_mem_global(0, total_vnodes);
        inject_mem_global(1, (uint32_t)my_virtual_id);
        inject_cpu_route_table();
        if (!g_runtime_gate_active || g_runtime_dispatch_kernel_memory_cache) {
            inject_memory_route_table();
        } else if (g_dev_fd >= 0) {
            fprintf(stderr,
                    "[RuntimeDispatch] skipped legacy Mode A memory cache for "
                    "non-1GiB manifest ranges\n");
        }
    } else {
        fprintf(stderr,
                "[RuntimeDispatch] fractal projection uses typed node-runtime "
                "dispatch; legacy route caches are disabled\n");
    }
    {
        char split_buf[32];
        snprintf(split_buf, sizeof(split_buf), "%u", my_local_cores);
        setenv("WVM_LOCAL_SPLIT", split_buf, 1);
    }

    // 8. 初始化共享内存 (RAM Backing Store)
    // The admitted runtime must provide the manifest-derived SHM name.
    const char *shm_path = getenv("WVM_SHM_FILE");
    if (!shm_path || shm_path[0] == '\0') {
        fprintf(stderr,
                "[System] manifest-derived SHM name is missing\n");
        return 1;
    }

    printf("[System] Initializing SHM: %s (Size: %lu MB)\n", shm_path, ram_mb);

    /* An admitted namespace is owned by one live launch. Do not let a
     * duplicate start unlink another instance's backing store. */
    if (g_runtime_gate_active) {
        int existing_shm_fd = shm_open(shm_path, O_RDWR, 0);

        if (existing_shm_fd >= 0) {
            close(existing_shm_fd);
            fprintf(stderr,
                    "[System] admitted SHM is already owned: %s\n",
                    shm_path);
            return 1;
        }
        if (errno != ENOENT) {
            fprintf(stderr,
                    "[System] cannot inspect admitted SHM '%s': %s\n",
                    shm_path, strerror(errno));
            return 1;
        }
    } else {
        shm_unlink(shm_path);
    }

    int shm_flags = O_CREAT | O_RDWR;
    if (g_runtime_gate_active) {
        shm_flags |= O_EXCL;
    }
    int shm_fd = shm_open(shm_path, shm_flags, 0666);
    if (shm_fd < 0) { 
        fprintf(stderr, "[-] Failed to open shm file '%s': %s\n", shm_path, strerror(errno));
        return 1; 
    }
    
    // 分配物理空间
    if (ftruncate(shm_fd, g_shm_size) < 0) {
        perror("ftruncate failed");
        close(shm_fd);
        return 1;
    }

    // 映射到进程空间
    g_shm_ptr = mmap(NULL, g_shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd); // 映射后即可关闭 fd
    
    if (g_shm_ptr == MAP_FAILED) { 
        perror("mmap failed"); 
        return 1; 
    }
    
    // 可选：预热内存 (避免运行时缺页抖动)
    // memset(g_shm_ptr, 0, g_shm_size);
    printf("[+] Memory Ready at %p\n", g_shm_ptr);

    // 9. 启动 UNIX Socket 监听 (QEMU 接口)
    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket AF_UNIX failed");
        return 1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    
    // The runtime and QEMU consume one manifest-derived endpoint.
    const char *sock_path = getenv("WVM_RUNTIME_SOCKET");
    if (!sock_path || sock_path[0] == '\0') {
        sock_path = getenv("WVM_ENV_SOCK_PATH");
    }
    if (!sock_path || sock_path[0] == '\0' ||
        strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr,
                "[System] manifest-derived runtime socket path is missing\n");
        close(listen_fd);
        return 1;
    }

    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (g_runtime_gate_active) {
        if (access(sock_path, F_OK) == 0 || errno != ENOENT) {
            fprintf(stderr,
                    "[System] admitted runtime socket is already owned: %s\n",
                    sock_path);
            close(listen_fd);
            return 1;
        }
    } else {
        unlink(sock_path); // 绑定前确保文件不存在
    }

    printf("[System] Control Socket: %s\n", sock_path);

    // Keep the same value visible to any locally launched QEMU child.
    setenv("WVM_ENV_SOCK_PATH", sock_path, 1);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { 
        perror("bind unix socket failed"); 
        return 1; 
    }
    
    if (listen(listen_fd, 100) < 0) {
        perror("listen failed");
        return 1;
    }

    /* Publish identity-bound readiness only after the endpoint is listening. */
    {
        char ready_error[256] = {0};

        if (wvm_runtime_ready_publish(
                &g_runtime_storage.manifest,
                g_runtime_storage.manifest.expected_node_instance_id,
                ready_error, sizeof(ready_error)) != 0) {
            fprintf(stderr, "[System] cannot publish runtime readiness: %s\n",
                    ready_error[0] ? ready_error : "invalid readiness state");
            close(listen_fd);
            return 1;
        }
    }

    printf("[+] WaveVM V29 Node Ready. Waiting for QEMU...\n");

    // 10. Backend/Logic Core 已在前面初始化并注入拓扑。
    // 此处严禁重复初始化，否则会重置 CPU 路由表为 AUTO_ROUTE。

    /*
     * An admitted runtime already has an immutable membership and route
     * snapshot.  Legacy seed gossip must not mutate or replace that authority.
     */
    if (!g_runtime_gate_active) {
        pthread_t monitor_tid;

        load_initial_seeds(config_file);
        pthread_create(&monitor_tid, NULL, autonomous_monitor_thread, NULL);
        pthread_detach(monitor_tid);
        printf("[Autonomous] Node started in SHADOW mode. Auto-scaling into cluster...\n");
    } else {
        printf("[RuntimeDispatch] admitted route snapshot active; legacy gossip disabled.\n");
    }

    // 14. 主循环：接受 QEMU 连接
    while (!g_shutdown_requested) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                if (g_shutdown_requested) {
                    break;
                }
                continue;
            }
            perror("accept error");
            // 生产环境可能选择 sleep 并重试，而非退出
            sleep(1);
            continue;
        }

        // [FIX-F1] 防御性检查：在 accept 后立即检查连接数上限，防止线程爆炸。
        // 旧代码无条件 pthread_create，仅在 client_handler 内部检查 MAX_QEMU_CLIENTS，
        // 但线程已经创建完毕。此处前置检查，超限直接拒绝连接。
        pthread_mutex_lock(&g_client_lock);
        int current_count = g_client_count;
        pthread_mutex_unlock(&g_client_lock);

        if (current_count >= MAX_QEMU_CLIENTS) {
            fprintf(stderr, "[IPC] WARN: MAX_QEMU_CLIENTS(%d) reached, rejecting fd=%d\n",
                    MAX_QEMU_CLIENTS, client_fd);
            close(client_fd);
            continue;
        }

        // 为每个 QEMU 连接创建一个处理线程
        pthread_t thread_id;
        int *new_sock = malloc(sizeof(int));
        if (new_sock) {
            *new_sock = client_fd;
            if (pthread_create(&thread_id, NULL, client_handler, (void*)new_sock) != 0) {
                perror("pthread_create failed");
                close(client_fd);
                free(new_sock);
            } else {
                pthread_detach(thread_id);
            }
        } else {
            perror("malloc failed");
            close(client_fd);
        }
    }

    /* Only the main thread performs teardown.  The signal handler above only
     * changes the stop flag, so these calls remain outside signal context. */
    if (g_runtime_gate_active) {
        char error[256] = {0};

        pthread_mutex_lock(&g_runtime_gate_lock);
        if (wvm_runtime_gate_quiesce(&g_runtime_gate, error, sizeof(error)) !=
            0) {
            fprintf(stderr, "[Lifecycle] runtime gate quiesce failed: %s\n",
                    error[0] ? error : "unknown error");
        }
        pthread_mutex_unlock(&g_runtime_gate_lock);
        if (wvm_runtime_ready_remove(&g_runtime_storage.manifest, error,
                                     sizeof(error)) != 0) {
            fprintf(stderr, "[Lifecycle] readiness removal failed: %s\n",
                    error[0] ? error : "unknown error");
        }
    }
    close(listen_fd);
    if (sock_path && sock_path[0] != '\0') {
        unlink(sock_path);
    }
    if (g_shm_ptr && g_shm_ptr != MAP_FAILED) {
        munmap(g_shm_ptr, g_shm_size);
        g_shm_ptr = NULL;
    }
    if (shm_path && shm_path[0] != '\0') {
        shm_unlink(shm_path);
    }
    if (g_dev_fd >= 0) {
        close(g_dev_fd);
        g_dev_fd = -1;
    }
    if (g_runtime_dispatch_active) {
        wvm_runtime_dispatch_storage_free(&g_runtime_dispatch_storage);
        g_runtime_dispatch_active = 0;
    }
    if (g_runtime_gate_active) {
        wvm_runtime_manifest_storage_free(&g_runtime_storage);
        g_runtime_gate_active = 0;
    }

    return 0;
}

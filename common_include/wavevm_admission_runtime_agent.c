#include "wavevm_admission_runtime_agent.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

struct agent_slot_storage {
    struct wvm_admission_participant_stage_storage prepared;
    struct wvm_admission_participant_stage_storage scratch;
};

struct agent_owned_storage {
    struct agent_slot_storage *slot_storage;
    struct wvm_admission_receiver_slot *slots;
    struct wvm_resource_reservation *reservation_records;
    struct wvm_vcpu_assignment *reservation_vcpus;
    struct wvm_memory_chunk_assignment *reservation_memory;
    struct wvm_storage_assignment *reservation_storage;
    struct wvm_required_member *reservation_members;
    struct wvm_capability_ref *reservation_required_capabilities;
    struct wvm_capability_ref *reservation_execution_capabilities;
    struct wvm_reservation_requirement *reservation_requirements;
    struct wvm_exclusive_lease *reservation_requirement_leases;
    struct wvm_exclusive_lease *reservation_leases;
    struct wvm_route_snapshot_key *reservation_routes;
    pid_t *runtime_pids;
};

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static int checked_count(size_t first, size_t second, size_t *result)
{
    if (!result || (second != 0 && first > SIZE_MAX / second)) {
        return -1;
    }
    *result = first * second;
    return 0;
}

static void free_participant_storage(
    struct wvm_admission_participant_stage_storage *storage)
{
    if (!storage) {
        return;
    }
    free(storage->candidate_storage.vcpu_placements);
    free(storage->candidate_storage.memory_placements);
    free(storage->candidate_storage.storage_assignments);
    free(storage->candidate_storage.required_members);
    free(storage->candidate_storage.required_capabilities);
    free(storage->candidate_storage.execution_capabilities);
    free(storage->candidate_storage.reservation_requirements);
    free(storage->candidate_storage.reservation_requirement_leases);
    free(storage->dispatch_cpu_entries);
    free(storage->dispatch_memory_entries);
    free(storage->runtime_vcpu_assignments);
    free(storage->runtime_memory_assignments);
    free(storage->runtime_storage_assignments);
    free(storage->runtime_capabilities);
    free(storage->runtime_dependencies);
    free(storage->activation_route_snapshot_keys);
    memset(storage, 0, sizeof(*storage));
}

static int allocate_participant_storage(
    struct wvm_admission_participant_stage_storage *storage,
    const struct wvm_admission_runtime_agent_config *config)
{
    size_t lease_count;
    struct wvm_admission_candidate_stage_storage *candidate;

    if (!storage || !config || checked_count(config->max_members,
                                             config->max_leases_per_requirement,
                                             &lease_count) != 0) {
        return -1;
    }
    memset(storage, 0, sizeof(*storage));
    candidate = &storage->candidate_storage;
#define ALLOC_FIELD(field, count)                                              \
    do {                                                                       \
        (field) = calloc((count) ? (count) : 1U, sizeof(*(field)));           \
        if (!(field)) {                                                        \
            free_participant_storage(storage);                                 \
            return -1;                                                         \
        }                                                                      \
    } while (0)
    ALLOC_FIELD(candidate->vcpu_placements, config->max_vcpus);
    ALLOC_FIELD(candidate->memory_placements, config->max_memory_chunks);
    ALLOC_FIELD(candidate->storage_assignments, config->max_storage_assignments);
    ALLOC_FIELD(candidate->required_members, config->max_members);
    ALLOC_FIELD(candidate->required_capabilities, config->max_members);
    ALLOC_FIELD(candidate->execution_capabilities, config->max_members);
    ALLOC_FIELD(candidate->reservation_requirements, config->max_members);
    ALLOC_FIELD(candidate->reservation_requirement_leases, lease_count);
    ALLOC_FIELD(storage->dispatch_cpu_entries, config->max_vcpus);
    ALLOC_FIELD(storage->dispatch_memory_entries, config->max_memory_chunks);
    ALLOC_FIELD(storage->runtime_vcpu_assignments, config->max_vcpus);
    ALLOC_FIELD(storage->runtime_memory_assignments, config->max_memory_chunks);
    ALLOC_FIELD(storage->runtime_storage_assignments,
                config->max_storage_assignments);
    ALLOC_FIELD(storage->runtime_capabilities, config->max_members);
    ALLOC_FIELD(storage->runtime_dependencies, config->max_members);
    ALLOC_FIELD(storage->activation_route_snapshot_keys, config->max_members);
#undef ALLOC_FIELD
    candidate->vcpu_placement_capacity = config->max_vcpus;
    candidate->memory_placement_capacity = config->max_memory_chunks;
    candidate->storage_assignment_capacity = config->max_storage_assignments;
    candidate->required_member_capacity = config->max_members;
    candidate->required_capability_capacity = config->max_members;
    candidate->execution_capability_capacity = config->max_members;
    candidate->reservation_requirement_capacity = config->max_members;
    candidate->reservation_requirement_leases =
        storage->candidate_storage.reservation_requirement_leases;
    candidate->reservation_requirement_lease_capacity =
        config->max_leases_per_requirement;
    storage->dispatch_cpu_capacity = config->max_vcpus;
    storage->dispatch_memory_capacity = config->max_memory_chunks;
    storage->runtime_vcpu_assignment_capacity = config->max_vcpus;
    storage->runtime_memory_assignment_capacity = config->max_memory_chunks;
    storage->runtime_storage_assignment_capacity =
        config->max_storage_assignments;
    storage->runtime_capability_capacity = config->max_members;
    storage->runtime_dependency_capacity = config->max_members;
    storage->activation_route_snapshot_key_capacity = config->max_members;
    return 0;
}

static int delivery_inputs(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime,
    const struct wvm_activation_record *activation,
    const struct wvm_cluster_record_set **records,
    const struct wvm_route_snapshot_record **route, char *error,
    size_t error_len)
{
    struct wvm_admission_runtime_agent *agent = context;
    struct wvm_route_control_snapshot *snapshot;

    (void)candidate;
    (void)activation;
    if (!agent || !runtime || !records || !route) {
        set_error(error, error_len, "runtime delivery input context is invalid");
        return -EINVAL;
    }
    snapshot = agent->delivery_snapshot;
    /* The receiver serializes delivery callbacks, so this transient view is
     * valid until the callback returns and is not shared with data workers. */
    if (snapshot->snapshot.route_snapshot_key.scope_key.vm_id != 0) {
        wvm_route_control_snapshot_free(snapshot);
    }
    memset(snapshot, 0, sizeof(*snapshot));
    if (wvm_route_control_snapshot_load(
            &agent->route_control, &runtime->required_route_snapshot_key,
            snapshot, error, error_len) != 0) {
        return -1;
    }
    *records = NULL;
    *route = &snapshot->snapshot;
    return 0;
}

static int resolve_slot(void *context, uint32_t vm_id,
                        uint64_t vm_incarnation, uint64_t manifest_generation,
                        struct wvm_admission_receiver_slot **slot_out,
                        char *error, size_t error_len)
{
    struct wvm_admission_runtime_agent *agent = context;

    return wvm_admission_slot_registry_resolve(
        agent ? &agent->slot_registry : NULL, vm_id, vm_incarnation,
        manifest_generation, slot_out, error, error_len);
}

static int start_runtime(
    void *context, const struct wvm_admission_receiver_slot *slot,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    struct wvm_admission_runtime_agent *agent = context;
    struct agent_owned_storage *owned;
    posix_spawnattr_t attributes;
    sigset_t empty_signals;
    char parent_pid[32];
    char node_instance[32];
    char *argv[9];
    pid_t pid;
    size_t index;
    int status;

    if (!agent || !agent->runtime_executable || !slot ||
        !slot->runtime_manifest_path || !runtime_manifest ||
        runtime_manifest->expected_node_instance_id == 0) {
        set_error(error, error_len, "admitted runtime launch is unavailable");
        return -EINVAL;
    }
    owned = agent->owned_storage;
    for (index = 0; index < agent->slot_capacity; index++) {
        if (&agent->slots[index] == slot) {
            break;
        }
    }
    if (index == agent->slot_capacity || !owned || !owned->runtime_pids) {
        set_error(error, error_len, "admitted runtime slot is not owned by agent");
        return -EINVAL;
    }
    pid = owned->runtime_pids[index];
    if (pid > 0) {
        pid_t waited = waitpid(pid, &status, WNOHANG);

        if (waited == 0) {
            return 0;
        }
        if (waited < 0 && errno != ECHILD) {
            set_error(error, error_len, "cannot inspect admitted runtime child");
            return -errno;
        }
        owned->runtime_pids[index] = 0;
    }
    (void)snprintf(parent_pid, sizeof(parent_pid), "%ld", (long)getpid());
    (void)snprintf(node_instance, sizeof(node_instance), "%" PRIu64,
                   runtime_manifest->expected_node_instance_id);
    argv[0] = agent->runtime_executable;
    argv[1] = "child";
    argv[2] = "--parent-pid";
    argv[3] = parent_pid;
    argv[4] = "--manifest";
    argv[5] = (char *)slot->runtime_manifest_path;
    argv[6] = "--node-instance";
    argv[7] = node_instance;
    argv[8] = NULL;
    status = posix_spawnattr_init(&attributes);
    if (status == 0) {
        status = sigemptyset(&empty_signals);
        if (status == 0) {
            status = posix_spawnattr_setsigmask(&attributes, &empty_signals);
        }
        if (status == 0) {
            status = posix_spawnattr_setflags(&attributes,
                                              POSIX_SPAWN_SETSIGMASK);
        }
        if (status == 0) {
            status = posix_spawn(&pid, agent->runtime_executable, NULL,
                                 &attributes, argv, environ);
        }
        posix_spawnattr_destroy(&attributes);
    }
    if (status != 0) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len, "cannot start admitted runtime: %s",
                           strerror(status));
        }
        return -status;
    }
    owned->runtime_pids[index] = pid;
    return 0;
}

static void reap_runtime_children(struct wvm_admission_runtime_agent *agent)
{
    struct agent_owned_storage *owned = agent ? agent->owned_storage : NULL;
    size_t i;

    if (!owned || !owned->runtime_pids) {
        return;
    }
    for (i = 0; i < agent->slot_capacity; i++) {
        int status;
        pid_t pid = owned->runtime_pids[i];

        if (pid > 0 && waitpid(pid, &status, WNOHANG) == pid) {
            owned->runtime_pids[i] = 0;
        }
    }
}

void wvm_admission_runtime_agent_reap(struct wvm_admission_runtime_agent *agent)
{
    if (!agent || !agent->node_service_initialized) {
        return;
    }
    pthread_mutex_lock(&agent->node_service.receiver.lock);
    reap_runtime_children(agent);
    pthread_mutex_unlock(&agent->node_service.receiver.lock);
}

static void stop_runtime_children(struct wvm_admission_runtime_agent *agent)
{
    struct agent_owned_storage *owned = agent ? agent->owned_storage : NULL;
    size_t i;

    if (!owned || !owned->runtime_pids) {
        return;
    }
    for (i = 0; i < agent->slot_capacity; i++) {
        if (owned->runtime_pids[i] > 0) {
            (void)kill(owned->runtime_pids[i], SIGKILL);
        }
    }
    for (i = 0; i < agent->slot_capacity; i++) {
        if (owned->runtime_pids[i] > 0) {
            int status;

            while (waitpid(owned->runtime_pids[i], &status, 0) < 0 &&
                   errno == EINTR) {
            }
            owned->runtime_pids[i] = 0;
        }
    }
}

static int agent_storage_init(
    struct wvm_admission_runtime_agent *agent,
    const struct wvm_admission_runtime_agent_config *config, char *error,
    size_t error_len)
{
    struct agent_owned_storage *owned;
    struct wvm_admission_node node;
    size_t i;

    owned = calloc(1, sizeof(*owned));
    if (!owned || config->slot_capacity > SIZE_MAX / sizeof(*owned->slots) ||
        config->slot_capacity > SIZE_MAX / sizeof(*owned->slot_storage)) {
        free(owned);
        set_error(error, error_len, "admission agent storage dimensions overflow");
        return -EOVERFLOW;
    }
    owned->slots = calloc(config->slot_capacity, sizeof(*owned->slots));
    owned->slot_storage = calloc(config->slot_capacity,
                                 sizeof(*owned->slot_storage));
    owned->reservation_records = calloc(
        config->slot_capacity, sizeof(*owned->reservation_records));
    owned->runtime_pids = calloc(config->slot_capacity,
                                 sizeof(*owned->runtime_pids));
    agent->owned_storage = owned;
    agent->slot_capacity = config->slot_capacity;
    if (!owned->slots || !owned->slot_storage ||
        !owned->reservation_records || !owned->runtime_pids) {
        set_error(error, error_len, "cannot allocate admission agent slots");
        return -ENOMEM;
    }
    for (i = 0; i < config->slot_capacity; i++) {
        if (allocate_participant_storage(&owned->slot_storage[i].prepared,
                                         config) != 0 ||
            allocate_participant_storage(&owned->slot_storage[i].scratch,
                                         config) != 0) {
            set_error(error, error_len,
                      "cannot allocate admission participant storage");
            return -ENOMEM;
        }
        owned->slots[i].prepared_storage = owned->slot_storage[i].prepared;
        owned->slots[i].scratch_storage = owned->slot_storage[i].scratch;
    }
    if (checked_count(config->max_members, config->max_leases_per_requirement,
                      &i) != 0) {
        set_error(error, error_len, "admission lease dimensions overflow");
        return -EOVERFLOW;
    }
    owned->reservation_vcpus = calloc(config->max_vcpus,
                                      sizeof(*owned->reservation_vcpus));
    owned->reservation_memory = calloc(config->max_memory_chunks,
                                       sizeof(*owned->reservation_memory));
    owned->reservation_storage = calloc(config->max_storage_assignments
                                            ? config->max_storage_assignments
                                            : 1U,
                                        sizeof(*owned->reservation_storage));
    owned->reservation_members = calloc(config->max_members,
                                        sizeof(*owned->reservation_members));
    owned->reservation_required_capabilities = calloc(
        config->max_members, sizeof(*owned->reservation_required_capabilities));
    owned->reservation_execution_capabilities = calloc(
        config->max_members, sizeof(*owned->reservation_execution_capabilities));
    owned->reservation_requirements = calloc(
        config->max_members, sizeof(*owned->reservation_requirements));
    owned->reservation_requirement_leases = calloc(
        i, sizeof(*owned->reservation_requirement_leases));
    owned->reservation_leases = calloc(config->max_leases_per_requirement,
                                       sizeof(*owned->reservation_leases));
    owned->reservation_routes = calloc(config->max_members,
                                       sizeof(*owned->reservation_routes));
    if (!owned->reservation_vcpus || !owned->reservation_memory ||
        !owned->reservation_storage || !owned->reservation_members ||
        !owned->reservation_required_capabilities ||
        !owned->reservation_execution_capabilities ||
        !owned->reservation_requirements ||
        !owned->reservation_requirement_leases || !owned->reservation_leases ||
        !owned->reservation_routes) {
        set_error(error, error_len, "cannot allocate admission decode storage");
        return -ENOMEM;
    }
    memset(&agent->reservation_scratch, 0, sizeof(agent->reservation_scratch));
    agent->reservation_scratch.candidate_storage.vcpu_placements =
        owned->reservation_vcpus;
    agent->reservation_scratch.candidate_storage.vcpu_placement_capacity =
        config->max_vcpus;
    agent->reservation_scratch.candidate_storage.memory_placements =
        owned->reservation_memory;
    agent->reservation_scratch.candidate_storage.memory_placement_capacity =
        config->max_memory_chunks;
    agent->reservation_scratch.candidate_storage.storage_assignments =
        owned->reservation_storage;
    agent->reservation_scratch.candidate_storage.storage_assignment_capacity =
        config->max_storage_assignments;
    agent->reservation_scratch.candidate_storage.required_members =
        owned->reservation_members;
    agent->reservation_scratch.candidate_storage.required_member_capacity =
        config->max_members;
    agent->reservation_scratch.candidate_storage.required_capabilities =
        owned->reservation_required_capabilities;
    agent->reservation_scratch.candidate_storage.required_capability_capacity =
        config->max_members;
    agent->reservation_scratch.candidate_storage.execution_capabilities =
        owned->reservation_execution_capabilities;
    agent->reservation_scratch.candidate_storage.execution_capability_capacity =
        config->max_members;
    agent->reservation_scratch.candidate_storage.reservation_requirements =
        owned->reservation_requirements;
    agent->reservation_scratch.candidate_storage.reservation_requirement_capacity =
        config->max_members;
    agent->reservation_scratch.candidate_storage.reservation_requirement_leases =
        owned->reservation_requirement_leases;
    agent->reservation_scratch.candidate_storage.reservation_requirement_lease_capacity =
        config->max_leases_per_requirement;
    agent->reservation_scratch.reservation_leases = owned->reservation_leases;
    agent->reservation_scratch.reservation_lease_capacity =
        config->max_leases_per_requirement;
    agent->reservation_scratch.activation_route_snapshot_keys =
        owned->reservation_routes;
    agent->reservation_scratch.activation_route_snapshot_key_capacity =
        config->max_members;
    memset(&node, 0, sizeof(node));
    node.physical_node_id = config->local_physical_node_id;
    node.node_instance_id = config->local_node_instance_id;
    node.inventory_revision = config->inventory_revision;
    node.allocatable_vcpu_slots = config->allocatable_vcpu_slots;
    node.allocatable_memory_bytes = config->allocatable_memory_bytes;
    if (wvm_local_reservation_registry_init(
            &agent->reservation_registry, &node, owned->reservation_records,
            config->slot_capacity, error, error_len) != 0) {
        return -1;
    }
    agent->reservation_initialized = 1;
    if (wvm_local_reservation_registry_open(
            &agent->reservation_registry, config->reservation_journal_path,
            64U * 1024U * 1024U, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

static int delivery_snapshot_owner_init(struct wvm_admission_runtime_agent *agent)
{
    struct wvm_route_control_snapshot *snapshot;

    snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) {
        return -ENOMEM;
    }
    agent->delivery_snapshot = snapshot;
    return 0;
}

int wvm_admission_runtime_agent_init(
    struct wvm_admission_runtime_agent *agent,
    const struct wvm_admission_runtime_agent_config *config, char *error,
    size_t error_len)
{
    struct wvm_admission_node_service_config service_config;
    struct wvm_admission_slot_registry_config slot_config;
    struct wvm_admission_receiver_config receiver_config;
    struct agent_owned_storage *owned;

    if (!agent || !config || !config->runtime_executable ||
        config->runtime_executable[0] != '/' || !config->socket_path ||
        !config->state_directory ||
        !config->runtime_directory || !config->route_journal_path ||
        !config->reservation_journal_path || config->slot_capacity == 0 ||
        config->max_vcpus == 0 || config->max_memory_chunks == 0 ||
        config->max_members == 0 || config->max_leases_per_requirement == 0 ||
        !config->authenticate || config->local_physical_node_id == 0 ||
        config->local_node_instance_id == 0 ||
        config->controller_physical_node_id == 0 ||
        config->controller_runtime_instance_id == 0) {
        set_error(error, error_len, "admission runtime agent configuration is invalid");
        return -EINVAL;
    }
    memset(agent, 0, sizeof(*agent));
    agent->runtime_executable = strdup(config->runtime_executable);
    if (!agent->runtime_executable) {
        set_error(error, error_len, "cannot copy runtime executable path");
        return -ENOMEM;
    }
    if (agent_storage_init(agent, config, error, error_len) != 0) {
        wvm_admission_runtime_agent_destroy(agent);
        return -1;
    }
    owned = agent->owned_storage;
    if (delivery_snapshot_owner_init(agent) != 0) {
        set_error(error, error_len, "cannot allocate route delivery snapshot");
        wvm_admission_runtime_agent_destroy(agent);
        return -ENOMEM;
    }
    wvm_route_runtime_init(&agent->route_runtime);
    agent->route_runtime_initialized = 1;
    if (wvm_route_control_open(&agent->route_control, &agent->route_runtime,
                               config->route_journal_path, error,
                               error_len) != 0) {
        wvm_admission_runtime_agent_destroy(agent);
        return -1;
    }
    agent->route_control_initialized = 1;
    memset(&receiver_config, 0, sizeof(receiver_config));
    receiver_config.controller_member_key = config->controller_member_key;
    receiver_config.controller_physical_node_id =
        config->controller_physical_node_id;
    receiver_config.controller_runtime_instance_id =
        config->controller_runtime_instance_id;
    receiver_config.local_physical_node_id = config->local_physical_node_id;
    receiver_config.local_node_instance_id = config->local_node_instance_id;
    receiver_config.reservation_registry = &agent->reservation_registry;
    receiver_config.reservation_scratch_storage = &agent->reservation_scratch;
    receiver_config.route_control = &agent->route_control;
    receiver_config.context = agent;
    receiver_config.resolve_slot = resolve_slot;
    receiver_config.delivery_inputs = delivery_inputs;
    receiver_config.start_runtime = start_runtime;
    memset(&service_config, 0, sizeof(service_config));
    service_config.socket_path = config->socket_path;
    service_config.socket_mode = config->socket_mode;
    service_config.listen_backlog = config->listen_backlog;
    service_config.local_physical_node_id = config->local_physical_node_id;
    service_config.local_runtime_instance_id = config->local_node_instance_id;
    service_config.max_frame_bytes = config->max_frame_bytes;
    service_config.authenticate = config->authenticate;
    service_config.authenticate_opaque = config->authenticate_opaque;
    service_config.receiver = receiver_config;
    if (wvm_admission_node_service_init(&agent->node_service, &service_config,
                                        error, error_len) != 0) {
        wvm_admission_runtime_agent_destroy(agent);
        return -1;
    }
    agent->node_service_initialized = 1;
    memset(&slot_config, 0, sizeof(slot_config));
    slot_config.receiver = &agent->node_service.receiver;
    slot_config.slots = owned->slots;
    slot_config.slot_capacity = config->slot_capacity;
    slot_config.state_directory = config->state_directory;
    slot_config.runtime_directory = config->runtime_directory;
    if (wvm_admission_slot_registry_init(&agent->slot_registry, &slot_config,
                                         error, error_len) != 0) {
        wvm_admission_runtime_agent_destroy(agent);
        return -1;
    }
    agent->slot_registry_initialized = 1;
    agent->slots = owned->slots;
    agent->slot_capacity = config->slot_capacity;
    agent->initialized = 1;
    return 0;
}

int wvm_admission_runtime_agent_start(
    struct wvm_admission_runtime_agent *agent, char *error, size_t error_len)
{
    if (!agent || !agent->initialized) {
        set_error(error, error_len, "admission runtime agent is not initialized");
        return -EINVAL;
    }
    return wvm_admission_node_service_start(&agent->node_service, error,
                                            error_len);
}

int wvm_admission_runtime_agent_stop(
    struct wvm_admission_runtime_agent *agent, char *error, size_t error_len)
{
    if (!agent || !agent->initialized) {
        set_error(error, error_len, "admission runtime agent is not initialized");
        return -EINVAL;
    }
    if (wvm_admission_node_service_stop(&agent->node_service, error,
                                        error_len) != 0) {
        return -1;
    }
    stop_runtime_children(agent);
    return 0;
}

void wvm_admission_runtime_agent_destroy(
    struct wvm_admission_runtime_agent *agent)
{
    struct agent_owned_storage *owned;
    size_t i;

    if (!agent) {
        return;
    }
    if (agent->node_service_initialized) {
        (void)wvm_admission_node_service_stop(&agent->node_service, NULL, 0);
    }
    stop_runtime_children(agent);
    if (agent->slot_registry_initialized) {
        wvm_admission_slot_registry_destroy(&agent->slot_registry);
    }
    if (agent->node_service_initialized) {
        wvm_admission_node_service_destroy(&agent->node_service);
    }
    if (agent->reservation_initialized) {
        wvm_local_reservation_registry_destroy(&agent->reservation_registry);
    }
    if (agent->route_control_initialized) {
        wvm_route_control_close(&agent->route_control);
    }
    if (agent->route_runtime_initialized) {
        wvm_route_runtime_destroy(&agent->route_runtime);
    }
    owned = agent->owned_storage;
    if (owned) {
        for (i = 0; i < agent->slot_capacity; i++) {
            if (owned->slot_storage) {
                free_participant_storage(&owned->slot_storage[i].prepared);
                free_participant_storage(&owned->slot_storage[i].scratch);
            }
        }
        free(owned->reservation_records);
        free(owned->reservation_vcpus);
        free(owned->reservation_memory);
        free(owned->reservation_storage);
        free(owned->reservation_members);
        free(owned->reservation_required_capabilities);
        free(owned->reservation_execution_capabilities);
        free(owned->reservation_requirements);
        free(owned->reservation_requirement_leases);
        free(owned->reservation_leases);
        free(owned->reservation_routes);
        free(owned->runtime_pids);
        free(owned->slots);
        free(owned->slot_storage);
        free(owned);
    }
    /* The delivery snapshot is separate because the callback needs it while
     * the receiver lock is held. */
    if (agent->delivery_snapshot) {
        wvm_route_control_snapshot_free(agent->delivery_snapshot);
        free(agent->delivery_snapshot);
    }
    free(agent->runtime_executable);
    memset(agent, 0, sizeof(*agent));
}

#ifndef WAVEVM_ADMISSION_RUNTIME_AGENT_H
#define WAVEVM_ADMISSION_RUNTIME_AGENT_H

/* Long-lived node owner for admission participants. */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "wavevm_admission_node_service.h"
#include "wavevm_admission_slot_registry.h"
#include "wavevm_route_control.h"

struct wvm_admission_runtime_agent_config {
    const char *runtime_executable;
    const char *socket_path;
    const char *state_directory;
    const char *runtime_directory;
    const char *route_journal_path;
    const char *reservation_journal_path;
    mode_t socket_mode;
    int listen_backlog;
    size_t max_frame_bytes;
    size_t slot_capacity;
    size_t max_vcpus;
    size_t max_memory_chunks;
    size_t max_storage_assignments;
    size_t max_members;
    size_t max_leases_per_requirement;
    uint32_t local_physical_node_id;
    uint64_t local_node_instance_id;
    uint64_t inventory_revision;
    uint32_t allocatable_vcpu_slots;
    uint64_t allocatable_memory_bytes;
    struct wvm_member_key controller_member_key;
    uint32_t controller_physical_node_id;
    uint64_t controller_runtime_instance_id;
    wvm_control_transport_authenticate_fn authenticate;
    void *authenticate_opaque;
};

struct wvm_admission_runtime_agent {
    struct wvm_route_runtime route_runtime;
    struct wvm_route_control route_control;
    struct wvm_local_reservation_registry reservation_registry;
    struct wvm_admission_node_service node_service;
    struct wvm_admission_slot_registry slot_registry;
    struct wvm_admission_receiver_slot *slots;
    struct wvm_admission_reservation_stage_storage reservation_scratch;
    void *owned_storage;
    struct wvm_route_control_snapshot *delivery_snapshot;
    char *runtime_executable;
    size_t slot_capacity;
    int route_runtime_initialized;
    int route_control_initialized;
    int reservation_initialized;
    int node_service_initialized;
    int slot_registry_initialized;
    int initialized;
};

int wvm_admission_runtime_agent_init(
    struct wvm_admission_runtime_agent *agent,
    const struct wvm_admission_runtime_agent_config *config, char *error,
    size_t error_len);

int wvm_admission_runtime_agent_start(
    struct wvm_admission_runtime_agent *agent, char *error, size_t error_len);

int wvm_admission_runtime_agent_stop(
    struct wvm_admission_runtime_agent *agent, char *error, size_t error_len);

void wvm_admission_runtime_agent_destroy(
    struct wvm_admission_runtime_agent *agent);

/* Reap exited per-VM children after SIGCHLD; safe between control requests. */
void wvm_admission_runtime_agent_reap(
    struct wvm_admission_runtime_agent *agent);

#endif

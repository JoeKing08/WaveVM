#ifndef WAVEVM_ADMISSION_TRANSPORT_H
#define WAVEVM_ADMISSION_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission_orchestrator.h"
#include "wavevm_control.h"
#include "wavevm_envelope.h"
#include "wavevm_runtime_dispatch.h"

/* One authenticated control destination selected from a captured record set. */
struct wvm_admission_transport_target {
    struct wvm_member_key member_key;
    struct wvm_endpoint endpoint;
};

/* Resolve an exact registered member to its current control endpoint. */
typedef int (*wvm_admission_transport_resolve_member_fn)(
    void *context, const struct wvm_member_key *member_key,
    struct wvm_admission_transport_target *target, char *error,
    size_t error_len);

/*
 * Submit one control request and return success only after TARGET durably
 * recorded its idempotent result. ENVELOPE is caller-owned during the call.
 */
typedef int (*wvm_admission_transport_submit_fn)(
    void *context, const struct wvm_admission_transport_target *target,
    const struct wvm_envelope *envelope, char *error, size_t error_len);

struct wvm_admission_transport {
    uint32_t controller_physical_node_id;
    uint64_t controller_instance_id;
    void *context;
    /* Borrowed only for the duration of one synchronous orchestration run. */
    const struct wvm_cluster_record_set *delivery_records;
    const struct wvm_route_snapshot_record *delivery_route_snapshot;
    wvm_admission_transport_resolve_member_fn resolve_member;
    wvm_admission_transport_submit_fn submit;
};

int wvm_admission_transport_init(
    struct wvm_admission_transport *transport,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    void *context, wvm_admission_transport_resolve_member_fn resolve_member,
    wvm_admission_transport_submit_fn submit, char *error,
    size_t error_len);

/* Populate the exact orchestrator stage callback set. */
int wvm_admission_transport_callbacks(
    struct wvm_admission_transport *transport,
    struct wvm_admission_orchestrator_callbacks *callbacks, char *error,
    size_t error_len);

/* Query the exact participant after it has activated and published readiness. */
int wvm_admission_transport_query_runtime_ready(
    struct wvm_admission_transport *transport,
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len);

#endif /* WAVEVM_ADMISSION_TRANSPORT_H */

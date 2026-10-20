#ifndef WAVEVM_ROUTE_RUNTIME_H
#define WAVEVM_ROUTE_RUNTIME_H

/*
 * Immutable, VM-scoped route snapshots consumed by node runtimes, sidecars,
 * and gateways. The control plane owns the canonical snapshot record; this
 * module owns only prepared/active/predecessor copies and exact-key lookup.
 */

#include <pthread.h>
#include <stddef.h>

#include "wavevm_control.h"
#include "wavevm_envelope.h"

#define WVM_ROUTE_RUNTIME_MAX_ENTRIES 65536U
#define WVM_ROUTE_RUNTIME_MAX_SCOPES 1024U

struct wvm_route_runtime_next_hop {
    uint16_t matched_destination_kind;
    uint16_t next_hop_kind;
    uint16_t hop_limit;
    struct wvm_member_key next_hop_member;
    struct wvm_endpoint next_hop_endpoint;
};

/*
 * The storage is intentionally opaque. Callers initialize it once, then use
 * prepare/activate/retire from the control path and lookup from data workers.
 */
struct wvm_route_runtime {
    pthread_rwlock_t lock;
    void *scopes;
    size_t scope_count;
    size_t scope_capacity;
};

void wvm_route_runtime_init(struct wvm_route_runtime *runtime);
void wvm_route_runtime_destroy(struct wvm_route_runtime *runtime);

/*
 * Prepare a complete canonical snapshot. A caller cannot inject a route rule
 * separately from its admitted snapshot key/digest.
 */
int wvm_route_runtime_prepare(
    struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len);

int wvm_route_runtime_activate(struct wvm_route_runtime *runtime,
                               const struct wvm_route_snapshot_key *key,
                               char *error, size_t error_len);

/* Remove only an exact prepared snapshot. Active routing is never aborted. */
int wvm_route_runtime_abort_prepared(
    struct wvm_route_runtime *runtime, const struct wvm_route_snapshot_key *key,
    char *error, size_t error_len);

/* True only while KEY names the exact pending successor in its route scope. */
int wvm_route_runtime_has_prepared_snapshot(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key);

/*
 * Retire one exact active or retained predecessor. A successor activation
 * retains one predecessor so control/query work can drain without exposing a
 * partially replaced table to data traffic.
 */
int wvm_route_runtime_retire(struct wvm_route_runtime *runtime,
                             const struct wvm_route_snapshot_key *key,
                             char *error, size_t error_len);

/*
 * A05: real in-flight operation refs for ROUTE_RETIRE proof. Pin while a
 * semantic operation uses the scope; put when it completes. Retire fails
 * closed while refs != 0. Query feeds owner ACK fields (no constant 0/1).
 */
int wvm_route_runtime_operation_ref_get(
    struct wvm_route_runtime *runtime, const struct wvm_vm_route_scope_key *scope,
    char *error, size_t error_len);
int wvm_route_runtime_operation_ref_put(
    struct wvm_route_runtime *runtime, const struct wvm_vm_route_scope_key *scope,
    char *error, size_t error_len);
int wvm_route_runtime_query_retire_proof(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key, uint64_t *active_operation_refs,
    int *retention_horizon_complete, char *error, size_t error_len);

/*
 * Look up one prevalidated V1 routed frame. The envelope's complete snapshot
 * key must equal the active key for its VM route scope. A predecessor is never
 * selected for new data traffic; callers receive a route-stale failure instead.
 */
int wvm_route_runtime_lookup(
    const struct wvm_route_runtime *runtime,
    const struct wvm_envelope *envelope,
    struct wvm_route_runtime_next_hop *next_hop_out, char *error,
    size_t error_len);

/*
 * Resolve one complete V1 leaf destination against an exact active immutable
 * snapshot. This is the outbound counterpart to envelope lookup: node
 * runtimes use it to derive a fresh route prefix without manufacturing a
 * temporary legacy target ID.
 */
int wvm_route_runtime_lookup_destination(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key, uint16_t destination_kind,
    uint64_t destination_scope, uint32_t destination_vnode_or_endpoint,
    struct wvm_route_runtime_next_hop *next_hop_out, char *error,
    size_t error_len);

int wvm_route_runtime_current_key(
    const struct wvm_route_runtime *runtime,
    const struct wvm_vm_route_scope_key *scope_key,
    struct wvm_route_snapshot_key *key_out);

int wvm_route_runtime_predecessor_key(
    const struct wvm_route_runtime *runtime,
    const struct wvm_vm_route_scope_key *scope_key,
    struct wvm_route_snapshot_key *key_out);

int wvm_route_runtime_has_snapshot(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key);

#endif /* WAVEVM_ROUTE_RUNTIME_H */

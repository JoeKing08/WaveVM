#ifndef WAVEVM_CONTROL_PLANE_H
#define WAVEVM_CONTROL_PLANE_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_control.h"
#include "wavevm_coordinator.h"
#include "wavevm_lifecycle.h"
#include "wavevm_membership_control.h"

struct wvm_admission_authority;

#define WVM_CONTROL_PLANE_MAX_RECORD_BYTES (1024U * 1024U)
#define WVM_CONTROL_PLANE_PATH_MAX 4096U

enum wvm_control_plane_submit_result {
    WVM_CONTROL_PLANE_SUBMIT_NEW = 1,
    WVM_CONTROL_PLANE_SUBMIT_REPLAY = 2,
};

enum wvm_control_plane_request_disposition {
    WVM_CONTROL_PLANE_REQUEST_ABSENT = 1,
    WVM_CONTROL_PLANE_REQUEST_REPLAY = 2,
    WVM_CONTROL_PLANE_REQUEST_CONFLICT = 3,
};

struct wvm_control_plane_entry {
    struct wvm_admission_transaction_record transaction;
};

/*
 * The control plane owns both canonical records after accepting a route
 * operation.  A transaction state is not sufficient to recover routing: the
 * immutable snapshot body is retained with the operation that published it.
 * The caller supplies the entry table so capacity remains an explicit
 * deployment limit rather than a hidden process-global cache.
 */
struct wvm_control_plane_route_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint16_t state;
    uint8_t *record_bytes;
    size_t record_byte_count;
    uint8_t *snapshot_bytes;
    size_t snapshot_byte_count;
};

/*
 * Retained per-node projections are keyed by the immutable candidate digest,
 * physical node identity, and reservation ID.  The caller supplies this table
 * so the control plane does not hide a process-global delivery cache.
 */
struct wvm_control_plane_runtime_manifest_entry {
    uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t physical_node_id;
    uint64_t expected_node_instance_id;
    uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t *record_bytes;
    size_t record_byte_count;
};

/*
 * Probe a runtime projection that is hosted on another physical node.  The
 * callback must use an authenticated control path and return zero only after
 * the remote participant has confirmed the exact manifest identity and ready
 * state.  It is deliberately separate from the local ready-file probe.
 */
typedef int (*wvm_control_plane_runtime_health_probe_fn)(
    void *context, const struct wvm_admission_transaction_record *transaction,
    const struct wvm_control_plane_runtime_manifest_entry *runtime_entry,
    char *error, size_t error_len);

/*
 * F08: after durable RUNNING→DEGRADED or DEGRADED→FAILED from required-member /
 * required-runtime health reconcile, invoke this hook so the real execution
 * gate is fail-closed. LIST_VM/journal FAILED alone must not be treated as the
 * execution boundary. Hook should quiesce/deny authorize for this exact
 * vm_id/incarnation only (do not touch sibling VMs). Return 0 on success;
 * non-zero is logged by reconcile but does not roll back the durable state.
 */
typedef int (*wvm_control_plane_execution_fail_closed_fn)(
    void *context, const struct wvm_admission_transaction_record *transaction,
    enum wvm_lifecycle_state new_state, char *error, size_t error_len);

/*
 * Membership is configured as a component of the one control-plane owner.
 * The caller supplies bounded tables and the transport-owned result sink;
 * neither the controller nor the receiver creates a process-global registry.
 */
struct wvm_control_plane_membership_config {
    struct wvm_membership_controller_member_entry *members;
    size_t member_capacity;
    struct wvm_membership_controller_route_entry *routes;
    size_t route_capacity;
    struct wvm_membership_dependency *dependencies;
    size_t dependency_capacity;
    struct wvm_membership_control_operation *operations;
    size_t operation_capacity;
    const char *membership_journal_path;
    const char *control_journal_path;
    wvm_membership_controller_authorize_fn authorize;
    void *authorize_context;
    wvm_membership_control_authorize_management_fn authorize_management;
    void *authorize_management_context;
    wvm_membership_control_authorize_membership_fn authorize_membership;
    void *authorize_membership_context;
    wvm_membership_control_result_sink_fn result_sink;
    void *result_sink_context;
};

/*
 * One local control-plane writer owns this durable journal. The caller owns
 * the entry storage so capacity is explicit and independent coordinators can
 * run without a hidden global registry.
 */
struct wvm_control_plane {
    int journal_fd;
    int journal_failed;
    uint64_t next_journal_sequence;
    struct wvm_control_plane_entry *entries;
    size_t entry_count;
    size_t entry_capacity;
    struct wvm_control_plane_route_entry *route_entries;
    size_t route_entry_count;
    size_t route_entry_capacity;
    struct wvm_control_plane_runtime_manifest_entry *runtime_manifest_entries;
    size_t runtime_manifest_entry_count;
    size_t runtime_manifest_entry_capacity;
    struct wvm_membership_controller membership_controller;
    struct wvm_membership_control membership_control;
    struct wvm_membership_control_dispatch_context membership_dispatch_context;
    char membership_journal_path[WVM_CONTROL_PLANE_PATH_MAX];
    char membership_control_journal_path[WVM_CONTROL_PLANE_PATH_MAX];
    int membership_configured;
    int membership_initialized;
    int membership_open;
    /* Local ready-owner probes are valid only for this physical host. */
    uint32_t local_physical_node_id;
    wvm_control_plane_runtime_health_probe_fn runtime_health_probe;
    void *runtime_health_probe_context;
    /* F08: optional per-VM execution fail-closed (quiesce/deny authorize). */
    wvm_control_plane_execution_fail_closed_fn execution_fail_closed;
    void *execution_fail_closed_context;
    const struct wvm_admission_authority *admission_authority;
};

void wvm_control_plane_init(struct wvm_control_plane *plane,
                            struct wvm_control_plane_entry *entries,
                            size_t entry_capacity);

/*
 * Configure bounded storage for persisted route transactions before opening
 * the journal. Existing route state is intentionally not replaced in place.
 */
void wvm_control_plane_set_route_transaction_entries(
    struct wvm_control_plane *plane,
    struct wvm_control_plane_route_entry *route_entries,
    size_t route_entry_capacity);

/*
 * Configure bounded storage for durable per-node runtime manifests before
 * opening the journal. Each candidate has at most one projection per
 * reservation-owning physical node.
 */
void wvm_control_plane_set_runtime_manifest_entries(
    struct wvm_control_plane *plane,
    struct wvm_control_plane_runtime_manifest_entry *runtime_manifest_entries,
    size_t runtime_manifest_entry_capacity);

/* Bind the host identity used by local ready-owner liveness checks. */
void wvm_control_plane_set_local_physical_node_id(
    struct wvm_control_plane *plane, uint32_t local_physical_node_id);

/* Install the authenticated remote participant health probe before serving. */
void wvm_control_plane_set_runtime_health_probe(
    struct wvm_control_plane *plane,
    wvm_control_plane_runtime_health_probe_fn probe, void *context);

/* Install F08 execution fail-closed hook (quiesce/deny) before serving. */
void wvm_control_plane_set_execution_fail_closed(
    struct wvm_control_plane *plane,
    wvm_control_plane_execution_fail_closed_fn fn, void *context);

/*
 * Bind the complete admission authority before the control service opens.
 * The plane retains the caller-owned binding for its lifetime; it never
 * manufactures evidence, route plans, listener leases, or participant ACKs.
 */
int wvm_control_plane_set_admission_authority(
    struct wvm_control_plane *plane,
    const struct wvm_admission_authority *authority, char *error,
    size_t error_len);

/* Configure and open the durable membership authority owned by this plane. */
int wvm_control_plane_configure_membership(
    struct wvm_control_plane *plane,
    const struct wvm_control_plane_membership_config *config,
    char *error, size_t error_len);
int wvm_control_plane_open_membership(struct wvm_control_plane *plane,
                                      char *error, size_t error_len);
void wvm_control_plane_close_membership(struct wvm_control_plane *plane);

/* Signature-compatible ingress adapter for the authoritative control plane. */
int wvm_control_plane_membership_dispatch(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len);

/* Per-connection typed-result adapter; does not use the shared result sink. */
int wvm_control_plane_membership_apply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len);

/*
 * Replays the journal, verifies every completed frame, and restores all
 * allocated namespaces into the supplied allocator. A trailing incomplete
 * frame is discarded because it was never fsync-complete; malformed completed
 * frames reject recovery rather than guessing a transaction result.
 */
int wvm_control_plane_open(
    struct wvm_control_plane *plane, const char *journal_path,
    struct wvm_vm_namespace_allocator *namespace_allocator, char *error,
    size_t error_len);

void wvm_control_plane_close(struct wvm_control_plane *plane);

const struct wvm_control_plane_entry *wvm_control_plane_find_request(
    const struct wvm_control_plane *plane,
    const uint8_t request_id[WVM_IDENTITY_ID_BYTES]);

/*
 * Classify one canonical request ID without allocating an identity.  Callers
 * use this before admission to reject semantic request-ID reuse distinctly
 * from a replay of the original durable operation.
 */
int wvm_control_plane_classify_request(
    const struct wvm_control_plane *plane, const struct wvm_vm_request *request,
    enum wvm_control_plane_request_disposition *disposition, char *error,
    size_t error_len);

const struct wvm_control_plane_route_entry *
wvm_control_plane_find_route_transaction(
    const struct wvm_control_plane *plane,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES]);

const struct wvm_control_plane_runtime_manifest_entry *
wvm_control_plane_find_runtime_manifest(
    const struct wvm_control_plane *plane,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    uint32_t physical_node_id);

/*
 * Persist one immutable route transaction state. The initial durable state
 * must be PREPARING. Replays are accepted only when the canonical transaction
 * core matches exactly; later records may only follow the route lifecycle.
 */
int wvm_control_plane_record_route_transaction(
    struct wvm_control_plane *plane,
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len);

/*
 * Bind and persist the complete immutable route snapshot for an existing
 * PREPARING route operation.  The operation, snapshot key, predecessor,
 * retention horizon, and required ACK participants must agree exactly.
 * Replaying identical canonical bytes is idempotent; a second body for the
 * same operation is rejected.
 */
int wvm_control_plane_record_route_snapshot(
    struct wvm_control_plane *plane,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len);

/*
 * Recover the exact snapshot body bound to one route operation.  No key-only
 * reconstruction is permitted after a restart.
 */
int wvm_control_plane_read_route_snapshot(
    const struct wvm_control_plane *plane,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

/*
 * Persist a new request/identity transaction or replay the original result
 * for an identical canonical request. A semantic change under a reused
 * request_id is rejected before a second namespace can be allocated.
 */
int wvm_control_plane_begin(
    struct wvm_control_plane *plane, const struct wvm_vm_request *request,
    struct wvm_vm_namespace_allocator *namespace_allocator,
    const struct wvm_coordinator_id_provider *id_provider,
    enum wvm_control_plane_submit_result *result,
    struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len);

/*
 * Persist the immutable candidate record and advance IDENTITY_ALLOCATED to
 * PLANNED. Further route/reservation/participant acknowledgements advance the
 * lifecycle through wvm_control_plane_transition().
 */
int wvm_control_plane_record_candidate(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_candidate_vm_manifest *candidate, char *error,
    size_t error_len);

int wvm_control_plane_transition(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    enum wvm_lifecycle_state expected, enum wvm_lifecycle_state next,
    char *error, size_t error_len);

/*
 * Recovery callers obtain the exact canonical records originally fsync'd by
 * the coordinator, then decode them into caller-owned list storage.
 */
int wvm_control_plane_read_candidate(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_control_plane_read_activation(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

/*
 * Persist exactly one activated per-node projection for each candidate
 * reservation. Duplicate delivery of identical canonical bytes is
 * idempotent; a conflicting projection for one physical node is rejected.
 */
int wvm_control_plane_record_runtime_manifest(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len);

/*
 * Return the activated canonical projection for one exact local node
 * identity. Recovery never substitutes another node's projection.
 */
int wvm_control_plane_read_runtime_manifest(
    const struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    uint32_t physical_node_id, uint64_t expected_node_instance_id,
    uint8_t *bytes, size_t capacity, size_t *encoded_bytes, char *error,
    size_t error_len);

/*
 * Capture metadata under the caller's single-writer lock immediately before
 * deciding. record_activation rejects a stale sequence; no intervening journal
 * write is allowed. The timestamp is wall-clock seconds, not a timeout clock.
 */
int wvm_control_plane_activation_options(
    const struct wvm_control_plane *plane, uint64_t coordinator_instance_id,
    struct wvm_coordinator_activation_options *options, char *error,
    size_t error_len);

/*
 * A single fsync'd activation frame moves the transaction index to
 * ACTIVATION_DECIDED or ABORTING, including on replay. Callers may issue remote
 * commit or abort RPCs only after success. A write error fences further writes
 * until close/open successfully replays and syncs the journal and its directory.
 */
int wvm_control_plane_record_activation(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len);

/*
 * Advance a committed VM only after every durable local runtime projection
 * presents identity-bound readiness evidence. Missing evidence returns
 * -EAGAIN and leaves the durable lifecycle state unchanged.
 */
typedef int (*wvm_control_plane_readiness_observer_fn)(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len);

int wvm_control_plane_start_if_ready(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_node_runtime_manifest *runtime_manifests,
    size_t runtime_manifest_count, char *error, size_t error_len);

/* Production path: every participant observes its own identity-bound readiness. */
int wvm_control_plane_start_if_participants_ready(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifests,
    size_t runtime_manifest_count,
    wvm_control_plane_readiness_observer_fn observe_ready,
    void *observer_context, char *error, size_t error_len);

/*
 * goal §1 continuous production loop: scan durable RUNNING|DEGRADED VMs and
 * fail-closed when required members are unhealthy OR required runtime/executor
 * ready-owners are dead (A12 child-death → no false RUNNING).
 *   RUNNING + unhealthy -> DEGRADED
 *   DEGRADED + still unhealthy -> FAILED
 * Does not invent RECOVERY_REBIND. ctl serve must call periodically.
 */
int wvm_control_plane_reconcile_required_member_health(
    struct wvm_control_plane *plane,
    struct wvm_membership_controller *membership_controller,
    size_t *transitioned_out, char *error, size_t error_len);

#endif /* WAVEVM_CONTROL_PLANE_H */

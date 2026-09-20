#ifndef WAVEVM_MEMBERSHIP_CONTROLLER_H
#define WAVEVM_MEMBERSHIP_CONTROLLER_H

/*
 * Durable controller-side membership authority.  This is deliberately
 * separate from gateway route caches and member health transport: callers
 * authenticate a peer before invoking registration, while the controller
 * owns the resulting desired-state, health, and route-transaction decisions.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "wavevm_cluster.h"
#include "wavevm_control.h"
#include "wavevm_membership.h"

#define WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES (1024U * 1024U)

enum wvm_membership_controller_authorization_action {
    WVM_MEMBERSHIP_CONTROLLER_AUTHORIZE_REGISTER_NODE = 1,
    WVM_MEMBERSHIP_CONTROLLER_AUTHORIZE_REGISTER_GATEWAY = 2,
    WVM_MEMBERSHIP_CONTROLLER_AUTHORIZE_REPORT_SELF_HEALTH = 3,
};

struct wvm_membership_controller_member_entry {
    enum wvm_membership_member_kind kind;
    struct wvm_member_key member_key;
    struct wvm_node_record node;
    struct wvm_gateway_record gateway;
    uint64_t active_dependency_count;
    int has_activation_route_operation_id;
    uint8_t activation_route_operation_id[WVM_IDENTITY_ID_BYTES];
};

/* A lock-safe, pointer-free view of one registered member. */
struct wvm_membership_controller_member_status {
    enum wvm_membership_member_kind kind;
    struct wvm_member_key member_key;
    struct wvm_endpoint endpoint;
    struct wvm_capability_ref capability;
    uint64_t inventory_revision;
    enum wvm_manifest_member_state desired_membership_state;
    enum wvm_membership_health_state observed_health_state;
    uint64_t active_dependency_count;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t admission_eligibility_revision;
};

struct wvm_membership_controller_route_ack_state {
    struct wvm_member_key member_key;
    int prepared;
    int activated;
};

struct wvm_membership_controller_route_entry {
    struct wvm_route_transaction_record transaction;
    struct wvm_required_ack_entry *required_ack_entries;
    struct wvm_required_ack_entry *optional_departure_entries;
    struct wvm_membership_controller_route_ack_state *required_ack_states;
    uint64_t prepared_membership_revision;
    uint64_t prepared_admission_eligibility_revision;
};

struct wvm_membership_controller_gateway_drain {
    int active;
    struct wvm_member_key gateway_member_key;
    uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES];
    uint64_t prepared_membership_revision;
    uint64_t prepared_admission_eligibility_revision;
    uint64_t reserved_topology_revision;
};

/*
 * Caller-owned immutable capture storage for admission and route compilation.
 * Nested NodeRecord/GatewayRecord lists are deep-copied into the three flat
 * arrays below, so no captured pointer aliases mutable controller state.
 */
struct wvm_membership_controller_capture {
    struct wvm_node_record *nodes;
    size_t node_capacity;
    size_t node_count;
    struct wvm_gateway_record *gateways;
    size_t gateway_capacity;
    size_t gateway_count;
    uint32_t *hosted_gateway_role_ids;
    size_t hosted_gateway_role_id_capacity;
    size_t hosted_gateway_role_id_count;
    uint32_t *gateway_parent_ids;
    size_t gateway_parent_id_capacity;
    size_t gateway_parent_id_count;
    uint32_t *gateway_child_ids;
    size_t gateway_child_id_capacity;
    size_t gateway_child_id_count;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t admission_eligibility_revision;
};

/*
 * The transport adapter calls this only after it has authenticated the peer.
 * The controller still checks that a self-registration or self-health actor
 * exactly matches the claimed member identity before calling this hook.
 */
typedef int (*wvm_membership_controller_authorize_fn)(
    void *context, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor,
    const struct wvm_member_key *subject, char *error, size_t error_len);

struct wvm_membership_controller {
    pthread_mutex_t lock;
    int journal_fd;
    uint64_t next_journal_sequence;
    struct wvm_membership_controller_member_entry *members;
    size_t member_count;
    size_t member_capacity;
    struct wvm_membership_controller_route_entry *routes;
    size_t route_count;
    size_t route_capacity;
    struct wvm_membership_dependency *dependencies;
    size_t dependency_count;
    size_t dependency_capacity;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t admission_eligibility_revision;
    struct wvm_membership_controller_gateway_drain gateway_drain;
    wvm_membership_controller_authorize_fn authorize;
    void *authorize_context;
};

/*
 * All tables are caller-owned bounded storage.  Per-record endpoint and graph
 * lists are copied by the controller and released by close().
 */
void wvm_membership_controller_init(
    struct wvm_membership_controller *controller,
    struct wvm_membership_controller_member_entry *members,
    size_t member_capacity,
    struct wvm_membership_controller_route_entry *routes,
    size_t route_capacity, struct wvm_membership_dependency *dependencies,
    size_t dependency_capacity,
    wvm_membership_controller_authorize_fn authorize, void *authorize_context);

int wvm_membership_controller_open(
    struct wvm_membership_controller *controller, const char *journal_path,
    char *error, size_t error_len);

void wvm_membership_controller_close(
    struct wvm_membership_controller *controller);

/*
 * Registration always records PENDING/RECOVERING state.  Registration is
 * idempotent only when it replays the same currently registered instance.
 */
int wvm_membership_controller_register_node(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_node_record *node, char *error, size_t error_len);

int wvm_membership_controller_register_gateway(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_gateway_record *gateway, char *error, size_t error_len);

int wvm_membership_controller_begin_validation(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len);
int wvm_membership_controller_prepare_member(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len);

/*
 * Advance a newly registered member through validation and preparation as one
 * idempotent controller operation. ACTIVE is accepted only when the same
 * committed route operation already authorized that member.
 */
int wvm_membership_controller_prepare_member_for_route(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);

/* Return the durable state of one route operation for replay decisions. */
int wvm_membership_controller_route_state(
    const struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint16_t *state_out,
    char *error, size_t error_len);

/*
 * A member can acknowledge only a PREPARING route transaction.  Commit is
 * rejected until every persisted required-ACK member has acknowledged.
 */
int wvm_membership_controller_route_begin(
    struct wvm_membership_controller *controller,
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len);
int wvm_membership_controller_route_ack_prepare(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const struct wvm_member_key *member_key, char *error, size_t error_len);
int wvm_membership_controller_route_commit(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);
int wvm_membership_controller_route_begin_retire(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t active_operation_refs, int retention_horizon_complete, char *error,
    size_t error_len);
int wvm_membership_controller_route_retire(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);
int wvm_membership_controller_route_abort(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);

int wvm_membership_controller_activate_member(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);
int wvm_membership_controller_cordon(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len);
int wvm_membership_controller_cordon_apply(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    uint64_t expected_membership_revision,
    uint64_t expected_topology_revision,
    uint64_t expected_admission_eligibility_revision, char *error,
    size_t error_len);
int wvm_membership_controller_begin_drain(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len);

/*
 * Gateway drain has a stricter publication rule than compute drain. The
 * caller supplies the complete immutable successor snapshot for one affected
 * scope; it must exclude the departing gateway and carry topology revision
 * current+1. Begin reserves that revision and invalidates unfinished
 * admissions. Commit atomically activates the prepared successor route and
 * changes the gateway membership state to DRAINING.
 *
 * V1 deliberately accepts one affected route scope per drain transaction.
 * A gateway with more than one registered dependency is rejected rather than
 * publishing only a partial replacement path.
 */
int wvm_membership_controller_gateway_drain_begin(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *gateway_member_key,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot, char *error,
    size_t error_len);
int wvm_membership_controller_gateway_drain_commit(
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);
int wvm_membership_controller_gateway_drain_abort(
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);

/*
 * Apply one canonical gateway-drain action under the controller lock. The
 * expected revisions name the state observed before PREPARE. COMMIT and
 * ABORT validate the durable intermediate eligibility revision created by
 * PREPARE; retries are accepted only when the exact target, route operation,
 * and resulting revisions match.
 */
int wvm_membership_controller_gateway_drain_apply(
    struct wvm_membership_controller *controller,
    enum wvm_gateway_drain_action action,
    const struct wvm_member_key *gateway_member_key,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t expected_membership_revision,
    uint64_t expected_topology_revision,
    uint64_t expected_admission_eligibility_revision, char *error,
    size_t error_len);
int wvm_membership_controller_remove(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len);

/* Copy one member's state while holding the controller lock. */
int wvm_membership_controller_member_status(
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    struct wvm_membership_controller_member_status *status, char *error,
    size_t error_len);

/*
 * Members may report only their own HEALTHY/RECOVERING observations.  A local
 * control-plane monitor records SUSPECT/UNREACHABLE evidence separately.
 */
int wvm_membership_controller_report_self_health(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *authenticated_actor,
    enum wvm_membership_health_state health_state, char *error,
    size_t error_len);
int wvm_membership_controller_mark_monitor_health(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    enum wvm_membership_health_state health_state, char *error,
    size_t error_len);

int wvm_membership_controller_dependency_acquire(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_dependency *dependency, char *error,
    size_t error_len);
int wvm_membership_controller_dependency_release(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_dependency *dependency, char *error,
    size_t error_len);

const struct wvm_membership_controller_member_entry *
wvm_membership_controller_find(
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key);

/*
 * Compatibility inspection API. Nested list pointers remain controller-owned
 * and are valid only until the corresponding member is replaced or the
 * controller is closed. Admission and topology compilation must use capture()
 * instead.
 */
int wvm_membership_controller_snapshot(
    const struct wvm_membership_controller *controller,
    struct wvm_node_record *nodes, size_t node_capacity, size_t *node_count,
    struct wvm_gateway_record *gateways, size_t gateway_capacity,
    size_t *gateway_count, uint64_t *membership_revision,
    uint64_t *topology_revision, uint64_t *admission_eligibility_revision,
    char *error, size_t error_len);

/*
 * Capture a deep-copied immutable membership view. This is the hand-off
 * boundary for a coordinator, topology compiler, or admission attempt: later
 * controller mutations cannot alter nested lists in the captured records.
 */
int wvm_membership_controller_capture(
    const struct wvm_membership_controller *controller,
    struct wvm_membership_controller_capture *capture, char *error,
    size_t error_len);

/*
 * Bind a completed immutable membership capture to separately captured
 * capability and reservation evidence. The returned record set borrows only
 * caller-owned capture/evidence storage and is safe to retain through one
 * coordinator operation.
 */
int wvm_membership_controller_capture_cluster_records(
    const struct wvm_membership_controller_capture *capture,
    const struct wvm_capability_record *capability_records,
    size_t capability_record_count,
    const struct wvm_resource_reservation *resource_reservations,
    size_t resource_reservation_count, uint64_t inventory_revision,
    uint64_t capability_profile_generation,
    struct wvm_cluster_record_set *records_out, char *error, size_t error_len);

/*
 * Capture current controller membership and bind it to immutable external
 * evidence in one call. The caller supplies all capture storage.
 */
int wvm_membership_controller_capture_current_cluster_records(
    const struct wvm_membership_controller *controller,
    struct wvm_membership_controller_capture *capture,
    const struct wvm_capability_record *capability_records,
    size_t capability_record_count,
    const struct wvm_resource_reservation *resource_reservations,
    size_t resource_reservation_count, uint64_t inventory_revision,
    uint64_t capability_profile_generation,
    struct wvm_cluster_record_set *records_out, char *error, size_t error_len);

#endif /* WAVEVM_MEMBERSHIP_CONTROLLER_H */

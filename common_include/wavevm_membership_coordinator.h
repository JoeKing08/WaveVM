#ifndef WAVEVM_MEMBERSHIP_COORDINATOR_H
#define WAVEVM_MEMBERSHIP_COORDINATOR_H

/*
 * Control-plane join orchestration. The durable membership controller remains
 * the authority; this layer only composes its idempotent operations and hands
 * real route-prepare transport to the caller.
 */

#include <stddef.h>

#include "wavevm_membership_controller.h"

typedef int (*wvm_membership_route_stage_fn)(
    void *context, const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_required_ack_entry *ack_entry, char *error,
    size_t error_len);

typedef int (*wvm_membership_cluster_enrollment_prepare_fn)(
    void *context, const struct wvm_cluster_admission_proof *proof,
    const struct wvm_cluster_admission_ack_entry *ack_entry, char *error,
    size_t error_len);

struct wvm_membership_cluster_enrollment_request {
    enum wvm_membership_member_kind member_kind;
    const struct wvm_member_key *authenticated_actor;
    const struct wvm_node_record *node;
    const struct wvm_gateway_record *gateway;
    const struct wvm_cluster_admission_proof *proof;
    wvm_membership_cluster_enrollment_prepare_fn prepare;
    void *prepare_context;
};

struct wvm_membership_join_request {
    enum wvm_membership_member_kind member_kind;
    const struct wvm_member_key *authenticated_actor;
    const struct wvm_node_record *node;
    const struct wvm_gateway_record *gateway;
    const struct wvm_route_transaction_record *route_transaction;
    const struct wvm_route_snapshot_record *route_snapshot;
    wvm_membership_route_stage_fn route_prepare;
    wvm_membership_route_stage_fn route_commit;
    void *route_prepare_context;
};

struct wvm_membership_compute_drain_request {
    struct wvm_member_key member_key;
};

struct wvm_membership_gateway_drain_request {
    const struct wvm_member_key *gateway_member_key;
    const struct wvm_route_transaction_record *successor_transaction;
    const struct wvm_route_snapshot_record *successor_snapshot;
    uint64_t expected_membership_revision;
    uint64_t expected_topology_revision;
    uint64_t expected_admission_eligibility_revision;
    wvm_membership_route_stage_fn route_prepare;
    void *route_prepare_context;
};

/*
 * Register/validate/prepare one member, publish one complete route snapshot,
 * collect remote prepare ACKs, commit the controller route, then collect
 * consumer commit ACKs before activating the joining member. A failure before
 * controller commit aborts the route; a consumer commit failure leaves the
 * member non-active and must be retried with the same transaction. Stage
 * callbacks must be idempotent for the supplied operation ID.
 */
int wvm_membership_coordinator_join(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_join_request *request, char *error,
    size_t error_len);

/*
 * Cluster-scope admission for members before VM route scopes exist. The
 * callback must perform the authenticated peer prepare/ACK exchange and bind
 * the responding identity to ack_entry. This library does not provide a
 * transport or validate capability/topology evidence. It never creates a VM
 * route record; a controller-owned proof builder and production transport are
 * required before this can be used as the live join path.
 */
int wvm_membership_coordinator_enroll_cluster_member(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_cluster_enrollment_request *request,
    char *error, size_t error_len);

/*
 * Compute members have no route replacement phase: cordon first, then drain
 * only after all recorded VM dependencies are gone. Replaying either
 * operation after DRAINING or REMOVED is successful.
 */
int wvm_membership_coordinator_drain_compute(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_compute_drain_request *request, char *error,
    size_t error_len);
int wvm_membership_coordinator_remove_compute(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_compute_drain_request *request, char *error,
    size_t error_len);

/*
 * Gateway removal is coupled to immutable successor publication. The route
 * callback prepares every required survivor; only then is the controller's
 * gateway-drain COMMIT allowed. A callback failure aborts only a PREPARING
 * transaction, never an already activated one.
 */
int wvm_membership_coordinator_drain_gateway(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_gateway_drain_request *request, char *error,
    size_t error_len);
int wvm_membership_coordinator_remove_gateway(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *gateway_member_key, char *error,
    size_t error_len);

#endif /* WAVEVM_MEMBERSHIP_COORDINATOR_H */

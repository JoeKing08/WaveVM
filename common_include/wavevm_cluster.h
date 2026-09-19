#ifndef WAVEVM_CLUSTER_H
#define WAVEVM_CLUSTER_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission.h"
#include "wavevm_capability.h"
#include "wavevm_control.h"
#include "wavevm_lifecycle.h"

/*
 * The source is the decoded, durable control-plane record set captured for
 * one proposal. Legacy topology files and launcher configuration are
 * intentionally absent from this API.
 */
struct wvm_cluster_record_set {
    const struct wvm_node_record *nodes;
    size_t node_count;
    const struct wvm_gateway_record *gateways;
    size_t gateway_count;
    const struct wvm_capability_record *capability_records;
    size_t capability_record_count;
    const struct wvm_resource_reservation *resource_reservations;
    size_t resource_reservation_count;
    uint64_t inventory_revision;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t admission_eligibility_revision;
    uint64_t capability_profile_generation;
};

struct wvm_cluster_snapshot {
    struct wvm_admission_snapshot admission;
    uint32_t active_gateway_count;
};

/*
 * On success, transfers an allocated nodes array to SNAPSHOT. The caller
 * releases it before reusing a successful output. Failure leaves SNAPSHOT intact.
 */
int wvm_cluster_snapshot_build(
    const struct wvm_cluster_record_set *records,
    struct wvm_cluster_snapshot *snapshot, char *error, size_t error_len);

/*
 * Apply the canonical VmRequest host constraints to all new resource
 * participants. Nodes that do not satisfy every constraint become
 * non-schedulable in the returned immutable snapshot; source records remain
 * unchanged. LABEL constraints reject until a canonical NodeMetadata record
 * exists, rather than consulting a launcher or host environment.
 * Source and destination must be distinct. On success the caller owns the
 * returned nodes; release an old output before replacement. Failure leaves
 * the destination unchanged.
 */
int wvm_cluster_snapshot_apply_host_constraints(
    const struct wvm_cluster_record_set *records,
    const struct wvm_cluster_snapshot *snapshot,
    const struct wvm_host_constraint_list *constraints,
    struct wvm_cluster_snapshot *constrained_snapshot, char *error,
    size_t error_len);

/*
 * Resolve the exact control-plane members required by one accepted placement
 * and prepared route ACK set, then calculate the immutable eligibility fence.
 * The caller supplies selected_members storage through fence->selected_members.
 */
int wvm_cluster_admission_fence_build(
    const struct wvm_cluster_record_set *records,
    const struct wvm_cluster_snapshot *snapshot,
    const struct wvm_admission_request *request,
    const struct wvm_admission_plan *plan,
    const struct wvm_vm_route_scope_key *route_scope_key,
    const struct wvm_required_ack_set *required_ack_set,
    struct wvm_admission_eligibility_fence *fence, char *error,
    size_t error_len);

#endif /* WAVEVM_CLUSTER_H */

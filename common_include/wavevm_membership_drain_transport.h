#ifndef WAVEVM_MEMBERSHIP_DRAIN_TRANSPORT_H
#define WAVEVM_MEMBERSHIP_DRAIN_TRANSPORT_H

/*
 * Controller-owned transport for one-scope gateway-drain successor peer
 * ROUTE_PREPARE / ROUTE_COMMIT / ROUTE_ABORT (cluster-membership-topology-
 * lifecycle §5.4, wire-ipc-abi §4.2.2). Does not invent drain actions;
 * PREPARE/COMMIT/ABORT remain canonical GatewayDrainRequest on the membership
 * receiver. Peer route stages keep participant state consistent with the
 * controller's durable drain decision.
 */

#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission_transport.h"
#include "wavevm_membership_coordinator.h"

struct wvm_membership_drain_transport {
    uint32_t controller_physical_node_id;
    uint64_t controller_instance_id;
    /* Manifest generation carried on ROUTE_* envelopes; drain is not a VM
     * admission reservation, but peer admission/route receivers require a
     * nonzero generation matching the successor scope identity. */
    uint64_t route_manifest_generation;
    void *context;
    wvm_admission_transport_submit_fn submit;
};

int wvm_membership_drain_transport_init(
    struct wvm_membership_drain_transport *transport,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    uint64_t route_manifest_generation, void *context,
    wvm_admission_transport_submit_fn submit, char *error, size_t error_len);

/*
 * Bind coordinator drain route_prepare/commit/abort to authenticated peer
 * ROUTE_* stages. prepare_context is the transport itself.
 */
int wvm_membership_drain_transport_bind(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_gateway_drain_request *request, char *error,
    size_t error_len);

/*
 * After durable DRAIN PREPARE, submit ROUTE_PREPARE to each RequiredAckSet
 * peer and record controller route_ack_prepare. On peer failure, best-effort
 * ROUTE_ABORT to peers that prepared, then aborts the PREPARING drain
 * (eligibility invalidation retained).
 */
int wvm_membership_drain_transport_collect_prepare_acks(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const struct wvm_membership_gateway_drain_request *request, char *error,
    size_t error_len);

/*
 * After durable DRAIN COMMIT, submit ROUTE_COMMIT to each RequiredAckSet peer
 * of the activated successor route (looked up by operation_id). Idempotent
 * retries use the same operation identity.
 */
int wvm_membership_drain_transport_deliver_commits(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);

/*
 * After durable DRAIN ABORT (or prepare-path abort), submit ROUTE_ABORT to
 * each RequiredAckSet peer of the PREPARING/ABORTED successor route.
 */
int wvm_membership_drain_transport_deliver_aborts(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);

#endif /* WAVEVM_MEMBERSHIP_DRAIN_TRANSPORT_H */

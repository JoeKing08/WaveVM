#ifndef WAVEVM_MEMBERSHIP_DRAIN_TRANSPORT_H
#define WAVEVM_MEMBERSHIP_DRAIN_TRANSPORT_H

/*
 * Controller-owned transport for one-scope gateway-drain successor
 * ROUTE_PREPARE peer ACKs (cluster-membership-topology-lifecycle §5.4,
 * wire-ipc-abi §4.2.2). Does not invent drain actions; PREPARE/COMMIT/ABORT
 * remain canonical GatewayDrainRequest on the membership receiver.
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
 * Bind coordinator drain route_prepare to authenticated peer ROUTE_PREPARE.
 * prepare_context is the transport itself.
 */
int wvm_membership_drain_transport_bind(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_gateway_drain_request *request, char *error,
    size_t error_len);

/*
 * After durable DRAIN PREPARE, submit ROUTE_PREPARE to each RequiredAckSet
 * peer and record controller route_ack_prepare. On peer failure, aborts the
 * PREPARING drain (eligibility invalidation retained).
 */
int wvm_membership_drain_transport_collect_prepare_acks(
    struct wvm_membership_drain_transport *transport,
    struct wvm_membership_controller *controller,
    const struct wvm_membership_gateway_drain_request *request, char *error,
    size_t error_len);

#endif /* WAVEVM_MEMBERSHIP_DRAIN_TRANSPORT_H */

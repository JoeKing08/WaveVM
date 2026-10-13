#ifndef WVM_CTL_GATEWAY_DRAIN_H
#define WVM_CTL_GATEWAY_DRAIN_H

/*
 * Production post-PREPARE peer route ACK collection for gateway 换血.
 * Specs: cluster-membership-topology-lifecycle §5.4; wire-ipc-abi §4.2.2;
 * canonical GatewayDrainRequest PREPARE|COMMIT|ABORT only.
 */

#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_control_plane.h"
#include "../common_include/wavevm_membership_drain_transport.h"
#include "membership_enrollment.h"

struct wvm_ctl_gateway_drain {
    struct wvm_control_plane *plane;
    struct wvm_membership_drain_transport transport;
    struct wvm_ctl_membership_enrollment *enrollment;
    int initialized;
};

int wvm_ctl_gateway_drain_init(
    struct wvm_ctl_gateway_drain *drain, struct wvm_control_plane *plane,
    struct wvm_ctl_membership_enrollment *enrollment,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    void *submit_context, wvm_admission_transport_submit_fn submit, char *error,
    size_t error_len);

void wvm_ctl_gateway_drain_destroy(struct wvm_ctl_gateway_drain *drain);

/*
 * Durable membership apply only (via enrollment wrapper). Peer ROUTE_* and
 * cluster enrollment run from after_membership_reply once the CTRL result is
 * fully written — never nested inside the open REGISTER/DRAIN exchange.
 */
int wvm_ctl_gateway_drain_apply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len);

void wvm_ctl_gateway_drain_after_reply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_membership_control_result *result);

#endif /* WVM_CTL_GATEWAY_DRAIN_H */

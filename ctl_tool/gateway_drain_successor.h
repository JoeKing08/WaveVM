#ifndef WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_H
#define WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_H

/*
 * One-scope gateway 换血 successor builder for EXECUTOR PREPARE payloads.
 *
 * Specs: cluster-membership-topology-lifecycle §5.4; wire-ipc-abi §4.2.2 —
 * PREPARE must carry a complete successor RouteTransaction+RouteSnapshot.
 * The membership receiver never invents successor topology from an incomplete
 * request. This helper constructs that complete successor from authoritative
 * membership controller state when the EXECUTOR names departing + successor
 * gateways. It does not invent multi-scope aggregates or pick a successor
 * gateway on its own.
 */

#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_control.h"
#include "../common_include/wavevm_membership_controller.h"

#define WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_ACK_CAP 8U

struct wvm_ctl_gateway_drain_successor {
    struct wvm_route_transaction_record transaction;
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record rule;
    struct wvm_required_ack_entry snapshot_acks[WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_ACK_CAP];
    struct wvm_required_ack_entry transaction_acks[WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_ACK_CAP];
    struct wvm_required_ack_entry decoded_acks[WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_ACK_CAP];
    struct wvm_required_ack_set ack_set;
    struct wvm_required_ack_entry optional_departure[1];
};

/*
 * Build one-scope successor for PREPARE.
 * - Departing gateway must be ACTIVE/healthy with exactly one dependency.
 * - Successor gateway must be a different ACTIVE/healthy GATEWAY (caller-named).
 * - Predecessor ACTIVATED route for that VM scope must match current
 *   topology_revision; RequiredAckSet keeps surviving NODE_RUNTIME peers and
 *   the successor gateway (departing excluded); optional_departure names
 *   departing once; topology_revision = current + 1.
 * Fail-closed on sole-path / multi-scope / missing predecessor / bad members.
 */
int wvm_ctl_gateway_drain_successor_build(
    struct wvm_ctl_gateway_drain_successor *out,
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *departing_gateway,
    const struct wvm_member_key *successor_gateway, char *error,
    size_t error_len);

#endif /* WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_H */

#include "gateway_drain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common_include/wavevm_control.h"
#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_manifest.h"

/*
 * One-scope gateway drain decode bounds (cluster-membership §5.4):
 * RequiredAckSet <= 8, next-hop rules <= 4, optional departure <= 2.
 * Larger multi-scope drains must be an explicit aggregate transaction.
 */
#define WVM_CTL_DRAIN_ACK_CAP 8U
#define WVM_CTL_DRAIN_RULE_CAP 4U
#define WVM_CTL_DRAIN_DEPARTURE_CAP 2U

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

int wvm_ctl_gateway_drain_init(
    struct wvm_ctl_gateway_drain *drain, struct wvm_control_plane *plane,
    struct wvm_ctl_membership_enrollment *enrollment,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    void *submit_context, wvm_admission_transport_submit_fn submit, char *error,
    size_t error_len)
{
    if (!drain || !plane || !enrollment || controller_physical_node_id == 0 ||
        controller_instance_id == 0 || !submit) {
        set_error(error, error_len, "ctl gateway drain configuration is invalid");
        return -1;
    }
    memset(drain, 0, sizeof(*drain));
    /*
     * Peer ROUTE_* stamp manifest_generation from the successor VM's
     * membership dependency (CREATE_VM dependency_acquire). One-scope drain
     * remains one VM route scope; generation is not a transport constant.
     */
    if (wvm_membership_drain_transport_init(
            &drain->transport, controller_physical_node_id,
            controller_instance_id, &plane->membership_controller,
            submit_context, submit, error, error_len) != 0) {
        return -1;
    }
    drain->plane = plane;
    drain->enrollment = enrollment;
    drain->initialized = 1;
    return 0;
}

void wvm_ctl_gateway_drain_destroy(struct wvm_ctl_gateway_drain *drain)
{
    if (!drain) {
        return;
    }
    memset(drain, 0, sizeof(*drain));
}

static int decode_prepare_successor(
    const uint8_t *bytes, size_t byte_count,
    struct wvm_gateway_drain_request *request,
    struct wvm_required_ack_entry *tx_acks, size_t tx_cap,
    struct wvm_required_ack_entry *departure, size_t departure_cap,
    struct wvm_route_rule_record *rules, size_t rule_cap,
    struct wvm_required_ack_entry *snap_acks, size_t snap_cap, char *error,
    size_t error_len)
{
    memset(request, 0, sizeof(*request));
    request->successor_transaction.required_ack_set.entries.entries = tx_acks;
    request->successor_transaction.required_ack_set.entries.capacity = tx_cap;
    request->successor_transaction.optional_departure_drain_set.entries =
        departure;
    request->successor_transaction.optional_departure_drain_set.capacity =
        departure_cap;
    request->successor_snapshot.next_hop_rules.entries = rules;
    request->successor_snapshot.next_hop_rules.capacity = rule_cap;
    request->successor_snapshot.required_ack_set.entries.entries = snap_acks;
    request->successor_snapshot.required_ack_set.entries.capacity = snap_cap;
    if (wvm_gateway_drain_request_decode(bytes, byte_count, request, error,
                                         error_len) != 0) {
        return -1;
    }
    if (request->action != WVM_GATEWAY_DRAIN_ACTION_PREPARE) {
        set_error(error, error_len, "gateway drain action is not PREPARE");
        return -1;
    }
    return 0;
}

/*
 * Reject PREPARE payloads outside the supported one-scope decode/transport
 * bounds before peer ROUTE_PREPARE (controller PREPARE already durable).
 */
static int validate_supported_drain_scope(
    const struct wvm_gateway_drain_request *decoded, char *error,
    size_t error_len)
{
    if (!decoded) {
        set_error(error, error_len, "gateway drain scope probe is missing");
        return -1;
    }
    if (decoded->successor_transaction.required_ack_set.entries.count >
            WVM_CTL_DRAIN_ACK_CAP ||
        decoded->successor_snapshot.required_ack_set.entries.count >
            WVM_CTL_DRAIN_ACK_CAP ||
        decoded->successor_snapshot.next_hop_rules.count >
            WVM_CTL_DRAIN_RULE_CAP ||
        decoded->successor_transaction.optional_departure_drain_set.count >
            WVM_CTL_DRAIN_DEPARTURE_CAP) {
        set_error(error, error_len,
                  "gateway drain exceeds supported one-scope ACK/rule/"
                  "departure bounds (ack<=8 rules<=4 departure<=2)");
        return -1;
    }
    /*
     * One-scope drain: require a concrete VM route scope. Peer ROUTE_*
     * generation is resolved from membership dependencies for that scope.
     */
    if (decoded->successor_snapshot.route_snapshot_key.scope_key.vm_id == 0 ||
        decoded->successor_snapshot.route_snapshot_key.scope_key
                .vm_incarnation == 0) {
        set_error(error, error_len,
                  "gateway drain successor lacks supported VM route scope");
        return -1;
    }
    return 0;
}

static int collect_acks_after_prepare(
    struct wvm_ctl_gateway_drain *drain, const struct wvm_envelope *request,
    char *error, size_t error_len)
{
    struct wvm_gateway_drain_request decoded;
    struct wvm_required_ack_entry tx_acks[WVM_CTL_DRAIN_ACK_CAP];
    struct wvm_required_ack_entry departure[WVM_CTL_DRAIN_DEPARTURE_CAP];
    struct wvm_required_ack_entry snap_acks[WVM_CTL_DRAIN_ACK_CAP];
    struct wvm_route_rule_record rules[WVM_CTL_DRAIN_RULE_CAP];
    struct wvm_membership_gateway_drain_request drain_request;

    if (decode_prepare_successor(request->payload, request->payload_bytes,
                                 &decoded, tx_acks, WVM_CTL_DRAIN_ACK_CAP,
                                 departure, WVM_CTL_DRAIN_DEPARTURE_CAP, rules,
                                 WVM_CTL_DRAIN_RULE_CAP, snap_acks,
                                 WVM_CTL_DRAIN_ACK_CAP, error, error_len) != 0) {
        return -1;
    }
    if (validate_supported_drain_scope(&decoded, error, error_len) != 0) {
        return -1;
    }
    memset(&drain_request, 0, sizeof(drain_request));
    drain_request.gateway_member_key = &decoded.target_gateway_member_key;
    drain_request.successor_transaction = &decoded.successor_transaction;
    drain_request.successor_snapshot = &decoded.successor_snapshot;
    drain_request.expected_membership_revision =
        decoded.expected_membership_revision;
    drain_request.expected_topology_revision =
        decoded.expected_topology_revision;
    drain_request.expected_admission_eligibility_revision =
        decoded.expected_admission_eligibility_revision;
    return wvm_membership_drain_transport_collect_prepare_acks(
        &drain->transport, &drain->plane->membership_controller, &drain_request,
        error, error_len);
}

static int deliver_after_commit_or_abort(
    struct wvm_ctl_gateway_drain *drain, const struct wvm_envelope *request,
    enum wvm_gateway_drain_action action, char *error, size_t error_len)
{
    struct wvm_gateway_drain_request decoded;

    memset(&decoded, 0, sizeof(decoded));
    if (wvm_gateway_drain_request_decode(request->payload, request->payload_bytes,
                                         &decoded, error, error_len) != 0 ||
        decoded.action != action) {
        set_error(error, error_len, "gateway drain commit/abort decode failed");
        return -1;
    }
    if (action == WVM_GATEWAY_DRAIN_ACTION_COMMIT) {
        return wvm_membership_drain_transport_deliver_commits(
            &drain->transport, &drain->plane->membership_controller,
            decoded.route_operation_id, error, error_len);
    }
    return wvm_membership_drain_transport_deliver_aborts(
        &drain->transport, &drain->plane->membership_controller,
        decoded.route_operation_id, error, error_len);
}

int wvm_ctl_gateway_drain_apply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    struct wvm_ctl_gateway_drain *drain = opaque;

    if (!drain || !drain->initialized || !drain->enrollment) {
        set_error(error, error_len, "ctl gateway drain is not ready");
        return -1;
    }
    return wvm_ctl_membership_enrollment_apply(
        drain->enrollment, request, authenticated_actor, result, error,
        error_len);
}

void wvm_ctl_gateway_drain_after_reply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_membership_control_result *result)
{
    struct wvm_ctl_gateway_drain *drain = opaque;
    char peer_error[256];

    if (!drain || !drain->initialized || !drain->enrollment) {
        return;
    }

    /* Cluster enrollment only after REGISTER reply is on the wire. */
    wvm_ctl_membership_enrollment_after_reply(
        drain->enrollment, request, authenticated_actor, result);

    if (!request || !result ||
        result->status_code != WVM_MEMBERSHIP_CONTROL_SUCCESS ||
        request->message_type != WVM_ENVELOPE_MSG_DRAIN) {
        return;
    }

    {
        struct wvm_gateway_drain_request probe;
        struct wvm_required_ack_entry tx_acks[WVM_CTL_DRAIN_ACK_CAP];
        struct wvm_required_ack_entry departure[WVM_CTL_DRAIN_DEPARTURE_CAP];
        struct wvm_required_ack_entry snap_acks[WVM_CTL_DRAIN_ACK_CAP];
        struct wvm_route_rule_record rules[WVM_CTL_DRAIN_RULE_CAP];

        memset(&probe, 0, sizeof(probe));
        probe.successor_transaction.required_ack_set.entries.entries = tx_acks;
        probe.successor_transaction.required_ack_set.entries.capacity =
            WVM_CTL_DRAIN_ACK_CAP;
        probe.successor_transaction.optional_departure_drain_set.entries =
            departure;
        probe.successor_transaction.optional_departure_drain_set.capacity =
            WVM_CTL_DRAIN_DEPARTURE_CAP;
        probe.successor_snapshot.next_hop_rules.entries = rules;
        probe.successor_snapshot.next_hop_rules.capacity = WVM_CTL_DRAIN_RULE_CAP;
        probe.successor_snapshot.required_ack_set.entries.entries = snap_acks;
        probe.successor_snapshot.required_ack_set.entries.capacity =
            WVM_CTL_DRAIN_ACK_CAP;
        peer_error[0] = '\0';
        if (wvm_gateway_drain_request_decode(request->payload,
                                             request->payload_bytes, &probe,
                                             peer_error, sizeof(peer_error)) !=
            0) {
            return;
        }
        if (probe.action == WVM_GATEWAY_DRAIN_ACTION_PREPARE) {
            peer_error[0] = '\0';
            if (collect_acks_after_prepare(drain, request, peer_error,
                                           sizeof(peer_error)) != 0) {
                fprintf(stderr,
                        "wvm_ctl: gateway drain peer ROUTE_PREPARE ACK failed "
                        "(PREPARE durable; COMMIT will fail-closed until "
                        "retry/ABORT): %s\n",
                        peer_error[0] ? peer_error : "unknown error");
            }
            return;
        }
        if (probe.action == WVM_GATEWAY_DRAIN_ACTION_COMMIT ||
            probe.action == WVM_GATEWAY_DRAIN_ACTION_ABORT) {
            peer_error[0] = '\0';
            if (deliver_after_commit_or_abort(drain, request, probe.action,
                                              peer_error,
                                              sizeof(peer_error)) != 0) {
                fprintf(stderr,
                        "wvm_ctl: gateway drain peer ROUTE_%s delivery failed "
                        "(controller decision durable; retry same operation): "
                        "%s\n",
                        probe.action == WVM_GATEWAY_DRAIN_ACTION_COMMIT
                            ? "COMMIT"
                            : "ABORT",
                        peer_error[0] ? peer_error : "unknown error");
            }
        }
    }
}

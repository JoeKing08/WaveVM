#include "gateway_drain_successor.h"

#include <stdio.h>
#include <string.h>

#include "../common_include/wavevm_manifest.h"
#include "../common_include/wavevm_membership.h"
#include "../common_include/wavevm_sha256.h"

static void set_error(char *error, size_t error_len, const char *message)
{
    if (!error || error_len == 0) {
        return;
    }
    snprintf(error, error_len, "%s", message ? message : "gateway drain successor error");
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static const struct wvm_membership_controller_member_entry *find_member(
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *key)
{
    size_t i;

    if (!controller || !key) {
        return NULL;
    }
    for (i = 0; i < controller->member_count; i++) {
        const struct wvm_membership_controller_member_entry *entry =
            &controller->members[i];

        if (member_key_equal(&entry->member_key, key)) {
            return entry;
        }
    }
    return NULL;
}

static const struct wvm_endpoint *member_endpoint(
    const struct wvm_membership_controller_member_entry *entry)
{
    if (!entry) {
        return NULL;
    }
    if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
        return &entry->node.control_endpoint;
    }
    return &entry->gateway.endpoint;
}

static uint16_t member_desired_state(
    const struct wvm_membership_controller_member_entry *entry)
{
    if (!entry) {
        return 0;
    }
    if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
        return entry->node.desired_membership_state;
    }
    return entry->gateway.desired_membership_state;
}

static uint16_t member_health(
    const struct wvm_membership_controller_member_entry *entry)
{
    if (!entry) {
        return 0;
    }
    if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
        return entry->node.observed_health_state;
    }
    return entry->gateway.observed_health_state;
}

static int gateway_usable(
    const struct wvm_membership_controller_member_entry *entry)
{
    return entry && entry->kind == WVM_MEMBERSHIP_GATEWAY &&
           member_desired_state(entry) == WVM_MANIFEST_MEMBER_ACTIVE &&
           member_health(entry) == WVM_MEMBERSHIP_HEALTHY;
}

static int build_ack_set(struct wvm_required_ack_set *ack_set,
                         struct wvm_required_ack_entry *entries,
                         struct wvm_required_ack_entry *decoded,
                         size_t entry_count,
                         const struct wvm_route_snapshot_key *route_key,
                         char *error, size_t error_len)
{
    struct wvm_required_ack_set source;
    uint8_t bytes[8192];
    size_t encoded_bytes = 0;
    size_t i;

    for (i = 0; i < entry_count; i++) {
        entries[i].expected_snapshot_key = *route_key;
    }
    memset(&source, 0, sizeof(source));
    source.entries.entries = entries;
    source.entries.count = entry_count;
    source.entries.capacity = entry_count;
    if (wvm_required_ack_set_encode(&source, bytes, sizeof(bytes),
                                    &encoded_bytes, error, error_len) != 0) {
        return -1;
    }
    memset(ack_set, 0, sizeof(*ack_set));
    ack_set->entries.entries = decoded;
    ack_set->entries.capacity = entry_count;
    return wvm_required_ack_set_decode(bytes, encoded_bytes, ack_set, error,
                                       error_len);
}

int wvm_ctl_gateway_drain_successor_build(
    struct wvm_ctl_gateway_drain_successor *out,
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *departing_gateway,
    const struct wvm_member_key *successor_gateway, char *error,
    size_t error_len)
{
    const struct wvm_membership_controller_member_entry *departing;
    const struct wvm_membership_controller_member_entry *successor;
    const struct wvm_membership_dependency *dep = NULL;
    const struct wvm_membership_controller_route_entry *predecessor = NULL;
    const struct wvm_endpoint *departing_endpoint;
    const struct wvm_endpoint *successor_endpoint;
    size_t dep_matches = 0;
    size_t i;
    size_t ack_count = 0;
    uint8_t encoded[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes = 0;

    if (!out || !controller || !departing_gateway || !successor_gateway) {
        set_error(error, error_len, "gateway drain successor build input is invalid");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    if (member_key_equal(departing_gateway, successor_gateway)) {
        set_error(error, error_len,
                  "gateway drain successor must differ from departing gateway");
        return -1;
    }
    departing = find_member(controller, departing_gateway);
    successor = find_member(controller, successor_gateway);
    if (!gateway_usable(departing) || !gateway_usable(successor)) {
        set_error(error, error_len,
                  "gateway drain requires ACTIVE healthy departing and successor");
        return -1;
    }
    if (departing->active_dependency_count != 1) {
        set_error(error, error_len,
                  "one-scope gateway drain requires exactly one dependency");
        return -1;
    }
    for (i = 0; i < controller->dependency_count; i++) {
        if (!member_key_equal(&controller->dependencies[i].member_key,
                              departing_gateway)) {
            continue;
        }
        dep_matches++;
        dep = &controller->dependencies[i];
    }
    if (dep_matches != 1 || !dep || dep->vm_id == 0 ||
        dep->vm_incarnation == 0 || dep->manifest_generation == 0) {
        set_error(error, error_len,
                  "gateway drain dependency set is not one-scope safe");
        return -1;
    }

    for (i = 0; i < controller->route_count; i++) {
        const struct wvm_membership_controller_route_entry *route =
            &controller->routes[i];

        if (route->transaction.state != WVM_ROUTE_TRANSACTION_ACTIVATED) {
            continue;
        }
        if (route->transaction.route_snapshot_key.scope_key.vm_id != dep->vm_id ||
            route->transaction.route_snapshot_key.scope_key.vm_incarnation !=
                dep->vm_incarnation) {
            continue;
        }
        if (route->transaction.route_snapshot_key.topology_revision !=
            controller->topology_revision) {
            continue;
        }
        if (predecessor) {
            set_error(error, error_len,
                      "gateway drain found multiple activated predecessors");
            return -1;
        }
        predecessor = route;
    }
    if (!predecessor) {
        set_error(error, error_len,
                  "gateway drain lacks activated predecessor at current topology");
        return -1;
    }

    /* Surviving RequiredAckSet: predecessor NODE_RUNTIME peers + successor GW. */
    for (i = 0; i < predecessor->transaction.required_ack_set.entries.count;
         i++) {
        const struct wvm_required_ack_entry *ack =
            &predecessor->transaction.required_ack_set.entries.entries[i];

        if (ack->member_key.role_type != WVM_MANIFEST_ROLE_NODE_RUNTIME) {
            continue;
        }
        if (ack_count >= WVM_CTL_GATEWAY_DRAIN_SUCCESSOR_ACK_CAP - 1U) {
            set_error(error, error_len,
                      "gateway drain successor ACK set exceeds one-scope capacity");
            return -1;
        }
        out->snapshot_acks[ack_count].member_key = ack->member_key;
        out->snapshot_acks[ack_count].endpoint = ack->endpoint;
        out->snapshot_acks[ack_count].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        ack_count++;
    }
    if (ack_count == 0) {
        set_error(error, error_len,
                  "gateway drain predecessor has no NODE_RUNTIME ACK peers");
        return -1;
    }
    successor_endpoint = member_endpoint(successor);
    departing_endpoint = member_endpoint(departing);
    if (!successor_endpoint || !departing_endpoint) {
        set_error(error, error_len, "gateway drain member endpoint is missing");
        return -1;
    }
    out->snapshot_acks[ack_count].member_key = *successor_gateway;
    out->snapshot_acks[ack_count].endpoint = *successor_endpoint;
    out->snapshot_acks[ack_count].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    ack_count++;

    out->snapshot.route_snapshot_key =
        predecessor->transaction.route_snapshot_key;
    out->snapshot.route_snapshot_key.topology_revision =
        controller->topology_revision + 1U;
    out->snapshot.route_snapshot_key.route_generation =
        predecessor->transaction.route_snapshot_key.route_generation + 1U;
    memset(out->snapshot.route_snapshot_key.snapshot_digest, 0,
           sizeof(out->snapshot.route_snapshot_key.snapshot_digest));
    out->snapshot.membership_revision = controller->membership_revision;
    out->snapshot.topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    out->snapshot.has_predecessor_snapshot_key = 1;
    out->snapshot.predecessor_snapshot_key =
        predecessor->transaction.route_snapshot_key;
    out->snapshot.operation_retention_horizon_ms =
        predecessor->transaction.operation_retention_horizon_ms != 0
            ? predecessor->transaction.operation_retention_horizon_ms
            : 5000;
    out->snapshot.retirement_policy = 1;

    memset(&out->rule, 0, sizeof(out->rule));
    out->rule.destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    out->rule.next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    out->rule.next_hop_member = *successor_gateway;
    out->rule.next_hop_endpoint = *successor_endpoint;
    out->rule.hop_limit = 4;
    out->snapshot.next_hop_rules.entries = &out->rule;
    out->snapshot.next_hop_rules.count = 1;
    out->snapshot.next_hop_rules.capacity = 1;

    for (i = 0; i < ack_count; i++) {
        out->snapshot_acks[i].expected_snapshot_key =
            out->snapshot.route_snapshot_key;
    }
    out->snapshot.required_ack_set.entries.entries = out->snapshot_acks;
    out->snapshot.required_ack_set.entries.count = ack_count;
    out->snapshot.required_ack_set.entries.capacity = ack_count;

    if (wvm_route_snapshot_record_encode(&out->snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(out->snapshot.route_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    for (i = 0; i < ack_count; i++) {
        memcpy(out->snapshot_acks[i].expected_snapshot_key.snapshot_digest,
               digest, sizeof(digest));
        out->transaction_acks[i] = out->snapshot_acks[i];
    }
    if (wvm_route_snapshot_record_validate(&out->snapshot, error, error_len) !=
            0 ||
        build_ack_set(&out->ack_set, out->transaction_acks, out->decoded_acks,
                      ack_count, &out->snapshot.route_snapshot_key, error,
                      error_len) != 0) {
        return -1;
    }

    memset(&out->transaction, 0, sizeof(out->transaction));
    /* Deterministic operation id from scope + reserved topology (not random). */
    out->transaction.operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x45;
    out->transaction.operation_id[WVM_IDENTITY_ID_BYTES - 2] =
        (uint8_t)(dep->vm_id & 0xffU);
    out->transaction.operation_id[WVM_IDENTITY_ID_BYTES - 3] =
        (uint8_t)((controller->topology_revision + 1U) & 0xffU);
    out->transaction.route_snapshot_key = out->snapshot.route_snapshot_key;
    out->transaction.has_predecessor_snapshot_key = 1;
    out->transaction.predecessor_snapshot_key =
        predecessor->transaction.route_snapshot_key;
    out->transaction.required_ack_set = out->ack_set;
    memset(out->optional_departure, 0, sizeof(out->optional_departure));
    out->optional_departure[0].member_key = *departing_gateway;
    out->optional_departure[0].endpoint = *departing_endpoint;
    out->optional_departure[0].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    out->optional_departure[0].expected_snapshot_key =
        predecessor->transaction.route_snapshot_key;
    out->transaction.optional_departure_drain_set.entries =
        out->optional_departure;
    out->transaction.optional_departure_drain_set.count = 1;
    out->transaction.optional_departure_drain_set.capacity = 1;
    out->transaction.operation_retention_horizon_ms =
        out->snapshot.operation_retention_horizon_ms;
    out->transaction.state = WVM_ROUTE_TRANSACTION_PREPARING;
    return wvm_route_transaction_record_validate(&out->transaction, error,
                                                   error_len);
}

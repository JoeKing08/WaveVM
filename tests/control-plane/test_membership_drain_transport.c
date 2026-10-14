#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <string.h>

#include "wavevm_envelope.h"
#include "wavevm_membership_drain_transport.h"

/*
 * Drain peer ROUTE_* must stamp manifest_generation from the successor VM's
 * membership dependency (CREATE_VM acquire), not a transport-wide constant.
 * One-scope first generation may still be 1 semantically when the dependency
 * says so; the dishonest case is ignoring the dependency entirely.
 */

#define CAPTURE_MAX 4

struct submit_capture {
    unsigned int calls;
    uint64_t generations[CAPTURE_MAX];
    uint16_t message_types[CAPTURE_MAX];
    uint32_t vm_ids[CAPTURE_MAX];
    int fail_next;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "membership-drain-transport test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static int capture_submit(void *context,
                          const struct wvm_admission_transport_target *target,
                          const struct wvm_envelope *envelope, char *error,
                          size_t error_len)
{
    struct submit_capture *capture = context;

    (void)target;
    if (!capture || !envelope) {
        if (error && error_len) {
            snprintf(error, error_len, "capture submit input is invalid");
        }
        return -1;
    }
    if (capture->fail_next) {
        capture->fail_next = 0;
        if (error && error_len) {
            snprintf(error, error_len, "forced submit failure");
        }
        return -1;
    }
    if (capture->calls >= CAPTURE_MAX) {
        if (error && error_len) {
            snprintf(error, error_len, "capture submit overflow");
        }
        return -1;
    }
    capture->generations[capture->calls] = envelope->manifest_generation;
    capture->message_types[capture->calls] = envelope->message_type;
    capture->vm_ids[capture->calls] = envelope->vm_id;
    capture->calls++;
    return 0;
}

static int build_bound_pair(
    struct wvm_route_transaction_record *transaction,
    struct wvm_route_snapshot_record *snapshot,
    struct wvm_route_rule_record *rule,
    struct wvm_required_ack_entry snapshot_acks[1],
    struct wvm_required_ack_entry tx_acks[1],
    struct wvm_required_ack_entry decoded_acks[1],
    struct wvm_required_ack_set *ack_set,
    const struct wvm_member_key *peer_member,
    const struct wvm_endpoint *peer_endpoint, uint32_t vm_id,
    uint64_t vm_incarnation, char *error, size_t error_len)
{
    uint8_t encoded[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    struct wvm_required_ack_set source;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = vm_id;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = vm_incarnation;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 1;
    snapshot->route_snapshot_key.topology_revision = 3;
    snapshot->route_snapshot_key.route_generation = 2;
    snapshot->membership_revision = 5;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    rule->next_hop_member = *peer_member;
    rule->next_hop_endpoint = *peer_endpoint;
    rule->hop_limit = 4;
    snapshot->next_hop_rules.entries = rule;
    snapshot->next_hop_rules.count = 1;
    snapshot->next_hop_rules.capacity = 1;

    memset(snapshot_acks, 0, sizeof(*snapshot_acks));
    snapshot_acks[0].member_key = *peer_member;
    snapshot_acks[0].endpoint = *peer_endpoint;
    snapshot_acks[0].role_type = peer_member->role_type;
    snapshot_acks[0].expected_snapshot_key = snapshot->route_snapshot_key;
    snapshot->required_ack_set.entries.entries = snapshot_acks;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;

    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    memcpy(snapshot_acks[0].expected_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    if (wvm_route_snapshot_record_validate(snapshot, error, error_len) != 0) {
        return -1;
    }

    memset(tx_acks, 0, sizeof(*tx_acks));
    tx_acks[0] = snapshot_acks[0];
    memset(&source, 0, sizeof(source));
    source.entries.entries = tx_acks;
    source.entries.count = 1;
    source.entries.capacity = 1;
    if (wvm_required_ack_set_encode(&source, encoded, sizeof(encoded),
                                    &encoded_bytes, error, error_len) != 0) {
        return -1;
    }
    memset(ack_set, 0, sizeof(*ack_set));
    ack_set->entries.entries = decoded_acks;
    ack_set->entries.capacity = 1;
    if (wvm_required_ack_set_decode(encoded, encoded_bytes, ack_set, error,
                                    error_len) != 0) {
        return -1;
    }

    memset(transaction, 0, sizeof(*transaction));
    transaction->operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x71;
    transaction->route_snapshot_key = snapshot->route_snapshot_key;
    transaction->required_ack_set = *ack_set;
    transaction->operation_retention_horizon_ms = 5000;
    transaction->state = WVM_ROUTE_TRANSACTION_PREPARING;
    return wvm_route_snapshot_record_binds_transaction(snapshot, transaction,
                                                       error, error_len);
}

int main(void)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_dependency dependencies[2];
    struct wvm_membership_drain_transport transport;
    struct submit_capture capture;
    struct wvm_membership_gateway_drain_request request;
    struct wvm_route_transaction_record transaction;
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record rule;
    struct wvm_required_ack_entry snapshot_acks[1];
    struct wvm_required_ack_entry tx_acks[1];
    struct wvm_required_ack_entry decoded_acks[1];
    struct wvm_required_ack_set ack_set;
    struct wvm_member_key peer;
    struct wvm_endpoint peer_endpoint;
    char error[256];
    const uint64_t expected_generation = 7;

    memset(&controller, 0, sizeof(controller));
    memset(dependencies, 0, sizeof(dependencies));
    memset(&peer, 0, sizeof(peer));
    peer.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    peer.role_id = 9;
    peer.instance_id = 3;
    fill_endpoint(&peer_endpoint, 9, 4000, 4001);

    dependencies[0].member_key = peer;
    dependencies[0].vm_id = 256;
    dependencies[0].vm_incarnation = 1;
    dependencies[0].manifest_generation = expected_generation;
    dependencies[0].dependency_kind = 2;
    controller.dependencies = dependencies;
    controller.dependency_count = 1;

    memset(&capture, 0, sizeof(capture));
    memset(error, 0, sizeof(error));
    if (expect(wvm_membership_drain_transport_init(
                   &transport, 1, 42, &controller, &capture, capture_submit,
                   error, sizeof(error)) == 0,
               "init drain transport with controller") != 0) {
        return 1;
    }
    if (expect(build_bound_pair(&transaction, &snapshot, &rule, snapshot_acks,
                                tx_acks, decoded_acks, &ack_set, &peer,
                                &peer_endpoint, 256, 1, error,
                                sizeof(error)) == 0,
               "build bound successor snapshot/transaction") != 0) {
        fprintf(stderr, "build error: %s\n", error);
        return 1;
    }

    memset(&request, 0, sizeof(request));
    request.successor_transaction = &transaction;
    request.successor_snapshot = &snapshot;
    if (expect(wvm_membership_drain_transport_bind(&transport, &request, error,
                                                   sizeof(error)) == 0,
               "bind drain transport callbacks") != 0 ||
        expect(request.route_prepare != NULL, "bind installs route_prepare") !=
            0) {
        return 1;
    }

    capture.calls = 0;
    if (expect(request.route_prepare(request.route_prepare_context,
                                     &transaction, &snapshot, &decoded_acks[0],
                                     error, sizeof(error)) == 0,
               "ROUTE_PREPARE submits with dependency-bound generation") != 0) {
        fprintf(stderr, "prepare error: %s\n", error);
        return 1;
    }
    if (expect(capture.calls == 1, "one peer ROUTE_PREPARE submitted") != 0 ||
        expect(capture.message_types[0] == WVM_ENVELOPE_MSG_ROUTE_PREPARE,
               "submitted message is ROUTE_PREPARE") != 0 ||
        expect(capture.vm_ids[0] == 256, "envelope vm_id matches scope") != 0 ||
        expect(capture.generations[0] == expected_generation,
               "envelope manifest_generation tracks dependency (not fixed 1)") !=
            0) {
        fprintf(stderr,
                "got generation=%llu message=0x%x vm=%u calls=%u\n",
                (unsigned long long)capture.generations[0],
                capture.message_types[0], capture.vm_ids[0], capture.calls);
        return 1;
    }

    /* Fail closed when the successor VM has no matching dependency. */
    controller.dependency_count = 0;
    capture.calls = 0;
    error[0] = '\0';
    if (expect(request.route_prepare(request.route_prepare_context,
                                     &transaction, &snapshot, &decoded_acks[0],
                                     error, sizeof(error)) != 0,
               "reject ROUTE_PREPARE without membership dependency") != 0 ||
        expect(capture.calls == 0,
               "missing dependency does not emit a peer envelope") != 0) {
        return 1;
    }

    /* Semantic generation=1 from the dependency is still honest. */
    dependencies[0].manifest_generation = 1;
    controller.dependency_count = 1;
    capture.calls = 0;
    if (expect(request.route_prepare(request.route_prepare_context,
                                     &transaction, &snapshot, &decoded_acks[0],
                                     error, sizeof(error)) == 0,
               "ROUTE_PREPARE accepts dependency generation 1") != 0 ||
        expect(capture.calls == 1 && capture.generations[0] == 1,
               "generation 1 is taken from the dependency") != 0) {
        return 1;
    }

    printf("membership-drain-transport test: ok\n");
    return 0;
}

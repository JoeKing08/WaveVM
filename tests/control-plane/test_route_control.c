#define _XOPEN_SOURCE 700

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_route_control.h"
#include "wavevm_membership.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "route-control test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port + 1000U);
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rule,
                             struct wvm_required_ack_entry *ack,
                             uint64_t generation, uint16_t port, char *error,
                             size_t error_len)
{
    uint8_t bytes[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 701;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 55;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 3;
    snapshot->route_snapshot_key.topology_revision = generation;
    snapshot->route_snapshot_key.route_generation = generation;
    snapshot->membership_revision = generation;
    snapshot->topology_kind = 1;

    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_vnode_or_endpoint = 0;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = (uint32_t)generation;
    rule->next_hop_member.instance_id = 7000U + generation;
    fill_endpoint(&rule->next_hop_endpoint, (uint8_t)(10U + generation), port);
    rule->hop_limit = 4;

    memset(ack, 0, sizeof(*ack));
    ack->member_key = rule->next_hop_member;
    ack->endpoint = rule->next_hop_endpoint;
    ack->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack->expected_snapshot_key = snapshot->route_snapshot_key;

    snapshot->next_hop_rules.entries = rule;
    snapshot->next_hop_rules.count = 1;
    snapshot->next_hop_rules.capacity = 1;
    snapshot->required_ack_set.entries.entries = ack;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(ack->expected_snapshot_key.snapshot_digest, digest, sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int encode_snapshot(const struct wvm_route_snapshot_record *snapshot,
                           uint8_t *bytes, size_t capacity, size_t *byte_count,
                           char *error, size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    return wvm_route_snapshot_record_encode(snapshot, bytes, capacity,
                                            byte_count, digest, error,
                                            error_len);
}

static int encode_key(const struct wvm_route_snapshot_key *key, uint8_t *bytes,
                      size_t capacity, size_t *byte_count, char *error,
                      size_t error_len)
{
    return wvm_route_snapshot_key_encode(key, bytes, capacity, byte_count,
                                         error, error_len);
}

static int encode_aborted_transaction(
    const struct wvm_route_snapshot_record *snapshot, uint8_t operation_tail,
    uint8_t *bytes, size_t capacity, size_t *byte_count, char *error,
    size_t error_len)
{
    struct wvm_route_transaction_record transaction;

    memset(&transaction, 0, sizeof(transaction));
    transaction.operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    transaction.route_snapshot_key = snapshot->route_snapshot_key;
    transaction.required_ack_set = snapshot->required_ack_set;
    memset(transaction.required_ack_set.entries_digest, 0,
           sizeof(transaction.required_ack_set.entries_digest));
    if (wvm_required_ack_set_encode(&transaction.required_ack_set, bytes,
                                    capacity, byte_count, error, error_len) !=
            0 ||
        wvm_required_ack_set_decode(bytes, *byte_count,
                                    &transaction.required_ack_set, error,
                                    error_len) != 0) {
        return -1;
    }
    transaction.operation_retention_horizon_ms =
        snapshot->operation_retention_horizon_ms;
    transaction.state = WVM_ROUTE_TRANSACTION_ABORTED;
    return wvm_route_transaction_record_encode(&transaction, bytes, capacity,
                                               byte_count, error, error_len);
}

static void make_request(struct wvm_envelope *request, uint16_t message_type,
                         uint8_t operation_tail, const uint8_t *payload,
                         size_t payload_bytes)
{
    memset(request, 0, sizeof(*request));
    request->message_type = message_type;
    request->vm_id = 701;
    request->vm_incarnation = 55;
    request->manifest_generation = 9;
    request->origin_physical_node_id = 17;
    request->origin_runtime_instance_id = 44;
    request->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_tail;
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 request->semantic_payload_digest);
}

static void make_lookup_envelope(
    struct wvm_envelope *envelope,
    const struct wvm_route_snapshot_key *key)
{
    memset(envelope, 0, sizeof(*envelope));
    envelope->vm_id = key->scope_key.vm_id;
    envelope->vm_incarnation = key->scope_key.vm_incarnation;
    envelope->route_scope_id = key->scope_key.route_scope_id;
    envelope->topology_revision = key->topology_revision;
    envelope->route_generation = key->route_generation;
    memcpy(envelope->route_snapshot_digest, key->snapshot_digest,
           sizeof(envelope->route_snapshot_digest));
    envelope->route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    envelope->route.destination_vnode_or_endpoint = 0;
    envelope->route.hop_limit = 4;
}

int main(void)
{
    char journal[] = "/tmp/wavevm-route-control.XXXXXX";
    struct wvm_route_runtime first_runtime;
    struct wvm_route_runtime recovered_runtime;
    struct wvm_route_control first_control;
    struct wvm_route_control recovered_control;
    struct wvm_route_snapshot_record first_snapshot;
    struct wvm_route_snapshot_record aborted_snapshot;
    struct wvm_route_snapshot_record successor_snapshot;
    struct wvm_route_rule_record first_rule;
    struct wvm_route_rule_record aborted_rule;
    struct wvm_route_rule_record successor_rule;
    struct wvm_required_ack_entry first_ack;
    struct wvm_required_ack_entry aborted_ack;
    struct wvm_required_ack_entry successor_ack;
    struct wvm_envelope request;
    struct wvm_envelope lookup;
    struct wvm_route_runtime_next_hop next_hop;
    struct wvm_route_control_snapshot loaded_snapshot = {0};
    uint8_t snapshot_bytes[8192];
    uint8_t key_bytes[8192];
    size_t snapshot_byte_count;
    size_t key_byte_count;
    char error[256] = {0};
    int fd;

    fd = mkstemp(journal);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    if (finalize_snapshot(&first_snapshot, &first_rule, &first_ack, 1, 19001,
                          error, sizeof(error)) != 0 ||
        finalize_snapshot(&aborted_snapshot, &aborted_rule, &aborted_ack, 2,
                          19002, error, sizeof(error)) != 0 ||
        finalize_snapshot(&successor_snapshot, &successor_rule, &successor_ack,
                          3, 19003, error, sizeof(error)) != 0) {
        fprintf(stderr, "route-control setup: %s\n", error);
        unlink(journal);
        return 1;
    }
    wvm_route_runtime_init(&first_runtime);
    if (expect(wvm_route_control_open(&first_control, &first_runtime, journal,
                                      error, sizeof(error)) == 0,
               "open empty route control journal") ||
        expect(encode_snapshot(&first_snapshot, snapshot_bytes,
                               sizeof(snapshot_bytes), &snapshot_byte_count,
                               error, sizeof(error)) == 0,
               "encode first route snapshot")) {
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_PREPARE, 1,
                 snapshot_bytes, snapshot_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "persist and prepare first snapshot") ||
        expect(wvm_route_control_snapshot_load(
                   &first_control, &first_snapshot.route_snapshot_key,
                   &loaded_snapshot, error, sizeof(error)) == 0 &&
                   loaded_snapshot.snapshot.next_hop_rules.count == 1 &&
                   loaded_snapshot.rules[0].next_hop_endpoint.data_port == 19001,
               "prepared snapshot can feed pre-route-commit activation") ||
        expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "replay duplicate route prepare") ||
        expect(encode_key(&first_snapshot.route_snapshot_key, key_bytes,
                          sizeof(key_bytes), &key_byte_count, error,
                          sizeof(error)) == 0,
               "encode first route key")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    wvm_route_control_snapshot_free(&loaded_snapshot);
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_COMMIT, 2, key_bytes,
                 key_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "persist and commit first snapshot")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_lookup_envelope(&lookup, &first_snapshot.route_snapshot_key);
    if (expect(wvm_route_runtime_lookup(&first_runtime, &lookup, &next_hop,
                                        error, sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19001,
               "first active snapshot routes data")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }

    if (expect(encode_snapshot(&aborted_snapshot, snapshot_bytes,
                               sizeof(snapshot_bytes), &snapshot_byte_count,
                               error, sizeof(error)) == 0,
               "encode abortable snapshot")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_PREPARE, 3,
                 snapshot_bytes, snapshot_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "prepare abortable snapshot") ||
        expect(encode_aborted_transaction(&aborted_snapshot, 9, key_bytes,
                                          sizeof(key_bytes), &key_byte_count,
                                          error, sizeof(error)) == 0,
               "encode route abort transaction")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_ABORT, 4, key_bytes,
                 key_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "abort exact prepared snapshot") ||
        expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "replay duplicate route abort") ||
        expect(!wvm_route_runtime_has_snapshot(
                   &first_runtime, &aborted_snapshot.route_snapshot_key),
               "aborted snapshot is never active")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    if (expect(encode_aborted_transaction(&aborted_snapshot, 10, key_bytes,
                                          sizeof(key_bytes), &key_byte_count,
                                          error, sizeof(error)) == 0,
               "encode conflicting route abort transaction")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_ABORT, 4, key_bytes,
                 key_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) != 0,
               "reject route abort operation ID payload conflict") ||
        expect(encode_snapshot(&successor_snapshot, snapshot_bytes,
                               sizeof(snapshot_bytes), &snapshot_byte_count,
                               error, sizeof(error)) == 0,
               "encode successor snapshot")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_PREPARE, 5,
                 snapshot_bytes, snapshot_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "prepare successor snapshot") ||
        expect(encode_key(&successor_snapshot.route_snapshot_key, key_bytes,
                          sizeof(key_bytes), &key_byte_count, error,
                          sizeof(error)) == 0,
               "encode successor route key")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_COMMIT, 6, key_bytes,
                 key_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "commit successor snapshot") ||
        expect(encode_aborted_transaction(&successor_snapshot, 11, key_bytes,
                                          sizeof(key_bytes), &key_byte_count,
                                          error, sizeof(error)) == 0,
               "encode active route abort transaction")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_ABORT, 7, key_bytes,
                 key_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) != 0,
               "reject route abort after activation") ||
        expect(encode_key(&first_snapshot.route_snapshot_key, key_bytes,
                          sizeof(key_bytes), &key_byte_count, error,
                          sizeof(error)) == 0,
               "encode predecessor key")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    make_request(&request, WVM_ENVELOPE_MSG_ROUTE_RETIRE, 8, key_bytes,
                 key_byte_count);
    if (expect(wvm_route_control_apply(&first_control, &request, NULL, error,
                                       sizeof(error)) == 0,
               "retire predecessor snapshot")) {
        wvm_route_control_close(&first_control);
        wvm_route_runtime_destroy(&first_runtime);
        unlink(journal);
        return 1;
    }
    wvm_route_control_close(&first_control);
    wvm_route_runtime_destroy(&first_runtime);

    fd = open(journal, O_WRONLY | O_APPEND);
    if (fd < 0 || write(fd, "WVM", 3) != 3) {
        perror("append torn route control journal tail");
        if (fd >= 0) {
            close(fd);
        }
        unlink(journal);
        return 1;
    }
    close(fd);

    wvm_route_runtime_init(&recovered_runtime);
    if (expect(wvm_route_control_open(&recovered_control, &recovered_runtime,
                                      journal, error, sizeof(error)) == 0,
               "replay route control journal") ||
        expect(!wvm_route_runtime_has_snapshot(
                   &recovered_runtime, &first_snapshot.route_snapshot_key),
               "keep predecessor retired after replay")) {
        wvm_route_runtime_destroy(&recovered_runtime);
        unlink(journal);
        return 1;
    }
    make_lookup_envelope(&lookup, &successor_snapshot.route_snapshot_key);
    if (expect(wvm_route_runtime_lookup(&recovered_runtime, &lookup,
                                        &next_hop, error, sizeof(error)) == 0 &&
                   next_hop.next_hop_endpoint.data_port == 19003,
               "recovered successor remains active")) {
        wvm_route_control_close(&recovered_control);
        wvm_route_runtime_destroy(&recovered_runtime);
        unlink(journal);
        return 1;
    }
    if (expect(wvm_route_control_snapshot_load(
                   &recovered_control, &successor_snapshot.route_snapshot_key,
                   &loaded_snapshot, error, sizeof(error)) == 0 &&
                   loaded_snapshot.snapshot.membership_revision ==
                       successor_snapshot.membership_revision &&
                   loaded_snapshot.snapshot.next_hop_rules.count == 1 &&
                   loaded_snapshot.rules[0].next_hop_endpoint.data_port == 19003,
               "recover full active route snapshot for runtime delivery")) {
        wvm_route_control_snapshot_free(&loaded_snapshot);
        wvm_route_control_close(&recovered_control);
        wvm_route_runtime_destroy(&recovered_runtime);
        unlink(journal);
        return 1;
    }
    wvm_route_control_snapshot_free(&loaded_snapshot);
    if (expect(wvm_route_control_snapshot_load(
                   &recovered_control, &first_snapshot.route_snapshot_key,
                   &loaded_snapshot, error, sizeof(error)) != 0,
               "retired snapshot cannot feed runtime delivery")) {
        wvm_route_control_close(&recovered_control);
        wvm_route_runtime_destroy(&recovered_runtime);
        unlink(journal);
        return 1;
    }

    wvm_route_control_close(&recovered_control);
    wvm_route_runtime_destroy(&recovered_runtime);
    unlink(journal);
    puts("route-control tests: PASS");
    return 0;
}

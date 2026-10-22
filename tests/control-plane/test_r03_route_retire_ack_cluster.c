/*
 * R03: dual-owner ROUTE_RETIRE ACK through production route_control.
 * Both RequiredAckSet owners must prove refs=0 + horizon before retire;
 * ACK result matches stream-transport contract (state=4, refs=0, horizon=0).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wavevm_control.h"
#include "wavevm_envelope.h"
#include "wavevm_route_control.h"
#include "wavevm_route_runtime.h"

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "r03-route-retire-ack: %s\n", msg);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last,
                          uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 127;
    endpoint->data_address[3] = last;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port + 1);
}

static int build_snapshot(struct wvm_route_snapshot_record *snapshot,
                          struct wvm_route_rule_record *rules,
                          struct wvm_required_ack_entry *acks, char *error,
                          size_t error_len)
{
    uint8_t encoded[8192];
    uint8_t digest[32];
    size_t encoded_bytes = 0;
    size_t i;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 900;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 1;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 42;
    snapshot->route_snapshot_key.topology_revision = 1;
    snapshot->route_snapshot_key.route_generation = 1;
    snapshot->membership_revision = 1;
    snapshot->topology_kind = 1;
    snapshot->operation_retention_horizon_ms = 1; /* short for test */
    snapshot->retirement_policy = 1;

    for (i = 0; i < 2; i++) {
        memset(&rules[i], 0, sizeof(rules[i]));
        rules[i].destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
        rules[i].destination_vnode_or_endpoint = (uint32_t)i;
        rules[i].next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
        rules[i].next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        rules[i].next_hop_member.role_id = (uint32_t)(10 + i);
        rules[i].next_hop_member.instance_id = (uint64_t)(100 + i);
        fill_endpoint(&rules[i].next_hop_endpoint, (uint8_t)(10 + i),
                      (uint16_t)(19000 + i));
        rules[i].hop_limit = 4;
        memset(&acks[i], 0, sizeof(acks[i]));
        acks[i].member_key = rules[i].next_hop_member;
        acks[i].endpoint = rules[i].next_hop_endpoint;
        acks[i].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        acks[i].expected_snapshot_key = snapshot->route_snapshot_key;
    }
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = 2;
    snapshot->next_hop_rules.capacity = 2;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = 2;
    snapshot->required_ack_set.entries.capacity = 2;

    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0)
        return -1;
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    for (i = 0; i < 2; i++)
        acks[i].expected_snapshot_key = snapshot->route_snapshot_key;
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int apply_retire(struct wvm_route_control *control,
                        const struct wvm_route_snapshot_key *key,
                        uint8_t op_tail, struct wvm_route_control_result *out,
                        char *error, size_t error_len)
{
    struct wvm_envelope retire;
    uint8_t key_bytes[256];
    size_t key_len = 0;

    if (wvm_route_snapshot_key_encode(key, key_bytes, sizeof(key_bytes),
                                      &key_len, error, error_len) != 0)
        return -1;
    memset(&retire, 0, sizeof(retire));
    retire.message_type = WVM_ENVELOPE_MSG_ROUTE_RETIRE;
    retire.vm_id = key->scope_key.vm_id;
    retire.vm_incarnation = key->scope_key.vm_incarnation;
    retire.manifest_generation = 1;
    retire.origin_physical_node_id = 17;
    retire.origin_runtime_instance_id = 44;
    memset(retire.operation_id, 0xC3, sizeof(retire.operation_id));
    retire.operation_id[15] = op_tail;
    retire.delivery_attempt_id = 1;
    retire.route_scope_id = key->scope_key.route_scope_id;
    retire.topology_revision = key->topology_revision;
    retire.route_generation = key->route_generation;
    memcpy(retire.route_snapshot_digest, key->snapshot_digest,
           sizeof(retire.route_snapshot_digest));
    retire.payload = key_bytes;
    retire.payload_bytes = key_len;
    wvm_envelope_semantic_digest(key_bytes, key_len,
                                 retire.semantic_payload_digest);
    memset(out, 0, sizeof(*out));
    return wvm_route_control_apply(control, &retire, out, error, error_len);
}

/* Stream-transport ROUTE_RETIRE ACK contract (admission_stream_transport.c). */
static int stream_ack_contract_ok(const struct wvm_route_control_result *r)
{
    return r->recorded_state == 4 && r->active_operation_refs == 0 &&
           r->retention_horizon_complete != 0;
}

int main(void)
{
    char directory[] = "/tmp/wavevm-r03-retire.XXXXXX";
    char journal0[512], journal1[512], error[256] = {0};
    struct wvm_route_runtime runtime0, runtime1;
    struct wvm_route_control control0, control1;
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[2];
    struct wvm_route_control_result result0, result1;
    uint64_t refs;
    int horizon;

    if (!mkdtemp(directory)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(journal0, sizeof(journal0), "%s/owner0.journal", directory);
    snprintf(journal1, sizeof(journal1), "%s/owner1.journal", directory);

    if (build_snapshot(&snapshot, rules, acks, error, sizeof(error)) != 0) {
        fprintf(stderr, "snapshot: %s\n", error);
        return 1;
    }

    wvm_route_runtime_init(&runtime0);
    wvm_route_runtime_init(&runtime1);
    if (expect(wvm_route_control_open(&control0, &runtime0, journal0, error,
                                      sizeof(error)) == 0,
               "open owner0") != 0 ||
        expect(wvm_route_control_open(&control1, &runtime1, journal1, error,
                                      sizeof(error)) == 0,
               "open owner1") != 0)
        return 1;

    if (expect(wvm_route_runtime_prepare(&runtime0, &snapshot, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime0, &snapshot.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate owner0") != 0 ||
        expect(wvm_route_runtime_prepare(&runtime1, &snapshot, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &runtime1, &snapshot.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate owner1") != 0)
        return 1;
    printf("[OK] dual owners activated RequiredAckSet=2\n");

    usleep(5000);
    if (expect(wvm_route_runtime_query_retire_proof(
                   &runtime0, &snapshot.route_snapshot_key, &refs, &horizon,
                   error, sizeof(error)) == 0 &&
                   refs == 0 && horizon,
               "owner0 proof") != 0 ||
        expect(wvm_route_runtime_query_retire_proof(
                   &runtime1, &snapshot.route_snapshot_key, &refs, &horizon,
                   error, sizeof(error)) == 0 &&
                   refs == 0 && horizon,
               "owner1 proof") != 0)
        return 1;

    if (expect(apply_retire(&control0, &snapshot.route_snapshot_key, 1,
                            &result0, error, sizeof(error)) == 0,
               "ROUTE_RETIRE owner0") != 0) {
        fprintf(stderr, "owner0 retire: %s\n", error);
        return 1;
    }
    if (expect(apply_retire(&control1, &snapshot.route_snapshot_key, 2,
                            &result1, error, sizeof(error)) == 0,
               "ROUTE_RETIRE owner1") != 0) {
        fprintf(stderr, "owner1 retire: %s\n", error);
        return 1;
    }
    if (expect(stream_ack_contract_ok(&result0),
               "owner0 ACK stream contract") != 0 ||
        expect(stream_ack_contract_ok(&result1),
               "owner1 ACK stream contract") != 0) {
        fprintf(stderr,
                "ACK0 state=%u refs=%llu horizon=%d; ACK1 state=%u refs=%llu "
                "horizon=%d\n",
                result0.recorded_state,
                (unsigned long long)result0.active_operation_refs,
                result0.retention_horizon_complete, result1.recorded_state,
                (unsigned long long)result1.active_operation_refs,
                result1.retention_horizon_complete);
        return 1;
    }
    printf("[OK] dual-owner ROUTE_RETIRE ACK state=4 refs=0 horizon_complete\n");

    wvm_route_control_close(&control0);
    wvm_route_control_close(&control1);
    wvm_route_runtime_destroy(&runtime0);
    wvm_route_runtime_destroy(&runtime1);
    puts("R03 ROUTE_RETIRE ACK cluster E2E: PASS");
    return 0;
}

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_control.h"
#include "wavevm_envelope.h"
#include "wavevm_manifest.h"
#include "wavevm_membership_control.h"
#include "wavevm_membership_controller.h"
#include "wavevm_sha256.h"

#define REQUEST_BYTES 65536U
#define RESPONSE_BYTES \
    (WVM_ENVELOPE_HEADER_BYTES + WVM_MEMBERSHIP_CONTROL_RESULT_BYTES)

/*
 * Submits DRAIN (0x0103) action=PREPARE with a complete successor
 * RouteTransaction+RouteSnapshot (topology=current+1) per wire-ipc-abi §4.2.2
 * and cluster-membership-topology-lifecycle §5.4.
 *
 * usage: submit_gateway_drain_prepare SOCKET JOURNAL_SNAP \\
 *         DEPART_GW_ID DEPART_INST SUCC_GW_ID SUCC_INST \\
 *         NODE_ID NODE_INST VM_ID
 */

static int write_full(int fd, const uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t written = write(fd, bytes + offset, byte_count - offset);

        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int read_full(int fd, uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t received = read(fd, bytes + offset, byte_count - offset);

        if (received > 0) {
            offset += (size_t)received;
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static void write_be32(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static uint32_t read_be32(const uint8_t bytes[4])
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static int parse_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (!text || !out) {
        return -1;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0') {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

static const struct wvm_membership_controller_member_entry *find_member(
    const struct wvm_membership_controller *controller, uint16_t role_type,
    uint32_t role_id, uint64_t instance_id)
{
    size_t i;

    for (i = 0; i < controller->member_count; i++) {
        const struct wvm_membership_controller_member_entry *entry =
            &controller->members[i];

        if (entry->member_key.role_type == role_type &&
            entry->member_key.role_id == role_id &&
            entry->member_key.instance_id == instance_id) {
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

static int build_ack_set(struct wvm_required_ack_set *ack_set,
                         struct wvm_required_ack_entry entries[2],
                         struct wvm_required_ack_entry decoded[2],
                         const struct wvm_route_snapshot_key *route_key,
                         const struct wvm_member_key *node_member,
                         const struct wvm_endpoint *node_endpoint,
                         const struct wvm_member_key *gateway_member,
                         const struct wvm_endpoint *gateway_endpoint,
                         char *error, size_t error_len)
{
    struct wvm_required_ack_set source;
    uint8_t bytes[4096];
    size_t encoded_bytes = 0;

    memset(entries, 0, 2 * sizeof(*entries));
    entries[0].member_key = *node_member;
    entries[0].endpoint = *node_endpoint;
    entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    entries[0].expected_snapshot_key = *route_key;
    entries[1].member_key = *gateway_member;
    entries[1].endpoint = *gateway_endpoint;
    entries[1].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    entries[1].expected_snapshot_key = *route_key;
    memset(&source, 0, sizeof(source));
    source.entries.entries = entries;
    source.entries.count = 2;
    source.entries.capacity = 2;
    if (wvm_required_ack_set_encode(&source, bytes, sizeof(bytes),
                                    &encoded_bytes, error, error_len) != 0) {
        return -1;
    }
    memset(ack_set, 0, sizeof(*ack_set));
    ack_set->entries.entries = decoded;
    ack_set->entries.capacity = 2;
    return wvm_required_ack_set_decode(bytes, encoded_bytes, ack_set, error,
                                       error_len);
}

static int build_successor(
    struct wvm_route_transaction_record *transaction,
    struct wvm_route_snapshot_record *snapshot,
    struct wvm_route_rule_record *rule,
    struct wvm_required_ack_entry snapshot_ack_entries[2],
    struct wvm_required_ack_entry transaction_ack_entries[2],
    struct wvm_required_ack_entry decoded_transaction_ack_entries[2],
    struct wvm_required_ack_set *ack_set,
    struct wvm_required_ack_entry optional_departure_entries[1],
    uint64_t topology_revision, uint64_t membership_revision,
    const struct wvm_route_snapshot_key *predecessor_key,
    const struct wvm_member_key *node_member,
    const struct wvm_endpoint *node_endpoint,
    const struct wvm_member_key *departing_gateway_member,
    const struct wvm_endpoint *departing_gateway_endpoint,
    const struct wvm_member_key *successor_gateway_member,
    const struct wvm_endpoint *successor_gateway_endpoint, char *error,
    size_t error_len)
{
    uint8_t encoded[8192];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes = 0;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key = predecessor_key->scope_key;
    snapshot->route_snapshot_key.topology_revision = topology_revision;
    snapshot->route_snapshot_key.route_generation =
        predecessor_key->route_generation + 1U;
    snapshot->membership_revision = membership_revision;
    snapshot->topology_kind = 1;
    snapshot->has_predecessor_snapshot_key = 1;
    snapshot->predecessor_snapshot_key = *predecessor_key;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    rule->next_hop_member = *successor_gateway_member;
    rule->next_hop_endpoint = *successor_gateway_endpoint;
    rule->hop_limit = 4;
    snapshot->next_hop_rules.entries = rule;
    snapshot->next_hop_rules.count = 1;
    snapshot->next_hop_rules.capacity = 1;

    memset(snapshot_ack_entries, 0, 2 * sizeof(*snapshot_ack_entries));
    snapshot_ack_entries[0].member_key = *node_member;
    snapshot_ack_entries[0].endpoint = *node_endpoint;
    snapshot_ack_entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    snapshot_ack_entries[0].expected_snapshot_key =
        snapshot->route_snapshot_key;
    snapshot_ack_entries[1].member_key = *successor_gateway_member;
    snapshot_ack_entries[1].endpoint = *successor_gateway_endpoint;
    snapshot_ack_entries[1].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    snapshot_ack_entries[1].expected_snapshot_key =
        snapshot->route_snapshot_key;
    snapshot->required_ack_set.entries.entries = snapshot_ack_entries;
    snapshot->required_ack_set.entries.count = 2;
    snapshot->required_ack_set.entries.capacity = 2;
    if (wvm_route_snapshot_record_encode(snapshot, encoded, sizeof(encoded),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest, sizeof(digest));
    memcpy(snapshot_ack_entries[0].expected_snapshot_key.snapshot_digest,
           digest, sizeof(digest));
    memcpy(snapshot_ack_entries[1].expected_snapshot_key.snapshot_digest,
           digest, sizeof(digest));
    if (wvm_route_snapshot_record_validate(snapshot, error, error_len) != 0 ||
        build_ack_set(ack_set, transaction_ack_entries,
                      decoded_transaction_ack_entries,
                      &snapshot->route_snapshot_key, node_member, node_endpoint,
                      successor_gateway_member, successor_gateway_endpoint,
                      error, error_len) != 0) {
        return -1;
    }
    memset(transaction, 0, sizeof(*transaction));
    transaction->operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x45;
    transaction->operation_id[WVM_IDENTITY_ID_BYTES - 2] =
        (uint8_t)(predecessor_key->scope_key.vm_id & 0xffU);
    transaction->route_snapshot_key = snapshot->route_snapshot_key;
    transaction->has_predecessor_snapshot_key = 1;
    transaction->predecessor_snapshot_key = *predecessor_key;
    transaction->required_ack_set = *ack_set;
    memset(optional_departure_entries, 0, sizeof(*optional_departure_entries));
    optional_departure_entries[0].member_key = *departing_gateway_member;
    optional_departure_entries[0].endpoint = *departing_gateway_endpoint;
    optional_departure_entries[0].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    optional_departure_entries[0].expected_snapshot_key = *predecessor_key;
    transaction->optional_departure_drain_set.entries =
        optional_departure_entries;
    transaction->optional_departure_drain_set.count = 1;
    transaction->optional_departure_drain_set.capacity = 1;
    transaction->operation_retention_horizon_ms = 5000;
    transaction->state = WVM_ROUTE_TRANSACTION_PREPARING;
    return wvm_route_transaction_record_validate(transaction, error, error_len);
}

static int find_predecessor_key(
    const struct wvm_membership_controller *controller, uint32_t vm_id,
    struct wvm_route_snapshot_key *key_out)
{
    size_t i;

    for (i = 0; i < controller->route_count; i++) {
        const struct wvm_membership_controller_route_entry *route =
            &controller->routes[i];

        if (route->transaction.state == WVM_ROUTE_TRANSACTION_ACTIVATED &&
            route->transaction.route_snapshot_key.scope_key.vm_id == vm_id) {
            *key_out = route->transaction.route_snapshot_key;
            return 0;
        }
    }
    return -1;
}

int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[16];
    struct wvm_membership_controller_route_entry routes[8];
    struct wvm_membership_dependency dependencies[16];
    struct wvm_gateway_drain_request request;
    struct wvm_route_transaction_record successor_tx;
    struct wvm_route_snapshot_record successor_snap;
    struct wvm_route_rule_record rule;
    struct wvm_required_ack_entry snap_acks[2];
    struct wvm_required_ack_entry tx_acks[2];
    struct wvm_required_ack_entry decoded_tx_acks[2];
    struct wvm_required_ack_set ack_set;
    struct wvm_required_ack_entry departure[1];
    struct wvm_route_snapshot_key predecessor_key;
    struct wvm_envelope envelope;
    struct wvm_envelope response;
    struct wvm_membership_control_result result;
    struct sockaddr_un address;
    const struct wvm_membership_controller_member_entry *departing;
    const struct wvm_membership_controller_member_entry *successor;
    const struct wvm_membership_controller_member_entry *node;
    uint8_t payload[REQUEST_BYTES];
    uint8_t request_frame[WVM_ENVELOPE_HEADER_BYTES + REQUEST_BYTES];
    uint8_t response_frame[RESPONSE_BYTES];
    uint8_t prefix[4];
    uint8_t response_prefix[4];
    size_t payload_bytes = 0;
    size_t request_frame_bytes = 0;
    uint32_t response_bytes;
    uint64_t depart_id, depart_inst, succ_id, succ_inst, node_id, node_inst,
        vm_id;
    char error[256] = {0};
    size_t path_bytes;
    int fd = -1;

    if (argc != 10) {
        fprintf(stderr,
                "usage: %s SOCKET JOURNAL DEPART_GW DEPART_INST SUCC_GW "
                "SUCC_INST NODE NODE_INST VM_ID\n",
                argv[0]);
        return 2;
    }
    if (parse_u64(argv[3], &depart_id) != 0 ||
        parse_u64(argv[4], &depart_inst) != 0 ||
        parse_u64(argv[5], &succ_id) != 0 ||
        parse_u64(argv[6], &succ_inst) != 0 ||
        parse_u64(argv[7], &node_id) != 0 ||
        parse_u64(argv[8], &node_inst) != 0 ||
        parse_u64(argv[9], &vm_id) != 0) {
        fprintf(stderr, "invalid numeric argument\n");
        return 2;
    }

    wvm_membership_controller_init(&controller, members, 16, routes, 8,
                                   dependencies, 16, NULL, NULL);
    if (wvm_membership_controller_open(&controller, argv[2], error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "journal open: %s\n", error);
        return 1;
    }
    departing = find_member(&controller, WVM_MANIFEST_ROLE_GATEWAY,
                            (uint32_t)depart_id, depart_inst);
    successor = find_member(&controller, WVM_MANIFEST_ROLE_GATEWAY,
                            (uint32_t)succ_id, succ_inst);
    node = find_member(&controller, WVM_MANIFEST_ROLE_NODE_RUNTIME,
                       (uint32_t)node_id, node_inst);
    if (!departing || !successor || !node ||
        find_predecessor_key(&controller, (uint32_t)vm_id, &predecessor_key) !=
            0) {
        fprintf(stderr, "members or activated predecessor missing in snap\n");
        wvm_membership_controller_close(&controller);
        return 1;
    }

    memset(&request, 0, sizeof(request));
    request.action = WVM_GATEWAY_DRAIN_ACTION_PREPARE;
    request.target_gateway_member_key = departing->member_key;
    request.expected_membership_revision = controller.membership_revision;
    request.expected_topology_revision = controller.topology_revision;
    request.expected_admission_eligibility_revision =
        controller.admission_eligibility_revision;
    if (build_successor(
            &successor_tx, &successor_snap, &rule, snap_acks, tx_acks,
            decoded_tx_acks, &ack_set, departure,
            controller.topology_revision + 1U, controller.membership_revision,
            &predecessor_key, &node->member_key, member_endpoint(node),
            &departing->member_key, member_endpoint(departing),
            &successor->member_key, member_endpoint(successor), error,
            sizeof(error)) != 0) {
        fprintf(stderr, "build successor: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }
    request.successor_transaction = successor_tx;
    request.successor_snapshot = successor_snap;
    memcpy(request.route_operation_id, successor_tx.operation_id,
           sizeof(request.route_operation_id));
    wvm_membership_controller_close(&controller);

    if (wvm_gateway_drain_request_encode(&request, payload, sizeof(payload),
                                         &payload_bytes, error,
                                         sizeof(error)) != 0) {
        fprintf(stderr, "encode: %s\n", error);
        return 1;
    }

    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = WVM_ENVELOPE_MSG_DRAIN;
    envelope.origin_physical_node_id = 9001;
    envelope.origin_runtime_instance_id = 9002;
    memcpy(envelope.operation_id, request.route_operation_id,
           sizeof(envelope.operation_id));
    envelope.delivery_attempt_id = 1;
    envelope.payload = payload;
    envelope.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 envelope.semantic_payload_digest);
    if (wvm_envelope_encode(&envelope, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            request_frame, sizeof(request_frame),
                            &request_frame_bytes, error, sizeof(error)) != 0) {
        fprintf(stderr, "encode envelope: %s\n", error);
        return 1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    path_bytes = strlen(argv[1]);
    if (fd < 0 || path_bytes + 1U > sizeof(address.sun_path)) {
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, argv[1], path_bytes + 1U);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                            path_bytes + 1U)) != 0) {
        close(fd);
        return 1;
    }
    write_be32(prefix, (uint32_t)request_frame_bytes);
    if (write_full(fd, prefix, sizeof(prefix)) != 0 ||
        write_full(fd, request_frame, request_frame_bytes) != 0 ||
        read_full(fd, response_prefix, sizeof(response_prefix)) != 0) {
        close(fd);
        return 1;
    }
    response_bytes = read_be32(response_prefix);
    if (response_bytes < WVM_ENVELOPE_HEADER_BYTES ||
        response_bytes > sizeof(response_frame) ||
        read_full(fd, response_frame, response_bytes) != 0 ||
        wvm_envelope_decode(response_frame, response_bytes,
                            WVM_ENVELOPE_TRANSPORT_LOCAL, &response, error,
                            sizeof(error)) != 0 ||
        response.message_type != WVM_ENVELOPE_MSG_CTRL_RESULT ||
        response.payload_bytes != WVM_MEMBERSHIP_CONTROL_RESULT_BYTES ||
        wvm_membership_control_result_decode(response.payload, &result) != 0) {
        close(fd);
        return 1;
    }
    close(fd);
    printf("status=%u recorded_state=%u applied_revision=%llu op=",
           (unsigned)result.status_code, (unsigned)result.recorded_state,
           (unsigned long long)result.applied_revision);
    {
        size_t i;

        for (i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
            printf("%02x", request.route_operation_id[i]);
        }
    }
    printf("\n");
    return result.status_code == WVM_MEMBERSHIP_CONTROL_SUCCESS ? 0 : 1;
}

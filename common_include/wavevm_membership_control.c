#define _POSIX_C_SOURCE 200809L

#include "wavevm_membership_control.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "wavevm_canonical.h"

#define WVM_MEMBERSHIP_CONTROL_JOURNAL_VERSION 1U
#define WVM_MEMBERSHIP_CONTROL_JOURNAL_HEADER_BYTES 56U
#define WVM_MEMBERSHIP_CONTROL_JOURNAL_PAYLOAD_BYTES 140U
#define WVM_MEMBERSHIP_CONTROL_REJOIN_RECORD 0x102aU

static const uint8_t membership_control_journal_magic[8] = {
    'W', 'V', 'M', 'C', 'R', 'X', '1', '\0',
};

enum decoded_member_kind {
    DECODED_MEMBER_NODE = 1,
    DECODED_MEMBER_GATEWAY = 2,
};

struct decoded_member_record {
    enum decoded_member_kind kind;
    struct wvm_node_record node;
    struct wvm_gateway_record gateway;
};

struct decoded_rejoin_request {
    const uint8_t *member_record;
    size_t member_record_bytes;
    int has_prior_member;
    struct wvm_member_key prior_member;
};

struct decoded_gateway_drain_request {
    struct wvm_gateway_drain_request request;
};

struct decoded_member_cordon_request {
    struct wvm_member_cordon_request request;
};

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_be64(uint8_t *bytes, uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        bytes[7U - i] = (uint8_t)(value >> (i * 8U));
    }
}

static uint16_t read_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t read_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static int write_full(int fd, const uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t written = write(fd, bytes + offset, byte_count - offset);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

/*
 * Returns one for a complete read, zero for clean EOF, and minus one for a
 * torn tail. The latter is discarded only during journal recovery.
 */
static int read_full(int fd, uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t received = read(fd, bytes + offset, byte_count - offset);

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            return offset == 0 ? 0 : -1;
        }
        offset += (size_t)received;
    }
    return 1;
}

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    if (!bytes) {
        return 1;
    }
    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int status_code_valid(uint16_t status_code)
{
    return status_code <= WVM_MEMBERSHIP_CONTROL_INTERNAL_FAILURE;
}

static int control_message_supported(uint16_t message_type)
{
    return message_type == WVM_ENVELOPE_MSG_REGISTER_MEMBER ||
           message_type == WVM_ENVELOPE_MSG_REJOIN ||
           message_type == WVM_ENVELOPE_MSG_CORDON ||
           message_type == WVM_ENVELOPE_MSG_DRAIN ||
           message_type == WVM_ENVELOPE_MSG_DRAIN_COMPUTE;
}

static void initialize_result(
    struct wvm_membership_control_result *result,
    const struct wvm_envelope *request, uint16_t status_code)
{
    memset(result, 0, sizeof(*result));
    result->status_code = status_code;
    if (request) {
        memcpy(result->in_reply_to_operation_id, request->operation_id,
               sizeof(result->in_reply_to_operation_id));
    }
}

int wvm_membership_control_result_encode(
    const struct wvm_membership_control_result *result,
    uint8_t bytes[WVM_MEMBERSHIP_CONTROL_RESULT_BYTES])
{
    if (!result || !bytes || !status_code_valid(result->status_code) ||
        result->result_flags != 0) {
        return -1;
    }
    write_be16(bytes + 0, result->status_code);
    write_be16(bytes + 2, result->recorded_state);
    write_be32(bytes + 4, result->result_flags);
    memcpy(bytes + 8, result->in_reply_to_operation_id,
           sizeof(result->in_reply_to_operation_id));
    memcpy(bytes + 24, result->record_digest, sizeof(result->record_digest));
    write_be64(bytes + 56, result->applied_revision);
    write_be64(bytes + 64, result->expiry_or_retention_deadline);
    return 0;
}

int wvm_membership_control_result_decode(
    const uint8_t bytes[WVM_MEMBERSHIP_CONTROL_RESULT_BYTES],
    struct wvm_membership_control_result *result)
{
    if (!bytes || !result || !status_code_valid(read_be16(bytes + 0)) ||
        read_be32(bytes + 4) != 0) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status_code = read_be16(bytes + 0);
    result->recorded_state = read_be16(bytes + 2);
    result->result_flags = read_be32(bytes + 4);
    memcpy(result->in_reply_to_operation_id, bytes + 8,
           sizeof(result->in_reply_to_operation_id));
    memcpy(result->record_digest, bytes + 24, sizeof(result->record_digest));
    result->applied_revision = read_be64(bytes + 56);
    result->expiry_or_retention_deadline = read_be64(bytes + 64);
    return 0;
}

void wvm_membership_control_init(
    struct wvm_membership_control *control,
    struct wvm_membership_controller *controller,
    struct wvm_membership_control_operation *operations,
    size_t operation_capacity)
{
    if (!control) {
        return;
    }
    memset(control, 0, sizeof(*control));
    control->journal_fd = -1;
    control->controller = controller;
    control->operations = operations;
    control->operation_capacity = operation_capacity;
    if (operations && operation_capacity != 0) {
        memset(operations, 0, operation_capacity * sizeof(*operations));
    }
}

int wvm_membership_control_set_management_authorizer(
    struct wvm_membership_control *control,
    wvm_membership_control_authorize_management_fn authorize,
    void *authorize_context)
{
    if (!control || control->lock_initialized || control->journal_fd >= 0) {
        return -1;
    }
    control->authorize_management = authorize;
    control->authorize_management_context = authorize_context;
    return 0;
}

int wvm_membership_control_set_membership_authorizer(
    struct wvm_membership_control *control,
    wvm_membership_control_authorize_membership_fn authorize,
    void *authorize_context)
{
    if (!control || control->lock_initialized || control->journal_fd >= 0) {
        return -1;
    }
    control->authorize_membership = authorize;
    control->authorize_membership_context = authorize_context;
    return 0;
}

static int envelope_is_valid(const struct wvm_envelope *request,
                             char *error, size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    if (!request || !control_message_supported(request->message_type) ||
        request->flags != 0 || request->vm_id != 0 ||
        request->vm_incarnation != 0 || request->manifest_generation != 0 ||
        request->origin_physical_node_id == 0 ||
        request->origin_runtime_instance_id == 0 ||
        bytes_are_zero(request->operation_id, sizeof(request->operation_id)) ||
        request->delivery_attempt_id == 0 ||
        request->route_scope_id != 0 || request->topology_revision != 0 ||
        request->route_generation != 0 ||
        !bytes_are_zero(request->route_snapshot_digest,
                        sizeof(request->route_snapshot_digest)) ||
        request->route.destination_kind != 0 ||
        request->route.destination_scope != 0 ||
        request->route.destination_vnode_or_endpoint != 0 ||
        request->route.hop_limit != 0 || request->route.hop_count != 0 ||
        !request->payload || request->payload_bytes == 0 ||
        request->payload_bytes > WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES) {
        set_error(error, error_len, "membership control envelope is invalid");
        return -1;
    }
    wvm_envelope_semantic_digest(request->payload, request->payload_bytes,
                                    digest);
    if (memcmp(digest, request->semantic_payload_digest, sizeof(digest)) !=
        0) {
        set_error(error, error_len,
                  "membership control semantic digest does not match payload");
        return -1;
    }
    return 0;
}

static int canonical_field_find(const struct wvm_canonical_record *record,
                                uint16_t wanted_tag,
                                struct wvm_canonical_field *field_out)
{
    struct wvm_canonical_field field;
    size_t offset = 0;
    int next;
    int found = 0;

    while ((next = wvm_canonical_record_next(record, &offset, &field)) > 0) {
        if (field.tag == wanted_tag) {
            if (found) {
                return -1;
            }
            *field_out = field;
            found = 1;
        }
    }
    return next < 0 || !found ? -1 : 0;
}

static int canonical_record_list_count(const uint8_t *bytes,
                                       size_t byte_count,
                                       size_t *count_out)
{
    uint32_t count;
    uint32_t i;
    size_t offset = 4;

    if (!bytes || !count_out || byte_count < 4) {
        return -1;
    }
    count = read_be32(bytes);
    for (i = 0; i < count; i++) {
        uint32_t item_bytes;

        if (byte_count - offset < 4) {
            return -1;
        }
        item_bytes = read_be32(bytes + offset);
        offset += 4;
        if (item_bytes == 0 || item_bytes > byte_count - offset) {
            return -1;
        }
        offset += item_bytes;
    }
    if (offset != byte_count) {
        return -1;
    }
    *count_out = count;
    return 0;
}

static int required_ack_set_entry_count(const uint8_t *bytes,
                                        size_t byte_count,
                                        size_t *count_out)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field entries;

    if (wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_REQUIRED_ACK_SET ||
        canonical_field_find(&record, 1, &entries) != 0) {
        return -1;
    }
    return canonical_record_list_count(entries.value, entries.value_bytes,
                                       count_out);
}

static int drain_transaction_entry_counts(const uint8_t *bytes,
                                          size_t byte_count,
                                          size_t *required_ack_count_out,
                                          size_t *optional_drain_count_out)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field ack_set;
    struct wvm_canonical_field optional_drain;

    if (wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_ROUTE_TRANSACTION ||
        canonical_field_find(&record, 4, &ack_set) != 0 ||
        canonical_field_find(&record, 5, &optional_drain) != 0 ||
        required_ack_set_entry_count(ack_set.value, ack_set.value_bytes,
                                     required_ack_count_out) != 0 ||
        canonical_record_list_count(optional_drain.value,
                                    optional_drain.value_bytes,
                                    optional_drain_count_out) != 0) {
        return -1;
    }
    return 0;
}

static int drain_snapshot_entry_counts(const uint8_t *bytes, size_t byte_count,
                                       size_t *rule_count_out,
                                       size_t *required_ack_count_out)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field rules;
    struct wvm_canonical_field ack_set;

    if (wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_ROUTE_SNAPSHOT ||
        canonical_field_find(&record, 4, &rules) != 0 ||
        canonical_field_find(&record, 5, &ack_set) != 0 ||
        canonical_record_list_count(rules.value, rules.value_bytes,
                                    rule_count_out) != 0 ||
        required_ack_set_entry_count(ack_set.value, ack_set.value_bytes,
                                     required_ack_count_out) != 0) {
        return -1;
    }
    return 0;
}

static void decoded_gateway_drain_request_free(
    struct decoded_gateway_drain_request *request)
{
    if (!request) {
        return;
    }
    free(request->request.successor_transaction.required_ack_set.entries.entries);
    free(request->request.successor_transaction
             .optional_departure_drain_set.entries);
    free(request->request.successor_snapshot.next_hop_rules.entries);
    free(request->request.successor_snapshot.required_ack_set.entries.entries);
    memset(request, 0, sizeof(*request));
}

static int decode_gateway_drain_request_alloc(
    const uint8_t *bytes, size_t byte_count,
    struct decoded_gateway_drain_request *request_out, char *error,
    size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field action_field;
    struct wvm_canonical_field transaction_field;
    struct wvm_canonical_field snapshot_field;
    enum wvm_gateway_drain_action action;
    size_t transaction_ack_count;
    size_t optional_drain_count;
    size_t snapshot_rule_count;
    size_t snapshot_ack_count;

    if (!bytes || !request_out ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_GATEWAY_DRAIN_REQUEST ||
        canonical_field_find(&record, 1, &action_field) != 0 ||
        action_field.value_bytes != 2) {
        set_error(error, error_len, "gateway drain payload is not canonical");
        return -1;
    }
    memset(request_out, 0, sizeof(*request_out));
    action = (enum wvm_gateway_drain_action)read_be16(action_field.value);
    if (action == WVM_GATEWAY_DRAIN_ACTION_PREPARE) {
        if (canonical_field_find(&record, 6, &transaction_field) != 0 ||
            canonical_field_find(&record, 7, &snapshot_field) != 0 ||
            drain_transaction_entry_counts(
                transaction_field.value, transaction_field.value_bytes,
                &transaction_ack_count, &optional_drain_count) != 0 ||
            drain_snapshot_entry_counts(snapshot_field.value,
                                        snapshot_field.value_bytes,
                                        &snapshot_rule_count,
                                        &snapshot_ack_count) != 0) {
            set_error(error, error_len,
                      "gateway drain successor lists are malformed");
            return -1;
        }
        if (transaction_ack_count != 0) {
            request_out->request.successor_transaction.required_ack_set.entries
                .entries = calloc(
                transaction_ack_count,
                sizeof(*request_out->request.successor_transaction
                            .required_ack_set.entries.entries));
            if (!request_out->request.successor_transaction.required_ack_set
                     .entries.entries) {
                goto allocation_failure;
            }
            request_out->request.successor_transaction.required_ack_set.entries
                .capacity = transaction_ack_count;
        }
        if (optional_drain_count != 0) {
            request_out->request.successor_transaction
                .optional_departure_drain_set.entries = calloc(
                optional_drain_count,
                sizeof(*request_out->request.successor_transaction
                            .optional_departure_drain_set.entries));
            if (!request_out->request.successor_transaction
                     .optional_departure_drain_set.entries) {
                goto allocation_failure;
            }
            request_out->request.successor_transaction
                .optional_departure_drain_set.capacity = optional_drain_count;
        }
        if (snapshot_rule_count != 0) {
            request_out->request.successor_snapshot.next_hop_rules.entries =
                calloc(snapshot_rule_count,
                       sizeof(*request_out->request.successor_snapshot
                                   .next_hop_rules.entries));
            if (!request_out->request.successor_snapshot.next_hop_rules.entries) {
                goto allocation_failure;
            }
            request_out->request.successor_snapshot.next_hop_rules.capacity =
                snapshot_rule_count;
        }
        if (snapshot_ack_count != 0) {
            request_out->request.successor_snapshot.required_ack_set.entries
                .entries = calloc(
                snapshot_ack_count,
                sizeof(*request_out->request.successor_snapshot
                            .required_ack_set.entries.entries));
            if (!request_out->request.successor_snapshot.required_ack_set.entries
                     .entries) {
                goto allocation_failure;
            }
            request_out->request.successor_snapshot.required_ack_set.entries
                .capacity = snapshot_ack_count;
        }
    }
    if (wvm_gateway_drain_request_decode(
            bytes, byte_count, &request_out->request, error, error_len) != 0) {
        decoded_gateway_drain_request_free(request_out);
        return -1;
    }
    return 0;

allocation_failure:
    set_error(error, error_len, "cannot allocate gateway drain successor");
    decoded_gateway_drain_request_free(request_out);
    return -1;
}

static int u32_list_count(const uint8_t *bytes, size_t byte_count,
                          size_t *count_out)
{
    uint32_t count;

    if (!bytes || !count_out || byte_count < 4) {
        return -1;
    }
    count = read_be32(bytes);
    if ((size_t)count > (byte_count - 4U) / 4U) {
        return -1;
    }
    *count_out = count;
    return 0;
}

static int node_gateway_count(const uint8_t *bytes, size_t byte_count,
                              size_t *count_out)
{
    struct wvm_canonical_record node_record;
    struct wvm_canonical_record inventory_record;
    struct wvm_canonical_field inventory_field;
    struct wvm_canonical_field gateways_field;

    if (wvm_canonical_record_parse(bytes, byte_count, &node_record) != 0 ||
        node_record.record_type != WVM_RECORD_NODE_RECORD ||
        canonical_field_find(&node_record, 10, &inventory_field) != 0 ||
        wvm_canonical_record_parse(inventory_field.value,
                                   inventory_field.value_bytes,
                                   &inventory_record) != 0 ||
        inventory_record.record_type != WVM_RECORD_NODE_INVENTORY ||
        canonical_field_find(&inventory_record, 11, &gateways_field) != 0 ||
        u32_list_count(gateways_field.value, gateways_field.value_bytes,
                       count_out) != 0) {
        return -1;
    }
    return 0;
}

static int gateway_graph_counts(const uint8_t *bytes, size_t byte_count,
                                size_t *parent_count_out,
                                size_t *child_count_out)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field parents;
    struct wvm_canonical_field children;

    if (wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_GATEWAY_RECORD ||
        canonical_field_find(&record, 8, &parents) != 0 ||
        canonical_field_find(&record, 9, &children) != 0 ||
        u32_list_count(parents.value, parents.value_bytes, parent_count_out) !=
            0 ||
        u32_list_count(children.value, children.value_bytes, child_count_out) !=
            0) {
        return -1;
    }
    return 0;
}

static void decoded_member_record_free(struct decoded_member_record *record)
{
    if (!record) {
        return;
    }
    free(record->node.inventory.hosted_gateway_role_ids);
    free(record->gateway.parent_gateway_ids);
    free(record->gateway.child_gateway_ids);
    memset(record, 0, sizeof(*record));
}

static int decode_member_record_alloc(const uint8_t *bytes, size_t byte_count,
                                      struct decoded_member_record *record,
                                      char *error, size_t error_len)
{
    struct wvm_canonical_record canonical;
    size_t count;

    if (!bytes || !record ||
        wvm_canonical_record_parse(bytes, byte_count, &canonical) != 0) {
        set_error(error, error_len, "member payload is not canonical");
        return -1;
    }
    memset(record, 0, sizeof(*record));
    if (canonical.record_type == WVM_RECORD_NODE_RECORD) {
        if (node_gateway_count(bytes, byte_count, &count) != 0) {
            set_error(error, error_len, "node hosted-gateway list is invalid");
            return -1;
        }
        if (count != 0) {
            record->node.inventory.hosted_gateway_role_ids =
                calloc(count, sizeof(*record->node.inventory
                                         .hosted_gateway_role_ids));
            if (!record->node.inventory.hosted_gateway_role_ids) {
                set_error(error, error_len, "cannot allocate node gateway list");
                return -1;
            }
            record->node.inventory.hosted_gateway_role_id_capacity = count;
        }
        if (wvm_node_record_decode(bytes, byte_count, &record->node, error,
                                   error_len) != 0) {
            decoded_member_record_free(record);
            return -1;
        }
        record->kind = DECODED_MEMBER_NODE;
        return 0;
    }
    if (canonical.record_type == WVM_RECORD_GATEWAY_RECORD) {
        size_t parent_count;
        size_t child_count;

        if (gateway_graph_counts(bytes, byte_count, &parent_count,
                                 &child_count) != 0) {
            set_error(error, error_len, "gateway graph lists are invalid");
            return -1;
        }
        if (parent_count != 0) {
            record->gateway.parent_gateway_ids =
                calloc(parent_count,
                       sizeof(*record->gateway.parent_gateway_ids));
            if (!record->gateway.parent_gateway_ids) {
                set_error(error, error_len, "cannot allocate gateway parents");
                return -1;
            }
            record->gateway.parent_gateway_id_capacity = parent_count;
        }
        if (child_count != 0) {
            record->gateway.child_gateway_ids =
                calloc(child_count,
                       sizeof(*record->gateway.child_gateway_ids));
            if (!record->gateway.child_gateway_ids) {
                set_error(error, error_len, "cannot allocate gateway children");
                decoded_member_record_free(record);
                return -1;
            }
            record->gateway.child_gateway_id_capacity = child_count;
        }
        if (wvm_gateway_record_decode(bytes, byte_count, &record->gateway,
                                      error, error_len) != 0) {
            decoded_member_record_free(record);
            return -1;
        }
        record->kind = DECODED_MEMBER_GATEWAY;
        return 0;
    }
    set_error(error, error_len, "member payload has an unsupported record type");
    return -1;
}

static void derive_member_key(const struct decoded_member_record *record,
                              struct wvm_member_key *member_key,
                              uint32_t *origin_physical_node_id,
                              uint64_t *origin_runtime_instance_id)
{
    memset(member_key, 0, sizeof(*member_key));
    if (record->kind == DECODED_MEMBER_NODE) {
        member_key->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        member_key->role_id = record->node.physical_node_id;
        member_key->instance_id = record->node.node_instance_id;
        *origin_physical_node_id = record->node.physical_node_id;
        *origin_runtime_instance_id = record->node.node_instance_id;
    } else {
        member_key->role_type = WVM_MANIFEST_ROLE_GATEWAY;
        member_key->role_id = record->gateway.gateway_id;
        member_key->instance_id = record->gateway.gateway_instance_id;
        *origin_physical_node_id = record->gateway.hosting_physical_node_id;
        *origin_runtime_instance_id = record->gateway.gateway_instance_id;
    }
}

static int decode_rejoin_request(const uint8_t *bytes, size_t byte_count,
                                 struct decoded_rejoin_request *request_out,
                                 char *error, size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    const uint8_t *member_record = NULL;
    size_t member_record_bytes = 0;
    uint8_t recovery_digest[WVM_SHA256_DIGEST_BYTES];
    size_t offset = 0;
    int have_recovery_digest = 0;
    int next;

    if (!bytes || !request_out ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_MEMBERSHIP_CONTROL_REJOIN_RECORD) {
        set_error(error, error_len, "rejoin payload has the wrong record type");
        return -1;
    }
    memset(request_out, 0, sizeof(*request_out));
    memset(recovery_digest, 0, sizeof(recovery_digest));
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) > 0) {
        switch (field.tag) {
        case 1:
            if (member_record) {
                set_error(error, error_len, "rejoin member record repeats");
                return -1;
            }
            member_record = field.value;
            member_record_bytes = field.value_bytes;
            break;
        case 2:
            if (request_out->has_prior_member ||
                wvm_member_key_decode(field.value, field.value_bytes,
                                      &request_out->prior_member, error,
                                      error_len) != 0) {
                set_error(error, error_len, "rejoin prior member is invalid");
                return -1;
            }
            request_out->has_prior_member = 1;
            break;
        case 3:
            if (have_recovery_digest ||
                field.value_bytes != sizeof(recovery_digest)) {
                set_error(error, error_len,
                          "rejoin recovery evidence is invalid");
                return -1;
            }
            memcpy(recovery_digest, field.value, sizeof(recovery_digest));
            have_recovery_digest = 1;
            break;
        default:
            set_error(error, error_len, "rejoin payload has an unknown field");
            return -1;
        }
    }
    if (next < 0 || !member_record || member_record_bytes == 0 ||
        !have_recovery_digest || bytes_are_zero(recovery_digest,
                                                sizeof(recovery_digest))) {
        set_error(error, error_len, "rejoin payload is incomplete");
        return -1;
    }
    request_out->member_record = member_record;
    request_out->member_record_bytes = member_record_bytes;
    return 0;
}

static int encode_member_record_alloc(
    const struct wvm_membership_controller_member_entry *entry,
    uint8_t **bytes_out, size_t *byte_count_out, char *error, size_t error_len)
{
    size_t capacity = 1024;

    while (capacity <= WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;
        int encoded;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate member result record");
            return -1;
        }
        encoded = entry->kind == WVM_MEMBERSHIP_COMPUTE
                      ? wvm_node_record_encode(&entry->node, bytes, capacity,
                                               &byte_count, error, error_len)
                      : wvm_gateway_record_encode(&entry->gateway, bytes,
                                                  capacity, &byte_count, error,
                                                  error_len);
        if (encoded == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES) {
            capacity = WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len, "member result record exceeds control limit");
    return -1;
}

static int build_success_result(
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    const struct wvm_envelope *request,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    const struct wvm_membership_controller_member_entry *entry;
    uint8_t *record = NULL;
    size_t record_bytes = 0;
    uint16_t state;
    uint64_t revision;
    int status = -1;

    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry ||
        encode_member_record_alloc(entry, &record, &record_bytes, error,
                                   error_len) != 0) {
        return -1;
    }
    initialize_result(result, request, WVM_MEMBERSHIP_CONTROL_SUCCESS);
    if (wvm_canonical_record_digest(record, record_bytes, 0,
                                    result->record_digest) != 0) {
        set_error(error, error_len, "cannot digest durable member record");
        goto out;
    }
    state = entry->kind == WVM_MEMBERSHIP_COMPUTE
                ? entry->node.desired_membership_state
                : entry->gateway.desired_membership_state;
    revision = entry->kind == WVM_MEMBERSHIP_COMPUTE
                   ? entry->node.membership_revision
                   : entry->gateway.membership_revision;
    result->recorded_state = state;
    result->applied_revision = revision;
    status = 0;
out:
    free(record);
    return status;
}

static struct wvm_membership_control_operation *find_operation(
    struct wvm_membership_control *control,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    for (i = 0; i < control->operation_count; i++) {
        if (memcmp(control->operations[i].operation_id, operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &control->operations[i];
        }
    }
    return NULL;
}

static int remember_operation(
    struct wvm_membership_control *control,
    const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    struct wvm_membership_control_operation *operation;

    if (control->operation_count == control->operation_capacity) {
        set_error(error, error_len,
                  "membership control operation capacity is full");
        return -1;
    }
    operation = &control->operations[control->operation_count++];
    memset(operation, 0, sizeof(*operation));
    operation->message_type = request->message_type;
    operation->authenticated_actor = *authenticated_actor;
    memcpy(operation->operation_id, request->operation_id,
           sizeof(operation->operation_id));
    memcpy(operation->semantic_payload_digest,
           request->semantic_payload_digest,
           sizeof(operation->semantic_payload_digest));
    operation->result = *result;
    return 0;
}

static int journal_payload_encode(
    const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_membership_control_result *result,
    uint8_t payload[WVM_MEMBERSHIP_CONTROL_JOURNAL_PAYLOAD_BYTES])
{
    if (!request || !authenticated_actor || !result) {
        return -1;
    }
    memset(payload, 0, WVM_MEMBERSHIP_CONTROL_JOURNAL_PAYLOAD_BYTES);
    write_be16(payload + 0, request->message_type);
    write_be16(payload + 4, authenticated_actor->role_type);
    write_be32(payload + 8, authenticated_actor->role_id);
    write_be64(payload + 12, authenticated_actor->instance_id);
    memcpy(payload + 20, request->operation_id,
           sizeof(request->operation_id));
    memcpy(payload + 36, request->semantic_payload_digest,
           sizeof(request->semantic_payload_digest));
    return wvm_membership_control_result_encode(result, payload + 68);
}

static int journal_payload_decode(
    struct wvm_membership_control *control,
    const uint8_t payload[WVM_MEMBERSHIP_CONTROL_JOURNAL_PAYLOAD_BYTES],
    char *error, size_t error_len)
{
    struct wvm_membership_control_operation decoded;

    if (!control || !payload || read_be16(payload + 2) != 0 ||
        read_be16(payload + 6) != 0 ||
        control->operation_count == control->operation_capacity) {
        set_error(error, error_len, "membership control journal payload invalid");
        return -1;
    }
    memset(&decoded, 0, sizeof(decoded));
    decoded.message_type = read_be16(payload + 0);
    decoded.authenticated_actor.role_type =
        (enum wvm_manifest_role_type)read_be16(payload + 4);
    decoded.authenticated_actor.role_id = read_be32(payload + 8);
    decoded.authenticated_actor.instance_id = read_be64(payload + 12);
    memcpy(decoded.operation_id, payload + 20, sizeof(decoded.operation_id));
    memcpy(decoded.semantic_payload_digest, payload + 36,
           sizeof(decoded.semantic_payload_digest));
    if (!control_message_supported(decoded.message_type) ||
        wvm_member_key_validate(&decoded.authenticated_actor, error,
                                error_len) != 0 ||
        bytes_are_zero(decoded.operation_id, sizeof(decoded.operation_id)) ||
        wvm_membership_control_result_decode(payload + 68, &decoded.result) !=
            0 ||
        decoded.result.status_code != WVM_MEMBERSHIP_CONTROL_SUCCESS ||
        memcmp(decoded.result.in_reply_to_operation_id, decoded.operation_id,
               sizeof(decoded.operation_id)) != 0 ||
        decoded.result.recorded_state == 0 ||
        decoded.result.applied_revision == 0 ||
        bytes_are_zero(decoded.result.record_digest,
                       sizeof(decoded.result.record_digest)) ||
        find_operation(control, decoded.operation_id) != NULL) {
        set_error(error, error_len, "membership control journal entry invalid");
        return -1;
    }
    control->operations[control->operation_count++] = decoded;
    return 0;
}

static int journal_append(struct wvm_membership_control *control,
                          const struct wvm_envelope *request,
                          const struct wvm_member_key *authenticated_actor,
                          const struct wvm_membership_control_result *result,
                          char *error, size_t error_len)
{
    uint8_t header[WVM_MEMBERSHIP_CONTROL_JOURNAL_HEADER_BYTES];
    uint8_t payload[WVM_MEMBERSHIP_CONTROL_JOURNAL_PAYLOAD_BYTES];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    if (!control || control->journal_fd < 0 ||
        control->next_journal_sequence == 0 ||
        journal_payload_encode(request, authenticated_actor, result, payload) !=
            0) {
        set_error(error, error_len, "membership control journal input invalid");
        return -1;
    }
    memset(header, 0, sizeof(header));
    memcpy(header, membership_control_journal_magic,
           sizeof(membership_control_journal_magic));
    write_be16(header + 8, WVM_MEMBERSHIP_CONTROL_JOURNAL_VERSION);
    write_be64(header + 12, control->next_journal_sequence);
    write_be32(header + 20, sizeof(payload));
    wvm_sha256_digest(payload, sizeof(payload), digest);
    memcpy(header + 24, digest, sizeof(digest));
    if (lseek(control->journal_fd, 0, SEEK_END) < 0 ||
        write_full(control->journal_fd, header, sizeof(header)) != 0 ||
        write_full(control->journal_fd, payload, sizeof(payload)) != 0 ||
        fsync(control->journal_fd) != 0) {
        set_error(error, error_len, "cannot persist membership control: %s",
                  strerror(errno));
        return -1;
    }
    control->next_journal_sequence++;
    return 0;
}

int wvm_membership_control_open(struct wvm_membership_control *control,
                                const char *journal_path, char *error,
                                size_t error_len)
{
    uint64_t expected_sequence = 1;
    off_t valid_end = 0;

    if (!control || control->lock_initialized || control->journal_fd >= 0 ||
        !control->controller || !control->operations ||
        control->operation_capacity == 0 || control->controller->journal_fd < 0 ||
        !journal_path || journal_path[0] == '\0') {
        set_error(error, error_len, "membership control initialization invalid");
        return -1;
    }
    if (pthread_mutex_init(&control->lock, NULL) != 0) {
        set_error(error, error_len, "cannot initialize membership control lock");
        return -1;
    }
    control->lock_initialized = 1;
    control->journal_fd =
        open(journal_path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (control->journal_fd < 0) {
        set_error(error, error_len, "cannot open membership control journal: %s",
                  strerror(errno));
        wvm_membership_control_close(control);
        return -1;
    }
    for (;;) {
        uint8_t header[WVM_MEMBERSHIP_CONTROL_JOURNAL_HEADER_BYTES];
        uint8_t payload[WVM_MEMBERSHIP_CONTROL_JOURNAL_PAYLOAD_BYTES];
        uint8_t digest[WVM_SHA256_DIGEST_BYTES];
        uint64_t sequence;
        uint32_t payload_bytes;
        int read_result = read_full(control->journal_fd, header, sizeof(header));

        if (read_result == 0) {
            break;
        }
        if (read_result < 0) {
            break;
        }
        sequence = read_be64(header + 12);
        payload_bytes = read_be32(header + 20);
        if (memcmp(header, membership_control_journal_magic,
                   sizeof(membership_control_journal_magic)) != 0 ||
            read_be16(header + 8) != WVM_MEMBERSHIP_CONTROL_JOURNAL_VERSION ||
            read_be16(header + 10) != 0 || sequence != expected_sequence ||
            payload_bytes != sizeof(payload)) {
            set_error(error, error_len, "membership control journal header invalid");
            wvm_membership_control_close(control);
            return -1;
        }
        if (read_full(control->journal_fd, payload, sizeof(payload)) != 1) {
            break;
        }
        wvm_sha256_digest(payload, sizeof(payload), digest);
        if (memcmp(digest, header + 24, sizeof(digest)) != 0 ||
            journal_payload_decode(control, payload, error, error_len) != 0) {
            set_error(error, error_len, "membership control journal corrupt");
            wvm_membership_control_close(control);
            return -1;
        }
        valid_end = lseek(control->journal_fd, 0, SEEK_CUR);
        expected_sequence++;
    }
    if (ftruncate(control->journal_fd, valid_end) != 0 ||
        lseek(control->journal_fd, 0, SEEK_END) < 0) {
        set_error(error, error_len, "cannot finalize membership control: %s",
                  strerror(errno));
        wvm_membership_control_close(control);
        return -1;
    }
    control->next_journal_sequence = expected_sequence;
    return 0;
}

void wvm_membership_control_close(struct wvm_membership_control *control)
{
    if (!control) {
        return;
    }
    if (control->journal_fd >= 0) {
        close(control->journal_fd);
    }
    if (control->lock_initialized) {
        pthread_mutex_destroy(&control->lock);
        control->lock_initialized = 0;
    }
    control->journal_fd = -1;
    control->operation_count = 0;
    if (control->operations && control->operation_capacity != 0) {
        memset(control->operations, 0,
               control->operation_capacity * sizeof(*control->operations));
    }
}

static int classify_controller_error(const char *error)
{
    if (error && strstr(error, "authorized")) {
        return WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE;
    }
    if (error && strstr(error, "unknown member")) {
        return WVM_MEMBERSHIP_CONTROL_NOT_FOUND;
    }
    if (error &&
        (strstr(error, "capacity") || strstr(error, "cannot allocate"))) {
        return WVM_MEMBERSHIP_CONTROL_BACKPRESSURE;
    }
    return WVM_MEMBERSHIP_CONTROL_PRECONDITION_FAILED;
}

static int gateway_drain_authorized(
    const struct wvm_membership_control *control,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_gateway_drain_request *request, char *error,
    size_t error_len)
{
    if (!control || !authenticated_actor || !request ||
        authenticated_actor->role_type != WVM_MANIFEST_ROLE_EXECUTOR ||
        !control->authorize_management ||
        control->authorize_management(
            control->authorize_management_context, request->action,
            authenticated_actor, &request->target_gateway_member_key, error,
            error_len) != 0) {
        set_error(error, error_len,
                  "gateway drain management actor is not authorized");
        return -1;
    }
    return 0;
}

static int member_cordon_authorized(
    const struct wvm_membership_control *control,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_member_cordon_request *request, char *error,
    size_t error_len)
{
    if (!control || !authenticated_actor || !request ||
        authenticated_actor->role_type != WVM_MANIFEST_ROLE_EXECUTOR ||
        !control->authorize_membership ||
        control->authorize_membership(
            control->authorize_membership_context,
            WVM_MEMBERSHIP_CONTROL_MEMBERSHIP_ACTION_CORDON,
            authenticated_actor, &request->target_member_key, error,
            error_len) != 0) {
        set_error(error, error_len,
                  "member cordon management actor is not authorized");
        return -1;
    }
    return 0;
}

static int apply_gateway_drain_record(
    struct wvm_membership_control *control,
    const struct wvm_gateway_drain_request *request, char *error,
    size_t error_len)
{
    const struct wvm_route_transaction_record *transaction = NULL;
    const struct wvm_route_snapshot_record *snapshot = NULL;

    if (request->action == WVM_GATEWAY_DRAIN_ACTION_PREPARE) {
        transaction = &request->successor_transaction;
        snapshot = &request->successor_snapshot;
    }
    return wvm_membership_controller_gateway_drain_apply(
        control->controller, request->action, &request->target_gateway_member_key,
        transaction, snapshot, request->route_operation_id,
        request->expected_membership_revision,
        request->expected_topology_revision,
        request->expected_admission_eligibility_revision, error, error_len);
}

static int apply_membership_record(
    struct wvm_membership_control *control,
    const struct wvm_member_key *authenticated_actor,
    const struct decoded_member_record *record,
    const struct wvm_member_key *member_key, int rejoin, char *error,
    size_t error_len)
{
    int result;

    if (record->kind == DECODED_MEMBER_NODE) {
        result = wvm_membership_controller_register_node(
            control->controller, authenticated_actor, &record->node, error,
            error_len);
    } else {
        result = wvm_membership_controller_register_gateway(
            control->controller, authenticated_actor, &record->gateway, error,
            error_len);
    }
    if (result != 0 || !rejoin) {
        return result;
    }
    return wvm_membership_controller_begin_validation(control->controller,
                                                       member_key, error,
                                                       error_len);
}

int wvm_membership_control_apply(
    struct wvm_membership_control *control,
    const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result_out, char *error,
    size_t error_len)
{
    struct wvm_membership_control_operation *existing;
    struct decoded_member_record record;
    struct decoded_rejoin_request rejoin_request;
    struct decoded_gateway_drain_request drain_request;
    struct decoded_member_cordon_request cordon_request;
    struct wvm_member_key member_key;
    struct wvm_membership_control_result result;
    uint32_t expected_origin_node;
    uint64_t expected_origin_instance;
    const uint8_t *member_bytes;
    size_t member_byte_count;
    int rejoin;
    int apply_result;

    if (!result_out || !control || control->journal_fd < 0 ||
        !control->controller || !authenticated_actor) {
        set_error(error, error_len, "membership control receiver is unavailable");
        return -1;
    }
    if (envelope_is_valid(request, error, error_len) != 0) {
        initialize_result(&result, request,
                          WVM_MEMBERSHIP_CONTROL_INVALID_ENVELOPE);
        *result_out = result;
        return 0;
    }
    if (wvm_member_key_validate(authenticated_actor, error, error_len) != 0) {
        initialize_result(&result, request,
                          WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE);
        *result_out = result;
        return 0;
    }
    pthread_mutex_lock(&control->lock);
    existing = find_operation(control, request->operation_id);
    if (existing) {
        if (existing->message_type != request->message_type ||
            !member_key_equal(&existing->authenticated_actor,
                              authenticated_actor) ||
            memcmp(existing->semantic_payload_digest,
                   request->semantic_payload_digest,
                   sizeof(existing->semantic_payload_digest)) != 0) {
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_OPERATION_ID_CONFLICT);
            *result_out = result;
        } else {
            *result_out = existing->result;
        }
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    if (control->operation_count == control->operation_capacity) {
        initialize_result(&result, request, WVM_MEMBERSHIP_CONTROL_BACKPRESSURE);
        *result_out = result;
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    memset(&drain_request, 0, sizeof(drain_request));
    memset(&cordon_request, 0, sizeof(cordon_request));
    if (request->message_type == WVM_ENVELOPE_MSG_CORDON) {
        if (wvm_member_cordon_request_decode(
                request->payload, request->payload_bytes,
                &cordon_request.request, error, error_len) != 0) {
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_INVALID_RECORD);
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        if (member_cordon_authorized(control, authenticated_actor,
                                     &cordon_request.request, error,
                                     error_len) != 0) {
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE);
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        apply_result = wvm_membership_controller_cordon_apply(
            control->controller, &cordon_request.request.target_member_key,
            cordon_request.request.expected_membership_revision,
            cordon_request.request.expected_topology_revision,
            cordon_request.request.expected_admission_eligibility_revision,
            error, error_len);
        if (apply_result != 0) {
            initialize_result(&result, request,
                              classify_controller_error(error));
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        if (build_success_result(
                control->controller, &cordon_request.request.target_member_key,
                request, &result, error, error_len) != 0 ||
            journal_append(control, request, authenticated_actor, &result, error,
                           error_len) != 0 ||
            remember_operation(control, request, authenticated_actor, &result,
                               error, error_len) != 0) {
            pthread_mutex_unlock(&control->lock);
            return -1;
        }
        *result_out = result;
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    if (request->message_type == WVM_ENVELOPE_MSG_DRAIN_COMPUTE) {
        if (wvm_member_cordon_request_decode(
                request->payload, request->payload_bytes,
                &cordon_request.request, error, error_len) != 0) {
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_INVALID_RECORD);
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        if (!control->authorize_membership ||
            authenticated_actor->role_type != WVM_MANIFEST_ROLE_EXECUTOR ||
            control->authorize_membership(
                control->authorize_membership_context,
                WVM_MEMBERSHIP_CONTROL_MEMBERSHIP_ACTION_DRAIN_COMPUTE,
                authenticated_actor, &cordon_request.request.target_member_key,
                error, error_len) != 0) {
            set_error(error, error_len,
                      "compute drain management actor is not authorized");
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE);
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        apply_result = wvm_membership_controller_begin_drain_apply(
            control->controller, &cordon_request.request.target_member_key,
            cordon_request.request.expected_membership_revision,
            cordon_request.request.expected_topology_revision,
            cordon_request.request.expected_admission_eligibility_revision,
            error, error_len);
        if (apply_result != 0) {
            initialize_result(&result, request,
                              classify_controller_error(error));
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        if (build_success_result(
                control->controller, &cordon_request.request.target_member_key,
                request, &result, error, error_len) != 0 ||
            journal_append(control, request, authenticated_actor, &result, error,
                           error_len) != 0 ||
            remember_operation(control, request, authenticated_actor, &result,
                               error, error_len) != 0) {
            pthread_mutex_unlock(&control->lock);
            return -1;
        }
        *result_out = result;
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    if (request->message_type == WVM_ENVELOPE_MSG_DRAIN) {
        if (decode_gateway_drain_request_alloc(
                request->payload, request->payload_bytes, &drain_request, error,
                error_len) != 0) {
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_INVALID_RECORD);
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        if (gateway_drain_authorized(control, authenticated_actor,
                                     &drain_request.request, error,
                                     error_len) != 0) {
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE);
            *result_out = result;
            decoded_gateway_drain_request_free(&drain_request);
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        apply_result = apply_gateway_drain_record(control, &drain_request.request,
                                                  error, error_len);
        if (apply_result != 0) {
            initialize_result(&result, request,
                              classify_controller_error(error));
            *result_out = result;
            decoded_gateway_drain_request_free(&drain_request);
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        if (build_success_result(
                control->controller,
                &drain_request.request.target_gateway_member_key, request,
                &result, error, error_len) != 0 ||
            journal_append(control, request, authenticated_actor, &result, error,
                           error_len) != 0 ||
            remember_operation(control, request, authenticated_actor, &result,
                               error, error_len) != 0) {
            decoded_gateway_drain_request_free(&drain_request);
            pthread_mutex_unlock(&control->lock);
            return -1;
        }
        *result_out = result;
        decoded_gateway_drain_request_free(&drain_request);
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    memset(&record, 0, sizeof(record));
    memset(&rejoin_request, 0, sizeof(rejoin_request));
    rejoin = request->message_type == WVM_ENVELOPE_MSG_REJOIN;
    if (rejoin) {
        if (decode_rejoin_request(request->payload, request->payload_bytes,
                                  &rejoin_request, error, error_len) != 0) {
            initialize_result(&result, request,
                              WVM_MEMBERSHIP_CONTROL_INVALID_RECORD);
            *result_out = result;
            pthread_mutex_unlock(&control->lock);
            return 0;
        }
        member_bytes = rejoin_request.member_record;
        member_byte_count = rejoin_request.member_record_bytes;
    } else {
        member_bytes = request->payload;
        member_byte_count = request->payload_bytes;
    }
    if (decode_member_record_alloc(member_bytes, member_byte_count, &record,
                                   error, error_len) != 0) {
        initialize_result(&result, request,
                          WVM_MEMBERSHIP_CONTROL_INVALID_RECORD);
        *result_out = result;
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    derive_member_key(&record, &member_key, &expected_origin_node,
                      &expected_origin_instance);
    if (!member_key_equal(authenticated_actor, &member_key) ||
        request->origin_physical_node_id != expected_origin_node ||
        request->origin_runtime_instance_id != expected_origin_instance ||
        (rejoin && rejoin_request.has_prior_member &&
         (rejoin_request.prior_member.role_type != member_key.role_type ||
          rejoin_request.prior_member.role_id != member_key.role_id ||
          rejoin_request.prior_member.instance_id == member_key.instance_id))) {
        initialize_result(&result, request,
                          WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE);
        *result_out = result;
        decoded_member_record_free(&record);
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    apply_result = apply_membership_record(
        control, authenticated_actor, &record, &member_key, rejoin,
        error, error_len);
    if (apply_result != 0) {
        initialize_result(&result, request, classify_controller_error(error));
        *result_out = result;
        decoded_member_record_free(&record);
        pthread_mutex_unlock(&control->lock);
        return 0;
    }
    if (build_success_result(control->controller, &member_key, request, &result,
                             error, error_len) != 0 ||
        journal_append(control, request, authenticated_actor, &result, error,
                       error_len) != 0 ||
        remember_operation(control, request, authenticated_actor, &result,
                           error, error_len) != 0) {
        decoded_member_record_free(&record);
        pthread_mutex_unlock(&control->lock);
        return -1;
    }
    *result_out = result;
    decoded_member_record_free(&record);
    pthread_mutex_unlock(&control->lock);
    return 0;
}

int wvm_membership_control_dispatch(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len)
{
    struct wvm_membership_control_dispatch_context *context = opaque;
    struct wvm_membership_control_result result;

    if (!context || !context->control || !context->result_sink || !request ||
        !authenticated_actor) {
        set_error(error, error_len,
                  "membership control dispatch context is incomplete");
        return -EINVAL;
    }
    if (wvm_membership_control_apply(
            context->control, request, authenticated_actor, &result, error,
            error_len) != 0) {
        return -EIO;
    }
    return context->result_sink(context->result_sink_context, request, &result,
                                error, error_len);
}

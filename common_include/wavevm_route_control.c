#define _GNU_SOURCE

#include "wavevm_route_control.h"

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
#include "wavevm_membership.h"
#include "wavevm_route_delivery.h"

#define WVM_ROUTE_CONTROL_JOURNAL_VERSION 1U
#define WVM_ROUTE_CONTROL_JOURNAL_HEADER_BYTES 56U

static const uint8_t route_control_journal_magic[8] = {
    'W', 'V', 'M', 'R', 'C', 'T', 'L', '1',
};

struct wvm_route_control_operation {
    uint16_t message_type;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_route_control_result result;
};

struct route_transaction_storage {
    struct wvm_route_transaction_record transaction;
    struct wvm_required_ack_entry *required_ack_entries;
    struct wvm_required_ack_entry *optional_drain_entries;
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
 * Returns one for a full buffer, zero for clean EOF before any bytes, and
 * minus one for a torn or unreadable record.
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

static int operation_type_valid(uint16_t message_type)
{
    return message_type == WVM_ENVELOPE_MSG_ROUTE_PREPARE ||
           message_type == WVM_ENVELOPE_MSG_ROUTE_COMMIT ||
           message_type == WVM_ENVELOPE_MSG_ROUTE_ABORT ||
           message_type == WVM_ENVELOPE_MSG_ROUTE_RETIRE;
}

static int route_key_equal(const struct wvm_route_snapshot_key *left,
                           const struct wvm_route_snapshot_key *right)
{
    return left && right &&
           left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  sizeof(left->snapshot_digest)) == 0;
}

static int request_matches_route_key(
    const struct wvm_envelope *request,
    const struct wvm_route_snapshot_key *key, char *error, size_t error_len)
{
    if (!request || !key || request->vm_id != key->scope_key.vm_id ||
        request->vm_incarnation != key->scope_key.vm_incarnation) {
        set_error(error, error_len,
                  "route control envelope does not match route scope");
        return -1;
    }
    return 0;
}

/*
 * RouteSnapshot encodes its required ACK entries with the snapshot key's
 * digest normalized away to avoid a self-reference.  RouteTransaction uses
 * the ordinary canonical ACK-set digest, so derive that form before binding
 * an abort to a previously prepared snapshot.
 */
static int required_ack_set_full_digest(
    const struct wvm_required_ack_set *ack_set,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len)
{
    struct wvm_required_ack_set standard_ack_set;
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    uint8_t *bytes = NULL;
    size_t capacity = 1024;
    size_t encoded_bytes;
    size_t offset;
    int next;
    int result = -1;

    if (!ack_set || !digest) {
        set_error(error, error_len, "route ACK set is missing");
        return -1;
    }
    standard_ack_set = *ack_set;
    memset(standard_ack_set.entries_digest, 0,
           sizeof(standard_ack_set.entries_digest));
    while (capacity <= WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
        bytes = malloc(capacity);
        if (!bytes) {
            set_error(error, error_len, "cannot allocate route ACK encoding");
            return -1;
        }
        if (wvm_required_ack_set_encode(&standard_ack_set, bytes, capacity,
                                        &encoded_bytes, error, error_len) == 0) {
            break;
        }
        free(bytes);
        bytes = NULL;
        if (capacity == WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
            return -1;
        }
        capacity *= 2U;
        if (capacity > WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
            capacity = WVM_ENVELOPE_MAX_LOCAL_PAYLOAD;
        }
    }
    if (!bytes ||
        wvm_canonical_record_parse(bytes, encoded_bytes, &record) != 0 ||
        record.record_type != WVM_RECORD_REQUIRED_ACK_SET) {
        set_error(error, error_len, "route ACK set encoding is malformed");
        goto out;
    }
    offset = 0;
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 2 && field.value_bytes == WVM_SHA256_DIGEST_BYTES) {
            memcpy(digest, field.value, WVM_SHA256_DIGEST_BYTES);
            result = 0;
            break;
        }
    }
    if (next < 0 || result != 0) {
        set_error(error, error_len, "route ACK set digest is missing");
    }
out:
    free(bytes);
    return result;
}

void wvm_route_control_snapshot_free(struct wvm_route_control_snapshot *storage)
{
    if (!storage) {
        return;
    }
    free(storage->rules);
    free(storage->ack_entries);
    memset(storage, 0, sizeof(*storage));
}

static void route_transaction_storage_free(
    struct route_transaction_storage *storage)
{
    if (!storage) {
        return;
    }
    free(storage->required_ack_entries);
    free(storage->optional_drain_entries);
    memset(storage, 0, sizeof(*storage));
}

static int record_list_count(const uint8_t *bytes, size_t byte_count,
                             size_t *count_out)
{
    uint32_t encoded_count;
    size_t offset = 4;
    uint32_t i;

    if (!bytes || !count_out || byte_count < 4) {
        return -1;
    }
    encoded_count = read_be32(bytes);
    for (i = 0; i < encoded_count; i++) {
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
    *count_out = encoded_count;
    return 0;
}

static int route_transaction_list_counts(const uint8_t *bytes,
                                         size_t byte_count,
                                         size_t *required_ack_count_out,
                                         size_t *optional_drain_count_out)
{
    struct wvm_canonical_record transaction_record;
    struct wvm_canonical_record ack_set_record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int have_ack_set = 0;
    int have_drain_set = 0;
    int next;

    if (!bytes || !required_ack_count_out || !optional_drain_count_out ||
        wvm_canonical_record_parse(bytes, byte_count, &transaction_record) != 0 ||
        transaction_record.record_type != WVM_RECORD_ROUTE_TRANSACTION) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&transaction_record, &offset,
                                               &field)) == 1) {
        if (field.tag == 4) {
            struct wvm_canonical_field ack_field;
            size_t ack_offset = 0;
            int ack_next;

            if (have_ack_set ||
                wvm_canonical_record_parse(field.value, field.value_bytes,
                                           &ack_set_record) != 0 ||
                ack_set_record.record_type != WVM_RECORD_REQUIRED_ACK_SET) {
                return -1;
            }
            while ((ack_next = wvm_canonical_record_next(&ack_set_record,
                                                          &ack_offset,
                                                          &ack_field)) == 1) {
                if (ack_field.tag == 1) {
                    if (record_list_count(ack_field.value,
                                          ack_field.value_bytes,
                                          required_ack_count_out) != 0) {
                        return -1;
                    }
                    have_ack_set = 1;
                    break;
                }
            }
            if (ack_next < 0 || !have_ack_set) {
                return -1;
            }
        } else if (field.tag == 5) {
            if (have_drain_set ||
                record_list_count(field.value, field.value_bytes,
                                  optional_drain_count_out) != 0) {
                return -1;
            }
            have_drain_set = 1;
        }
    }
    return next == 0 && have_ack_set && have_drain_set ? 0 : -1;
}

static int route_transaction_decode_alloc(
    const uint8_t *bytes, size_t byte_count,
    struct route_transaction_storage *storage, char *error, size_t error_len)
{
    size_t required_ack_count;
    size_t optional_drain_count;

    if (!storage ||
        route_transaction_list_counts(bytes, byte_count, &required_ack_count,
                                      &optional_drain_count) != 0 ||
        required_ack_count > WVM_ROUTE_RUNTIME_MAX_ENTRIES ||
        optional_drain_count > WVM_ROUTE_RUNTIME_MAX_ENTRIES) {
        set_error(error, error_len, "route abort payload is not a transaction");
        return -1;
    }
    memset(storage, 0, sizeof(*storage));
    storage->required_ack_entries =
        calloc(required_ack_count, sizeof(*storage->required_ack_entries));
    storage->optional_drain_entries =
        optional_drain_count
            ? calloc(optional_drain_count,
                     sizeof(*storage->optional_drain_entries))
            : NULL;
    if (!storage->required_ack_entries ||
        (optional_drain_count && !storage->optional_drain_entries)) {
        set_error(error, error_len,
                  "cannot allocate route abort transaction lists");
        route_transaction_storage_free(storage);
        return -1;
    }
    storage->transaction.required_ack_set.entries.entries =
        storage->required_ack_entries;
    storage->transaction.required_ack_set.entries.capacity = required_ack_count;
    storage->transaction.optional_departure_drain_set.entries =
        storage->optional_drain_entries;
    storage->transaction.optional_departure_drain_set.capacity =
        optional_drain_count;
    if (wvm_route_transaction_record_decode(bytes, byte_count,
                                            &storage->transaction, error,
                                            error_len) != 0) {
        route_transaction_storage_free(storage);
        return -1;
    }
    return 0;
}

static int route_snapshot_list_counts(const uint8_t *bytes, size_t byte_count,
                                      size_t *rule_count_out,
                                      size_t *ack_count_out, char *error,
                                      size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    const uint8_t *rule_list = NULL;
    const uint8_t *ack_record = NULL;
    size_t rule_list_bytes = 0;
    size_t ack_record_bytes = 0;
    size_t offset = 0;
    int next;

    if (!bytes || !rule_count_out || !ack_count_out ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_ROUTE_SNAPSHOT) {
        set_error(error, error_len, "route prepare payload is not a snapshot");
        return -1;
    }
    *rule_count_out = 0;
    *ack_count_out = 0;
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) > 0) {
        if (field.tag == 4) {
            rule_list = field.value;
            rule_list_bytes = field.value_bytes;
        } else if (field.tag == 5) {
            ack_record = field.value;
            ack_record_bytes = field.value_bytes;
        }
    }
    if (next < 0 || !rule_list || rule_list_bytes < 4 || !ack_record ||
        wvm_canonical_record_parse(ack_record, ack_record_bytes, &record) !=
            0 ||
        record.record_type != WVM_RECORD_REQUIRED_ACK_SET) {
        set_error(error, error_len, "route snapshot list encoding is invalid");
        return -1;
    }
    *rule_count_out = read_be32(rule_list);
    offset = 0;
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) > 0) {
        if (field.tag == 1) {
            if (field.value_bytes < 4) {
                set_error(error, error_len, "route ACK list is invalid");
                return -1;
            }
            *ack_count_out = read_be32(field.value);
            break;
        }
    }
    if (next < 0 || *rule_count_out == 0 || *ack_count_out == 0 ||
        *rule_count_out > WVM_ROUTE_RUNTIME_MAX_ENTRIES ||
        *ack_count_out > WVM_ROUTE_RUNTIME_MAX_ENTRIES) {
        set_error(error, error_len, "route snapshot list exceeds limits");
        return -1;
    }
    return 0;
}

static int route_snapshot_decode_alloc(const uint8_t *bytes, size_t byte_count,
                                       struct wvm_route_control_snapshot *storage,
                                       char *error, size_t error_len)
{
    size_t rule_count;
    size_t ack_count;

    if (!storage ||
        route_snapshot_list_counts(bytes, byte_count, &rule_count, &ack_count,
                                   error, error_len) != 0) {
        return -1;
    }
    memset(storage, 0, sizeof(*storage));
    storage->rules = calloc(rule_count, sizeof(*storage->rules));
    storage->ack_entries = calloc(ack_count, sizeof(*storage->ack_entries));
    if (!storage->rules || !storage->ack_entries) {
        set_error(error, error_len, "cannot allocate route snapshot lists");
        wvm_route_control_snapshot_free(storage);
        return -1;
    }
    storage->snapshot.next_hop_rules.entries = storage->rules;
    storage->snapshot.next_hop_rules.capacity = rule_count;
    storage->snapshot.required_ack_set.entries.entries = storage->ack_entries;
    storage->snapshot.required_ack_set.entries.capacity = ack_count;
    if (wvm_route_snapshot_record_decode(bytes, byte_count, &storage->snapshot,
                                         error, error_len) != 0) {
        wvm_route_control_snapshot_free(storage);
        return -1;
    }
    return 0;
}

static struct wvm_route_control_operation *find_operation(
    struct wvm_route_control *control, const struct wvm_envelope *request)
{
    size_t i;

    for (i = 0; i < control->operation_count; i++) {
        struct wvm_route_control_operation *operation =
            &control->operations[i];

        if (operation->message_type == request->message_type &&
            memcmp(operation->operation_id, request->operation_id,
                   sizeof(operation->operation_id)) == 0) {
            return operation;
        }
    }
    return NULL;
}

static int prepared_snapshot_matches_abort(
    const struct wvm_route_control *control,
    const struct wvm_route_transaction_record *transaction)
{
    size_t i;

    if (!control || !transaction) {
        return 0;
    }
    for (i = 0; i < control->operation_count; i++) {
        const struct wvm_route_control_operation *operation =
            &control->operations[i];

        if (operation->message_type == WVM_ENVELOPE_MSG_ROUTE_PREPARE &&
            operation->result.recorded_state == 1 &&
            route_key_equal(&operation->result.route_snapshot_key,
                            &transaction->route_snapshot_key) &&
            memcmp(operation->result.required_ack_set_digest,
                   transaction->required_ack_set.entries_digest,
                   WVM_SHA256_DIGEST_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

static int validate_route_abort(struct wvm_route_control *control,
                                const struct wvm_envelope *request,
                                char *error, size_t error_len)
{
    struct route_transaction_storage storage;
    int result = -1;

    memset(&storage, 0, sizeof(storage));
    if (!control || !request ||
        route_transaction_decode_alloc(request->payload, request->payload_bytes,
                                       &storage, error, error_len) != 0 ||
        request_matches_route_key(request, &storage.transaction.route_snapshot_key,
                                  error, error_len) != 0 ||
        storage.transaction.state != WVM_ROUTE_TRANSACTION_ABORTED ||
        !prepared_snapshot_matches_abort(control, &storage.transaction) ||
        !wvm_route_runtime_has_prepared_snapshot(
            control->runtime, &storage.transaction.route_snapshot_key)) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "route abort does not match a prepared snapshot");
        }
        goto out;
    }
    result = 0;
out:
    route_transaction_storage_free(&storage);
    return result;
}

static int remember_operation(struct wvm_route_control *control,
                              const struct wvm_envelope *request,
                              const struct wvm_route_control_result *result,
                              char *error, size_t error_len)
{
    struct wvm_route_control_operation *operations;
    size_t new_capacity;
    struct wvm_route_control_operation *operation;

    if (control->operation_count == WVM_ROUTE_CONTROL_MAX_OPERATIONS) {
        set_error(error, error_len, "route control operation capacity is full");
        return -1;
    }
    if (control->operation_count == control->operation_capacity) {
        new_capacity = control->operation_capacity
                           ? control->operation_capacity * 2U
                           : 16U;
        if (new_capacity > WVM_ROUTE_CONTROL_MAX_OPERATIONS) {
            new_capacity = WVM_ROUTE_CONTROL_MAX_OPERATIONS;
        }
        operations = realloc(control->operations,
                             new_capacity * sizeof(*operations));
        if (!operations) {
            set_error(error, error_len,
                      "cannot allocate route control operation table");
            return -1;
        }
        control->operations = operations;
        control->operation_capacity = new_capacity;
    }
    operation = &control->operations[control->operation_count++];
    memset(operation, 0, sizeof(*operation));
    operation->message_type = request->message_type;
    memcpy(operation->operation_id, request->operation_id,
           sizeof(operation->operation_id));
    memcpy(operation->semantic_payload_digest,
           request->semantic_payload_digest,
           sizeof(operation->semantic_payload_digest));
    operation->result = *result;
    return 0;
}

static int apply_unlogged(struct wvm_route_control *control,
                          const struct wvm_envelope *request, char *error,
                          size_t error_len,
                          struct wvm_route_control_result *result_out)
{
    struct wvm_route_control_snapshot storage;
    struct route_transaction_storage transaction_storage;
    struct wvm_route_snapshot_key key;
    int result;

    if (!control || !control->runtime || !request ||
        !operation_type_valid(request->message_type)) {
        set_error(error, error_len, "route control request is invalid");
        return -1;
    }
    if (request->message_type == WVM_ENVELOPE_MSG_ROUTE_PREPARE) {
        memset(&storage, 0, sizeof(storage));
        if (route_snapshot_decode_alloc(request->payload, request->payload_bytes,
                                        &storage, error, error_len) != 0 ||
            request_matches_route_key(request,
                                      &storage.snapshot.route_snapshot_key,
                                      error, error_len) != 0) {
            wvm_route_control_snapshot_free(&storage);
            return -1;
        }
        result = wvm_route_runtime_prepare(control->runtime, &storage.snapshot,
                                           error, error_len);
        if (result == 0 && result_out) {
            result_out->recorded_state = 1;
            result_out->route_snapshot_key =
                storage.snapshot.route_snapshot_key;
            if (required_ack_set_full_digest(
                    &storage.snapshot.required_ack_set,
                    result_out->required_ack_set_digest, error,
                    error_len) != 0) {
                wvm_route_control_snapshot_free(&storage);
                return -1;
            }
            result_out->operation_retention_horizon_ms =
                storage.snapshot.operation_retention_horizon_ms;
        }
        wvm_route_control_snapshot_free(&storage);
        return result;
    }
    if (request->message_type == WVM_ENVELOPE_MSG_ROUTE_ABORT) {
        memset(&transaction_storage, 0, sizeof(transaction_storage));
        if (route_transaction_decode_alloc(request->payload,
                                           request->payload_bytes,
                                           &transaction_storage, error,
                                           error_len) != 0 ||
            request_matches_route_key(
                request, &transaction_storage.transaction.route_snapshot_key,
                error, error_len) != 0 ||
            transaction_storage.transaction.state !=
                WVM_ROUTE_TRANSACTION_ABORTED ||
            !prepared_snapshot_matches_abort(control,
                                             &transaction_storage.transaction)) {
            route_transaction_storage_free(&transaction_storage);
            if (error && error[0] == '\0') {
                set_error(error, error_len,
                          "route abort does not match a prepared snapshot");
            }
            return -1;
        }
        result = wvm_route_runtime_abort_prepared(
            control->runtime, &transaction_storage.transaction.route_snapshot_key,
            error, error_len);
        if (result == 0 && result_out) {
            result_out->recorded_state = 3;
            result_out->route_snapshot_key =
                transaction_storage.transaction.route_snapshot_key;
            memcpy(result_out->required_ack_set_digest,
                   transaction_storage.transaction.required_ack_set.entries_digest,
                   sizeof(result_out->required_ack_set_digest));
            result_out->operation_retention_horizon_ms =
                transaction_storage.transaction.operation_retention_horizon_ms;
        }
        route_transaction_storage_free(&transaction_storage);
        return result;
    }
    if (wvm_route_snapshot_key_decode(request->payload, request->payload_bytes,
                                      &key, error, error_len) != 0 ||
        request_matches_route_key(request, &key, error, error_len) != 0) {
        return -1;
    }
    if (request->message_type == WVM_ENVELOPE_MSG_ROUTE_COMMIT) {
        result = wvm_route_runtime_activate(control->runtime, &key, error,
                                            error_len);
        if (result == 0 && result_out) {
            result_out->recorded_state = 2;
            result_out->route_snapshot_key = key;
        }
        return result;
    }
    result = wvm_route_runtime_retire(control->runtime, &key, error,
                                      error_len);
    if (result == 0 && result_out) {
        result_out->recorded_state = 4;
        result_out->route_snapshot_key = key;
    }
    return result;
}

static int encode_local_frame(const struct wvm_envelope *request,
                              uint8_t **frame_out, size_t *frame_bytes_out,
                              char *error, size_t error_len)
{
    uint8_t *frame;
    size_t frame_bytes = 0;

    frame = malloc(WVM_ROUTE_CONTROL_MAX_FRAME_BYTES);
    if (!frame) {
        set_error(error, error_len, "cannot allocate route control frame");
        return -1;
    }
    if (wvm_envelope_encode(request, WVM_ENVELOPE_TRANSPORT_LOCAL,
                               frame, WVM_ROUTE_CONTROL_MAX_FRAME_BYTES,
                               &frame_bytes, error, error_len) != 0) {
        free(frame);
        return -1;
    }
    *frame_out = frame;
    *frame_bytes_out = frame_bytes;
    return 0;
}

static int journal_append(struct wvm_route_control *control,
                          const uint8_t *frame, size_t frame_bytes, char *error,
                          size_t error_len)
{
    uint8_t header[WVM_ROUTE_CONTROL_JOURNAL_HEADER_BYTES];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t sequence;

    if (!control || control->journal_fd < 0 || !frame ||
        frame_bytes == 0 || frame_bytes > WVM_ROUTE_CONTROL_MAX_FRAME_BYTES ||
        control->next_sequence == 0) {
        set_error(error, error_len, "route control journal input is invalid");
        return -1;
    }
    sequence = control->next_sequence;
    memset(header, 0, sizeof(header));
    memcpy(header, route_control_journal_magic,
           sizeof(route_control_journal_magic));
    write_be16(header + 8, WVM_ROUTE_CONTROL_JOURNAL_VERSION);
    write_be64(header + 12, sequence);
    write_be32(header + 20, (uint32_t)frame_bytes);
    wvm_sha256_digest(frame, frame_bytes, digest);
    memcpy(header + 24, digest, sizeof(digest));
    if (lseek(control->journal_fd, 0, SEEK_END) < 0 ||
        write_full(control->journal_fd, header, sizeof(header)) != 0 ||
        write_full(control->journal_fd, frame, frame_bytes) != 0 ||
        fsync(control->journal_fd) != 0) {
        set_error(error, error_len, "cannot persist route control journal: %s",
                  strerror(errno));
        return -1;
    }
    control->next_sequence = sequence + 1U;
    return 0;
}

static int apply_and_record(struct wvm_route_control *control,
                            const struct wvm_envelope *request,
                            const uint8_t *frame, size_t frame_bytes,
                            int replaying,
                            struct wvm_route_control_result *result_out,
                            char *error, size_t error_len)
{
    struct wvm_route_control_operation *existing;
    struct wvm_route_control_result result;

    existing = find_operation(control, request);
    if (existing) {
        if (memcmp(existing->semantic_payload_digest,
                   request->semantic_payload_digest,
                   sizeof(existing->semantic_payload_digest)) != 0) {
            set_error(error, error_len,
                      "route control operation ID conflicts with payload");
            return -1;
        }
        if (result_out) {
            *result_out = existing->result;
        }
        return 0;
    }
    /*
     * Persist first. A successful response is never emitted for an
     * in-memory-only route transition; replay finishes a transition after a
     * process restart. If applying now fails, the caller receives failure and
     * no data path uses the new snapshot until replay/duplicate succeeds.
     */
    if (!replaying &&
        journal_append(control, frame, frame_bytes, error, error_len) != 0) {
        return -1;
    }
    memset(&result, 0, sizeof(result));
    if (apply_unlogged(control, request, error, error_len, &result) != 0 ||
        remember_operation(control, request, &result, error, error_len) !=
            0) {
        return -1;
    }
    if (result_out) {
        *result_out = result;
    }
    return 0;
}

int wvm_route_control_open(struct wvm_route_control *control,
                           struct wvm_route_runtime *runtime,
                           const char *journal_path, char *error,
                           size_t error_len)
{
    uint64_t expected_sequence = 1;
    off_t valid_end = 0;

    if (!control || !runtime || !journal_path || journal_path[0] == '\0') {
        set_error(error, error_len, "route control initialization is invalid");
        return -1;
    }
    memset(control, 0, sizeof(*control));
    control->journal_fd = -1;
    control->runtime = runtime;
    pthread_mutex_init(&control->lock, NULL);
    control->journal_fd =
        open(journal_path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (control->journal_fd < 0) {
        set_error(error, error_len, "cannot open route control journal: %s",
                  strerror(errno));
        wvm_route_control_close(control);
        return -1;
    }
    for (;;) {
        uint8_t header[WVM_ROUTE_CONTROL_JOURNAL_HEADER_BYTES];
        uint8_t digest[WVM_SHA256_DIGEST_BYTES];
        uint8_t *frame = NULL;
        uint32_t frame_bytes;
        uint64_t sequence;
        struct wvm_envelope request;
        int read_result = read_full(control->journal_fd, header, sizeof(header));

        if (read_result == 0) {
            break;
        }
        if (read_result < 0 ||
            memcmp(header, route_control_journal_magic,
                   sizeof(route_control_journal_magic)) != 0 ||
            read_be16(header + 8) != WVM_ROUTE_CONTROL_JOURNAL_VERSION ||
            read_be16(header + 10) != 0 ||
            (sequence = read_be64(header + 12)) != expected_sequence ||
            (frame_bytes = read_be32(header + 20)) == 0 ||
            frame_bytes > WVM_ROUTE_CONTROL_MAX_FRAME_BYTES) {
            if (read_result < 0) {
                break;
            }
            set_error(error, error_len, "route control journal header is invalid");
            wvm_route_control_close(control);
            return -1;
        }
        frame = malloc(frame_bytes);
        if (!frame || read_full(control->journal_fd, frame, frame_bytes) != 1) {
            free(frame);
            break;
        }
        wvm_sha256_digest(frame, frame_bytes, digest);
        if (memcmp(digest, header + 24, sizeof(digest)) != 0 ||
            wvm_envelope_decode(frame, frame_bytes,
                                   WVM_ENVELOPE_TRANSPORT_LOCAL, &request,
                                   error, error_len) != 0 ||
            !operation_type_valid(request.message_type) ||
            apply_and_record(control, &request, frame, frame_bytes, 1, NULL,
                             error, error_len) != 0) {
            free(frame);
            wvm_route_control_close(control);
            return -1;
        }
        free(frame);
        valid_end = lseek(control->journal_fd, 0, SEEK_CUR);
        expected_sequence++;
    }
    if (ftruncate(control->journal_fd, valid_end) != 0 ||
        lseek(control->journal_fd, 0, SEEK_END) < 0) {
        set_error(error, error_len, "cannot finalize route control journal: %s",
                  strerror(errno));
        wvm_route_control_close(control);
        return -1;
    }
    control->next_sequence = expected_sequence;
    return 0;
}

void wvm_route_control_close(struct wvm_route_control *control)
{
    if (!control) {
        return;
    }
    if (control->journal_fd >= 0) {
        close(control->journal_fd);
    }
    free(control->operations);
    if (control->runtime) {
        pthread_mutex_destroy(&control->lock);
    }
    memset(control, 0, sizeof(*control));
    control->journal_fd = -1;
}

int wvm_route_control_snapshot_load(
    struct wvm_route_control *control, const struct wvm_route_snapshot_key *key,
    struct wvm_route_control_snapshot *output, char *error, size_t error_len)
{
    struct wvm_route_snapshot_key active_key;
    off_t original_offset;
    uint64_t expected_sequence = 1;
    int result = -1;

    if (!control || control->journal_fd < 0 || !control->runtime || !key ||
        !output || output->rules || output->ack_entries) {
        set_error(error, error_len, "route snapshot load input is invalid");
        return -1;
    }
    pthread_mutex_lock(&control->lock);
    if (!wvm_route_runtime_has_prepared_snapshot(control->runtime, key) &&
        (wvm_route_runtime_current_key(control->runtime, &key->scope_key,
                                       &active_key) != 0 ||
         !route_key_equal(&active_key, key))) {
        set_error(error, error_len, "route snapshot is not prepared or active");
        pthread_mutex_unlock(&control->lock);
        return -1;
    }
    if ((original_offset = lseek(control->journal_fd, 0, SEEK_CUR)) < 0 ||
        lseek(control->journal_fd, 0, SEEK_SET) < 0) {
        set_error(error, error_len, "cannot seek route snapshot journal");
        pthread_mutex_unlock(&control->lock);
        return -1;
    }
    for (;;) {
        uint8_t header[WVM_ROUTE_CONTROL_JOURNAL_HEADER_BYTES];
        uint8_t digest[WVM_SHA256_DIGEST_BYTES];
        uint8_t *frame = NULL;
        uint32_t frame_bytes;
        struct wvm_envelope request;
        struct wvm_route_control_snapshot decoded = {0};
        int read_result = read_full(control->journal_fd, header, sizeof(header));

        if (read_result == 0) {
            set_error(error, error_len, "active route snapshot is absent from journal");
            break;
        }
        if (read_result < 0 ||
            memcmp(header, route_control_journal_magic,
                   sizeof(route_control_journal_magic)) != 0 ||
            read_be16(header + 8) != WVM_ROUTE_CONTROL_JOURNAL_VERSION ||
            read_be16(header + 10) != 0 ||
            read_be64(header + 12) != expected_sequence ||
            (frame_bytes = read_be32(header + 20)) == 0 ||
            frame_bytes > WVM_ROUTE_CONTROL_MAX_FRAME_BYTES ||
            !(frame = malloc(frame_bytes)) ||
            read_full(control->journal_fd, frame, frame_bytes) != 1) {
            set_error(error, error_len, "route snapshot journal is unreadable");
            free(frame);
            break;
        }
        expected_sequence++;
        wvm_sha256_digest(frame, frame_bytes, digest);
        if (memcmp(digest, header + 24, sizeof(digest)) != 0 ||
            wvm_envelope_decode(frame, frame_bytes,
                                WVM_ENVELOPE_TRANSPORT_LOCAL, &request,
                                error, error_len) != 0) {
            set_error(error, error_len, "route snapshot journal frame is invalid");
            free(frame);
            break;
        }
        if (request.message_type == WVM_ENVELOPE_MSG_ROUTE_PREPARE &&
            route_snapshot_decode_alloc(request.payload, request.payload_bytes,
                                        &decoded, error, error_len) != 0) {
            free(frame);
            break;
        }
        free(frame);
        if (decoded.rules &&
            route_key_equal(&decoded.snapshot.route_snapshot_key, key)) {
            *output = decoded;
            result = 0;
            break;
        }
        wvm_route_control_snapshot_free(&decoded);
    }
    if (lseek(control->journal_fd, original_offset, SEEK_SET) < 0) {
        wvm_route_control_snapshot_free(output);
        set_error(error, error_len, "cannot restore route journal position");
        result = -1;
    }
    pthread_mutex_unlock(&control->lock);
    return result;
}

int wvm_route_control_apply(struct wvm_route_control *control,
                            const struct wvm_envelope *request,
                            struct wvm_route_control_result *result_out,
                            char *error, size_t error_len)
{
    struct wvm_envelope normalized_request;
    uint8_t *frame = NULL;
    size_t frame_bytes = 0;
    int result;

    if (!control || control->journal_fd < 0 || !request ||
        !operation_type_valid(request->message_type)) {
        set_error(error, error_len, "route control request is unsupported");
        return -1;
    }
    if (encode_local_frame(request, &frame, &frame_bytes, error, error_len) !=
        0 ||
        wvm_envelope_decode(frame, frame_bytes, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            &normalized_request, error, error_len) != 0) {
        free(frame);
        return -1;
    }
    pthread_mutex_lock(&control->lock);
    if (normalized_request.message_type == WVM_ENVELOPE_MSG_ROUTE_ABORT &&
        !find_operation(control, &normalized_request) &&
        validate_route_abort(control, &normalized_request, error, error_len) !=
            0) {
        pthread_mutex_unlock(&control->lock);
        free(frame);
        return -1;
    }
    result = apply_and_record(control, &normalized_request, frame, frame_bytes, 0,
                              result_out, error, error_len);
    pthread_mutex_unlock(&control->lock);
    free(frame);
    return result;
}

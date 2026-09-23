#include "wavevm_control_plane.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_admission_orchestrator.h"
#include "wavevm_runtime_names.h"
#include "wavevm_membership.h"
#include "wavevm_sha256.h"

#define WVM_CONTROL_JOURNAL_HEADER_BYTES 60U
#define WVM_CONTROL_JOURNAL_VERSION 1U

enum wvm_control_journal_kind {
    WVM_CONTROL_JOURNAL_REQUEST = 1,
    WVM_CONTROL_JOURNAL_TRANSACTION = 2,
    WVM_CONTROL_JOURNAL_CANDIDATE = 3,
    WVM_CONTROL_JOURNAL_ACTIVATION = 4,
    WVM_CONTROL_JOURNAL_ROUTE_TRANSACTION = 5,
    WVM_CONTROL_JOURNAL_RUNTIME_MANIFEST = 6,
    WVM_CONTROL_JOURNAL_ROUTE_SNAPSHOT = 7,
};

struct decoded_route_transaction {
    struct wvm_route_transaction_record record;
    struct wvm_required_ack_entry *required_ack_entries;
    struct wvm_required_ack_entry *optional_drain_entries;
};

struct decoded_route_snapshot {
    struct wvm_route_snapshot_record record;
    struct wvm_route_rule_record *rules;
    struct wvm_required_ack_entry *required_ack_entries;
};

struct runtime_manifest_identity {
    uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t admission_tx_id[WVM_IDENTITY_ID_BYTES];
    uint8_t eligibility_fence_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t activation_fence[WVM_IDENTITY_ID_BYTES];
    uint32_t physical_node_id;
    uint64_t expected_node_instance_id;
    uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_route_snapshot_key required_route_snapshot_key;
};

static const uint8_t journal_magic[8] = {
    'W', 'V', 'M', 'J', 'N', 'L', '0', '1',
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

static int admission_authority_complete(
    const struct wvm_admission_authority *authority)
{
    const struct wvm_admission_orchestrator_callbacks *callbacks;

    if (!authority || !authority->prepare_input ||
        !authority->refresh_input) {
        return 0;
    }
    callbacks = &authority->callbacks;
    return callbacks->route_plan && callbacks->route_prepare &&
           callbacks->route_commit && callbacks->route_abort &&
           callbacks->reservation_prepare &&
           callbacks->reservation_commit && callbacks->reservation_abort &&
           callbacks->participant_prepare && callbacks->participant_commit &&
           callbacks->participant_abort && callbacks->participant_ready;
}

static void write_be16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value >> 8);
    dst[1] = (uint8_t)value;
}

static void write_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static void write_be64(uint8_t *dst, uint64_t value)
{
    dst[0] = (uint8_t)(value >> 56);
    dst[1] = (uint8_t)(value >> 48);
    dst[2] = (uint8_t)(value >> 40);
    dst[3] = (uint8_t)(value >> 32);
    dst[4] = (uint8_t)(value >> 24);
    dst[5] = (uint8_t)(value >> 16);
    dst[6] = (uint8_t)(value >> 8);
    dst[7] = (uint8_t)value;
}

static uint16_t read_be16(const uint8_t *src)
{
    return ((uint16_t)src[0] << 8) | src[1];
}

static uint32_t read_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | src[3];
}

static uint64_t read_be64(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8) | src[7];
}

static int route_snapshot_key_equal(
    const struct wvm_route_snapshot_key *left,
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

static int durable_runtime_manifests_complete(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len);

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
 * Return 1 on a full read, 0 on clean EOF before any bytes, -1 for a
 * truncated frame, and -2 for a read failure.
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
            return -2;
        }
        if (received == 0) {
            return offset == 0 ? 0 : -1;
        }
        offset += (size_t)received;
    }
    return 1;
}

static int transaction_core_equal(
    const struct wvm_admission_transaction_record *left,
    const struct wvm_admission_transaction_record *right)
{
    return left && right &&
           memcmp(left->request_id, right->request_id,
                  sizeof(left->request_id)) == 0 &&
           memcmp(left->request_digest, right->request_digest,
                  sizeof(left->request_digest)) == 0 &&
           left->vm_id == right->vm_id &&
           left->vm_incarnation == right->vm_incarnation &&
           left->manifest_generation == right->manifest_generation &&
           memcmp(left->admission_tx_id, right->admission_tx_id,
                  sizeof(left->admission_tx_id)) == 0 &&
           memcmp(left->manifest_id, right->manifest_id,
                  sizeof(left->manifest_id)) == 0 &&
           left->route_scope_key.vm_id == right->route_scope_key.vm_id &&
           left->route_scope_key.vm_incarnation ==
               right->route_scope_key.vm_incarnation &&
           left->route_scope_key.route_scope_id ==
               right->route_scope_key.route_scope_id &&
           (!left->has_candidate_manifest_digest ||
            (right->has_candidate_manifest_digest &&
             memcmp(left->candidate_manifest_digest,
                    right->candidate_manifest_digest,
                    sizeof(left->candidate_manifest_digest)) == 0 &&
             left->has_prepared_route_snapshot_key &&
             right->has_prepared_route_snapshot_key &&
             route_snapshot_key_equal(
                 &left->prepared_route_snapshot_key,
                 &right->prepared_route_snapshot_key)));
}

static int transaction_equal(
    const struct wvm_admission_transaction_record *left,
    const struct wvm_admission_transaction_record *right)
{
    return transaction_core_equal(left, right) && left->state == right->state &&
           left->has_candidate_manifest_digest ==
               right->has_candidate_manifest_digest &&
           memcmp(left->candidate_manifest_digest,
                  right->candidate_manifest_digest,
                  sizeof(left->candidate_manifest_digest)) == 0 &&
           left->has_prepared_route_snapshot_key ==
               right->has_prepared_route_snapshot_key &&
           route_snapshot_key_equal(&left->prepared_route_snapshot_key,
                                    &right->prepared_route_snapshot_key) &&
           left->has_activation_record_digest ==
               right->has_activation_record_digest &&
           memcmp(left->activation_record_digest,
                  right->activation_record_digest,
                  sizeof(left->activation_record_digest)) == 0 &&
           left->transaction_sequence == right->transaction_sequence;
}

static struct wvm_control_plane_entry *find_mutable_request(
    struct wvm_control_plane *plane,
    const uint8_t request_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!plane || !request_id) {
        return NULL;
    }
    for (i = 0; i < plane->entry_count; i++) {
        if (memcmp(plane->entries[i].transaction.request_id, request_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &plane->entries[i];
        }
    }
    return NULL;
}

const struct wvm_control_plane_entry *wvm_control_plane_find_request(
    const struct wvm_control_plane *plane,
    const uint8_t request_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!plane || !request_id) {
        return NULL;
    }
    for (i = 0; i < plane->entry_count; i++) {
        if (memcmp(plane->entries[i].transaction.request_id, request_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &plane->entries[i];
        }
    }
    return NULL;
}

const struct wvm_control_plane_route_entry *
wvm_control_plane_find_route_transaction(
    const struct wvm_control_plane *plane,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!plane || !operation_id) {
        return NULL;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        if (memcmp(plane->route_entries[i].operation_id, operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &plane->route_entries[i];
        }
    }
    return NULL;
}

static struct wvm_control_plane_runtime_manifest_entry *
find_mutable_runtime_manifest(
    struct wvm_control_plane *plane,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    uint32_t physical_node_id)
{
    size_t i;

    if (!plane || !candidate_manifest_digest || physical_node_id == 0) {
        return NULL;
    }
    for (i = 0; i < plane->runtime_manifest_entry_count; i++) {
        struct wvm_control_plane_runtime_manifest_entry *entry =
            &plane->runtime_manifest_entries[i];

        if (entry->physical_node_id == physical_node_id &&
            memcmp(entry->candidate_manifest_digest, candidate_manifest_digest,
                   sizeof(entry->candidate_manifest_digest)) == 0) {
            return entry;
        }
    }
    return NULL;
}

const struct wvm_control_plane_runtime_manifest_entry *
wvm_control_plane_find_runtime_manifest(
    const struct wvm_control_plane *plane,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    uint32_t physical_node_id)
{
    size_t i;

    if (!plane || !candidate_manifest_digest || physical_node_id == 0) {
        return NULL;
    }
    for (i = 0; i < plane->runtime_manifest_entry_count; i++) {
        const struct wvm_control_plane_runtime_manifest_entry *entry =
            &plane->runtime_manifest_entries[i];

        if (entry->physical_node_id == physical_node_id &&
            memcmp(entry->candidate_manifest_digest, candidate_manifest_digest,
                   sizeof(entry->candidate_manifest_digest)) == 0) {
            return entry;
        }
    }
    return NULL;
}

static int apply_transaction_record(
    struct wvm_control_plane *plane,
    const struct wvm_admission_transaction_record *record, char *error,
    size_t error_len)
{
    struct wvm_control_plane_entry *existing;
    size_t i;

    if (!plane || !record ||
        wvm_admission_transaction_record_validate(record, error, error_len) !=
            0) {
        return -1;
    }
    existing = find_mutable_request(plane, record->request_id);
    if (existing) {
        if (!transaction_core_equal(&existing->transaction, record)) {
            set_error(error, error_len,
                      "request ID maps to conflicting durable transaction");
            return -1;
        }
        if (record->transaction_sequence <
            existing->transaction.transaction_sequence) {
            set_error(error, error_len,
                      "durable transaction sequence regressed");
            return -1;
        }
        if (record->transaction_sequence ==
            existing->transaction.transaction_sequence) {
            if (!transaction_equal(&existing->transaction, record)) {
                set_error(error, error_len,
                          "durable transaction sequence conflicts");
                return -1;
            }
            return 0;
        }
        existing->transaction = *record;
        return 0;
    }
    for (i = 0; i < plane->entry_count; i++) {
        if (memcmp(plane->entries[i].transaction.admission_tx_id,
                   record->admission_tx_id,
                   sizeof(record->admission_tx_id)) == 0) {
            set_error(error, error_len,
                      "admission transaction ID maps to two requests");
            return -1;
        }
    }
    if (!plane->entries || plane->entry_count == plane->entry_capacity) {
        set_error(error, error_len, "control-plane transaction capacity is full");
        return -1;
    }
    plane->entries[plane->entry_count++].transaction = *record;
    return 0;
}

static void decoded_route_transaction_destroy(
    struct decoded_route_transaction *decoded)
{
    if (!decoded) {
        return;
    }
    free(decoded->required_ack_entries);
    free(decoded->optional_drain_entries);
    memset(decoded, 0, sizeof(*decoded));
}

static void decoded_route_snapshot_destroy(struct decoded_route_snapshot *decoded)
{
    if (!decoded) {
        return;
    }
    free(decoded->rules);
    free(decoded->required_ack_entries);
    memset(decoded, 0, sizeof(*decoded));
}

static int record_list_entry_count(const uint8_t *bytes, size_t byte_count,
                                   size_t *count_out)
{
    uint32_t encoded_count;
    size_t offset;
    uint32_t i;

    if (!bytes || !count_out || byte_count < 4) {
        return -1;
    }
    encoded_count = read_be32(bytes);
    if ((size_t)encoded_count > (byte_count - 4U) / 4U) {
        return -1;
    }
    offset = 4;
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

static int required_ack_set_entry_count(const uint8_t *bytes,
                                        size_t byte_count, size_t *count_out)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int have_entries = 0;
    int next;

    if (!bytes || !count_out ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_REQUIRED_ACK_SET) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 1) {
            if (have_entries ||
                record_list_entry_count(field.value, field.value_bytes,
                                        count_out) != 0) {
                return -1;
            }
            have_entries = 1;
        }
    }
    return next == 0 && have_entries ? 0 : -1;
}

static int route_snapshot_list_capacities(const uint8_t *bytes,
                                          size_t byte_count,
                                          size_t *rule_count,
                                          size_t *required_ack_count)
{
    struct wvm_canonical_record outer;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int have_rules = 0;
    int have_required_ack_set = 0;
    int next;

    if (!bytes || !rule_count || !required_ack_count ||
        wvm_canonical_record_parse(bytes, byte_count, &outer) != 0 ||
        outer.record_type != WVM_RECORD_ROUTE_SNAPSHOT) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&outer, &offset, &field)) == 1) {
        if (field.tag == 4) {
            if (have_rules ||
                record_list_entry_count(field.value, field.value_bytes,
                                        rule_count) != 0) {
                return -1;
            }
            have_rules = 1;
        } else if (field.tag == 5) {
            if (have_required_ack_set ||
                required_ack_set_entry_count(field.value, field.value_bytes,
                                             required_ack_count) != 0) {
                return -1;
            }
            have_required_ack_set = 1;
        }
    }
    return next == 0 && have_rules && have_required_ack_set ? 0 : -1;
}

static int decode_route_snapshot_alloc(
    const uint8_t *bytes, size_t byte_count,
    struct decoded_route_snapshot *decoded, char *error, size_t error_len)
{
    size_t rule_count;
    size_t required_ack_count;

    if (!decoded ||
        route_snapshot_list_capacities(bytes, byte_count, &rule_count,
                                       &required_ack_count) != 0 ||
        rule_count > SIZE_MAX / sizeof(*decoded->rules) ||
        required_ack_count > SIZE_MAX / sizeof(*decoded->required_ack_entries)) {
        set_error(error, error_len, "route snapshot record is malformed");
        return -1;
    }
    memset(decoded, 0, sizeof(*decoded));
    if (rule_count != 0) {
        decoded->rules = calloc(rule_count, sizeof(*decoded->rules));
        if (!decoded->rules) {
            set_error(error, error_len, "cannot allocate route snapshot rules");
            return -1;
        }
    }
    if (required_ack_count != 0) {
        decoded->required_ack_entries =
            calloc(required_ack_count, sizeof(*decoded->required_ack_entries));
        if (!decoded->required_ack_entries) {
            decoded_route_snapshot_destroy(decoded);
            set_error(error, error_len,
                      "cannot allocate route snapshot ACK entries");
            return -1;
        }
    }
    decoded->record.next_hop_rules.entries = decoded->rules;
    decoded->record.next_hop_rules.capacity = rule_count;
    decoded->record.required_ack_set.entries.entries =
        decoded->required_ack_entries;
    decoded->record.required_ack_set.entries.capacity = required_ack_count;
    if (wvm_route_snapshot_record_decode(bytes, byte_count, &decoded->record,
                                         error, error_len) != 0) {
        decoded_route_snapshot_destroy(decoded);
        return -1;
    }
    return 0;
}

static int route_transaction_list_capacities(const uint8_t *bytes,
                                             size_t byte_count,
                                             size_t *required_ack_count,
                                             size_t *optional_drain_count)
{
    struct wvm_canonical_record outer;
    struct wvm_canonical_field outer_field;
    int have_required_ack_set = 0;
    int have_optional_drain_set = 0;
    size_t outer_offset = 0;
    int next;

    if (!bytes || !required_ack_count || !optional_drain_count ||
        wvm_canonical_record_parse(bytes, byte_count, &outer) != 0 ||
        outer.record_type != WVM_RECORD_ROUTE_TRANSACTION) {
        return -1;
    }
    while ((next =
                wvm_canonical_record_next(&outer, &outer_offset,
                                          &outer_field)) == 1) {
        if (outer_field.tag == 4) {
            struct wvm_canonical_record ack_set;
            struct wvm_canonical_field ack_field;
            size_t ack_offset = 0;
            int ack_next;

            if (have_required_ack_set ||
                wvm_canonical_record_parse(outer_field.value,
                                           outer_field.value_bytes,
                                           &ack_set) != 0 ||
                ack_set.record_type != WVM_RECORD_REQUIRED_ACK_SET) {
                return -1;
            }
            while ((ack_next =
                        wvm_canonical_record_next(&ack_set, &ack_offset,
                                                  &ack_field)) == 1) {
                if (ack_field.tag == 1) {
                    if (record_list_entry_count(ack_field.value,
                                                ack_field.value_bytes,
                                                required_ack_count) != 0) {
                        return -1;
                    }
                    have_required_ack_set = 1;
                    break;
                }
            }
            if (ack_next < 0 || !have_required_ack_set) {
                return -1;
            }
        } else if (outer_field.tag == 5) {
            if (have_optional_drain_set ||
                record_list_entry_count(outer_field.value,
                                        outer_field.value_bytes,
                                        optional_drain_count) != 0) {
                return -1;
            }
            have_optional_drain_set = 1;
        }
    }
    return next == 0 && have_required_ack_set && have_optional_drain_set ? 0
                                                                           : -1;
}

static int decode_route_transaction_alloc(
    const uint8_t *bytes, size_t byte_count,
    struct decoded_route_transaction *decoded, char *error, size_t error_len)
{
    size_t required_ack_count;
    size_t optional_drain_count;

    if (!decoded ||
        route_transaction_list_capacities(bytes, byte_count,
                                          &required_ack_count,
                                          &optional_drain_count) != 0 ||
        required_ack_count > SIZE_MAX / sizeof(*decoded->required_ack_entries) ||
        optional_drain_count >
            SIZE_MAX / sizeof(*decoded->optional_drain_entries)) {
        set_error(error, error_len, "route transaction record is malformed");
        return -1;
    }
    memset(decoded, 0, sizeof(*decoded));
    if (required_ack_count != 0) {
        decoded->required_ack_entries =
            calloc(required_ack_count, sizeof(*decoded->required_ack_entries));
        if (!decoded->required_ack_entries) {
            set_error(error, error_len,
                      "cannot allocate route transaction ACK entries");
            return -1;
        }
    }
    if (optional_drain_count != 0) {
        decoded->optional_drain_entries = calloc(
            optional_drain_count, sizeof(*decoded->optional_drain_entries));
        if (!decoded->optional_drain_entries) {
            decoded_route_transaction_destroy(decoded);
            set_error(error, error_len,
                      "cannot allocate route transaction drain entries");
            return -1;
        }
    }
    decoded->record.required_ack_set.entries.entries =
        decoded->required_ack_entries;
    decoded->record.required_ack_set.entries.capacity = required_ack_count;
    decoded->record.optional_departure_drain_set.entries =
        decoded->optional_drain_entries;
    decoded->record.optional_departure_drain_set.capacity =
        optional_drain_count;
    if (wvm_route_transaction_record_decode(bytes, byte_count,
                                            &decoded->record, error,
                                            error_len) != 0) {
        decoded_route_transaction_destroy(decoded);
        return -1;
    }
    return 0;
}

static int route_entry_has_matching_snapshot(
    const struct wvm_control_plane_route_entry *entry,
    const struct wvm_route_snapshot_key *snapshot_key, char *error,
    size_t error_len)
{
    struct decoded_route_snapshot decoded;
    int result = -1;

    if (!entry || !snapshot_key || !entry->snapshot_bytes ||
        entry->snapshot_byte_count == 0) {
        set_error(error, error_len, "durable route snapshot body was not found");
        return -1;
    }
    memset(&decoded, 0, sizeof(decoded));
    if (decode_route_snapshot_alloc(entry->snapshot_bytes,
                                    entry->snapshot_byte_count, &decoded,
                                    error, error_len) == 0 &&
        route_snapshot_key_equal(&decoded.record.route_snapshot_key,
                                 snapshot_key)) {
        result = 0;
    } else if (error && error[0] == '\0') {
        set_error(error, error_len, "durable route snapshot body is invalid");
    }
    decoded_route_snapshot_destroy(&decoded);
    return result;
}

/*
 * Route operations are keyed by operation ID in the journal, while admission
 * binds a VM to the immutable route snapshot key published by its candidate.
 * Decode retained records here so lifecycle gates cannot accidentally match a
 * different operation from the same route scope.
 */
static int durable_route_snapshot_has_state(
    const struct wvm_control_plane *plane,
    const struct wvm_route_snapshot_key *snapshot_key, uint16_t required_state,
    char *error, size_t error_len)
{
    size_t i;
    size_t matches = 0;

    if (!plane || !snapshot_key ||
        wvm_route_snapshot_key_validate(snapshot_key, error, error_len) != 0) {
        set_error(error, error_len, "route lifecycle gate has invalid key");
        return -1;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        const struct wvm_control_plane_route_entry *entry =
            &plane->route_entries[i];
        struct decoded_route_transaction decoded;

        memset(&decoded, 0, sizeof(decoded));
        if (!entry->record_bytes || entry->record_byte_count == 0 ||
            decode_route_transaction_alloc(entry->record_bytes,
                                           entry->record_byte_count, &decoded,
                                           error, error_len) != 0) {
            set_error(error, error_len,
                      "durable route transaction record is invalid");
            return -1;
        }
        if (decoded.record.state != entry->state) {
            decoded_route_transaction_destroy(&decoded);
            set_error(error, error_len,
                      "durable route transaction state does not match record");
            return -1;
        }
        if (route_snapshot_key_equal(&decoded.record.route_snapshot_key,
                                     snapshot_key)) {
            matches++;
            if (decoded.record.state != required_state) {
                decoded_route_transaction_destroy(&decoded);
                set_error(error, error_len,
                          "route snapshot is not in the required state");
                return -1;
            }
            if (route_entry_has_matching_snapshot(entry, snapshot_key, error,
                                                  error_len) != 0) {
                decoded_route_transaction_destroy(&decoded);
                return -1;
            }
        }
        decoded_route_transaction_destroy(&decoded);
    }
    if (matches != 1) {
        set_error(error, error_len,
                  matches == 0 ? "durable route snapshot was not found"
                               : "route snapshot maps to multiple operations");
        return -1;
    }
    return 0;
}

static int lifecycle_route_gate_state(enum wvm_lifecycle_state expected,
                                      enum wvm_lifecycle_state next,
                                      uint16_t *required_state_out)
{
    uint16_t required_state;

    if (expected == WVM_LIFECYCLE_PLANNED &&
        next == WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED) {
        required_state = WVM_ROUTE_TRANSACTION_PREPARING;
    } else if (expected == WVM_LIFECYCLE_ACTIVATION_DECIDED &&
               next == WVM_LIFECYCLE_COMMITTED) {
        required_state = WVM_ROUTE_TRANSACTION_ACTIVATED;
    } else if (expected == WVM_LIFECYCLE_STOPPING &&
               next == WVM_LIFECYCLE_RETIRING) {
        required_state = WVM_ROUTE_TRANSACTION_RETIRING;
    } else if (expected == WVM_LIFECYCLE_RETIRING &&
               next == WVM_LIFECYCLE_STOPPED) {
        required_state = WVM_ROUTE_TRANSACTION_RETIRED;
    } else if (expected == WVM_LIFECYCLE_ABORTING &&
               next == WVM_LIFECYCLE_ABORTED) {
        required_state = WVM_ROUTE_TRANSACTION_ABORTED;
    } else {
        return 0;
    }
    if (required_state_out) {
        *required_state_out = required_state;
    }
    return 1;
}

static int route_transaction_core_equal(const uint8_t *left,
                                        size_t left_byte_count,
                                        const uint8_t *right,
                                        size_t right_byte_count)
{
    struct wvm_canonical_record left_record;
    struct wvm_canonical_record right_record;
    struct wvm_canonical_field left_field;
    struct wvm_canonical_field right_field;
    size_t left_offset = 0;
    size_t right_offset = 0;
    int left_next;
    int right_next;

    if (wvm_canonical_record_parse(left, left_byte_count, &left_record) != 0 ||
        wvm_canonical_record_parse(right, right_byte_count, &right_record) !=
            0 ||
        left_record.record_type != WVM_RECORD_ROUTE_TRANSACTION ||
        right_record.record_type != WVM_RECORD_ROUTE_TRANSACTION) {
        return 0;
    }
    while (1) {
        left_next =
            wvm_canonical_record_next(&left_record, &left_offset, &left_field);
        right_next = wvm_canonical_record_next(&right_record, &right_offset,
                                                &right_field);
        if (left_next != right_next || left_next < 0) {
            return 0;
        }
        if (left_next == 0) {
            return 1;
        }
        if (left_field.tag != right_field.tag ||
            left_field.value_bytes != right_field.value_bytes ||
            (left_field.tag != 7 &&
             memcmp(left_field.value, right_field.value,
                    left_field.value_bytes) != 0)) {
            return 0;
        }
    }
}

static int route_transaction_state_transition_allowed(uint16_t previous,
                                                      uint16_t next)
{
    if (previous == next) {
        return 1;
    }
    if (previous == WVM_ROUTE_TRANSACTION_PREPARING) {
        return next == WVM_ROUTE_TRANSACTION_ACTIVATED ||
               next == WVM_ROUTE_TRANSACTION_ABORTED;
    }
    if (previous == WVM_ROUTE_TRANSACTION_ACTIVATED) {
        return next == WVM_ROUTE_TRANSACTION_RETIRING;
    }
    return previous == WVM_ROUTE_TRANSACTION_RETIRING &&
           next == WVM_ROUTE_TRANSACTION_RETIRED;
}

static struct wvm_control_plane_route_entry *
find_mutable_route_transaction(
    struct wvm_control_plane *plane,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!plane || !operation_id) {
        return NULL;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        if (memcmp(plane->route_entries[i].operation_id, operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &plane->route_entries[i];
        }
    }
    return NULL;
}

static int validate_route_transaction_update(
    const struct wvm_control_plane *plane,
    const struct decoded_route_transaction *decoded, const uint8_t *bytes,
    size_t byte_count, char *error, size_t error_len)
{
    const struct wvm_control_plane_route_entry *existing;

    if (!plane || !decoded || !bytes) {
        set_error(error, error_len, "route transaction persistence input is invalid");
        return -1;
    }
    existing = wvm_control_plane_find_route_transaction(
        plane, decoded->record.operation_id);
    if (!existing) {
        if (!plane->route_entries || plane->route_entry_capacity == 0 ||
            plane->route_entry_count == plane->route_entry_capacity ||
            decoded->record.state != WVM_ROUTE_TRANSACTION_PREPARING) {
            set_error(error, error_len,
                      "route transaction cannot begin in durable control plane");
            return -1;
        }
        return 0;
    }
    if (!route_transaction_core_equal(existing->record_bytes,
                                      existing->record_byte_count, bytes,
                                      byte_count) ||
        !route_transaction_state_transition_allowed(existing->state,
                                                    decoded->record.state)) {
        set_error(error, error_len,
                  "route transaction update conflicts with durable operation");
        return -1;
    }
    return 0;
}

static void install_route_transaction_record(
    struct wvm_control_plane *plane,
    const struct decoded_route_transaction *decoded, uint8_t *record_bytes,
    size_t record_byte_count)
{
    struct wvm_control_plane_route_entry *entry =
        find_mutable_route_transaction(plane, decoded->record.operation_id);

    if (!entry) {
        entry = &plane->route_entries[plane->route_entry_count++];
        memset(entry, 0, sizeof(*entry));
        memcpy(entry->operation_id, decoded->record.operation_id,
               sizeof(entry->operation_id));
    } else {
        free(entry->record_bytes);
    }
    entry->state = decoded->record.state;
    entry->record_bytes = record_bytes;
    entry->record_byte_count = record_byte_count;
}

static int apply_route_transaction_record(
    struct wvm_control_plane *plane, const uint8_t *bytes, size_t byte_count,
    char *error, size_t error_len)
{
    struct decoded_route_transaction decoded;
    uint8_t *copy;

    memset(&decoded, 0, sizeof(decoded));
    if (decode_route_transaction_alloc(bytes, byte_count, &decoded, error,
                                       error_len) != 0 ||
        validate_route_transaction_update(plane, &decoded, bytes, byte_count,
                                          error, error_len) != 0) {
        decoded_route_transaction_destroy(&decoded);
        return -1;
    }
    copy = malloc(byte_count);
    if (!copy) {
        decoded_route_transaction_destroy(&decoded);
        set_error(error, error_len,
                  "cannot retain route transaction recovery record");
        return -1;
    }
    memcpy(copy, bytes, byte_count);
    install_route_transaction_record(plane, &decoded, copy, byte_count);
    decoded_route_transaction_destroy(&decoded);
    return 0;
}

static struct wvm_control_plane_route_entry *
find_mutable_route_transaction_for_snapshot(
    struct wvm_control_plane *plane,
    const struct wvm_route_snapshot_key *snapshot_key, char *error,
    size_t error_len)
{
    struct wvm_control_plane_route_entry *match = NULL;
    size_t i;

    if (!plane || !snapshot_key) {
        set_error(error, error_len, "route snapshot binding input is invalid");
        return NULL;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        struct decoded_route_transaction decoded;

        memset(&decoded, 0, sizeof(decoded));
        if (!plane->route_entries[i].record_bytes ||
            decode_route_transaction_alloc(
                plane->route_entries[i].record_bytes,
                plane->route_entries[i].record_byte_count, &decoded, error,
                error_len) != 0) {
            decoded_route_transaction_destroy(&decoded);
            set_error(error, error_len,
                      "durable route transaction record is invalid");
            return NULL;
        }
        if (route_snapshot_key_equal(&decoded.record.route_snapshot_key,
                                     snapshot_key)) {
            if (match) {
                decoded_route_transaction_destroy(&decoded);
                set_error(error, error_len,
                          "route snapshot maps to multiple operations");
                return NULL;
            }
            match = &plane->route_entries[i];
        }
        decoded_route_transaction_destroy(&decoded);
    }
    if (!match) {
        set_error(error, error_len,
                  "route snapshot has no durable route operation");
    }
    return match;
}

static int validate_route_snapshot_binding(
    const struct wvm_control_plane_route_entry *entry,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    struct decoded_route_transaction decoded;
    int result = -1;

    if (!entry || !snapshot) {
        set_error(error, error_len, "route snapshot binding input is invalid");
        return -1;
    }
    memset(&decoded, 0, sizeof(decoded));
    if (decode_route_transaction_alloc(entry->record_bytes,
                                       entry->record_byte_count, &decoded,
                                       error, error_len) != 0) {
        set_error(error, error_len,
                  "route snapshot has an invalid durable route operation");
        goto out;
    }
    if (wvm_route_snapshot_record_binds_transaction(snapshot, &decoded.record,
                                                     error, error_len) != 0) {
        goto out;
    }
    result = 0;

out:
    decoded_route_transaction_destroy(&decoded);
    return result;
}

static int install_route_snapshot_record(
    struct wvm_control_plane_route_entry *entry, uint8_t *snapshot_bytes,
    size_t snapshot_byte_count, char *error, size_t error_len)
{
    if (!entry || !snapshot_bytes || snapshot_byte_count == 0) {
        set_error(error, error_len, "route snapshot retention input is invalid");
        return -1;
    }
    if (entry->snapshot_bytes) {
        if (entry->snapshot_byte_count != snapshot_byte_count ||
            memcmp(entry->snapshot_bytes, snapshot_bytes,
                   snapshot_byte_count) != 0) {
            set_error(error, error_len,
                      "route operation has conflicting snapshot body");
            return -1;
        }
        free(snapshot_bytes);
        return 0;
    }
    entry->snapshot_bytes = snapshot_bytes;
    entry->snapshot_byte_count = snapshot_byte_count;
    return 0;
}

static int apply_route_snapshot_record(struct wvm_control_plane *plane,
                                       const uint8_t *bytes,
                                       size_t byte_count, char *error,
                                       size_t error_len)
{
    struct decoded_route_snapshot decoded;
    struct wvm_control_plane_route_entry *entry;
    uint8_t *copy;
    int result;

    memset(&decoded, 0, sizeof(decoded));
    if (decode_route_snapshot_alloc(bytes, byte_count, &decoded, error,
                                    error_len) != 0 ||
        !(entry = find_mutable_route_transaction_for_snapshot(
              plane, &decoded.record.route_snapshot_key, error, error_len)) ||
        validate_route_snapshot_binding(entry, &decoded.record, error,
                                        error_len) != 0) {
        decoded_route_snapshot_destroy(&decoded);
        return -1;
    }
    copy = malloc(byte_count);
    if (!copy) {
        decoded_route_snapshot_destroy(&decoded);
        set_error(error, error_len,
                  "cannot retain route snapshot recovery record");
        return -1;
    }
    memcpy(copy, bytes, byte_count);
    result = install_route_snapshot_record(entry, copy, byte_count, error,
                                           error_len);
    decoded_route_snapshot_destroy(&decoded);
    return result;
}

static int runtime_manifest_identity_from_record(
    const uint8_t *bytes, size_t byte_count,
    struct runtime_manifest_identity *identity)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    struct wvm_canonical_field fields[18];
    unsigned char present[18];
    size_t offset = 0;
    int next;

    if (!bytes || !identity ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_NODE_RUNTIME_MANIFEST) {
        return -1;
    }
    memset(fields, 0, sizeof(fields));
    memset(present, 0, sizeof(present));
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag < sizeof(fields) / sizeof(fields[0])) {
            fields[field.tag] = field;
            present[field.tag] = 1;
        }
    }
    if (next < 0 || !present[1] || !present[2] || !present[3] ||
        !present[4] || !present[5] || !present[6] || !present[7] ||
        !present[8] || !present[9] || !present[14] || !present[17] ||
        fields[1].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[2].value_bytes != 4 || fields[3].value_bytes != 8 ||
        fields[4].value_bytes != 8 ||
        fields[5].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[6].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[7].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[8].value_bytes != 4 || fields[9].value_bytes != 8 ||
        fields[17].value_bytes != WVM_IDENTITY_ID_BYTES) {
        return -1;
    }
    memset(identity, 0, sizeof(*identity));
    memcpy(identity->candidate_manifest_digest, fields[1].value,
           sizeof(identity->candidate_manifest_digest));
    identity->vm_id = read_be32(fields[2].value);
    identity->vm_incarnation = read_be64(fields[3].value);
    identity->manifest_generation = read_be64(fields[4].value);
    memcpy(identity->admission_tx_id, fields[5].value,
           sizeof(identity->admission_tx_id));
    memcpy(identity->eligibility_fence_digest, fields[6].value,
           sizeof(identity->eligibility_fence_digest));
    memcpy(identity->activation_fence, fields[7].value,
           sizeof(identity->activation_fence));
    identity->physical_node_id = read_be32(fields[8].value);
    identity->expected_node_instance_id = read_be64(fields[9].value);
    memcpy(identity->reservation_id, fields[17].value,
           sizeof(identity->reservation_id));
    if (wvm_route_snapshot_key_decode(
            fields[14].value, fields[14].value_bytes,
            &identity->required_route_snapshot_key, NULL, 0) != 0) {
        return -1;
    }
    return identity->vm_id != 0 && identity->vm_incarnation != 0 &&
                   identity->manifest_generation != 0 &&
                   identity->physical_node_id != 0 &&
                   identity->expected_node_instance_id != 0
               ? 0
               : -1;
}

static int install_runtime_manifest_record(
    struct wvm_control_plane *plane,
    const struct runtime_manifest_identity *identity, uint8_t *record_bytes,
    size_t record_byte_count, char *error, size_t error_len)
{
    struct wvm_control_plane_runtime_manifest_entry *entry;

    if (!plane || !identity || !record_bytes || record_byte_count == 0) {
        set_error(error, error_len, "runtime manifest install input is invalid");
        return -1;
    }
    entry = find_mutable_runtime_manifest(
        plane, identity->candidate_manifest_digest, identity->physical_node_id);
    if (entry) {
        if (entry->expected_node_instance_id !=
                identity->expected_node_instance_id ||
            memcmp(entry->reservation_id, identity->reservation_id,
                   sizeof(entry->reservation_id)) != 0 ||
            entry->record_byte_count != record_byte_count ||
            memcmp(entry->record_bytes, record_bytes, record_byte_count) != 0) {
            set_error(error, error_len,
                      "runtime manifest conflicts with durable node projection");
            return -1;
        }
        return 1;
    }
    if (!plane->runtime_manifest_entries ||
        plane->runtime_manifest_entry_count ==
            plane->runtime_manifest_entry_capacity) {
        set_error(error, error_len, "runtime manifest entry capacity is full");
        return -1;
    }
    entry =
        &plane->runtime_manifest_entries[plane->runtime_manifest_entry_count++];
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->candidate_manifest_digest,
           identity->candidate_manifest_digest,
           sizeof(entry->candidate_manifest_digest));
    entry->physical_node_id = identity->physical_node_id;
    entry->expected_node_instance_id = identity->expected_node_instance_id;
    memcpy(entry->reservation_id, identity->reservation_id,
           sizeof(entry->reservation_id));
    entry->record_bytes = record_bytes;
    entry->record_byte_count = record_byte_count;
    return 0;
}

static int apply_runtime_manifest_record(
    struct wvm_control_plane *plane, const uint8_t *bytes, size_t byte_count,
    char *error, size_t error_len)
{
    struct runtime_manifest_identity identity;
    uint8_t *copy;
    int result;

    if (runtime_manifest_identity_from_record(bytes, byte_count, &identity) !=
        0) {
        set_error(error, error_len, "runtime manifest journal record is invalid");
        return -1;
    }
    copy = malloc(byte_count);
    if (!copy) {
        set_error(error, error_len,
                  "cannot retain runtime manifest recovery record");
        return -1;
    }
    memcpy(copy, bytes, byte_count);
    result = install_runtime_manifest_record(plane, &identity, copy, byte_count,
                                             error, error_len);
    if (result != 0) {
        free(copy);
    }
    return result < 0 ? -1 : 0;
}

static int validate_record_type(const uint8_t *bytes, size_t byte_count,
                                uint16_t record_type, char *error,
                                size_t error_len)
{
    struct wvm_canonical_record record;

    if (!bytes || byte_count == 0 ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != record_type) {
        set_error(error, error_len, "journal payload is not record 0x%04x",
                  record_type);
        return -1;
    }
    return 0;
}

static int activation_transaction(
    const struct wvm_control_plane *plane,
    const struct wvm_control_plane_entry *entry,
    const struct wvm_activation_record *activation, uint64_t sequence,
    const uint8_t digest[WVM_SHA256_DIGEST_BYTES],
    struct wvm_admission_transaction_record *updated, char *error,
    size_t error_len)
{
    if (!entry || !entry->transaction.has_candidate_manifest_digest ||
        !entry->transaction.has_prepared_route_snapshot_key ||
        entry->transaction.has_activation_record_digest || sequence == 0 ||
        activation->durable_decision_sequence != sequence ||
        memcmp(entry->transaction.admission_tx_id, activation->admission_tx_id,
               sizeof(activation->admission_tx_id)) != 0 ||
        memcmp(entry->transaction.candidate_manifest_digest,
               activation->candidate_manifest_digest,
               sizeof(activation->candidate_manifest_digest)) != 0 ||
        activation->required_route_snapshot_count != 1 ||
        !route_snapshot_key_equal(
            &entry->transaction.prepared_route_snapshot_key,
            &activation->required_route_snapshot_keys[0])) {
        set_error(error, error_len,
                  "activation does not match undecided transaction and journal sequence");
        return -1;
    }
    if (durable_route_snapshot_has_state(
            plane, &entry->transaction.prepared_route_snapshot_key,
            WVM_ROUTE_TRANSACTION_PREPARING, error, error_len) != 0) {
        return -1;
    }
    *updated = entry->transaction;
    if (activation->decision == WVM_ACTIVATION_ACTIVATE &&
        entry->transaction.state == WVM_LIFECYCLE_PARTICIPANTS_PREPARED) {
        updated->state = WVM_LIFECYCLE_ACTIVATION_DECIDED;
    } else if (activation->decision == WVM_ACTIVATION_ABORT &&
               entry->transaction.state >= WVM_LIFECYCLE_PLANNED &&
               entry->transaction.state < WVM_LIFECYCLE_ACTIVATION_DECIDED) {
        updated->state = WVM_LIFECYCLE_ABORTING;
    } else {
        set_error(error, error_len,
                  "activation decision is invalid for durable transaction state");
        return -1;
    }
    updated->has_activation_record_digest = 1;
    memcpy(updated->activation_record_digest, digest,
           sizeof(updated->activation_record_digest));
    updated->transaction_sequence = sequence;
    return wvm_admission_transaction_record_validate(updated, error, error_len);
}

static int replay_activation(struct wvm_control_plane *plane,
                              const uint8_t *bytes, size_t byte_count,
                              uint64_t sequence, char *error, size_t error_len)
{
    struct wvm_activation_record activation = {0};
    struct wvm_route_snapshot_key route_key;
    struct wvm_admission_transaction_record updated;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t i;

    activation.required_route_snapshot_keys = &route_key;
    activation.required_route_snapshot_capacity = 1;
    if (wvm_activation_record_decode(bytes, byte_count, &activation, error,
                                     error_len) != 0) {
        return -1;
    }
    wvm_sha256_digest(bytes, byte_count, digest);
    for (i = 0; i < plane->entry_count; i++) {
        if (memcmp(plane->entries[i].transaction.admission_tx_id,
                   activation.admission_tx_id,
                   sizeof(activation.admission_tx_id)) == 0) {
            if (activation_transaction(plane, &plane->entries[i], &activation,
                                        sequence, digest, &updated, error,
                                        error_len) != 0) {
                return -1;
            }
            return apply_transaction_record(plane, &updated, error, error_len);
        }
    }
    set_error(error, error_len, "activation journal frame has no transaction");
    return -1;
}

static int replay_journal_frame(struct wvm_control_plane *plane,
                                uint16_t kind, uint64_t sequence,
                                const uint8_t *payload, size_t payload_bytes,
                                char *error, size_t error_len)
{
    struct wvm_admission_transaction_record transaction;
    uint16_t record_type;

    if (!plane || !payload || sequence == 0 || sequence == UINT64_MAX ||
        (plane->next_journal_sequence != 0 &&
         sequence != plane->next_journal_sequence)) {
        set_error(error, error_len, "journal sequence is invalid");
        return -1;
    }
    switch (kind) {
    case WVM_CONTROL_JOURNAL_REQUEST:
        record_type = WVM_RECORD_VM_REQUEST;
        break;
    case WVM_CONTROL_JOURNAL_TRANSACTION:
        record_type = WVM_RECORD_ADMISSION_TRANSACTION;
        break;
    case WVM_CONTROL_JOURNAL_CANDIDATE:
        record_type = WVM_RECORD_CANDIDATE_VM_MANIFEST;
        break;
    case WVM_CONTROL_JOURNAL_ACTIVATION:
        record_type = WVM_RECORD_ACTIVATION_RECORD;
        break;
    case WVM_CONTROL_JOURNAL_ROUTE_TRANSACTION:
        record_type = WVM_RECORD_ROUTE_TRANSACTION;
        break;
    case WVM_CONTROL_JOURNAL_RUNTIME_MANIFEST:
        record_type = WVM_RECORD_NODE_RUNTIME_MANIFEST;
        break;
    case WVM_CONTROL_JOURNAL_ROUTE_SNAPSHOT:
        record_type = WVM_RECORD_ROUTE_SNAPSHOT;
        break;
    default:
        set_error(error, error_len, "journal has unknown frame kind %u", kind);
        return -1;
    }
    if (validate_record_type(payload, payload_bytes, record_type, error,
                             error_len) != 0) {
        return -1;
    }
    if (kind == WVM_CONTROL_JOURNAL_TRANSACTION) {
        if (wvm_admission_transaction_record_decode(
                payload, payload_bytes, &transaction, error, error_len) != 0 ||
            transaction.transaction_sequence != sequence ||
            apply_transaction_record(plane, &transaction, error, error_len) !=
                0) {
            set_error(error, error_len, "journal transaction frame is invalid");
            return -1;
        }
    } else if (kind == WVM_CONTROL_JOURNAL_ACTIVATION &&
               replay_activation(plane, payload, payload_bytes, sequence,
                                  error, error_len) != 0) {
        return -1;
    } else if (kind == WVM_CONTROL_JOURNAL_ROUTE_TRANSACTION &&
               apply_route_transaction_record(plane, payload, payload_bytes,
                                              error, error_len) != 0) {
        set_error(error, error_len, "journal route transaction frame is invalid");
        return -1;
    } else if (kind == WVM_CONTROL_JOURNAL_ROUTE_SNAPSHOT &&
               apply_route_snapshot_record(plane, payload, payload_bytes,
                                           error, error_len) != 0) {
        set_error(error, error_len, "journal route snapshot frame is invalid");
        return -1;
    } else if (kind == WVM_CONTROL_JOURNAL_RUNTIME_MANIFEST &&
               apply_runtime_manifest_record(plane, payload, payload_bytes,
                                             error, error_len) != 0) {
        set_error(error, error_len, "journal runtime manifest frame is invalid");
        return -1;
    }
    plane->next_journal_sequence = sequence + 1U;
    return 0;
}

static int append_journal_frame(struct wvm_control_plane *plane, uint16_t kind,
                                const uint8_t *payload, size_t payload_bytes,
                                uint64_t *sequence_out, char *error,
                                size_t error_len)
{
    uint8_t header[WVM_CONTROL_JOURNAL_HEADER_BYTES];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t sequence;

    if (!plane || plane->journal_fd < 0 || plane->journal_failed ||
        !payload || payload_bytes == 0 ||
        payload_bytes > WVM_CONTROL_PLANE_MAX_RECORD_BYTES ||
        !sequence_out || plane->next_journal_sequence == 0 ||
        plane->next_journal_sequence == UINT64_MAX) {
        set_error(error, error_len, "cannot append control-plane journal frame");
        return -1;
    }
    sequence = plane->next_journal_sequence;
    memset(header, 0, sizeof(header));
    memcpy(header, journal_magic, sizeof(journal_magic));
    write_be16(header + 8, WVM_CONTROL_JOURNAL_VERSION);
    write_be16(header + 10, kind);
    write_be64(header + 12, sequence);
    write_be32(header + 20, (uint32_t)payload_bytes);
    wvm_sha256_digest(payload, payload_bytes, digest);
    memcpy(header + 28, digest, sizeof(digest));
    if (write_full(plane->journal_fd, header, sizeof(header)) != 0 ||
        write_full(plane->journal_fd, payload, payload_bytes) != 0 ||
        fsync(plane->journal_fd) != 0) {
        plane->journal_failed = 1;
        set_error(error, error_len, "cannot persist control-plane journal: %s",
                  strerror(errno));
        return -1;
    }
    plane->next_journal_sequence = sequence + 1U;
    *sequence_out = sequence;
    return 0;
}

static int encode_request_alloc(const struct wvm_vm_request *request,
                                uint8_t **bytes_out, size_t *byte_count_out,
                                uint8_t digest[WVM_SHA256_DIGEST_BYTES],
                                char *error, size_t error_len)
{
    size_t capacity = 1024;

    if (!request || !bytes_out || !byte_count_out || !digest) {
        set_error(error, error_len, "request encoding input is invalid");
        return -1;
    }
    while (capacity <= WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate canonical request");
            return -1;
        }
        if (wvm_vm_request_encode(request, bytes, capacity, &byte_count, error,
                                  error_len) == 0) {
            wvm_sha256_digest(bytes, byte_count, digest);
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len, "canonical request exceeds control-plane limit");
    return -1;
}

int wvm_control_plane_classify_request(
    const struct wvm_control_plane *plane, const struct wvm_vm_request *request,
    enum wvm_control_plane_request_disposition *disposition, char *error,
    size_t error_len)
{
    const struct wvm_control_plane_entry *entry;
    uint8_t *request_bytes = NULL;
    uint8_t request_digest[WVM_SHA256_DIGEST_BYTES];
    size_t request_byte_count = 0;

    if (!plane || !request || !disposition ||
        encode_request_alloc(request, &request_bytes, &request_byte_count,
                             request_digest, error, error_len) != 0) {
        return -1;
    }
    entry = wvm_control_plane_find_request(plane, request->request_id);
    if (!entry) {
        *disposition = WVM_CONTROL_PLANE_REQUEST_ABSENT;
    } else if (memcmp(entry->transaction.request_digest, request_digest,
                      sizeof(request_digest)) == 0) {
        *disposition = WVM_CONTROL_PLANE_REQUEST_REPLAY;
    } else {
        *disposition = WVM_CONTROL_PLANE_REQUEST_CONFLICT;
    }
    free(request_bytes);
    return 0;
}

static int encode_candidate_alloc(
    const struct wvm_candidate_vm_manifest *candidate, uint8_t **bytes_out,
    size_t *byte_count_out, char *error, size_t error_len)
{
    size_t capacity = 4096;

    if (!candidate || !bytes_out || !byte_count_out) {
        set_error(error, error_len, "candidate encoding input is invalid");
        return -1;
    }
    while (capacity <= WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;
        uint8_t encoded_digest[WVM_SHA256_DIGEST_BYTES];

        if (!bytes) {
            set_error(error, error_len, "cannot allocate candidate record");
            return -1;
        }
        if (wvm_candidate_vm_manifest_encode(
                candidate, bytes, capacity, &byte_count, encoded_digest, error,
                error_len) == 0) {
            if (memcmp(encoded_digest, candidate->manifest_digest,
                       sizeof(encoded_digest)) != 0) {
                free(bytes);
                set_error(error, error_len,
                          "candidate manifest digest does not match payload");
                return -1;
            }
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len,
              "candidate manifest exceeds control-plane limit");
    return -1;
}

static int encode_runtime_manifest_alloc(
    const struct wvm_node_runtime_manifest *runtime_manifest,
    uint8_t **bytes_out, size_t *byte_count_out, char *error,
    size_t error_len)
{
    size_t capacity = 4096;

    if (!runtime_manifest || !bytes_out || !byte_count_out) {
        set_error(error, error_len, "runtime manifest encoding input is invalid");
        return -1;
    }
    while (capacity <= WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate runtime manifest");
            return -1;
        }
        if (wvm_node_runtime_manifest_encode(runtime_manifest, bytes, capacity,
                                             &byte_count, error,
                                             error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len,
              "runtime manifest exceeds control-plane limit");
    return -1;
}

static int encode_activation_alloc(
    const struct wvm_activation_record *activation, uint8_t **bytes_out,
    size_t *byte_count_out, uint8_t digest[WVM_SHA256_DIGEST_BYTES],
    char *error, size_t error_len)
{
    size_t capacity = 1024;

    if (!activation || !bytes_out || !byte_count_out || !digest) {
        set_error(error, error_len, "activation encoding input is invalid");
        return -1;
    }
    while (capacity <= WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate activation record");
            return -1;
        }
        if (wvm_activation_record_encode(activation, bytes, capacity,
                                         &byte_count, error, error_len) == 0) {
            wvm_sha256_digest(bytes, byte_count, digest);
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len,
              "activation record exceeds control-plane limit");
    return -1;
}

static int encode_route_transaction_alloc(
    const struct wvm_route_transaction_record *transaction,
    uint8_t **bytes_out, size_t *byte_count_out, char *error,
    size_t error_len)
{
    size_t capacity = 1024;

    if (!transaction || !bytes_out || !byte_count_out) {
        set_error(error, error_len,
                  "route transaction encoding input is invalid");
        return -1;
    }
    while (capacity <= WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len,
                      "cannot allocate route transaction record");
            return -1;
        }
        if (wvm_route_transaction_record_encode(transaction, bytes, capacity,
                                                &byte_count, error,
                                                error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len,
              "route transaction record exceeds control-plane limit");
    return -1;
}

static int encode_route_snapshot_alloc(
    const struct wvm_route_snapshot_record *snapshot, uint8_t **bytes_out,
    size_t *byte_count_out, char *error, size_t error_len)
{
    size_t capacity = 4096;

    if (!snapshot || !bytes_out || !byte_count_out ||
        wvm_route_snapshot_record_validate(snapshot, error, error_len) != 0) {
        set_error(error, error_len, "route snapshot encoding input is invalid");
        return -1;
    }
    while (capacity <= WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate route snapshot record");
            return -1;
        }
        if (wvm_route_snapshot_record_encode(snapshot, bytes, capacity,
                                             &byte_count, NULL, error,
                                             error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            capacity = WVM_CONTROL_PLANE_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len, "route snapshot exceeds control-plane limit");
    return -1;
}

static void transaction_from_coordinator(
    struct wvm_admission_transaction_record *record,
    const struct wvm_coordinator_transaction *transaction,
    const uint8_t request_digest[WVM_SHA256_DIGEST_BYTES])
{
    memset(record, 0, sizeof(*record));
    memcpy(record->request_id, transaction->request_id,
           sizeof(record->request_id));
    memcpy(record->request_digest, request_digest,
           sizeof(record->request_digest));
    record->vm_id = transaction->vm_id;
    record->vm_incarnation = transaction->vm_incarnation;
    record->manifest_generation = transaction->manifest_generation;
    memcpy(record->admission_tx_id, transaction->admission_tx_id,
           sizeof(record->admission_tx_id));
    memcpy(record->manifest_id, transaction->manifest_id,
           sizeof(record->manifest_id));
    record->route_scope_key = transaction->route_scope_key;
    record->state = WVM_LIFECYCLE_IDENTITY_ALLOCATED;
}

static void transaction_to_coordinator(
    const struct wvm_admission_transaction_record *record,
    struct wvm_coordinator_transaction *transaction)
{
    memset(transaction, 0, sizeof(*transaction));
    memcpy(transaction->request_id, record->request_id,
           sizeof(transaction->request_id));
    transaction->vm_id = record->vm_id;
    transaction->vm_incarnation = record->vm_incarnation;
    transaction->manifest_generation = record->manifest_generation;
    memcpy(transaction->admission_tx_id, record->admission_tx_id,
           sizeof(transaction->admission_tx_id));
    memcpy(transaction->manifest_id, record->manifest_id,
           sizeof(transaction->manifest_id));
    transaction->route_scope_key = record->route_scope_key;
}

static int append_transaction(struct wvm_control_plane *plane,
                              struct wvm_admission_transaction_record *record,
                              char *error, size_t error_len)
{
    uint8_t bytes[1024];
    size_t byte_count;
    uint64_t sequence;

    if (!plane || !record || plane->next_journal_sequence == 0) {
        set_error(error, error_len, "transaction append input is invalid");
        return -1;
    }
    record->transaction_sequence = plane->next_journal_sequence;
    if (wvm_admission_transaction_record_encode(record, bytes, sizeof(bytes),
                                                &byte_count, error,
                                                error_len) != 0 ||
        append_journal_frame(plane, WVM_CONTROL_JOURNAL_TRANSACTION, bytes,
                             byte_count, &sequence, error, error_len) != 0 ||
        sequence != record->transaction_sequence ||
        apply_transaction_record(plane, record, error, error_len) != 0) {
        set_error(error, error_len, "cannot persist admission transaction");
        return -1;
    }
    return 0;
}

int wvm_control_plane_record_route_transaction(
    struct wvm_control_plane *plane,
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len)
{
    struct decoded_route_transaction decoded;
    uint8_t *encoded_bytes = NULL;
    uint8_t *retained_bytes = NULL;
    size_t encoded_byte_count = 0;
    uint64_t ignored_sequence;
    int result = -1;

    memset(&decoded, 0, sizeof(decoded));
    if (!plane || plane->journal_fd < 0 || !transaction ||
        encode_route_transaction_alloc(transaction, &encoded_bytes,
                                       &encoded_byte_count, error,
                                       error_len) != 0 ||
        decode_route_transaction_alloc(encoded_bytes, encoded_byte_count,
                                       &decoded, error, error_len) != 0 ||
        validate_route_transaction_update(plane, &decoded, encoded_bytes,
                                          encoded_byte_count, error,
                                          error_len) != 0) {
        goto out;
    }
    retained_bytes = malloc(encoded_byte_count);
    if (!retained_bytes) {
        set_error(error, error_len,
                  "cannot allocate durable route transaction state");
        goto out;
    }
    memcpy(retained_bytes, encoded_bytes, encoded_byte_count);
    if (append_journal_frame(plane, WVM_CONTROL_JOURNAL_ROUTE_TRANSACTION,
                             encoded_bytes, encoded_byte_count,
                             &ignored_sequence, error, error_len) != 0) {
        goto out;
    }
    install_route_transaction_record(plane, &decoded, retained_bytes,
                                     encoded_byte_count);
    retained_bytes = NULL;
    result = 0;

out:
    free(retained_bytes);
    free(encoded_bytes);
    decoded_route_transaction_destroy(&decoded);
    return result;
}

int wvm_control_plane_record_route_snapshot(
    struct wvm_control_plane *plane,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    struct wvm_control_plane_route_entry *entry;
    struct decoded_route_snapshot decoded;
    uint8_t *encoded_bytes = NULL;
    uint8_t *retained_bytes = NULL;
    size_t encoded_byte_count = 0;
    uint64_t ignored_sequence;
    int result = -1;

    memset(&decoded, 0, sizeof(decoded));
    if (!plane || plane->journal_fd < 0 || !operation_id || !snapshot ||
        !(entry = find_mutable_route_transaction(plane, operation_id)) ||
        encode_route_snapshot_alloc(snapshot, &encoded_bytes,
                                    &encoded_byte_count, error, error_len) != 0 ||
        decode_route_snapshot_alloc(encoded_bytes, encoded_byte_count, &decoded,
                                    error, error_len) != 0 ||
        validate_route_snapshot_binding(entry, &decoded.record, error,
                                        error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "route snapshot has no matching durable operation");
        }
        goto out;
    }
    if (entry->snapshot_bytes) {
        if (entry->snapshot_byte_count == encoded_byte_count &&
            memcmp(entry->snapshot_bytes, encoded_bytes,
                   encoded_byte_count) == 0) {
            result = 0;
        } else {
            set_error(error, error_len,
                      "route operation has conflicting snapshot body");
        }
        goto out;
    }
    retained_bytes = malloc(encoded_byte_count);
    if (!retained_bytes) {
        set_error(error, error_len, "cannot allocate durable route snapshot");
        goto out;
    }
    memcpy(retained_bytes, encoded_bytes, encoded_byte_count);
    if (append_journal_frame(plane, WVM_CONTROL_JOURNAL_ROUTE_SNAPSHOT,
                             encoded_bytes, encoded_byte_count,
                             &ignored_sequence, error, error_len) != 0) {
        goto out;
    }
    entry->snapshot_bytes = retained_bytes;
    entry->snapshot_byte_count = encoded_byte_count;
    retained_bytes = NULL;
    result = 0;

out:
    free(retained_bytes);
    free(encoded_bytes);
    decoded_route_snapshot_destroy(&decoded);
    return result;
}

int wvm_control_plane_read_route_snapshot(
    const struct wvm_control_plane *plane,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    const struct wvm_control_plane_route_entry *entry;

    if (!plane || !operation_id || !bytes || !encoded_bytes ||
        !(entry = wvm_control_plane_find_route_transaction(plane,
                                                            operation_id)) ||
        !entry->snapshot_bytes || entry->snapshot_byte_count == 0 ||
        entry->snapshot_byte_count > capacity) {
        set_error(error, error_len,
                  "route snapshot recovery does not match durable operation");
        return -1;
    }
    memcpy(bytes, entry->snapshot_bytes, entry->snapshot_byte_count);
    *encoded_bytes = entry->snapshot_byte_count;
    return 0;
}

static int restore_namespace(
    struct wvm_vm_namespace_allocator *namespace_allocator,
    const struct wvm_admission_transaction_record *transaction, char *error,
    size_t error_len)
{
    enum wvm_vm_namespace_state state = WVM_VM_NAMESPACE_ALLOCATED;

    if (transaction->state >= WVM_LIFECYCLE_COMMITTED &&
        transaction->state != WVM_LIFECYCLE_STOPPED &&
        transaction->state != WVM_LIFECYCLE_ABORTING &&
        transaction->state != WVM_LIFECYCLE_ABORTED) {
        state = WVM_VM_NAMESPACE_ACTIVE;
    }
    /*
     * STOPPED/ABORTED remain ALLOCATED after restart until explicit retirement
     * reconciliation proves every route/cache/operation reference is gone.
     */
    return wvm_vm_namespace_restore(
        namespace_allocator, WVM_NAMESPACE_ABI_U32, transaction->vm_id,
        transaction->vm_incarnation, state, error, error_len);
}

static void clear_route_transaction_entries(struct wvm_control_plane *plane)
{
    size_t i;

    if (!plane || !plane->route_entries) {
        return;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        free(plane->route_entries[i].record_bytes);
        free(plane->route_entries[i].snapshot_bytes);
        memset(&plane->route_entries[i], 0, sizeof(plane->route_entries[i]));
    }
    plane->route_entry_count = 0;
}

static void clear_runtime_manifest_entries(struct wvm_control_plane *plane)
{
    size_t i;

    if (!plane || !plane->runtime_manifest_entries) {
        return;
    }
    for (i = 0; i < plane->runtime_manifest_entry_count; i++) {
        free(plane->runtime_manifest_entries[i].record_bytes);
        memset(&plane->runtime_manifest_entries[i], 0,
               sizeof(plane->runtime_manifest_entries[i]));
    }
    plane->runtime_manifest_entry_count = 0;
}

void wvm_control_plane_init(struct wvm_control_plane *plane,
                            struct wvm_control_plane_entry *entries,
                            size_t entry_capacity)
{
    if (!plane) {
        return;
    }
    memset(plane, 0, sizeof(*plane));
    plane->journal_fd = -1;
    plane->next_journal_sequence = 1;
    plane->entries = entries;
    plane->entry_capacity = entry_capacity;
    if (entries && entry_capacity != 0) {
        memset(entries, 0, entry_capacity * sizeof(*entries));
    }
}

void wvm_control_plane_set_route_transaction_entries(
    struct wvm_control_plane *plane,
    struct wvm_control_plane_route_entry *route_entries,
    size_t route_entry_capacity)
{
    if (!plane || plane->route_entry_count != 0) {
        return;
    }
    plane->route_entries = route_entries;
    plane->route_entry_capacity = route_entry_capacity;
    if (route_entries && route_entry_capacity != 0) {
        memset(route_entries, 0, route_entry_capacity * sizeof(*route_entries));
    }
}

void wvm_control_plane_set_runtime_manifest_entries(
    struct wvm_control_plane *plane,
    struct wvm_control_plane_runtime_manifest_entry *runtime_manifest_entries,
    size_t runtime_manifest_entry_capacity)
{
    if (!plane || plane->runtime_manifest_entry_count != 0) {
        return;
    }
    plane->runtime_manifest_entries = runtime_manifest_entries;
    plane->runtime_manifest_entry_capacity = runtime_manifest_entry_capacity;
    if (runtime_manifest_entries && runtime_manifest_entry_capacity != 0) {
        memset(runtime_manifest_entries, 0,
               runtime_manifest_entry_capacity *
                   sizeof(*runtime_manifest_entries));
    }
}

int wvm_control_plane_set_admission_authority(
    struct wvm_control_plane *plane,
    const struct wvm_admission_authority *authority, char *error,
    size_t error_len)
{
    if (!plane) {
        set_error(error, error_len, "plane is NULL");
        return -EINVAL;
    }
    if (!authority) {
        set_error(error, error_len, "authority is NULL");
        return -EINVAL;
    }
    if (plane->journal_fd >= 0) {
        set_error(error, error_len, "admission journal already open");
        return -EINVAL;
    }
    if (plane->membership_open) {
        set_error(error, error_len, "membership already open");
        return -EINVAL;
    }
    if (plane->admission_authority) {
        set_error(error, error_len, "admission authority already set");
        return -EINVAL;
    }
    if (!admission_authority_complete(authority)) {
        set_error(error, error_len, "admission authority is incomplete");
        return -EINVAL;
    }
    plane->admission_authority = authority;
    return 0;
}

static int copy_membership_journal_path(char destination[WVM_CONTROL_PLANE_PATH_MAX],
                                        const char *source)
{
    size_t length;

    if (!destination || !source || source[0] == '\0') {
        return -1;
    }
    length = strlen(source);
    if (length >= WVM_CONTROL_PLANE_PATH_MAX) {
        return -1;
    }
    memcpy(destination, source, length + 1U);
    return 0;
}

int wvm_control_plane_configure_membership(
    struct wvm_control_plane *plane,
    const struct wvm_control_plane_membership_config *config,
    char *error, size_t error_len)
{
    int result;

    if (!plane || !config || plane->journal_fd >= 0 ||
        plane->membership_configured || !config->members ||
        config->member_capacity == 0 || !config->routes ||
        config->route_capacity == 0 || !config->dependencies ||
        config->dependency_capacity == 0 || !config->operations ||
        config->operation_capacity == 0 ||
        copy_membership_journal_path(plane->membership_journal_path,
                                     config->membership_journal_path) != 0 ||
        copy_membership_journal_path(plane->membership_control_journal_path,
                                     config->control_journal_path) != 0) {
        set_error(error, error_len,
                  "control-plane membership configuration is invalid");
        return -EINVAL;
    }

    wvm_membership_controller_init(
        &plane->membership_controller, config->members,
        config->member_capacity, config->routes, config->route_capacity,
        config->dependencies, config->dependency_capacity, config->authorize,
        config->authorize_context);
    plane->membership_initialized = 1;
    wvm_membership_control_init(
        &plane->membership_control, &plane->membership_controller,
        config->operations, config->operation_capacity);
    result = wvm_membership_control_set_management_authorizer(
        &plane->membership_control, config->authorize_management,
        config->authorize_management_context);
    if (result == 0) {
        result = wvm_membership_control_set_membership_authorizer(
            &plane->membership_control, config->authorize_membership,
            config->authorize_membership_context);
    }
    if (result != 0) {
        wvm_membership_control_close(&plane->membership_control);
        wvm_membership_controller_close(&plane->membership_controller);
        plane->membership_initialized = 0;
        plane->membership_journal_path[0] = '\0';
        plane->membership_control_journal_path[0] = '\0';
        set_error(error, error_len,
                  "cannot configure membership authorization boundary");
        return -EINVAL;
    }
    plane->membership_dispatch_context.control = &plane->membership_control;
    plane->membership_dispatch_context.result_sink = config->result_sink;
    plane->membership_dispatch_context.result_sink_context =
        config->result_sink_context;
    plane->membership_configured = 1;
    return 0;
}

int wvm_control_plane_open_membership(struct wvm_control_plane *plane,
                                      char *error, size_t error_len)
{
    if (!plane || !plane->membership_configured ||
        !plane->membership_initialized || plane->membership_open ||
        plane->membership_controller.journal_fd >= 0 ||
        plane->membership_control.journal_fd >= 0) {
        set_error(error, error_len,
                  "control-plane membership open state is invalid");
        return -EINVAL;
    }
    if (wvm_membership_controller_open(
            &plane->membership_controller, plane->membership_journal_path,
            error, error_len) != 0) {
        plane->membership_initialized = 0;
        return -1;
    }
    if (wvm_membership_control_open(
            &plane->membership_control,
            plane->membership_control_journal_path, error, error_len) != 0) {
        wvm_membership_controller_close(&plane->membership_controller);
        plane->membership_initialized = 0;
        return -1;
    }
    plane->membership_open = 1;
    return 0;
}

void wvm_control_plane_close_membership(struct wvm_control_plane *plane)
{
    if (!plane) {
        return;
    }
    if (plane->membership_open) {
        wvm_membership_control_close(&plane->membership_control);
        wvm_membership_controller_close(&plane->membership_controller);
        plane->membership_open = 0;
        plane->membership_initialized = 0;
    } else if (plane->membership_initialized) {
        /* Configuration may be discarded before the membership journals open. */
        wvm_membership_control_close(&plane->membership_control);
        wvm_membership_controller_close(&plane->membership_controller);
        plane->membership_initialized = 0;
    }
    plane->membership_configured = 0;
    memset(&plane->membership_dispatch_context, 0,
           sizeof(plane->membership_dispatch_context));
    plane->membership_journal_path[0] = '\0';
    plane->membership_control_journal_path[0] = '\0';
}

int wvm_control_plane_membership_dispatch(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len)
{
    struct wvm_control_plane *plane = opaque;

    if (!plane || !plane->membership_open) {
        set_error(error, error_len,
                  "authoritative membership control plane is not open");
        return -EAGAIN;
    }
    return wvm_membership_control_dispatch(
        &plane->membership_dispatch_context, request, authenticated_actor,
        error, error_len);
}

int wvm_control_plane_membership_apply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    struct wvm_control_plane *plane = opaque;

    if (!plane || !plane->membership_open) {
        set_error(error, error_len,
                  "authoritative membership control plane is not open");
        return -EAGAIN;
    }
    return wvm_membership_control_apply(
        &plane->membership_control, request, authenticated_actor, result, error,
        error_len);
}

static int sync_journal_directory(const char *path)
{
    char *parent = strdup(path);
    char *slash;
    int fd;
    int result;
    int saved_errno;

    if (!parent) {
        return -1;
    }
    slash = strrchr(parent, '/');
    if (slash) {
        slash[slash == parent ? 1 : 0] = '\0';
    } else {
        free(parent);
        parent = strdup(".");
        if (!parent) {
            return -1;
        }
    }
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(parent);
    if (fd < 0) {
        return -1;
    }
    result = fsync(fd);
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return result;
}

int wvm_control_plane_open(
    struct wvm_control_plane *plane, const char *journal_path,
    struct wvm_vm_namespace_allocator *namespace_allocator, char *error,
    size_t error_len)
{
    uint8_t header[WVM_CONTROL_JOURNAL_HEADER_BYTES];
    off_t frame_offset;
    int result;
    size_t i;

    if (!plane || !journal_path || journal_path[0] == '\0' ||
        !namespace_allocator || plane->journal_fd >= 0 ||
        !plane->entries || plane->entry_capacity == 0) {
        set_error(error, error_len, "control-plane journal open input is invalid");
        return -1;
    }
    plane->journal_fd =
        open(journal_path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (plane->journal_fd < 0 ||
        flock(plane->journal_fd, LOCK_EX | LOCK_NB) != 0 ||
        lseek(plane->journal_fd, 0, SEEK_SET) < 0) {
        set_error(error, error_len, "cannot open control-plane journal: %s",
                  strerror(errno));
        wvm_control_plane_close(plane);
        return -1;
    }
    plane->entry_count = 0;
    memset(plane->entries, 0, plane->entry_capacity * sizeof(*plane->entries));
    plane->next_journal_sequence = 1;
    plane->journal_failed = 0;
    while (1) {
        uint8_t *payload;
        uint8_t digest[WVM_SHA256_DIGEST_BYTES];
        uint16_t version;
        uint16_t kind;
        uint64_t sequence;
        uint32_t payload_bytes;

        frame_offset = lseek(plane->journal_fd, 0, SEEK_CUR);
        if (frame_offset < 0) {
            set_error(error, error_len, "cannot seek control-plane journal");
            wvm_control_plane_close(plane);
            return -1;
        }
        result = read_full(plane->journal_fd, header, sizeof(header));
        if (result == 0) {
            break;
        }
        if (result == -2) {
            set_error(error, error_len, "cannot read control-plane journal: %s",
                      strerror(errno));
            wvm_control_plane_close(plane);
            return -1;
        }
        if (result < 0) {
            if (ftruncate(plane->journal_fd, frame_offset) != 0 ||
                fsync(plane->journal_fd) != 0) {
                set_error(error, error_len,
                          "cannot discard incomplete journal frame: %s",
                          strerror(errno));
                wvm_control_plane_close(plane);
                return -1;
            }
            break;
        }
        version = read_be16(header + 8);
        kind = read_be16(header + 10);
        sequence = read_be64(header + 12);
        payload_bytes = read_be32(header + 20);
        if (memcmp(header, journal_magic, sizeof(journal_magic)) != 0 ||
            version != WVM_CONTROL_JOURNAL_VERSION ||
            read_be32(header + 24) != 0 ||
            payload_bytes == 0 ||
            payload_bytes > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            set_error(error, error_len, "control-plane journal header is invalid");
            wvm_control_plane_close(plane);
            return -1;
        }
        payload = malloc(payload_bytes);
        if (!payload) {
            set_error(error, error_len, "cannot allocate journal replay frame");
            wvm_control_plane_close(plane);
            return -1;
        }
        result = read_full(plane->journal_fd, payload, payload_bytes);
        if (result == -2) {
            free(payload);
            set_error(error, error_len, "cannot read journal payload: %s",
                      strerror(errno));
            wvm_control_plane_close(plane);
            return -1;
        }
        if (result < 0) {
            free(payload);
            if (ftruncate(plane->journal_fd, frame_offset) != 0 ||
                fsync(plane->journal_fd) != 0) {
                set_error(error, error_len,
                          "cannot discard incomplete journal payload: %s",
                          strerror(errno));
                wvm_control_plane_close(plane);
                return -1;
            }
            break;
        }
        if (result == 0) {
            free(payload);
            if (ftruncate(plane->journal_fd, frame_offset) != 0 ||
                fsync(plane->journal_fd) != 0) {
                set_error(error, error_len,
                          "cannot discard incomplete journal payload: %s",
                          strerror(errno));
                wvm_control_plane_close(plane);
                return -1;
            }
            break;
        }
        wvm_sha256_digest(payload, payload_bytes, digest);
        if (memcmp(digest, header + 28, sizeof(digest)) != 0 ||
            replay_journal_frame(plane, kind, sequence, payload, payload_bytes,
                                 error, error_len) != 0) {
            free(payload);
            wvm_control_plane_close(plane);
            return -1;
        }
        free(payload);
    }
    /* Surviving complete frames may come from an unsuccessful prior fsync. */
    if (fsync(plane->journal_fd) != 0 ||
        sync_journal_directory(journal_path) != 0) {
        set_error(error, error_len, "cannot sync recovered control-plane journal: %s",
                  strerror(errno));
        wvm_control_plane_close(plane);
        return -1;
    }
    for (i = 0; i < plane->entry_count; i++) {
        if (restore_namespace(namespace_allocator,
                              &plane->entries[i].transaction, error,
                              error_len) != 0) {
            wvm_control_plane_close(plane);
            return -1;
        }
    }
    if (lseek(plane->journal_fd, 0, SEEK_END) < 0) {
        set_error(error, error_len, "cannot seek journal append position");
        wvm_control_plane_close(plane);
        return -1;
    }
    return 0;
}

void wvm_control_plane_close(struct wvm_control_plane *plane)
{
    if (!plane) {
        return;
    }
    wvm_control_plane_close_membership(plane);
    clear_route_transaction_entries(plane);
    clear_runtime_manifest_entries(plane);
    if (plane->journal_fd >= 0) {
        (void)flock(plane->journal_fd, LOCK_UN);
        (void)close(plane->journal_fd);
        plane->journal_fd = -1;
    }
}

int wvm_control_plane_begin(
    struct wvm_control_plane *plane, const struct wvm_vm_request *request,
    struct wvm_vm_namespace_allocator *namespace_allocator,
    const struct wvm_coordinator_id_provider *id_provider,
    enum wvm_control_plane_submit_result *result,
    struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len)
{
    struct wvm_control_plane_entry *existing;
    struct wvm_admission_transaction_record durable_transaction;
    uint8_t *request_bytes = NULL;
    uint8_t request_digest[WVM_SHA256_DIGEST_BYTES];
    size_t request_byte_count = 0;
    uint64_t ignored_sequence;

    if (!plane || !request || !namespace_allocator || !id_provider || !result ||
        !transaction ||
        encode_request_alloc(request, &request_bytes, &request_byte_count,
                             request_digest, error, error_len) != 0) {
        return -1;
    }
    existing = find_mutable_request(plane, request->request_id);
    if (existing) {
        if (memcmp(existing->transaction.request_digest, request_digest,
                   sizeof(request_digest)) != 0) {
            free(request_bytes);
            set_error(error, error_len,
                      "request ID was reused with different semantic fields");
            return -1;
        }
        transaction_to_coordinator(&existing->transaction, transaction);
        *result = WVM_CONTROL_PLANE_SUBMIT_REPLAY;
        free(request_bytes);
        return 0;
    }
    if (plane->entry_count == plane->entry_capacity ||
        wvm_coordinator_begin(request, namespace_allocator, id_provider,
                              transaction, error, error_len) != 0) {
        free(request_bytes);
        return -1;
    }
    transaction_from_coordinator(&durable_transaction, transaction,
                                 request_digest);
    if (append_journal_frame(plane, WVM_CONTROL_JOURNAL_REQUEST, request_bytes,
                             request_byte_count, &ignored_sequence, error,
                             error_len) != 0 ||
        append_transaction(plane, &durable_transaction, error, error_len) !=
            0) {
        /*
         * No durable transaction record was accepted if the append failed, so
         * release the in-memory allocation before returning the error.
         */
        (void)wvm_vm_namespace_begin_retire(namespace_allocator,
                                            transaction->vm_id,
                                            transaction->vm_incarnation, NULL,
                                            0);
        (void)wvm_vm_namespace_quarantine(namespace_allocator,
                                          transaction->vm_id,
                                          transaction->vm_incarnation,
                                          request_digest, 1, NULL, 0);
        (void)wvm_vm_namespace_release(namespace_allocator, transaction->vm_id,
                                       transaction->vm_incarnation, NULL, 0);
        free(request_bytes);
        return -1;
    }
    *result = WVM_CONTROL_PLANE_SUBMIT_NEW;
    free(request_bytes);
    return 0;
}

int wvm_control_plane_record_candidate(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_candidate_vm_manifest *candidate, char *error,
    size_t error_len)
{
    struct wvm_control_plane_entry *entry;
    struct wvm_admission_transaction_record updated_transaction;
    uint8_t *candidate_bytes = NULL;
    size_t candidate_byte_count = 0;
    uint64_t ignored_sequence;

    if (!plane || !transaction || !candidate ||
        encode_candidate_alloc(candidate, &candidate_bytes,
                               &candidate_byte_count, error, error_len) != 0) {
        return -1;
    }
    entry = find_mutable_request(plane, transaction->request_id);
    if (!entry ||
        entry->transaction.state != WVM_LIFECYCLE_IDENTITY_ALLOCATED ||
        entry->transaction.vm_id != candidate->vm_id ||
        entry->transaction.vm_incarnation != candidate->vm_incarnation ||
        entry->transaction.manifest_generation != candidate->manifest_generation ||
        memcmp(entry->transaction.admission_tx_id, candidate->admission_tx_id,
               sizeof(candidate->admission_tx_id)) != 0 ||
        memcmp(entry->transaction.manifest_id, candidate->manifest_id,
               sizeof(candidate->manifest_id)) != 0 ||
        memcmp(entry->transaction.request_id, candidate->request_id,
               sizeof(candidate->request_id)) != 0 ||
        entry->transaction.route_scope_key.vm_id != candidate->route_scope_key.vm_id ||
        entry->transaction.route_scope_key.vm_incarnation !=
            candidate->route_scope_key.vm_incarnation ||
        entry->transaction.route_scope_key.route_scope_id !=
            candidate->route_scope_key.route_scope_id) {
        free(candidate_bytes);
        set_error(error, error_len,
                  "candidate does not match durable admission transaction");
        return -1;
    }
    if (append_journal_frame(plane, WVM_CONTROL_JOURNAL_CANDIDATE,
                             candidate_bytes, candidate_byte_count,
                             &ignored_sequence, error, error_len) != 0) {
        free(candidate_bytes);
        return -1;
    }
    updated_transaction = entry->transaction;
    updated_transaction.state = WVM_LIFECYCLE_PLANNED;
    updated_transaction.has_candidate_manifest_digest = 1;
    memcpy(updated_transaction.candidate_manifest_digest,
           candidate->manifest_digest,
           sizeof(updated_transaction.candidate_manifest_digest));
    updated_transaction.has_prepared_route_snapshot_key = 1;
    updated_transaction.prepared_route_snapshot_key =
        candidate->prepared_route_snapshot_key;
    if (append_transaction(plane, &updated_transaction, error, error_len) != 0) {
        free(candidate_bytes);
        return -1;
    }
    free(candidate_bytes);
    return 0;
}

int wvm_control_plane_transition(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    enum wvm_lifecycle_state expected, enum wvm_lifecycle_state next,
    char *error, size_t error_len)
{
    struct wvm_control_plane_entry *entry;
    struct wvm_lifecycle_transaction lifecycle;
    struct wvm_admission_transaction_record updated_transaction;
    uint16_t required_route_state;

    if (!plane || !transaction) {
        set_error(error, error_len, "lifecycle transition input is invalid");
        return -1;
    }
    entry = find_mutable_request(plane, transaction->request_id);
    if (!entry || entry->transaction.state != expected ||
        entry->transaction.vm_id != transaction->vm_id ||
        entry->transaction.vm_incarnation != transaction->vm_incarnation ||
        memcmp(entry->transaction.admission_tx_id, transaction->admission_tx_id,
               sizeof(transaction->admission_tx_id)) != 0) {
        set_error(error, error_len,
                  "lifecycle transition does not match durable transaction");
        return -1;
    }
    if ((expected == WVM_LIFECYCLE_IDENTITY_ALLOCATED &&
         next == WVM_LIFECYCLE_PLANNED) ||
        (next >= WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED &&
         next != WVM_LIFECYCLE_ABORTING &&
         next != WVM_LIFECYCLE_ABORTED &&
         !entry->transaction.has_candidate_manifest_digest)) {
        set_error(error, error_len,
                  "candidate record must be durable before this transition");
        return -1;
    }
    if (lifecycle_route_gate_state(expected, next, &required_route_state)) {
        if (!entry->transaction.has_prepared_route_snapshot_key) {
            set_error(error, error_len,
                      "lifecycle transition lacks durable route snapshot");
            return -1;
        }
        if (durable_route_snapshot_has_state(
                plane, &entry->transaction.prepared_route_snapshot_key,
                required_route_state, error, error_len) != 0) {
            return -1;
        }
    }
    if (expected == WVM_LIFECYCLE_ACTIVATION_DECIDED &&
        next == WVM_LIFECYCLE_COMMITTED &&
        durable_runtime_manifests_complete(plane, transaction, error,
                                           error_len) != 0) {
        return -1;
    }
    memset(&lifecycle, 0, sizeof(lifecycle));
    lifecycle.vm_id = entry->transaction.vm_id;
    lifecycle.vm_incarnation = entry->transaction.vm_incarnation;
    memcpy(lifecycle.admission_tx_id, entry->transaction.admission_tx_id,
           sizeof(lifecycle.admission_tx_id));
    memcpy(lifecycle.candidate_manifest_digest,
           entry->transaction.candidate_manifest_digest,
           sizeof(lifecycle.candidate_manifest_digest));
    lifecycle.state = entry->transaction.state;
    if (wvm_lifecycle_transition(&lifecycle, expected, next, error,
                                 error_len) != 0) {
        return -1;
    }
    updated_transaction = entry->transaction;
    updated_transaction.state = lifecycle.state;
    return append_transaction(plane, &updated_transaction, error, error_len);
}

typedef int (*journal_record_match_fn)(
    const uint8_t *payload, size_t payload_bytes,
    const struct wvm_coordinator_transaction *transaction,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES]);

static int candidate_record_matches_transaction(
    const uint8_t *payload, size_t payload_bytes,
    const struct wvm_coordinator_transaction *transaction,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES])
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    struct wvm_canonical_field manifest_id;
    struct wvm_canonical_field manifest_digest;
    struct wvm_canonical_field vm_id;
    struct wvm_canonical_field vm_incarnation;
    struct wvm_canonical_field request_id;
    struct wvm_canonical_field admission_tx_id;
    int have_manifest_id = 0;
    int have_manifest_digest = 0;
    int have_vm_id = 0;
    int have_vm_incarnation = 0;
    int have_request_id = 0;
    int have_admission_tx_id = 0;
    size_t offset = 0;
    uint16_t previous_tag = 0;
    int next;

    if (!payload || !transaction || !candidate_manifest_digest ||
        wvm_canonical_record_parse(payload, payload_bytes, &record) != 0 ||
        record.record_type != WVM_RECORD_CANDIDATE_VM_MANIFEST) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 0 || field.tag <= previous_tag) {
            return -1;
        }
        previous_tag = field.tag;
        switch (field.tag) {
        case 1:
            manifest_id = field;
            have_manifest_id = 1;
            break;
        case 3:
            manifest_digest = field;
            have_manifest_digest = 1;
            break;
        case 4:
            vm_id = field;
            have_vm_id = 1;
            break;
        case 5:
            vm_incarnation = field;
            have_vm_incarnation = 1;
            break;
        case 7:
            request_id = field;
            have_request_id = 1;
            break;
        case 8:
            admission_tx_id = field;
            have_admission_tx_id = 1;
            break;
        }
    }
    if (next < 0 || !have_manifest_id || !have_manifest_digest ||
        !have_vm_id || !have_vm_incarnation || !have_request_id ||
        !have_admission_tx_id ||
        manifest_id.value_bytes != WVM_IDENTITY_ID_BYTES ||
        manifest_digest.value_bytes != WVM_SHA256_DIGEST_BYTES ||
        vm_id.value_bytes != 4 || vm_incarnation.value_bytes != 8 ||
        request_id.value_bytes != WVM_IDENTITY_ID_BYTES ||
        admission_tx_id.value_bytes != WVM_IDENTITY_ID_BYTES) {
        return -1;
    }
    return memcmp(manifest_id.value, transaction->manifest_id,
                  sizeof(transaction->manifest_id)) == 0 &&
                   memcmp(manifest_digest.value, candidate_manifest_digest,
                          WVM_SHA256_DIGEST_BYTES) == 0 &&
                   read_be32(vm_id.value) == transaction->vm_id &&
                   read_be64(vm_incarnation.value) ==
                       transaction->vm_incarnation &&
                   memcmp(request_id.value, transaction->request_id,
                          sizeof(transaction->request_id)) == 0 &&
                   memcmp(admission_tx_id.value, transaction->admission_tx_id,
                          sizeof(transaction->admission_tx_id)) == 0
               ? 1
               : 0;
}

static int activation_record_matches_transaction(
    const uint8_t *payload, size_t payload_bytes,
    const struct wvm_coordinator_transaction *transaction,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES])
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    struct wvm_canonical_field admission_tx_id;
    struct wvm_canonical_field manifest_digest;
    int have_admission_tx_id = 0;
    int have_manifest_digest = 0;
    size_t offset = 0;
    uint16_t previous_tag = 0;
    int next;

    if (!payload || !transaction || !candidate_manifest_digest ||
        wvm_canonical_record_parse(payload, payload_bytes, &record) != 0 ||
        record.record_type != WVM_RECORD_ACTIVATION_RECORD) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 0 || field.tag <= previous_tag) {
            return -1;
        }
        previous_tag = field.tag;
        if (field.tag == 1) {
            admission_tx_id = field;
            have_admission_tx_id = 1;
        } else if (field.tag == 2) {
            manifest_digest = field;
            have_manifest_digest = 1;
        }
    }
    if (next < 0 || !have_admission_tx_id || !have_manifest_digest ||
        admission_tx_id.value_bytes != WVM_IDENTITY_ID_BYTES ||
        manifest_digest.value_bytes != WVM_SHA256_DIGEST_BYTES) {
        return -1;
    }
    return memcmp(admission_tx_id.value, transaction->admission_tx_id,
                  sizeof(transaction->admission_tx_id)) == 0 &&
                   memcmp(manifest_digest.value, candidate_manifest_digest,
                          WVM_SHA256_DIGEST_BYTES) == 0
               ? 1
               : 0;
}

static int read_record_for_transaction(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, uint16_t kind,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    const uint8_t expected_record_digest[WVM_SHA256_DIGEST_BYTES],
    journal_record_match_fn matches, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    uint8_t header[WVM_CONTROL_JOURNAL_HEADER_BYTES];
    uint8_t *found = NULL;
    size_t found_bytes = 0;
    off_t append_position;
    int result = -1;

    if (!plane || plane->journal_fd < 0 || !transaction ||
        !candidate_manifest_digest || !matches || !bytes || !encoded_bytes) {
        set_error(error, error_len, "journal query input is invalid");
        return -1;
    }
    append_position = lseek(plane->journal_fd, 0, SEEK_CUR);
    if (append_position < 0 || lseek(plane->journal_fd, 0, SEEK_SET) < 0) {
        set_error(error, error_len, "cannot seek control-plane journal");
        return -1;
    }
    while (1) {
        uint8_t *payload;
        uint8_t digest[WVM_SHA256_DIGEST_BYTES];
        uint16_t frame_kind;
        uint32_t payload_bytes;
        int matched;

        result = read_full(plane->journal_fd, header, sizeof(header));
        if (result == 0) {
            result = 0;
            break;
        }
        if (result != 1 ||
            memcmp(header, journal_magic, sizeof(journal_magic)) != 0 ||
            read_be16(header + 8) != WVM_CONTROL_JOURNAL_VERSION ||
            read_be32(header + 24) != 0) {
            set_error(error, error_len, "journal is invalid during recovery query");
            result = -1;
            break;
        }
        frame_kind = read_be16(header + 10);
        payload_bytes = read_be32(header + 20);
        if (payload_bytes == 0 ||
            payload_bytes > WVM_CONTROL_PLANE_MAX_RECORD_BYTES) {
            set_error(error, error_len, "journal frame has invalid payload size");
            result = -1;
            break;
        }
        payload = malloc(payload_bytes);
        if (!payload) {
            set_error(error, error_len, "cannot allocate journal query payload");
            result = -1;
            break;
        }
        if (read_full(plane->journal_fd, payload, payload_bytes) != 1) {
            free(payload);
            set_error(error, error_len, "journal changed during recovery query");
            result = -1;
            break;
        }
        wvm_sha256_digest(payload, payload_bytes, digest);
        if (memcmp(digest, header + 28, sizeof(digest)) != 0) {
            free(payload);
            set_error(error, error_len, "journal payload digest is invalid");
            result = -1;
            break;
        }
        if (frame_kind != kind) {
            free(payload);
            continue;
        }
        matched = matches(payload, payload_bytes, transaction,
                          candidate_manifest_digest);
        if (matched < 0) {
            free(payload);
            set_error(error, error_len, "journal record is malformed");
            result = -1;
            break;
        }
        if (matched == 0) {
            free(payload);
            continue;
        }
        if (expected_record_digest &&
            memcmp(digest, expected_record_digest, sizeof(digest)) != 0) {
            free(payload);
            set_error(error, error_len,
                      "journal record does not match persisted transaction digest");
            result = -1;
            break;
        }
        if (found) {
            if (found_bytes != payload_bytes ||
                memcmp(found, payload, payload_bytes) != 0) {
                free(payload);
                set_error(error, error_len,
                          "transaction has conflicting durable records");
                result = -1;
                break;
            }
            free(payload);
            continue;
        }
        found = payload;
        found_bytes = payload_bytes;
    }
    if (lseek(plane->journal_fd, append_position, SEEK_SET) < 0) {
        free(found);
        set_error(error, error_len, "cannot restore journal append position");
        return -1;
    }
    if (result != 0) {
        free(found);
        return -1;
    }
    if (!found) {
        set_error(error, error_len, "durable transaction record was not found");
        return -1;
    }
    if (found_bytes > capacity) {
        free(found);
        set_error(error, error_len, "journal record output buffer is too small");
        return -1;
    }
    memcpy(bytes, found, found_bytes);
    *encoded_bytes = found_bytes;
    free(found);
    return 0;
}

int wvm_control_plane_read_candidate(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    const struct wvm_control_plane_entry *entry;

    if (!plane || !transaction) {
        set_error(error, error_len, "candidate recovery input is invalid");
        return -1;
    }
    entry = wvm_control_plane_find_request(plane, transaction->request_id);
    if (!entry || !entry->transaction.has_candidate_manifest_digest ||
        entry->transaction.vm_id != transaction->vm_id ||
        entry->transaction.vm_incarnation != transaction->vm_incarnation ||
        memcmp(entry->transaction.admission_tx_id, transaction->admission_tx_id,
               sizeof(transaction->admission_tx_id)) != 0) {
        set_error(error, error_len,
                  "candidate recovery does not match durable transaction");
        return -1;
    }
    return read_record_for_transaction(
        plane, transaction, WVM_CONTROL_JOURNAL_CANDIDATE,
        entry->transaction.candidate_manifest_digest, NULL,
        candidate_record_matches_transaction, bytes, capacity, encoded_bytes,
        error, error_len);
}

int wvm_control_plane_read_activation(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    const struct wvm_control_plane_entry *entry;

    if (!plane || !transaction) {
        set_error(error, error_len, "activation recovery input is invalid");
        return -1;
    }
    entry = wvm_control_plane_find_request(plane, transaction->request_id);
    if (!entry || !entry->transaction.has_candidate_manifest_digest ||
        !entry->transaction.has_activation_record_digest ||
        entry->transaction.vm_id != transaction->vm_id ||
        entry->transaction.vm_incarnation != transaction->vm_incarnation ||
        memcmp(entry->transaction.admission_tx_id, transaction->admission_tx_id,
               sizeof(transaction->admission_tx_id)) != 0) {
        set_error(error, error_len,
                  "activation recovery does not match durable transaction");
        return -1;
    }
    return read_record_for_transaction(
        plane, transaction, WVM_CONTROL_JOURNAL_ACTIVATION,
        entry->transaction.candidate_manifest_digest,
        entry->transaction.activation_record_digest,
        activation_record_matches_transaction, bytes, capacity, encoded_bytes,
        error, error_len);
}

static int read_candidate_alloc(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, uint8_t **bytes_out,
    size_t *byte_count_out, char *error, size_t error_len)
{
    uint8_t *bytes;
    size_t byte_count = 0;

    if (!bytes_out || !byte_count_out) {
        set_error(error, error_len, "candidate allocation output is invalid");
        return -1;
    }
    bytes = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    if (!bytes ||
        wvm_control_plane_read_candidate(
            plane, transaction, bytes, WVM_CONTROL_PLANE_MAX_RECORD_BYTES,
            &byte_count, error, error_len) != 0) {
        free(bytes);
        return -1;
    }
    *bytes_out = bytes;
    *byte_count_out = byte_count;
    return 0;
}

static int reservation_requirement_identity_from_record(
    const uint8_t *bytes, size_t byte_count, uint8_t reservation_id[16],
    uint32_t *physical_node_id, uint64_t *node_instance_id)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    struct wvm_canonical_field fields[4];
    unsigned char present[4];
    size_t offset = 0;
    int next;

    if (!bytes || !reservation_id || !physical_node_id || !node_instance_id ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_RESERVATION_REQUIREMENT) {
        return -1;
    }
    memset(fields, 0, sizeof(fields));
    memset(present, 0, sizeof(present));
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag < sizeof(fields) / sizeof(fields[0])) {
            fields[field.tag] = field;
            present[field.tag] = 1;
        }
    }
    if (next < 0 || !present[1] || !present[2] || !present[3] ||
        fields[1].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[2].value_bytes != 4 || fields[3].value_bytes != 8) {
        return -1;
    }
    memcpy(reservation_id, fields[1].value, WVM_IDENTITY_ID_BYTES);
    *physical_node_id = read_be32(fields[2].value);
    *node_instance_id = read_be64(fields[3].value);
    return *physical_node_id != 0 && *node_instance_id != 0 ? 0 : -1;
}

static int candidate_runtime_binding_matches(
    const uint8_t *bytes, size_t byte_count,
    const struct runtime_manifest_identity *runtime_identity)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    struct wvm_canonical_field fields[24];
    unsigned char present[24];
    struct wvm_route_snapshot_key route_key;
    size_t offset = 0;
    int next;

    if (!bytes || !runtime_identity ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_CANDIDATE_VM_MANIFEST) {
        return -1;
    }
    memset(fields, 0, sizeof(fields));
    memset(present, 0, sizeof(present));
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag < sizeof(fields) / sizeof(fields[0])) {
            fields[field.tag] = field;
            present[field.tag] = 1;
        }
    }
    if (next < 0 || !present[3] || !present[4] || !present[5] ||
        !present[6] || !present[8] || !present[9] || !present[23] ||
        fields[3].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[4].value_bytes != 4 || fields[5].value_bytes != 8 ||
        fields[6].value_bytes != 8 ||
        fields[8].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[9].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        wvm_route_snapshot_key_decode(fields[23].value, fields[23].value_bytes,
                                      &route_key, NULL, 0) != 0) {
        return -1;
    }
    return memcmp(fields[3].value, runtime_identity->candidate_manifest_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0 &&
                   read_be32(fields[4].value) == runtime_identity->vm_id &&
                   read_be64(fields[5].value) ==
                       runtime_identity->vm_incarnation &&
                   read_be64(fields[6].value) ==
                       runtime_identity->manifest_generation &&
                   memcmp(fields[8].value, runtime_identity->admission_tx_id,
                          WVM_IDENTITY_ID_BYTES) == 0 &&
                   memcmp(fields[9].value,
                          runtime_identity->eligibility_fence_digest,
                          WVM_SHA256_DIGEST_BYTES) == 0 &&
                   route_snapshot_key_equal(
                       &route_key,
                       &runtime_identity->required_route_snapshot_key);
}

static int candidate_contains_runtime_requirement(
    const uint8_t *bytes, size_t byte_count,
    const struct runtime_manifest_identity *runtime_identity)
{
    struct wvm_canonical_record candidate;
    struct wvm_canonical_field field;
    const uint8_t *list_bytes = NULL;
    size_t list_byte_count = 0;
    size_t offset = 0;
    size_t list_offset;
    uint32_t count;
    uint32_t i;
    int next;

    if (!bytes || !runtime_identity ||
        wvm_canonical_record_parse(bytes, byte_count, &candidate) != 0 ||
        candidate.record_type != WVM_RECORD_CANDIDATE_VM_MANIFEST) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&candidate, &offset, &field)) ==
           1) {
        if (field.tag == 21) {
            list_bytes = field.value;
            list_byte_count = field.value_bytes;
            break;
        }
    }
    if (next < 0 || !list_bytes || list_byte_count < 4) {
        return -1;
    }
    count = read_be32(list_bytes);
    list_offset = 4;
    for (i = 0; i < count; i++) {
        uint32_t item_byte_count;
        uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
        uint32_t physical_node_id;
        uint64_t node_instance_id;

        if (list_byte_count - list_offset < 4) {
            return -1;
        }
        item_byte_count = read_be32(list_bytes + list_offset);
        list_offset += 4;
        if (item_byte_count == 0 || item_byte_count > list_byte_count - list_offset ||
            reservation_requirement_identity_from_record(
                list_bytes + list_offset, item_byte_count, reservation_id,
                &physical_node_id, &node_instance_id) != 0) {
            return -1;
        }
        list_offset += item_byte_count;
        if (physical_node_id == runtime_identity->physical_node_id &&
            node_instance_id == runtime_identity->expected_node_instance_id &&
            memcmp(reservation_id, runtime_identity->reservation_id,
                   sizeof(reservation_id)) == 0) {
            return 1;
        }
    }
    return list_offset == list_byte_count ? 0 : -1;
}

static int durable_activation_matches_runtime(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct runtime_manifest_identity *runtime_identity, char *error,
    size_t error_len)
{
    uint8_t *activation_bytes;
    size_t activation_byte_count = 0;
    struct wvm_canonical_record activation;
    struct wvm_canonical_field field;
    struct wvm_canonical_field fields[8];
    unsigned char present[8];
    size_t offset = 0;
    int next;
    int result = -1;

    activation_bytes = malloc(WVM_CONTROL_PLANE_MAX_RECORD_BYTES);
    if (!activation_bytes ||
        wvm_control_plane_read_activation(
            plane, transaction, activation_bytes,
            WVM_CONTROL_PLANE_MAX_RECORD_BYTES, &activation_byte_count, error,
            error_len) != 0 ||
        wvm_canonical_record_parse(activation_bytes, activation_byte_count,
                                   &activation) != 0 ||
        activation.record_type != WVM_RECORD_ACTIVATION_RECORD) {
        free(activation_bytes);
        return -1;
    }
    memset(fields, 0, sizeof(fields));
    memset(present, 0, sizeof(present));
    while ((next = wvm_canonical_record_next(&activation, &offset, &field)) ==
           1) {
        if (field.tag < sizeof(fields) / sizeof(fields[0])) {
            fields[field.tag] = field;
            present[field.tag] = 1;
        }
    }
    if (next == 0 && present[1] && present[2] && present[3] && present[7] &&
        fields[1].value_bytes == WVM_IDENTITY_ID_BYTES &&
        fields[2].value_bytes == WVM_SHA256_DIGEST_BYTES &&
        fields[3].value_bytes == WVM_IDENTITY_ID_BYTES &&
        fields[7].value_bytes == 2 &&
        read_be16(fields[7].value) == WVM_ACTIVATION_ACTIVATE &&
        memcmp(fields[1].value, runtime_identity->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) == 0 &&
        memcmp(fields[2].value, runtime_identity->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) == 0 &&
        memcmp(fields[3].value, runtime_identity->activation_fence,
               WVM_IDENTITY_ID_BYTES) == 0) {
        result = 0;
    } else {
        set_error(error, error_len,
                  "runtime manifest activation fence is not durable");
    }
    free(activation_bytes);
    return result;
}

static int durable_runtime_manifests_complete(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len)
{
    const struct wvm_control_plane_entry *transaction_entry;
    uint8_t *candidate_bytes = NULL;
    size_t candidate_byte_count = 0;
    struct wvm_canonical_record candidate;
    struct wvm_canonical_field field;
    const uint8_t *list_bytes = NULL;
    size_t list_byte_count = 0;
    size_t offset = 0;
    size_t list_offset;
    size_t persisted_count = 0;
    uint32_t requirement_count;
    uint32_t i;
    int next;
    int result = -1;

    if (!plane || !transaction ||
        !(transaction_entry =
              wvm_control_plane_find_request(plane, transaction->request_id)) ||
        !transaction_entry->transaction.has_candidate_manifest_digest ||
        !transaction_entry->transaction.has_activation_record_digest ||
        transaction_entry->transaction.vm_id != transaction->vm_id ||
        transaction_entry->transaction.vm_incarnation !=
            transaction->vm_incarnation ||
        memcmp(transaction_entry->transaction.admission_tx_id,
               transaction->admission_tx_id,
               sizeof(transaction->admission_tx_id)) != 0 ||
        read_candidate_alloc(plane, transaction, &candidate_bytes,
                             &candidate_byte_count, error, error_len) != 0 ||
        wvm_canonical_record_parse(candidate_bytes, candidate_byte_count,
                                   &candidate) != 0 ||
        candidate.record_type != WVM_RECORD_CANDIDATE_VM_MANIFEST) {
        free(candidate_bytes);
        set_error(error, error_len,
                  "cannot verify durable runtime manifest projections");
        return -1;
    }
    while ((next = wvm_canonical_record_next(&candidate, &offset, &field)) ==
           1) {
        if (field.tag == 21) {
            list_bytes = field.value;
            list_byte_count = field.value_bytes;
            break;
        }
    }
    if (next < 0 || !list_bytes || list_byte_count < 4) {
        set_error(error, error_len,
                  "candidate lacks durable reservation requirements");
        goto out;
    }
    requirement_count = read_be32(list_bytes);
    if (requirement_count == 0) {
        set_error(error, error_len, "candidate has no runtime participants");
        goto out;
    }
    list_offset = 4;
    for (i = 0; i < requirement_count; i++) {
        uint32_t item_byte_count;
        uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
        uint32_t physical_node_id;
        uint64_t node_instance_id;
        const struct wvm_control_plane_runtime_manifest_entry *runtime_entry;
        struct runtime_manifest_identity runtime_identity;

        if (list_byte_count - list_offset < 4) {
            set_error(error, error_len,
                      "candidate reservation requirement list is invalid");
            goto out;
        }
        item_byte_count = read_be32(list_bytes + list_offset);
        list_offset += 4;
        if (item_byte_count == 0 || item_byte_count > list_byte_count - list_offset ||
            reservation_requirement_identity_from_record(
                list_bytes + list_offset, item_byte_count, reservation_id,
                &physical_node_id, &node_instance_id) != 0) {
            set_error(error, error_len,
                      "candidate reservation requirement is invalid");
            goto out;
        }
        list_offset += item_byte_count;
        runtime_entry = wvm_control_plane_find_runtime_manifest(
            plane, transaction_entry->transaction.candidate_manifest_digest,
            physical_node_id);
        if (!runtime_entry ||
            runtime_entry->expected_node_instance_id != node_instance_id ||
            memcmp(runtime_entry->reservation_id, reservation_id,
                   sizeof(reservation_id)) != 0 ||
            runtime_manifest_identity_from_record(
                runtime_entry->record_bytes, runtime_entry->record_byte_count,
                &runtime_identity) != 0 ||
            candidate_runtime_binding_matches(
                candidate_bytes, candidate_byte_count, &runtime_identity) != 1 ||
            durable_activation_matches_runtime(plane, transaction,
                                               &runtime_identity, error,
                                               error_len) != 0) {
            set_error(error, error_len,
                      "candidate lacks durable runtime manifest projection");
            goto out;
        }
    }
    if (list_offset != list_byte_count) {
        set_error(error, error_len,
                  "candidate reservation requirement list has trailing bytes");
        goto out;
    }
    for (i = 0; i < plane->runtime_manifest_entry_count; i++) {
        if (memcmp(plane->runtime_manifest_entries[i].candidate_manifest_digest,
                   transaction_entry->transaction.candidate_manifest_digest,
                   WVM_SHA256_DIGEST_BYTES) == 0) {
            persisted_count++;
        }
    }
    if (persisted_count != requirement_count) {
        set_error(error, error_len,
                  "candidate has extra or missing durable runtime projections");
        goto out;
    }
    result = 0;

out:
    free(candidate_bytes);
    return result;
}

int wvm_control_plane_record_runtime_manifest(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    struct wvm_control_plane_entry *transaction_entry;
    struct runtime_manifest_identity runtime_identity;
    struct wvm_control_plane_runtime_manifest_entry *existing;
    uint8_t *runtime_manifest_bytes = NULL;
    uint8_t *candidate_bytes = NULL;
    size_t runtime_manifest_byte_count = 0;
    size_t candidate_byte_count = 0;
    uint64_t ignored_sequence;
    int result = -1;

    if (!plane || !transaction || !runtime_manifest ||
        wvm_node_runtime_manifest_validate(runtime_manifest, error,
                                           error_len) != 0 ||
        encode_runtime_manifest_alloc(runtime_manifest, &runtime_manifest_bytes,
                                     &runtime_manifest_byte_count, error,
                                     error_len) != 0 ||
        runtime_manifest_identity_from_record(runtime_manifest_bytes,
                                              runtime_manifest_byte_count,
                                              &runtime_identity) != 0) {
        free(runtime_manifest_bytes);
        set_error(error, error_len, "runtime manifest persistence input is invalid");
        return -1;
    }
    transaction_entry = find_mutable_request(plane, transaction->request_id);
    if (!transaction_entry ||
        transaction_entry->transaction.state !=
            WVM_LIFECYCLE_ACTIVATION_DECIDED ||
        !transaction_entry->transaction.has_candidate_manifest_digest ||
        !transaction_entry->transaction.has_activation_record_digest ||
        transaction_entry->transaction.vm_id != runtime_identity.vm_id ||
        transaction_entry->transaction.vm_incarnation !=
            runtime_identity.vm_incarnation ||
        transaction_entry->transaction.manifest_generation !=
            runtime_identity.manifest_generation ||
        memcmp(transaction_entry->transaction.admission_tx_id,
               runtime_identity.admission_tx_id,
               sizeof(runtime_identity.admission_tx_id)) != 0 ||
        memcmp(transaction_entry->transaction.candidate_manifest_digest,
               runtime_identity.candidate_manifest_digest,
               sizeof(runtime_identity.candidate_manifest_digest)) != 0 ||
        read_candidate_alloc(plane, transaction, &candidate_bytes,
                             &candidate_byte_count, error, error_len) != 0 ||
        candidate_runtime_binding_matches(candidate_bytes, candidate_byte_count,
                                          &runtime_identity) != 1 ||
        candidate_contains_runtime_requirement(
            candidate_bytes, candidate_byte_count, &runtime_identity) != 1 ||
        durable_activation_matches_runtime(plane, transaction, &runtime_identity,
                                           error, error_len) != 0) {
        set_error(error, error_len,
                  "runtime manifest does not match durable activation");
        goto out;
    }
    existing = find_mutable_runtime_manifest(
        plane, runtime_identity.candidate_manifest_digest,
        runtime_identity.physical_node_id);
    if (existing) {
        if (existing->expected_node_instance_id ==
                runtime_identity.expected_node_instance_id &&
            memcmp(existing->reservation_id, runtime_identity.reservation_id,
                   sizeof(existing->reservation_id)) == 0 &&
            existing->record_byte_count == runtime_manifest_byte_count &&
            memcmp(existing->record_bytes, runtime_manifest_bytes,
                   runtime_manifest_byte_count) == 0) {
            result = 0;
            goto out;
        }
        set_error(error, error_len,
                  "runtime manifest conflicts with durable node projection");
        goto out;
    }
    if (!plane->runtime_manifest_entries ||
        plane->runtime_manifest_entry_count ==
            plane->runtime_manifest_entry_capacity) {
        set_error(error, error_len, "runtime manifest entry capacity is full");
        goto out;
    }
    if (append_journal_frame(plane, WVM_CONTROL_JOURNAL_RUNTIME_MANIFEST,
                             runtime_manifest_bytes,
                             runtime_manifest_byte_count, &ignored_sequence,
                             error, error_len) != 0 ||
        install_runtime_manifest_record(
            plane, &runtime_identity, runtime_manifest_bytes,
            runtime_manifest_byte_count, error, error_len) != 0) {
        goto out;
    }
    runtime_manifest_bytes = NULL;
    result = 0;

out:
    free(candidate_bytes);
    free(runtime_manifest_bytes);
    return result;
}

int wvm_control_plane_read_runtime_manifest(
    const struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    uint32_t physical_node_id, uint64_t expected_node_instance_id,
    uint8_t *bytes, size_t capacity, size_t *encoded_bytes, char *error,
    size_t error_len)
{
    const struct wvm_control_plane_entry *transaction_entry;
    const struct wvm_control_plane_runtime_manifest_entry *runtime_entry;

    if (!plane || !transaction || physical_node_id == 0 ||
        expected_node_instance_id == 0 || !bytes || !encoded_bytes ||
        !(transaction_entry =
              wvm_control_plane_find_request(plane, transaction->request_id)) ||
        !transaction_entry->transaction.has_candidate_manifest_digest ||
        transaction_entry->transaction.vm_id != transaction->vm_id ||
        transaction_entry->transaction.vm_incarnation !=
            transaction->vm_incarnation ||
        memcmp(transaction_entry->transaction.admission_tx_id,
               transaction->admission_tx_id,
               sizeof(transaction->admission_tx_id)) != 0 ||
        !(runtime_entry = wvm_control_plane_find_runtime_manifest(
              plane, transaction_entry->transaction.candidate_manifest_digest,
              physical_node_id)) ||
        runtime_entry->expected_node_instance_id != expected_node_instance_id ||
        runtime_entry->record_byte_count > capacity) {
        set_error(error, error_len,
                  "runtime manifest recovery does not match durable transaction");
        return -1;
    }
    memcpy(bytes, runtime_entry->record_bytes, runtime_entry->record_byte_count);
    *encoded_bytes = runtime_entry->record_byte_count;
    return 0;
}

int wvm_control_plane_activation_options(
    const struct wvm_control_plane *plane, uint64_t coordinator_instance_id,
    struct wvm_coordinator_activation_options *options, char *error,
    size_t error_len)
{
    struct timespec now;

    if (!plane || plane->journal_fd < 0 || plane->journal_failed ||
        plane->next_journal_sequence == 0 ||
        plane->next_journal_sequence == UINT64_MAX ||
        coordinator_instance_id == 0 || !options ||
        clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec <= 0) {
        set_error(error, error_len, "activation metadata requires a writable journal and owner");
        return -1;
    }
    options->coordinator_instance_id = coordinator_instance_id;
    options->durable_decision_sequence = plane->next_journal_sequence;
    options->decided_at = (uint64_t)now.tv_sec;
    return 0;
}

int wvm_control_plane_record_activation(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    struct wvm_control_plane_entry *entry;
    struct wvm_admission_transaction_record updated_transaction;
    uint8_t *activation_bytes = NULL;
    uint8_t activation_digest[WVM_SHA256_DIGEST_BYTES];
    size_t activation_byte_count = 0;
    uint64_t sequence;

    if (!plane || plane->journal_fd < 0 || plane->journal_failed ||
        !transaction || !activation ||
        encode_activation_alloc(activation, &activation_bytes,
                                &activation_byte_count, activation_digest,
                                error, error_len) != 0) {
        return -1;
    }
    entry = find_mutable_request(plane, transaction->request_id);
    if (!entry ||
        entry->transaction.vm_id != transaction->vm_id ||
        entry->transaction.vm_incarnation != transaction->vm_incarnation ||
        entry->transaction.manifest_generation != transaction->manifest_generation ||
        memcmp(entry->transaction.admission_tx_id, transaction->admission_tx_id,
               sizeof(transaction->admission_tx_id)) != 0) {
        free(activation_bytes);
        set_error(error, error_len,
                  "activation does not match durable candidate transaction");
        return -1;
    }
    if (entry->transaction.has_activation_record_digest) {
        int matches = memcmp(entry->transaction.activation_record_digest,
                             activation_digest, sizeof(activation_digest)) == 0;
        free(activation_bytes);
        if (!matches) {
            set_error(error, error_len, "activation conflicts with durable decision");
        }
        return matches ? 0 : -1;
    }
    if (activation_transaction(plane, entry, activation,
                                plane->next_journal_sequence,
                                activation_digest, &updated_transaction,
                                error, error_len) != 0) {
        free(activation_bytes);
        return -1;
    }
    if (append_journal_frame(plane, WVM_CONTROL_JOURNAL_ACTIVATION,
                             activation_bytes, activation_byte_count,
                             &sequence, error, error_len) != 0) {
        free(activation_bytes);
        return -1;
    }
    /* The decision frame itself is the state transition, including on replay. */
    entry->transaction = updated_transaction;
    free(activation_bytes);
    return 0;
}

static int control_plane_start_after_readiness(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifests,
    size_t runtime_manifest_count,
    wvm_control_plane_readiness_observer_fn observe_ready,
    void *observer_context, char *error, size_t error_len)
{
    struct wvm_control_plane_entry *entry;
    size_t durable_count = 0;
    size_t i;

    if (!plane || !transaction || !runtime_manifests ||
        runtime_manifest_count == 0) {
        set_error(error, error_len, "runtime readiness input is invalid");
        return -1;
    }
    entry = find_mutable_request(plane, transaction->request_id);
    if (!entry || entry->transaction.vm_id != transaction->vm_id ||
        entry->transaction.vm_incarnation != transaction->vm_incarnation ||
        !entry->transaction.has_candidate_manifest_digest ||
        memcmp(entry->transaction.admission_tx_id,
               transaction->admission_tx_id,
               sizeof(transaction->admission_tx_id)) != 0) {
        set_error(error, error_len,
                  "runtime readiness transaction is not durable");
        return -1;
    }
    if (entry->transaction.state == WVM_LIFECYCLE_RUNNING) {
        return 0;
    }
    if (entry->transaction.state != WVM_LIFECYCLE_COMMITTED) {
        set_error(error, error_len,
                  "runtime readiness requires COMMITTED lifecycle state");
        return -1;
    }
    for (i = 0; i < plane->runtime_manifest_entry_count; i++) {
        if (memcmp(plane->runtime_manifest_entries[i]
                       .candidate_manifest_digest,
                   entry->transaction.candidate_manifest_digest,
                   sizeof(entry->transaction.candidate_manifest_digest)) == 0) {
            durable_count++;
        }
    }
    if (durable_count != runtime_manifest_count) {
        set_error(error, error_len,
                  "runtime readiness projection count does not match durable state");
        return -1;
    }
    if (durable_runtime_manifests_complete(plane, transaction, error,
                                           error_len) != 0) {
        return -1;
    }
    for (i = 0; i < runtime_manifest_count; i++) {
        const struct wvm_node_runtime_manifest *manifest =
            &runtime_manifests[i];
        size_t j;

        if (memcmp(manifest->candidate_manifest_digest,
                   entry->transaction.candidate_manifest_digest,
                   sizeof(manifest->candidate_manifest_digest)) != 0 ||
            manifest->vm_id != entry->transaction.vm_id ||
            manifest->vm_incarnation != entry->transaction.vm_incarnation ||
            !manifest->has_activation_fence) {
            set_error(error, error_len,
                      "runtime readiness manifest identity mismatch");
            return -1;
        }
        if (candidate &&
            (candidate->vm_id != manifest->vm_id ||
             candidate->vm_incarnation != manifest->vm_incarnation ||
             candidate->manifest_generation != manifest->manifest_generation ||
             memcmp(candidate->manifest_digest,
                    manifest->candidate_manifest_digest,
                    sizeof(candidate->manifest_digest)) != 0 ||
             memcmp(candidate->admission_tx_id, manifest->admission_tx_id,
                    sizeof(candidate->admission_tx_id)) != 0)) {
            set_error(error, error_len,
                      "runtime readiness candidate does not match participant");
            return -1;
        }
        for (j = 0; j < i; j++) {
            if (runtime_manifests[j].physical_node_id ==
                manifest->physical_node_id) {
                set_error(error, error_len,
                          "runtime readiness contains duplicate physical node");
                return -1;
            }
        }
        {
            int ready_result = observe_ready
                                   ? observe_ready(observer_context, candidate,
                                                   manifest, error, error_len)
                                   : wvm_runtime_ready_validate(
                                         manifest,
                                         manifest->expected_node_instance_id,
                                         error, error_len);

            if (ready_result != 0) {
                return ready_result == -EAGAIN ? -EAGAIN : -1;
            }
        }
    }
    if (wvm_control_plane_transition(
            plane, transaction, WVM_LIFECYCLE_COMMITTED,
            WVM_LIFECYCLE_STARTING, error, error_len) != 0 ||
        wvm_control_plane_transition(
            plane, transaction, WVM_LIFECYCLE_STARTING,
            WVM_LIFECYCLE_RUNNING, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

int wvm_control_plane_start_if_ready(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_node_runtime_manifest *runtime_manifests,
    size_t runtime_manifest_count, char *error, size_t error_len)
{
    return control_plane_start_after_readiness(
        plane, transaction, NULL, runtime_manifests, runtime_manifest_count,
        NULL, NULL, error, error_len);
}

int wvm_control_plane_start_if_participants_ready(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifests,
    size_t runtime_manifest_count,
    wvm_control_plane_readiness_observer_fn observe_ready,
    void *observer_context, char *error, size_t error_len)
{
    if (!candidate || !observe_ready ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0) {
        set_error(error, error_len,
                  "participant readiness observer input is invalid");
        return -1;
    }
    return control_plane_start_after_readiness(
        plane, transaction, candidate, runtime_manifests,
        runtime_manifest_count, observe_ready, observer_context, error,
        error_len);
}

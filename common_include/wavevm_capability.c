#include "wavevm_capability.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_canonical.h"

typedef int (*capability_record_size_fn)(const void *entry,
                                         size_t *encoded_size);
typedef int (*capability_record_encode_fn)(const void *entry, uint8_t *bytes,
                                           size_t capacity,
                                           size_t *encoded_bytes, char *error,
                                           size_t error_len);
typedef int (*capability_record_decode_fn)(const uint8_t *bytes,
                                           size_t encoded_bytes, void *entry,
                                           char *error, size_t error_len);

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

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int checked_add_size(size_t *total, size_t value)
{
    if (!total || value > SIZE_MAX - *total) {
        return -1;
    }
    *total += value;
    return 0;
}

static int canonical_record_size(const size_t *value_sizes, size_t field_count,
                                 size_t *encoded_size)
{
    size_t total = WVM_CANONICAL_RECORD_HEADER_BYTES;
    size_t i;

    if (!value_sizes || !encoded_size) {
        return -1;
    }
    for (i = 0; i < field_count; i++) {
        if (checked_add_size(&total, WVM_CANONICAL_FIELD_HEADER_BYTES) != 0 ||
            checked_add_size(&total, value_sizes[i]) != 0) {
            return -1;
        }
    }
    *encoded_size = total;
    return 0;
}

static int parse_exact_fields(const uint8_t *bytes, size_t encoded_bytes,
                              uint16_t expected_record_type,
                              struct wvm_canonical_field *fields,
                              size_t expected_field_count, char *error,
                              size_t error_len)
{
    struct wvm_canonical_record record;
    size_t offset = 0;
    size_t count = 0;
    int next;

    if (wvm_canonical_record_parse(bytes, encoded_bytes, &record) != 0 ||
        record.record_type != expected_record_type) {
        set_error(error, error_len, "invalid canonical record type 0x%04x",
                  expected_record_type);
        return -1;
    }
    while (1) {
        struct wvm_canonical_field field;

        next = wvm_canonical_record_next(&record, &offset, &field);
        if (next != 1) {
            break;
        }
        if (count >= expected_field_count || field.tag != count + 1U) {
            set_error(error, error_len, "record has unknown or missing fields");
            return -1;
        }
        fields[count++] = field;
    }
    if (next < 0 || count != expected_field_count) {
        set_error(error, error_len, "record has malformed fields");
        return -1;
    }
    return 0;
}

static int record_list_size(const void *entries, size_t count,
                            size_t entry_bytes, capability_record_size_fn size_fn,
                            size_t *encoded_size)
{
    const uint8_t *base = entries;
    size_t total = 4;
    size_t i;

    if (!size_fn || !encoded_size || (count != 0 && !entries) ||
        count > UINT32_MAX) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        size_t item_bytes;

        if (size_fn(base + i * entry_bytes, &item_bytes) != 0 ||
            item_bytes > UINT32_MAX || checked_add_size(&total, 4) != 0 ||
            checked_add_size(&total, item_bytes) != 0) {
            return -1;
        }
    }
    *encoded_size = total;
    return 0;
}

static int record_list_encode(const void *entries, size_t count,
                              size_t entry_bytes,
                              capability_record_size_fn size_fn,
                              capability_record_encode_fn encode_fn,
                              uint8_t *bytes, size_t encoded_bytes,
                              char *error, size_t error_len)
{
    const uint8_t *base = entries;
    size_t expected_bytes;
    size_t offset = 4;
    size_t i;

    if (!bytes || !encode_fn ||
        record_list_size(entries, count, entry_bytes, size_fn,
                         &expected_bytes) != 0 ||
        expected_bytes != encoded_bytes) {
        set_error(error, error_len, "canonical capability list has bad size");
        return -1;
    }
    write_be32(bytes, (uint32_t)count);
    for (i = 0; i < count; i++) {
        size_t item_bytes;
        size_t actual_bytes;

        if (size_fn(base + i * entry_bytes, &item_bytes) != 0) {
            return -1;
        }
        write_be32(bytes + offset, (uint32_t)item_bytes);
        offset += 4;
        if (encode_fn(base + i * entry_bytes, bytes + offset, item_bytes,
                      &actual_bytes, error, error_len) != 0 ||
            actual_bytes != item_bytes) {
            return -1;
        }
        offset += item_bytes;
    }
    return offset == encoded_bytes ? 0 : -1;
}

static int record_list_decode(const uint8_t *bytes, size_t encoded_bytes,
                              void *entries, size_t capacity,
                              size_t entry_bytes, size_t *count_out,
                              capability_record_decode_fn decode_fn,
                              char *error, size_t error_len)
{
    uint8_t *base = entries;
    uint32_t count;
    uint32_t i;
    size_t offset = 4;

    if (!bytes || !count_out || !decode_fn || encoded_bytes < 4) {
        set_error(error, error_len, "canonical capability list is malformed");
        return -1;
    }
    count = read_be32(bytes);
    if (count > capacity || (count != 0 && !entries)) {
        set_error(error, error_len,
                  "canonical capability list exceeds capacity");
        return -1;
    }
    for (i = 0; i < count; i++) {
        uint32_t item_bytes;

        if (encoded_bytes - offset < 4) {
            set_error(error, error_len, "canonical capability list is truncated");
            return -1;
        }
        item_bytes = read_be32(bytes + offset);
        offset += 4;
        if (item_bytes == 0 || item_bytes > encoded_bytes - offset ||
            decode_fn(bytes + offset, item_bytes, base + i * entry_bytes,
                      error, error_len) != 0) {
            set_error(error, error_len,
                      "canonical capability list has bad entry");
            return -1;
        }
        offset += item_bytes;
    }
    if (offset != encoded_bytes) {
        set_error(error, error_len,
                  "canonical capability list has trailing bytes");
        return -1;
    }
    *count_out = count;
    return 0;
}

static int valid_capability_state(enum wvm_capability_state state)
{
    return state >= WVM_CAPABILITY_UNPROBED &&
           state <= WVM_CAPABILITY_DEGRADED;
}

int wvm_capability_limit_validate(const struct wvm_capability_limit *limit,
                                  char *error, size_t error_len)
{
    if (!limit || limit->limit_kind == 0) {
        set_error(error, error_len, "capability limit is invalid");
        return -1;
    }
    return 0;
}

static int capability_limit_size(const void *entry, size_t *encoded_size)
{
    if (wvm_capability_limit_validate(entry, NULL, 0) != 0) {
        return -1;
    }
    return canonical_record_size((const size_t[]){2, 8}, 2, encoded_size);
}

int wvm_capability_limit_encode(const struct wvm_capability_limit *limit,
                                uint8_t *bytes, size_t capacity,
                                size_t *encoded_bytes, char *error,
                                size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_capability_limit_validate(limit, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_CAPABILITY_LIMIT) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, limit->limit_kind) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2, limit->value) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode capability limit");
        return -1;
    }
    return 0;
}

int wvm_capability_limit_decode(const uint8_t *bytes, size_t encoded_bytes,
                                struct wvm_capability_limit *limit,
                                char *error, size_t error_len)
{
    struct wvm_canonical_field fields[2];

    if (!limit ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_CAPABILITY_LIMIT,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes != 8) {
        set_error(error, error_len, "capability limit has invalid fields");
        return -1;
    }
    limit->limit_kind = read_be16(fields[0].value);
    limit->value = read_be64(fields[1].value);
    return wvm_capability_limit_validate(limit, error, error_len);
}

int wvm_capability_constraint_validate(
    const struct wvm_capability_constraint *constraint, char *error,
    size_t error_len)
{
    size_t detail_bytes;

    if (!constraint || constraint->constraint_kind == 0 ||
        constraint->state == 0) {
        set_error(error, error_len, "capability constraint is invalid");
        return -1;
    }
    detail_bytes = strnlen(constraint->detail, sizeof(constraint->detail));
    if (detail_bytes == 0 ||
        detail_bytes > WVM_CAPABILITY_CONSTRAINT_DETAIL_MAX_BYTES) {
        set_error(error, error_len, "capability constraint detail is invalid");
        return -1;
    }
    return 0;
}

static int capability_constraint_size(const void *entry, size_t *encoded_size)
{
    const struct wvm_capability_constraint *constraint = entry;

    if (wvm_capability_constraint_validate(constraint, NULL, 0) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){2, 2, strlen(constraint->detail)}, 3, encoded_size);
}

int wvm_capability_constraint_encode(
    const struct wvm_capability_constraint *constraint, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_capability_constraint_validate(constraint, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_CAPABILITY_CONSTRAINT) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1,
                                       constraint->constraint_kind) != 0 ||
        wvm_canonical_field_append_u16(&builder, 2, constraint->state) != 0 ||
        wvm_canonical_field_append(&builder, 3, constraint->detail,
                                   strlen(constraint->detail)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode capability constraint");
        return -1;
    }
    return 0;
}

int wvm_capability_constraint_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_capability_constraint *constraint, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[3];

    if (!constraint ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_CAPABILITY_CONSTRAINT,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes != 2 ||
        fields[2].value_bytes == 0 ||
        fields[2].value_bytes > WVM_CAPABILITY_CONSTRAINT_DETAIL_MAX_BYTES ||
        memchr(fields[2].value, '\0', fields[2].value_bytes) != NULL) {
        set_error(error, error_len, "capability constraint has invalid fields");
        return -1;
    }
    memset(constraint, 0, sizeof(*constraint));
    constraint->constraint_kind = read_be16(fields[0].value);
    constraint->state = read_be16(fields[1].value);
    memcpy(constraint->detail, fields[2].value, fields[2].value_bytes);
    return wvm_capability_constraint_validate(constraint, error, error_len);
}

static int capability_limit_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_capability_limit_encode(entry, bytes, capacity, encoded_bytes,
                                       error, error_len);
}

static int capability_limit_decode_adapter(const uint8_t *bytes,
                                           size_t encoded_bytes, void *entry,
                                           char *error, size_t error_len)
{
    return wvm_capability_limit_decode(bytes, encoded_bytes, entry, error,
                                       error_len);
}

static int capability_constraint_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_capability_constraint_encode(entry, bytes, capacity,
                                            encoded_bytes, error, error_len);
}

static int capability_constraint_decode_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return wvm_capability_constraint_decode(bytes, encoded_bytes, entry, error,
                                            error_len);
}

static int capability_limit_list_validate(
    const struct wvm_capability_limit_list *limits, char *error,
    size_t error_len)
{
    size_t i;

    if (!limits || (limits->count != 0 && !limits->entries) ||
        limits->count > limits->capacity) {
        set_error(error, error_len, "capability limit list is invalid");
        return -1;
    }
    for (i = 0; i < limits->count; i++) {
        if (wvm_capability_limit_validate(&limits->entries[i], error,
                                          error_len) != 0 ||
            (i != 0 &&
             limits->entries[i - 1].limit_kind >= limits->entries[i].limit_kind)) {
            set_error(error, error_len,
                      "capability limits are not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int capability_constraint_list_validate(
    const struct wvm_capability_constraint_list *constraints, char *error,
    size_t error_len)
{
    size_t i;

    if (!constraints || (constraints->count != 0 && !constraints->entries) ||
        constraints->count > constraints->capacity) {
        set_error(error, error_len, "capability constraint list is invalid");
        return -1;
    }
    for (i = 0; i < constraints->count; i++) {
        if (wvm_capability_constraint_validate(&constraints->entries[i], error,
                                               error_len) != 0 ||
            (i != 0 &&
             constraints->entries[i - 1].constraint_kind >=
                 constraints->entries[i].constraint_kind)) {
            set_error(error, error_len,
                      "capability constraints are not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int capability_record_size(const struct wvm_capability_record *record,
                                  size_t *encoded_size)
{
    size_t limits_bytes;
    size_t constraints_bytes;

    if (wvm_capability_record_validate(record, NULL, 0) != 0 ||
        record_list_size(record->limits.entries, record->limits.count,
                         sizeof(*record->limits.entries), capability_limit_size,
                         &limits_bytes) != 0 ||
        record_list_size(record->constraints.entries, record->constraints.count,
                         sizeof(*record->constraints.entries),
                         capability_constraint_size, &constraints_bytes) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){2, 2, 4, 8, 8, 2, 4, 8, limits_bytes,
                          constraints_bytes, 8, WVM_IDENTITY_ID_BYTES, 2},
        13, encoded_size);
}

int wvm_capability_record_validate(
    const struct wvm_capability_record *record, char *error, size_t error_len)
{
    int requires_reason;

    if (!record || record->capability_id == 0 ||
        record->capability_schema_version != WVM_CANONICAL_SCHEMA ||
        record->physical_node_id == 0 || record->node_instance_id == 0 ||
        record->provider_instance_id == 0 ||
        !valid_capability_state(record->state) || record->abi_version == 0 ||
        record->observed_at == 0 ||
        bytes_are_zero(record->probe_operation_id,
                       sizeof(record->probe_operation_id)) ||
        capability_limit_list_validate(&record->limits, error, error_len) != 0 ||
        capability_constraint_list_validate(&record->constraints, error,
                                            error_len) != 0) {
        set_error(error, error_len, "capability record is invalid");
        return -1;
    }
    requires_reason = record->state == WVM_CAPABILITY_UNAVAILABLE ||
                      record->state == WVM_CAPABILITY_DEGRADED;
    if ((requires_reason && record->reason_code == 0) ||
        (!requires_reason && record->reason_code != 0)) {
        set_error(error, error_len, "capability record reason is invalid");
        return -1;
    }
    return 0;
}

int wvm_capability_record_encode(
    const struct wvm_capability_record *record, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    size_t limits_bytes;
    size_t constraints_bytes;

    if (wvm_capability_record_validate(record, error, error_len) != 0 ||
        record_list_size(record->limits.entries, record->limits.count,
                         sizeof(*record->limits.entries), capability_limit_size,
                         &limits_bytes) != 0 ||
        record_list_size(record->constraints.entries, record->constraints.count,
                         sizeof(*record->constraints.entries),
                         capability_constraint_size, &constraints_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_CAPABILITY_RECORD) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, record->capability_id) != 0 ||
        wvm_canonical_field_append_u16(&builder, 2,
                                       record->capability_schema_version) != 0 ||
        wvm_canonical_field_append_u32(&builder, 3,
                                       record->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       record->node_instance_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 5,
                                       record->provider_instance_id) != 0 ||
        wvm_canonical_field_append_u16(&builder, 6, record->state) != 0 ||
        wvm_canonical_field_append_u32(&builder, 7, record->abi_version) != 0 ||
        wvm_canonical_field_append_u64(&builder, 8, record->feature_bits) != 0 ||
        wvm_canonical_field_reserve(&builder, 9, (uint32_t)limits_bytes,
                                    &field_value) != 0 ||
        record_list_encode(record->limits.entries, record->limits.count,
                           sizeof(*record->limits.entries), capability_limit_size,
                           capability_limit_encode_adapter, field_value,
                           limits_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 10, (uint32_t)constraints_bytes,
                                    &field_value) != 0 ||
        record_list_encode(record->constraints.entries,
                           record->constraints.count,
                           sizeof(*record->constraints.entries),
                           capability_constraint_size,
                           capability_constraint_encode_adapter, field_value,
                           constraints_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append_u64(&builder, 11, record->observed_at) != 0 ||
        wvm_canonical_field_append(&builder, 12, record->probe_operation_id,
                                   sizeof(record->probe_operation_id)) != 0 ||
        wvm_canonical_field_append_u16(&builder, 13, record->reason_code) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode capability record");
        return -1;
    }
    return 0;
}

int wvm_capability_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_capability_record *record, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[13];
    struct wvm_capability_limit_list limits;
    struct wvm_capability_constraint_list constraints;

    if (!record ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_CAPABILITY_RECORD,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes != 2 ||
        fields[2].value_bytes != 4 || fields[3].value_bytes != 8 ||
        fields[4].value_bytes != 8 || fields[5].value_bytes != 2 ||
        fields[6].value_bytes != 4 || fields[7].value_bytes != 8 ||
        fields[10].value_bytes != 8 ||
        fields[11].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[12].value_bytes != 2) {
        set_error(error, error_len, "capability record has invalid fields");
        return -1;
    }
    limits = record->limits;
    constraints = record->constraints;
    memset(record, 0, sizeof(*record));
    record->limits = limits;
    record->constraints = constraints;
    record->capability_id = read_be16(fields[0].value);
    record->capability_schema_version = read_be16(fields[1].value);
    record->physical_node_id = read_be32(fields[2].value);
    record->node_instance_id = read_be64(fields[3].value);
    record->provider_instance_id = read_be64(fields[4].value);
    record->state = (enum wvm_capability_state)read_be16(fields[5].value);
    record->abi_version = read_be32(fields[6].value);
    record->feature_bits = read_be64(fields[7].value);
    record->observed_at = read_be64(fields[10].value);
    memcpy(record->probe_operation_id, fields[11].value,
           sizeof(record->probe_operation_id));
    record->reason_code = read_be16(fields[12].value);
    if (record_list_decode(fields[8].value, fields[8].value_bytes,
                           record->limits.entries, record->limits.capacity,
                           sizeof(*record->limits.entries), &record->limits.count,
                           capability_limit_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[9].value, fields[9].value_bytes,
                           record->constraints.entries,
                           record->constraints.capacity,
                           sizeof(*record->constraints.entries),
                           &record->constraints.count,
                           capability_constraint_decode_adapter, error,
                           error_len) != 0) {
        return -1;
    }
    return wvm_capability_record_validate(record, error, error_len);
}

static int capability_record_profile_compare(
    const struct wvm_capability_record *left,
    const struct wvm_capability_record *right)
{
    if (left->capability_id != right->capability_id) {
        return left->capability_id < right->capability_id ? -1 : 1;
    }
    if (left->provider_instance_id != right->provider_instance_id) {
        return left->provider_instance_id < right->provider_instance_id ? -1 : 1;
    }
    return 0;
}

int wvm_capability_profile_digest(
    uint32_t physical_node_id, uint64_t node_instance_id,
    uint64_t profile_generation, const struct wvm_capability_record *records,
    size_t record_count, uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len)
{
    static const char domain[] = "WVM-CAPABILITY-PROFILE-V1";
    struct wvm_sha256_ctx sha;
    uint8_t scalar[8];
    size_t i;

    if (physical_node_id == 0 || node_instance_id == 0 ||
        profile_generation == 0 || !records || record_count == 0 || !digest ||
        record_count > UINT32_MAX) {
        set_error(error, error_len, "capability profile input is invalid");
        return -1;
    }
    wvm_sha256_init(&sha);
    wvm_sha256_update(&sha, domain, sizeof(domain) - 1U);
    write_be32(scalar, physical_node_id);
    wvm_sha256_update(&sha, scalar, 4);
    write_be64(scalar, node_instance_id);
    wvm_sha256_update(&sha, scalar, 8);
    write_be64(scalar, profile_generation);
    wvm_sha256_update(&sha, scalar, 8);
    write_be32(scalar, (uint32_t)record_count);
    wvm_sha256_update(&sha, scalar, 4);

    for (i = 0; i < record_count; i++) {
        uint8_t *record_bytes;
        uint8_t record_digest[WVM_SHA256_DIGEST_BYTES];
        size_t record_bytes_count;
        size_t encoded_bytes;

        if (wvm_capability_record_validate(&records[i], error, error_len) != 0 ||
            records[i].physical_node_id != physical_node_id ||
            records[i].node_instance_id != node_instance_id ||
            (i != 0 &&
             capability_record_profile_compare(&records[i - 1], &records[i]) >=
                 0) ||
            capability_record_size(&records[i], &record_bytes_count) != 0) {
            set_error(error, error_len,
                      "capability profile record set is invalid");
            return -1;
        }
        record_bytes = malloc(record_bytes_count);
        if (!record_bytes ||
            wvm_capability_record_encode(&records[i], record_bytes,
                                         record_bytes_count, &encoded_bytes,
                                         error, error_len) != 0 ||
            encoded_bytes != record_bytes_count) {
            free(record_bytes);
            set_error(error, error_len, "cannot encode capability profile");
            return -1;
        }
        wvm_sha256_digest(record_bytes, encoded_bytes, record_digest);
        free(record_bytes);
        wvm_sha256_update(&sha, record_digest, sizeof(record_digest));
    }
    wvm_sha256_final(&sha, digest);
    return 0;
}

int wvm_capability_report_encode(
    const struct wvm_capability_report *report, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t *list;
    size_t list_bytes = 4, offset = 4, i;

    if (!report || !report->records || report->record_count == 0 ||
        wvm_capability_profile_digest(
            report->records[0].physical_node_id,
            report->records[0].node_instance_id, report->profile_generation,
            report->records, report->record_count, digest, error, error_len) != 0) {
        return -1;
    }
    for (i = 0; i < report->record_count; i++) {
        size_t size;
        if (capability_record_size(&report->records[i], &size) != 0 ||
            checked_add_size(&list_bytes, 4) != 0 ||
            checked_add_size(&list_bytes, size) != 0 ||
            list_bytes > WVM_CAPABILITY_REPORT_MAX_BYTES - 32U) {
            set_error(error, error_len, "capability report exceeds byte budget");
            return -1;
        }
    }
    if (wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_CAPABILITY_REPORT) != 0 ||
        wvm_canonical_field_append_u64(&builder, 1,
                                       report->profile_generation) != 0 ||
        wvm_canonical_field_reserve(&builder, 2, (uint32_t)list_bytes,
                                    &list) != 0) {
        return -1;
    }
    write_be32(list, (uint32_t)report->record_count);
    for (i = 0; i < report->record_count; i++) {
        size_t size;
        if (wvm_capability_record_encode(&report->records[i], list + offset + 4,
                                          list_bytes - offset - 4, &size,
                                          error, error_len) != 0) {
            return -1;
        }
        write_be32(list + offset, (uint32_t)size);
        offset += 4 + size;
    }
    return wvm_canonical_record_finish(&builder, encoded_bytes);
}

void wvm_capability_report_destroy(struct wvm_capability_report *report)
{
    size_t i;
    if (!report) {
        return;
    }
    for (i = 0; i < report->record_count; i++) {
        free(report->records[i].limits.entries);
        free(report->records[i].constraints.entries);
    }
    free(report->records);
    memset(report, 0, sizeof(*report));
}

int wvm_capability_report_decode(
    const uint8_t *bytes, size_t byte_count, struct wvm_capability_report *report,
    char *error, size_t error_len)
{
    struct wvm_canonical_field fields[2];
    struct wvm_capability_report decoded = {0};
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    const uint8_t *list;
    size_t list_bytes, offset = 4, i;

    if (!report || byte_count > WVM_CAPABILITY_REPORT_MAX_BYTES ||
        parse_exact_fields(bytes, byte_count, WVM_RECORD_CAPABILITY_REPORT,
                            fields, 2, error, error_len) != 0 ||
        fields[0].value_bytes != 8 || fields[1].value_bytes < 4) {
        return -1;
    }
    decoded.profile_generation = read_be64(fields[0].value);
    list = fields[1].value;
    list_bytes = fields[1].value_bytes;
    decoded.record_count = read_be32(list);
    /* Each record has 13 field headers, even before scalar/list contents. */
    if (!decoded.record_count ||
        decoded.record_count > (list_bytes - 4) / 116U) {
        goto invalid;
    }
    decoded.records = calloc(decoded.record_count, sizeof(*decoded.records));
    if (!decoded.records) {
        decoded.record_count = 0;
        goto invalid;
    }
    for (i = 0; i < decoded.record_count; i++) {
        struct wvm_capability_record *record = &decoded.records[i];
        struct wvm_canonical_field entry_fields[13];
        size_t size, limits, constraints;

        if (list_bytes - offset < 4) {
            goto invalid;
        }
        size = read_be32(list + offset);
        offset += 4;
        if (size > list_bytes - offset ||
            parse_exact_fields(list + offset, size, WVM_RECORD_CAPABILITY_RECORD,
                                entry_fields, 13, error, error_len) != 0 ||
            entry_fields[8].value_bytes < 4 ||
            entry_fields[9].value_bytes < 4) {
            goto invalid;
        }
        limits = read_be32(entry_fields[8].value);
        constraints = read_be32(entry_fields[9].value);
        if (limits > (entry_fields[8].value_bytes - 4U) / 38U ||
            constraints > (entry_fields[9].value_bytes - 4U) / 40U) {
            goto invalid;
        }
        if (limits) {
            record->limits.entries = calloc(limits, sizeof(*record->limits.entries));
            if (!record->limits.entries) {
                goto invalid;
            }
            record->limits.capacity = limits;
        }
        if (constraints) {
            record->constraints.entries = calloc(constraints, sizeof(*record->constraints.entries));
            if (!record->constraints.entries) {
                goto invalid;
            }
            record->constraints.capacity = constraints;
        }
        if (wvm_capability_record_decode(list + offset, size, record,
                                          error, error_len) != 0) {
            goto invalid;
        }
        offset += size;
    }
    if (offset != list_bytes ||
        wvm_capability_profile_digest(
            decoded.records[0].physical_node_id,
            decoded.records[0].node_instance_id, decoded.profile_generation,
            decoded.records, decoded.record_count, digest, error, error_len) != 0) {
        goto invalid;
    }
    wvm_capability_report_destroy(report);
    *report = decoded;
    return 0;

invalid:
    /* record_count is set before allocation to validate the encoded count. */
    if (!decoded.records) {
        decoded.record_count = 0;
    }
    wvm_capability_report_destroy(&decoded);
    set_error(error, error_len, "invalid or oversized capability report");
    return -1;
}

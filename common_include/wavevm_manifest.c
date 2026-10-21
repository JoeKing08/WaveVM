#include "wavevm_manifest.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_canonical.h"

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
            set_error(error, error_len,
                      "record 0x%04x has an unknown or missing field",
                      expected_record_type);
            return -1;
        }
        fields[count] = field;
        count++;
    }
    if (next < 0 || count != expected_field_count) {
        set_error(error, error_len, "record 0x%04x has an invalid field set",
                  expected_record_type);
        return -1;
    }
    return 0;
}

static int valid_backend(enum wvm_manifest_backend backend)
{
    return backend == WVM_MANIFEST_BACKEND_KVM ||
           backend == WVM_MANIFEST_BACKEND_TCG;
}

int wvm_vm_route_scope_key_validate(
    const struct wvm_vm_route_scope_key *scope_key, char *error,
    size_t error_len)
{
    if (!scope_key || scope_key->vm_id == 0 ||
        scope_key->vm_incarnation == 0 || scope_key->route_scope_id == 0) {
        set_error(error, error_len, "route scope key has invalid identity");
        return -1;
    }
    return 0;
}

int wvm_vm_route_scope_key_encode(
    const struct wvm_vm_route_scope_key *scope_key, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_vm_route_scope_key_validate(scope_key, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_VM_ROUTE_SCOPE_KEY) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1, scope_key->vm_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       scope_key->vm_incarnation) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       scope_key->route_scope_id) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode route scope key");
        return -1;
    }
    return 0;
}

int wvm_vm_route_scope_key_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_vm_route_scope_key *scope_key, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[3];

    if (!scope_key ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_VM_ROUTE_SCOPE_KEY, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 4 || fields[1].value_bytes != 8 ||
        fields[2].value_bytes != 8) {
        set_error(error, error_len, "route scope key has invalid field widths");
        return -1;
    }
    scope_key->vm_id = read_be32(fields[0].value);
    scope_key->vm_incarnation = read_be64(fields[1].value);
    scope_key->route_scope_id = read_be64(fields[2].value);
    return wvm_vm_route_scope_key_validate(scope_key, error, error_len);
}

int wvm_route_snapshot_key_validate(
    const struct wvm_route_snapshot_key *snapshot_key, char *error,
    size_t error_len)
{
    if (!snapshot_key ||
        wvm_vm_route_scope_key_validate(&snapshot_key->scope_key, error,
                                        error_len) != 0 ||
        snapshot_key->topology_revision == 0 ||
        snapshot_key->route_generation == 0 ||
        bytes_are_zero(snapshot_key->snapshot_digest,
                       sizeof(snapshot_key->snapshot_digest))) {
        set_error(error, error_len, "route snapshot key has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_route_snapshot_key_encode(
    const struct wvm_route_snapshot_key *snapshot_key, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t scope_bytes[64];
    uint8_t *field_value;
    size_t scope_encoded_bytes;

    if (wvm_route_snapshot_key_validate(snapshot_key, error, error_len) != 0 ||
        wvm_vm_route_scope_key_encode(&snapshot_key->scope_key, scope_bytes,
                                      sizeof(scope_bytes), &scope_encoded_bytes,
                                      error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ROUTE_SNAPSHOT_KEY) != 0 ||
        wvm_canonical_field_reserve(&builder, 1, scope_encoded_bytes,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode route snapshot key");
        return -1;
    }
    memcpy(field_value, scope_bytes, scope_encoded_bytes);
    if (wvm_canonical_field_append_u64(&builder, 2,
                                       snapshot_key->topology_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       snapshot_key->route_generation) != 0 ||
        wvm_canonical_field_append(&builder, 4, snapshot_key->snapshot_digest,
                                   sizeof(snapshot_key->snapshot_digest)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot finish route snapshot key");
        return -1;
    }
    return 0;
}

int wvm_route_snapshot_key_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_route_snapshot_key *snapshot_key, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[4];

    if (!snapshot_key ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_ROUTE_SNAPSHOT_KEY, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[1].value_bytes != 8 || fields[2].value_bytes != 8 ||
        fields[3].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        wvm_vm_route_scope_key_decode(fields[0].value, fields[0].value_bytes,
                                      &snapshot_key->scope_key, error,
                                      error_len) != 0) {
        set_error(error, error_len,
                  "route snapshot key has invalid nested fields");
        return -1;
    }
    snapshot_key->topology_revision = read_be64(fields[1].value);
    snapshot_key->route_generation = read_be64(fields[2].value);
    memcpy(snapshot_key->snapshot_digest, fields[3].value,
           sizeof(snapshot_key->snapshot_digest));
    return wvm_route_snapshot_key_validate(snapshot_key, error, error_len);
}

int wvm_local_name_namespace_encode(
    const struct wvm_local_name_namespace *namespace_value, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t name_bytes;

    if (wvm_local_name_namespace_validate(namespace_value, error, error_len) !=
        0) {
        return -1;
    }
    name_bytes = strlen(namespace_value->namespace_name);
    if (wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_LOCAL_NAME_NAMESPACE) != 0 ||
        wvm_canonical_field_append(&builder, 1,
                                   namespace_value->namespace_name,
                                   (uint32_t)name_bytes) != 0 ||
        wvm_canonical_field_append(
            &builder, 2, namespace_value->derivation_salt_digest,
            sizeof(namespace_value->derivation_salt_digest)) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       namespace_value->name_generation) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode local name namespace");
        return -1;
    }
    return 0;
}

int wvm_local_name_namespace_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_local_name_namespace *namespace_value, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[3];

    if (!namespace_value ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_LOCAL_NAME_NAMESPACE, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes == 0 ||
        fields[0].value_bytes > WVM_LOCAL_NAMESPACE_MAX_BYTES ||
        fields[1].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[2].value_bytes != 8 ||
        memchr(fields[0].value, '\0', fields[0].value_bytes) != NULL) {
        set_error(error, error_len, "local namespace has invalid fields");
        return -1;
    }
    memset(namespace_value, 0, sizeof(*namespace_value));
    memcpy(namespace_value->namespace_name, fields[0].value,
           fields[0].value_bytes);
    memcpy(namespace_value->derivation_salt_digest, fields[1].value,
           sizeof(namespace_value->derivation_salt_digest));
    namespace_value->name_generation = read_be64(fields[2].value);
    return wvm_local_name_namespace_validate(namespace_value, error, error_len);
}

int wvm_vcpu_assignment_validate(
    const struct wvm_vcpu_assignment *assignment, char *error,
    size_t error_len)
{
    if (!assignment || assignment->executor_physical_node_id == 0 ||
        !valid_backend(assignment->backend) || assignment->executor_class == 0 ||
        bytes_are_zero(assignment->reservation_id,
                       sizeof(assignment->reservation_id))) {
        set_error(error, error_len, "vCPU assignment has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_vcpu_assignment_encode(
    const struct wvm_vcpu_assignment *assignment, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_vcpu_assignment_validate(assignment, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_VCPU_ASSIGNMENT) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1,
                                       assignment->guest_vcpu_index) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 2, assignment->executor_physical_node_id) != 0 ||
        wvm_canonical_field_append_u16(&builder, 3, assignment->backend) != 0 ||
        wvm_canonical_field_append_u16(&builder, 4,
                                       assignment->executor_class) != 0 ||
        wvm_canonical_field_append_u32(&builder, 5,
                                       assignment->executor_slot) != 0 ||
        wvm_canonical_field_append(&builder, 6, assignment->reservation_id,
                                   sizeof(assignment->reservation_id)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode vCPU assignment");
        return -1;
    }
    return 0;
}

int wvm_vcpu_assignment_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_vcpu_assignment *assignment, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[6];

    if (!assignment ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_VCPU_ASSIGNMENT,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 4 || fields[1].value_bytes != 4 ||
        fields[2].value_bytes != 2 || fields[3].value_bytes != 2 ||
        fields[4].value_bytes != 4 ||
        fields[5].value_bytes != WVM_IDENTITY_ID_BYTES) {
        set_error(error, error_len, "vCPU assignment has invalid field widths");
        return -1;
    }
    memset(assignment, 0, sizeof(*assignment));
    assignment->guest_vcpu_index = read_be32(fields[0].value);
    assignment->executor_physical_node_id = read_be32(fields[1].value);
    assignment->backend = (enum wvm_manifest_backend)read_be16(fields[2].value);
    assignment->executor_class = read_be16(fields[3].value);
    assignment->executor_slot = read_be32(fields[4].value);
    memcpy(assignment->reservation_id, fields[5].value,
           sizeof(assignment->reservation_id));
    return wvm_vcpu_assignment_validate(assignment, error, error_len);
}

int wvm_memory_chunk_assignment_validate(
    const struct wvm_memory_chunk_assignment *assignment, char *error,
    size_t error_len)
{
    if (!assignment || assignment->gpa_start % WVM_MANIFEST_PAGE_BYTES != 0 ||
        assignment->bytes == 0 ||
        assignment->bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        assignment->gpa_start > UINT64_MAX - assignment->bytes ||
        assignment->directory_physical_node_id == 0 ||
        assignment->executor_physical_node_id == 0 ||
        assignment->consistency_policy == 0 ||
        bytes_are_zero(assignment->reservation_id,
                       sizeof(assignment->reservation_id))) {
        set_error(error, error_len, "memory assignment has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_memory_chunk_assignment_encode(
    const struct wvm_memory_chunk_assignment *assignment, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_memory_chunk_assignment_validate(assignment, error, error_len) !=
            0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_MEMORY_CHUNK_ASSIGNMENT) != 0 ||
        wvm_canonical_field_append_u64(&builder, 1, assignment->gpa_start) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 2, assignment->bytes) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 3, assignment->directory_physical_node_id) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 4, assignment->executor_physical_node_id) != 0 ||
        wvm_canonical_field_append_u16(&builder, 5,
                                       assignment->consistency_policy) != 0 ||
        wvm_canonical_field_append(&builder, 6, assignment->reservation_id,
                                   sizeof(assignment->reservation_id)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode memory assignment");
        return -1;
    }
    return 0;
}

int wvm_memory_chunk_assignment_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_memory_chunk_assignment *assignment, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[6];

    if (!assignment ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_MEMORY_CHUNK_ASSIGNMENT, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 8 || fields[1].value_bytes != 8 ||
        fields[2].value_bytes != 4 || fields[3].value_bytes != 4 ||
        fields[4].value_bytes != 2 ||
        fields[5].value_bytes != WVM_IDENTITY_ID_BYTES) {
        set_error(error, error_len,
                  "memory assignment has invalid field widths");
        return -1;
    }
    memset(assignment, 0, sizeof(*assignment));
    assignment->gpa_start = read_be64(fields[0].value);
    assignment->bytes = read_be64(fields[1].value);
    assignment->directory_physical_node_id = read_be32(fields[2].value);
    assignment->executor_physical_node_id = read_be32(fields[3].value);
    assignment->consistency_policy = read_be16(fields[4].value);
    memcpy(assignment->reservation_id, fields[5].value,
           sizeof(assignment->reservation_id));
    return wvm_memory_chunk_assignment_validate(assignment, error, error_len);
}

static int valid_text(const char *text, size_t max_bytes)
{
    size_t bytes;

    if (!text) {
        return 0;
    }
    bytes = strnlen(text, max_bytes + 1U);
    if (bytes == 0 || bytes > max_bytes) {
        return 0;
    }
    return memchr(text, '\0', bytes) == NULL;
}

static int storage_assignment_validate_common(
    const struct wvm_storage_assignment *assignment, int allow_template,
    char *error, size_t error_len);

static int storage_assignment_size_common(
    const struct wvm_storage_assignment *assignment, int allow_template,
    size_t *encoded_size)
{
    static const size_t fields[] = {4, 4, 2, WVM_IDENTITY_ID_BYTES,
                                    WVM_SHA256_DIGEST_BYTES};

    if (storage_assignment_validate_common(assignment, allow_template, NULL,
                                           0) != 0) {
        return -1;
    }
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int storage_assignment_size(const struct wvm_storage_assignment *assignment,
                                   size_t *encoded_size)
{
    return storage_assignment_size_common(assignment, 0, encoded_size);
}

static int storage_assignment_size_request(
    const struct wvm_storage_assignment *assignment, size_t *encoded_size)
{
    return storage_assignment_size_common(assignment, 1, encoded_size);
}

static int storage_assignment_validate_common(
    const struct wvm_storage_assignment *assignment, int allow_template,
    char *error, size_t error_len)
{
    if (!assignment || assignment->backend_kind == 0 ||
        bytes_are_zero(assignment->device_contract_digest,
                       sizeof(assignment->device_contract_digest)) ||
        (!allow_template &&
         (assignment->storage_physical_node_id == 0 ||
          bytes_are_zero(assignment->reservation_id,
                         sizeof(assignment->reservation_id))))) {
        set_error(error, error_len, "storage assignment has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_storage_assignment_validate(
    const struct wvm_storage_assignment *assignment, char *error,
    size_t error_len)
{
    return storage_assignment_validate_common(assignment, 0, error, error_len);
}


static int storage_assignment_encode_common(
    const struct wvm_storage_assignment *assignment, int allow_template,
    uint8_t *bytes, size_t capacity, size_t *encoded_bytes, char *error,
    size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (storage_assignment_validate_common(assignment, allow_template, error,
                                           error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_STORAGE_ASSIGNMENT) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1, assignment->device_index) !=
            0 ||
        wvm_canonical_field_append_u32(
            &builder, 2, assignment->storage_physical_node_id) != 0 ||
        wvm_canonical_field_append_u16(&builder, 3,
                                       assignment->backend_kind) != 0 ||
        wvm_canonical_field_append(&builder, 4, assignment->reservation_id,
                                   sizeof(assignment->reservation_id)) != 0 ||
        wvm_canonical_field_append(
            &builder, 5, assignment->device_contract_digest,
            sizeof(assignment->device_contract_digest)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode storage assignment");
        return -1;
    }
    return 0;
}

int wvm_storage_assignment_encode(
    const struct wvm_storage_assignment *assignment, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    return storage_assignment_encode_common(assignment, 0, bytes, capacity,
                                            encoded_bytes, error, error_len);
}

static int storage_assignment_encode_request(
    const struct wvm_storage_assignment *assignment, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    return storage_assignment_encode_common(assignment, 1, bytes, capacity,
                                            encoded_bytes, error, error_len);
}

static int storage_assignment_decode_common(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_assignment *assignment, int allow_template, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[5];

    if (!assignment ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_STORAGE_ASSIGNMENT,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 4 || fields[1].value_bytes != 4 ||
        fields[2].value_bytes != 2 ||
        fields[3].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[4].value_bytes != WVM_SHA256_DIGEST_BYTES) {
        set_error(error, error_len,
                  "storage assignment has invalid field widths");
        return -1;
    }
    memset(assignment, 0, sizeof(*assignment));
    assignment->device_index = read_be32(fields[0].value);
    assignment->storage_physical_node_id = read_be32(fields[1].value);
    assignment->backend_kind = read_be16(fields[2].value);
    memcpy(assignment->reservation_id, fields[3].value,
           sizeof(assignment->reservation_id));
    memcpy(assignment->device_contract_digest, fields[4].value,
           sizeof(assignment->device_contract_digest));
    return storage_assignment_validate_common(assignment, allow_template, error,
                                              error_len);
}

int wvm_storage_assignment_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_assignment *assignment, char *error, size_t error_len)
{
    return storage_assignment_decode_common(bytes, encoded_bytes, assignment, 0,
                                            error, error_len);
}

static int storage_assignment_decode_request(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_assignment *assignment, char *error, size_t error_len)
{
    return storage_assignment_decode_common(bytes, encoded_bytes, assignment, 1,
                                            error, error_len);
}

static int exclusive_lease_size(const struct wvm_exclusive_lease *lease,
                                size_t *encoded_size)
{
    size_t fields[3];

    if (wvm_exclusive_lease_validate(lease, NULL, 0) != 0) {
        return -1;
    }
    fields[0] = 2;
    fields[1] = strlen(lease->lease_name);
    fields[2] = 8;
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

int wvm_exclusive_lease_validate(const struct wvm_exclusive_lease *lease,
                                 char *error, size_t error_len)
{
    if (!lease || lease->lease_kind == 0 ||
        !valid_text(lease->lease_name, WVM_MANIFEST_LEASE_NAME_MAX_BYTES) ||
        lease->lease_generation == 0) {
        set_error(error, error_len, "exclusive lease has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_exclusive_lease_encode(const struct wvm_exclusive_lease *lease,
                               uint8_t *bytes, size_t capacity,
                               size_t *encoded_bytes, char *error,
                               size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t name_bytes;

    if (wvm_exclusive_lease_validate(lease, error, error_len) != 0) {
        return -1;
    }
    name_bytes = strlen(lease->lease_name);
    if (wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_EXCLUSIVE_LEASE) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, lease->lease_kind) != 0 ||
        wvm_canonical_field_append(&builder, 2, lease->lease_name,
                                   (uint32_t)name_bytes) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       lease->lease_generation) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode exclusive lease");
        return -1;
    }
    return 0;
}

int wvm_exclusive_lease_decode(const uint8_t *bytes, size_t encoded_bytes,
                               struct wvm_exclusive_lease *lease, char *error,
                               size_t error_len)
{
    struct wvm_canonical_field fields[3];

    if (!lease ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_EXCLUSIVE_LEASE,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes == 0 ||
        fields[1].value_bytes > WVM_MANIFEST_LEASE_NAME_MAX_BYTES ||
        fields[2].value_bytes != 8 ||
        memchr(fields[1].value, '\0', fields[1].value_bytes) != NULL) {
        set_error(error, error_len, "exclusive lease has invalid fields");
        return -1;
    }
    memset(lease, 0, sizeof(*lease));
    lease->lease_kind = read_be16(fields[0].value);
    memcpy(lease->lease_name, fields[1].value, fields[1].value_bytes);
    lease->lease_generation = read_be64(fields[2].value);
    return wvm_exclusive_lease_validate(lease, error, error_len);
}

static int lease_key_compare(const struct wvm_exclusive_lease *left,
                             const struct wvm_exclusive_lease *right)
{
    int cmp;

    if (left->lease_kind != right->lease_kind) {
        return left->lease_kind < right->lease_kind ? -1 : 1;
    }
    cmp = strcmp(left->lease_name, right->lease_name);
    return cmp < 0 ? -1 : cmp > 0;
}

static int exclusive_lease_list_validate(
    const struct wvm_exclusive_lease_list *leases, char *error,
    size_t error_len)
{
    size_t i;

    if (!leases || (leases->count != 0 && !leases->entries) ||
        leases->count > UINT32_MAX) {
        set_error(error, error_len, "exclusive lease list is invalid");
        return -1;
    }
    for (i = 0; i < leases->count; i++) {
        if (wvm_exclusive_lease_validate(&leases->entries[i], error,
                                         error_len) != 0 ||
            (i != 0 &&
             lease_key_compare(&leases->entries[i - 1], &leases->entries[i]) >=
                 0)) {
            set_error(error, error_len,
                      "exclusive lease list is not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int exclusive_lease_list_size(
    const struct wvm_exclusive_lease_list *leases, size_t *encoded_size)
{
    size_t total = 4;
    size_t i;

    if (exclusive_lease_list_validate(leases, NULL, 0) != 0) {
        return -1;
    }
    for (i = 0; i < leases->count; i++) {
        size_t item_bytes;

        if (exclusive_lease_size(&leases->entries[i], &item_bytes) != 0 ||
            checked_add_size(&total, 4) != 0 ||
            checked_add_size(&total, item_bytes) != 0) {
            return -1;
        }
    }
    *encoded_size = total;
    return 0;
}

static int exclusive_lease_list_encode(
    const struct wvm_exclusive_lease_list *leases, uint8_t *bytes,
    size_t encoded_bytes, char *error, size_t error_len)
{
    size_t expected_bytes;
    size_t offset = 4;
    size_t i;

    if (exclusive_lease_list_size(leases, &expected_bytes) != 0 ||
        expected_bytes != encoded_bytes) {
        set_error(error, error_len, "exclusive lease list has invalid size");
        return -1;
    }
    write_be32(bytes, (uint32_t)leases->count);
    for (i = 0; i < leases->count; i++) {
        size_t item_bytes;
        size_t actual_bytes;

        if (exclusive_lease_size(&leases->entries[i], &item_bytes) != 0) {
            return -1;
        }
        write_be32(bytes + offset, (uint32_t)item_bytes);
        offset += 4;
        if (wvm_exclusive_lease_encode(&leases->entries[i], bytes + offset,
                                       item_bytes, &actual_bytes, error,
                                       error_len) != 0 ||
            actual_bytes != item_bytes) {
            return -1;
        }
        offset += item_bytes;
    }
    return offset == encoded_bytes ? 0 : -1;
}

static int exclusive_lease_list_decode(const uint8_t *bytes,
                                       size_t encoded_bytes,
                                       struct wvm_exclusive_lease_list *leases,
                                       char *error, size_t error_len)
{
    uint32_t count;
    size_t offset = 4;
    uint32_t i;

    if (!bytes || !leases || encoded_bytes < 4) {
        set_error(error, error_len, "exclusive lease list is malformed");
        return -1;
    }
    count = read_be32(bytes);
    if (count > leases->capacity || (count != 0 && !leases->entries)) {
        set_error(error, error_len, "exclusive lease list exceeds capacity");
        return -1;
    }
    for (i = 0; i < count; i++) {
        uint32_t item_bytes;

        if (encoded_bytes - offset < 4) {
            set_error(error, error_len, "exclusive lease list is truncated");
            return -1;
        }
        item_bytes = read_be32(bytes + offset);
        offset += 4;
        if (item_bytes == 0 || item_bytes > encoded_bytes - offset ||
            wvm_exclusive_lease_decode(bytes + offset, item_bytes,
                                       &leases->entries[i], error,
                                       error_len) != 0) {
            set_error(error, error_len, "exclusive lease list has bad entry");
            return -1;
        }
        offset += item_bytes;
    }
    if (offset != encoded_bytes) {
        set_error(error, error_len, "exclusive lease list has trailing bytes");
        return -1;
    }
    leases->count = count;
    return exclusive_lease_list_validate(leases, error, error_len);
}

static int reservation_requirement_size(
    const struct wvm_reservation_requirement *requirement,
    size_t *encoded_size)
{
    size_t fields[9];

    if (wvm_reservation_requirement_validate(requirement, NULL, 0) != 0) {
        return -1;
    }
    fields[0] = WVM_IDENTITY_ID_BYTES;
    fields[1] = 4;
    fields[2] = 8;
    fields[3] = 8;
    fields[4] = 4;
    fields[5] = 8;
    fields[6] = 4;
    fields[7] = 8;
    if (exclusive_lease_list_size(&requirement->exclusive_leases, &fields[8]) !=
        0) {
        return -1;
    }
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

int wvm_reservation_requirement_validate(
    const struct wvm_reservation_requirement *requirement, char *error,
    size_t error_len)
{
    if (!requirement ||
        bytes_are_zero(requirement->reservation_id,
                       sizeof(requirement->reservation_id)) ||
        requirement->physical_node_id == 0 || requirement->node_instance_id == 0 ||
        requirement->inventory_revision == 0 ||
        requirement->guest_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        requirement->overhead_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        exclusive_lease_list_validate(&requirement->exclusive_leases, error,
                                      error_len) != 0) {
        set_error(error, error_len, "reservation requirement is invalid");
        return -1;
    }
    return 0;
}

int wvm_reservation_requirement_encode(
    const struct wvm_reservation_requirement *requirement, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *lease_value;
    size_t lease_bytes;

    if (wvm_reservation_requirement_validate(requirement, error, error_len) !=
            0 ||
        exclusive_lease_list_size(&requirement->exclusive_leases,
                                  &lease_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_RESERVATION_REQUIREMENT) != 0 ||
        wvm_canonical_field_append(&builder, 1, requirement->reservation_id,
                                   sizeof(requirement->reservation_id)) != 0 ||
        wvm_canonical_field_append_u32(&builder, 2,
                                       requirement->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       requirement->node_instance_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       requirement->inventory_revision) != 0 ||
        wvm_canonical_field_append_u32(&builder, 5,
                                       requirement->guest_vcpu_slots) != 0 ||
        wvm_canonical_field_append_u64(&builder, 6,
                                       requirement->guest_memory_bytes) != 0 ||
        wvm_canonical_field_append_u32(&builder, 7,
                                       requirement->overhead_vcpu_slots) != 0 ||
        wvm_canonical_field_append_u64(&builder, 8,
                                       requirement->overhead_memory_bytes) != 0 ||
        wvm_canonical_field_reserve(&builder, 9, lease_bytes, &lease_value) !=
            0 ||
        exclusive_lease_list_encode(&requirement->exclusive_leases, lease_value,
                                    lease_bytes, error, error_len) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode reservation requirement");
        return -1;
    }
    return 0;
}

int wvm_reservation_requirement_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_reservation_requirement *requirement, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[9];
    struct wvm_exclusive_lease_list leases;

    if (!requirement ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_RESERVATION_REQUIREMENT, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[1].value_bytes != 4 || fields[2].value_bytes != 8 ||
        fields[3].value_bytes != 8 || fields[4].value_bytes != 4 ||
        fields[5].value_bytes != 8 || fields[6].value_bytes != 4 ||
        fields[7].value_bytes != 8) {
        set_error(error, error_len,
                  "reservation requirement has invalid field widths");
        return -1;
    }
    leases = requirement->exclusive_leases;
    memset(requirement, 0, sizeof(*requirement));
    requirement->exclusive_leases = leases;
    memcpy(requirement->reservation_id, fields[0].value,
           sizeof(requirement->reservation_id));
    requirement->physical_node_id = read_be32(fields[1].value);
    requirement->node_instance_id = read_be64(fields[2].value);
    requirement->inventory_revision = read_be64(fields[3].value);
    requirement->guest_vcpu_slots = read_be32(fields[4].value);
    requirement->guest_memory_bytes = read_be64(fields[5].value);
    requirement->overhead_vcpu_slots = read_be32(fields[6].value);
    requirement->overhead_memory_bytes = read_be64(fields[7].value);
    if (exclusive_lease_list_decode(fields[8].value, fields[8].value_bytes,
                                    &requirement->exclusive_leases, error,
                                    error_len) != 0) {
        return -1;
    }
    return wvm_reservation_requirement_validate(requirement, error, error_len);
}

int wvm_guest_topology_validate(const struct wvm_guest_topology *topology,
                                char *error, size_t error_len)
{
    if (!topology ||
        (topology->topology_policy != WVM_MANIFEST_GUEST_TOPOLOGY_FLAT &&
         topology->topology_policy !=
             WVM_MANIFEST_GUEST_TOPOLOGY_PLACEMENT_NUMA &&
         topology->topology_policy !=
             WVM_MANIFEST_GUEST_TOPOLOGY_SYNTHETIC_NUMA) ||
        topology->guest_numa_nodes == 0 ||
        (topology->topology_policy == WVM_MANIFEST_GUEST_TOPOLOGY_FLAT &&
         topology->guest_numa_nodes != 1) ||
        (topology->has_topology_layout_digest != 0 &&
         topology->has_topology_layout_digest != 1) ||
        (topology->has_topology_layout_digest &&
         bytes_are_zero(topology->topology_layout_digest,
                        sizeof(topology->topology_layout_digest)))) {
        set_error(error, error_len, "guest topology is invalid");
        return -1;
    }
    return 0;
}

static int guest_topology_size(const struct wvm_guest_topology *topology,
                               size_t *encoded_size)
{
    const size_t required_fields[] = {2, 4};
    size_t fields[3];
    size_t field_count = 2;

    if (wvm_guest_topology_validate(topology, NULL, 0) != 0) {
        return -1;
    }
    fields[0] = required_fields[0];
    fields[1] = required_fields[1];
    if (topology->has_topology_layout_digest) {
        fields[field_count++] = WVM_SHA256_DIGEST_BYTES;
    }
    return canonical_record_size(fields, field_count, encoded_size);
}

int wvm_guest_topology_encode(const struct wvm_guest_topology *topology,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_guest_topology_validate(topology, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_GUEST_TOPOLOGY) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1,
                                       topology->topology_policy) != 0 ||
        wvm_canonical_field_append_u32(&builder, 2,
                                       topology->guest_numa_nodes) != 0 ||
        (topology->has_topology_layout_digest &&
         wvm_canonical_field_append(
             &builder, 3, topology->topology_layout_digest,
             sizeof(topology->topology_layout_digest)) != 0) ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode guest topology");
        return -1;
    }
    return 0;
}

int wvm_guest_topology_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_guest_topology *topology,
                              char *error, size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    unsigned int count = 0;

    if (!topology || wvm_canonical_record_parse(bytes, encoded_bytes, &record) !=
                          0 ||
        record.record_type != WVM_RECORD_GUEST_TOPOLOGY) {
        set_error(error, error_len, "invalid guest topology record");
        return -1;
    }
    memset(topology, 0, sizeof(*topology));
    while (wvm_canonical_record_next(&record, &offset, &field) == 1) {
        count++;
        if ((field.tag == 1 && field.value_bytes == 2) ||
            (field.tag == 2 && field.value_bytes == 4) ||
            (field.tag == 3 &&
             field.value_bytes == WVM_SHA256_DIGEST_BYTES)) {
            if (field.tag == 1) {
                topology->topology_policy =
                    (enum wvm_manifest_guest_topology_policy)read_be16(
                        field.value);
            } else if (field.tag == 2) {
                topology->guest_numa_nodes = read_be32(field.value);
            } else {
                topology->has_topology_layout_digest = 1;
                memcpy(topology->topology_layout_digest, field.value,
                       sizeof(topology->topology_layout_digest));
            }
            continue;
        }
        set_error(error, error_len, "guest topology has invalid fields");
        return -1;
    }
    if (count < 2 || count > 3) {
        set_error(error, error_len, "guest topology has incomplete fields");
        return -1;
    }
    return wvm_guest_topology_validate(topology, error, error_len);
}

typedef int (*record_size_fn)(const void *entry, size_t *encoded_size);
typedef int (*record_encode_fn)(const void *entry, uint8_t *bytes,
                                size_t capacity, size_t *encoded_bytes,
                                char *error, size_t error_len);
typedef int (*record_decode_fn)(const uint8_t *bytes, size_t encoded_bytes,
                                void *entry, char *error, size_t error_len);

static int vcpu_assignment_size(const struct wvm_vcpu_assignment *assignment,
                                size_t *encoded_size)
{
    static const size_t fields[] = {4, 4, 2, 2, 4, WVM_IDENTITY_ID_BYTES};

    if (wvm_vcpu_assignment_validate(assignment, NULL, 0) != 0) {
        return -1;
    }
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int memory_assignment_size(
    const struct wvm_memory_chunk_assignment *assignment, size_t *encoded_size)
{
    static const size_t fields[] = {8, 8, 4, 4, 2, WVM_IDENTITY_ID_BYTES};

    if (wvm_memory_chunk_assignment_validate(assignment, NULL, 0) != 0) {
        return -1;
    }
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int vcpu_assignment_size_adapter(const void *entry, size_t *encoded_size)
{
    return vcpu_assignment_size(entry, encoded_size);
}

static int memory_assignment_size_adapter(const void *entry,
                                          size_t *encoded_size)
{
    return memory_assignment_size(entry, encoded_size);
}

static int storage_assignment_size_adapter(const void *entry,
                                           size_t *encoded_size)
{
    return storage_assignment_size(entry, encoded_size);
}

static int requirement_size_adapter(const void *entry, size_t *encoded_size)
{
    return reservation_requirement_size(entry, encoded_size);
}

static int vcpu_assignment_encode_adapter(const void *entry, uint8_t *bytes,
                                          size_t capacity,
                                          size_t *encoded_bytes, char *error,
                                          size_t error_len)
{
    return wvm_vcpu_assignment_encode(entry, bytes, capacity, encoded_bytes,
                                      error, error_len);
}

static int memory_assignment_encode_adapter(const void *entry, uint8_t *bytes,
                                            size_t capacity,
                                            size_t *encoded_bytes, char *error,
                                            size_t error_len)
{
    return wvm_memory_chunk_assignment_encode(entry, bytes, capacity,
                                              encoded_bytes, error, error_len);
}

static int storage_assignment_encode_adapter(const void *entry, uint8_t *bytes,
                                             size_t capacity,
                                             size_t *encoded_bytes,
                                             char *error, size_t error_len)
{
    return wvm_storage_assignment_encode(entry, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int requirement_encode_adapter(const void *entry, uint8_t *bytes,
                                      size_t capacity, size_t *encoded_bytes,
                                      char *error, size_t error_len)
{
    return wvm_reservation_requirement_encode(entry, bytes, capacity,
                                              encoded_bytes, error, error_len);
}

static int vcpu_assignment_decode_adapter(const uint8_t *bytes,
                                          size_t encoded_bytes, void *entry,
                                          char *error, size_t error_len)
{
    return wvm_vcpu_assignment_decode(bytes, encoded_bytes, entry, error,
                                      error_len);
}

static int memory_assignment_decode_adapter(const uint8_t *bytes,
                                            size_t encoded_bytes, void *entry,
                                            char *error, size_t error_len)
{
    return wvm_memory_chunk_assignment_decode(bytes, encoded_bytes, entry,
                                              error, error_len);
}

static int storage_assignment_decode_adapter(const uint8_t *bytes,
                                             size_t encoded_bytes, void *entry,
                                             char *error, size_t error_len)
{
    return wvm_storage_assignment_decode(bytes, encoded_bytes, entry, error,
                                         error_len);
}

static int storage_assignment_size_request_adapter(const void *entry,
                                                   size_t *encoded_size)
{
    return storage_assignment_size_request(entry, encoded_size);
}

static int storage_assignment_encode_request_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return storage_assignment_encode_request(entry, bytes, capacity,
                                             encoded_bytes, error, error_len);
}

static int storage_assignment_decode_request_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return storage_assignment_decode_request(bytes, encoded_bytes, entry, error,
                                             error_len);
}

static int requirement_decode_adapter(const uint8_t *bytes,
                                      size_t encoded_bytes, void *entry,
                                      char *error, size_t error_len)
{
    return wvm_reservation_requirement_decode(bytes, encoded_bytes, entry,
                                             error, error_len);
}

static int record_list_size(const void *entries, size_t count,
                            size_t entry_bytes, record_size_fn item_size,
                            size_t *encoded_size)
{
    const uint8_t *base = entries;
    size_t total = 4;
    size_t i;

    if ((count != 0 && !entries) || count > UINT32_MAX || !item_size) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        size_t item_bytes;

        if (item_size(base + i * entry_bytes, &item_bytes) != 0 ||
            item_bytes > UINT32_MAX || checked_add_size(&total, 4) != 0 ||
            checked_add_size(&total, item_bytes) != 0) {
            return -1;
        }
    }
    *encoded_size = total;
    return 0;
}

static int record_list_encode(const void *entries, size_t count,
                              size_t entry_bytes, record_size_fn item_size,
                              record_encode_fn item_encode, uint8_t *bytes,
                              size_t encoded_bytes, char *error,
                              size_t error_len)
{
    const uint8_t *base = entries;
    size_t expected_bytes;
    size_t offset = 4;
    size_t i;

    if (record_list_size(entries, count, entry_bytes, item_size,
                         &expected_bytes) != 0 ||
        expected_bytes != encoded_bytes || !item_encode) {
        set_error(error, error_len, "canonical record list has invalid size");
        return -1;
    }
    write_be32(bytes, (uint32_t)count);
    for (i = 0; i < count; i++) {
        size_t item_bytes;
        size_t actual_bytes;

        if (item_size(base + i * entry_bytes, &item_bytes) != 0) {
            return -1;
        }
        write_be32(bytes + offset, (uint32_t)item_bytes);
        offset += 4;
        if (item_encode(base + i * entry_bytes, bytes + offset, item_bytes,
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
                              record_decode_fn item_decode, char *error,
                              size_t error_len)
{
    uint8_t *base = entries;
    uint32_t count;
    uint32_t i;
    size_t offset = 4;

    if (!bytes || !count_out || !item_decode || encoded_bytes < 4) {
        set_error(error, error_len, "canonical record list is malformed");
        return -1;
    }
    count = read_be32(bytes);
    if (count > capacity || (count != 0 && !entries)) {
        set_error(error, error_len, "canonical record list exceeds capacity");
        return -1;
    }
    for (i = 0; i < count; i++) {
        uint32_t item_bytes;

        if (encoded_bytes - offset < 4) {
            set_error(error, error_len, "canonical record list is truncated");
            return -1;
        }
        item_bytes = read_be32(bytes + offset);
        offset += 4;
        if (item_bytes == 0 || item_bytes > encoded_bytes - offset ||
            item_decode(bytes + offset, item_bytes, base + i * entry_bytes,
                        error, error_len) != 0) {
            set_error(error, error_len, "canonical record list has bad entry");
            return -1;
        }
        offset += item_bytes;
    }
    if (offset != encoded_bytes) {
        set_error(error, error_len, "canonical record list has trailing bytes");
        return -1;
    }
    *count_out = count;
    return 0;
}

static const struct wvm_reservation_requirement *
find_requirement(const struct wvm_reservation_requirement_list *requirements,
                 const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    for (i = 0; i < requirements->count; i++) {
        if (memcmp(requirements->entries[i].reservation_id, reservation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &requirements->entries[i];
        }
    }
    return NULL;
}

static int reservation_requirement_list_validate(
    const struct wvm_reservation_requirement_list *requirements, char *error,
    size_t error_len)
{
    size_t i;
    size_t j;

    if (!requirements || (requirements->count != 0 && !requirements->entries) ||
        requirements->count == 0 || requirements->count > UINT32_MAX) {
        set_error(error, error_len, "reservation requirement list is invalid");
        return -1;
    }
    for (i = 0; i < requirements->count; i++) {
        if (wvm_reservation_requirement_validate(&requirements->entries[i],
                                                 error, error_len) != 0 ||
            (i != 0 &&
             memcmp(requirements->entries[i - 1].reservation_id,
                    requirements->entries[i].reservation_id,
                    WVM_IDENTITY_ID_BYTES) >= 0)) {
            set_error(error, error_len,
                      "reservation requirements are not strictly ordered");
            return -1;
        }
        for (j = 0; j < i; j++) {
            if (requirements->entries[j].physical_node_id ==
                requirements->entries[i].physical_node_id) {
                set_error(error, error_len,
                          "multiple reservation requirements target one node");
                return -1;
            }
        }
    }
    return 0;
}

static int assignment_lists_validate(const struct wvm_placement_plan *plan,
                                     char *error, size_t error_len)
{
    enum wvm_manifest_backend backend = 0;
    uint64_t expected_gpa = 0;
    size_t i;

    if (!plan->vcpu_assignments.entries ||
        plan->vcpu_assignments.count == 0 ||
        plan->vcpu_assignments.count > UINT32_MAX ||
        !plan->memory_assignments.entries ||
        plan->memory_assignments.count == 0 ||
        plan->memory_assignments.count > UINT32_MAX ||
        (plan->storage_assignments.count != 0 &&
         !plan->storage_assignments.entries) ||
        plan->storage_assignments.count > UINT32_MAX) {
        set_error(error, error_len, "placement plan has missing assignments");
        return -1;
    }

    for (i = 0; i < plan->vcpu_assignments.count; i++) {
        const struct wvm_vcpu_assignment *assignment =
            &plan->vcpu_assignments.entries[i];

        if (wvm_vcpu_assignment_validate(assignment, error, error_len) != 0 ||
            assignment->guest_vcpu_index != i ||
            (backend != 0 && assignment->backend != backend)) {
            set_error(error, error_len,
                      "placement plan has non-canonical vCPU assignments");
            return -1;
        }
        backend = assignment->backend;
    }

    for (i = 0; i < plan->memory_assignments.count; i++) {
        const struct wvm_memory_chunk_assignment *assignment =
            &plan->memory_assignments.entries[i];

        if (wvm_memory_chunk_assignment_validate(assignment, error, error_len) !=
                0 ||
            assignment->gpa_start != expected_gpa) {
            set_error(error, error_len,
                      "placement plan has gapped memory assignments");
            return -1;
        }
        if (assignment->directory_physical_node_id !=
            assignment->executor_physical_node_id) {
            set_error(error, error_len,
                      "placement plan splits memory directory from executor "
                      "(remote memory placement not admitted)");
            return -1;
        }
        expected_gpa += assignment->bytes;
    }

    for (i = 0; i < plan->storage_assignments.count; i++) {
        const struct wvm_storage_assignment *assignment =
            &plan->storage_assignments.entries[i];

        if (wvm_storage_assignment_validate(assignment, error, error_len) != 0 ||
            (i != 0 &&
             plan->storage_assignments.entries[i - 1].device_index >=
                 assignment->device_index)) {
            set_error(error, error_len,
                      "placement plan has non-canonical storage assignments");
            return -1;
        }
    }
    return 0;
}

int wvm_placement_plan_validate(const struct wvm_placement_plan *plan,
                                char *error, size_t error_len)
{
    int host_requirement_seen = 0;
    size_t i;

    if (!plan ||
        bytes_are_zero(plan->admission_tx_id, sizeof(plan->admission_tx_id)) ||
        bytes_are_zero(plan->eligibility_fence_digest,
                       sizeof(plan->eligibility_fence_digest)) ||
        plan->inventory_revision == 0 || plan->membership_revision == 0 ||
        plan->topology_revision == 0 ||
        plan->capability_profile_generation == 0 || plan->host_node == 0) {
        set_error(error, error_len, "placement plan has invalid metadata");
        return -1;
    }
    if (wvm_vm_route_scope_key_validate(&plan->route_scope_key, error,
                                        error_len) != 0 ||
        wvm_guest_topology_validate(&plan->guest_topology, error, error_len) !=
            0 ||
        reservation_requirement_list_validate(&plan->reservation_requirements,
                                              error, error_len) != 0 ||
        assignment_lists_validate(plan, error, error_len) != 0) {
        /* Keep the first specific validation error. */
        return -1;
    }

    for (i = 0; i < plan->reservation_requirements.count; i++) {
        const struct wvm_reservation_requirement *requirement =
            &plan->reservation_requirements.entries[i];
        uint64_t guest_memory_bytes = 0;
        uint32_t guest_vcpu_slots = 0;
        int referenced = 0;
        size_t j;

        if (requirement->physical_node_id == plan->host_node) {
            host_requirement_seen = 1;
        } else if (requirement->overhead_vcpu_slots != 0 ||
                   requirement->overhead_memory_bytes != 0) {
            set_error(error, error_len,
                      "non-host reservation carries host overhead");
            return -1;
        }

        for (j = 0; j < plan->vcpu_assignments.count; j++) {
            const struct wvm_vcpu_assignment *assignment =
                &plan->vcpu_assignments.entries[j];

            if (memcmp(assignment->reservation_id, requirement->reservation_id,
                       WVM_IDENTITY_ID_BYTES) == 0) {
                if (assignment->executor_physical_node_id !=
                    requirement->physical_node_id) {
                    set_error(error, error_len,
                              "vCPU assignment targets the wrong reservation node");
                    return -1;
                }
                guest_vcpu_slots++;
                referenced = 1;
            }
        }
        for (j = 0; j < plan->memory_assignments.count; j++) {
            const struct wvm_memory_chunk_assignment *assignment =
                &plan->memory_assignments.entries[j];

            if (memcmp(assignment->reservation_id, requirement->reservation_id,
                       WVM_IDENTITY_ID_BYTES) == 0) {
                if (assignment->executor_physical_node_id !=
                    requirement->physical_node_id ||
                    assignment->bytes > UINT64_MAX - guest_memory_bytes) {
                    set_error(error, error_len,
                              "memory assignment targets the wrong reservation");
                    return -1;
                }
                guest_memory_bytes += assignment->bytes;
                referenced = 1;
            }
        }
        for (j = 0; j < plan->storage_assignments.count; j++) {
            const struct wvm_storage_assignment *assignment =
                &plan->storage_assignments.entries[j];

            if (memcmp(assignment->reservation_id, requirement->reservation_id,
                       WVM_IDENTITY_ID_BYTES) == 0) {
                if (assignment->storage_physical_node_id !=
                    requirement->physical_node_id) {
                    set_error(error, error_len,
                              "storage assignment targets the wrong reservation");
                    return -1;
                }
                referenced = 1;
            }
        }
        if (guest_vcpu_slots != requirement->guest_vcpu_slots ||
            guest_memory_bytes != requirement->guest_memory_bytes ||
            (!referenced && requirement->exclusive_leases.count == 0 &&
             requirement->overhead_vcpu_slots == 0 &&
             requirement->overhead_memory_bytes == 0)) {
            set_error(error, error_len,
                      "reservation requirement does not match assignments");
            return -1;
        }
    }

    if (!host_requirement_seen) {
        set_error(error, error_len,
                  "placement plan host has no reservation requirement");
        return -1;
    }
    for (i = 0; i < plan->vcpu_assignments.count; i++) {
        if (!find_requirement(&plan->reservation_requirements,
                              plan->vcpu_assignments.entries[i].reservation_id)) {
            set_error(error, error_len,
                      "vCPU assignment references an unknown reservation");
            return -1;
        }
    }
    for (i = 0; i < plan->memory_assignments.count; i++) {
        if (!find_requirement(
                &plan->reservation_requirements,
                plan->memory_assignments.entries[i].reservation_id)) {
            set_error(error, error_len,
                      "memory assignment references an unknown reservation");
            return -1;
        }
    }
    for (i = 0; i < plan->storage_assignments.count; i++) {
        if (!find_requirement(
                &plan->reservation_requirements,
                plan->storage_assignments.entries[i].reservation_id)) {
            set_error(error, error_len,
                      "storage assignment references an unknown reservation");
            return -1;
        }
    }
    return 0;
}

static int placement_plan_field_sizes(const struct wvm_placement_plan *plan,
                                      size_t fields[14], char *error,
                                      size_t error_len)
{
    if (record_list_size(plan->vcpu_assignments.entries,
                         plan->vcpu_assignments.count,
                         sizeof(*plan->vcpu_assignments.entries),
                         vcpu_assignment_size_adapter, &fields[8]) != 0 ||
        record_list_size(plan->memory_assignments.entries,
                         plan->memory_assignments.count,
                         sizeof(*plan->memory_assignments.entries),
                         memory_assignment_size_adapter, &fields[9]) != 0 ||
        record_list_size(plan->storage_assignments.entries,
                         plan->storage_assignments.count,
                         sizeof(*plan->storage_assignments.entries),
                         storage_assignment_size_adapter, &fields[10]) != 0 ||
        record_list_size(plan->reservation_requirements.entries,
                         plan->reservation_requirements.count,
                         sizeof(*plan->reservation_requirements.entries),
                         requirement_size_adapter, &fields[11]) != 0 ||
        guest_topology_size(&plan->guest_topology, &fields[12]) != 0 ||
        canonical_record_size((const size_t[]){4, 8, 8}, 3,
                              &fields[13]) != 0) {
        set_error(error, error_len, "cannot size placement plan fields");
        return -1;
    }
    fields[0] = WVM_SHA256_DIGEST_BYTES;
    fields[1] = WVM_IDENTITY_ID_BYTES;
    fields[2] = WVM_SHA256_DIGEST_BYTES;
    fields[3] = 8;
    fields[4] = 8;
    fields[5] = 8;
    fields[6] = 8;
    fields[7] = 4;
    return 0;
}

int wvm_placement_plan_encode(const struct wvm_placement_plan *plan,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes,
                              uint8_t plan_digest[WVM_SHA256_DIGEST_BYTES],
                              char *error, size_t error_len)
{
    static const uint8_t zero_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    size_t fields[14];
    size_t expected_bytes;
    size_t actual_bytes;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];

    if (!bytes || !plan_digest ||
        wvm_placement_plan_validate(plan, error, error_len) != 0 ||
        placement_plan_field_sizes(plan, fields, error, error_len) != 0 ||
        canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                              &expected_bytes) != 0 ||
        expected_bytes > capacity ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_PLACEMENT_PLAN) != 0 ||
        wvm_canonical_field_append(&builder, 1, zero_digest,
                                   sizeof(zero_digest)) != 0 ||
        wvm_canonical_field_append(&builder, 2, plan->admission_tx_id,
                                   sizeof(plan->admission_tx_id)) != 0 ||
        wvm_canonical_field_append(
            &builder, 3, plan->eligibility_fence_digest,
            sizeof(plan->eligibility_fence_digest)) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       plan->inventory_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 5,
                                       plan->membership_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 6,
                                       plan->topology_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 7,
                                       plan->capability_profile_generation) !=
            0 ||
        wvm_canonical_field_append_u32(&builder, 8, plan->host_node) != 0) {
        set_error(error, error_len, "cannot begin placement plan encoding");
        return -1;
    }

    if (wvm_canonical_field_reserve(&builder, 9, fields[8], &field_value) !=
            0 ||
        record_list_encode(plan->vcpu_assignments.entries,
                           plan->vcpu_assignments.count,
                           sizeof(*plan->vcpu_assignments.entries),
                           vcpu_assignment_size_adapter,
                           vcpu_assignment_encode_adapter, field_value,
                           fields[8], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 10, fields[9], &field_value) !=
            0 ||
        record_list_encode(plan->memory_assignments.entries,
                           plan->memory_assignments.count,
                           sizeof(*plan->memory_assignments.entries),
                           memory_assignment_size_adapter,
                           memory_assignment_encode_adapter, field_value,
                           fields[9], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 11, fields[10], &field_value) !=
            0 ||
        record_list_encode(plan->storage_assignments.entries,
                           plan->storage_assignments.count,
                           sizeof(*plan->storage_assignments.entries),
                           storage_assignment_size_adapter,
                           storage_assignment_encode_adapter, field_value,
                           fields[10], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 12, fields[11], &field_value) !=
            0 ||
        record_list_encode(plan->reservation_requirements.entries,
                           plan->reservation_requirements.count,
                           sizeof(*plan->reservation_requirements.entries),
                           requirement_size_adapter, requirement_encode_adapter,
                           field_value, fields[11], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 13, fields[12], &field_value) !=
            0 ||
        wvm_guest_topology_encode(&plan->guest_topology, field_value,
                                  fields[12], &actual_bytes, error,
                                  error_len) != 0 ||
        actual_bytes != fields[12] ||
        wvm_canonical_field_reserve(&builder, 14, fields[13], &field_value) !=
            0 ||
        wvm_vm_route_scope_key_encode(&plan->route_scope_key, field_value,
                                      fields[13], &actual_bytes, error,
                                      error_len) != 0 ||
        actual_bytes != fields[13] ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0 ||
        *encoded_bytes != expected_bytes ||
        wvm_canonical_record_digest(bytes, *encoded_bytes, 1,
                                    calculated_digest) != 0) {
        set_error(error, error_len, "cannot finish placement plan encoding");
        return -1;
    }

    if (!bytes_are_zero(plan->plan_digest, sizeof(plan->plan_digest)) &&
        memcmp(plan->plan_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len, "placement plan digest does not match plan");
        return -1;
    }
    memcpy(bytes + WVM_CANONICAL_RECORD_HEADER_BYTES +
               WVM_CANONICAL_FIELD_HEADER_BYTES,
           calculated_digest, sizeof(calculated_digest));
    memcpy(plan_digest, calculated_digest, sizeof(calculated_digest));
    return 0;
}

int wvm_placement_plan_decode(
    const uint8_t *bytes, size_t encoded_bytes, struct wvm_placement_plan *plan,
    char *error, size_t error_len)
{
    struct wvm_canonical_field fields[14];
    struct wvm_vcpu_assignment_list vcpu_assignments;
    struct wvm_memory_chunk_assignment_list memory_assignments;
    struct wvm_storage_assignment_list storage_assignments;
    struct wvm_reservation_requirement_list reservation_requirements;
    uint8_t expected_digest[WVM_SHA256_DIGEST_BYTES];

    if (!plan ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_PLACEMENT_PLAN,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[1].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[2].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[3].value_bytes != 8 || fields[4].value_bytes != 8 ||
        fields[5].value_bytes != 8 || fields[6].value_bytes != 8 ||
        fields[7].value_bytes != 4) {
        set_error(error, error_len, "placement plan has invalid field widths");
        return -1;
    }

    vcpu_assignments = plan->vcpu_assignments;
    memory_assignments = plan->memory_assignments;
    storage_assignments = plan->storage_assignments;
    reservation_requirements = plan->reservation_requirements;
    memset(plan, 0, sizeof(*plan));
    plan->vcpu_assignments = vcpu_assignments;
    plan->memory_assignments = memory_assignments;
    plan->storage_assignments = storage_assignments;
    plan->reservation_requirements = reservation_requirements;

    memcpy(plan->plan_digest, fields[0].value, sizeof(plan->plan_digest));
    memcpy(plan->admission_tx_id, fields[1].value, sizeof(plan->admission_tx_id));
    memcpy(plan->eligibility_fence_digest, fields[2].value,
           sizeof(plan->eligibility_fence_digest));
    plan->inventory_revision = read_be64(fields[3].value);
    plan->membership_revision = read_be64(fields[4].value);
    plan->topology_revision = read_be64(fields[5].value);
    plan->capability_profile_generation = read_be64(fields[6].value);
    plan->host_node = read_be32(fields[7].value);
    if (record_list_decode(fields[8].value, fields[8].value_bytes,
                           plan->vcpu_assignments.entries,
                           plan->vcpu_assignments.capacity,
                           sizeof(*plan->vcpu_assignments.entries),
                           &plan->vcpu_assignments.count,
                           vcpu_assignment_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[9].value, fields[9].value_bytes,
                           plan->memory_assignments.entries,
                           plan->memory_assignments.capacity,
                           sizeof(*plan->memory_assignments.entries),
                           &plan->memory_assignments.count,
                           memory_assignment_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[10].value, fields[10].value_bytes,
                           plan->storage_assignments.entries,
                           plan->storage_assignments.capacity,
                           sizeof(*plan->storage_assignments.entries),
                           &plan->storage_assignments.count,
                           storage_assignment_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[11].value, fields[11].value_bytes,
                           plan->reservation_requirements.entries,
                           plan->reservation_requirements.capacity,
                           sizeof(*plan->reservation_requirements.entries),
                           &plan->reservation_requirements.count,
                           requirement_decode_adapter, error,
                           error_len) != 0 ||
        wvm_guest_topology_decode(fields[12].value, fields[12].value_bytes,
                                  &plan->guest_topology, error, error_len) !=
            0 ||
        wvm_vm_route_scope_key_decode(fields[13].value, fields[13].value_bytes,
                                      &plan->route_scope_key, error,
                                      error_len) != 0 ||
        wvm_canonical_record_digest(bytes, encoded_bytes, 1,
                                    expected_digest) != 0 ||
        memcmp(plan->plan_digest, expected_digest,
               sizeof(expected_digest)) != 0) {
        set_error(error, error_len,
                  "placement plan has invalid nested data or digest");
        return -1;
    }
    return wvm_placement_plan_validate(plan, error, error_len);
}

static int valid_role_type(enum wvm_manifest_role_type role_type)
{
    return role_type >= WVM_MANIFEST_ROLE_NODE_RUNTIME &&
           role_type <= WVM_MANIFEST_ROLE_KERNEL_CONTEXT;
}

static int valid_member_state(enum wvm_manifest_member_state state)
{
    return state >= WVM_MANIFEST_MEMBER_PENDING &&
           state <= WVM_MANIFEST_MEMBER_FAILED;
}

static int member_key_size(const struct wvm_member_key *member_key,
                           size_t *encoded_size)
{
    return wvm_member_key_validate(member_key, NULL, 0) == 0
               ? canonical_record_size((const size_t[]){2, 4, 8}, 3,
                                       encoded_size)
               : -1;
}

int wvm_member_key_validate(const struct wvm_member_key *member_key,
                            char *error, size_t error_len)
{
    if (!member_key || !valid_role_type(member_key->role_type) ||
        member_key->role_id == 0 || member_key->instance_id == 0) {
        set_error(error, error_len, "member key has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_member_key_encode(const struct wvm_member_key *member_key,
                          uint8_t *bytes, size_t capacity,
                          size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_member_key_validate(member_key, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_MEMBER_KEY) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, member_key->role_type) !=
            0 ||
        wvm_canonical_field_append_u32(&builder, 2, member_key->role_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3, member_key->instance_id) !=
            0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode member key");
        return -1;
    }
    return 0;
}

int wvm_member_key_decode(const uint8_t *bytes, size_t encoded_bytes,
                          struct wvm_member_key *member_key, char *error,
                          size_t error_len)
{
    struct wvm_canonical_field fields[3];

    if (!member_key ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_MEMBER_KEY, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes != 4 ||
        fields[2].value_bytes != 8) {
        set_error(error, error_len, "member key has invalid field widths");
        return -1;
    }
    memset(member_key, 0, sizeof(*member_key));
    member_key->role_type = (enum wvm_manifest_role_type)read_be16(fields[0].value);
    member_key->role_id = read_be32(fields[1].value);
    member_key->instance_id = read_be64(fields[2].value);
    return wvm_member_key_validate(member_key, error, error_len);
}

static int capability_ref_size(const struct wvm_capability_ref *capability,
                               size_t *encoded_size)
{
    return wvm_capability_ref_validate(capability, NULL, 0) == 0
               ? canonical_record_size(
                     (const size_t[]){4, 8, 8, WVM_SHA256_DIGEST_BYTES}, 4,
                     encoded_size)
               : -1;
}

int wvm_capability_ref_validate(const struct wvm_capability_ref *capability,
                                char *error, size_t error_len)
{
    if (!capability || capability->physical_node_id == 0 ||
        capability->node_instance_id == 0 ||
        capability->profile_generation == 0 ||
        bytes_are_zero(capability->profile_digest,
                       sizeof(capability->profile_digest))) {
        set_error(error, error_len, "capability reference has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_capability_ref_encode(const struct wvm_capability_ref *capability,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_capability_ref_validate(capability, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_CAPABILITY_REF) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1,
                                       capability->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       capability->node_instance_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       capability->profile_generation) != 0 ||
        wvm_canonical_field_append(&builder, 4, capability->profile_digest,
                                   sizeof(capability->profile_digest)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode capability reference");
        return -1;
    }
    return 0;
}

int wvm_capability_ref_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_capability_ref *capability,
                              char *error, size_t error_len)
{
    struct wvm_canonical_field fields[4];

    if (!capability ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_CAPABILITY_REF,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 4 || fields[1].value_bytes != 8 ||
        fields[2].value_bytes != 8 ||
        fields[3].value_bytes != WVM_SHA256_DIGEST_BYTES) {
        set_error(error, error_len,
                  "capability reference has invalid field widths");
        return -1;
    }
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = read_be32(fields[0].value);
    capability->node_instance_id = read_be64(fields[1].value);
    capability->profile_generation = read_be64(fields[2].value);
    memcpy(capability->profile_digest, fields[3].value,
           sizeof(capability->profile_digest));
    return wvm_capability_ref_validate(capability, error, error_len);
}

static int member_key_compare(const struct wvm_member_key *left,
                              const struct wvm_member_key *right)
{
    if (left->role_type != right->role_type) {
        return left->role_type < right->role_type ? -1 : 1;
    }
    if (left->role_id != right->role_id) {
        return left->role_id < right->role_id ? -1 : 1;
    }
    if (left->instance_id != right->instance_id) {
        return left->instance_id < right->instance_id ? -1 : 1;
    }
    return 0;
}

static int required_member_size(const struct wvm_required_member *member,
                                size_t *encoded_size)
{
    size_t member_key_bytes;
    size_t capability_bytes;

    if (wvm_required_member_validate(member, NULL, 0) != 0 ||
        member_key_size(&member->member_key, &member_key_bytes) != 0 ||
        capability_ref_size(&member->capability, &capability_bytes) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){member_key_bytes, 4, 8, capability_bytes, 2}, 5,
        encoded_size);
}

int wvm_required_member_validate(const struct wvm_required_member *member,
                                 char *error, size_t error_len)
{
    if (!member || wvm_member_key_validate(&member->member_key, error,
                                           error_len) != 0 ||
        member->physical_node_id == 0 || member->failure_domain_id == 0 ||
        wvm_capability_ref_validate(&member->capability, error, error_len) !=
            0 ||
        member->capability.physical_node_id != member->physical_node_id ||
        !valid_member_state(member->required_state)) {
        set_error(error, error_len, "required member has invalid metadata");
        return -1;
    }
    return 0;
}

int wvm_required_member_encode(const struct wvm_required_member *member,
                               uint8_t *bytes, size_t capacity,
                               size_t *encoded_bytes, char *error,
                               size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    size_t member_key_bytes;
    size_t capability_bytes;
    size_t actual_bytes;

    if (wvm_required_member_validate(member, error, error_len) != 0 ||
        member_key_size(&member->member_key, &member_key_bytes) != 0 ||
        capability_ref_size(&member->capability, &capability_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_REQUIRED_MEMBER) != 0 ||
        wvm_canonical_field_reserve(&builder, 1, member_key_bytes,
                                    &field_value) != 0 ||
        wvm_member_key_encode(&member->member_key, field_value,
                              member_key_bytes, &actual_bytes, error,
                              error_len) != 0 ||
        actual_bytes != member_key_bytes ||
        wvm_canonical_field_append_u32(&builder, 2,
                                       member->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       member->failure_domain_id) != 0 ||
        wvm_canonical_field_reserve(&builder, 4, capability_bytes,
                                    &field_value) != 0 ||
        wvm_capability_ref_encode(&member->capability, field_value,
                                  capability_bytes, &actual_bytes, error,
                                  error_len) != 0 ||
        actual_bytes != capability_bytes ||
        wvm_canonical_field_append_u16(&builder, 5, member->required_state) !=
            0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode required member");
        return -1;
    }
    return 0;
}

int wvm_required_member_decode(const uint8_t *bytes, size_t encoded_bytes,
                               struct wvm_required_member *member,
                               char *error, size_t error_len)
{
    struct wvm_canonical_field fields[5];

    if (!member ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_REQUIRED_MEMBER,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[1].value_bytes != 4 || fields[2].value_bytes != 8 ||
        fields[4].value_bytes != 2) {
        set_error(error, error_len, "required member has invalid field widths");
        return -1;
    }
    memset(member, 0, sizeof(*member));
    if (wvm_member_key_decode(fields[0].value, fields[0].value_bytes,
                              &member->member_key, error, error_len) != 0 ||
        wvm_capability_ref_decode(fields[3].value, fields[3].value_bytes,
                                  &member->capability, error, error_len) != 0) {
        return -1;
    }
    member->physical_node_id = read_be32(fields[1].value);
    member->failure_domain_id = read_be64(fields[2].value);
    member->required_state =
        (enum wvm_manifest_member_state)read_be16(fields[4].value);
    return wvm_required_member_validate(member, error, error_len);
}

static int machine_config_size(const struct wvm_machine_config *config,
                               size_t *encoded_size)
{
    if (wvm_machine_config_validate(config, NULL, 0) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){strlen(config->architecture), strlen(config->machine_type),
                         4, 2},
        4, encoded_size);
}

int wvm_machine_config_validate(const struct wvm_machine_config *config,
                                char *error, size_t error_len)
{
    if (!config ||
        !valid_text(config->architecture, WVM_MANIFEST_ARCH_MAX_BYTES) ||
        !valid_text(config->machine_type, WVM_MANIFEST_MACHINE_TYPE_MAX_BYTES) ||
        config->qemu_compat_version == 0 || config->firmware_policy == 0) {
        set_error(error, error_len, "machine configuration is invalid");
        return -1;
    }
    return 0;
}

int wvm_machine_config_encode(const struct wvm_machine_config *config,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_machine_config_validate(config, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_MACHINE_CONFIG) != 0 ||
        wvm_canonical_field_append(&builder, 1, config->architecture,
                                   (uint32_t)strlen(config->architecture)) !=
            0 ||
        wvm_canonical_field_append(&builder, 2, config->machine_type,
                                   (uint32_t)strlen(config->machine_type)) !=
            0 ||
        wvm_canonical_field_append_u32(&builder, 3,
                                       config->qemu_compat_version) != 0 ||
        wvm_canonical_field_append_u16(&builder, 4, config->firmware_policy) !=
            0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode machine configuration");
        return -1;
    }
    return 0;
}

int wvm_machine_config_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_machine_config *config, char *error,
                              size_t error_len)
{
    struct wvm_canonical_field fields[4];

    if (!config ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_MACHINE_CONFIG,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes == 0 ||
        fields[0].value_bytes > WVM_MANIFEST_ARCH_MAX_BYTES ||
        fields[1].value_bytes == 0 ||
        fields[1].value_bytes > WVM_MANIFEST_MACHINE_TYPE_MAX_BYTES ||
        fields[2].value_bytes != 4 || fields[3].value_bytes != 2 ||
        memchr(fields[0].value, '\0', fields[0].value_bytes) != NULL ||
        memchr(fields[1].value, '\0', fields[1].value_bytes) != NULL) {
        set_error(error, error_len, "machine configuration has invalid fields");
        return -1;
    }
    memset(config, 0, sizeof(*config));
    memcpy(config->architecture, fields[0].value, fields[0].value_bytes);
    memcpy(config->machine_type, fields[1].value, fields[1].value_bytes);
    config->qemu_compat_version = read_be32(fields[2].value);
    config->firmware_policy = read_be16(fields[3].value);
    return wvm_machine_config_validate(config, error, error_len);
}

int wvm_consistency_policy_validate(
    const struct wvm_consistency_policy *policy, char *error, size_t error_len)
{
    if (!policy || policy->dirty_batch_size == 0 ||
        policy->handoff_commit_policy == 0 ||
        policy->subscriber_delivery_policy == 0 ||
        policy->max_commit_latency_ms == 0) {
        set_error(error, error_len, "consistency policy is invalid");
        return -1;
    }
    return 0;
}

int wvm_consistency_policy_encode(
    const struct wvm_consistency_policy *policy, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_consistency_policy_validate(policy, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_CONSISTENCY_POLICY) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1, policy->dirty_batch_size) !=
            0 ||
        wvm_canonical_field_append_u16(&builder, 2,
                                       policy->handoff_commit_policy) != 0 ||
        wvm_canonical_field_append_u16(&builder, 3,
                                       policy->subscriber_delivery_policy) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       policy->max_commit_latency_ms) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode consistency policy");
        return -1;
    }
    return 0;
}

int wvm_consistency_policy_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_consistency_policy *policy, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[4];

    if (!policy ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_CONSISTENCY_POLICY, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 4 || fields[1].value_bytes != 2 ||
        fields[2].value_bytes != 2 || fields[3].value_bytes != 8) {
        set_error(error, error_len, "consistency policy has invalid widths");
        return -1;
    }
    memset(policy, 0, sizeof(*policy));
    policy->dirty_batch_size = read_be32(fields[0].value);
    policy->handoff_commit_policy = read_be16(fields[1].value);
    policy->subscriber_delivery_policy = read_be16(fields[2].value);
    policy->max_commit_latency_ms = read_be64(fields[3].value);
    return wvm_consistency_policy_validate(policy, error, error_len);
}

int wvm_lifecycle_policy_validate(
    const struct wvm_lifecycle_policy *policy, char *error, size_t error_len)
{
    if (!policy || policy->start_policy == 0 || policy->failure_policy == 0 ||
        policy->completion_query_horizon_ms == 0 ||
        policy->route_retention_horizon_ms == 0) {
        set_error(error, error_len, "lifecycle policy is invalid");
        return -1;
    }
    return 0;
}

int wvm_lifecycle_policy_encode(
    const struct wvm_lifecycle_policy *policy, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_lifecycle_policy_validate(policy, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_LIFECYCLE_POLICY) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, policy->start_policy) !=
            0 ||
        wvm_canonical_field_append_u16(&builder, 2, policy->failure_policy) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       policy->completion_query_horizon_ms) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       policy->route_retention_horizon_ms) !=
            0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode lifecycle policy");
        return -1;
    }
    return 0;
}

int wvm_lifecycle_policy_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_lifecycle_policy *policy, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[4];

    if (!policy ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_LIFECYCLE_POLICY,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes != 2 ||
        fields[2].value_bytes != 8 || fields[3].value_bytes != 8) {
        set_error(error, error_len, "lifecycle policy has invalid widths");
        return -1;
    }
    memset(policy, 0, sizeof(*policy));
    policy->start_policy = read_be16(fields[0].value);
    policy->failure_policy = read_be16(fields[1].value);
    policy->completion_query_horizon_ms = read_be64(fields[2].value);
    policy->route_retention_horizon_ms = read_be64(fields[3].value);
    return wvm_lifecycle_policy_validate(policy, error, error_len);
}

static int capability_ref_size_adapter(const void *entry, size_t *encoded_size)
{
    return capability_ref_size(entry, encoded_size);
}

static int capability_ref_encode_adapter(const void *entry, uint8_t *bytes,
                                         size_t capacity, size_t *encoded_bytes,
                                         char *error, size_t error_len)
{
    return wvm_capability_ref_encode(entry, bytes, capacity, encoded_bytes,
                                     error, error_len);
}

static int capability_ref_decode_adapter(const uint8_t *bytes,
                                         size_t encoded_bytes, void *entry,
                                         char *error, size_t error_len)
{
    return wvm_capability_ref_decode(bytes, encoded_bytes, entry, error,
                                     error_len);
}

static int capability_ref_list_validate(
    const struct wvm_capability_ref_list *capabilities, int require_nonempty,
    char *error, size_t error_len)
{
    size_t i;

    if (!capabilities ||
        (capabilities->count != 0 && !capabilities->entries) ||
        capabilities->count > UINT32_MAX ||
        (require_nonempty && capabilities->count == 0)) {
        set_error(error, error_len, "capability reference list is invalid");
        return -1;
    }
    for (i = 0; i < capabilities->count; i++) {
        if (wvm_capability_ref_validate(&capabilities->entries[i], error,
                                        error_len) != 0 ||
            (i != 0 &&
             capabilities->entries[i - 1].physical_node_id >=
                 capabilities->entries[i].physical_node_id)) {
            set_error(error, error_len,
                      "capability references are not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int execution_fault_profile_size(
    const struct wvm_execution_fault_profile *profile, size_t *encoded_size)
{
    size_t capability_list_bytes;

    if (wvm_execution_fault_profile_validate(profile, NULL, 0) != 0 ||
        record_list_size(profile->per_node_capabilities.entries,
                         profile->per_node_capabilities.count,
                         sizeof(*profile->per_node_capabilities.entries),
                         capability_ref_size_adapter,
                         &capability_list_bytes) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){2, 4, 2, 2, 2, 8, capability_list_bytes,
                         WVM_SHA256_DIGEST_BYTES, 2},
        9, encoded_size);
}

int wvm_execution_fault_profile_validate(
    const struct wvm_execution_fault_profile *profile, char *error,
    size_t error_len)
{
    if (!profile || !valid_backend(profile->backend) ||
        profile->context_schema_version == 0 || profile->dirty_capture_engine == 0 ||
        profile->read_fault_engine == 0 || profile->invalidation_engine == 0 ||
        profile->fallback_decision == 0 ||
        bytes_are_zero(profile->supported_memory_policies_digest,
                       sizeof(profile->supported_memory_policies_digest)) ||
        capability_ref_list_validate(&profile->per_node_capabilities, 1, error,
                                     error_len) != 0) {
        set_error(error, error_len, "execution fault profile is invalid");
        return -1;
    }
    return 0;
}

int wvm_execution_fault_profile_encode(
    const struct wvm_execution_fault_profile *profile, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    size_t capability_list_bytes;

    if (wvm_execution_fault_profile_validate(profile, error, error_len) != 0 ||
        record_list_size(profile->per_node_capabilities.entries,
                         profile->per_node_capabilities.count,
                         sizeof(*profile->per_node_capabilities.entries),
                         capability_ref_size_adapter,
                         &capability_list_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_EXECUTION_FAULT_PROFILE) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, profile->backend) != 0 ||
        wvm_canonical_field_append_u32(&builder, 2,
                                       profile->context_schema_version) != 0 ||
        wvm_canonical_field_append_u16(&builder, 3,
                                       profile->dirty_capture_engine) != 0 ||
        wvm_canonical_field_append_u16(&builder, 4,
                                       profile->read_fault_engine) != 0 ||
        wvm_canonical_field_append_u16(&builder, 5,
                                       profile->invalidation_engine) != 0 ||
        wvm_canonical_field_append_u64(&builder, 6,
                                       profile->kernel_accelerator_bits) != 0 ||
        wvm_canonical_field_reserve(&builder, 7, capability_list_bytes,
                                    &field_value) != 0 ||
        record_list_encode(profile->per_node_capabilities.entries,
                           profile->per_node_capabilities.count,
                           sizeof(*profile->per_node_capabilities.entries),
                           capability_ref_size_adapter,
                           capability_ref_encode_adapter, field_value,
                           capability_list_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append(
            &builder, 8, profile->supported_memory_policies_digest,
            sizeof(profile->supported_memory_policies_digest)) != 0 ||
        wvm_canonical_field_append_u16(&builder, 9,
                                       profile->fallback_decision) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode execution fault profile");
        return -1;
    }
    return 0;
}

int wvm_execution_fault_profile_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_execution_fault_profile *profile, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[9];
    struct wvm_capability_ref_list capabilities;

    if (!profile ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_EXECUTION_FAULT_PROFILE, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes != 4 ||
        fields[2].value_bytes != 2 || fields[3].value_bytes != 2 ||
        fields[4].value_bytes != 2 || fields[5].value_bytes != 8 ||
        fields[7].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[8].value_bytes != 2) {
        set_error(error, error_len, "execution fault profile has bad widths");
        return -1;
    }
    capabilities = profile->per_node_capabilities;
    memset(profile, 0, sizeof(*profile));
    profile->per_node_capabilities = capabilities;
    profile->backend = (enum wvm_manifest_backend)read_be16(fields[0].value);
    profile->context_schema_version = read_be32(fields[1].value);
    profile->dirty_capture_engine = read_be16(fields[2].value);
    profile->read_fault_engine = read_be16(fields[3].value);
    profile->invalidation_engine = read_be16(fields[4].value);
    profile->kernel_accelerator_bits = read_be64(fields[5].value);
    memcpy(profile->supported_memory_policies_digest, fields[7].value,
           sizeof(profile->supported_memory_policies_digest));
    profile->fallback_decision = read_be16(fields[8].value);
    if (record_list_decode(fields[6].value, fields[6].value_bytes,
                           profile->per_node_capabilities.entries,
                           profile->per_node_capabilities.capacity,
                           sizeof(*profile->per_node_capabilities.entries),
                           &profile->per_node_capabilities.count,
                           capability_ref_decode_adapter, error,
                           error_len) != 0) {
        return -1;
    }
    return wvm_execution_fault_profile_validate(profile, error, error_len);
}

static int storage_device_plan_validate_common(
    const struct wvm_storage_device_plan *plan, int allow_template, char *error,
    size_t error_len)
{
    size_t i;

    if (!plan || (plan->assignments.count != 0 && !plan->assignments.entries) ||
        plan->assignments.count > UINT32_MAX ||
        bytes_are_zero(plan->qemu_device_configuration_digest,
                       sizeof(plan->qemu_device_configuration_digest))) {
        set_error(error, error_len, "storage device plan is invalid");
        return -1;
    }
    for (i = 0; i < plan->assignments.count; i++) {
        if (storage_assignment_validate_common(&plan->assignments.entries[i],
                                               allow_template, error,
                                               error_len) != 0 ||
            (i != 0 && plan->assignments.entries[i - 1].device_index >=
                           plan->assignments.entries[i].device_index)) {
            set_error(error, error_len,
                      "storage device assignments are not ordered");
            return -1;
        }
    }
    return 0;
}

int wvm_storage_device_plan_validate(
    const struct wvm_storage_device_plan *plan, char *error, size_t error_len)
{
    return storage_device_plan_validate_common(plan, 0, error, error_len);
}

static int storage_device_plan_validate_request(
    const struct wvm_storage_device_plan *plan, char *error, size_t error_len)
{
    return storage_device_plan_validate_common(plan, 1, error, error_len);
}

static int storage_device_plan_size_common(
    const struct wvm_storage_device_plan *plan, int allow_template,
    size_t *encoded_size)
{
    size_t assignments_bytes;

    if (storage_device_plan_validate_common(plan, allow_template, NULL, 0) != 0 ||
        record_list_size(
            plan->assignments.entries, plan->assignments.count,
            sizeof(*plan->assignments.entries),
            allow_template ? storage_assignment_size_request_adapter
                           : storage_assignment_size_adapter,
            &assignments_bytes) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){assignments_bytes, WVM_SHA256_DIGEST_BYTES}, 2,
        encoded_size);
}

static int storage_device_plan_size(const struct wvm_storage_device_plan *plan,
                                    size_t *encoded_size)
{
    return storage_device_plan_size_common(plan, 0, encoded_size);
}

static int storage_device_plan_size_request(
    const struct wvm_storage_device_plan *plan, size_t *encoded_size)
{
    return storage_device_plan_size_common(plan, 1, encoded_size);
}

static int storage_device_plan_encode_common(
    const struct wvm_storage_device_plan *plan, int allow_template,
    uint8_t *bytes, size_t capacity, size_t *encoded_bytes, char *error,
    size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    size_t assignments_bytes;

    if (storage_device_plan_validate_common(plan, allow_template, error,
                                            error_len) != 0 ||
        record_list_size(
            plan->assignments.entries, plan->assignments.count,
            sizeof(*plan->assignments.entries),
            allow_template ? storage_assignment_size_request_adapter
                           : storage_assignment_size_adapter,
            &assignments_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_STORAGE_DEVICE_PLAN) != 0 ||
        wvm_canonical_field_reserve(&builder, 1, assignments_bytes,
                                    &field_value) != 0 ||
        record_list_encode(
            plan->assignments.entries, plan->assignments.count,
            sizeof(*plan->assignments.entries),
            allow_template ? storage_assignment_size_request_adapter
                           : storage_assignment_size_adapter,
            allow_template ? storage_assignment_encode_request_adapter
                           : storage_assignment_encode_adapter,
            field_value, assignments_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append(
            &builder, 2, plan->qemu_device_configuration_digest,
            sizeof(plan->qemu_device_configuration_digest)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode storage device plan");
        return -1;
    }
    return 0;
}

int wvm_storage_device_plan_encode(
    const struct wvm_storage_device_plan *plan, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    return storage_device_plan_encode_common(plan, 0, bytes, capacity,
                                             encoded_bytes, error, error_len);
}

static int storage_device_plan_encode_request(
    const struct wvm_storage_device_plan *plan, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    return storage_device_plan_encode_common(plan, 1, bytes, capacity,
                                             encoded_bytes, error, error_len);
}

static int storage_device_plan_decode_common(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_device_plan *plan, int allow_template, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[2];
    struct wvm_storage_assignment_list assignments;

    if (!plan ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_STORAGE_DEVICE_PLAN,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[1].value_bytes != WVM_SHA256_DIGEST_BYTES) {
        set_error(error, error_len, "storage device plan has bad widths");
        return -1;
    }
    assignments = plan->assignments;
    memset(plan, 0, sizeof(*plan));
    plan->assignments = assignments;
    if (record_list_decode(fields[0].value, fields[0].value_bytes,
                           plan->assignments.entries, plan->assignments.capacity,
                           sizeof(*plan->assignments.entries),
                           &plan->assignments.count,
                           allow_template
                               ? storage_assignment_decode_request_adapter
                               : storage_assignment_decode_adapter,
                           error, error_len) != 0) {
        return -1;
    }
    memcpy(plan->qemu_device_configuration_digest, fields[1].value,
           sizeof(plan->qemu_device_configuration_digest));
    return storage_device_plan_validate_common(plan, allow_template, error,
                                               error_len);
}

int wvm_storage_device_plan_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_device_plan *plan, char *error, size_t error_len)
{
    return storage_device_plan_decode_common(bytes, encoded_bytes, plan, 0,
                                              error, error_len);
}

static int storage_device_plan_decode_request(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_device_plan *plan, char *error, size_t error_len)
{
    return storage_device_plan_decode_common(bytes, encoded_bytes, plan, 1,
                                              error, error_len);
}

static int required_member_size_adapter(const void *entry, size_t *encoded_size)
{
    return required_member_size(entry, encoded_size);
}

static int required_member_encode_adapter(const void *entry, uint8_t *bytes,
                                          size_t capacity,
                                          size_t *encoded_bytes, char *error,
                                          size_t error_len)
{
    return wvm_required_member_encode(entry, bytes, capacity, encoded_bytes,
                                      error, error_len);
}

static int required_member_decode_adapter(const uint8_t *bytes,
                                          size_t encoded_bytes, void *entry,
                                          char *error, size_t error_len)
{
    return wvm_required_member_decode(bytes, encoded_bytes, entry, error,
                                      error_len);
}

static int required_member_list_validate(
    const struct wvm_required_member_list *members, int require_nonempty,
    char *error, size_t error_len)
{
    size_t i;

    if (!members || (members->count != 0 && !members->entries) ||
        members->count > UINT32_MAX || (require_nonempty && members->count == 0)) {
        set_error(error, error_len, "required member list is invalid");
        return -1;
    }
    for (i = 0; i < members->count; i++) {
        if (wvm_required_member_validate(&members->entries[i], error,
                                         error_len) != 0 ||
            (i != 0 &&
             member_key_compare(&members->entries[i - 1].member_key,
                                &members->entries[i].member_key) >= 0)) {
            set_error(error, error_len,
                      "required members are not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int local_name_namespace_size(
    const struct wvm_local_name_namespace *namespace_value,
    size_t *encoded_size)
{
    if (wvm_local_name_namespace_validate(namespace_value, NULL, 0) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){strlen(namespace_value->namespace_name),
                         WVM_SHA256_DIGEST_BYTES, 8},
        3, encoded_size);
}

static int consistency_policy_size(const struct wvm_consistency_policy *policy,
                                   size_t *encoded_size)
{
    return wvm_consistency_policy_validate(policy, NULL, 0) == 0
               ? canonical_record_size((const size_t[]){4, 2, 2, 8}, 4,
                                       encoded_size)
               : -1;
}

static int lifecycle_policy_size(const struct wvm_lifecycle_policy *policy,
                                 size_t *encoded_size)
{
    return wvm_lifecycle_policy_validate(policy, NULL, 0) == 0
               ? canonical_record_size((const size_t[]){2, 2, 8, 8}, 4,
                                       encoded_size)
               : -1;
}

static int scope_key_equal(const struct wvm_vm_route_scope_key *left,
                           const struct wvm_vm_route_scope_key *right)
{
    return left->vm_id == right->vm_id &&
           left->vm_incarnation == right->vm_incarnation &&
           left->route_scope_id == right->route_scope_id;
}

static int capability_ref_equal(const struct wvm_capability_ref *left,
                                const struct wvm_capability_ref *right)
{
    return left->physical_node_id == right->physical_node_id &&
           left->node_instance_id == right->node_instance_id &&
           left->profile_generation == right->profile_generation &&
           memcmp(left->profile_digest, right->profile_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int candidate_has_capability(
    const struct wvm_capability_ref_list *capabilities,
    const struct wvm_capability_ref *capability)
{
    size_t i;

    for (i = 0; i < capabilities->count; i++) {
        if (capability_ref_equal(&capabilities->entries[i], capability)) {
            return 1;
        }
    }
    return 0;
}

static int candidate_assignment_shape_validate(
    const struct wvm_candidate_vm_manifest *candidate, char *error,
    size_t error_len)
{
    struct wvm_placement_plan shape;

    memset(&shape, 0, sizeof(shape));
    memcpy(shape.admission_tx_id, candidate->admission_tx_id,
           sizeof(shape.admission_tx_id));
    memcpy(shape.eligibility_fence_digest, candidate->eligibility_fence_digest,
           sizeof(shape.eligibility_fence_digest));
    shape.inventory_revision = 1;
    shape.membership_revision = 1;
    shape.topology_revision = candidate->prepared_route_snapshot_key.topology_revision;
    shape.capability_profile_generation = 1;
    shape.host_node = candidate->host_node;
    shape.vcpu_assignments = candidate->vcpu_placements;
    shape.memory_assignments = candidate->memory_placements;
    shape.storage_assignments = candidate->storage_device_plan.assignments;
    shape.reservation_requirements = candidate->reservation_requirements;
    shape.guest_topology = candidate->guest_topology;
    shape.route_scope_key = candidate->route_scope_key;
    return wvm_placement_plan_validate(&shape, error, error_len);
}

int wvm_candidate_vm_manifest_validate(
    const struct wvm_candidate_vm_manifest *candidate, char *error,
    size_t error_len)
{
    size_t i;
    int host_member_seen = 0;

    if (!candidate ||
        bytes_are_zero(candidate->manifest_id, sizeof(candidate->manifest_id)) ||
        candidate->manifest_schema_version != WVM_CANONICAL_SCHEMA ||
        candidate->vm_id == 0 || candidate->vm_incarnation == 0 ||
        candidate->manifest_generation == 0 ||
        bytes_are_zero(candidate->request_id, sizeof(candidate->request_id)) ||
        bytes_are_zero(candidate->admission_tx_id,
                       sizeof(candidate->admission_tx_id)) ||
        bytes_are_zero(candidate->eligibility_fence_digest,
                       sizeof(candidate->eligibility_fence_digest)) ||
        candidate->candidate_created_at == 0 || candidate->host_node == 0 ||
        wvm_machine_config_validate(&candidate->guest_machine, error,
                                    error_len) != 0 ||
        wvm_guest_topology_validate(&candidate->guest_topology, error,
                                    error_len) != 0 ||
        wvm_execution_fault_profile_validate(&candidate->execution_plan, error,
                                             error_len) != 0 ||
        wvm_consistency_policy_validate(&candidate->consistency_policy, error,
                                        error_len) != 0 ||
        wvm_storage_device_plan_validate(&candidate->storage_device_plan, error,
                                         error_len) != 0 ||
        required_member_list_validate(&candidate->required_members, 1, error,
                                      error_len) != 0 ||
        capability_ref_list_validate(&candidate->required_capabilities, 1,
                                     error, error_len) != 0 ||
        wvm_vm_route_scope_key_validate(&candidate->route_scope_key, error,
                                        error_len) != 0 ||
        wvm_route_snapshot_key_validate(&candidate->prepared_route_snapshot_key,
                                        error, error_len) != 0 ||
        !scope_key_equal(&candidate->route_scope_key,
                         &candidate->prepared_route_snapshot_key.scope_key) ||
        bytes_are_zero(candidate->plan_digest,
                       sizeof(candidate->plan_digest)) ||
        wvm_local_name_namespace_validate(&candidate->local_name_namespace,
                                          error, error_len) != 0 ||
        candidate->local_name_namespace.name_generation !=
            candidate->manifest_generation ||
        wvm_lifecycle_policy_validate(&candidate->lifecycle_policy, error,
                                      error_len) != 0 ||
        (candidate->namespace_abi != WVM_MANIFEST_NAMESPACE_LEGACY &&
         candidate->namespace_abi != WVM_MANIFEST_NAMESPACE_U32) ||
        (candidate->namespace_abi == WVM_MANIFEST_NAMESPACE_LEGACY &&
         candidate->vm_id > 255) ||
        candidate_assignment_shape_validate(candidate, error, error_len) != 0) {
        set_error(error, error_len, "candidate manifest has invalid metadata");
        return -1;
    }

    for (i = 0; i < candidate->vcpu_placements.count; i++) {
        if (candidate->vcpu_placements.entries[i].backend !=
            candidate->execution_plan.backend) {
            set_error(error, error_len,
                      "candidate vCPU backend differs from execution profile");
            return -1;
        }
    }
    for (i = 0; i < candidate->required_members.count; i++) {
        const struct wvm_required_member *member =
            &candidate->required_members.entries[i];

        if (!candidate_has_capability(&candidate->required_capabilities,
                                      &member->capability)) {
            set_error(error, error_len,
                      "candidate member lacks a required capability reference");
            return -1;
        }
        if (member->physical_node_id == candidate->host_node) {
            host_member_seen = 1;
        }
    }
    if (!host_member_seen) {
        set_error(error, error_len,
                  "candidate host is absent from required members");
        return -1;
    }
    for (i = 0; i < candidate->execution_plan.per_node_capabilities.count; i++) {
        if (!candidate_has_capability(
                &candidate->required_capabilities,
                &candidate->execution_plan.per_node_capabilities.entries[i])) {
            set_error(error, error_len,
                      "execution profile names a non-participant capability");
            return -1;
        }
    }
    return 0;
}

static int vcpu_assignment_equal(const struct wvm_vcpu_assignment *left,
                                 const struct wvm_vcpu_assignment *right)
{
    return left->guest_vcpu_index == right->guest_vcpu_index &&
           left->executor_physical_node_id == right->executor_physical_node_id &&
           left->backend == right->backend &&
           left->executor_class == right->executor_class &&
           left->executor_slot == right->executor_slot &&
           memcmp(left->reservation_id, right->reservation_id,
                  WVM_IDENTITY_ID_BYTES) == 0;
}

static int memory_assignment_equal(
    const struct wvm_memory_chunk_assignment *left,
    const struct wvm_memory_chunk_assignment *right)
{
    return left->gpa_start == right->gpa_start && left->bytes == right->bytes &&
           left->directory_physical_node_id ==
               right->directory_physical_node_id &&
           left->executor_physical_node_id ==
               right->executor_physical_node_id &&
           left->consistency_policy == right->consistency_policy &&
           memcmp(left->reservation_id, right->reservation_id,
                  WVM_IDENTITY_ID_BYTES) == 0;
}

static int storage_assignment_equal(const struct wvm_storage_assignment *left,
                                    const struct wvm_storage_assignment *right)
{
    return left->device_index == right->device_index &&
           left->storage_physical_node_id == right->storage_physical_node_id &&
           left->backend_kind == right->backend_kind &&
           memcmp(left->reservation_id, right->reservation_id,
                  WVM_IDENTITY_ID_BYTES) == 0 &&
           memcmp(left->device_contract_digest, right->device_contract_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int reservation_requirement_equal(
    const struct wvm_reservation_requirement *left,
    const struct wvm_reservation_requirement *right)
{
    size_t i;

    if (memcmp(left->reservation_id, right->reservation_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        left->physical_node_id != right->physical_node_id ||
        left->node_instance_id != right->node_instance_id ||
        left->inventory_revision != right->inventory_revision ||
        left->guest_vcpu_slots != right->guest_vcpu_slots ||
        left->guest_memory_bytes != right->guest_memory_bytes ||
        left->overhead_vcpu_slots != right->overhead_vcpu_slots ||
        left->overhead_memory_bytes != right->overhead_memory_bytes ||
        left->exclusive_leases.count != right->exclusive_leases.count) {
        return 0;
    }
    for (i = 0; i < left->exclusive_leases.count; i++) {
        if (left->exclusive_leases.entries[i].lease_kind !=
                right->exclusive_leases.entries[i].lease_kind ||
            left->exclusive_leases.entries[i].lease_generation !=
                right->exclusive_leases.entries[i].lease_generation ||
            strcmp(left->exclusive_leases.entries[i].lease_name,
                   right->exclusive_leases.entries[i].lease_name) != 0) {
            return 0;
        }
    }
    return 1;
}

int wvm_candidate_vm_manifest_matches_plan(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_placement_plan *plan, char *error, size_t error_len)
{
    size_t i;

    if (wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        wvm_placement_plan_validate(plan, error, error_len) != 0 ||
        bytes_are_zero(plan->plan_digest, sizeof(plan->plan_digest)) ||
        memcmp(candidate->plan_digest, plan->plan_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        memcmp(candidate->admission_tx_id, plan->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(candidate->eligibility_fence_digest,
               plan->eligibility_fence_digest, WVM_SHA256_DIGEST_BYTES) != 0 ||
        candidate->host_node != plan->host_node ||
        !scope_key_equal(&candidate->route_scope_key, &plan->route_scope_key) ||
        candidate->guest_topology.topology_policy !=
            plan->guest_topology.topology_policy ||
        candidate->guest_topology.guest_numa_nodes !=
            plan->guest_topology.guest_numa_nodes ||
        candidate->guest_topology.has_topology_layout_digest !=
            plan->guest_topology.has_topology_layout_digest ||
        (candidate->guest_topology.has_topology_layout_digest &&
         memcmp(candidate->guest_topology.topology_layout_digest,
                plan->guest_topology.topology_layout_digest,
                WVM_SHA256_DIGEST_BYTES) != 0) ||
        candidate->vcpu_placements.count != plan->vcpu_assignments.count ||
        candidate->memory_placements.count != plan->memory_assignments.count ||
        candidate->storage_device_plan.assignments.count !=
            plan->storage_assignments.count ||
        candidate->reservation_requirements.count !=
            plan->reservation_requirements.count) {
        set_error(error, error_len, "candidate manifest does not match plan");
        return -1;
    }
    for (i = 0; i < plan->vcpu_assignments.count; i++) {
        if (!vcpu_assignment_equal(&candidate->vcpu_placements.entries[i],
                                   &plan->vcpu_assignments.entries[i])) {
            set_error(error, error_len,
                      "candidate has different vCPU placement");
            return -1;
        }
    }
    for (i = 0; i < plan->memory_assignments.count; i++) {
        if (!memory_assignment_equal(&candidate->memory_placements.entries[i],
                                     &plan->memory_assignments.entries[i])) {
            set_error(error, error_len,
                      "candidate has different memory placement");
            return -1;
        }
    }
    for (i = 0; i < plan->storage_assignments.count; i++) {
        if (!storage_assignment_equal(
                &candidate->storage_device_plan.assignments.entries[i],
                &plan->storage_assignments.entries[i])) {
            set_error(error, error_len,
                      "candidate has different storage placement");
            return -1;
        }
    }
    for (i = 0; i < plan->reservation_requirements.count; i++) {
        if (!reservation_requirement_equal(
                &candidate->reservation_requirements.entries[i],
                &plan->reservation_requirements.entries[i])) {
            set_error(error, error_len,
                      "candidate has different reservation requirements");
            return -1;
        }
    }
    return 0;
}

static int route_scope_key_size(const struct wvm_vm_route_scope_key *scope_key,
                                size_t *encoded_size)
{
    return wvm_vm_route_scope_key_validate(scope_key, NULL, 0) == 0
               ? canonical_record_size((const size_t[]){4, 8, 8}, 3,
                                       encoded_size)
               : -1;
}

static int route_snapshot_key_size(
    const struct wvm_route_snapshot_key *snapshot_key, size_t *encoded_size)
{
    size_t scope_key_bytes;

    if (wvm_route_snapshot_key_validate(snapshot_key, NULL, 0) != 0 ||
        route_scope_key_size(&snapshot_key->scope_key, &scope_key_bytes) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){scope_key_bytes, 8, 8, WVM_SHA256_DIGEST_BYTES}, 4,
        encoded_size);
}

static int candidate_manifest_field_sizes(
    const struct wvm_candidate_vm_manifest *candidate, size_t fields[27],
    char *error, size_t error_len)
{
    if (machine_config_size(&candidate->guest_machine, &fields[10]) != 0 ||
        guest_topology_size(&candidate->guest_topology, &fields[11]) != 0 ||
        execution_fault_profile_size(&candidate->execution_plan, &fields[12]) !=
            0 ||
        consistency_policy_size(&candidate->consistency_policy, &fields[13]) !=
            0 ||
        storage_device_plan_size(&candidate->storage_device_plan, &fields[14]) !=
            0 ||
        record_list_size(candidate->vcpu_placements.entries,
                         candidate->vcpu_placements.count,
                         sizeof(*candidate->vcpu_placements.entries),
                         vcpu_assignment_size_adapter, &fields[16]) != 0 ||
        record_list_size(candidate->memory_placements.entries,
                         candidate->memory_placements.count,
                         sizeof(*candidate->memory_placements.entries),
                         memory_assignment_size_adapter, &fields[17]) != 0 ||
        record_list_size(candidate->required_members.entries,
                         candidate->required_members.count,
                         sizeof(*candidate->required_members.entries),
                         required_member_size_adapter, &fields[18]) != 0 ||
        record_list_size(candidate->required_capabilities.entries,
                         candidate->required_capabilities.count,
                         sizeof(*candidate->required_capabilities.entries),
                         capability_ref_size_adapter, &fields[19]) != 0 ||
        record_list_size(candidate->reservation_requirements.entries,
                         candidate->reservation_requirements.count,
                         sizeof(*candidate->reservation_requirements.entries),
                         requirement_size_adapter, &fields[20]) != 0 ||
        route_scope_key_size(&candidate->route_scope_key, &fields[21]) != 0 ||
        route_snapshot_key_size(&candidate->prepared_route_snapshot_key,
                                &fields[22]) != 0 ||
        local_name_namespace_size(&candidate->local_name_namespace,
                                  &fields[24]) != 0 ||
        lifecycle_policy_size(&candidate->lifecycle_policy, &fields[25]) != 0) {
        set_error(error, error_len, "cannot size candidate manifest fields");
        return -1;
    }
    fields[0] = WVM_IDENTITY_ID_BYTES;
    fields[1] = 2;
    fields[2] = WVM_SHA256_DIGEST_BYTES;
    fields[3] = 4;
    fields[4] = 8;
    fields[5] = 8;
    fields[6] = WVM_IDENTITY_ID_BYTES;
    fields[7] = WVM_IDENTITY_ID_BYTES;
    fields[8] = WVM_SHA256_DIGEST_BYTES;
    fields[9] = 8;
    fields[15] = 4;
    fields[23] = WVM_SHA256_DIGEST_BYTES;
    fields[26] = 2;
    return 0;
}

static int encode_nested_record(struct wvm_canonical_builder *builder,
                                uint16_t tag, size_t expected_bytes,
                                int (*encode)(const void *, uint8_t *, size_t,
                                              size_t *, char *, size_t),
                                const void *value, char *error,
                                size_t error_len)
{
    uint8_t *field_value;
    size_t actual_bytes;

    if (expected_bytes > UINT32_MAX ||
        wvm_canonical_field_reserve(builder, tag, (uint32_t)expected_bytes,
                                    &field_value) != 0 ||
        encode(value, field_value, expected_bytes, &actual_bytes, error,
               error_len) != 0 ||
        actual_bytes != expected_bytes) {
        return -1;
    }
    return 0;
}

static int machine_config_encode_adapter(const void *entry, uint8_t *bytes,
                                         size_t capacity, size_t *encoded_bytes,
                                         char *error, size_t error_len)
{
    return wvm_machine_config_encode(entry, bytes, capacity, encoded_bytes,
                                     error, error_len);
}

static int guest_topology_encode_adapter(const void *entry, uint8_t *bytes,
                                         size_t capacity, size_t *encoded_bytes,
                                         char *error, size_t error_len)
{
    return wvm_guest_topology_encode(entry, bytes, capacity, encoded_bytes,
                                     error, error_len);
}

static int execution_profile_encode_adapter(const void *entry, uint8_t *bytes,
                                            size_t capacity,
                                            size_t *encoded_bytes, char *error,
                                            size_t error_len)
{
    return wvm_execution_fault_profile_encode(entry, bytes, capacity,
                                              encoded_bytes, error, error_len);
}

static int consistency_policy_encode_adapter(const void *entry, uint8_t *bytes,
                                             size_t capacity,
                                             size_t *encoded_bytes,
                                             char *error, size_t error_len)
{
    return wvm_consistency_policy_encode(entry, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int storage_device_plan_encode_adapter(const void *entry, uint8_t *bytes,
                                              size_t capacity,
                                              size_t *encoded_bytes,
                                              char *error, size_t error_len)
{
    return wvm_storage_device_plan_encode(entry, bytes, capacity, encoded_bytes,
                                          error, error_len);
}

static int route_scope_key_encode_adapter(const void *entry, uint8_t *bytes,
                                          size_t capacity,
                                          size_t *encoded_bytes, char *error,
                                          size_t error_len)
{
    return wvm_vm_route_scope_key_encode(entry, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int route_snapshot_key_encode_adapter(const void *entry, uint8_t *bytes,
                                             size_t capacity,
                                             size_t *encoded_bytes,
                                             char *error, size_t error_len)
{
    return wvm_route_snapshot_key_encode(entry, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int local_namespace_encode_adapter(const void *entry, uint8_t *bytes,
                                          size_t capacity,
                                          size_t *encoded_bytes, char *error,
                                          size_t error_len)
{
    return wvm_local_name_namespace_encode(entry, bytes, capacity,
                                           encoded_bytes, error, error_len);
}

static int lifecycle_policy_encode_adapter(const void *entry, uint8_t *bytes,
                                           size_t capacity,
                                           size_t *encoded_bytes, char *error,
                                           size_t error_len)
{
    return wvm_lifecycle_policy_encode(entry, bytes, capacity, encoded_bytes,
                                       error, error_len);
}

int wvm_candidate_vm_manifest_encode(
    const struct wvm_candidate_vm_manifest *candidate, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes,
    uint8_t manifest_digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len)
{
    static const uint8_t zero_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_canonical_builder builder;
    size_t fields[27];
    size_t expected_bytes;
    uint8_t *field_value;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];

    if (!bytes || !encoded_bytes || !manifest_digest ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        candidate_manifest_field_sizes(candidate, fields, error, error_len) !=
            0 ||
        canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                              &expected_bytes) != 0 ||
        expected_bytes > capacity ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_CANDIDATE_VM_MANIFEST) != 0 ||
        wvm_canonical_field_append(&builder, 1, candidate->manifest_id,
                                   sizeof(candidate->manifest_id)) != 0 ||
        wvm_canonical_field_append_u16(&builder, 2,
                                       candidate->manifest_schema_version) !=
            0 ||
        wvm_canonical_field_append(&builder, 3, zero_digest,
                                   sizeof(zero_digest)) != 0 ||
        wvm_canonical_field_append_u32(&builder, 4, candidate->vm_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 5,
                                       candidate->vm_incarnation) != 0 ||
        wvm_canonical_field_append_u64(&builder, 6,
                                       candidate->manifest_generation) != 0 ||
        wvm_canonical_field_append(&builder, 7, candidate->request_id,
                                   sizeof(candidate->request_id)) != 0 ||
        wvm_canonical_field_append(&builder, 8, candidate->admission_tx_id,
                                   sizeof(candidate->admission_tx_id)) != 0 ||
        wvm_canonical_field_append(
            &builder, 9, candidate->eligibility_fence_digest,
            sizeof(candidate->eligibility_fence_digest)) != 0 ||
        wvm_canonical_field_append_u64(&builder, 10,
                                       candidate->candidate_created_at) != 0 ||
        encode_nested_record(&builder, 11, fields[10],
                             machine_config_encode_adapter,
                             &candidate->guest_machine, error, error_len) != 0 ||
        encode_nested_record(&builder, 12, fields[11],
                             guest_topology_encode_adapter,
                             &candidate->guest_topology, error, error_len) != 0 ||
        encode_nested_record(&builder, 13, fields[12],
                             execution_profile_encode_adapter,
                             &candidate->execution_plan, error, error_len) != 0 ||
        encode_nested_record(&builder, 14, fields[13],
                             consistency_policy_encode_adapter,
                             &candidate->consistency_policy, error,
                             error_len) != 0 ||
        encode_nested_record(&builder, 15, fields[14],
                             storage_device_plan_encode_adapter,
                             &candidate->storage_device_plan, error,
                             error_len) != 0 ||
        wvm_canonical_field_append_u32(&builder, 16, candidate->host_node) !=
            0) {
        set_error(error, error_len, "cannot begin candidate manifest encoding");
        return -1;
    }

    if (wvm_canonical_field_reserve(&builder, 17, fields[16], &field_value) !=
            0 ||
        record_list_encode(candidate->vcpu_placements.entries,
                           candidate->vcpu_placements.count,
                           sizeof(*candidate->vcpu_placements.entries),
                           vcpu_assignment_size_adapter,
                           vcpu_assignment_encode_adapter, field_value,
                           fields[16], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 18, fields[17], &field_value) !=
            0 ||
        record_list_encode(candidate->memory_placements.entries,
                           candidate->memory_placements.count,
                           sizeof(*candidate->memory_placements.entries),
                           memory_assignment_size_adapter,
                           memory_assignment_encode_adapter, field_value,
                           fields[17], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 19, fields[18], &field_value) !=
            0 ||
        record_list_encode(candidate->required_members.entries,
                           candidate->required_members.count,
                           sizeof(*candidate->required_members.entries),
                           required_member_size_adapter,
                           required_member_encode_adapter, field_value,
                           fields[18], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 20, fields[19], &field_value) !=
            0 ||
        record_list_encode(candidate->required_capabilities.entries,
                           candidate->required_capabilities.count,
                           sizeof(*candidate->required_capabilities.entries),
                           capability_ref_size_adapter,
                           capability_ref_encode_adapter, field_value,
                           fields[19], error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 21, fields[20], &field_value) !=
            0 ||
        record_list_encode(candidate->reservation_requirements.entries,
                           candidate->reservation_requirements.count,
                           sizeof(*candidate->reservation_requirements.entries),
                           requirement_size_adapter, requirement_encode_adapter,
                           field_value, fields[20], error, error_len) != 0 ||
        encode_nested_record(&builder, 22, fields[21],
                             route_scope_key_encode_adapter,
                             &candidate->route_scope_key, error, error_len) !=
            0 ||
        encode_nested_record(&builder, 23, fields[22],
                             route_snapshot_key_encode_adapter,
                             &candidate->prepared_route_snapshot_key, error,
                             error_len) != 0 ||
        wvm_canonical_field_append(&builder, 24, candidate->plan_digest,
                                   sizeof(candidate->plan_digest)) != 0 ||
        encode_nested_record(&builder, 25, fields[24],
                             local_namespace_encode_adapter,
                             &candidate->local_name_namespace, error,
                             error_len) != 0 ||
        encode_nested_record(&builder, 26, fields[25],
                             lifecycle_policy_encode_adapter,
                             &candidate->lifecycle_policy, error,
                             error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 27,
                                       candidate->namespace_abi) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0 ||
        *encoded_bytes != expected_bytes ||
        wvm_canonical_record_digest(bytes, *encoded_bytes, 3,
                                    calculated_digest) != 0) {
        set_error(error, error_len, "cannot finish candidate manifest encoding");
        return -1;
    }
    if (!bytes_are_zero(candidate->manifest_digest,
                        sizeof(candidate->manifest_digest)) &&
        memcmp(candidate->manifest_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len, "candidate manifest digest mismatch");
        return -1;
    }
    memcpy(bytes + WVM_CANONICAL_RECORD_HEADER_BYTES +
               WVM_CANONICAL_FIELD_HEADER_BYTES + WVM_IDENTITY_ID_BYTES +
               WVM_CANONICAL_FIELD_HEADER_BYTES + 2 +
               WVM_CANONICAL_FIELD_HEADER_BYTES,
           calculated_digest, sizeof(calculated_digest));
    memcpy(manifest_digest, calculated_digest, sizeof(calculated_digest));
    return 0;
}

int wvm_candidate_vm_manifest_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_candidate_vm_manifest *candidate, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[27];
    struct wvm_capability_ref_list profile_capabilities;
    struct wvm_storage_assignment_list storage_assignments;
    struct wvm_vcpu_assignment_list vcpu_placements;
    struct wvm_memory_chunk_assignment_list memory_placements;
    struct wvm_required_member_list required_members;
    struct wvm_capability_ref_list required_capabilities;
    struct wvm_reservation_requirement_list reservation_requirements;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];

    if (!candidate ||
        parse_exact_fields(bytes, encoded_bytes,
                           WVM_RECORD_CANDIDATE_VM_MANIFEST, fields,
                           sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[1].value_bytes != 2 ||
        fields[2].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[3].value_bytes != 4 || fields[4].value_bytes != 8 ||
        fields[5].value_bytes != 8 ||
        fields[6].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[7].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[8].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[9].value_bytes != 8 || fields[15].value_bytes != 4 ||
        fields[23].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[26].value_bytes != 2) {
        set_error(error, error_len, "candidate manifest has invalid widths");
        return -1;
    }

    profile_capabilities = candidate->execution_plan.per_node_capabilities;
    storage_assignments = candidate->storage_device_plan.assignments;
    vcpu_placements = candidate->vcpu_placements;
    memory_placements = candidate->memory_placements;
    required_members = candidate->required_members;
    required_capabilities = candidate->required_capabilities;
    reservation_requirements = candidate->reservation_requirements;
    memset(candidate, 0, sizeof(*candidate));
    candidate->execution_plan.per_node_capabilities = profile_capabilities;
    candidate->storage_device_plan.assignments = storage_assignments;
    candidate->vcpu_placements = vcpu_placements;
    candidate->memory_placements = memory_placements;
    candidate->required_members = required_members;
    candidate->required_capabilities = required_capabilities;
    candidate->reservation_requirements = reservation_requirements;

    memcpy(candidate->manifest_id, fields[0].value,
           sizeof(candidate->manifest_id));
    candidate->manifest_schema_version = read_be16(fields[1].value);
    memcpy(candidate->manifest_digest, fields[2].value,
           sizeof(candidate->manifest_digest));
    candidate->vm_id = read_be32(fields[3].value);
    candidate->vm_incarnation = read_be64(fields[4].value);
    candidate->manifest_generation = read_be64(fields[5].value);
    memcpy(candidate->request_id, fields[6].value,
           sizeof(candidate->request_id));
    memcpy(candidate->admission_tx_id, fields[7].value,
           sizeof(candidate->admission_tx_id));
    memcpy(candidate->eligibility_fence_digest, fields[8].value,
           sizeof(candidate->eligibility_fence_digest));
    candidate->candidate_created_at = read_be64(fields[9].value);
    candidate->host_node = read_be32(fields[15].value);
    memcpy(candidate->plan_digest, fields[23].value,
           sizeof(candidate->plan_digest));
    candidate->namespace_abi =
        (enum wvm_manifest_namespace_abi)read_be16(fields[26].value);

    if (wvm_machine_config_decode(fields[10].value, fields[10].value_bytes,
                                  &candidate->guest_machine, error,
                                  error_len) != 0 ||
        wvm_guest_topology_decode(fields[11].value, fields[11].value_bytes,
                                  &candidate->guest_topology, error,
                                  error_len) != 0 ||
        wvm_execution_fault_profile_decode(
            fields[12].value, fields[12].value_bytes,
            &candidate->execution_plan, error, error_len) != 0 ||
        wvm_consistency_policy_decode(fields[13].value, fields[13].value_bytes,
                                      &candidate->consistency_policy, error,
                                      error_len) != 0 ||
        wvm_storage_device_plan_decode(fields[14].value, fields[14].value_bytes,
                                       &candidate->storage_device_plan, error,
                                       error_len) != 0 ||
        record_list_decode(fields[16].value, fields[16].value_bytes,
                           candidate->vcpu_placements.entries,
                           candidate->vcpu_placements.capacity,
                           sizeof(*candidate->vcpu_placements.entries),
                           &candidate->vcpu_placements.count,
                           vcpu_assignment_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[17].value, fields[17].value_bytes,
                           candidate->memory_placements.entries,
                           candidate->memory_placements.capacity,
                           sizeof(*candidate->memory_placements.entries),
                           &candidate->memory_placements.count,
                           memory_assignment_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[18].value, fields[18].value_bytes,
                           candidate->required_members.entries,
                           candidate->required_members.capacity,
                           sizeof(*candidate->required_members.entries),
                           &candidate->required_members.count,
                           required_member_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[19].value, fields[19].value_bytes,
                           candidate->required_capabilities.entries,
                           candidate->required_capabilities.capacity,
                           sizeof(*candidate->required_capabilities.entries),
                           &candidate->required_capabilities.count,
                           capability_ref_decode_adapter, error,
                           error_len) != 0 ||
        record_list_decode(fields[20].value, fields[20].value_bytes,
                           candidate->reservation_requirements.entries,
                           candidate->reservation_requirements.capacity,
                           sizeof(*candidate->reservation_requirements.entries),
                           &candidate->reservation_requirements.count,
                           requirement_decode_adapter, error,
                           error_len) != 0 ||
        wvm_vm_route_scope_key_decode(fields[21].value, fields[21].value_bytes,
                                      &candidate->route_scope_key, error,
                                      error_len) != 0 ||
        wvm_route_snapshot_key_decode(fields[22].value, fields[22].value_bytes,
                                      &candidate->prepared_route_snapshot_key,
                                      error, error_len) != 0 ||
        wvm_local_name_namespace_decode(fields[24].value, fields[24].value_bytes,
                                        &candidate->local_name_namespace, error,
                                        error_len) != 0 ||
        wvm_lifecycle_policy_decode(fields[25].value, fields[25].value_bytes,
                                    &candidate->lifecycle_policy, error,
                                    error_len) != 0 ||
        wvm_canonical_record_digest(bytes, encoded_bytes, 3,
                                    calculated_digest) != 0 ||
        memcmp(candidate->manifest_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len,
                  "candidate manifest has invalid nested records or digest");
        return -1;
    }
    return wvm_candidate_vm_manifest_validate(candidate, error, error_len);
}

static int valid_backend_policy(enum wvm_manifest_backend_policy policy)
{
    return policy >= WVM_MANIFEST_BACKEND_POLICY_AUTO &&
           policy <= WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG;
}

static int valid_accelerator_policy(enum wvm_manifest_accelerator_policy policy)
{
    return policy >= WVM_MANIFEST_ACCELERATOR_DISABLED &&
           policy <= WVM_MANIFEST_ACCELERATOR_REQUIRE_KERNEL;
}

static int valid_placement_policy(enum wvm_manifest_placement_policy policy)
{
    return policy == WVM_MANIFEST_PLACEMENT_COMPACT ||
           policy == WVM_MANIFEST_PLACEMENT_SPREAD;
}

static int valid_host_constraint_kind(
    enum wvm_manifest_host_constraint_kind kind)
{
    return kind >= WVM_MANIFEST_HOST_CONSTRAINT_PHYSICAL_NODE &&
           kind <= WVM_MANIFEST_HOST_CONSTRAINT_LABEL;
}

static int valid_host_constraint_operator(
    enum wvm_manifest_host_constraint_operator comparison_operator)
{
    return comparison_operator == WVM_MANIFEST_HOST_CONSTRAINT_EQUALS ||
           comparison_operator == WVM_MANIFEST_HOST_CONSTRAINT_NOT_EQUALS;
}

int wvm_host_constraint_validate(
    const struct wvm_host_constraint *constraint, char *error,
    size_t error_len)
{
    if (!constraint || !valid_host_constraint_kind(constraint->constraint_kind) ||
        !valid_host_constraint_operator(constraint->comparison_operator) ||
        !valid_text(constraint->subject,
                    WVM_MANIFEST_CONSTRAINT_SUBJECT_MAX_BYTES) ||
        !valid_text(constraint->value, WVM_MANIFEST_CONSTRAINT_VALUE_MAX_BYTES)) {
        set_error(error, error_len, "host constraint is invalid");
        return -1;
    }
    return 0;
}

static int host_constraint_size(const struct wvm_host_constraint *constraint,
                                size_t *encoded_size)
{
    if (wvm_host_constraint_validate(constraint, NULL, 0) != 0) {
        return -1;
    }
    return canonical_record_size(
        (const size_t[]){2, 2, strlen(constraint->subject),
                         strlen(constraint->value)},
        4, encoded_size);
}

int wvm_host_constraint_encode(
    const struct wvm_host_constraint *constraint, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_host_constraint_validate(constraint, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_HOST_CONSTRAINT) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1,
                                       constraint->constraint_kind) != 0 ||
        wvm_canonical_field_append_u16(&builder, 2,
                                       constraint->comparison_operator) != 0 ||
        wvm_canonical_field_append(&builder, 3, constraint->subject,
                                   strlen(constraint->subject)) != 0 ||
        wvm_canonical_field_append(&builder, 4, constraint->value,
                                   strlen(constraint->value)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode host constraint");
        return -1;
    }
    return 0;
}

int wvm_host_constraint_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_host_constraint *constraint, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[4];

    if (!constraint ||
        parse_exact_fields(bytes, encoded_bytes, WVM_RECORD_HOST_CONSTRAINT,
                           fields, sizeof(fields) / sizeof(fields[0]), error,
                           error_len) != 0 ||
        fields[0].value_bytes != 2 || fields[1].value_bytes != 2 ||
        fields[2].value_bytes == 0 ||
        fields[2].value_bytes > WVM_MANIFEST_CONSTRAINT_SUBJECT_MAX_BYTES ||
        fields[3].value_bytes == 0 ||
        fields[3].value_bytes > WVM_MANIFEST_CONSTRAINT_VALUE_MAX_BYTES) {
        set_error(error, error_len, "host constraint has invalid fields");
        return -1;
    }
    memset(constraint, 0, sizeof(*constraint));
    constraint->constraint_kind =
        (enum wvm_manifest_host_constraint_kind)read_be16(fields[0].value);
    constraint->comparison_operator =
        (enum wvm_manifest_host_constraint_operator)read_be16(fields[1].value);
    memcpy(constraint->subject, fields[2].value, fields[2].value_bytes);
    memcpy(constraint->value, fields[3].value, fields[3].value_bytes);
    return wvm_host_constraint_validate(constraint, error, error_len);
}

static int host_constraint_size_adapter(const void *entry, size_t *encoded_size)
{
    return host_constraint_size(entry, encoded_size);
}

static int host_constraint_encode_adapter(const void *entry, uint8_t *bytes,
                                          size_t capacity,
                                          size_t *encoded_bytes, char *error,
                                          size_t error_len)
{
    return wvm_host_constraint_encode(entry, bytes, capacity, encoded_bytes,
                                      error, error_len);
}

static int host_constraint_decode_adapter(const uint8_t *bytes,
                                          size_t encoded_bytes, void *entry,
                                          char *error, size_t error_len)
{
    return wvm_host_constraint_decode(bytes, encoded_bytes, entry, error,
                                      error_len);
}

static int host_constraint_compare(const struct wvm_host_constraint *left,
                                   const struct wvm_host_constraint *right)
{
    int comparison;

    if (left->constraint_kind != right->constraint_kind) {
        return left->constraint_kind < right->constraint_kind ? -1 : 1;
    }
    comparison = strcmp(left->subject, right->subject);
    if (comparison != 0) {
        return comparison;
    }
    if (left->comparison_operator != right->comparison_operator) {
        return left->comparison_operator < right->comparison_operator ? -1 : 1;
    }
    return strcmp(left->value, right->value);
}

static int host_constraint_list_validate(
    const struct wvm_host_constraint_list *constraints, char *error,
    size_t error_len)
{
    size_t i;

    if (!constraints ||
        (constraints->count != 0 && !constraints->entries) ||
        constraints->count > UINT32_MAX) {
        set_error(error, error_len, "host constraint list is invalid");
        return -1;
    }
    for (i = 0; i < constraints->count; i++) {
        if (wvm_host_constraint_validate(&constraints->entries[i], error,
                                         error_len) != 0 ||
            (i != 0 &&
             host_constraint_compare(&constraints->entries[i - 1],
                                     &constraints->entries[i]) >= 0)) {
            set_error(error, error_len,
                      "host constraints are not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int host_constraint_list_size(
    const struct wvm_host_constraint_list *constraints, size_t *encoded_size)
{
    if (host_constraint_list_validate(constraints, NULL, 0) != 0) {
        return -1;
    }
    return record_list_size(constraints->entries, constraints->count,
                            sizeof(*constraints->entries),
                            host_constraint_size_adapter, encoded_size);
}

static int host_constraint_list_encode(
    const struct wvm_host_constraint_list *constraints, uint8_t *bytes,
    size_t encoded_bytes, char *error, size_t error_len)
{
    return record_list_encode(constraints->entries, constraints->count,
                              sizeof(*constraints->entries),
                              host_constraint_size_adapter,
                              host_constraint_encode_adapter, bytes,
                              encoded_bytes, error, error_len);
}

static int host_constraint_list_decode(const uint8_t *bytes,
                                       size_t encoded_bytes,
                                       struct wvm_host_constraint_list *constraints,
                                       char *error, size_t error_len)
{
    if (!constraints ||
        record_list_decode(bytes, encoded_bytes, constraints->entries,
                           constraints->capacity,
                           sizeof(*constraints->entries), &constraints->count,
                           host_constraint_decode_adapter, error, error_len) !=
            0) {
        return -1;
    }
    return host_constraint_list_validate(constraints, error, error_len);
}

int wvm_vm_request_validate(const struct wvm_vm_request *request, char *error,
                            size_t error_len)
{
    struct wvm_guest_topology topology;

    if (!request || request->api_version != WVM_CANONICAL_SCHEMA ||
        bytes_are_zero(request->request_id, sizeof(request->request_id)) ||
        (request->has_display_name != 0 && request->has_display_name != 1) ||
        (request->has_display_name &&
         !valid_text(request->display_name, WVM_MANIFEST_DISPLAY_NAME_MAX_BYTES)) ||
        request->requested_vcpus == 0 || request->requested_memory_bytes == 0 ||
        request->requested_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        !valid_backend_policy(request->execution_backend_policy) ||
        !valid_accelerator_policy(request->accelerator_policy) ||
        !valid_placement_policy(request->placement_policy) ||
        host_constraint_list_validate(&request->host_constraints, error,
                                      error_len) != 0 ||
        wvm_consistency_policy_validate(&request->consistency_policy, error,
                                        error_len) != 0 ||
        storage_device_plan_validate_request(&request->storage_device_plan,
                                             error, error_len) != 0 ||
        wvm_lifecycle_policy_validate(&request->lifecycle_policy, error,
                                      error_len) != 0) {
        set_error(error, error_len, "VM request is invalid");
        return -1;
    }
    memset(&topology, 0, sizeof(topology));
    topology.topology_policy = request->guest_topology_policy;
    topology.guest_numa_nodes =
        request->guest_topology_policy == WVM_MANIFEST_GUEST_TOPOLOGY_FLAT
            ? 1
            : 2;
    if (wvm_guest_topology_validate(&topology, error, error_len) != 0) {
        set_error(error, error_len, "VM request has invalid guest topology");
        return -1;
    }
    return 0;
}

int wvm_vm_request_encode(const struct wvm_vm_request *request, uint8_t *bytes,
                          size_t capacity, size_t *encoded_bytes, char *error,
                          size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *constraint_value;
    size_t constraint_bytes;
    size_t consistency_bytes;
    size_t storage_bytes;
    size_t lifecycle_bytes;

    if (wvm_vm_request_validate(request, error, error_len) != 0 ||
        host_constraint_list_size(&request->host_constraints,
                                  &constraint_bytes) != 0 ||
        consistency_policy_size(&request->consistency_policy,
                                &consistency_bytes) != 0 ||
        storage_device_plan_size_request(&request->storage_device_plan,
                                         &storage_bytes) != 0 ||
        lifecycle_policy_size(&request->lifecycle_policy, &lifecycle_bytes) !=
            0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_VM_REQUEST) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, request->api_version) != 0 ||
        wvm_canonical_field_append(&builder, 2, request->request_id,
                                   sizeof(request->request_id)) != 0 ||
        (request->has_display_name &&
         wvm_canonical_field_append(&builder, 3, request->display_name,
                                    strlen(request->display_name)) != 0) ||
        wvm_canonical_field_append_u32(&builder, 4, request->requested_vcpus) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 5,
                                       request->requested_memory_bytes) != 0 ||
        wvm_canonical_field_append_u16(&builder, 6,
                                       request->execution_backend_policy) != 0 ||
        wvm_canonical_field_append_u16(&builder, 7,
                                       request->accelerator_policy) != 0 ||
        wvm_canonical_field_append_u16(&builder, 8,
                                       request->placement_policy) != 0 ||
        wvm_canonical_field_reserve(&builder, 9, (uint32_t)constraint_bytes,
                                    &constraint_value) != 0 ||
        host_constraint_list_encode(&request->host_constraints, constraint_value,
                                    constraint_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 10,
                                       request->guest_topology_policy) != 0 ||
        wvm_canonical_field_reserve(&builder, 11, (uint32_t)consistency_bytes,
                                    &constraint_value) != 0 ||
        wvm_consistency_policy_encode(&request->consistency_policy,
                                      constraint_value, consistency_bytes,
                                      &consistency_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 12, (uint32_t)storage_bytes,
                                    &constraint_value) != 0 ||
        storage_device_plan_encode_request(&request->storage_device_plan,
                                           constraint_value, storage_bytes,
                                           &storage_bytes, error,
                                           error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 13, (uint32_t)lifecycle_bytes,
                                    &constraint_value) != 0 ||
        wvm_lifecycle_policy_encode(&request->lifecycle_policy,
                                    constraint_value, lifecycle_bytes,
                                    &lifecycle_bytes, error, error_len) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode VM request");
        return -1;
    }
    return 0;
}

int wvm_vm_request_decode(const uint8_t *bytes, size_t encoded_bytes,
                          struct wvm_vm_request *request, char *error,
                          size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field fields[14];
    unsigned char present[14] = {0};
    struct wvm_host_constraint_list constraints;
    struct wvm_storage_assignment_list storage_assignments;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int next;

    if (!request ||
        wvm_canonical_record_parse(bytes, encoded_bytes, &record) != 0 ||
        record.record_type != WVM_RECORD_VM_REQUEST) {
        set_error(error, error_len, "invalid VM request record");
        return -1;
    }
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 0 || field.tag > 13 || present[field.tag]) {
            set_error(error, error_len, "VM request has invalid fields");
            return -1;
        }
        fields[field.tag] = field;
        present[field.tag] = 1;
    }
    if (next < 0 || !present[1] || !present[2] || !present[4] ||
        !present[5] || !present[6] || !present[7] || !present[8] ||
        !present[9] || !present[10] || !present[11] || !present[12] ||
        !present[13] || fields[1].value_bytes != 2 ||
        fields[2].value_bytes != WVM_IDENTITY_ID_BYTES ||
        (present[3] &&
         (fields[3].value_bytes == 0 ||
          fields[3].value_bytes > WVM_MANIFEST_DISPLAY_NAME_MAX_BYTES)) ||
        fields[4].value_bytes != 4 || fields[5].value_bytes != 8 ||
        fields[6].value_bytes != 2 || fields[7].value_bytes != 2 ||
        fields[8].value_bytes != 2 || fields[10].value_bytes != 2) {
        set_error(error, error_len, "VM request has invalid field widths");
        return -1;
    }

    constraints = request->host_constraints;
    storage_assignments = request->storage_device_plan.assignments;
    memset(request, 0, sizeof(*request));
    request->host_constraints = constraints;
    request->storage_device_plan.assignments = storage_assignments;
    request->api_version = read_be16(fields[1].value);
    memcpy(request->request_id, fields[2].value, sizeof(request->request_id));
    request->has_display_name = present[3];
    if (request->has_display_name) {
        memcpy(request->display_name, fields[3].value, fields[3].value_bytes);
    }
    request->requested_vcpus = read_be32(fields[4].value);
    request->requested_memory_bytes = read_be64(fields[5].value);
    request->execution_backend_policy =
        (enum wvm_manifest_backend_policy)read_be16(fields[6].value);
    request->accelerator_policy =
        (enum wvm_manifest_accelerator_policy)read_be16(fields[7].value);
    request->placement_policy =
        (enum wvm_manifest_placement_policy)read_be16(fields[8].value);
    request->guest_topology_policy =
        (enum wvm_manifest_guest_topology_policy)read_be16(fields[10].value);
    if (host_constraint_list_decode(fields[9].value, fields[9].value_bytes,
                                    &request->host_constraints, error,
                                    error_len) != 0 ||
        wvm_consistency_policy_decode(fields[11].value, fields[11].value_bytes,
                                      &request->consistency_policy, error,
                                      error_len) != 0 ||
        storage_device_plan_decode_request(fields[12].value,
                                            fields[12].value_bytes,
                                            &request->storage_device_plan,
                                            error, error_len) != 0 ||
        wvm_lifecycle_policy_decode(fields[13].value, fields[13].value_bytes,
                                    &request->lifecycle_policy, error,
                                    error_len) != 0) {
        return -1;
    }
    return wvm_vm_request_validate(request, error, error_len);
}

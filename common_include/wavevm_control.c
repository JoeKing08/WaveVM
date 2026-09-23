#include "wavevm_control.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_canonical.h"

typedef int (*record_size_fn)(const void *entry, size_t *encoded_size);
typedef int (*record_encode_fn)(const void *entry, uint8_t *bytes,
                                size_t capacity, size_t *encoded_bytes,
                                char *error, size_t error_len);
typedef int (*record_decode_fn)(const uint8_t *bytes, size_t encoded_bytes,
                                void *entry, char *error, size_t error_len);

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

static int parse_record_fields(const uint8_t *bytes, size_t encoded_bytes,
                               uint16_t record_type,
                               struct wvm_canonical_field *fields,
                               unsigned char *present, size_t max_tag,
                               char *error, size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int next;

    if (!fields || !present || max_tag == 0 ||
        wvm_canonical_record_parse(bytes, encoded_bytes, &record) != 0 ||
        record.record_type != record_type) {
        set_error(error, error_len, "invalid canonical record 0x%04x",
                  record_type);
        return -1;
    }
    memset(fields, 0, (max_tag + 1U) * sizeof(*fields));
    memset(present, 0, max_tag + 1U);
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag > max_tag || present[field.tag]) {
            set_error(error, error_len, "record 0x%04x has an unknown field",
                      record_type);
            return -1;
        }
        fields[field.tag] = field;
        present[field.tag] = 1;
    }
    if (next < 0) {
        set_error(error, error_len, "record 0x%04x is malformed", record_type);
        return -1;
    }
    return 0;
}

static int valid_address_bytes(uint8_t bytes)
{
    return bytes == 4 || bytes == 16;
}

static int valid_utf8_text(const char *text, size_t max_bytes)
{
    const unsigned char *cursor = (const unsigned char *)text;
    size_t bytes = 0;

    if (!text) {
        return 0;
    }
    while (bytes <= max_bytes && cursor[bytes] != '\0') {
        bytes++;
    }
    if (bytes == 0 || bytes > max_bytes) {
        return 0;
    }
    while (*cursor != '\0') {
        unsigned char first = *cursor++;

        if (first < 0x80) {
            if (first == 0) {
                return 0;
            }
            continue;
        }
        if (first < 0xc2 || first > 0xf4) {
            return 0;
        }
        if (first < 0xe0) {
            if ((cursor[0] & 0xc0) != 0x80) {
                return 0;
            }
            cursor++;
        } else if (first < 0xf0) {
            if ((cursor[0] & 0xc0) != 0x80 ||
                (cursor[1] & 0xc0) != 0x80 ||
                (first == 0xe0 && cursor[0] < 0xa0) ||
                (first == 0xed && cursor[0] >= 0xa0)) {
                return 0;
            }
            cursor += 2;
        } else {
            if ((cursor[0] & 0xc0) != 0x80 ||
                (cursor[1] & 0xc0) != 0x80 ||
                (cursor[2] & 0xc0) != 0x80 ||
                (first == 0xf0 && cursor[0] < 0x90) ||
                (first == 0xf4 && cursor[0] >= 0x90)) {
                return 0;
            }
            cursor += 3;
        }
    }
    return 1;
}

static int valid_data_transport(enum wvm_data_transport transport)
{
    return transport == WVM_DATA_TRANSPORT_UDP ||
           transport == WVM_DATA_TRANSPORT_QUIC_DATAGRAM;
}

static int valid_control_transport(enum wvm_control_transport transport)
{
    return transport == WVM_CONTROL_TRANSPORT_UNIX_STREAM ||
           transport == WVM_CONTROL_TRANSPORT_TLS_TCP ||
           transport == WVM_CONTROL_TRANSPORT_QUIC_STREAM;
}

static int valid_route_topology(uint16_t topology_kind)
{
    return topology_kind == 1 || topology_kind == 2;
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

static int route_scope_identity_equal(
    const struct wvm_route_snapshot_key *left,
    const struct wvm_route_snapshot_key *right)
{
    return left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation;
}

static int route_snapshot_key_shape_validate(
    const struct wvm_route_snapshot_key *key, int allow_zero_digest,
    char *error, size_t error_len)
{
    if (!key ||
        wvm_vm_route_scope_key_validate(&key->scope_key, error, error_len) !=
            0 ||
        key->topology_revision == 0 || key->route_generation == 0 ||
        (!allow_zero_digest &&
         bytes_are_zero(key->snapshot_digest, WVM_SHA256_DIGEST_BYTES))) {
        set_error(error, error_len, "route snapshot key is invalid");
        return -1;
    }
    return 0;
}

static int member_key_size(size_t *encoded_size)
{
    static const size_t fields[] = {2, 4, 8};

    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int route_scope_key_size(size_t *encoded_size)
{
    static const size_t fields[] = {4, 8, 8};

    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int route_snapshot_key_size(size_t *encoded_size)
{
    size_t fields[4];

    if (route_scope_key_size(&fields[0]) != 0) {
        return -1;
    }
    fields[1] = 8;
    fields[2] = 8;
    fields[3] = WVM_SHA256_DIGEST_BYTES;
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int append_nested_record(struct wvm_canonical_builder *builder,
                                uint16_t field_tag, size_t nested_bytes,
                                record_encode_fn encode, const void *value,
                                char *error, size_t error_len)
{
    uint8_t *nested_value;
    size_t actual_bytes;

    if (!encode || nested_bytes > UINT32_MAX ||
        wvm_canonical_field_reserve(builder, field_tag, (uint32_t)nested_bytes,
                                    &nested_value) != 0 ||
        encode(value, nested_value, nested_bytes, &actual_bytes, error,
               error_len) != 0 ||
        actual_bytes != nested_bytes) {
        return -1;
    }
    return 0;
}

static int member_key_encode_adapter(const void *value, uint8_t *bytes,
                                     size_t capacity, size_t *encoded_bytes,
                                     char *error, size_t error_len)
{
    return wvm_member_key_encode(value, bytes, capacity, encoded_bytes, error,
                                 error_len);
}

static int route_snapshot_key_encode_adapter(const void *value, uint8_t *bytes,
                                             size_t capacity,
                                             size_t *encoded_bytes,
                                             char *error, size_t error_len)
{
    return wvm_route_snapshot_key_encode(value, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int route_snapshot_key_encode_allow_zero(
    const struct wvm_route_snapshot_key *key, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *scope_value;
    size_t scope_bytes;

    if (route_snapshot_key_shape_validate(key, 1, error, error_len) != 0 ||
        route_scope_key_size(&scope_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ROUTE_SNAPSHOT_KEY) != 0 ||
        wvm_canonical_field_reserve(&builder, 1, (uint32_t)scope_bytes,
                                    &scope_value) != 0 ||
        wvm_vm_route_scope_key_encode(&key->scope_key, scope_value, scope_bytes,
                                      &scope_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       key->topology_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       key->route_generation) != 0 ||
        wvm_canonical_field_append(&builder, 4, key->snapshot_digest,
                                   sizeof(key->snapshot_digest)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode route snapshot key");
        return -1;
    }
    return 0;
}

static int route_snapshot_key_decode_allow_zero(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_route_snapshot_key *key, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[5];
    unsigned char present[5];

    if (!key ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_ROUTE_SNAPSHOT_KEY,
                            fields, present, 4, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        fields[2].value_bytes != 8 || fields[3].value_bytes != 8 ||
        fields[4].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        wvm_vm_route_scope_key_decode(fields[1].value, fields[1].value_bytes,
                                      &key->scope_key, error, error_len) != 0) {
        set_error(error, error_len, "route snapshot key has invalid fields");
        return -1;
    }
    key->topology_revision = read_be64(fields[2].value);
    key->route_generation = read_be64(fields[3].value);
    memcpy(key->snapshot_digest, fields[4].value, sizeof(key->snapshot_digest));
    return route_snapshot_key_shape_validate(key, 1, error, error_len);
}

static int route_snapshot_key_encode_allow_zero_adapter(
    const void *value, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return route_snapshot_key_encode_allow_zero(value, bytes, capacity,
                                                encoded_bytes, error, error_len);
}

static int record_list_size(const void *entries, size_t count,
                            size_t entry_bytes, record_size_fn item_size,
                            size_t *encoded_size)
{
    const uint8_t *base = entries;
    size_t total = 4;
    size_t i;

    if (!item_size || (count != 0 && !entries) || count > UINT32_MAX) {
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

    if (!item_encode ||
        record_list_size(entries, count, entry_bytes, item_size,
                         &expected_bytes) != 0 ||
        expected_bytes != encoded_bytes) {
        set_error(error, error_len, "canonical list has invalid size");
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
        set_error(error, error_len, "canonical list is malformed");
        return -1;
    }
    count = read_be32(bytes);
    if (count > capacity || (count != 0 && !entries)) {
        set_error(error, error_len, "canonical list exceeds capacity");
        return -1;
    }
    for (i = 0; i < count; i++) {
        uint32_t item_bytes;

        if (encoded_bytes - offset < 4) {
            set_error(error, error_len, "canonical list is truncated");
            return -1;
        }
        item_bytes = read_be32(bytes + offset);
        offset += 4;
        if (item_bytes == 0 || item_bytes > encoded_bytes - offset ||
            item_decode(bytes + offset, item_bytes, base + i * entry_bytes,
                        error, error_len) != 0) {
            set_error(error, error_len, "canonical list has an invalid entry");
            return -1;
        }
        offset += item_bytes;
    }
    if (offset != encoded_bytes) {
        set_error(error, error_len, "canonical list has trailing bytes");
        return -1;
    }
    *count_out = count;
    return 0;
}

int wvm_endpoint_validate(const struct wvm_endpoint *endpoint, char *error,
                          size_t error_len)
{
    if (!endpoint || !valid_data_transport(endpoint->data_transport) ||
        !valid_address_bytes(endpoint->data_address_bytes) ||
        endpoint->data_port == 0 ||
        !valid_control_transport(endpoint->control_transport) ||
        endpoint->control_port == 0 ||
        (endpoint->has_control_address != 0 &&
         endpoint->has_control_address != 1) ||
        (endpoint->has_control_address &&
         !valid_address_bytes(endpoint->control_address_bytes)) ||
        (endpoint->has_server_name != 0 && endpoint->has_server_name != 1) ||
        (endpoint->has_server_name &&
         !valid_utf8_text(endpoint->server_name,
                          WVM_ENDPOINT_SERVER_NAME_MAX_BYTES)) ||
        (endpoint->has_control_socket_path != 0 &&
         endpoint->has_control_socket_path != 1) ||
        (endpoint->has_control_socket_path &&
         (!valid_utf8_text(endpoint->control_socket_path,
                           WVM_ENDPOINT_CONTROL_SOCKET_PATH_MAX_BYTES) ||
          endpoint->control_socket_path[0] != '/')) ||
        ((endpoint->control_transport == WVM_CONTROL_TRANSPORT_UNIX_STREAM) !=
         endpoint->has_control_socket_path)) {
        set_error(error, error_len, "endpoint is invalid");
        return -1;
    }
    return 0;
}

static int endpoint_size(const struct wvm_endpoint *endpoint,
                         size_t *encoded_size)
{
    size_t fields[8];
    size_t field_count = 0;

    if (wvm_endpoint_validate(endpoint, NULL, 0) != 0) {
        return -1;
    }
    fields[field_count++] = 2;
    fields[field_count++] = endpoint->data_address_bytes;
    fields[field_count++] = 2;
    fields[field_count++] = 2;
    if (endpoint->has_control_address) {
        fields[field_count++] = endpoint->control_address_bytes;
    }
    fields[field_count++] = 2;
    if (endpoint->has_server_name) {
        fields[field_count++] = strlen(endpoint->server_name);
    }
    if (endpoint->has_control_socket_path) {
        fields[field_count++] = strlen(endpoint->control_socket_path);
    }
    return canonical_record_size(fields, field_count, encoded_size);
}

int wvm_endpoint_encode(const struct wvm_endpoint *endpoint, uint8_t *bytes,
                        size_t capacity, size_t *encoded_bytes, char *error,
                        size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (wvm_endpoint_validate(endpoint, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ENDPOINT) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1,
                                       endpoint->data_transport) != 0 ||
        wvm_canonical_field_append(&builder, 2, endpoint->data_address,
                                   endpoint->data_address_bytes) != 0 ||
        wvm_canonical_field_append_u16(&builder, 3, endpoint->data_port) !=
            0 ||
        wvm_canonical_field_append_u16(&builder, 4,
                                       endpoint->control_transport) != 0 ||
        (endpoint->has_control_address &&
         wvm_canonical_field_append(&builder, 5, endpoint->control_address,
                                    endpoint->control_address_bytes) != 0) ||
        wvm_canonical_field_append_u16(&builder, 6, endpoint->control_port) !=
            0 ||
        (endpoint->has_server_name &&
         wvm_canonical_field_append(&builder, 7, endpoint->server_name,
                                    (uint32_t)strlen(endpoint->server_name)) !=
             0) ||
        (endpoint->has_control_socket_path &&
         wvm_canonical_field_append(&builder, 8,
                                    endpoint->control_socket_path,
                                    (uint32_t)strlen(
                                        endpoint->control_socket_path)) != 0) ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode endpoint");
        return -1;
    }
    return 0;
}

int wvm_endpoint_decode(const uint8_t *bytes, size_t encoded_bytes,
                        struct wvm_endpoint *endpoint, char *error,
                        size_t error_len)
{
    struct wvm_canonical_field fields[9];
    unsigned char present[9];

    if (!endpoint ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_ENDPOINT, fields,
                            present, 8, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[6] || fields[1].value_bytes != 2 ||
        !valid_address_bytes((uint8_t)fields[2].value_bytes) ||
        fields[3].value_bytes != 2 || fields[4].value_bytes != 2 ||
        (present[5] && !valid_address_bytes((uint8_t)fields[5].value_bytes)) ||
        fields[6].value_bytes != 2 ||
        (present[7] &&
         (fields[7].value_bytes == 0 ||
          fields[7].value_bytes > WVM_ENDPOINT_SERVER_NAME_MAX_BYTES ||
          memchr(fields[7].value, '\0', fields[7].value_bytes) != NULL)) ||
        (present[8] &&
         (fields[8].value_bytes == 0 ||
          fields[8].value_bytes > WVM_ENDPOINT_CONTROL_SOCKET_PATH_MAX_BYTES ||
          memchr(fields[8].value, '\0', fields[8].value_bytes) != NULL))) {
        set_error(error, error_len, "endpoint has invalid fields");
        return -1;
    }
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = (enum wvm_data_transport)read_be16(fields[1].value);
    endpoint->data_address_bytes = (uint8_t)fields[2].value_bytes;
    memcpy(endpoint->data_address, fields[2].value,
           endpoint->data_address_bytes);
    endpoint->data_port = read_be16(fields[3].value);
    endpoint->control_transport =
        (enum wvm_control_transport)read_be16(fields[4].value);
    endpoint->has_control_address = present[5];
    if (endpoint->has_control_address) {
        endpoint->control_address_bytes = (uint8_t)fields[5].value_bytes;
        memcpy(endpoint->control_address, fields[5].value,
               endpoint->control_address_bytes);
    }
    endpoint->control_port = read_be16(fields[6].value);
    endpoint->has_server_name = present[7];
    if (endpoint->has_server_name) {
        memcpy(endpoint->server_name, fields[7].value, fields[7].value_bytes);
    }
    endpoint->has_control_socket_path = present[8];
    if (endpoint->has_control_socket_path) {
        memcpy(endpoint->control_socket_path, fields[8].value,
               fields[8].value_bytes);
    }
    return wvm_endpoint_validate(endpoint, error, error_len);
}

static int endpoint_encode_adapter(const void *value, uint8_t *bytes,
                                   size_t capacity, size_t *encoded_bytes,
                                   char *error, size_t error_len)
{
    return wvm_endpoint_encode(value, bytes, capacity, encoded_bytes, error,
                               error_len);
}

static int required_ack_entry_validate(
    const struct wvm_required_ack_entry *entry, int allow_zero_self_digest,
    const struct wvm_route_snapshot_key *self_key, char *error,
    size_t error_len)
{
    if (!entry ||
        wvm_member_key_validate(&entry->member_key, error, error_len) != 0 ||
        wvm_endpoint_validate(&entry->endpoint, error, error_len) != 0 ||
        entry->role_type != entry->member_key.role_type ||
        route_snapshot_key_shape_validate(&entry->expected_snapshot_key,
                                          allow_zero_self_digest, error,
                                          error_len) != 0 ||
        (self_key &&
         !route_scope_identity_equal(&entry->expected_snapshot_key,
                                     self_key))) {
        set_error(error, error_len, "required ACK entry is invalid");
        return -1;
    }
    return 0;
}

static int required_ack_entry_size(const struct wvm_required_ack_entry *entry,
                                   size_t *encoded_size)
{
    size_t fields[4];

    if (!entry || member_key_size(&fields[0]) != 0 ||
        endpoint_size(&entry->endpoint, &fields[1]) != 0 ||
        route_snapshot_key_size(&fields[3]) != 0) {
        return -1;
    }
    fields[2] = 2;
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int required_ack_entry_encode_variant(
    const struct wvm_required_ack_entry *entry,
    const struct wvm_route_snapshot_key *self_key, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    struct wvm_route_snapshot_key expected_key;
    size_t member_key_bytes;
    size_t endpoint_bytes;
    size_t snapshot_key_bytes;

    if (required_ack_entry_validate(entry, self_key != NULL, self_key, error,
                                    error_len) != 0 ||
        member_key_size(&member_key_bytes) != 0 ||
        endpoint_size(&entry->endpoint, &endpoint_bytes) != 0 ||
        route_snapshot_key_size(&snapshot_key_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_REQUIRED_ACK_ENTRY) != 0 ||
        append_nested_record(&builder, 1, member_key_bytes,
                             member_key_encode_adapter, &entry->member_key,
                             error, error_len) != 0 ||
        append_nested_record(&builder, 2, endpoint_bytes, endpoint_encode_adapter,
                             &entry->endpoint, error, error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 3, entry->role_type) != 0) {
        set_error(error, error_len, "cannot encode required ACK entry");
        return -1;
    }
    expected_key = entry->expected_snapshot_key;
    if (self_key &&
        route_scope_identity_equal(&expected_key, self_key)) {
        expected_key = *self_key;
    }
    if (append_nested_record(&builder, 4, snapshot_key_bytes,
                             self_key
                                 ? route_snapshot_key_encode_allow_zero_adapter
                                 : route_snapshot_key_encode_adapter,
                             &expected_key, error, error_len) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot finish required ACK entry");
        return -1;
    }
    return 0;
}

static int required_ack_entry_decode(const uint8_t *bytes, size_t encoded_bytes,
                                     void *value, char *error,
                                     size_t error_len)
{
    struct wvm_required_ack_entry *entry = value;
    struct wvm_canonical_field fields[5];
    unsigned char present[5];

    if (!entry ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_REQUIRED_ACK_ENTRY,
                            fields, present, 4, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        fields[3].value_bytes != 2 ||
        wvm_member_key_decode(fields[1].value, fields[1].value_bytes,
                              &entry->member_key, error, error_len) != 0 ||
        wvm_endpoint_decode(fields[2].value, fields[2].value_bytes,
                            &entry->endpoint, error, error_len) != 0 ||
        wvm_route_snapshot_key_decode(
            fields[4].value, fields[4].value_bytes,
            &entry->expected_snapshot_key, error, error_len) != 0) {
        set_error(error, error_len, "required ACK entry has invalid fields");
        return -1;
    }
    entry->role_type = (enum wvm_manifest_role_type)read_be16(fields[3].value);
    return required_ack_entry_validate(entry, 0, NULL, error, error_len);
}

static int required_ack_entry_size_adapter(const void *value,
                                           size_t *encoded_size)
{
    return required_ack_entry_size(value, encoded_size);
}

static int required_ack_entry_list_validate(
    const struct wvm_required_ack_entry_list *entries, int require_nonempty,
    int allow_zero_self_digest, const struct wvm_route_snapshot_key *self_key,
    char *error, size_t error_len)
{
    size_t i;

    if (!entries || (entries->count != 0 && !entries->entries) ||
        entries->count > entries->capacity || entries->count > UINT32_MAX ||
        (require_nonempty && entries->count == 0)) {
        set_error(error, error_len, "required ACK entry list is invalid");
        return -1;
    }
    for (i = 0; i < entries->count; i++) {
        if (required_ack_entry_validate(&entries->entries[i],
                                        allow_zero_self_digest, self_key, error,
                                        error_len) != 0 ||
            (i != 0 &&
             member_key_compare(&entries->entries[i - 1].member_key,
                                &entries->entries[i].member_key) >= 0)) {
            set_error(error, error_len,
                      "required ACK entries are not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int required_ack_entry_list_size(
    const struct wvm_required_ack_entry_list *entries, int require_nonempty,
    int allow_zero_self_digest, const struct wvm_route_snapshot_key *self_key,
    size_t *encoded_size)
{
    if (required_ack_entry_list_validate(entries, require_nonempty,
                                         allow_zero_self_digest, self_key, NULL,
                                         0) != 0) {
        return -1;
    }
    return record_list_size(entries->entries, entries->count,
                            sizeof(*entries->entries),
                            required_ack_entry_size_adapter, encoded_size);
}

static int required_ack_entry_list_encode(
    const struct wvm_required_ack_entry_list *entries,
    const struct wvm_route_snapshot_key *self_key, uint8_t *bytes,
    size_t encoded_bytes, char *error, size_t error_len)
{
    size_t offset = 4;
    size_t i;

    if (required_ack_entry_list_validate(entries, 1, self_key != NULL, self_key,
                                         error, error_len) != 0) {
        return -1;
    }
    write_be32(bytes, (uint32_t)entries->count);
    for (i = 0; i < entries->count; i++) {
        size_t item_bytes;
        size_t actual_bytes;

        if (required_ack_entry_size(&entries->entries[i], &item_bytes) != 0 ||
            encoded_bytes - offset < 4 + item_bytes) {
            return -1;
        }
        write_be32(bytes + offset, (uint32_t)item_bytes);
        offset += 4;
        if (required_ack_entry_encode_variant(&entries->entries[i], self_key,
                                              bytes + offset, item_bytes,
                                              &actual_bytes, error,
                                              error_len) != 0 ||
            actual_bytes != item_bytes) {
            return -1;
        }
        offset += item_bytes;
    }
    return offset == encoded_bytes ? 0 : -1;
}

static int required_ack_entry_list_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_required_ack_entry_list *entries, char *error, size_t error_len)
{
    if (!entries ||
        record_list_decode(bytes, encoded_bytes, entries->entries,
                           entries->capacity, sizeof(*entries->entries),
                           &entries->count, required_ack_entry_decode, error,
                           error_len) != 0) {
        return -1;
    }
    return required_ack_entry_list_validate(entries, 1, 0, NULL, error,
                                            error_len);
}

static int required_ack_entry_list_digest_normalized(
    const uint8_t *bytes, size_t encoded_bytes,
    const struct wvm_route_snapshot_key *self_key,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES])
{
    struct wvm_sha256_ctx ctx;
    uint32_t count;
    uint32_t i;
    size_t offset = 4;
    size_t hashed_bytes = 0;

    if (!bytes || !self_key || !digest || encoded_bytes < 4) {
        return -1;
    }
    count = read_be32(bytes);
    wvm_sha256_init(&ctx);
    for (i = 0; i < count; i++) {
        struct wvm_canonical_field fields[5];
        unsigned char present[5];
        struct wvm_route_snapshot_key expected_key;
        uint32_t item_bytes;
        const uint8_t *digest_ptr;

        if (encoded_bytes - offset < 4) {
            return -1;
        }
        item_bytes = read_be32(bytes + offset);
        offset += 4;
        if (item_bytes == 0 || item_bytes > encoded_bytes - offset ||
            parse_record_fields(bytes + offset, item_bytes,
                                WVM_RECORD_REQUIRED_ACK_ENTRY, fields, present,
                                4, NULL, 0) != 0 ||
            !present[4] ||
            route_snapshot_key_decode_allow_zero(
                fields[4].value, fields[4].value_bytes, &expected_key, NULL,
                0) != 0) {
            return -1;
        }
        if (route_scope_identity_equal(&expected_key, self_key)) {
            struct wvm_canonical_record nested;
            struct wvm_canonical_field nested_field;
            size_t nested_offset = 0;

            if (wvm_canonical_record_parse(fields[4].value,
                                           fields[4].value_bytes,
                                           &nested) != 0) {
                return -1;
            }
            do {
                if (wvm_canonical_record_next(&nested, &nested_offset,
                                              &nested_field) != 1) {
                    return -1;
                }
            } while (nested_field.tag != 4);
            digest_ptr = nested_field.value;
            wvm_sha256_update(&ctx, bytes + hashed_bytes,
                              (size_t)(digest_ptr - bytes) - hashed_bytes);
            wvm_sha256_update(&ctx, (const uint8_t[WVM_SHA256_DIGEST_BYTES]){0},
                              WVM_SHA256_DIGEST_BYTES);
            hashed_bytes =
                (size_t)(digest_ptr - bytes) + WVM_SHA256_DIGEST_BYTES;
        }
        offset += item_bytes;
    }
    if (offset != encoded_bytes) {
        return -1;
    }
    wvm_sha256_update(&ctx, bytes + hashed_bytes, encoded_bytes - hashed_bytes);
    wvm_sha256_final(&ctx, digest);
    return 0;
}

static int required_ack_set_shape_validate(
    const struct wvm_required_ack_set *ack_set, int allow_zero_digest,
    const struct wvm_route_snapshot_key *self_key, char *error,
    size_t error_len)
{
    if (!ack_set ||
        required_ack_entry_list_validate(&ack_set->entries, 1,
                                         self_key != NULL, self_key, error,
                                         error_len) != 0 ||
        (!allow_zero_digest &&
         bytes_are_zero(ack_set->entries_digest,
                        sizeof(ack_set->entries_digest)))) {
        set_error(error, error_len, "required ACK set is invalid");
        return -1;
    }
    return 0;
}

int wvm_required_ack_set_validate(const struct wvm_required_ack_set *ack_set,
                                  char *error, size_t error_len)
{
    return required_ack_set_shape_validate(ack_set, 0, NULL, error, error_len);
}

static int required_ack_set_size(const struct wvm_required_ack_set *ack_set,
                                 const struct wvm_route_snapshot_key *self_key,
                                 size_t *encoded_size)
{
    size_t fields[2];

    if (required_ack_set_shape_validate(ack_set, 1, self_key, NULL, 0) != 0 ||
        required_ack_entry_list_size(&ack_set->entries, 1, self_key != NULL,
                                     self_key, &fields[0]) != 0) {
        return -1;
    }
    fields[1] = WVM_SHA256_DIGEST_BYTES;
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int required_ack_set_encode_variant(
    const struct wvm_required_ack_set *ack_set,
    const struct wvm_route_snapshot_key *self_key, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes,
    uint8_t entries_digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *entries_value;
    size_t entries_bytes;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];

    if (required_ack_set_shape_validate(ack_set, 1, self_key, error,
                                        error_len) != 0 ||
        required_ack_entry_list_size(&ack_set->entries, 1, self_key != NULL,
                                     self_key, &entries_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_REQUIRED_ACK_SET) != 0 ||
        wvm_canonical_field_reserve(&builder, 1, (uint32_t)entries_bytes,
                                    &entries_value) != 0 ||
        required_ack_entry_list_encode(&ack_set->entries, self_key,
                                       entries_value, entries_bytes, error,
                                       error_len) != 0 ||
        (self_key
             ? required_ack_entry_list_digest_normalized(
                   entries_value, entries_bytes, self_key, calculated_digest)
             : (wvm_sha256_digest(entries_value, entries_bytes,
                                  calculated_digest),
                0)) != 0 ||
        (!bytes_are_zero(ack_set->entries_digest,
                         sizeof(ack_set->entries_digest)) &&
         memcmp(ack_set->entries_digest, calculated_digest,
                sizeof(calculated_digest)) != 0) ||
        wvm_canonical_field_append(&builder, 2, calculated_digest,
                                   sizeof(calculated_digest)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode required ACK set");
        return -1;
    }
    if (entries_digest) {
        memcpy(entries_digest, calculated_digest, sizeof(calculated_digest));
    }
    return 0;
}

int wvm_required_ack_set_encode(const struct wvm_required_ack_set *ack_set,
                                uint8_t *bytes, size_t capacity,
                                size_t *encoded_bytes, char *error,
                                size_t error_len)
{
    return required_ack_set_encode_variant(ack_set, NULL, bytes, capacity,
                                           encoded_bytes, NULL, error,
                                           error_len);
}

static int required_ack_set_decode_variant(
    const uint8_t *bytes, size_t encoded_bytes, struct wvm_required_ack_set *ack_set,
    const struct wvm_route_snapshot_key *self_key, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[3];
    unsigned char present[3];
    struct wvm_required_ack_entry_list entries;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];

    if (!ack_set ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_REQUIRED_ACK_SET,
                            fields, present, 2, error, error_len) != 0 ||
        !present[1] || !present[2] ||
        fields[2].value_bytes != WVM_SHA256_DIGEST_BYTES) {
        set_error(error, error_len, "required ACK set has invalid fields");
        return -1;
    }
    entries = ack_set->entries;
    memset(ack_set, 0, sizeof(*ack_set));
    ack_set->entries = entries;
    if (required_ack_entry_list_decode(fields[1].value, fields[1].value_bytes,
                                       &ack_set->entries, error, error_len) !=
            0 ||
        (self_key &&
         required_ack_entry_list_validate(&ack_set->entries, 1, 0, self_key,
                                          error, error_len) != 0) ||
        (self_key
             ? required_ack_entry_list_digest_normalized(
                   fields[1].value, fields[1].value_bytes, self_key,
                   calculated_digest)
             : (wvm_sha256_digest(fields[1].value, fields[1].value_bytes,
                                  calculated_digest),
                0)) != 0 ||
        memcmp(fields[2].value, calculated_digest, sizeof(calculated_digest)) !=
            0) {
        set_error(error, error_len, "required ACK set digest is invalid");
        return -1;
    }
    memcpy(ack_set->entries_digest, fields[2].value,
           sizeof(ack_set->entries_digest));
    return required_ack_set_shape_validate(ack_set, 0, self_key, error,
                                           error_len);
}

int wvm_required_ack_set_decode(const uint8_t *bytes, size_t encoded_bytes,
                                struct wvm_required_ack_set *ack_set,
                                char *error, size_t error_len)
{
    return required_ack_set_decode_variant(bytes, encoded_bytes, ack_set, NULL,
                                           error, error_len);
}

static int route_rule_compare(const struct wvm_route_rule_record *left,
                              const struct wvm_route_rule_record *right)
{
    if (left->destination_kind != right->destination_kind) {
        return left->destination_kind < right->destination_kind ? -1 : 1;
    }
    if (left->destination_scope != right->destination_scope) {
        return left->destination_scope < right->destination_scope ? -1 : 1;
    }
    if (left->destination_vnode_or_endpoint !=
        right->destination_vnode_or_endpoint) {
        return left->destination_vnode_or_endpoint <
                       right->destination_vnode_or_endpoint
                   ? -1
                   : 1;
    }
    return 0;
}

static int route_rule_validate(const struct wvm_route_rule_record *rule,
                               char *error, size_t error_len)
{
    if (!rule || rule->hop_limit == 0 ||
        wvm_member_key_validate(&rule->next_hop_member, error, error_len) !=
            0 ||
        wvm_endpoint_validate(&rule->next_hop_endpoint, error, error_len) !=
            0) {
        set_error(error, error_len, "route rule is invalid");
        return -1;
    }
    switch (rule->destination_kind) {
    case WVM_ROUTE_DESTINATION_EXACT_VNODE:
        break;
    case WVM_ROUTE_DESTINATION_PREFIX:
        /*
         * Prefix rules describe an admitted fractal subtree.  A prefix never
         * identifies a leaf executor, and forwarding it directly to a node
         * runtime would make a route scope silently collapse into raw-ID
         * routing.
         */
        if (rule->destination_scope == 0 ||
            rule->destination_vnode_or_endpoint != 0 ||
            rule->next_hop_kind != WVM_ROUTE_NEXT_HOP_GATEWAY ||
            rule->next_hop_member.role_type != WVM_MANIFEST_ROLE_GATEWAY) {
            set_error(error, error_len, "route prefix rule is invalid");
            return -1;
        }
        break;
    default:
        set_error(error, error_len, "route destination kind is invalid");
        return -1;
    }
    switch (rule->next_hop_kind) {
    case WVM_ROUTE_NEXT_HOP_ENDPOINT:
        break;
    case WVM_ROUTE_NEXT_HOP_GATEWAY:
        if (rule->next_hop_member.role_type != WVM_MANIFEST_ROLE_GATEWAY) {
            set_error(error, error_len,
                      "gateway next hop lacks a gateway member");
            return -1;
        }
        break;
    default:
        set_error(error, error_len, "route next-hop kind is invalid");
        return -1;
    }
    return 0;
}

static int route_rule_size(const struct wvm_route_rule_record *rule,
                           size_t *encoded_size)
{
    size_t fields[7];

    if (route_rule_validate(rule, NULL, 0) != 0 ||
        member_key_size(&fields[4]) != 0 ||
        endpoint_size(&rule->next_hop_endpoint, &fields[5]) != 0) {
        return -1;
    }
    fields[0] = 2;
    fields[1] = 8;
    fields[2] = 4;
    fields[3] = 2;
    fields[6] = 2;
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int route_rule_encode(const void *value, uint8_t *bytes, size_t capacity,
                             size_t *encoded_bytes, char *error,
                             size_t error_len)
{
    const struct wvm_route_rule_record *rule = value;
    struct wvm_canonical_builder builder;
    size_t member_key_bytes;
    size_t endpoint_bytes;

    if (route_rule_validate(rule, error, error_len) != 0 ||
        member_key_size(&member_key_bytes) != 0 ||
        endpoint_size(&rule->next_hop_endpoint, &endpoint_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ROUTE_RULE) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, rule->destination_kind) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       rule->destination_scope) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 3, rule->destination_vnode_or_endpoint) != 0 ||
        wvm_canonical_field_append_u16(&builder, 4, rule->next_hop_kind) != 0 ||
        append_nested_record(&builder, 5, member_key_bytes,
                             member_key_encode_adapter, &rule->next_hop_member,
                             error, error_len) != 0 ||
        append_nested_record(&builder, 6, endpoint_bytes, endpoint_encode_adapter,
                             &rule->next_hop_endpoint, error, error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 7, rule->hop_limit) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode route rule");
        return -1;
    }
    return 0;
}

static int route_rule_decode(const uint8_t *bytes, size_t encoded_bytes,
                             void *value, char *error, size_t error_len)
{
    struct wvm_route_rule_record *rule = value;
    struct wvm_canonical_field fields[8];
    unsigned char present[8];

    if (!rule ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_ROUTE_RULE, fields,
                            present, 7, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || !present[6] || !present[7] ||
        fields[1].value_bytes != 2 || fields[2].value_bytes != 8 ||
        fields[3].value_bytes != 4 || fields[4].value_bytes != 2 ||
        fields[7].value_bytes != 2 ||
        wvm_member_key_decode(fields[5].value, fields[5].value_bytes,
                              &rule->next_hop_member, error, error_len) != 0 ||
        wvm_endpoint_decode(fields[6].value, fields[6].value_bytes,
                            &rule->next_hop_endpoint, error, error_len) != 0) {
        set_error(error, error_len, "route rule has invalid fields");
        return -1;
    }
    rule->destination_kind = read_be16(fields[1].value);
    rule->destination_scope = read_be64(fields[2].value);
    rule->destination_vnode_or_endpoint = read_be32(fields[3].value);
    rule->next_hop_kind = read_be16(fields[4].value);
    rule->hop_limit = read_be16(fields[7].value);
    return route_rule_validate(rule, error, error_len);
}

static int route_rule_size_adapter(const void *value, size_t *encoded_size)
{
    return route_rule_size(value, encoded_size);
}

static int route_rule_list_validate(
    const struct wvm_route_rule_record_list *rules, char *error,
    size_t error_len)
{
    size_t i;

    if (!rules || !rules->entries || rules->count == 0 ||
        rules->count > rules->capacity || rules->count > UINT32_MAX) {
        set_error(error, error_len, "route rule list is invalid");
        return -1;
    }
    for (i = 0; i < rules->count; i++) {
        if (route_rule_validate(&rules->entries[i], error, error_len) != 0 ||
            (i != 0 &&
             route_rule_compare(&rules->entries[i - 1], &rules->entries[i]) >=
                 0)) {
            set_error(error, error_len,
                      "route rules are not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int route_rule_list_size(const struct wvm_route_rule_record_list *rules,
                                size_t *encoded_size)
{
    if (route_rule_list_validate(rules, NULL, 0) != 0) {
        return -1;
    }
    return record_list_size(rules->entries, rules->count,
                            sizeof(*rules->entries), route_rule_size_adapter,
                            encoded_size);
}

static int route_snapshot_shape_validate(
    const struct wvm_route_snapshot_record *snapshot, int allow_zero_digest,
    char *error, size_t error_len)
{
    size_t i;

    if (!snapshot ||
        route_snapshot_key_shape_validate(&snapshot->route_snapshot_key, 1,
                                          error, error_len) != 0 ||
        (!allow_zero_digest &&
         bytes_are_zero(snapshot->route_snapshot_key.snapshot_digest,
                        WVM_SHA256_DIGEST_BYTES)) ||
        snapshot->membership_revision == 0 ||
        !valid_route_topology(snapshot->topology_kind) ||
        route_rule_list_validate(&snapshot->next_hop_rules, error, error_len) !=
            0 ||
        required_ack_set_shape_validate(&snapshot->required_ack_set, 1,
                                        &snapshot->route_snapshot_key, error,
                                        error_len) != 0 ||
        (snapshot->has_predecessor_snapshot_key != 0 &&
         snapshot->has_predecessor_snapshot_key != 1) ||
        (snapshot->has_predecessor_snapshot_key &&
         (wvm_route_snapshot_key_validate(&snapshot->predecessor_snapshot_key,
                                          error, error_len) != 0 ||
          snapshot->predecessor_snapshot_key.scope_key.vm_id !=
              snapshot->route_snapshot_key.scope_key.vm_id ||
          snapshot->predecessor_snapshot_key.scope_key.vm_incarnation !=
              snapshot->route_snapshot_key.scope_key.vm_incarnation ||
          snapshot->predecessor_snapshot_key.scope_key.route_scope_id !=
              snapshot->route_snapshot_key.scope_key.route_scope_id)) ||
        snapshot->operation_retention_horizon_ms == 0 ||
        snapshot->retirement_policy == 0) {
        set_error(error, error_len, "route snapshot is invalid");
        return -1;
    }
    if (!allow_zero_digest) {
        for (i = 0; i < snapshot->required_ack_set.entries.count; i++) {
            const struct wvm_route_snapshot_key *expected =
                &snapshot->required_ack_set.entries.entries[i]
                     .expected_snapshot_key;

            if (!route_scope_identity_equal(expected,
                                            &snapshot->route_snapshot_key) ||
                memcmp(expected->snapshot_digest,
                       snapshot->route_snapshot_key.snapshot_digest,
                       WVM_SHA256_DIGEST_BYTES) != 0) {
                set_error(error, error_len,
                          "route snapshot ACK set has the wrong final key");
                return -1;
            }
        }
    }
    for (i = 0; i < snapshot->next_hop_rules.count; i++) {
        const struct wvm_route_rule_record *rule =
            &snapshot->next_hop_rules.entries[i];

        if (snapshot->topology_kind == 1 &&
            (rule->destination_kind != WVM_ROUTE_DESTINATION_EXACT_VNODE ||
             rule->destination_scope != 0)) {
            set_error(error, error_len,
                      "flat route snapshot contains a non-flat rule");
            return -1;
        }
        if (snapshot->topology_kind == 2 &&
            rule->destination_kind ==
                WVM_ROUTE_DESTINATION_EXACT_VNODE &&
            rule->destination_scope == 0) {
            set_error(error, error_len,
                      "fractal exact route lacks a destination scope");
            return -1;
        }
    }
    return 0;
}

static int route_snapshot_hash_with_normalized_self_refs(
    const uint8_t *bytes, size_t encoded_bytes,
    const struct wvm_route_snapshot_key *self_key,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES])
{
    struct wvm_canonical_field fields[9];
    unsigned char present[9];
    struct wvm_canonical_record nested;
    struct wvm_canonical_field nested_field;
    struct wvm_sha256_ctx ctx;
    size_t nested_offset = 0;
    size_t hashed_bytes = 0;
    const uint8_t *digest_ptr;

    if (!bytes || !self_key || !digest ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_ROUTE_SNAPSHOT,
                            fields, present, 8, NULL, 0) != 0 ||
        !present[1] || !present[5] ||
        wvm_canonical_record_parse(fields[1].value, fields[1].value_bytes,
                                   &nested) != 0) {
        return -1;
    }
    do {
        if (wvm_canonical_record_next(&nested, &nested_offset, &nested_field) !=
            1) {
            return -1;
        }
    } while (nested_field.tag != 4);
    digest_ptr = nested_field.value;
    wvm_sha256_init(&ctx);
    wvm_sha256_update(&ctx, bytes, (size_t)(digest_ptr - bytes));
    wvm_sha256_update(&ctx, (const uint8_t[WVM_SHA256_DIGEST_BYTES]){0},
                      WVM_SHA256_DIGEST_BYTES);
    hashed_bytes = (size_t)(digest_ptr - bytes) + WVM_SHA256_DIGEST_BYTES;

    {
        struct wvm_canonical_field ack_fields[3];
        unsigned char ack_present[3];

        if (parse_record_fields(fields[5].value, fields[5].value_bytes,
                                WVM_RECORD_REQUIRED_ACK_SET, ack_fields,
                                ack_present, 2, NULL, 0) != 0 ||
            !ack_present[1]) {
            return -1;
        }
        if (required_ack_entry_list_digest_normalized(
                ack_fields[1].value, ack_fields[1].value_bytes, self_key,
                digest) != 0) {
            return -1;
        }

        /*
         * The helper above only calculates the ACK-list digest. Re-scan its
         * self-reference locations so the enclosing snapshot hash sees the
         * same normalization without copying the complete route record.
         */
        {
            uint32_t count = read_be32(ack_fields[1].value);
            uint32_t i;
            size_t list_offset = 4;

            for (i = 0; i < count; i++) {
                struct wvm_canonical_field entry_fields[5];
                unsigned char entry_present[5];
                struct wvm_route_snapshot_key expected;
                uint32_t item_bytes;

                if (ack_fields[1].value_bytes - list_offset < 4) {
                    return -1;
                }
                item_bytes = read_be32(ack_fields[1].value + list_offset);
                list_offset += 4;
                if (item_bytes == 0 ||
                    item_bytes > ack_fields[1].value_bytes - list_offset ||
                    parse_record_fields(ack_fields[1].value + list_offset,
                                        item_bytes,
                                        WVM_RECORD_REQUIRED_ACK_ENTRY,
                                        entry_fields, entry_present, 4, NULL,
                                        0) != 0 ||
                    !entry_present[4] ||
                    route_snapshot_key_decode_allow_zero(
                        entry_fields[4].value, entry_fields[4].value_bytes,
                        &expected, NULL, 0) != 0) {
                    return -1;
                }
                if (route_scope_identity_equal(&expected, self_key)) {
                    struct wvm_canonical_record entry_key;
                    size_t key_offset = 0;

                    if (wvm_canonical_record_parse(
                            entry_fields[4].value,
                            entry_fields[4].value_bytes, &entry_key) != 0) {
                        return -1;
                    }
                    do {
                        if (wvm_canonical_record_next(
                                &entry_key, &key_offset, &nested_field) != 1) {
                            return -1;
                        }
                    } while (nested_field.tag != 4);
                    digest_ptr = nested_field.value;
                    wvm_sha256_update(
                        &ctx, bytes + hashed_bytes,
                        (size_t)(digest_ptr - bytes) - hashed_bytes);
                    wvm_sha256_update(
                        &ctx, (const uint8_t[WVM_SHA256_DIGEST_BYTES]){0},
                        WVM_SHA256_DIGEST_BYTES);
                    hashed_bytes =
                        (size_t)(digest_ptr - bytes) + WVM_SHA256_DIGEST_BYTES;
                }
                list_offset += item_bytes;
            }
            if (list_offset != ack_fields[1].value_bytes) {
                return -1;
            }
        }
    }
    wvm_sha256_update(&ctx, bytes + hashed_bytes, encoded_bytes - hashed_bytes);
    wvm_sha256_final(&ctx, digest);
    return 0;
}

int wvm_route_snapshot_record_validate(
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    return route_snapshot_shape_validate(snapshot, 0, error, error_len);
}

int wvm_route_snapshot_record_encode(
    const struct wvm_route_snapshot_record *snapshot, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes,
    uint8_t snapshot_digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len)
{
    struct wvm_canonical_builder builder;
    struct wvm_route_snapshot_key final_key;
    uint8_t *key_value;
    uint8_t *rules_value;
    uint8_t *ack_value;
    size_t key_bytes;
    size_t rules_bytes;
    size_t ack_bytes;
    size_t predecessor_bytes;
    size_t actual_bytes;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t ack_digest[WVM_SHA256_DIGEST_BYTES];

    if (route_snapshot_shape_validate(snapshot, 1, error, error_len) != 0 ||
        route_snapshot_key_size(&key_bytes) != 0 ||
        route_rule_list_size(&snapshot->next_hop_rules, &rules_bytes) != 0 ||
        required_ack_set_size(&snapshot->required_ack_set,
                              &snapshot->route_snapshot_key, &ack_bytes) != 0 ||
        (snapshot->has_predecessor_snapshot_key &&
         route_snapshot_key_size(&predecessor_bytes) != 0) ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ROUTE_SNAPSHOT) != 0 ||
        wvm_canonical_field_reserve(&builder, 1, (uint32_t)key_bytes,
                                    &key_value) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       snapshot->membership_revision) != 0 ||
        wvm_canonical_field_append_u16(&builder, 3,
                                       snapshot->topology_kind) != 0 ||
        wvm_canonical_field_reserve(&builder, 4, (uint32_t)rules_bytes,
                                    &rules_value) != 0 ||
        record_list_encode(snapshot->next_hop_rules.entries,
                           snapshot->next_hop_rules.count,
                           sizeof(*snapshot->next_hop_rules.entries),
                           route_rule_size_adapter, route_rule_encode,
                           rules_value, rules_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 5, (uint32_t)ack_bytes,
                                    &ack_value) != 0 ||
        (snapshot->has_predecessor_snapshot_key &&
         append_nested_record(&builder, 6, predecessor_bytes,
                              route_snapshot_key_encode_adapter,
                              &snapshot->predecessor_snapshot_key, error,
                              error_len) != 0) ||
        wvm_canonical_field_append_u64(&builder, 7,
                                       snapshot->operation_retention_horizon_ms) !=
            0 ||
        wvm_canonical_field_append_u16(&builder, 8,
                                       snapshot->retirement_policy) != 0) {
        set_error(error, error_len, "cannot construct route snapshot");
        return -1;
    }

    final_key = snapshot->route_snapshot_key;
    memset(final_key.snapshot_digest, 0, sizeof(final_key.snapshot_digest));
    if (route_snapshot_key_encode_allow_zero(&final_key, key_value, key_bytes,
                                             &actual_bytes, error,
                                             error_len) != 0 ||
        actual_bytes != key_bytes ||
        required_ack_set_encode_variant(
            &snapshot->required_ack_set, &final_key, ack_value, ack_bytes,
            &actual_bytes, ack_digest, error, error_len) != 0 ||
        actual_bytes != ack_bytes ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0 ||
        route_snapshot_hash_with_normalized_self_refs(
            bytes, *encoded_bytes, &final_key, calculated_digest) != 0) {
        set_error(error, error_len, "cannot finalize route snapshot");
        return -1;
    }
    if (!bytes_are_zero(snapshot->route_snapshot_key.snapshot_digest,
                        sizeof(snapshot->route_snapshot_key.snapshot_digest)) &&
        memcmp(snapshot->route_snapshot_key.snapshot_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len, "route snapshot self-digest mismatches");
        return -1;
    }

    memcpy(final_key.snapshot_digest, calculated_digest, sizeof(calculated_digest));
    if (route_snapshot_key_encode_allow_zero(&final_key, key_value, key_bytes,
                                             &actual_bytes, error,
                                             error_len) != 0 ||
        actual_bytes != key_bytes ||
        required_ack_set_encode_variant(
            &snapshot->required_ack_set, &final_key, ack_value, ack_bytes,
            &actual_bytes, ack_digest, error, error_len) != 0 ||
        actual_bytes != ack_bytes ||
        route_snapshot_hash_with_normalized_self_refs(
            bytes, *encoded_bytes, &final_key, calculated_digest) != 0 ||
        memcmp(final_key.snapshot_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len, "route snapshot finalization is unstable");
        return -1;
    }
    if (snapshot_digest) {
        memcpy(snapshot_digest, calculated_digest, sizeof(calculated_digest));
    }
    return 0;
}

int wvm_route_snapshot_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_route_snapshot_record *snapshot, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[9];
    unsigned char present[9];
    struct wvm_route_rule_record_list rules;
    struct wvm_required_ack_set ack_set;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];

    if (!snapshot ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_ROUTE_SNAPSHOT,
                            fields, present, 8, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || !present[7] || !present[8] ||
        fields[2].value_bytes != 8 || fields[3].value_bytes != 2 ||
        fields[7].value_bytes != 8 || fields[8].value_bytes != 2) {
        set_error(error, error_len, "route snapshot has invalid fields");
        return -1;
    }
    rules = snapshot->next_hop_rules;
    ack_set = snapshot->required_ack_set;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->next_hop_rules = rules;
    snapshot->required_ack_set = ack_set;
    if (wvm_route_snapshot_key_decode(
            fields[1].value, fields[1].value_bytes,
            &snapshot->route_snapshot_key, error, error_len) != 0 ||
        record_list_decode(fields[4].value, fields[4].value_bytes,
                           snapshot->next_hop_rules.entries,
                           snapshot->next_hop_rules.capacity,
                           sizeof(*snapshot->next_hop_rules.entries),
                           &snapshot->next_hop_rules.count, route_rule_decode,
                           error, error_len) != 0 ||
        required_ack_set_decode_variant(
            fields[5].value, fields[5].value_bytes,
            &snapshot->required_ack_set, &snapshot->route_snapshot_key, error,
            error_len) != 0 ||
        (present[6] &&
         wvm_route_snapshot_key_decode(
             fields[6].value, fields[6].value_bytes,
             &snapshot->predecessor_snapshot_key, error, error_len) != 0)) {
        set_error(error, error_len, "route snapshot nested record is invalid");
        return -1;
    }
    snapshot->membership_revision = read_be64(fields[2].value);
    snapshot->topology_kind = read_be16(fields[3].value);
    snapshot->has_predecessor_snapshot_key = present[6];
    snapshot->operation_retention_horizon_ms = read_be64(fields[7].value);
    snapshot->retirement_policy = read_be16(fields[8].value);
    if (wvm_route_snapshot_record_validate(snapshot, error, error_len) != 0 ||
        route_snapshot_hash_with_normalized_self_refs(
            bytes, encoded_bytes, &snapshot->route_snapshot_key,
            calculated_digest) != 0 ||
        memcmp(snapshot->route_snapshot_key.snapshot_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len, "route snapshot self-digest is invalid");
        return -1;
    }
    return 0;
}

static int capability_ref_size(size_t *encoded_size)
{
    static const size_t fields[] = {4, 8, 8, WVM_SHA256_DIGEST_BYTES};

    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int capability_ref_encode_adapter(const void *value, uint8_t *bytes,
                                         size_t capacity,
                                         size_t *encoded_bytes, char *error,
                                         size_t error_len)
{
    return wvm_capability_ref_encode(value, bytes, capacity, encoded_bytes,
                                     error, error_len);
}

static int valid_membership_state(enum wvm_manifest_member_state state)
{
    return state >= WVM_MANIFEST_MEMBER_PENDING &&
           state <= WVM_MANIFEST_MEMBER_FAILED;
}

static int valid_health_state(uint16_t state)
{
    return state >= 1 && state <= 4;
}

static int valid_route_transaction_state(uint16_t state)
{
    return state >= 1 && state <= 5;
}

static int u32_list_validate(const uint32_t *entries, size_t count,
                             size_t capacity, char *error, size_t error_len)
{
    size_t i;

    if ((count != 0 && !entries) || count > capacity || count > UINT32_MAX) {
        set_error(error, error_len, "U32 list is invalid");
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (entries[i] == 0 || (i != 0 && entries[i - 1] >= entries[i])) {
            set_error(error, error_len, "U32 list is not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int u32_list_size(const uint32_t *entries, size_t count,
                         size_t capacity, size_t *encoded_size)
{
    size_t total;

    if (u32_list_validate(entries, count, capacity, NULL, 0) != 0 ||
        count > (SIZE_MAX - 4U) / 8U) {
        return -1;
    }
    total = 4U + count * 8U;
    *encoded_size = total;
    return 0;
}

static int u32_list_encode(const uint32_t *entries, size_t count,
                           size_t capacity, uint8_t *bytes,
                           size_t encoded_bytes, char *error,
                           size_t error_len)
{
    size_t expected_bytes;
    size_t i;
    size_t offset = 4;

    if (u32_list_size(entries, count, capacity, &expected_bytes) != 0 ||
        expected_bytes != encoded_bytes) {
        set_error(error, error_len, "U32 list has invalid size");
        return -1;
    }
    write_be32(bytes, (uint32_t)count);
    for (i = 0; i < count; i++) {
        write_be32(bytes + offset, 4);
        write_be32(bytes + offset + 4, entries[i]);
        offset += 8;
    }
    return 0;
}

static int u32_list_decode(const uint8_t *bytes, size_t encoded_bytes,
                           uint32_t *entries, size_t capacity, size_t *count,
                           char *error, size_t error_len)
{
    uint32_t decoded_count;
    uint32_t i;
    size_t offset = 4;

    if (!bytes || !count || encoded_bytes < 4) {
        set_error(error, error_len, "U32 list is malformed");
        return -1;
    }
    decoded_count = read_be32(bytes);
    if (decoded_count > capacity || (decoded_count != 0 && !entries)) {
        set_error(error, error_len, "U32 list exceeds capacity");
        return -1;
    }
    for (i = 0; i < decoded_count; i++) {
        if (encoded_bytes - offset < 8 || read_be32(bytes + offset) != 4) {
            set_error(error, error_len, "U32 list has malformed entry");
            return -1;
        }
        entries[i] = read_be32(bytes + offset + 4);
        offset += 8;
    }
    if (offset != encoded_bytes) {
        set_error(error, error_len, "U32 list has trailing bytes");
        return -1;
    }
    *count = decoded_count;
    return u32_list_validate(entries, decoded_count, capacity, error, error_len);
}

int wvm_node_inventory_record_validate(
    const struct wvm_node_inventory_record *inventory, char *error,
    size_t error_len)
{
    uint64_t allocated_memory;
    uint32_t allocated_vcpus;

    if (!inventory || inventory->physical_node_id == 0 ||
        inventory->node_instance_id == 0 || inventory->failure_domain_id == 0 ||
        inventory->inventory_revision == 0 ||
        inventory->registered_vcpu_slots == 0 ||
        inventory->registered_memory_bytes == 0 ||
        inventory->registered_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        inventory->reserved_host_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        inventory->reserved_gateway_memory_bytes % WVM_MANIFEST_PAGE_BYTES !=
            0 ||
        inventory->reserved_host_cpu_slots >
            inventory->registered_vcpu_slots ||
        inventory->reserved_gateway_cpu_slots >
            inventory->registered_vcpu_slots -
                inventory->reserved_host_cpu_slots ||
        inventory->reserved_host_memory_bytes >
            inventory->registered_memory_bytes ||
        inventory->reserved_gateway_memory_bytes >
            inventory->registered_memory_bytes -
                inventory->reserved_host_memory_bytes ||
        u32_list_validate(inventory->hosted_gateway_role_ids,
                          inventory->hosted_gateway_role_id_count,
                          inventory->hosted_gateway_role_id_capacity, error,
                          error_len) != 0 ||
        bytes_are_zero(inventory->storage_capabilities_digest,
                       sizeof(inventory->storage_capabilities_digest)) ||
        bytes_are_zero(inventory->accelerator_fault_capabilities_digest,
                       sizeof(inventory->accelerator_fault_capabilities_digest)) ||
        bytes_are_zero(inventory->exclusive_resource_inventory_digest,
                       sizeof(inventory->exclusive_resource_inventory_digest))) {
        set_error(error, error_len, "node inventory is invalid");
        return -1;
    }
    allocated_vcpus = inventory->registered_vcpu_slots -
                      inventory->reserved_host_cpu_slots -
                      inventory->reserved_gateway_cpu_slots;
    allocated_memory = inventory->registered_memory_bytes -
                       inventory->reserved_host_memory_bytes -
                       inventory->reserved_gateway_memory_bytes;
    if (inventory->allocatable_vcpu_slots != allocated_vcpus ||
        inventory->allocatable_memory_bytes != allocated_memory) {
        set_error(error, error_len,
                  "node inventory allocatable capacity does not match reserves");
        return -1;
    }
    return 0;
}

static int node_inventory_size(const struct wvm_node_inventory_record *inventory,
                               size_t *encoded_size)
{
    size_t fields[16];

    if (wvm_node_inventory_record_validate(inventory, NULL, 0) != 0 ||
        u32_list_size(inventory->hosted_gateway_role_ids,
                      inventory->hosted_gateway_role_id_count,
                      inventory->hosted_gateway_role_id_capacity, &fields[10]) !=
            0) {
        return -1;
    }
    fields[0] = 4;
    fields[1] = 8;
    fields[2] = 8;
    fields[3] = 8;
    fields[4] = 4;
    fields[5] = 8;
    fields[6] = 4;
    fields[7] = 8;
    fields[8] = 4;
    fields[9] = 8;
    fields[11] = 4;
    fields[12] = 8;
    fields[13] = WVM_SHA256_DIGEST_BYTES;
    fields[14] = WVM_SHA256_DIGEST_BYTES;
    fields[15] = WVM_SHA256_DIGEST_BYTES;
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

int wvm_node_inventory_record_encode(
    const struct wvm_node_inventory_record *inventory, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *hosted_gateway_ids;
    size_t hosted_gateway_id_bytes;

    if (wvm_node_inventory_record_validate(inventory, error, error_len) != 0 ||
        u32_list_size(inventory->hosted_gateway_role_ids,
                      inventory->hosted_gateway_role_id_count,
                      inventory->hosted_gateway_role_id_capacity,
                      &hosted_gateway_id_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_NODE_INVENTORY) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1,
                                       inventory->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       inventory->node_instance_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       inventory->failure_domain_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       inventory->inventory_revision) != 0 ||
        wvm_canonical_field_append_u32(&builder, 5,
                                       inventory->registered_vcpu_slots) != 0 ||
        wvm_canonical_field_append_u64(&builder, 6,
                                       inventory->registered_memory_bytes) !=
            0 ||
        wvm_canonical_field_append_u32(&builder, 7,
                                       inventory->reserved_host_cpu_slots) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 8,
                                       inventory->reserved_host_memory_bytes) !=
            0 ||
        wvm_canonical_field_append_u32(
            &builder, 9, inventory->reserved_gateway_cpu_slots) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 10, inventory->reserved_gateway_memory_bytes) != 0 ||
        wvm_canonical_field_reserve(&builder, 11,
                                    (uint32_t)hosted_gateway_id_bytes,
                                    &hosted_gateway_ids) != 0 ||
        u32_list_encode(inventory->hosted_gateway_role_ids,
                        inventory->hosted_gateway_role_id_count,
                        inventory->hosted_gateway_role_id_capacity,
                        hosted_gateway_ids, hosted_gateway_id_bytes, error,
                        error_len) != 0 ||
        wvm_canonical_field_append_u32(&builder, 12,
                                       inventory->allocatable_vcpu_slots) != 0 ||
        wvm_canonical_field_append_u64(&builder, 13,
                                       inventory->allocatable_memory_bytes) !=
            0 ||
        wvm_canonical_field_append(
            &builder, 14, inventory->storage_capabilities_digest,
            sizeof(inventory->storage_capabilities_digest)) != 0 ||
        wvm_canonical_field_append(
            &builder, 15, inventory->accelerator_fault_capabilities_digest,
            sizeof(inventory->accelerator_fault_capabilities_digest)) != 0 ||
        wvm_canonical_field_append(
            &builder, 16, inventory->exclusive_resource_inventory_digest,
            sizeof(inventory->exclusive_resource_inventory_digest)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode node inventory");
        return -1;
    }
    return 0;
}

int wvm_node_inventory_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_node_inventory_record *inventory, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[17];
    unsigned char present[17];
    uint32_t *hosted_gateway_ids;
    size_t hosted_gateway_id_capacity;

    if (!inventory ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_NODE_INVENTORY,
                            fields, present, 16, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || !present[6] || !present[7] || !present[8] ||
        !present[9] || !present[10] || !present[11] || !present[12] ||
        !present[13] || !present[14] || !present[15] || !present[16] ||
        fields[1].value_bytes != 4 || fields[2].value_bytes != 8 ||
        fields[3].value_bytes != 8 || fields[4].value_bytes != 8 ||
        fields[5].value_bytes != 4 || fields[6].value_bytes != 8 ||
        fields[7].value_bytes != 4 || fields[8].value_bytes != 8 ||
        fields[9].value_bytes != 4 || fields[10].value_bytes != 8 ||
        fields[12].value_bytes != 4 || fields[13].value_bytes != 8 ||
        fields[14].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[15].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[16].value_bytes != WVM_SHA256_DIGEST_BYTES) {
        set_error(error, error_len, "node inventory has invalid fields");
        return -1;
    }
    hosted_gateway_ids = inventory->hosted_gateway_role_ids;
    hosted_gateway_id_capacity = inventory->hosted_gateway_role_id_capacity;
    memset(inventory, 0, sizeof(*inventory));
    inventory->hosted_gateway_role_ids = hosted_gateway_ids;
    inventory->hosted_gateway_role_id_capacity = hosted_gateway_id_capacity;
    inventory->physical_node_id = read_be32(fields[1].value);
    inventory->node_instance_id = read_be64(fields[2].value);
    inventory->failure_domain_id = read_be64(fields[3].value);
    inventory->inventory_revision = read_be64(fields[4].value);
    inventory->registered_vcpu_slots = read_be32(fields[5].value);
    inventory->registered_memory_bytes = read_be64(fields[6].value);
    inventory->reserved_host_cpu_slots = read_be32(fields[7].value);
    inventory->reserved_host_memory_bytes = read_be64(fields[8].value);
    inventory->reserved_gateway_cpu_slots = read_be32(fields[9].value);
    inventory->reserved_gateway_memory_bytes = read_be64(fields[10].value);
    inventory->allocatable_vcpu_slots = read_be32(fields[12].value);
    inventory->allocatable_memory_bytes = read_be64(fields[13].value);
    memcpy(inventory->storage_capabilities_digest, fields[14].value,
           sizeof(inventory->storage_capabilities_digest));
    memcpy(inventory->accelerator_fault_capabilities_digest, fields[15].value,
           sizeof(inventory->accelerator_fault_capabilities_digest));
    memcpy(inventory->exclusive_resource_inventory_digest, fields[16].value,
           sizeof(inventory->exclusive_resource_inventory_digest));
    if (u32_list_decode(fields[11].value, fields[11].value_bytes,
                        inventory->hosted_gateway_role_ids,
                        inventory->hosted_gateway_role_id_capacity,
                        &inventory->hosted_gateway_role_id_count, error,
                        error_len) != 0) {
        return -1;
    }
    return wvm_node_inventory_record_validate(inventory, error, error_len);
}

static int node_inventory_encode_adapter(const void *value, uint8_t *bytes,
                                         size_t capacity,
                                         size_t *encoded_bytes, char *error,
                                         size_t error_len)
{
    return wvm_node_inventory_record_encode(value, bytes, capacity,
                                            encoded_bytes, error, error_len);
}

int wvm_node_record_validate(const struct wvm_node_record *node, char *error,
                             size_t error_len)
{
    if (!node || node->physical_node_id == 0 || node->node_instance_id == 0 ||
        node->failure_domain_id == 0 ||
        wvm_endpoint_validate(&node->control_endpoint, error, error_len) != 0 ||
        wvm_endpoint_validate(&node->sidecar_endpoint, error, error_len) != 0 ||
        node->role_bits == 0 || node->local_vnode_count == 0 ||
        node->local_vnode_first >
            UINT32_MAX - (node->local_vnode_count - 1U) ||
        wvm_node_inventory_record_validate(&node->inventory, error,
                                           error_len) != 0 ||
        node->inventory.physical_node_id != node->physical_node_id ||
        node->inventory.node_instance_id != node->node_instance_id ||
        node->inventory.failure_domain_id != node->failure_domain_id ||
        wvm_capability_ref_validate(&node->capability, error, error_len) != 0 ||
        node->capability.physical_node_id != node->physical_node_id ||
        node->capability.node_instance_id != node->node_instance_id ||
        !valid_membership_state(node->desired_membership_state) ||
        !valid_health_state(node->observed_health_state) ||
        node->membership_revision == 0 || node->topology_revision == 0) {
        set_error(error, error_len, "node record is invalid");
        return -1;
    }
    return 0;
}

int wvm_node_record_encode(const struct wvm_node_record *node, uint8_t *bytes,
                           size_t capacity, size_t *encoded_bytes, char *error,
                           size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t control_endpoint_bytes;
    size_t sidecar_endpoint_bytes;
    size_t inventory_bytes;
    size_t capability_bytes;

    if (wvm_node_record_validate(node, error, error_len) != 0 ||
        endpoint_size(&node->control_endpoint, &control_endpoint_bytes) != 0 ||
        endpoint_size(&node->sidecar_endpoint, &sidecar_endpoint_bytes) != 0 ||
        node_inventory_size(&node->inventory, &inventory_bytes) != 0 ||
        capability_ref_size(&capability_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_NODE_RECORD) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1, node->physical_node_id) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 2, node->node_instance_id) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 3, node->failure_domain_id) !=
            0 ||
        append_nested_record(&builder, 4, control_endpoint_bytes,
                             endpoint_encode_adapter, &node->control_endpoint,
                             error, error_len) != 0 ||
        append_nested_record(&builder, 5, sidecar_endpoint_bytes,
                             endpoint_encode_adapter, &node->sidecar_endpoint,
                             error, error_len) != 0 ||
        wvm_canonical_field_append_u64(&builder, 6, node->role_bits) != 0 ||
        wvm_canonical_field_append_u64(&builder, 7, node->pod_id) != 0 ||
        wvm_canonical_field_append_u32(&builder, 8, node->local_vnode_first) !=
            0 ||
        wvm_canonical_field_append_u32(&builder, 9, node->local_vnode_count) !=
            0 ||
        append_nested_record(&builder, 10, inventory_bytes,
                             node_inventory_encode_adapter, &node->inventory,
                             error, error_len) != 0 ||
        append_nested_record(&builder, 11, capability_bytes,
                             capability_ref_encode_adapter, &node->capability,
                             error, error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 12,
                                       node->desired_membership_state) != 0 ||
        wvm_canonical_field_append_u16(&builder, 13,
                                       node->observed_health_state) != 0 ||
        wvm_canonical_field_append_u64(&builder, 14,
                                       node->membership_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 15,
                                       node->topology_revision) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode node record");
        return -1;
    }
    return 0;
}

int wvm_node_record_decode(const uint8_t *bytes, size_t encoded_bytes,
                           struct wvm_node_record *node, char *error,
                           size_t error_len)
{
    struct wvm_canonical_field fields[16];
    unsigned char present[16];
    struct wvm_node_inventory_record inventory;

    if (!node ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_NODE_RECORD,
                            fields, present, 15, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || !present[6] || !present[7] || !present[8] ||
        !present[9] || !present[10] || !present[11] || !present[12] ||
        !present[13] || !present[14] || !present[15] ||
        fields[1].value_bytes != 4 || fields[2].value_bytes != 8 ||
        fields[3].value_bytes != 8 || fields[6].value_bytes != 8 ||
        fields[7].value_bytes != 8 || fields[8].value_bytes != 4 ||
        fields[9].value_bytes != 4 || fields[12].value_bytes != 2 ||
        fields[13].value_bytes != 2 || fields[14].value_bytes != 8 ||
        fields[15].value_bytes != 8) {
        set_error(error, error_len, "node record has invalid fields");
        return -1;
    }
    inventory = node->inventory;
    memset(node, 0, sizeof(*node));
    node->inventory = inventory;
    node->physical_node_id = read_be32(fields[1].value);
    node->node_instance_id = read_be64(fields[2].value);
    node->failure_domain_id = read_be64(fields[3].value);
    node->role_bits = read_be64(fields[6].value);
    node->pod_id = read_be64(fields[7].value);
    node->local_vnode_first = read_be32(fields[8].value);
    node->local_vnode_count = read_be32(fields[9].value);
    node->desired_membership_state =
        (enum wvm_manifest_member_state)read_be16(fields[12].value);
    node->observed_health_state = read_be16(fields[13].value);
    node->membership_revision = read_be64(fields[14].value);
    node->topology_revision = read_be64(fields[15].value);
    if (wvm_endpoint_decode(fields[4].value, fields[4].value_bytes,
                            &node->control_endpoint, error, error_len) != 0 ||
        wvm_endpoint_decode(fields[5].value, fields[5].value_bytes,
                            &node->sidecar_endpoint, error, error_len) != 0 ||
        wvm_node_inventory_record_decode(fields[10].value,
                                         fields[10].value_bytes,
                                         &node->inventory, error, error_len) !=
            0 ||
        wvm_capability_ref_decode(fields[11].value, fields[11].value_bytes,
                                  &node->capability, error, error_len) != 0) {
        return -1;
    }
    return wvm_node_record_validate(node, error, error_len);
}

static int u32_lists_disjoint(const uint32_t *left, size_t left_count,
                              const uint32_t *right, size_t right_count)
{
    size_t left_index = 0;
    size_t right_index = 0;

    while (left_index < left_count && right_index < right_count) {
        if (left[left_index] == right[right_index]) {
            return 0;
        }
        if (left[left_index] < right[right_index]) {
            left_index++;
        } else {
            right_index++;
        }
    }
    return 1;
}

int wvm_gateway_record_validate(const struct wvm_gateway_record *gateway,
                                char *error, size_t error_len)
{
    if (!gateway || gateway->gateway_id == 0 ||
        gateway->gateway_instance_id == 0 ||
        gateway->hosting_physical_node_id == 0 ||
        gateway->failure_domain_id == 0 ||
        wvm_endpoint_validate(&gateway->endpoint, error, error_len) != 0 ||
        gateway->role_bits == 0 ||
        u32_list_validate(gateway->parent_gateway_ids,
                          gateway->parent_gateway_id_count,
                          gateway->parent_gateway_id_capacity, error,
                          error_len) != 0 ||
        u32_list_validate(gateway->child_gateway_ids,
                          gateway->child_gateway_id_count,
                          gateway->child_gateway_id_capacity, error,
                          error_len) != 0 ||
        !u32_lists_disjoint(gateway->parent_gateway_ids,
                            gateway->parent_gateway_id_count,
                            gateway->child_gateway_ids,
                            gateway->child_gateway_id_count) ||
        !valid_membership_state(gateway->desired_membership_state) ||
        !valid_health_state(gateway->observed_health_state) ||
        gateway->membership_revision == 0 || gateway->topology_revision == 0) {
        set_error(error, error_len, "gateway record is invalid");
        return -1;
    }
    return 0;
}

int wvm_gateway_record_encode(const struct wvm_gateway_record *gateway,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t endpoint_bytes;
    size_t parent_bytes;
    size_t child_bytes;
    uint8_t *parent_value;
    uint8_t *child_value;

    if (wvm_gateway_record_validate(gateway, error, error_len) != 0 ||
        endpoint_size(&gateway->endpoint, &endpoint_bytes) != 0 ||
        u32_list_size(gateway->parent_gateway_ids,
                      gateway->parent_gateway_id_count,
                      gateway->parent_gateway_id_capacity, &parent_bytes) != 0 ||
        u32_list_size(gateway->child_gateway_ids,
                      gateway->child_gateway_id_count,
                      gateway->child_gateway_id_capacity, &child_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_GATEWAY_RECORD) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1, gateway->gateway_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       gateway->gateway_instance_id) != 0 ||
        wvm_canonical_field_append_u32(&builder, 3,
                                       gateway->hosting_physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       gateway->failure_domain_id) != 0 ||
        append_nested_record(&builder, 5, endpoint_bytes, endpoint_encode_adapter,
                             &gateway->endpoint, error, error_len) != 0 ||
        wvm_canonical_field_append_u64(&builder, 6, gateway->role_bits) != 0 ||
        wvm_canonical_field_append_u64(&builder, 7,
                                       gateway->pod_id_or_scope) != 0 ||
        wvm_canonical_field_reserve(&builder, 8, (uint32_t)parent_bytes,
                                    &parent_value) != 0 ||
        u32_list_encode(gateway->parent_gateway_ids,
                        gateway->parent_gateway_id_count,
                        gateway->parent_gateway_id_capacity, parent_value,
                        parent_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 9, (uint32_t)child_bytes,
                                    &child_value) != 0 ||
        u32_list_encode(gateway->child_gateway_ids,
                        gateway->child_gateway_id_count,
                        gateway->child_gateway_id_capacity, child_value,
                        child_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 10,
                                       gateway->desired_membership_state) != 0 ||
        wvm_canonical_field_append_u16(&builder, 11,
                                       gateway->observed_health_state) != 0 ||
        wvm_canonical_field_append_u64(&builder, 12,
                                       gateway->membership_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 13,
                                       gateway->topology_revision) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode gateway record");
        return -1;
    }
    return 0;
}

int wvm_gateway_record_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_gateway_record *gateway, char *error,
                              size_t error_len)
{
    struct wvm_canonical_field fields[14];
    unsigned char present[14];
    uint32_t *parents;
    size_t parent_capacity;
    uint32_t *children;
    size_t child_capacity;

    if (!gateway ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_GATEWAY_RECORD,
                            fields, present, 13, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || !present[6] || !present[7] || !present[8] ||
        !present[9] || !present[10] || !present[11] || !present[12] ||
        !present[13] || fields[1].value_bytes != 4 ||
        fields[2].value_bytes != 8 || fields[3].value_bytes != 4 ||
        fields[4].value_bytes != 8 || fields[6].value_bytes != 8 ||
        fields[7].value_bytes != 8 || fields[10].value_bytes != 2 ||
        fields[11].value_bytes != 2 || fields[12].value_bytes != 8 ||
        fields[13].value_bytes != 8) {
        set_error(error, error_len, "gateway record has invalid fields");
        return -1;
    }
    parents = gateway->parent_gateway_ids;
    parent_capacity = gateway->parent_gateway_id_capacity;
    children = gateway->child_gateway_ids;
    child_capacity = gateway->child_gateway_id_capacity;
    memset(gateway, 0, sizeof(*gateway));
    gateway->parent_gateway_ids = parents;
    gateway->parent_gateway_id_capacity = parent_capacity;
    gateway->child_gateway_ids = children;
    gateway->child_gateway_id_capacity = child_capacity;
    gateway->gateway_id = read_be32(fields[1].value);
    gateway->gateway_instance_id = read_be64(fields[2].value);
    gateway->hosting_physical_node_id = read_be32(fields[3].value);
    gateway->failure_domain_id = read_be64(fields[4].value);
    gateway->role_bits = read_be64(fields[6].value);
    gateway->pod_id_or_scope = read_be64(fields[7].value);
    gateway->desired_membership_state =
        (enum wvm_manifest_member_state)read_be16(fields[10].value);
    gateway->observed_health_state = read_be16(fields[11].value);
    gateway->membership_revision = read_be64(fields[12].value);
    gateway->topology_revision = read_be64(fields[13].value);
    if (wvm_endpoint_decode(fields[5].value, fields[5].value_bytes,
                            &gateway->endpoint, error, error_len) != 0 ||
        u32_list_decode(fields[8].value, fields[8].value_bytes,
                        gateway->parent_gateway_ids,
                        gateway->parent_gateway_id_capacity,
                        &gateway->parent_gateway_id_count, error,
                        error_len) != 0 ||
        u32_list_decode(fields[9].value, fields[9].value_bytes,
                        gateway->child_gateway_ids,
                        gateway->child_gateway_id_capacity,
                        &gateway->child_gateway_id_count, error,
                        error_len) != 0) {
        return -1;
    }
    return wvm_gateway_record_validate(gateway, error, error_len);
}

static int required_member_size(const struct wvm_required_member *member,
                                size_t *encoded_size)
{
    size_t fields[5];

    if (wvm_required_member_validate(member, NULL, 0) != 0 ||
        member_key_size(&fields[0]) != 0 ||
        capability_ref_size(&fields[3]) != 0) {
        return -1;
    }
    fields[1] = 4;
    fields[2] = 8;
    fields[4] = 2;
    return canonical_record_size(fields, sizeof(fields) / sizeof(fields[0]),
                                 encoded_size);
}

static int required_member_encode_adapter(const void *value, uint8_t *bytes,
                                          size_t capacity,
                                          size_t *encoded_bytes, char *error,
                                          size_t error_len)
{
    return wvm_required_member_encode(value, bytes, capacity, encoded_bytes,
                                      error, error_len);
}

static int required_member_decode_adapter(const uint8_t *bytes,
                                          size_t encoded_bytes, void *value,
                                          char *error, size_t error_len)
{
    return wvm_required_member_decode(bytes, encoded_bytes, value, error,
                                      error_len);
}

static int required_member_size_adapter(const void *value,
                                        size_t *encoded_size)
{
    return required_member_size(value, encoded_size);
}

static int required_member_list_validate(
    const struct wvm_required_member_list *members, char *error,
    size_t error_len)
{
    size_t i;

    if (!members || !members->entries || members->count == 0 ||
        members->count > members->capacity || members->count > UINT32_MAX) {
        set_error(error, error_len, "selected member list is invalid");
        return -1;
    }
    for (i = 0; i < members->count; i++) {
        const struct wvm_required_member *member = &members->entries[i];

        if (wvm_required_member_validate(member, error, error_len) != 0 ||
            member->required_state != WVM_MANIFEST_MEMBER_ACTIVE ||
            (i != 0 &&
             member_key_compare(&members->entries[i - 1].member_key,
                                &member->member_key) >= 0)) {
            set_error(error, error_len,
                      "selected members are not a strict ACTIVE set");
            return -1;
        }
    }
    return 0;
}

static int required_member_list_size(
    const struct wvm_required_member_list *members, size_t *encoded_size)
{
    if (required_member_list_validate(members, NULL, 0) != 0) {
        return -1;
    }
    return record_list_size(members->entries, members->count,
                            sizeof(*members->entries),
                            required_member_size_adapter, encoded_size);
}

static int admission_fence_shape_validate(
    const struct wvm_admission_eligibility_fence *fence, int allow_zero_digest,
    char *error, size_t error_len)
{
    if (!fence ||
        bytes_are_zero(fence->admission_tx_id, sizeof(fence->admission_tx_id)) ||
        fence->membership_revision == 0 || fence->topology_revision == 0 ||
        fence->admission_eligibility_revision == 0 ||
        fence->inventory_revision == 0 ||
        fence->capability_profile_generation == 0 ||
        required_member_list_validate(&fence->selected_members, error,
                                      error_len) != 0 ||
        wvm_vm_route_scope_key_validate(&fence->required_route_scope_key, error,
                                        error_len) != 0 ||
        bytes_are_zero(fence->required_ack_set_digest,
                       sizeof(fence->required_ack_set_digest)) ||
        (!allow_zero_digest &&
         bytes_are_zero(fence->fence_digest, sizeof(fence->fence_digest)))) {
        set_error(error, error_len, "admission eligibility fence is invalid");
        return -1;
    }
    return 0;
}

int wvm_admission_eligibility_fence_validate(
    const struct wvm_admission_eligibility_fence *fence, char *error,
    size_t error_len)
{
    return admission_fence_shape_validate(fence, 0, error, error_len);
}

int wvm_admission_eligibility_fence_encode(
    const struct wvm_admission_eligibility_fence *fence, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes,
    uint8_t fence_digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t member_list_bytes;
    size_t scope_key_bytes;
    uint8_t *member_list_value;
    uint8_t *scope_key_value;
    uint8_t *fence_digest_value;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t zero_digest[WVM_SHA256_DIGEST_BYTES] = {0};

    if (admission_fence_shape_validate(fence, 1, error, error_len) != 0 ||
        required_member_list_size(&fence->selected_members,
                                  &member_list_bytes) != 0 ||
        route_scope_key_size(&scope_key_bytes) != 0 ||
        wvm_canonical_record_begin(
            &builder, bytes, capacity, WVM_RECORD_ADMISSION_ELIGIBILITY_FENCE) !=
            0 ||
        wvm_canonical_field_append(&builder, 1, fence->admission_tx_id,
                                   sizeof(fence->admission_tx_id)) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       fence->membership_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       fence->topology_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       fence->inventory_revision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 5,
                                       fence->capability_profile_generation) !=
            0 ||
        wvm_canonical_field_reserve(&builder, 6, (uint32_t)member_list_bytes,
                                    &member_list_value) != 0 ||
        record_list_encode(fence->selected_members.entries,
                           fence->selected_members.count,
                           sizeof(*fence->selected_members.entries),
                           required_member_size_adapter,
                           required_member_encode_adapter, member_list_value,
                           member_list_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 7, (uint32_t)scope_key_bytes,
                                    &scope_key_value) != 0 ||
        wvm_vm_route_scope_key_encode(&fence->required_route_scope_key,
                                      scope_key_value, scope_key_bytes,
                                      &scope_key_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append(&builder, 8, fence->required_ack_set_digest,
                                   sizeof(fence->required_ack_set_digest)) != 0 ||
        wvm_canonical_field_reserve(&builder, 9, sizeof(zero_digest),
                                    &fence_digest_value) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 10, fence->admission_eligibility_revision) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0 ||
        wvm_canonical_record_digest(bytes, *encoded_bytes, 9, calculated_digest) !=
            0) {
        set_error(error, error_len, "cannot encode admission eligibility fence");
        return -1;
    }
    if (!bytes_are_zero(fence->fence_digest, sizeof(fence->fence_digest)) &&
        memcmp(fence->fence_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len, "admission eligibility fence digest mismatches");
        return -1;
    }
    memcpy(fence_digest_value, calculated_digest, sizeof(calculated_digest));
    if (fence_digest) {
        memcpy(fence_digest, calculated_digest, sizeof(calculated_digest));
    }
    return 0;
}

int wvm_admission_eligibility_fence_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_admission_eligibility_fence *fence, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[11];
    unsigned char present[11];
    struct wvm_required_member_list members;
    uint8_t calculated_digest[WVM_SHA256_DIGEST_BYTES];

    if (!fence ||
        parse_record_fields(bytes, encoded_bytes,
                            WVM_RECORD_ADMISSION_ELIGIBILITY_FENCE, fields,
                            present, 10, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || !present[6] || !present[7] || !present[8] ||
        !present[9] || !present[10] ||
        fields[1].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[2].value_bytes != 8 || fields[3].value_bytes != 8 ||
        fields[4].value_bytes != 8 || fields[5].value_bytes != 8 ||
        fields[8].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[9].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[10].value_bytes != 8) {
        set_error(error, error_len, "admission eligibility fence has invalid fields");
        return -1;
    }
    members = fence->selected_members;
    memset(fence, 0, sizeof(*fence));
    fence->selected_members = members;
    memcpy(fence->admission_tx_id, fields[1].value, sizeof(fence->admission_tx_id));
    fence->membership_revision = read_be64(fields[2].value);
    fence->topology_revision = read_be64(fields[3].value);
    fence->inventory_revision = read_be64(fields[4].value);
    fence->capability_profile_generation = read_be64(fields[5].value);
    fence->admission_eligibility_revision = read_be64(fields[10].value);
    memcpy(fence->required_ack_set_digest, fields[8].value,
           sizeof(fence->required_ack_set_digest));
    memcpy(fence->fence_digest, fields[9].value, sizeof(fence->fence_digest));
    if (record_list_decode(fields[6].value, fields[6].value_bytes,
                           fence->selected_members.entries,
                           fence->selected_members.capacity,
                           sizeof(*fence->selected_members.entries),
                           &fence->selected_members.count,
                           required_member_decode_adapter, error,
                           error_len) != 0 ||
        wvm_vm_route_scope_key_decode(
            fields[7].value, fields[7].value_bytes,
            &fence->required_route_scope_key, error, error_len) != 0 ||
        admission_fence_shape_validate(fence, 0, error, error_len) != 0 ||
        wvm_canonical_record_digest(bytes, encoded_bytes, 9, calculated_digest) !=
            0 ||
        memcmp(fence->fence_digest, calculated_digest,
               sizeof(calculated_digest)) != 0) {
        set_error(error, error_len, "admission eligibility fence digest is invalid");
        return -1;
    }
    return 0;
}

static int route_snapshot_key_full_equal(
    const struct wvm_route_snapshot_key *left,
    const struct wvm_route_snapshot_key *right)
{
    return route_scope_identity_equal(left, right) &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int required_ack_entry_encode_standard_adapter(
    const void *value, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return required_ack_entry_encode_variant(value, NULL, bytes, capacity,
                                             encoded_bytes, error, error_len);
}

static int route_transaction_ack_entries_validate(
    const struct wvm_required_ack_entry_list *entries,
    const struct wvm_route_snapshot_key *expected_key, int require_nonempty,
    char *error, size_t error_len)
{
    size_t i;

    if (required_ack_entry_list_validate(entries, require_nonempty, 0, NULL,
                                         error, error_len) != 0) {
        return -1;
    }
    for (i = 0; i < entries->count; i++) {
        if (!route_snapshot_key_full_equal(
                &entries->entries[i].expected_snapshot_key, expected_key)) {
            set_error(error, error_len,
                      "route transaction ACK entry has the wrong snapshot key");
            return -1;
        }
    }
    return 0;
}

int wvm_route_transaction_record_validate(
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len)
{
    if (!transaction ||
        bytes_are_zero(transaction->operation_id,
                       sizeof(transaction->operation_id)) ||
        wvm_route_snapshot_key_validate(&transaction->route_snapshot_key, error,
                                        error_len) != 0 ||
        wvm_required_ack_set_validate(&transaction->required_ack_set, error,
                                      error_len) != 0 ||
        route_transaction_ack_entries_validate(
            &transaction->required_ack_set.entries,
            &transaction->route_snapshot_key, 1, error, error_len) != 0 ||
        (transaction->has_predecessor_snapshot_key != 0 &&
         transaction->has_predecessor_snapshot_key != 1) ||
        (transaction->has_predecessor_snapshot_key &&
         (wvm_route_snapshot_key_validate(
              &transaction->predecessor_snapshot_key, error, error_len) != 0 ||
          transaction->predecessor_snapshot_key.scope_key.vm_id !=
              transaction->route_snapshot_key.scope_key.vm_id ||
          transaction->predecessor_snapshot_key.scope_key.vm_incarnation !=
              transaction->route_snapshot_key.scope_key.vm_incarnation ||
          transaction->predecessor_snapshot_key.scope_key.route_scope_id !=
              transaction->route_snapshot_key.scope_key.route_scope_id)) ||
        route_transaction_ack_entries_validate(
            &transaction->optional_departure_drain_set,
            transaction->has_predecessor_snapshot_key
                ? &transaction->predecessor_snapshot_key
                : &transaction->route_snapshot_key,
            0, error, error_len) != 0 ||
        (!transaction->has_predecessor_snapshot_key &&
         transaction->optional_departure_drain_set.count != 0) ||
        transaction->operation_retention_horizon_ms == 0 ||
        !valid_route_transaction_state(transaction->state)) {
        set_error(error, error_len, "route transaction record is invalid");
        return -1;
    }
    return 0;
}

static int route_snapshot_endpoint_equal(const struct wvm_endpoint *left,
                                         const struct wvm_endpoint *right)
{
    if (!left || !right || left->data_transport != right->data_transport ||
        left->data_address_bytes != right->data_address_bytes ||
        left->data_port != right->data_port ||
        left->control_transport != right->control_transport ||
        left->has_control_address != right->has_control_address ||
        left->control_port != right->control_port ||
        left->has_server_name != right->has_server_name ||
        left->has_control_socket_path != right->has_control_socket_path ||
        memcmp(left->data_address, right->data_address,
               left->data_address_bytes) != 0) {
        return 0;
    }
    if (left->has_control_address &&
        (left->control_address_bytes != right->control_address_bytes ||
         memcmp(left->control_address, right->control_address,
                left->control_address_bytes) != 0)) {
        return 0;
    }
    return (!left->has_server_name ||
            strcmp(left->server_name, right->server_name) == 0) &&
           (!left->has_control_socket_path ||
            strcmp(left->control_socket_path,
                   right->control_socket_path) == 0);
}

static int route_snapshot_ack_sets_equal(
    const struct wvm_required_ack_set *left,
    const struct wvm_required_ack_set *right)
{
    size_t i;

    if (!left || !right || left->entries.count != right->entries.count) {
        return 0;
    }
    for (i = 0; i < left->entries.count; i++) {
        const struct wvm_required_ack_entry *left_entry =
            &left->entries.entries[i];
        const struct wvm_required_ack_entry *right_entry =
            &right->entries.entries[i];

        if (left_entry->member_key.role_type != right_entry->member_key.role_type ||
            left_entry->member_key.role_id != right_entry->member_key.role_id ||
            left_entry->member_key.instance_id !=
                right_entry->member_key.instance_id ||
            !route_snapshot_endpoint_equal(&left_entry->endpoint,
                                           &right_entry->endpoint) ||
            left_entry->role_type != right_entry->role_type ||
            !route_snapshot_key_full_equal(&left_entry->expected_snapshot_key,
                                           &right_entry->expected_snapshot_key)) {
            return 0;
        }
    }
    return 1;
}

int wvm_route_snapshot_record_binds_transaction(
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len)
{
    if (wvm_route_snapshot_record_validate(snapshot, error, error_len) != 0 ||
        wvm_route_transaction_record_validate(transaction, error, error_len) !=
            0) {
        return -1;
    }
    if (!route_snapshot_key_full_equal(&snapshot->route_snapshot_key,
                                       &transaction->route_snapshot_key) ||
        snapshot->has_predecessor_snapshot_key !=
            transaction->has_predecessor_snapshot_key ||
        (snapshot->has_predecessor_snapshot_key &&
         !route_snapshot_key_full_equal(&snapshot->predecessor_snapshot_key,
                                        &transaction->predecessor_snapshot_key)) ||
        snapshot->operation_retention_horizon_ms !=
            transaction->operation_retention_horizon_ms ||
        !route_snapshot_ack_sets_equal(&snapshot->required_ack_set,
                                       &transaction->required_ack_set)) {
        set_error(error, error_len,
                  "route snapshot does not bind the route transaction");
        return -1;
    }
    return 0;
}

int wvm_route_transaction_record_encode(
    const struct wvm_route_transaction_record *transaction, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t route_key_bytes;
    size_t predecessor_key_bytes;
    size_t ack_set_bytes;
    size_t optional_drain_bytes;
    uint8_t *optional_drain_value;

    if (wvm_route_transaction_record_validate(transaction, error, error_len) !=
            0 ||
        route_snapshot_key_size(&route_key_bytes) != 0 ||
        (transaction->has_predecessor_snapshot_key &&
         route_snapshot_key_size(&predecessor_key_bytes) != 0) ||
        required_ack_set_size(&transaction->required_ack_set, NULL,
                              &ack_set_bytes) != 0 ||
        record_list_size(transaction->optional_departure_drain_set.entries,
                         transaction->optional_departure_drain_set.count,
                         sizeof(*transaction->optional_departure_drain_set.entries),
                         required_ack_entry_size_adapter,
                         &optional_drain_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ROUTE_TRANSACTION) != 0 ||
        wvm_canonical_field_append(&builder, 1, transaction->operation_id,
                                   sizeof(transaction->operation_id)) != 0 ||
        append_nested_record(&builder, 2, route_key_bytes,
                             route_snapshot_key_encode_adapter,
                             &transaction->route_snapshot_key, error,
                             error_len) != 0 ||
        (transaction->has_predecessor_snapshot_key &&
         append_nested_record(&builder, 3, predecessor_key_bytes,
                              route_snapshot_key_encode_adapter,
                              &transaction->predecessor_snapshot_key, error,
                              error_len) != 0) ||
        append_nested_record(&builder, 4, ack_set_bytes,
                             (record_encode_fn)wvm_required_ack_set_encode,
                             &transaction->required_ack_set, error,
                             error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 5,
                                    (uint32_t)optional_drain_bytes,
                                    &optional_drain_value) != 0 ||
        record_list_encode(transaction->optional_departure_drain_set.entries,
                           transaction->optional_departure_drain_set.count,
                           sizeof(*transaction->optional_departure_drain_set.entries),
                           required_ack_entry_size_adapter,
                           required_ack_entry_encode_standard_adapter,
                           optional_drain_value, optional_drain_bytes, error,
                           error_len) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 6, transaction->operation_retention_horizon_ms) != 0 ||
        wvm_canonical_field_append_u16(&builder, 7, transaction->state) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode route transaction record");
        return -1;
    }
    return 0;
}

int wvm_route_transaction_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[8];
    unsigned char present[8];
    struct wvm_required_ack_set ack_set;
    struct wvm_required_ack_entry_list optional_drain_set;

    if (!transaction ||
        parse_record_fields(bytes, encoded_bytes, WVM_RECORD_ROUTE_TRANSACTION,
                            fields, present, 7, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[4] || !present[5] ||
        !present[6] || !present[7] ||
        fields[1].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[6].value_bytes != 8 || fields[7].value_bytes != 2) {
        set_error(error, error_len, "route transaction record has invalid fields");
        return -1;
    }
    ack_set = transaction->required_ack_set;
    optional_drain_set = transaction->optional_departure_drain_set;
    memset(transaction, 0, sizeof(*transaction));
    transaction->required_ack_set = ack_set;
    transaction->optional_departure_drain_set = optional_drain_set;
    memcpy(transaction->operation_id, fields[1].value,
           sizeof(transaction->operation_id));
    transaction->has_predecessor_snapshot_key = present[3];
    transaction->operation_retention_horizon_ms = read_be64(fields[6].value);
    transaction->state = read_be16(fields[7].value);
    if (wvm_route_snapshot_key_decode(
            fields[2].value, fields[2].value_bytes,
            &transaction->route_snapshot_key, error, error_len) != 0 ||
        (transaction->has_predecessor_snapshot_key &&
         wvm_route_snapshot_key_decode(
             fields[3].value, fields[3].value_bytes,
             &transaction->predecessor_snapshot_key, error, error_len) != 0) ||
        wvm_required_ack_set_decode(fields[4].value, fields[4].value_bytes,
                                    &transaction->required_ack_set, error,
                                    error_len) != 0 ||
        record_list_decode(
            fields[5].value, fields[5].value_bytes,
            transaction->optional_departure_drain_set.entries,
            transaction->optional_departure_drain_set.capacity,
            sizeof(*transaction->optional_departure_drain_set.entries),
            &transaction->optional_departure_drain_set.count,
            required_ack_entry_decode, error, error_len) != 0) {
        return -1;
    }
    return wvm_route_transaction_record_validate(transaction, error, error_len);
}

static int route_snapshot_record_size(
    const struct wvm_route_snapshot_record *snapshot, size_t *encoded_size)
{
    size_t fields[8];
    size_t field_count = 0;

    if (wvm_route_snapshot_record_validate(snapshot, NULL, 0) != 0 ||
        route_snapshot_key_size(&fields[field_count++]) != 0) {
        return -1;
    }
    fields[field_count++] = 8;
    fields[field_count++] = 2;
    if (route_rule_list_size(&snapshot->next_hop_rules,
                             &fields[field_count++]) != 0 ||
        required_ack_set_size(&snapshot->required_ack_set,
                              &snapshot->route_snapshot_key,
                              &fields[field_count++]) != 0) {
        return -1;
    }
    if (snapshot->has_predecessor_snapshot_key &&
        route_snapshot_key_size(&fields[field_count++]) != 0) {
        return -1;
    }
    fields[field_count++] = 8;
    fields[field_count++] = 2;
    return canonical_record_size(fields, field_count, encoded_size);
}

static int route_transaction_record_size(
    const struct wvm_route_transaction_record *transaction,
    size_t *encoded_size)
{
    size_t fields[7];
    size_t field_count = 0;

    if (wvm_route_transaction_record_validate(transaction, NULL, 0) != 0) {
        return -1;
    }
    fields[field_count++] = WVM_IDENTITY_ID_BYTES;
    if (route_snapshot_key_size(&fields[field_count++]) != 0) {
        return -1;
    }
    if (transaction->has_predecessor_snapshot_key &&
        route_snapshot_key_size(&fields[field_count++]) != 0) {
        return -1;
    }
    if (required_ack_set_size(&transaction->required_ack_set, NULL,
                              &fields[field_count++]) != 0 ||
        record_list_size(
            transaction->optional_departure_drain_set.entries,
            transaction->optional_departure_drain_set.count,
            sizeof(*transaction->optional_departure_drain_set.entries),
            required_ack_entry_size_adapter,
            &fields[field_count++]) != 0) {
        return -1;
    }
    fields[field_count++] = 8;
    fields[field_count++] = 2;
    return canonical_record_size(fields, field_count, encoded_size);
}

static int route_snapshot_record_encode_adapter(
    const void *value, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    return wvm_route_snapshot_record_encode(value, bytes, capacity,
                                            encoded_bytes, digest, error,
                                            error_len);
}

static int route_transaction_record_encode_adapter(
    const void *value, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_route_transaction_record_encode(value, bytes, capacity,
                                               encoded_bytes, error, error_len);
}

static int valid_gateway_drain_action(enum wvm_gateway_drain_action action)
{
    return action == WVM_GATEWAY_DRAIN_ACTION_PREPARE ||
           action == WVM_GATEWAY_DRAIN_ACTION_COMMIT ||
           action == WVM_GATEWAY_DRAIN_ACTION_ABORT;
}

int wvm_gateway_drain_request_validate(
    const struct wvm_gateway_drain_request *request, char *error,
    size_t error_len)
{
    if (!request || !valid_gateway_drain_action(request->action) ||
        request->target_gateway_member_key.role_type !=
            WVM_MANIFEST_ROLE_GATEWAY ||
        wvm_member_key_validate(&request->target_gateway_member_key, error,
                                error_len) != 0 ||
        request->expected_membership_revision == 0 ||
        request->expected_topology_revision == 0 ||
        request->expected_admission_eligibility_revision == 0 ||
        bytes_are_zero(request->route_operation_id,
                       sizeof(request->route_operation_id))) {
        set_error(error, error_len, "gateway drain request is invalid");
        return -1;
    }
    if (request->action != WVM_GATEWAY_DRAIN_ACTION_PREPARE) {
        return 0;
    }
    if (wvm_route_transaction_record_validate(&request->successor_transaction,
                                              error, error_len) != 0 ||
        wvm_route_snapshot_record_validate(&request->successor_snapshot, error,
                                           error_len) != 0 ||
        memcmp(request->route_operation_id,
               request->successor_transaction.operation_id,
               sizeof(request->route_operation_id)) != 0 ||
        !route_snapshot_key_full_equal(
            &request->successor_transaction.route_snapshot_key,
            &request->successor_snapshot.route_snapshot_key) ||
        request->successor_snapshot.membership_revision !=
            request->expected_membership_revision) {
        set_error(error, error_len,
                  "gateway drain prepare successor does not match its fence");
        return -1;
    }
    return 0;
}

int wvm_gateway_drain_request_encode(
    const struct wvm_gateway_drain_request *request, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t member_key_bytes;
    size_t transaction_bytes = 0;
    size_t snapshot_bytes = 0;

    if (!bytes || !encoded_bytes ||
        wvm_gateway_drain_request_validate(request, error, error_len) != 0 ||
        member_key_size(&member_key_bytes) != 0 ||
        (request->action == WVM_GATEWAY_DRAIN_ACTION_PREPARE &&
         (route_transaction_record_size(&request->successor_transaction,
                                        &transaction_bytes) != 0 ||
          route_snapshot_record_size(&request->successor_snapshot,
                                     &snapshot_bytes) != 0)) ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_GATEWAY_DRAIN_REQUEST) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1, request->action) != 0 ||
        append_nested_record(&builder, 2, member_key_bytes,
                             member_key_encode_adapter,
                             &request->target_gateway_member_key, error,
                             error_len) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 3, request->expected_membership_revision) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 4, request->expected_topology_revision) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 5, request->expected_admission_eligibility_revision) !=
            0 ||
        (request->action == WVM_GATEWAY_DRAIN_ACTION_PREPARE &&
         (append_nested_record(&builder, 6, transaction_bytes,
                               route_transaction_record_encode_adapter,
                               &request->successor_transaction, error,
                               error_len) != 0 ||
          append_nested_record(&builder, 7, snapshot_bytes,
                               route_snapshot_record_encode_adapter,
                               &request->successor_snapshot, error,
                               error_len) != 0)) ||
        wvm_canonical_field_append(&builder, 8, request->route_operation_id,
                                   sizeof(request->route_operation_id)) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode gateway drain request");
        return -1;
    }
    return 0;
}

int wvm_gateway_drain_request_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_gateway_drain_request *request, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[9];
    unsigned char present[9];
    struct wvm_route_transaction_record transaction;
    struct wvm_route_snapshot_record snapshot;

    if (!request ||
        parse_record_fields(bytes, encoded_bytes,
                            WVM_RECORD_GATEWAY_DRAIN_REQUEST, fields, present,
                            8, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || !present[8] || fields[1].value_bytes != 2 ||
        fields[3].value_bytes != 8 || fields[4].value_bytes != 8 ||
        fields[5].value_bytes != 8 ||
        fields[8].value_bytes != WVM_IDENTITY_ID_BYTES) {
        set_error(error, error_len, "gateway drain request has invalid fields");
        return -1;
    }
    transaction = request->successor_transaction;
    snapshot = request->successor_snapshot;
    memset(request, 0, sizeof(*request));
    request->successor_transaction = transaction;
    request->successor_snapshot = snapshot;
    request->action = (enum wvm_gateway_drain_action)read_be16(fields[1].value);
    request->expected_membership_revision = read_be64(fields[3].value);
    request->expected_topology_revision = read_be64(fields[4].value);
    request->expected_admission_eligibility_revision = read_be64(fields[5].value);
    memcpy(request->route_operation_id, fields[8].value,
           sizeof(request->route_operation_id));
    if (wvm_member_key_decode(fields[2].value, fields[2].value_bytes,
                              &request->target_gateway_member_key, error,
                              error_len) != 0 ||
        ((request->action == WVM_GATEWAY_DRAIN_ACTION_PREPARE &&
          (!present[6] || !present[7] ||
           wvm_route_transaction_record_decode(
               fields[6].value, fields[6].value_bytes,
               &request->successor_transaction, error, error_len) != 0 ||
           wvm_route_snapshot_record_decode(
               fields[7].value, fields[7].value_bytes,
               &request->successor_snapshot, error, error_len) != 0)) ||
         (request->action != WVM_GATEWAY_DRAIN_ACTION_PREPARE &&
          (present[6] || present[7]))) ||
        wvm_gateway_drain_request_validate(request, error, error_len) != 0) {
        set_error(error, error_len, "gateway drain request is malformed");
        return -1;
    }
    return 0;
}

static int valid_member_cordon_role(enum wvm_manifest_role_type role_type)
{
    return role_type == WVM_MANIFEST_ROLE_NODE_RUNTIME ||
           role_type == WVM_MANIFEST_ROLE_GATEWAY;
}

int wvm_member_cordon_request_validate(
    const struct wvm_member_cordon_request *request, char *error,
    size_t error_len)
{
    if (!request || !valid_member_cordon_role(request->target_member_key.role_type) ||
        wvm_member_key_validate(&request->target_member_key, error,
                                error_len) != 0 ||
        request->expected_membership_revision == 0 ||
        request->expected_topology_revision == 0 ||
        request->expected_admission_eligibility_revision == 0 ||
        request->reason_code == 0) {
        set_error(error, error_len, "member cordon request is invalid");
        return -1;
    }
    return 0;
}

int wvm_member_cordon_request_encode(
    const struct wvm_member_cordon_request *request, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    size_t member_key_bytes;

    if (!bytes || !encoded_bytes ||
        wvm_member_cordon_request_validate(request, error, error_len) != 0 ||
        member_key_size(&member_key_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_MEMBER_CORDON_REQUEST) != 0 ||
        append_nested_record(&builder, 1, member_key_bytes,
                             member_key_encode_adapter,
                             &request->target_member_key, error,
                             error_len) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 2, request->expected_membership_revision) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 3, request->expected_topology_revision) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 4, request->expected_admission_eligibility_revision) !=
            0 ||
        wvm_canonical_field_append_u16(&builder, 5, request->reason_code) !=
            0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode member cordon request");
        return -1;
    }
    return 0;
}

int wvm_member_cordon_request_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_member_cordon_request *request, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[6];
    unsigned char present[6];

    if (!request ||
        parse_record_fields(bytes, encoded_bytes,
                            WVM_RECORD_MEMBER_CORDON_REQUEST, fields, present,
                            5, error, error_len) != 0 ||
        !present[1] || !present[2] || !present[3] || !present[4] ||
        !present[5] || fields[2].value_bytes != 8 ||
        fields[3].value_bytes != 8 || fields[4].value_bytes != 8 ||
        fields[5].value_bytes != 2 ||
        wvm_member_key_decode(fields[1].value, fields[1].value_bytes,
                              &request->target_member_key, error,
                              error_len) != 0) {
        set_error(error, error_len, "member cordon request has invalid fields");
        return -1;
    }
    request->expected_membership_revision = read_be64(fields[2].value);
    request->expected_topology_revision = read_be64(fields[3].value);
    request->expected_admission_eligibility_revision =
        read_be64(fields[4].value);
    request->reason_code = read_be16(fields[5].value);
    if (wvm_member_cordon_request_validate(request, error, error_len) != 0) {
        set_error(error, error_len, "member cordon request is malformed");
        return -1;
    }
    return 0;
}

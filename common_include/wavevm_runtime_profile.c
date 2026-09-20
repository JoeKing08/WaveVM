#include "wavevm_runtime_profile.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_canonical.h"

static void set_error(char *error, size_t error_len, const char *format, ...)
{
    va_list arguments;

    if (!error || error_len == 0) {
        return;
    }
    va_start(arguments, format);
    vsnprintf(error, error_len, format, arguments);
    va_end(arguments);
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
    return ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8) | bytes[7];
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

static int parse_fields(const uint8_t *bytes, size_t byte_count,
                        struct wvm_canonical_field fields[12])
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0, count = 0;
    int next;

    if (wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_NODE_RUNTIME_PROFILE) {
        return -1;
    }
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (count >= 12 || field.tag != count + 1U) {
            return -1;
        }
        fields[count] = field;
        count++;
        if (count == 12 && offset != record.body_bytes) {
            return -1;
        }
    }
    return next == 0 && count == 12 ? 0 : -1;
}

static int port_in_pool(uint16_t port, const uint16_t *ports, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (ports[i] == port) {
            return 1;
        }
    }
    return 0;
}

static int port_pool_validate(const uint16_t *ports, size_t count)
{
    size_t i;

    if (!ports || count == 0 || count > (UINT32_MAX - 4U) / 2U) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (ports[i] == 0 || (i != 0 && ports[i - 1] >= ports[i])) {
            return -1;
        }
    }
    return 0;
}

int wvm_node_runtime_profile_validate(
    const struct wvm_node_runtime_profile *profile, char *error,
    size_t error_len)
{
    size_t i;

    if (!profile || profile->physical_node_id == 0 ||
        profile->node_instance_id == 0 || profile->inventory_revision == 0 ||
        profile->capability_profile_generation == 0 ||
        profile->runtime_profile_generation == 0 ||
        profile->node_runtime_control_port == 0 ||
        profile->local_executor_control_port == 0 ||
        profile->node_runtime_control_port ==
            profile->local_executor_control_port ||
        profile->executor_worker_count == 0 || profile->sync_batch_size == 0 ||
        profile->vcpu_handoff_record_capacity == 0 ||
        port_pool_validate(profile->node_runtime_data_ports,
                           profile->node_runtime_data_port_count) != 0 ||
        port_pool_validate(profile->local_executor_service_ports,
                           profile->local_executor_service_port_count) != 0 ||
        port_in_pool(profile->node_runtime_control_port,
                     profile->node_runtime_data_ports,
                     profile->node_runtime_data_port_count) ||
        port_in_pool(profile->local_executor_control_port,
                     profile->node_runtime_data_ports,
                     profile->node_runtime_data_port_count) ||
        port_in_pool(profile->node_runtime_control_port,
                     profile->local_executor_service_ports,
                     profile->local_executor_service_port_count) ||
        port_in_pool(profile->local_executor_control_port,
                     profile->local_executor_service_ports,
                     profile->local_executor_service_port_count)) {
        set_error(error, error_len, "node runtime profile is invalid");
        return -1;
    }
    for (i = 0; i < profile->node_runtime_data_port_count; i++) {
        if (port_in_pool(profile->node_runtime_data_ports[i],
                         profile->local_executor_service_ports,
                         profile->local_executor_service_port_count)) {
            set_error(error, error_len,
                      "node runtime profile reuses a listener port");
            return -1;
        }
    }
    return 0;
}

static int append_port_pool(struct wvm_canonical_builder *builder,
                            uint16_t tag, const uint16_t *ports, size_t count)
{
    uint8_t *value;
    size_t i, byte_count = 4U + count * 2U;

    if (byte_count > UINT32_MAX ||
        wvm_canonical_field_reserve(builder, tag, (uint32_t)byte_count,
                                    &value) != 0) {
        return -1;
    }
    write_be32(value, (uint32_t)count);
    for (i = 0; i < count; i++) {
        write_be16(value + 4U + i * 2U, ports[i]);
    }
    return 0;
}

int wvm_node_runtime_profile_encode(
    const struct wvm_node_runtime_profile *profile, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;

    if (!bytes || !encoded_bytes ||
        wvm_node_runtime_profile_validate(profile, error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_NODE_RUNTIME_PROFILE) != 0 ||
        wvm_canonical_field_append_u32(&builder, 1,
                                       profile->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 2,
                                       profile->node_instance_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       profile->inventory_revision) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 4, profile->capability_profile_generation) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 5, profile->runtime_profile_generation) != 0 ||
        wvm_canonical_field_append_u16(
            &builder, 6, profile->node_runtime_control_port) != 0 ||
        wvm_canonical_field_append_u16(
            &builder, 7, profile->local_executor_control_port) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 8, profile->executor_worker_count) != 0 ||
        wvm_canonical_field_append_u32(&builder, 9,
                                       profile->sync_batch_size) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 10, profile->vcpu_handoff_record_capacity) != 0 ||
        append_port_pool(&builder, 11, profile->node_runtime_data_ports,
                         profile->node_runtime_data_port_count) != 0 ||
        append_port_pool(&builder, 12,
                         profile->local_executor_service_ports,
                         profile->local_executor_service_port_count) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode node runtime profile");
        return -1;
    }
    if (*encoded_bytes > WVM_NODE_RUNTIME_PROFILE_MAX_BYTES) {
        set_error(error, error_len, "node runtime profile is oversized");
        return -1;
    }
    return 0;
}

static int decode_port_pool(const struct wvm_canonical_field *field,
                            uint16_t **ports, size_t *count)
{
    uint32_t encoded_count;
    size_t i;

    if (!field || field->value_bytes < 6U) {
        return -1;
    }
    encoded_count = read_be32(field->value);
    if (encoded_count == 0 ||
        field->value_bytes != 4U + (size_t)encoded_count * 2U) {
        return -1;
    }
    *ports = calloc(encoded_count, sizeof(**ports));
    if (!*ports) {
        return -1;
    }
    *count = encoded_count;
    for (i = 0; i < encoded_count; i++) {
        (*ports)[i] = read_be16(field->value + 4U + i * 2U);
    }
    return 0;
}

int wvm_node_runtime_profile_decode(
    const uint8_t *bytes, size_t byte_count,
    struct wvm_node_runtime_profile *profile, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[12];
    struct wvm_node_runtime_profile decoded = {0};

    if (!profile || byte_count > WVM_NODE_RUNTIME_PROFILE_MAX_BYTES ||
        parse_fields(bytes, byte_count, fields) != 0 ||
        fields[0].value_bytes != 4 || fields[1].value_bytes != 8 ||
        fields[2].value_bytes != 8 || fields[3].value_bytes != 8 ||
        fields[4].value_bytes != 8 || fields[5].value_bytes != 2 ||
        fields[6].value_bytes != 2 || fields[7].value_bytes != 4 ||
        fields[8].value_bytes != 4 || fields[9].value_bytes != 4) {
        set_error(error, error_len, "node runtime profile record is malformed");
        return -1;
    }
    decoded.physical_node_id = read_be32(fields[0].value);
    decoded.node_instance_id = read_be64(fields[1].value);
    decoded.inventory_revision = read_be64(fields[2].value);
    decoded.capability_profile_generation = read_be64(fields[3].value);
    decoded.runtime_profile_generation = read_be64(fields[4].value);
    decoded.node_runtime_control_port = read_be16(fields[5].value);
    decoded.local_executor_control_port = read_be16(fields[6].value);
    decoded.executor_worker_count = read_be32(fields[7].value);
    decoded.sync_batch_size = read_be32(fields[8].value);
    decoded.vcpu_handoff_record_capacity = read_be32(fields[9].value);
    if (decode_port_pool(&fields[10], &decoded.node_runtime_data_ports,
                         &decoded.node_runtime_data_port_count) != 0 ||
        decode_port_pool(&fields[11], &decoded.local_executor_service_ports,
                         &decoded.local_executor_service_port_count) != 0 ||
        wvm_node_runtime_profile_validate(&decoded, error, error_len) != 0) {
        wvm_node_runtime_profile_destroy(&decoded);
        if (error && error_len && error[0] == '\0') {
            set_error(error, error_len, "node runtime profile is invalid");
        }
        return -1;
    }
    wvm_node_runtime_profile_destroy(profile);
    *profile = decoded;
    return 0;
}

void wvm_node_runtime_profile_destroy(struct wvm_node_runtime_profile *profile)
{
    if (!profile) {
        return;
    }
    free(profile->node_runtime_data_ports);
    free(profile->local_executor_service_ports);
    memset(profile, 0, sizeof(*profile));
}

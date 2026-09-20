#include "wavevm_envelope.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fragment_prefix {
    uint32_t logical_payload_bytes;
    uint16_t fragment_index;
    uint16_t fragment_count;
    uint32_t fragment_offset;
    const uint8_t *data;
    size_t data_bytes;
};

struct fragment_piece {
    uint32_t offset;
    uint16_t bytes;
    uint8_t received;
};

struct reassembly_entry {
    int in_use;
    uint64_t expiry_ms;
    struct wvm_envelope envelope;
    uint32_t logical_payload_bytes;
    uint16_t fragment_count;
    uint16_t received_count;
    size_t received_bytes;
    uint8_t *payload;
    struct fragment_piece *pieces;
};

static uint32_t crc32c_table[256];
static pthread_once_t crc32c_once = PTHREAD_ONCE_INIT;

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

static int all_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
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

static void crc32c_init(void)
{
    uint32_t index;

    for (index = 0; index < 256U; index++) {
        uint32_t value = index;
        unsigned int bit;

        for (bit = 0; bit < 8U; bit++) {
            value = (value & 1U) ? (value >> 1) ^ 0x82f63b78U
                                 : value >> 1;
        }
        crc32c_table[index] = value;
    }
}

static uint32_t crc32c_update(uint32_t crc, const uint8_t *bytes,
                              size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        crc = (crc >> 8) ^ crc32c_table[(crc ^ bytes[i]) & 0xffU];
    }
    return crc;
}

uint32_t wvm_envelope_crc32c(const uint8_t *bytes, size_t byte_count)
{
    uint32_t crc = 0xffffffffU;

    if (byte_count != 0 && !bytes) {
        return 0;
    }
    pthread_once(&crc32c_once, crc32c_init);
    crc = crc32c_update(crc, bytes, byte_count);
    return crc ^ 0xffffffffU;
}

static uint32_t crc32c_header_payload(const uint8_t *header,
                                      const uint8_t *payload,
                                      size_t payload_bytes)
{
    uint32_t crc = 0xffffffffU;

    pthread_once(&crc32c_once, crc32c_init);
    crc = crc32c_update(crc, header, WVM_ENVELOPE_HEADER_BYTES - 4U);
    crc = crc32c_update(crc, payload, payload_bytes);
    return crc ^ 0xffffffffU;
}

void wvm_envelope_semantic_digest(
    const uint8_t *payload, size_t payload_bytes,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES])
{
    static const uint8_t empty_payload = 0;

    if (!digest) {
        return;
    }
    if (payload_bytes != 0 && !payload) {
        memset(digest, 0, WVM_SHA256_DIGEST_BYTES);
        return;
    }
    wvm_sha256_digest(payload_bytes == 0 ? &empty_payload : payload,
                      payload_bytes, digest);
}

static int message_type_known(uint16_t message_type)
{
    switch (message_type) {
    case WVM_ENVELOPE_MSG_MEM_READ:
    case WVM_ENVELOPE_MSG_MEM_WRITE:
    case WVM_ENVELOPE_MSG_MEM_ACK:
    case WVM_ENVELOPE_MSG_VCPU_RUN:
    case WVM_ENVELOPE_MSG_VCPU_EXIT:
    case WVM_ENVELOPE_MSG_VFIO_IRQ:
    case WVM_ENVELOPE_MSG_INVALIDATE:
    case WVM_ENVELOPE_MSG_DOWNGRADE:
    case WVM_ENVELOPE_MSG_FETCH_AND_INVALIDATE:
    case WVM_ENVELOPE_MSG_WRITE_BACK:
    case WVM_ENVELOPE_MSG_DECLARE_INTEREST:
    case WVM_ENVELOPE_MSG_PAGE_PUSH_FULL:
    case WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF:
    case WVM_ENVELOPE_MSG_COMMIT_DIFF:
    case WVM_ENVELOPE_MSG_FORCE_SYNC:
    case WVM_ENVELOPE_MSG_MEM_COMMIT_ACK:
    case WVM_ENVELOPE_MSG_BLOCK_READ:
    case WVM_ENVELOPE_MSG_BLOCK_WRITE:
    case WVM_ENVELOPE_MSG_BLOCK_ACK:
    case WVM_ENVELOPE_MSG_BLOCK_FLUSH:
    case WVM_ENVELOPE_MSG_CTRL_RESULT:
    case WVM_ENVELOPE_MSG_REGISTER_MEMBER:
    case WVM_ENVELOPE_MSG_CORDON:
    case WVM_ENVELOPE_MSG_DRAIN:
    case WVM_ENVELOPE_MSG_PREPARE_RESERVATION:
    case WVM_ENVELOPE_MSG_COMMIT_RESERVATION:
    case WVM_ENVELOPE_MSG_ABORT_RESERVATION:
    case WVM_ENVELOPE_MSG_PREPARE_MANIFEST:
    case WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST:
    case WVM_ENVELOPE_MSG_ABORT_MANIFEST:
    case WVM_ENVELOPE_MSG_QUERY_TX:
    case WVM_ENVELOPE_MSG_ROUTE_PREPARE:
    case WVM_ENVELOPE_MSG_ROUTE_COMMIT:
    case WVM_ENVELOPE_MSG_ROUTE_RETIRE:
    case WVM_ENVELOPE_MSG_ROUTE_ABORT:
    case WVM_ENVELOPE_MSG_REJOIN:
    case WVM_ENVELOPE_MSG_RECOVERY_REBIND:
    case WVM_ENVELOPE_MSG_CREATE_VM:
    case WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES:
    case WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE:
        return 1;
    default:
        return 0;
    }
}

static int cluster_control_message(uint16_t message_type)
{
    switch (message_type) {
    case WVM_ENVELOPE_MSG_CTRL_RESULT:
    case WVM_ENVELOPE_MSG_REGISTER_MEMBER:
    case WVM_ENVELOPE_MSG_CORDON:
    case WVM_ENVELOPE_MSG_DRAIN:
    case WVM_ENVELOPE_MSG_REJOIN:
    case WVM_ENVELOPE_MSG_RECOVERY_REBIND:
    case WVM_ENVELOPE_MSG_CREATE_VM:
    case WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES:
    case WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE:
        return 1;
    default:
        return 0;
    }
}

static int routed_data_message(uint16_t message_type)
{
    switch (message_type) {
    case WVM_ENVELOPE_MSG_MEM_READ:
    case WVM_ENVELOPE_MSG_MEM_WRITE:
    case WVM_ENVELOPE_MSG_MEM_ACK:
    case WVM_ENVELOPE_MSG_VCPU_RUN:
    case WVM_ENVELOPE_MSG_VCPU_EXIT:
    case WVM_ENVELOPE_MSG_VFIO_IRQ:
    case WVM_ENVELOPE_MSG_INVALIDATE:
    case WVM_ENVELOPE_MSG_DOWNGRADE:
    case WVM_ENVELOPE_MSG_FETCH_AND_INVALIDATE:
    case WVM_ENVELOPE_MSG_WRITE_BACK:
    case WVM_ENVELOPE_MSG_DECLARE_INTEREST:
    case WVM_ENVELOPE_MSG_PAGE_PUSH_FULL:
    case WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF:
    case WVM_ENVELOPE_MSG_COMMIT_DIFF:
    case WVM_ENVELOPE_MSG_FORCE_SYNC:
    case WVM_ENVELOPE_MSG_MEM_COMMIT_ACK:
    case WVM_ENVELOPE_MSG_BLOCK_READ:
    case WVM_ENVELOPE_MSG_BLOCK_WRITE:
    case WVM_ENVELOPE_MSG_BLOCK_ACK:
    case WVM_ENVELOPE_MSG_BLOCK_FLUSH:
        return 1;
    default:
        return 0;
    }
}

static int route_prefix_required(const struct wvm_envelope *envelope)
{
    return envelope && routed_data_message(envelope->message_type);
}

static int route_fields_valid(const struct wvm_envelope *envelope,
                              char *error, size_t error_len)
{
    const struct wvm_envelope_route *route;

    if (!route_prefix_required(envelope)) {
        return 0;
    }
    route = &envelope->route;
    if (route->destination_vnode_or_endpoint ==
            WVM_ENVELOPE_ROUTE_DESTINATION_UNSPECIFIED ||
        route->hop_limit == 0 || route->hop_count > route->hop_limit) {
        set_error(error, error_len, "route destination or hop budget is invalid");
        return -1;
    }
    switch (route->destination_kind) {
    case WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE:
        if (route->destination_scope != 0) {
            set_error(error, error_len,
                      "flat route destination must not carry a scope");
            return -1;
        }
        return 0;
    case WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE:
        if (route->destination_scope == 0) {
            set_error(error, error_len,
                      "fractal route destination lacks a scope");
            return -1;
        }
        return 0;
    default:
        set_error(error, error_len, "route destination kind is unknown");
        return -1;
    }
}

static size_t route_prefix_bytes(const struct wvm_envelope *envelope)
{
    return route_prefix_required(envelope) ? WVM_ENVELOPE_ROUTE_PREFIX_BYTES
                                           : 0U;
}

static int parse_fragment_prefix(const struct wvm_envelope *envelope,
                                 struct fragment_prefix *prefix, char *error,
                                 size_t error_len)
{
    size_t i;

    if (!envelope || !prefix ||
        envelope->payload_bytes < WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES) {
        set_error(error, error_len, "fragment prefix is truncated");
        return -1;
    }
    prefix->logical_payload_bytes = read_be32(envelope->payload + 0);
    prefix->fragment_index = read_be16(envelope->payload + 4);
    prefix->fragment_count = read_be16(envelope->payload + 6);
    prefix->fragment_offset = read_be32(envelope->payload + 8);
    prefix->data = envelope->payload + WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES;
    prefix->data_bytes =
        envelope->payload_bytes - WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES;
    for (i = 12; i < WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES; i++) {
        if (envelope->payload[i] != 0) {
            set_error(error, error_len, "fragment prefix reserved bytes set");
            return -1;
        }
    }
    if (prefix->logical_payload_bytes == 0 ||
        prefix->logical_payload_bytes >
            WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD ||
        prefix->fragment_count == 0 ||
        prefix->fragment_count > WVM_ENVELOPE_MAX_FRAGMENTS ||
        prefix->fragment_index >= prefix->fragment_count ||
        prefix->data_bytes == 0 ||
        prefix->data_bytes > WVM_ENVELOPE_MAX_FRAGMENT_DATA_BYTES ||
        prefix->fragment_offset >= prefix->logical_payload_bytes ||
        prefix->data_bytes >
            prefix->logical_payload_bytes - prefix->fragment_offset) {
        set_error(error, error_len, "fragment bounds are invalid");
        return -1;
    }
    return 0;
}

static int transport_payload_valid(const struct wvm_envelope *envelope,
                                   enum wvm_envelope_transport transport,
                                   char *error, size_t error_len)
{
    size_t frame_payload_bytes;
    size_t max_frame_payload;

    if (!envelope ||
        envelope->payload_bytes > SIZE_MAX - route_prefix_bytes(envelope)) {
        set_error(error, error_len, "envelope payload size is invalid");
        return -1;
    }
    frame_payload_bytes =
        route_prefix_bytes(envelope) + envelope->payload_bytes;
    if (transport == WVM_ENVELOPE_TRANSPORT_LOCAL) {
        if (frame_payload_bytes > WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
            set_error(error, error_len, "local envelope payload exceeds limit");
            return -1;
        }
        return 0;
    }
    if (transport != WVM_ENVELOPE_TRANSPORT_NETWORK) {
        set_error(error, error_len, "unknown envelope transport");
        return -1;
    }
    max_frame_payload = WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES -
                        WVM_ENVELOPE_HEADER_BYTES;
    if (frame_payload_bytes > max_frame_payload) {
        set_error(error, error_len, "network envelope frame exceeds MTU");
        return -1;
    }
    if (envelope->flags & WVM_ENVELOPE_FLAG_FRAGMENTED) {
        struct fragment_prefix prefix;

        if (parse_fragment_prefix(envelope, &prefix, error, error_len) != 0) {
            return -1;
        }
    } else if (envelope->payload_bytes >
               WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD) {
        set_error(error, error_len, "network envelope payload exceeds limit");
        return -1;
    }
    return 0;
}

static int envelope_fields_valid(const struct wvm_envelope *envelope,
                                 enum wvm_envelope_transport transport,
                                 int verify_semantic_digest, char *error,
                                 size_t error_len)
{
    uint8_t expected_digest[WVM_SHA256_DIGEST_BYTES];
    int has_route;

    if (!envelope || !message_type_known(envelope->message_type) ||
        (envelope->flags & ~WVM_ENVELOPE_KNOWN_FLAGS) != 0 ||
        (envelope->payload_bytes != 0 && !envelope->payload) ||
        envelope->origin_physical_node_id == 0 ||
        envelope->origin_runtime_instance_id == 0 ||
        all_zero(envelope->operation_id, sizeof(envelope->operation_id)) ||
        envelope->delivery_attempt_id == 0 ||
        route_fields_valid(envelope, error, error_len) != 0 ||
        transport_payload_valid(envelope, transport, error, error_len) != 0) {
        set_error(error, error_len, "envelope header fields are invalid");
        return -1;
    }
    if (envelope->vm_id == 0) {
        if (!cluster_control_message(envelope->message_type) ||
            envelope->vm_incarnation != 0 ||
            envelope->manifest_generation != 0) {
            set_error(error, error_len,
                      "zero VM namespace is reserved for cluster control");
            return -1;
        }
    } else if (envelope->vm_incarnation == 0 ||
               envelope->manifest_generation == 0) {
        set_error(error, error_len, "VM envelope identity is incomplete");
        return -1;
    }

    has_route = envelope->route_scope_id != 0 ||
                envelope->topology_revision != 0 ||
                envelope->route_generation != 0 ||
                !all_zero(envelope->route_snapshot_digest,
                          sizeof(envelope->route_snapshot_digest));
    if (routed_data_message(envelope->message_type)) {
        if (envelope->vm_id == 0 || envelope->route_scope_id == 0 ||
            envelope->topology_revision == 0 ||
            envelope->route_generation == 0 ||
            all_zero(envelope->route_snapshot_digest,
                     sizeof(envelope->route_snapshot_digest))) {
            set_error(error, error_len,
                      "routed data envelope lacks a complete route key");
            return -1;
        }
    } else if (has_route &&
               (envelope->route_scope_id == 0 ||
                envelope->topology_revision == 0 ||
                envelope->route_generation == 0 ||
                all_zero(envelope->route_snapshot_digest,
                         sizeof(envelope->route_snapshot_digest)))) {
        set_error(error, error_len, "route metadata is only partially set");
        return -1;
    }

    if (envelope->flags & WVM_ENVELOPE_FLAG_FRAGMENTED) {
        if (all_zero(envelope->semantic_payload_digest,
                     sizeof(envelope->semantic_payload_digest))) {
            set_error(error, error_len,
                      "fragmented envelope lacks semantic payload digest");
            return -1;
        }
        return 0;
    }
    if (verify_semantic_digest) {
        wvm_envelope_semantic_digest(envelope->payload,
                                        envelope->payload_bytes,
                                        expected_digest);
        if (memcmp(expected_digest, envelope->semantic_payload_digest,
                   sizeof(expected_digest)) != 0) {
            set_error(error, error_len, "semantic payload digest mismatch");
            return -1;
        }
    }
    return 0;
}

int wvm_envelope_encode(
    const struct wvm_envelope *envelope,
    enum wvm_envelope_transport transport, uint8_t *output,
    size_t output_capacity, size_t *encoded_bytes, char *error,
    size_t error_len)
{
    struct wvm_envelope normalized;
    size_t routing_bytes;
    size_t frame_payload_bytes;
    size_t total_bytes;

    if (!envelope || !output || !encoded_bytes ||
        (envelope->payload_bytes != 0 && !envelope->payload) ||
        envelope->payload_bytes > UINT32_MAX ||
        envelope->payload_bytes >
            SIZE_MAX - WVM_ENVELOPE_HEADER_BYTES) {
        set_error(error, error_len, "envelope encode input is invalid");
        return -1;
    }
    normalized = *envelope;
    if (!(normalized.flags & WVM_ENVELOPE_FLAG_FRAGMENTED)) {
        wvm_envelope_semantic_digest(normalized.payload,
                                        normalized.payload_bytes,
                                        normalized.semantic_payload_digest);
    }
    if (envelope_fields_valid(&normalized, transport, 1, error, error_len) !=
        0) {
        return -1;
    }
    routing_bytes = route_prefix_bytes(&normalized);
    frame_payload_bytes = routing_bytes + normalized.payload_bytes;
    total_bytes = WVM_ENVELOPE_HEADER_BYTES + frame_payload_bytes;
    if (output_capacity < total_bytes) {
        set_error(error, error_len, "envelope output buffer is too small");
        return -1;
    }

    memset(output, 0, WVM_ENVELOPE_HEADER_BYTES);
    write_be32(output + 0, WVM_ENVELOPE_MAGIC);
    write_be16(output + 4, WVM_ENVELOPE_PROTOCOL_VERSION);
    write_be16(output + 6, WVM_ENVELOPE_HEADER_BYTES);
    write_be16(output + 8, normalized.message_type);
    write_be16(output + 10, normalized.flags);
    write_be32(output + 12, (uint32_t)frame_payload_bytes);
    write_be32(output + 16, normalized.vm_id);
    write_be64(output + 20, normalized.vm_incarnation);
    write_be64(output + 28, normalized.manifest_generation);
    write_be32(output + 36, normalized.origin_physical_node_id);
    write_be64(output + 40, normalized.origin_runtime_instance_id);
    memcpy(output + 48, normalized.operation_id,
           sizeof(normalized.operation_id));
    write_be64(output + 64, normalized.delivery_attempt_id);
    write_be64(output + 72, normalized.route_scope_id);
    write_be64(output + 80, normalized.topology_revision);
    write_be64(output + 88, normalized.route_generation);
    memcpy(output + 96, normalized.route_snapshot_digest,
           sizeof(normalized.route_snapshot_digest));
    memcpy(output + 128, normalized.semantic_payload_digest,
           sizeof(normalized.semantic_payload_digest));
    if (routing_bytes != 0) {
        uint8_t *prefix = output + WVM_ENVELOPE_HEADER_BYTES;

        write_be16(prefix + 0, WVM_ENVELOPE_ROUTE_PREFIX_VERSION);
        write_be16(prefix + 2, WVM_ENVELOPE_ROUTE_PREFIX_BYTES);
        write_be16(prefix + 4, normalized.route.destination_kind);
        write_be16(prefix + 6, 0);
        write_be64(prefix + 8, normalized.route.destination_scope);
        write_be32(prefix + 16,
                   normalized.route.destination_vnode_or_endpoint);
        write_be16(prefix + 20, normalized.route.hop_limit);
        write_be16(prefix + 22, normalized.route.hop_count);
    }
    if (normalized.payload_bytes != 0) {
        memcpy(output + WVM_ENVELOPE_HEADER_BYTES + routing_bytes,
               normalized.payload,
               normalized.payload_bytes);
    }
    write_be32(output + 160,
               crc32c_header_payload(output,
                                     output + WVM_ENVELOPE_HEADER_BYTES,
                                     frame_payload_bytes));
    *encoded_bytes = total_bytes;
    return 0;
}

int wvm_envelope_emit_network_frames(
    const struct wvm_envelope *envelope,
    wvm_envelope_emit_frame_fn emit_frame, void *opaque, char *error,
    size_t error_len)
{
    struct wvm_envelope fragment;
    uint8_t frame[WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES];
    uint8_t fragment_payload[WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES +
                             WVM_ENVELOPE_MAX_FRAGMENT_DATA_BYTES];
    uint8_t semantic_digest[WVM_SHA256_DIGEST_BYTES];
    size_t route_bytes;
    size_t max_unfragmented_payload;
    size_t offset;
    size_t frame_bytes;
    uint16_t fragment_count;
    uint16_t fragment_index;

    if (!envelope || !emit_frame ||
        (envelope->payload_bytes != 0 && !envelope->payload) ||
        (envelope->flags & WVM_ENVELOPE_FLAG_FRAGMENTED) != 0 ||
        envelope->payload_bytes > WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD) {
        set_error(error, error_len,
                  "network frame emission input is invalid");
        return -1;
    }
    route_bytes = route_prefix_bytes(envelope);
    max_unfragmented_payload =
        WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES -
        WVM_ENVELOPE_HEADER_BYTES - route_bytes;
    if (envelope->payload_bytes <= max_unfragmented_payload) {
        if (wvm_envelope_encode(envelope, WVM_ENVELOPE_TRANSPORT_NETWORK,
                                   frame, sizeof(frame), &frame_bytes, error,
                                   error_len) != 0) {
            return -1;
        }
        return emit_frame(opaque, frame, frame_bytes, error, error_len);
    }

    fragment_count =
        (uint16_t)((envelope->payload_bytes +
                    WVM_ENVELOPE_MAX_FRAGMENT_DATA_BYTES - 1U) /
                   WVM_ENVELOPE_MAX_FRAGMENT_DATA_BYTES);
    if (fragment_count == 0 ||
        fragment_count > WVM_ENVELOPE_MAX_FRAGMENTS) {
        set_error(error, error_len, "network fragmentation count is invalid");
        return -1;
    }
    wvm_envelope_semantic_digest(envelope->payload, envelope->payload_bytes,
                                    semantic_digest);
    offset = 0;
    for (fragment_index = 0; fragment_index < fragment_count;
         fragment_index++) {
        size_t data_bytes = envelope->payload_bytes - offset;

        if (data_bytes > WVM_ENVELOPE_MAX_FRAGMENT_DATA_BYTES) {
            data_bytes = WVM_ENVELOPE_MAX_FRAGMENT_DATA_BYTES;
        }
        memset(fragment_payload, 0,
               WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES + data_bytes);
        write_be32(fragment_payload + 0, (uint32_t)envelope->payload_bytes);
        write_be16(fragment_payload + 4, fragment_index);
        write_be16(fragment_payload + 6, fragment_count);
        write_be32(fragment_payload + 8, (uint32_t)offset);
        memcpy(fragment_payload + WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES,
               envelope->payload + offset, data_bytes);

        fragment = *envelope;
        fragment.flags |= WVM_ENVELOPE_FLAG_FRAGMENTED;
        memcpy(fragment.semantic_payload_digest, semantic_digest,
               sizeof(fragment.semantic_payload_digest));
        fragment.payload = fragment_payload;
        fragment.payload_bytes =
            WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES + data_bytes;
        if (wvm_envelope_encode(&fragment,
                                   WVM_ENVELOPE_TRANSPORT_NETWORK, frame,
                                   sizeof(frame), &frame_bytes, error,
                                   error_len) != 0 ||
            emit_frame(opaque, frame, frame_bytes, error, error_len) != 0) {
            return -1;
        }
        offset += data_bytes;
    }
    return 0;
}

int wvm_envelope_decode(
    const uint8_t *input, size_t input_bytes,
    enum wvm_envelope_transport transport,
    struct wvm_envelope *envelope, char *error, size_t error_len)
{
    uint16_t message_type;
    uint32_t payload_bytes;
    uint32_t received_crc;
    size_t routing_bytes;

    if (!input || !envelope || input_bytes < WVM_ENVELOPE_HEADER_BYTES ||
        read_be32(input + 0) != WVM_ENVELOPE_MAGIC ||
        read_be16(input + 4) != WVM_ENVELOPE_PROTOCOL_VERSION ||
        read_be16(input + 6) != WVM_ENVELOPE_HEADER_BYTES) {
        set_error(error, error_len, "envelope prefix is invalid");
        return -1;
    }
    payload_bytes = read_be32(input + 12);
    if (input_bytes - WVM_ENVELOPE_HEADER_BYTES != payload_bytes) {
        set_error(error, error_len, "envelope length is invalid");
        return -1;
    }
    received_crc = read_be32(input + 160);
    if (received_crc !=
        crc32c_header_payload(input, input + WVM_ENVELOPE_HEADER_BYTES,
                              payload_bytes)) {
        set_error(error, error_len, "envelope CRC32C mismatch");
        return -1;
    }

    memset(envelope, 0, sizeof(*envelope));
    message_type = read_be16(input + 8);
    envelope->message_type = message_type;
    envelope->flags = read_be16(input + 10);
    routing_bytes = routed_data_message(message_type)
                        ? WVM_ENVELOPE_ROUTE_PREFIX_BYTES
                        : 0U;
    if (payload_bytes < routing_bytes) {
        set_error(error, error_len, "routed envelope lacks route prefix");
        return -1;
    }
    envelope->payload_bytes = payload_bytes - routing_bytes;
    envelope->vm_id = read_be32(input + 16);
    envelope->vm_incarnation = read_be64(input + 20);
    envelope->manifest_generation = read_be64(input + 28);
    envelope->origin_physical_node_id = read_be32(input + 36);
    envelope->origin_runtime_instance_id = read_be64(input + 40);
    memcpy(envelope->operation_id, input + 48, sizeof(envelope->operation_id));
    envelope->delivery_attempt_id = read_be64(input + 64);
    envelope->route_scope_id = read_be64(input + 72);
    envelope->topology_revision = read_be64(input + 80);
    envelope->route_generation = read_be64(input + 88);
    memcpy(envelope->route_snapshot_digest, input + 96,
           sizeof(envelope->route_snapshot_digest));
    memcpy(envelope->semantic_payload_digest, input + 128,
           sizeof(envelope->semantic_payload_digest));
    envelope->crc32c = received_crc;
    if (routing_bytes != 0) {
        const uint8_t *prefix = input + WVM_ENVELOPE_HEADER_BYTES;

        if (read_be16(prefix + 0) != WVM_ENVELOPE_ROUTE_PREFIX_VERSION ||
            read_be16(prefix + 2) != WVM_ENVELOPE_ROUTE_PREFIX_BYTES ||
            read_be16(prefix + 6) != 0) {
            set_error(error, error_len, "route prefix is invalid");
            return -1;
        }
        envelope->route.destination_kind = read_be16(prefix + 4);
        envelope->route.destination_scope = read_be64(prefix + 8);
        envelope->route.destination_vnode_or_endpoint = read_be32(prefix + 16);
        envelope->route.hop_limit = read_be16(prefix + 20);
        envelope->route.hop_count = read_be16(prefix + 22);
    }
    envelope->payload = input + WVM_ENVELOPE_HEADER_BYTES + routing_bytes;
    return envelope_fields_valid(envelope, transport, 1, error, error_len);
}

int wvm_envelope_validate_admitted(
    const struct wvm_envelope *envelope,
    const struct wvm_envelope_admitted_identity *identity, char *error,
    size_t error_len)
{
    if (!envelope || !identity || identity->vm_id == 0 ||
        identity->vm_incarnation == 0 || identity->manifest_generation == 0 ||
        identity->route_scope_id == 0 || identity->topology_revision == 0 ||
        identity->route_generation == 0 ||
        all_zero(identity->route_snapshot_digest,
                 sizeof(identity->route_snapshot_digest)) ||
        envelope->vm_id != identity->vm_id ||
        envelope->vm_incarnation != identity->vm_incarnation ||
        envelope->manifest_generation != identity->manifest_generation ||
        envelope->route_scope_id != identity->route_scope_id ||
        envelope->topology_revision != identity->topology_revision ||
        envelope->route_generation != identity->route_generation ||
        memcmp(envelope->route_snapshot_digest,
               identity->route_snapshot_digest,
               sizeof(identity->route_snapshot_digest)) != 0) {
        set_error(error, error_len,
                  "envelope identity does not match admitted runtime");
        return -1;
    }
    return 0;
}

int wvm_envelope_route_advance(struct wvm_envelope *envelope,
                                  char *error, size_t error_len)
{
    if (!envelope || !route_prefix_required(envelope) ||
        route_fields_valid(envelope, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "envelope does not carry a route key");
        }
        return -1;
    }
    if (envelope->route.hop_count == envelope->route.hop_limit) {
        set_error(error, error_len, "route hop budget is exhausted");
        return -1;
    }
    envelope->route.hop_count++;
    return 0;
}

static void reassembly_entry_clear(struct reassembly_entry *entry,
                                   size_t *allocated_payload_bytes)
{
    if (!entry) {
        return;
    }
    if (allocated_payload_bytes && entry->in_use) {
        *allocated_payload_bytes -= entry->logical_payload_bytes;
    }
    free(entry->payload);
    free(entry->pieces);
    memset(entry, 0, sizeof(*entry));
}

int wvm_envelope_reassembler_init(
    struct wvm_envelope_reassembler *reassembler)
{
    struct reassembly_entry *entries;

    if (!reassembler) {
        return -1;
    }
    memset(reassembler, 0, sizeof(*reassembler));
    entries = calloc(WVM_ENVELOPE_MAX_REASSEMBLIES, sizeof(*entries));
    if (!entries) {
        return -1;
    }
    reassembler->entries = entries;
    reassembler->entry_capacity = WVM_ENVELOPE_MAX_REASSEMBLIES;
    return 0;
}

void wvm_envelope_reassembler_destroy(
    struct wvm_envelope_reassembler *reassembler)
{
    struct reassembly_entry *entries;
    size_t i;

    if (!reassembler) {
        return;
    }
    entries = reassembler->entries;
    for (i = 0; entries && i < reassembler->entry_capacity; i++) {
        reassembly_entry_clear(&entries[i], NULL);
    }
    free(entries);
    memset(reassembler, 0, sizeof(*reassembler));
}

static int operation_key_equal(const struct wvm_envelope *left,
                               const struct wvm_envelope *right)
{
    return left->message_type == right->message_type &&
           left->vm_id == right->vm_id &&
           left->vm_incarnation == right->vm_incarnation &&
           left->origin_physical_node_id == right->origin_physical_node_id &&
           left->origin_runtime_instance_id ==
               right->origin_runtime_instance_id &&
           left->delivery_attempt_id == right->delivery_attempt_id &&
           memcmp(left->operation_id, right->operation_id,
                  sizeof(left->operation_id)) == 0;
}

static void reassembler_expire(struct wvm_envelope_reassembler *reassembler,
                               uint64_t now_ms)
{
    struct reassembly_entry *entries = reassembler->entries;
    size_t i;

    for (i = 0; i < reassembler->entry_capacity; i++) {
        if (entries[i].in_use && entries[i].expiry_ms <= now_ms) {
            reassembly_entry_clear(&entries[i],
                                   &reassembler->allocated_payload_bytes);
        }
    }
}

static struct reassembly_entry *reassembly_find(
    struct wvm_envelope_reassembler *reassembler,
    const struct wvm_envelope *fragment)
{
    struct reassembly_entry *entries = reassembler->entries;
    size_t i;

    for (i = 0; i < reassembler->entry_capacity; i++) {
        if (entries[i].in_use &&
            operation_key_equal(&entries[i].envelope, fragment)) {
            return &entries[i];
        }
    }
    return NULL;
}

static struct reassembly_entry *reassembly_allocate(
    struct wvm_envelope_reassembler *reassembler,
    const struct wvm_envelope *fragment,
    const struct fragment_prefix *prefix, uint64_t now_ms, char *error,
    size_t error_len)
{
    struct reassembly_entry *entries = reassembler->entries;
    struct reassembly_entry *entry = NULL;
    size_t i;

    if (prefix->logical_payload_bytes >
        WVM_ENVELOPE_MAX_REASSEMBLY_BYTES -
            reassembler->allocated_payload_bytes) {
        set_error(error, error_len, "reassembly payload budget is exhausted");
        return NULL;
    }
    for (i = 0; i < reassembler->entry_capacity; i++) {
        if (!entries[i].in_use) {
            entry = &entries[i];
            break;
        }
    }
    if (!entry) {
        set_error(error, error_len, "reassembly entry capacity is exhausted");
        return NULL;
    }
    entry->payload = calloc(prefix->logical_payload_bytes, 1);
    entry->pieces = calloc(prefix->fragment_count, sizeof(*entry->pieces));
    if (!entry->payload || !entry->pieces) {
        reassembly_entry_clear(entry, NULL);
        set_error(error, error_len, "cannot allocate reassembly state");
        return NULL;
    }
    entry->in_use = 1;
    entry->expiry_ms = now_ms + WVM_ENVELOPE_REASSEMBLY_LIFETIME_MS;
    entry->envelope = *fragment;
    entry->logical_payload_bytes = prefix->logical_payload_bytes;
    entry->fragment_count = prefix->fragment_count;
    reassembler->allocated_payload_bytes += prefix->logical_payload_bytes;
    return entry;
}

static int fragment_metadata_matches(const struct reassembly_entry *entry,
                                     const struct wvm_envelope *fragment,
                                     const struct fragment_prefix *prefix)
{
    return entry->logical_payload_bytes == prefix->logical_payload_bytes &&
           entry->fragment_count == prefix->fragment_count &&
           memcmp(entry->envelope.semantic_payload_digest,
                  fragment->semantic_payload_digest,
                  sizeof(fragment->semantic_payload_digest)) == 0;
}

static int fragment_overlaps_existing(const struct reassembly_entry *entry,
                                      const struct fragment_prefix *prefix)
{
    uint32_t end = prefix->fragment_offset + (uint32_t)prefix->data_bytes;
    uint16_t i;

    for (i = 0; i < entry->fragment_count; i++) {
        uint32_t other_end;

        if (!entry->pieces[i].received || i == prefix->fragment_index) {
            continue;
        }
        other_end = entry->pieces[i].offset + entry->pieces[i].bytes;
        if (prefix->fragment_offset < other_end &&
            entry->pieces[i].offset < end) {
            return 1;
        }
    }
    return 0;
}

int wvm_envelope_reassembler_accept(
    struct wvm_envelope_reassembler *reassembler,
    const struct wvm_envelope *fragment, uint64_t now_ms,
    struct wvm_envelope_reassembled *output, char *error,
    size_t error_len)
{
    struct fragment_prefix prefix;
    struct reassembly_entry *entry;
    struct fragment_piece *piece;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    if (!reassembler || !reassembler->entries || !fragment || !output ||
        !(fragment->flags & WVM_ENVELOPE_FLAG_FRAGMENTED) ||
        parse_fragment_prefix(fragment, &prefix, error, error_len) != 0) {
        set_error(error, error_len, "fragment reassembly input is invalid");
        return -1;
    }
    memset(output, 0, sizeof(*output));
    reassembler_expire(reassembler, now_ms);
    entry = reassembly_find(reassembler, fragment);
    if (!entry) {
        entry = reassembly_allocate(reassembler, fragment, &prefix, now_ms,
                                    error, error_len);
        if (!entry) {
            return -1;
        }
    } else if (!fragment_metadata_matches(entry, fragment, &prefix)) {
        set_error(error, error_len, "fragment metadata conflicts with retry");
        return -1;
    }

    piece = &entry->pieces[prefix.fragment_index];
    if (piece->received) {
        if (piece->offset != prefix.fragment_offset ||
            piece->bytes != prefix.data_bytes ||
            memcmp(entry->payload + piece->offset, prefix.data,
                   prefix.data_bytes) != 0) {
            set_error(error, error_len, "fragment retry conflicts with prior data");
            return -1;
        }
        return 0;
    }
    if (fragment_overlaps_existing(entry, &prefix)) {
        set_error(error, error_len, "fragment overlaps an existing range");
        return -1;
    }
    memcpy(entry->payload + prefix.fragment_offset, prefix.data,
           prefix.data_bytes);
    piece->offset = prefix.fragment_offset;
    piece->bytes = (uint16_t)prefix.data_bytes;
    piece->received = 1;
    entry->received_count++;
    entry->received_bytes += prefix.data_bytes;
    if (entry->received_count != entry->fragment_count ||
        entry->received_bytes != entry->logical_payload_bytes) {
        return 0;
    }
    wvm_envelope_semantic_digest(entry->payload,
                                    entry->logical_payload_bytes, digest);
    if (memcmp(digest, entry->envelope.semantic_payload_digest,
               sizeof(digest)) != 0) {
        reassembly_entry_clear(entry, &reassembler->allocated_payload_bytes);
        set_error(error, error_len, "reassembled semantic digest mismatch");
        return -1;
    }
    output->envelope = entry->envelope;
    output->envelope.flags &= ~WVM_ENVELOPE_FLAG_FRAGMENTED;
    output->envelope.payload = entry->payload;
    output->envelope.payload_bytes = entry->logical_payload_bytes;
    output->payload = entry->payload;
    output->payload_bytes = entry->logical_payload_bytes;
    entry->payload = NULL;
    reassembly_entry_clear(entry, &reassembler->allocated_payload_bytes);
    return 1;
}

void wvm_envelope_reassembled_release(
    struct wvm_envelope_reassembled *reassembled)
{
    if (!reassembled) {
        return;
    }
    free(reassembled->payload);
    memset(reassembled, 0, sizeof(*reassembled));
}

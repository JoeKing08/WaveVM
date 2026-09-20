#ifndef WAVEVM_ENVELOPE_H
#define WAVEVM_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_sha256.h"

/*
 * Fixed wire representation defined by docs/specs/wire-ipc-abi.md.  The C
 * representation below is host-native; encode/decode always use explicit
 * big-endian offsets and never cast a network buffer to a C structure.
 */
#define WVM_ENVELOPE_MAGIC 0x57564d31U /* "WVM1" */
#define WVM_ENVELOPE_PROTOCOL_VERSION 1U
#define WVM_ENVELOPE_HEADER_BYTES 164U

#define WVM_ENVELOPE_MAX_LOCAL_PAYLOAD (4U * 1024U * 1024U)
#define WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD (1U * 1024U * 1024U)
#define WVM_ENVELOPE_MAX_NETWORK_FRAME_BYTES 1280U
#define WVM_ENVELOPE_ROUTE_PREFIX_VERSION 1U
#define WVM_ENVELOPE_ROUTE_PREFIX_BYTES 24U
#define WVM_ENVELOPE_ROUTE_DESTINATION_UNSPECIFIED UINT32_MAX
#define WVM_ENVELOPE_MAX_FRAGMENT_DATA_BYTES 1024U
#define WVM_ENVELOPE_FRAGMENT_PREFIX_BYTES 40U
#define WVM_ENVELOPE_MAX_FRAGMENTS 1024U
#define WVM_ENVELOPE_MAX_REASSEMBLIES 64U
#define WVM_ENVELOPE_MAX_REASSEMBLY_BYTES (8U * 1024U * 1024U)
#define WVM_ENVELOPE_REASSEMBLY_LIFETIME_MS 5000U

#define WVM_ENVELOPE_FLAG_FRAGMENTED 0x0001U
#define WVM_ENVELOPE_KNOWN_FLAGS WVM_ENVELOPE_FLAG_FRAGMENTED

enum wvm_envelope_transport {
    WVM_ENVELOPE_TRANSPORT_NETWORK = 1,
    WVM_ENVELOPE_TRANSPORT_LOCAL = 2,
};

/*
 * Routed semantic operations carry this mutable forwarding key immediately
 * after the fixed V1 envelope.  It is protected by the frame CRC but excluded
 * from the semantic payload digest, so a route refresh or hop advancement
 * cannot change operation identity.
 */
enum wvm_envelope_route_destination_kind {
    WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE = 1,
    WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE = 2,
};

struct wvm_envelope_route {
    uint16_t destination_kind;
    uint64_t destination_scope;
    uint32_t destination_vnode_or_endpoint;
    uint16_t hop_limit;
    uint16_t hop_count;
};

/*
 * Data message values intentionally retain the existing semantic registry,
 * while the envelope removes the legacy header's overloaded identity fields.
 */
enum wvm_envelope_message_type {
    WVM_ENVELOPE_MSG_MEM_READ = 0x0001U,
    WVM_ENVELOPE_MSG_MEM_WRITE = 0x0002U,
    WVM_ENVELOPE_MSG_MEM_ACK = 0x0003U,
    WVM_ENVELOPE_MSG_VCPU_RUN = 0x0005U,
    WVM_ENVELOPE_MSG_VCPU_EXIT = 0x0006U,
    WVM_ENVELOPE_MSG_VFIO_IRQ = 0x0007U,
    WVM_ENVELOPE_MSG_INVALIDATE = 0x000aU,
    WVM_ENVELOPE_MSG_DOWNGRADE = 0x000bU,
    WVM_ENVELOPE_MSG_FETCH_AND_INVALIDATE = 0x000cU,
    WVM_ENVELOPE_MSG_WRITE_BACK = 0x000dU,
    WVM_ENVELOPE_MSG_DECLARE_INTEREST = 0x0019U,
    WVM_ENVELOPE_MSG_PAGE_PUSH_FULL = 0x001aU,
    WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF = 0x001bU,
    WVM_ENVELOPE_MSG_COMMIT_DIFF = 0x001cU,
    WVM_ENVELOPE_MSG_FORCE_SYNC = 0x001dU,
    WVM_ENVELOPE_MSG_MEM_COMMIT_ACK = 0x001eU,
    WVM_ENVELOPE_MSG_BLOCK_READ = 0x0032U,
    WVM_ENVELOPE_MSG_BLOCK_WRITE = 0x0033U,
    WVM_ENVELOPE_MSG_BLOCK_ACK = 0x0034U,
    WVM_ENVELOPE_MSG_BLOCK_FLUSH = 0x0035U,

    WVM_ENVELOPE_MSG_CTRL_RESULT = 0x01ffU,
    WVM_ENVELOPE_MSG_REGISTER_MEMBER = 0x0101U,
    WVM_ENVELOPE_MSG_CORDON = 0x0102U,
    WVM_ENVELOPE_MSG_DRAIN = 0x0103U,
    WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES = 0x0104U,
    WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE = 0x0105U,
    WVM_ENVELOPE_MSG_PREPARE_RESERVATION = 0x0201U,
    WVM_ENVELOPE_MSG_COMMIT_RESERVATION = 0x0202U,
    WVM_ENVELOPE_MSG_ABORT_RESERVATION = 0x0203U,
    WVM_ENVELOPE_MSG_PREPARE_MANIFEST = 0x0301U,
    WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST = 0x0302U,
    WVM_ENVELOPE_MSG_ABORT_MANIFEST = 0x0303U,
    WVM_ENVELOPE_MSG_QUERY_TX = 0x0304U,
    WVM_ENVELOPE_MSG_ROUTE_PREPARE = 0x0401U,
    WVM_ENVELOPE_MSG_ROUTE_COMMIT = 0x0402U,
    WVM_ENVELOPE_MSG_ROUTE_RETIRE = 0x0403U,
    WVM_ENVELOPE_MSG_ROUTE_ABORT = 0x0404U,
    WVM_ENVELOPE_MSG_REJOIN = 0x0501U,
    WVM_ENVELOPE_MSG_RECOVERY_REBIND = 0x0502U,
    WVM_ENVELOPE_MSG_CREATE_VM = 0x0601U,
};

struct wvm_envelope {
    uint16_t message_type;
    uint16_t flags;
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint32_t origin_physical_node_id;
    uint64_t origin_runtime_instance_id;
    uint8_t operation_id[16];
    uint64_t delivery_attempt_id;
    uint64_t route_scope_id;
    uint64_t topology_revision;
    uint64_t route_generation;
    uint8_t route_snapshot_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_envelope_route route;
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t crc32c;
    const uint8_t *payload;
    size_t payload_bytes;
};

/*
 * The route/manifest fields a receiving node runtime has admitted for one
 * local VM instance. The source identity is intentionally not pinned here:
 * remote origins are authorized by the selected operation's role contract.
 */
struct wvm_envelope_admitted_identity {
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint64_t route_scope_id;
    uint64_t topology_revision;
    uint64_t route_generation;
    uint8_t route_snapshot_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_envelope_reassembled {
    struct wvm_envelope envelope;
    uint8_t *payload;
    size_t payload_bytes;
};

/*
 * Network senders submit encoded frames through this callback. A logical V1
 * envelope may produce multiple bounded frames when its semantic payload does
 * not fit one datagram. The callback consumes FRAME before returning.
 */
typedef int (*wvm_envelope_emit_frame_fn)(
    void *opaque, const uint8_t *frame, size_t frame_bytes, char *error,
    size_t error_len);

/*
 * Reassembly state is deliberately caller-owned and not internally locked.
 * One ingress owner should keep a separate instance per source/queue domain.
 */
struct wvm_envelope_reassembler {
    void *entries;
    size_t entry_capacity;
    size_t allocated_payload_bytes;
};

void wvm_envelope_semantic_digest(
    const uint8_t *payload, size_t payload_bytes,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES]);

uint32_t wvm_envelope_crc32c(const uint8_t *bytes, size_t byte_count);

int wvm_envelope_encode(
    const struct wvm_envelope *envelope,
    enum wvm_envelope_transport transport, uint8_t *output,
    size_t output_capacity, size_t *encoded_bytes, char *error,
    size_t error_len);

/*
 * Emit an unfragmented logical envelope as one or more valid network frames.
 * The function computes one semantic digest for the complete payload and
 * preserves it across fragments. Callers must not pass a pre-fragmented
 * envelope; route refresh and delivery-attempt changes are applied before
 * this boundary.
 */
int wvm_envelope_emit_network_frames(
    const struct wvm_envelope *envelope,
    wvm_envelope_emit_frame_fn emit_frame, void *opaque, char *error,
    size_t error_len);

int wvm_envelope_decode(
    const uint8_t *input, size_t input_bytes,
    enum wvm_envelope_transport transport,
    struct wvm_envelope *envelope, char *error, size_t error_len);

int wvm_envelope_validate_admitted(
    const struct wvm_envelope *envelope,
    const struct wvm_envelope_admitted_identity *identity, char *error,
    size_t error_len);

/*
 * Advance one gateway/sidecar forwarding hop.  This changes only forwarding
 * metadata and fails before the configured route hop budget is exceeded.
 */
int wvm_envelope_route_advance(struct wvm_envelope *envelope,
                                  char *error, size_t error_len);

int wvm_envelope_reassembler_init(
    struct wvm_envelope_reassembler *reassembler);

void wvm_envelope_reassembler_destroy(
    struct wvm_envelope_reassembler *reassembler);

/*
 * Returns 0 while the logical message is incomplete, 1 when output receives
 * a complete semantic payload, and -1 for malformed/expired/over-capacity
 * input. now_ms is monotonic time supplied by the owner.
 */
int wvm_envelope_reassembler_accept(
    struct wvm_envelope_reassembler *reassembler,
    const struct wvm_envelope *fragment, uint64_t now_ms,
    struct wvm_envelope_reassembled *output, char *error,
    size_t error_len);

void wvm_envelope_reassembled_release(
    struct wvm_envelope_reassembled *reassembled);

#endif /* WAVEVM_ENVELOPE_H */

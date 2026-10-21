#ifndef WAVEVM_BLOCK_WIRE_H
#define WAVEVM_BLOCK_WIRE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Canonical V1 block payloads.
 *
 * Identity, incarnation, the 128-bit operation id, route generation and the
 * semantic digest live in the WVM envelope.  These payloads carry only the
 * device operation, its ordering flags, the byte range, and the reply leaf
 * that the ACK must be routed back to.  Nothing here is a second identity
 * source.
 */
#define WVM_BLOCK_WIRE_VERSION 1U
#define WVM_BLOCK_SECTOR_BYTES 512U
/*
 * One block completion is one UDP datagram.  The bound leaves room for the
 * fixed envelope, the routed-frame prefix and fragmentation metadata.
 */
#define WVM_BLOCK_MAX_SECTORS 120U
#define WVM_BLOCK_MAX_DATA_BYTES (WVM_BLOCK_MAX_SECTORS * WVM_BLOCK_SECTOR_BYTES)

enum wvm_block_operation {
    WVM_BLOCK_OPERATION_READ = 1,
    WVM_BLOCK_OPERATION_WRITE = 2,
    WVM_BLOCK_OPERATION_FLUSH = 3,
};

#define WVM_BLOCK_ORDER_FUA 0x0001U
#define WVM_BLOCK_ORDER_SYNC 0x0002U
#define WVM_BLOCK_ORDER_KNOWN (WVM_BLOCK_ORDER_FUA | WVM_BLOCK_ORDER_SYNC)

enum wvm_block_wire_status {
    WVM_BLOCK_WIRE_SUCCESS = 0,
    WVM_BLOCK_WIRE_IO_ERROR = 1,
    WVM_BLOCK_WIRE_INVALID = 2,
    /* The same operation id was reused with different semantics. */
    WVM_BLOCK_WIRE_CONFLICT = 3,
    /*
     * The operation was executed, but its result aged out of the retention
     * window.  The initiator must treat this as a typed terminal outcome for
     * that operation, never as permission to silently execute it again.
     */
    WVM_BLOCK_WIRE_EXPIRED = 4,
};

struct wvm_block_request {
    uint16_t payload_version;
    uint16_t operation;
    uint32_t flags;
    uint64_t lba_512;
    uint32_t sector_count;
    uint32_t payload_bytes;
    uint16_t reply_destination_kind;
    uint64_t reply_destination_scope;
    uint32_t reply_destination_vnode;
    /*
     * Ordering domain and position.  Two requests with different queue ids may
     * execute concurrently; within one queue the receiver executes exactly in
     * sequence order and reports retryable backpressure for a gap or a stale
     * predecessor instead of letting a later WRITE/FLUSH overtake it.
     */
    uint32_t queue_id;
    uint32_t queue_sequence;
    /*
     * Guest device identity.  V1 has no implicit "the VM has one disk"
     * assumption: the executor must be told which device it is serving so a
     * multi-device manifest cannot alias two backends under one operation.
     */
    uint32_t device_index;
};

struct wvm_block_completion {
    uint16_t payload_version;
    uint16_t status;
    uint32_t transferred_bytes;
};

#define WVM_BLOCK_REQUEST_HEADER_BYTES 50U
#define WVM_BLOCK_COMPLETION_HEADER_BYTES 8U

int wvm_block_request_encode(
    const struct wvm_block_request *request, const uint8_t *data,
    size_t data_bytes, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len);

int wvm_block_request_decode(
    const uint8_t *bytes, size_t byte_count, struct wvm_block_request *request,
    const uint8_t **data, size_t *data_bytes, char *error, size_t error_len);

/*
 * Validate the request against the bytes actually received.  PAYLOAD_BYTES must
 * equal DATA_BYTES: a decoder that trusts a length larger than the frame is how
 * stale length arithmetic used to smuggle truncated operations through.
 */
int wvm_block_request_validate(
    const struct wvm_block_request *request, size_t data_bytes, char *error,
    size_t error_len);

int wvm_block_completion_encode(
    const struct wvm_block_completion *completion, const uint8_t *data,
    size_t data_bytes, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len);

int wvm_block_completion_decode(
    const uint8_t *bytes, size_t byte_count,
    struct wvm_block_completion *completion, const uint8_t **data,
    size_t *data_bytes, char *error, size_t error_len);

#endif /* WAVEVM_BLOCK_WIRE_H */

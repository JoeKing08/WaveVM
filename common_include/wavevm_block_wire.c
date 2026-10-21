#define _POSIX_C_SOURCE 200809L

#include "wavevm_block_wire.h"

#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0)
        snprintf(error, error_len, "%s", message);
}

static void put_be16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void put_be32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void put_be64(uint8_t *out, uint64_t value)
{
    put_be32(out, (uint32_t)(value >> 32));
    put_be32(out + 4, (uint32_t)value);
}

static uint16_t get_be16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t get_be32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t get_be64(const uint8_t *in)
{
    return ((uint64_t)get_be32(in) << 32) | get_be32(in + 4);
}

int wvm_block_request_validate(
    const struct wvm_block_request *request, size_t data_bytes, char *error,
    size_t error_len)
{
    uint64_t end_sector;

    if (!request) {
        set_error(error, error_len, "block request is null");
        return -1;
    }
    if (request->payload_version != WVM_BLOCK_WIRE_VERSION) {
        set_error(error, error_len, "block request version is not V1");
        return -1;
    }
    if (request->operation != WVM_BLOCK_OPERATION_READ &&
        request->operation != WVM_BLOCK_OPERATION_WRITE &&
        request->operation != WVM_BLOCK_OPERATION_FLUSH) {
        set_error(error, error_len, "block request operation is unknown");
        return -1;
    }
    if ((request->flags & ~WVM_BLOCK_ORDER_KNOWN) != 0) {
        set_error(error, error_len, "block request has unknown ordering flags");
        return -1;
    }
    if (request->reply_destination_vnode == 0xffffffffU) {
        set_error(error, error_len, "block request has no reply destination");
        return -1;
    }
    if (request->queue_sequence == 0) {
        set_error(error, error_len, "block request has no queue sequence");
        return -1;
    }
    if (request->sector_count > WVM_BLOCK_MAX_SECTORS) {
        set_error(error, error_len, "block request exceeds one datagram");
        return -1;
    }
    /*
     * FLUSH may name zero sectors (flush everything); READ and WRITE must
     * transfer at least one sector or the operation has no meaning.
     */
    if (request->operation != WVM_BLOCK_OPERATION_FLUSH &&
        request->sector_count == 0) {
        set_error(error, error_len, "block request has an empty range");
        return -1;
    }
    if (data_bytes != request->payload_bytes) {
        set_error(error, error_len,
                  "block request payload length disagrees with the frame");
        return -1;
    }
    if (request->operation == WVM_BLOCK_OPERATION_WRITE) {
        if (request->payload_bytes !=
            request->sector_count * WVM_BLOCK_SECTOR_BYTES) {
            set_error(error, error_len, "block write byte count is inconsistent");
            return -1;
        }
    } else if (request->payload_bytes != 0) {
        set_error(error, error_len,
                  "block read/flush must not carry payload bytes");
        return -1;
    }

    end_sector = request->lba_512 + (uint64_t)request->sector_count;
    if (end_sector < request->lba_512) {
        set_error(error, error_len, "block request range overflows");
        return -1;
    }
    return 0;
}

int wvm_block_request_encode(
    const struct wvm_block_request *request, const uint8_t *data,
    size_t data_bytes, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    size_t total;

    if (!request || !bytes || !encoded_bytes) {
        set_error(error, error_len, "block request encode arguments are null");
        return -1;
    }
    if (wvm_block_request_validate(request, data_bytes, error, error_len) != 0)
        return -1;
    total = WVM_BLOCK_REQUEST_HEADER_BYTES + data_bytes;
    if (total > capacity) {
        set_error(error, error_len, "block request does not fit the buffer");
        return -1;
    }

    put_be16(bytes + 0, request->payload_version);
    put_be16(bytes + 2, request->operation);
    put_be32(bytes + 4, request->flags);
    put_be64(bytes + 8, request->lba_512);
    put_be32(bytes + 16, request->sector_count);
    put_be32(bytes + 20, request->payload_bytes);
    put_be16(bytes + 24, request->reply_destination_kind);
    put_be64(bytes + 26, request->reply_destination_scope);
    put_be32(bytes + 34, request->reply_destination_vnode);
    put_be32(bytes + 38, request->queue_id);
    put_be32(bytes + 42, request->queue_sequence);
    put_be32(bytes + 46, request->device_index);
    if (data_bytes != 0) {
        if (!data) {
            set_error(error, error_len, "block request data is missing");
            return -1;
        }
        memcpy(bytes + WVM_BLOCK_REQUEST_HEADER_BYTES, data, data_bytes);
    }
    *encoded_bytes = total;
    return 0;
}

int wvm_block_request_decode(
    const uint8_t *bytes, size_t byte_count, struct wvm_block_request *request,
    const uint8_t **data, size_t *data_bytes, char *error, size_t error_len)
{
    struct wvm_block_request decoded;
    size_t carried;

    if (!bytes || !request || !data || !data_bytes) {
        set_error(error, error_len, "block request decode arguments are null");
        return -1;
    }
    if (byte_count < WVM_BLOCK_REQUEST_HEADER_BYTES) {
        set_error(error, error_len, "block request frame is too short");
        return -1;
    }
    memset(&decoded, 0, sizeof(decoded));
    decoded.payload_version = get_be16(bytes + 0);
    decoded.operation = get_be16(bytes + 2);
    decoded.flags = get_be32(bytes + 4);
    decoded.lba_512 = get_be64(bytes + 8);
    decoded.sector_count = get_be32(bytes + 16);
    decoded.payload_bytes = get_be32(bytes + 20);
    decoded.reply_destination_kind = get_be16(bytes + 24);
    decoded.reply_destination_scope = get_be64(bytes + 26);
    decoded.reply_destination_vnode = get_be32(bytes + 34);
    decoded.queue_id = get_be32(bytes + 38);
    decoded.queue_sequence = get_be32(bytes + 42);
    decoded.device_index = get_be32(bytes + 46);

    carried = byte_count - WVM_BLOCK_REQUEST_HEADER_BYTES;
    if (wvm_block_request_validate(&decoded, carried, error, error_len) != 0)
        return -1;
    *request = decoded;
    *data = bytes + WVM_BLOCK_REQUEST_HEADER_BYTES;
    *data_bytes = carried;
    return 0;
}

int wvm_block_completion_encode(
    const struct wvm_block_completion *completion, const uint8_t *data,
    size_t data_bytes, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len)
{
    size_t total;

    if (!completion || !bytes || !encoded_bytes) {
        set_error(error, error_len, "block completion encode arguments are null");
        return -1;
    }
    if (completion->payload_version != WVM_BLOCK_WIRE_VERSION) {
        set_error(error, error_len, "block completion version is not V1");
        return -1;
    }
    if (completion->transferred_bytes != data_bytes) {
        set_error(error, error_len,
                  "block completion byte count disagrees with its data");
        return -1;
    }
    if (data_bytes > WVM_BLOCK_MAX_DATA_BYTES) {
        set_error(error, error_len, "block completion exceeds one datagram");
        return -1;
    }
    total = WVM_BLOCK_COMPLETION_HEADER_BYTES + data_bytes;
    if (total > capacity) {
        set_error(error, error_len, "block completion does not fit the buffer");
        return -1;
    }
    put_be16(bytes + 0, completion->payload_version);
    put_be16(bytes + 2, completion->status);
    put_be32(bytes + 4, completion->transferred_bytes);
    if (data_bytes != 0) {
        if (!data) {
            set_error(error, error_len, "block completion data is missing");
            return -1;
        }
        memcpy(bytes + WVM_BLOCK_COMPLETION_HEADER_BYTES, data, data_bytes);
    }
    *encoded_bytes = total;
    return 0;
}

int wvm_block_completion_decode(
    const uint8_t *bytes, size_t byte_count,
    struct wvm_block_completion *completion, const uint8_t **data,
    size_t *data_bytes, char *error, size_t error_len)
{
    struct wvm_block_completion decoded;
    size_t carried;

    if (!bytes || !completion || !data || !data_bytes) {
        set_error(error, error_len, "block completion decode arguments are null");
        return -1;
    }
    if (byte_count < WVM_BLOCK_COMPLETION_HEADER_BYTES) {
        set_error(error, error_len, "block completion frame is too short");
        return -1;
    }
    decoded.payload_version = get_be16(bytes + 0);
    decoded.status = get_be16(bytes + 2);
    decoded.transferred_bytes = get_be32(bytes + 4);
    carried = byte_count - WVM_BLOCK_COMPLETION_HEADER_BYTES;
    if (decoded.payload_version != WVM_BLOCK_WIRE_VERSION) {
        set_error(error, error_len, "block completion version is not V1");
        return -1;
    }
    if (decoded.transferred_bytes != carried) {
        set_error(error, error_len,
                  "block completion byte count disagrees with the frame");
        return -1;
    }
    if (carried > WVM_BLOCK_MAX_DATA_BYTES) {
        set_error(error, error_len, "block completion exceeds one datagram");
        return -1;
    }
    *completion = decoded;
    *data = bytes + WVM_BLOCK_COMPLETION_HEADER_BYTES;
    *data_bytes = carried;
    return 0;
}

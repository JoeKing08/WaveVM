#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wavevm_manifest.h"
#include "wavevm_lifecycle.h"
#include "wavevm_block_wire.h"
#include "wavevm_block_chunk_store.h"
struct block_runtime_context {
    const struct wvm_node_runtime_manifest *manifest;
    const struct wvm_route_runtime *route_runtime;
    struct memory_network_context *network;
};
static int block_device_is_local(const struct block_runtime_context *context,
                                 uint32_t device_index)
{
    size_t i;

    if (!context || !context->manifest)
        return 0;
    for (i = 0; i < context->manifest->local_storage_assignments.count; i++) {
        if (context->manifest->local_storage_assignments.entries[i]
                .device_index == device_index)
            return 1;
    }
    return 0;
}

static int execute_local_block(void *opaque, uint32_t device_index,
                               uint16_t operation, uint32_t flags,
                               uint64_t lba_512, uint32_t sector_count,
                               const uint8_t *data, size_t data_bytes,
                               uint8_t *out, size_t out_capacity,
                               size_t *out_bytes, char *error, size_t error_len)
{
    struct block_runtime_context *context = opaque;

    if (!block_device_is_local(context, device_index)) {
        if (error && error_len != 0)
            snprintf(error, error_len,
                     "block device %u has no admitted local assignment",
                     device_index);
        return -ENODEV;
    }
    if (operation == WVM_BLOCK_OPERATION_READ)
        return wvm_block_chunk_read(lba_512, sector_count, out, out_capacity,
                                    out_bytes, error, error_len);
    if (operation == WVM_BLOCK_OPERATION_WRITE)
        return wvm_block_chunk_write(lba_512, sector_count, data, data_bytes,
                                     (flags & WVM_BLOCK_ORDER_FUA) != 0, error,
                                     error_len);
    if (sector_count == 0)
        return wvm_block_chunk_flush_all(error, error_len);
    return wvm_block_chunk_flush_range(lba_512, sector_count, error, error_len);
}

int main(int argc, char **argv)
{
    struct wvm_storage_assignment devices[2] = {{0}};
    struct wvm_node_runtime_manifest manifest = {0};
    struct block_runtime_context context = {0};
    uint8_t first[512], second[512], out[512];
    size_t bytes = 0;
    char error[256] = {0};
    int first_rc, second_rc, read_rc;
    if (argc != 2) return 2;
    devices[0].device_index = 0;
    devices[1].device_index = 1;
    manifest.local_storage_assignments.entries = devices;
    manifest.local_storage_assignments.count = 2;
    manifest.local_storage_assignments.capacity = 2;
    context.manifest = &manifest;
    memset(first, 'A', sizeof(first));
    memset(second, 'B', sizeof(second));
    memset(out, 0, sizeof(out));
    if (wvm_block_chunk_store_set_dir(argv[1], error, sizeof(error)) ||
        wvm_block_chunk_store_set_identity("vm7_inc1_vol0", error, sizeof(error)))
        return 3;
    first_rc = execute_local_block(&context, 0, WVM_BLOCK_OPERATION_WRITE, 0,
                                   0, 1, first, 512, NULL, 0, &bytes, error, sizeof(error));
    second_rc = execute_local_block(&context, 1, WVM_BLOCK_OPERATION_WRITE, 0,
                                    0, 1, second, 512, NULL, 0, &bytes, error, sizeof(error));
    read_rc = execute_local_block(&context, 0, WVM_BLOCK_OPERATION_READ, 0,
                                  0, 1, NULL, 0, out, 512, &bytes, error, sizeof(error));
    printf("write_device0_rc=%d write_device1_rc=%d read_device0_rc=%d bytes=%zu expected=A actual=%c aliased=%d\n",
           first_rc, second_rc, read_rc, bytes, out[0], out[0] == 'B');
    return first_rc || second_rc || read_rc ? 4 : 0;
}

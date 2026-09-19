#include "qemu/osdep.h"
#include "qemu/iov.h"
#include <stdlib.h>
#include "../../../common_include/wavevm_protocol.h"

/*
 * virtio-blk hook entry point. Returns 0 when the request is handled by the
 * WaveVM IPC path. Returns -1 to let virtio-blk use its normal local path.
 *
 * Enabled only when WVM_BLOCK_IO=1 is set in the environment.
 */
int wavevm_blk_interceptor(uint64_t sector, QEMUIOVector *qiov, int is_write);

extern int wvm_send_typed_block_request(uint64_t lba_512, void *buf,
                                         uint32_t sector_count, uint32_t operation,
                                         uint32_t flags)
    __attribute__((weak));

extern int wvm_send_ipc_block_io(uint64_t lba, void *buf, uint32_t len, int is_write)
    __attribute__((weak));

static int wvm_block_io_enabled = -1; /* -1 = not checked yet */
static int wvm_block_io_use_typed = -1; /* -1 = not checked, 1 = typed, 0 = legacy */

int wavevm_blk_interceptor(uint64_t sector, QEMUIOVector *qiov, int is_write)
{
    /* Lazy init: check WVM_BLOCK_IO env once */
    if (wvm_block_io_enabled < 0) {
        const char *env = getenv("WVM_BLOCK_IO");
        wvm_block_io_enabled = (env && strcmp(env, "1") == 0) ? 1 : 0;
    }

    if (!wvm_block_io_enabled) {
        return -1; /* fall through to QEMU local block layer */
    }

    /* Check if typed protocol is preferred */
    if (wvm_block_io_use_typed < 0) {
        const char *typed_env = getenv("WVM_BLOCK_TYPED");
        wvm_block_io_use_typed = (typed_env && strcmp(typed_env, "1") == 0) ? 1 : 0;
    }

    size_t total_len = qiov->size;
    uint8_t *linear_buf;
    int ret;

    if (total_len == 0 || total_len > UINT32_MAX) {
        return -1;
    }

    /* Calculate sector count (assuming 512-byte sectors) */
    if (total_len % 512 != 0) {
        return -1; /* Must be sector-aligned */
    }
    uint32_t sector_count = total_len / 512;

    linear_buf = g_malloc(total_len);
    if (!linear_buf) {
        return -1;
    }

    if (is_write) {
        qemu_iovec_to_buf(qiov, 0, linear_buf, total_len);
    }

    /* Try typed protocol first if enabled and available */
    if (wvm_block_io_use_typed && wvm_send_typed_block_request) {
        uint32_t operation = is_write ? WVM_BLOCK_OP_WRITE : WVM_BLOCK_OP_READ;
        uint32_t flags = 0;
        ret = wvm_send_typed_block_request(sector, linear_buf, sector_count, operation, flags);
    } else if (wvm_send_ipc_block_io) {
        /* Fallback to legacy protocol */
        ret = wvm_send_ipc_block_io(sector, linear_buf, (uint32_t)total_len, is_write);
    } else {
        g_free(linear_buf);
        return -1;
    }

    if (!is_write && ret == 0) {
        qemu_iovec_from_buf(qiov, 0, linear_buf, total_len);
    }

    g_free(linear_buf);
    return ret;
}

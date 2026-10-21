#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "qemu/thread.h"
#include <stdlib.h>
#include "../../../common_include/wavevm_protocol.h"

/*
 * virtio-blk hook entry point (A07/A08/R02):
 *   0  = WaveVM handled successfully (guest sees OK)
 *   1  = WaveVM handled remote/transport failure (guest MUST see IOERR;
 *        never fall through to local disk — no silent local fallback)
 *  -1  = not claimed (WVM_BLOCK_IO off or interceptor unavailable)
 *
 * Enabled only when WVM_BLOCK_IO=1 is set in the environment.
 * Typed path is the default when enabled; set WVM_BLOCK_TYPED=0 to force legacy.
 */
int wavevm_blk_interceptor(uint64_t sector, QEMUIOVector *qiov, int is_write);
int wavevm_blk_interceptor_ex(uint64_t sector, QEMUIOVector *qiov, int is_write,
                              uint32_t flags, void *device);
int wavevm_blk_flush_interceptor(void *device);

extern int wvm_send_typed_block_request(uint64_t lba_512, void *buf,
                                         uint32_t sector_count, uint32_t operation,
                                         uint32_t flags, uint32_t device_index)
    __attribute__((weak));

/*
 * V1 device identity for the typed block path.
 *
 * The manifest names devices by index; QEMU names them by object pointer.  This
 * registry assigns indices in realize/first-use order and keeps them stable for
 * the process lifetime, so the manifest assignment and the guest device cannot
 * drift silently.  An exhausted registry returns UINT32_MAX and the request
 * fails closed instead of aliasing another device.
 */
#define WVM_BLOCK_MAX_DEVICES 64U
static void *wvm_block_devices[WVM_BLOCK_MAX_DEVICES];
static uint32_t wvm_block_device_count;
static QemuMutex wvm_block_device_lock;
static GOnce wvm_block_device_once = G_ONCE_INIT;

static gpointer wvm_block_device_lock_init(gpointer unused)
{
    (void)unused;
    qemu_mutex_init(&wvm_block_device_lock);
    return NULL;
}

static uint32_t wvm_block_device_index(void *device)
{
    uint32_t i;
    uint32_t index = UINT32_MAX;

    g_once(&wvm_block_device_once, wvm_block_device_lock_init, NULL);
    qemu_mutex_lock(&wvm_block_device_lock);
    for (i = 0; i < wvm_block_device_count; i++) {
        if (wvm_block_devices[i] == device) {
            index = i;
            break;
        }
    }
    if (index == UINT32_MAX && wvm_block_device_count < WVM_BLOCK_MAX_DEVICES) {
        wvm_block_devices[wvm_block_device_count] = device;
        index = wvm_block_device_count;
        wvm_block_device_count++;
    }
    qemu_mutex_unlock(&wvm_block_device_lock);
    return index;
}

extern int wvm_send_ipc_block_io(uint64_t lba, void *buf, uint32_t len, int is_write)
    __attribute__((weak));

static int wvm_block_io_enabled = -1; /* -1 = not checked yet */
static int wvm_block_io_use_typed = -1; /* -1 = not checked, 1 = typed, 0 = legacy */

static void wvm_block_io_lazy_init(void)
{
    if (wvm_block_io_enabled < 0) {
        const char *env = getenv("WVM_BLOCK_IO");
        wvm_block_io_enabled = (env && strcmp(env, "1") == 0) ? 1 : 0;
    }
    if (wvm_block_io_use_typed < 0) {
        const char *typed_env = getenv("WVM_BLOCK_TYPED");
        /* R02: typed is default when block IO is on; only "0" forces legacy. */
        if (typed_env && strcmp(typed_env, "0") == 0)
            wvm_block_io_use_typed = 0;
        else
            wvm_block_io_use_typed = 1;
    }
}

int wavevm_blk_interceptor_ex(uint64_t sector, QEMUIOVector *qiov, int is_write,
                              uint32_t flags, void *device)
{
    size_t total_len;
    uint8_t *linear_buf;
    uint32_t device_index;
    int ret;

    wvm_block_io_lazy_init();
    if (!wvm_block_io_enabled)
        return -1;

    total_len = qiov->size;
    if (total_len == 0 || total_len > UINT32_MAX)
        return -1;
    if (total_len % 512 != 0)
        return -1;

    uint32_t sector_count = total_len / 512;
    linear_buf = g_malloc(total_len);
    if (!linear_buf)
        return -1;

    if (is_write)
        qemu_iovec_to_buf(qiov, 0, linear_buf, total_len);

    device_index = wvm_block_device_index(device);
    if (device_index == UINT32_MAX) {
        g_free(linear_buf);
        return 1;
    }
    if (wvm_block_io_use_typed && wvm_send_typed_block_request) {
        uint32_t operation = is_write ? WVM_BLOCK_OP_WRITE : WVM_BLOCK_OP_READ;
        ret = wvm_send_typed_block_request(sector, linear_buf, sector_count,
                                           operation, flags, device_index);
    } else if (wvm_send_ipc_block_io) {
        ret = wvm_send_ipc_block_io(sector, linear_buf, (uint32_t)total_len,
                                    is_write);
    } else {
        g_free(linear_buf);
        return -1;
    }

    if (!is_write && ret == 0)
        qemu_iovec_from_buf(qiov, 0, linear_buf, total_len);

    g_free(linear_buf);
    if (ret != 0)
        return 1;
    return 0;
}

int wavevm_blk_interceptor(uint64_t sector, QEMUIOVector *qiov, int is_write)
{
    return wavevm_blk_interceptor_ex(sector, qiov, is_write, 0, NULL);
}

/* R02: guest FLUSH must hit remote storage, not local virtio_blk_handle_flush. */
int wavevm_blk_flush_interceptor(void *device)
{
    uint32_t device_index;
    int ret;

    wvm_block_io_lazy_init();
    if (!wvm_block_io_enabled)
        return -1;

    device_index = wvm_block_device_index(device);
    if (device_index == UINT32_MAX)
        return 1;
    if (wvm_block_io_use_typed && wvm_send_typed_block_request) {
        ret = wvm_send_typed_block_request(0, NULL, 0, WVM_BLOCK_OP_FLUSH, 0,
                                           device_index);
        return ret == 0 ? 0 : 1;
    }
    /* Legacy path has no dedicated flush IPC — claim failure rather than
     * silently flushing the local disk under WaveVM block authority. */
    return 1;
}

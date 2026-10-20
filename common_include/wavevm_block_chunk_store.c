#define _POSIX_C_SOURCE 200809L
#include "wavevm_block_chunk_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_chunk_dir[512] = "/var/lib/wavevm/chunks";

static void set_error(char *error, size_t error_len, const char *msg)
{
    if (error && error_len)
        snprintf(error, error_len, "%s", msg ? msg : "block chunk error");
}

int wvm_block_chunk_store_set_dir(const char *dir, char *error, size_t error_len)
{
    if (!dir || !dir[0] || strlen(dir) >= sizeof(g_chunk_dir)) {
        set_error(error, error_len, "chunk dir invalid");
        return -1;
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        set_error(error, error_len, "cannot create chunk dir");
        return -1;
    }
    snprintf(g_chunk_dir, sizeof(g_chunk_dir), "%s", dir);
    return 0;
}

const char *wvm_block_chunk_store_dir(void)
{
    return g_chunk_dir;
}

static int open_chunk(uint64_t chunk_id, int *fd_out, char *error,
                      size_t error_len)
{
    char path[640];
    int fd;

    snprintf(path, sizeof(path), "%s/c_%llu.bin", g_chunk_dir,
             (unsigned long long)chunk_id);
    fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        set_error(error, error_len, "cannot open chunk file");
        return -1;
    }
    *fd_out = fd;
    return 0;
}

static void map_lba(uint64_t lba_512, uint64_t *chunk_id, off_t *offset)
{
    *chunk_id = (lba_512 << 9) >> WVM_STORAGE_CHUNK_SHIFT;
    *offset = (off_t)((lba_512 << 9) & ((1ULL << WVM_STORAGE_CHUNK_SHIFT) - 1));
}

int wvm_block_chunk_write(uint64_t lba_512, uint32_t sector_count,
                          const uint8_t *data, size_t data_bytes, int fua,
                          char *error, size_t error_len)
{
    uint64_t chunk_id;
    off_t offset;
    size_t need;
    int fd = -1;
    ssize_t n;

    if (!data || sector_count == 0 || sector_count > (64U << 20) / 512) {
        set_error(error, error_len, "write args invalid");
        return -1;
    }
    need = (size_t)sector_count * 512;
    if (data_bytes != need) {
        set_error(error, error_len, "write payload length mismatch");
        return -1;
    }
    map_lba(lba_512, &chunk_id, &offset);
    if (open_chunk(chunk_id, &fd, error, error_len) != 0)
        return -1;
    n = pwrite(fd, data, need, offset);
    if (n != (ssize_t)need) {
        close(fd);
        set_error(error, error_len, "pwrite incomplete");
        return -1;
    }
    if (fua) {
        if (fdatasync(fd) != 0) {
            close(fd);
            set_error(error, error_len, "FUA fdatasync failed");
            return -1;
        }
    }
    close(fd);
    return 0;
}

int wvm_block_chunk_read(uint64_t lba_512, uint32_t sector_count, uint8_t *data,
                         size_t data_cap, size_t *out_bytes, char *error,
                         size_t error_len)
{
    uint64_t chunk_id;
    off_t offset;
    size_t need;
    int fd = -1;
    ssize_t n;

    if (!data || !out_bytes || sector_count == 0 ||
        sector_count > (64U << 20) / 512) {
        set_error(error, error_len, "read args invalid");
        return -1;
    }
    need = (size_t)sector_count * 512;
    if (data_cap < need) {
        set_error(error, error_len, "read buffer too small");
        return -1;
    }
    map_lba(lba_512, &chunk_id, &offset);
    if (open_chunk(chunk_id, &fd, error, error_len) != 0)
        return -1;
    memset(data, 0, need);
    n = pread(fd, data, need, offset);
    close(fd);
    if (n < 0) {
        set_error(error, error_len, "pread failed");
        return -1;
    }
    *out_bytes = need;
    return 0;
}

int wvm_block_chunk_flush(uint64_t lba_512, char *error, size_t error_len)
{
    uint64_t chunk_id;
    off_t offset;
    int fd = -1;

    map_lba(lba_512, &chunk_id, &offset);
    (void)offset;
    if (open_chunk(chunk_id, &fd, error, error_len) != 0)
        return -1;
    if (fdatasync(fd) != 0) {
        close(fd);
        set_error(error, error_len, "flush fdatasync failed");
        return -1;
    }
    close(fd);
    return 0;
}

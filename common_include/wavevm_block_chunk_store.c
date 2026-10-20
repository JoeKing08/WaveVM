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

/* Optional identity prefix for isolated backend naming (R02). Empty = legacy. */
static char g_identity_prefix[256] = "";

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

int wvm_block_chunk_store_set_identity(const char *identity_prefix,
                                       char *error, size_t error_len)
{
    if (!identity_prefix) {
        g_identity_prefix[0] = '\0';
        return 0;
    }
    if (strlen(identity_prefix) >= sizeof(g_identity_prefix)) {
        set_error(error, error_len, "chunk identity prefix too long");
        return -1;
    }
    /* Allow only safe path-component characters. */
    for (const char *p = identity_prefix; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
            set_error(error, error_len, "chunk identity has invalid chars");
            return -1;
        }
    }
    snprintf(g_identity_prefix, sizeof(g_identity_prefix), "%s",
             identity_prefix);
    return 0;
}

const char *wvm_block_chunk_store_identity(void)
{
    return g_identity_prefix;
}

static int open_chunk(uint64_t chunk_id, int *fd_out, char *error,
                      size_t error_len)
{
    char path[896];
    int fd;

    if (g_identity_prefix[0]) {
        snprintf(path, sizeof(path), "%s/%s/c_%llu.bin", g_chunk_dir,
                 g_identity_prefix, (unsigned long long)chunk_id);
        {
            char idir[768];
            snprintf(idir, sizeof(idir), "%s/%s", g_chunk_dir,
                     g_identity_prefix);
            if (mkdir(idir, 0755) != 0 && errno != EEXIST) {
                set_error(error, error_len, "cannot create identity chunk dir");
                return -1;
            }
        }
    } else {
        snprintf(path, sizeof(path), "%s/c_%llu.bin", g_chunk_dir,
                 (unsigned long long)chunk_id);
    }
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

/* Bytes remaining in the current chunk from offset to chunk end. */
static size_t bytes_to_chunk_end(off_t offset)
{
    const uint64_t chunk_bytes = 1ULL << WVM_STORAGE_CHUNK_SHIFT;
    if ((uint64_t)offset >= chunk_bytes)
        return 0;
    return (size_t)(chunk_bytes - (uint64_t)offset);
}

int wvm_block_chunk_write(uint64_t lba_512, uint32_t sector_count,
                          const uint8_t *data, size_t data_bytes, int fua,
                          char *error, size_t error_len)
{
    size_t need;
    size_t done = 0;
    uint64_t cur_lba;
    uint32_t remaining;

    if (!data || sector_count == 0 || sector_count > (64U << 20) / 512) {
        set_error(error, error_len, "write args invalid");
        return -1;
    }
    need = (size_t)sector_count * 512;
    if (data_bytes != need) {
        set_error(error, error_len, "write payload length mismatch");
        return -1;
    }

    /*
     * R01: segment at 64 MiB chunk boundaries. A single pwrite from the start
     * LBA's file would spill past EOF of that chunk file; the next chunk's
     * file would then miss those bytes on read.
     */
    cur_lba = lba_512;
    remaining = sector_count;
    while (remaining > 0) {
        uint64_t chunk_id;
        off_t offset;
        size_t bytes_this;
        uint32_t sectors_this;
        int fd = -1;
        ssize_t n;

        map_lba(cur_lba, &chunk_id, &offset);
        bytes_this = bytes_to_chunk_end(offset);
        if (bytes_this == 0) {
            set_error(error, error_len, "chunk offset invalid");
            return -1;
        }
        if (bytes_this > (size_t)remaining * 512)
            bytes_this = (size_t)remaining * 512;
        /* Always transfer whole sectors. */
        bytes_this -= bytes_this % 512;
        if (bytes_this == 0) {
            set_error(error, error_len, "chunk segment empty");
            return -1;
        }
        sectors_this = (uint32_t)(bytes_this / 512);

        if (open_chunk(chunk_id, &fd, error, error_len) != 0)
            return -1;
        n = pwrite(fd, data + done, bytes_this, offset);
        if (n != (ssize_t)bytes_this) {
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

        done += bytes_this;
        cur_lba += sectors_this;
        remaining -= sectors_this;
    }
    return 0;
}

int wvm_block_chunk_read(uint64_t lba_512, uint32_t sector_count, uint8_t *data,
                         size_t data_cap, size_t *out_bytes, char *error,
                         size_t error_len)
{
    size_t need;
    size_t done = 0;
    uint64_t cur_lba;
    uint32_t remaining;

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
    memset(data, 0, need);

    cur_lba = lba_512;
    remaining = sector_count;
    while (remaining > 0) {
        uint64_t chunk_id;
        off_t offset;
        size_t bytes_this;
        uint32_t sectors_this;
        int fd = -1;
        ssize_t n;

        map_lba(cur_lba, &chunk_id, &offset);
        bytes_this = bytes_to_chunk_end(offset);
        if (bytes_this == 0) {
            set_error(error, error_len, "chunk offset invalid");
            return -1;
        }
        if (bytes_this > (size_t)remaining * 512)
            bytes_this = (size_t)remaining * 512;
        bytes_this -= bytes_this % 512;
        if (bytes_this == 0) {
            set_error(error, error_len, "chunk segment empty");
            return -1;
        }
        sectors_this = (uint32_t)(bytes_this / 512);

        if (open_chunk(chunk_id, &fd, error, error_len) != 0)
            return -1;
        n = pread(fd, data + done, bytes_this, offset);
        close(fd);
        if (n < 0) {
            set_error(error, error_len, "pread failed");
            return -1;
        }
        /* Short read leaves zeros from memset — treat as sparse OK. */

        done += bytes_this;
        cur_lba += sectors_this;
        remaining -= sectors_this;
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

int wvm_block_chunk_flush_range(uint64_t lba_512, uint32_t sector_count,
                                char *error, size_t error_len)
{
    uint32_t flush_count = sector_count == 0 ? 1 : sector_count;
    uint64_t end_lba = lba_512 + flush_count;
    uint64_t cur = lba_512;

    while (cur < end_lba) {
        uint64_t chunk_id = (cur << 9) >> WVM_STORAGE_CHUNK_SHIFT;
        uint64_t next_chunk_base =
            ((chunk_id + 1) << WVM_STORAGE_CHUNK_SHIFT) >> 9;

        if (wvm_block_chunk_flush(cur, error, error_len) != 0)
            return -1;
        if (next_chunk_base <= cur)
            break;
        cur = next_chunk_base;
    }
    return 0;
}

#include <dirent.h>

int wvm_block_chunk_flush_all(char *error, size_t error_len)
{
    char dirpath[768];
    DIR *d;
    struct dirent *ent;
    int any = 0;
    int failed = 0;

    if (g_identity_prefix[0])
        snprintf(dirpath, sizeof(dirpath), "%s/%s", g_chunk_dir, g_identity_prefix);
    else
        snprintf(dirpath, sizeof(dirpath), "%s", g_chunk_dir);

    d = opendir(dirpath);
    if (!d) {
        /* Empty store: nothing to flush. */
        if (errno == ENOENT)
            return 0;
        set_error(error, error_len, "cannot open chunk dir for flush_all");
        return -1;
    }
    while ((ent = readdir(d)) != NULL) {
        char path[1100];
        int fd;
        int n;
        if (strncmp(ent->d_name, "c_", 2) != 0)
            continue;
        n = snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            failed = 1;
            continue;
        }
        fd = open(path, O_RDWR);
        if (fd < 0) {
            failed = 1;
            continue;
        }
        if (fdatasync(fd) != 0)
            failed = 1;
        close(fd);
        any = 1;
    }
    closedir(d);
    (void)any;
    if (failed) {
        set_error(error, error_len, "flush_all fdatasync failed");
        return -1;
    }
    return 0;
}

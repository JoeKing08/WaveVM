#ifndef WAVEVM_BLOCK_CHUNK_STORE_H
#define WAVEVM_BLOCK_CHUNK_STORE_H

#include <stddef.h>
#include <stdint.h>

#ifndef WVM_STORAGE_CHUNK_SHIFT
#define WVM_STORAGE_CHUNK_SHIFT 26
#endif

/*
 * File-backed remote block chunk store (storage-device-authority.md).
 * Used by slave executors and control-plane oracles. Chunk directory defaults
 * to /var/lib/wavevm/chunks; override with WVM_STORAGE_CHUNK_DIR.
 */
int wvm_block_chunk_store_set_dir(const char *dir, char *error, size_t error_len);
const char *wvm_block_chunk_store_dir(void);

int wvm_block_chunk_write(uint64_t lba_512, uint32_t sector_count,
                          const uint8_t *data, size_t data_bytes, int fua,
                          char *error, size_t error_len);
int wvm_block_chunk_read(uint64_t lba_512, uint32_t sector_count, uint8_t *data,
                         size_t data_cap, size_t *out_bytes, char *error,
                         size_t error_len);
int wvm_block_chunk_flush(uint64_t lba_512, char *error, size_t error_len);

#endif

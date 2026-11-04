#ifndef WAVEVM_NODE_RUNTIME_KVM_PAGE_CACHE_H
#define WAVEVM_NODE_RUNTIME_KVM_PAGE_CACHE_H

#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_memory.h"

#define WVM_KVM_PAGE_OPERATION_ID_BYTES 16U

enum wvm_kvm_page_state {
    WVM_KVM_PAGE_ABSENT = 0,
    WVM_KVM_PAGE_CLEAN = 1,
    WVM_KVM_PAGE_DIRTY = 2,
    WVM_KVM_PAGE_SUBMITTING = 3,
    WVM_KVM_PAGE_RESYNC = 4,
};

struct wvm_kvm_page_cache;
struct wvm_kvm_memory_slice;

struct wvm_kvm_page_cache_config {
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t max_page_records;
    uint64_t completion_timeout_ms;
};

struct wvm_kvm_dirty_page {
    uint64_t gpa;
    uint64_t base_version;
    uint8_t operation_id[WVM_KVM_PAGE_OPERATION_ID_BYTES];
    uint64_t delivery_attempt_id;
};

int wvm_kvm_page_cache_init(
    struct wvm_kvm_page_cache *cache,
    const struct wvm_kvm_page_cache_config *config, char *error,
    size_t error_len);
void wvm_kvm_page_cache_destroy(struct wvm_kvm_page_cache *cache);
struct wvm_kvm_page_cache *wvm_kvm_page_cache_create(
    const struct wvm_kvm_page_cache_config *config, char *error,
    size_t error_len);
void wvm_kvm_page_cache_free(struct wvm_kvm_page_cache *cache);

/*
 * Install only authoritative snapshots. A stale duplicate returns -EALREADY
 * and must not overwrite the local page. A snapshot racing a dirty slice
 * returns -EBUSY and leaves that slice in RESYNC.
 */
int wvm_kvm_page_cache_install_full(
    struct wvm_kvm_page_cache *cache, uint64_t gpa, uint64_t version,
    char *error, size_t error_len);
int wvm_kvm_page_cache_apply_diff(
    struct wvm_kvm_page_cache *cache, uint64_t gpa, uint64_t version,
    uint16_t offset, size_t data_bytes, int zero_page, char *error,
    size_t error_len);
int wvm_kvm_page_cache_invalidate(
    struct wvm_kvm_page_cache *cache, uint64_t gpa, char *error,
    size_t error_len);
int wvm_kvm_page_cache_lookup(
    const struct wvm_kvm_page_cache *cache, uint64_t gpa, uint8_t *state_out,
    uint64_t *version_out, char *error, size_t error_len);

int wvm_kvm_memory_slice_begin(
    struct wvm_kvm_page_cache *cache,
    struct wvm_kvm_memory_slice **slice_out, char *error, size_t error_len);
int wvm_kvm_memory_slice_capture_dirty(
    struct wvm_kvm_memory_slice *slice, uint64_t gpa,
    struct wvm_kvm_dirty_page *dirty_page, char *error, size_t error_len);
int wvm_kvm_memory_slice_fail(
    struct wvm_kvm_memory_slice *slice, uint64_t gpa, char *error,
    size_t error_len);
int wvm_kvm_memory_slice_complete_dirty(
    struct wvm_kvm_memory_slice *slice,
    const struct wvm_kvm_dirty_page *dirty_page, uint16_t status,
    uint64_t result_version, char *error, size_t error_len);
int wvm_kvm_memory_slice_seal(
    struct wvm_kvm_memory_slice *slice, char *error, size_t error_len);
int wvm_kvm_memory_slice_wait(
    struct wvm_kvm_memory_slice *slice, int *success_out, uint64_t *error_gpa,
    char *error, size_t error_len);
void wvm_kvm_memory_slice_destroy(struct wvm_kvm_memory_slice *slice);

/*
 * The legacy executor is compiled into node_runtime. These wrappers expose
 * the one admitted cache instance without creating a second memory authority.
 */
int wvm_kvm_page_cache_global_install(
    const struct wvm_kvm_page_cache_config *config, char *error,
    size_t error_len);
void wvm_kvm_page_cache_global_uninstall(void);
int wvm_kvm_page_cache_global_active(void);
int wvm_kvm_page_cache_global_install_full(
    uint64_t gpa, uint64_t version, char *error, size_t error_len);
int wvm_kvm_page_cache_global_apply_diff(
    uint64_t gpa, uint64_t version, uint16_t offset, size_t data_bytes,
    int zero_page, char *error, size_t error_len);
int wvm_kvm_page_cache_global_invalidate(
    uint64_t gpa, char *error, size_t error_len);
int wvm_kvm_page_cache_global_lookup(
    uint64_t gpa, uint8_t *state_out, uint64_t *version_out, char *error,
    size_t error_len);
/* Byte installation and execution admission share the same short lock. */
int wvm_kvm_page_cache_global_install_data(
    uint64_t gpa, uint64_t version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, int full_page, uint8_t *hva, uint8_t *mirror,
    char *error, size_t error_len);

typedef int (*wvm_kvm_prepare_input_fn)(void *opaque, uint64_t *error_gpa);
/* One cohort shares a snapshot and dirty-log commit, not a KVM_RUN lock.
 * Even a failed join may return a slice which must leave/wait/release. */
int wvm_kvm_execution_global_join(
    wvm_kvm_prepare_input_fn prepare, void *opaque,
    struct wvm_kvm_memory_slice **slice_out, uint64_t *error_gpa,
    char *error, size_t error_len);
/* Returns 1 only to the last exiting vCPU, which harvests the shared log. */
int wvm_kvm_execution_leave(struct wvm_kvm_memory_slice *slice,
                            int status, uint64_t error_gpa);
void wvm_kvm_execution_complete(struct wvm_kvm_memory_slice *slice,
                                 int status, uint64_t error_gpa);
int wvm_kvm_execution_wait(struct wvm_kvm_memory_slice *slice,
                            uint64_t *error_gpa);
void wvm_kvm_execution_release(struct wvm_kvm_memory_slice *slice);
int wvm_kvm_memory_slice_global_begin(
    struct wvm_kvm_memory_slice **slice_out, char *error, size_t error_len);

#endif

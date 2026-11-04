#define _POSIX_C_SOURCE 200809L

#include "kvm_page_cache.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CACHE_INITIAL_BUCKETS 256U
#define CACHE_MAX_BUCKETS (1U << 20)

struct cache_page {
    struct cache_page *next;
    struct wvm_kvm_memory_slice *slice;
    uint64_t gpa;
    uint64_t version;
    uint8_t state;
};

struct wvm_kvm_page_cache {
    struct wvm_kvm_page_cache_config config;
    pthread_mutex_t lock;
    pthread_cond_t completed;
    struct cache_page **buckets;
    size_t bucket_count;
    uint64_t page_count;
    uint64_t next_slice_id;
    int execution_active;
    struct wvm_kvm_memory_slice *execution_slice;
    int initialized;
};

struct wvm_kvm_memory_slice {
    struct wvm_kvm_page_cache *cache;
    uint64_t id;
    uint64_t pending;
    uint64_t error_gpa;
    int failed;
    int sealed;
    int destroy_requested;
    unsigned participants;
    unsigned running;
    int preparing;
    int closing;
    int execution_complete;
    int execution_status;
};

struct global_cache {
    pthread_mutex_t lock;
    struct wvm_kvm_page_cache cache;
    int active;
};

static struct global_cache g_global_cache = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        snprintf(error, error_len, "%s", message);
    }
}

static size_t hash_gpa(uint64_t gpa, size_t bucket_count)
{
    gpa ^= gpa >> 33;
    gpa *= UINT64_C(0xff51afd7ed558ccd);
    gpa ^= gpa >> 33;
    return (size_t)(gpa & (bucket_count - 1U));
}

static int valid_gpa(uint64_t gpa)
{
    return (gpa % WVM_MEMORY_PAGE_BYTES) == 0;
}

static int valid_version(uint64_t version)
{
    return version != 0;
}

static int next_version(uint64_t current, uint64_t candidate)
{
    return current != UINT64_MAX && candidate == current + 1U;
}

static void mark_slice_failed_locked(struct wvm_kvm_memory_slice *slice,
                                     uint64_t gpa)
{
    if (!slice) {
        return;
    }
    slice->failed = 1;
    if (slice->participants != 0) {
        slice->closing = 1;
    }
    if (slice->error_gpa == 0) {
        slice->error_gpa = gpa;
    }
}

static struct cache_page *find_page_locked(
    struct wvm_kvm_page_cache *cache, uint64_t gpa)
{
    struct cache_page *page;

    page = cache->buckets[hash_gpa(gpa, cache->bucket_count)];
    while (page) {
        if (page->gpa == gpa) {
            return page;
        }
        page = page->next;
    }
    return NULL;
}

static struct cache_page *allocate_page_locked(
    struct wvm_kvm_page_cache *cache, uint64_t gpa)
{
    struct cache_page *page;
    size_t bucket;

    if (cache->page_count >= cache->config.max_page_records) {
        return NULL;
    }
    page = calloc(1, sizeof(*page));
    if (!page) {
        return NULL;
    }
    page->gpa = gpa;
    page->state = WVM_KVM_PAGE_ABSENT;
    bucket = hash_gpa(gpa, cache->bucket_count);
    page->next = cache->buckets[bucket];
    cache->buckets[bucket] = page;
    cache->page_count++;
    return page;
}

static int deadline_from_now(uint64_t timeout_ms, struct timespec *deadline)
{
    uint64_t nanoseconds;

    if (!deadline || timeout_ms > UINT64_MAX / 1000000U ||
        clock_gettime(CLOCK_REALTIME, deadline) != 0) {
        return -1;
    }
    nanoseconds = (uint64_t)deadline->tv_nsec + timeout_ms * 1000000U;
    deadline->tv_sec += (time_t)(nanoseconds / 1000000000U);
    deadline->tv_nsec = (long)(nanoseconds % 1000000000U);
    return 0;
}

int wvm_kvm_page_cache_init(
    struct wvm_kvm_page_cache *cache,
    const struct wvm_kvm_page_cache_config *config, char *error,
    size_t error_len)
{
    size_t bucket_count = CACHE_INITIAL_BUCKETS;

    if (!cache || !config || config->vm_id == 0 ||
        config->vm_incarnation == 0 || config->max_page_records == 0 ||
        config->completion_timeout_ms == 0) {
        set_error(error, error_len, "KVM page cache configuration is invalid");
        return -EINVAL;
    }
    while (bucket_count < config->max_page_records / 4U &&
           bucket_count < CACHE_MAX_BUCKETS) {
        bucket_count <<= 1;
    }
    memset(cache, 0, sizeof(*cache));
    cache->config = *config;
    cache->bucket_count = bucket_count;
    cache->buckets = calloc(bucket_count, sizeof(*cache->buckets));
    if (!cache->buckets ||
        pthread_mutex_init(&cache->lock, NULL) != 0 ||
        pthread_cond_init(&cache->completed, NULL) != 0) {
        free(cache->buckets);
        cache->buckets = NULL;
        set_error(error, error_len, "KVM page cache allocation failed");
        return -ENOMEM;
    }
    cache->next_slice_id = 1;
    cache->initialized = 1;
    return 0;
}

void wvm_kvm_page_cache_destroy(struct wvm_kvm_page_cache *cache)
{
    size_t i;

    if (!cache || !cache->initialized) {
        return;
    }
    pthread_mutex_lock(&cache->lock);
    for (i = 0; i < cache->bucket_count; i++) {
        struct cache_page *page = cache->buckets[i];

        while (page) {
            struct cache_page *next = page->next;

            free(page);
            page = next;
        }
    }
    free(cache->buckets);
    cache->buckets = NULL;
    cache->initialized = 0;
    pthread_mutex_unlock(&cache->lock);
    pthread_cond_destroy(&cache->completed);
    pthread_mutex_destroy(&cache->lock);
}

struct wvm_kvm_page_cache *wvm_kvm_page_cache_create(
    const struct wvm_kvm_page_cache_config *config, char *error,
    size_t error_len)
{
    struct wvm_kvm_page_cache *cache;

    cache = calloc(1, sizeof(*cache));
    if (!cache) {
        set_error(error, error_len, "KVM page cache allocation failed");
        return NULL;
    }
    if (wvm_kvm_page_cache_init(cache, config, error, error_len) != 0) {
        free(cache);
        return NULL;
    }
    return cache;
}

void wvm_kvm_page_cache_free(struct wvm_kvm_page_cache *cache)
{
    if (!cache) {
        return;
    }
    wvm_kvm_page_cache_destroy(cache);
    free(cache);
}

int wvm_kvm_page_cache_install_full(
    struct wvm_kvm_page_cache *cache, uint64_t gpa, uint64_t version,
    char *error, size_t error_len)
{
    struct cache_page *page;
    int result = 0;

    if (!cache || !cache->initialized || !valid_gpa(gpa) ||
        !valid_version(version)) {
        set_error(error, error_len, "KVM full snapshot is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&cache->lock);
    page = find_page_locked(cache, gpa);
    if (page && page->state == WVM_KVM_PAGE_CLEAN &&
        version <= page->version) {
        pthread_mutex_unlock(&cache->lock);
        return -EALREADY;
    }
    if (cache->execution_active) {
        mark_slice_failed_locked(cache->execution_slice, gpa);
        if (page) {
            mark_slice_failed_locked(page->slice, gpa);
            page->state = WVM_KVM_PAGE_RESYNC;
            page->version = 0;
        }
        pthread_cond_broadcast(&cache->completed);
        pthread_mutex_unlock(&cache->lock);
        set_error(error, error_len,
                  "KVM snapshot arrived during execution");
        return -EBUSY;
    }
    if (!page) {
        page = allocate_page_locked(cache, gpa);
    }
    if (!page) {
        pthread_mutex_unlock(&cache->lock);
        set_error(error, error_len, "KVM page cache is full");
        return -EAGAIN;
    }
    if (page->state == WVM_KVM_PAGE_DIRTY ||
        page->state == WVM_KVM_PAGE_SUBMITTING ||
        (page->state == WVM_KVM_PAGE_RESYNC && page->slice != NULL)) {
        mark_slice_failed_locked(page->slice, gpa);
        page->state = WVM_KVM_PAGE_RESYNC;
        pthread_cond_broadcast(&cache->completed);
        result = -EBUSY;
    } else if (page->state == WVM_KVM_PAGE_CLEAN &&
               version <= page->version) {
        result = -EALREADY;
    } else {
        page->version = version;
        page->state = WVM_KVM_PAGE_CLEAN;
    }
    pthread_mutex_unlock(&cache->lock);
    if (result == -EBUSY) {
        set_error(error, error_len, "KVM snapshot races a dirty slice");
    }
    return result;
}

int wvm_kvm_page_cache_apply_diff(
    struct wvm_kvm_page_cache *cache, uint64_t gpa, uint64_t version,
    uint16_t offset, size_t data_bytes, int zero_page, char *error,
    size_t error_len)
{
    struct cache_page *page;

    if (!cache || !cache->initialized || !valid_gpa(gpa) ||
        !valid_version(version) || offset > WVM_MEMORY_PAGE_BYTES ||
        data_bytes > WVM_MEMORY_PAGE_BYTES - offset ||
        (!zero_page && data_bytes == 0)) {
        set_error(error, error_len, "KVM page diff is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&cache->lock);
    page = find_page_locked(cache, gpa);
    if (page && page->state == WVM_KVM_PAGE_CLEAN &&
        version <= page->version) {
        pthread_mutex_unlock(&cache->lock);
        return -EALREADY;
    }
    if (cache->execution_active) {
        mark_slice_failed_locked(cache->execution_slice, gpa);
        if (page) {
            mark_slice_failed_locked(page->slice, gpa);
            page->state = WVM_KVM_PAGE_RESYNC;
            page->version = 0;
        }
        pthread_cond_broadcast(&cache->completed);
        pthread_mutex_unlock(&cache->lock);
        set_error(error, error_len,
                  "KVM page diff arrived during execution");
        return -EBUSY;
    }
    if (!page || page->state != WVM_KVM_PAGE_CLEAN) {
        if (page && page->slice) {
            mark_slice_failed_locked(page->slice, gpa);
            page->state = WVM_KVM_PAGE_RESYNC;
        }
        pthread_mutex_unlock(&cache->lock);
        set_error(error, error_len, "KVM page diff has no clean base");
        return -ESTALE;
    }
    if (version <= page->version) {
        pthread_mutex_unlock(&cache->lock);
        return -EALREADY;
    }
    if (!next_version(page->version, version)) {
        page->state = WVM_KVM_PAGE_RESYNC;
        pthread_mutex_unlock(&cache->lock);
        set_error(error, error_len, "KVM page diff has a version gap");
        return -ESTALE;
    }
    page->version = version;
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

int wvm_kvm_page_cache_invalidate(
    struct wvm_kvm_page_cache *cache, uint64_t gpa, char *error,
    size_t error_len)
{
    struct cache_page *page;

    if (!cache || !cache->initialized || !valid_gpa(gpa)) {
        set_error(error, error_len, "KVM page invalidation is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&cache->lock);
    page = find_page_locked(cache, gpa);
    if (cache->execution_slice &&
        !cache->execution_slice->execution_complete) {
        mark_slice_failed_locked(cache->execution_slice, gpa);
    }
    if (cache->execution_active) {
        if (page) {
            mark_slice_failed_locked(page->slice, gpa);
            page->state = WVM_KVM_PAGE_RESYNC;
            page->version = 0;
        }
        pthread_cond_broadcast(&cache->completed);
        pthread_mutex_unlock(&cache->lock);
        set_error(error, error_len,
                  "KVM invalidation arrived during execution");
        return -EBUSY;
    }
    if (page) {
        if (page->slice) {
            mark_slice_failed_locked(page->slice, gpa);
            page->state = WVM_KVM_PAGE_RESYNC;
            page->version = 0;
        } else {
            page->state = WVM_KVM_PAGE_ABSENT;
            page->version = 0;
        }
    }
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

int wvm_kvm_page_cache_lookup(
    const struct wvm_kvm_page_cache *cache, uint64_t gpa, uint8_t *state_out,
    uint64_t *version_out, char *error, size_t error_len)
{
    struct cache_page *page;
    struct wvm_kvm_page_cache *mutable_cache =
        (struct wvm_kvm_page_cache *)(uintptr_t)cache;

    if (!cache || !cache->initialized || !state_out || !version_out ||
        !valid_gpa(gpa)) {
        set_error(error, error_len, "KVM page lookup is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&mutable_cache->lock);
    page = find_page_locked(mutable_cache, gpa);
    if (!page) {
        *state_out = WVM_KVM_PAGE_ABSENT;
        *version_out = 0;
        pthread_mutex_unlock(&mutable_cache->lock);
        return 0;
    }
    *state_out = page->state;
    *version_out = page->version;
    pthread_mutex_unlock(&mutable_cache->lock);
    return 0;
}

int wvm_kvm_memory_slice_begin(
    struct wvm_kvm_page_cache *cache,
    struct wvm_kvm_memory_slice **slice_out, char *error, size_t error_len)
{
    struct wvm_kvm_memory_slice *slice;

    if (!cache || !cache->initialized || !slice_out) {
        set_error(error, error_len, "KVM memory slice input is invalid");
        return -EINVAL;
    }
    slice = calloc(1, sizeof(*slice));
    if (!slice) {
        set_error(error, error_len, "KVM memory slice allocation failed");
        return -ENOMEM;
    }
    pthread_mutex_lock(&cache->lock);
    slice->cache = cache;
    slice->id = cache->next_slice_id++;
    if (slice->id == 0) {
        slice->id = cache->next_slice_id++;
    }
    pthread_mutex_unlock(&cache->lock);
    *slice_out = slice;
    return 0;
}

int wvm_kvm_memory_slice_capture_dirty(
    struct wvm_kvm_memory_slice *slice, uint64_t gpa,
    struct wvm_kvm_dirty_page *dirty_page, char *error, size_t error_len)
{
    struct cache_page *page;
    uint64_t operation_prefix;

    if (!slice || !slice->cache || !dirty_page || !valid_gpa(gpa)) {
        set_error(error, error_len, "KVM dirty page input is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&slice->cache->lock);
    page = find_page_locked(slice->cache, gpa);
    if (!page || page->state != WVM_KVM_PAGE_CLEAN ||
        page->version == 0 || slice->sealed || slice->failed) {
        mark_slice_failed_locked(slice, gpa);
        pthread_mutex_unlock(&slice->cache->lock);
        set_error(error, error_len,
                  "KVM dirty page has no authoritative clean base");
        return -ESTALE;
    }
    page->state = WVM_KVM_PAGE_DIRTY;
    page->slice = slice;
    memset(dirty_page, 0, sizeof(*dirty_page));
    dirty_page->gpa = gpa;
    dirty_page->base_version = page->version;
    operation_prefix = slice->id ^ slice->cache->config.vm_incarnation;
    if (operation_prefix == 0) {
        operation_prefix = 1;
    }
    memcpy(dirty_page->operation_id, &operation_prefix, sizeof(operation_prefix));
    memcpy(dirty_page->operation_id + sizeof(operation_prefix), &gpa,
           sizeof(gpa));
    dirty_page->delivery_attempt_id = 1;
    slice->pending++;
    pthread_mutex_unlock(&slice->cache->lock);
    return 0;
}

int wvm_kvm_memory_slice_fail(
    struct wvm_kvm_memory_slice *slice, uint64_t gpa, char *error,
    size_t error_len)
{
    if (!slice || !slice->cache) {
        set_error(error, error_len, "KVM memory slice failure is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&slice->cache->lock);
    mark_slice_failed_locked(slice, gpa);
    pthread_cond_broadcast(&slice->cache->completed);
    pthread_mutex_unlock(&slice->cache->lock);
    return 0;
}

int wvm_kvm_memory_slice_complete_dirty(
    struct wvm_kvm_memory_slice *slice,
    const struct wvm_kvm_dirty_page *dirty_page, uint16_t status,
    uint64_t result_version, char *error, size_t error_len)
{
    struct cache_page *page;
    int success = status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                  result_version != 0;
    int release_slice = 0;

    if (!slice || !slice->cache || !dirty_page ||
        !valid_gpa(dirty_page->gpa)) {
        set_error(error, error_len, "KVM dirty completion is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&slice->cache->lock);
    page = find_page_locked(slice->cache, dirty_page->gpa);
    if (!page || page->slice != slice ||
        (page->state != WVM_KVM_PAGE_DIRTY &&
         page->state != WVM_KVM_PAGE_SUBMITTING &&
         page->state != WVM_KVM_PAGE_RESYNC)) {
        pthread_mutex_unlock(&slice->cache->lock);
        set_error(error, error_len, "KVM dirty completion is not pending");
        return -ENOENT;
    }
    if (success && !slice->failed && page->state != WVM_KVM_PAGE_RESYNC) {
        page->version = result_version;
        page->state = WVM_KVM_PAGE_CLEAN;
    } else {
        page->state = WVM_KVM_PAGE_RESYNC;
        mark_slice_failed_locked(slice, dirty_page->gpa);
    }
    page->slice = NULL;
    if (slice->pending != 0) {
        slice->pending--;
    }
    if (slice->pending == 0 && slice->destroy_requested) {
        release_slice = 1;
    }
    pthread_cond_broadcast(&slice->cache->completed);
    pthread_mutex_unlock(&slice->cache->lock);
    if (release_slice) {
        free(slice);
    }
    return success ? 0 : -EIO;
}

int wvm_kvm_memory_slice_seal(
    struct wvm_kvm_memory_slice *slice, char *error, size_t error_len)
{
    if (!slice || !slice->cache) {
        set_error(error, error_len, "KVM memory slice is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&slice->cache->lock);
    slice->sealed = 1;
    pthread_cond_broadcast(&slice->cache->completed);
    pthread_mutex_unlock(&slice->cache->lock);
    return 0;
}

int wvm_kvm_memory_slice_wait(
    struct wvm_kvm_memory_slice *slice, int *success_out, uint64_t *error_gpa,
    char *error, size_t error_len)
{
    struct timespec deadline;
    int wait_result;

    if (!slice || !slice->cache || !success_out || !error_gpa ||
        !slice->sealed ||
        deadline_from_now(slice->cache->config.completion_timeout_ms,
                          &deadline) != 0) {
        set_error(error, error_len, "KVM memory slice wait is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&slice->cache->lock);
    while (slice->pending != 0) {
        wait_result = pthread_cond_timedwait(&slice->cache->completed,
                                             &slice->cache->lock, &deadline);
        if (wait_result == ETIMEDOUT && slice->pending != 0) {
            slice->failed = 1;
            pthread_mutex_unlock(&slice->cache->lock);
            set_error(error, error_len, "KVM dirty commits exceeded horizon");
            return -ETIMEDOUT;
        }
        if (wait_result != 0 && slice->pending != 0) {
            pthread_mutex_unlock(&slice->cache->lock);
            set_error(error, error_len, "KVM dirty commit wait failed");
            return -wait_result;
        }
    }
    *success_out = !slice->failed;
    *error_gpa = slice->error_gpa;
    pthread_mutex_unlock(&slice->cache->lock);
    if (!*success_out) {
        set_error(error, error_len, "KVM memory slice requires resync");
        return -EUCLEAN;
    }
    return 0;
}

void wvm_kvm_memory_slice_destroy(struct wvm_kvm_memory_slice *slice)
{
    struct wvm_kvm_page_cache *cache;
    int release_slice = 0;

    if (!slice) {
        return;
    }
    cache = slice->cache;
    if (!cache || !cache->initialized) {
        free(slice);
        return;
    }
    pthread_mutex_lock(&cache->lock);
    if (slice->pending == 0) {
        release_slice = 1;
    } else {
        slice->destroy_requested = 1;
    }
    pthread_mutex_unlock(&cache->lock);
    if (release_slice) {
        free(slice);
    }
}

int wvm_kvm_page_cache_global_install(
    const struct wvm_kvm_page_cache_config *config, char *error,
    size_t error_len)
{
    int result;

    pthread_mutex_lock(&g_global_cache.lock);
    if (g_global_cache.active) {
        pthread_mutex_unlock(&g_global_cache.lock);
        set_error(error, error_len, "global KVM page cache is already active");
        return -EALREADY;
    }
    result = wvm_kvm_page_cache_init(&g_global_cache.cache, config, error,
                                     error_len);
    if (result == 0) {
        g_global_cache.active = 1;
    }
    pthread_mutex_unlock(&g_global_cache.lock);
    return result;
}

void wvm_kvm_page_cache_global_uninstall(void)
{
    pthread_mutex_lock(&g_global_cache.lock);
    if (g_global_cache.active) {
        wvm_kvm_page_cache_destroy(&g_global_cache.cache);
        g_global_cache.active = 0;
    }
    pthread_mutex_unlock(&g_global_cache.lock);
}

int wvm_kvm_page_cache_global_active(void)
{
    int active;

    pthread_mutex_lock(&g_global_cache.lock);
    active = g_global_cache.active;
    pthread_mutex_unlock(&g_global_cache.lock);
    return active;
}

int wvm_kvm_page_cache_global_install_full(
    uint64_t gpa, uint64_t version, char *error, size_t error_len)
{
    int result;

    pthread_mutex_lock(&g_global_cache.lock);
    result = g_global_cache.active
                 ? wvm_kvm_page_cache_install_full(
                       &g_global_cache.cache, gpa, version, error, error_len)
                 : -ENOTCONN;
    pthread_mutex_unlock(&g_global_cache.lock);
    return result;
}

int wvm_kvm_page_cache_global_apply_diff(
    uint64_t gpa, uint64_t version, uint16_t offset, size_t data_bytes,
    int zero_page, char *error, size_t error_len)
{
    int result;

    pthread_mutex_lock(&g_global_cache.lock);
    result = g_global_cache.active
                 ? wvm_kvm_page_cache_apply_diff(
                       &g_global_cache.cache, gpa, version, offset, data_bytes,
                       zero_page, error, error_len)
                 : -ENOTCONN;
    pthread_mutex_unlock(&g_global_cache.lock);
    return result;
}

int wvm_kvm_page_cache_global_invalidate(
    uint64_t gpa, char *error, size_t error_len)
{
    int result;

    pthread_mutex_lock(&g_global_cache.lock);
    result = g_global_cache.active
                 ? wvm_kvm_page_cache_invalidate(
                       &g_global_cache.cache, gpa, error, error_len)
                 : -ENOTCONN;
    pthread_mutex_unlock(&g_global_cache.lock);
    return result;
}

int wvm_kvm_page_cache_global_lookup(
    uint64_t gpa, uint8_t *state_out, uint64_t *version_out, char *error,
    size_t error_len)
{
    int result;

    pthread_mutex_lock(&g_global_cache.lock);
    result = g_global_cache.active
                 ? wvm_kvm_page_cache_lookup(
                       &g_global_cache.cache, gpa, state_out, version_out,
                       error, error_len)
                 : -ENOTCONN;
    pthread_mutex_unlock(&g_global_cache.lock);
    return result;
}

int wvm_kvm_page_cache_global_install_data(
    uint64_t gpa, uint64_t version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, int full_page, uint8_t *hva, uint8_t *mirror,
    char *error, size_t error_len)
{
    int result;

    if (!data || !hva || offset > WVM_MEMORY_PAGE_BYTES ||
        data_bytes > WVM_MEMORY_PAGE_BYTES - offset ||
        (full_page && (offset != 0 || data_bytes != WVM_MEMORY_PAGE_BYTES))) {
        return -EINVAL;
    }
    pthread_mutex_lock(&g_global_cache.lock);
    if (!g_global_cache.active) {
        result = -ENOTCONN;
    } else if (full_page) {
        result = wvm_kvm_page_cache_install_full(
            &g_global_cache.cache, gpa, version, error, error_len);
    } else {
        result = wvm_kvm_page_cache_apply_diff(
            &g_global_cache.cache, gpa, version, offset, data_bytes, 0,
            error, error_len);
    }
    if (result == 0) {
        memcpy(hva + offset, data, data_bytes);
        if (mirror && mirror != hva) {
            memcpy(mirror + offset, data, data_bytes);
        }
    }
    pthread_mutex_unlock(&g_global_cache.lock);
    return result;
}

int wvm_kvm_execution_global_join(
    wvm_kvm_prepare_input_fn prepare, void *opaque,
    struct wvm_kvm_memory_slice **slice_out, uint64_t *error_gpa,
    char *error, size_t error_len)
{
    struct wvm_kvm_page_cache *cache = &g_global_cache.cache;
    struct wvm_kvm_memory_slice *slice;
    struct timespec deadline;
    int result;

    if (!prepare || !slice_out || !error_gpa) {
        return -EINVAL;
    }
    *slice_out = NULL;
    *error_gpa = 0;
    pthread_mutex_lock(&g_global_cache.lock);
    if (!g_global_cache.active ||
        deadline_from_now(cache->config.completion_timeout_ms, &deadline)) {
        pthread_mutex_unlock(&g_global_cache.lock);
        return -ENOTCONN;
    }
    pthread_mutex_lock(&cache->lock);
    pthread_mutex_unlock(&g_global_cache.lock);
    for (;;) {
        slice = cache->execution_slice;
        if (!slice) {
            slice = calloc(1, sizeof(*slice));
            if (!slice) {
                pthread_mutex_unlock(&cache->lock);
                return -ENOMEM;
            }
            slice->cache = cache;
            slice->id = cache->next_slice_id++;
            if (slice->id == 0) slice->id = cache->next_slice_id++;
            slice->preparing = 1;
            slice->participants = slice->running = 1;
            cache->execution_slice = slice;
            *slice_out = slice;
            pthread_mutex_unlock(&cache->lock);

            /* No cache/scheduling lock is held during remote input fetch. */
            result = prepare(opaque, error_gpa);
            pthread_mutex_lock(&g_global_cache.lock);
            pthread_mutex_lock(&cache->lock);
            if (result || slice->failed) {
                mark_slice_failed_locked(slice, *error_gpa);
                slice->closing = 1;
                result = result ? result : -EUCLEAN;
            } else {
                cache->execution_active = 1;
            }
            slice->preparing = 0;
            pthread_cond_broadcast(&cache->completed);
            pthread_mutex_unlock(&cache->lock);
            pthread_mutex_unlock(&g_global_cache.lock);
            return result;
        }
        if (!slice->preparing && !slice->closing) {
            slice->participants++;
            slice->running++;
            *slice_out = slice;
            pthread_mutex_unlock(&cache->lock);
            return 0;
        }
        result = pthread_cond_timedwait(&cache->completed, &cache->lock,
                                         &deadline);
        if (result == ETIMEDOUT &&
            (!cache->execution_slice ||
             (!cache->execution_slice->preparing &&
              !cache->execution_slice->closing))) {
            continue;
        }
        if (result) {
            pthread_mutex_unlock(&cache->lock);
            set_error(error, error_len, "KVM execution cohort admission timed out");
            return -result;
        }
    }
}

int wvm_kvm_execution_leave(struct wvm_kvm_memory_slice *slice,
                            int status, uint64_t error_gpa)
{
    int harvest;

    pthread_mutex_lock(&slice->cache->lock);
    slice->closing = 1;
    if (status) mark_slice_failed_locked(slice, error_gpa);
    harvest = --slice->running == 0;
    pthread_cond_broadcast(&slice->cache->completed);
    pthread_mutex_unlock(&slice->cache->lock);
    return harvest;
}

void wvm_kvm_execution_complete(struct wvm_kvm_memory_slice *slice,
                                 int status, uint64_t error_gpa)
{
    pthread_mutex_lock(&slice->cache->lock);
    if (status) mark_slice_failed_locked(slice, error_gpa);
    slice->execution_status = slice->failed ? -EUCLEAN : 0;
    slice->execution_complete = 1;
    slice->cache->execution_active = 0;
    pthread_cond_broadcast(&slice->cache->completed);
    pthread_mutex_unlock(&slice->cache->lock);
}

int wvm_kvm_execution_wait(struct wvm_kvm_memory_slice *slice,
                            uint64_t *error_gpa)
{
    struct timespec deadline;
    int result = 0;

    if (deadline_from_now(slice->cache->config.completion_timeout_ms,
                          &deadline)) return -EINVAL;
    pthread_mutex_lock(&slice->cache->lock);
    while (!slice->execution_complete) {
        result = pthread_cond_timedwait(&slice->cache->completed,
                                         &slice->cache->lock, &deadline);
        if (slice->execution_complete) break;
        if (result) {
            mark_slice_failed_locked(slice, 0);
            break;
        }
    }
    *error_gpa = slice->error_gpa;
    result = slice->execution_complete ? slice->execution_status : -result;
    pthread_mutex_unlock(&slice->cache->lock);
    return result;
}

void wvm_kvm_execution_release(struct wvm_kvm_memory_slice *slice)
{
    int last;

    pthread_mutex_lock(&slice->cache->lock);
    last = --slice->participants == 0;
    if (last) {
        slice->cache->execution_slice = NULL;
        pthread_cond_broadcast(&slice->cache->completed);
    }
    pthread_mutex_unlock(&slice->cache->lock);
    if (last) wvm_kvm_memory_slice_destroy(slice);
}

int wvm_kvm_memory_slice_global_begin(
    struct wvm_kvm_memory_slice **slice_out, char *error, size_t error_len)
{
    int result;

    pthread_mutex_lock(&g_global_cache.lock);
    result = g_global_cache.active
                 ? wvm_kvm_memory_slice_begin(
                       &g_global_cache.cache, slice_out, error, error_len)
                 : -ENOTCONN;
    pthread_mutex_unlock(&g_global_cache.lock);
    return result;
}

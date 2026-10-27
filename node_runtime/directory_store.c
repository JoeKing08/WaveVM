#include "directory_store.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct wvm_directory_page {
    uint64_t gpa;
    uint64_t version;
    uint8_t data[WVM_MEMORY_PAGE_BYTES];
    struct wvm_directory_page *next;
};

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static int gpa_valid(uint64_t gpa)
{
    return (gpa & (WVM_MEMORY_PAGE_BYTES - 1U)) == 0;
}

static size_t bucket_index(uint64_t gpa)
{
    uint64_t page = gpa / WVM_MEMORY_PAGE_BYTES;

    page ^= page >> 33;
    page *= UINT64_C(0xff51afd7ed558ccd);
    page ^= page >> 33;
    return (size_t)page & (WVM_DIRECTORY_STORE_BUCKETS - 1U);
}

static struct wvm_directory_page *find_page_locked(
    struct wvm_directory_store *store, size_t bucket, uint64_t gpa)
{
    struct wvm_directory_page *page;

    for (page = store->buckets[bucket]; page; page = page->next) {
        if (page->gpa == gpa) {
            return page;
        }
    }
    return NULL;
}

static uint64_t initial_version(uint32_t epoch)
{
    return ((uint64_t)epoch << 32) | UINT64_C(1);
}

int wvm_directory_store_init(
    struct wvm_directory_store *store,
    const struct wvm_directory_store_config *config, char *error,
    size_t error_len)
{
    size_t i;

    if (!store || !config || config->initial_epoch == 0 ||
        config->max_page_records == 0) {
        set_error(error, error_len,
                  "V1 directory store configuration is invalid");
        return -EINVAL;
    }
    memset(store, 0, sizeof(*store));
    store->config = *config;
    store->buckets = calloc(WVM_DIRECTORY_STORE_BUCKETS,
                            sizeof(*store->buckets));
    store->bucket_locks = calloc(WVM_DIRECTORY_STORE_BUCKETS,
                                 sizeof(*store->bucket_locks));
    if (!store->buckets || !store->bucket_locks) {
        set_error(error, error_len,
                  "V1 directory store cannot allocate bucket tables");
        free(store->buckets);
        free(store->bucket_locks);
        memset(store, 0, sizeof(*store));
        return -ENOMEM;
    }
    if (pthread_mutex_init(&store->allocation_lock, NULL) != 0) {
        set_error(error, error_len,
                  "V1 directory store cannot initialize allocation lock");
        free(store->buckets);
        free(store->bucket_locks);
        memset(store, 0, sizeof(*store));
        return -1;
    }
    for (i = 0; i < WVM_DIRECTORY_STORE_BUCKETS; i++) {
        if (pthread_mutex_init(&store->bucket_locks[i], NULL) != 0) {
            while (i > 0) {
                i--;
                pthread_mutex_destroy(&store->bucket_locks[i]);
            }
            pthread_mutex_destroy(&store->allocation_lock);
            free(store->buckets);
            free(store->bucket_locks);
            memset(store, 0, sizeof(*store));
            set_error(error, error_len,
                      "V1 directory store cannot initialize bucket lock");
            return -1;
        }
    }
    store->initialized = 1;
    return 0;
}

void wvm_directory_store_destroy(struct wvm_directory_store *store)
{
    size_t i;

    if (!store || !store->initialized) {
        return;
    }
    for (i = 0; i < WVM_DIRECTORY_STORE_BUCKETS; i++) {
        struct wvm_directory_page *page = store->buckets[i];

        while (page) {
            struct wvm_directory_page *next = page->next;

            free(page);
            page = next;
        }
        pthread_mutex_destroy(&store->bucket_locks[i]);
    }
    pthread_mutex_destroy(&store->allocation_lock);
    free(store->buckets);
    free(store->bucket_locks);
    memset(store, 0, sizeof(*store));
}

int wvm_directory_store_read_page(
    struct wvm_directory_store *store, uint64_t gpa,
    uint8_t data[WVM_MEMORY_PAGE_BYTES], uint64_t *version_out,
    char *error, size_t error_len)
{
    struct wvm_directory_page *page;
    size_t bucket;

    if (!store || !store->initialized || !data || !version_out ||
        !gpa_valid(gpa)) {
        set_error(error, error_len, "V1 directory read arguments are invalid");
        return -EINVAL;
    }
    bucket = bucket_index(gpa);
    pthread_mutex_lock(&store->bucket_locks[bucket]);
    page = find_page_locked(store, bucket, gpa);
    if (page) {
        memcpy(data, page->data, sizeof(page->data));
        *version_out = page->version;
        pthread_mutex_unlock(&store->bucket_locks[bucket]);
        return 0;
    }
    pthread_mutex_unlock(&store->bucket_locks[bucket]);

    /*
     * Capacity is checked outside the bucket lock. Recheck the bucket after
     * taking allocation_lock so concurrent first touches cannot duplicate a
     * page or exceed the configured metadata bound.
     */
    pthread_mutex_lock(&store->allocation_lock);
    if (store->page_record_count >= store->config.max_page_records) {
        pthread_mutex_unlock(&store->allocation_lock);
        set_error(error, error_len, "V1 directory page table is full");
        return -EAGAIN;
    }
    pthread_mutex_lock(&store->bucket_locks[bucket]);
    page = find_page_locked(store, bucket, gpa);
    if (!page) {
        page = calloc(1, sizeof(*page));
        if (!page) {
            pthread_mutex_unlock(&store->bucket_locks[bucket]);
            pthread_mutex_unlock(&store->allocation_lock);
            set_error(error, error_len,
                      "V1 directory page allocation failed");
            return -ENOMEM;
        }
        page->gpa = gpa;
        page->version = initial_version(store->config.initial_epoch);
        page->next = store->buckets[bucket];
        store->buckets[bucket] = page;
        store->page_record_count++;
    }
    memcpy(data, page->data, sizeof(page->data));
    *version_out = page->version;
    pthread_mutex_unlock(&store->bucket_locks[bucket]);
    pthread_mutex_unlock(&store->allocation_lock);
    return 0;
}

int wvm_directory_store_commit_page(
    struct wvm_directory_store *store, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, uint64_t *result_version, char *error,
    size_t error_len)
{
    struct wvm_directory_page *page;
    uint32_t epoch;
    uint32_t counter;
    size_t bucket;

    if (!store || !store->initialized || !gpa_valid(gpa) ||
        base_version == 0 || !data || data_bytes == 0 ||
        data_bytes > WVM_MEMORY_PAGE_BYTES ||
        offset > WVM_MEMORY_PAGE_BYTES - data_bytes ||
        !result_version) {
        set_error(error, error_len, "V1 directory commit arguments are invalid");
        return -EINVAL;
    }
    bucket = bucket_index(gpa);
    /*
     * Handoff / first publish: allow commit against the implicit zero page at
     * initial_version without a prior fault-read. Cirros remote vCPU handoff
     * dirties thousands of pages; fault-materializing each one exhausts the
     * V1 waiter retention table. Create-on-commit with the exact initial base
     * preserves version rules while keeping the bulk path waiter-free.
     */
    if (base_version == initial_version(store->config.initial_epoch)) {
        pthread_mutex_lock(&store->allocation_lock);
        if (store->page_record_count >= store->config.max_page_records) {
            pthread_mutex_unlock(&store->allocation_lock);
            set_error(error, error_len, "V1 directory page table is full");
            return -EAGAIN;
        }
        pthread_mutex_lock(&store->bucket_locks[bucket]);
        page = find_page_locked(store, bucket, gpa);
        if (!page) {
            page = calloc(1, sizeof(*page));
            if (!page) {
                pthread_mutex_unlock(&store->bucket_locks[bucket]);
                pthread_mutex_unlock(&store->allocation_lock);
                set_error(error, error_len,
                          "V1 directory page allocation failed");
                return -ENOMEM;
            }
            page->gpa = gpa;
            page->version = initial_version(store->config.initial_epoch);
            page->next = store->buckets[bucket];
            store->buckets[bucket] = page;
            store->page_record_count++;
        }
        pthread_mutex_unlock(&store->allocation_lock);
    } else {
        pthread_mutex_lock(&store->bucket_locks[bucket]);
        page = find_page_locked(store, bucket, gpa);
        if (!page) {
            pthread_mutex_unlock(&store->bucket_locks[bucket]);
            set_error(error, error_len, "V1 directory page is not materialized");
            return -ENOENT;
        }
    }
    if (page->version != base_version) {
        pthread_mutex_unlock(&store->bucket_locks[bucket]);
        set_error(error, error_len,
                  "V1 directory commit base version is stale");
        return -ESTALE;
    }
    epoch = (uint32_t)(page->version >> 32);
    counter = (uint32_t)page->version;
    if (epoch != store->config.initial_epoch || counter == UINT32_MAX) {
        pthread_mutex_unlock(&store->bucket_locks[bucket]);
        set_error(error, error_len,
                  "V1 directory page version cannot advance");
        return -EOVERFLOW;
    }
    memcpy(page->data + offset, data, data_bytes);
    page->version = ((uint64_t)epoch << 32) | (uint64_t)(counter + 1U);
    *result_version = page->version;
    pthread_mutex_unlock(&store->bucket_locks[bucket]);
    return 0;
}

uint64_t wvm_directory_store_page_count(
    const struct wvm_directory_store *store)
{
    if (!store || !store->initialized) {
        return 0;
    }
    return store->page_record_count;
}

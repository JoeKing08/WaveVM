#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "directory_store.h"

struct first_touch_thread {
    struct wvm_directory_store *store;
    int result;
    uint64_t version;
};

static void *run_first_touch(void *opaque)
{
    struct first_touch_thread *thread = opaque;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    char error[128] = {0};

    thread->result = wvm_directory_store_read_page(
        thread->store, 0, page, &thread->version, error, sizeof(error));
    return NULL;
}

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "v1-directory-store test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_directory_store_config config = {
        .initial_epoch = 9,
        .max_page_records = 2,
    };
    struct wvm_directory_store store;
    struct first_touch_thread first_touch[8];
    pthread_t first_touch_threads[8];
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint8_t data[3] = {0x11, 0x22, 0x33};
    uint64_t version = 0;
    uint64_t next_version = 0;
    char error[256] = {0};
    size_t i;

    if (expect(wvm_directory_store_init(&store, &config, error,
                                           sizeof(error)) == 0,
               "initialize bounded V1 directory store")) {
        return 1;
    }
    if (expect(wvm_directory_store_read_page(
                   &store, 0, page, &version, error, sizeof(error)) == 0 &&
                   version == UINT64_C(0x0000000900000001) &&
                   page[0] == 0 && page[WVM_MEMORY_PAGE_BYTES - 1] == 0 &&
                   wvm_directory_store_page_count(&store) == 1,
               "materialize a zero page with the initial version")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }
    if (expect(wvm_directory_store_commit_page(
                   &store, 0, version, 4, data, sizeof(data), &next_version,
                   error, sizeof(error)) == 0 &&
                   next_version == version + 1U,
               "apply an exact-base page diff")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }
    memset(page, 0, sizeof(page));
    if (expect(wvm_directory_store_read_page(
                   &store, 0, page, &version, error, sizeof(error)) == 0 &&
                   version == next_version && page[4] == data[0] &&
                   page[5] == data[1] && page[6] == data[2],
               "read the committed bytes and version")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }
    if (expect(wvm_directory_store_commit_page(
                   &store, 0, version - 1U, 0, data, sizeof(data),
                   &next_version, error, sizeof(error)) == -ESTALE,
               "reject a stale base version")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }
    if (expect(wvm_directory_store_commit_page(
                   &store, WVM_MEMORY_PAGE_BYTES, version, 0, data,
                   sizeof(data), &next_version, error, sizeof(error)) ==
                   -ENOENT,
               "reject a commit for an unmaterialized page")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }
    if (expect(wvm_directory_store_read_page(
                   &store, WVM_MEMORY_PAGE_BYTES, page, &version, error,
                   sizeof(error)) == 0 &&
                   wvm_directory_store_page_count(&store) == 2,
               "materialize a second page within the bound")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }
    if (expect(wvm_directory_store_read_page(
                   &store, 2U * WVM_MEMORY_PAGE_BYTES, page, &version,
                   error, sizeof(error)) == -EAGAIN,
               "return bounded backpressure at the metadata limit")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }

    wvm_directory_store_destroy(&store);

    config.max_page_records = 1;
    if (expect(wvm_directory_store_init(&store, &config, error,
                                           sizeof(error)) == 0,
               "initialize store for concurrent first touch")) {
        return 1;
    }
    memset(first_touch, 0, sizeof(first_touch));
    for (i = 0; i < sizeof(first_touch) / sizeof(first_touch[0]); i++) {
        first_touch[i].store = &store;
        if (pthread_create(&first_touch_threads[i], NULL, run_first_touch,
                           &first_touch[i]) != 0) {
            fprintf(stderr, "v1-directory-store test: create thread failed\n");
            wvm_directory_store_destroy(&store);
            return 1;
        }
    }
    for (i = 0; i < sizeof(first_touch) / sizeof(first_touch[0]); i++) {
        pthread_join(first_touch_threads[i], NULL);
    }
    if (expect(wvm_directory_store_page_count(&store) == 1,
               "materialize one page under concurrent first touch")) {
        wvm_directory_store_destroy(&store);
        return 1;
    }
    for (i = 0; i < sizeof(first_touch) / sizeof(first_touch[0]); i++) {
        if (expect(first_touch[i].result == 0 &&
                       first_touch[i].version ==
                           UINT64_C(0x0000000900000001),
                   "return one consistent version to concurrent readers")) {
            wvm_directory_store_destroy(&store);
            return 1;
        }
    }
    wvm_directory_store_destroy(&store);
    printf("EVID directory_store: initial_version=0x%llx commit_next=%llu ESTALE_stale_base=1\n",
           (unsigned long long)UINT64_C(0x0000000900000001),
           (unsigned long long)(UINT64_C(0x0000000900000001) + 1U));
    puts("V1 directory-store tests: PASS");
    return 0;
}

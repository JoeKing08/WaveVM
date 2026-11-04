#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kvm_page_cache.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "KVM page-cache test: %s\n", message);
        return -1;
    }
    return 0;
}

struct delayed_completion {
    struct wvm_kvm_memory_slice *slice;
    struct wvm_kvm_dirty_page dirty;
};

static int prepare_input(void *opaque, uint64_t *error_gpa)
{
    unsigned *calls = opaque;
    (void)error_gpa;
    ++*calls;
    return 0;
}

static void *complete_after_timeout(void *opaque)
{
    struct delayed_completion *completion = opaque;
    char error[128] = {0};

    {
        const struct timespec delay = {
            .tv_sec = 0,
            .tv_nsec = 100000000L,
        };
        nanosleep(&delay, NULL);
    }
    (void)wvm_kvm_memory_slice_complete_dirty(
        completion->slice, &completion->dirty, WVM_MEM_COMMIT_ACK_SUCCESS, 8,
        error, sizeof(error));
    return NULL;
}

int main(void)
{
    struct wvm_kvm_page_cache *cache;
    struct wvm_kvm_page_cache_config config = {
        .vm_id = 42,
        .vm_incarnation = 9,
        .max_page_records = 2,
        .completion_timeout_ms = 1000,
    };
    struct wvm_kvm_memory_slice *slice = NULL;
    struct wvm_kvm_dirty_page dirty;
    uint8_t state = 0;
    uint64_t version = 0;
    uint64_t error_gpa = 0;
    int success = 0;
    char error[256] = {0};

    cache = wvm_kvm_page_cache_create(&config, error, sizeof(error));
    if (expect(cache != NULL,
               "initialize cache") ||
        expect(wvm_kvm_page_cache_install_full(
                   cache, 0, 7, error, sizeof(error)) == 0,
               "install an authoritative page") ||
        expect(wvm_kvm_page_cache_lookup(
                   cache, 0, &state, &version, error, sizeof(error)) == 0 &&
                   state == WVM_KVM_PAGE_CLEAN && version == 7,
               "record the authoritative version")) {
        wvm_kvm_page_cache_free(cache);
        return 1;
    }

    if (expect(wvm_kvm_memory_slice_begin(cache, &slice, error,
                                          sizeof(error)) == 0 &&
                   wvm_kvm_memory_slice_capture_dirty(
                       slice, 0, &dirty, error, sizeof(error)) == 0 &&
                   dirty.base_version == 7 &&
                   dirty.delivery_attempt_id == 1 &&
                   memcmp(dirty.operation_id,
                          (uint8_t[WVM_KVM_PAGE_OPERATION_ID_BYTES]){0},
                          sizeof(dirty.operation_id)) != 0,
               "bind a dirty page to its base version and operation") ||
        expect(wvm_kvm_page_cache_install_full(
                   cache, 0, 8, error, sizeof(error)) == -EBUSY,
               "reject a snapshot racing a dirty slice") ||
        expect(wvm_kvm_memory_slice_complete_dirty(
                   slice, &dirty, WVM_MEM_COMMIT_ACK_SUCCESS, 8, error,
                   sizeof(error)) == 0 &&
                   wvm_kvm_memory_slice_seal(slice, error, sizeof(error)) ==
                       0 &&
                   wvm_kvm_memory_slice_wait(
                       slice, &success, &error_gpa, error, sizeof(error)) ==
                       -EUCLEAN &&
                   !success && error_gpa == 0,
               "fail a slice whose input snapshot raced its dirty write")) {
        wvm_kvm_memory_slice_destroy(slice);
        wvm_kvm_page_cache_free(cache);
        return 1;
    }
    wvm_kvm_memory_slice_destroy(slice);
    slice = NULL;

    if (expect(wvm_kvm_page_cache_install_full(
                   cache, 0, 8, error, sizeof(error)) == 0,
               "repair the raced slice with a full snapshot") ||
        expect(wvm_kvm_memory_slice_begin(cache, &slice, error,
                                          sizeof(error)) == 0 &&
                   wvm_kvm_memory_slice_capture_dirty(
                       slice, 0, &dirty, error, sizeof(error)) == 0 &&
                   dirty.base_version == 8 &&
                   wvm_kvm_memory_slice_complete_dirty(
                       slice, &dirty, WVM_MEM_COMMIT_ACK_SUCCESS, 9, error,
                       sizeof(error)) == 0 &&
                   wvm_kvm_memory_slice_seal(slice, error, sizeof(error)) ==
                       0 &&
                   wvm_kvm_memory_slice_wait(
                       slice, &success, &error_gpa, error, sizeof(error)) ==
                       0 &&
                   success,
               "complete a slice after authoritative recovery")) {
        wvm_kvm_memory_slice_destroy(slice);
        wvm_kvm_page_cache_free(cache);
        return 1;
    }
    wvm_kvm_memory_slice_destroy(slice);
    slice = NULL;

    if (expect(wvm_kvm_page_cache_apply_diff(
                   cache, 0, 10, 0, 1, 0, error, sizeof(error)) == 0,
               "accept the next authoritative diff") ||
        expect(wvm_kvm_page_cache_apply_diff(
                   cache, 0, 12, 0, 1, 0, error, sizeof(error)) == -ESTALE,
               "enter resync on a version gap") ||
        expect(wvm_kvm_page_cache_lookup(
                   cache, 0, &state, &version, error, sizeof(error)) == 0 &&
                   state == WVM_KVM_PAGE_RESYNC,
               "retain RESYNC after a version gap") ||
        expect(wvm_kvm_memory_slice_begin(cache, &slice, error,
                                          sizeof(error)) == 0 &&
                   wvm_kvm_memory_slice_capture_dirty(
                       slice, 0, &dirty, error, sizeof(error)) == -ESTALE,
               "refuse a dirty page without an authoritative base")) {
        wvm_kvm_memory_slice_destroy(slice);
        wvm_kvm_page_cache_free(cache);
        return 1;
    }
    wvm_kvm_memory_slice_destroy(slice);
    slice = NULL;

    if (expect(wvm_kvm_page_cache_install_full(
                   cache, 0, 13, error, sizeof(error)) == 0,
               "repair RESYNC with a full snapshot") ||
        expect(wvm_kvm_memory_slice_begin(cache, &slice, error,
                                          sizeof(error)) == 0 &&
                   wvm_kvm_memory_slice_capture_dirty(
                       slice, 0, &dirty, error, sizeof(error)) == 0 &&
                   wvm_kvm_memory_slice_complete_dirty(
                       slice, &dirty, WVM_MEM_COMMIT_ACK_STALE_BASE_VERSION, 0,
                       error, sizeof(error)) == -EIO &&
                   wvm_kvm_memory_slice_seal(slice, error, sizeof(error)) ==
                       0 &&
                   wvm_kvm_memory_slice_wait(
                       slice, &success, &error_gpa, error, sizeof(error)) ==
                       -EUCLEAN &&
                   !success && error_gpa == 0,
               "turn a stale commit into a failed slice") ||
        expect(wvm_kvm_page_cache_install_full(
                   cache, WVM_MEMORY_PAGE_BYTES, 13, error,
                   sizeof(error)) == 0 &&
                   wvm_kvm_page_cache_install_full(
                       cache, 2 * WVM_MEMORY_PAGE_BYTES, 14, error,
                       sizeof(error)) == -EAGAIN,
               "enforce the admitted page-record bound")) {
        wvm_kvm_memory_slice_destroy(slice);
        wvm_kvm_page_cache_free(cache);
        return 1;
    }
    wvm_kvm_memory_slice_destroy(slice);
    wvm_kvm_page_cache_free(cache);

    /*
     * A timed-out sender may still deliver its ACK. Destroying the slice must
     * defer reclamation until that late completion releases the pending page,
     * and the late ACK must not turn a timed-out slice into success.
     */
    {
        struct wvm_kvm_page_cache_config late_config = {
            .vm_id = 43,
            .vm_incarnation = 10,
            .max_page_records = 1,
            .completion_timeout_ms = 20,
        };
        struct wvm_kvm_page_cache *late_cache;
        struct wvm_kvm_memory_slice *late_slice = NULL;
        struct wvm_kvm_dirty_page late_dirty;
        struct delayed_completion completion;
        pthread_t completion_thread;

        late_cache = wvm_kvm_page_cache_create(
            &late_config, error, sizeof(error));
        if (expect(late_cache != NULL, "initialize the late-ACK cache") ||
            expect(wvm_kvm_page_cache_install_full(
                       late_cache, 0, 7, error, sizeof(error)) == 0,
                   "install a base for the late-ACK case") ||
            expect(wvm_kvm_memory_slice_begin(
                       late_cache, &late_slice, error, sizeof(error)) == 0 &&
                       wvm_kvm_memory_slice_capture_dirty(
                           late_slice, 0, &late_dirty, error,
                           sizeof(error)) == 0,
                   "capture a page for the late-ACK case")) {
            wvm_kvm_memory_slice_destroy(late_slice);
            wvm_kvm_page_cache_free(late_cache);
            return 1;
        }
        completion.slice = late_slice;
        completion.dirty = late_dirty;
        if (expect(pthread_create(&completion_thread, NULL,
                                  complete_after_timeout, &completion) == 0,
                   "start the delayed completion") ||
            expect(wvm_kvm_memory_slice_seal(
                       late_slice, error, sizeof(error)) == 0 &&
                       wvm_kvm_memory_slice_wait(
                           late_slice, &success, &error_gpa, error,
                           sizeof(error)) == -ETIMEDOUT,
                   "time out while the sender still owns the page")) {
            pthread_join(completion_thread, NULL);
            wvm_kvm_memory_slice_destroy(late_slice);
            wvm_kvm_page_cache_free(late_cache);
            return 1;
        }
        wvm_kvm_memory_slice_destroy(late_slice);
        pthread_join(completion_thread, NULL);
        if (expect(wvm_kvm_page_cache_lookup(
                       late_cache, 0, &state, &version, error,
                       sizeof(error)) == 0 &&
                       state == WVM_KVM_PAGE_RESYNC && version == 7,
                   "retain RESYNC after a late completion")) {
            wvm_kvm_page_cache_free(late_cache);
            return 1;
        }
        wvm_kvm_page_cache_free(late_cache);
    }

    {
        struct wvm_kvm_page_cache_config window_config = {
            .vm_id = 44,
            .vm_incarnation = 11,
            .max_page_records = 2,
            .completion_timeout_ms = 1000,
        };
        struct wvm_kvm_memory_slice *first = NULL, *second = NULL;
        uint8_t bytes[WVM_MEMORY_PAGE_BYTES] = {0};
        uint8_t update[WVM_MEMORY_PAGE_BYTES] = {1};
        unsigned prepares = 0;

        if (expect(wvm_kvm_page_cache_global_install(
                       &window_config, error, sizeof(error)) == 0,
                   "install the global execution-window cache") ||
            expect(wvm_kvm_page_cache_global_install_full(
                       0, 1, error, sizeof(error)) == 0,
                   "install the execution-window base page") ||
            expect(wvm_kvm_execution_global_join(
                       prepare_input, &prepares, &first, &error_gpa,
                       error, sizeof(error)) == 0 &&
                   wvm_kvm_execution_global_join(
                       prepare_input, &prepares, &second, &error_gpa,
                       error, sizeof(error)) == 0 && first == second &&
                   prepares == 1,
                   "independent vCPUs join one prepared execution cohort") ||
            expect(wvm_kvm_page_cache_global_install_data(
                       0, 1, 0, update, sizeof(update), 1, bytes, NULL,
                       error, sizeof(error)) == -EALREADY && bytes[0] == 0,
                   "replayed input cannot overwrite RAM during execution") ||
            expect(wvm_kvm_page_cache_global_install_data(
                       0, 2, 0, update, sizeof(update), 1, bytes, NULL,
                       error, sizeof(error)) == -EBUSY && bytes[0] == 0,
                   "reject a full snapshot during execution") ||
            expect(wvm_kvm_page_cache_global_lookup(
                       0, &state, &version, error, sizeof(error)) == 0 &&
                   state == WVM_KVM_PAGE_RESYNC && version == 0,
                   "retain resync after a blocked full snapshot") ||
            expect(wvm_kvm_page_cache_global_apply_diff(
                       0, 2, 0, 1, 0, error, sizeof(error)) == -EBUSY,
                   "reject a diff during execution")) {
            return 1;
        }
        if (expect(wvm_kvm_execution_leave(first, 0, 0) == 0 &&
                   wvm_kvm_execution_leave(second, 0, 0) == 1,
                   "only the last exiting vCPU may harvest the shared log")) {
            return 1;
        }
        wvm_kvm_execution_complete(second, 0, 0);
        if (expect(wvm_kvm_execution_wait(first, &error_gpa) == -EUCLEAN &&
                   wvm_kvm_execution_wait(second, &error_gpa) == -EUCLEAN,
                   "input conflict fails every vCPU even without dirty pages")) {
            return 1;
        }
        wvm_kvm_execution_release(first);
        wvm_kvm_execution_release(second);
        if (expect(wvm_kvm_page_cache_global_install_full(
                       0, 2, error, sizeof(error)) == 0,
                   "repair a blocked page after execution") ||
            expect(wvm_kvm_execution_global_join(
                       prepare_input, &prepares, &first, &error_gpa,
                       error, sizeof(error)) == 0,
                   "begin a second execution cohort") ||
            expect(wvm_kvm_page_cache_global_invalidate(
                       0, error, sizeof(error)) == -EBUSY,
                   "reject invalidation during execution")) {
            return 1;
        }
        (void)wvm_kvm_execution_leave(first, 0, 0);
        wvm_kvm_execution_complete(first, 0, 0);
        if (expect(wvm_kvm_execution_wait(first, &error_gpa) == -EUCLEAN,
                   "a clean-page invalidation fails the whole cohort")) return 1;
        wvm_kvm_execution_release(first);
        wvm_kvm_page_cache_global_uninstall();
        puts("EVID kvm_cohort: members=2 preparations=1 single_harvester=1 "
             "input_conflict_fails_all=1 byte_install_guarded=1");
    }

    puts("KVM page-cache tests: PASS");
    return 0;
}

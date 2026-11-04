#include "memory_service.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum pending_entry_state {
    WVM_MEMORY_PENDING_EMPTY = 0,
    WVM_MEMORY_PENDING_WAITING = 1,
    WVM_MEMORY_PENDING_COMPLETED = 2,
    WVM_MEMORY_PENDING_COMPLETING = 3,
};

enum local_waiter_state {
    WVM_MEMORY_WAITER_EMPTY = 0,
    WVM_MEMORY_WAITER_WAITING = 1,
    WVM_MEMORY_WAITER_COMPLETED = 2,
    WVM_MEMORY_WAITER_ORPHANED = 3,
};

struct local_waiter_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint64_t gpa;
    uint64_t version;
    uint16_t status;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    size_t data_bytes;
    uint8_t data[WVM_MEMORY_PAGE_BYTES];
    uint8_t state;
    uint8_t owner_present;
    uint64_t retained_until_ms;
    pthread_cond_t completed;
};

struct local_commit_waiter_entry {
    struct local_commit_waiter_entry *next;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint64_t gpa;
    struct wvm_mem_commit_ack ack;
    uint8_t state;
    uint8_t owner_present;
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t retained_until_ms;
    pthread_cond_t completed;
};

struct global_memory_service {
    pthread_mutex_t lock;
    pthread_cond_t capacity_changed;
    struct wvm_memory_service *service;
    struct local_waiter_entry waiters[WVM_MEMORY_SERVICE_MAX_PENDING];
    struct local_commit_waiter_entry *commit_waiters;
};

static struct global_memory_service g_global_memory_service = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .capacity_changed = PTHREAD_COND_INITIALIZER,
};

enum local_commit_waiter_state {
    WVM_MEMORY_COMMIT_WAITER_EMPTY = 0,
    WVM_MEMORY_COMMIT_WAITER_WAITING = 1,
    WVM_MEMORY_COMMIT_WAITER_COMPLETED = 2,
    WVM_MEMORY_COMMIT_WAITER_ORPHANED = 3,
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

static void envelope_from_route_key(
    const struct wvm_memory_service *service, uint16_t message_type,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, const struct wvm_envelope_route *route,
    const struct wvm_route_snapshot_key *snapshot_key,
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_envelope *envelope);

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    if ((uint64_t)now.tv_sec > UINT64_MAX / 1000U) {
        return UINT64_MAX;
    }
    return (uint64_t)now.tv_sec * 1000U +
           (uint64_t)now.tv_nsec / 1000000U;
}

static void record_remote_completion(struct wvm_memory_service *service,
                                     const struct wvm_envelope *envelope,
                                     uint32_t directory_node,
                                     uint64_t directory_instance,
                                     uint64_t gpa, int is_commit)
{
    const struct wvm_runtime_dispatch_projection *p = service->config.dispatch;
    uint64_t now, previous;
    char operation[WVM_IDENTITY_ID_BYTES * 2 + 1];

    if (directory_node == service->config.local_physical_node_id &&
        directory_instance == service->config.local_node_instance_id) {
        return;
    }
    __atomic_fetch_add(is_commit ? &service->remote_commit_completions :
                                  &service->remote_read_completions,
                       1, __ATOMIC_RELAXED);
    now = monotonic_milliseconds();
    previous = __atomic_load_n(&service->completion_log_ms, __ATOMIC_RELAXED);
    if ((previous != 0 && now - previous < 250) ||
        !__atomic_compare_exchange_n(&service->completion_log_ms, &previous,
                                      now, 0, __ATOMIC_RELAXED,
                                      __ATOMIC_RELAXED)) {
        return;
    }
    for (size_t i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
        snprintf(operation + 2 * i, 3, "%02x", envelope->operation_id[i]);
    }
    /* Only the first accepted semantic completion reaches this counter. */
    fprintf(stderr,
            "[WVM-MEM-STATS] vm=%u incarnation=%llu manifest=%llu "
            "origin=%u instance=%llu runtime=%llu pid=%ld "
            "directory=%u directory_instance=%llu operation=%s gpa=%llu "
            "remote_reads=%llu remote_commits=%llu\n",
            p->vm_id, (unsigned long long)p->vm_incarnation,
            (unsigned long long)p->manifest_generation,
            service->config.local_physical_node_id,
            (unsigned long long)service->config.local_node_instance_id,
            (unsigned long long)service->config.local_runtime_instance_id,
            (long)getpid(), directory_node,
            (unsigned long long)directory_instance, operation,
            (unsigned long long)gpa,
            (unsigned long long)__atomic_load_n(
                &service->remote_read_completions, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(
                &service->remote_commit_completions, __ATOMIC_RELAXED));
}

static uint64_t retention_deadline_ms(
    const struct wvm_memory_service *service)
{
    uint64_t now = monotonic_milliseconds();
    uint64_t horizon;

    if (!service) {
        return now;
    }
    horizon = service->config.completion_timeout_ms;
    if (now == UINT64_MAX || horizon > UINT64_MAX - now) {
        return UINT64_MAX;
    }
    return now + horizon;
}

static int retention_expired(uint64_t retained_until_ms, uint64_t now)
{
    return retained_until_ms != 0 && now != 0 &&
           retained_until_ms <= now;
}

static int bytes_are_zero(const uint8_t *bytes, size_t bytes_count)
{
    size_t i;

    for (i = 0; i < bytes_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int build_commit_semantic_digest(
    const struct wvm_memory_service *service, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, uint8_t digest[WVM_SHA256_DIGEST_BYTES],
    char *error, size_t error_len)
{
    uint8_t payload[WVM_MEM_COMMIT_HEADER_BYTES +
                    WVM_MEMORY_PAGE_BYTES];
    size_t payload_bytes = 0;

    if (!service || !service->config.dispatch || !data || !digest ||
        wvm_mem_commit_encode(
            &(struct wvm_mem_commit) {
                .gpa = gpa,
                .base_version = base_version,
                .offset = offset,
                .size = (uint16_t)data_bytes,
                .reply_destination_kind =
                    service->config.dispatch->local_primary.destination_kind,
                .reply_destination_scope =
                    service->config.dispatch->local_primary.destination_scope,
                .reply_destination_vnode =
                    service->config.dispatch->local_primary.destination_vnode,
                .reply_node_instance_id = service->config.local_node_instance_id,
                .data = data,
                .data_bytes = data_bytes,
            },
            payload, sizeof(payload), &payload_bytes, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "V1 commit payload is invalid");
        }
        return -EINVAL;
    }
    wvm_envelope_semantic_digest(payload, payload_bytes, digest);
    return 0;
}

static int route_destination_equal(
    const struct wvm_runtime_route_destination *destination,
    const struct wvm_envelope_route *route)
{
    return destination && route &&
           destination->destination_kind == route->destination_kind &&
           destination->destination_scope == route->destination_scope &&
           destination->destination_vnode ==
               route->destination_vnode_or_endpoint;
}

static int route_scope_key_equal(
    const struct wvm_vm_route_scope_key *left,
    const struct wvm_vm_route_scope_key *right)
{
    return left && right && left->vm_id == right->vm_id &&
           left->vm_incarnation == right->vm_incarnation &&
           left->route_scope_id == right->route_scope_id;
}

static int version_is_next(uint64_t base_version, uint64_t version)
{
    uint32_t base_epoch = (uint32_t)(base_version >> 32);
    uint32_t base_counter = (uint32_t)base_version;
    uint32_t result_epoch = (uint32_t)(version >> 32);
    uint32_t result_counter = (uint32_t)version;

    return base_version != 0 && version != 0 && base_epoch == result_epoch &&
           base_counter != UINT32_MAX && result_counter == base_counter + 1U;
}

static uint64_t next_delivery_attempt(struct wvm_memory_service *service)
{
    uint64_t attempt;

    if (!service) {
        return 0;
    }
    attempt = __atomic_add_fetch(&service->next_delivery_attempt_id, 1,
                                 __ATOMIC_RELAXED);
    if (attempt == 0) {
        attempt = __atomic_add_fetch(&service->next_delivery_attempt_id, 1,
                                     __ATOMIC_RELAXED);
    }
    return attempt;
}

static int envelope_matches_projection(
    const struct wvm_runtime_dispatch_projection *projection,
    const struct wvm_envelope *envelope)
{
    return projection && envelope &&
           envelope->vm_id == projection->vm_id &&
           envelope->vm_incarnation == projection->vm_incarnation &&
           envelope->manifest_generation == projection->manifest_generation &&
           envelope->route_scope_id ==
               projection->required_route_snapshot_key.scope_key.route_scope_id &&
           envelope->topology_revision ==
               projection->required_route_snapshot_key.topology_revision &&
           envelope->route_generation ==
               projection->required_route_snapshot_key.route_generation &&
           memcmp(envelope->route_snapshot_digest,
                  projection->required_route_snapshot_key.snapshot_digest,
                  sizeof(envelope->route_snapshot_digest)) == 0;
}

static size_t pending_bucket(const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                             size_t bucket_count)
{
    uint64_t hash = UINT64_C(14695981039346656037);

    for (size_t i = 0; i < WVM_IDENTITY_ID_BYTES; ++i) {
        hash = (hash ^ operation_id[i]) * UINT64_C(1099511628211);
    }
    return (size_t)hash & (bucket_count - 1);
}

static struct wvm_memory_pending_entry *find_pending_locked(
    struct wvm_memory_service *service,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t bucket = pending_bucket(operation_id, service->pending_bucket_count);

    for (struct wvm_memory_pending_entry *entry = service->pending_buckets[bucket];
         entry; entry = entry->next) {
        if (memcmp(entry->operation_id, operation_id,
                   sizeof(entry->operation_id)) == 0) {
            return entry;
        }
    }
    return NULL;
}

/* A05: pin/put route scope refs for in-flight memory ops (retire proof). */
static int memory_route_op_ref_get(struct wvm_memory_service *service,
                                   char *error, size_t error_len)
{
    struct wvm_route_runtime *runtime;

    if (!service || !service->config.route_runtime || !service->config.dispatch) {
        set_error(error, error_len, "V1 memory route ref get has no runtime");
        return -EINVAL;
    }
    runtime = (struct wvm_route_runtime *)service->config.route_runtime;
    return wvm_route_runtime_operation_ref_get(
        runtime,
        &service->config.dispatch->required_route_snapshot_key.scope_key,
        error, error_len);
}

static void memory_route_op_ref_put(struct wvm_memory_service *service)
{
    char discard[128];
    struct wvm_route_runtime *runtime;

    if (!service || !service->config.route_runtime || !service->config.dispatch) {
        return;
    }
    runtime = (struct wvm_route_runtime *)service->config.route_runtime;
    (void)wvm_route_runtime_operation_ref_put(
        runtime,
        &service->config.dispatch->required_route_snapshot_key.scope_key,
        discard, sizeof(discard));
}

static int memory_call_begin(struct wvm_memory_service *service,
                             int completion_only, char *error,
                             size_t error_len)
{
    int result;

    if (!service || !service->initialized) {
        set_error(error, error_len, "memory service is not initialized");
        return -EINVAL;
    }
    pthread_mutex_lock(&service->subscriber_lock);
    if (service->lifecycle_state == WVM_MEMORY_SERVICE_RETIRED ||
        (service->lifecycle_state == WVM_MEMORY_SERVICE_DRAINING &&
         !completion_only)) {
        pthread_mutex_unlock(&service->subscriber_lock);
        set_error(error, error_len, "memory service is stopping");
        return -ESHUTDOWN;
    }
    service->active_calls++;
    pthread_mutex_unlock(&service->subscriber_lock);

    /* Keep route retirement behind callbacks, including synchronous sends.
     * This is a reference, not a lock held across network operations. */
    result = memory_route_op_ref_get(service, error, error_len);
    if (result != 0) {
        pthread_mutex_lock(&service->subscriber_lock);
        service->active_calls--;
        pthread_mutex_unlock(&service->subscriber_lock);
    }
    return result;
}

static void memory_call_end(struct wvm_memory_service *service)
{
    memory_route_op_ref_put(service);
    pthread_mutex_lock(&service->subscriber_lock);
    service->active_calls--;
    pthread_mutex_unlock(&service->subscriber_lock);
}

/*
 * Completed identities are retained only through the admitted operation
 * horizon.  The service tables are separate from the global waiter tables,
 * so they need their own bounded reap before looking for an EMPTY slot.
 */
static void reap_pending_bucket_locked(
    struct wvm_memory_service *service, size_t bucket, uint64_t now)
{
    struct wvm_memory_pending_entry **cursor = &service->pending_buckets[bucket];

    while (*cursor) {
        struct wvm_memory_pending_entry *entry = *cursor;
        if (entry->state == WVM_MEMORY_PENDING_COMPLETED &&
            retention_expired(entry->retained_until_ms, now)) {
            *cursor = entry->next;
            free(entry);
            service->pending_count--;
        } else {
            cursor = &entry->next;
        }
    }
}

static int pending_registry_init(struct wvm_memory_service *service)
{
    uint64_t pages = 0;

    for (size_t i = 0; i < service->config.dispatch->memory_dispatch.count; ++i) {
        uint64_t count = service->config.dispatch->memory_dispatch.entries[i].bytes /
                         WVM_MEMORY_PAGE_BYTES;
        if (count > UINT64_MAX - pages) return -EOVERFLOW;
        pages += count;
    }
    if (pages > (UINT64_MAX - WVM_MEMORY_SERVICE_MAX_PENDING) / 2) return -EOVERFLOW;
    service->pending_limit = pages * 2 + WVM_MEMORY_SERVICE_MAX_PENDING;
    service->pending_bucket_count = 256;
    service->pending_buckets = calloc(service->pending_bucket_count,
                                       sizeof(*service->pending_buckets));
    if (!service->pending_buckets) {
        service->pending_bucket_count = 0;
        return -ENOMEM;
    }
    return 0;
}

static int pending_grow_locked(struct wvm_memory_service *service)
{
    size_t count = service->pending_bucket_count;
    struct wvm_memory_pending_entry **buckets;

    if (service->pending_count < count * 2) return 0;
    if (count > SIZE_MAX / 2 / sizeof(*buckets)) return -EOVERFLOW;
    buckets = calloc(count * 2, sizeof(*buckets));
    if (!buckets) return -ENOMEM;
    for (size_t i = 0; i < count; ++i) {
        struct wvm_memory_pending_entry *entry = service->pending_buckets[i];
        while (entry) {
            struct wvm_memory_pending_entry *next = entry->next;
            size_t bucket = pending_bucket(entry->operation_id, count * 2);
            entry->next = buckets[bucket];
            buckets[bucket] = entry;
            entry = next;
        }
    }
    free(service->pending_buckets);
    service->pending_buckets = buckets;
    service->pending_bucket_count = count * 2;
    return 0;
}

static void reap_commit_completed_locked(
    struct wvm_memory_service *service, uint64_t now)
{
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct wvm_memory_commit_entry *entry = &service->commits[i];

        if ((entry->state == WVM_MEMORY_COMMIT_COMPLETED ||
             entry->state == WVM_MEMORY_COMMIT_RETRYABLE) &&
            retention_expired(entry->retained_until_ms, now)) {
            memset(entry, 0, sizeof(*entry));
        }
    }
}

static void reap_outgoing_completed_locked(
    struct wvm_memory_service *service, uint64_t now)
{
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct wvm_memory_outgoing_commit_entry *entry =
            &service->outgoing_commits[i];

        if (entry->state == WVM_MEMORY_COMMIT_COMPLETED &&
            retention_expired(entry->retained_until_ms, now)) {
            memset(entry, 0, sizeof(*entry));
        }
    }
}

static int pending_register(struct wvm_memory_service *service,
                            const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                            const struct wvm_runtime_memory_dispatch *memory,
                            uint64_t gpa, int *already_waiting)
{
    struct wvm_memory_pending_entry *entry;
    uint64_t now = monotonic_milliseconds();
    size_t bucket;
    int result;
    char error[128];

    result = memory_route_op_ref_get(service, error, sizeof(error));
    if (result != 0) return result;
    pthread_mutex_lock(&service->pending_lock);
    bucket = pending_bucket(operation_id, service->pending_bucket_count);
    reap_pending_bucket_locked(service, bucket, now);
    reap_pending_bucket_locked(service, service->pending_reap_cursor++ %
                                service->pending_bucket_count, now);
    entry = find_pending_locked(service, operation_id);
    if (entry) {
        if (entry->gpa != gpa ||
            entry->directory_physical_node_id !=
                memory->directory_physical_node_id ||
            entry->directory_node_instance_id !=
                memory->directory_node_instance_id) {
            result = -EEXIST;
            goto fail;
        }
        if (entry->state == WVM_MEMORY_PENDING_COMPLETING) {
            result = -EAGAIN;
            goto fail;
        }
        if (entry->state == WVM_MEMORY_PENDING_WAITING) {
            *already_waiting = 1;
            result = 0;
            goto fail;
        }
    }
    if (service->pending_active >= WVM_MEMORY_SERVICE_MAX_PENDING) {
        result = -EAGAIN;
        goto fail;
    }
    if (!entry) {
        if (service->pending_count >= service->pending_limit) {
            for (size_t i = 0; i < service->pending_bucket_count; ++i) {
                reap_pending_bucket_locked(service, i, now);
            }
        }
        if (service->pending_count >= service->pending_limit) {
            result = -EAGAIN;
            goto fail;
        }
        result = pending_grow_locked(service);
        if (result != 0) goto fail;
        entry = calloc(1, sizeof(*entry));
        if (!entry) {
            result = -ENOMEM;
            goto fail;
        }
        memcpy(entry->operation_id, operation_id, sizeof(entry->operation_id));
        entry->gpa = gpa;
        entry->directory_physical_node_id = memory->directory_physical_node_id;
        entry->directory_node_instance_id = memory->directory_node_instance_id;
        bucket = pending_bucket(operation_id, service->pending_bucket_count);
        entry->next = service->pending_buckets[bucket];
        service->pending_buckets[bucket] = entry;
        service->pending_count++;
    }
    entry->state = WVM_MEMORY_PENDING_WAITING;
    entry->route_op_ref_held = 1;
    service->pending_active++;
    *already_waiting = 0;
    pthread_mutex_unlock(&service->pending_lock);
    return 0;
fail:
    pthread_mutex_unlock(&service->pending_lock);
    memory_route_op_ref_put(service);
    return result;
}

static void pending_remove(struct wvm_memory_service *service,
                           const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    struct wvm_memory_pending_entry *entry;
    int put_ref = 0;

    pthread_mutex_lock(&service->pending_lock);
    entry = find_pending_locked(service, operation_id);
    if (entry && entry->state == WVM_MEMORY_PENDING_WAITING) {
        put_ref = entry->route_op_ref_held;
        entry->route_op_ref_held = 0;
        entry->state = WVM_MEMORY_PENDING_COMPLETED;
        entry->retained_until_ms = retention_deadline_ms(service);
        service->pending_active--;
    }
    pthread_mutex_unlock(&service->pending_lock);
    if (put_ref)
        memory_route_op_ref_put(service);
}

static struct wvm_memory_outgoing_commit_entry *
find_outgoing_commit_locked(
    struct wvm_memory_service *service,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct wvm_memory_outgoing_commit_entry *entry =
            &service->outgoing_commits[i];

        if (entry->state != WVM_MEMORY_COMMIT_EMPTY &&
            memcmp(entry->operation_id, operation_id,
                   sizeof(entry->operation_id)) == 0) {
            return entry;
        }
    }
    return NULL;
}

static int outgoing_commit_register(
    struct wvm_memory_service *service,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES],
    const struct wvm_runtime_memory_dispatch *memory, uint64_t gpa,
    int *already_waiting, char *error, size_t error_len)
{
    struct wvm_memory_outgoing_commit_entry *empty = NULL;
    size_t i;

    pthread_mutex_lock(&service->outgoing_commit_lock);
    reap_outgoing_completed_locked(service, monotonic_milliseconds());
    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct wvm_memory_outgoing_commit_entry *entry =
            &service->outgoing_commits[i];

        if (entry->state == WVM_MEMORY_COMMIT_EMPTY) {
            if (!empty) {
                empty = entry;
            }
            continue;
        }
        if (memcmp(entry->operation_id, operation_id,
                   sizeof(entry->operation_id)) != 0) {
            continue;
        }
        if (entry->gpa != gpa ||
            entry->directory_physical_node_id !=
                memory->directory_physical_node_id ||
            entry->directory_node_instance_id !=
                memory->directory_node_instance_id ||
            memcmp(entry->semantic_payload_digest, semantic_payload_digest,
                   sizeof(entry->semantic_payload_digest)) != 0) {
            pthread_mutex_unlock(&service->outgoing_commit_lock);
            set_error(error, error_len,
                      "V1 outgoing commit operation conflicts with pending work");
            return -EEXIST;
        }
        if (entry->state == WVM_MEMORY_COMMIT_IN_FLIGHT) {
            *already_waiting = 1;
            pthread_mutex_unlock(&service->outgoing_commit_lock);
            return 0;
        }
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        set_error(error, error_len,
                  "V1 outgoing commit already completed for this operation");
        return -EALREADY;
    }
    if (!empty) {
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        set_error(error, error_len, "V1 outgoing commit table is full");
        return -EAGAIN;
    }
    memset(empty, 0, sizeof(*empty));
    memcpy(empty->operation_id, operation_id, sizeof(empty->operation_id));
    memcpy(empty->semantic_payload_digest, semantic_payload_digest,
           sizeof(empty->semantic_payload_digest));
    empty->gpa = gpa;
    empty->directory_physical_node_id = memory->directory_physical_node_id;
    empty->directory_node_instance_id = memory->directory_node_instance_id;
    empty->state = WVM_MEMORY_COMMIT_IN_FLIGHT;
    empty->route_op_ref_held = 0;
    *already_waiting = 0;
    pthread_mutex_unlock(&service->outgoing_commit_lock);
    {
        char pin_err[128];
        uint8_t op_copy[WVM_IDENTITY_ID_BYTES];

        memcpy(op_copy, operation_id, sizeof(op_copy));
        if (memory_route_op_ref_get(service, pin_err, sizeof(pin_err)) != 0) {
            pthread_mutex_lock(&service->outgoing_commit_lock);
            empty = find_outgoing_commit_locked(service, op_copy);
            if (empty && empty->state == WVM_MEMORY_COMMIT_IN_FLIGHT)
                memset(empty, 0, sizeof(*empty));
            pthread_mutex_unlock(&service->outgoing_commit_lock);
            set_error(error, error_len, pin_err[0] ? pin_err
                      : "V1 outgoing commit route ref pin failed");
            return -EAGAIN;
        }
        pthread_mutex_lock(&service->outgoing_commit_lock);
        empty = find_outgoing_commit_locked(service, op_copy);
        if (empty && empty->state == WVM_MEMORY_COMMIT_IN_FLIGHT) {
            empty->route_op_ref_held = 1;
            pthread_mutex_unlock(&service->outgoing_commit_lock);
            return 0;
        }
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        memory_route_op_ref_put(service);
        set_error(error, error_len, "V1 outgoing commit disappeared during pin");
        return -EAGAIN;
    }
}

static void outgoing_commit_remove(
    struct wvm_memory_service *service,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    struct wvm_memory_outgoing_commit_entry *entry;
    int put_ref = 0;

    pthread_mutex_lock(&service->outgoing_commit_lock);
    entry = find_outgoing_commit_locked(service, operation_id);
    if (entry && entry->state == WVM_MEMORY_COMMIT_IN_FLIGHT) {
        put_ref = entry->route_op_ref_held;
        memset(entry, 0, sizeof(*entry));
    }
    pthread_mutex_unlock(&service->outgoing_commit_lock);
    if (put_ref)
        memory_route_op_ref_put(service);
}

static int resolve_route_with_hop(
    const struct wvm_memory_service *service,
    const struct wvm_runtime_route_destination *destination,
    struct wvm_envelope_route *route,
    struct wvm_route_runtime_next_hop *next_hop_out, char *error,
    size_t error_len)
{
    struct wvm_route_runtime_next_hop next_hop;

    if (!service || !destination || !route ||
        wvm_route_runtime_lookup_destination(
            service->config.route_runtime,
            &service->config.dispatch->required_route_snapshot_key,
            destination->destination_kind, destination->destination_scope,
            destination->destination_vnode, &next_hop, error, error_len) !=
            0) {
        return -1;
    }
    if (next_hop_out) {
        *next_hop_out = next_hop;
    }
    memset(route, 0, sizeof(*route));
    route->destination_kind = destination->destination_kind;
    route->destination_scope = destination->destination_scope;
    route->destination_vnode_or_endpoint = destination->destination_vnode;
    route->hop_limit = next_hop.hop_limit;
    return 0;
}

static int resolve_route(
    const struct wvm_memory_service *service,
    const struct wvm_runtime_route_destination *destination,
    struct wvm_envelope_route *route, char *error, size_t error_len)
{
    return resolve_route_with_hop(service, destination, route, NULL, error,
                                  error_len);
}

static struct wvm_memory_cache_entry *cache_find_locked(
    struct wvm_memory_service *service, uint64_t gpa)
{
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_CACHE_ENTRIES; i++) {
        if (service->cache[i].gpa == gpa &&
            (service->cache[i].valid || service->cache[i].resync_in_flight)) {
            return &service->cache[i];
        }
    }
    return NULL;
}

static struct wvm_memory_cache_entry *cache_slot_locked(
    struct wvm_memory_service *service, uint64_t gpa)
{
    struct wvm_memory_cache_entry *free_slot = NULL;
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_CACHE_ENTRIES; i++) {
        if (service->cache[i].gpa == gpa &&
            (service->cache[i].valid || service->cache[i].resync_in_flight)) {
            return &service->cache[i];
        }
        if (!free_slot && !service->cache[i].valid &&
            !service->cache[i].resync_in_flight) {
            free_slot = &service->cache[i];
        }
    }
    if (free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->gpa = gpa;
    }
    return free_slot;
}

static void cache_record_version(struct wvm_memory_service *service,
                                 uint64_t gpa, uint64_t version)
{
    struct wvm_memory_cache_entry *entry;

    if (!service || version == 0) {
        return;
    }
    pthread_mutex_lock(&service->cache_lock);
    entry = cache_slot_locked(service, gpa);
    if (entry && version >= entry->version) {
        entry->version = version;
        entry->valid = 1;
        entry->resync_in_flight = 0;
    }
    pthread_mutex_unlock(&service->cache_lock);
}

static int cache_accept_push(struct wvm_memory_service *service,
                             const struct wvm_mem_push *push, int *apply)
{
    struct wvm_memory_cache_entry *entry;
    int full;
    int accepted = 0;

    if (!service || !push || !apply) {
        return -EINVAL;
    }
    full = (push->flags & WVM_MEM_PUSH_FLAG_FULL) != 0;
    *apply = 0;
    pthread_mutex_lock(&service->cache_lock);
    entry = cache_find_locked(service, push->gpa);
    if (entry && entry->valid) {
        if (push->version == entry->version) {
            pthread_mutex_unlock(&service->cache_lock);
            return 0;
        }
        if (push->version < entry->version && !full) {
            pthread_mutex_unlock(&service->cache_lock);
            return 0;
        }
        if (!full && !version_is_next(entry->version, push->version)) {
            entry->valid = 0;
            entry->resync_in_flight = 0;
            pthread_mutex_unlock(&service->cache_lock);
            return -ESTALE;
        }
        if (full && push->version < entry->version) {
            pthread_mutex_unlock(&service->cache_lock);
            return 0;
        }
    } else if (!full) {
        pthread_mutex_unlock(&service->cache_lock);
        return -ESTALE;
    }
    entry = cache_slot_locked(service, push->gpa);
    if (!entry) {
        pthread_mutex_unlock(&service->cache_lock);
        return -EAGAIN;
    }
    entry->version = push->version;
    entry->valid = 0;
    accepted = 1;
    pthread_mutex_unlock(&service->cache_lock);
    *apply = accepted;
    return 0;
}

static void cache_invalidate(struct wvm_memory_service *service, uint64_t gpa)
{
    struct wvm_memory_cache_entry *entry;

    pthread_mutex_lock(&service->cache_lock);
    entry = cache_slot_locked(service, gpa);
    if (entry) {
        entry->valid = 0;
    }
    pthread_mutex_unlock(&service->cache_lock);
}

static void cache_mark_resync_in_flight(struct wvm_memory_service *service,
                                        uint64_t gpa, int in_flight)
{
    struct wvm_memory_cache_entry *entry;

    pthread_mutex_lock(&service->cache_lock);
    entry = cache_slot_locked(service, gpa);
    if (entry) {
        entry->valid = 0;
        entry->resync_in_flight = in_flight != 0;
    }
    pthread_mutex_unlock(&service->cache_lock);
}

static size_t subscriber_bucket(uint64_t gpa, size_t buckets)
{
    uint64_t page = gpa / WVM_MEMORY_PAGE_BYTES;

    page ^= page >> 33;
    page *= UINT64_C(0xff51afd7ed558ccd);
    page ^= page >> 33;
    return (size_t)(page & (buckets - 1));
}

static int subscriber_registry_init(struct wvm_memory_service *service)
{
    const struct wvm_runtime_dispatch_projection *p = service->config.dispatch;
    uint64_t pages = 0;
    uint64_t participants = 1;

    for (size_t i = 0; i < p->memory_dispatch.count; ++i) {
        const struct wvm_runtime_memory_dispatch *m = &p->memory_dispatch.entries[i];
        uint64_t count = m->bytes / WVM_MEMORY_PAGE_BYTES;

        if (m->directory_physical_node_id != service->config.local_physical_node_id ||
            m->directory_node_instance_id != service->config.local_node_instance_id)
            continue;
        if (count > UINT64_MAX - pages) return -EOVERFLOW;
        pages += count;
    }
    /* Frontend plus CPU/memory/storage participants. Duplicate placement
     * entries overestimate the bound; they cannot exclude a legitimate leaf.
     * Keep room for one retiring instance alongside each active identity. */
    if (p->cpu_dispatch.count > UINT64_MAX - participants) return -EOVERFLOW;
    participants += p->cpu_dispatch.count;
    if (p->memory_dispatch.count > UINT64_MAX - participants) return -EOVERFLOW;
    participants += p->memory_dispatch.count;
    if (p->storage_dispatch.count > UINT64_MAX - participants) return -EOVERFLOW;
    participants += p->storage_dispatch.count;
    if (participants > UINT64_MAX / 2 ||
        pages > UINT64_MAX / (participants * 2)) return -EOVERFLOW;
    service->subscriber_limit = pages * participants * 2;
    service->subscriber_bucket_count = 256;
    service->subscriber_buckets = calloc(service->subscriber_bucket_count,
                                         sizeof(*service->subscriber_buckets));
    if (!service->subscriber_buckets) {
        service->subscriber_bucket_count = 0;
        return -ENOMEM;
    }
    return 0;
}

static int subscriber_grow_locked(struct wvm_memory_service *service)
{
    size_t old_count = service->subscriber_bucket_count;
    size_t new_count;
    struct wvm_memory_subscriber **buckets;

    if (service->subscriber_count < old_count * 2) return 0;
    if (old_count > SIZE_MAX / 2 / sizeof(*buckets)) return -EOVERFLOW;
    new_count = old_count * 2;
    buckets = calloc(new_count, sizeof(*buckets));
    if (!buckets) return -ENOMEM;
    for (size_t i = 0; i < old_count; ++i) {
        struct wvm_memory_subscriber *s = service->subscriber_buckets[i];

        while (s) {
            struct wvm_memory_subscriber *next = s->next;
            size_t bucket = subscriber_bucket(s->gpa, new_count);

            s->next = buckets[bucket];
            buckets[bucket] = s;
            s = next;
        }
    }
    free(service->subscriber_buckets);
    service->subscriber_buckets = buckets;
    service->subscriber_bucket_count = new_count;
    return 0;
}

static struct wvm_memory_subscriber *subscriber_find_locked(
    struct wvm_memory_service *service, uint64_t gpa, uint32_t physical_node,
    uint64_t node_instance, uint64_t runtime_instance,
    const struct wvm_vm_route_scope_key *scope_key)
{
    size_t bucket = subscriber_bucket(gpa, service->subscriber_bucket_count);

    for (struct wvm_memory_subscriber *subscriber = service->subscriber_buckets[bucket];
         subscriber; subscriber = subscriber->next) {

        if (subscriber->state == WVM_MEMORY_SUBSCRIBER_EMPTY ||
            subscriber->state == WVM_MEMORY_SUBSCRIBER_REMOVED ||
            subscriber->gpa != gpa ||
            subscriber->subscriber_physical_node_id != physical_node ||
            subscriber->subscriber_node_instance_id != node_instance ||
            subscriber->subscriber_runtime_instance_id != runtime_instance ||
            !route_scope_key_equal(&subscriber->route_scope_key, scope_key)) {
            continue;
        }
        return subscriber;
    }
    return NULL;
}

static void subscriber_reap_bucket_locked(struct wvm_memory_service *service,
                                          size_t bucket, uint64_t now)
{
    uint64_t horizon = service->config.completion_timeout_ms;
    struct wvm_memory_subscriber **cursor = &service->subscriber_buckets[bucket];

    while (*cursor) {
        struct wvm_memory_subscriber *subscriber = *cursor;

        if ((subscriber->state == WVM_MEMORY_SUBSCRIBER_STALE ||
             subscriber->state == WVM_MEMORY_SUBSCRIBER_REMOVED) &&
            subscriber->last_validated_at != 0 && now >=
                subscriber->last_validated_at &&
            now - subscriber->last_validated_at >= horizon) {
            *cursor = subscriber->next;
            free(subscriber);
            service->subscriber_count--;
        } else {
            cursor = &subscriber->next;
        }
    }
}

static int subscriber_upsert(
    struct wvm_memory_service *service, uint64_t gpa,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint32_t physical_node, uint64_t node_instance, uint64_t runtime_instance,
    const struct wvm_vm_route_scope_key *scope_key,
    const struct wvm_runtime_route_destination *destination,
    const struct wvm_route_snapshot_key *snapshot_key, uint64_t version,
    uint64_t *qualification_revision,
    char *error, size_t error_len)
{
    struct wvm_memory_subscriber *subscriber = NULL;
    uint64_t now = monotonic_milliseconds();
    size_t bucket;

    if (!service || !operation_id || !scope_key || !destination ||
        !snapshot_key || physical_node == 0 || node_instance == 0 ||
        runtime_instance == 0) {
        set_error(error, error_len, "V1 subscriber identity is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&service->subscriber_lock);
    bucket = subscriber_bucket(gpa, service->subscriber_bucket_count);
    subscriber_reap_bucket_locked(service, bucket, now);
    subscriber = subscriber_find_locked(service, gpa, physical_node,
                                       node_instance, runtime_instance,
                                       scope_key);
    if (!subscriber) {
        if (service->subscriber_count >= service->subscriber_limit) {
            for (size_t i = 0; i < service->subscriber_bucket_count; ++i)
                subscriber_reap_bucket_locked(service, i, now);
        }
        if (service->subscriber_count < service->subscriber_limit &&
            subscriber_grow_locked(service) == 0) {
            subscriber = calloc(1, sizeof(*subscriber));
            if (subscriber) {
                bucket = subscriber_bucket(gpa, service->subscriber_bucket_count);
                subscriber->next = service->subscriber_buckets[bucket];
                service->subscriber_buckets[bucket] = subscriber;
                service->subscriber_count++;
            }
        }
    }
    if (!subscriber) {
        pthread_mutex_unlock(&service->subscriber_lock);
        set_error(error, error_len, "V1 subscriber table is full");
        return -EAGAIN;
    }
    /* A new node/runtime instance never inherits the old instance's lease. */
    for (struct wvm_memory_subscriber *old = service->subscriber_buckets[bucket];
         old; old = old->next) {

        if (old == subscriber || old->state == WVM_MEMORY_SUBSCRIBER_EMPTY ||
            old->state == WVM_MEMORY_SUBSCRIBER_REMOVED ||
            old->gpa != gpa || old->subscriber_physical_node_id != physical_node ||
            !route_scope_key_equal(&old->route_scope_key, scope_key)) {
            continue;
        }
        if (old->subscriber_node_instance_id != node_instance ||
            old->subscriber_runtime_instance_id != runtime_instance) {
            old->state = WVM_MEMORY_SUBSCRIBER_STALE;
            if (old->qualification_revision != UINT64_MAX)
                old->qualification_revision++;
        }
    }
    if (bytes_are_zero(subscriber->subscription_id,
                       sizeof(subscriber->subscription_id))) {
        memcpy(subscriber->subscription_id, operation_id,
               sizeof(subscriber->subscription_id));
    }
    subscriber->gpa = gpa;
    subscriber->subscriber_physical_node_id = physical_node;
    subscriber->subscriber_node_instance_id = node_instance;
    subscriber->subscriber_runtime_instance_id = runtime_instance;
    subscriber->route_scope_key = *scope_key;
    subscriber->destination = *destination;
    subscriber->route_snapshot_key = *snapshot_key;
    if (subscriber->state == WVM_MEMORY_SUBSCRIBER_EMPTY ||
        subscriber->state == WVM_MEMORY_SUBSCRIBER_STALE) {
        if (subscriber->qualification_revision == UINT64_MAX) {
            pthread_mutex_unlock(&service->subscriber_lock);
            return -EOVERFLOW;
        }
        subscriber->qualification_revision++;
        subscriber->observed_version = 0;
    }
    if (version > subscriber->observed_version)
        subscriber->observed_version = version;
    subscriber->delivery_requirement = WVM_MEMORY_DELIVERY_HINT;
    subscriber->state = subscriber->observed_version ?
        WVM_MEMORY_SUBSCRIBER_ACTIVE : WVM_MEMORY_SUBSCRIBER_READING;
    subscriber->last_validated_at = now;
    subscriber->lease_or_observed_epoch = snapshot_key->route_generation;
    if (qualification_revision)
        *qualification_revision = subscriber->qualification_revision;
    pthread_mutex_unlock(&service->subscriber_lock);
    return 0;
}

static int subscriber_finish_read(
    struct wvm_memory_service *service, uint64_t gpa, uint32_t physical_node,
    uint64_t node_instance, uint64_t runtime_instance,
    const struct wvm_vm_route_scope_key *scope_key, uint64_t revision,
    uint64_t version)
{
    struct wvm_memory_subscriber *s;
    int result = -ESTALE;

    pthread_mutex_lock(&service->subscriber_lock);
    s = subscriber_find_locked(service, gpa, physical_node, node_instance,
                                runtime_instance, scope_key);
    if (s && s->qualification_revision == revision &&
        (s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE ||
         s->state == WVM_MEMORY_SUBSCRIBER_READING)) {
        if (version) {
            if (version > s->observed_version) s->observed_version = version;
            s->state = WVM_MEMORY_SUBSCRIBER_ACTIVE;
            result = 0;
        } else if (!s->observed_version) {
            s->state = WVM_MEMORY_SUBSCRIBER_STALE;
            if (s->qualification_revision != UINT64_MAX)
                s->qualification_revision++;
        }
        s->last_validated_at = monotonic_milliseconds();
    }
    pthread_mutex_unlock(&service->subscriber_lock);
    return result;
}

static void subscriber_mark_stale(struct wvm_memory_service *service,
                                  const struct wvm_memory_subscriber *snapshot)
{
    struct wvm_memory_subscriber *subscriber;

    if (!service || !snapshot) {
        return;
    }
    pthread_mutex_lock(&service->subscriber_lock);
    subscriber = subscriber_find_locked(
        service, snapshot->gpa, snapshot->subscriber_physical_node_id,
        snapshot->subscriber_node_instance_id,
        snapshot->subscriber_runtime_instance_id, &snapshot->route_scope_key);
    if (subscriber && subscriber->qualification_revision ==
                          snapshot->qualification_revision) {
        subscriber->state = WVM_MEMORY_SUBSCRIBER_STALE;
        if (subscriber->qualification_revision != UINT64_MAX)
            subscriber->qualification_revision++;
        subscriber->last_validated_at = monotonic_milliseconds();
    }
    pthread_mutex_unlock(&service->subscriber_lock);
}

static int subscriber_matches_writer(
    const struct wvm_memory_subscriber *subscriber, uint32_t physical_node,
    uint64_t runtime_instance)
{
    return subscriber &&
           subscriber->subscriber_physical_node_id == physical_node &&
           subscriber->subscriber_runtime_instance_id == runtime_instance;
}

static int publish_typed_commit(
    struct wvm_memory_service *service, uint64_t gpa, uint64_t base_version,
    uint64_t result_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint32_t writer_physical_node, uint64_t writer_runtime_instance,
    char *error, size_t error_len)
{
    struct wvm_memory_subscriber *snapshot = NULL;
    uint8_t full_page[WVM_MEMORY_PAGE_BYTES];
    uint8_t payload[WVM_MEM_PUSH_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    size_t subscriber_count = 0;
    size_t i;
    int full = data_bytes >= 1024U;
    int result = 0;

    if (!service || !service->config.enable_typed_subscriber_delivery) {
        return 0;
    }
    if (!data || !operation_id || result_version == 0 || data_bytes == 0) {
        set_error(error, error_len, "V1 typed publish input is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&service->subscriber_lock);
    size_t bucket = subscriber_bucket(gpa, service->subscriber_bucket_count);
    for (struct wvm_memory_subscriber *s = service->subscriber_buckets[bucket];
         s; s = s->next) {
        if ((s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE ||
             s->state == WVM_MEMORY_SUBSCRIBER_READING) && s->gpa == gpa) {
            subscriber_count++;
        }
    }
    if (subscriber_count != 0) {
        snapshot = calloc(subscriber_count, sizeof(*snapshot));
        if (!snapshot) {
            pthread_mutex_unlock(&service->subscriber_lock);
            set_error(error, error_len, "V1 typed subscriber snapshot is full");
            return -ENOMEM;
        }
        subscriber_count = 0;
        for (struct wvm_memory_subscriber *s = service->subscriber_buckets[bucket];
             s; s = s->next) {
            if ((s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE ||
                 s->state == WVM_MEMORY_SUBSCRIBER_READING) && s->gpa == gpa) {
                snapshot[subscriber_count++] = *s;
            }
        }
    }
    pthread_mutex_unlock(&service->subscriber_lock);

    if (subscriber_count == 0) {
        free(snapshot);
        return 0;
    }
    if (full && (!service->config.read_page ||
                 service->config.read_page(service->config.opaque, gpa,
                                           full_page, &result_version, error,
                                           error_len) != 0)) {
        /* The mutation remains authoritative; HINT subscribers must resync. */
        for (i = 0; i < subscriber_count; i++)
            subscriber_mark_stale(service, &snapshot[i]);
        free(snapshot);
        return 0;
    }

    for (i = 0; i < subscriber_count; i++) {
        struct wvm_memory_subscriber *subscriber = &snapshot[i];
        struct wvm_route_snapshot_key current_key;
        struct wvm_route_runtime_next_hop next_hop;
        struct wvm_envelope_route route;
        struct wvm_envelope envelope;
        struct wvm_mem_push push;
        size_t payload_bytes = 0;
        int send_result;

        if (subscriber_matches_writer(subscriber, writer_physical_node,
                                      writer_runtime_instance)) {
            continue;
        }
        if (wvm_route_runtime_current_key(
                service->config.route_runtime, &subscriber->route_scope_key,
                &current_key) != 0 ||
            wvm_route_runtime_lookup_destination(
                service->config.route_runtime, &current_key,
                subscriber->destination.destination_kind,
                subscriber->destination.destination_scope,
                subscriber->destination.destination_vnode, &next_hop, error,
                error_len) != 0) {
            subscriber_mark_stale(service, subscriber);
            if (subscriber->delivery_requirement ==
                WVM_MEMORY_DELIVERY_FENCE_REQUIRED) {
                result = -ESTALE;
            }
            continue;
        }
        memset(&route, 0, sizeof(route));
        route.destination_kind = subscriber->destination.destination_kind;
        route.destination_scope = subscriber->destination.destination_scope;
        route.destination_vnode_or_endpoint =
            subscriber->destination.destination_vnode;
        route.hop_limit = next_hop.hop_limit;
        memset(&push, 0, sizeof(push));
        push.gpa = gpa;
        push.base_version = full ? 0 : base_version;
        push.version = result_version;
        push.offset = full ? 0 : offset;
        push.size = full ? WVM_MEMORY_PAGE_BYTES : (uint16_t)data_bytes;
        push.flags = full ? WVM_MEM_PUSH_FLAG_FULL : 0;
        push.directory_physical_node_id =
            service->config.local_physical_node_id;
        push.directory_node_instance_id = service->config.local_node_instance_id;
        push.data = full ? full_page : data;
        push.data_bytes = full ? WVM_MEMORY_PAGE_BYTES : data_bytes;
        if (wvm_mem_push_encode(
                &push, payload, sizeof(payload), &payload_bytes, error,
                error_len) != 0) {
            subscriber_mark_stale(service, subscriber);
            continue;
        }
        envelope_from_route_key(
            service, full ? WVM_ENVELOPE_MSG_PAGE_PUSH_FULL
                          : WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF,
            operation_id, next_delivery_attempt(service), &route, &current_key,
            payload, payload_bytes, &envelope);
        send_result = service->config.send_envelope(
            service->config.opaque, &envelope, error, error_len);
        if (send_result != 0) {
            subscriber_mark_stale(service, subscriber);
            if (subscriber->delivery_requirement ==
                WVM_MEMORY_DELIVERY_FENCE_REQUIRED) {
                result = send_result;
            }
            continue;
        }
        pthread_mutex_lock(&service->subscriber_lock);
        {
            struct wvm_memory_subscriber *live = subscriber_find_locked(
                service, subscriber->gpa,
                subscriber->subscriber_physical_node_id,
                subscriber->subscriber_node_instance_id,
                subscriber->subscriber_runtime_instance_id,
                &subscriber->route_scope_key);
            if (live) {
                /* send_envelope only confirms local transport submission.
                 * HINT has no application ACK, so do not claim the receiver
                 * installed this version. A later read re-qualifies it. */
                live->route_snapshot_key = current_key;
            }
        }
        pthread_mutex_unlock(&service->subscriber_lock);
    }
    free(snapshot);
    return result;
}

static void derive_resync_operation_id(
    uint64_t gpa, uint64_t version,
    const uint8_t source_operation_id[WVM_IDENTITY_ID_BYTES],
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    uint8_t seed[sizeof(gpa) + sizeof(version) + WVM_IDENTITY_ID_BYTES];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    memcpy(seed, &gpa, sizeof(gpa));
    memcpy(seed + sizeof(gpa), &version, sizeof(version));
    memcpy(seed + sizeof(gpa) + sizeof(version), source_operation_id,
           WVM_IDENTITY_ID_BYTES);
    wvm_sha256_digest(seed, sizeof(seed), digest);
    memcpy(operation_id, digest, WVM_IDENTITY_ID_BYTES);
    if (bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES)) {
        operation_id[0] = 1;
    }
}

static int request_page_resync(struct wvm_memory_service *service,
                               uint64_t gpa, uint64_t version,
                               const uint8_t source_operation_id[
                                   WVM_IDENTITY_ID_BYTES],
                               char *error, size_t error_len)
{
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    int result;

    pthread_mutex_lock(&service->cache_lock);
    {
        struct wvm_memory_cache_entry *entry = cache_slot_locked(service, gpa);
        if (entry && entry->resync_in_flight) {
            pthread_mutex_unlock(&service->cache_lock);
            return 0;
        }
        if (entry) {
            entry->resync_in_flight = 1;
            entry->valid = 0;
        }
    }
    pthread_mutex_unlock(&service->cache_lock);
    derive_resync_operation_id(gpa, version, source_operation_id,
                               operation_id);
    result = wvm_memory_service_request_fault(
        service, gpa, operation_id, next_delivery_attempt(service), error,
        error_len);
    if (result != 0 && result != -EALREADY) {
        cache_mark_resync_in_flight(service, gpa, 0);
    }
    return result == -EALREADY ? 0 : result;
}

static void envelope_from_route_key(
    const struct wvm_memory_service *service, uint16_t message_type,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, const struct wvm_envelope_route *route,
    const struct wvm_route_snapshot_key *snapshot_key,
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_envelope *envelope)
{
    memset(envelope, 0, sizeof(*envelope));
    envelope->message_type = message_type;
    envelope->vm_id = service->config.dispatch->vm_id;
    envelope->vm_incarnation = service->config.dispatch->vm_incarnation;
    envelope->manifest_generation =
        service->config.dispatch->manifest_generation;
    envelope->origin_physical_node_id = service->config.local_physical_node_id;
    envelope->origin_runtime_instance_id =
        service->config.local_runtime_instance_id;
    memcpy(envelope->operation_id, operation_id, sizeof(envelope->operation_id));
    envelope->delivery_attempt_id = delivery_attempt_id;
    envelope->route_scope_id = snapshot_key->scope_key.route_scope_id;
    envelope->topology_revision = snapshot_key->topology_revision;
    envelope->route_generation = snapshot_key->route_generation;
    memcpy(envelope->route_snapshot_digest, snapshot_key->snapshot_digest,
           sizeof(envelope->route_snapshot_digest));
    envelope->route = *route;
    envelope->payload = payload;
    envelope->payload_bytes = payload_bytes;
}

static void envelope_from_projection(
    const struct wvm_memory_service *service, uint16_t message_type,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, const struct wvm_envelope_route *route,
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_envelope *envelope)
{
    envelope_from_route_key(
        service, message_type, operation_id, delivery_attempt_id, route,
        &service->config.dispatch->required_route_snapshot_key, payload,
        payload_bytes, envelope);
}

static int complete_local_fault(struct wvm_memory_service *service,
                                const uint8_t operation_id[
                                    WVM_IDENTITY_ID_BYTES],
                                uint64_t gpa, uint64_t version,
                                uint16_t status,
                                uint32_t directory_physical_node_id,
                                uint64_t directory_node_instance_id,
                                const uint8_t *data, size_t data_bytes,
                                char *error, size_t error_len)
{
    return service->config.complete_fault(
        service->config.opaque, operation_id, gpa, version, status,
        directory_physical_node_id, directory_node_instance_id, data,
        data_bytes, error, error_len);
}

static int service_remote_read(struct wvm_memory_service *service,
                               const struct wvm_envelope *envelope,
                               char *error, size_t error_len)
{
    struct wvm_mem_read read;
    const struct wvm_runtime_memory_dispatch *memory;
    struct wvm_runtime_route_destination reply_destination;
    struct wvm_route_runtime_next_hop reply_next_hop;
    struct wvm_envelope_route reply_route;
    struct wvm_mem_ack ack;
    struct wvm_envelope response;
    struct wvm_vm_route_scope_key subscriber_scope;
    struct wvm_route_snapshot_key subscriber_snapshot;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint8_t payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    uint64_t version = 0;
    uint64_t response_attempt;
    uint64_t subscriber_revision = 0;
    size_t payload_bytes = 0;
    int read_result;

    if (wvm_mem_read_decode(envelope->payload, envelope->payload_bytes,
                               &read, error, error_len) != 0 ||
        !route_destination_equal(&service->config.dispatch->local_primary,
                                 &envelope->route) ||
        !(memory = wvm_runtime_dispatch_find_memory(
              service->config.dispatch, read.gpa)) ||
        memory->directory_physical_node_id !=
            service->config.local_physical_node_id ||
        memory->directory_node_instance_id !=
            service->config.local_node_instance_id) {
        set_error(error, error_len, "V1 memory read targets a nonlocal directory");
        return -EPERM;
    }

    memset(&reply_destination, 0, sizeof(reply_destination));
    reply_destination.destination_kind = read.reply_destination_kind;
    reply_destination.destination_scope = read.reply_destination_scope;
    reply_destination.destination_vnode = read.reply_destination_vnode;
    if (resolve_route_with_hop(service, &reply_destination, &reply_route,
                               &reply_next_hop, error, error_len) != 0) {
        return -ESTALE;
    }
    memset(&ack, 0, sizeof(ack));
    ack.gpa = read.gpa;
    ack.directory_physical_node_id = service->config.local_physical_node_id;
    ack.directory_node_instance_id = service->config.local_node_instance_id;
    /* Join the update target set before the page snapshot. Registering after
     * sending an ACK can miss a concurrent commit and leave a stale CLEAN page. */
    read_result = 0;
    if (service->config.enable_typed_subscriber_delivery) {
        memset(&subscriber_scope, 0, sizeof(subscriber_scope));
        subscriber_scope.vm_id = envelope->vm_id;
        subscriber_scope.vm_incarnation = envelope->vm_incarnation;
        subscriber_scope.route_scope_id = envelope->route_scope_id;
        memset(&subscriber_snapshot, 0, sizeof(subscriber_snapshot));
        subscriber_snapshot.scope_key = subscriber_scope;
        subscriber_snapshot.topology_revision = envelope->topology_revision;
        subscriber_snapshot.route_generation = envelope->route_generation;
        memcpy(subscriber_snapshot.snapshot_digest, envelope->route_snapshot_digest,
               sizeof(subscriber_snapshot.snapshot_digest));
        read_result = subscriber_upsert(
            service, read.gpa, envelope->operation_id,
            envelope->origin_physical_node_id, read.reply_node_instance_id,
            envelope->origin_runtime_instance_id, &subscriber_scope,
            &reply_destination, &subscriber_snapshot, 0, &subscriber_revision,
            error, error_len);
    }
    if (read_result == 0) {
        read_result = service->config.read_page(service->config.opaque, read.gpa,
                                                page, &version, error, error_len);
        if (service->config.enable_typed_subscriber_delivery) {
            int qualified = subscriber_finish_read(
                service, read.gpa, envelope->origin_physical_node_id,
                read.reply_node_instance_id, envelope->origin_runtime_instance_id,
                &subscriber_scope, subscriber_revision, read_result ? 0 : version);

            if (!read_result && qualified) read_result = qualified;
        }
    }
    if (read_result == 0) {
        ack.version = version;
        ack.status = WVM_MEM_ACK_SUCCESS;
        ack.data = page;
        ack.data_bytes = sizeof(page);
    } else {
        ack.status = read_result == -ENOENT ? WVM_MEM_ACK_NOT_FOUND
                                            : WVM_MEM_ACK_INTERNAL_FAILURE;
    }
    if (envelope->delivery_attempt_id == UINT64_MAX) {
        set_error(error, error_len, "V1 memory read delivery attempt overflow");
        return -ERANGE;
    }
    response_attempt = envelope->delivery_attempt_id + 1U;
    if (wvm_mem_ack_envelope_build(
            envelope, &reply_route, response_attempt, &ack, payload,
            sizeof(payload), &payload_bytes, &response, error, error_len) !=
        0) {
        return -EINVAL;
    }
    read_result = service->config.send_envelope(service->config.opaque,
                                                &response, error, error_len);
    return read_result;
}

static int service_remote_push(struct wvm_memory_service *service,
                               const struct wvm_envelope *envelope,
                               char *error, size_t error_len)
{
    struct wvm_mem_push push;
    const struct wvm_runtime_memory_dispatch *memory;
    int apply = 0;
    int result;

    if (!service->config.enable_typed_subscriber_delivery ||
        !service->config.apply_push ||
        wvm_mem_push_decode(envelope->payload, envelope->payload_bytes, &push,
                            error, error_len) != 0 ||
        !route_destination_equal(&service->config.dispatch->local_primary,
                                 &envelope->route) ||
        envelope->origin_physical_node_id !=
            push.directory_physical_node_id ||
        envelope->origin_runtime_instance_id !=
            push.directory_node_instance_id ||
        !(memory = wvm_runtime_dispatch_find_memory(
              service->config.dispatch, push.gpa)) ||
        memory->directory_physical_node_id !=
            push.directory_physical_node_id ||
        memory->directory_node_instance_id !=
            push.directory_node_instance_id) {
        set_error(error, error_len, "V1 memory push authority is not admitted");
        return -EPERM;
    }
    result = cache_accept_push(service, &push, &apply);
    if (result == -ESTALE) {
        result = request_page_resync(service, push.gpa, push.version,
                                     envelope->operation_id, error, error_len);
        return result == 0 ? 0 : result;
    }
    if (result != 0 || !apply) {
        return result;
    }
    result = service->config.apply_push(
        service->config.opaque, push.directory_physical_node_id,
        push.directory_node_instance_id, push.gpa, push.base_version,
        push.version, push.offset, push.data, push.data_bytes,
        (push.flags & WVM_MEM_PUSH_FLAG_FULL) != 0, error, error_len);
    if (result != 0) {
        cache_invalidate(service, push.gpa);
        return result;
    }
    cache_record_version(service, push.gpa, push.version);
    return 0;
}

static int accept_read_result(struct wvm_memory_service *service,
                              const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                              const struct wvm_mem_ack *ack,
                              const uint8_t payload_digest[WVM_SHA256_DIGEST_BYTES],
                              int *completed, char *error, size_t error_len)
{
    struct wvm_memory_pending_entry *pending;
    int completion_result;
    int put_ref = 0;

    *completed = 0;
    pthread_mutex_lock(&service->pending_lock);
    pending = find_pending_locked(service, operation_id);
    if (!pending) {
        pthread_mutex_unlock(&service->pending_lock);
        set_error(error, error_len, "V1 memory ACK has no pending operation");
        return -ENOENT;
    }
    if (pending->gpa != ack->gpa ||
        pending->directory_physical_node_id !=
            ack->directory_physical_node_id ||
        pending->directory_node_instance_id !=
            ack->directory_node_instance_id) {
        pthread_mutex_unlock(&service->pending_lock);
        set_error(error, error_len, "V1 memory ACK directory authority mismatch");
        return -EPERM;
    }
    if (pending->result_version != 0 &&
        (ack->status != WVM_MEM_ACK_SUCCESS ||
         ack->version < pending->result_version)) {
        /* A delayed retry result cannot replace a newer completed snapshot. */
        pthread_mutex_unlock(&service->pending_lock);
        return 0;
    }
    if (pending->result_version != 0 && ack->version == pending->result_version &&
        memcmp(pending->completion_payload_digest, payload_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        pthread_mutex_unlock(&service->pending_lock);
        set_error(error, error_len, "memory read changed bytes at the same version");
        return -EEXIST;
    }
    if (pending->state != WVM_MEMORY_PENDING_WAITING) {
        /* Only an explicitly reissued read can complete its consumer again. */
        pthread_mutex_unlock(&service->pending_lock);
        return 0;
    }
    pending->state = WVM_MEMORY_PENDING_COMPLETING;
    pthread_mutex_unlock(&service->pending_lock);

    completion_result = complete_local_fault(
        service, operation_id, ack->gpa, ack->version, ack->status,
        ack->directory_physical_node_id, ack->directory_node_instance_id,
        ack->data, ack->data_bytes, error, error_len);
    if (completion_result == 0 && ack->status == WVM_MEM_ACK_SUCCESS) {
        cache_record_version(service, ack->gpa, ack->version);
    }

    pthread_mutex_lock(&service->pending_lock);
    pending = find_pending_locked(service, operation_id);
    if (pending && pending->state == WVM_MEMORY_PENDING_COMPLETING) {
        if (completion_result == 0) {
            put_ref = pending->route_op_ref_held;
            pending->route_op_ref_held = 0;
            pending->state = WVM_MEMORY_PENDING_COMPLETED;
            pending->retained_until_ms = retention_deadline_ms(service);
            pending->result_version = ack->version;
            service->pending_active--;
            *completed = 1;
            memcpy(pending->completion_payload_digest, payload_digest,
                   WVM_SHA256_DIGEST_BYTES);
        } else {
            pending->state = WVM_MEMORY_PENDING_WAITING;
        }
    }
    pthread_mutex_unlock(&service->pending_lock);
    if (put_ref) memory_route_op_ref_put(service);
    pthread_mutex_lock(&g_global_memory_service.lock);
    pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
    pthread_mutex_unlock(&g_global_memory_service.lock);
    return completion_result;
}

static int service_remote_ack(struct wvm_memory_service *service,
                              const struct wvm_envelope *envelope,
                              char *error, size_t error_len)
{
    struct wvm_mem_ack ack;
    uint8_t payload_digest[WVM_SHA256_DIGEST_BYTES];
    int completed;
    int result;

    if (wvm_mem_ack_decode(envelope->payload, envelope->payload_bytes, &ack,
                           error, error_len) != 0 ||
        !route_destination_equal(&service->config.dispatch->local_primary,
                                 &envelope->route)) {
        set_error(error, error_len, "V1 memory ACK does not target this runtime");
        return -EPERM;
    }
    wvm_envelope_semantic_digest(envelope->payload, envelope->payload_bytes,
                                 payload_digest);
    result = accept_read_result(service, envelope->operation_id, &ack,
                                 payload_digest, &completed, error, error_len);
    if (completed && ack.status == WVM_MEM_ACK_SUCCESS) {
        record_remote_completion(service, envelope,
                                 ack.directory_physical_node_id,
                                 ack.directory_node_instance_id, ack.gpa, 0);
    }
    return result;
}

static int commit_entry_begin(
    struct wvm_memory_service *service,
    const struct wvm_envelope *envelope,
    const uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES],
    struct wvm_memory_commit_entry **entry_out, int *replay,
    char *error, size_t error_len)
{
    struct wvm_memory_commit_entry *empty = NULL;
    size_t i;

    if (!service || !envelope || !semantic_payload_digest || !entry_out ||
        !replay) {
        set_error(error, error_len, "V1 memory commit identity is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&service->commit_lock);
    reap_commit_completed_locked(service, monotonic_milliseconds());
    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct wvm_memory_commit_entry *entry = &service->commits[i];

        if (entry->state == WVM_MEMORY_COMMIT_EMPTY) {
            if (!empty) {
                empty = entry;
            }
            continue;
        }
        if (entry->origin_physical_node_id !=
                envelope->origin_physical_node_id ||
            entry->origin_runtime_instance_id !=
                envelope->origin_runtime_instance_id ||
            memcmp(entry->operation_id, envelope->operation_id,
                   sizeof(entry->operation_id)) != 0) {
            continue;
        }
        if (memcmp(entry->semantic_payload_digest, semantic_payload_digest,
                   sizeof(entry->semantic_payload_digest)) != 0) {
            pthread_mutex_unlock(&service->commit_lock);
            set_error(error, error_len,
                      "V1 memory commit operation ID conflicts with payload");
            return -EEXIST;
        }
        if (entry->state == WVM_MEMORY_COMMIT_IN_FLIGHT) {
            pthread_mutex_unlock(&service->commit_lock);
            set_error(error, error_len,
                      "V1 memory commit is already executing");
            return -EAGAIN;
        }
        if (entry->state == WVM_MEMORY_COMMIT_COMPLETED) {
            *entry_out = entry;
            *replay = 1;
        } else {
            /*
             * A prior bounded-backpressure response did not mutate the page.
             * Preserve the identity binding but let this same operation make
             * a fresh attempt.
             */
            entry->state = WVM_MEMORY_COMMIT_IN_FLIGHT;
            *entry_out = entry;
            *replay = 0;
        }
        pthread_mutex_unlock(&service->commit_lock);
        return 0;
    }
    if (!empty) {
        pthread_mutex_unlock(&service->commit_lock);
        set_error(error, error_len, "V1 memory commit result table is full");
        return -EAGAIN;
    }
    memset(empty, 0, sizeof(*empty));
    memcpy(empty->operation_id, envelope->operation_id,
           sizeof(empty->operation_id));
    memcpy(empty->semantic_payload_digest, semantic_payload_digest,
           sizeof(empty->semantic_payload_digest));
    empty->origin_physical_node_id = envelope->origin_physical_node_id;
    empty->origin_runtime_instance_id = envelope->origin_runtime_instance_id;
    empty->state = WVM_MEMORY_COMMIT_IN_FLIGHT;
    *entry_out = empty;
    *replay = 0;
    pthread_mutex_unlock(&service->commit_lock);
    return 0;
}

static void commit_entry_complete(
    struct wvm_memory_service *service,
    struct wvm_memory_commit_entry *entry,
    const struct wvm_mem_commit_ack *result)
{
    if (!service || !entry || !result) {
        return;
    }
    pthread_mutex_lock(&service->commit_lock);
    entry->result = *result;
    entry->retained_until_ms = retention_deadline_ms(service);
    entry->state = WVM_MEMORY_COMMIT_COMPLETED;
    pthread_mutex_unlock(&service->commit_lock);
}

static void commit_entry_retryable(
    struct wvm_memory_service *service,
    struct wvm_memory_commit_entry *entry)
{
    if (!service || !entry) {
        return;
    }
    pthread_mutex_lock(&service->commit_lock);
    entry->retained_until_ms = retention_deadline_ms(service);
    entry->state = WVM_MEMORY_COMMIT_RETRYABLE;
    pthread_mutex_unlock(&service->commit_lock);
}

static uint16_t commit_status_from_result(int result);

static uint16_t commit_status_from_result(int result)
{
    if (result == 0) {
        return WVM_MEM_COMMIT_ACK_SUCCESS;
    }
    if (result == -ESTALE) {
        return WVM_MEM_COMMIT_ACK_STALE_BASE_VERSION;
    }
    if (result == -ENOENT) {
        return WVM_MEM_COMMIT_ACK_NOT_FOUND;
    }
    if (result == -EAGAIN || result == -ENOBUFS) {
        return WVM_MEM_COMMIT_ACK_BACKPRESSURE;
    }
    return WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
}

static int service_local_commit(
    struct wvm_memory_service *service, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    int source_shared_backing, char *error, size_t error_len)
{
    const struct wvm_runtime_memory_dispatch *memory;
    uint64_t result_version = 0;
    uint16_t status;
    int publish_result = 0;
    int apply_result;

    if (!service || !operation_id || !service->config.commit_page ||
        !service->config.complete_commit ||
        !(memory = wvm_runtime_dispatch_find_memory(
              service->config.dispatch, gpa)) ||
        memory->directory_physical_node_id !=
            service->config.local_physical_node_id ||
        memory->directory_node_instance_id !=
            service->config.local_node_instance_id) {
        set_error(error, error_len,
                  "V1 local commit has no admitted local directory adapter");
        return -ENOTSUP;
    }

    apply_result = service->config.commit_page(
        service->config.opaque, gpa, base_version, offset, data, data_bytes,
        source_shared_backing, &result_version, error, error_len);
    status = commit_status_from_result(apply_result);
    if (status == WVM_MEM_COMMIT_ACK_SUCCESS && result_version == 0) {
        status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
    }
    if (status != WVM_MEM_COMMIT_ACK_SUCCESS) {
        result_version = 0;
    } else if (service->config.publish_commit) {
        /*
         * Publishing is deliberately after the authoritative page mutation.
         * A required local delivery failure is reported as an incomplete
         * fence. The mutation remains identified by the caller's operation;
         * retry must resync/retry delivery, never apply the bytes a second time.
         */
        publish_result = service->config.publish_commit(
            service->config.opaque, gpa, result_version, offset, data,
            data_bytes, service->config.local_physical_node_id, error,
            error_len);
        if (publish_result != 0) {
            status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
            result_version = 0;
        }
    }
    if (status == WVM_MEM_COMMIT_ACK_SUCCESS &&
        service->config.enable_typed_subscriber_delivery) {
        publish_result = publish_typed_commit(
            service, gpa, base_version, result_version, offset, data,
            data_bytes, operation_id, service->config.local_physical_node_id,
            service->config.local_runtime_instance_id, error, error_len);
        if (publish_result != 0) {
            status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
            result_version = 0;
        } else {
            struct wvm_vm_route_scope_key scope_key =
                service->config.dispatch->required_route_snapshot_key.scope_key;

            (void)subscriber_upsert(
                service, gpa, operation_id,
                service->config.local_physical_node_id,
                service->config.local_node_instance_id,
                service->config.local_runtime_instance_id, &scope_key,
                &service->config.dispatch->local_primary,
                &service->config.dispatch->required_route_snapshot_key,
                result_version, NULL, error, error_len);
        }
    }
    if (status == WVM_MEM_COMMIT_ACK_SUCCESS) {
        cache_record_version(service, gpa, result_version);
    }
    return service->config.complete_commit(
        service->config.opaque, operation_id, gpa, status, result_version,
        service->config.local_physical_node_id,
        service->config.local_node_instance_id, error, error_len);
}

static int service_remote_commit_ack(
    struct wvm_memory_service *service,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    struct wvm_mem_commit_ack ack;
    struct wvm_memory_outgoing_commit_entry *pending;
    struct wvm_mem_commit_ack previous;
    int duplicate;
    int completion_result;

    if (!service->config.complete_commit ||
        envelope->payload_bytes != WVM_MEM_COMMIT_ACK_BYTES ||
        wvm_mem_commit_ack_decode(envelope->payload, &ack, error,
                                     error_len) != 0 ||
        !route_destination_equal(&service->config.dispatch->local_primary,
                                 &envelope->route) ||
        envelope->origin_physical_node_id !=
            service->config.local_physical_node_id ||
        envelope->origin_runtime_instance_id !=
            service->config.local_runtime_instance_id) {
        set_error(error, error_len,
                  "V1 memory commit ACK does not target this runtime");
        return -EPERM;
    }
    pthread_mutex_lock(&service->outgoing_commit_lock);
    pending = find_outgoing_commit_locked(service, envelope->operation_id);
    if (!pending) {
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        set_error(error, error_len,
                  "V1 memory commit ACK has no pending operation");
        return -ENOENT;
    }
    if (pending->gpa != ack.gpa ||
        pending->directory_physical_node_id !=
            ack.directory_physical_node_id ||
        pending->directory_node_instance_id !=
            ack.directory_node_instance_id) {
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        set_error(error, error_len,
                  "V1 memory commit ACK directory authority mismatch");
        return -EPERM;
    }
    if (pending->state == WVM_MEMORY_COMMIT_COMPLETED) {
        previous = pending->result;
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        duplicate = previous.gpa == ack.gpa &&
                    previous.result_version == ack.result_version &&
                    previous.status == ack.status &&
                    previous.directory_physical_node_id ==
                        ack.directory_physical_node_id &&
                    previous.directory_node_instance_id ==
                        ack.directory_node_instance_id;
        if (!duplicate) {
            set_error(error, error_len,
                      "V1 memory commit ACK conflicts with completion");
            return -EEXIST;
        }
        return 0;
    }
    pending->result = ack;
    /*
     * Claim completion before calling the local consumer. A retransmitted ACK
     * must never make a QEMU dirty journal apply its completion twice.
     */
    {
        int put_ref = pending->route_op_ref_held;

        pending->route_op_ref_held = 0;
        pending->state = WVM_MEMORY_COMMIT_COMPLETED;
        pending->retained_until_ms = retention_deadline_ms(service);
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        if (put_ref)
            memory_route_op_ref_put(service);
    }

    completion_result = service->config.complete_commit(
        service->config.opaque, envelope->operation_id, ack.gpa, ack.status,
        ack.result_version, ack.directory_physical_node_id,
        ack.directory_node_instance_id, error, error_len);
    if (completion_result == 0 && ack.status == WVM_MEM_COMMIT_ACK_SUCCESS) {
        record_remote_completion(service, envelope,
                                 ack.directory_physical_node_id,
                                 ack.directory_node_instance_id, ack.gpa, 1);
    }
    return completion_result;
}

static int service_request_commit(
    struct wvm_memory_service *service, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, int source_shared_backing,
    char *error, size_t error_len)
{
    const struct wvm_runtime_memory_dispatch *memory;
    struct wvm_mem_commit commit;
    struct wvm_envelope_route route;
    struct wvm_envelope envelope;
    uint8_t payload[WVM_MEM_COMMIT_HEADER_BYTES +
                    WVM_MEMORY_PAGE_BYTES];
    uint8_t payload_digest[WVM_SHA256_DIGEST_BYTES];
    size_t payload_bytes;
    int already_waiting = 0;
    int result;

    if (!service || !service->initialized || !operation_id ||
        bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES) ||
        delivery_attempt_id == 0 || base_version == 0 ||
        data_bytes == 0 || data_bytes > WVM_MEMORY_PAGE_BYTES ||
        offset > WVM_MEMORY_PAGE_BYTES - data_bytes ||
        !data || !(memory = wvm_runtime_dispatch_find_memory(
                       service->config.dispatch, gpa))) {
        set_error(error, error_len, "V1 memory commit has no admitted mapping");
        return -EINVAL;
    }
    if (memory->directory_physical_node_id ==
            service->config.local_physical_node_id &&
        memory->directory_node_instance_id ==
            service->config.local_node_instance_id) {
        return service_local_commit(
            service, gpa, base_version, offset, data, data_bytes,
            operation_id, source_shared_backing, error, error_len);
    }
    if (!service->config.complete_commit) {
        set_error(error, error_len,
                  "V1 memory commit completion adapter is not installed");
        return -ENOTSUP;
    }
    memset(&commit, 0, sizeof(commit));
    commit.gpa = gpa;
    commit.base_version = base_version;
    commit.offset = offset;
    commit.size = (uint16_t)data_bytes;
    commit.reply_destination_kind =
        service->config.dispatch->local_primary.destination_kind;
    commit.reply_destination_scope =
        service->config.dispatch->local_primary.destination_scope;
    commit.reply_destination_vnode =
        service->config.dispatch->local_primary.destination_vnode;
    commit.reply_node_instance_id = service->config.local_node_instance_id;
    commit.data = data;
    commit.data_bytes = data_bytes;
    if (resolve_route(service, &memory->directory, &route, error, error_len) !=
        0 ||
        wvm_mem_commit_encode(&commit, payload, sizeof(payload),
                                 &payload_bytes, error, error_len) != 0) {
        return -ESTALE;
    }
    wvm_envelope_semantic_digest(payload, payload_bytes, payload_digest);
    result = outgoing_commit_register(
        service, operation_id, payload_digest, memory, gpa, &already_waiting,
        error, error_len);
    if (result != 0) {
        return result;
    }
    envelope_from_projection(service, WVM_ENVELOPE_MSG_COMMIT_DIFF,
                             operation_id, delivery_attempt_id, &route, payload,
                             payload_bytes, &envelope);
    result = service->config.send_envelope(service->config.opaque, &envelope,
                                           error, error_len);
    if (result != 0 && !already_waiting) {
        outgoing_commit_remove(service, operation_id);
    }
    return result;
}

static int service_remote_commit(struct wvm_memory_service *service,
                                 const struct wvm_envelope *envelope,
                                 char *error, size_t error_len)
{
    struct wvm_mem_commit commit;
    const struct wvm_runtime_memory_dispatch *memory;
    struct wvm_runtime_route_destination reply_destination;
    struct wvm_envelope_route reply_route;
    struct wvm_memory_commit_entry *entry;
    struct wvm_mem_commit_ack result;
    struct wvm_envelope response;
    struct wvm_route_runtime_next_hop reply_next_hop;
    uint8_t payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t response_payload[WVM_MEM_COMMIT_ACK_BYTES];
    uint64_t result_version = 0;
    uint64_t response_attempt;
    int replay;
    int apply_result;
    int publish_result = 0;

    if (!service->config.commit_page) {
        set_error(error, error_len,
                  "V1 directory commit adapter is not installed");
        return -ENOTSUP;
    }
    if (wvm_mem_commit_decode(envelope->payload, envelope->payload_bytes,
                                 &commit, error, error_len) != 0 ||
        !route_destination_equal(&service->config.dispatch->local_primary,
                                 &envelope->route) ||
        !(memory = wvm_runtime_dispatch_find_memory(
              service->config.dispatch, commit.gpa)) ||
        memory->directory_physical_node_id !=
            service->config.local_physical_node_id ||
        memory->directory_node_instance_id !=
            service->config.local_node_instance_id) {
        set_error(error, error_len,
                  "V1 memory commit targets a nonlocal directory");
        return -EPERM;
    }
    memset(&reply_destination, 0, sizeof(reply_destination));
    reply_destination.destination_kind = commit.reply_destination_kind;
    reply_destination.destination_scope = commit.reply_destination_scope;
    reply_destination.destination_vnode = commit.reply_destination_vnode;
    if (resolve_route_with_hop(service, &reply_destination, &reply_route,
                               &reply_next_hop, error, error_len) != 0) {
        return -ESTALE;
    }
    wvm_envelope_semantic_digest(envelope->payload, envelope->payload_bytes,
                                    payload_digest);
    apply_result = commit_entry_begin(service, envelope, payload_digest, &entry,
                                      &replay, error, error_len);
    if (apply_result != 0) {
        return apply_result;
    }

    if (replay) {
        result = entry->result;
    } else {
        memset(&result, 0, sizeof(result));
        result.gpa = commit.gpa;
        result.directory_physical_node_id =
            service->config.local_physical_node_id;
        result.directory_node_instance_id =
            service->config.local_node_instance_id;
        apply_result = service->config.commit_page(
            service->config.opaque, commit.gpa, commit.base_version,
            commit.offset, commit.data, commit.data_bytes, 0,
            &result_version, error, error_len);
        result.status = commit_status_from_result(apply_result);
        if (result.status == WVM_MEM_COMMIT_ACK_SUCCESS) {
            if (result_version == 0) {
                result.status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
            } else {
                result.result_version = result_version;
                if (service->config.publish_commit) {
                    /*
                     * Do not republish a replayed result: only the directory
                     * apply path above owns subscriber delivery for this ID.
                     */
                    int publish_result = service->config.publish_commit(
                        service->config.opaque, commit.gpa, result_version,
                        commit.offset, commit.data, commit.data_bytes,
                        envelope->origin_physical_node_id, error,
                        error_len);
                    if (publish_result != 0) {
                        result.status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
                        result.result_version = 0;
                    }
                }
                if (result.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                    service->config.enable_typed_subscriber_delivery) {
                    publish_result = publish_typed_commit(
                        service, commit.gpa, commit.base_version, result_version,
                        commit.offset, commit.data, commit.data_bytes,
                        envelope->operation_id,
                        envelope->origin_physical_node_id,
                        envelope->origin_runtime_instance_id, error,
                        error_len);
                    if (publish_result != 0) {
                        result.status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
                        result.result_version = 0;
                    } else {
                        struct wvm_vm_route_scope_key scope_key =
                            service->config.dispatch->required_route_snapshot_key
                                .scope_key;

                        (void)subscriber_upsert(
                            service, commit.gpa, envelope->operation_id,
                            envelope->origin_physical_node_id,
                            commit.reply_node_instance_id,
                            envelope->origin_runtime_instance_id, &scope_key,
                            &reply_destination,
                            &service->config.dispatch
                                 ->required_route_snapshot_key,
                            result_version, NULL, error, error_len);
                    }
                }
            }
        }
        if (result.status == WVM_MEM_COMMIT_ACK_BACKPRESSURE) {
            commit_entry_retryable(service, entry);
        } else {
            commit_entry_complete(service, entry, &result);
        }
    }
    if (envelope->delivery_attempt_id == UINT64_MAX) {
        set_error(error, error_len,
                  "V1 memory commit delivery attempt overflow");
        return -ERANGE;
    }
    response_attempt = envelope->delivery_attempt_id + 1U;
    if (wvm_mem_commit_ack_envelope_build(
            envelope, &reply_route, response_attempt, &result,
            response_payload, &response, error, error_len) != 0) {
        return -EINVAL;
    }
    return service->config.send_envelope(service->config.opaque, &response,
                                         error, error_len);
}

int wvm_memory_service_init(
    struct wvm_memory_service *service,
    const struct wvm_memory_service_config *config, char *error,
    size_t error_len)
{
    if (!service || !config || !config->dispatch || !config->route_runtime ||
        config->local_physical_node_id == 0 ||
        config->local_node_instance_id == 0 ||
        config->local_runtime_instance_id == 0 ||
        config->completion_timeout_ms == 0 || !config->read_page ||
        !config->complete_fault || !config->send_envelope ||
        (config->enable_typed_subscriber_delivery &&
         (!config->apply_push || !config->publish_commit)) ||
        wvm_runtime_dispatch_projection_validate(config->dispatch, error,
                                                 error_len) != 0 ||
        config->dispatch->physical_node_id != config->local_physical_node_id ||
        config->dispatch->expected_node_instance_id !=
            config->local_node_instance_id ||
        !wvm_route_runtime_has_snapshot(
            config->route_runtime,
            &config->dispatch->required_route_snapshot_key)) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "V1 memory service configuration is not admitted");
        }
        return -1;
    }
    memset(service, 0, sizeof(*service));
    service->config = *config;
    if (pthread_mutex_init(&service->pending_lock, NULL) != 0) {
        set_error(error, error_len, "cannot initialize V1 memory pending lock");
        return -1;
    }
    if (pthread_mutex_init(&service->commit_lock, NULL) != 0) {
        pthread_mutex_destroy(&service->pending_lock);
        set_error(error, error_len, "cannot initialize V1 memory commit lock");
        return -1;
    }
    if (pthread_mutex_init(&service->outgoing_commit_lock, NULL) != 0) {
        pthread_mutex_destroy(&service->commit_lock);
        pthread_mutex_destroy(&service->pending_lock);
        set_error(error, error_len,
                  "cannot initialize V1 outgoing commit lock");
        return -1;
    }
    if (pthread_mutex_init(&service->subscriber_lock, NULL) != 0) {
        pthread_mutex_destroy(&service->outgoing_commit_lock);
        pthread_mutex_destroy(&service->commit_lock);
        pthread_mutex_destroy(&service->pending_lock);
        set_error(error, error_len,
                  "cannot initialize V1 memory subscriber lock");
        return -1;
    }
    if (pthread_mutex_init(&service->cache_lock, NULL) != 0) {
        pthread_mutex_destroy(&service->subscriber_lock);
        pthread_mutex_destroy(&service->outgoing_commit_lock);
        pthread_mutex_destroy(&service->commit_lock);
        pthread_mutex_destroy(&service->pending_lock);
        set_error(error, error_len, "cannot initialize V1 memory cache lock");
        return -1;
    }
    service->initialized = 1;
    if (pending_registry_init(service) != 0) {
        set_error(error, error_len, "cannot initialize admitted read receipt registry");
        wvm_memory_service_destroy(service);
        return -1;
    }
    if (subscriber_registry_init(service) != 0) {
        set_error(error, error_len, "cannot initialize admitted subscriber registry");
        wvm_memory_service_destroy(service);
        return -1;
    }
    return 0;
}

int wvm_memory_service_drain(struct wvm_memory_service *service,
                             uint32_t timeout_ms, char *error,
                             size_t error_len)
{
    uint64_t start = monotonic_milliseconds();
    struct timespec delay = {0, 10000000L};
    size_t i;

    if (!service || !service->initialized) {
        set_error(error, error_len, "memory service is not initialized");
        return -EINVAL;
    }
    pthread_mutex_lock(&service->subscriber_lock);
    if (service->lifecycle_state == WVM_MEMORY_SERVICE_RETIRED) {
        pthread_mutex_unlock(&service->subscriber_lock);
        return 0;
    }
    service->lifecycle_state = WVM_MEMORY_SERVICE_DRAINING;
    pthread_mutex_unlock(&service->subscriber_lock);
    for (;;) {
        int active;

        pthread_mutex_lock(&service->subscriber_lock);
        active = service->active_calls != 0;
        pthread_mutex_unlock(&service->subscriber_lock);

        pthread_mutex_lock(&service->pending_lock);
        active += service->pending_active != 0;
        pthread_mutex_unlock(&service->pending_lock);

        pthread_mutex_lock(&service->commit_lock);
        for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING && !active; i++) {
            if (service->commits[i].state == WVM_MEMORY_COMMIT_IN_FLIGHT) {
                active++;
                break;
            }
        }
        pthread_mutex_unlock(&service->commit_lock);

        pthread_mutex_lock(&service->outgoing_commit_lock);
        for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING && !active; i++) {
            if (service->outgoing_commits[i].state ==
                WVM_MEMORY_COMMIT_IN_FLIGHT) {
                active++;
                break;
            }
        }
        pthread_mutex_unlock(&service->outgoing_commit_lock);

        if (!active) {
            pthread_mutex_lock(&service->subscriber_lock);
            if (service->active_calls == 0) {
                service->lifecycle_state = WVM_MEMORY_SERVICE_RETIRED;
                for (i = 0; i < service->subscriber_bucket_count; i++) {
                    for (struct wvm_memory_subscriber *s = service->subscriber_buckets[i];
                         s; s = s->next) {
                        s->state = WVM_MEMORY_SUBSCRIBER_REMOVING;
                        /* All delivery callbacks and operation refs drained. */
                        s->state = WVM_MEMORY_SUBSCRIBER_REMOVED;
                    }
                }
                pthread_mutex_unlock(&service->subscriber_lock);
                pthread_mutex_lock(&service->cache_lock);
                memset(service->cache, 0, sizeof(service->cache));
                pthread_mutex_unlock(&service->cache_lock);
                return 0;
            }
            pthread_mutex_unlock(&service->subscriber_lock);
        }
        if (monotonic_milliseconds() - start >= timeout_ms) {
            set_error(error, error_len,
                      "memory service did not drain in %u ms", timeout_ms);
            return -ETIMEDOUT;
        }
        nanosleep(&delay, NULL);
    }
}

void wvm_memory_service_destroy(struct wvm_memory_service *service)
{
    if (!service) {
        return;
    }
    if (service->initialized) {
        for (size_t i = 0; i < service->pending_bucket_count; ++i) {
            struct wvm_memory_pending_entry *entry = service->pending_buckets[i];
            while (entry) {
                struct wvm_memory_pending_entry *next = entry->next;
                if (entry->route_op_ref_held) memory_route_op_ref_put(service);
                free(entry);
                entry = next;
            }
        }
        free(service->pending_buckets);
        for (size_t i = 0; i < service->subscriber_bucket_count; ++i) {
            struct wvm_memory_subscriber *s = service->subscriber_buckets[i];

            while (s) {
                struct wvm_memory_subscriber *next = s->next;
                free(s);
                s = next;
            }
        }
        free(service->subscriber_buckets);
        pthread_mutex_destroy(&service->pending_lock);
        pthread_mutex_destroy(&service->commit_lock);
        pthread_mutex_destroy(&service->outgoing_commit_lock);
        pthread_mutex_destroy(&service->subscriber_lock);
        pthread_mutex_destroy(&service->cache_lock);
    }
    memset(service, 0, sizeof(*service));
}

static int service_request_fault(
    struct wvm_memory_service *service, uint64_t gpa,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, char *error, size_t error_len)
{
    const struct wvm_runtime_memory_dispatch *memory;
    struct wvm_mem_read read;
    struct wvm_envelope_route route;
    struct wvm_envelope envelope;
    uint8_t payload[WVM_MEM_READ_PAYLOAD_BYTES];
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint64_t version = 0;
    int already_waiting = 0;
    int result;

    if (!service || !service->initialized || !operation_id ||
        bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES) ||
        delivery_attempt_id == 0 ||
        !(memory = wvm_runtime_dispatch_find_memory(service->config.dispatch,
                                                     gpa))) {
        set_error(error, error_len, "V1 memory fault has no admitted mapping");
        return -EINVAL;
    }
    result = pending_register(service, operation_id, memory, gpa,
                              &already_waiting);
    if (result != 0) {
        set_error(error, error_len, "memory read identity/capacity rejected: %d", result);
        return result;
    }
    if (memory->directory_physical_node_id ==
            service->config.local_physical_node_id &&
        memory->directory_node_instance_id ==
            service->config.local_node_instance_id) {
        result = service->config.read_page(service->config.opaque, gpa, page,
                                           &version, error, error_len);
        if (result != 0) {
            if (!already_waiting) pending_remove(service, operation_id);
            return result;
        }
        {
            struct wvm_mem_ack ack = {
                .gpa = gpa, .version = version, .status = WVM_MEM_ACK_SUCCESS,
                .directory_physical_node_id = service->config.local_physical_node_id,
                .directory_node_instance_id = service->config.local_node_instance_id,
                .data = page, .data_bytes = sizeof(page),
            };
            uint8_t encoded[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
            uint8_t digest[WVM_SHA256_DIGEST_BYTES];
            size_t bytes;
            int completed;

            result = wvm_mem_ack_encode(&ack, encoded, sizeof(encoded), &bytes,
                                         error, error_len);
            if (result == 0) {
                wvm_envelope_semantic_digest(encoded, bytes, digest);
                result = accept_read_result(service, operation_id, &ack, digest,
                                             &completed, error, error_len);
            }
        }
        if (result != 0 && !already_waiting) pending_remove(service, operation_id);
        return result;
    }
    if (resolve_route(service, &memory->directory, &route, error, error_len) !=
        0) {
        if (!already_waiting) {
            pending_remove(service, operation_id);
        }
        return -ESTALE;
    }
    memset(&read, 0, sizeof(read));
    read.gpa = gpa;
    read.reply_destination_kind =
        service->config.dispatch->local_primary.destination_kind;
    read.reply_destination_scope =
        service->config.dispatch->local_primary.destination_scope;
    read.reply_destination_vnode =
        service->config.dispatch->local_primary.destination_vnode;
    read.reply_node_instance_id = service->config.local_node_instance_id;
    if (wvm_mem_read_encode(&read, payload, error, error_len) != 0) {
        if (!already_waiting) {
            pending_remove(service, operation_id);
        }
        return -EINVAL;
    }
    envelope_from_projection(service, WVM_ENVELOPE_MSG_MEM_READ,
                             operation_id, delivery_attempt_id, &route, payload,
                             sizeof(payload), &envelope);
    result = service->config.send_envelope(service->config.opaque, &envelope,
                                           error, error_len);
    if (result != 0 && !already_waiting) {
        pending_remove(service, operation_id);
    }
    return result;
}

static int service_dispatch(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len)
{
    struct wvm_memory_service *service = opaque;

    if (!service || !service->initialized || !envelope ||
        !envelope_matches_projection(service->config.dispatch, envelope)) {
        set_error(error, error_len, "V1 memory service envelope is not admitted");
        return -EPERM;
    }
    switch (envelope->message_type) {
    case WVM_ENVELOPE_MSG_MEM_READ:
        return service_remote_read(service, envelope, error, error_len);
    case WVM_ENVELOPE_MSG_MEM_ACK:
        return service_remote_ack(service, envelope, error, error_len);
    case WVM_ENVELOPE_MSG_COMMIT_DIFF:
        return service_remote_commit(service, envelope, error, error_len);
    case WVM_ENVELOPE_MSG_MEM_COMMIT_ACK:
        return service_remote_commit_ack(service, envelope, error, error_len);
    case WVM_ENVELOPE_MSG_PAGE_PUSH_FULL:
    case WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF:
        return service_remote_push(service, envelope, error, error_len);
    default:
        set_error(error, error_len, "V1 memory service message is unsupported");
        return -ENOTSUP;
    }
}

int wvm_memory_service_dispatch(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len)
{
    struct wvm_memory_service *service = opaque;
    int completion = envelope &&
        (envelope->message_type == WVM_ENVELOPE_MSG_MEM_ACK ||
         envelope->message_type == WVM_ENVELOPE_MSG_MEM_COMMIT_ACK);
    int result = memory_call_begin(service, completion, error, error_len);

    if (result != 0) {
        return result;
    }
    result = service_dispatch(service, envelope, error, error_len);
    memory_call_end(service);
    return result;
}

int wvm_memory_service_request_fault(
    struct wvm_memory_service *service, uint64_t gpa,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, char *error, size_t error_len)
{
    int result = memory_call_begin(service, 0, error, error_len);

    if (result != 0) {
        return result;
    }
    result = service_request_fault(service, gpa, operation_id,
                                   delivery_attempt_id, error, error_len);
    memory_call_end(service);
    return result;
}

static int memory_service_request_commit_from_backing(
    struct wvm_memory_service *service, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, int source_shared_backing,
    char *error, size_t error_len)
{
    int result = memory_call_begin(service, 0, error, error_len);

    if (result != 0) {
        return result;
    }
    result = service_request_commit(service, gpa, base_version, offset, data,
                                    data_bytes, operation_id,
                                    delivery_attempt_id, source_shared_backing,
                                    error, error_len);
    memory_call_end(service);
    return result;
}

int wvm_memory_service_request_commit(
    struct wvm_memory_service *service, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, char *error, size_t error_len)
{
    return memory_service_request_commit_from_backing(
        service, gpa, base_version, offset, data, data_bytes, operation_id,
        delivery_attempt_id, 0, error, error_len);
}

static struct local_waiter_entry *global_waiter_find_locked(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct local_waiter_entry *entry =
            &g_global_memory_service.waiters[i];

        if (entry->state != WVM_MEMORY_WAITER_EMPTY &&
            memcmp(entry->operation_id, operation_id,
                   sizeof(entry->operation_id)) == 0) {
            return entry;
        }
    }
    return NULL;
}

static struct local_commit_waiter_entry *
global_commit_waiter_find_locked(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    for (struct local_commit_waiter_entry *entry =
             g_global_memory_service.commit_waiters;
         entry; entry = entry->next) {
        if (memcmp(entry->operation_id, operation_id,
                   sizeof(entry->operation_id)) == 0) {
            return entry;
        }
    }
    return NULL;
}

static void global_reap_expired_locked(void);

static struct local_commit_waiter_entry *
global_commit_waiter_allocate_locked(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint64_t gpa)
{
    global_reap_expired_locked();
    struct local_commit_waiter_entry *entry = calloc(1, sizeof(*entry));

    if (!entry) {
        return NULL;
    }
    memcpy(entry->operation_id, operation_id, sizeof(entry->operation_id));
    entry->gpa = gpa;
    if (pthread_cond_init(&entry->completed, NULL) != 0) {
        free(entry);
        return NULL;
    }
    entry->state = WVM_MEMORY_COMMIT_WAITER_WAITING;
    entry->owner_present = 1;
    entry->next = g_global_memory_service.commit_waiters;
    g_global_memory_service.commit_waiters = entry;
    return entry;
}

static void global_commit_waiter_release_locked(
    struct local_commit_waiter_entry *entry)
{
    struct local_commit_waiter_entry **cursor =
        &g_global_memory_service.commit_waiters;

    if (!entry) {
        return;
    }
    while (*cursor && *cursor != entry) {
        cursor = &(*cursor)->next;
    }
    if (!*cursor) {
        return;
    }
    *cursor = entry->next;
    pthread_cond_destroy(&entry->completed);
    free(entry);
    pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
}

static struct local_waiter_entry *global_waiter_allocate_locked(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint64_t gpa)
{
    size_t i;

    global_reap_expired_locked();
    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct local_waiter_entry *entry =
            &g_global_memory_service.waiters[i];

        if (entry->state == WVM_MEMORY_WAITER_EMPTY) {
            memset(entry, 0, sizeof(*entry));
            memcpy(entry->operation_id, operation_id,
                   sizeof(entry->operation_id));
            entry->gpa = gpa;
            if (pthread_cond_init(&entry->completed, NULL) != 0) {
                memset(entry, 0, sizeof(*entry));
                return NULL;
            }
            entry->state = WVM_MEMORY_WAITER_WAITING;
            entry->owner_present = 1;
            return entry;
        }
    }
    return NULL;
}

static void global_waiter_release_locked(struct local_waiter_entry *entry)
{
    if (!entry || entry->state == WVM_MEMORY_WAITER_EMPTY) {
        return;
    }
    pthread_cond_destroy(&entry->completed);
    memset(entry, 0, sizeof(*entry));
    pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
}

static void global_reap_expired_locked(void)
{
    uint64_t now = monotonic_milliseconds();
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct local_waiter_entry *waiter =
            &g_global_memory_service.waiters[i];
        if (!waiter->owner_present &&
            (waiter->state == WVM_MEMORY_WAITER_COMPLETED ||
             waiter->state == WVM_MEMORY_WAITER_ORPHANED) &&
            retention_expired(waiter->retained_until_ms, now)) {
            global_waiter_release_locked(waiter);
        }
    }
    struct local_commit_waiter_entry **cursor =
        &g_global_memory_service.commit_waiters;
    while (*cursor) {
        struct local_commit_waiter_entry *entry = *cursor;

        if (!entry->owner_present &&
            (entry->state == WVM_MEMORY_COMMIT_WAITER_COMPLETED ||
             entry->state == WVM_MEMORY_COMMIT_WAITER_ORPHANED) &&
            retention_expired(entry->retained_until_ms, now)) {
            *cursor = entry->next;
            pthread_cond_destroy(&entry->completed);
            free(entry);
        } else {
            cursor = &entry->next;
        }
    }
}

static void global_waiter_finish_locked(
    struct local_waiter_entry *waiter,
    struct wvm_memory_service *service)
{
    if (!waiter) {
        return;
    }
    waiter->owner_present = 0;
    if (service && g_global_memory_service.service == service) {
        if (waiter->retained_until_ms == 0) {
            waiter->retained_until_ms = retention_deadline_ms(service);
        }
        waiter->state = WVM_MEMORY_WAITER_COMPLETED;
        pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
        return;
    }
    global_waiter_release_locked(waiter);
}

static void global_commit_waiter_finish_locked(
    struct local_commit_waiter_entry *waiter,
    struct wvm_memory_service *service)
{
    if (!waiter) {
        return;
    }
    waiter->owner_present = 0;
    if (service && g_global_memory_service.service == service) {
        if (waiter->retained_until_ms == 0) {
            waiter->retained_until_ms = retention_deadline_ms(service);
        }
        waiter->state = WVM_MEMORY_COMMIT_WAITER_COMPLETED;
        pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
        return;
    }
    global_commit_waiter_release_locked(waiter);
}

static int global_waiter_deadline(uint64_t timeout_ms, struct timespec *deadline)
{
    uint64_t nanoseconds;

    if (!deadline || clock_gettime(CLOCK_REALTIME, deadline) != 0 ||
        timeout_ms > UINT64_MAX / 1000000U) {
        return -1;
    }
    nanoseconds = (uint64_t)deadline->tv_nsec + timeout_ms * 1000000U;
    deadline->tv_sec += (time_t)(nanoseconds / 1000000000U);
    deadline->tv_nsec = (long)(nanoseconds % 1000000000U);
    return 0;
}

/* Read receipts retain identity, so consumed page payloads can be evicted. */
static int global_fault_capacity_locked(struct wvm_memory_service *service,
                                        const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                                        uint64_t *next_retirement)
{
    struct local_waiter_entry *evict = NULL;
    int waiter_space = 0;
    int pending_space;

    *next_retirement = UINT64_MAX;
    for (size_t i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        const struct local_waiter_entry *entry =
            &g_global_memory_service.waiters[i];

        if (entry->state == WVM_MEMORY_WAITER_EMPTY) {
            waiter_space = 1;
        } else if (!entry->owner_present) {
            if (entry->retained_until_ms != 0 &&
                entry->retained_until_ms < *next_retirement) {
                *next_retirement = entry->retained_until_ms;
            }
            if (entry->state == WVM_MEMORY_WAITER_COMPLETED &&
                (!evict || entry->retained_until_ms < evict->retained_until_ms)) {
                evict = &g_global_memory_service.waiters[i];
            }
        }
    }
    if (!waiter_space && evict) {
        global_waiter_release_locked(evict);
        waiter_space = 1;
    }
    pthread_mutex_lock(&service->pending_lock);
    pending_space = service->pending_active < WVM_MEMORY_SERVICE_MAX_PENDING;
    if (pending_space && service->pending_count >= service->pending_limit &&
        !find_pending_locked(service, operation_id)) {
        uint64_t now = monotonic_milliseconds();

        for (size_t i = 0; i < service->pending_bucket_count; ++i) {
            reap_pending_bucket_locked(service, i, now);
            for (struct wvm_memory_pending_entry *entry = service->pending_buckets[i];
                 entry; entry = entry->next) {
                if (entry->state == WVM_MEMORY_PENDING_COMPLETED &&
                    entry->retained_until_ms < *next_retirement) {
                    *next_retirement = entry->retained_until_ms;
                }
            }
        }
        pending_space = service->pending_count < service->pending_limit;
    }
    pthread_mutex_unlock(&service->pending_lock);
    return waiter_space && pending_space;
}

static int global_commit_capacity_locked(struct wvm_memory_service *service,
                                         uint64_t gpa,
                                         uint64_t *next_retirement)
{
    const struct wvm_runtime_memory_dispatch *memory =
        wvm_runtime_dispatch_find_memory(service->config.dispatch, gpa);
    int outgoing_space = 0;

    *next_retirement = UINT64_MAX;
    for (struct local_commit_waiter_entry *entry =
             g_global_memory_service.commit_waiters;
         entry; entry = entry->next) {
        if (!entry->owner_present) {
            if (entry->retained_until_ms != 0 &&
                entry->retained_until_ms < *next_retirement) {
                *next_retirement = entry->retained_until_ms;
            }
        }
    }
    if (memory && memory->directory_physical_node_id ==
                      service->config.local_physical_node_id &&
        memory->directory_node_instance_id ==
            service->config.local_node_instance_id) {
        /* Completed ACKs remain replayable through their admitted horizon. */
        return 1;
    }
    pthread_mutex_lock(&service->outgoing_commit_lock);
    reap_outgoing_completed_locked(service, monotonic_milliseconds());
    for (size_t i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        const struct wvm_memory_outgoing_commit_entry *entry =
            &service->outgoing_commits[i];

        if (entry->state == WVM_MEMORY_COMMIT_EMPTY) {
            outgoing_space = 1;
        } else if (entry->state == WVM_MEMORY_COMMIT_COMPLETED &&
                   entry->retained_until_ms != 0 &&
                   entry->retained_until_ms < *next_retirement) {
            *next_retirement = entry->retained_until_ms;
        }
    }
    pthread_mutex_unlock(&service->outgoing_commit_lock);
    return outgoing_space;
}

int wvm_memory_service_global_install(
    struct wvm_memory_service *service, char *error, size_t error_len)
{
    if (!service || !service->initialized) {
        set_error(error, error_len,
                  "cannot install an uninitialized V1 memory service");
        return -EINVAL;
    }
    pthread_mutex_lock(&g_global_memory_service.lock);
    if (g_global_memory_service.service) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "V1 memory service is already installed");
        return -EALREADY;
    }
    g_global_memory_service.service = service;
    pthread_mutex_unlock(&g_global_memory_service.lock);
    return 0;
}

void wvm_memory_service_global_uninstall(
    struct wvm_memory_service *service)
{
    size_t i;

    pthread_mutex_lock(&g_global_memory_service.lock);
    if (g_global_memory_service.service == service) {
        g_global_memory_service.service = NULL;
        pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
        for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
            struct local_waiter_entry *waiter =
                &g_global_memory_service.waiters[i];

            /*
             * A request thread can still be inside pthread_cond_timedwait.
             * Wake it with a terminal result and let that owner release the
             * condition variable after it has reacquired the mutex; destroying
             * it from teardown would be undefined behavior.
             */
            if (waiter->state == WVM_MEMORY_WAITER_WAITING) {
                waiter->version = 0;
                waiter->status = WVM_MEM_ACK_INTERNAL_FAILURE;
                waiter->directory_physical_node_id = 0;
                waiter->directory_node_instance_id = 0;
                waiter->data_bytes = 0;
                waiter->state = WVM_MEMORY_WAITER_COMPLETED;
                pthread_cond_broadcast(&waiter->completed);
            }
        }
        for (struct local_commit_waiter_entry *entry =
                 g_global_memory_service.commit_waiters;
             entry; entry = entry->next) {
            if (entry->state == WVM_MEMORY_COMMIT_WAITER_WAITING) {
                memset(&entry->ack, 0, sizeof(entry->ack));
                entry->ack.gpa = entry->gpa;
                entry->ack.status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
                entry->state = WVM_MEMORY_COMMIT_WAITER_COMPLETED;
                pthread_cond_broadcast(&entry->completed);
            }
        }
        struct local_commit_waiter_entry **cursor =
            &g_global_memory_service.commit_waiters;
        while (*cursor) {
            struct local_commit_waiter_entry *entry = *cursor;
            if (!entry->owner_present &&
                entry->state != WVM_MEMORY_COMMIT_WAITER_WAITING) {
                *cursor = entry->next;
                pthread_cond_destroy(&entry->completed);
                free(entry);
            } else {
                cursor = &entry->next;
            }
        }
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);
}

uint64_t wvm_memory_service_global_fault_deadline(void)
{
    uint64_t deadline = 0;

    pthread_mutex_lock(&g_global_memory_service.lock);
    if (g_global_memory_service.service) {
        deadline = retention_deadline_ms(g_global_memory_service.service);
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);
    return deadline;
}

int wvm_memory_service_global_request_fault_before(
    uint64_t gpa, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, uint64_t deadline_ms, struct wvm_mem_ack *ack,
    uint8_t page[WVM_MEMORY_PAGE_BYTES], char *error, size_t error_len)
{
    struct wvm_memory_service *service;
    struct local_waiter_entry *waiter;
    struct timespec deadline;
    uint64_t capacity_deadline;
    int service_result;
    int wait_result;
    int adopted_orphan = 0;

    if (!operation_id || !ack || !page ||
        bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len, "V1 local memory fault input is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&g_global_memory_service.lock);
    service = g_global_memory_service.service;
    if (!service) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "V1 memory service is not installed");
        return -ENOTCONN;
    }
    capacity_deadline = retention_deadline_ms(service);
    if (deadline_ms && deadline_ms < capacity_deadline) {
        capacity_deadline = deadline_ms;
    }
    uint64_t now = monotonic_milliseconds();
    if (!now || now >= capacity_deadline) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "memory fault deadline exceeded");
        return -ETIMEDOUT;
    }
    if (global_waiter_deadline(capacity_deadline - now, &deadline) != 0) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "cannot create memory fault deadline");
        return -EIO;
    }
retry_capacity:
    if (g_global_memory_service.service != service) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "memory service stopped during capacity wait");
        return -ENOTCONN;
    }
    if (monotonic_milliseconds() >= capacity_deadline) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "memory fault capacity deadline exceeded");
        return -ETIMEDOUT;
    }
    global_reap_expired_locked();
    waiter = global_waiter_find_locked(operation_id);
    if (waiter) {
        if (waiter->gpa != gpa) {
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "V1 local memory operation conflicts with active fault");
            return -EEXIST;
        }
        if (waiter->state == WVM_MEMORY_WAITER_COMPLETED) {
            memset(ack, 0, sizeof(*ack));
            ack->gpa = waiter->gpa;
            ack->version = waiter->version;
            ack->status = waiter->status;
            ack->directory_physical_node_id =
                waiter->directory_physical_node_id;
            ack->directory_node_instance_id =
                waiter->directory_node_instance_id;
            if (waiter->status == WVM_MEM_ACK_SUCCESS) {
                ack->data = page;
                ack->data_bytes = waiter->data_bytes;
                memcpy(page, waiter->data, waiter->data_bytes);
            }
            pthread_mutex_unlock(&g_global_memory_service.lock);
            return 0;
        }
        if (waiter->state == WVM_MEMORY_WAITER_WAITING) {
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "V1 local memory operation is already being waited");
            return -EALREADY;
        }
        if (waiter->state == WVM_MEMORY_WAITER_ORPHANED) {
            waiter->state = WVM_MEMORY_WAITER_WAITING;
            waiter->owner_present = 1;
            adopted_orphan = 1;
        }
    } else {
        uint64_t next_retirement;

        if (!global_fault_capacity_locked(service, operation_id, &next_retirement)) {
            struct timespec capacity_wakeup;
            uint64_t now = monotonic_milliseconds();
            uint64_t wakeup = next_retirement < capacity_deadline ?
                                  next_retirement : capacity_deadline;

            if (now >= capacity_deadline) {
                pthread_mutex_unlock(&g_global_memory_service.lock);
                set_error(error, error_len, "memory fault capacity deadline exceeded");
                return -ETIMEDOUT;
            }
            if (wakeup <= now) {
                goto retry_capacity;
            }
            if (global_waiter_deadline(wakeup - now, &capacity_wakeup) != 0) {
                pthread_mutex_unlock(&g_global_memory_service.lock);
                return -EIO;
            }
            wait_result = pthread_cond_timedwait(
                &g_global_memory_service.capacity_changed,
                &g_global_memory_service.lock, &capacity_wakeup);
            if (wait_result != 0 && wait_result != ETIMEDOUT) {
                pthread_mutex_unlock(&g_global_memory_service.lock);
                return -wait_result;
            }
            goto retry_capacity;
        }
        waiter = global_waiter_allocate_locked(operation_id, gpa);
        if (!waiter) {
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len, "V1 local memory waiter table is full");
            return -EAGAIN;
        }
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);

    service_result = wvm_memory_service_request_fault(
        service, gpa, operation_id, delivery_attempt_id, error, error_len);
    if (service_result != 0) {
        pthread_mutex_lock(&g_global_memory_service.lock);
        if (adopted_orphan) {
            waiter->state = WVM_MEMORY_WAITER_ORPHANED;
            waiter->owner_present = 0;
            waiter->retained_until_ms = retention_deadline_ms(service);
        } else {
            global_waiter_release_locked(waiter);
        }
        pthread_mutex_unlock(&g_global_memory_service.lock);
        return service_result;
    }
    pthread_mutex_lock(&g_global_memory_service.lock);
    while (waiter->state == WVM_MEMORY_WAITER_WAITING) {
        wait_result = pthread_cond_timedwait(&waiter->completed,
                                             &g_global_memory_service.lock,
                                             &deadline);
        if (wait_result == ETIMEDOUT &&
            waiter->state != WVM_MEMORY_WAITER_WAITING) {
            break;
        }
        if (wait_result == ETIMEDOUT) {
            /*
             * Keep the operation identity alive through the route retention
             * horizon. A late ACK may still complete this waiter, and a
             * retry with the same operation ID may rejoin it.
             */
            waiter->state = WVM_MEMORY_WAITER_ORPHANED;
            waiter->owner_present = 0;
            if (waiter->retained_until_ms == 0) {
                waiter->retained_until_ms = retention_deadline_ms(service);
            }
            pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "V1 local memory fault exceeded completion horizon");
            return -ETIMEDOUT;
        }
        if (wait_result != 0) {
            pending_remove(service, operation_id);
            global_waiter_release_locked(waiter);
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len, "V1 local memory wait failed");
            return -wait_result;
        }
    }
    memset(ack, 0, sizeof(*ack));
    ack->gpa = waiter->gpa;
    ack->version = waiter->version;
    ack->status = waiter->status;
    ack->directory_physical_node_id = waiter->directory_physical_node_id;
    ack->directory_node_instance_id = waiter->directory_node_instance_id;
    if (waiter->status == WVM_MEM_ACK_SUCCESS) {
        ack->data = page;
        ack->data_bytes = waiter->data_bytes;
        memcpy(page, waiter->data, waiter->data_bytes);
    }
    /*
     * Keep a bounded page-result cache. Under pressure only this consumed
     * payload is evicted; the compact receipt still checks the operation's
     * GPA, directory and result version when a retry fetches a fresh snapshot.
     */
    global_waiter_finish_locked(waiter, service);
    pthread_mutex_unlock(&g_global_memory_service.lock);
    return 0;
}

int wvm_memory_service_global_request_fault(
    uint64_t gpa, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, struct wvm_mem_ack *ack,
    uint8_t page[WVM_MEMORY_PAGE_BYTES], char *error, size_t error_len)
{
    return wvm_memory_service_global_request_fault_before(
        gpa, operation_id, delivery_attempt_id, 0, ack, page, error, error_len);
}

int wvm_memory_service_global_complete(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint64_t gpa,
    uint64_t version, uint16_t status,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    const uint8_t *data, size_t data_bytes, char *error, size_t error_len)
{
    struct local_waiter_entry *waiter;
    size_t i;

    if (!operation_id || bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES) ||
        status > WVM_MEM_ACK_INTERNAL_FAILURE ||
        (status == WVM_MEM_ACK_SUCCESS &&
         (version == 0 || !data || data_bytes != WVM_MEMORY_PAGE_BYTES)) ||
        (status != WVM_MEM_ACK_SUCCESS &&
         (version != 0 || data_bytes != 0))) {
        set_error(error, error_len, "V1 local memory completion is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&g_global_memory_service.lock);
    global_reap_expired_locked();
    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        waiter = &g_global_memory_service.waiters[i];
        if (waiter->gpa != gpa ||
            memcmp(waiter->operation_id, operation_id,
                   sizeof(waiter->operation_id)) != 0) {
            continue;
        }
        if (waiter->state == WVM_MEMORY_WAITER_COMPLETED) {
            int duplicate =
                waiter->version == version && waiter->status == status &&
                waiter->directory_physical_node_id ==
                    directory_physical_node_id &&
                waiter->directory_node_instance_id ==
                    directory_node_instance_id &&
                waiter->data_bytes == data_bytes &&
                (data_bytes == 0 ||
                 memcmp(waiter->data, data, data_bytes) == 0);

            pthread_mutex_unlock(&g_global_memory_service.lock);
            if (!duplicate) {
                set_error(error, error_len,
                          "V1 local memory completion conflicts with result");
                return -EEXIST;
            }
            return 0;
        }
        if (waiter->state == WVM_MEMORY_WAITER_WAITING ||
            waiter->state == WVM_MEMORY_WAITER_ORPHANED) {
            waiter->version = version;
            waiter->status = status;
            waiter->directory_physical_node_id = directory_physical_node_id;
            waiter->directory_node_instance_id = directory_node_instance_id;
            waiter->data_bytes = data_bytes;
            if (data_bytes != 0) {
                memcpy(waiter->data, data, data_bytes);
            }
            waiter->state = WVM_MEMORY_WAITER_COMPLETED;
            if (waiter->retained_until_ms == 0) {
                waiter->retained_until_ms =
                    retention_deadline_ms(g_global_memory_service.service);
            }
            pthread_cond_broadcast(&waiter->completed);
            pthread_mutex_unlock(&g_global_memory_service.lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);
    set_error(error, error_len,
              "V1 local memory completion has no pending operation");
    return -ENOENT;
}

int wvm_memory_service_global_request_commit_from_shared_backing(
    uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, int source_shared_backing,
    struct wvm_mem_commit_ack *ack, char *error, size_t error_len)
{
    struct wvm_memory_service *service;
    struct local_commit_waiter_entry *waiter;
    struct timespec deadline;
    uint64_t capacity_deadline;
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    int service_result;
    int wait_result;
    int adopted_orphan = 0;

    if (!operation_id || !ack || bytes_are_zero(operation_id,
                                                WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len, "V1 local commit input is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&g_global_memory_service.lock);
    service = g_global_memory_service.service;
    if (!service) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "V1 memory service is not installed");
        return -ENOTCONN;
    }
    if (build_commit_semantic_digest(
            service, gpa, base_version, offset, data, data_bytes,
            semantic_payload_digest, error, error_len) != 0) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        return -EINVAL;
    }
    capacity_deadline = retention_deadline_ms(service);
    if (global_waiter_deadline(service->config.completion_timeout_ms,
                               &deadline) != 0) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "cannot create memory commit deadline");
        return -EIO;
    }
retry_capacity:
    if (g_global_memory_service.service != service) {
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "memory service stopped during capacity wait");
        return -ENOTCONN;
    }
    global_reap_expired_locked();
    waiter = global_commit_waiter_find_locked(operation_id);
    if (waiter) {
        if (waiter->gpa != gpa ||
            memcmp(waiter->semantic_payload_digest, semantic_payload_digest,
                   sizeof(semantic_payload_digest)) != 0) {
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "V1 local commit operation conflicts with prior work");
            return -EEXIST;
        }
        if (waiter->state == WVM_MEMORY_COMMIT_WAITER_COMPLETED) {
            *ack = waiter->ack;
            pthread_mutex_unlock(&g_global_memory_service.lock);
            return 0;
        }
        if (waiter->state == WVM_MEMORY_COMMIT_WAITER_WAITING) {
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "V1 local commit operation is already being waited");
            return -EALREADY;
        }
        if (waiter->state == WVM_MEMORY_COMMIT_WAITER_ORPHANED) {
            waiter->state = WVM_MEMORY_COMMIT_WAITER_WAITING;
            waiter->owner_present = 1;
            adopted_orphan = 1;
        }
    } else {
        uint64_t next_retirement;

        if (!global_commit_capacity_locked(service, gpa, &next_retirement)) {
            struct timespec capacity_wakeup;
            uint64_t now = monotonic_milliseconds();
            uint64_t wakeup = next_retirement < capacity_deadline ?
                                  next_retirement : capacity_deadline;

            if (now >= capacity_deadline) {
                pthread_mutex_unlock(&g_global_memory_service.lock);
                set_error(error, error_len, "memory commit capacity deadline exceeded");
                return -ETIMEDOUT;
            }
            if (wakeup <= now) {
                goto retry_capacity;
            }
            if (global_waiter_deadline(wakeup - now, &capacity_wakeup) != 0) {
                pthread_mutex_unlock(&g_global_memory_service.lock);
                return -EIO;
            }
            wait_result = pthread_cond_timedwait(
                &g_global_memory_service.capacity_changed,
                &g_global_memory_service.lock, &capacity_wakeup);
            if (wait_result != 0 && wait_result != ETIMEDOUT) {
                pthread_mutex_unlock(&g_global_memory_service.lock);
                return -wait_result;
            }
            goto retry_capacity;
        }
        waiter = global_commit_waiter_allocate_locked(operation_id, gpa);
        if (!waiter) {
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "cannot allocate V1 local commit replay receipt");
            return -ENOMEM;
        }
        memcpy(waiter->semantic_payload_digest, semantic_payload_digest,
               sizeof(waiter->semantic_payload_digest));
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);

    service_result = memory_service_request_commit_from_backing(
        service, gpa, base_version, offset, data, data_bytes, operation_id,
        delivery_attempt_id, source_shared_backing, error, error_len);
    if (service_result != 0) {
        pthread_mutex_lock(&g_global_memory_service.lock);
        if (adopted_orphan) {
            waiter->state = WVM_MEMORY_COMMIT_WAITER_ORPHANED;
            waiter->owner_present = 0;
            waiter->retained_until_ms = retention_deadline_ms(service);
        } else {
            global_commit_waiter_release_locked(waiter);
        }
        pthread_mutex_unlock(&g_global_memory_service.lock);
        return service_result;
    }
    pthread_mutex_lock(&g_global_memory_service.lock);
    while (waiter->state == WVM_MEMORY_COMMIT_WAITER_WAITING) {
        wait_result = pthread_cond_timedwait(&waiter->completed,
                                             &g_global_memory_service.lock,
                                             &deadline);
        if (wait_result == ETIMEDOUT &&
            waiter->state != WVM_MEMORY_COMMIT_WAITER_WAITING) {
            break;
        }
        if (wait_result == ETIMEDOUT) {
            waiter->state = WVM_MEMORY_COMMIT_WAITER_ORPHANED;
            waiter->owner_present = 0;
            if (waiter->retained_until_ms == 0) {
                waiter->retained_until_ms = retention_deadline_ms(service);
            }
            pthread_cond_broadcast(&g_global_memory_service.capacity_changed);
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "V1 local memory commit exceeded completion horizon");
            return -ETIMEDOUT;
        }
        if (wait_result != 0) {
            global_commit_waiter_release_locked(waiter);
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len, "V1 local memory commit wait failed");
            return -wait_result;
        }
    }
    *ack = waiter->ack;
    /*
     * G10/G5-aligned: retain COMPLETED commit waiters through the horizon for
     * idempotent replay. Capacity waiting preserves the admitted horizon.
     */
    global_commit_waiter_finish_locked(waiter, service);
    pthread_mutex_unlock(&g_global_memory_service.lock);
    return 0;
}

int wvm_memory_service_global_request_commit(
    uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, struct wvm_mem_commit_ack *ack,
    char *error, size_t error_len)
{
    return wvm_memory_service_global_request_commit_from_shared_backing(
        gpa, base_version, offset, data, data_bytes, operation_id,
        delivery_attempt_id, 0, ack, error, error_len);
}

int wvm_memory_service_global_complete_commit(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint64_t gpa,
    uint16_t status, uint64_t result_version,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    char *error, size_t error_len)
{
    size_t i;

    if (!operation_id || bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES) ||
        status > WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE ||
        (status == WVM_MEM_COMMIT_ACK_SUCCESS && result_version == 0) ||
        (status != WVM_MEM_COMMIT_ACK_SUCCESS && result_version != 0)) {
        set_error(error, error_len, "V1 local commit completion is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&g_global_memory_service.lock);
    global_reap_expired_locked();
    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct local_commit_waiter_entry *waiter =
            &g_global_memory_service.commit_waiters[i];

        if (waiter->gpa != gpa ||
            memcmp(waiter->operation_id, operation_id,
                   sizeof(waiter->operation_id)) != 0) {
            continue;
        }
        if (waiter->state == WVM_MEMORY_COMMIT_WAITER_COMPLETED) {
            int duplicate =
                waiter->ack.gpa == gpa && waiter->ack.status == status &&
                waiter->ack.result_version == result_version &&
                waiter->ack.directory_physical_node_id ==
                    directory_physical_node_id &&
                waiter->ack.directory_node_instance_id ==
                    directory_node_instance_id;

            pthread_mutex_unlock(&g_global_memory_service.lock);
            if (!duplicate) {
                set_error(error, error_len,
                          "V1 local commit completion conflicts with result");
                return -EEXIST;
            }
            return 0;
        }
        if (waiter->state == WVM_MEMORY_COMMIT_WAITER_WAITING ||
            waiter->state == WVM_MEMORY_COMMIT_WAITER_ORPHANED) {
            memset(&waiter->ack, 0, sizeof(waiter->ack));
            waiter->ack.gpa = gpa;
            waiter->ack.status = status;
            waiter->ack.result_version = result_version;
            waiter->ack.directory_physical_node_id =
                directory_physical_node_id;
            waiter->ack.directory_node_instance_id =
                directory_node_instance_id;
            waiter->state = WVM_MEMORY_COMMIT_WAITER_COMPLETED;
            if (waiter->retained_until_ms == 0) {
                waiter->retained_until_ms =
                    retention_deadline_ms(g_global_memory_service.service);
            }
            pthread_cond_broadcast(&waiter->completed);
            pthread_mutex_unlock(&g_global_memory_service.lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);
    set_error(error, error_len,
              "V1 local commit completion has no pending operation");
    return -ENOENT;
}

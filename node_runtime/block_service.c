#define _POSIX_C_SOURCE 200809L

#include "block_service.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* A05: pin the admitted route scope while this operation can still be retried. */
static int block_route_ref_get(struct wvm_block_service *service,
                               char *error, size_t error_len)
{
    if (!service->config.pin_scope)
        return 0;
    return service->config.pin_scope(service->config.scope_opaque, error,
                                     error_len);
}

static void block_route_ref_put(struct wvm_block_service *service)
{
    if (service->config.unpin_scope)
        service->config.unpin_scope(service->config.scope_opaque);
}

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0)
        snprintf(error, error_len, "%s", message);
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void release_entry_locked(struct wvm_block_service *service,
                                 struct wvm_block_entry *entry)
{
    if (entry->result) {
        free(entry->result);
        entry->result = NULL;
    }
    if (service->retained_bytes >= entry->result_bytes)
        service->retained_bytes -= entry->result_bytes;
    else
        service->retained_bytes = 0;
    entry->result_bytes = 0;
    memset(entry->operation_id, 0, sizeof(entry->operation_id));
    entry->origin_physical_node_id = 0;
    entry->origin_runtime_instance_id = 0;
    entry->operation = 0;
    entry->flags = 0;
    memset(entry->semantic_digest, 0, sizeof(entry->semantic_digest));
    entry->state = WVM_BLOCK_ENTRY_EMPTY;
    entry->status = 0;
    entry->completed_at_ms = 0;
    entry->expired_at_ms = 0;
    /* entry->completed stays initialized for the life of the service. */
}

/*
 * Age one completed operation out of its result window.  The identity stays
 * behind as a tombstone: a late retry gets a typed terminal answer instead of
 * being executed again and overwriting newer data.
 */
static void expire_entry_locked(struct wvm_block_service *service,
                                struct wvm_block_entry *entry, uint64_t now)
{
    if (entry->result) {
        free(entry->result);
        entry->result = NULL;
    }
    if (service->retained_bytes >= entry->result_bytes)
        service->retained_bytes -= entry->result_bytes;
    else
        service->retained_bytes = 0;
    entry->result_bytes = 0;
    entry->state = WVM_BLOCK_ENTRY_EXPIRED;
    entry->expired_at_ms = now;
}

/* Tombstones are bounded: they may be reclaimed only after the grace window. */
static void reclaim_tombstones_locked(struct wvm_block_service *service,
                                      uint64_t now)
{
    unsigned int i;

    for (i = 0; i < WVM_BLOCK_SERVICE_MAX_ENTRIES; i++) {
        struct wvm_block_entry *entry = &service->entries[i];
        if (entry->state == WVM_BLOCK_ENTRY_EXPIRED &&
            now - entry->expired_at_ms > service->config.tombstone_ms)
            release_entry_locked(service, entry);
    }
}

static int entry_matches(const struct wvm_block_entry *entry,
                         const struct wvm_envelope *envelope)
{
    return entry->state != WVM_BLOCK_ENTRY_EMPTY &&
           entry->origin_physical_node_id == envelope->origin_physical_node_id &&
           entry->origin_runtime_instance_id ==
               envelope->origin_runtime_instance_id &&
           memcmp(entry->operation_id, envelope->operation_id,
                  sizeof(entry->operation_id)) == 0;
}

static struct wvm_block_entry *find_locked(
    struct wvm_block_service *service, const struct wvm_envelope *envelope)
{
    unsigned int i;

    for (i = 0; i < WVM_BLOCK_SERVICE_MAX_ENTRIES; i++) {
        if (entry_matches(&service->entries[i], envelope))
            return &service->entries[i];
    }
    return NULL;
}

/*
 * Reserve a slot and the result budget BEFORE the operation executes.  A
 * completed entry inside its retention window is never sacrificed for new
 * work: the request must come back later instead of causing a silent re-run.
 */
static struct wvm_block_entry *reserve_entry_locked(
    struct wvm_block_service *service, const struct wvm_envelope *envelope,
    const struct wvm_block_request *request, uint64_t now, char *error,
    size_t error_len)
{
    size_t need_bytes = 0;
    struct wvm_block_entry *entry = NULL;
    unsigned int i;

    if (request->operation == WVM_BLOCK_OPERATION_READ)
        need_bytes = (size_t)request->sector_count * WVM_BLOCK_SECTOR_BYTES;

    reclaim_tombstones_locked(service, now);
    for (i = 0; i < WVM_BLOCK_SERVICE_MAX_ENTRIES; i++) {
        if (service->entries[i].state == WVM_BLOCK_ENTRY_EMPTY) {
            entry = &service->entries[i];
            break;
        }
    }
    if (!entry) {
        set_error(error, error_len,
                  "block operation table is full; retry after retention");
        return NULL;
    }
    if (need_bytes != 0 &&
        service->retained_bytes + need_bytes > service->config.retention_bytes) {
        set_error(error, error_len,
                  "block result budget is full; retry after retention");
        return NULL;
    }

    memset(entry->operation_id, 0, sizeof(entry->operation_id));
    memcpy(entry->operation_id, envelope->operation_id,
           sizeof(entry->operation_id));
    entry->origin_physical_node_id = envelope->origin_physical_node_id;
    entry->origin_runtime_instance_id = envelope->origin_runtime_instance_id;
    entry->operation = request->operation;
    entry->flags = request->flags;
    memcpy(entry->semantic_digest, envelope->semantic_payload_digest,
           sizeof(entry->semantic_digest));
    entry->state = WVM_BLOCK_ENTRY_IN_FLIGHT;
    entry->status = 0;
    entry->completed_at_ms = 0;
    entry->expired_at_ms = 0;
    return entry;
}

static struct wvm_block_queue_state *queue_find_locked(
    struct wvm_block_service *service, const struct wvm_envelope *envelope,
    uint32_t queue_id)
{
    struct wvm_block_queue_state *oldest = NULL;
    unsigned int i;

    for (i = 0; i < WVM_BLOCK_SERVICE_QUEUE_SLOTS; i++) {
        struct wvm_block_queue_state *state = &service->queues[i];
        if (state->occupied && state->queue_id == queue_id &&
            state->origin_runtime_instance_id ==
                envelope->origin_runtime_instance_id)
            return state;
        if (!state->occupied && !oldest)
            oldest = state;
        else if (state->occupied &&
                 (!oldest || !oldest->occupied ||
                  state->last_activity_ms < oldest->last_activity_ms))
            oldest = state;
    }
    memset(oldest, 0, sizeof(*oldest));
    oldest->occupied = 1;
    oldest->queue_id = queue_id;
    oldest->origin_runtime_instance_id = envelope->origin_runtime_instance_id;
    return oldest;
}

/*
 * Strict per-queue ordering.  A gap or a stale predecessor is retryable
 * backpressure, never permission to run a later WRITE/FLUSH first.  An idle
 * queue restarts its sequence domain so one lost predecessor cannot stall the
 * device forever.
 */
static int queue_gate_locked(struct wvm_block_service *service,
                             const struct wvm_envelope *envelope,
                             const struct wvm_block_request *request,
                             uint64_t now,
                             struct wvm_block_queue_state **state_out,
                             char *error, size_t error_len)
{
    struct wvm_block_queue_state *state = queue_find_locked(
        service, envelope, request->queue_id);

    if (!state->occupied || state->next_sequence == 0 ||
        now - state->last_activity_ms >
            (uint64_t)WVM_BLOCK_SERVICE_QUEUE_IDLE_MS) {
        state->next_sequence = request->queue_sequence;
    }
    if (request->queue_sequence < state->next_sequence) {
        set_error(error, error_len, "block queue sequence is stale");
        return -EAGAIN;
    }
    if (request->queue_sequence > state->next_sequence) {
        set_error(error, error_len, "block queue sequence has a gap");
        return -EAGAIN;
    }
    *state_out = state;
    return 0;
}

static void queue_advance_locked(struct wvm_block_queue_state *state,
                                 const struct wvm_block_request *request,
                                 uint64_t now)
{
    state->next_sequence = request->queue_sequence + 1U;
    state->last_activity_ms = now;
}

static int wait_for_entry_locked(struct wvm_block_service *service,
                                 struct wvm_block_entry *entry)
{
    struct timespec deadline;
    int rc;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += WVM_BLOCK_SERVICE_DUPLICATE_WAIT_MS / 1000U;
    deadline.tv_nsec +=
        (long)(WVM_BLOCK_SERVICE_DUPLICATE_WAIT_MS % 1000U) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    rc = pthread_cond_timedwait(&entry->completed, &service->lock, &deadline);
    return rc == ETIMEDOUT ? -EAGAIN : 0;
}

static int send_result(struct wvm_block_service *service,
                       const struct wvm_envelope *request,
                       const struct wvm_block_request *request_payload,
                       uint16_t status, const uint8_t *data, size_t data_bytes,
                       char *error, size_t error_len)
{
    struct wvm_envelope_route route;
    struct wvm_envelope reply;
    struct wvm_block_completion completion;
    uint8_t *payload;
    size_t payload_bytes = WVM_BLOCK_COMPLETION_HEADER_BYTES + data_bytes;
    size_t encoded_bytes = 0;
    int rc;

    if (service->config.resolve_route(
            service->config.opaque, request_payload->reply_destination_kind,
            request_payload->reply_destination_scope,
            request_payload->reply_destination_vnode, &route, error,
            error_len) != 0)
        return -1;

    payload = malloc(payload_bytes ? payload_bytes : 1U);
    if (!payload) {
        set_error(error, error_len, "block completion buffer is exhausted");
        return -ENOMEM;
    }
    memset(&completion, 0, sizeof(completion));
    completion.payload_version = WVM_BLOCK_WIRE_VERSION;
    completion.status = status;
    completion.transferred_bytes = (uint32_t)data_bytes;
    if (wvm_block_completion_encode(&completion, data, data_bytes, payload,
                                    payload_bytes, &encoded_bytes, error,
                                    error_len) != 0) {
        free(payload);
        return -1;
    }

    memset(&reply, 0, sizeof(reply));
    reply.message_type = WVM_ENVELOPE_MSG_BLOCK_ACK;
    reply.vm_id = request->vm_id;
    reply.vm_incarnation = request->vm_incarnation;
    reply.manifest_generation = request->manifest_generation;
    reply.origin_physical_node_id = service->config.local_physical_node_id;
    reply.origin_runtime_instance_id =
        service->config.local_runtime_instance_id;
    memcpy(reply.operation_id, request->operation_id,
           sizeof(reply.operation_id));
    reply.delivery_attempt_id = 1;
    reply.route_scope_id = request->route_scope_id;
    reply.topology_revision = request->topology_revision;
    reply.route_generation = request->route_generation;
    memcpy(reply.route_snapshot_digest, request->route_snapshot_digest,
           sizeof(reply.route_snapshot_digest));
    reply.route = route;
    reply.payload = payload;
    reply.payload_bytes = encoded_bytes;
    wvm_envelope_semantic_digest(payload, encoded_bytes,
                                 reply.semantic_payload_digest);

    rc = service->config.send_envelope(service->config.opaque, &reply, error,
                                       error_len);
    free(payload);
    return rc;
}

int wvm_block_service_init(struct wvm_block_service *service,
                           const struct wvm_block_service_config *config,
                           char *error, size_t error_len)
{
    unsigned int i;

    if (!service || !config || !config->execute || !config->resolve_route ||
        !config->send_envelope) {
        set_error(error, error_len, "block service configuration is incomplete");
        return -EINVAL;
    }
    memset(service, 0, sizeof(*service));
    service->config = *config;
    if (service->config.retention_ms == 0)
        service->config.retention_ms = WVM_BLOCK_SERVICE_DEFAULT_RETENTION_MS;
    if (service->config.tombstone_ms == 0)
        service->config.tombstone_ms = WVM_BLOCK_SERVICE_DEFAULT_TOMBSTONE_MS;
    if (service->config.retention_bytes == 0)
        service->config.retention_bytes =
            WVM_BLOCK_SERVICE_DEFAULT_RETENTION_BYTES;
    if (pthread_mutex_init(&service->lock, NULL) != 0)
        return -ENOMEM;
    for (i = 0; i < WVM_BLOCK_SERVICE_EXECUTE_LOCKS; i++) {
        if (pthread_mutex_init(&service->queue_locks[i], NULL) != 0) {
            while (i > 0)
                pthread_mutex_destroy(&service->queue_locks[--i]);
            pthread_mutex_destroy(&service->lock);
            return -ENOMEM;
        }
    }
    for (i = 0; i < WVM_BLOCK_SERVICE_MAX_ENTRIES; i++) {
        if (pthread_cond_init(&service->entries[i].completed, NULL) != 0) {
            while (i > 0)
                pthread_cond_destroy(&service->entries[--i].completed);
            for (i = 0; i < WVM_BLOCK_SERVICE_EXECUTE_LOCKS; i++)
                pthread_mutex_destroy(&service->queue_locks[i]);
            pthread_mutex_destroy(&service->lock);
            return -ENOMEM;
        }
    }
    service->initialized = 1;
    return 0;
}

void wvm_block_service_destroy(struct wvm_block_service *service)
{
    unsigned int i;

    if (!service || !service->initialized)
        return;
    for (i = 0; i < WVM_BLOCK_SERVICE_MAX_ENTRIES; i++) {
        if (service->entries[i].state != WVM_BLOCK_ENTRY_EMPTY)
            release_entry_locked(service, &service->entries[i]);
        pthread_cond_destroy(&service->entries[i].completed);
    }
    for (i = 0; i < WVM_BLOCK_SERVICE_EXECUTE_LOCKS; i++)
        pthread_mutex_destroy(&service->queue_locks[i]);
    pthread_mutex_destroy(&service->lock);
    service->initialized = 0;
}

int wvm_block_service_dispatch(void *opaque,
                               const struct wvm_envelope *envelope, char *error,
                               size_t error_len)
{
    struct wvm_block_service *service = opaque;
    struct wvm_block_request request;
    const uint8_t *data = NULL;
    size_t data_bytes = 0;
    uint8_t *out = NULL;
    size_t out_capacity = 0;
    size_t out_bytes = 0;
    struct wvm_block_entry *entry;
    struct wvm_block_queue_state *queue_state = NULL;
    unsigned int queue_lock_index;
    uint16_t status;
    uint64_t now;
    int waited = 0;
    int ref_held = 0;
    int rc;

    if (!service || !service->initialized || !envelope) {
        set_error(error, error_len, "block service is not initialized");
        return -EINVAL;
    }
    if (envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_READ &&
        envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_WRITE &&
        envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_FLUSH) {
        set_error(error, error_len, "envelope is not a block request");
        return -EPROTO;
    }
    if (envelope->vm_id != service->config.vm_id ||
        envelope->vm_incarnation != service->config.vm_incarnation ||
        envelope->manifest_generation != service->config.manifest_generation) {
        set_error(error, error_len, "block request is not admitted here");
        return -EPERM;
    }
    if (wvm_block_request_decode(envelope->payload, envelope->payload_bytes,
                                 &request, &data, &data_bytes, error,
                                 error_len) != 0)
        return -EINVAL;
    /*
     * The message type and the payload operation are two encodings of one
     * fact.  A mismatch would let one operation id execute under a different
     * semantic contract depending on which field the executor read.
     */
    if ((request.operation == WVM_BLOCK_OPERATION_READ &&
         envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_READ) ||
        (request.operation == WVM_BLOCK_OPERATION_WRITE &&
         envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_WRITE) ||
        (request.operation == WVM_BLOCK_OPERATION_FLUSH &&
         envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_FLUSH)) {
        set_error(error, error_len,
                  "block message type disagrees with its payload operation");
        return -EINVAL;
    }

    if (request.operation == WVM_BLOCK_OPERATION_READ) {
        out_capacity =
            (size_t)request.sector_count * WVM_BLOCK_SECTOR_BYTES;
        out = malloc(out_capacity);
        if (!out) {
            set_error(error, error_len, "block read buffer is exhausted");
            return -ENOMEM;
        }
    }

    /*
     * One request queue executes in order; independent queues are not
     * serialized behind one another.  This is also what makes a duplicate
     * request wait for the original execution instead of racing it.
     */
    queue_lock_index = request.queue_id % WVM_BLOCK_SERVICE_EXECUTE_LOCKS;
    pthread_mutex_lock(&service->queue_locks[queue_lock_index]);

    for (;;) {
        pthread_mutex_lock(&service->lock);
        now = monotonic_ms();
        entry = find_locked(service, envelope);
        if (entry && entry->state == WVM_BLOCK_ENTRY_COMPLETED &&
            now - entry->completed_at_ms >
                (uint64_t)service->config.retention_ms)
            expire_entry_locked(service, entry, now);

        if (entry &&
            (entry->operation != request.operation ||
             memcmp(entry->semantic_digest, envelope->semantic_payload_digest,
                    sizeof(entry->semantic_digest)) != 0)) {
            pthread_mutex_unlock(&service->lock);
            set_error(error, error_len,
                      "operation id was reused with different semantics");
            rc = send_result(service, envelope, &request,
                             WVM_BLOCK_WIRE_CONFLICT, NULL, 0, error,
                             error_len);
            goto out;
        }
        if (entry && entry->state == WVM_BLOCK_ENTRY_EXPIRED) {
            pthread_mutex_unlock(&service->lock);
            set_error(error, error_len,
                      "operation result aged out of the retention window");
            rc = send_result(service, envelope, &request,
                             WVM_BLOCK_WIRE_EXPIRED, NULL, 0, error,
                             error_len);
            goto out;
        }
        if (entry && entry->state == WVM_BLOCK_ENTRY_COMPLETED) {
            uint16_t cached_status = entry->status;
            uint8_t *copy = NULL;
            size_t copy_bytes = entry->result_bytes;

            if (copy_bytes != 0) {
                copy = malloc(copy_bytes);
                if (!copy) {
                    pthread_mutex_unlock(&service->lock);
                    set_error(error, error_len,
                              "block replay buffer is exhausted");
                    rc = -ENOMEM;
                    goto out;
                }
                memcpy(copy, entry->result, copy_bytes);
            }
            pthread_mutex_unlock(&service->lock);
            rc = send_result(service, envelope, &request, cached_status, copy,
                             copy_bytes, error, error_len);
            free(copy);
            goto out;
        }
        if (entry) {
            /*
             * IN_FLIGHT.  A duplicate must not execute again; wait for the
             * single owner, then re-resolve the key.
             */
            if (waited) {
                pthread_mutex_unlock(&service->lock);
                set_error(error, error_len,
                          "duplicate block operation is still in flight");
                rc = -EAGAIN;
                goto out;
            }
            rc = wait_for_entry_locked(service, entry);
            pthread_mutex_unlock(&service->lock);
            if (rc != 0) {
                set_error(error, error_len,
                          "duplicate block operation did not complete in time");
                rc = -EAGAIN;
                goto out;
            }
            waited = 1;
            continue;
        }
        /*
         * Not present.  If this thread already waited for an earlier copy,
         * the entry was reclaimed while waking up: report retryable
         * backpressure rather than executing the operation a second time.
         */
        if (waited) {
            pthread_mutex_unlock(&service->lock);
            set_error(error, error_len,
                      "block result vanished while waiting; retry");
            rc = -EAGAIN;
            goto out;
        }

        rc = queue_gate_locked(service, envelope, &request, now, &queue_state,
                               error, error_len);
        if (rc != 0) {
            pthread_mutex_unlock(&service->lock);
            goto out;
        }
        entry = reserve_entry_locked(service, envelope, &request, now, error,
                                     error_len);
        if (!entry) {
            pthread_mutex_unlock(&service->lock);
            rc = -EAGAIN;
            goto out;
        }
        queue_advance_locked(queue_state, &request, now);
        pthread_mutex_unlock(&service->lock);
        break;
    }

    {
        char ref_error[128] = {0};

        if (block_route_ref_get(service, ref_error, sizeof(ref_error)) != 0) {
            pthread_mutex_lock(&service->lock);
            release_entry_locked(service, entry);
            pthread_mutex_unlock(&service->lock);
            if (error && error_len != 0)
                snprintf(error, error_len,
                         "block route scope is not active: %s",
                         ref_error[0] ? ref_error : "unknown");
            rc = -ESTALE;
            goto out;
        }
        ref_held = service->config.pin_scope != NULL;
    }

    rc = service->config.execute(
        service->config.opaque, request.device_index, request.operation,
        request.flags, request.lba_512, request.sector_count, data, data_bytes,
        out, out_capacity, &out_bytes, error, error_len);

    status = rc == 0 ? WVM_BLOCK_WIRE_SUCCESS : WVM_BLOCK_WIRE_IO_ERROR;
    if (rc == 0 && request.operation == WVM_BLOCK_OPERATION_READ &&
        out_bytes != out_capacity)
        status = WVM_BLOCK_WIRE_IO_ERROR;

    pthread_mutex_lock(&service->lock);
    entry->status = status;
    if (status == WVM_BLOCK_WIRE_SUCCESS &&
        request.operation == WVM_BLOCK_OPERATION_READ && out_bytes != 0) {
        entry->result = malloc(out_bytes);
        if (entry->result) {
            memcpy(entry->result, out, out_bytes);
            entry->result_bytes = out_bytes;
            service->retained_bytes += out_bytes;
        } else {
            entry->status = WVM_BLOCK_WIRE_IO_ERROR;
        }
    }
    status = entry->status;
    entry->state = WVM_BLOCK_ENTRY_COMPLETED;
    entry->completed_at_ms = monotonic_ms();
    pthread_cond_broadcast(&entry->completed);
    pthread_mutex_unlock(&service->lock);
    if (ref_held)
        block_route_ref_put(service);

    rc = send_result(service, envelope, &request, status,
                     status == WVM_BLOCK_WIRE_SUCCESS &&
                             request.operation == WVM_BLOCK_OPERATION_READ
                         ? out
                         : NULL,
                     status == WVM_BLOCK_WIRE_SUCCESS &&
                             request.operation == WVM_BLOCK_OPERATION_READ
                         ? out_bytes
                         : 0,
                     error, error_len);
out:
    pthread_mutex_unlock(&service->queue_locks[queue_lock_index]);
    free(out);
    return rc;
}

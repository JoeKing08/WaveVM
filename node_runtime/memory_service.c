#include "memory_service.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum pending_entry_state {
    WVM_MEMORY_PENDING_EMPTY = 0,
    WVM_MEMORY_PENDING_WAITING = 1,
    WVM_MEMORY_PENDING_COMPLETED = 2,
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
    uint64_t retained_until_ms;
    pthread_cond_t completed;
};

struct local_commit_waiter_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint64_t gpa;
    struct wvm_mem_commit_ack ack;
    uint8_t state;
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t retained_until_ms;
    pthread_cond_t completed;
};

struct global_memory_service {
    pthread_mutex_t lock;
    struct wvm_memory_service *service;
    struct local_waiter_entry waiters[WVM_MEMORY_SERVICE_MAX_PENDING];
    struct local_commit_waiter_entry
        commit_waiters[WVM_MEMORY_SERVICE_MAX_PENDING];
};

static struct global_memory_service g_global_memory_service = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
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

static struct wvm_memory_pending_entry *find_pending_locked(
    struct wvm_memory_service *service,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct wvm_memory_pending_entry *entry = &service->pending[i];

        if (entry->state != WVM_MEMORY_PENDING_EMPTY &&
            memcmp(entry->operation_id, operation_id,
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

static int pending_register(struct wvm_memory_service *service,
                            const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                            const struct wvm_runtime_memory_dispatch *memory,
                            uint64_t gpa, int *already_waiting)
{
    struct wvm_memory_pending_entry *entry;
    size_t i;

    pthread_mutex_lock(&service->pending_lock);
    entry = find_pending_locked(service, operation_id);
    if (entry) {
        if (entry->gpa != gpa ||
            entry->directory_physical_node_id !=
                memory->directory_physical_node_id ||
            entry->directory_node_instance_id !=
                memory->directory_node_instance_id) {
            pthread_mutex_unlock(&service->pending_lock);
            return -EEXIST;
        }
        *already_waiting =
            entry->state == WVM_MEMORY_PENDING_WAITING;
        pthread_mutex_unlock(&service->pending_lock);
        return *already_waiting ? 0 : -EALREADY;
    }
    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        entry = &service->pending[i];
        if (entry->state == WVM_MEMORY_PENDING_EMPTY) {
            memset(entry, 0, sizeof(*entry));
            memcpy(entry->operation_id, operation_id,
                   sizeof(entry->operation_id));
            entry->gpa = gpa;
            entry->directory_physical_node_id =
                memory->directory_physical_node_id;
            entry->directory_node_instance_id =
                memory->directory_node_instance_id;
            entry->state = WVM_MEMORY_PENDING_WAITING;
            entry->route_op_ref_held = 0;
            *already_waiting = 0;
            pthread_mutex_unlock(&service->pending_lock);
            {
                char pin_err[128];

                if (memory_route_op_ref_get(service, pin_err,
                                            sizeof(pin_err)) != 0) {
                    pthread_mutex_lock(&service->pending_lock);
                    entry = find_pending_locked(service, operation_id);
                    if (entry && entry->state == WVM_MEMORY_PENDING_WAITING)
                        memset(entry, 0, sizeof(*entry));
                    pthread_mutex_unlock(&service->pending_lock);
                    return -EAGAIN;
                }
                pthread_mutex_lock(&service->pending_lock);
                entry = find_pending_locked(service, operation_id);
                if (entry && entry->state == WVM_MEMORY_PENDING_WAITING) {
                    entry->route_op_ref_held = 1;
                    pthread_mutex_unlock(&service->pending_lock);
                    return 0;
                }
                pthread_mutex_unlock(&service->pending_lock);
                memory_route_op_ref_put(service);
                return -EAGAIN;
            }
        }
    }
    pthread_mutex_unlock(&service->pending_lock);
    return -EAGAIN;
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
        memset(entry, 0, sizeof(*entry));
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

static int resolve_route(
    const struct wvm_memory_service *service,
    const struct wvm_runtime_route_destination *destination,
    struct wvm_envelope_route *route, char *error, size_t error_len)
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
    memset(route, 0, sizeof(*route));
    route->destination_kind = destination->destination_kind;
    route->destination_scope = destination->destination_scope;
    route->destination_vnode_or_endpoint = destination->destination_vnode;
    route->hop_limit = next_hop.hop_limit;
    return 0;
}

static void envelope_from_projection(
    const struct wvm_memory_service *service, uint16_t message_type,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, const struct wvm_envelope_route *route,
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_envelope *envelope)
{
    const struct wvm_runtime_dispatch_projection *projection =
        service->config.dispatch;

    memset(envelope, 0, sizeof(*envelope));
    envelope->message_type = message_type;
    envelope->vm_id = projection->vm_id;
    envelope->vm_incarnation = projection->vm_incarnation;
    envelope->manifest_generation = projection->manifest_generation;
    envelope->origin_physical_node_id = service->config.local_physical_node_id;
    envelope->origin_runtime_instance_id =
        service->config.local_runtime_instance_id;
    memcpy(envelope->operation_id, operation_id, sizeof(envelope->operation_id));
    envelope->delivery_attempt_id = delivery_attempt_id;
    envelope->route_scope_id =
        projection->required_route_snapshot_key.scope_key.route_scope_id;
    envelope->topology_revision =
        projection->required_route_snapshot_key.topology_revision;
    envelope->route_generation =
        projection->required_route_snapshot_key.route_generation;
    memcpy(envelope->route_snapshot_digest,
           projection->required_route_snapshot_key.snapshot_digest,
           sizeof(envelope->route_snapshot_digest));
    envelope->route = *route;
    envelope->payload = payload;
    envelope->payload_bytes = payload_bytes;
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
    struct wvm_envelope_route reply_route;
    struct wvm_mem_ack ack;
    struct wvm_envelope response;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint8_t payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    uint64_t version = 0;
    uint64_t response_attempt;
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
    if (resolve_route(service, &reply_destination, &reply_route, error,
                      error_len) != 0) {
        return -ESTALE;
    }
    memset(&ack, 0, sizeof(ack));
    ack.gpa = read.gpa;
    ack.directory_physical_node_id = service->config.local_physical_node_id;
    ack.directory_node_instance_id = service->config.local_node_instance_id;
    read_result = service->config.read_page(service->config.opaque, read.gpa,
                                            page, &version, error, error_len);
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
    return service->config.send_envelope(service->config.opaque, &response,
                                         error, error_len);
}

static int service_remote_ack(struct wvm_memory_service *service,
                              const struct wvm_envelope *envelope,
                              char *error, size_t error_len)
{
    struct wvm_mem_ack ack;
    struct wvm_memory_pending_entry *pending;
    uint8_t payload_digest[WVM_SHA256_DIGEST_BYTES];
    int completion_result;

    if (wvm_mem_ack_decode(envelope->payload, envelope->payload_bytes, &ack,
                              error, error_len) != 0 ||
        !route_destination_equal(&service->config.dispatch->local_primary,
                                 &envelope->route)) {
        set_error(error, error_len, "V1 memory ACK does not target this runtime");
        return -EPERM;
    }
    wvm_envelope_semantic_digest(envelope->payload, envelope->payload_bytes,
                                    payload_digest);
    pthread_mutex_lock(&service->pending_lock);
    pending = find_pending_locked(service, envelope->operation_id);
    if (!pending) {
        pthread_mutex_unlock(&service->pending_lock);
        set_error(error, error_len, "V1 memory ACK has no pending operation");
        return -ENOENT;
    }
    if (pending->gpa != ack.gpa ||
        pending->directory_physical_node_id !=
            ack.directory_physical_node_id ||
        pending->directory_node_instance_id !=
            ack.directory_node_instance_id) {
        pthread_mutex_unlock(&service->pending_lock);
        set_error(error, error_len, "V1 memory ACK directory authority mismatch");
        return -EPERM;
    }
    if (pending->state == WVM_MEMORY_PENDING_COMPLETED) {
        int duplicate =
            memcmp(pending->completion_payload_digest, payload_digest,
                   sizeof(payload_digest)) == 0;

        pthread_mutex_unlock(&service->pending_lock);
        if (!duplicate) {
            set_error(error, error_len,
                      "V1 memory ACK conflicts with completed operation");
            return -EEXIST;
        }
        return 0;
    }
    pthread_mutex_unlock(&service->pending_lock);

    completion_result = complete_local_fault(
        service, envelope->operation_id, ack.gpa, ack.version, ack.status,
        ack.directory_physical_node_id, ack.directory_node_instance_id,
        ack.data, ack.data_bytes, error, error_len);
    if (completion_result != 0) {
        return completion_result;
    }

    {
        int put_ref = 0;

        pthread_mutex_lock(&service->pending_lock);
        pending = find_pending_locked(service, envelope->operation_id);
        if (pending && pending->state == WVM_MEMORY_PENDING_WAITING) {
            put_ref = pending->route_op_ref_held;
            pending->route_op_ref_held = 0;
            pending->state = WVM_MEMORY_PENDING_COMPLETED;
            memcpy(pending->completion_payload_digest, payload_digest,
                   sizeof(payload_digest));
        }
        pthread_mutex_unlock(&service->pending_lock);
        if (put_ref)
            memory_route_op_ref_put(service);
    }
    return 0;
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
    char *error, size_t error_len)
{
    const struct wvm_runtime_memory_dispatch *memory;
    uint64_t result_version = 0;
    uint16_t status;
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
        &result_version, error, error_len);
    status = commit_status_from_result(apply_result);
    if (status == WVM_MEM_COMMIT_ACK_SUCCESS && result_version == 0) {
        status = WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
    }
    if (status != WVM_MEM_COMMIT_ACK_SUCCESS) {
        result_version = 0;
    } else if (service->config.publish_commit) {
        /*
         * Publishing is deliberately after the authoritative page mutation.
         * HINT delivery may be dropped and repaired by a later read; it must
         * not turn an already-applied directory commit into a false failure.
         */
        (void)service->config.publish_commit(
            service->config.opaque, gpa, result_version, offset, data,
            data_bytes, service->config.local_physical_node_id, error,
            error_len);
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
        pthread_mutex_unlock(&service->outgoing_commit_lock);
        if (put_ref)
            memory_route_op_ref_put(service);
    }

    completion_result = service->config.complete_commit(
        service->config.opaque, envelope->operation_id, ack.gpa, ack.status,
        ack.result_version, ack.directory_physical_node_id,
        ack.directory_node_instance_id, error, error_len);
    return completion_result;
}

int wvm_memory_service_request_commit(
    struct wvm_memory_service *service, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, char *error, size_t error_len)
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
            operation_id, error, error_len);
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
    uint8_t payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t response_payload[WVM_MEM_COMMIT_ACK_BYTES];
    uint64_t result_version = 0;
    uint64_t response_attempt;
    int replay;
    int apply_result;

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
    if (resolve_route(service, &reply_destination, &reply_route, error,
                      error_len) != 0) {
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
            commit.offset, commit.data, commit.data_bytes, &result_version,
            error, error_len);
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
                    (void)service->config.publish_commit(
                        service->config.opaque, commit.gpa, result_version,
                        commit.offset, commit.data, commit.data_bytes,
                        envelope->origin_physical_node_id, error,
                        error_len);
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
    service->initialized = 1;
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
    for (;;) {
        int active = 0;

        pthread_mutex_lock(&service->pending_lock);
        for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
            if (service->pending[i].state == WVM_MEMORY_PENDING_WAITING) {
                active++;
                break;
            }
        }
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
            return 0;
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
        pthread_mutex_destroy(&service->pending_lock);
        pthread_mutex_destroy(&service->commit_lock);
        pthread_mutex_destroy(&service->outgoing_commit_lock);
    }
    memset(service, 0, sizeof(*service));
}

int wvm_memory_service_request_fault(
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
    if (memory->directory_physical_node_id ==
            service->config.local_physical_node_id &&
        memory->directory_node_instance_id ==
            service->config.local_node_instance_id) {
        result = service->config.read_page(service->config.opaque, gpa, page,
                                           &version, error, error_len);
        if (result != 0) {
            return result;
        }
        return complete_local_fault(
            service, operation_id, gpa, version, WVM_MEM_ACK_SUCCESS,
            service->config.local_physical_node_id,
            service->config.local_node_instance_id, page, sizeof(page),
            error, error_len);
    }

    result = pending_register(service, operation_id, memory, gpa,
                              &already_waiting);
    if (result != 0) {
        if (result == -EALREADY) {
            set_error(error, error_len,
                      "V1 memory fault already completed for this operation");
        } else if (result == -EEXIST) {
            set_error(error, error_len,
                      "V1 memory fault operation conflicts with pending work");
        } else if (result == -EAGAIN) {
            set_error(error, error_len, "V1 memory pending table is full");
        }
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

int wvm_memory_service_dispatch(
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
    default:
        set_error(error, error_len, "V1 memory service message is unsupported");
        return -ENOTSUP;
    }
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
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct local_commit_waiter_entry *entry =
            &g_global_memory_service.commit_waiters[i];

        if (entry->state != WVM_MEMORY_COMMIT_WAITER_EMPTY &&
            memcmp(entry->operation_id, operation_id,
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
    size_t i;

    global_reap_expired_locked();
    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct local_commit_waiter_entry *entry =
            &g_global_memory_service.commit_waiters[i];

        if (entry->state == WVM_MEMORY_COMMIT_WAITER_EMPTY) {
            memset(entry, 0, sizeof(*entry));
            memcpy(entry->operation_id, operation_id,
                   sizeof(entry->operation_id));
            entry->gpa = gpa;
            if (pthread_cond_init(&entry->completed, NULL) != 0) {
                memset(entry, 0, sizeof(*entry));
                return NULL;
            }
            entry->state = WVM_MEMORY_COMMIT_WAITER_WAITING;
            return entry;
        }
    }
    return NULL;
}

static void global_commit_waiter_release_locked(
    struct local_commit_waiter_entry *entry)
{
    if (!entry || entry->state == WVM_MEMORY_COMMIT_WAITER_EMPTY) {
        return;
    }
    pthread_cond_destroy(&entry->completed);
    memset(entry, 0, sizeof(*entry));
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
}

static void global_reap_expired_locked(void)
{
    uint64_t now = monotonic_milliseconds();
    size_t i;

    for (i = 0; i < WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
        struct local_waiter_entry *waiter =
            &g_global_memory_service.waiters[i];
        struct local_commit_waiter_entry *commit_waiter =
            &g_global_memory_service.commit_waiters[i];

        if ((waiter->state == WVM_MEMORY_WAITER_COMPLETED ||
             waiter->state == WVM_MEMORY_WAITER_ORPHANED) &&
            retention_expired(waiter->retained_until_ms, now)) {
            global_waiter_release_locked(waiter);
        }
        if ((commit_waiter->state == WVM_MEMORY_COMMIT_WAITER_COMPLETED ||
             commit_waiter->state == WVM_MEMORY_COMMIT_WAITER_ORPHANED) &&
            retention_expired(commit_waiter->retained_until_ms, now)) {
            global_commit_waiter_release_locked(commit_waiter);
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
    if (service && g_global_memory_service.service == service) {
        if (waiter->retained_until_ms == 0) {
            waiter->retained_until_ms = retention_deadline_ms(service);
        }
        waiter->state = WVM_MEMORY_WAITER_COMPLETED;
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
    if (service && g_global_memory_service.service == service) {
        if (waiter->retained_until_ms == 0) {
            waiter->retained_until_ms = retention_deadline_ms(service);
        }
        waiter->state = WVM_MEMORY_COMMIT_WAITER_COMPLETED;
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
            {
                struct local_commit_waiter_entry *commit_waiter =
                    &g_global_memory_service.commit_waiters[i];

                if (commit_waiter->state ==
                    WVM_MEMORY_COMMIT_WAITER_WAITING) {
                    memset(&commit_waiter->ack, 0,
                           sizeof(commit_waiter->ack));
                    commit_waiter->ack.gpa = commit_waiter->gpa;
                    commit_waiter->ack.status =
                        WVM_MEM_COMMIT_ACK_INTERNAL_FAILURE;
                    commit_waiter->state =
                        WVM_MEMORY_COMMIT_WAITER_COMPLETED;
                    pthread_cond_broadcast(&commit_waiter->completed);
                }
            }
        }
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);
}

int wvm_memory_service_global_request_fault(
    uint64_t gpa, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, struct wvm_mem_ack *ack,
    uint8_t page[WVM_MEMORY_PAGE_BYTES], char *error, size_t error_len)
{
    struct wvm_memory_service *service;
    struct local_waiter_entry *waiter;
    struct timespec deadline;
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
            adopted_orphan = 1;
        }
    } else {
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
            waiter->retained_until_ms = retention_deadline_ms(service);
        } else {
            global_waiter_release_locked(waiter);
        }
        pthread_mutex_unlock(&g_global_memory_service.lock);
        return service_result;
    }
    if (global_waiter_deadline(service->config.completion_timeout_ms,
                               &deadline) != 0) {
        pthread_mutex_lock(&g_global_memory_service.lock);
        pending_remove(service, operation_id);
        global_waiter_release_locked(waiter);
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len, "cannot create V1 memory fault deadline");
        return -EIO;
    }

    pthread_mutex_lock(&g_global_memory_service.lock);
    while (waiter->state == WVM_MEMORY_WAITER_WAITING) {
        wait_result = pthread_cond_timedwait(&waiter->completed,
                                             &g_global_memory_service.lock,
                                             &deadline);
        if (wait_result == ETIMEDOUT) {
            /*
             * Keep the operation identity alive through the route retention
             * horizon. A late ACK may still complete this waiter, and a
             * retry with the same operation ID may rejoin it.
             */
            waiter->state = WVM_MEMORY_WAITER_ORPHANED;
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
     * G10/G5-aligned: retain COMPLETED through completion_timeout_ms horizon so
     * same-operation_id replay and conflict checks work. Capacity pressure is
     * handled by reap_expired + allocate backpressure (-EAGAIN when full), not
     * by forgetting results before the horizon.
     */
    global_waiter_finish_locked(waiter, service);
    pthread_mutex_unlock(&g_global_memory_service.lock);
    return 0;
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

int wvm_memory_service_global_request_commit(
    uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, struct wvm_mem_commit_ack *ack,
    char *error, size_t error_len)
{
    struct wvm_memory_service *service;
    struct local_commit_waiter_entry *waiter;
    struct timespec deadline;
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
            adopted_orphan = 1;
        }
    } else {
        waiter = global_commit_waiter_allocate_locked(operation_id, gpa);
        if (!waiter) {
            pthread_mutex_unlock(&g_global_memory_service.lock);
            set_error(error, error_len,
                      "V1 local commit waiter table is full");
            return -EAGAIN;
        }
        memcpy(waiter->semantic_payload_digest, semantic_payload_digest,
               sizeof(waiter->semantic_payload_digest));
    }
    pthread_mutex_unlock(&g_global_memory_service.lock);

    service_result = wvm_memory_service_request_commit(
        service, gpa, base_version, offset, data, data_bytes, operation_id,
        delivery_attempt_id, error, error_len);
    if (service_result != 0) {
        pthread_mutex_lock(&g_global_memory_service.lock);
        if (adopted_orphan) {
            waiter->state = WVM_MEMORY_COMMIT_WAITER_ORPHANED;
            waiter->retained_until_ms = retention_deadline_ms(service);
        } else {
            global_commit_waiter_release_locked(waiter);
        }
        pthread_mutex_unlock(&g_global_memory_service.lock);
        return service_result;
    }
    if (global_waiter_deadline(service->config.completion_timeout_ms,
                               &deadline) != 0) {
        pthread_mutex_lock(&g_global_memory_service.lock);
        global_commit_waiter_release_locked(waiter);
        pthread_mutex_unlock(&g_global_memory_service.lock);
        set_error(error, error_len,
                  "cannot create V1 memory commit deadline");
        return -EIO;
    }

    pthread_mutex_lock(&g_global_memory_service.lock);
    while (waiter->state == WVM_MEMORY_COMMIT_WAITER_WAITING) {
        wait_result = pthread_cond_timedwait(&waiter->completed,
                                             &g_global_memory_service.lock,
                                             &deadline);
        if (wait_result == ETIMEDOUT) {
            waiter->state = WVM_MEMORY_COMMIT_WAITER_ORPHANED;
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
     * idempotent replay. Reap + -EAGAIN backpressure handle table pressure.
     */
    global_commit_waiter_finish_locked(waiter, service);
    pthread_mutex_unlock(&g_global_memory_service.lock);
    return 0;
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

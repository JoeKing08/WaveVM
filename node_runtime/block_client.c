#define _POSIX_C_SOURCE 200809L

#include "block_client.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

static struct wvm_block_client *g_block_client;

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0)
        snprintf(error, error_len, "%s", message);
}

/* A05: the requester pins the scope until the completion correlates. */
static int block_client_ref_get(struct wvm_block_client *client, char *error,
                                size_t error_len)
{
    if (!client->config.pin_scope)
        return 0;
    return client->config.pin_scope(client->config.scope_opaque, error,
                                    error_len);
}

static void block_client_ref_put(struct wvm_block_client *client)
{
    if (client->config.unpin_scope)
        client->config.unpin_scope(client->config.scope_opaque);
}

static void new_operation_id(uint8_t operation_id[16])
{
    static uint64_t counter;

    if (getrandom(operation_id, 16, 0) != 16) {
        uint64_t value = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32) ^
                         (__sync_add_and_fetch(&counter, 1));
        memset(operation_id, 0, 16);
        memcpy(operation_id, &value, sizeof(value));
        memcpy(operation_id + 8, &counter, sizeof(counter));
    }
    if (operation_id[0] == 0 && operation_id[1] == 0 &&
        operation_id[2] == 0 && operation_id[3] == 0)
        operation_id[0] = 1;
}

int wvm_block_client_init(struct wvm_block_client *client,
                          const struct wvm_block_client_config *config,
                          char *error, size_t error_len)
{
    unsigned int i;

    if (!client || !config || !config->dispatch ||
        !config->send_envelope || !config->resolve_route) {
        set_error(error, error_len, "block client configuration is incomplete");
        return -EINVAL;
    }
    memset(client, 0, sizeof(*client));
    client->config = *config;
    if (client->config.timeout_ms == 0)
        client->config.timeout_ms = WVM_BLOCK_CLIENT_DEFAULT_TIMEOUT_MS;
    if (pthread_mutex_init(&client->lock, NULL) != 0)
        return -ENOMEM;
    for (i = 0; i < WVM_BLOCK_CLIENT_MAX_PENDING; i++) {
        if (pthread_cond_init(&client->pending[i].done, NULL) != 0) {
            while (i > 0)
                pthread_cond_destroy(&client->pending[--i].done);
            pthread_mutex_destroy(&client->lock);
            return -ENOMEM;
        }
    }
    client->initialized = 1;
    return 0;
}

void wvm_block_client_destroy(struct wvm_block_client *client)
{
    unsigned int i;

    if (!client || !client->initialized)
        return;
    for (i = 0; i < WVM_BLOCK_CLIENT_MAX_PENDING; i++)
        pthread_cond_destroy(&client->pending[i].done);
    pthread_mutex_destroy(&client->lock);
    client->initialized = 0;
}

/*
 * Reset one slot without touching its condition variable: a pthread_cond_t
 * must never be zeroed or re-initialized after it was created.
 */
static void pending_reset(struct wvm_block_pending *pending)
{
    pending->occupied = 0;
    pending->completed = 0;
    memset(pending->operation_id, 0, sizeof(pending->operation_id));
    pending->expected_physical_node_id = 0;
    pending->status = 0;
    pending->out = NULL;
    pending->out_capacity = 0;
    pending->out_bytes = 0;
}

static struct wvm_block_pending *pending_find_locked(
    struct wvm_block_client *client,
    const uint8_t operation_id[16])
{
    unsigned int i;

    for (i = 0; i < WVM_BLOCK_CLIENT_MAX_PENDING; i++) {
        if (client->pending[i].occupied &&
            memcmp(client->pending[i].operation_id, operation_id,
                   sizeof(client->pending[i].operation_id)) == 0)
            return &client->pending[i];
    }
    return NULL;
}

static struct wvm_block_pending *pending_alloc_locked(
    struct wvm_block_client *client, unsigned int *slot_out)
{
    unsigned int i;

    for (i = 0; i < WVM_BLOCK_CLIENT_MAX_PENDING; i++) {
        if (!client->pending[i].occupied) {
            pending_reset(&client->pending[i]);
            client->pending[i].occupied = 1;
            *slot_out = i;
            return &client->pending[i];
        }
    }
    return NULL;
}

int wvm_block_client_dispatch_ack(void *opaque,
                                  const struct wvm_envelope *envelope,
                                  char *error, size_t error_len)
{
    struct wvm_block_client *client = opaque;
    struct wvm_block_completion completion;
    struct wvm_block_pending *pending;
    const uint8_t *data = NULL;
    size_t data_bytes = 0;

    if (!client || !client->initialized || !envelope) {
        set_error(error, error_len, "block client is not initialized");
        return -EINVAL;
    }
    if (envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_ACK) {
        set_error(error, error_len, "envelope is not a block completion");
        return -EPROTO;
    }
    if (wvm_block_completion_decode(envelope->payload, envelope->payload_bytes,
                                    &completion, &data, &data_bytes, error,
                                    error_len) != 0)
        return -EINVAL;

    pthread_mutex_lock(&client->lock);
    pending = pending_find_locked(client, envelope->operation_id);
    if (!pending) {
        /*
         * A late completion after the caller gave up.  It is not an error:
         * the operation identity already resolved on this runtime.
         */
        pthread_mutex_unlock(&client->lock);
        return 0;
    }
    if (envelope->origin_physical_node_id !=
        pending->expected_physical_node_id) {
        pthread_mutex_unlock(&client->lock);
        set_error(error, error_len,
                  "block completion came from an unexpected node");
        return -EPERM;
    }
    if (data_bytes > pending->out_capacity) {
        pthread_mutex_unlock(&client->lock);
        set_error(error, error_len, "block completion exceeds the caller buffer");
        return -EMSGSIZE;
    }
    if (data_bytes != 0)
        memcpy(pending->out, data, data_bytes);
    pending->out_bytes = data_bytes;
    pending->status = completion.status;
    pending->completed = 1;
    pthread_cond_broadcast(&pending->done);
    pthread_mutex_unlock(&client->lock);
    return 0;
}

int wvm_block_client_request(
    struct wvm_block_client *client, uint32_t device_index, uint16_t operation,
    uint32_t flags, uint64_t lba_512, uint32_t sector_count,
    const uint8_t *data, size_t data_bytes, uint8_t *out, size_t out_capacity,
    size_t *out_bytes, uint16_t *status, char *error, size_t error_len)
{
    const struct wvm_runtime_storage_dispatch *placement;
    struct wvm_block_request request;
    struct wvm_envelope_route route;
    struct wvm_envelope envelope;
    struct wvm_block_pending *pending = NULL;
    uint8_t payload[WVM_BLOCK_REQUEST_HEADER_BYTES + WVM_BLOCK_MAX_DATA_BYTES];
    uint8_t operation_id[16];
    size_t payload_bytes = 0;
    unsigned int slot = 0;
    uint32_t sequence;
    struct timespec deadline;
    int rc;

    if (!client || !client->initialized || !out_bytes || !status) {
        set_error(error, error_len, "block client request arguments are invalid");
        return -EINVAL;
    }
    if (device_index >= WVM_BLOCK_CLIENT_MAX_DEVICES) {
        set_error(error, error_len, "block device index is out of range");
        return -EINVAL;
    }
    placement = wvm_runtime_dispatch_find_storage(client->config.dispatch,
                                                  device_index);
    if (!placement) {
        set_error(error, error_len,
                  "block device has no admitted storage placement");
        return -ENODEV;
    }
    if (operation == WVM_BLOCK_OPERATION_READ) {
        size_t need = (size_t)sector_count * WVM_BLOCK_SECTOR_BYTES;

        if (!out || out_capacity < need) {
            set_error(error, error_len, "block read buffer is too small");
            return -EINVAL;
        }
    }
    if (client->config.resolve_route(
            client->config.opaque, placement->storage.destination_kind,
            placement->storage.destination_scope,
            placement->storage.destination_vnode, &route, error,
            error_len) != 0)
        return -1;

    memset(&request, 0, sizeof(request));
    request.payload_version = WVM_BLOCK_WIRE_VERSION;
    request.operation = operation;
    request.flags = flags;
    request.lba_512 = lba_512;
    request.sector_count = sector_count;
    request.payload_bytes = (uint32_t)data_bytes;
    request.reply_destination_kind =
        client->config.dispatch->local_primary.destination_kind;
    request.reply_destination_scope =
        client->config.dispatch->local_primary.destination_scope;
    request.reply_destination_vnode =
        client->config.dispatch->local_primary.destination_vnode;
    request.device_index = device_index;

    pthread_mutex_lock(&client->lock);
    sequence = ++client->next_sequence[device_index];
    request.queue_id = device_index;
    request.queue_sequence = sequence;
    pthread_mutex_unlock(&client->lock);

    if (wvm_block_request_encode(&request, data, data_bytes, payload,
                                 sizeof(payload), &payload_bytes, error,
                                 error_len) != 0)
        return -1;

    new_operation_id(operation_id);
    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type =
        operation == WVM_BLOCK_OPERATION_READ
            ? WVM_ENVELOPE_MSG_BLOCK_READ
            : operation == WVM_BLOCK_OPERATION_WRITE
                  ? WVM_ENVELOPE_MSG_BLOCK_WRITE
                  : WVM_ENVELOPE_MSG_BLOCK_FLUSH;
    envelope.vm_id = client->config.dispatch->vm_id;
    envelope.vm_incarnation = client->config.dispatch->vm_incarnation;
    envelope.manifest_generation =
        client->config.dispatch->manifest_generation;
    envelope.origin_physical_node_id = client->config.local_physical_node_id;
    envelope.origin_runtime_instance_id =
        client->config.local_runtime_instance_id;
    memcpy(envelope.operation_id, operation_id, sizeof(envelope.operation_id));
    envelope.delivery_attempt_id = 1;
    envelope.route_scope_id = client->config.dispatch
                                  ->required_route_snapshot_key.scope_key
                                  .route_scope_id;
    envelope.topology_revision =
        client->config.dispatch->required_route_snapshot_key.topology_revision;
    envelope.route_generation =
        client->config.dispatch->required_route_snapshot_key.route_generation;
    memcpy(envelope.route_snapshot_digest,
           client->config.dispatch->required_route_snapshot_key.snapshot_digest,
           sizeof(envelope.route_snapshot_digest));
    envelope.route = route;
    envelope.payload = payload;
    envelope.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 envelope.semantic_payload_digest);

    {
        char ref_error[128] = {0};

        if (block_client_ref_get(client, ref_error, sizeof(ref_error)) != 0) {
            if (error && error_len != 0)
                snprintf(error, error_len,
                         "block route scope is not active: %s",
                         ref_error[0] ? ref_error : "unknown");
            return -ESTALE;
        }
    }

    pthread_mutex_lock(&client->lock);
    pending = pending_alloc_locked(client, &slot);
    if (!pending) {
        pthread_mutex_unlock(&client->lock);
        block_client_ref_put(client);
        set_error(error, error_len, "block client pending table is full");
        return -EAGAIN;
    }
    memcpy(pending->operation_id, operation_id, sizeof(operation_id));
    pending->expected_physical_node_id = placement->storage_physical_node_id;
    pending->out = out;
    pending->out_capacity = out_capacity;
    pthread_mutex_unlock(&client->lock);

    rc = client->config.send_envelope(client->config.opaque, &envelope, error,
                                      error_len);
    if (rc != 0) {
        pthread_mutex_lock(&client->lock);
        pending_reset(&client->pending[slot]);
        pthread_mutex_unlock(&client->lock);
        block_client_ref_put(client);
        return -1;
    }

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += client->config.timeout_ms / 1000U;
    deadline.tv_nsec +=
        (long)(client->config.timeout_ms % 1000U) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&client->lock);
    while (!pending->completed && rc == 0)
        rc = pthread_cond_timedwait(&pending->done, &client->lock, &deadline) ==
                     ETIMEDOUT
                 ? -ETIMEDOUT
                 : 0;
    if (!pending->completed) {
        pending_reset(pending);
        pthread_mutex_unlock(&client->lock);
        block_client_ref_put(client);
        set_error(error, error_len, "block completion timed out");
        return -ETIMEDOUT;
    }
    *status = pending->status;
    *out_bytes = pending->out_bytes;
    pending_reset(pending);
    pthread_mutex_unlock(&client->lock);
    block_client_ref_put(client);
    return 0;
}

int wvm_block_client_global_install(struct wvm_block_client *client,
                                    char *error, size_t error_len)
{
    if (!client || !client->initialized) {
        set_error(error, error_len, "block client cannot be installed");
        return -EINVAL;
    }
    g_block_client = client;
    return 0;
}

void wvm_block_client_global_uninstall(void)
{
    g_block_client = NULL;
}

int wvm_block_client_global_request(
    uint32_t device_index, uint16_t operation, uint32_t flags,
    uint64_t lba_512, uint32_t sector_count, const uint8_t *data,
    size_t data_bytes, uint8_t *out, size_t out_capacity, size_t *out_bytes,
    uint16_t *status, char *error, size_t error_len)
{
    if (!g_block_client) {
        set_error(error, error_len,
                  "block client is not installed in this runtime");
        return -ENODEV;
    }
    return wvm_block_client_request(g_block_client, device_index, operation,
                                    flags, lba_512, sector_count, data,
                                    data_bytes, out, out_capacity, out_bytes,
                                    status, error, error_len);
}

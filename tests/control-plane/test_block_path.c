/* R02: initiator <-> target loopback over the real production functions.
 *
 * The client builds one canonical envelope, the service validates and executes
 * it once against the real chunk store, and the completion is correlated back
 * by operation key.  No test-local handler stands in for either side.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "block_client.h"
#include "block_service.h"
#include "wavevm_block_chunk_store.h"
#include "wavevm_block_wire.h"
#include "wavevm_envelope.h"

#define VM_ID 7U
#define INCARNATION 0x1122334455667788ULL
#define GENERATION 3ULL
#define STORAGE_NODE 11U
#define STORAGE_INSTANCE 33ULL
#define STORAGE_VNODE 5U
#define REQUESTER_NODE 3U
#define REQUESTER_RUNTIME 4U
#define DEVICE 2U
#define SECTORS 8U
#define BYTES (SECTORS * 512U)

static struct wvm_block_service g_service;
static struct wvm_block_client g_client;
static unsigned g_executions;
static uint32_t g_last_flags;
static int g_failures;
static uint8_t g_last_operation_id[16];
static int g_capture_operation_id;
static unsigned g_pins;
static unsigned g_unpins;

static int pin_scope(void *opaque, char *error, size_t error_len)
{
    (void)opaque;
    (void)error;
    (void)error_len;
    g_pins++;
    return 0;
}

static void unpin_scope(void *opaque)
{
    (void)opaque;
    g_unpins++;
}

static int failing_pin(void *opaque, char *error, size_t error_len)
{
    (void)opaque;
    if (error && error_len)
        snprintf(error, error_len, "scope is not active");
    return -1;
}

static void fail(const char *message)
{
    fprintf(stderr, "block-path FAIL: %s\n", message);
    g_failures++;
}

static void expect(int condition, const char *message)
{
    if (!condition)
        fail(message);
}

static int execute_block(void *opaque, uint32_t device_index,
                         uint16_t operation, uint32_t flags, uint64_t lba_512,
                         uint32_t sector_count, const uint8_t *data,
                         size_t data_bytes, uint8_t *out, size_t out_capacity,
                         size_t *out_bytes, char *error, size_t error_len)
{
    (void)opaque;
    if (device_index != DEVICE) {
        if (error && error_len)
            snprintf(error, error_len, "unexpected device %u", device_index);
        return -1;
    }
    g_executions++;
    g_last_flags = flags;
    if (operation == WVM_BLOCK_OPERATION_READ)
        return wvm_block_chunk_read(lba_512, sector_count, out, out_capacity,
                                    out_bytes, error, error_len);
    if (operation == WVM_BLOCK_OPERATION_WRITE) {
        int rc = wvm_block_chunk_write(lba_512, sector_count, data, data_bytes,
                                       (flags & WVM_BLOCK_ORDER_FUA) != 0,
                                       error, error_len);
        *out_bytes = 0;
        return rc;
    }
    *out_bytes = 0;
    return wvm_block_chunk_flush_range(lba_512, sector_count, error, error_len);
}

static int resolve_route(void *opaque, uint16_t destination_kind,
                         uint64_t destination_scope,
                         uint32_t destination_vnode,
                         struct wvm_envelope_route *route, char *error,
                         size_t error_len)
{
    (void)opaque;
    (void)error;
    (void)error_len;
    memset(route, 0, sizeof(*route));
    route->destination_kind = destination_kind;
    route->destination_scope = destination_scope;
    route->destination_vnode_or_endpoint = destination_vnode;
    route->hop_limit = 8;
    return 0;
}

/* Service -> client: the completion goes straight back through real ingress. */
static int service_send_envelope(void *opaque,
                                 const struct wvm_envelope *envelope,
                                 char *error, size_t error_len)
{
    (void)opaque;
    return wvm_block_client_dispatch_ack(&g_client, envelope, error,
                                         error_len);
}

/* Client -> service: the request enters the real target dispatch. */
static int client_send_envelope(void *opaque,
                                const struct wvm_envelope *envelope,
                                char *error, size_t error_len)
{
    (void)opaque;
    if (g_capture_operation_id)
        memcpy(g_last_operation_id, envelope->operation_id, 16);
    return wvm_block_service_dispatch(&g_service, envelope, error, error_len);
}

static int drop_envelope(void *opaque, const struct wvm_envelope *envelope,
                         char *error, size_t error_len)
{
    (void)opaque;
    (void)envelope;
    (void)error;
    (void)error_len;
    return 0;
}

static void fill_projection(struct wvm_runtime_dispatch_projection *projection,
                            struct wvm_runtime_storage_dispatch *storage)
{
    memset(projection, 0, sizeof(*projection));
    projection->vm_id = VM_ID;
    projection->vm_incarnation = INCARNATION;
    projection->manifest_generation = GENERATION;
    projection->local_primary.destination_kind = 1;
    projection->local_primary.destination_vnode = 1;
    projection->required_route_snapshot_key.scope_key.vm_id = VM_ID;
    projection->required_route_snapshot_key.scope_key.vm_incarnation =
        INCARNATION;
    projection->required_route_snapshot_key.scope_key.route_scope_id = 9;
    projection->required_route_snapshot_key.topology_revision = 2;
    projection->required_route_snapshot_key.route_generation = 1;
    memset(projection->required_route_snapshot_key.snapshot_digest, 0x42, 32);

    memset(storage, 0, sizeof(*storage));
    storage->device_index = DEVICE;
    storage->storage_physical_node_id = STORAGE_NODE;
    storage->storage_node_instance_id = STORAGE_INSTANCE;
    storage->storage.destination_kind = 1;
    storage->storage.destination_vnode = STORAGE_VNODE;
    projection->storage_dispatch.entries = storage;
    projection->storage_dispatch.count = 1;
    projection->storage_dispatch.capacity = 1;
}

int main(void)
{
    const char *tmp_root = getenv("TMPDIR");
    char directory[512];
    struct wvm_block_service_config service_config;
    struct wvm_block_client_config client_config;
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_storage_dispatch storage;
    struct wvm_block_client drop_client;
    struct wvm_block_client_config drop_config;
    char error[160] = {0};
    uint8_t pattern[BYTES];
    uint8_t written[BYTES];
    uint8_t out[BYTES];
    size_t out_bytes = 0;
    uint16_t status = 0;
    unsigned int i;

    snprintf(directory, sizeof(directory), "%s/wavevm-block-path-XXXXXX",
             tmp_root && tmp_root[0] ? tmp_root : "/tmp");
    if (!mkdtemp(directory)) {
        fprintf(stderr, "block-path FAIL: cannot create temp dir\n");
        return 1;
    }
    if (wvm_block_chunk_store_set_dir(directory, error, sizeof(error)) != 0 ||
        wvm_block_chunk_store_set_identity("path-test", error, sizeof(error)) !=
            0) {
        fprintf(stderr, "block-path FAIL: chunk store: %s\n", error);
        return 1;
    }
    for (i = 0; i < BYTES; i++)
        pattern[i] = (uint8_t)(i * 3U + 1U);
    if (wvm_block_chunk_write(0, SECTORS, pattern, sizeof(pattern), 1, error,
                              sizeof(error)) != 0) {
        fprintf(stderr, "block-path FAIL: seed write: %s\n", error);
        return 1;
    }

    fill_projection(&projection, &storage);
    memset(&service_config, 0, sizeof(service_config));
    service_config.vm_id = VM_ID;
    service_config.vm_incarnation = INCARNATION;
    service_config.manifest_generation = GENERATION;
    service_config.local_physical_node_id = STORAGE_NODE;
    service_config.local_runtime_instance_id = STORAGE_INSTANCE;
    service_config.execute = execute_block;
    service_config.resolve_route = resolve_route;
    service_config.send_envelope = service_send_envelope;
    service_config.pin_scope = pin_scope;
    service_config.unpin_scope = unpin_scope;
    if (wvm_block_service_init(&g_service, &service_config, error,
                               sizeof(error)) != 0) {
        fprintf(stderr, "block-path FAIL: service init: %s\n", error);
        return 1;
    }

    memset(&client_config, 0, sizeof(client_config));
    client_config.dispatch = &projection;
    client_config.local_physical_node_id = REQUESTER_NODE;
    client_config.local_runtime_instance_id = REQUESTER_RUNTIME;
    client_config.timeout_ms = 2000;
    client_config.send_envelope = client_send_envelope;
    client_config.resolve_route = resolve_route;
    client_config.pin_scope = pin_scope;
    client_config.unpin_scope = unpin_scope;
    if (wvm_block_client_init(&g_client, &client_config, error,
                              sizeof(error)) != 0) {
        fprintf(stderr, "block-path FAIL: client init: %s\n", error);
        return 1;
    }

    /* 1. READ round trip. */
    memset(out, 0, sizeof(out));
    expect(wvm_block_client_request(&g_client, DEVICE, WVM_BLOCK_OPERATION_READ,
                                    0, 0, SECTORS, NULL, 0, out, sizeof(out),
                                    &out_bytes, &status, error,
                                    sizeof(error)) == 0,
           "READ request completed");
    expect(status == WVM_BLOCK_WIRE_SUCCESS, "READ status is success");
    expect(out_bytes == BYTES, "READ returned the full range");
    expect(memcmp(out, pattern, BYTES) == 0, "READ data matches the store");
    expect(g_executions == 1, "READ executed once");

    /* 2. WRITE with FUA, then read it back. */
    for (i = 0; i < BYTES; i++)
        written[i] = (uint8_t)(0x5aU ^ (uint8_t)i);
    expect(wvm_block_client_request(&g_client, DEVICE, WVM_BLOCK_OPERATION_WRITE,
                                    WVM_BLOCK_ORDER_FUA, 32, SECTORS, written,
                                    sizeof(written), NULL, 0, &out_bytes,
                                    &status, error, sizeof(error)) == 0,
           "WRITE request completed");
    expect(status == WVM_BLOCK_WIRE_SUCCESS, "WRITE status is success");
    expect((g_last_flags & WVM_BLOCK_ORDER_FUA) != 0,
           "WRITE reached the executor with FUA");
    expect(wvm_block_client_request(&g_client, DEVICE, WVM_BLOCK_OPERATION_READ,
                                    0, 32, SECTORS, NULL, 0, out, sizeof(out),
                                    &out_bytes, &status, error,
                                    sizeof(error)) == 0,
           "re-READ request completed");
    expect(memcmp(out, written, BYTES) == 0, "re-READ returned the new bytes");

    /* 3. FLUSH round trip. */
    expect(wvm_block_client_request(&g_client, DEVICE, WVM_BLOCK_OPERATION_FLUSH,
                                    0, 32, SECTORS, NULL, 0, NULL, 0,
                                    &out_bytes, &status, error,
                                    sizeof(error)) == 0,
           "FLUSH request completed");
    expect(status == WVM_BLOCK_WIRE_SUCCESS, "FLUSH status is success");
    /*
     * A05: every in-flight operation must pin the admitted route scope on both
     * sides and release it before returning.
     */
    expect(g_pins > 0 && g_pins == g_unpins,
           "route scope pins are balanced after completion");

    /* 4. A device with no admitted placement fails closed. */
    g_executions = 0;
    expect(wvm_block_client_request(&g_client, 9, WVM_BLOCK_OPERATION_READ, 0, 0,
                                    SECTORS, NULL, 0, out, sizeof(out),
                                    &out_bytes, &status, error,
                                    sizeof(error)) == -ENODEV,
           "unplaced device is rejected");
    expect(g_executions == 0, "unplaced device never executes");

    /* 5. A dropped completion is a bounded timeout, not a re-execution. */
    memset(&drop_config, 0, sizeof(drop_config));
    drop_config = client_config;
    drop_config.timeout_ms = 100;
    drop_config.send_envelope = drop_envelope;
    drop_config.opaque = NULL;
    if (wvm_block_client_init(&drop_client, &drop_config, error,
                              sizeof(error)) != 0) {
        fprintf(stderr, "block-path FAIL: drop client init: %s\n", error);
        return 1;
    }
    g_executions = 0;
    expect(wvm_block_client_request(&drop_client, DEVICE,
                                    WVM_BLOCK_OPERATION_READ, 0, 0, SECTORS,
                                    NULL, 0, out, sizeof(out), &out_bytes,
                                    &status, error, sizeof(error)) ==
               -ETIMEDOUT,
           "dropped completion times out");
    expect(g_executions == 0, "dropped completion did not execute");

    /* 5b. A scope that is not active rejects the request before execution. */
    {
        struct wvm_block_client inactive;
        struct wvm_block_client_config inactive_config = client_config;

        inactive_config.pin_scope = failing_pin;
        if (wvm_block_client_init(&inactive, &inactive_config, error,
                                  sizeof(error)) != 0) {
            fprintf(stderr, "block-path FAIL: inactive init: %s\n", error);
            return 1;
        }
        g_executions = 0;
        expect(wvm_block_client_request(&inactive, DEVICE,
                                        WVM_BLOCK_OPERATION_READ, 0, 0,
                                        SECTORS, NULL, 0, out, sizeof(out),
                                        &out_bytes, &status, error,
                                        sizeof(error)) == -ESTALE,
               "inactive route scope rejects the request");
        expect(g_executions == 0, "inactive scope never executes");
        wvm_block_client_destroy(&inactive);
    }

    /* 6. Two operations never share one operation id. */
    g_capture_operation_id = 1;
    expect(wvm_block_client_request(&g_client, DEVICE, WVM_BLOCK_OPERATION_READ,
                                    0, 0, SECTORS, NULL, 0, out, sizeof(out),
                                    &out_bytes, &status, error,
                                    sizeof(error)) == 0,
           "capture READ completed");
    {
        uint8_t first[16];

        memcpy(first, g_last_operation_id, 16);
        expect(wvm_block_client_request(&g_client, DEVICE,
                                        WVM_BLOCK_OPERATION_READ, 0, 0,
                                        SECTORS, NULL, 0, out, sizeof(out),
                                        &out_bytes, &status, error,
                                        sizeof(error)) == 0,
               "second capture READ completed");
        expect(memcmp(first, g_last_operation_id, 16) != 0,
               "operation ids are unique per request");
    }
    g_capture_operation_id = 0;

    wvm_block_client_destroy(&drop_client);
    wvm_block_client_destroy(&g_client);
    wvm_block_service_destroy(&g_service);
    if (g_failures == 0) {
        printf("block-path: PASS (client->service->executor->client)\n");
        return 0;
    }
    return 1;
}

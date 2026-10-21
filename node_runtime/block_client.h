#ifndef WAVEVM_NODE_RUNTIME_BLOCK_CLIENT_H
#define WAVEVM_NODE_RUNTIME_BLOCK_CLIENT_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_block_wire.h"
#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_route_runtime.h"
#include "../common_include/wavevm_runtime_dispatch.h"

#define WVM_BLOCK_CLIENT_MAX_PENDING 64U
#define WVM_BLOCK_CLIENT_DEFAULT_TIMEOUT_MS 5000U
#define WVM_BLOCK_CLIENT_MAX_DEVICES 64U

/*
 * Submit one immutable completion envelope to the local sidecar/gateway
 * boundary.  The callback consumes the envelope synchronously.
 */
typedef int (*wvm_block_client_send_fn)(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

typedef int (*wvm_block_client_route_fn)(
    void *opaque, uint16_t destination_kind, uint64_t destination_scope,
    uint32_t destination_vnode, struct wvm_envelope_route *route, char *error,
    size_t error_len);

struct wvm_block_client_config {
    const struct wvm_runtime_dispatch_projection *dispatch;
    /* Optional A05 pin: held for the whole request/response correlation. */
    int (*pin_scope)(void *opaque, char *error, size_t error_len);
    void (*unpin_scope)(void *opaque);
    void *scope_opaque;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    uint32_t timeout_ms;
    wvm_block_client_send_fn send_envelope;
    wvm_block_client_route_fn resolve_route;
    void *opaque;
};

struct wvm_block_pending {
    int occupied;
    int completed;
    uint8_t operation_id[16];
    uint32_t expected_physical_node_id;
    uint16_t status;
    uint8_t *out;
    size_t out_capacity;
    size_t out_bytes;
    pthread_cond_t done;
};

struct wvm_block_client {
    struct wvm_block_client_config config;
    pthread_mutex_t lock;
    struct wvm_block_pending pending[WVM_BLOCK_CLIENT_MAX_PENDING];
    uint32_t next_sequence[WVM_BLOCK_CLIENT_MAX_DEVICES];
    int initialized;
};

int wvm_block_client_init(struct wvm_block_client *client,
                          const struct wvm_block_client_config *config,
                          char *error, size_t error_len);
void wvm_block_client_destroy(struct wvm_block_client *client);

/*
 * One admitted block operation.  DEVICE_INDEX resolves through the admitted
 * storage dispatch; the call blocks until the correlated completion arrives or
 * the bounded timeout expires.  On success STATUS carries the remote status
 * and OUT/OUT_BYTES carry READ data.  A missing placement is -ENODEV.
 */
int wvm_block_client_request(
    struct wvm_block_client *client, uint32_t device_index, uint16_t operation,
    uint32_t flags, uint64_t lba_512, uint32_t sector_count,
    const uint8_t *data, size_t data_bytes, uint8_t *out, size_t out_capacity,
    size_t *out_bytes, uint16_t *status, char *error, size_t error_len);

/* Ingress entry for WVM_ENVELOPE_MSG_BLOCK_ACK. */
int wvm_block_client_dispatch_ack(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

int wvm_block_client_global_install(struct wvm_block_client *client,
                                    char *error, size_t error_len);
void wvm_block_client_global_uninstall(void);
/*
 * Weak on purpose: a legacy standalone master may link without the unified
 * block client and must fail closed instead of dropping the request.
 */
int wvm_block_client_global_request(
    uint32_t device_index, uint16_t operation, uint32_t flags,
    uint64_t lba_512, uint32_t sector_count, const uint8_t *data,
    size_t data_bytes, uint8_t *out, size_t out_capacity, size_t *out_bytes,
    uint16_t *status, char *error, size_t error_len) __attribute__((weak));

#endif /* WAVEVM_NODE_RUNTIME_BLOCK_CLIENT_H */

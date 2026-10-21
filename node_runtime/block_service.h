#ifndef WAVEVM_NODE_RUNTIME_BLOCK_SERVICE_H
#define WAVEVM_NODE_RUNTIME_BLOCK_SERVICE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_block_wire.h"
#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_route_runtime.h"

#define WVM_BLOCK_SERVICE_MAX_ENTRIES 256U
#define WVM_BLOCK_SERVICE_DEFAULT_RETENTION_MS 30000U
#define WVM_BLOCK_SERVICE_DEFAULT_TOMBSTONE_MS 120000U
#define WVM_BLOCK_SERVICE_DEFAULT_RETENTION_BYTES (8U * 1024U * 1024U)
#define WVM_BLOCK_SERVICE_DUPLICATE_WAIT_MS 5000U
#define WVM_BLOCK_SERVICE_QUEUE_SLOTS 64U
#define WVM_BLOCK_SERVICE_QUEUE_IDLE_MS 5000U
#define WVM_BLOCK_SERVICE_EXECUTE_LOCKS 16U

/*
 * Execute one admitted block operation against the local storage executor.
 * The callback owns durability and must not send network traffic.  It returns
 * 0 on success, or a nonzero status that is reported to the initiator.
 */
typedef int (*wvm_block_execute_fn)(
    void *opaque, uint32_t device_index, uint16_t operation, uint32_t flags,
    uint64_t lba_512, uint32_t sector_count, const uint8_t *data,
    size_t data_bytes, uint8_t *out, size_t out_capacity, size_t *out_bytes,
    char *error, size_t error_len);

/*
 * Resolve one reply leaf against the admitted route snapshot.  The service
 * never derives a destination from a source address or a legacy target id.
 */
typedef int (*wvm_block_route_fn)(
    void *opaque, uint16_t destination_kind, uint64_t destination_scope,
    uint32_t destination_vnode, struct wvm_envelope_route *route, char *error,
    size_t error_len);

/*
 * Submit one immutable completion envelope to the local sidecar/gateway
 * boundary.  The callback consumes the envelope synchronously.
 */
typedef int (*wvm_block_send_fn)(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

struct wvm_block_service_config {
    /* Admitted identity of this runtime; a request for another VM is rejected. */
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    /*
     * Optional A05 pin/unpin of the admitted route scope.  A block operation
     * holds one ref from admission to completion; the unpin records the
     * retention deadline that keeps retire honest.
     */
    int (*pin_scope)(void *opaque, char *error, size_t error_len);
    void (*unpin_scope)(void *opaque);
    void *scope_opaque;
    /*
     * Result retention and tombstone windows must be derived from the admitted
     * lifecycle/route retry window, not left at a default, before the service
     * is advertised as covering the storage contract.
     */
    uint32_t retention_ms;
    uint32_t tombstone_ms;
    size_t retention_bytes;
    wvm_block_execute_fn execute;
    wvm_block_route_fn resolve_route;
    wvm_block_send_fn send_envelope;
    void *opaque;
};

enum wvm_block_entry_state {
    WVM_BLOCK_ENTRY_EMPTY = 0,
    WVM_BLOCK_ENTRY_IN_FLIGHT = 1,
    WVM_BLOCK_ENTRY_COMPLETED = 2,
    /* Executed, result aged out; the identity still rejects silent re-runs. */
    WVM_BLOCK_ENTRY_EXPIRED = 3,
};

struct wvm_block_entry {
    uint8_t operation_id[16];
    uint32_t origin_physical_node_id;
    uint64_t origin_runtime_instance_id;
    uint16_t operation;
    uint32_t flags;
    uint8_t semantic_digest[32];
    uint8_t state;
    uint16_t status;
    uint8_t *result;
    size_t result_bytes;
    uint64_t completed_at_ms;
    uint64_t expired_at_ms;
    pthread_cond_t completed;
};

struct wvm_block_queue_state {
    int occupied;
    uint32_t queue_id;
    uint64_t origin_runtime_instance_id;
    uint32_t next_sequence;
    uint64_t last_activity_ms;
};

struct wvm_block_service {
    struct wvm_block_service_config config;
    pthread_mutex_t lock;
    pthread_mutex_t queue_locks[WVM_BLOCK_SERVICE_EXECUTE_LOCKS];
    struct wvm_block_entry entries[WVM_BLOCK_SERVICE_MAX_ENTRIES];
    struct wvm_block_queue_state queues[WVM_BLOCK_SERVICE_QUEUE_SLOTS];
    size_t retained_bytes;
    int initialized;
};

int wvm_block_service_init(struct wvm_block_service *service,
                           const struct wvm_block_service_config *config,
                           char *error, size_t error_len);
void wvm_block_service_destroy(struct wvm_block_service *service);

/*
 * V1 ingress entry.  The envelope has already passed admitted-identity and
 * route authorization; this function still validates the semantic payload,
 * enforces per-queue sequence order, deduplicates the complete operation
 * identity, executes once, and returns the retained result to every duplicate.
 *
 * A missing slot or result budget is retryable backpressure (-EAGAIN) decided
 * BEFORE execution: the service never executes an operation it cannot keep a
 * deduplication record for.
 */
int wvm_block_service_dispatch(void *opaque, const struct wvm_envelope *envelope,
                               char *error, size_t error_len);

#endif /* WAVEVM_NODE_RUNTIME_BLOCK_SERVICE_H */

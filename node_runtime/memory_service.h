#ifndef WAVEVM_NODE_RUNTIME_MEMORY_SERVICE_H
#define WAVEVM_NODE_RUNTIME_MEMORY_SERVICE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_memory.h"
#include "../common_include/wavevm_route_runtime.h"
#include "../common_include/wavevm_runtime_dispatch.h"

#define WVM_MEMORY_SERVICE_MAX_PENDING 1024U
#define WVM_MEMORY_SERVICE_MAX_CACHE_ENTRIES 4096U

enum wvm_memory_subscriber_state {
    WVM_MEMORY_SUBSCRIBER_EMPTY = 0,
    WVM_MEMORY_SUBSCRIBER_ACTIVE = 1,
    WVM_MEMORY_SUBSCRIBER_STALE = 2,
    WVM_MEMORY_SUBSCRIBER_REMOVING = 3,
    WVM_MEMORY_SUBSCRIBER_REMOVED = 4,
    WVM_MEMORY_SUBSCRIBER_READING = 5,
};

enum wvm_memory_delivery_requirement {
    WVM_MEMORY_DELIVERY_HINT = 1,
    WVM_MEMORY_DELIVERY_FENCE_REQUIRED = 2,
};

enum wvm_memory_service_state {
    WVM_MEMORY_SERVICE_SERVING = 0,
    WVM_MEMORY_SERVICE_DRAINING = 1,
    WVM_MEMORY_SERVICE_RETIRED = 2,
};

enum wvm_memory_commit_state {
    WVM_MEMORY_COMMIT_EMPTY = 0,
    WVM_MEMORY_COMMIT_IN_FLIGHT = 1,
    WVM_MEMORY_COMMIT_COMPLETED = 2,
    /*
     * The directory declined before applying any bytes due to bounded local
     * pressure. Keep the operation identity/digest to reject a conflicting
     * reuse, but let the same operation retry the local apply.
     */
    WVM_MEMORY_COMMIT_RETRYABLE = 3,
};

/*
 * Callbacks remain local to the node runtime. SEND_ENVELOPE submits one
 * immutable V1 envelope to the local sidecar/gateway boundary; it must not
 * create a direct executor-to-executor network path and must consume the
 * envelope synchronously before returning.
 */
typedef int (*wvm_memory_read_page_fn)(
    void *opaque, uint64_t gpa, uint8_t data[WVM_MEMORY_PAGE_BYTES],
    uint64_t *version_out, char *error, size_t error_len);
typedef int (*wvm_memory_complete_fault_fn)(
    void *opaque, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t gpa, uint64_t version, uint16_t status,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    const uint8_t *data, size_t data_bytes, char *error, size_t error_len);
/*
 * Applies one version-checked diff at the local directory. The callback owns
 * the page lock and must return only after the authoritative result version is
 * durable in its local directory state. It must not send legacy network
 * traffic; subscriber delivery belongs above this local adapter.
 *
 * Return 0 with a nonzero RESULT_VERSION for success, -ESTALE for a base
 * version conflict, -ENOENT for an absent page, -EAGAIN/-ENOBUFS for bounded
 * backpressure, or another negative errno for terminal failure.
 */
typedef int (*wvm_memory_commit_page_fn)(
    void *opaque, uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes, int source_shared_backing,
    uint64_t *result_version, char *error, size_t error_len);
typedef int (*wvm_memory_publish_commit_fn)(
    void *opaque, uint64_t gpa, uint64_t result_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes, uint32_t writer_physical_node_id,
    char *error, size_t error_len);
typedef int (*wvm_memory_complete_commit_fn)(
    void *opaque, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t gpa, uint16_t status, uint64_t result_version,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    char *error, size_t error_len);
typedef int (*wvm_memory_send_envelope_fn)(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);
typedef int (*wvm_memory_apply_push_fn)(
    void *opaque, uint32_t directory_physical_node_id,
    uint64_t directory_node_instance_id, uint64_t gpa,
    uint64_t base_version, uint64_t version, uint16_t offset,
    const uint8_t *data, size_t data_bytes, int full_page, char *error,
    size_t error_len);

struct wvm_memory_service_config {
    const struct wvm_runtime_dispatch_projection *dispatch;
    const struct wvm_route_runtime *route_runtime;
    uint32_t local_physical_node_id;
    uint64_t local_node_instance_id;
    uint64_t local_runtime_instance_id;
    uint64_t completion_timeout_ms;
    wvm_memory_read_page_fn read_page;
    wvm_memory_commit_page_fn commit_page;
    wvm_memory_publish_commit_fn publish_commit;
    wvm_memory_complete_commit_fn complete_commit;
    wvm_memory_complete_fault_fn complete_fault;
    wvm_memory_send_envelope_fn send_envelope;
    wvm_memory_apply_push_fn apply_push;
    int enable_typed_subscriber_delivery;
    void *opaque;
};

struct wvm_memory_subscriber {
    struct wvm_memory_subscriber *next;
    uint8_t subscription_id[WVM_IDENTITY_ID_BYTES];
    uint64_t gpa;
    uint32_t subscriber_physical_node_id;
    uint64_t subscriber_node_instance_id;
    uint64_t subscriber_runtime_instance_id;
    struct wvm_vm_route_scope_key route_scope_key;
    struct wvm_runtime_route_destination destination;
    struct wvm_route_snapshot_key route_snapshot_key;
    uint64_t observed_version;
    uint64_t qualification_revision;
    uint16_t delivery_requirement;
    uint8_t state;
    uint64_t last_validated_at;
    uint64_t lease_or_observed_epoch;
};

struct wvm_memory_cache_entry {
    uint64_t gpa;
    uint64_t version;
    uint8_t valid;
    uint8_t resync_in_flight;
};

struct wvm_memory_pending_entry {
    struct wvm_memory_pending_entry *next;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t completion_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t gpa;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    uint64_t retained_until_ms;
    uint64_t result_version;
    uint8_t state;
    uint8_t route_op_ref_held; /* A05: outstanding_operation_refs pin */
};

struct wvm_memory_commit_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t origin_physical_node_id;
    uint64_t origin_runtime_instance_id;
    struct wvm_mem_commit_ack result;
    uint64_t retained_until_ms;
    uint8_t state;
};

struct wvm_memory_outgoing_commit_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t gpa;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    struct wvm_mem_commit_ack result;
    uint64_t retained_until_ms;
    uint8_t state;
    uint8_t route_op_ref_held; /* A05: outstanding_operation_refs pin */
};

struct wvm_memory_service {
    struct wvm_memory_service_config config;
    pthread_mutex_t pending_lock;
    pthread_mutex_t commit_lock;
    pthread_mutex_t outgoing_commit_lock;
    pthread_mutex_t subscriber_lock;
    pthread_mutex_t cache_lock;
    /* Compact read receipts outlive the bounded, page-bearing waiters. */
    struct wvm_memory_pending_entry **pending_buckets;
    size_t pending_bucket_count;
    size_t pending_reap_cursor;
    uint64_t pending_count;
    uint64_t pending_limit;
    uint32_t pending_active;
    struct wvm_memory_commit_entry
        commits[WVM_MEMORY_SERVICE_MAX_PENDING];
    struct wvm_memory_outgoing_commit_entry outgoing_commits
        [WVM_MEMORY_SERVICE_MAX_PENDING];
    struct wvm_memory_subscriber **subscriber_buckets;
    size_t subscriber_bucket_count;
    uint64_t subscriber_count;
    uint64_t subscriber_limit;
    struct wvm_memory_cache_entry cache
        [WVM_MEMORY_SERVICE_MAX_CACHE_ENTRIES];
    uint64_t next_delivery_attempt_id;
    uint64_t remote_read_completions;
    uint64_t remote_commit_completions;
    uint64_t completion_log_ms;
    /* Protected by subscriber_lock; callbacks run without holding it. */
    uint64_t active_calls;
    enum wvm_memory_service_state lifecycle_state;
    int initialized;
};

int wvm_memory_service_init(
    struct wvm_memory_service *service,
    const struct wvm_memory_service_config *config, char *error,
    size_t error_len);
void wvm_memory_service_destroy(struct wvm_memory_service *service);

/*
 * F07: drop ACTIVE/READING qualification for matching subscribers.
 * Match rules (all provided non-zero / non-NULL filters AND together):
 *   physical_node!=0, node_instance!=0, runtime_instance!=0, optional scope.
 * runtime_instance==0 with physical_node+node_instance set → every runtime on
 * that member instance (membership failure / replace).
 * Does not invent HA/rebind. Normal G→G+1 ROUTE_COMMIT must not call this.
 */
int wvm_memory_service_invalidate_subscriber_instance(
    struct wvm_memory_service *service, uint32_t physical_node,
    uint64_t node_instance, uint64_t runtime_instance,
    const struct wvm_vm_route_scope_key *scope_key, char *error,
    size_t error_len);

/*
 * F07: route-scope retirement — mark every ACTIVE/READING subscriber for
 * SCOPE_KEY STALE. Called from the route_runtime retire hook when the local
 * memory service owns that scope's directory table.
 */
int wvm_memory_service_invalidate_subscribers_for_scope(
    struct wvm_memory_service *service,
    const struct wvm_vm_route_scope_key *scope_key, char *error,
    size_t error_len);

/*
 * Reject new work, allow pending ACKs to complete, then retire subscribers
 * after callbacks and in-flight fault/commit records finish. Call after the
 * ingress and executor producers stop. A timeout is STOP-incomplete.
 */
int wvm_memory_service_drain(struct wvm_memory_service *service,
                             uint32_t timeout_ms, char *error,
                             size_t error_len);

/*
 * Start one local QEMU/executor page-fault operation. OPERATION_ID remains
 * stable across retry; DELIVERY_ATTEMPT_ID is mutable forwarding metadata.
 */
int wvm_memory_service_request_fault(
    struct wvm_memory_service *service, uint64_t gpa,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, char *error, size_t error_len);

/*
 * Submit one versioned dirty diff. Remote completion returns through the
 * typed MEM_COMMIT_ACK ingress and invokes complete_commit exactly once for
 * one matching result.
 */
int wvm_memory_service_request_commit(
    struct wvm_memory_service *service, uint64_t gpa,
    uint64_t base_version, uint16_t offset, const uint8_t *data,
    size_t data_bytes, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, char *error, size_t error_len);

/*
 * V1 ingress calls this after envelope identity and payload validation. Only
 * MEM_READ and MEM_ACK are accepted here; other families retain separate
 * typed coordinators.
 */
int wvm_memory_service_dispatch(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

/*
 * The unified node runtime exposes one local fault boundary to its QEMU and
 * executor adapters. Local callers submit an explicit operation ID, then wait
 * only through the route snapshot's bounded completion horizon. Network ACKs
 * still enter through V1 ingress and complete this local operation by identity.
 */
int wvm_memory_service_global_install(
    struct wvm_memory_service *service, char *error, size_t error_len);
void wvm_memory_service_global_uninstall(
    struct wvm_memory_service *service);
int wvm_memory_service_global_request_fault(
    uint64_t gpa, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, struct wvm_mem_ack *ack,
    uint8_t page[WVM_MEMORY_PAGE_BYTES], char *error, size_t error_len);
/* Share one monotonic deadline across a bounded group of page requests. */
uint64_t wvm_memory_service_global_fault_deadline(void);
int wvm_memory_service_global_request_fault_before(
    uint64_t gpa, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, uint64_t deadline_ms, struct wvm_mem_ack *ack,
    uint8_t page[WVM_MEMORY_PAGE_BYTES], char *error, size_t error_len);
int wvm_memory_service_global_complete(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint64_t gpa,
    uint64_t version, uint16_t status,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    const uint8_t *data, size_t data_bytes, char *error, size_t error_len);

int wvm_memory_service_global_request_commit(
    uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, struct wvm_mem_commit_ack *ack,
    char *error, size_t error_len);
int wvm_memory_service_global_request_commit_from_shared_backing(
    uint64_t gpa, uint64_t base_version, uint16_t offset,
    const uint8_t *data, size_t data_bytes,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t delivery_attempt_id, int source_shared_backing,
    struct wvm_mem_commit_ack *ack, char *error, size_t error_len);

/*
 * F07: mark ACTIVE/READING subscribers for one member/runtime instance STALE
 * via the installed global service (member-fail / instance-replace hook).
 * runtime_instance==0 → all runtimes for that member instance.
 */
int wvm_memory_service_global_invalidate_subscriber_instance(
    uint32_t physical_node, uint64_t node_instance, uint64_t runtime_instance,
    const struct wvm_vm_route_scope_key *scope_key, char *error,
    size_t error_len);

int wvm_memory_service_global_invalidate_subscribers_for_scope(
    const struct wvm_vm_route_scope_key *scope_key, char *error,
    size_t error_len);

/*
 * F07: membership-controller hook target. Marks STALE for physical_node +
 * node_instance (all runtimes). Safe no-op (-ENOTCONN) if no global service.
 */
void wvm_memory_service_membership_failure_invalidate_hook(
    void *context, uint32_t physical_node_id, uint64_t node_instance_id,
    uint16_t desired_state, uint16_t health_state);

int wvm_memory_service_global_complete_commit(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint64_t gpa,
    uint16_t status, uint64_t result_version,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    char *error, size_t error_len);

#endif /* WAVEVM_NODE_RUNTIME_MEMORY_SERVICE_H */

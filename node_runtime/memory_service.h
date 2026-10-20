#ifndef WAVEVM_NODE_RUNTIME_MEMORY_SERVICE_H
#define WAVEVM_NODE_RUNTIME_MEMORY_SERVICE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_memory.h"
#include "../common_include/wavevm_route_runtime.h"
#include "../common_include/wavevm_runtime_dispatch.h"

#define WVM_MEMORY_SERVICE_MAX_PENDING 1024U

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
    const uint8_t *data, size_t data_bytes, uint64_t *result_version,
    char *error, size_t error_len);
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
    void *opaque;
};

struct wvm_memory_pending_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t completion_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t gpa;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    uint8_t state;
    uint8_t route_op_ref_held; /* A05: outstanding_operation_refs pin */
};

struct wvm_memory_commit_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t origin_physical_node_id;
    uint64_t origin_runtime_instance_id;
    struct wvm_mem_commit_ack result;
    uint8_t state;
};

struct wvm_memory_outgoing_commit_entry {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t gpa;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    struct wvm_mem_commit_ack result;
    uint8_t state;
    uint8_t route_op_ref_held; /* A05: outstanding_operation_refs pin */
};

struct wvm_memory_service {
    struct wvm_memory_service_config config;
    pthread_mutex_t pending_lock;
    pthread_mutex_t commit_lock;
    pthread_mutex_t outgoing_commit_lock;
    struct wvm_memory_pending_entry
        pending[WVM_MEMORY_SERVICE_MAX_PENDING];
    struct wvm_memory_commit_entry
        commits[WVM_MEMORY_SERVICE_MAX_PENDING];
    struct wvm_memory_outgoing_commit_entry outgoing_commits
        [WVM_MEMORY_SERVICE_MAX_PENDING];
    int initialized;
};

int wvm_memory_service_init(
    struct wvm_memory_service *service,
    const struct wvm_memory_service_config *config, char *error,
    size_t error_len);
void wvm_memory_service_destroy(struct wvm_memory_service *service);

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

int wvm_memory_service_global_complete_commit(
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint64_t gpa,
    uint16_t status, uint64_t result_version,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    char *error, size_t error_len);

#endif /* WAVEVM_NODE_RUNTIME_MEMORY_SERVICE_H */

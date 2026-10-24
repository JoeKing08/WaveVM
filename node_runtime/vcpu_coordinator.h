#ifndef WAVEVM_NODE_RUNTIME_VCPU_COORDINATOR_H
#define WAVEVM_NODE_RUNTIME_VCPU_COORDINATOR_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_route_runtime.h"
#include "../common_include/wavevm_runtime_dispatch.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../common_include/wavevm_vcpu_handoff.h"

enum wvm_vcpu_handoff_owner_state {
    WVM_VCPU_OWNER_LOCAL_OWNED = 1,
    WVM_VCPU_OWNER_REMOTE_IN_FLIGHT = 2,
    WVM_VCPU_OWNER_COMPLETED = 3,
    WVM_VCPU_OWNER_FAILED = 4,
};

/*
 * The caller must have completed the handoff memory fence before submit. The
 * coordinator allocates the next per-vCPU handoff sequence and derives both
 * destination and reply RouteKeys from the admitted runtime projection.
 */
struct wvm_vcpu_handoff_submit {
    uint16_t backend;
    uint32_t vcpu_index;
    uint16_t memory_fence_result;
    uint64_t memory_fence_id;
    uint64_t local_interrupt_watermark;
    uint64_t device_event_watermark;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint16_t context_schema_version;
    uint64_t context_valid_fields;
    const uint8_t *context;
    size_t context_bytes;
};

typedef int (*wvm_vcpu_handoff_send_envelope_fn)(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

/*
 * Completion is called at most once for a terminal VCPU_EXIT. The pointers
 * are valid only for the duration of the callback.
 */
typedef int (*wvm_vcpu_handoff_complete_fn)(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result, char *error,
    size_t error_len);

struct wvm_vcpu_handoff_coordinator_config {
    const struct wvm_node_runtime_manifest *manifest;
    const struct wvm_runtime_gate *runtime_gate;
    const struct wvm_runtime_dispatch_projection *dispatch;
    const struct wvm_route_runtime *route_runtime;
    uint64_t local_runtime_instance_id;
    uint64_t runtime_connection_id;
    uint64_t operation_retention_horizon_ms;
    wvm_vcpu_handoff_send_envelope_fn send_envelope;
    void *send_envelope_opaque;
    wvm_vcpu_handoff_complete_fn complete;
    void *complete_opaque;
};

struct wvm_vcpu_handoff_coordinator {
    struct wvm_vcpu_handoff_coordinator_config config;
    pthread_mutex_t lock;
    void *entries;
    void *lanes;
    size_t capacity;
    int initialized;
};

int wvm_vcpu_handoff_coordinator_init(
    struct wvm_vcpu_handoff_coordinator *coordinator,
    const struct wvm_vcpu_handoff_coordinator_config *config, char *error,
    size_t error_len);
void wvm_vcpu_handoff_coordinator_destroy(
    struct wvm_vcpu_handoff_coordinator *coordinator);

/* Wait for remote in-flight handoffs to produce a terminal result. */
int wvm_vcpu_handoff_coordinator_drain(
    struct wvm_vcpu_handoff_coordinator *coordinator, uint32_t timeout_ms,
    char *error, size_t error_len);

/*
 * Compile and submit one admitted VCPU_RUN. Repeating the same operation ID
 * with identical semantic input only re-emits the retained request; it never
 * creates another executable sequence.
 */
int wvm_vcpu_handoff_coordinator_submit(
    struct wvm_vcpu_handoff_coordinator *coordinator,
    const struct wvm_vcpu_handoff_submit *submit, char *error,
    size_t error_len);

/*
 * Node-runtime ingress invokes this for a decoded VCPU_EXIT. It verifies the
 * stored request, completes one matching handoff exactly once, and rejects
 * unsolicited or conflicting results.
 */
int wvm_vcpu_handoff_coordinator_dispatch(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

/*
 * Return a terminal cached result for one operation_id without minting a new
 * handoff sequence (lost VCPU_EXIT across route-generation change).
 * 0 = filled; -ENOENT unknown; -EINPROGRESS still in flight.
 */
int wvm_vcpu_handoff_coordinator_lookup_completed(
    struct wvm_vcpu_handoff_coordinator *coordinator, uint32_t vcpu_index,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    struct wvm_vcpu_handoff_request *request_out,
    struct wvm_vcpu_handoff_result *result_out, char *error, size_t error_len);

#endif /* WAVEVM_NODE_RUNTIME_VCPU_COORDINATOR_H */

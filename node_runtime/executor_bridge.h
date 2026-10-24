#ifndef WAVEVM_EXECUTOR_BRIDGE_H
#define WAVEVM_EXECUTOR_BRIDGE_H

#include <stddef.h>
#include <pthread.h>
#include <stdint.h>

#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_route_runtime.h"
#include "../common_include/wavevm_runtime_dispatch.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../common_include/wavevm_vcpu_handoff.h"

/*
 * The bridge submits complete immutable envelopes to the local
 * sidecar/gateway boundary. The callback must consume the envelope before it
 * returns; bridge-owned result storage is released immediately afterward.
 */
typedef int (*wvm_executor_bridge_send_envelope_fn)(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

/*
 * The node-runtime/executor boundary is a typed handoff, regardless of
 * whether the executor is implemented by threads, a KVM worker, or a TCG
 * helper process. The bridge supplies the result buffer, so completed state
 * is never borrowed from an executor thread's stack or transient cache.
 */
typedef int (*wvm_executor_bridge_execute_handoff_fn)(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    struct wvm_vcpu_handoff_result *result, uint8_t *result_context,
    size_t result_context_capacity, char *error, size_t error_len);

struct wvm_executor_bridge_config {
    const struct wvm_node_runtime_manifest *manifest;
    const struct wvm_runtime_gate *runtime_gate;
    const struct wvm_runtime_dispatch_projection *dispatch;
    const struct wvm_route_runtime *route_runtime;
    uint64_t local_runtime_instance_id;
    uint64_t runtime_connection_id;
    uint64_t operation_retention_horizon_ms;
    wvm_executor_bridge_execute_handoff_fn execute_handoff;
    void *execute_handoff_opaque;
    wvm_executor_bridge_send_envelope_fn send_envelope;
    void *send_envelope_opaque;
};

/* Create/destroy the admitted typed ingress dispatcher. */
int wvm_executor_bridge_dispatch_init(
    const struct wvm_executor_bridge_config *config, void **dispatch_opaque,
    char *error, size_t error_len);
void wvm_executor_bridge_dispatch_destroy(void *dispatch_opaque);

/*
 * Wait until the ordered typed task queue and its sole worker are idle.
 * Call after the ingress/executor producers stop and before destroying any
 * service the worker may still call. Returns -ETIMEDOUT without discarding
 * queued work; the caller must treat STOP as incomplete and fail closed.
 */
int wvm_executor_bridge_dispatch_drain(void *dispatch_opaque,
                                       uint32_t timeout_ms, char *error,
                                       size_t error_len);

/*
 * Typed vCPU ingress reaches the executor only through this adapter. It
 * independently rechecks the manifest-bound executor identity and local
 * RouteKey before producing a typed VCPU_EXIT through the local sidecar.
 */
int wvm_executor_bridge_dispatch(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

#endif

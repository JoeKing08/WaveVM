#ifndef WAVEVM_NODE_RUNTIME_CONTEXT_H
#define WAVEVM_NODE_RUNTIME_CONTEXT_H

#include <stdint.h>

#include "../common_include/wavevm_manifest.h"
#include "../common_include/wavevm_runtime_names.h"
#include "../common_include/wavevm_runtime_dispatch.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../common_include/wavevm_route_runtime.h"

/*
 * One admitted local runtime context.  The node runtime owns this object and
 * passes it to the coordinator and executor roles; neither role reconstructs
 * identity or placement from positional arguments or legacy environment
 * configuration.
 */
struct wvm_node_runtime_context {
    const char *manifest_path;
    const char *route_snapshot_path;
    const char *dispatch_path;
    const struct wvm_runtime_manifest_storage *manifest_storage;
    const struct wvm_runtime_dispatch_storage *dispatch_storage;
    struct wvm_runtime_name_set names;
    const struct wvm_node_runtime_manifest *manifest;
    const struct wvm_runtime_dispatch_projection *dispatch;
    struct wvm_runtime_gate *runtime_gate;
    struct wvm_route_runtime *route_runtime;
    uint64_t node_instance_id;
    uint32_t physical_node_id;
    uint32_t local_primary_vnode;
    uint32_t local_vcpu_count;
    uint64_t local_memory_bytes;
    uint64_t guest_memory_bytes;
    uint16_t node_runtime_data_port;
    uint16_t node_runtime_control_port;
    uint16_t executor_service_port;
    uint16_t executor_control_port;
    uint32_t executor_worker_count;
    uint32_t sync_batch_size;
};

#endif /* WAVEVM_NODE_RUNTIME_CONTEXT_H */

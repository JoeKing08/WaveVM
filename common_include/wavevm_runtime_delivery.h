#ifndef WAVEVM_RUNTIME_DELIVERY_H
#define WAVEVM_RUNTIME_DELIVERY_H

#include <stddef.h>

#include "wavevm_runtime_dispatch.h"
#include "wavevm_runtime_gate.h"

/*
 * Crash-safe local handoff performed after an authenticated control receiver
 * accepts ACTIVATE_MANIFEST.  The caller supplies only canonical authorities:
 * this module derives the legacy adapter cache and never reconstructs
 * placement or routes from launch configuration.
 */
struct wvm_runtime_delivery_request {
    const struct wvm_candidate_vm_manifest *candidate;
    const struct wvm_node_runtime_manifest *runtime_manifest;
    const struct wvm_cluster_record_set *cluster_records;
    const struct wvm_route_snapshot_record *route_snapshot;
    const struct wvm_runtime_dispatch_projection *dispatch_projection;
    const char *runtime_manifest_path;
};

/*
 * Publish the complete local launch bundle.  Route and dispatch artifacts are
 * made durable before the final runtime manifest becomes visible, so a node
 * runtime cannot observe an admitted manifest without its required inputs.
 *
 * Replays are accepted only when every existing artifact is canonically
 * identical to the requested bundle.  A conflicting path is rejected rather
 * than replacing a live VM incarnation in place.
 */
int wvm_runtime_delivery_publish(
    const struct wvm_runtime_delivery_request *request, char *error,
    size_t error_len);

#endif /* WAVEVM_RUNTIME_DELIVERY_H */

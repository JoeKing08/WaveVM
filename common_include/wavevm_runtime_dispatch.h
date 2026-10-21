#ifndef WAVEVM_RUNTIME_DISPATCH_H
#define WAVEVM_RUNTIME_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_cluster.h"
#include "wavevm_envelope.h"
#include "wavevm_route_delivery.h"

#define WVM_RECORD_RUNTIME_DISPATCH_PROJECTION 0x1028U
#define WVM_RUNTIME_DISPATCH_MAX_BYTES (4U * 1024U * 1024U)
#define WVM_RUNTIME_DISPATCH_PATH_MAX 4096U

/*
 * This is a derived cache for the node-runtime dispatch boundary. It is not a
 * second placement or routing authority: every field is bound to one admitted
 * manifest, one activated local runtime projection, and one route snapshot.
 */
struct wvm_runtime_route_destination {
    uint16_t destination_kind;
    uint64_t destination_scope;
    uint32_t destination_vnode;
};

struct wvm_runtime_cpu_dispatch {
    uint32_t guest_vcpu_index;
    struct wvm_runtime_route_destination executor;
};

struct wvm_runtime_memory_dispatch {
    uint64_t gpa_start;
    uint64_t bytes;
    struct wvm_runtime_route_destination directory;
    struct wvm_runtime_route_destination executor;
    uint32_t directory_physical_node_id;
    uint64_t directory_node_instance_id;
    uint16_t consistency_policy;
};

/*
 * Device placement projection.  A block request names its device; the runtime
 * resolves that device to the admitted storage node and to the route leaf that
 * the completion must return on.  Nothing here may be re-derived from a legacy
 * hash ring at request time.
 */
struct wvm_runtime_storage_dispatch {
    uint32_t device_index;
    uint32_t storage_physical_node_id;
    uint64_t storage_node_instance_id;
    struct wvm_runtime_route_destination storage;
};

#define WVM_RUNTIME_DISPATCH_STORAGE_ENTRY_BYTES 30U
#define WVM_STORAGE_ROUTE_TABLE_SIZE 16U

struct wvm_runtime_cpu_dispatch_list {
    struct wvm_runtime_cpu_dispatch *entries;
    size_t count;
    size_t capacity;
};

struct wvm_runtime_memory_dispatch_list {
    struct wvm_runtime_memory_dispatch *entries;
    size_t count;
    size_t capacity;
};

struct wvm_runtime_storage_dispatch_list {
    struct wvm_runtime_storage_dispatch *entries;
    size_t count;
    size_t capacity;
};

struct wvm_runtime_dispatch_projection {
    uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint32_t physical_node_id;
    uint64_t expected_node_instance_id;
    uint8_t activation_fence[WVM_IDENTITY_ID_BYTES];
    struct wvm_route_snapshot_key required_route_snapshot_key;
    uint16_t route_topology_kind;
    struct wvm_runtime_route_destination local_primary;
    struct wvm_endpoint local_sidecar_endpoint;
    struct wvm_runtime_cpu_dispatch_list cpu_dispatch;
    struct wvm_runtime_memory_dispatch_list memory_dispatch;
    struct wvm_runtime_storage_dispatch_list storage_dispatch;
};

struct wvm_runtime_dispatch_storage {
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_cpu_dispatch *cpu_entries;
    struct wvm_runtime_memory_dispatch *memory_entries;
    struct wvm_runtime_storage_dispatch *storage_entries;
};

void wvm_runtime_dispatch_storage_init(
    struct wvm_runtime_dispatch_storage *storage);
void wvm_runtime_dispatch_storage_free(
    struct wvm_runtime_dispatch_storage *storage);

/*
 * Compile the minimal runtime cache required by the current logic-core
 * adapter.  Cluster records supply physical-node to vnode/sidecar bindings;
 * the immutable candidate supplies placement; the route snapshot supplies the
 * active local sidecar endpoint.
 */
int wvm_runtime_dispatch_projection_build(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_cluster_record_set *records,
    const struct wvm_route_snapshot_record *route_snapshot,
    struct wvm_runtime_dispatch_projection *projection, char *error,
    size_t error_len);

int wvm_runtime_dispatch_projection_validate(
    const struct wvm_runtime_dispatch_projection *projection, char *error,
    size_t error_len);

/*
 * Resolve one admitted placement without consulting launcher configuration or
 * legacy raw node IDs. The returned pointer is owned by the projection.
 */
const struct wvm_runtime_cpu_dispatch *wvm_runtime_dispatch_find_cpu(
    const struct wvm_runtime_dispatch_projection *projection,
    uint32_t guest_vcpu_index);
const struct wvm_runtime_memory_dispatch *wvm_runtime_dispatch_find_memory(
    const struct wvm_runtime_dispatch_projection *projection, uint64_t gpa);
/*
 * Inline so a block client can resolve placement without linking the whole
 * canonical dispatch module.  Entries are validated strictly increasing.
 */
static inline const struct wvm_runtime_storage_dispatch *
wvm_runtime_dispatch_find_storage(
    const struct wvm_runtime_dispatch_projection *projection,
    uint32_t device_index)
{
    size_t left = 0;
    size_t right;

    if (!projection || !projection->storage_dispatch.entries)
        return NULL;
    right = projection->storage_dispatch.count;
    while (left < right) {
        size_t middle = left + (right - left) / 2U;
        const struct wvm_runtime_storage_dispatch *entry =
            &projection->storage_dispatch.entries[middle];

        if (entry->device_index == device_index)
            return entry;
        if (entry->device_index < device_index)
            left = middle + 1U;
        else
            right = middle;
    }
    return NULL;
}

int wvm_runtime_dispatch_projection_encode(
    const struct wvm_runtime_dispatch_projection *projection, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_runtime_dispatch_projection_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_runtime_dispatch_projection *projection, char *error,
    size_t error_len);

int wvm_runtime_dispatch_path_from_manifest(
    const char *manifest_path, char *dispatch_path, size_t dispatch_path_capacity,
    char *error, size_t error_len);
int wvm_runtime_dispatch_file_publish(
    const char *path, const struct wvm_runtime_dispatch_projection *projection,
    char *error, size_t error_len);
int wvm_runtime_dispatch_file_load(
    const char *path, struct wvm_runtime_dispatch_storage *storage,
    char *error, size_t error_len);

#endif /* WAVEVM_RUNTIME_DISPATCH_H */

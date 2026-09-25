#define _POSIX_C_SOURCE 200809L

#include "wavevm_runtime_delivery.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static int route_key_equal(const struct wvm_route_snapshot_key *left,
                           const struct wvm_route_snapshot_key *right)
{
    return left && right &&
           left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int manifest_matches_candidate(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    if (!candidate || !runtime_manifest ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        wvm_node_runtime_manifest_validate(runtime_manifest, error,
                                           error_len) != 0 ||
        !runtime_manifest->has_activation_fence ||
        memcmp(runtime_manifest->candidate_manifest_digest,
               candidate->manifest_digest,
               sizeof(runtime_manifest->candidate_manifest_digest)) != 0 ||
        runtime_manifest->vm_id != candidate->vm_id ||
        runtime_manifest->vm_incarnation != candidate->vm_incarnation ||
        runtime_manifest->manifest_generation != candidate->manifest_generation ||
        memcmp(runtime_manifest->admission_tx_id, candidate->admission_tx_id,
               sizeof(runtime_manifest->admission_tx_id)) != 0 ||
        memcmp(runtime_manifest->eligibility_fence_digest,
               candidate->eligibility_fence_digest,
               sizeof(runtime_manifest->eligibility_fence_digest)) != 0 ||
        !route_key_equal(&runtime_manifest->required_route_snapshot_key,
                         &candidate->prepared_route_snapshot_key)) {
        set_error(error, error_len,
                  "runtime manifest does not match activated candidate");
        return -1;
    }
    return 0;
}

static int projection_equal(const struct wvm_runtime_dispatch_projection *left,
                            const struct wvm_runtime_dispatch_projection *right)
{
    size_t cpu_bytes;
    size_t memory_bytes;

    if (!left || !right ||
        left->cpu_dispatch.count != right->cpu_dispatch.count ||
        left->memory_dispatch.count != right->memory_dispatch.count ||
        memcmp(left->candidate_manifest_digest, right->candidate_manifest_digest,
               sizeof(left->candidate_manifest_digest)) != 0 ||
        left->vm_id != right->vm_id ||
        left->vm_incarnation != right->vm_incarnation ||
        left->manifest_generation != right->manifest_generation ||
        left->physical_node_id != right->physical_node_id ||
        left->expected_node_instance_id != right->expected_node_instance_id ||
        memcmp(left->activation_fence, right->activation_fence,
               sizeof(left->activation_fence)) != 0 ||
        !route_key_equal(&left->required_route_snapshot_key,
                         &right->required_route_snapshot_key) ||
        left->route_topology_kind != right->route_topology_kind ||
        memcmp(&left->local_primary, &right->local_primary,
               sizeof(left->local_primary)) != 0 ||
        memcmp(&left->local_sidecar_endpoint, &right->local_sidecar_endpoint,
               sizeof(left->local_sidecar_endpoint)) != 0) {
        return 0;
    }
    cpu_bytes = left->cpu_dispatch.count * sizeof(*left->cpu_dispatch.entries);
    memory_bytes =
        left->memory_dispatch.count * sizeof(*left->memory_dispatch.entries);
    return (!cpu_bytes ||
            memcmp(left->cpu_dispatch.entries, right->cpu_dispatch.entries,
                   cpu_bytes) == 0) &&
           (!memory_bytes ||
            memcmp(left->memory_dispatch.entries, right->memory_dispatch.entries,
                   memory_bytes) == 0);
}

static int manifest_equal(const struct wvm_node_runtime_manifest *left,
                          const struct wvm_node_runtime_manifest *right,
                          char *error, size_t error_len)
{
    size_t capacity = 4096;

    while (capacity <= WVM_RUNTIME_DISPATCH_MAX_BYTES) {
        uint8_t *left_bytes = malloc(capacity);
        uint8_t *right_bytes = malloc(capacity);
        size_t left_count = 0;
        size_t right_count = 0;
        int left_result;
        int right_result;
        int equal;

        if (!left_bytes || !right_bytes) {
            free(left_bytes);
            free(right_bytes);
            set_error(error, error_len, "cannot allocate manifest comparison");
            return -1;
        }
        left_result = wvm_node_runtime_manifest_encode(
            left, left_bytes, capacity, &left_count, error, error_len);
        right_result = wvm_node_runtime_manifest_encode(
            right, right_bytes, capacity, &right_count, error, error_len);
        if (left_result == 0 && right_result == 0) {
            equal = left_count == right_count &&
                    memcmp(left_bytes, right_bytes, left_count) == 0;
            free(left_bytes);
            free(right_bytes);
            return equal ? 1 : 0;
        }
        free(left_bytes);
        free(right_bytes);
        if (capacity == WVM_RUNTIME_DISPATCH_MAX_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_RUNTIME_DISPATCH_MAX_BYTES) {
            capacity = WVM_RUNTIME_DISPATCH_MAX_BYTES;
        }
    }
    set_error(error, error_len, "runtime manifest exceeds delivery limit");
    return -1;
}

static int dispatch_matches_activation(
    const struct wvm_runtime_dispatch_projection *dispatch,
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_route_snapshot_record *route_snapshot,
    char *error, size_t error_len)
{
    size_t i;

    if (!dispatch || !candidate || !runtime_manifest || !route_snapshot ||
        wvm_runtime_dispatch_projection_validate(dispatch, error, error_len) !=
            0 ||
        dispatch->vm_id != candidate->vm_id ||
        dispatch->vm_incarnation != candidate->vm_incarnation ||
        dispatch->manifest_generation != candidate->manifest_generation ||
        dispatch->physical_node_id != runtime_manifest->physical_node_id ||
        dispatch->expected_node_instance_id !=
            runtime_manifest->expected_node_instance_id ||
        memcmp(dispatch->candidate_manifest_digest, candidate->manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        memcmp(dispatch->activation_fence, runtime_manifest->activation_fence,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        !route_key_equal(&dispatch->required_route_snapshot_key,
                         &runtime_manifest->required_route_snapshot_key) ||
        !route_key_equal(&dispatch->required_route_snapshot_key,
                         &route_snapshot->route_snapshot_key) ||
        dispatch->cpu_dispatch.count != candidate->vcpu_placements.count ||
        dispatch->memory_dispatch.count !=
            candidate->memory_placements.count) {
        set_error(error, error_len,
                  "runtime dispatch does not bind activated participant");
        return -1;
    }
    for (i = 0; i < candidate->vcpu_placements.count; i++) {
        if (dispatch->cpu_dispatch.entries[i].guest_vcpu_index !=
            candidate->vcpu_placements.entries[i].guest_vcpu_index) {
            set_error(error, error_len,
                      "runtime dispatch vCPU set differs from candidate");
            return -1;
        }
    }
    for (i = 0; i < candidate->memory_placements.count; i++) {
        const struct wvm_memory_chunk_assignment *assignment =
            &candidate->memory_placements.entries[i];
        const struct wvm_runtime_memory_dispatch *entry =
            &dispatch->memory_dispatch.entries[i];

        if (entry->gpa_start != assignment->gpa_start ||
            entry->bytes != assignment->bytes ||
            entry->directory_physical_node_id !=
                assignment->directory_physical_node_id ||
            entry->consistency_policy != assignment->consistency_policy) {
            set_error(error, error_len,
                      "runtime dispatch memory set differs from candidate");
            return -1;
        }
    }
    return 0;
}

static int existing_bundle_matches(
    const char *manifest_path, const char *route_path, const char *dispatch_path,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_route_snapshot_record *route_snapshot,
    const struct wvm_runtime_dispatch_projection *dispatch, char *error,
    size_t error_len)
{
    struct wvm_runtime_manifest_storage manifest_storage;
    struct wvm_route_snapshot_file_storage route_storage;
    struct wvm_runtime_dispatch_storage dispatch_storage;
    struct stat manifest_stat;
    int manifest_equal_result;
    int result = -1;

    wvm_runtime_manifest_storage_init(&manifest_storage);
    wvm_route_snapshot_file_storage_init(&route_storage);
    wvm_runtime_dispatch_storage_init(&dispatch_storage);
    if (stat(manifest_path, &manifest_stat) != 0) {
        if (errno == ENOENT) {
            result = 0;
        } else {
            set_error(error, error_len, "cannot inspect runtime manifest: %s",
                      strerror(errno));
        }
        goto out;
    }
    if (wvm_runtime_manifest_load_file(manifest_path, &manifest_storage, error,
                                       error_len) != 0 ||
        (manifest_equal_result =
             manifest_equal(&manifest_storage.manifest, runtime_manifest,
                            error, error_len)) != 1 ||
        wvm_route_snapshot_file_load(route_path, &route_storage, error,
                                     error_len) != 0 ||
        !route_key_equal(&route_storage.snapshot.route_snapshot_key,
                         &route_snapshot->route_snapshot_key) ||
        wvm_runtime_dispatch_file_load(dispatch_path, &dispatch_storage, error,
                                       error_len) != 0 ||
        !projection_equal(&dispatch_storage.projection, dispatch)) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "runtime delivery conflicts with visible manifest");
        }
        goto out;
    }
    result = 1;
out:
    wvm_runtime_manifest_storage_free(&manifest_storage);
    wvm_route_snapshot_file_storage_free(&route_storage);
    wvm_runtime_dispatch_storage_free(&dispatch_storage);
    return result;
}

int wvm_runtime_delivery_publish(
    const struct wvm_runtime_delivery_request *request, char *error,
    size_t error_len)
{
    struct wvm_runtime_dispatch_projection dispatch;
    char route_path[WVM_ROUTE_DELIVERY_PATH_MAX];
    char dispatch_path[WVM_RUNTIME_DISPATCH_PATH_MAX];
    int existing;

    if (!request || !request->candidate || !request->runtime_manifest ||
        (!request->dispatch_projection && !request->cluster_records) ||
        !request->route_snapshot ||
        !request->runtime_manifest_path ||
        request->runtime_manifest_path[0] == '\0' ||
        manifest_matches_candidate(request->candidate, request->runtime_manifest,
                                   error, error_len) != 0 ||
        wvm_route_snapshot_record_validate(request->route_snapshot, error,
                                           error_len) != 0 ||
        !route_key_equal(&request->route_snapshot->route_snapshot_key,
                         &request->runtime_manifest
                              ->required_route_snapshot_key)) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "runtime delivery request is invalid");
        }
        return -1;
    }

    memset(&dispatch, 0, sizeof(dispatch));
    if (request->dispatch_projection) {
        dispatch = *request->dispatch_projection;
        if (dispatch_matches_activation(&dispatch, request->candidate,
                                        request->runtime_manifest,
                                        request->route_snapshot, error,
                                        error_len) != 0) {
            return -1;
        }
    } else {
        dispatch.cpu_dispatch.entries = calloc(
            request->candidate->vcpu_placements.count
                ? request->candidate->vcpu_placements.count
                : 1U,
            sizeof(*dispatch.cpu_dispatch.entries));
        dispatch.memory_dispatch.entries = calloc(
            request->candidate->memory_placements.count
                ? request->candidate->memory_placements.count
                : 1U,
            sizeof(*dispatch.memory_dispatch.entries));
        dispatch.cpu_dispatch.capacity =
            request->candidate->vcpu_placements.count;
        dispatch.memory_dispatch.capacity =
            request->candidate->memory_placements.count;
    }
    if ((!request->dispatch_projection &&
         (!dispatch.cpu_dispatch.entries || !dispatch.memory_dispatch.entries ||
          wvm_runtime_dispatch_projection_build(
              request->candidate, request->runtime_manifest,
              request->cluster_records, request->route_snapshot, &dispatch,
              error, error_len) != 0)) ||
        wvm_route_snapshot_path_from_manifest(
            request->runtime_manifest_path, route_path, sizeof(route_path),
            error, error_len) != 0 ||
        wvm_runtime_dispatch_path_from_manifest(
            request->runtime_manifest_path, dispatch_path, sizeof(dispatch_path),
            error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "cannot derive runtime delivery bundle");
        }
        if (!request->dispatch_projection) {
            free(dispatch.cpu_dispatch.entries);
            free(dispatch.memory_dispatch.entries);
        }
        return -1;
    }

    existing = existing_bundle_matches(
        request->runtime_manifest_path, route_path, dispatch_path,
        request->runtime_manifest, request->route_snapshot, &dispatch, error,
        error_len);
    if (existing < 0) {
        if (!request->dispatch_projection) {
            free(dispatch.cpu_dispatch.entries);
            free(dispatch.memory_dispatch.entries);
        }
        return -1;
    }
    if (existing == 0 &&
        (wvm_route_snapshot_file_publish(route_path, request->route_snapshot,
                                         error, error_len) != 0 ||
         wvm_runtime_dispatch_file_publish(dispatch_path, &dispatch, error,
                                           error_len) != 0 ||
         wvm_runtime_manifest_file_publish(request->runtime_manifest_path,
                                           request->runtime_manifest, error,
                                           error_len) != 0)) {
        free(dispatch.cpu_dispatch.entries);
        free(dispatch.memory_dispatch.entries);
        return -1;
    }

    if (!request->dispatch_projection) {
        free(dispatch.cpu_dispatch.entries);
        free(dispatch.memory_dispatch.entries);
    }
    return 0;
}

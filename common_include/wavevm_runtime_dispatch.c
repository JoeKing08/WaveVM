#define _GNU_SOURCE

#include "wavevm_runtime_dispatch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_config.h"
#include "wavevm_membership.h"

#define WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES 18U
#define WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES 58U

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

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static uint16_t read_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t read_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_be64(uint8_t *bytes, uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        bytes[7U - i] = (uint8_t)(value >> (i * 8U));
    }
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

static int endpoint_is_legacy_udp_v4(const struct wvm_endpoint *endpoint)
{
    return endpoint &&
           endpoint->data_transport == WVM_DATA_TRANSPORT_UDP &&
           endpoint->data_address_bytes == 4 && endpoint->data_port != 0;
}

static const struct wvm_node_record *find_node(
    const struct wvm_cluster_record_set *records, uint32_t physical_node_id)
{
    size_t i;

    if (!records || !records->nodes) {
        return NULL;
    }
    for (i = 0; i < records->node_count; i++) {
        if (records->nodes[i].physical_node_id == physical_node_id) {
            return &records->nodes[i];
        }
    }
    return NULL;
}

static const struct wvm_route_rule_record *find_exact_route(
    const struct wvm_route_snapshot_record *snapshot, uint64_t scope,
    uint32_t vnode)
{
    size_t i;

    if (!snapshot) {
        return NULL;
    }
    for (i = 0; i < snapshot->next_hop_rules.count; i++) {
        const struct wvm_route_rule_record *rule =
            &snapshot->next_hop_rules.entries[i];

        if (rule->destination_kind == WVM_ROUTE_DESTINATION_EXACT_VNODE &&
            rule->destination_scope == scope &&
            rule->destination_vnode_or_endpoint == vnode) {
            return rule;
        }
    }
    return NULL;
}

static int route_topology_valid(uint16_t topology_kind)
{
    return topology_kind == WVM_ROUTE_TOPOLOGY_FLAT ||
           topology_kind == WVM_ROUTE_TOPOLOGY_FRACTAL;
}

static int route_destination_validate(
    const struct wvm_runtime_route_destination *destination,
    uint16_t topology_kind, char *error, size_t error_len)
{
    if (!destination || !route_topology_valid(topology_kind)) {
        set_error(error, error_len, "runtime route destination is invalid");
        return -1;
    }
    /* Accept full u32 vnode space; reserved values (0, UINT32_MAX) checked elsewhere */
    if (topology_kind == WVM_ROUTE_TOPOLOGY_FLAT &&
        destination->destination_kind ==
            WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE &&
        destination->destination_scope == 0) {
        return 0;
    }
    if (topology_kind == WVM_ROUTE_TOPOLOGY_FRACTAL &&
        destination->destination_kind ==
            WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE &&
        destination->destination_scope != 0) {
        return 0;
    }
    set_error(error, error_len,
              "runtime route destination does not match topology");
    return -1;
}

static int primary_destination_for_node(
    const struct wvm_cluster_record_set *records, uint32_t physical_node_id,
    uint16_t topology_kind, struct wvm_runtime_route_destination *destination,
    char *error, size_t error_len)
{
    const struct wvm_node_record *node = find_node(records, physical_node_id);

    if (!node || !destination || !route_topology_valid(topology_kind) ||
        wvm_node_record_validate(node, error, error_len) != 0 ||
        node->local_vnode_count == 0 ||
        (topology_kind == WVM_ROUTE_TOPOLOGY_FRACTAL &&
         node->pod_id == 0)) {
        set_error(error, error_len,
                  "physical node %u has no representable route destination",
                  physical_node_id);
        return -1;
    }
    /* Check for overflow in the vnode range (local_vnode_first + count),
     * but don't reject high sparse vnodes — u32 space is valid */
    if (node->local_vnode_count > UINT32_MAX - node->local_vnode_first) {
        set_error(error, error_len,
                  "physical node %u vnode range overflows u32",
                  physical_node_id);
        return -1;
    }

    memset(destination, 0, sizeof(*destination));
    destination->destination_kind =
        topology_kind == WVM_ROUTE_TOPOLOGY_FLAT
            ? WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE
            : WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    destination->destination_scope =
        topology_kind == WVM_ROUTE_TOPOLOGY_FLAT ? 0 : node->pod_id;
    destination->destination_vnode = node->local_vnode_first;
    if (route_destination_validate(destination, topology_kind, error,
                                   error_len) != 0) {
        return -1;
    }
    return 0;
}

static int validate_cpu_dispatch(
    const struct wvm_runtime_cpu_dispatch_list *list, uint16_t topology_kind,
    char *error, size_t error_len)
{
    size_t i;

    if (!list || (list->count != 0 && !list->entries) ||
        list->count > list->capacity ||
        list->count > WVM_CPU_ROUTE_TABLE_SIZE) {
        set_error(error, error_len, "runtime CPU dispatch list is invalid");
        return -1;
    }
    for (i = 0; i < list->count; i++) {
        const struct wvm_runtime_cpu_dispatch *entry = &list->entries[i];

        if (entry->guest_vcpu_index >= WVM_CPU_ROUTE_TABLE_SIZE ||
            route_destination_validate(&entry->executor, topology_kind, error,
                                       error_len) != 0 ||
            (i != 0 &&
             list->entries[i - 1].guest_vcpu_index >= entry->guest_vcpu_index)) {
            set_error(error, error_len, "runtime CPU dispatch entry is invalid");
            return -1;
        }
    }
    return 0;
}

static int validate_memory_dispatch(
    const struct wvm_runtime_memory_dispatch_list *list,
    uint16_t topology_kind, char *error, size_t error_len)
{
    size_t i;

    if (!list || (list->count != 0 && !list->entries) ||
        list->count > list->capacity ||
        list->count > WVM_MEMORY_ROUTE_TABLE_SIZE) {
        set_error(error, error_len, "runtime memory dispatch list is invalid");
        return -1;
    }
    for (i = 0; i < list->count; i++) {
        const struct wvm_runtime_memory_dispatch *entry = &list->entries[i];

        if (entry->bytes == 0 || entry->gpa_start > UINT64_MAX - entry->bytes ||
            route_destination_validate(&entry->directory, topology_kind, error,
                                       error_len) != 0 ||
            route_destination_validate(&entry->executor, topology_kind, error,
                                       error_len) != 0 ||
            entry->directory_physical_node_id == 0 ||
            entry->directory_node_instance_id == 0 ||
            entry->consistency_policy == 0 ||
            (i != 0 &&
             list->entries[i - 1].gpa_start + list->entries[i - 1].bytes >
                 entry->gpa_start)) {
            set_error(error, error_len,
                      "runtime memory dispatch entry is invalid");
            return -1;
        }
    }
    return 0;
}

void wvm_runtime_dispatch_storage_init(
    struct wvm_runtime_dispatch_storage *storage)
{
    if (storage) {
        memset(storage, 0, sizeof(*storage));
    }
}

void wvm_runtime_dispatch_storage_free(
    struct wvm_runtime_dispatch_storage *storage)
{
    if (!storage) {
        return;
    }
    free(storage->cpu_entries);
    free(storage->memory_entries);
    memset(storage, 0, sizeof(*storage));
}

int wvm_runtime_dispatch_projection_validate(
    const struct wvm_runtime_dispatch_projection *projection, char *error,
    size_t error_len)
{
    if (!projection ||
        bytes_are_zero(projection->candidate_manifest_digest,
                       sizeof(projection->candidate_manifest_digest)) ||
        projection->vm_id == 0 || projection->vm_incarnation == 0 ||
        projection->manifest_generation == 0 || projection->physical_node_id == 0 ||
        projection->expected_node_instance_id == 0 ||
        bytes_are_zero(projection->activation_fence,
                       sizeof(projection->activation_fence)) ||
        wvm_route_snapshot_key_validate(&projection->required_route_snapshot_key,
                                        error, error_len) != 0 ||
        projection->required_route_snapshot_key.scope_key.vm_id !=
            projection->vm_id ||
        projection->required_route_snapshot_key.scope_key.vm_incarnation !=
            projection->vm_incarnation ||
        !route_topology_valid(projection->route_topology_kind) ||
        route_destination_validate(&projection->local_primary,
                                   projection->route_topology_kind, error,
                                   error_len) != 0 ||
        wvm_endpoint_validate(&projection->local_sidecar_endpoint, error,
                              error_len) != 0 ||
        !endpoint_is_legacy_udp_v4(&projection->local_sidecar_endpoint) ||
        validate_cpu_dispatch(&projection->cpu_dispatch,
                              projection->route_topology_kind, error,
                              error_len) != 0 ||
        validate_memory_dispatch(&projection->memory_dispatch,
                                 projection->route_topology_kind, error,
                                 error_len) != 0) {
        set_error(error, error_len, "runtime dispatch projection is invalid");
        return -1;
    }
    return 0;
}

int wvm_runtime_dispatch_projection_build(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_cluster_record_set *records,
    const struct wvm_route_snapshot_record *route_snapshot,
    struct wvm_runtime_dispatch_projection *projection, char *error,
    size_t error_len)
{
    const struct wvm_node_record *local_node;
    const struct wvm_route_rule_record *local_route;
    struct wvm_runtime_cpu_dispatch_list cpu_dispatch;
    struct wvm_runtime_memory_dispatch_list memory_dispatch;
    struct wvm_runtime_route_destination local_primary;
    size_t i;

    if (!candidate || !runtime_manifest || !records || !route_snapshot ||
        !projection ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        wvm_node_runtime_manifest_validate(runtime_manifest, error,
                                           error_len) != 0 ||
        wvm_route_snapshot_record_validate(route_snapshot, error,
                                           error_len) != 0 ||
        !runtime_manifest->has_activation_fence ||
        memcmp(candidate->manifest_digest,
               runtime_manifest->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        candidate->vm_id != runtime_manifest->vm_id ||
        candidate->vm_incarnation != runtime_manifest->vm_incarnation ||
        candidate->manifest_generation != runtime_manifest->manifest_generation ||
        memcmp(candidate->admission_tx_id, runtime_manifest->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        !route_key_equal(&candidate->prepared_route_snapshot_key,
                         &runtime_manifest->required_route_snapshot_key) ||
        !route_key_equal(&runtime_manifest->required_route_snapshot_key,
                         &route_snapshot->route_snapshot_key) ||
        !route_topology_valid(route_snapshot->topology_kind) ||
        candidate->vcpu_placements.count > projection->cpu_dispatch.capacity ||
        candidate->memory_placements.count >
            projection->memory_dispatch.capacity ||
        !projection->cpu_dispatch.entries ||
        !projection->memory_dispatch.entries) {
        set_error(error, error_len,
                  "cannot build runtime dispatch projection");
        return -1;
    }

    local_node = find_node(records, runtime_manifest->physical_node_id);
    if (!local_node ||
        local_node->node_instance_id !=
            runtime_manifest->expected_node_instance_id ||
        primary_destination_for_node(
            records, runtime_manifest->physical_node_id,
            route_snapshot->topology_kind, &local_primary, error,
            error_len) != 0 ||
        !(local_route = find_exact_route(
              route_snapshot, local_primary.destination_scope,
              local_primary.destination_vnode)) ||
        !endpoint_is_legacy_udp_v4(&local_route->next_hop_endpoint)) {
        set_error(error, error_len,
                  "runtime dispatch has no admitted local sidecar route");
        return -1;
    }

    cpu_dispatch = projection->cpu_dispatch;
    memory_dispatch = projection->memory_dispatch;
    memset(projection, 0, sizeof(*projection));
    projection->cpu_dispatch = cpu_dispatch;
    projection->memory_dispatch = memory_dispatch;
    projection->cpu_dispatch.count = 0;
    projection->memory_dispatch.count = 0;
    memcpy(projection->candidate_manifest_digest,
           runtime_manifest->candidate_manifest_digest,
           sizeof(projection->candidate_manifest_digest));
    projection->vm_id = runtime_manifest->vm_id;
    projection->vm_incarnation = runtime_manifest->vm_incarnation;
    projection->manifest_generation = runtime_manifest->manifest_generation;
    projection->physical_node_id = runtime_manifest->physical_node_id;
    projection->expected_node_instance_id =
        runtime_manifest->expected_node_instance_id;
    memcpy(projection->activation_fence, runtime_manifest->activation_fence,
           sizeof(projection->activation_fence));
    projection->required_route_snapshot_key =
        runtime_manifest->required_route_snapshot_key;
    projection->route_topology_kind = route_snapshot->topology_kind;
    projection->local_primary = local_primary;
    projection->local_sidecar_endpoint = local_route->next_hop_endpoint;

    for (i = 0; i < candidate->vcpu_placements.count; i++) {
        struct wvm_runtime_route_destination executor;
        const struct wvm_vcpu_assignment *assignment =
            &candidate->vcpu_placements.entries[i];

        if (primary_destination_for_node(
                records, assignment->executor_physical_node_id,
                route_snapshot->topology_kind, &executor, error,
                error_len) != 0 ||
            !find_exact_route(route_snapshot, executor.destination_scope,
                              executor.destination_vnode)) {
            set_error(error, error_len,
                      "vCPU %u has no admitted runtime route",
                      assignment->guest_vcpu_index);
            return -1;
        }
        projection->cpu_dispatch.entries[projection->cpu_dispatch.count++] =
            (struct wvm_runtime_cpu_dispatch){
                .guest_vcpu_index = assignment->guest_vcpu_index,
                .executor = executor,
            };
    }
    for (i = 0; i < candidate->memory_placements.count; i++) {
        struct wvm_runtime_route_destination directory;
        struct wvm_runtime_route_destination executor;
        const struct wvm_memory_chunk_assignment *assignment =
            &candidate->memory_placements.entries[i];
        const struct wvm_node_record *directory_node;

        directory_node =
            find_node(records, assignment->directory_physical_node_id);
        if (primary_destination_for_node(
                records, assignment->directory_physical_node_id,
                route_snapshot->topology_kind, &directory, error,
                error_len) != 0 ||
            primary_destination_for_node(
                records, assignment->executor_physical_node_id,
                route_snapshot->topology_kind, &executor, error,
                error_len) != 0 ||
            !directory_node || directory_node->node_instance_id == 0 ||
            !find_exact_route(route_snapshot, directory.destination_scope,
                              directory.destination_vnode) ||
            !find_exact_route(route_snapshot, executor.destination_scope,
                              executor.destination_vnode)) {
            set_error(error, error_len,
                      "memory range %#llx has no admitted runtime route",
                      (unsigned long long)assignment->gpa_start);
            return -1;
        }
        projection->memory_dispatch.entries[
            projection->memory_dispatch.count++] =
            (struct wvm_runtime_memory_dispatch){
                .gpa_start = assignment->gpa_start,
                .bytes = assignment->bytes,
                .directory = directory,
                .executor = executor,
                .directory_physical_node_id =
                    assignment->directory_physical_node_id,
                .directory_node_instance_id =
                    directory_node->node_instance_id,
                .consistency_policy = assignment->consistency_policy,
            };
    }
    return wvm_runtime_dispatch_projection_validate(projection, error,
                                                    error_len);
}

const struct wvm_runtime_cpu_dispatch *wvm_runtime_dispatch_find_cpu(
    const struct wvm_runtime_dispatch_projection *projection,
    uint32_t guest_vcpu_index)
{
    size_t left = 0;
    size_t right;

    if (!projection || !projection->cpu_dispatch.entries) {
        return NULL;
    }
    right = projection->cpu_dispatch.count;
    while (left < right) {
        size_t middle = left + (right - left) / 2U;
        const struct wvm_runtime_cpu_dispatch *entry =
            &projection->cpu_dispatch.entries[middle];

        if (entry->guest_vcpu_index == guest_vcpu_index) {
            return entry;
        }
        if (entry->guest_vcpu_index < guest_vcpu_index) {
            left = middle + 1U;
        } else {
            right = middle;
        }
    }
    return NULL;
}

const struct wvm_runtime_memory_dispatch *wvm_runtime_dispatch_find_memory(
    const struct wvm_runtime_dispatch_projection *projection, uint64_t gpa)
{
    size_t left = 0;
    size_t right;

    if (!projection || !projection->memory_dispatch.entries) {
        return NULL;
    }
    right = projection->memory_dispatch.count;
    while (left < right) {
        size_t middle = left + (right - left) / 2U;
        const struct wvm_runtime_memory_dispatch *entry =
            &projection->memory_dispatch.entries[middle];

        if (gpa < entry->gpa_start) {
            right = middle;
        } else if (gpa - entry->gpa_start >= entry->bytes) {
            left = middle + 1U;
        } else {
            return entry;
        }
    }
    return NULL;
}

static int encode_cpu_list(const struct wvm_runtime_cpu_dispatch_list *list,
                           uint8_t *bytes, size_t byte_count)
{
    size_t i;

    if (!list || !bytes ||
        byte_count != sizeof(uint32_t) +
                          list->count * WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES ||
        list->count > UINT32_MAX) {
        return -1;
    }
    write_be32(bytes, (uint32_t)list->count);
    for (i = 0; i < list->count; i++) {
        uint8_t *entry = bytes + sizeof(uint32_t) +
                         i * WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES;

        write_be32(entry, list->entries[i].guest_vcpu_index);
        write_be16(entry + 4,
                   list->entries[i].executor.destination_kind);
        write_be64(entry + 6,
                   list->entries[i].executor.destination_scope);
        write_be32(entry + 14,
                   list->entries[i].executor.destination_vnode);
    }
    return 0;
}

static int encode_memory_list(
    const struct wvm_runtime_memory_dispatch_list *list, uint8_t *bytes,
    size_t byte_count)
{
    size_t i;

    if (!list || !bytes ||
        byte_count != sizeof(uint32_t) +
                          list->count *
                              WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES ||
        list->count > UINT32_MAX) {
        return -1;
    }
    write_be32(bytes, (uint32_t)list->count);
    for (i = 0; i < list->count; i++) {
        const struct wvm_runtime_memory_dispatch *source = &list->entries[i];
        uint8_t *entry = bytes + sizeof(uint32_t) +
                         i * WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES;

        write_be64(entry, source->gpa_start);
        write_be64(entry + 8, source->bytes);
        write_be16(entry + 16, source->directory.destination_kind);
        write_be64(entry + 18, source->directory.destination_scope);
        write_be32(entry + 26, source->directory.destination_vnode);
        write_be16(entry + 30, source->executor.destination_kind);
        write_be64(entry + 32, source->executor.destination_scope);
        write_be32(entry + 40, source->executor.destination_vnode);
        write_be32(entry + 44, source->directory_physical_node_id);
        write_be64(entry + 48, source->directory_node_instance_id);
        write_be16(entry + 56, source->consistency_policy);
    }
    return 0;
}

int wvm_runtime_dispatch_projection_encode(
    const struct wvm_runtime_dispatch_projection *projection, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t route_key_bytes[256];
    uint8_t endpoint_bytes[512];
    uint8_t *field_value;
    size_t route_key_byte_count;
    size_t endpoint_byte_count;
    size_t cpu_byte_count;
    size_t memory_byte_count;

    if (wvm_runtime_dispatch_projection_validate(projection, error,
                                                 error_len) != 0 ||
        projection->cpu_dispatch.count >
            (SIZE_MAX - sizeof(uint32_t)) /
                WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES ||
        projection->memory_dispatch.count >
            (SIZE_MAX - sizeof(uint32_t)) /
                WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES) {
        return -1;
    }
    cpu_byte_count = sizeof(uint32_t) + projection->cpu_dispatch.count *
                                             WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES;
    memory_byte_count = sizeof(uint32_t) + projection->memory_dispatch.count *
                                                WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES;
    if (cpu_byte_count > UINT32_MAX || memory_byte_count > UINT32_MAX ||
        wvm_route_snapshot_key_encode(
            &projection->required_route_snapshot_key, route_key_bytes,
            sizeof(route_key_bytes), &route_key_byte_count, error,
            error_len) != 0 ||
        wvm_endpoint_encode(&projection->local_sidecar_endpoint, endpoint_bytes,
                            sizeof(endpoint_bytes), &endpoint_byte_count, error,
                            error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_RUNTIME_DISPATCH_PROJECTION) !=
            0 ||
        wvm_canonical_field_append(
            &builder, 1, projection->candidate_manifest_digest,
            sizeof(projection->candidate_manifest_digest)) != 0 ||
        wvm_canonical_field_append_u32(&builder, 2, projection->vm_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       projection->vm_incarnation) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       projection->manifest_generation) != 0 ||
        wvm_canonical_field_append_u32(&builder, 5,
                                       projection->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 6, projection->expected_node_instance_id) != 0 ||
        wvm_canonical_field_append(&builder, 7, projection->activation_fence,
                                   sizeof(projection->activation_fence)) != 0 ||
        wvm_canonical_field_reserve(&builder, 8, (uint32_t)route_key_byte_count,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode runtime dispatch projection");
        return -1;
    }
    memcpy(field_value, route_key_bytes, route_key_byte_count);
    if (wvm_canonical_field_append_u16(&builder, 9,
                                       projection->route_topology_kind) != 0 ||
        wvm_canonical_field_append_u16(
            &builder, 10, projection->local_primary.destination_kind) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 11, projection->local_primary.destination_scope) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 12, projection->local_primary.destination_vnode) != 0 ||
        wvm_canonical_field_reserve(&builder, 13,
                                    (uint32_t)endpoint_byte_count,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode runtime dispatch projection");
        return -1;
    }
    memcpy(field_value, endpoint_bytes, endpoint_byte_count);
    if (wvm_canonical_field_reserve(&builder, 14, (uint32_t)cpu_byte_count,
                                    &field_value) != 0 ||
        encode_cpu_list(&projection->cpu_dispatch, field_value,
                        cpu_byte_count) != 0 ||
        wvm_canonical_field_reserve(&builder, 15, (uint32_t)memory_byte_count,
                                    &field_value) != 0 ||
        encode_memory_list(&projection->memory_dispatch, field_value,
                           memory_byte_count) != 0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot finish runtime dispatch projection");
        return -1;
    }
    return 0;
}

static int collect_fields(const uint8_t *bytes, size_t encoded_bytes,
                          struct wvm_canonical_field fields[16],
                          unsigned char present[16], char *error,
                          size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int next;

    if (wvm_canonical_record_parse(bytes, encoded_bytes, &record) != 0 ||
        record.record_type != WVM_RECORD_RUNTIME_DISPATCH_PROJECTION) {
        set_error(error, error_len, "runtime dispatch record is malformed");
        return -1;
    }
    memset(fields, 0, sizeof(struct wvm_canonical_field) * 16);
    memset(present, 0, 16);
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 0 || field.tag > 15 || present[field.tag]) {
            set_error(error, error_len,
                      "runtime dispatch record has an unknown field");
            return -1;
        }
        fields[field.tag] = field;
        present[field.tag] = 1;
    }
    if (next < 0) {
        set_error(error, error_len, "runtime dispatch record is malformed");
        return -1;
    }
    for (size_t i = 1; i <= 15; i++) {
        if (!present[i]) {
            set_error(error, error_len,
                      "runtime dispatch record misses field %zu", i);
            return -1;
        }
    }
    return 0;
}

static int list_count(const struct wvm_canonical_field *field,
                      size_t entry_bytes, size_t max_count,
                      size_t *count_out)
{
    size_t count;

    if (!field || !count_out || field->value_bytes < sizeof(uint32_t)) {
        return -1;
    }
    count = read_be32(field->value);
    if (count > max_count ||
        count > (SIZE_MAX - sizeof(uint32_t)) / entry_bytes ||
        field->value_bytes != sizeof(uint32_t) + count * entry_bytes) {
        return -1;
    }
    *count_out = count;
    return 0;
}

static int decode_cpu_list(const struct wvm_canonical_field *field,
                           struct wvm_runtime_cpu_dispatch_list *list)
{
    size_t count;
    size_t i;

    if (!list ||
        list_count(field, WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES,
                   WVM_CPU_ROUTE_TABLE_SIZE, &count) != 0 ||
        count > list->capacity || (count != 0 && !list->entries)) {
        return -1;
    }
    list->count = count;
    for (i = 0; i < count; i++) {
        const uint8_t *entry = field->value + sizeof(uint32_t) +
                               i * WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES;

        list->entries[i].guest_vcpu_index = read_be32(entry);
        list->entries[i].executor.destination_kind = read_be16(entry + 4);
        list->entries[i].executor.destination_scope = read_be64(entry + 6);
        list->entries[i].executor.destination_vnode = read_be32(entry + 14);
    }
    return 0;
}

static int decode_memory_list(
    const struct wvm_canonical_field *field,
    struct wvm_runtime_memory_dispatch_list *list)
{
    size_t count;
    size_t i;

    if (!list ||
        list_count(field, WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES,
                   WVM_MEMORY_ROUTE_TABLE_SIZE, &count) != 0 ||
        count > list->capacity || (count != 0 && !list->entries)) {
        return -1;
    }
    list->count = count;
    for (i = 0; i < count; i++) {
        const uint8_t *entry = field->value + sizeof(uint32_t) +
                               i * WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES;

        list->entries[i].gpa_start = read_be64(entry);
        list->entries[i].bytes = read_be64(entry + 8);
        list->entries[i].directory.destination_kind = read_be16(entry + 16);
        list->entries[i].directory.destination_scope = read_be64(entry + 18);
        list->entries[i].directory.destination_vnode = read_be32(entry + 26);
        list->entries[i].executor.destination_kind = read_be16(entry + 30);
        list->entries[i].executor.destination_scope = read_be64(entry + 32);
        list->entries[i].executor.destination_vnode = read_be32(entry + 40);
        list->entries[i].directory_physical_node_id = read_be32(entry + 44);
        list->entries[i].directory_node_instance_id = read_be64(entry + 48);
        list->entries[i].consistency_policy = read_be16(entry + 56);
    }
    return 0;
}

int wvm_runtime_dispatch_projection_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_runtime_dispatch_projection *projection, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[16];
    unsigned char present[16];
    struct wvm_runtime_cpu_dispatch_list cpu_dispatch;
    struct wvm_runtime_memory_dispatch_list memory_dispatch;

    if (!projection ||
        collect_fields(bytes, encoded_bytes, fields, present, error,
                       error_len) != 0 ||
        fields[1].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[2].value_bytes != 4 || fields[3].value_bytes != 8 ||
        fields[4].value_bytes != 8 || fields[5].value_bytes != 4 ||
        fields[6].value_bytes != 8 ||
        fields[7].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[9].value_bytes != 2 || fields[10].value_bytes != 2 ||
        fields[11].value_bytes != 8 || fields[12].value_bytes != 4) {
        set_error(error, error_len, "runtime dispatch record has invalid fields");
        return -1;
    }
    cpu_dispatch = projection->cpu_dispatch;
    memory_dispatch = projection->memory_dispatch;
    memset(projection, 0, sizeof(*projection));
    projection->cpu_dispatch = cpu_dispatch;
    projection->memory_dispatch = memory_dispatch;
    memcpy(projection->candidate_manifest_digest, fields[1].value,
           sizeof(projection->candidate_manifest_digest));
    projection->vm_id = read_be32(fields[2].value);
    projection->vm_incarnation = read_be64(fields[3].value);
    projection->manifest_generation = read_be64(fields[4].value);
    projection->physical_node_id = read_be32(fields[5].value);
    projection->expected_node_instance_id = read_be64(fields[6].value);
    memcpy(projection->activation_fence, fields[7].value,
           sizeof(projection->activation_fence));
    projection->route_topology_kind = read_be16(fields[9].value);
    projection->local_primary.destination_kind = read_be16(fields[10].value);
    projection->local_primary.destination_scope = read_be64(fields[11].value);
    projection->local_primary.destination_vnode = read_be32(fields[12].value);
    if (wvm_route_snapshot_key_decode(
            fields[8].value, fields[8].value_bytes,
            &projection->required_route_snapshot_key, error, error_len) != 0 ||
        wvm_endpoint_decode(fields[13].value, fields[13].value_bytes,
                            &projection->local_sidecar_endpoint, error,
                            error_len) != 0 ||
        decode_cpu_list(&fields[14], &projection->cpu_dispatch) != 0 ||
        decode_memory_list(&fields[15], &projection->memory_dispatch) != 0) {
        set_error(error, error_len, "runtime dispatch list decoding failed");
        return -1;
    }
    return wvm_runtime_dispatch_projection_validate(projection, error,
                                                    error_len);
}

int wvm_runtime_dispatch_path_from_manifest(
    const char *manifest_path, char *dispatch_path, size_t dispatch_path_capacity,
    char *error, size_t error_len)
{
    int written;

    if (!manifest_path || manifest_path[0] == '\0' || !dispatch_path ||
        dispatch_path_capacity == 0) {
        set_error(error, error_len, "runtime dispatch path input is invalid");
        return -1;
    }
    written = snprintf(dispatch_path, dispatch_path_capacity, "%s.dispatch",
                       manifest_path);
    if (written < 0 || (size_t)written >= dispatch_path_capacity ||
        (size_t)written >= WVM_RUNTIME_DISPATCH_PATH_MAX) {
        set_error(error, error_len, "runtime dispatch path is too long");
        return -1;
    }
    return 0;
}

static int write_full(int fd, const uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t written = write(fd, bytes + offset, byte_count - offset);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int read_full(int fd, uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t received = read(fd, bytes + offset, byte_count - offset);

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static int path_parent(const char *path, char *parent, size_t capacity)
{
    const char *slash;
    size_t length;

    if (!path || !parent || capacity == 0) {
        return -1;
    }
    slash = strrchr(path, '/');
    if (!slash) {
        return snprintf(parent, capacity, ".") < (int)capacity ? 0 : -1;
    }
    length = (size_t)(slash - path);
    if (length == 0) {
        length = 1;
    }
    if (length + 1 > capacity) {
        return -1;
    }
    memcpy(parent, path, length);
    parent[length] = '\0';
    return 0;
}

static int encode_projection_alloc(
    const struct wvm_runtime_dispatch_projection *projection,
    uint8_t **bytes_out, size_t *byte_count_out, char *error,
    size_t error_len)
{
    size_t capacity = 4096;

    while (capacity <= WVM_RUNTIME_DISPATCH_MAX_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len,
                      "cannot allocate runtime dispatch projection");
            return -1;
        }
        if (wvm_runtime_dispatch_projection_encode(
                projection, bytes, capacity, &byte_count, error,
                error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_RUNTIME_DISPATCH_MAX_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_RUNTIME_DISPATCH_MAX_BYTES) {
            capacity = WVM_RUNTIME_DISPATCH_MAX_BYTES;
        }
    }
    set_error(error, error_len, "runtime dispatch projection is too large");
    return -1;
}

int wvm_runtime_dispatch_file_publish(
    const char *path, const struct wvm_runtime_dispatch_projection *projection,
    char *error, size_t error_len)
{
    uint8_t *bytes = NULL;
    size_t byte_count = 0;
    char temporary[WVM_RUNTIME_DISPATCH_PATH_MAX];
    char parent[WVM_RUNTIME_DISPATCH_PATH_MAX];
    int fd = -1;
    int directory_fd = -1;
    int result = -1;

    temporary[0] = '\0';
    if (!path || path[0] == '\0' ||
        encode_projection_alloc(projection, &bytes, &byte_count, error,
                                error_len) != 0 ||
        path_parent(path, parent, sizeof(parent)) != 0 ||
        snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
                 (long)getpid()) >= (int)sizeof(temporary)) {
        set_error(error, error_len,
                  "runtime dispatch publish input is invalid");
        goto out;
    }
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 || write_full(fd, bytes, byte_count) != 0 || fsync(fd) != 0) {
        set_error(error, error_len, "cannot write runtime dispatch: %s",
                  strerror(errno));
        goto out;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_error(error, error_len, "cannot close runtime dispatch: %s",
                  strerror(errno));
        goto out;
    }
    fd = -1;
    if (rename(temporary, path) != 0) {
        set_error(error, error_len, "cannot activate runtime dispatch: %s",
                  strerror(errno));
        goto out;
    }
    directory_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || fsync(directory_fd) != 0) {
        set_error(error, error_len,
                  "cannot fsync runtime dispatch directory: %s",
                  strerror(errno));
        goto out;
    }
    result = 0;

out:
    if (fd >= 0) {
        close(fd);
    }
    if (directory_fd >= 0) {
        close(directory_fd);
    }
    if (result != 0 && temporary[0] != '\0') {
        unlink(temporary);
    }
    free(bytes);
    return result;
}

static int find_dispatch_list_counts(const uint8_t *bytes, size_t byte_count,
                                     size_t *cpu_count, size_t *memory_count)
{
    struct wvm_canonical_field fields[16];
    unsigned char present[16];

    if (collect_fields(bytes, byte_count, fields, present, NULL, 0) != 0 ||
        list_count(&fields[14], WVM_RUNTIME_DISPATCH_CPU_ENTRY_BYTES,
                   WVM_CPU_ROUTE_TABLE_SIZE, cpu_count) != 0 ||
        list_count(&fields[15], WVM_RUNTIME_DISPATCH_MEMORY_ENTRY_BYTES,
                   WVM_MEMORY_ROUTE_TABLE_SIZE, memory_count) != 0) {
        return -1;
    }
    return 0;
}

int wvm_runtime_dispatch_file_load(
    const char *path, struct wvm_runtime_dispatch_storage *storage,
    char *error, size_t error_len)
{
    struct stat st;
    uint8_t *bytes = NULL;
    size_t cpu_count;
    size_t memory_count;
    int fd = -1;
    int result = -1;

    if (!path || !storage || stat(path, &st) != 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > WVM_RUNTIME_DISPATCH_MAX_BYTES) {
        set_error(error, error_len, "runtime dispatch file size is invalid");
        return -1;
    }
    bytes = malloc((size_t)st.st_size);
    if (!bytes) {
        set_error(error, error_len,
                  "cannot allocate runtime dispatch file buffer");
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read_full(fd, bytes, (size_t)st.st_size) != 0) {
        set_error(error, error_len, "cannot read runtime dispatch: %s",
                  strerror(errno));
        goto out;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_error(error, error_len, "cannot close runtime dispatch: %s",
                  strerror(errno));
        goto out;
    }
    fd = -1;
    if (find_dispatch_list_counts(bytes, (size_t)st.st_size, &cpu_count,
                                  &memory_count) != 0) {
        set_error(error, error_len, "runtime dispatch list layout is invalid");
        goto out;
    }
    wvm_runtime_dispatch_storage_free(storage);
    storage->cpu_entries = calloc(cpu_count ? cpu_count : 1,
                                  sizeof(*storage->cpu_entries));
    storage->memory_entries = calloc(memory_count ? memory_count : 1,
                                     sizeof(*storage->memory_entries));
    if (!storage->cpu_entries || !storage->memory_entries) {
        set_error(error, error_len, "cannot allocate runtime dispatch lists");
        goto out;
    }
    storage->projection.cpu_dispatch.entries = storage->cpu_entries;
    storage->projection.cpu_dispatch.capacity = cpu_count;
    storage->projection.memory_dispatch.entries = storage->memory_entries;
    storage->projection.memory_dispatch.capacity = memory_count;
    if (wvm_runtime_dispatch_projection_decode(
            bytes, (size_t)st.st_size, &storage->projection, error,
            error_len) != 0) {
        goto out;
    }
    result = 0;

out:
    if (fd >= 0) {
        close(fd);
    }
    free(bytes);
    if (result != 0) {
        wvm_runtime_dispatch_storage_free(storage);
    }
    return result;
}

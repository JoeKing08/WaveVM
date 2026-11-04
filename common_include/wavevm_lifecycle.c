#include "wavevm_lifecycle.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_canonical.h"

static int lifecycle_exclusive_lease_list_validate(
    const struct wvm_exclusive_lease_list *leases, char *error,
    size_t error_len);
static int lifecycle_startup_dependency_list_validate(
    const struct wvm_startup_dependency_list *dependencies, char *error,
    size_t error_len);
static int lifecycle_vcpu_assignment_list_validate(
    const struct wvm_vcpu_assignment_list *assignments,
    uint32_t physical_node_id,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);
static int lifecycle_memory_assignment_list_validate(
    const struct wvm_memory_chunk_assignment_list *assignments,
    uint32_t physical_node_id,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);
static int lifecycle_storage_assignment_list_validate(
    const struct wvm_storage_assignment_list *assignments,
    uint32_t physical_node_id,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len);
static uint16_t lifecycle_read_be16(const uint8_t *src);
static uint32_t lifecycle_read_be32(const uint8_t *src);
static uint64_t lifecycle_read_be64(const uint8_t *src);
static int lifecycle_parse_record_fields(
    const uint8_t *bytes, size_t encoded_bytes, uint16_t expected_record_type,
    struct wvm_canonical_field *fields, unsigned char *present,
    size_t field_capacity, char *error, size_t error_len);

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

/*
 * The canonical list key intentionally excludes the digest.  Two records
 * claiming the same snapshot generation but carrying different digests are
 * conflicting records, not two sortable entries.
 */
static int route_snapshot_key_compare(
    const struct wvm_route_snapshot_key *left,
    const struct wvm_route_snapshot_key *right)
{
    if (left->scope_key.vm_id != right->scope_key.vm_id) {
        return left->scope_key.vm_id < right->scope_key.vm_id ? -1 : 1;
    }
    if (left->scope_key.vm_incarnation != right->scope_key.vm_incarnation) {
        return left->scope_key.vm_incarnation <
                       right->scope_key.vm_incarnation
                   ? -1
                   : 1;
    }
    if (left->scope_key.route_scope_id != right->scope_key.route_scope_id) {
        return left->scope_key.route_scope_id <
                       right->scope_key.route_scope_id
                   ? -1
                   : 1;
    }
    if (left->topology_revision != right->topology_revision) {
        return left->topology_revision < right->topology_revision ? -1 : 1;
    }
    if (left->route_generation != right->route_generation) {
        return left->route_generation < right->route_generation ? -1 : 1;
    }
    return 0;
}

static int exclusive_lease_equal(const struct wvm_exclusive_lease *left,
                                 const struct wvm_exclusive_lease *right)
{
    return left->lease_kind == right->lease_kind &&
           left->lease_generation == right->lease_generation &&
           strcmp(left->lease_name, right->lease_name) == 0;
}

static int reservation_requirement_equal(
    const struct wvm_reservation_requirement *left,
    const struct wvm_reservation_requirement *right)
{
    size_t i;

    if (memcmp(left->reservation_id, right->reservation_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        left->physical_node_id != right->physical_node_id ||
        left->node_instance_id != right->node_instance_id ||
        left->inventory_revision != right->inventory_revision ||
        left->guest_vcpu_slots != right->guest_vcpu_slots ||
        left->guest_memory_bytes != right->guest_memory_bytes ||
        left->overhead_vcpu_slots != right->overhead_vcpu_slots ||
        left->overhead_memory_bytes != right->overhead_memory_bytes ||
        left->exclusive_leases.count != right->exclusive_leases.count) {
        return 0;
    }
    for (i = 0; i < left->exclusive_leases.count; i++) {
        if (!exclusive_lease_equal(&left->exclusive_leases.entries[i],
                                  &right->exclusive_leases.entries[i])) {
            return 0;
        }
    }
    return 1;
}

static const struct wvm_reservation_requirement *
find_requirement(const struct wvm_candidate_vm_manifest *candidate,
                 uint32_t physical_node_id)
{
    size_t i;

    for (i = 0; i < candidate->reservation_requirements.count; i++) {
        const struct wvm_reservation_requirement *requirement =
            &candidate->reservation_requirements.entries[i];

        if (requirement->physical_node_id == physical_node_id) {
            return requirement;
        }
    }
    return NULL;
}

static int requirement_equal_reservation(
    const struct wvm_reservation_requirement *requirement,
    const struct wvm_resource_reservation *reservation)
{
    return memcmp(requirement->reservation_id, reservation->reservation_id,
                  WVM_IDENTITY_ID_BYTES) == 0 &&
           requirement->physical_node_id == reservation->physical_node_id &&
           requirement->node_instance_id == reservation->node_instance_id &&
           requirement->inventory_revision == reservation->inventory_revision &&
           requirement->guest_vcpu_slots == reservation->guest_vcpu_slots &&
           requirement->guest_memory_bytes == reservation->guest_memory_bytes &&
           requirement->overhead_vcpu_slots ==
               reservation->overhead_vcpu_slots &&
           requirement->overhead_memory_bytes ==
               reservation->overhead_memory_bytes;
}

int wvm_resource_reservation_validate(
    const struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    if (!reservation ||
        bytes_are_zero(reservation->reservation_id,
                       sizeof(reservation->reservation_id)) ||
        bytes_are_zero(reservation->plan_digest, sizeof(reservation->plan_digest)) ||
        bytes_are_zero(reservation->candidate_manifest_digest,
                       sizeof(reservation->candidate_manifest_digest)) ||
        bytes_are_zero(reservation->admission_tx_id,
                       sizeof(reservation->admission_tx_id)) ||
        bytes_are_zero(reservation->eligibility_fence_digest,
                       sizeof(reservation->eligibility_fence_digest)) ||
        reservation->vm_id == 0 || reservation->vm_incarnation == 0 ||
        reservation->physical_node_id == 0 ||
        reservation->node_instance_id == 0 || reservation->inventory_revision == 0 ||
        reservation->guest_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        reservation->overhead_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        reservation->state < WVM_RESERVATION_PREPARED ||
        reservation->state > WVM_RESERVATION_RELEASED ||
        lifecycle_exclusive_lease_list_validate(&reservation->exclusive_leases,
                                                error, error_len) != 0 ||
        (reservation->state == WVM_RESERVATION_PREPARED &&
         (!reservation->has_prepared_expiry ||
          reservation->prepared_expiry_unix_time_ms == 0 ||
          reservation->has_activation_fence)) ||
        (reservation->state == WVM_RESERVATION_COMMITTED &&
         (!reservation->has_activation_fence ||
          bytes_are_zero(reservation->activation_fence,
                         sizeof(reservation->activation_fence)))) ||
        (reservation->has_activation_fence &&
         bytes_are_zero(reservation->activation_fence,
                        sizeof(reservation->activation_fence)))) {
        set_error(error, error_len, "resource reservation is invalid");
        return -1;
    }
    return 0;
}

int wvm_resource_reservation_derive(
    const struct wvm_reservation_requirement *requirement,
    const struct wvm_candidate_vm_manifest *candidate,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    struct wvm_resource_reservation *reservation, uint64_t prepared_expiry_ms,
    char *error, size_t error_len)
{
    if (!requirement || !candidate || !reservation || prepared_expiry_ms == 0 ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        bytes_are_zero(candidate_manifest_digest, WVM_SHA256_DIGEST_BYTES) ||
        memcmp(candidate->manifest_digest, candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        !find_requirement(candidate, requirement->physical_node_id) ||
        !reservation_requirement_equal(
            requirement,
            find_requirement(candidate, requirement->physical_node_id))) {
        set_error(error, error_len, "cannot derive resource reservation");
        return -1;
    }
    memset(reservation, 0, sizeof(*reservation));
    memcpy(reservation->reservation_id, requirement->reservation_id,
           sizeof(reservation->reservation_id));
    memcpy(reservation->plan_digest, candidate->plan_digest,
           sizeof(reservation->plan_digest));
    memcpy(reservation->candidate_manifest_digest, candidate_manifest_digest,
           sizeof(reservation->candidate_manifest_digest));
    memcpy(reservation->admission_tx_id, candidate->admission_tx_id,
           sizeof(reservation->admission_tx_id));
    memcpy(reservation->eligibility_fence_digest,
           candidate->eligibility_fence_digest,
           sizeof(reservation->eligibility_fence_digest));
    reservation->vm_id = candidate->vm_id;
    reservation->vm_incarnation = candidate->vm_incarnation;
    reservation->physical_node_id = requirement->physical_node_id;
    reservation->node_instance_id = requirement->node_instance_id;
    reservation->inventory_revision = requirement->inventory_revision;
    reservation->guest_vcpu_slots = requirement->guest_vcpu_slots;
    reservation->guest_memory_bytes = requirement->guest_memory_bytes;
    reservation->overhead_vcpu_slots = requirement->overhead_vcpu_slots;
    reservation->overhead_memory_bytes = requirement->overhead_memory_bytes;
    reservation->exclusive_leases = requirement->exclusive_leases;
    reservation->state = WVM_RESERVATION_PREPARED;
    reservation->has_prepared_expiry = 1;
    reservation->prepared_expiry_unix_time_ms = prepared_expiry_ms;
    return wvm_resource_reservation_validate(reservation, error, error_len);
}

int wvm_activation_record_validate(const struct wvm_activation_record *activation,
                                   char *error, size_t error_len)
{
    size_t i;

    if (!activation ||
        bytes_are_zero(activation->admission_tx_id,
                       sizeof(activation->admission_tx_id)) ||
        bytes_are_zero(activation->candidate_manifest_digest,
                       sizeof(activation->candidate_manifest_digest)) ||
        activation->coordinator_instance_id == 0 ||
        bytes_are_zero(activation->required_participant_set_digest,
                       sizeof(activation->required_participant_set_digest)) ||
        !activation->required_route_snapshot_keys ||
        activation->required_route_snapshot_count == 0 ||
        activation->required_route_snapshot_count >
            activation->required_route_snapshot_capacity ||
        activation->decision < WVM_ACTIVATION_ACTIVATE ||
        activation->decision > WVM_ACTIVATION_ABORT ||
        activation->durable_decision_sequence == 0 || activation->decided_at == 0 ||
        ((activation->decision == WVM_ACTIVATION_ACTIVATE) !=
         activation->has_activation_fence) ||
        (activation->has_activation_fence &&
         bytes_are_zero(activation->activation_fence,
                        sizeof(activation->activation_fence)))) {
        set_error(error, error_len, "activation record is invalid");
        return -1;
    }
    for (i = 0; i < activation->required_route_snapshot_count; i++) {
        if (wvm_route_snapshot_key_validate(
                &activation->required_route_snapshot_keys[i], error,
                error_len) != 0 ||
            (i != 0 &&
             route_snapshot_key_compare(
                 &activation->required_route_snapshot_keys[i - 1],
                 &activation->required_route_snapshot_keys[i]) >= 0)) {
            set_error(error, error_len,
                      "activation record route snapshot set is invalid");
            return -1;
        }
    }
    return 0;
}

int wvm_activation_record_decide(
    struct wvm_activation_record *activation,
    const struct wvm_candidate_vm_manifest *candidate,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    const uint8_t activation_fence[WVM_IDENTITY_ID_BYTES],
    uint64_t coordinator_instance_id,
    const uint8_t required_participant_set_digest[WVM_SHA256_DIGEST_BYTES],
    struct wvm_route_snapshot_key *required_route_snapshot_keys,
    size_t required_route_snapshot_count, size_t required_route_snapshot_capacity,
    enum wvm_activation_decision decision, uint64_t durable_decision_sequence,
    uint64_t decided_at, char *error, size_t error_len)
{
    if (!activation || !candidate ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        bytes_are_zero(candidate_manifest_digest, WVM_SHA256_DIGEST_BYTES) ||
        !required_route_snapshot_keys || required_route_snapshot_count == 0 ||
        required_route_snapshot_count > required_route_snapshot_capacity ||
        !required_participant_set_digest ||
        (decision == WVM_ACTIVATION_ACTIVATE &&
         (!activation_fence ||
          bytes_are_zero(activation_fence, WVM_IDENTITY_ID_BYTES))) ||
        (decision == WVM_ACTIVATION_ABORT && activation_fence != NULL)) {
        set_error(error, error_len, "cannot decide activation");
        return -1;
    }
    memset(activation, 0, sizeof(*activation));
    memcpy(activation->admission_tx_id, candidate->admission_tx_id,
           sizeof(activation->admission_tx_id));
    memcpy(activation->candidate_manifest_digest, candidate_manifest_digest,
           sizeof(activation->candidate_manifest_digest));
    activation->has_activation_fence = decision == WVM_ACTIVATION_ACTIVATE;
    if (activation->has_activation_fence) {
        memcpy(activation->activation_fence, activation_fence,
               sizeof(activation->activation_fence));
    }
    activation->coordinator_instance_id = coordinator_instance_id;
    memcpy(activation->required_participant_set_digest,
           required_participant_set_digest,
           sizeof(activation->required_participant_set_digest));
    activation->required_route_snapshot_keys = required_route_snapshot_keys;
    activation->required_route_snapshot_count = required_route_snapshot_count;
    activation->required_route_snapshot_capacity = required_route_snapshot_capacity;
    activation->decision = decision;
    activation->durable_decision_sequence = durable_decision_sequence;
    activation->decided_at = decided_at;
    return wvm_activation_record_validate(activation, error, error_len);
}

int wvm_resource_reservation_commit(
    struct wvm_resource_reservation *reservation,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    if (!reservation || wvm_resource_reservation_validate(reservation, error,
                                                           error_len) != 0 ||
        reservation->state != WVM_RESERVATION_PREPARED ||
        wvm_activation_record_validate(activation, error, error_len) != 0 ||
        activation->decision != WVM_ACTIVATION_ACTIVATE ||
        memcmp(reservation->admission_tx_id, activation->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(reservation->candidate_manifest_digest,
               activation->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        set_error(error, error_len, "reservation cannot commit");
        return -1;
    }
    reservation->state = WVM_RESERVATION_COMMITTED;
    reservation->has_prepared_expiry = 0;
    reservation->prepared_expiry_unix_time_ms = 0;
    reservation->has_activation_fence = 1;
    memcpy(reservation->activation_fence, activation->activation_fence,
           sizeof(reservation->activation_fence));
    return wvm_resource_reservation_validate(reservation, error, error_len);
}

int wvm_resource_reservation_release(
    struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    if (!reservation || wvm_resource_reservation_validate(reservation, error,
                                                           error_len) != 0 ||
        reservation->state != WVM_RESERVATION_RELEASING) {
        set_error(error, error_len, "reservation cannot be released");
        return -1;
    }
    reservation->state = WVM_RESERVATION_RELEASED;
    reservation->has_prepared_expiry = 0;
    reservation->prepared_expiry_unix_time_ms = 0;
    return wvm_resource_reservation_validate(reservation, error, error_len);
}

int wvm_resource_reservation_begin_release(
    struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    if (!reservation || wvm_resource_reservation_validate(reservation, error,
                                                           error_len) != 0 ||
        (reservation->state != WVM_RESERVATION_PREPARED &&
         reservation->state != WVM_RESERVATION_COMMITTED)) {
        set_error(error, error_len, "reservation cannot begin release");
        return -1;
    }
    reservation->state = WVM_RESERVATION_RELEASING;
    reservation->has_prepared_expiry = 0;
    reservation->prepared_expiry_unix_time_ms = 0;
    return wvm_resource_reservation_validate(reservation, error, error_len);
}

int wvm_node_runtime_manifest_validate(
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    if (!runtime_manifest ||
        bytes_are_zero(runtime_manifest->candidate_manifest_digest,
                       sizeof(runtime_manifest->candidate_manifest_digest)) ||
        runtime_manifest->vm_id == 0 || runtime_manifest->vm_incarnation == 0 ||
        runtime_manifest->manifest_generation == 0 ||
        bytes_are_zero(runtime_manifest->admission_tx_id,
                       sizeof(runtime_manifest->admission_tx_id)) ||
        bytes_are_zero(runtime_manifest->eligibility_fence_digest,
                       sizeof(runtime_manifest->eligibility_fence_digest)) ||
        runtime_manifest->physical_node_id == 0 ||
        runtime_manifest->expected_node_instance_id == 0 ||
        runtime_manifest->local_role_bits == 0 ||
        wvm_route_snapshot_key_validate(
            &runtime_manifest->required_route_snapshot_key, error,
            error_len) != 0 ||
        wvm_local_name_namespace_validate(&runtime_manifest->local_names, error,
                                          error_len) != 0 ||
        wvm_execution_fault_profile_validate(
            &runtime_manifest->negotiated_profile, error, error_len) != 0 ||
        bytes_are_zero(runtime_manifest->reservation_id,
                       sizeof(runtime_manifest->reservation_id)) ||
        wvm_node_runtime_launch_plan_validate(&runtime_manifest->launch_plan,
                                              error, error_len) != 0 ||
        lifecycle_vcpu_assignment_list_validate(
            &runtime_manifest->local_vcpu_assignments,
            runtime_manifest->physical_node_id, runtime_manifest->reservation_id,
            error, error_len) != 0 ||
        lifecycle_memory_assignment_list_validate(
            &runtime_manifest->local_memory_assignments,
            runtime_manifest->physical_node_id, runtime_manifest->reservation_id,
            error, error_len) != 0 ||
        lifecycle_storage_assignment_list_validate(
            &runtime_manifest->local_storage_assignments,
            runtime_manifest->physical_node_id, runtime_manifest->reservation_id,
            error, error_len) != 0 ||
        lifecycle_startup_dependency_list_validate(
            &runtime_manifest->startup_dependencies, error, error_len) != 0 ||
        (runtime_manifest->has_activation_fence &&
         bytes_are_zero(runtime_manifest->activation_fence,
                        sizeof(runtime_manifest->activation_fence)))) {
        set_error(error, error_len, "node runtime manifest is invalid");
        return -1;
    }
    return 0;
}

static int machine_config_equal(const struct wvm_machine_config *left,
                                const struct wvm_machine_config *right)
{
    return left && right && strcmp(left->architecture, right->architecture) == 0 &&
           strcmp(left->machine_type, right->machine_type) == 0 &&
           left->qemu_compat_version == right->qemu_compat_version &&
           left->firmware_policy == right->firmware_policy;
}

static int consistency_policy_equal(const struct wvm_consistency_policy *left,
                                    const struct wvm_consistency_policy *right)
{
    return left && right &&
           left->dirty_batch_size == right->dirty_batch_size &&
           left->handoff_commit_policy == right->handoff_commit_policy &&
           left->subscriber_delivery_policy == right->subscriber_delivery_policy &&
           left->max_commit_latency_ms == right->max_commit_latency_ms;
}

static int candidate_total_memory_bytes(
    const struct wvm_candidate_vm_manifest *candidate, uint64_t *total_out)
{
    uint64_t total = 0;
    size_t i;

    if (!candidate || !total_out) {
        return -1;
    }
    for (i = 0; i < candidate->memory_placements.count; i++) {
        const uint64_t bytes = candidate->memory_placements.entries[i].bytes;

        if (bytes == 0 || bytes > UINT64_MAX - total) {
            return -1;
        }
        total += bytes;
    }
    *total_out = total;
    return 0;
}

int wvm_node_runtime_launch_plan_validate(
    const struct wvm_node_runtime_launch_plan *launch_plan, char *error,
    size_t error_len)
{
    if (!launch_plan ||
        launch_plan->plan_version != WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION ||
        launch_plan->node_runtime_data_port == 0 ||
        launch_plan->node_runtime_control_port == 0 ||
        launch_plan->local_executor_service_port == 0 ||
        launch_plan->local_executor_control_port == 0 ||
        launch_plan->node_runtime_data_port ==
            launch_plan->local_executor_service_port ||
        launch_plan->executor_worker_count == 0 ||
        launch_plan->vcpu_handoff_record_capacity == 0 ||
        launch_plan->sync_batch_size == 0 ||
        launch_plan->guest_total_memory_bytes == 0 ||
        launch_plan->guest_total_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        wvm_machine_config_validate(&launch_plan->guest_machine, error,
                                    error_len) != 0 ||
        wvm_consistency_policy_validate(&launch_plan->consistency_policy, error,
                                        error_len) != 0) {
        set_error(error, error_len, "node runtime launch plan is invalid");
        return -1;
    }
    return 0;
}

int wvm_node_runtime_launch_plan_encode(
    const struct wvm_node_runtime_launch_plan *launch_plan, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t machine_bytes[256];
    uint8_t consistency_bytes[128];
    uint8_t *field_value;
    size_t machine_encoded_bytes;
    size_t consistency_encoded_bytes;

    if (wvm_node_runtime_launch_plan_validate(launch_plan, error, error_len) !=
            0 ||
        wvm_machine_config_encode(&launch_plan->guest_machine, machine_bytes,
                                  sizeof(machine_bytes), &machine_encoded_bytes,
                                  error, error_len) != 0 ||
        wvm_consistency_policy_encode(
            &launch_plan->consistency_policy, consistency_bytes,
            sizeof(consistency_bytes), &consistency_encoded_bytes, error,
            error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_NODE_RUNTIME_LAUNCH_PLAN) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1,
                                       launch_plan->plan_version) != 0 ||
        wvm_canonical_field_append_u16(&builder, 2,
                                       launch_plan->node_runtime_data_port) !=
            0 ||
        wvm_canonical_field_append_u16(
            &builder, 3, launch_plan->node_runtime_control_port) != 0 ||
        wvm_canonical_field_append_u16(
            &builder, 4, launch_plan->local_executor_service_port) != 0 ||
        wvm_canonical_field_append_u16(
            &builder, 5, launch_plan->local_executor_control_port) != 0 ||
        wvm_canonical_field_append_u32(
            &builder, 6, launch_plan->executor_worker_count) != 0 ||
        wvm_canonical_field_append_u32(&builder, 7,
                                       launch_plan->sync_batch_size) != 0 ||
        wvm_canonical_field_append_u64(
            &builder, 8, launch_plan->guest_total_memory_bytes) != 0 ||
        wvm_canonical_field_reserve(&builder, 9,
                                    (uint32_t)machine_encoded_bytes,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode node runtime launch plan");
        return -1;
    }
    memcpy(field_value, machine_bytes, machine_encoded_bytes);
    if (wvm_canonical_field_reserve(&builder, 10,
                                    (uint32_t)consistency_encoded_bytes,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode node runtime launch plan");
        return -1;
    }
    memcpy(field_value, consistency_bytes, consistency_encoded_bytes);
    if (wvm_canonical_field_append_u32(
            &builder, 11, launch_plan->vcpu_handoff_record_capacity) != 0) {
        set_error(error, error_len, "cannot encode node runtime launch plan");
        return -1;
    }
    if (wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot finish node runtime launch plan");
        return -1;
    }
    return 0;
}

int wvm_node_runtime_launch_plan_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_node_runtime_launch_plan *launch_plan, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[12];
    unsigned char present[12];
    size_t i;

    if (!launch_plan ||
        lifecycle_parse_record_fields(
            bytes, encoded_bytes, WVM_RECORD_NODE_RUNTIME_LAUNCH_PLAN, fields,
            present, sizeof(present), error, error_len) != 0) {
        return -1;
    }
    for (i = 1; i <= 11; i++) {
        if (!present[i]) {
            set_error(error, error_len,
                      "node runtime launch plan misses field %zu", i);
            return -1;
        }
    }
    if (fields[1].value_bytes != 2 || fields[2].value_bytes != 2 ||
        fields[3].value_bytes != 2 || fields[4].value_bytes != 2 ||
        fields[5].value_bytes != 2 || fields[6].value_bytes != 4 ||
        fields[7].value_bytes != 4 || fields[8].value_bytes != 8 ||
        fields[11].value_bytes != 4) {
        set_error(error, error_len,
                  "node runtime launch plan has invalid fields");
        return -1;
    }
    memset(launch_plan, 0, sizeof(*launch_plan));
    launch_plan->plan_version = lifecycle_read_be16(fields[1].value);
    launch_plan->node_runtime_data_port =
        lifecycle_read_be16(fields[2].value);
    launch_plan->node_runtime_control_port =
        lifecycle_read_be16(fields[3].value);
    launch_plan->local_executor_service_port =
        lifecycle_read_be16(fields[4].value);
    launch_plan->local_executor_control_port =
        lifecycle_read_be16(fields[5].value);
    launch_plan->executor_worker_count = lifecycle_read_be32(fields[6].value);
    launch_plan->sync_batch_size = lifecycle_read_be32(fields[7].value);
    launch_plan->guest_total_memory_bytes =
        lifecycle_read_be64(fields[8].value);
    launch_plan->vcpu_handoff_record_capacity =
        lifecycle_read_be32(fields[11].value);
    if (wvm_machine_config_decode(fields[9].value, fields[9].value_bytes,
                                  &launch_plan->guest_machine, error,
                                  error_len) != 0 ||
        wvm_consistency_policy_decode(
            fields[10].value, fields[10].value_bytes,
            &launch_plan->consistency_policy, error, error_len) != 0) {
        return -1;
    }
    return wvm_node_runtime_launch_plan_validate(launch_plan, error,
                                                 error_len);
}

int wvm_node_runtime_manifest_project(
    const struct wvm_candidate_vm_manifest *candidate,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    const struct wvm_resource_reservation *reservation,
    const struct wvm_activation_record *activation,
    const struct wvm_node_runtime_launch_plan *launch_plan,
    uint64_t local_role_bits,
    struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    const struct wvm_reservation_requirement *requirement;
    struct wvm_local_name_identity local_identity;
    struct wvm_vcpu_assignment_list vcpus;
    struct wvm_memory_chunk_assignment_list memory;
    struct wvm_storage_assignment_list storage;
    struct wvm_startup_dependency_list dependencies;
    struct wvm_node_runtime_launch_plan retained_launch_plan;
    uint64_t total_memory_bytes;
    size_t i;

    if (!candidate || !reservation || !runtime_manifest ||
        local_role_bits == 0 ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        wvm_resource_reservation_validate(reservation, error, error_len) != 0 ||
        bytes_are_zero(candidate_manifest_digest, WVM_SHA256_DIGEST_BYTES) ||
        memcmp(reservation->candidate_manifest_digest, candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        memcmp(reservation->plan_digest, candidate->plan_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        memcmp(reservation->admission_tx_id, candidate->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        reservation->vm_id != candidate->vm_id ||
        reservation->vm_incarnation != candidate->vm_incarnation ||
        !(requirement = find_requirement(candidate,
                                         reservation->physical_node_id)) ||
        !requirement_equal_reservation(requirement, reservation)) {
        set_error(error, error_len, "cannot project node runtime manifest");
        return -1;
    }
    if (activation &&
        (wvm_activation_record_validate(activation, error, error_len) != 0 ||
         memcmp(activation->admission_tx_id, candidate->admission_tx_id,
                WVM_IDENTITY_ID_BYTES) != 0 ||
         memcmp(activation->candidate_manifest_digest, candidate_manifest_digest,
                WVM_SHA256_DIGEST_BYTES) != 0)) {
        return -1;
    }
    retained_launch_plan =
        launch_plan ? *launch_plan : runtime_manifest->launch_plan;
    if (wvm_node_runtime_launch_plan_validate(&retained_launch_plan, error,
                                              error_len) != 0 ||
        !machine_config_equal(&retained_launch_plan.guest_machine,
                              &candidate->guest_machine) ||
        !consistency_policy_equal(&retained_launch_plan.consistency_policy,
                                  &candidate->consistency_policy) ||
        candidate_total_memory_bytes(candidate, &total_memory_bytes) != 0 ||
        retained_launch_plan.guest_total_memory_bytes != total_memory_bytes) {
        set_error(error, error_len,
                  "runtime launch plan does not match candidate manifest");
        return -1;
    }

    vcpus = runtime_manifest->local_vcpu_assignments;
    memory = runtime_manifest->local_memory_assignments;
    storage = runtime_manifest->local_storage_assignments;
    dependencies = runtime_manifest->startup_dependencies;
    if ((candidate->vcpu_placements.count > vcpus.capacity) ||
        (candidate->memory_placements.count > memory.capacity) ||
        (candidate->storage_device_plan.assignments.count > storage.capacity)) {
        set_error(error, error_len, "node runtime projection buffers are small");
        return -1;
    }
    memset(runtime_manifest, 0, sizeof(*runtime_manifest));
    runtime_manifest->local_vcpu_assignments = vcpus;
    runtime_manifest->local_memory_assignments = memory;
    runtime_manifest->local_storage_assignments = storage;
    runtime_manifest->startup_dependencies = dependencies;
    runtime_manifest->launch_plan = retained_launch_plan;
    runtime_manifest->local_vcpu_assignments.count = 0;
    runtime_manifest->local_memory_assignments.count = 0;
    runtime_manifest->local_storage_assignments.count = 0;
    runtime_manifest->startup_dependencies.count = 0;
    memcpy(runtime_manifest->candidate_manifest_digest, candidate_manifest_digest,
           sizeof(runtime_manifest->candidate_manifest_digest));
    runtime_manifest->vm_id = candidate->vm_id;
    runtime_manifest->vm_incarnation = candidate->vm_incarnation;
    runtime_manifest->manifest_generation = candidate->manifest_generation;
    memcpy(runtime_manifest->admission_tx_id, candidate->admission_tx_id,
           sizeof(runtime_manifest->admission_tx_id));
    memcpy(runtime_manifest->eligibility_fence_digest,
           candidate->eligibility_fence_digest,
           sizeof(runtime_manifest->eligibility_fence_digest));
    runtime_manifest->physical_node_id = reservation->physical_node_id;
    runtime_manifest->expected_node_instance_id = reservation->node_instance_id;
    runtime_manifest->local_role_bits = local_role_bits;
    runtime_manifest->required_route_snapshot_key =
        candidate->prepared_route_snapshot_key;
    runtime_manifest->negotiated_profile = candidate->execution_plan;
    memcpy(runtime_manifest->reservation_id, reservation->reservation_id,
           sizeof(runtime_manifest->reservation_id));

    memset(&local_identity, 0, sizeof(local_identity));
    local_identity.vm_id = candidate->vm_id;
    local_identity.vm_incarnation = candidate->vm_incarnation;
    local_identity.manifest_generation = candidate->manifest_generation;
    local_identity.physical_node_id = reservation->physical_node_id;
    memcpy(local_identity.manifest_id, candidate->manifest_id,
           sizeof(local_identity.manifest_id));
    memcpy(local_identity.admission_tx_id, candidate->admission_tx_id,
           sizeof(local_identity.admission_tx_id));
    if (wvm_local_name_namespace_derive(&local_identity,
                                        &runtime_manifest->local_names, error,
                                        error_len) != 0) {
        return -1;
    }
    if (activation && activation->decision == WVM_ACTIVATION_ACTIVATE) {
        runtime_manifest->has_activation_fence = 1;
        memcpy(runtime_manifest->activation_fence, activation->activation_fence,
               sizeof(runtime_manifest->activation_fence));
    }
    for (i = 0; i < candidate->vcpu_placements.count; i++) {
        if (candidate->vcpu_placements.entries[i].executor_physical_node_id ==
            reservation->physical_node_id) {
            if (!runtime_manifest->local_vcpu_assignments.entries) {
                return -1;
            }
            runtime_manifest->local_vcpu_assignments
                .entries[runtime_manifest->local_vcpu_assignments.count++] =
                candidate->vcpu_placements.entries[i];
        }
    }
    for (i = 0; i < candidate->memory_placements.count; i++) {
        if (candidate->memory_placements.entries[i].directory_physical_node_id ==
                reservation->physical_node_id ||
            candidate->memory_placements.entries[i].executor_physical_node_id ==
                reservation->physical_node_id) {
            if (!runtime_manifest->local_memory_assignments.entries) {
                return -1;
            }
            runtime_manifest->local_memory_assignments
                .entries[runtime_manifest->local_memory_assignments.count++] =
                candidate->memory_placements.entries[i];
        }
    }
    for (i = 0; i < candidate->storage_device_plan.assignments.count; i++) {
        if (candidate->storage_device_plan.assignments.entries[i]
                .storage_physical_node_id == reservation->physical_node_id) {
            if (!runtime_manifest->local_storage_assignments.entries) {
                return -1;
            }
            runtime_manifest->local_storage_assignments
                .entries[runtime_manifest->local_storage_assignments.count++] =
                candidate->storage_device_plan.assignments.entries[i];
        }
    }
    return wvm_node_runtime_manifest_validate(runtime_manifest, error, error_len);
}

int wvm_lifecycle_transaction_init(
    struct wvm_lifecycle_transaction *transaction,
    const struct wvm_candidate_vm_manifest *candidate,
    const uint8_t candidate_manifest_digest[WVM_SHA256_DIGEST_BYTES],
    char *error, size_t error_len)
{
    if (!transaction ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        bytes_are_zero(candidate_manifest_digest, WVM_SHA256_DIGEST_BYTES)) {
        set_error(error, error_len, "cannot initialize lifecycle transaction");
        return -1;
    }
    memset(transaction, 0, sizeof(*transaction));
    transaction->vm_id = candidate->vm_id;
    transaction->vm_incarnation = candidate->vm_incarnation;
    memcpy(transaction->admission_tx_id, candidate->admission_tx_id,
           sizeof(transaction->admission_tx_id));
    memcpy(transaction->candidate_manifest_digest, candidate_manifest_digest,
           sizeof(transaction->candidate_manifest_digest));
    transaction->state = WVM_LIFECYCLE_PLANNED;
    return 0;
}

int wvm_lifecycle_transition(struct wvm_lifecycle_transaction *transaction,
                             enum wvm_lifecycle_state expected,
                             enum wvm_lifecycle_state next, char *error,
                             size_t error_len)
{
    int allowed = 0;

    if (!transaction || transaction->state != expected ||
        expected < WVM_LIFECYCLE_ABSENT ||
        expected > WVM_LIFECYCLE_FAILED ||
        next < WVM_LIFECYCLE_ABSENT || next > WVM_LIFECYCLE_FAILED) {
        set_error(error, error_len, "lifecycle transition is invalid");
        return -1;
    }
    switch (expected) {
    case WVM_LIFECYCLE_ABSENT:
        allowed = next == WVM_LIFECYCLE_REQUESTED;
        break;
    case WVM_LIFECYCLE_REQUESTED:
        allowed = next == WVM_LIFECYCLE_VALIDATING ||
                  next == WVM_LIFECYCLE_ABORTING;
        break;
    case WVM_LIFECYCLE_VALIDATING:
        allowed = next == WVM_LIFECYCLE_IDENTITY_ALLOCATED ||
                  next == WVM_LIFECYCLE_ABORTING;
        break;
    case WVM_LIFECYCLE_IDENTITY_ALLOCATED:
        allowed = next == WVM_LIFECYCLE_PLANNED ||
                  next == WVM_LIFECYCLE_ABORTING;
        break;
    case WVM_LIFECYCLE_PLANNED:
        allowed = next == WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED ||
                  next == WVM_LIFECYCLE_ABORTING;
        break;
    case WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED:
        allowed = next == WVM_LIFECYCLE_RESERVATIONS_PREPARED ||
                  next == WVM_LIFECYCLE_ABORTING;
        break;
    case WVM_LIFECYCLE_RESERVATIONS_PREPARED:
        allowed = next == WVM_LIFECYCLE_PARTICIPANTS_PREPARED ||
                  next == WVM_LIFECYCLE_ABORTING;
        break;
    case WVM_LIFECYCLE_PARTICIPANTS_PREPARED:
        allowed = next == WVM_LIFECYCLE_ACTIVATION_DECIDED ||
                  next == WVM_LIFECYCLE_ABORTING;
        break;
    case WVM_LIFECYCLE_ACTIVATION_DECIDED:
        allowed = next == WVM_LIFECYCLE_COMMITTED ||
                  next == WVM_LIFECYCLE_STOPPING;
        break;
    case WVM_LIFECYCLE_COMMITTED:
        allowed = next == WVM_LIFECYCLE_STARTING ||
                  next == WVM_LIFECYCLE_STOPPING;
        break;
    case WVM_LIFECYCLE_STARTING:
        allowed = next == WVM_LIFECYCLE_RUNNING ||
                  next == WVM_LIFECYCLE_STOPPING ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_RUNNING:
        allowed = next == WVM_LIFECYCLE_PAUSING ||
                  next == WVM_LIFECYCLE_STOPPING ||
                  next == WVM_LIFECYCLE_DEGRADED ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_PAUSING:
        allowed = next == WVM_LIFECYCLE_PAUSED ||
                  next == WVM_LIFECYCLE_STOPPING ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_PAUSED:
        allowed = next == WVM_LIFECYCLE_RUNNING ||
                  next == WVM_LIFECYCLE_STOPPING ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_DEGRADED:
        allowed = next == WVM_LIFECYCLE_PAUSING ||
                  next == WVM_LIFECYCLE_STOPPING ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_STOPPING:
        allowed = next == WVM_LIFECYCLE_RETIRING ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_RETIRING:
        allowed = next == WVM_LIFECYCLE_STOPPED ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_STOPPED:
    case WVM_LIFECYCLE_ABORTED:
        allowed = next == WVM_LIFECYCLE_ABSENT;
        break;
    case WVM_LIFECYCLE_ABORTING:
        allowed = next == WVM_LIFECYCLE_ABORTED ||
                  next == WVM_LIFECYCLE_FAILED;
        break;
    case WVM_LIFECYCLE_FAILED:
        allowed = next == WVM_LIFECYCLE_STOPPING ||
                  next == WVM_LIFECYCLE_RETIRING ||
                  next == WVM_LIFECYCLE_STOPPED;
        break;
    }
    if (!allowed) {
        set_error(error, error_len, "lifecycle transition is not allowed");
        return -1;
    }
    transaction->state = next;
    return 0;
}

typedef int (*lifecycle_record_size_fn)(const void *entry,
                                        size_t *encoded_size);
typedef int (*lifecycle_record_encode_fn)(const void *entry, uint8_t *bytes,
                                          size_t capacity,
                                          size_t *encoded_bytes, char *error,
                                          size_t error_len);
typedef int (*lifecycle_record_decode_fn)(const uint8_t *bytes,
                                          size_t encoded_bytes, void *entry,
                                          char *error, size_t error_len);

static uint16_t lifecycle_read_be16(const uint8_t *src)
{
    return ((uint16_t)src[0] << 8) | src[1];
}

static uint32_t lifecycle_read_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | src[3];
}

static uint64_t lifecycle_read_be64(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8) | src[7];
}

static void lifecycle_write_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static int lifecycle_checked_add_size(size_t *total, size_t value)
{
    if (!total || value > SIZE_MAX - *total) {
        return -1;
    }
    *total += value;
    return 0;
}

static int lifecycle_record_size(const size_t *value_sizes, size_t field_count,
                                 size_t *encoded_size)
{
    size_t total = WVM_CANONICAL_RECORD_HEADER_BYTES;
    size_t i;

    if (!value_sizes || !encoded_size) {
        return -1;
    }
    for (i = 0; i < field_count; i++) {
        if (lifecycle_checked_add_size(&total,
                                       WVM_CANONICAL_FIELD_HEADER_BYTES) != 0 ||
            lifecycle_checked_add_size(&total, value_sizes[i]) != 0) {
            return -1;
        }
    }
    *encoded_size = total;
    return 0;
}

static int lifecycle_parse_record_fields(
    const uint8_t *bytes, size_t encoded_bytes, uint16_t expected_record_type,
    struct wvm_canonical_field *fields, unsigned char *present,
    size_t field_capacity, char *error, size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    uint16_t previous_tag = 0;
    int next;

    if (!fields || !present || field_capacity < 2 ||
        wvm_canonical_record_parse(bytes, encoded_bytes, &record) != 0 ||
        record.record_type != expected_record_type) {
        set_error(error, error_len, "invalid canonical record type 0x%04x",
                  expected_record_type);
        return -1;
    }
    memset(present, 0, field_capacity);
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 0 || field.tag >= field_capacity || present[field.tag] ||
            field.tag <= previous_tag) {
            set_error(error, error_len, "record 0x%04x has invalid fields",
                      expected_record_type);
            return -1;
        }
        fields[field.tag] = field;
        present[field.tag] = 1;
        previous_tag = field.tag;
    }
    if (next < 0) {
        set_error(error, error_len, "record 0x%04x is malformed",
                  expected_record_type);
        return -1;
    }
    return 0;
}

static int lifecycle_record_list_size(const void *entries, size_t count,
                                      size_t entry_bytes,
                                      lifecycle_record_size_fn item_size,
                                      size_t *encoded_size)
{
    const uint8_t *base = entries;
    size_t total = 4;
    size_t i;

    if (!item_size || !encoded_size || (count != 0 && !entries) ||
        count > UINT32_MAX) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        size_t item_bytes;

        if (item_size(base + i * entry_bytes, &item_bytes) != 0 ||
            item_bytes > UINT32_MAX ||
            lifecycle_checked_add_size(&total, 4) != 0 ||
            lifecycle_checked_add_size(&total, item_bytes) != 0) {
            return -1;
        }
    }
    *encoded_size = total;
    return 0;
}

static int lifecycle_record_list_encode(
    const void *entries, size_t count, size_t entry_bytes,
    lifecycle_record_size_fn item_size, lifecycle_record_encode_fn item_encode,
    uint8_t *bytes, size_t encoded_bytes, char *error, size_t error_len)
{
    const uint8_t *base = entries;
    size_t expected_bytes;
    size_t offset = 4;
    size_t i;

    if (!bytes || !item_encode ||
        lifecycle_record_list_size(entries, count, entry_bytes, item_size,
                                   &expected_bytes) != 0 ||
        expected_bytes != encoded_bytes) {
        set_error(error, error_len, "canonical record list has invalid size");
        return -1;
    }
    lifecycle_write_be32(bytes, (uint32_t)count);
    for (i = 0; i < count; i++) {
        size_t item_bytes;
        size_t actual_bytes;

        if (item_size(base + i * entry_bytes, &item_bytes) != 0) {
            return -1;
        }
        lifecycle_write_be32(bytes + offset, (uint32_t)item_bytes);
        offset += 4;
        if (item_encode(base + i * entry_bytes, bytes + offset, item_bytes,
                        &actual_bytes, error, error_len) != 0 ||
            actual_bytes != item_bytes) {
            return -1;
        }
        offset += item_bytes;
    }
    return offset == encoded_bytes ? 0 : -1;
}

static int lifecycle_record_list_decode(
    const uint8_t *bytes, size_t encoded_bytes, void *entries, size_t capacity,
    size_t entry_bytes, size_t *count_out, lifecycle_record_decode_fn item_decode,
    char *error, size_t error_len)
{
    uint8_t *base = entries;
    uint32_t count;
    uint32_t i;
    size_t offset = 4;

    if (!bytes || !count_out || !item_decode || encoded_bytes < 4) {
        set_error(error, error_len, "canonical record list is malformed");
        return -1;
    }
    count = lifecycle_read_be32(bytes);
    if (count > capacity || (count != 0 && !entries)) {
        set_error(error, error_len, "canonical record list exceeds capacity");
        return -1;
    }
    for (i = 0; i < count; i++) {
        uint32_t item_bytes;

        if (encoded_bytes - offset < 4) {
            set_error(error, error_len, "canonical record list is truncated");
            return -1;
        }
        item_bytes = lifecycle_read_be32(bytes + offset);
        offset += 4;
        if (item_bytes == 0 || item_bytes > encoded_bytes - offset ||
            item_decode(bytes + offset, item_bytes, base + i * entry_bytes,
                        error, error_len) != 0) {
            set_error(error, error_len, "canonical record list has bad entry");
            return -1;
        }
        offset += item_bytes;
    }
    if (offset != encoded_bytes) {
        set_error(error, error_len, "canonical record list has trailing bytes");
        return -1;
    }
    *count_out = count;
    return 0;
}

static int lifecycle_member_key_compare(const struct wvm_member_key *left,
                                        const struct wvm_member_key *right)
{
    if (left->role_type != right->role_type) {
        return left->role_type < right->role_type ? -1 : 1;
    }
    if (left->role_id != right->role_id) {
        return left->role_id < right->role_id ? -1 : 1;
    }
    if (left->instance_id != right->instance_id) {
        return left->instance_id < right->instance_id ? -1 : 1;
    }
    return 0;
}

static int lifecycle_exclusive_lease_compare(
    const struct wvm_exclusive_lease *left,
    const struct wvm_exclusive_lease *right)
{
    int comparison;

    if (left->lease_kind != right->lease_kind) {
        return left->lease_kind < right->lease_kind ? -1 : 1;
    }
    comparison = strcmp(left->lease_name, right->lease_name);
    return comparison;
}

static int lifecycle_exclusive_lease_list_validate(
    const struct wvm_exclusive_lease_list *leases, char *error,
    size_t error_len)
{
    size_t i;

    if (!leases || (leases->count != 0 && !leases->entries) ||
        leases->count > leases->capacity) {
        set_error(error, error_len, "exclusive lease list is invalid");
        return -1;
    }
    for (i = 0; i < leases->count; i++) {
        if (wvm_exclusive_lease_validate(&leases->entries[i], error,
                                         error_len) != 0 ||
            (i != 0 &&
             lifecycle_exclusive_lease_compare(&leases->entries[i - 1],
                                                &leases->entries[i]) >= 0)) {
            set_error(error, error_len,
                      "exclusive lease list is not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int lifecycle_member_key_size(const void *entry, size_t *encoded_size)
{
    const struct wvm_member_key *member_key = entry;

    if (wvm_member_key_validate(member_key, NULL, 0) != 0) {
        return -1;
    }
    return lifecycle_record_size((const size_t[]){2, 4, 8}, 3, encoded_size);
}

static int lifecycle_route_snapshot_key_size(const void *entry,
                                             size_t *encoded_size)
{
    const struct wvm_route_snapshot_key *key = entry;
    size_t scope_bytes;

    if (wvm_route_snapshot_key_validate(key, NULL, 0) != 0 ||
        lifecycle_record_size((const size_t[]){4, 8, 8}, 3, &scope_bytes) !=
            0) {
        return -1;
    }
    return lifecycle_record_size(
        (const size_t[]){scope_bytes, 8, 8, WVM_SHA256_DIGEST_BYTES}, 4,
        encoded_size);
}

static int lifecycle_vcpu_assignment_size(const void *entry,
                                          size_t *encoded_size)
{
    if (wvm_vcpu_assignment_validate(entry, NULL, 0) != 0) {
        return -1;
    }
    return lifecycle_record_size((const size_t[]){4, 4, 2, 2, 4,
                                                  WVM_IDENTITY_ID_BYTES},
                                 6, encoded_size);
}

static int lifecycle_memory_assignment_size(const void *entry,
                                            size_t *encoded_size)
{
    if (wvm_memory_chunk_assignment_validate(entry, NULL, 0) != 0) {
        return -1;
    }
    return lifecycle_record_size((const size_t[]){8, 8, 4, 4, 2,
                                                  WVM_IDENTITY_ID_BYTES},
                                 6, encoded_size);
}

static int lifecycle_storage_assignment_size(const void *entry,
                                             size_t *encoded_size)
{
    if (wvm_storage_assignment_validate(entry, NULL, 0) != 0) {
        return -1;
    }
    return lifecycle_record_size((const size_t[]){4, 4, 2,
                                                  WVM_IDENTITY_ID_BYTES,
                                                  WVM_SHA256_DIGEST_BYTES},
                                 5, encoded_size);
}

static int lifecycle_exclusive_lease_size(const void *entry,
                                          size_t *encoded_size)
{
    const struct wvm_exclusive_lease *lease = entry;

    if (wvm_exclusive_lease_validate(lease, NULL, 0) != 0) {
        return -1;
    }
    return lifecycle_record_size(
        (const size_t[]){2, strlen(lease->lease_name), 8}, 3, encoded_size);
}

static int lifecycle_capability_ref_size(const struct wvm_capability_ref *ref,
                                         size_t *encoded_size)
{
    if (wvm_capability_ref_validate(ref, NULL, 0) != 0) {
        return -1;
    }
    return lifecycle_record_size((const size_t[]){4, 8, 8,
                                                  WVM_SHA256_DIGEST_BYTES},
                                 4, encoded_size);
}

static int lifecycle_execution_fault_profile_size(
    const struct wvm_execution_fault_profile *profile, size_t *encoded_size)
{
    size_t capabilities_bytes;
    size_t i;

    if (wvm_execution_fault_profile_validate(profile, NULL, 0) != 0 ||
        profile->per_node_capabilities.count > UINT32_MAX) {
        return -1;
    }
    capabilities_bytes = 4;
    for (i = 0; i < profile->per_node_capabilities.count; i++) {
        size_t capability_bytes;

        if (lifecycle_capability_ref_size(
                &profile->per_node_capabilities.entries[i],
                &capability_bytes) != 0 ||
            lifecycle_checked_add_size(&capabilities_bytes, 4) != 0 ||
            lifecycle_checked_add_size(&capabilities_bytes, capability_bytes) !=
                0) {
            return -1;
        }
    }
    return lifecycle_record_size(
        (const size_t[]){2, 4, 2, 2, 2, 8, capabilities_bytes,
                          WVM_SHA256_DIGEST_BYTES, 2},
        9, encoded_size);
}

static int lifecycle_route_snapshot_key_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_route_snapshot_key_encode(entry, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int lifecycle_vcpu_assignment_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_vcpu_assignment_encode(entry, bytes, capacity, encoded_bytes,
                                      error, error_len);
}

static int lifecycle_memory_assignment_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_memory_chunk_assignment_encode(entry, bytes, capacity,
                                              encoded_bytes, error, error_len);
}

static int lifecycle_storage_assignment_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_storage_assignment_encode(entry, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int lifecycle_exclusive_lease_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_exclusive_lease_encode(entry, bytes, capacity, encoded_bytes,
                                      error, error_len);
}

static int lifecycle_route_snapshot_key_decode_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return wvm_route_snapshot_key_decode(bytes, encoded_bytes, entry, error,
                                         error_len);
}

static int lifecycle_vcpu_assignment_decode_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return wvm_vcpu_assignment_decode(bytes, encoded_bytes, entry, error,
                                      error_len);
}

static int lifecycle_memory_assignment_decode_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return wvm_memory_chunk_assignment_decode(bytes, encoded_bytes, entry,
                                              error, error_len);
}

static int lifecycle_storage_assignment_decode_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return wvm_storage_assignment_decode(bytes, encoded_bytes, entry, error,
                                         error_len);
}

static int lifecycle_exclusive_lease_decode_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return wvm_exclusive_lease_decode(bytes, encoded_bytes, entry, error,
                                      error_len);
}

int wvm_resource_reservation_encode(
    const struct wvm_resource_reservation *reservation, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    size_t leases_bytes;

    if (wvm_resource_reservation_validate(reservation, error, error_len) != 0 ||
        lifecycle_exclusive_lease_list_validate(&reservation->exclusive_leases,
                                                error, error_len) != 0 ||
        lifecycle_record_list_size(reservation->exclusive_leases.entries,
                                   reservation->exclusive_leases.count,
                                   sizeof(*reservation->exclusive_leases.entries),
                                   lifecycle_exclusive_lease_size,
                                   &leases_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_RESOURCE_RESERVATION) != 0 ||
        wvm_canonical_field_append(&builder, 1, reservation->reservation_id,
                                   sizeof(reservation->reservation_id)) != 0 ||
        wvm_canonical_field_append(&builder, 2, reservation->plan_digest,
                                   sizeof(reservation->plan_digest)) != 0 ||
        wvm_canonical_field_append(&builder, 3,
                                   reservation->candidate_manifest_digest,
                                   sizeof(reservation->candidate_manifest_digest)) !=
            0 ||
        wvm_canonical_field_append(&builder, 4, reservation->admission_tx_id,
                                   sizeof(reservation->admission_tx_id)) != 0 ||
        wvm_canonical_field_append(&builder, 5,
                                   reservation->eligibility_fence_digest,
                                   sizeof(reservation->eligibility_fence_digest)) !=
            0 ||
        wvm_canonical_field_append_u32(&builder, 6, reservation->vm_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 7,
                                       reservation->vm_incarnation) != 0 ||
        wvm_canonical_field_append_u32(&builder, 8,
                                       reservation->physical_node_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 9,
                                       reservation->node_instance_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 10,
                                       reservation->inventory_revision) != 0 ||
        wvm_canonical_field_append_u32(&builder, 11,
                                       reservation->guest_vcpu_slots) != 0 ||
        wvm_canonical_field_append_u64(&builder, 12,
                                       reservation->guest_memory_bytes) != 0 ||
        wvm_canonical_field_append_u32(&builder, 13,
                                       reservation->overhead_vcpu_slots) != 0 ||
        wvm_canonical_field_append_u64(&builder, 14,
                                       reservation->overhead_memory_bytes) != 0 ||
        wvm_canonical_field_reserve(&builder, 15, (uint32_t)leases_bytes,
                                    &field_value) != 0 ||
        lifecycle_record_list_encode(
            reservation->exclusive_leases.entries,
            reservation->exclusive_leases.count,
            sizeof(*reservation->exclusive_leases.entries),
            lifecycle_exclusive_lease_size,
            lifecycle_exclusive_lease_encode_adapter, field_value, leases_bytes,
            error, error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 16, reservation->state) != 0 ||
        (reservation->has_prepared_expiry &&
         wvm_canonical_field_append_u64(
             &builder, 17, reservation->prepared_expiry_unix_time_ms) != 0) ||
        (reservation->has_activation_fence &&
         wvm_canonical_field_append(&builder, 18, reservation->activation_fence,
                                    sizeof(reservation->activation_fence)) != 0) ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode resource reservation");
        return -1;
    }
    return 0;
}

int wvm_resource_reservation_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[19];
    unsigned char present[19];
    struct wvm_exclusive_lease_list leases;
    size_t i;

    if (!reservation ||
        lifecycle_parse_record_fields(bytes, encoded_bytes,
                                      WVM_RECORD_RESOURCE_RESERVATION, fields,
                                      present, sizeof(present), error,
                                      error_len) != 0) {
        return -1;
    }
    for (i = 1; i <= 16; i++) {
        if (!present[i]) {
            set_error(error, error_len, "resource reservation misses field %zu",
                      i);
            return -1;
        }
    }
    if (fields[1].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[2].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[3].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[4].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[5].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[6].value_bytes != 4 || fields[7].value_bytes != 8 ||
        fields[8].value_bytes != 4 || fields[9].value_bytes != 8 ||
        fields[10].value_bytes != 8 || fields[11].value_bytes != 4 ||
        fields[12].value_bytes != 8 || fields[13].value_bytes != 4 ||
        fields[14].value_bytes != 8 || fields[16].value_bytes != 2 ||
        (present[17] && fields[17].value_bytes != 8) ||
        (present[18] && fields[18].value_bytes != WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len, "resource reservation has invalid fields");
        return -1;
    }

    leases = reservation->exclusive_leases;
    memset(reservation, 0, sizeof(*reservation));
    reservation->exclusive_leases = leases;
    memcpy(reservation->reservation_id, fields[1].value,
           sizeof(reservation->reservation_id));
    memcpy(reservation->plan_digest, fields[2].value,
           sizeof(reservation->plan_digest));
    memcpy(reservation->candidate_manifest_digest, fields[3].value,
           sizeof(reservation->candidate_manifest_digest));
    memcpy(reservation->admission_tx_id, fields[4].value,
           sizeof(reservation->admission_tx_id));
    memcpy(reservation->eligibility_fence_digest, fields[5].value,
           sizeof(reservation->eligibility_fence_digest));
    reservation->vm_id = lifecycle_read_be32(fields[6].value);
    reservation->vm_incarnation = lifecycle_read_be64(fields[7].value);
    reservation->physical_node_id = lifecycle_read_be32(fields[8].value);
    reservation->node_instance_id = lifecycle_read_be64(fields[9].value);
    reservation->inventory_revision = lifecycle_read_be64(fields[10].value);
    reservation->guest_vcpu_slots = lifecycle_read_be32(fields[11].value);
    reservation->guest_memory_bytes = lifecycle_read_be64(fields[12].value);
    reservation->overhead_vcpu_slots = lifecycle_read_be32(fields[13].value);
    reservation->overhead_memory_bytes = lifecycle_read_be64(fields[14].value);
    reservation->state =
        (enum wvm_reservation_state)lifecycle_read_be16(fields[16].value);
    reservation->has_prepared_expiry = present[17];
    if (reservation->has_prepared_expiry) {
        reservation->prepared_expiry_unix_time_ms =
            lifecycle_read_be64(fields[17].value);
    }
    reservation->has_activation_fence = present[18];
    if (reservation->has_activation_fence) {
        memcpy(reservation->activation_fence, fields[18].value,
               sizeof(reservation->activation_fence));
    }
    if (lifecycle_record_list_decode(
            fields[15].value, fields[15].value_bytes,
            reservation->exclusive_leases.entries,
            reservation->exclusive_leases.capacity,
            sizeof(*reservation->exclusive_leases.entries),
            &reservation->exclusive_leases.count,
            lifecycle_exclusive_lease_decode_adapter, error, error_len) != 0 ||
        lifecycle_exclusive_lease_list_validate(&reservation->exclusive_leases,
                                                error, error_len) != 0) {
        return -1;
    }
    return wvm_resource_reservation_validate(reservation, error, error_len);
}

static int lifecycle_route_snapshot_key_list_validate(
    const struct wvm_route_snapshot_key *keys, size_t count, size_t capacity,
    char *error, size_t error_len)
{
    size_t i;

    if ((count != 0 && !keys) || count > capacity) {
        set_error(error, error_len, "route snapshot key list is invalid");
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (wvm_route_snapshot_key_validate(&keys[i], error, error_len) != 0 ||
            (i != 0 &&
             route_snapshot_key_compare(&keys[i - 1], &keys[i]) >= 0)) {
            set_error(error, error_len,
                      "route snapshot key list is not strictly ordered");
            return -1;
        }
    }
    return 0;
}

int wvm_activation_record_encode(
    const struct wvm_activation_record *activation, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    size_t route_keys_bytes;

    if (wvm_activation_record_validate(activation, error, error_len) != 0 ||
        lifecycle_route_snapshot_key_list_validate(
            activation->required_route_snapshot_keys,
            activation->required_route_snapshot_count,
            activation->required_route_snapshot_capacity, error, error_len) !=
            0 ||
        lifecycle_record_list_size(
            activation->required_route_snapshot_keys,
            activation->required_route_snapshot_count,
            sizeof(*activation->required_route_snapshot_keys),
            lifecycle_route_snapshot_key_size, &route_keys_bytes) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ACTIVATION_RECORD) != 0 ||
        wvm_canonical_field_append(&builder, 1, activation->admission_tx_id,
                                   sizeof(activation->admission_tx_id)) != 0 ||
        wvm_canonical_field_append(
            &builder, 2, activation->candidate_manifest_digest,
            sizeof(activation->candidate_manifest_digest)) != 0 ||
        (activation->has_activation_fence &&
         wvm_canonical_field_append(&builder, 3, activation->activation_fence,
                                    sizeof(activation->activation_fence)) != 0) ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       activation->coordinator_instance_id) != 0 ||
        wvm_canonical_field_append(
            &builder, 5, activation->required_participant_set_digest,
            sizeof(activation->required_participant_set_digest)) != 0 ||
        wvm_canonical_field_reserve(&builder, 6, (uint32_t)route_keys_bytes,
                                    &field_value) != 0 ||
        lifecycle_record_list_encode(
            activation->required_route_snapshot_keys,
            activation->required_route_snapshot_count,
            sizeof(*activation->required_route_snapshot_keys),
            lifecycle_route_snapshot_key_size,
            lifecycle_route_snapshot_key_encode_adapter, field_value,
            route_keys_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append_u16(&builder, 7, activation->decision) != 0 ||
        wvm_canonical_field_append_u64(&builder, 8,
                                       activation->durable_decision_sequence) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 9, activation->decided_at) !=
            0 ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode activation record");
        return -1;
    }
    return 0;
}

int wvm_activation_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_activation_record *activation, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[10];
    unsigned char present[10];
    struct wvm_route_snapshot_key *route_keys;
    size_t route_key_capacity;
    size_t i;

    if (!activation ||
        lifecycle_parse_record_fields(bytes, encoded_bytes,
                                      WVM_RECORD_ACTIVATION_RECORD, fields,
                                      present, sizeof(present), error,
                                      error_len) != 0) {
        return -1;
    }
    for (i = 1; i <= 9; i++) {
        if (i != 3 && !present[i]) {
            set_error(error, error_len, "activation record misses field %zu", i);
            return -1;
        }
    }
    if (fields[1].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[2].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        (present[3] && fields[3].value_bytes != WVM_IDENTITY_ID_BYTES) ||
        fields[4].value_bytes != 8 ||
        fields[5].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[7].value_bytes != 2 || fields[8].value_bytes != 8 ||
        fields[9].value_bytes != 8) {
        set_error(error, error_len, "activation record has invalid fields");
        return -1;
    }
    route_keys = activation->required_route_snapshot_keys;
    route_key_capacity = activation->required_route_snapshot_capacity;
    memset(activation, 0, sizeof(*activation));
    activation->required_route_snapshot_keys = route_keys;
    activation->required_route_snapshot_capacity = route_key_capacity;
    memcpy(activation->admission_tx_id, fields[1].value,
           sizeof(activation->admission_tx_id));
    memcpy(activation->candidate_manifest_digest, fields[2].value,
           sizeof(activation->candidate_manifest_digest));
    activation->has_activation_fence = present[3];
    if (activation->has_activation_fence) {
        memcpy(activation->activation_fence, fields[3].value,
               sizeof(activation->activation_fence));
    }
    activation->coordinator_instance_id = lifecycle_read_be64(fields[4].value);
    memcpy(activation->required_participant_set_digest, fields[5].value,
           sizeof(activation->required_participant_set_digest));
    activation->decision =
        (enum wvm_activation_decision)lifecycle_read_be16(fields[7].value);
    activation->durable_decision_sequence =
        lifecycle_read_be64(fields[8].value);
    activation->decided_at = lifecycle_read_be64(fields[9].value);
    if (lifecycle_record_list_decode(
            fields[6].value, fields[6].value_bytes,
            activation->required_route_snapshot_keys,
            activation->required_route_snapshot_capacity,
            sizeof(*activation->required_route_snapshot_keys),
            &activation->required_route_snapshot_count,
            lifecycle_route_snapshot_key_decode_adapter, error, error_len) !=
            0 ||
        lifecycle_route_snapshot_key_list_validate(
            activation->required_route_snapshot_keys,
            activation->required_route_snapshot_count,
            activation->required_route_snapshot_capacity, error, error_len) !=
            0) {
        return -1;
    }
    return wvm_activation_record_validate(activation, error, error_len);
}

static int lifecycle_startup_dependency_shape_validate(
    const struct wvm_startup_dependency *dependency, int allow_zero_digest,
    char *error, size_t error_len)
{
    if (!dependency ||
        dependency->dependency_kind != WVM_STARTUP_DEPENDENCY_REQUIRED_MEMBER ||
        wvm_member_key_validate(&dependency->member_key, error, error_len) !=
            0 ||
        dependency->required_state < WVM_MANIFEST_MEMBER_PENDING ||
        dependency->required_state > WVM_MANIFEST_MEMBER_FAILED ||
        (!allow_zero_digest &&
         bytes_are_zero(dependency->dependency_digest,
                        sizeof(dependency->dependency_digest)))) {
        set_error(error, error_len, "startup dependency is invalid");
        return -1;
    }
    return 0;
}

int wvm_startup_dependency_validate(
    const struct wvm_startup_dependency *dependency, char *error,
    size_t error_len)
{
    return lifecycle_startup_dependency_shape_validate(dependency, 0, error,
                                                       error_len);
}

static int lifecycle_startup_dependency_size(const void *entry,
                                             size_t *encoded_size)
{
    size_t member_key_bytes;

    if (lifecycle_startup_dependency_shape_validate(entry, 1, NULL, 0) != 0 ||
        lifecycle_member_key_size(
            &((const struct wvm_startup_dependency *)entry)->member_key,
            &member_key_bytes) != 0) {
        return -1;
    }
    return lifecycle_record_size(
        (const size_t[]){2, member_key_bytes, 2, WVM_SHA256_DIGEST_BYTES}, 4,
        encoded_size);
}

int wvm_startup_dependency_encode(
    const struct wvm_startup_dependency *dependency, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t member_key_bytes[64];
    uint8_t *field_value;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t member_key_encoded_bytes;

    if (lifecycle_startup_dependency_shape_validate(dependency, 1, error,
                                                    error_len) != 0 ||
        wvm_member_key_encode(&dependency->member_key, member_key_bytes,
                              sizeof(member_key_bytes), &member_key_encoded_bytes,
                              error, error_len) != 0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_STARTUP_DEPENDENCY) != 0 ||
        wvm_canonical_field_append_u16(&builder, 1,
                                       dependency->dependency_kind) != 0 ||
        wvm_canonical_field_reserve(&builder, 2,
                                    (uint32_t)member_key_encoded_bytes,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode startup dependency");
        return -1;
    }
    memcpy(field_value, member_key_bytes, member_key_encoded_bytes);
    if (wvm_canonical_field_append_u16(&builder, 3,
                                       dependency->required_state) != 0 ||
        wvm_canonical_field_reserve(&builder, 4, WVM_SHA256_DIGEST_BYTES,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode startup dependency");
        return -1;
    }
    memset(field_value, 0, WVM_SHA256_DIGEST_BYTES);
    if (wvm_canonical_record_finish(&builder, encoded_bytes) != 0 ||
        wvm_canonical_record_digest(bytes, *encoded_bytes, 4, digest) != 0 ||
        (!bytes_are_zero(dependency->dependency_digest,
                         sizeof(dependency->dependency_digest)) &&
         memcmp(dependency->dependency_digest, digest, sizeof(digest)) != 0)) {
        set_error(error, error_len, "startup dependency digest is invalid");
        return -1;
    }
    memcpy(field_value, digest, sizeof(digest));
    return 0;
}

int wvm_startup_dependency_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_startup_dependency *dependency, char *error, size_t error_len)
{
    struct wvm_canonical_field fields[5];
    unsigned char present[5];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t i;

    if (!dependency ||
        lifecycle_parse_record_fields(bytes, encoded_bytes,
                                      WVM_RECORD_STARTUP_DEPENDENCY, fields,
                                      present, sizeof(present), error,
                                      error_len) != 0) {
        return -1;
    }
    for (i = 1; i <= 4; i++) {
        if (!present[i]) {
            set_error(error, error_len, "startup dependency misses field %zu",
                      i);
            return -1;
        }
    }
    if (fields[1].value_bytes != 2 || fields[3].value_bytes != 2 ||
        fields[4].value_bytes != WVM_SHA256_DIGEST_BYTES) {
        set_error(error, error_len, "startup dependency has invalid fields");
        return -1;
    }
    memset(dependency, 0, sizeof(*dependency));
    dependency->dependency_kind =
        (enum wvm_startup_dependency_kind)lifecycle_read_be16(fields[1].value);
    dependency->required_state =
        (enum wvm_manifest_member_state)lifecycle_read_be16(fields[3].value);
    memcpy(dependency->dependency_digest, fields[4].value,
           sizeof(dependency->dependency_digest));
    if (wvm_member_key_decode(fields[2].value, fields[2].value_bytes,
                              &dependency->member_key, error, error_len) != 0 ||
        wvm_startup_dependency_validate(dependency, error, error_len) != 0 ||
        wvm_canonical_record_digest(bytes, encoded_bytes, 4, digest) != 0 ||
        memcmp(digest, dependency->dependency_digest, sizeof(digest)) != 0) {
        set_error(error, error_len, "startup dependency digest does not match");
        return -1;
    }
    return 0;
}

static int lifecycle_startup_dependency_encode_adapter(
    const void *entry, uint8_t *bytes, size_t capacity, size_t *encoded_bytes,
    char *error, size_t error_len)
{
    return wvm_startup_dependency_encode(entry, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int lifecycle_startup_dependency_decode_adapter(
    const uint8_t *bytes, size_t encoded_bytes, void *entry, char *error,
    size_t error_len)
{
    return wvm_startup_dependency_decode(bytes, encoded_bytes, entry, error,
                                         error_len);
}

static int lifecycle_startup_dependency_compare(
    const struct wvm_startup_dependency *left,
    const struct wvm_startup_dependency *right)
{
    int comparison;

    if (left->dependency_kind != right->dependency_kind) {
        return left->dependency_kind < right->dependency_kind ? -1 : 1;
    }
    comparison = lifecycle_member_key_compare(&left->member_key,
                                              &right->member_key);
    if (comparison != 0) {
        return comparison;
    }
    return 0;
}

static int lifecycle_startup_dependency_list_validate(
    const struct wvm_startup_dependency_list *dependencies, char *error,
    size_t error_len)
{
    size_t i;

    if (!dependencies ||
        (dependencies->count != 0 && !dependencies->entries) ||
        dependencies->count > dependencies->capacity) {
        set_error(error, error_len, "startup dependency list is invalid");
        return -1;
    }
    for (i = 0; i < dependencies->count; i++) {
        if (wvm_startup_dependency_validate(&dependencies->entries[i], error,
                                            error_len) != 0 ||
            (i != 0 &&
             lifecycle_startup_dependency_compare(&dependencies->entries[i - 1],
                                                  &dependencies->entries[i]) >=
                 0)) {
            set_error(error, error_len,
                      "startup dependency list is not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int lifecycle_vcpu_assignment_list_validate(
    const struct wvm_vcpu_assignment_list *assignments,
    uint32_t physical_node_id, const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES],
    char *error, size_t error_len)
{
    size_t i;

    if (!assignments || (assignments->count != 0 && !assignments->entries) ||
        assignments->count > assignments->capacity) {
        set_error(error, error_len, "local vCPU assignment list is invalid");
        return -1;
    }
    for (i = 0; i < assignments->count; i++) {
        const struct wvm_vcpu_assignment *assignment = &assignments->entries[i];

        if (wvm_vcpu_assignment_validate(assignment, error, error_len) != 0 ||
            assignment->executor_physical_node_id != physical_node_id ||
            memcmp(assignment->reservation_id, reservation_id,
                   WVM_IDENTITY_ID_BYTES) != 0 ||
            (i != 0 &&
             assignments->entries[i - 1].guest_vcpu_index >=
                 assignment->guest_vcpu_index)) {
            set_error(error, error_len, "local vCPU assignments are invalid");
            return -1;
        }
    }
    return 0;
}

static int lifecycle_memory_assignment_list_validate(
    const struct wvm_memory_chunk_assignment_list *assignments,
    uint32_t physical_node_id, const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES],
    char *error, size_t error_len)
{
    size_t i;

    if (!assignments || (assignments->count != 0 && !assignments->entries) ||
        assignments->count > assignments->capacity) {
        set_error(error, error_len, "local memory assignment list is invalid");
        return -1;
    }
    for (i = 0; i < assignments->count; i++) {
        const struct wvm_memory_chunk_assignment *assignment =
            &assignments->entries[i];

        if (wvm_memory_chunk_assignment_validate(assignment, error, error_len) !=
                0 ||
            (assignment->directory_physical_node_id != physical_node_id &&
             assignment->executor_physical_node_id != physical_node_id) ||
            (assignment->directory_physical_node_id == physical_node_id &&
             memcmp(assignment->reservation_id, reservation_id,
                    WVM_IDENTITY_ID_BYTES) != 0) ||
            (i != 0 &&
             assignments->entries[i - 1].gpa_start >= assignment->gpa_start)) {
            set_error(error, error_len, "local memory assignments are invalid");
            return -1;
        }
    }
    return 0;
}

static int lifecycle_storage_assignment_list_validate(
    const struct wvm_storage_assignment_list *assignments,
    uint32_t physical_node_id, const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES],
    char *error, size_t error_len)
{
    size_t i;

    if (!assignments || (assignments->count != 0 && !assignments->entries) ||
        assignments->count > assignments->capacity) {
        set_error(error, error_len, "local storage assignment list is invalid");
        return -1;
    }
    for (i = 0; i < assignments->count; i++) {
        const struct wvm_storage_assignment *assignment =
            &assignments->entries[i];

        if (wvm_storage_assignment_validate(assignment, error, error_len) != 0 ||
            assignment->storage_physical_node_id != physical_node_id ||
            memcmp(assignment->reservation_id, reservation_id,
                   WVM_IDENTITY_ID_BYTES) != 0 ||
            (i != 0 &&
             assignments->entries[i - 1].device_index >=
                 assignment->device_index)) {
            set_error(error, error_len, "local storage assignments are invalid");
            return -1;
        }
    }
    return 0;
}

int wvm_node_runtime_manifest_encode(
    const struct wvm_node_runtime_manifest *runtime_manifest, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *field_value;
    uint8_t route_snapshot_key_bytes[256];
    uint8_t local_names_bytes[512];
    uint8_t launch_plan_bytes[512];
    size_t vcpu_bytes;
    size_t memory_bytes;
    size_t storage_bytes;
    size_t route_snapshot_key_encoded_bytes;
    size_t local_names_encoded_bytes;
    size_t profile_bytes;
    size_t startup_dependencies_bytes;
    size_t launch_plan_encoded_bytes;

    if (wvm_node_runtime_manifest_validate(runtime_manifest, error, error_len) !=
            0 ||
        lifecycle_record_list_size(
            runtime_manifest->local_vcpu_assignments.entries,
            runtime_manifest->local_vcpu_assignments.count,
            sizeof(*runtime_manifest->local_vcpu_assignments.entries),
            lifecycle_vcpu_assignment_size, &vcpu_bytes) != 0 ||
        lifecycle_record_list_size(
            runtime_manifest->local_memory_assignments.entries,
            runtime_manifest->local_memory_assignments.count,
            sizeof(*runtime_manifest->local_memory_assignments.entries),
            lifecycle_memory_assignment_size, &memory_bytes) != 0 ||
        lifecycle_record_list_size(
            runtime_manifest->local_storage_assignments.entries,
            runtime_manifest->local_storage_assignments.count,
            sizeof(*runtime_manifest->local_storage_assignments.entries),
            lifecycle_storage_assignment_size, &storage_bytes) != 0 ||
        wvm_route_snapshot_key_encode(
            &runtime_manifest->required_route_snapshot_key,
            route_snapshot_key_bytes, sizeof(route_snapshot_key_bytes),
            &route_snapshot_key_encoded_bytes, error, error_len) != 0 ||
        wvm_local_name_namespace_encode(&runtime_manifest->local_names,
                                        local_names_bytes,
                                        sizeof(local_names_bytes),
                                        &local_names_encoded_bytes, error,
                                        error_len) != 0 ||
        wvm_node_runtime_launch_plan_encode(
            &runtime_manifest->launch_plan, launch_plan_bytes,
            sizeof(launch_plan_bytes), &launch_plan_encoded_bytes, error,
            error_len) != 0 ||
        lifecycle_execution_fault_profile_size(
            &runtime_manifest->negotiated_profile, &profile_bytes) != 0 ||
        lifecycle_record_list_size(
            runtime_manifest->startup_dependencies.entries,
            runtime_manifest->startup_dependencies.count,
            sizeof(*runtime_manifest->startup_dependencies.entries),
            lifecycle_startup_dependency_size, &startup_dependencies_bytes) !=
            0 ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_NODE_RUNTIME_MANIFEST) != 0 ||
        wvm_canonical_field_append(
            &builder, 1, runtime_manifest->candidate_manifest_digest,
            sizeof(runtime_manifest->candidate_manifest_digest)) != 0 ||
        wvm_canonical_field_append_u32(&builder, 2, runtime_manifest->vm_id) !=
            0 ||
        wvm_canonical_field_append_u64(&builder, 3,
                                       runtime_manifest->vm_incarnation) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       runtime_manifest->manifest_generation) !=
            0 ||
        wvm_canonical_field_append(&builder, 5, runtime_manifest->admission_tx_id,
                                   sizeof(runtime_manifest->admission_tx_id)) !=
            0 ||
        wvm_canonical_field_append(
            &builder, 6, runtime_manifest->eligibility_fence_digest,
            sizeof(runtime_manifest->eligibility_fence_digest)) != 0 ||
        (runtime_manifest->has_activation_fence &&
         wvm_canonical_field_append(
             &builder, 7, runtime_manifest->activation_fence,
             sizeof(runtime_manifest->activation_fence)) != 0) ||
        wvm_canonical_field_append_u32(&builder, 8,
                                       runtime_manifest->physical_node_id) !=
            0 ||
        wvm_canonical_field_append_u64(
            &builder, 9, runtime_manifest->expected_node_instance_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 10,
                                       runtime_manifest->local_role_bits) != 0 ||
        wvm_canonical_field_reserve(&builder, 11, (uint32_t)vcpu_bytes,
                                    &field_value) != 0 ||
        lifecycle_record_list_encode(
            runtime_manifest->local_vcpu_assignments.entries,
            runtime_manifest->local_vcpu_assignments.count,
            sizeof(*runtime_manifest->local_vcpu_assignments.entries),
            lifecycle_vcpu_assignment_size,
            lifecycle_vcpu_assignment_encode_adapter, field_value, vcpu_bytes,
            error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 12, (uint32_t)memory_bytes,
                                    &field_value) != 0 ||
        lifecycle_record_list_encode(
            runtime_manifest->local_memory_assignments.entries,
            runtime_manifest->local_memory_assignments.count,
            sizeof(*runtime_manifest->local_memory_assignments.entries),
            lifecycle_memory_assignment_size,
            lifecycle_memory_assignment_encode_adapter, field_value,
            memory_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 13, (uint32_t)storage_bytes,
                                    &field_value) != 0 ||
        lifecycle_record_list_encode(
            runtime_manifest->local_storage_assignments.entries,
            runtime_manifest->local_storage_assignments.count,
            sizeof(*runtime_manifest->local_storage_assignments.entries),
            lifecycle_storage_assignment_size,
            lifecycle_storage_assignment_encode_adapter, field_value,
            storage_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(
            &builder, 14, (uint32_t)route_snapshot_key_encoded_bytes,
            &field_value) != 0) {
        set_error(error, error_len, "cannot encode node runtime manifest");
        return -1;
    }
    memcpy(field_value, route_snapshot_key_bytes, route_snapshot_key_encoded_bytes);
    if (wvm_canonical_field_reserve(&builder, 15,
                                    (uint32_t)local_names_encoded_bytes,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot encode node runtime manifest");
        return -1;
    }
    memcpy(field_value, local_names_bytes, local_names_encoded_bytes);
    if (wvm_canonical_field_reserve(&builder, 16, (uint32_t)profile_bytes,
                                    &field_value) != 0 ||
        wvm_execution_fault_profile_encode(
            &runtime_manifest->negotiated_profile, field_value, profile_bytes,
            &profile_bytes, error, error_len) != 0 ||
        wvm_canonical_field_append(&builder, 17, runtime_manifest->reservation_id,
                                   sizeof(runtime_manifest->reservation_id)) !=
            0 ||
        wvm_canonical_field_reserve(
            &builder, 18, (uint32_t)startup_dependencies_bytes,
            &field_value) != 0 ||
        lifecycle_record_list_encode(
            runtime_manifest->startup_dependencies.entries,
            runtime_manifest->startup_dependencies.count,
            sizeof(*runtime_manifest->startup_dependencies.entries),
            lifecycle_startup_dependency_size,
            lifecycle_startup_dependency_encode_adapter, field_value,
            startup_dependencies_bytes, error, error_len) != 0 ||
        wvm_canonical_field_reserve(&builder, 19,
                                    (uint32_t)launch_plan_encoded_bytes,
                                    &field_value) != 0) {
        set_error(error, error_len, "cannot finish node runtime manifest");
        return -1;
    }
    memcpy(field_value, launch_plan_bytes, launch_plan_encoded_bytes);
    if (wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot finish node runtime manifest");
        return -1;
    }
    return 0;
}

int wvm_node_runtime_manifest_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[20];
    unsigned char present[20];
    struct wvm_vcpu_assignment_list vcpus;
    struct wvm_memory_chunk_assignment_list memory;
    struct wvm_storage_assignment_list storage;
    struct wvm_startup_dependency_list dependencies;
    struct wvm_capability_ref_list capabilities;
    size_t i;

    if (!runtime_manifest ||
        lifecycle_parse_record_fields(bytes, encoded_bytes,
                                      WVM_RECORD_NODE_RUNTIME_MANIFEST, fields,
                                      present, sizeof(present), error,
                                      error_len) != 0) {
        return -1;
    }
    for (i = 1; i <= 19; i++) {
        if (i != 7 && !present[i]) {
            set_error(error, error_len,
                      "node runtime manifest misses field %zu", i);
            return -1;
        }
    }
    if (fields[1].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[2].value_bytes != 4 || fields[3].value_bytes != 8 ||
        fields[4].value_bytes != 8 ||
        fields[5].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[6].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        (present[7] && fields[7].value_bytes != WVM_IDENTITY_ID_BYTES) ||
        fields[8].value_bytes != 4 || fields[9].value_bytes != 8 ||
        fields[10].value_bytes != 8 ||
        fields[17].value_bytes != WVM_IDENTITY_ID_BYTES) {
        set_error(error, error_len, "node runtime manifest has invalid fields");
        return -1;
    }
    vcpus = runtime_manifest->local_vcpu_assignments;
    memory = runtime_manifest->local_memory_assignments;
    storage = runtime_manifest->local_storage_assignments;
    dependencies = runtime_manifest->startup_dependencies;
    capabilities =
        runtime_manifest->negotiated_profile.per_node_capabilities;
    memset(runtime_manifest, 0, sizeof(*runtime_manifest));
    runtime_manifest->local_vcpu_assignments = vcpus;
    runtime_manifest->local_memory_assignments = memory;
    runtime_manifest->local_storage_assignments = storage;
    runtime_manifest->startup_dependencies = dependencies;
    runtime_manifest->negotiated_profile.per_node_capabilities = capabilities;
    memcpy(runtime_manifest->candidate_manifest_digest, fields[1].value,
           sizeof(runtime_manifest->candidate_manifest_digest));
    runtime_manifest->vm_id = lifecycle_read_be32(fields[2].value);
    runtime_manifest->vm_incarnation = lifecycle_read_be64(fields[3].value);
    runtime_manifest->manifest_generation =
        lifecycle_read_be64(fields[4].value);
    memcpy(runtime_manifest->admission_tx_id, fields[5].value,
           sizeof(runtime_manifest->admission_tx_id));
    memcpy(runtime_manifest->eligibility_fence_digest, fields[6].value,
           sizeof(runtime_manifest->eligibility_fence_digest));
    runtime_manifest->has_activation_fence = present[7];
    if (runtime_manifest->has_activation_fence) {
        memcpy(runtime_manifest->activation_fence, fields[7].value,
               sizeof(runtime_manifest->activation_fence));
    }
    runtime_manifest->physical_node_id = lifecycle_read_be32(fields[8].value);
    runtime_manifest->expected_node_instance_id =
        lifecycle_read_be64(fields[9].value);
    runtime_manifest->local_role_bits = lifecycle_read_be64(fields[10].value);
    memcpy(runtime_manifest->reservation_id, fields[17].value,
           sizeof(runtime_manifest->reservation_id));
    if (wvm_route_snapshot_key_decode(
            fields[14].value, fields[14].value_bytes,
            &runtime_manifest->required_route_snapshot_key, error,
            error_len) != 0 ||
        wvm_local_name_namespace_decode(fields[15].value, fields[15].value_bytes,
                                        &runtime_manifest->local_names, error,
                                        error_len) != 0 ||
        wvm_execution_fault_profile_decode(
            fields[16].value, fields[16].value_bytes,
            &runtime_manifest->negotiated_profile, error, error_len) != 0 ||
        lifecycle_record_list_decode(
            fields[11].value, fields[11].value_bytes,
            runtime_manifest->local_vcpu_assignments.entries,
            runtime_manifest->local_vcpu_assignments.capacity,
            sizeof(*runtime_manifest->local_vcpu_assignments.entries),
            &runtime_manifest->local_vcpu_assignments.count,
            lifecycle_vcpu_assignment_decode_adapter, error, error_len) != 0 ||
        lifecycle_record_list_decode(
            fields[12].value, fields[12].value_bytes,
            runtime_manifest->local_memory_assignments.entries,
            runtime_manifest->local_memory_assignments.capacity,
            sizeof(*runtime_manifest->local_memory_assignments.entries),
            &runtime_manifest->local_memory_assignments.count,
            lifecycle_memory_assignment_decode_adapter, error, error_len) != 0 ||
        lifecycle_record_list_decode(
            fields[13].value, fields[13].value_bytes,
            runtime_manifest->local_storage_assignments.entries,
            runtime_manifest->local_storage_assignments.capacity,
            sizeof(*runtime_manifest->local_storage_assignments.entries),
            &runtime_manifest->local_storage_assignments.count,
            lifecycle_storage_assignment_decode_adapter, error, error_len) !=
            0 ||
        lifecycle_record_list_decode(
            fields[18].value, fields[18].value_bytes,
            runtime_manifest->startup_dependencies.entries,
            runtime_manifest->startup_dependencies.capacity,
            sizeof(*runtime_manifest->startup_dependencies.entries),
            &runtime_manifest->startup_dependencies.count,
            lifecycle_startup_dependency_decode_adapter, error, error_len) !=
            0 ||
        wvm_node_runtime_launch_plan_decode(
            fields[19].value, fields[19].value_bytes,
            &runtime_manifest->launch_plan, error, error_len) != 0) {
        return -1;
    }
    return wvm_node_runtime_manifest_validate(runtime_manifest, error, error_len);
}

int wvm_admission_transaction_record_validate(
    const struct wvm_admission_transaction_record *record, char *error,
    size_t error_len)
{
    if (!record ||
        bytes_are_zero(record->request_id, sizeof(record->request_id)) ||
        bytes_are_zero(record->request_digest, sizeof(record->request_digest)) ||
        record->vm_id < 256 || record->vm_incarnation == 0 ||
        record->manifest_generation == 0 ||
        bytes_are_zero(record->admission_tx_id,
                       sizeof(record->admission_tx_id)) ||
        bytes_are_zero(record->manifest_id, sizeof(record->manifest_id)) ||
        wvm_vm_route_scope_key_validate(&record->route_scope_key, error,
                                        error_len) != 0 ||
        record->route_scope_key.vm_id != record->vm_id ||
        record->route_scope_key.vm_incarnation != record->vm_incarnation ||
        record->state < WVM_LIFECYCLE_REQUESTED ||
        record->state > WVM_LIFECYCLE_FAILED ||
        (record->has_candidate_manifest_digest != 0 &&
         record->has_candidate_manifest_digest != 1) ||
        (record->has_prepared_route_snapshot_key != 0 &&
         record->has_prepared_route_snapshot_key != 1) ||
        (record->has_activation_record_digest != 0 &&
         record->has_activation_record_digest != 1) ||
        (record->has_candidate_manifest_digest &&
         bytes_are_zero(record->candidate_manifest_digest,
                        sizeof(record->candidate_manifest_digest))) ||
        (!record->has_candidate_manifest_digest &&
         !bytes_are_zero(record->candidate_manifest_digest,
                         sizeof(record->candidate_manifest_digest))) ||
        (record->has_candidate_manifest_digest !=
         record->has_prepared_route_snapshot_key) ||
        (record->has_prepared_route_snapshot_key &&
         (wvm_route_snapshot_key_validate(
              &record->prepared_route_snapshot_key, error, error_len) != 0 ||
          record->prepared_route_snapshot_key.scope_key.vm_id !=
              record->route_scope_key.vm_id ||
          record->prepared_route_snapshot_key.scope_key.vm_incarnation !=
              record->route_scope_key.vm_incarnation ||
          record->prepared_route_snapshot_key.scope_key.route_scope_id !=
              record->route_scope_key.route_scope_id)) ||
        (record->has_activation_record_digest &&
         bytes_are_zero(record->activation_record_digest,
                        sizeof(record->activation_record_digest))) ||
        (!record->has_activation_record_digest &&
         !bytes_are_zero(record->activation_record_digest,
                         sizeof(record->activation_record_digest))) ||
        record->transaction_sequence == 0) {
        set_error(error, error_len, "admission transaction record is invalid");
        return -1;
    }
    return 0;
}

int wvm_admission_transaction_record_encode(
    const struct wvm_admission_transaction_record *record, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t route_scope_bytes[128];
    uint8_t prepared_route_snapshot_key_bytes[256];
    size_t route_scope_encoded_bytes;
    size_t prepared_route_snapshot_key_encoded_bytes = 0;

    if (wvm_admission_transaction_record_validate(record, error, error_len) !=
            0 ||
        wvm_vm_route_scope_key_encode(&record->route_scope_key,
                                      route_scope_bytes,
                                      sizeof(route_scope_bytes),
                                      &route_scope_encoded_bytes, error,
                                      error_len) != 0 ||
        (record->has_prepared_route_snapshot_key &&
         wvm_route_snapshot_key_encode(
             &record->prepared_route_snapshot_key,
             prepared_route_snapshot_key_bytes,
             sizeof(prepared_route_snapshot_key_bytes),
             &prepared_route_snapshot_key_encoded_bytes, error,
             error_len) != 0) ||
        wvm_canonical_record_begin(&builder, bytes, capacity,
                                   WVM_RECORD_ADMISSION_TRANSACTION) != 0 ||
        wvm_canonical_field_append(&builder, 1, record->request_id,
                                   sizeof(record->request_id)) != 0 ||
        wvm_canonical_field_append(&builder, 2, record->request_digest,
                                   sizeof(record->request_digest)) != 0 ||
        wvm_canonical_field_append_u32(&builder, 3, record->vm_id) != 0 ||
        wvm_canonical_field_append_u64(&builder, 4,
                                       record->vm_incarnation) != 0 ||
        wvm_canonical_field_append_u64(&builder, 5,
                                       record->manifest_generation) != 0 ||
        wvm_canonical_field_append(&builder, 6, record->admission_tx_id,
                                   sizeof(record->admission_tx_id)) != 0 ||
        wvm_canonical_field_append(&builder, 7, record->manifest_id,
                                   sizeof(record->manifest_id)) != 0 ||
        wvm_canonical_field_append(&builder, 8, route_scope_bytes,
                                   (uint32_t)route_scope_encoded_bytes) != 0 ||
        wvm_canonical_field_append_u16(&builder, 9, record->state) != 0 ||
        (record->has_candidate_manifest_digest &&
         wvm_canonical_field_append(
             &builder, 10, record->candidate_manifest_digest,
             sizeof(record->candidate_manifest_digest)) != 0) ||
        (record->has_activation_record_digest &&
         wvm_canonical_field_append(
             &builder, 11, record->activation_record_digest,
             sizeof(record->activation_record_digest)) != 0) ||
        wvm_canonical_field_append_u64(&builder, 12,
                                       record->transaction_sequence) != 0 ||
        (record->has_prepared_route_snapshot_key &&
         wvm_canonical_field_append(
             &builder, 13, prepared_route_snapshot_key_bytes,
             (uint32_t)prepared_route_snapshot_key_encoded_bytes) != 0) ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode admission transaction");
        return -1;
    }
    return 0;
}

int wvm_admission_transaction_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_admission_transaction_record *record, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[14];
    unsigned char present[14];
    size_t i;

    if (!record ||
        lifecycle_parse_record_fields(
            bytes, encoded_bytes, WVM_RECORD_ADMISSION_TRANSACTION, fields,
            present, sizeof(present), error, error_len) != 0) {
        return -1;
    }
    for (i = 1; i <= 13; i++) {
        if (i != 10 && i != 11 && i != 13 && !present[i]) {
            set_error(error, error_len,
                      "admission transaction misses field %zu", i);
            return -1;
        }
    }
    if (fields[1].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[2].value_bytes != WVM_SHA256_DIGEST_BYTES ||
        fields[3].value_bytes != 4 || fields[4].value_bytes != 8 ||
        fields[5].value_bytes != 8 ||
        fields[6].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[7].value_bytes != WVM_IDENTITY_ID_BYTES ||
        fields[9].value_bytes != 2 || fields[12].value_bytes != 8 ||
        (present[10] &&
         fields[10].value_bytes != WVM_SHA256_DIGEST_BYTES) ||
        (present[11] &&
         fields[11].value_bytes != WVM_SHA256_DIGEST_BYTES)) {
        set_error(error, error_len,
                  "admission transaction has invalid field widths");
        return -1;
    }

    memset(record, 0, sizeof(*record));
    memcpy(record->request_id, fields[1].value, sizeof(record->request_id));
    memcpy(record->request_digest, fields[2].value,
           sizeof(record->request_digest));
    record->vm_id = lifecycle_read_be32(fields[3].value);
    record->vm_incarnation = lifecycle_read_be64(fields[4].value);
    record->manifest_generation = lifecycle_read_be64(fields[5].value);
    memcpy(record->admission_tx_id, fields[6].value,
           sizeof(record->admission_tx_id));
    memcpy(record->manifest_id, fields[7].value, sizeof(record->manifest_id));
    record->state = (enum wvm_lifecycle_state)lifecycle_read_be16(
        fields[9].value);
    record->has_candidate_manifest_digest = present[10];
    if (record->has_candidate_manifest_digest) {
        memcpy(record->candidate_manifest_digest, fields[10].value,
               sizeof(record->candidate_manifest_digest));
    }
    record->has_prepared_route_snapshot_key = present[13];
    record->has_activation_record_digest = present[11];
    if (record->has_activation_record_digest) {
        memcpy(record->activation_record_digest, fields[11].value,
               sizeof(record->activation_record_digest));
    }
    record->transaction_sequence = lifecycle_read_be64(fields[12].value);
    if (wvm_vm_route_scope_key_decode(fields[8].value, fields[8].value_bytes,
                                      &record->route_scope_key, error,
                                      error_len) != 0 ||
        (record->has_prepared_route_snapshot_key &&
         wvm_route_snapshot_key_decode(
             fields[13].value, fields[13].value_bytes,
             &record->prepared_route_snapshot_key, error, error_len) != 0)) {
        return -1;
    }
    return wvm_admission_transaction_record_validate(record, error, error_len);
}

#include "wavevm_coordinator.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_canonical.h"
#include "wavevm_fault_engine.h"
#include "wavevm_reservation_runtime.h"
#include "wavevm_sha256.h"

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

static void abort_registered_reservations(
    struct wvm_coordinator_prepared_vm *prepared_vm)
{
    size_t i;

    if (!prepared_vm || !prepared_vm->reservation_registries) {
        return;
    }
    for (i = 0; i < prepared_vm->reservation_count; i++) {
        size_t j;

        for (j = 0; j < prepared_vm->reservation_registry_count; j++) {
            struct wvm_local_reservation_registry *registry =
                prepared_vm->reservation_registries[j];

            if (registry &&
                registry->physical_node_id ==
                    prepared_vm->reservations[i].physical_node_id) {
                (void)wvm_local_reservation_abort(
                    registry, &prepared_vm->reservations[i], NULL,
                    NULL, 0);
                break;
            }
        }
    }
}

static int reservation_registry_for(
    const struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_resource_reservation *reservation,
    struct wvm_local_reservation_registry **registry_out, char *error,
    size_t error_len)
{
    struct wvm_local_reservation_registry *match = NULL;
    size_t i;

    if (!prepared_vm || !reservation || !registry_out) {
        set_error(error, error_len, "reservation registry lookup is invalid");
        return -1;
    }
    *registry_out = NULL;
    if (!prepared_vm->reservation_registries) {
        return 0;
    }
    if (prepared_vm->reservation_registry_count == 0) {
        set_error(error, error_len, "reservation registry list is empty");
        return -1;
    }
    for (i = 0; i < prepared_vm->reservation_registry_count; i++) {
        struct wvm_local_reservation_registry *candidate =
            prepared_vm->reservation_registries[i];

        if (!candidate ||
            candidate->physical_node_id != reservation->physical_node_id) {
            continue;
        }
        if (match) {
            set_error(error, error_len,
                      "multiple reservation registries claim one node");
            return -1;
        }
        match = candidate;
    }
    if (!match) {
        set_error(error, error_len,
                  "prepared reservation has no node-local registry");
        return -1;
    }
    *registry_out = match;
    return 0;
}

static int reservation_matches_activation(
    const struct wvm_resource_reservation *reservation,
    const struct wvm_activation_record *activation)
{
    return reservation &&
           reservation->state == WVM_RESERVATION_COMMITTED &&
           reservation->has_activation_fence &&
           memcmp(reservation->activation_fence, activation->activation_fence,
                  sizeof(reservation->activation_fence)) == 0;
}

static int commit_derived_reservation(
    struct wvm_resource_reservation *reservation,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    if (reservation_matches_activation(reservation, activation)) {
        return 0;
    }
    if (!reservation || reservation->state != WVM_RESERVATION_PREPARED ||
        wvm_resource_reservation_commit(reservation, activation, error,
                                        error_len) != 0) {
        set_error(error, error_len,
                  "derived reservation cannot commit the activation");
        return -1;
    }
    return 0;
}

static int release_derived_reservation(
    struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    if (reservation && reservation->state == WVM_RESERVATION_RELEASED) {
        return 0;
    }
    if (!reservation || reservation->state != WVM_RESERVATION_PREPARED ||
        wvm_resource_reservation_begin_release(reservation, error,
                                               error_len) != 0 ||
        wvm_resource_reservation_release(reservation, error, error_len) != 0) {
        set_error(error, error_len, "derived reservation cannot be released");
        return -1;
    }
    return 0;
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

static int route_snapshot_key_equal(const struct wvm_route_snapshot_key *left,
                                    const struct wvm_route_snapshot_key *right)
{
    return left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static void write_be32(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static int request_allows_backend(const struct wvm_vm_request *request,
                                  enum wvm_manifest_backend backend)
{
    return request->execution_backend_policy ==
               WVM_MANIFEST_BACKEND_POLICY_AUTO ||
           (request->execution_backend_policy ==
                WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM &&
            backend == WVM_MANIFEST_BACKEND_KVM) ||
           (request->execution_backend_policy ==
                WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG &&
            backend == WVM_MANIFEST_BACKEND_TCG);
}

static int backend_to_admission(enum wvm_manifest_backend backend,
                                enum wvm_admission_backend *admission_backend)
{
    if (backend == WVM_MANIFEST_BACKEND_KVM) {
        *admission_backend = WVM_ADMISSION_BACKEND_KVM;
        return 0;
    }
    if (backend == WVM_MANIFEST_BACKEND_TCG) {
        *admission_backend = WVM_ADMISSION_BACKEND_TCG;
        return 0;
    }
    return -1;
}

static int placement_policy_to_admission(
    enum wvm_manifest_placement_policy placement_policy,
    enum wvm_admission_placement_policy *admission_policy)
{
    if (placement_policy == WVM_MANIFEST_PLACEMENT_COMPACT) {
        *admission_policy = WVM_ADMISSION_PLACEMENT_COMPACT;
        return 0;
    }
    if (placement_policy == WVM_MANIFEST_PLACEMENT_SPREAD) {
        *admission_policy = WVM_ADMISSION_PLACEMENT_SPREAD;
        return 0;
    }
    return -1;
}

static int build_admission_request(
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_prepare_options *options,
    struct wvm_admission_request *admission_request, char *error,
    size_t error_len)
{
    if (!request || !transaction || !options || !admission_request) {
        set_error(error, error_len, "cannot normalize VM admission request");
        return -1;
    }
    memset(admission_request, 0, sizeof(*admission_request));
    if (
        backend_to_admission(options->execution_profile.backend,
                             &admission_request->backend) != 0 ||
        placement_policy_to_admission(request->placement_policy,
                                      &admission_request->placement_policy) !=
            0) {
        set_error(error, error_len, "cannot normalize VM admission request");
        return -1;
    }
    admission_request->vm_id = transaction->vm_id;
    admission_request->vm_incarnation = transaction->vm_incarnation;
    admission_request->manifest_generation = transaction->manifest_generation;
    admission_request->requested_vcpu_slots = request->requested_vcpus;
    admission_request->requested_memory_bytes = request->requested_memory_bytes;
    admission_request->memory_chunk_bytes = options->memory_chunk_bytes;
    admission_request->host_overhead_vcpu_slots =
        options->host_overhead_vcpu_slots;
    admission_request->host_overhead_memory_bytes =
        options->host_overhead_memory_bytes;
    return 0;
}

static const struct wvm_coordinator_node_launch_plan *find_node_launch_plan(
    const struct wvm_coordinator_prepare_options *options,
    uint32_t physical_node_id, uint64_t node_instance_id)
{
    size_t i;

    if (!options || physical_node_id == 0 || node_instance_id == 0 ||
        !options->node_launch_plans) {
        return NULL;
    }
    for (i = 0; i < options->node_launch_plan_count; i++) {
        const struct wvm_coordinator_node_launch_plan *entry =
            &options->node_launch_plans[i];

        if (entry->physical_node_id == physical_node_id &&
            entry->expected_node_instance_id == node_instance_id) {
            return entry;
        }
    }
    return NULL;
}

static int launch_plan_matches_request(
    const struct wvm_node_runtime_launch_plan *launch_plan,
    const struct wvm_vm_request *request,
    const struct wvm_machine_config *guest_machine)
{
    const struct wvm_consistency_policy *policy;

    if (!launch_plan || !request || !guest_machine) {
        return 0;
    }
    policy = &launch_plan->consistency_policy;
    return launch_plan->guest_total_memory_bytes ==
               request->requested_memory_bytes &&
           strcmp(launch_plan->guest_machine.architecture,
                  guest_machine->architecture) == 0 &&
           strcmp(launch_plan->guest_machine.machine_type,
                  guest_machine->machine_type) == 0 &&
           launch_plan->guest_machine.qemu_compat_version ==
               guest_machine->qemu_compat_version &&
           launch_plan->guest_machine.firmware_policy ==
               guest_machine->firmware_policy &&
           policy->dirty_batch_size == request->consistency_policy.dirty_batch_size &&
           policy->handoff_commit_policy ==
               request->consistency_policy.handoff_commit_policy &&
           policy->subscriber_delivery_policy ==
               request->consistency_policy.subscriber_delivery_policy &&
           policy->max_commit_latency_ms ==
               request->consistency_policy.max_commit_latency_ms;
}

static const struct wvm_capability_record *
find_available_capability(const struct wvm_cluster_record_set *records,
                          const struct wvm_capability_ref *reference,
                          uint16_t capability_id)
{
    size_t i;

    for (i = 0; i < records->capability_record_count; i++) {
        const struct wvm_capability_record *record =
            &records->capability_records[i];

        if (record->physical_node_id == reference->physical_node_id &&
            record->node_instance_id == reference->node_instance_id &&
            record->capability_id == capability_id &&
            record->state == WVM_CAPABILITY_AVAILABLE) {
            return record;
        }
    }
    return NULL;
}

static int append_required_capability(
    struct wvm_capability_ref_list *capabilities,
    const struct wvm_capability_ref *capability, char *error, size_t error_len)
{
    size_t i;

    if (!capabilities || !capability || !capabilities->entries ||
        capabilities->count >= capabilities->capacity ||
        wvm_capability_ref_validate(capability, error, error_len) != 0) {
        set_error(error, error_len, "cannot append required capability");
        return -1;
    }
    for (i = 0; i < capabilities->count; i++) {
        struct wvm_capability_ref *current = &capabilities->entries[i];

        if (current->physical_node_id == capability->physical_node_id) {
            if (memcmp(current, capability, sizeof(*capability)) != 0) {
                set_error(error, error_len,
                          "conflicting capability reference for one node");
                return -1;
            }
            return 0;
        }
        if (current->physical_node_id > capability->physical_node_id) {
            size_t move;

            for (move = capabilities->count; move > i; move--) {
                capabilities->entries[move] = capabilities->entries[move - 1U];
            }
            capabilities->entries[i] = *capability;
            capabilities->count++;
            return 0;
        }
    }
    capabilities->entries[capabilities->count++] = *capability;
    return 0;
}

static int route_is_prepared_for_transaction(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_cluster_snapshot *snapshot, char *error, size_t error_len)
{
    size_t i;

    if (!prepared_route || !prepared_route->required_ack_set ||
        wvm_route_snapshot_key_validate(&prepared_route->route_snapshot_key,
                                        error, error_len) != 0 ||
        wvm_required_ack_set_validate(prepared_route->required_ack_set, error,
                                      error_len) != 0) {
        return -1;
    }
    if (prepared_route->route_snapshot_key.scope_key.vm_id !=
            transaction->route_scope_key.vm_id ||
        prepared_route->route_snapshot_key.scope_key.vm_incarnation !=
            transaction->route_scope_key.vm_incarnation ||
        prepared_route->route_snapshot_key.scope_key.route_scope_id !=
            transaction->route_scope_key.route_scope_id ||
        prepared_route->route_snapshot_key.topology_revision !=
            snapshot->admission.topology_revision) {
        set_error(error, error_len,
                  "prepared route does not match transaction scope");
        return -1;
    }
    for (i = 0; i < prepared_route->required_ack_set->entries.count; i++) {
        if (!route_snapshot_key_equal(
                &prepared_route->required_ack_set->entries.entries[i]
                     .expected_snapshot_key,
                &prepared_route->route_snapshot_key)) {
            set_error(error, error_len,
                      "prepared route ACK set does not bind one snapshot");
            return -1;
        }
    }
    return 0;
}

static int fill_startup_dependencies(
    const struct wvm_candidate_vm_manifest *candidate,
    struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    struct wvm_startup_dependency_list *dependencies =
        &runtime_manifest->startup_dependencies;
    uint8_t bytes[256];
    size_t i;

    if ((dependencies->capacity != 0 && !dependencies->entries) ||
        candidate->required_members.count > dependencies->capacity + 1U) {
        set_error(error, error_len, "startup dependency output is too small");
        return -1;
    }
    dependencies->count = 0;
    for (i = 0; i < candidate->required_members.count; i++) {
        const struct wvm_required_member *member =
            &candidate->required_members.entries[i];
        struct wvm_startup_dependency dependency;
        size_t encoded_bytes;

        if (member->member_key.role_type == WVM_MANIFEST_ROLE_NODE_RUNTIME &&
            member->physical_node_id == runtime_manifest->physical_node_id &&
            member->member_key.instance_id ==
                runtime_manifest->expected_node_instance_id) {
            continue;
        }
        if (dependencies->count == dependencies->capacity) {
            set_error(error, error_len, "startup dependency output is too small");
            return -1;
        }
        memset(&dependency, 0, sizeof(dependency));
        dependency.dependency_kind = WVM_STARTUP_DEPENDENCY_REQUIRED_MEMBER;
        dependency.member_key = member->member_key;
        dependency.required_state = member->required_state;
        if (wvm_startup_dependency_encode(&dependency, bytes, sizeof(bytes),
                                          &encoded_bytes, error,
                                          error_len) != 0 ||
            wvm_startup_dependency_decode(
                bytes, encoded_bytes, &dependencies->entries[dependencies->count],
                error, error_len) != 0) {
            return -1;
        }
        dependencies->count++;
    }
    return 0;
}

static int required_participant_set_digest(
    const struct wvm_admission_eligibility_fence *fence,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len)
{
    struct wvm_sha256_ctx context;
    uint8_t count_bytes[4];
    size_t i;

    if (!fence || !digest ||
        wvm_admission_eligibility_fence_validate(fence, error, error_len) !=
            0 ||
        fence->selected_members.count > UINT32_MAX) {
        set_error(error, error_len, "participant set cannot be digested");
        return -1;
    }
    write_be32(count_bytes, (uint32_t)fence->selected_members.count);
    wvm_sha256_init(&context);
    wvm_sha256_update(&context, count_bytes, sizeof(count_bytes));
    for (i = 0; i < fence->selected_members.count; i++) {
        uint8_t member_bytes[1024];
        uint8_t member_size_bytes[4];
        size_t member_bytes_used;

        if (wvm_required_member_encode(
                &fence->selected_members.entries[i], member_bytes,
                sizeof(member_bytes), &member_bytes_used, error,
                error_len) != 0 ||
            member_bytes_used > UINT32_MAX) {
            return -1;
        }
        write_be32(member_size_bytes, (uint32_t)member_bytes_used);
        wvm_sha256_update(&context, member_size_bytes,
                          sizeof(member_size_bytes));
        wvm_sha256_update(&context, member_bytes, member_bytes_used);
    }
    wvm_sha256_final(&context, digest);
    return 0;
}

static int prepared_candidate_validate(
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len)
{
    struct wvm_candidate_vm_manifest *candidate;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    size_t i;

    if (!transaction || !prepared_vm) {
        set_error(error, error_len, "prepared candidate input is missing");
        return -1;
    }
    candidate = &prepared_vm->candidate;
    if (wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        wvm_admission_request_validate(&prepared_vm->admission_request, error,
                                       error_len) != 0 ||
        wvm_placement_plan_validate(&prepared_vm->placement_plan, error,
                                    error_len) != 0 ||
        wvm_candidate_vm_manifest_matches_plan(candidate,
                                                &prepared_vm->placement_plan,
                                                error, error_len) != 0 ||
        candidate->vm_id != transaction->vm_id ||
        candidate->vm_incarnation != transaction->vm_incarnation ||
        candidate->manifest_generation != transaction->manifest_generation ||
        memcmp(candidate->manifest_id, transaction->manifest_id,
               sizeof(candidate->manifest_id)) != 0 ||
        memcmp(candidate->request_id, transaction->request_id,
               sizeof(candidate->request_id)) != 0 ||
        memcmp(candidate->admission_tx_id, transaction->admission_tx_id,
               sizeof(candidate->admission_tx_id)) != 0 ||
        candidate->route_scope_key.vm_id != transaction->route_scope_key.vm_id ||
        candidate->route_scope_key.vm_incarnation !=
            transaction->route_scope_key.vm_incarnation ||
        candidate->route_scope_key.route_scope_id !=
            transaction->route_scope_key.route_scope_id ||
        prepared_vm->admission_request.vm_id != transaction->vm_id ||
        prepared_vm->admission_request.vm_incarnation !=
            transaction->vm_incarnation ||
        prepared_vm->admission_request.manifest_generation !=
            transaction->manifest_generation ||
        bytes_are_zero(candidate->manifest_digest,
                       sizeof(candidate->manifest_digest)) ||
        bytes_are_zero(prepared_vm->candidate_manifest_digest,
                       sizeof(prepared_vm->candidate_manifest_digest)) ||
        memcmp(candidate->manifest_digest,
               prepared_vm->candidate_manifest_digest,
               sizeof(candidate->manifest_digest)) != 0 ||
        !prepared_vm->candidate_manifest_record ||
        prepared_vm->candidate_manifest_record_capacity == 0 ||
        prepared_vm->candidate_manifest_bytes == 0 ||
        wvm_candidate_vm_manifest_encode(
            candidate, prepared_vm->candidate_manifest_record,
            prepared_vm->candidate_manifest_record_capacity, &encoded_bytes,
            digest, error, error_len) != 0 ||
        encoded_bytes != prepared_vm->candidate_manifest_bytes ||
        memcmp(digest, prepared_vm->candidate_manifest_digest,
               sizeof(digest)) != 0 ||
        prepared_vm->reservation_count !=
            candidate->reservation_requirements.count ||
        !prepared_vm->reservations) {
        set_error(error, error_len, "prepared candidate is inconsistent");
        return -1;
    }
    for (i = 0; i < candidate->reservation_requirements.count; i++) {
        const struct wvm_reservation_requirement *requirement =
            &candidate->reservation_requirements.entries[i];
        size_t j;
        int found = 0;

        for (j = 0; j < prepared_vm->reservation_count; j++) {
            const struct wvm_resource_reservation *reservation =
                &prepared_vm->reservations[j];

            if (reservation->physical_node_id != requirement->physical_node_id) {
                continue;
            }
            if (found || wvm_resource_reservation_validate(reservation, error,
                                                            error_len) != 0 ||
                memcmp(reservation->reservation_id, requirement->reservation_id,
                       sizeof(reservation->reservation_id)) != 0 ||
                reservation->node_instance_id != requirement->node_instance_id ||
                reservation->inventory_revision !=
                    requirement->inventory_revision ||
                reservation->guest_vcpu_slots != requirement->guest_vcpu_slots ||
                reservation->guest_memory_bytes !=
                    requirement->guest_memory_bytes ||
                reservation->overhead_vcpu_slots !=
                    requirement->overhead_vcpu_slots ||
                reservation->overhead_memory_bytes !=
                    requirement->overhead_memory_bytes ||
                memcmp(reservation->plan_digest, candidate->plan_digest,
                       sizeof(reservation->plan_digest)) != 0 ||
                memcmp(reservation->candidate_manifest_digest,
                       prepared_vm->candidate_manifest_digest,
                       sizeof(reservation->candidate_manifest_digest)) != 0 ||
                memcmp(reservation->admission_tx_id, candidate->admission_tx_id,
                       sizeof(reservation->admission_tx_id)) != 0 ||
                memcmp(reservation->eligibility_fence_digest,
                       candidate->eligibility_fence_digest,
                       sizeof(reservation->eligibility_fence_digest)) != 0) {
                set_error(error, error_len,
                          "prepared reservation does not match candidate");
                return -1;
            }
            found = 1;
        }
        if (!found) {
            set_error(error, error_len,
                      "candidate reservation has no prepared record");
            return -1;
        }
    }
    return 0;
}

static int current_fence_matches(
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len)
{
    struct wvm_cluster_snapshot snapshot = {0};
    struct wvm_cluster_snapshot constrained_snapshot = {0};
    struct wvm_admission_eligibility_fence current_fence;
    struct wvm_required_member *selected_members;
    size_t selected_member_capacity;
    int result = -1;

    if (!request || !transaction || !records || !prepared_route || !prepared_vm ||
        wvm_admission_eligibility_fence_validate(&prepared_vm->fence, error,
                                                 error_len) != 0 ||
        !route_snapshot_key_equal(&prepared_vm->candidate
                                       .prepared_route_snapshot_key,
                                  &prepared_route->route_snapshot_key) ||
        records->node_count > SIZE_MAX - records->gateway_count) {
        set_error(error, error_len, "current admission fence input is invalid");
        return -1;
    }
    selected_member_capacity = records->node_count + records->gateway_count;
    if (selected_member_capacity == 0 ||
        selected_member_capacity > SIZE_MAX / sizeof(*selected_members)) {
        set_error(error, error_len, "current admission fence is too large");
        return -1;
    }
    selected_members = calloc(selected_member_capacity, sizeof(*selected_members));
    if (!selected_members) {
        set_error(error, error_len, "cannot allocate current admission fence");
        return -1;
    }
    memset(&current_fence, 0, sizeof(current_fence));
    current_fence.selected_members.entries = selected_members;
    current_fence.selected_members.capacity = selected_member_capacity;
    if (wvm_cluster_snapshot_build(records, &snapshot, error, error_len) != 0 ||
        wvm_cluster_snapshot_apply_host_constraints(
            records, &snapshot, &request->host_constraints, &constrained_snapshot,
            error, error_len) != 0 ||
        route_is_prepared_for_transaction(transaction, prepared_route,
                                          &constrained_snapshot, error,
                                          error_len) != 0 ||
        wvm_admission_plan_validate(&constrained_snapshot.admission,
                                    &prepared_vm->admission_request,
                                    &prepared_vm->admission_plan, error,
                                    error_len) != 0 ||
        wvm_cluster_admission_fence_build(
            records, &constrained_snapshot, &prepared_vm->admission_request,
            &prepared_vm->admission_plan, &transaction->route_scope_key,
            prepared_route->required_ack_set, &current_fence, error,
            error_len) != 0) {
        goto out;
    }
    if (memcmp(current_fence.fence_digest, prepared_vm->fence.fence_digest,
               sizeof(current_fence.fence_digest)) != 0) {
        set_error(error, error_len,
                  "prepared admission eligibility fence is stale");
        goto out;
    }
    result = 0;

out:
    free(selected_members);
    wvm_admission_snapshot_cleanup(&constrained_snapshot.admission);
    wvm_admission_snapshot_cleanup(&snapshot.admission);
    return result;
}

static int activation_matches_prepared(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    uint8_t participant_set_digest[WVM_SHA256_DIGEST_BYTES];

    if (!transaction || !prepared_vm || !activation ||
        wvm_activation_record_validate(activation, error, error_len) != 0 ||
        activation->decision != WVM_ACTIVATION_ACTIVATE ||
        activation->required_route_snapshot_count != 1 ||
        memcmp(activation->admission_tx_id, transaction->admission_tx_id,
               sizeof(activation->admission_tx_id)) != 0 ||
        memcmp(activation->candidate_manifest_digest,
               prepared_vm->candidate_manifest_digest,
               sizeof(activation->candidate_manifest_digest)) != 0 ||
        !route_snapshot_key_equal(
            &activation->required_route_snapshot_keys[0],
            &prepared_vm->candidate.prepared_route_snapshot_key) ||
        required_participant_set_digest(&prepared_vm->fence,
                                        participant_set_digest, error,
                                        error_len) != 0 ||
        memcmp(activation->required_participant_set_digest,
               participant_set_digest, sizeof(participant_set_digest)) != 0) {
        set_error(error, error_len, "activation does not match prepared VM");
        return -1;
    }
    return 0;
}

static int abort_matches_prepared(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    uint8_t participant_set_digest[WVM_SHA256_DIGEST_BYTES];

    if (!transaction || !prepared_vm || !activation ||
        wvm_activation_record_validate(activation, error, error_len) != 0 ||
        activation->decision != WVM_ACTIVATION_ABORT ||
        activation->has_activation_fence ||
        activation->required_route_snapshot_count != 1 ||
        memcmp(activation->admission_tx_id, transaction->admission_tx_id,
               sizeof(activation->admission_tx_id)) != 0 ||
        memcmp(activation->candidate_manifest_digest,
               prepared_vm->candidate_manifest_digest,
               sizeof(activation->candidate_manifest_digest)) != 0 ||
        !route_snapshot_key_equal(
            &activation->required_route_snapshot_keys[0],
            &prepared_vm->candidate.prepared_route_snapshot_key) ||
        required_participant_set_digest(&prepared_vm->fence,
                                        participant_set_digest, error,
                                        error_len) != 0 ||
        memcmp(activation->required_participant_set_digest,
               participant_set_digest, sizeof(participant_set_digest)) != 0) {
        set_error(error, error_len, "abort does not match prepared VM");
        return -1;
    }
    return 0;
}

static void clear_prepared_runtime(
    struct wvm_node_runtime_manifest *runtime_manifest)
{
    struct wvm_vcpu_assignment_list vcpus =
        runtime_manifest->local_vcpu_assignments;
    struct wvm_memory_chunk_assignment_list memory =
        runtime_manifest->local_memory_assignments;
    struct wvm_storage_assignment_list storage =
        runtime_manifest->local_storage_assignments;
    struct wvm_startup_dependency_list dependencies =
        runtime_manifest->startup_dependencies;

    memset(runtime_manifest, 0, sizeof(*runtime_manifest));
    runtime_manifest->local_vcpu_assignments = vcpus;
    runtime_manifest->local_memory_assignments = memory;
    runtime_manifest->local_storage_assignments = storage;
    runtime_manifest->startup_dependencies = dependencies;
}

int wvm_coordinator_begin(
    const struct wvm_vm_request *request,
    struct wvm_vm_namespace_allocator *namespace_allocator,
    const struct wvm_coordinator_id_provider *id_provider,
    struct wvm_coordinator_transaction *transaction, char *error,
    size_t error_len)
{
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t route_scope_id;

    if (!request || !namespace_allocator || !id_provider ||
        !id_provider->allocate_id16 || !id_provider->allocate_route_scope_id ||
        !transaction ||
        wvm_vm_request_validate(request, error, error_len) != 0 ||
        wvm_vm_namespace_allocate(namespace_allocator,
                                  WVM_NAMESPACE_ABI_U32, &vm_id,
                                  &vm_incarnation, error, error_len) != 0 ||
        id_provider->allocate_id16(id_provider->context,
                                   WVM_COORDINATOR_ID_ADMISSION_TX,
                                   transaction->admission_tx_id, error,
                                   error_len) != 0 ||
        id_provider->allocate_id16(id_provider->context,
                                   WVM_COORDINATOR_ID_MANIFEST,
                                   transaction->manifest_id, error,
                                   error_len) != 0 ||
        id_provider->allocate_route_scope_id(id_provider->context,
                                             &route_scope_id, error,
                                             error_len) != 0 ||
        bytes_are_zero(transaction->admission_tx_id,
                       sizeof(transaction->admission_tx_id)) ||
        bytes_are_zero(transaction->manifest_id,
                       sizeof(transaction->manifest_id)) ||
        route_scope_id == 0) {
        set_error(error, error_len, "cannot begin VM admission transaction");
        return -1;
    }
    memcpy(transaction->request_id, request->request_id,
           sizeof(transaction->request_id));
    transaction->vm_id = vm_id;
    transaction->vm_incarnation = vm_incarnation;
    transaction->manifest_generation = 1;
    transaction->route_scope_key.vm_id = vm_id;
    transaction->route_scope_key.vm_incarnation = vm_incarnation;
    transaction->route_scope_key.route_scope_id = route_scope_id;
    return 0;
}

void wvm_coordinator_prepared_vm_cleanup(
    struct wvm_coordinator_prepared_vm *prepared_vm)
{
    if (!prepared_vm) {
        return;
    }
    wvm_admission_snapshot_cleanup(&prepared_vm->cluster_snapshot.admission);
    free(prepared_vm->admission_plan.reservations);
    memset(&prepared_vm->cluster_snapshot, 0,
           sizeof(prepared_vm->cluster_snapshot));
    memset(&prepared_vm->admission_plan, 0, sizeof(prepared_vm->admission_plan));
}

int wvm_coordinator_prepare(
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_coordinator_prepare_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm, char *error,
    size_t error_len)
{
    struct wvm_cluster_snapshot constrained_snapshot = {0};
    struct wvm_admission_request admission_request;
    struct wvm_admission_placement_options placement_options;
    struct wvm_candidate_vm_manifest candidate;
    struct wvm_capability_ref_list required_capabilities;
    struct wvm_local_name_identity local_name_identity;
    uint8_t placement_digest[WVM_SHA256_DIGEST_BYTES];
    size_t i;
    int result = -1;

    if (!request || !transaction || !records || !options || !prepared_vm ||
        wvm_vm_request_validate(request, error, error_len) != 0 ||
        memcmp(request->request_id, transaction->request_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        transaction->vm_id == 0 || transaction->vm_incarnation == 0 ||
        transaction->manifest_generation != 1 ||
        bytes_are_zero(transaction->admission_tx_id,
                       sizeof(transaction->admission_tx_id)) ||
        bytes_are_zero(transaction->manifest_id, sizeof(transaction->manifest_id)) ||
        wvm_vm_route_scope_key_validate(&transaction->route_scope_key, error,
                                        error_len) != 0 ||
        /* Keep remote storage closed until identity, replay, ordering and
         * persistence are verified across the complete typed execution path. */
        request->storage_device_plan.assignments.count != 0 ||
        wvm_machine_config_validate(&options->guest_machine, error,
                                    error_len) != 0 ||
        wvm_execution_fault_profile_validate(&options->execution_profile, error,
                                             error_len) != 0 ||
        wvm_fault_engine_profile_validate(&options->execution_profile, error,
                                          error_len) != 0 ||
        !request_allows_backend(request, options->execution_profile.backend) ||
        options->memory_chunk_bytes == 0 ||
        options->memory_chunk_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        options->host_overhead_memory_bytes % WVM_MANIFEST_PAGE_BYTES != 0 ||
        (options->host_overhead_vcpu_slots == 0 &&
         options->host_overhead_memory_bytes == 0) ||
        options->memory_consistency_policy == 0 ||
        options->executor_class == 0 || options->node_runtime_role_bits == 0 ||
        options->candidate_created_at == 0 ||
        options->prepared_reservation_expiry_unix_time_ms == 0 ||
        !options->node_launch_plans || options->node_launch_plan_count == 0 ||
        !options->node_listener_plans || options->node_listener_plan_count == 0 ||
        !options->placement_plan_bytes ||
        options->placement_plan_bytes_capacity == 0 ||
        !options->candidate_manifest_bytes ||
        options->candidate_manifest_bytes_capacity == 0 ||
        !prepared_vm->reservations ||
        prepared_vm->reservation_capacity == 0 ||
        !prepared_vm->node_runtime_manifests ||
        prepared_vm->node_runtime_manifest_capacity == 0) {
        set_error(error, error_len, "coordinator prepare input is invalid");
        return -1;
    }
    if ((request->accelerator_policy == WVM_MANIFEST_ACCELERATOR_DISABLED &&
         options->execution_profile.kernel_accelerator_bits != 0) ||
        (request->accelerator_policy ==
             WVM_MANIFEST_ACCELERATOR_REQUIRE_KERNEL &&
         options->execution_profile.kernel_accelerator_bits == 0)) {
        set_error(error, error_len,
                  "resolved accelerator profile violates request policy");
        return -1;
    }
    wvm_coordinator_prepared_vm_cleanup(prepared_vm);
    memset(&admission_request, 0, sizeof(admission_request));
    if (build_admission_request(request, transaction, options,
                                &admission_request, error, error_len) != 0 ||
        wvm_cluster_snapshot_build(records, &prepared_vm->cluster_snapshot,
                                   error, error_len) != 0 ||
        wvm_cluster_snapshot_apply_host_constraints(
            records, &prepared_vm->cluster_snapshot, &request->host_constraints,
            &constrained_snapshot, error, error_len) != 0 ||
        route_is_prepared_for_transaction(transaction, prepared_route,
                                          &constrained_snapshot, error,
                                          error_len) != 0) {
        goto out;
    }

    if (wvm_admission_plan_propose(&constrained_snapshot.admission,
                                   &admission_request,
                                   transaction->admission_tx_id,
                                   &prepared_vm->admission_plan, error,
                                   error_len) != 0 ||
        wvm_cluster_admission_fence_build(
            records, &constrained_snapshot, &admission_request,
            &prepared_vm->admission_plan, &transaction->route_scope_key,
            prepared_route->required_ack_set, &prepared_vm->fence, error,
            error_len) != 0) {
        goto out;
    }

    memset(&placement_options, 0, sizeof(placement_options));
    placement_options.memory_consistency_policy =
        options->memory_consistency_policy;
    placement_options.guest_topology_policy = request->guest_topology_policy;
    placement_options.guest_numa_nodes =
        request->guest_topology_policy == WVM_MANIFEST_GUEST_TOPOLOGY_FLAT
            ? 1
            : options->guest_numa_nodes;
    placement_options.executor_class = options->executor_class;
    placement_options.kernel_accelerator_required =
        options->execution_profile.kernel_accelerator_bits != 0;
    placement_options.route_scope_key = transaction->route_scope_key;
    placement_options.listener_plans = options->node_listener_plans;
    placement_options.listener_plan_count = options->node_listener_plan_count;
    if (wvm_admission_placement_plan_build(
            &constrained_snapshot.admission, &admission_request,
            &prepared_vm->admission_plan, prepared_vm->fence.fence_digest,
            &placement_options, &prepared_vm->placement_plan, error,
            error_len) != 0 ||
        wvm_placement_plan_encode(
            &prepared_vm->placement_plan, options->placement_plan_bytes,
            options->placement_plan_bytes_capacity,
            &prepared_vm->placement_plan_bytes, placement_digest, error,
            error_len) != 0) {
        goto out;
    }
    memcpy(prepared_vm->placement_plan.plan_digest, placement_digest,
           sizeof(prepared_vm->placement_plan.plan_digest));

    required_capabilities = prepared_vm->candidate.required_capabilities;
    if (!required_capabilities.entries || required_capabilities.capacity == 0) {
        set_error(error, error_len, "candidate capability output is missing");
        goto out;
    }
    required_capabilities.count = 0;
    for (i = 0; i < prepared_vm->fence.selected_members.count; i++) {
        const struct wvm_capability_ref *capability =
            &prepared_vm->fence.selected_members.entries[i].capability;

        if (!find_available_capability(records, capability,
                                       WVM_CAPABILITY_ID_VM_ID_U32) ||
            append_required_capability(&required_capabilities, capability,
                                       error, error_len) != 0) {
            set_error(error, error_len,
                      "selected member lacks required V1 namespace capability");
            goto out;
        }
    }

    memset(&candidate, 0, sizeof(candidate));
    candidate.required_capabilities = required_capabilities;
    memcpy(candidate.manifest_id, transaction->manifest_id,
           sizeof(candidate.manifest_id));
    candidate.manifest_schema_version = WVM_CANONICAL_SCHEMA;
    candidate.vm_id = transaction->vm_id;
    candidate.vm_incarnation = transaction->vm_incarnation;
    candidate.manifest_generation = transaction->manifest_generation;
    memcpy(candidate.request_id, request->request_id, sizeof(candidate.request_id));
    memcpy(candidate.admission_tx_id, transaction->admission_tx_id,
           sizeof(candidate.admission_tx_id));
    memcpy(candidate.eligibility_fence_digest, prepared_vm->fence.fence_digest,
           sizeof(candidate.eligibility_fence_digest));
    candidate.candidate_created_at = options->candidate_created_at;
    candidate.guest_machine = options->guest_machine;
    candidate.guest_topology = prepared_vm->placement_plan.guest_topology;
    candidate.execution_plan = options->execution_profile;
    candidate.execution_plan.per_node_capabilities = required_capabilities;
    candidate.consistency_policy = request->consistency_policy;
    candidate.storage_device_plan = request->storage_device_plan;
    candidate.storage_device_plan.assignments =
        prepared_vm->placement_plan.storage_assignments;
    candidate.host_node = prepared_vm->placement_plan.host_node;
    candidate.vcpu_placements = prepared_vm->placement_plan.vcpu_assignments;
    candidate.memory_placements = prepared_vm->placement_plan.memory_assignments;
    candidate.required_members = prepared_vm->fence.selected_members;
    candidate.reservation_requirements =
        prepared_vm->placement_plan.reservation_requirements;
    candidate.route_scope_key = transaction->route_scope_key;
    candidate.prepared_route_snapshot_key = prepared_route->route_snapshot_key;
    memcpy(candidate.plan_digest, prepared_vm->placement_plan.plan_digest,
           sizeof(candidate.plan_digest));
    candidate.lifecycle_policy = request->lifecycle_policy;
    candidate.namespace_abi = WVM_MANIFEST_NAMESPACE_U32;
    memset(&local_name_identity, 0, sizeof(local_name_identity));
    local_name_identity.vm_id = candidate.vm_id;
    local_name_identity.vm_incarnation = candidate.vm_incarnation;
    local_name_identity.manifest_generation = candidate.manifest_generation;
    local_name_identity.physical_node_id = candidate.host_node;
    memcpy(local_name_identity.manifest_id, candidate.manifest_id,
           sizeof(local_name_identity.manifest_id));
    memcpy(local_name_identity.admission_tx_id, candidate.admission_tx_id,
           sizeof(local_name_identity.admission_tx_id));
    if (wvm_local_name_namespace_derive(&local_name_identity,
                                        &candidate.local_name_namespace, error,
                                        error_len) != 0 ||
        wvm_candidate_vm_manifest_encode(
            &candidate, options->candidate_manifest_bytes,
            options->candidate_manifest_bytes_capacity,
            &prepared_vm->candidate_manifest_bytes,
            prepared_vm->candidate_manifest_digest, error, error_len) != 0) {
        goto out;
    }
    memcpy(candidate.manifest_digest, prepared_vm->candidate_manifest_digest,
           sizeof(candidate.manifest_digest));
    if (wvm_candidate_vm_manifest_matches_plan(&candidate,
                                                &prepared_vm->placement_plan,
                                                error, error_len) != 0 ||
        prepared_vm->reservation_capacity <
            candidate.reservation_requirements.count ||
        prepared_vm->node_runtime_manifest_capacity <
            candidate.reservation_requirements.count) {
        set_error(error, error_len, "prepared VM output buffers are too small");
        goto out;
    }

    prepared_vm->reservation_count = 0;
    prepared_vm->node_runtime_manifest_count = 0;
    for (i = 0; i < candidate.reservation_requirements.count; i++) {
        struct wvm_resource_reservation *reservation =
            &prepared_vm->reservations[prepared_vm->reservation_count];
        struct wvm_node_runtime_manifest *runtime_manifest =
            &prepared_vm->node_runtime_manifests[
                prepared_vm->node_runtime_manifest_count];
        const struct wvm_coordinator_node_launch_plan *launch_plan;
        uint64_t local_role_bits = options->node_runtime_role_bits;

        if (candidate.reservation_requirements.entries[i].physical_node_id ==
            candidate.host_node) {
            local_role_bits |= options->host_extra_role_bits;
        }
        launch_plan = find_node_launch_plan(
            options,
            candidate.reservation_requirements.entries[i].physical_node_id,
            candidate.reservation_requirements.entries[i].node_instance_id);
        if (!launch_plan ||
            wvm_node_runtime_launch_plan_validate(&launch_plan->launch_plan,
                                                  error, error_len) != 0 ||
            !launch_plan_matches_request(&launch_plan->launch_plan, request,
                                         &options->guest_machine)) {
            set_error(error, error_len,
                      "coordinator node launch plan is invalid or mismatched");
            abort_registered_reservations(prepared_vm);
            goto out;
        }
        if (wvm_resource_reservation_derive(
                &candidate.reservation_requirements.entries[i], &candidate,
                prepared_vm->candidate_manifest_digest, reservation,
                options->prepared_reservation_expiry_unix_time_ms, error,
                error_len) != 0 ||
            wvm_node_runtime_manifest_project(
                &candidate, prepared_vm->candidate_manifest_digest, reservation,
                NULL, &launch_plan->launch_plan, local_role_bits,
                runtime_manifest, error, error_len) !=
                0 ||
            fill_startup_dependencies(&candidate, runtime_manifest, error,
                                      error_len) != 0 ||
            wvm_node_runtime_manifest_validate(runtime_manifest, error,
                                               error_len) != 0) {
            abort_registered_reservations(prepared_vm);
            goto out;
        }
        if (prepared_vm->reservation_registries) {
            struct wvm_local_reservation_registry *registry;

            if (reservation_registry_for(prepared_vm, reservation, &registry,
                                         error, error_len) != 0 ||
                wvm_local_reservation_prepare(registry, reservation, NULL,
                                              error, error_len) != 0) {
                abort_registered_reservations(prepared_vm);
                goto out;
            }
        }
        prepared_vm->reservation_count++;
        prepared_vm->node_runtime_manifest_count++;
    }
    prepared_vm->admission_request = admission_request;
    prepared_vm->candidate = candidate;
    prepared_vm->candidate_manifest_record = options->candidate_manifest_bytes;
    prepared_vm->candidate_manifest_record_capacity =
        options->candidate_manifest_bytes_capacity;
    result = 0;
out:
    wvm_admission_snapshot_cleanup(&constrained_snapshot.admission);
    if (result != 0) {
        wvm_coordinator_prepared_vm_cleanup(prepared_vm);
    }
    return result;
}

int wvm_coordinator_decide_activation(
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_prepared_route *prepared_route,
    const struct wvm_coordinator_id_provider *id_provider,
    const struct wvm_coordinator_activation_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_activation_record *activation, char *error, size_t error_len)
{
    uint8_t activation_fence[WVM_IDENTITY_ID_BYTES];
    uint8_t participant_set_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_route_snapshot_key *route_snapshot_keys;
    size_t route_snapshot_capacity;

    if (!request || !transaction || !records || !prepared_route || !id_provider ||
        !id_provider->allocate_id16 || !options || !prepared_vm || !activation ||
        wvm_vm_request_validate(request, error, error_len) != 0 ||
        memcmp(request->request_id, transaction->request_id,
               sizeof(transaction->request_id)) != 0 ||
        options->coordinator_instance_id == 0 ||
        options->durable_decision_sequence == 0 || options->decided_at == 0 ||
        prepared_candidate_validate(transaction, prepared_vm, error,
                                   error_len) != 0 ||
        current_fence_matches(request, transaction, records, prepared_route,
                              prepared_vm, error, error_len) != 0 ||
        required_participant_set_digest(&prepared_vm->fence,
                                        participant_set_digest, error,
                                        error_len) != 0) {
        set_error(error, error_len, "cannot decide activation");
        return -1;
    }

    route_snapshot_keys = activation->required_route_snapshot_keys;
    route_snapshot_capacity = activation->required_route_snapshot_capacity;
    if (!route_snapshot_keys || route_snapshot_capacity == 0 ||
        id_provider->allocate_id16(
            id_provider->context, WVM_COORDINATOR_ID_ACTIVATION_FENCE,
            activation_fence, error, error_len) != 0 ||
        bytes_are_zero(activation_fence, sizeof(activation_fence))) {
        set_error(error, error_len, "cannot allocate activation fence");
        return -1;
    }
    route_snapshot_keys[0] = prepared_vm->candidate.prepared_route_snapshot_key;
    return wvm_activation_record_decide(
        activation, &prepared_vm->candidate,
        prepared_vm->candidate_manifest_digest, activation_fence,
        options->coordinator_instance_id, participant_set_digest,
        route_snapshot_keys, 1, route_snapshot_capacity,
        WVM_ACTIVATION_ACTIVATE, options->durable_decision_sequence,
        options->decided_at, error, error_len);
}


int wvm_coordinator_commit_local(
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    size_t i;

    if (!transaction || !prepared_vm ||
        prepared_candidate_validate(transaction, prepared_vm, error,
                                   error_len) != 0 ||
        activation_matches_prepared(transaction, prepared_vm, activation, error,
                                    error_len) != 0 ||
        prepared_vm->node_runtime_manifest_count !=
            prepared_vm->reservation_count ||
        !prepared_vm->node_runtime_manifests) {
        set_error(error, error_len, "cannot commit prepared VM locally");
        return -1;
    }

    for (i = 0; i < prepared_vm->reservation_count; i++) {
        const struct wvm_resource_reservation *reservation =
            &prepared_vm->reservations[i];
        const struct wvm_node_runtime_manifest *runtime_manifest =
            &prepared_vm->node_runtime_manifests[i];

        if ((reservation->state != WVM_RESERVATION_PREPARED &&
             !reservation_matches_activation(reservation, activation)) ||
            runtime_manifest->physical_node_id !=
                reservation->physical_node_id ||
            runtime_manifest->expected_node_instance_id !=
                reservation->node_instance_id ||
            runtime_manifest->local_role_bits == 0 ||
            runtime_manifest->local_vcpu_assignments.capacity <
                prepared_vm->candidate.vcpu_placements.count ||
            runtime_manifest->local_memory_assignments.capacity <
                prepared_vm->candidate.memory_placements.count ||
            runtime_manifest->local_storage_assignments.capacity <
                prepared_vm->candidate.storage_device_plan.assignments.count ||
            prepared_vm->candidate.required_members.count >
                runtime_manifest->startup_dependencies.capacity + 1U) {
            set_error(error, error_len,
                      "local runtime projection cannot be committed");
            return -1;
        }
        if (prepared_vm->reservation_registries) {
            struct wvm_local_reservation_registry *registry;

            if (reservation_registry_for(prepared_vm, reservation, &registry,
                                         error, error_len) != 0) {
                return -1;
            }
        }
    }

    for (i = 0; i < prepared_vm->reservation_count; i++) {
        struct wvm_resource_reservation *reservation =
            &prepared_vm->reservations[i];
        struct wvm_node_runtime_manifest *runtime_manifest =
            &prepared_vm->node_runtime_manifests[i];
        const uint64_t local_role_bits = runtime_manifest->local_role_bits;
        struct wvm_local_reservation_registry *registry = NULL;

        if (reservation_registry_for(prepared_vm, reservation, &registry, error,
                                     error_len) != 0 ||
            (registry && wvm_local_reservation_commit(
                             registry, reservation, activation,
                             NULL, error, error_len) != 0) ||
            commit_derived_reservation(reservation, activation, error,
                                       error_len) != 0 ||
            wvm_node_runtime_manifest_project(
                &prepared_vm->candidate,
                prepared_vm->candidate_manifest_digest, reservation, activation,
                NULL, local_role_bits, runtime_manifest, error, error_len) !=
                0 ||
            fill_startup_dependencies(&prepared_vm->candidate, runtime_manifest,
                                      error, error_len) != 0 ||
            wvm_node_runtime_manifest_validate(runtime_manifest, error,
                                               error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

int wvm_coordinator_decide_abort(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_coordinator_activation_options *options,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_activation_record *activation, char *error, size_t error_len)
{
    uint8_t participant_set_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_route_snapshot_key *route_snapshot_keys;
    size_t route_snapshot_capacity;

    if (!transaction || !options || !prepared_vm || !activation ||
        options->coordinator_instance_id == 0 ||
        options->durable_decision_sequence == 0 || options->decided_at == 0 ||
        prepared_candidate_validate(transaction, prepared_vm, error,
                                   error_len) != 0 ||
        required_participant_set_digest(&prepared_vm->fence,
                                        participant_set_digest, error,
                                        error_len) != 0) {
        set_error(error, error_len, "cannot decide abort");
        return -1;
    }
    route_snapshot_keys = activation->required_route_snapshot_keys;
    route_snapshot_capacity = activation->required_route_snapshot_capacity;
    if (!route_snapshot_keys || route_snapshot_capacity == 0) {
        set_error(error, error_len, "abort route snapshot output is missing");
        return -1;
    }
    route_snapshot_keys[0] = prepared_vm->candidate.prepared_route_snapshot_key;
    return wvm_activation_record_decide(
        activation, &prepared_vm->candidate,
        prepared_vm->candidate_manifest_digest, NULL,
        options->coordinator_instance_id, participant_set_digest,
        route_snapshot_keys, 1, route_snapshot_capacity,
        WVM_ACTIVATION_ABORT, options->durable_decision_sequence,
        options->decided_at, error, error_len);
}

int wvm_coordinator_validate_abort(
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    size_t i;

    if (!transaction || !prepared_vm ||
        prepared_candidate_validate(transaction, prepared_vm, error,
                                   error_len) != 0 ||
        abort_matches_prepared(transaction, prepared_vm, activation, error,
                               error_len) != 0 ||
        prepared_vm->node_runtime_manifest_count !=
            prepared_vm->reservation_count ||
        !prepared_vm->node_runtime_manifests) {
        set_error(error, error_len, "cannot abort prepared VM locally");
        return -1;
    }
    for (i = 0; i < prepared_vm->reservation_count; i++) {
        struct wvm_resource_reservation *reservation =
            &prepared_vm->reservations[i];

        if (reservation->state != WVM_RESERVATION_PREPARED &&
            reservation->state != WVM_RESERVATION_RELEASED) {
            set_error(error, error_len,
                      "abort can release only pre-activation reservations");
            return -1;
        }
        if (prepared_vm->reservation_registries) {
            struct wvm_local_reservation_registry *registry;

            if (reservation_registry_for(prepared_vm, reservation, &registry,
                                         error, error_len) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

int wvm_coordinator_abort_local(
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    size_t i;

    if (wvm_coordinator_validate_abort(transaction, prepared_vm, activation,
                                       error, error_len) != 0) {
        return -1;
    }
    for (i = 0; i < prepared_vm->reservation_count; i++) {
        struct wvm_resource_reservation *reservation =
            &prepared_vm->reservations[i];
        struct wvm_local_reservation_registry *registry = NULL;

        if (reservation_registry_for(prepared_vm, reservation, &registry, error,
                                     error_len) != 0 ||
            (registry && wvm_local_reservation_abort(
                             registry, reservation, NULL, error,
                             error_len) != 0) ||
            release_derived_reservation(reservation, error, error_len) != 0) {
            return -1;
        }
        clear_prepared_runtime(&prepared_vm->node_runtime_manifests[i]);
    }
    return 0;
}

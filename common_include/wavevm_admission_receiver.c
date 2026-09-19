#include "wavevm_admission_receiver.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_envelope.h"

typedef int (*canonical_encode_fn)(const void *record, uint8_t *bytes,
                                   size_t capacity, size_t *encoded_bytes,
                                   char *error, size_t error_len);

static void set_error(char *error, size_t error_len, const char *format, ...)
{
    va_list arguments;

    if (!error || error_len == 0) {
        return;
    }
    va_start(arguments, format);
    vsnprintf(error, error_len, format, arguments);
    va_end(arguments);
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
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

static int route_metadata_is_empty(const struct wvm_envelope *request)
{
    return request && request->route.destination_kind == 0 &&
           request->route.destination_scope == 0 &&
           request->route.destination_vnode_or_endpoint == 0 &&
           request->route.hop_limit == 0 && request->route.hop_count == 0;
}

static int envelope_matches_route_key(
    const struct wvm_envelope *request,
    const struct wvm_route_snapshot_key *route_key)
{
    return request && route_key && route_metadata_is_empty(request) &&
           request->vm_id == route_key->scope_key.vm_id &&
           request->vm_incarnation == route_key->scope_key.vm_incarnation &&
           request->route_scope_id == route_key->scope_key.route_scope_id &&
           request->topology_revision == route_key->topology_revision &&
           request->route_generation == route_key->route_generation &&
           memcmp(request->route_snapshot_digest, route_key->snapshot_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int encode_candidate(const void *record, uint8_t *bytes,
                            size_t capacity, size_t *encoded_bytes,
                            char *error, size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    return wvm_candidate_vm_manifest_encode(record, bytes, capacity,
                                            encoded_bytes, digest, error,
                                            error_len);
}

static int encode_runtime_manifest(const void *record, uint8_t *bytes,
                                   size_t capacity, size_t *encoded_bytes,
                                   char *error, size_t error_len)
{
    return wvm_node_runtime_manifest_encode(record, bytes, capacity,
                                            encoded_bytes, error, error_len);
}

static int encode_activation(const void *record, uint8_t *bytes,
                              size_t capacity, size_t *encoded_bytes,
                              char *error, size_t error_len)
{
    return wvm_activation_record_encode(record, bytes, capacity, encoded_bytes,
                                         error, error_len);
}

static int canonical_equal(canonical_encode_fn encode, const void *left,
                           const void *right, char *error, size_t error_len)
{
    size_t capacity = 4096U;

    while (capacity <= WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
        uint8_t *left_bytes = malloc(capacity);
        uint8_t *right_bytes = malloc(capacity);
        size_t left_count = 0;
        size_t right_count = 0;
        int equal;

        if (!left_bytes || !right_bytes) {
            free(left_bytes);
            free(right_bytes);
            set_error(error, error_len,
                      "cannot allocate canonical admission comparison");
            return -1;
        }
        if (encode(left, left_bytes, capacity, &left_count, error, error_len) ==
                0 &&
            encode(right, right_bytes, capacity, &right_count, error,
                   error_len) == 0) {
            equal = left_count == right_count &&
                    memcmp(left_bytes, right_bytes, left_count) == 0;
            free(right_bytes);
            free(left_bytes);
            return equal;
        }
        free(right_bytes);
        free(left_bytes);
        if (capacity == WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
            capacity = WVM_ENVELOPE_MAX_LOCAL_PAYLOAD;
        }
    }
    set_error(error, error_len, "canonical admission record exceeds receiver limit");
    return -1;
}

static int runtime_projection_equal(
    const struct wvm_node_runtime_manifest *left,
    const struct wvm_node_runtime_manifest *right, int ignore_activation_fence,
    char *error, size_t error_len)
{
    struct wvm_node_runtime_manifest normalized_left;
    struct wvm_node_runtime_manifest normalized_right;

    if (!left || !right) {
        return -1;
    }
    normalized_left = *left;
    normalized_right = *right;
    if (ignore_activation_fence) {
        normalized_left.has_activation_fence = 0;
        normalized_right.has_activation_fence = 0;
        memset(normalized_left.activation_fence, 0,
               sizeof(normalized_left.activation_fence));
        memset(normalized_right.activation_fence, 0,
               sizeof(normalized_right.activation_fence));
    }
    return canonical_equal(encode_runtime_manifest, &normalized_left,
                           &normalized_right, error, error_len);
}

static int stage_message_type(uint16_t message_type)
{
    switch (message_type) {
    case WVM_ENVELOPE_MSG_PREPARE_RESERVATION:
    case WVM_ENVELOPE_MSG_COMMIT_RESERVATION:
    case WVM_ENVELOPE_MSG_ABORT_RESERVATION:
    case WVM_ENVELOPE_MSG_PREPARE_MANIFEST:
    case WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST:
    case WVM_ENVELOPE_MSG_ABORT_MANIFEST:
    case WVM_ENVELOPE_MSG_ROUTE_PREPARE:
    case WVM_ENVELOPE_MSG_ROUTE_COMMIT:
    case WVM_ENVELOPE_MSG_ROUTE_ABORT:
    case WVM_ENVELOPE_MSG_ROUTE_RETIRE:
        return 1;
    default:
        return 0;
    }
}

static void result_init(struct wvm_control_result *result,
                        const struct wvm_envelope *request)
{
    memset(result, 0, sizeof(*result));
    memcpy(result->in_reply_to_operation_id, request->operation_id,
           sizeof(result->in_reply_to_operation_id));
    memcpy(result->record_digest, request->semantic_payload_digest,
           sizeof(result->record_digest));
    result->vm_id = request->vm_id;
    result->vm_incarnation = request->vm_incarnation;
    result->manifest_generation = request->manifest_generation;
    result->route_scope_id = request->route_scope_id;
}

static void result_bind_candidate(
    struct wvm_control_result *result,
    const struct wvm_candidate_vm_manifest *candidate)
{
    if (!result || !candidate) {
        return;
    }
    result->vm_id = candidate->vm_id;
    result->vm_incarnation = candidate->vm_incarnation;
    result->manifest_generation = candidate->manifest_generation;
    memcpy(result->admission_tx_id, candidate->admission_tx_id,
           sizeof(result->admission_tx_id));
    memcpy(result->manifest_id, candidate->manifest_id,
           sizeof(result->manifest_id));
    result->route_scope_id = candidate->route_scope_key.route_scope_id;
}

static int receiver_config_valid(const struct wvm_admission_receiver *receiver)
{
    const struct wvm_admission_receiver_config *config;

    if (!receiver || !receiver->initialized) {
        return 0;
    }
    config = &receiver->config;
    return wvm_member_key_validate(&config->controller_member_key, NULL, 0) ==
               0 &&
           config->controller_physical_node_id != 0 &&
           config->controller_runtime_instance_id != 0 &&
           config->local_physical_node_id != 0 &&
           config->local_node_instance_id != 0;
}

static int controller_matches(const struct wvm_admission_receiver *receiver,
                              const struct wvm_envelope *request,
                              const struct wvm_member_key *actor)
{
    return receiver && request && actor &&
           member_key_equal(actor, &receiver->config.controller_member_key) &&
           request->origin_physical_node_id ==
               receiver->config.controller_physical_node_id &&
           request->origin_runtime_instance_id ==
               receiver->config.controller_runtime_instance_id;
}

static int candidate_matches_request(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_envelope *request)
{
    return candidate && request && candidate->vm_id == request->vm_id &&
           candidate->vm_incarnation == request->vm_incarnation &&
           candidate->manifest_generation == request->manifest_generation &&
           envelope_matches_route_key(request,
                                      &candidate->prepared_route_snapshot_key);
}

static int reservation_matches_requirement(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation)
{
    const struct wvm_reservation_requirement *requirement = NULL;
    size_t i;

    if (!candidate || !reservation ||
        candidate->vm_id != reservation->vm_id ||
        candidate->vm_incarnation != reservation->vm_incarnation ||
        memcmp(candidate->admission_tx_id, reservation->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(candidate->manifest_digest, reservation->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        memcmp(candidate->eligibility_fence_digest,
               reservation->eligibility_fence_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        return 0;
    }
    for (i = 0; i < candidate->reservation_requirements.count; i++) {
        const struct wvm_reservation_requirement *current =
            &candidate->reservation_requirements.entries[i];

        if (current->physical_node_id == reservation->physical_node_id &&
            current->node_instance_id == reservation->node_instance_id) {
            if (requirement) {
                return 0;
            }
            requirement = current;
        }
    }
    if (!requirement ||
        memcmp(requirement->reservation_id, reservation->reservation_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        requirement->inventory_revision != reservation->inventory_revision ||
        requirement->guest_vcpu_slots != reservation->guest_vcpu_slots ||
        requirement->guest_memory_bytes != reservation->guest_memory_bytes ||
        requirement->overhead_vcpu_slots != reservation->overhead_vcpu_slots ||
        requirement->overhead_memory_bytes != reservation->overhead_memory_bytes ||
        requirement->exclusive_leases.count !=
            reservation->exclusive_leases.count) {
        return 0;
    }
    for (i = 0; i < requirement->exclusive_leases.count; i++) {
        const struct wvm_exclusive_lease *left =
            &requirement->exclusive_leases.entries[i];
        const struct wvm_exclusive_lease *right =
            &reservation->exclusive_leases.entries[i];

        if (left->lease_kind != right->lease_kind ||
            left->lease_generation != right->lease_generation ||
            strcmp(left->lease_name, right->lease_name) != 0) {
            return 0;
        }
    }
    return 1;
}

static int activation_matches_route(
    const struct wvm_activation_record *activation,
    const struct wvm_candidate_vm_manifest *candidate)
{
    size_t i;

    if (!activation || !candidate || !activation->has_activation_fence ||
        activation->decision != WVM_ACTIVATION_ACTIVATE ||
        memcmp(activation->admission_tx_id, candidate->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(activation->candidate_manifest_digest, candidate->manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        return 0;
    }
    for (i = 0; i < activation->required_route_snapshot_count; i++) {
        if (route_key_equal(&activation->required_route_snapshot_keys[i],
                            &candidate->prepared_route_snapshot_key)) {
            return 1;
        }
    }
    return 0;
}

static int resolve_slot(struct wvm_admission_receiver *receiver,
                        const struct wvm_envelope *request,
                        struct wvm_admission_receiver_slot **slot_out,
                        char *error, size_t error_len)
{
    struct wvm_admission_receiver_slot *slot = NULL;

    if (!receiver || !request || !slot_out || !receiver->config.resolve_slot ||
        receiver->config.resolve_slot(receiver->config.context, request->vm_id,
                                      request->vm_incarnation,
                                      request->manifest_generation, &slot, error,
                                      error_len) != 0 ||
        !slot || !slot->runtime_manifest_path ||
        slot->runtime_manifest_path[0] == '\0') {
        set_error(error, error_len, "local runtime slot is unavailable");
        return -1;
    }
    *slot_out = slot;
    return 0;
}

static int slot_is_durable(const struct wvm_admission_receiver_slot *slot,
                           const struct wvm_envelope *request)
{
    return slot && slot->state_path && slot->state_lock_fd >= 0 &&
           !slot->state_failed && slot->vm_id == request->vm_id &&
           slot->vm_incarnation == request->vm_incarnation &&
           slot->manifest_generation == request->manifest_generation;
}

static int local_reservation_matches_stage(
    const struct wvm_admission_receiver *receiver,
    const struct wvm_admission_participant_stage *stage,
    enum wvm_reservation_state state)
{
    struct wvm_local_reservation_registry *registry;
    const struct wvm_resource_reservation *reservation;
    int matches;

    if (!receiver || !stage || !stage->candidate || !stage->runtime_manifest ||
        !(registry = receiver->config.reservation_registry) ||
        !registry->initialized ||
        stage->runtime_manifest->physical_node_id !=
            receiver->config.local_physical_node_id ||
        stage->runtime_manifest->expected_node_instance_id !=
            receiver->config.local_node_instance_id ||
        !route_key_equal(&stage->runtime_manifest->required_route_snapshot_key,
                         &stage->candidate->prepared_route_snapshot_key)) {
        return 0;
    }
    pthread_mutex_lock(&registry->lock);
    reservation = wvm_local_reservation_find(registry,
                                             stage->runtime_manifest->reservation_id);
    matches = registry->journal_fd >= 0 && !registry->journal_failed &&
              reservation && reservation->state == state &&
              reservation_matches_requirement(stage->candidate, reservation) &&
              (state != WVM_RESERVATION_COMMITTED ||
               (stage->activation && reservation->has_activation_fence &&
                memcmp(reservation->activation_fence, stage->activation->activation_fence,
                       WVM_IDENTITY_ID_BYTES) == 0));
    pthread_mutex_unlock(&registry->lock);
    return matches;
}

static int local_reservation_allows_abort(
    const struct wvm_admission_receiver *receiver,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES])
{
    struct wvm_local_reservation_registry *registry = receiver->config.reservation_registry;
    const struct wvm_resource_reservation *reservation;
    int allowed;

    if (!registry || !registry->initialized) {
        return 0;
    }
    pthread_mutex_lock(&registry->lock);
    reservation = wvm_local_reservation_find(registry, reservation_id);
    allowed = registry->journal_fd >= 0 && !registry->journal_failed &&
              (!reservation || (!reservation->has_activation_fence &&
                                reservation->state != WVM_RESERVATION_COMMITTED));
    pthread_mutex_unlock(&registry->lock);
    return allowed;
}

static int prepared_slot_uses_reservation(
    struct wvm_admission_receiver *receiver,
    const struct wvm_envelope *request,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_admission_receiver_slot *slot;

    if (!receiver || !request || !reservation_id) {
        return -1;
    }
    if (resolve_slot(receiver, request, &slot, error, error_len) != 0 ||
        !slot_is_durable(slot, request)) {
        return -1;
    }
    return slot->has_prepared &&
                   memcmp(slot->prepared_storage.runtime_manifest.reservation_id,
                          reservation_id, WVM_IDENTITY_ID_BYTES) == 0
               ? 1
               : 0;
}

static int apply_reservation_stage(
    struct wvm_admission_receiver *receiver, const struct wvm_envelope *request,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    struct wvm_admission_reservation_stage_storage *storage;
    struct wvm_admission_reservation_stage stage;
    enum wvm_reservation_runtime_result reservation_result;
    int equal = -1;

    if (!receiver->config.reservation_registry ||
        !receiver->config.reservation_scratch_storage ||
        !wvm_local_reservation_registry_is_durable(
            receiver->config.reservation_registry)) {
        set_error(error, error_len, "durable local reservation authority is unavailable");
        return -1;
    }
    storage = receiver->config.reservation_scratch_storage;
    if (wvm_admission_reservation_stage_decode(
            request->payload, request->payload_bytes, request->message_type,
            storage, &stage, error, error_len) != 0 ||
        !candidate_matches_request(stage.candidate, request) ||
        !reservation_matches_requirement(stage.candidate, stage.reservation) ||
        stage.reservation->physical_node_id !=
            receiver->config.local_physical_node_id ||
        stage.reservation->node_instance_id !=
            receiver->config.local_node_instance_id) {
        set_error(error, error_len, "reservation stage does not target this node");
        goto fail;
    }
    result_bind_candidate(result, stage.candidate);
    if (request->message_type == WVM_ENVELOPE_MSG_PREPARE_RESERVATION) {
        if (wvm_local_reservation_prepare(receiver->config.reservation_registry,
                                          stage.reservation,
                                          &reservation_result, error,
                                          error_len) != 0) {
            goto fail;
        }
        result->recorded_state = WVM_RESERVATION_PREPARED;
    } else if (request->message_type == WVM_ENVELOPE_MSG_COMMIT_RESERVATION) {
        if (!activation_matches_route(stage.activation, stage.candidate) ||
            wvm_local_reservation_commit(
                receiver->config.reservation_registry,
                stage.reservation, stage.activation,
                &reservation_result, error, error_len) != 0) {
            goto fail;
        }
        result->recorded_state = WVM_RESERVATION_COMMITTED;
    } else {
        equal = prepared_slot_uses_reservation(
            receiver, request, stage.reservation->reservation_id, error,
            error_len);
        if (equal != 0 ||
            wvm_local_reservation_abort(receiver->config.reservation_registry,
                                        stage.reservation,
                                        &reservation_result, error,
                                        error_len) != 0) {
            if (equal > 0) {
                set_error(error, error_len,
                          "runtime manifest must abort before reservation release");
            }
            goto fail;
        }
        result->recorded_state = WVM_RESERVATION_RELEASED;
    }
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    return 0;

fail:
    return -1;
}

static int decode_participant_scratch(
    const struct wvm_envelope *request, struct wvm_admission_receiver_slot *slot,
    struct wvm_admission_participant_stage *stage, char *error,
    size_t error_len)
{
    if (!request || !slot || !stage ||
        wvm_admission_participant_stage_decode(
            request->payload, request->payload_bytes, request->message_type,
            &slot->scratch_storage, stage, error, error_len) != 0) {
        return -1;
    }
    return candidate_matches_request(stage->candidate, request) ? 0 : -1;
}

static int state_parent_open(const char *path)
{
    char parent[4096];
    const char *slash = strrchr(path, '/');
    size_t length = slash ? (size_t)(slash - path) : 0;

    if (!slash) {
        return open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    if (length == 0) {
        length = 1;
    }
    if (length >= sizeof(parent)) {
        return -1;
    }
    memcpy(parent, path, length);
    parent[length] = '\0';
    return open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int state_write_full(int fd, const uint8_t *bytes, size_t count)
{
    size_t offset = 0;

    while (offset < count) {
        ssize_t written = write(fd, bytes + offset, count - offset);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

/* A complete envelope supplies the existing framing, CRC, and payload digest.
 * Rename makes each bounded slot a single durable snapshot, not a growing log. */
static int persist_participant_stage(
    struct wvm_admission_receiver_slot *slot, const struct wvm_envelope *request,
    char *error, size_t error_len)
{
    uint8_t *bytes = NULL;
    size_t count = 0;
    char temporary[4096] = {0};
    int fd = -1, directory_fd = -1, result = -1;
    int length;

    if (!slot_is_durable(slot, request) ||
        request->payload_bytes > WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
        set_error(error, error_len, "participant durable state is unavailable");
        return -1;
    }
    bytes = malloc(WVM_ENVELOPE_HEADER_BYTES + request->payload_bytes);
    if (!bytes ||
        wvm_envelope_encode(request, WVM_ENVELOPE_TRANSPORT_LOCAL, bytes,
                            WVM_ENVELOPE_HEADER_BYTES + request->payload_bytes,
                            &count, error, error_len) != 0) {
        goto out;
    }
    length = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX",
                       slot->state_path);
    if (length < 0 || (size_t)length >= sizeof(temporary)) {
        temporary[0] = '\0';
        goto out;
    }
    directory_fd = state_parent_open(slot->state_path);
    if (directory_fd < 0 || (fd = mkstemp(temporary)) < 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ||
        state_write_full(fd, bytes, count) != 0 || fsync(fd) != 0) {
        goto out;
    }
    if (rename(temporary, slot->state_path) != 0 || fsync(directory_fd) != 0) {
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
    if (temporary[0]) {
        unlink(temporary);
    }
    free(bytes);
    if (result != 0) {
        slot->state_failed = 1;
        set_error(error, error_len, "cannot persist participant stage; reopen required");
    }
    return result;
}

static int restore_participant_stage(
    struct wvm_admission_receiver *receiver,
    struct wvm_admission_receiver_slot *slot, const struct wvm_envelope *request,
    char *error, size_t error_len)
{
    struct wvm_admission_participant_stage stage;

    if (request->flags != 0 || !slot_is_durable(slot, request) ||
        (request->message_type != WVM_ENVELOPE_MSG_PREPARE_MANIFEST &&
         request->message_type != WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST &&
         request->message_type != WVM_ENVELOPE_MSG_ABORT_MANIFEST) ||
        wvm_admission_participant_stage_decode(
            request->payload, request->payload_bytes, request->message_type,
            &slot->prepared_storage, &stage, error, error_len) != 0 ||
        !candidate_matches_request(stage.candidate, request) ||
        stage.runtime_manifest->physical_node_id !=
            receiver->config.local_physical_node_id ||
        stage.runtime_manifest->expected_node_instance_id !=
            receiver->config.local_node_instance_id ||
        (stage.activation &&
         !activation_matches_route(stage.activation, stage.candidate))) {
        set_error(error, error_len, "participant state does not bind this slot");
        return -1;
    }
    slot->has_aborted = request->message_type == WVM_ENVELOPE_MSG_ABORT_MANIFEST;
    slot->has_activation_decision =
        request->message_type == WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST;
    slot->has_prepared = !slot->has_aborted;
    slot->has_activated = 0;
    wvm_runtime_gate_init(&slot->gate);
    if (slot->has_prepared &&
        wvm_runtime_gate_prepare(&slot->gate, &slot->prepared_storage.runtime_manifest,
                                 receiver->config.local_physical_node_id,
                                 receiver->config.local_node_instance_id,
                                 error, error_len) != 0) {
        return -1;
    }
    return 0;
}

static int activate_delivery(struct wvm_admission_receiver *receiver,
                             struct wvm_admission_receiver_slot *slot,
                             const struct wvm_candidate_vm_manifest *candidate,
                             const struct wvm_node_runtime_manifest *runtime_manifest,
                             const struct wvm_activation_record *activation,
                             char *error, size_t error_len)
{
    const struct wvm_cluster_record_set *records;
    const struct wvm_route_snapshot_record *route_snapshot;
    struct wvm_runtime_delivery_request delivery;
    if (!receiver->config.delivery_inputs || !candidate || !runtime_manifest ||
        receiver->config.delivery_inputs(receiver->config.context, candidate,
                                         runtime_manifest, activation, &records,
                                         &route_snapshot, error, error_len) != 0 ||
        !records || !route_snapshot ||
        !route_key_equal(&route_snapshot->route_snapshot_key,
                         &runtime_manifest->required_route_snapshot_key)) {
        set_error(error, error_len, "runtime delivery inputs do not bind activation");
        return -1;
    }
    memset(&delivery, 0, sizeof(delivery));
    delivery.candidate = candidate;
    delivery.runtime_manifest = runtime_manifest;
    delivery.cluster_records = records;
    delivery.route_snapshot = route_snapshot;
    delivery.runtime_manifest_path = slot->runtime_manifest_path;
    return wvm_runtime_delivery_publish(&delivery, error, error_len);
}

static int apply_participant_stage(
    struct wvm_admission_receiver *receiver, const struct wvm_envelope *request,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    struct wvm_admission_receiver_slot *slot;
    struct wvm_admission_participant_stage scratch;
    int equal;

    if (resolve_slot(receiver, request, &slot, error, error_len) != 0 ||
        !slot_is_durable(slot, request) ||
        decode_participant_scratch(request, slot, &scratch, error, error_len) !=
            0 ||
        scratch.runtime_manifest->physical_node_id !=
            receiver->config.local_physical_node_id ||
        scratch.runtime_manifest->expected_node_instance_id !=
            receiver->config.local_node_instance_id) {
        set_error(error, error_len, "runtime stage does not target this node");
        return -1;
    }
    result_bind_candidate(result, scratch.candidate);
    if (request->message_type == WVM_ENVELOPE_MSG_PREPARE_MANIFEST) {
        if (slot->has_activation_decision || slot->has_aborted) {
            set_error(error, error_len,
                      "manifest prepare cannot follow an activation or abort decision");
            return -1;
        }
        if (slot->has_prepared) {
            equal = canonical_equal(encode_candidate,
                                    &slot->prepared_storage.candidate,
                                    scratch.candidate, error, error_len);
            if (equal != 1 ||
                runtime_projection_equal(&slot->prepared_storage.runtime_manifest,
                                         scratch.runtime_manifest, 1, error,
                                         error_len) != 1) {
                set_error(error, error_len,
                          "manifest prepare conflicts with retained projection");
                return -1;
            }
        } else if (!local_reservation_matches_stage(receiver, &scratch,
                                                     WVM_RESERVATION_PREPARED)) {
            set_error(error, error_len, "cannot retain local runtime prepare");
            return -1;
        } else {
            if (restore_participant_stage(receiver, slot, request, error,
                                           error_len) != 0 ||
                persist_participant_stage(slot, request, error, error_len) != 0) {
                slot->state_failed = 1;
                return -1;
            }
        }
        result->recorded_state = WVM_LIFECYCLE_PARTICIPANTS_PREPARED;
    } else if (request->message_type == WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST) {
        if (!slot->has_prepared || slot->has_aborted ||
            !activation_matches_route(scratch.activation, scratch.candidate) ||
            canonical_equal(encode_candidate, &slot->prepared_storage.candidate,
                            scratch.candidate, error, error_len) != 1 ||
            runtime_projection_equal(&slot->prepared_storage.runtime_manifest,
                                     scratch.runtime_manifest, 1, error,
                                     error_len) != 1 ||
            !local_reservation_matches_stage(receiver, &scratch,
                                               WVM_RESERVATION_COMMITTED) ||
            (slot->has_activation_decision &&
             canonical_equal(encode_activation, &slot->prepared_storage.activation,
                             scratch.activation, error, error_len) != 1)) {
            set_error(error, error_len, "cannot activate local runtime projection");
            return -1;
        }
        if (!slot->has_activation_decision) {
            struct wvm_admission_participant_stage retained;

            /* Retain the decision before publishing any runnable projection.
             * A crash here must retry activation, never fall back to abort. */
            if (wvm_admission_participant_stage_decode(
                    request->payload, request->payload_bytes, request->message_type,
                    &slot->prepared_storage, &retained, error, error_len) != 0 ||
                persist_participant_stage(slot, request, error, error_len) != 0) {
                slot->state_failed = 1;
                return -1;
            }
            slot->has_activation_decision = 1;
        }
        if (activate_delivery(receiver, slot, scratch.candidate,
                               scratch.runtime_manifest, scratch.activation,
                               error, error_len) != 0 ||
            wvm_runtime_gate_activate(&slot->gate,
                                      scratch.activation->activation_fence,
                                      error, error_len) != 0) {
            return -1;
        }
        slot->has_activated = 1;
        result->recorded_state = WVM_LIFECYCLE_COMMITTED;
    } else {
        if (slot->has_activation_decision ||
            !local_reservation_allows_abort(receiver,
                                            scratch.runtime_manifest->reservation_id) ||
            ((slot->has_prepared || slot->has_aborted) &&
             (canonical_equal(encode_candidate, &slot->prepared_storage.candidate,
                             scratch.candidate, error, error_len) != 1 ||
             runtime_projection_equal(&slot->prepared_storage.runtime_manifest,
                                      scratch.runtime_manifest, 1, error,
                                      error_len) != 1))) {
            set_error(error, error_len, "cannot abort local runtime projection");
            return -1;
        }
        if (!slot->has_aborted &&
            (restore_participant_stage(receiver, slot, request, error, error_len) != 0 ||
             persist_participant_stage(slot, request, error, error_len) != 0)) {
            slot->state_failed = 1;
            return -1;
        }
        result->recorded_state = WVM_LIFECYCLE_ABORTED;
    }
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    return 0;
}

static int apply_route_stage(struct wvm_admission_receiver *receiver,
                             const struct wvm_envelope *request,
                             struct wvm_control_result *result, char *error,
                             size_t error_len)
{
    struct wvm_route_control_result route_result;

    if (!receiver->config.route_control ||
        wvm_route_control_apply(receiver->config.route_control, request,
                                &route_result, error, error_len) != 0) {
        return -1;
    }
    if (!envelope_matches_route_key(request, &route_result.route_snapshot_key)) {
        set_error(error, error_len, "route stage result does not match envelope");
        return -1;
    }
    result->recorded_state = route_result.recorded_state;
    result->applied_revision =
        route_result.route_snapshot_key.route_generation;
    result->expiry_or_retention_deadline =
        route_result.operation_retention_horizon_ms;
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    return 0;
}

void wvm_admission_receiver_slot_init(struct wvm_admission_receiver_slot *slot)
{
    if (!slot) {
        return;
    }
    wvm_runtime_gate_init(&slot->gate);
    slot->has_prepared = 0;
    slot->has_activated = 0;
    slot->has_activation_decision = 0;
    slot->has_aborted = 0;
    slot->vm_id = 0;
    slot->vm_incarnation = 0;
    slot->manifest_generation = 0;
    slot->state_path = NULL;
    slot->state_lock_fd = -1;
    slot->state_failed = 0;
}

void wvm_admission_receiver_slot_close(struct wvm_admission_receiver_slot *slot)
{
    if (!slot) {
        return;
    }
    if (slot->state_path && slot->state_lock_fd >= 0) {
        close(slot->state_lock_fd);
    }
    free(slot->state_path);
    wvm_admission_receiver_slot_init(slot);
}

int wvm_admission_receiver_slot_open(
    struct wvm_admission_receiver *receiver,
    struct wvm_admission_receiver_slot *slot, const char *state_path,
    uint32_t vm_id, uint64_t vm_incarnation, uint64_t manifest_generation,
    char *error, size_t error_len)
{
    char lock_path[4096];
    struct stat info;
    struct wvm_envelope saved;
    uint8_t *bytes = NULL;
    size_t count, offset = 0;
    int fd = -1, directory_fd = -1, result = -1;
    int length;

    if (!receiver_config_valid(receiver) || !slot || slot->state_path ||
        !state_path || !state_path[0] || !slot->runtime_manifest_path ||
        !slot->runtime_manifest_path[0] ||
        strcmp(state_path, slot->runtime_manifest_path) == 0 ||
        !vm_id || !vm_incarnation || !manifest_generation) {
        set_error(error, error_len, "participant state open input is invalid");
        return -1;
    }
    wvm_admission_receiver_slot_init(slot);
    slot->state_path = strdup(state_path);
    slot->vm_id = vm_id;
    slot->vm_incarnation = vm_incarnation;
    slot->manifest_generation = manifest_generation;
    length = snprintf(lock_path, sizeof(lock_path), "%s.lock", state_path);
    if (!slot->state_path || length < 0 || (size_t)length >= sizeof(lock_path)) {
        goto out;
    }
    slot->state_lock_fd = open(lock_path,
                              O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (slot->state_lock_fd < 0 ||
        fstat(slot->state_lock_fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        flock(slot->state_lock_fd, LOCK_EX | LOCK_NB) != 0 ||
        fsync(slot->state_lock_fd) != 0 ||
        (directory_fd = state_parent_open(state_path)) < 0) {
        goto out;
    }
    fd = open(state_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT &&
            lstat(slot->runtime_manifest_path, &info) != 0 && errno == ENOENT &&
            fsync(directory_fd) == 0) {
            result = 0;
        }
        goto out;
    }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size < WVM_ENVELOPE_HEADER_BYTES ||
        (uintmax_t)info.st_size >
            WVM_ENVELOPE_HEADER_BYTES + WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
        goto out;
    }
    count = (size_t)info.st_size;
    bytes = malloc(count);
    if (!bytes) {
        goto out;
    }
    while (offset < count) {
        ssize_t received = read(fd, bytes + offset, count - offset);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            goto out;
        }
        offset += (size_t)received;
    }
    if (wvm_envelope_decode(bytes, count, WVM_ENVELOPE_TRANSPORT_LOCAL,
                            &saved, error, error_len) != 0 ||
        restore_participant_stage(receiver, slot, &saved, error, error_len) != 0 ||
        fsync(fd) != 0 || fsync(directory_fd) != 0) {
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
    free(bytes);
    if (result != 0) {
        wvm_admission_receiver_slot_close(slot);
        slot->state_failed = 1;
        set_error(error, error_len, "cannot open or recover participant state");
    }
    return result;
}

int wvm_admission_receiver_init(
    struct wvm_admission_receiver *receiver,
    const struct wvm_admission_receiver_config *config, char *error,
    size_t error_len)
{
    if (!receiver || !config ||
        wvm_member_key_validate(&config->controller_member_key, error,
                                error_len) != 0 ||
        config->controller_physical_node_id == 0 ||
        config->controller_runtime_instance_id == 0 ||
        config->local_physical_node_id == 0 || config->local_node_instance_id == 0) {
        set_error(error, error_len, "admission receiver configuration is invalid");
        return -1;
    }
    memset(receiver, 0, sizeof(*receiver));
    receiver->config = *config;
    if (pthread_mutex_init(&receiver->lock, NULL) != 0) {
        set_error(error, error_len, "admission receiver mutex initialization failed");
        return -1;
    }
    receiver->initialized = 1;
    return 0;
}

void wvm_admission_receiver_destroy(struct wvm_admission_receiver *receiver)
{
    if (!receiver) {
        return;
    }
    if (receiver->initialized) {
        pthread_mutex_destroy(&receiver->lock);
    }
    memset(receiver, 0, sizeof(*receiver));
}

int wvm_admission_receiver_apply(
    void *context, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_control_result *result, char *error, size_t error_len)
{
    struct wvm_admission_receiver *receiver = context;
    int apply_result = -1;

    if (!receiver_config_valid(receiver) || !request || !result) {
        set_error(error, error_len, "admission receiver is not initialized");
        return -1;
    }
    result_init(result, request);
    if (!stage_message_type(request->message_type) || request->flags != 0 ||
        !controller_matches(receiver, request, authenticated_actor)) {
        result->status_code = !controller_matches(receiver, request,
                                                   authenticated_actor)
                                  ? WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE
                                  : WVM_CONTROL_RESULT_INVALID_ENVELOPE;
        return 0;
    }
    pthread_mutex_lock(&receiver->lock);
    switch (request->message_type) {
    case WVM_ENVELOPE_MSG_PREPARE_RESERVATION:
    case WVM_ENVELOPE_MSG_COMMIT_RESERVATION:
    case WVM_ENVELOPE_MSG_ABORT_RESERVATION:
        apply_result = apply_reservation_stage(receiver, request, result, error,
                                               error_len);
        break;
    case WVM_ENVELOPE_MSG_PREPARE_MANIFEST:
    case WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST:
    case WVM_ENVELOPE_MSG_ABORT_MANIFEST:
        apply_result = apply_participant_stage(receiver, request, result, error,
                                               error_len);
        break;
    default:
        apply_result = apply_route_stage(receiver, request, result, error,
                                         error_len);
        break;
    }
    pthread_mutex_unlock(&receiver->lock);
    if (apply_result != 0) {
        result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
    }
    return 0;
}

#include "wavevm_admission_stage.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_canonical.h"
#include "wavevm_envelope.h"

typedef int (*stage_nested_encode_fn)(const void *record, uint8_t *bytes,
                                      size_t capacity,
                                      size_t *encoded_bytes, char *error,
                                      size_t error_len);

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

static uint16_t read_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static int candidate_matches_reservation(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    if (!candidate || !reservation ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        wvm_resource_reservation_validate(reservation, error, error_len) != 0 ||
        candidate->vm_id != reservation->vm_id ||
        candidate->vm_incarnation != reservation->vm_incarnation ||
        memcmp(candidate->admission_tx_id, reservation->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(candidate->manifest_digest, reservation->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        memcmp(candidate->eligibility_fence_digest,
               reservation->eligibility_fence_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        set_error(error, error_len,
                  "reservation stage does not bind the immutable candidate");
        return -1;
    }
    return 0;
}

static int candidate_matches_runtime(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    if (!candidate || !runtime_manifest ||
        wvm_candidate_vm_manifest_validate(candidate, error, error_len) != 0 ||
        wvm_node_runtime_manifest_validate(runtime_manifest, error,
                                           error_len) != 0 ||
        candidate->vm_id != runtime_manifest->vm_id ||
        candidate->vm_incarnation != runtime_manifest->vm_incarnation ||
        candidate->manifest_generation != runtime_manifest->manifest_generation ||
        memcmp(candidate->manifest_digest,
               runtime_manifest->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        memcmp(candidate->admission_tx_id, runtime_manifest->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(candidate->eligibility_fence_digest,
               runtime_manifest->eligibility_fence_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        set_error(error, error_len,
                  "participant stage does not bind the immutable candidate");
        return -1;
    }
    return 0;
}

static int activation_matches_candidate(
    const struct wvm_activation_record *activation,
    const struct wvm_candidate_vm_manifest *candidate, char *error,
    size_t error_len)
{
    if (!activation || !candidate ||
        wvm_activation_record_validate(activation, error, error_len) != 0 ||
        activation->decision != WVM_ACTIVATION_ACTIVATE ||
        !activation->has_activation_fence ||
        memcmp(activation->admission_tx_id, candidate->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(activation->candidate_manifest_digest, candidate->manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        set_error(error, error_len,
                  "activation decision does not bind the immutable candidate");
        return -1;
    }
    return 0;
}

static int reservation_stage_validate(
    const struct wvm_admission_reservation_stage *stage, char *error,
    size_t error_len)
{
    if (!stage || candidate_matches_reservation(stage->candidate,
                                                stage->reservation, error,
                                                error_len) != 0) {
        return -1;
    }
    switch (stage->message_type) {
    case WVM_ENVELOPE_MSG_PREPARE_RESERVATION:
        if (stage->reservation->state == WVM_RESERVATION_PREPARED &&
            !stage->activation && stage->abort_reason == 0) {
            return 0;
        }
        break;
    case WVM_ENVELOPE_MSG_COMMIT_RESERVATION:
        if (stage->reservation->state == WVM_RESERVATION_COMMITTED &&
            stage->abort_reason == 0 &&
            activation_matches_candidate(stage->activation, stage->candidate,
                                         error, error_len) == 0 &&
            stage->reservation->has_activation_fence &&
            memcmp(stage->reservation->activation_fence,
                   stage->activation->activation_fence,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return 0;
        }
        break;
    case WVM_ENVELOPE_MSG_ABORT_RESERVATION:
        if (stage->reservation->state == WVM_RESERVATION_PREPARED &&
            !stage->activation && stage->abort_reason != 0) {
            return 0;
        }
        break;
    default:
        break;
    }
    set_error(error, error_len, "reservation stage does not match its transition");
    return -1;
}

static int participant_stage_validate(
    const struct wvm_admission_participant_stage *stage, char *error,
    size_t error_len)
{
    if (!stage || candidate_matches_runtime(stage->candidate,
                                            stage->runtime_manifest, error,
                                            error_len) != 0) {
        return -1;
    }
    switch (stage->message_type) {
    case WVM_ENVELOPE_MSG_PREPARE_MANIFEST:
        if (!stage->runtime_manifest->has_activation_fence &&
            !stage->activation && stage->abort_reason == 0) {
            return 0;
        }
        break;
    case WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST:
        if (stage->runtime_manifest->has_activation_fence &&
            stage->abort_reason == 0 &&
            activation_matches_candidate(stage->activation, stage->candidate,
                                         error, error_len) == 0 &&
            memcmp(stage->runtime_manifest->activation_fence,
                   stage->activation->activation_fence,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return 0;
        }
        break;
    case WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY:
        if (stage->runtime_manifest->has_activation_fence &&
            !stage->activation && stage->abort_reason == 0) {
            return 0;
        }
        break;
    case WVM_ENVELOPE_MSG_ABORT_MANIFEST:
        if (!stage->runtime_manifest->has_activation_fence &&
            !stage->activation && stage->abort_reason != 0) {
            return 0;
        }
        break;
    default:
        break;
    }
    set_error(error, error_len, "participant stage does not match its transition");
    return -1;
}

static int encode_candidate(const void *record, uint8_t *bytes, size_t capacity,
                            size_t *encoded_bytes, char *error,
                            size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    return wvm_candidate_vm_manifest_encode(record, bytes, capacity,
                                            encoded_bytes, digest, error,
                                            error_len);
}

static int encode_reservation(const void *record, uint8_t *bytes,
                              size_t capacity, size_t *encoded_bytes,
                              char *error, size_t error_len)
{
    return wvm_resource_reservation_encode(record, bytes, capacity,
                                           encoded_bytes, error, error_len);
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

static int encode_nested_alloc(stage_nested_encode_fn encode, const void *record,
                               uint8_t **bytes_out, size_t *encoded_bytes_out,
                               char *error, size_t error_len)
{
    size_t capacity = 4096U;

    if (!encode || !record || !bytes_out || !encoded_bytes_out) {
        set_error(error, error_len, "admission stage nested record is invalid");
        return -1;
    }
    while (capacity <= WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
        uint8_t *bytes = malloc(capacity);
        size_t encoded_bytes = 0;

        if (!bytes) {
            set_error(error, error_len,
                      "cannot allocate admission stage nested record");
            return -1;
        }
        if (encode(record, bytes, capacity, &encoded_bytes, error, error_len) ==
            0) {
            *bytes_out = bytes;
            *encoded_bytes_out = encoded_bytes;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_ENVELOPE_MAX_LOCAL_PAYLOAD) {
            capacity = WVM_ENVELOPE_MAX_LOCAL_PAYLOAD;
        }
    }
    set_error(error, error_len, "admission stage nested record is too large");
    return -1;
}

static int stage_encode(uint16_t record_type, const void *first_record,
                        stage_nested_encode_fn first_encode,
                        const void *second_record,
                        stage_nested_encode_fn second_encode,
                        const struct wvm_activation_record *activation,
                        uint16_t abort_reason, uint8_t *bytes, size_t capacity,
                        size_t *encoded_bytes, char *error, size_t error_len)
{
    struct wvm_canonical_builder builder;
    uint8_t *first_bytes = NULL;
    uint8_t *second_bytes = NULL;
    uint8_t *activation_bytes = NULL;
    size_t first_byte_count = 0;
    size_t second_byte_count = 0;
    size_t activation_byte_count = 0;
    int result = -1;

    if (!bytes || !encoded_bytes ||
        encode_nested_alloc(first_encode, first_record, &first_bytes,
                            &first_byte_count, error, error_len) != 0 ||
        encode_nested_alloc(second_encode, second_record, &second_bytes,
                            &second_byte_count, error, error_len) != 0 ||
        (activation &&
         encode_nested_alloc(encode_activation, activation, &activation_bytes,
                             &activation_byte_count, error, error_len) != 0) ||
        wvm_canonical_record_begin(&builder, bytes, capacity, record_type) != 0 ||
        wvm_canonical_field_append(&builder, 1, first_bytes,
                                   (uint32_t)first_byte_count) != 0 ||
        wvm_canonical_field_append(&builder, 2, second_bytes,
                                   (uint32_t)second_byte_count) != 0 ||
        (activation &&
         wvm_canonical_field_append(&builder, 3, activation_bytes,
                                    (uint32_t)activation_byte_count) != 0) ||
        (abort_reason != 0 &&
         wvm_canonical_field_append_u16(&builder, 4, abort_reason) != 0) ||
        wvm_canonical_record_finish(&builder, encoded_bytes) != 0) {
        set_error(error, error_len, "cannot encode admission stage carrier");
        goto out;
    }
    result = 0;
out:
    free(activation_bytes);
    free(second_bytes);
    free(first_bytes);
    return result;
}

int wvm_admission_reservation_stage_encode(
    const struct wvm_admission_reservation_stage *stage, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    if (reservation_stage_validate(stage, error, error_len) != 0) {
        return -1;
    }
    switch (stage->message_type) {
    case WVM_ENVELOPE_MSG_PREPARE_RESERVATION:
        return stage_encode(WVM_RECORD_ADMISSION_RESERVATION_STAGE,
                            stage->candidate, encode_candidate,
                            stage->reservation, encode_reservation, NULL, 0,
                            bytes, capacity, encoded_bytes, error, error_len);
    case WVM_ENVELOPE_MSG_COMMIT_RESERVATION:
        return stage_encode(WVM_RECORD_ADMISSION_RESERVATION_STAGE,
                            stage->candidate, encode_candidate,
                            stage->reservation, encode_reservation,
                            stage->activation, 0, bytes, capacity,
                            encoded_bytes, error, error_len);
    case WVM_ENVELOPE_MSG_ABORT_RESERVATION:
        return stage_encode(WVM_RECORD_ADMISSION_RESERVATION_STAGE,
                            stage->candidate, encode_candidate,
                            stage->reservation, encode_reservation, NULL,
                            stage->abort_reason, bytes, capacity, encoded_bytes,
                            error, error_len);
    default:
        break;
    }
    set_error(error, error_len, "reservation stage does not match its transition");
    return -1;
}

int wvm_admission_participant_stage_encode(
    const struct wvm_admission_participant_stage *stage, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len)
{
    if (participant_stage_validate(stage, error, error_len) != 0) {
        return -1;
    }
    switch (stage->message_type) {
    case WVM_ENVELOPE_MSG_PREPARE_MANIFEST:
        return stage_encode(WVM_RECORD_ADMISSION_PARTICIPANT_STAGE,
                            stage->candidate, encode_candidate,
                            stage->runtime_manifest, encode_runtime_manifest,
                            NULL, 0, bytes, capacity, encoded_bytes, error,
                            error_len);
    case WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST:
        return stage_encode(WVM_RECORD_ADMISSION_PARTICIPANT_STAGE,
                            stage->candidate, encode_candidate,
                            stage->runtime_manifest, encode_runtime_manifest,
                            stage->activation, 0, bytes, capacity,
                            encoded_bytes, error, error_len);
    case WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY:
        return stage_encode(WVM_RECORD_ADMISSION_PARTICIPANT_STAGE,
                            stage->candidate, encode_candidate,
                            stage->runtime_manifest, encode_runtime_manifest,
                            NULL, 0, bytes, capacity, encoded_bytes, error,
                            error_len);
    case WVM_ENVELOPE_MSG_ABORT_MANIFEST:
        return stage_encode(WVM_RECORD_ADMISSION_PARTICIPANT_STAGE,
                            stage->candidate, encode_candidate,
                            stage->runtime_manifest, encode_runtime_manifest,
                            NULL, stage->abort_reason, bytes, capacity,
                            encoded_bytes, error, error_len);
    default:
        break;
    }
    set_error(error, error_len, "participant stage does not match its transition");
    return -1;
}

static int parse_stage_fields(const uint8_t *bytes, size_t encoded_bytes,
                              uint16_t record_type,
                              struct wvm_canonical_field fields[5],
                              unsigned char present[5], char *error,
                              size_t error_len)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    uint16_t last_tag = 0;
    int next;

    if (!bytes || !fields || !present ||
        wvm_canonical_record_parse(bytes, encoded_bytes, &record) != 0 ||
        record.record_type != record_type) {
        set_error(error, error_len, "admission stage carrier type is invalid");
        return -1;
    }
    memset(fields, 0, 5U * sizeof(*fields));
    memset(present, 0, 5U);
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 0 || field.tag > 4 || field.tag <= last_tag ||
            present[field.tag]) {
            set_error(error, error_len, "admission stage carrier fields are invalid");
            return -1;
        }
        fields[field.tag] = field;
        present[field.tag] = 1;
        last_tag = field.tag;
    }
    if (next < 0 || !present[1] || !present[2]) {
        set_error(error, error_len, "admission stage carrier misses required fields");
        return -1;
    }
    return 0;
}

static int bind_candidate_storage(
    struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_admission_candidate_stage_storage *storage, char *error,
    size_t error_len)
{
    size_t i;

    if (!candidate || !storage ||
        (storage->vcpu_placement_capacity && !storage->vcpu_placements) ||
        (storage->memory_placement_capacity && !storage->memory_placements) ||
        (storage->storage_assignment_capacity && !storage->storage_assignments) ||
        (storage->required_member_capacity && !storage->required_members) ||
        (storage->required_capability_capacity &&
         !storage->required_capabilities) ||
        (storage->execution_capability_capacity &&
         !storage->execution_capabilities) ||
        (storage->reservation_requirement_capacity &&
         !storage->reservation_requirements) ||
        (storage->reservation_requirement_capacity &&
         storage->reservation_requirement_lease_capacity &&
         (!storage->reservation_requirement_leases ||
          storage->reservation_requirement_capacity >
              SIZE_MAX / storage->reservation_requirement_lease_capacity))) {
        set_error(error, error_len, "candidate stage decode storage is invalid");
        return -1;
    }
    memset(candidate, 0, sizeof(*candidate));
    candidate->vcpu_placements.entries = storage->vcpu_placements;
    candidate->vcpu_placements.capacity = storage->vcpu_placement_capacity;
    candidate->memory_placements.entries = storage->memory_placements;
    candidate->memory_placements.capacity = storage->memory_placement_capacity;
    candidate->storage_device_plan.assignments.entries =
        storage->storage_assignments;
    candidate->storage_device_plan.assignments.capacity =
        storage->storage_assignment_capacity;
    candidate->required_members.entries = storage->required_members;
    candidate->required_members.capacity = storage->required_member_capacity;
    candidate->required_capabilities.entries = storage->required_capabilities;
    candidate->required_capabilities.capacity =
        storage->required_capability_capacity;
    candidate->execution_plan.per_node_capabilities.entries =
        storage->execution_capabilities;
    candidate->execution_plan.per_node_capabilities.capacity =
        storage->execution_capability_capacity;
    candidate->reservation_requirements.entries =
        storage->reservation_requirements;
    candidate->reservation_requirements.capacity =
        storage->reservation_requirement_capacity;
    for (i = 0; i < storage->reservation_requirement_capacity; i++) {
        struct wvm_reservation_requirement *requirement =
            &storage->reservation_requirements[i];

        memset(requirement, 0, sizeof(*requirement));
        requirement->exclusive_leases.entries =
            storage->reservation_requirement_leases
                ? storage->reservation_requirement_leases +
                      i * storage->reservation_requirement_lease_capacity
                : NULL;
        requirement->exclusive_leases.capacity =
            storage->reservation_requirement_lease_capacity;
    }
    return 0;
}

static int bind_activation_storage(
    struct wvm_activation_record *activation,
    struct wvm_route_snapshot_key *route_snapshot_keys, size_t capacity,
    char *error, size_t error_len)
{
    if (!activation || (capacity && !route_snapshot_keys)) {
        set_error(error, error_len, "activation stage decode storage is invalid");
        return -1;
    }
    memset(activation, 0, sizeof(*activation));
    activation->required_route_snapshot_keys = route_snapshot_keys;
    activation->required_route_snapshot_capacity = capacity;
    return 0;
}

static int bind_runtime_storage(
    struct wvm_node_runtime_manifest *runtime_manifest,
    struct wvm_admission_participant_stage_storage *storage, char *error,
    size_t error_len)
{
    if (!runtime_manifest || !storage ||
        (storage->runtime_vcpu_assignment_capacity &&
         !storage->runtime_vcpu_assignments) ||
        (storage->runtime_memory_assignment_capacity &&
         !storage->runtime_memory_assignments) ||
        (storage->runtime_storage_assignment_capacity &&
         !storage->runtime_storage_assignments) ||
        (storage->runtime_capability_capacity && !storage->runtime_capabilities) ||
        (storage->runtime_dependency_capacity && !storage->runtime_dependencies)) {
        set_error(error, error_len, "runtime stage decode storage is invalid");
        return -1;
    }
    memset(runtime_manifest, 0, sizeof(*runtime_manifest));
    runtime_manifest->local_vcpu_assignments.entries =
        storage->runtime_vcpu_assignments;
    runtime_manifest->local_vcpu_assignments.capacity =
        storage->runtime_vcpu_assignment_capacity;
    runtime_manifest->local_memory_assignments.entries =
        storage->runtime_memory_assignments;
    runtime_manifest->local_memory_assignments.capacity =
        storage->runtime_memory_assignment_capacity;
    runtime_manifest->local_storage_assignments.entries =
        storage->runtime_storage_assignments;
    runtime_manifest->local_storage_assignments.capacity =
        storage->runtime_storage_assignment_capacity;
    runtime_manifest->negotiated_profile.per_node_capabilities.entries =
        storage->runtime_capabilities;
    runtime_manifest->negotiated_profile.per_node_capabilities.capacity =
        storage->runtime_capability_capacity;
    runtime_manifest->startup_dependencies.entries = storage->runtime_dependencies;
    runtime_manifest->startup_dependencies.capacity =
        storage->runtime_dependency_capacity;
    return 0;
}

int wvm_admission_reservation_stage_decode(
    const uint8_t *bytes, size_t encoded_bytes, uint16_t message_type,
    struct wvm_admission_reservation_stage_storage *storage,
    struct wvm_admission_reservation_stage *stage, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[5];
    unsigned char present[5];

    if (!storage || !stage ||
        parse_stage_fields(bytes, encoded_bytes,
                           WVM_RECORD_ADMISSION_RESERVATION_STAGE, fields,
                           present, error, error_len) != 0 ||
        bind_candidate_storage(&storage->candidate, &storage->candidate_storage,
                               error, error_len) != 0 ||
        wvm_candidate_vm_manifest_decode(fields[1].value, fields[1].value_bytes,
                                         &storage->candidate, error,
                                         error_len) != 0) {
        return -1;
    }
    if ((storage->reservation_lease_capacity && !storage->reservation_leases)) {
        set_error(error, error_len, "reservation stage decode storage is invalid");
        return -1;
    }
    memset(&storage->reservation, 0, sizeof(storage->reservation));
    storage->reservation.exclusive_leases.entries = storage->reservation_leases;
    storage->reservation.exclusive_leases.capacity =
        storage->reservation_lease_capacity;
    if (wvm_resource_reservation_decode(fields[2].value, fields[2].value_bytes,
                                        &storage->reservation, error,
                                        error_len) != 0 ||
        (present[3] &&
         (bind_activation_storage(&storage->activation,
                                  storage->activation_route_snapshot_keys,
                                  storage->activation_route_snapshot_key_capacity,
                                  error, error_len) != 0 ||
          wvm_activation_record_decode(fields[3].value, fields[3].value_bytes,
                                       &storage->activation, error,
                                       error_len) != 0)) ||
        (present[4] && fields[4].value_bytes != 2)) {
        return -1;
    }
    memset(stage, 0, sizeof(*stage));
    stage->message_type = message_type;
    stage->candidate = &storage->candidate;
    stage->reservation = &storage->reservation;
    stage->activation = present[3] ? &storage->activation : NULL;
    stage->abort_reason = present[4] ? read_be16(fields[4].value) : 0;
    return reservation_stage_validate(stage, error, error_len);
}

int wvm_admission_participant_stage_decode(
    const uint8_t *bytes, size_t encoded_bytes, uint16_t message_type,
    struct wvm_admission_participant_stage_storage *storage,
    struct wvm_admission_participant_stage *stage, char *error,
    size_t error_len)
{
    struct wvm_canonical_field fields[5];
    unsigned char present[5];

    if (!storage || !stage ||
        parse_stage_fields(bytes, encoded_bytes,
                           WVM_RECORD_ADMISSION_PARTICIPANT_STAGE, fields,
                           present, error, error_len) != 0 ||
        bind_candidate_storage(&storage->candidate, &storage->candidate_storage,
                               error, error_len) != 0 ||
        wvm_candidate_vm_manifest_decode(fields[1].value, fields[1].value_bytes,
                                         &storage->candidate, error,
                                         error_len) != 0 ||
        bind_runtime_storage(&storage->runtime_manifest, storage, error,
                             error_len) != 0 ||
        wvm_node_runtime_manifest_decode(fields[2].value, fields[2].value_bytes,
                                         &storage->runtime_manifest, error,
                                         error_len) != 0 ||
        (present[3] &&
         (bind_activation_storage(&storage->activation,
                                  storage->activation_route_snapshot_keys,
                                  storage->activation_route_snapshot_key_capacity,
                                  error, error_len) != 0 ||
          wvm_activation_record_decode(fields[3].value, fields[3].value_bytes,
                                       &storage->activation, error,
                                       error_len) != 0)) ||
        (present[4] && fields[4].value_bytes != 2)) {
        return -1;
    }
    memset(stage, 0, sizeof(*stage));
    stage->message_type = message_type;
    stage->candidate = &storage->candidate;
    stage->runtime_manifest = &storage->runtime_manifest;
    stage->activation = present[3] ? &storage->activation : NULL;
    stage->abort_reason = present[4] ? read_be16(fields[4].value) : 0;
    return participant_stage_validate(stage, error, error_len);
}

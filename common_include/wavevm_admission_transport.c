#include "wavevm_admission_transport.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_lifecycle.h"
#include "wavevm_sha256.h"
#include "wavevm_admission_stage.h"

typedef int (*record_encode_fn)(const void *record, uint8_t *bytes,
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

static int target_validate(const struct wvm_admission_transport_target *target,
                           char *error, size_t error_len)
{
    if (!target || wvm_member_key_validate(&target->member_key, error,
                                           error_len) != 0 ||
        wvm_endpoint_validate(&target->endpoint, error, error_len) != 0) {
        set_error(error, error_len, "admission transport target is invalid");
        return -1;
    }
    return 0;
}

static int endpoint_equal(const struct wvm_endpoint *left,
                          const struct wvm_endpoint *right)
{
    if (!left || !right || left->data_transport != right->data_transport ||
        left->data_address_bytes != right->data_address_bytes ||
        left->data_port != right->data_port ||
        left->control_transport != right->control_transport ||
        left->has_control_address != right->has_control_address ||
        left->control_port != right->control_port ||
        left->has_server_name != right->has_server_name ||
        left->has_control_socket_path != right->has_control_socket_path ||
        memcmp(left->data_address, right->data_address,
               left->data_address_bytes) != 0) {
        return 0;
    }
    if (left->has_control_address &&
        (left->control_address_bytes != right->control_address_bytes ||
         memcmp(left->control_address, right->control_address,
                left->control_address_bytes) != 0)) {
        return 0;
    }
    return (!left->has_server_name ||
            strcmp(left->server_name, right->server_name) == 0) &&
           (!left->has_control_socket_path ||
            strcmp(left->control_socket_path,
                   right->control_socket_path) == 0);
}

static int transport_validate(const struct wvm_admission_transport *transport,
                              char *error, size_t error_len)
{
    if (!transport || transport->controller_physical_node_id == 0 ||
        transport->controller_instance_id == 0 || !transport->resolve_member ||
        !transport->submit) {
        set_error(error, error_len,
                  "admission transport requires registered control providers");
        return -1;
    }
    return 0;
}

static void write_be16(uint8_t bytes[2], uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_be32(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_be64(uint8_t bytes[8], uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        bytes[7U - i] = (uint8_t)(value >> (8U * i));
    }
}

static int stage_operation_id(const uint8_t transaction_id[WVM_IDENTITY_ID_BYTES],
                              uint16_t message_type,
                              const struct wvm_member_key *target,
                              uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    static const char domain[] = "wavevm/admission-stage";
    struct wvm_sha256_ctx hash;
    uint8_t type_bytes[2];
    uint8_t role_bytes[2];
    uint8_t role_id_bytes[4];
    uint8_t instance_bytes[8];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    if (!transaction_id || !target || !operation_id ||
        bytes_are_zero(transaction_id, WVM_IDENTITY_ID_BYTES)) {
        return -1;
    }
    write_be16(type_bytes, message_type);
    write_be16(role_bytes, (uint16_t)target->role_type);
    write_be32(role_id_bytes, target->role_id);
    write_be64(instance_bytes, target->instance_id);
    wvm_sha256_init(&hash);
    wvm_sha256_update(&hash, domain, sizeof(domain) - 1U);
    wvm_sha256_update(&hash, transaction_id, WVM_IDENTITY_ID_BYTES);
    wvm_sha256_update(&hash, type_bytes, sizeof(type_bytes));
    wvm_sha256_update(&hash, role_bytes, sizeof(role_bytes));
    wvm_sha256_update(&hash, role_id_bytes, sizeof(role_id_bytes));
    wvm_sha256_update(&hash, instance_bytes, sizeof(instance_bytes));
    wvm_sha256_final(&hash, digest);
    memcpy(operation_id, digest, WVM_IDENTITY_ID_BYTES);
    return bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES) ? -1 : 0;
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
                  "reservation does not bind the immutable candidate");
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
        wvm_node_runtime_manifest_validate(runtime_manifest, error, error_len) !=
            0 ||
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
                  "runtime manifest does not bind the immutable candidate");
        return -1;
    }
    return 0;
}

static int resolve_member_target(
    struct wvm_admission_transport *transport,
    const struct wvm_member_key *expected_member,
    const struct wvm_endpoint *expected_endpoint,
    struct wvm_admission_transport_target *target, char *error,
    size_t error_len)
{
    if (transport_validate(transport, error, error_len) != 0 || !expected_member ||
        wvm_member_key_validate(expected_member, error, error_len) != 0 ||
        !target ||
        transport->resolve_member(transport->context, expected_member, target,
                                  error, error_len) != 0 ||
        target_validate(target, error, error_len) != 0 ||
        target->member_key.role_type != expected_member->role_type ||
        target->member_key.role_id != expected_member->role_id ||
        target->member_key.instance_id != expected_member->instance_id ||
        (expected_endpoint && !endpoint_equal(&target->endpoint,
                                              expected_endpoint))) {
        set_error(error, error_len,
                  "control target does not match the membership snapshot");
        return -1;
    }
    return 0;
}

static int resolve_node_target(struct wvm_admission_transport *transport,
                               uint32_t physical_node_id,
                               uint64_t node_instance_id,
                               struct wvm_admission_transport_target *target,
                               char *error, size_t error_len)
{
    struct wvm_member_key member = {
        .role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME,
        .role_id = physical_node_id,
        .instance_id = node_instance_id,
    };

    return resolve_member_target(transport, &member, NULL, target, error,
                                 error_len);
}

static int submit_record(struct wvm_admission_transport *transport,
                         const struct wvm_admission_transport_target *target,
                         uint16_t message_type,
                         const uint8_t transaction_id[WVM_IDENTITY_ID_BYTES],
                         uint32_t vm_id, uint64_t vm_incarnation,
                         uint64_t manifest_generation,
                         const struct wvm_route_snapshot_key *route_key,
                         record_encode_fn encode, const void *record,
                         char *error, size_t error_len)
{
    struct wvm_envelope envelope;
    uint8_t *payload;
    size_t payload_bytes = 0;
    int result;

    if (transport_validate(transport, error, error_len) != 0 ||
        target_validate(target, error, error_len) != 0 || !encode || !record ||
        vm_id == 0 || vm_incarnation == 0 || manifest_generation == 0) {
        set_error(error, error_len, "admission transport request is invalid");
        return -1;
    }
    payload = malloc(WVM_ENVELOPE_MAX_LOCAL_PAYLOAD);
    if (!payload) {
        set_error(error, error_len, "cannot allocate admission transport payload");
        return -1;
    }
    result = encode(record, payload, WVM_ENVELOPE_MAX_LOCAL_PAYLOAD,
                    &payload_bytes, error, error_len);
    if (result != 0 || payload_bytes == 0) {
        free(payload);
        if (error && error[0] == '\0') {
            set_error(error, error_len, "cannot encode admission transport record");
        }
        return -1;
    }
    memset(&envelope, 0, sizeof(envelope));
    envelope.message_type = message_type;
    envelope.vm_id = vm_id;
    envelope.vm_incarnation = vm_incarnation;
    envelope.manifest_generation = manifest_generation;
    envelope.origin_physical_node_id = transport->controller_physical_node_id;
    envelope.origin_runtime_instance_id = transport->controller_instance_id;
    envelope.delivery_attempt_id = 1;
    envelope.payload = payload;
    envelope.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 envelope.semantic_payload_digest);
    if (route_key) {
        envelope.route_scope_id = route_key->scope_key.route_scope_id;
        envelope.topology_revision = route_key->topology_revision;
        envelope.route_generation = route_key->route_generation;
        memcpy(envelope.route_snapshot_digest, route_key->snapshot_digest,
               sizeof(envelope.route_snapshot_digest));
    }
    if (stage_operation_id(transaction_id, message_type, &target->member_key,
                           envelope.operation_id) != 0 ||
        transport->submit(transport->context, target, &envelope, error,
                          error_len) != 0) {
        free(payload);
        if (error && error[0] == '\0') {
            set_error(error, error_len, "admission control stage was not durable");
        }
        return -1;
    }
    free(payload);
    return 0;
}

static int encode_reservation_stage(const void *record, uint8_t *bytes,
                                    size_t capacity, size_t *encoded_bytes,
                                    char *error, size_t error_len)
{
    return wvm_admission_reservation_stage_encode(record, bytes, capacity,
                                                  encoded_bytes, error,
                                                  error_len);
}

static int encode_participant_stage(const void *record, uint8_t *bytes,
                                    size_t capacity, size_t *encoded_bytes,
                                    char *error, size_t error_len)
{
    return wvm_admission_participant_stage_encode(record, bytes, capacity,
                                                  encoded_bytes, error,
                                                  error_len);
}

static int encode_route_snapshot(const void *record, uint8_t *bytes,
                                 size_t capacity, size_t *encoded_bytes,
                                 char *error, size_t error_len)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    return wvm_route_snapshot_record_encode(record, bytes, capacity,
                                            encoded_bytes, digest, error,
                                            error_len);
}

static int encode_route_transaction(const void *record, uint8_t *bytes,
                                    size_t capacity, size_t *encoded_bytes,
                                    char *error, size_t error_len)
{
    return wvm_route_transaction_record_encode(record, bytes, capacity,
                                               encoded_bytes, error, error_len);
}

static int encode_route_snapshot_key(const void *record, uint8_t *bytes,
                                     size_t capacity, size_t *encoded_bytes,
                                     char *error, size_t error_len)
{
    return wvm_route_snapshot_key_encode(record, bytes, capacity,
                                         encoded_bytes, error, error_len);
}

static int route_stage(struct wvm_admission_transport *transport,
                       const struct wvm_coordinator_transaction *coordinator,
                       const struct wvm_route_transaction_record *transaction,
                       const struct wvm_route_snapshot_record *snapshot,
                       uint16_t message_type, record_encode_fn encode,
                       const void *record, char *error, size_t error_len)
{
    size_t i;

    if (!coordinator || !transaction || !snapshot ||
        wvm_route_snapshot_record_binds_transaction(snapshot, transaction,
                                                     error, error_len) != 0 ||
        coordinator->vm_id != snapshot->route_snapshot_key.scope_key.vm_id ||
        coordinator->vm_incarnation !=
            snapshot->route_snapshot_key.scope_key.vm_incarnation) {
        set_error(error, error_len, "route stage does not bind coordinator identity");
        return -1;
    }
    for (i = 0; i < transaction->required_ack_set.entries.count; i++) {
        const struct wvm_required_ack_entry *ack =
            &transaction->required_ack_set.entries.entries[i];
        struct wvm_admission_transport_target target;

        memset(&target, 0, sizeof(target));
        if (resolve_member_target(transport, &ack->member_key, &ack->endpoint,
                                  &target, error, error_len) != 0) {
            return -1;
        }
        if (submit_record(transport, &target, message_type,
                          transaction->operation_id, coordinator->vm_id,
                          coordinator->vm_incarnation,
                          coordinator->manifest_generation,
                          &snapshot->route_snapshot_key, encode, record, error,
                          error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int transport_route_prepare(
    void *context, const struct wvm_coordinator_transaction *coordinator,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    return route_stage(context, coordinator, transaction, snapshot,
                       WVM_ENVELOPE_MSG_ROUTE_PREPARE, encode_route_snapshot,
                       snapshot, error, error_len);
}

static int transport_route_commit(
    void *context, const struct wvm_coordinator_transaction *coordinator,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    return route_stage(context, coordinator, transaction, snapshot,
                       WVM_ENVELOPE_MSG_ROUTE_COMMIT,
                       encode_route_snapshot_key,
                       &snapshot->route_snapshot_key, error, error_len);
}

static int transport_route_abort(
    void *context, const struct wvm_coordinator_transaction *coordinator,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    struct wvm_route_transaction_record aborted;

    aborted = *transaction;
    aborted.state = WVM_ROUTE_TRANSACTION_ABORTED;
    return route_stage(context, coordinator, &aborted, snapshot,
                       WVM_ENVELOPE_MSG_ROUTE_ABORT, encode_route_transaction,
                       &aborted, error, error_len);
}

static int transport_reservation_stage(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation, uint16_t message_type,
    char *error, size_t error_len)
{
    struct wvm_admission_transport *transport = context;
    struct wvm_admission_transport_target target;
    struct wvm_admission_reservation_stage stage;

    if (candidate_matches_reservation(candidate, reservation, error,
                                      error_len) != 0 ||
        resolve_node_target(transport, reservation->physical_node_id,
                            reservation->node_instance_id, &target, error,
                            error_len) != 0) {
        return -1;
    }
    memset(&stage, 0, sizeof(stage));
    stage.message_type = message_type;
    stage.candidate = candidate;
    stage.reservation = reservation;
    if (message_type == WVM_ENVELOPE_MSG_ABORT_RESERVATION) {
        stage.abort_reason = WVM_ADMISSION_ABORT_REASON_PRE_ACTIVATION_FAILURE;
    }
    return submit_record(transport, &target, message_type,
                         candidate->admission_tx_id, candidate->vm_id,
                         candidate->vm_incarnation,
                         candidate->manifest_generation,
                         &candidate->prepared_route_snapshot_key,
                         encode_reservation_stage, &stage, error, error_len);
}

static int transport_reservation_prepare(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    return transport_reservation_stage(context, candidate, reservation,
                                       WVM_ENVELOPE_MSG_PREPARE_RESERVATION,
                                       error, error_len);
}

static int transport_reservation_commit(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    struct wvm_admission_reservation_stage stage;

    if (!activation || !activation->has_activation_fence) {
        set_error(error, error_len,
                  "reservation commit lacks durable activation fence");
        return -1;
    }
    if (candidate_matches_reservation(candidate, reservation, error,
                                      error_len) != 0 ||
        wvm_activation_record_validate(activation, error, error_len) != 0 ||
        activation->decision != WVM_ACTIVATION_ACTIVATE ||
        memcmp(activation->admission_tx_id, candidate->admission_tx_id,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        memcmp(activation->candidate_manifest_digest, candidate->manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0) {
        set_error(error, error_len,
                  "reservation commit does not bind the activation decision");
        return -1;
    }
    if (reservation->state != WVM_RESERVATION_COMMITTED ||
        !reservation->has_activation_fence ||
        memcmp(reservation->activation_fence, activation->activation_fence,
               WVM_IDENTITY_ID_BYTES) != 0) {
        set_error(error, error_len,
                  "reservation commit is not a durable committed reservation");
        return -1;
    }
    {
        struct wvm_admission_transport *transport = context;
        struct wvm_admission_transport_target target;

        if (resolve_node_target(transport, reservation->physical_node_id,
                                reservation->node_instance_id, &target, error,
                                error_len) != 0) {
            return -1;
        }
        memset(&stage, 0, sizeof(stage));
        stage.message_type = WVM_ENVELOPE_MSG_COMMIT_RESERVATION;
        stage.candidate = candidate;
        stage.reservation = reservation;
        stage.activation = activation;
        return submit_record(transport, &target,
                             WVM_ENVELOPE_MSG_COMMIT_RESERVATION,
                             candidate->admission_tx_id, candidate->vm_id,
                             candidate->vm_incarnation,
                             candidate->manifest_generation,
                             &candidate->prepared_route_snapshot_key,
                             encode_reservation_stage, &stage, error, error_len);
    }
}

static int transport_reservation_abort(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation, char *error,
    size_t error_len)
{
    return transport_reservation_stage(context, candidate, reservation,
                                       WVM_ENVELOPE_MSG_ABORT_RESERVATION,
                                       error, error_len);
}

static int transport_participant_stage(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_activation_record *activation, uint16_t message_type,
    char *error, size_t error_len)
{
    struct wvm_admission_transport *transport = context;
    struct wvm_admission_transport_target target;
    struct wvm_admission_participant_stage stage;
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_cpu_dispatch *cpu_entries = NULL;
    struct wvm_runtime_memory_dispatch *memory_entries = NULL;
    int result;

    if (candidate_matches_runtime(candidate, runtime_manifest, error,
                                  error_len) != 0 ||
        resolve_node_target(transport, runtime_manifest->physical_node_id,
                            runtime_manifest->expected_node_instance_id, &target,
                            error, error_len) != 0) {
        return -1;
    }
    memset(&stage, 0, sizeof(stage));
    stage.message_type = message_type;
    stage.candidate = candidate;
    stage.runtime_manifest = runtime_manifest;
    stage.activation = activation;
    if (message_type == WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST) {
        if (!transport->delivery_records ||
            !transport->delivery_route_snapshot ||
            candidate->vcpu_placements.count >
                SIZE_MAX / sizeof(*cpu_entries) ||
            candidate->memory_placements.count >
                SIZE_MAX / sizeof(*memory_entries)) {
            set_error(error, error_len,
                      "activation has no captured dispatch authorities");
            return -1;
        }
        cpu_entries = calloc(candidate->vcpu_placements.count
                                 ? candidate->vcpu_placements.count
                                 : 1U,
                             sizeof(*cpu_entries));
        memory_entries = calloc(candidate->memory_placements.count
                                    ? candidate->memory_placements.count
                                    : 1U,
                                sizeof(*memory_entries));
        if (!cpu_entries || !memory_entries) {
            free(memory_entries);
            free(cpu_entries);
            set_error(error, error_len,
                      "cannot allocate participant dispatch projection");
            return -1;
        }
        memset(&projection, 0, sizeof(projection));
        projection.cpu_dispatch.entries = cpu_entries;
        projection.cpu_dispatch.capacity = candidate->vcpu_placements.count;
        projection.memory_dispatch.entries = memory_entries;
        projection.memory_dispatch.capacity =
            candidate->memory_placements.count;
        if (wvm_runtime_dispatch_projection_build(
                candidate, runtime_manifest, transport->delivery_records,
                transport->delivery_route_snapshot, &projection, error,
                error_len) != 0) {
            free(memory_entries);
            free(cpu_entries);
            return -1;
        }
        stage.dispatch_projection = &projection;
    }
    if (message_type == WVM_ENVELOPE_MSG_ABORT_MANIFEST) {
        stage.abort_reason = WVM_ADMISSION_ABORT_REASON_PRE_ACTIVATION_FAILURE;
    }
    result = submit_record(transport, &target, message_type,
                           candidate->admission_tx_id, candidate->vm_id,
                           candidate->vm_incarnation,
                           candidate->manifest_generation,
                           &runtime_manifest->required_route_snapshot_key,
                           encode_participant_stage, &stage, error, error_len);
    free(memory_entries);
    free(cpu_entries);
    return result;
}

static int transport_participant_prepare(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    return transport_participant_stage(context, candidate, runtime_manifest,
                                       NULL, WVM_ENVELOPE_MSG_PREPARE_MANIFEST,
                                       error, error_len);
}

static int transport_participant_commit(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    if (!activation || !activation->has_activation_fence ||
        !runtime_manifest->has_activation_fence ||
        memcmp(activation->activation_fence, runtime_manifest->activation_fence,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        candidate_matches_runtime(candidate, runtime_manifest, error,
                                  error_len) != 0) {
        set_error(error, error_len,
                  "participant activation does not bind durable activation fence");
        return -1;
    }
    return transport_participant_stage(context, candidate, runtime_manifest,
                                       activation, WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST,
                                       error, error_len);
}

static int transport_participant_abort(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    return transport_participant_stage(context, candidate, runtime_manifest,
                                       NULL, WVM_ENVELOPE_MSG_ABORT_MANIFEST,
                                       error, error_len);
}

static int transport_participant_ready(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    struct wvm_admission_transport *transport = context;

    return wvm_admission_transport_query_runtime_ready(
        transport, candidate, runtime_manifest, error, error_len);
}

int wvm_admission_transport_query_runtime_ready(
    struct wvm_admission_transport *transport,
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    struct wvm_admission_transport_target target;
    struct wvm_admission_participant_stage stage;

    if (candidate_matches_runtime(candidate, runtime_manifest, error,
                                  error_len) != 0 ||
        !runtime_manifest->has_activation_fence ||
        resolve_node_target(transport, runtime_manifest->physical_node_id,
                            runtime_manifest->expected_node_instance_id,
                            &target, error, error_len) != 0) {
        set_error(error, error_len,
                  "runtime readiness query does not bind an activated participant");
        return -1;
    }
    memset(&stage, 0, sizeof(stage));
    stage.message_type = WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY;
    stage.candidate = candidate;
    stage.runtime_manifest = runtime_manifest;
    return submit_record(transport, &target,
                         WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY,
                         candidate->admission_tx_id, candidate->vm_id,
                         candidate->vm_incarnation,
                         candidate->manifest_generation,
                         &runtime_manifest->required_route_snapshot_key,
                         encode_participant_stage, &stage, error, error_len);
}

int wvm_admission_transport_init(
    struct wvm_admission_transport *transport,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    void *context, wvm_admission_transport_resolve_member_fn resolve_member,
    wvm_admission_transport_submit_fn submit, char *error, size_t error_len)
{
    if (!transport) {
        set_error(error, error_len, "admission transport storage is missing");
        return -1;
    }
    memset(transport, 0, sizeof(*transport));
    transport->controller_physical_node_id = controller_physical_node_id;
    transport->controller_instance_id = controller_instance_id;
    transport->context = context;
    transport->resolve_member = resolve_member;
    transport->submit = submit;
    return transport_validate(transport, error, error_len);
}

int wvm_admission_transport_callbacks(
    struct wvm_admission_transport *transport,
    struct wvm_admission_orchestrator_callbacks *callbacks, char *error,
    size_t error_len)
{
    if (transport_validate(transport, error, error_len) != 0 || !callbacks) {
        set_error(error, error_len, "admission transport callback output is invalid");
        return -1;
    }
    memset(callbacks, 0, sizeof(*callbacks));
    callbacks->route_plan = NULL;
    callbacks->route_prepare = transport_route_prepare;
    callbacks->route_commit = transport_route_commit;
    callbacks->route_abort = transport_route_abort;
    callbacks->reservation_prepare = transport_reservation_prepare;
    callbacks->reservation_commit = transport_reservation_commit;
    callbacks->reservation_abort = transport_reservation_abort;
    callbacks->participant_prepare = transport_participant_prepare;
    callbacks->participant_commit = transport_participant_commit;
    callbacks->participant_abort = transport_participant_abort;
    callbacks->participant_ready = transport_participant_ready;
    return 0;
}

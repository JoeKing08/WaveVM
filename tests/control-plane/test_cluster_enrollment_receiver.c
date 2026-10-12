#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_admission_node_service.h"
#include "wavevm_admission_receiver.h"
#include "wavevm_control_transport.h"

#define PROOF_CAPACITY WVM_ADMISSION_ENROLLMENT_DEFAULT_PROOF_BYTES

struct authentication_context {
    struct wvm_member_key actor;
};

static int authenticate_controller(void *opaque, int stream_fd,
                                   struct wvm_member_key *actor, char *error,
                                   size_t error_len)
{
    struct authentication_context *context = opaque;

    (void)stream_fd;
    (void)error;
    (void)error_len;
    if (!context || !actor) {
        return -1;
    }
    *actor = context->actor;
    return 0;
}

static int connect_retry(const char *path)
{
    struct sockaddr_un address;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000L};
    int attempt;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (!path || strlen(path) >= sizeof(address.sun_path)) {
        return -1;
    }
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    for (attempt = 0; attempt < 200; attempt++) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

        if (fd >= 0 && connect(fd, (const struct sockaddr *)&address,
                               (socklen_t)(offsetof(struct sockaddr_un,
                                                    sun_path) +
                                           strlen(path) + 1U)) == 0) {
            return fd;
        }
        if (fd >= 0) {
            close(fd);
        }
        nanosleep(&delay, NULL);
    }
    return -1;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = (uint8_t)(port & 0xffU);
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->has_control_address = 1;
    endpoint->control_address_bytes = 4;
    endpoint->control_address[0] = 198;
    endpoint->control_address[1] = 51;
    endpoint->control_address[2] = 100;
    endpoint->control_address[3] = (uint8_t)(port & 0xffU);
    endpoint->control_port = (uint16_t)(port + 1000U);
}

static void fill_key(struct wvm_member_key *key, uint32_t role_id,
                     uint64_t instance_id)
{
    memset(key, 0, sizeof(*key));
    key->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    key->role_id = role_id;
    key->instance_id = instance_id;
}

static void fill_proof(struct wvm_cluster_admission_proof *proof,
                       struct wvm_cluster_admission_ack_entry *acks,
                       const struct wvm_endpoint *local_endpoint,
                       const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                       int include_local)
{
    struct wvm_endpoint peer_endpoint;

    memset(proof, 0, sizeof(*proof));
    memcpy(proof->operation_id, operation_id, WVM_IDENTITY_ID_BYTES);
    fill_key(&proof->member_key, 803, 804);
    proof->membership_revision = 7;
    proof->topology_revision = 8;
    proof->admission_eligibility_revision = 9;
    memset(proof->canonical_member_record_digest, 0x11,
           sizeof(proof->canonical_member_record_digest));
    memset(proof->capability_evidence_digest, 0x22,
           sizeof(proof->capability_evidence_digest));
    memset(proof->topology_assignment_digest, 0x33,
           sizeof(proof->topology_assignment_digest));
    fill_endpoint(&peer_endpoint, 803);
    proof->required_ack_set.entries.entries = acks;
    proof->required_ack_set.entries.capacity = include_local ? 2 : 1;
    proof->required_ack_set.entries.count = include_local ? 2 : 1;
    if (include_local) {
        fill_key(&acks[0].member_key, 801, 802);
        acks[0].endpoint = *local_endpoint;
        acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        acks[1].member_key = proof->member_key;
        acks[1].endpoint = peer_endpoint;
        acks[1].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    } else {
        acks[0].member_key = proof->member_key;
        acks[0].endpoint = peer_endpoint;
        acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    }
}

static int encode_proof(struct wvm_cluster_admission_proof *proof,
                        uint8_t *payload, size_t payload_capacity,
                        size_t *payload_bytes, char *error, size_t error_len)
{
    return wvm_cluster_admission_proof_encode(
        proof, payload, payload_capacity, payload_bytes, error, error_len);
}

static void fill_request(struct wvm_envelope *request, uint16_t message_type,
                         const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                         const uint8_t *payload, size_t payload_bytes)
{
    memset(request, 0, sizeof(*request));
    request->message_type = message_type;
    request->origin_physical_node_id = 701;
    request->origin_runtime_instance_id = 702;
    memcpy(request->operation_id, operation_id, WVM_IDENTITY_ID_BYTES);
    request->delivery_attempt_id = 1;
    request->payload = payload;
    request->payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 request->semantic_payload_digest);
}

static void init_enrollment_slots(
    struct wvm_admission_enrollment_slot *slots, uint8_t *storage,
    size_t slot_count)
{
    size_t i;

    for (i = 0; i < slot_count; i++) {
        memset(&slots[i], 0, sizeof(slots[i]));
        slots[i].proof_bytes = storage + i * PROOF_CAPACITY;
        slots[i].proof_capacity = PROOF_CAPACITY;
    }
}

static void fill_receiver_config(
    struct wvm_admission_receiver_config *config,
    struct wvm_member_key *controller, const struct wvm_endpoint *endpoint,
    const char *state_directory,
    struct wvm_admission_enrollment_slot *slots, size_t slot_count,
    uint8_t *proof_storage, uint8_t *proof_scratch,
    struct wvm_cluster_admission_ack_entry *ack_scratch)
{
    memset(config, 0, sizeof(*config));
    config->controller_member_key = *controller;
    config->controller_physical_node_id = 701;
    config->controller_runtime_instance_id = 702;
    config->local_physical_node_id = 801;
    config->local_node_instance_id = 802;
    config->local_endpoint = endpoint;
    config->enrollment_state_directory = state_directory;
    config->enrollment_slots = slots;
    config->enrollment_slot_capacity = slot_count;
    config->enrollment_proof_storage = proof_storage;
    config->enrollment_proof_capacity = PROOF_CAPACITY;
    config->enrollment_proof_scratch = proof_scratch;
    config->enrollment_proof_scratch_capacity = PROOF_CAPACITY;
    config->enrollment_ack_scratch = ack_scratch;
    config->enrollment_ack_scratch_capacity = 4;
}

static int apply_expect(struct wvm_admission_receiver *receiver,
                        const struct wvm_envelope *request,
                        const struct wvm_member_key *actor, uint16_t status,
                        uint16_t state, char *error, size_t error_len)
{
    struct wvm_control_result result;

    memset(&result, 0, sizeof(result));
    if (wvm_admission_receiver_apply(receiver, request, actor, &result, error,
                                     error_len) != 0 ||
        result.status_code != status ||
        (status == WVM_CONTROL_RESULT_SUCCESS &&
         result.recorded_state != state)) {
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_admission_receiver receiver;
    struct wvm_admission_receiver_config receiver_config;
    struct wvm_admission_node_service service;
    struct wvm_admission_node_service_config service_config;
    struct authentication_context authentication;
    struct wvm_member_key controller;
    struct wvm_member_key wrong_actor;
    struct wvm_endpoint local_endpoint;
    struct wvm_admission_enrollment_slot slots[4];
    struct wvm_cluster_admission_ack_entry acks[2];
    uint8_t proof_storage[4][PROOF_CAPACITY];
    uint8_t proof_scratch[PROOF_CAPACITY];
    struct wvm_cluster_admission_ack_entry ack_scratch[4];
    struct wvm_cluster_admission_proof proof;
    struct wvm_envelope request;
    char directory[] = "/tmp/wavevm-cluster-enrollment.XXXXXX";
    char socket_path[256];
    uint8_t payload[PROOF_CAPACITY];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0};
    size_t payload_bytes = 0;
    size_t i;
    char error[256] = {0};
    int fd = -1;
    int status = 1;

    operation_id[15] = 0x41;
    fill_key(&controller, 701, 702);
    fill_key(&wrong_actor, 705, 706);
    fill_endpoint(&local_endpoint, 801);
    if (!mkdtemp(directory) ||
        snprintf(socket_path, sizeof(socket_path), "%s/admission.sock",
                 directory) < 0) {
        return 1;
    }
    init_enrollment_slots(slots, &proof_storage[0][0], 4);
    fill_receiver_config(&receiver_config, &controller, &local_endpoint,
                         directory, slots, 4, &proof_storage[0][0],
                         proof_scratch, ack_scratch);
    if (wvm_admission_receiver_init(&receiver, &receiver_config, error,
                                    sizeof(error)) != 0) {
        fprintf(stderr, "receiver init: %s\n", error);
        goto out;
    }

    fill_proof(&proof, acks, &local_endpoint, operation_id, 0);
    if (encode_proof(&proof, payload, sizeof(payload), &payload_bytes, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "missing-ACK proof encode: %s\n", error);
        goto receiver_out;
    }
    fill_request(&request, WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_PREPARE,
                 operation_id, payload, payload_bytes);
    if (apply_expect(&receiver, &request, &wrong_actor,
                     WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE, 0, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "wrong actor was accepted: %s\n", error);
        goto receiver_out;
    }
    if (apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_PRECONDITION_FAILED, 0, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "missing local ACK was accepted: %s\n", error);
        goto receiver_out;
    }

    fill_proof(&proof, acks, &local_endpoint, operation_id, 1);
    if (encode_proof(&proof, payload, sizeof(payload), &payload_bytes, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "valid proof encode: %s\n", error);
        goto receiver_out;
    }
    fill_request(&request, WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_PREPARE,
                 operation_id, payload, payload_bytes);
    if (apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_SUCCESS,
                     WVM_ADMISSION_ENROLLMENT_PARTICIPANT_PREPARED, error,
                     sizeof(error)) != 0 ||
        apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_SUCCESS,
                     WVM_ADMISSION_ENROLLMENT_PARTICIPANT_PREPARED, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "prepare or prepare replay failed: %s\n", error);
        goto receiver_out;
    }
    request.message_type = WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_COMMIT;
    if (apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_SUCCESS,
                     WVM_ADMISSION_ENROLLMENT_PARTICIPANT_COMMITTED, error,
                     sizeof(error)) != 0 ||
        apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_SUCCESS,
                     WVM_ADMISSION_ENROLLMENT_PARTICIPANT_COMMITTED, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "commit or commit replay failed: %s\n", error);
        goto receiver_out;
    }
    request.message_type = WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_ABORT;
    if (apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_PRECONDITION_FAILED, 0, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "abort/commit conflict was accepted: %s\n", error);
        goto receiver_out;
    }

    operation_id[15] = 0x42;
    fill_proof(&proof, acks, &local_endpoint, operation_id, 1);
    if (encode_proof(&proof, payload, sizeof(payload), &payload_bytes, error,
                     sizeof(error)) != 0) {
        goto receiver_out;
    }
    fill_request(&request, WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_PREPARE,
                 operation_id, payload, payload_bytes);
    if (apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_SUCCESS,
                     WVM_ADMISSION_ENROLLMENT_PARTICIPANT_PREPARED, error,
                     sizeof(error)) != 0) {
        goto receiver_out;
    }
    request.message_type = WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_ABORT;
    if (apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_SUCCESS,
                     WVM_ADMISSION_ENROLLMENT_PARTICIPANT_ABORTED, error,
                     sizeof(error)) != 0 ||
        apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_SUCCESS,
                     WVM_ADMISSION_ENROLLMENT_PARTICIPANT_ABORTED, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "abort or abort replay failed: %s\n", error);
        goto receiver_out;
    }
    request.message_type = WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_COMMIT;
    if (apply_expect(&receiver, &request, &controller,
                     WVM_CONTROL_RESULT_PRECONDITION_FAILED, 0, error,
                     sizeof(error)) != 0) {
        fprintf(stderr, "commit/abort conflict was accepted: %s\n", error);
        goto receiver_out;
    }
    wvm_admission_receiver_destroy(&receiver);

    /* GATEWAY local_role_type must match proof ACK role for participation. */
    memset(slots, 0, sizeof(slots));
    init_enrollment_slots(slots, &proof_storage[0][0], 4);
    fill_receiver_config(&receiver_config, &controller, &local_endpoint,
                         directory, slots, 4, &proof_storage[0][0],
                         proof_scratch, ack_scratch);
    receiver_config.local_role_type = WVM_MANIFEST_ROLE_GATEWAY;
    receiver_config.local_physical_node_id = 901;
    receiver_config.local_node_instance_id = 902;
    if (wvm_admission_receiver_init(&receiver, &receiver_config, error,
                                    sizeof(error)) != 0) {
        fprintf(stderr, "gateway receiver init failed: %s\n", error);
        goto out;
    }
    {
        struct wvm_member_key gateway_key;
        struct wvm_endpoint gateway_endpoint = local_endpoint;
        uint8_t gw_operation_id[WVM_IDENTITY_ID_BYTES];

        memset(&gateway_key, 0, sizeof(gateway_key));
        gateway_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
        gateway_key.role_id = 901;
        gateway_key.instance_id = 902;
        memset(gw_operation_id, 0, sizeof(gw_operation_id));
        gw_operation_id[15] = 0x91;
        memset(&proof, 0, sizeof(proof));
        memcpy(proof.operation_id, gw_operation_id, WVM_IDENTITY_ID_BYTES);
        proof.member_key = gateway_key;
        proof.membership_revision = 7;
        proof.topology_revision = 8;
        proof.admission_eligibility_revision = 9;
        memset(proof.canonical_member_record_digest, 0x41,
               sizeof(proof.canonical_member_record_digest));
        memset(proof.capability_evidence_digest, 0x42,
               sizeof(proof.capability_evidence_digest));
        memset(proof.topology_assignment_digest, 0x43,
               sizeof(proof.topology_assignment_digest));
        proof.required_ack_set.entries.entries = acks;
        proof.required_ack_set.entries.capacity = 1;
        proof.required_ack_set.entries.count = 1;
        acks[0].member_key = gateway_key;
        acks[0].endpoint = gateway_endpoint;
        acks[0].role_type = WVM_MANIFEST_ROLE_GATEWAY;
        if (encode_proof(&proof, payload, sizeof(payload), &payload_bytes, error,
                         sizeof(error)) != 0) {
            fprintf(stderr, "gateway proof encode failed: %s\n", error);
            goto receiver_out;
        }
        fill_request(&request, WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_PREPARE,
                     gw_operation_id, payload, payload_bytes);
        if (apply_expect(&receiver, &request, &controller,
                         WVM_CONTROL_RESULT_SUCCESS,
                         WVM_ADMISSION_ENROLLMENT_PARTICIPANT_PREPARED, error,
                         sizeof(error)) != 0) {
            fprintf(stderr, "gateway prepare failed: %s\n", error);
            goto receiver_out;
        }
        fill_request(&request, WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_COMMIT,
                     gw_operation_id, payload, payload_bytes);
        if (apply_expect(&receiver, &request, &controller,
                         WVM_CONTROL_RESULT_SUCCESS,
                         WVM_ADMISSION_ENROLLMENT_PARTICIPANT_COMMITTED, error,
                         sizeof(error)) != 0) {
            fprintf(stderr, "gateway commit failed: %s\n", error);
            goto receiver_out;
        }
    }
    wvm_admission_receiver_destroy(&receiver);

    memset(slots, 0, sizeof(slots));
    init_enrollment_slots(slots, &proof_storage[0][0], 4);
    fill_receiver_config(&receiver_config, &controller, &local_endpoint,
                         directory, slots, 4, &proof_storage[0][0],
                         proof_scratch, ack_scratch);
    memset(&service_config, 0, sizeof(service_config));
    service_config.socket_path = socket_path;
    service_config.socket_mode = S_IRUSR | S_IWUSR;
    service_config.listen_backlog = 4;
    service_config.local_physical_node_id = 801;
    service_config.local_runtime_instance_id = 802;
    service_config.max_frame_bytes = WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    service_config.authenticate = authenticate_controller;
    service_config.authenticate_opaque = &authentication;
    service_config.receiver = receiver_config;
    authentication.actor = controller;
    if (wvm_admission_node_service_init(&service, &service_config, error,
                                        sizeof(error)) != 0 ||
        wvm_admission_node_service_start(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "node service init: %s\n", error);
        goto out;
    }
    operation_id[15] = 0x43;
    fill_proof(&proof, acks, &local_endpoint, operation_id, 1);
    if (encode_proof(&proof, payload, sizeof(payload), &payload_bytes, error,
                     sizeof(error)) != 0) {
        goto service_out;
    }
    fill_request(&request, WVM_ENVELOPE_MSG_CLUSTER_ENROLLMENT_PREPARE,
                 operation_id, payload, payload_bytes);
    fd = connect_retry(socket_path);
    if (fd < 0) {
        goto service_out;
    }
    {
        struct wvm_control_result result;

        memset(&result, 0, sizeof(result));
        if (wvm_control_transport_exchange(fd, 801, 802, &request, &result,
                                            error, sizeof(error)) != 0 ||
            result.status_code != WVM_CONTROL_RESULT_SUCCESS ||
            result.recorded_state !=
                WVM_ADMISSION_ENROLLMENT_PARTICIPANT_PREPARED) {
            fprintf(stderr, "typed service enrollment result failed: %s\n",
                    error);
            close(fd);
            goto service_out;
        }
    }
    close(fd);
    status = 0;
service_out:
    (void)wvm_admission_node_service_stop(&service, error, sizeof(error));
    wvm_admission_node_service_destroy(&service);
    goto out;
receiver_out:
    wvm_admission_receiver_destroy(&receiver);
out:
    for (i = 0; i < 4; i++) {
        memset(&slots[i], 0, sizeof(slots[i]));
    }
    if (fd >= 0) {
        close(fd);
    }
    unlink(socket_path);
    rmdir(directory);
    return status;
}

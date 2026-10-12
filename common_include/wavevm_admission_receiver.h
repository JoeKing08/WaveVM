#ifndef WAVEVM_ADMISSION_RECEIVER_H
#define WAVEVM_ADMISSION_RECEIVER_H

/*
 * Local participant adapter for the canonical admission transaction.  This
 * module owns no placement, membership, route, or VM state.  Its caller
 * supplies every persistent local authority and the exact delivery inputs
 * captured by the controller-owned transaction.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission_stage.h"
#include "wavevm_manifest.h"
#include "wavevm_control_transport.h"
#include "wavevm_reservation_runtime.h"
#include "wavevm_route_control.h"
#include "wavevm_runtime_delivery.h"

#define WVM_ADMISSION_ENROLLMENT_STATE_PATH_MAX 4096U
#define WVM_ADMISSION_ENROLLMENT_DEFAULT_PROOF_BYTES (64U * 1024U)

enum wvm_admission_enrollment_participant_state {
    WVM_ADMISSION_ENROLLMENT_PARTICIPANT_NONE = 0,
    WVM_ADMISSION_ENROLLMENT_PARTICIPANT_PREPARED = 1,
    WVM_ADMISSION_ENROLLMENT_PARTICIPANT_COMMITTED = 2,
    WVM_ADMISSION_ENROLLMENT_PARTICIPANT_ABORTED = 3,
};

/* Caller-owned, fixed-capacity durable state for one cluster enrollment op. */
struct wvm_admission_enrollment_slot {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    enum wvm_admission_enrollment_participant_state state;
    uint8_t *proof_bytes;
    size_t proof_capacity;
    size_t proof_bytes_count;
    char state_path[WVM_ADMISSION_ENROLLMENT_STATE_PATH_MAX];
    int state_failed;
};

struct wvm_admission_receiver_slot {
    /* Both storage sets and all nested arrays are caller-owned and bounded. */
    struct wvm_admission_participant_stage_storage prepared_storage;
    struct wvm_admission_participant_stage_storage scratch_storage;
    struct wvm_runtime_gate gate;
    const char *runtime_manifest_path;
    int has_prepared;
    int has_activated;
    int has_activation_decision;
    int has_aborted;
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    char *state_path;
    int state_lock_fd;
    int state_failed;
};

typedef int (*wvm_admission_receiver_resolve_slot_fn)(
    void *context, uint32_t vm_id, uint64_t vm_incarnation,
    uint64_t manifest_generation, struct wvm_admission_receiver_slot **slot_out,
    char *error, size_t error_len);

/*
 * Resolve the exact immutable inputs needed to publish one activated local
 * projection. The provider returns borrowed references valid for this call;
 * it must not derive a replacement route or cluster record set.
 */
typedef int (*wvm_admission_receiver_delivery_inputs_fn)(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest,
    const struct wvm_activation_record *activation,
    const struct wvm_cluster_record_set **cluster_records_out,
    const struct wvm_route_snapshot_record **route_snapshot_out, char *error,
    size_t error_len);

typedef int (*wvm_admission_receiver_start_runtime_fn)(
    void *context, const struct wvm_admission_receiver_slot *slot,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len);

struct wvm_admission_receiver_config {
    struct wvm_member_key controller_member_key;
    uint32_t controller_physical_node_id;
    uint64_t controller_runtime_instance_id;
    uint32_t local_physical_node_id;
    uint64_t local_node_instance_id;
    /*
     * Local membership role for cluster-enrollment participation.
     * NODE_RUNTIME uses physical_node_id as role_id; GATEWAY uses gateway_id
     * in local_physical_node_id. Zero means NODE_RUNTIME for back-compat.
     */
    enum wvm_manifest_role_type local_role_type;
    struct wvm_local_reservation_registry *reservation_registry;
    /*
     * Transient decode storage reused under the receiver lock.  All nested
     * buffers remain caller-owned, so a control message cannot allocate the
     * protocol maximum on the receive path.
     */
    struct wvm_admission_reservation_stage_storage *reservation_scratch_storage;
    struct wvm_route_control *route_control;
    const struct wvm_endpoint *local_endpoint;
    const char *enrollment_state_directory;
    struct wvm_admission_enrollment_slot *enrollment_slots;
    size_t enrollment_slot_capacity;
    uint8_t *enrollment_proof_storage;
    size_t enrollment_proof_capacity;
    uint8_t *enrollment_proof_scratch;
    size_t enrollment_proof_scratch_capacity;
    struct wvm_cluster_admission_ack_entry *enrollment_ack_scratch;
    size_t enrollment_ack_scratch_capacity;
    void *context;
    wvm_admission_receiver_resolve_slot_fn resolve_slot;
    wvm_admission_receiver_delivery_inputs_fn delivery_inputs;
    wvm_admission_receiver_start_runtime_fn start_runtime;
};

struct wvm_admission_receiver {
    struct wvm_admission_receiver_config config;
    pthread_mutex_t lock;
    int initialized;
};

/* Call after configuring caller-owned storage in SLOT. */
void wvm_admission_receiver_slot_init(struct wvm_admission_receiver_slot *slot);

/* Open once before publishing SLOT through resolve_slot. The bounded state
 * file retains the latest canonical stage, including abort tombstones. An
 * activation recovered here is not runnable until delivery is retried.
 * A failed/uncertain write requires close/open; callers must not recycle an
 * identity or remove its state file to recover from an error. */
int wvm_admission_receiver_slot_open(
    struct wvm_admission_receiver *receiver,
    struct wvm_admission_receiver_slot *slot, const char *state_path,
    uint32_t vm_id, uint64_t vm_incarnation, uint64_t manifest_generation,
    char *error, size_t error_len);

/* Does not free caller-owned decode arrays or delete durable state. */
void wvm_admission_receiver_slot_close(struct wvm_admission_receiver_slot *slot);

int wvm_admission_receiver_init(
    struct wvm_admission_receiver *receiver,
    const struct wvm_admission_receiver_config *config, char *error,
    size_t error_len);

void wvm_admission_receiver_destroy(struct wvm_admission_receiver *receiver);

/*
 * Apply one authenticated admission or route stage. Semantic rejection is
 * returned in RESULT; a nonzero return is reserved for invalid receiver
 * setup or an output failure that prevents forming a typed result.
 */
int wvm_admission_receiver_apply(
    void *context, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_control_result *result, char *error, size_t error_len);

#endif /* WAVEVM_ADMISSION_RECEIVER_H */

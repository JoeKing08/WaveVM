#ifndef WAVEVM_MEMBERSHIP_CONTROL_H
#define WAVEVM_MEMBERSHIP_CONTROL_H

/*
 * Authenticated V1 control receiver for membership registration, rejoin, and
 * explicitly authorized gateway drain. The transport authenticates a principal
 * before calling apply(); this layer validates the envelope/payload binding,
 * invokes the durable membership authority, and persists exactly one
 * replayable ControlResult per operation.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "wavevm_envelope.h"
#include "wavevm_membership_controller.h"

#define WVM_MEMBERSHIP_CONTROL_RESULT_BYTES 72U
#define WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES \
    WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES

enum wvm_membership_control_status {
    WVM_MEMBERSHIP_CONTROL_SUCCESS = 0,
    WVM_MEMBERSHIP_CONTROL_INVALID_ENVELOPE = 1,
    WVM_MEMBERSHIP_CONTROL_INVALID_RECORD = 2,
    WVM_MEMBERSHIP_CONTROL_UNAUTHORIZED_ROLE = 3,
    WVM_MEMBERSHIP_CONTROL_STALE_INSTANCE = 4,
    WVM_MEMBERSHIP_CONTROL_ELIGIBILITY_FENCE_STALE = 5,
    WVM_MEMBERSHIP_CONTROL_PRECONDITION_FAILED = 6,
    WVM_MEMBERSHIP_CONTROL_OPERATION_ID_CONFLICT = 7,
    WVM_MEMBERSHIP_CONTROL_NOT_FOUND = 8,
    WVM_MEMBERSHIP_CONTROL_RESULT_EXPIRED = 9,
    WVM_MEMBERSHIP_CONTROL_BACKPRESSURE = 10,
    WVM_MEMBERSHIP_CONTROL_UNSUPPORTED = 11,
    WVM_MEMBERSHIP_CONTROL_INTERNAL_FAILURE = 12,
};

struct wvm_membership_control_result {
    uint16_t status_code;
    uint16_t recorded_state;
    uint32_t result_flags;
    uint8_t in_reply_to_operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t record_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t applied_revision;
    uint64_t expiry_or_retention_deadline;
};

struct wvm_membership_control_operation {
    uint16_t message_type;
    struct wvm_member_key authenticated_actor;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t semantic_payload_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_membership_control_result result;
};

typedef int (*wvm_membership_control_result_sink_fn)(
    void *context, const struct wvm_envelope *request,
    const struct wvm_membership_control_result *result, char *error,
    size_t error_len);

/*
 * Adapter state for the authenticated ingress boundary. The sink owns the
 * transport-specific response path; this layer only applies the durable
 * operation and hands it the typed result.
 */
struct wvm_membership_control_dispatch_context {
    struct wvm_membership_control *control;
    wvm_membership_control_result_sink_fn result_sink;
    void *result_sink_context;
};

enum wvm_membership_control_membership_action {
    WVM_MEMBERSHIP_CONTROL_MEMBERSHIP_ACTION_CORDON = 1,
    WVM_MEMBERSHIP_CONTROL_MEMBERSHIP_ACTION_DRAIN_COMPUTE = 2,
};

/*
 * Gateway drain is a management operation. It is never self-authorized by the
 * target gateway and never borrows a node-runtime membership principal. The
 * transport supplies an authenticated EXECUTOR principal and this callback
 * makes the control-plane authorization decision. A missing callback denies
 * the operation.
 */
typedef int (*wvm_membership_control_authorize_management_fn)(
    void *context, enum wvm_gateway_drain_action action,
    const struct wvm_member_key *actor,
    const struct wvm_member_key *target_gateway, char *error,
    size_t error_len);

/*
 * Cordon and compute drain are membership-management operations. They have a
 * separate trust hook from gateway drain because the target may be a node
 * runtime (or gateway for cordon), and the policy is not a route replacement.
 */
typedef int (*wvm_membership_control_authorize_membership_fn)(
    void *context, enum wvm_membership_control_membership_action action,
    const struct wvm_member_key *actor,
    const struct wvm_member_key *target_member, char *error, size_t error_len);

struct wvm_membership_control {
    pthread_mutex_t lock;
    int lock_initialized;
    int journal_fd;
    uint64_t next_journal_sequence;
    struct wvm_membership_controller *controller;
    struct wvm_membership_control_operation *operations;
    size_t operation_count;
    size_t operation_capacity;
    wvm_membership_control_authorize_management_fn authorize_management;
    void *authorize_management_context;
    wvm_membership_control_authorize_membership_fn authorize_membership;
    void *authorize_membership_context;
};

/*
 * Operation storage is caller-owned and bounded. The controller must already
 * be opened before this receiver is opened, because its state journal is the
 * durable authority mutated by successful requests.
 */
void wvm_membership_control_init(
    struct wvm_membership_control *control,
    struct wvm_membership_controller *controller,
    struct wvm_membership_control_operation *operations,
    size_t operation_capacity);

/*
 * Set before open(). Runtime replacement is rejected to keep the authorization
 * boundary immutable for one recovered operation journal.
 */
int wvm_membership_control_set_management_authorizer(
    struct wvm_membership_control *control,
    wvm_membership_control_authorize_management_fn authorize,
    void *authorize_context);
int wvm_membership_control_set_membership_authorizer(
    struct wvm_membership_control *control,
    wvm_membership_control_authorize_membership_fn authorize,
    void *authorize_context);

int wvm_membership_control_open(struct wvm_membership_control *control,
                                const char *journal_path, char *error,
                                size_t error_len);

void wvm_membership_control_close(struct wvm_membership_control *control);

/*
 * Encode/decode the fixed wire payload documented as ControlResult. The
 * result itself is not a canonical record.
 */
int wvm_membership_control_result_encode(
    const struct wvm_membership_control_result *result,
    uint8_t bytes[WVM_MEMBERSHIP_CONTROL_RESULT_BYTES]);
int wvm_membership_control_result_decode(
    const uint8_t bytes[WVM_MEMBERSHIP_CONTROL_RESULT_BYTES],
    struct wvm_membership_control_result *result);

/*
 * Apply one already transport-authenticated and V1-decoded control request.
 * A syntactically valid request always receives a typed result in RESULT_OUT;
 * nonzero return means no durable success result is available (for example a
 * journal write failed). AUTHENTICATED_ACTOR is transport identity, never a
 * payload-provided substitute.
 */
int wvm_membership_control_apply(
    struct wvm_membership_control *control,
    const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result_out, char *error,
    size_t error_len);

/* Signature-compatible with wvm_ingress_control_dispatch_fn. */
int wvm_membership_control_dispatch(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len);

/*
 * Encode canonical 0x102a RejoinMemberRequest for production senders and
 * dual-impl fixtures. PRIOR_MEMBER may be NULL; recovery digest must be
 * nonzero. Layout matches decode_rejoin_request / canonical-record-schema.
 */
int wvm_membership_rejoin_request_encode(
    const uint8_t *member_record, size_t member_record_bytes,
    const struct wvm_member_key *prior_member,
    const uint8_t recovery_evidence_digest[WVM_SHA256_DIGEST_BYTES],
    uint8_t *bytes, size_t capacity, size_t *encoded_bytes, char *error,
    size_t error_len);

#endif /* WAVEVM_MEMBERSHIP_CONTROL_H */

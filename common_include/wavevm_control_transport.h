#ifndef WAVEVM_CONTROL_TRANSPORT_H
#define WAVEVM_CONTROL_TRANSPORT_H

/*
 * Reliable, ordered control-plane stream framing.  This adapter deliberately
 * has no membership state of its own: the caller supplies the authenticated
 * actor and the one authoritative control-plane dispatcher.
 */

#include <stddef.h>
#include <stdint.h>

#include "wavevm_membership_control.h"

#define WVM_CONTROL_TRANSPORT_FRAME_PREFIX_BYTES 4U
#define WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES \
    (WVM_ENVELOPE_HEADER_BYTES + WVM_ENVELOPE_MAX_LOCAL_PAYLOAD)
#define WVM_CONTROL_RESULT_BYTES 132U

/* Shared status registry for non-membership control operations. */
enum wvm_control_result_status {
    WVM_CONTROL_RESULT_SUCCESS = 0,
    WVM_CONTROL_RESULT_INVALID_ENVELOPE = 1,
    WVM_CONTROL_RESULT_INVALID_REQUEST = 2,
    WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE = 3,
    WVM_CONTROL_RESULT_STALE_INSTANCE = 4,
    WVM_CONTROL_RESULT_ELIGIBILITY_FENCE_STALE = 5,
    WVM_CONTROL_RESULT_PRECONDITION_FAILED = 6,
    WVM_CONTROL_RESULT_OPERATION_ID_CONFLICT = 7,
    WVM_CONTROL_RESULT_NOT_FOUND = 8,
    WVM_CONTROL_RESULT_EXPIRED = 9,
    WVM_CONTROL_RESULT_BACKPRESSURE = 10,
    WVM_CONTROL_RESULT_UNSUPPORTED = 11,
    WVM_CONTROL_RESULT_INTERNAL_FAILURE = 12,
};

/* Common result for control operations that may allocate a VM namespace. */
struct wvm_control_result {
    uint16_t status_code;
    uint16_t recorded_state;
    uint32_t result_flags;
    uint8_t in_reply_to_operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t record_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t applied_revision;
    uint64_t expiry_or_retention_deadline;
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t admission_tx_id[WVM_IDENTITY_ID_BYTES];
    uint8_t manifest_id[WVM_IDENTITY_ID_BYTES];
    uint64_t route_scope_id;
};

enum wvm_control_transport_status {
    WVM_CONTROL_TRANSPORT_ACCEPTED = 0,
    WVM_CONTROL_TRANSPORT_EOF = 1,
};

typedef int (*wvm_control_transport_authenticate_fn)(
    void *opaque, int stream_fd, struct wvm_member_key *actor, char *error,
    size_t error_len);

typedef int (*wvm_control_transport_dispatch_fn)(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len);

typedef int (*wvm_control_transport_apply_fn)(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len);

typedef int (*wvm_control_transport_control_apply_fn)(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_control_result *result, char *error, size_t error_len);

/* Admission stages have a separate owner from ordinary control requests. */
typedef int (*wvm_control_transport_admission_apply_fn)(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_control_result *result, char *error, size_t error_len);

struct wvm_control_transport_config {
    int stream_fd;
    size_t max_frame_bytes;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    wvm_control_transport_authenticate_fn authenticate;
    void *authenticate_opaque;
    wvm_control_transport_apply_fn apply;
    void *apply_opaque;
    wvm_control_transport_control_apply_fn control_apply;
    void *control_apply_opaque;
    wvm_control_transport_admission_apply_fn admission_apply;
    void *admission_apply_opaque;
    wvm_control_transport_dispatch_fn dispatch;
    void *dispatch_opaque;
};

struct wvm_control_stream {
    struct wvm_control_transport_config config;
    int response_sent;
};

int wvm_control_transport_init(
    struct wvm_control_stream *transport,
    const struct wvm_control_transport_config *config, char *error,
    size_t error_len);

void wvm_control_transport_destroy(struct wvm_control_stream *transport);

/*
 * Serve exactly one length-prefixed local envelope.  A clean EOF before the
 * next prefix returns WVM_CONTROL_TRANSPORT_EOF.  Protocol and I/O failures
 * are negative errno-style values and the stream owner should close the fd.
 */
int wvm_control_transport_serve_once(
    struct wvm_control_stream *transport, char *error, size_t error_len);

/*
 * Exchange one CREATE_VM or admission-stage request on a caller-owned,
 * authenticated stream socket. The owner supplies the verified peer identity,
 * configures I/O timeouts, serializes exchanges, and closes the socket on error.
 * This is framing only, not a TLS connector; never pass an unwrapped TLS socket.
 * Zero means a correlated reply was received, NOT semantic success: inspect
 * RESULT.status_code and the stage-specific recorded state before proceeding.
 * Failure leaves RESULT unchanged.
 */
int wvm_control_transport_exchange(
    int stream_fd, uint32_t peer_physical_node_id,
    uint64_t peer_runtime_instance_id, const struct wvm_envelope *request,
    struct wvm_control_result *result, char *error, size_t error_len);

/*
 * Encode a typed result and write CTRL_RESULT back on the same ordered stream.
 * Production control-plane streams should use the apply callback so each
 * connection owns its response path; the legacy dispatch/sink form remains
 * available for callers that already provide a connection-local sink.
 */
int wvm_control_transport_result_sink(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_membership_control_result *result, char *error,
    size_t error_len);

int wvm_control_result_encode(
    const struct wvm_control_result *result,
    uint8_t bytes[WVM_CONTROL_RESULT_BYTES]);
int wvm_control_result_decode(
    const uint8_t bytes[WVM_CONTROL_RESULT_BYTES],
    struct wvm_control_result *result);

#endif /* WAVEVM_CONTROL_TRANSPORT_H */

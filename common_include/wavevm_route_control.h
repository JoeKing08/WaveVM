#ifndef WAVEVM_ROUTE_CONTROL_H
#define WAVEVM_ROUTE_CONTROL_H

/*
 * Durable local consumer for typed route transactions. A control transport
 * authenticates the peer and passes decoded local-control envelopes here;
 * this module records and replays only the participant-side route install
 * state.  It is not a second membership or placement authority.
 */

#include <stddef.h>

#include "wavevm_envelope.h"
#include "wavevm_route_runtime.h"

#define WVM_ROUTE_CONTROL_MAX_OPERATIONS 65536U
#define WVM_ROUTE_CONTROL_MAX_FRAME_BYTES \
    (WVM_ENVELOPE_HEADER_BYTES + WVM_ENVELOPE_MAX_LOCAL_PAYLOAD)

struct wvm_route_control_operation;

struct wvm_route_control_snapshot {
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record *rules;
    struct wvm_required_ack_entry *ack_entries;
};

struct wvm_route_control_result {
    uint16_t recorded_state;
    struct wvm_route_snapshot_key route_snapshot_key;
    uint8_t required_ack_set_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t operation_retention_horizon_ms;
};

struct wvm_route_control {
    pthread_mutex_t lock;
    struct wvm_route_runtime *runtime;
    int journal_fd;
    uint64_t next_sequence;
    struct wvm_route_control_operation *operations;
    size_t operation_count;
    size_t operation_capacity;
};

/*
 * Opens or creates one append-only participant journal and replays every
 * completed route control frame into RUNTIME. A torn tail is discarded;
 * a completed malformed frame rejects startup rather than guessing state.
 */
int wvm_route_control_open(struct wvm_route_control *control,
                           struct wvm_route_runtime *runtime,
                           const char *journal_path, char *error,
                           size_t error_len);

void wvm_route_control_close(struct wvm_route_control *control);

/* Recover the full prepared or active canonical snapshot, not only the routing
 * cache. ACTIVATE_MANIFEST precedes ROUTE_COMMIT in the admission transaction.
 * The caller owns OUTPUT and releases it with wvm_route_control_snapshot_free.
 * A retired or mismatched key is never a delivery input. OUTPUT starts empty. */
int wvm_route_control_snapshot_load(
    struct wvm_route_control *control, const struct wvm_route_snapshot_key *key,
    struct wvm_route_control_snapshot *output, char *error, size_t error_len);

void wvm_route_control_snapshot_free(struct wvm_route_control_snapshot *snapshot);

/*
 * Applies exactly one decoded local-control frame. Only ROUTE_PREPARE,
 * ROUTE_COMMIT, ROUTE_ABORT, and ROUTE_RETIRE are accepted. The operation
 * identity is idempotent per message type; reuse with a different semantic
 * payload digest is rejected.
 */
int wvm_route_control_apply(struct wvm_route_control *control,
                            const struct wvm_envelope *request,
                            struct wvm_route_control_result *result_out,
                            char *error, size_t error_len);

#endif /* WAVEVM_ROUTE_CONTROL_H */

#ifndef WAVEVM_NODE_RUNTIME_INGRESS_H
#define WAVEVM_NODE_RUNTIME_INGRESS_H

#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_membership.h"
#include "../common_include/wavevm_runtime_gate.h"

/*
 * An admitted envelope reaches this boundary only after gateway/sidecar
 * forwarding.
 * The dispatcher is local-only: it may submit to a local executor adapter,
 * but it must never create a direct remote-executor path.
 *
 * Return 0 after taking responsibility for the immutable envelope, -EAGAIN
 * for bounded local backpressure, -ENOTSUP for an operation whose semantic
 * payload schema has not been implemented, and another negative errno value
 * for a terminal local rejection.
 */
typedef int (*wvm_ingress_dispatch_fn)(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len);

/*
 * Control messages use the cluster namespace (vm_id == 0), so they cannot
 * pass the per-VM runtime gate. The transport must authenticate ACTOR before
 * calling the authenticated ingress entry; this callback must not infer an
 * actor from the envelope source fields.
 */
typedef int (*wvm_ingress_control_dispatch_fn)(
    void *opaque, const struct wvm_envelope *envelope,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len);

enum wvm_ingress_status {
    WVM_INGRESS_ACCEPTED = 0,
    WVM_INGRESS_INCOMPLETE = 1,
    WVM_INGRESS_REJECTED = 2,
    WVM_INGRESS_BACKPRESSURE = 3,
    WVM_INGRESS_UNSUPPORTED = 4,
};

struct wvm_ingress_config {
    const struct wvm_node_runtime_manifest *manifest;
    const struct wvm_runtime_gate *runtime_gate;
    uint64_t runtime_connection_id;
    wvm_ingress_dispatch_fn memory_dispatch;
    void *memory_dispatch_opaque;
    wvm_ingress_dispatch_fn vcpu_dispatch;
    void *vcpu_dispatch_opaque;
    wvm_ingress_dispatch_fn vcpu_result_dispatch;
    void *vcpu_result_dispatch_opaque;
    wvm_ingress_dispatch_fn block_dispatch;
    void *block_dispatch_opaque;
    wvm_ingress_dispatch_fn block_result_dispatch;
    void *block_result_dispatch_opaque;
    wvm_ingress_control_dispatch_fn control_dispatch;
    void *control_dispatch_opaque;
};

struct wvm_ingress {
    struct wvm_ingress_config config;
    struct wvm_envelope_admitted_identity admitted_identity;
    int initialized;
};

/*
 * The caller owns REASSEMBLER. RX threads keep one instance each, which
 * bounds fragment state without putting unrelated packets behind a global
 * ingress lock.
 */
int wvm_ingress_init(struct wvm_ingress *ingress,
                        const struct wvm_ingress_config *config,
                        char *error, size_t error_len);

int wvm_ingress_accept(struct wvm_ingress *ingress,
                          struct wvm_envelope_reassembler *reassembler,
                          const uint8_t *frame, size_t frame_bytes,
                          uint64_t now_ms, char *error, size_t error_len);

/*
 * Authenticated control-plane transport entry. ACTOR is supplied by the
 * transport authentication layer and is never taken from envelope fields.
 * The non-authenticated wrapper above intentionally cannot accept control
 * messages.
 */
int wvm_ingress_accept_authenticated(
    struct wvm_ingress *ingress,
    struct wvm_envelope_reassembler *reassembler, const uint8_t *frame,
    size_t frame_bytes, uint64_t now_ms,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len);

/*
 * Unified node-runtime entry. It is initialized before the legacy master RX
 * threads start. Standalone legacy masters intentionally leave this symbol
 * unresolved weakly and continue to ignore admitted envelopes.
 */
int wvm_ingress_global_init(const struct wvm_ingress_config *config,
                               char *error, size_t error_len);
int wvm_ingress_handle_datagram_ex(const uint8_t *frame, size_t frame_bytes,
                                   char *error, size_t error_len);
int wvm_ingress_handle_authenticated_datagram_ex(
    const uint8_t *frame, size_t frame_bytes,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len);
int wvm_ingress_handle_datagram(const uint8_t *frame, size_t frame_bytes);

#endif /* WAVEVM_NODE_RUNTIME_INGRESS_H */

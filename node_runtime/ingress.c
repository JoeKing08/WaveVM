#define _POSIX_C_SOURCE 200809L

#include "ingress.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../common_include/wavevm_block_wire.h"
#include "../common_include/wavevm_memory.h"
#include "../common_include/wavevm_vcpu_handoff.h"

struct ingress_thread_state {
    int initialized;
    struct wvm_envelope_reassembler reassembler;
};

static struct wvm_ingress g_ingress;
static _Thread_local struct ingress_thread_state g_thread_ingress;

static int control_message(uint16_t message_type)
{
    return message_type == WVM_ENVELOPE_MSG_REGISTER_MEMBER ||
           message_type == WVM_ENVELOPE_MSG_CORDON ||
           message_type == WVM_ENVELOPE_MSG_DRAIN ||
           message_type == WVM_ENVELOPE_MSG_DRAIN_COMPUTE ||
           message_type == WVM_ENVELOPE_MSG_REJOIN;
}

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

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000U +
           (uint64_t)now.tv_nsec / 1000000U;
}

static int route_key_from_envelope(
    const struct wvm_envelope *envelope,
    struct wvm_route_snapshot_key *route_key)
{
    if (!envelope || !route_key) {
        return -1;
    }
    memset(route_key, 0, sizeof(*route_key));
    route_key->scope_key.vm_id = envelope->vm_id;
    route_key->scope_key.vm_incarnation = envelope->vm_incarnation;
    route_key->scope_key.route_scope_id = envelope->route_scope_id;
    route_key->topology_revision = envelope->topology_revision;
    route_key->route_generation = envelope->route_generation;
    memcpy(route_key->snapshot_digest, envelope->route_snapshot_digest,
           sizeof(route_key->snapshot_digest));
    return 0;
}

static int authorize_envelope(const struct wvm_ingress *ingress,
                              const struct wvm_envelope *envelope,
                              char *error, size_t error_len)
{
    struct wvm_runtime_operation operation;

    if (!ingress || !envelope) {
        set_error(error, error_len, "ingress authorization input is invalid");
        return -1;
    }
    memset(&operation, 0, sizeof(operation));
    operation.connection_id = ingress->config.runtime_connection_id;
    operation.vm_id = envelope->vm_id;
    operation.vm_incarnation = envelope->vm_incarnation;
    operation.manifest_generation = envelope->manifest_generation;
    memcpy(operation.candidate_manifest_digest,
           ingress->config.manifest->candidate_manifest_digest,
           sizeof(operation.candidate_manifest_digest));
    route_key_from_envelope(envelope, &operation.route_snapshot_key);
    memcpy(operation.activation_fence,
           ingress->config.manifest->activation_fence,
           sizeof(operation.activation_fence));
    memcpy(operation.operation_id, envelope->operation_id,
           sizeof(operation.operation_id));
    return wvm_runtime_gate_authorize(ingress->config.runtime_gate, &operation,
                                      error, error_len);
}

static int dispatch_complete_envelope(struct wvm_ingress *ingress,
                                      const struct wvm_envelope *envelope,
                                      const struct wvm_member_key
                                          *authenticated_actor,
                                      char *error, size_t error_len)
{
    wvm_ingress_dispatch_fn dispatch;
    wvm_ingress_control_dispatch_fn control_dispatch;
    void *dispatch_opaque;
    int dispatch_result;

    if (control_message(envelope->message_type)) {
        if (!authenticated_actor || !ingress->config.control_dispatch) {
            set_error(error, error_len,
                      "control message requires an authenticated transport");
            return WVM_INGRESS_REJECTED;
        }
        control_dispatch = ingress->config.control_dispatch;
        dispatch_result = control_dispatch(
            ingress->config.control_dispatch_opaque, envelope,
            authenticated_actor, error, error_len);
    } else {
        if (wvm_envelope_validate_admitted(
                envelope, &ingress->admitted_identity, error, error_len) != 0 ||
            authorize_envelope(ingress, envelope, error, error_len) != 0) {
            return WVM_INGRESS_REJECTED;
        }

        switch (envelope->message_type) {
        case WVM_ENVELOPE_MSG_MEM_READ:
        case WVM_ENVELOPE_MSG_MEM_ACK:
        case WVM_ENVELOPE_MSG_COMMIT_DIFF:
        case WVM_ENVELOPE_MSG_MEM_COMMIT_ACK:
            if (!ingress->config.memory_dispatch) {
                set_error(error, error_len,
                          "memory operation has no local dispatcher");
                return WVM_INGRESS_UNSUPPORTED;
            }
            if (wvm_memory_payload_validate(envelope->message_type,
                                            envelope->payload,
                                            envelope->payload_bytes, error,
                                            error_len) != 0) {
                return WVM_INGRESS_REJECTED;
            }
            dispatch = ingress->config.memory_dispatch;
            dispatch_opaque = ingress->config.memory_dispatch_opaque;
            break;
        case WVM_ENVELOPE_MSG_VCPU_RUN: {
            struct wvm_vcpu_handoff_request request;

            if (!ingress->config.vcpu_dispatch) {
                set_error(error, error_len,
                          "vCPU handoff has no local executor dispatcher");
                return WVM_INGRESS_UNSUPPORTED;
            }
            if (wvm_vcpu_handoff_request_decode(
                    envelope->payload, envelope->payload_bytes, &request,
                    error, error_len) != 0 ||
                wvm_vcpu_handoff_request_validate_envelope(
                    &request, envelope, error, error_len) != 0) {
                return WVM_INGRESS_REJECTED;
            }
            dispatch = ingress->config.vcpu_dispatch;
            dispatch_opaque = ingress->config.vcpu_dispatch_opaque;
            break;
        }
        case WVM_ENVELOPE_MSG_BLOCK_READ:
        case WVM_ENVELOPE_MSG_BLOCK_WRITE:
        case WVM_ENVELOPE_MSG_BLOCK_FLUSH: {
            struct wvm_block_request block_request;
            const uint8_t *block_data = NULL;
            size_t block_data_bytes = 0;

            if (!ingress->config.block_dispatch) {
                set_error(error, error_len,
                          "block operation has no local storage executor");
                return WVM_INGRESS_UNSUPPORTED;
            }
            if (wvm_block_request_decode(
                    envelope->payload, envelope->payload_bytes,
                    &block_request, &block_data, &block_data_bytes, error,
                    error_len) != 0) {
                return WVM_INGRESS_REJECTED;
            }
            (void)block_data;
            dispatch = ingress->config.block_dispatch;
            dispatch_opaque = ingress->config.block_dispatch_opaque;
            break;
        }
        case WVM_ENVELOPE_MSG_BLOCK_ACK: {
            struct wvm_block_completion block_completion;
            const uint8_t *block_data = NULL;
            size_t block_data_bytes = 0;

            if (!ingress->config.block_result_dispatch) {
                set_error(error, error_len,
                          "block completion has no local coordinator");
                return WVM_INGRESS_UNSUPPORTED;
            }
            if (wvm_block_completion_decode(
                    envelope->payload, envelope->payload_bytes,
                    &block_completion, &block_data, &block_data_bytes, error,
                    error_len) != 0) {
                return WVM_INGRESS_REJECTED;
            }
            (void)block_data;
            (void)block_data_bytes;
            dispatch = ingress->config.block_result_dispatch;
            dispatch_opaque = ingress->config.block_result_dispatch_opaque;
            break;
        }
        case WVM_ENVELOPE_MSG_VCPU_EXIT: {
            struct wvm_vcpu_handoff_result result;

            if (!ingress->config.vcpu_result_dispatch) {
                set_error(error, error_len,
                          "vCPU exit has no local result coordinator");
                return WVM_INGRESS_UNSUPPORTED;
            }
            if (wvm_vcpu_handoff_result_decode(
                    envelope->payload, envelope->payload_bytes, &result,
                    error, error_len) != 0) {
                return WVM_INGRESS_REJECTED;
            }
            dispatch = ingress->config.vcpu_result_dispatch;
            dispatch_opaque = ingress->config.vcpu_result_dispatch_opaque;
            break;
        }
        default:
            set_error(error, error_len,
                      "envelope operation has no admitted local dispatcher");
            return WVM_INGRESS_UNSUPPORTED;
        }
        dispatch_result = dispatch(dispatch_opaque, envelope, error, error_len);
    }
    if (dispatch_result == 0) {
        return WVM_INGRESS_ACCEPTED;
    }
    if (dispatch_result == -EAGAIN || dispatch_result == -ENOBUFS) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "local executor queue is full");
        }
        return WVM_INGRESS_BACKPRESSURE;
    }
    if (dispatch_result == -ENOTSUP) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "operation payload schema is not implemented");
        }
        return WVM_INGRESS_UNSUPPORTED;
    }
    if (!error || error[0] == '\0') {
        set_error(error, error_len, "local dispatcher rejected operation");
    }
    return WVM_INGRESS_REJECTED;
}

int wvm_ingress_init(struct wvm_ingress *ingress,
                        const struct wvm_ingress_config *config,
                        char *error, size_t error_len)
{
    const struct wvm_node_runtime_manifest *manifest;

    if (!ingress || !config || !config->manifest || !config->runtime_gate ||
        config->runtime_connection_id == 0 || !config->memory_dispatch) {
        set_error(error, error_len, "ingress configuration is incomplete");
        return -1;
    }
    manifest = config->manifest;
    if (config->runtime_gate->state != WVM_RUNTIME_GATE_ACTIVE ||
        config->runtime_gate->manifest != manifest ||
        !manifest->has_activation_fence ||
        !(manifest->local_role_bits &
          WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_NODE_RUNTIME)) ||
        manifest->required_route_snapshot_key.scope_key.vm_id !=
            manifest->vm_id ||
        manifest->required_route_snapshot_key.scope_key.vm_incarnation !=
            manifest->vm_incarnation ||
        wvm_route_snapshot_key_validate(
            &manifest->required_route_snapshot_key, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "ingress manifest has no admitted node-runtime route");
        }
        return -1;
    }

    memset(ingress, 0, sizeof(*ingress));
    ingress->config = *config;
    ingress->admitted_identity.vm_id = manifest->vm_id;
    ingress->admitted_identity.vm_incarnation = manifest->vm_incarnation;
    ingress->admitted_identity.manifest_generation =
        manifest->manifest_generation;
    ingress->admitted_identity.route_scope_id =
        manifest->required_route_snapshot_key.scope_key.route_scope_id;
    ingress->admitted_identity.topology_revision =
        manifest->required_route_snapshot_key.topology_revision;
    ingress->admitted_identity.route_generation =
        manifest->required_route_snapshot_key.route_generation;
    memcpy(ingress->admitted_identity.route_snapshot_digest,
           manifest->required_route_snapshot_key.snapshot_digest,
           sizeof(ingress->admitted_identity.route_snapshot_digest));
    ingress->initialized = 1;
    return 0;
}

int wvm_ingress_accept_authenticated(
    struct wvm_ingress *ingress,
    struct wvm_envelope_reassembler *reassembler, const uint8_t *frame,
    size_t frame_bytes, uint64_t now_ms,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len)
{
    struct wvm_envelope envelope;

    if (!ingress || !ingress->initialized || !reassembler || !frame ||
        frame_bytes == 0) {
        set_error(error, error_len, "ingress input is invalid");
        return WVM_INGRESS_REJECTED;
    }
    if (wvm_envelope_decode(frame, frame_bytes,
                               WVM_ENVELOPE_TRANSPORT_NETWORK, &envelope,
                               error, error_len) != 0) {
        return WVM_INGRESS_REJECTED;
    }
    /*
     * Check frame identity before retaining a fragmented payload. This keeps
     * stale VM/route traffic from consuming the bounded reassembly budget.
     */
    if ((!control_message(envelope.message_type) &&
         wvm_envelope_validate_admitted(
             &envelope, &ingress->admitted_identity, error, error_len) != 0) ||
        (control_message(envelope.message_type) &&
         (!authenticated_actor || !ingress->config.control_dispatch))) {
        if (control_message(envelope.message_type) &&
            (!error || error[0] == '\0')) {
            set_error(error, error_len,
                      "control message requires an authenticated transport");
        }
        return WVM_INGRESS_REJECTED;
    }
    if (!(envelope.flags & WVM_ENVELOPE_FLAG_FRAGMENTED)) {
        return dispatch_complete_envelope(ingress, &envelope,
                                          authenticated_actor, error,
                                          error_len);
    }

    {
        struct wvm_envelope_reassembled reassembled;
        int reassembly_result;

        memset(&reassembled, 0, sizeof(reassembled));
        reassembly_result = wvm_envelope_reassembler_accept(
            reassembler, &envelope, now_ms, &reassembled, error, error_len);
        if (reassembly_result < 0) {
            return WVM_INGRESS_REJECTED;
        }
        if (reassembly_result == 0) {
            return WVM_INGRESS_INCOMPLETE;
        }
        reassembly_result = dispatch_complete_envelope(
            ingress, &reassembled.envelope, authenticated_actor, error,
            error_len);
        wvm_envelope_reassembled_release(&reassembled);
        return reassembly_result;
    }
}

int wvm_ingress_accept(struct wvm_ingress *ingress,
                       struct wvm_envelope_reassembler *reassembler,
                       const uint8_t *frame, size_t frame_bytes,
                       uint64_t now_ms, char *error, size_t error_len)
{
    return wvm_ingress_accept_authenticated(
        ingress, reassembler, frame, frame_bytes, now_ms, NULL, error,
        error_len);
}

int wvm_ingress_global_init(const struct wvm_ingress_config *config,
                               char *error, size_t error_len)
{
    /*
     * The runtime is initialized exactly once before master RX threads start.
     * Refusing a second initialization prevents an active manifest/gate from
     * being swapped under concurrent packet processing.
     */
    if (g_ingress.initialized) {
        set_error(error, error_len, "ingress is already initialized");
        return -1;
    }
    return wvm_ingress_init(&g_ingress, config, error, error_len);
}

int wvm_ingress_handle_datagram_ex(const uint8_t *frame, size_t frame_bytes,
                                   char *error, size_t error_len)
{
    return wvm_ingress_handle_authenticated_datagram_ex(
        frame, frame_bytes, NULL, error, error_len);
}

int wvm_ingress_handle_authenticated_datagram_ex(
    const uint8_t *frame, size_t frame_bytes,
    const struct wvm_member_key *authenticated_actor, char *error,
    size_t error_len)
{
    if (!g_ingress.initialized) {
        set_error(error, error_len, "ingress is not initialized");
        return WVM_INGRESS_REJECTED;
    }
    if (!g_thread_ingress.initialized) {
        if (wvm_envelope_reassembler_init(&g_thread_ingress.reassembler) !=
            0) {
            set_error(error, error_len,
                      "cannot initialize thread-local reassembler");
            return WVM_INGRESS_BACKPRESSURE;
        }
        g_thread_ingress.initialized = 1;
    }
    return wvm_ingress_accept_authenticated(
        &g_ingress, &g_thread_ingress.reassembler, frame, frame_bytes,
        monotonic_milliseconds(), authenticated_actor, error, error_len);
}

int wvm_ingress_handle_datagram(const uint8_t *frame, size_t frame_bytes)
{
    return wvm_ingress_handle_datagram_ex(frame, frame_bytes, NULL, 0);
}

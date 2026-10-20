#include "wavevm_admission_stream_transport.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_lifecycle.h"
#include "wavevm_envelope.h"

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

int wvm_admission_stream_transport_init(
    struct wvm_admission_stream_transport *transport,
    const struct wvm_control_stream_connector *connector, char *error,
    size_t error_len)
{
    if (!transport ||
        wvm_control_stream_client_init(&transport->client, connector, error,
                                       error_len) != 0) {
        if (transport) {
            memset(transport, 0, sizeof(*transport));
        }
        return -EINVAL;
    }
    transport->initialized = 1;
    return 0;
}

void wvm_admission_stream_transport_destroy(
    struct wvm_admission_stream_transport *transport)
{
    if (!transport) {
        return;
    }
    wvm_control_stream_client_destroy(&transport->client);
    memset(transport, 0, sizeof(*transport));
}

int wvm_admission_stream_transport_submit(
    void *context, const struct wvm_admission_transport_target *target,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    struct wvm_admission_stream_transport *transport = context;
    struct wvm_control_result result;

    if (!transport || !transport->initialized || !target || !envelope) {
        set_error(error, error_len, "admission stream transport is invalid");
        return -EINVAL;
    }
    memset(&result, 0, sizeof(result));
    {
        int status = wvm_control_stream_client_exchange(
            &transport->client, &target->member_key, &target->endpoint,
            envelope, &result, error, error_len);

        if (status != 0) {
            return status;
        }
    }
    if (envelope->message_type == WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY &&
        result.status_code == WVM_CONTROL_RESULT_NOT_READY &&
        result.recorded_state == WVM_LIFECYCLE_COMMITTED) {
        set_error(error, error_len, "admitted runtime is starting");
        return -EAGAIN;
    }
    if (result.status_code != WVM_CONTROL_RESULT_SUCCESS) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "admission stage rejected with status %u",
                           result.status_code);
        }
        return -EACCES;
    }
    if (envelope->message_type == WVM_ENVELOPE_MSG_QUERY_RUNTIME_READY &&
        result.recorded_state != WVM_LIFECYCLE_COMMITTED) {
        set_error(error, error_len,
                  "runtime readiness reply does not report COMMITTED state");
        return -EPROTO;
    }
    if (envelope->message_type == WVM_ENVELOPE_MSG_ROUTE_RETIRE) {
        /*
         * F5: begin_retire may only use ACK-proven values.
         * recorded_state 4 = retired; applied_revision = active refs (0);
         * expiry_or_retention_deadline 0 = horizon complete.
         * result_flags must remain 0 (control_result encode contract).
         */
        if (result.recorded_state != 4 || result.applied_revision != 0 ||
            result.expiry_or_retention_deadline != 0 ||
            result.result_flags != 0) {
            if (error && error_len != 0) {
                (void)snprintf(
                    error, error_len,
                    "ROUTE_RETIRE ACK lacks refs=0/horizon-complete proof "
                    "(state=%u refs=%llu horizon_ms=%llu flags=%u)",
                    (unsigned)result.recorded_state,
                    (unsigned long long)result.applied_revision,
                    (unsigned long long)result.expiry_or_retention_deadline,
                    (unsigned)result.result_flags);
            }
            return -EPROTO;
        }
    }
    return 0;
}

#include "wavevm_admission_stream_transport.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

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
    if (result.status_code != WVM_CONTROL_RESULT_SUCCESS) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "admission stage rejected with status %u",
                           result.status_code);
        }
        return -EACCES;
    }
    return 0;
}

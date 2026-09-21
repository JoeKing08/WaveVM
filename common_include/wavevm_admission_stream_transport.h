#ifndef WAVEVM_ADMISSION_STREAM_TRANSPORT_H
#define WAVEVM_ADMISSION_STREAM_TRANSPORT_H

#include <stddef.h>

#include "wavevm_admission_transport.h"
#include "wavevm_control_client.h"

struct wvm_admission_stream_transport {
    struct wvm_control_stream_client client;
    int initialized;
};

int wvm_admission_stream_transport_init(
    struct wvm_admission_stream_transport *transport,
    const struct wvm_control_stream_connector *connector, char *error,
    size_t error_len);

void wvm_admission_stream_transport_destroy(
    struct wvm_admission_stream_transport *transport);

/* Submit only after the peer returned a successful, bound control result. */
int wvm_admission_stream_transport_submit(
    void *context, const struct wvm_admission_transport_target *target,
    const struct wvm_envelope *envelope, char *error, size_t error_len);

#endif /* WAVEVM_ADMISSION_STREAM_TRANSPORT_H */

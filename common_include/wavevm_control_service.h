#ifndef WAVEVM_CONTROL_SERVICE_H
#define WAVEVM_CONTROL_SERVICE_H

/*
 * Production lifecycle binding between the authoritative control plane and
 * its local authenticated stream listener. The service owns only the
 * listener; the caller retains ownership of the already-open durable control
 * plane and its membership state.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "wavevm_control_owner.h"
#include "wavevm_control_plane.h"

struct wvm_control_service_config {
    struct wvm_control_plane *plane;
    const char *socket_path;
    mode_t socket_mode;
    int listen_backlog;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    size_t max_frame_bytes;
    wvm_control_transport_authenticate_fn authenticate;
    void *authenticate_opaque;
    wvm_control_transport_control_apply_fn control_apply;
    void *control_apply_opaque;
    wvm_control_transport_admission_apply_fn admission_apply;
    void *admission_apply_opaque;
};

struct wvm_control_service {
    struct wvm_control_service_config config;
    struct wvm_control_owner owner;
    int initialized;
};

/*
 * PLANE must be configured and opened before service initialization. This
 * makes the durable membership authority available before its listener can
 * accept a request, and keeps listener stop separate from control-plane
 * recovery ownership.
 */
int wvm_control_service_init(
    struct wvm_control_service *service,
    const struct wvm_control_service_config *config, char *error,
    size_t error_len);

int wvm_control_service_start(struct wvm_control_service *service,
                              char *error, size_t error_len);

/* Stops only the stream listener. It does not close or mutate the plane. */
int wvm_control_service_stop(struct wvm_control_service *service, char *error,
                             size_t error_len);

void wvm_control_service_destroy(struct wvm_control_service *service);

#endif /* WAVEVM_CONTROL_SERVICE_H */

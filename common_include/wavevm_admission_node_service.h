#ifndef WAVEVM_ADMISSION_NODE_SERVICE_H
#define WAVEVM_ADMISSION_NODE_SERVICE_H

/*
 * Node-level admission listener lifecycle. This is the boundary between a
 * long-lived node agent and the per-VM receiver/slot authorities supplied by
 * that agent. It owns the authenticated stream listener, but it does not
 * create a second placement, membership, reservation, or route authority.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "wavevm_admission_receiver.h"
#include "wavevm_control_owner.h"

struct wvm_admission_node_service_config {
    const char *socket_path;
    mode_t socket_mode;
    int listen_backlog;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    size_t max_frame_bytes;
    wvm_control_transport_authenticate_fn authenticate;
    void *authenticate_opaque;
    struct wvm_admission_receiver_config receiver;
};

struct wvm_admission_node_service {
    struct wvm_admission_receiver receiver;
    struct wvm_control_owner owner;
    int initialized;
};

/* The receiver config must already contain its caller-owned slot/resources. */
int wvm_admission_node_service_init(
    struct wvm_admission_node_service *service,
    const struct wvm_admission_node_service_config *config, char *error,
    size_t error_len);

int wvm_admission_node_service_start(
    struct wvm_admission_node_service *service, char *error,
    size_t error_len);

int wvm_admission_node_service_stop(
    struct wvm_admission_node_service *service, char *error,
    size_t error_len);

void wvm_admission_node_service_destroy(
    struct wvm_admission_node_service *service);

#endif /* WAVEVM_ADMISSION_NODE_SERVICE_H */

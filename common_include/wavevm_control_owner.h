#ifndef WAVEVM_CONTROL_OWNER_H
#define WAVEVM_CONTROL_OWNER_H

/*
 * The control owner is the lifecycle boundary around one authoritative
 * control-plane instance.  It owns no membership cache of its own: callers
 * provide the typed transport callbacks that operate on their durable owner.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "wavevm_control_transport.h"

#define WVM_CONTROL_OWNER_SOCKET_PATH_MAX \
    (sizeof(((struct sockaddr_un *)0)->sun_path))

struct wvm_control_owner_client;

struct wvm_control_owner_config {
    const char *socket_path;
    const struct wvm_endpoint *network_endpoint;
    const char *tls_ca_file;
    const char *tls_certificate_file;
    const char *tls_private_key_file;
    mode_t socket_mode;
    int listen_backlog;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    size_t max_frame_bytes;
    wvm_control_transport_authenticate_fn authenticate;
    wvm_control_transport_authenticate_io_fn authenticate_io;
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

struct wvm_control_owner {
    struct wvm_control_owner_config config;
    char socket_path[WVM_CONTROL_OWNER_SOCKET_PATH_MAX];
    struct wvm_endpoint network_endpoint;
    int listener_fd;
    int network_listener_fd;
    int stop_read_fd;
    int stop_write_fd;
    pthread_t listener_thread;
    pthread_mutex_t lock;
    pthread_cond_t clients_changed;
    struct wvm_control_owner_client *clients;
    int lock_initialized;
    int started;
    int stopping;
    void *tls_context;
};

int wvm_control_owner_init(struct wvm_control_owner *owner,
                           const struct wvm_control_owner_config *config,
                           char *error, size_t error_len);

int wvm_control_owner_start(struct wvm_control_owner *owner, char *error,
                             size_t error_len);

/* Stop is idempotent and waits for all accepted client streams to close. */
int wvm_control_owner_stop(struct wvm_control_owner *owner, char *error,
                           size_t error_len);

void wvm_control_owner_destroy(struct wvm_control_owner *owner);

#endif /* WAVEVM_CONTROL_OWNER_H */

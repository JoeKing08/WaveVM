#include "wavevm_admission_node_service.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

int wvm_admission_node_service_init(
    struct wvm_admission_node_service *service,
    const struct wvm_admission_node_service_config *config, char *error,
    size_t error_len)
{
    struct wvm_control_owner_config owner_config;

    if (!service || !config || !config->socket_path ||
        config->socket_path[0] == '\0' || config->socket_mode == 0 ||
        config->listen_backlog <= 0 || config->local_physical_node_id == 0 ||
        config->local_runtime_instance_id == 0 || !config->authenticate) {
        set_error(error, error_len,
                  "admission node service configuration is invalid");
        return -EINVAL;
    }
    memset(service, 0, sizeof(*service));
    if (wvm_admission_receiver_init(&service->receiver, &config->receiver,
                                    error, error_len) != 0) {
        return -EINVAL;
    }

    memset(&owner_config, 0, sizeof(owner_config));
    owner_config.socket_path = config->socket_path;
    owner_config.socket_mode = config->socket_mode;
    owner_config.listen_backlog = config->listen_backlog;
    owner_config.local_physical_node_id = config->local_physical_node_id;
    owner_config.local_runtime_instance_id = config->local_runtime_instance_id;
    owner_config.max_frame_bytes = config->max_frame_bytes;
    owner_config.authenticate = config->authenticate;
    owner_config.authenticate_opaque = config->authenticate_opaque;
    owner_config.admission_apply = wvm_admission_receiver_apply;
    owner_config.admission_apply_opaque = &service->receiver;
    if (wvm_control_owner_init(&service->owner, &owner_config, error,
                               error_len) != 0) {
        wvm_admission_receiver_destroy(&service->receiver);
        return -EINVAL;
    }
    service->initialized = 1;
    return 0;
}

int wvm_admission_node_service_start(
    struct wvm_admission_node_service *service, char *error,
    size_t error_len)
{
    if (!service || !service->initialized) {
        set_error(error, error_len, "admission node service is not initialized");
        return -EINVAL;
    }
    return wvm_control_owner_start(&service->owner, error, error_len);
}

int wvm_admission_node_service_stop(
    struct wvm_admission_node_service *service, char *error,
    size_t error_len)
{
    if (!service || !service->initialized) {
        set_error(error, error_len, "admission node service is not initialized");
        return -EINVAL;
    }
    return wvm_control_owner_stop(&service->owner, error, error_len);
}

void wvm_admission_node_service_destroy(
    struct wvm_admission_node_service *service)
{
    if (!service) {
        return;
    }
    if (service->initialized) {
        wvm_control_owner_destroy(&service->owner);
        wvm_admission_receiver_destroy(&service->receiver);
    }
    memset(service, 0, sizeof(*service));
}

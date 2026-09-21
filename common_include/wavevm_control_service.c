#include "wavevm_control_service.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static int control_plane_apply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    return wvm_control_plane_membership_apply(
        opaque, request, authenticated_actor, result, error, error_len);
}

int wvm_control_service_init(
    struct wvm_control_service *service,
    const struct wvm_control_service_config *config, char *error,
    size_t error_len)
{
    struct wvm_control_owner_config owner_config;

    if (!service || !config || !config->plane ||
        !config->plane->membership_open || !config->socket_path ||
        config->socket_path[0] == '\0' || config->socket_mode == 0 ||
        config->listen_backlog <= 0 || config->local_physical_node_id == 0 ||
        config->local_runtime_instance_id == 0 || !config->authenticate) {
        set_error(error, error_len, "control service configuration is invalid");
        return -EINVAL;
    }

    memset(service, 0, sizeof(*service));
    service->config = *config;
    memset(&owner_config, 0, sizeof(owner_config));
    owner_config.socket_path = config->socket_path;
    owner_config.socket_mode = config->socket_mode;
    owner_config.listen_backlog = config->listen_backlog;
    owner_config.local_physical_node_id = config->local_physical_node_id;
    owner_config.local_runtime_instance_id = config->local_runtime_instance_id;
    owner_config.max_frame_bytes = config->max_frame_bytes;
    owner_config.authenticate = config->authenticate;
    owner_config.authenticate_opaque = config->authenticate_opaque;
    owner_config.apply = control_plane_apply;
    owner_config.apply_opaque = config->plane;
    owner_config.control_apply = config->control_apply;
    owner_config.control_apply_opaque = config->control_apply_opaque;
    owner_config.admission_apply = config->admission_apply;
    owner_config.admission_apply_opaque = config->admission_apply_opaque;
    if (wvm_control_owner_init(&service->owner, &owner_config, error,
                               error_len) != 0) {
        memset(service, 0, sizeof(*service));
        return -EINVAL;
    }
    service->initialized = 1;
    return 0;
}

int wvm_control_service_start(struct wvm_control_service *service, char *error,
                              size_t error_len)
{
    if (!service || !service->initialized || !service->config.plane ||
        !service->config.plane->membership_open) {
        set_error(error, error_len, "control service is not bound to an open plane");
        return -EINVAL;
    }
    return wvm_control_owner_start(&service->owner, error, error_len);
}

int wvm_control_service_stop(struct wvm_control_service *service, char *error,
                             size_t error_len)
{
    if (!service || !service->initialized) {
        set_error(error, error_len, "control service is not initialized");
        return -EINVAL;
    }
    return wvm_control_owner_stop(&service->owner, error, error_len);
}

void wvm_control_service_destroy(struct wvm_control_service *service)
{
    if (!service) {
        return;
    }
    if (service->initialized) {
        wvm_control_owner_destroy(&service->owner);
    }
    memset(service, 0, sizeof(*service));
}

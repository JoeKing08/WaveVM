#ifndef WAVEVM_CTL_RUNTIME_PROFILE_PUBLICATION_H
#define WAVEVM_CTL_RUNTIME_PROFILE_PUBLICATION_H

#include "../common_include/wavevm_control_transport.h"
#include "../common_include/wavevm_runtime_profile.h"

struct wvm_ctl_runtime_profile_set {
    struct wvm_node_runtime_profile *profiles;
    size_t profile_count;
};

int wvm_ctl_publish_runtime_profile(
    const char *state_directory, struct wvm_membership_controller *controller,
    const struct wvm_envelope *request, const struct wvm_member_key *actor,
    struct wvm_control_result *result, char *error, size_t error_len);

int wvm_ctl_load_runtime_profile(
    const char *state_directory, const struct wvm_node_record *node,
    struct wvm_node_runtime_profile *profile, char *error, size_t error_len);

int wvm_ctl_load_runtime_profile_set(
    const char *state_directory,
    const struct wvm_membership_controller_capture *capture,
    struct wvm_ctl_runtime_profile_set *set, char *error, size_t error_len);
void wvm_ctl_runtime_profile_set_destroy(
    struct wvm_ctl_runtime_profile_set *set);

int wvm_ctl_runtime_profile_publish_command(int argc, char **argv);

#endif /* WAVEVM_CTL_RUNTIME_PROFILE_PUBLICATION_H */

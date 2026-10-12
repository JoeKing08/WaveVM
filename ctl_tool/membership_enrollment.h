#ifndef WVM_CTL_MEMBERSHIP_ENROLLMENT_H
#define WVM_CTL_MEMBERSHIP_ENROLLMENT_H

#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_control_plane.h"
#include "../common_include/wavevm_membership_enrollment_transport.h"

struct wvm_ctl_membership_enrollment {
    struct wvm_control_plane *plane;
    struct wvm_membership_enrollment_transport transport;
    struct wvm_cluster_admission_ack_entry *ack_storage;
    size_t ack_capacity;
    uint32_t controller_physical_node_id;
    uint64_t controller_instance_id;
    int initialized;
};

int wvm_ctl_membership_enrollment_init(
    struct wvm_ctl_membership_enrollment *enrollment,
    struct wvm_control_plane *plane, uint32_t controller_physical_node_id,
    uint64_t controller_instance_id, void *submit_context,
    wvm_admission_transport_submit_fn submit,
    struct wvm_cluster_admission_ack_entry *ack_storage, size_t ack_capacity,
    char *error, size_t error_len);

void wvm_ctl_membership_enrollment_destroy(
    struct wvm_ctl_membership_enrollment *enrollment);

/*
 * Drive REGISTER -> ClusterAdmissionProof prepare/ACK/commit -> ACTIVE for one
 * already-registered compute member. Uses controller-owned proof builder and
 * real peer transport. Does not forge ACTIVE or create a VM route scope.
 */
int wvm_ctl_membership_enrollment_activate_compute(
    struct wvm_ctl_membership_enrollment *enrollment,
    const struct wvm_member_key *member_key, char *error, size_t error_len);

/*
 * Same enrollment path for a registered GATEWAY member. Does not create a VM
 * route scope and does not forge ACTIVE without proof prepare/ACK/commit.
 */
int wvm_ctl_membership_enrollment_activate_gateway(
    struct wvm_ctl_membership_enrollment *enrollment,
    const struct wvm_member_key *member_key, char *error, size_t error_len);

/*
 * Membership apply wrapper: after a successful REGISTER_MEMBER for a compute
 * node or gateway, continue controller-owned cluster enrollment to ACTIVE.
 * Registration success is preserved even when enrollment fails.
 */
int wvm_ctl_membership_enrollment_apply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len);

#endif /* WVM_CTL_MEMBERSHIP_ENROLLMENT_H */

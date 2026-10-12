#ifndef WAVEVM_MEMBERSHIP_ENROLLMENT_TRANSPORT_H
#define WAVEVM_MEMBERSHIP_ENROLLMENT_TRANSPORT_H

/*
 * Controller-owned transport for ClusterAdmissionProof prepare/commit/abort.
 * Uses the authenticated control stream; does not create VM route scopes.
 */

#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission_transport.h"
#include "wavevm_membership_coordinator.h"

struct wvm_membership_enrollment_transport {
    uint32_t controller_physical_node_id;
    uint64_t controller_instance_id;
    void *context;
    wvm_admission_transport_submit_fn submit;
};

int wvm_membership_enrollment_transport_init(
    struct wvm_membership_enrollment_transport *transport,
    uint32_t controller_physical_node_id, uint64_t controller_instance_id,
    void *context, wvm_admission_transport_submit_fn submit, char *error,
    size_t error_len);

/*
 * Bind coordinator stage callbacks. prepare_context is the transport itself.
 */
int wvm_membership_enrollment_transport_bind(
    struct wvm_membership_enrollment_transport *transport,
    struct wvm_membership_cluster_enrollment_request *request, char *error,
    size_t error_len);

#endif /* WAVEVM_MEMBERSHIP_ENROLLMENT_TRANSPORT_H */

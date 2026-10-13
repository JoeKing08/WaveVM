#include "membership_enrollment.h"
#include "capability_publication.h"

#include <stdio.h>
#include <string.h>

#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_manifest.h"
#include "../common_include/wavevm_membership_coordinator.h"
#include "../common_include/wavevm_sha256.h"

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len != 0) {
        (void)snprintf(error, error_len, "%s", message);
    }
}

static int read_random_bytes(uint8_t *bytes, size_t byte_count, char *error,
                             size_t error_len)
{
    FILE *fp;
    size_t offset = 0;

    if (!bytes || byte_count == 0) {
        set_error(error, error_len, "random ID buffer is invalid");
        return -1;
    }
    fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        set_error(error, error_len, "cannot open random source");
        return -1;
    }
    while (offset < byte_count) {
        size_t got = fread(bytes + offset, 1, byte_count - offset, fp);

        if (got == 0) {
            fclose(fp);
            set_error(error, error_len, "cannot read random source");
            return -1;
        }
        offset += got;
    }
    fclose(fp);
    return 0;
}

static int allocate_nonzero_operation_id(uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                                         char *error, size_t error_len)
{
    size_t attempt;

    for (attempt = 0; attempt < 8; attempt++) {
        size_t i;
        int nonzero = 0;

        if (read_random_bytes(operation_id, WVM_IDENTITY_ID_BYTES, error,
                              error_len) != 0) {
            return -1;
        }
        for (i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
            if (operation_id[i] != 0) {
                nonzero = 1;
                break;
            }
        }
        if (nonzero) {
            return 0;
        }
    }
    set_error(error, error_len, "random enrollment operation ID is zero");
    return -1;
}

static int capability_evidence_digest_from_node(
    const struct wvm_node_record *node,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len)
{
    uint8_t encoded[4096];
    size_t encoded_bytes = 0;

    if (!node || !digest ||
        wvm_capability_ref_encode(&node->capability, encoded, sizeof(encoded),
                                  &encoded_bytes, error, error_len) != 0 ||
        encoded_bytes == 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "cannot bind capability evidence for enrollment");
        }
        return -1;
    }
    wvm_sha256_digest(encoded, encoded_bytes, digest);
    return 0;
}

static int topology_assignment_digest_from_node(
    const struct wvm_node_record *node,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len)
{
    uint8_t encoded[64];
    size_t offset = 0;

    if (!node || !digest || node->failure_domain_id == 0 || node->pod_id == 0 ||
        node->local_vnode_count == 0) {
        set_error(error, error_len,
                  "node topology assignment for enrollment is incomplete");
        return -1;
    }
    memset(encoded, 0, sizeof(encoded));
    /* Deterministic binding of the authoritative topology assignment fields. */
    encoded[offset++] = (uint8_t)(node->failure_domain_id >> 56);
    encoded[offset++] = (uint8_t)(node->failure_domain_id >> 48);
    encoded[offset++] = (uint8_t)(node->failure_domain_id >> 40);
    encoded[offset++] = (uint8_t)(node->failure_domain_id >> 32);
    encoded[offset++] = (uint8_t)(node->failure_domain_id >> 24);
    encoded[offset++] = (uint8_t)(node->failure_domain_id >> 16);
    encoded[offset++] = (uint8_t)(node->failure_domain_id >> 8);
    encoded[offset++] = (uint8_t)node->failure_domain_id;
    encoded[offset++] = (uint8_t)(node->pod_id >> 56);
    encoded[offset++] = (uint8_t)(node->pod_id >> 48);
    encoded[offset++] = (uint8_t)(node->pod_id >> 40);
    encoded[offset++] = (uint8_t)(node->pod_id >> 32);
    encoded[offset++] = (uint8_t)(node->pod_id >> 24);
    encoded[offset++] = (uint8_t)(node->pod_id >> 16);
    encoded[offset++] = (uint8_t)(node->pod_id >> 8);
    encoded[offset++] = (uint8_t)node->pod_id;
    encoded[offset++] = (uint8_t)(node->local_vnode_first >> 24);
    encoded[offset++] = (uint8_t)(node->local_vnode_first >> 16);
    encoded[offset++] = (uint8_t)(node->local_vnode_first >> 8);
    encoded[offset++] = (uint8_t)node->local_vnode_first;
    encoded[offset++] = (uint8_t)(node->local_vnode_count >> 24);
    encoded[offset++] = (uint8_t)(node->local_vnode_count >> 16);
    encoded[offset++] = (uint8_t)(node->local_vnode_count >> 8);
    encoded[offset++] = (uint8_t)node->local_vnode_count;
    wvm_sha256_digest(encoded, offset, digest);
    return 0;
}


static int capability_evidence_digest_from_gateway(
    const struct wvm_gateway_record *gateway,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len)
{
    uint8_t encoded[64];
    size_t offset = 0;

    if (!gateway || !digest || gateway->gateway_id == 0 ||
        gateway->gateway_instance_id == 0 ||
        gateway->hosting_physical_node_id == 0) {
        set_error(error, error_len,
                  "gateway capability evidence for enrollment is incomplete");
        return -1;
    }
    memset(encoded, 0, sizeof(encoded));
    encoded[offset++] = (uint8_t)(gateway->gateway_id >> 24);
    encoded[offset++] = (uint8_t)(gateway->gateway_id >> 16);
    encoded[offset++] = (uint8_t)(gateway->gateway_id >> 8);
    encoded[offset++] = (uint8_t)gateway->gateway_id;
    encoded[offset++] = (uint8_t)(gateway->gateway_instance_id >> 56);
    encoded[offset++] = (uint8_t)(gateway->gateway_instance_id >> 48);
    encoded[offset++] = (uint8_t)(gateway->gateway_instance_id >> 40);
    encoded[offset++] = (uint8_t)(gateway->gateway_instance_id >> 32);
    encoded[offset++] = (uint8_t)(gateway->gateway_instance_id >> 24);
    encoded[offset++] = (uint8_t)(gateway->gateway_instance_id >> 16);
    encoded[offset++] = (uint8_t)(gateway->gateway_instance_id >> 8);
    encoded[offset++] = (uint8_t)gateway->gateway_instance_id;
    encoded[offset++] = (uint8_t)(gateway->hosting_physical_node_id >> 24);
    encoded[offset++] = (uint8_t)(gateway->hosting_physical_node_id >> 16);
    encoded[offset++] = (uint8_t)(gateway->hosting_physical_node_id >> 8);
    encoded[offset++] = (uint8_t)gateway->hosting_physical_node_id;
    encoded[offset++] = (uint8_t)(gateway->role_bits >> 56);
    encoded[offset++] = (uint8_t)(gateway->role_bits >> 48);
    encoded[offset++] = (uint8_t)(gateway->role_bits >> 40);
    encoded[offset++] = (uint8_t)(gateway->role_bits >> 32);
    encoded[offset++] = (uint8_t)(gateway->role_bits >> 24);
    encoded[offset++] = (uint8_t)(gateway->role_bits >> 16);
    encoded[offset++] = (uint8_t)(gateway->role_bits >> 8);
    encoded[offset++] = (uint8_t)gateway->role_bits;
    wvm_sha256_digest(encoded, offset, digest);
    return 0;
}

static int topology_assignment_digest_from_gateway(
    const struct wvm_gateway_record *gateway,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len)
{
    uint8_t encoded[32];
    size_t offset = 0;

    if (!gateway || !digest || gateway->failure_domain_id == 0 ||
        gateway->pod_id_or_scope == 0) {
        set_error(error, error_len,
                  "gateway topology assignment for enrollment is incomplete");
        return -1;
    }
    memset(encoded, 0, sizeof(encoded));
    encoded[offset++] = (uint8_t)(gateway->failure_domain_id >> 56);
    encoded[offset++] = (uint8_t)(gateway->failure_domain_id >> 48);
    encoded[offset++] = (uint8_t)(gateway->failure_domain_id >> 40);
    encoded[offset++] = (uint8_t)(gateway->failure_domain_id >> 32);
    encoded[offset++] = (uint8_t)(gateway->failure_domain_id >> 24);
    encoded[offset++] = (uint8_t)(gateway->failure_domain_id >> 16);
    encoded[offset++] = (uint8_t)(gateway->failure_domain_id >> 8);
    encoded[offset++] = (uint8_t)gateway->failure_domain_id;
    encoded[offset++] = (uint8_t)(gateway->pod_id_or_scope >> 56);
    encoded[offset++] = (uint8_t)(gateway->pod_id_or_scope >> 48);
    encoded[offset++] = (uint8_t)(gateway->pod_id_or_scope >> 40);
    encoded[offset++] = (uint8_t)(gateway->pod_id_or_scope >> 32);
    encoded[offset++] = (uint8_t)(gateway->pod_id_or_scope >> 24);
    encoded[offset++] = (uint8_t)(gateway->pod_id_or_scope >> 16);
    encoded[offset++] = (uint8_t)(gateway->pod_id_or_scope >> 8);
    encoded[offset++] = (uint8_t)gateway->pod_id_or_scope;
    wvm_sha256_digest(encoded, offset, digest);
    return 0;
}

int wvm_ctl_membership_enrollment_init(
    struct wvm_ctl_membership_enrollment *enrollment,
    struct wvm_control_plane *plane, uint32_t controller_physical_node_id,
    uint64_t controller_instance_id, const char *state_directory,
    void *submit_context, wvm_admission_transport_submit_fn submit,
    struct wvm_cluster_admission_ack_entry *ack_storage, size_t ack_capacity,
    char *error, size_t error_len)
{
    if (!enrollment || !plane || !state_directory || !state_directory[0] ||
        !ack_storage || ack_capacity == 0) {
        set_error(error, error_len,
                  "ctl membership enrollment configuration is invalid");
        return -1;
    }
    memset(enrollment, 0, sizeof(*enrollment));
    if (wvm_membership_enrollment_transport_init(
            &enrollment->transport, controller_physical_node_id,
            controller_instance_id, submit_context, submit, error,
            error_len) != 0) {
        return -1;
    }
    enrollment->plane = plane;
    enrollment->ack_storage = ack_storage;
    enrollment->ack_capacity = ack_capacity;
    enrollment->state_directory = state_directory;
    enrollment->controller_physical_node_id = controller_physical_node_id;
    enrollment->controller_instance_id = controller_instance_id;
    enrollment->initialized = 1;
    return 0;
}

void wvm_ctl_membership_enrollment_destroy(
    struct wvm_ctl_membership_enrollment *enrollment)
{
    if (!enrollment) {
        return;
    }
    memset(enrollment, 0, sizeof(*enrollment));
}

int wvm_ctl_membership_enrollment_activate_compute(
    struct wvm_ctl_membership_enrollment *enrollment,
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    struct wvm_membership_controller *controller;
    const struct wvm_membership_controller_member_entry *entry;
    struct wvm_cluster_admission_proof proof;
    struct wvm_membership_cluster_enrollment_request request;
    uint8_t capability_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t topology_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_node_record node_copy;

    if (!enrollment || !enrollment->initialized || !enrollment->plane ||
        !member_key ||
        member_key->role_type != WVM_MANIFEST_ROLE_NODE_RUNTIME ||
        wvm_member_key_validate(member_key, error, error_len) != 0) {
        set_error(error, error_len, "cluster enrollment target is invalid");
        return -1;
    }
    controller = &enrollment->plane->membership_controller;
    if (controller->route_count != 0) {
        set_error(error, error_len,
                  "cluster enrollment refuses VM route scopes; use route join");
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry || entry->kind != WVM_MEMBERSHIP_COMPUTE) {
        set_error(error, error_len,
                  "cluster enrollment target compute member is missing");
        return -1;
    }
    if (entry->node.desired_membership_state == WVM_MANIFEST_MEMBER_ACTIVE) {
        return 0;
    }
    /*
     * Advance to PREPARED/HEALTHY before binding the proof revision fence.
     * enroll_cluster_member repeats these steps idempotently and must not
     * advance revisions after the proof is built.
     */
    if (wvm_membership_controller_report_self_health(
            controller, member_key, WVM_MEMBERSHIP_HEALTHY, error,
            error_len) != 0) {
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry) {
        set_error(error, error_len,
                  "cluster enrollment target disappeared during preparation");
        return -1;
    }
    if (entry->node.desired_membership_state == WVM_MANIFEST_MEMBER_PENDING &&
        wvm_membership_controller_begin_validation(controller, member_key, error,
                                                   error_len) != 0) {
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry) {
        set_error(error, error_len,
                  "cluster enrollment target disappeared during validation");
        return -1;
    }
    if ((entry->node.desired_membership_state == WVM_MANIFEST_MEMBER_PENDING ||
         entry->node.desired_membership_state ==
             WVM_MANIFEST_MEMBER_VALIDATING) &&
        wvm_membership_controller_prepare_member(controller, member_key, error,
                                                 error_len) != 0) {
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry || entry->kind != WVM_MEMBERSHIP_COMPUTE) {
        set_error(error, error_len,
                  "cluster enrollment target missing after prepare");
        return -1;
    }
    if (entry->node.desired_membership_state != WVM_MANIFEST_MEMBER_PREPARED &&
        entry->node.desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE) {
        set_error(error, error_len,
                  "cluster enrollment target did not reach PREPARED");
        return -1;
    }
    if (entry->node.desired_membership_state == WVM_MANIFEST_MEMBER_ACTIVE) {
        return 0;
    }
    node_copy = entry->node;
    {
        struct wvm_capability_report evidence_report = {0};
        uint16_t resume_state = 0;

        /*
         * ACTIVE requires durable capability evidence that still matches the
         * member CapabilityRef — not a digest of the ref alone.
         */
        if (wvm_ctl_load_capabilities(enrollment->state_directory,
                                      &node_copy.capability, &evidence_report,
                                      error, error_len) != 0) {
            return -1;
        }
        wvm_capability_report_destroy(&evidence_report);
        if (capability_evidence_digest_from_node(&node_copy, capability_digest,
                                                 error, error_len) != 0 ||
            topology_assignment_digest_from_node(&node_copy, topology_digest,
                                                 error, error_len) != 0) {
            return -1;
        }
        memset(&proof, 0, sizeof(proof));
        if (wvm_membership_controller_find_resumable_enrollment(
                controller, member_key, &proof, enrollment->ack_storage,
                enrollment->ack_capacity, &resume_state, error,
                error_len) == 0) {
            /* Resume same operation_id/proof after a prior commit failure. */
        } else if (allocate_nonzero_operation_id(operation_id, error,
                                                 error_len) != 0 ||
                   wvm_membership_controller_build_cluster_admission_proof(
                       controller, member_key, operation_id,
                       controller->membership_revision,
                       controller->topology_revision,
                       controller->admission_eligibility_revision,
                       capability_digest, topology_digest, &proof,
                       enrollment->ack_storage, enrollment->ack_capacity, error,
                       error_len) != 0) {
            return -1;
        }
    }
    memset(&request, 0, sizeof(request));
    request.member_kind = WVM_MEMBERSHIP_COMPUTE;
    request.authenticated_actor = member_key;
    request.node = &node_copy;
    request.proof = &proof;
    if (wvm_membership_enrollment_transport_bind(&enrollment->transport,
                                                 &request, error,
                                                 error_len) != 0) {
        return -1;
    }
    return wvm_membership_coordinator_enroll_cluster_member(
        controller, &request, error, error_len);
}


int wvm_ctl_membership_enrollment_activate_gateway(
    struct wvm_ctl_membership_enrollment *enrollment,
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    struct wvm_membership_controller *controller;
    const struct wvm_membership_controller_member_entry *entry;
    struct wvm_cluster_admission_proof proof;
    struct wvm_membership_cluster_enrollment_request request;
    uint8_t capability_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t topology_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_gateway_record gateway_copy;

    if (!enrollment || !enrollment->initialized || !enrollment->plane ||
        !member_key ||
        member_key->role_type != WVM_MANIFEST_ROLE_GATEWAY ||
        wvm_member_key_validate(member_key, error, error_len) != 0) {
        set_error(error, error_len, "cluster enrollment gateway target is invalid");
        return -1;
    }
    controller = &enrollment->plane->membership_controller;
    if (controller->route_count != 0) {
        set_error(error, error_len,
                  "cluster enrollment refuses VM route scopes; use route join");
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry || entry->kind != WVM_MEMBERSHIP_GATEWAY) {
        set_error(error, error_len,
                  "cluster enrollment target gateway member is missing");
        return -1;
    }
    if (entry->gateway.desired_membership_state == WVM_MANIFEST_MEMBER_ACTIVE) {
        return 0;
    }
    if (wvm_membership_controller_report_self_health(
            controller, member_key, WVM_MEMBERSHIP_HEALTHY, error,
            error_len) != 0) {
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry) {
        set_error(error, error_len,
                  "cluster enrollment gateway disappeared during preparation");
        return -1;
    }
    if (entry->gateway.desired_membership_state == WVM_MANIFEST_MEMBER_PENDING &&
        wvm_membership_controller_begin_validation(controller, member_key, error,
                                                   error_len) != 0) {
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry) {
        set_error(error, error_len,
                  "cluster enrollment gateway disappeared during validation");
        return -1;
    }
    if ((entry->gateway.desired_membership_state == WVM_MANIFEST_MEMBER_PENDING ||
         entry->gateway.desired_membership_state ==
             WVM_MANIFEST_MEMBER_VALIDATING) &&
        wvm_membership_controller_prepare_member(controller, member_key, error,
                                                 error_len) != 0) {
        return -1;
    }
    entry = wvm_membership_controller_find(controller, member_key);
    if (!entry || entry->kind != WVM_MEMBERSHIP_GATEWAY) {
        set_error(error, error_len,
                  "cluster enrollment gateway missing after prepare");
        return -1;
    }
    if (entry->gateway.desired_membership_state != WVM_MANIFEST_MEMBER_PREPARED &&
        entry->gateway.desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE) {
        set_error(error, error_len,
                  "cluster enrollment gateway did not reach PREPARED");
        return -1;
    }
    if (entry->gateway.desired_membership_state == WVM_MANIFEST_MEMBER_ACTIVE) {
        return 0;
    }
    gateway_copy = entry->gateway;
    {
        uint16_t resume_state = 0;

        if (capability_evidence_digest_from_gateway(&gateway_copy,
                                                    capability_digest, error,
                                                    error_len) != 0 ||
            topology_assignment_digest_from_gateway(&gateway_copy,
                                                    topology_digest, error,
                                                    error_len) != 0) {
            return -1;
        }
        memset(&proof, 0, sizeof(proof));
        if (wvm_membership_controller_find_resumable_enrollment(
                controller, member_key, &proof, enrollment->ack_storage,
                enrollment->ack_capacity, &resume_state, error,
                error_len) == 0) {
            /* Resume same operation_id/proof after commit failure. */
        } else if (allocate_nonzero_operation_id(operation_id, error,
                                                 error_len) != 0 ||
                   wvm_membership_controller_build_cluster_admission_proof(
                       controller, member_key, operation_id,
                       controller->membership_revision,
                       controller->topology_revision,
                       controller->admission_eligibility_revision,
                       capability_digest, topology_digest, &proof,
                       enrollment->ack_storage, enrollment->ack_capacity, error,
                       error_len) != 0) {
            return -1;
        }
    }
    memset(&request, 0, sizeof(request));
    request.member_kind = WVM_MEMBERSHIP_GATEWAY;
    request.authenticated_actor = member_key;
    request.gateway = &gateway_copy;
    request.proof = &proof;
    if (wvm_membership_enrollment_transport_bind(&enrollment->transport,
                                                 &request, error,
                                                 error_len) != 0) {
        return -1;
    }
    return wvm_membership_coordinator_enroll_cluster_member(
        controller, &request, error, error_len);
}

int wvm_ctl_membership_enrollment_apply(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *authenticated_actor,
    struct wvm_membership_control_result *result, char *error,
    size_t error_len)
{
    struct wvm_ctl_membership_enrollment *enrollment = opaque;
    char enroll_error[256];
    int rc;

    if (!enrollment || !enrollment->initialized || !enrollment->plane) {
        set_error(error, error_len, "ctl membership enrollment is not ready");
        return -1;
    }
    rc = wvm_control_plane_membership_apply(
        enrollment->plane, request, authenticated_actor, result, error,
        error_len);
    if (rc != 0 || !request || !result ||
        result->status_code != WVM_MEMBERSHIP_CONTROL_SUCCESS ||
        request->message_type != WVM_ENVELOPE_MSG_REGISTER_MEMBER ||
        !authenticated_actor) {
        return rc;
    }
    enroll_error[0] = '\0';
    if (authenticated_actor->role_type == WVM_MANIFEST_ROLE_NODE_RUNTIME) {
        if (wvm_ctl_membership_enrollment_activate_compute(
                enrollment, authenticated_actor, enroll_error,
                sizeof(enroll_error)) != 0) {
            fprintf(stderr,
                    "wvm_ctl: cluster enrollment after REGISTER deferred: %s\n",
                    enroll_error[0] ? enroll_error : "unknown error");
        }
    } else if (authenticated_actor->role_type == WVM_MANIFEST_ROLE_GATEWAY) {
        if (wvm_ctl_membership_enrollment_activate_gateway(
                enrollment, authenticated_actor, enroll_error,
                sizeof(enroll_error)) != 0) {
            fprintf(stderr,
                    "wvm_ctl: gateway enrollment after REGISTER deferred: %s\n",
                    enroll_error[0] ? enroll_error : "unknown error");
        }
    }
    return 0;
}

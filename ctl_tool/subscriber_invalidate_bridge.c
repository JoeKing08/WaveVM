/*
 * N05: ctl overrides the weak memory_service membership invalidate hook.
 * Membership lives in wvm_ctl; the directory memory_service lives in
 * node_runtime. Fan out INVALIDATE_SUBSCRIBERS to ACTIVE compute members so
 * expired/failed instance leases are dropped in the process that owns them.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "../common_include/wavevm_admission_transport.h"
#include "../common_include/wavevm_envelope.h"
#include "../common_include/wavevm_membership_controller.h"
#include "../common_include/wavevm_manifest.h"

struct n05_bridge {
    pthread_mutex_t lock;
    int ready;
    struct wvm_membership_controller *membership;
    struct wvm_admission_transport *transport;
    struct wvm_membership_controller_capture *capture;
};

static struct n05_bridge g_n05 = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

void wvm_ctl_subscriber_invalidate_bridge_bind(
    struct wvm_membership_controller *membership,
    struct wvm_admission_transport *transport,
    struct wvm_membership_controller_capture *capture)
{
    pthread_mutex_lock(&g_n05.lock);
    g_n05.membership = membership;
    g_n05.transport = transport;
    g_n05.capture = capture;
    g_n05.ready = membership && transport && capture;
    pthread_mutex_unlock(&g_n05.lock);
}

/*
 * Strong definition: overrides weak NULL from membership_controller when
 * linked into wvm_ctl (which does not link memory_service.c).
 */
void wvm_memory_service_membership_failure_invalidate_hook(
    void *context, uint32_t physical_node_id, uint64_t node_instance_id,
    uint16_t desired_state, uint16_t health_state)
{
    struct wvm_membership_controller *membership;
    struct wvm_admission_transport *transport;
    struct wvm_membership_controller_capture *capture;
    char error[256];
    size_t i;
    size_t sent = 0;
    size_t failed = 0;

    (void)context;
    (void)desired_state;
    (void)health_state;
    if (physical_node_id == 0 || node_instance_id == 0) {
        return;
    }

    pthread_mutex_lock(&g_n05.lock);
    if (!g_n05.ready) {
        pthread_mutex_unlock(&g_n05.lock);
        return;
    }
    membership = g_n05.membership;
    transport = g_n05.transport;
    capture = g_n05.capture;
    pthread_mutex_unlock(&g_n05.lock);

    error[0] = '\0';
    if (wvm_membership_controller_capture(membership, capture, error,
                                          sizeof(error)) != 0) {
        fprintf(stderr,
                "[wvm_ctl] N05: cannot capture membership for subscriber "
                "invalidate: %s\n",
                error[0] ? error : "(none)");
        return;
    }

    for (i = 0; i < capture->node_count; i++) {
        const struct wvm_node_record *node = &capture->nodes[i];
        struct wvm_admission_transport_target target;
        struct wvm_envelope envelope;
        uint8_t payload[16];
        char local_error[256];
        int rc;

        if (node->desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE) {
            continue;
        }
        if (node->physical_node_id == 0 || node->node_instance_id == 0) {
            continue;
        }
        memset(&target, 0, sizeof(target));
        target.member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
        target.member_key.role_id = node->physical_node_id;
        target.member_key.instance_id = node->node_instance_id;
        target.endpoint = node->control_endpoint;

        memset(payload, 0, sizeof(payload));
        payload[0] = (uint8_t)(physical_node_id & 0xffU);
        payload[1] = (uint8_t)((physical_node_id >> 8) & 0xffU);
        payload[2] = (uint8_t)((physical_node_id >> 16) & 0xffU);
        payload[3] = (uint8_t)((physical_node_id >> 24) & 0xffU);
        payload[4] = (uint8_t)(node_instance_id & 0xffU);
        payload[5] = (uint8_t)((node_instance_id >> 8) & 0xffU);
        payload[6] = (uint8_t)((node_instance_id >> 16) & 0xffU);
        payload[7] = (uint8_t)((node_instance_id >> 24) & 0xffU);
        payload[8] = (uint8_t)((node_instance_id >> 32) & 0xffU);
        payload[9] = (uint8_t)((node_instance_id >> 40) & 0xffU);
        payload[10] = (uint8_t)((node_instance_id >> 48) & 0xffU);
        payload[11] = (uint8_t)((node_instance_id >> 56) & 0xffU);

        memset(&envelope, 0, sizeof(envelope));
        envelope.message_type = WVM_ENVELOPE_MSG_INVALIDATE_SUBSCRIBERS;
        envelope.payload = payload;
        envelope.payload_bytes = 12;

        local_error[0] = '\0';
        /*
         * Best-effort fanout: unreachable directories are counted but do not
         * stop other ACTIVE directories from receiving the invalidate.
         */
        rc = transport->submit ? transport->submit(transport->context, &target,
                                                   &envelope, local_error,
                                                   sizeof(local_error))
                               : -ENOTSUP;
        if (rc != 0) {
            failed++;
            fprintf(stderr,
                    "[wvm_ctl] N05: invalidate fanout failed node=%u inst=%llu "
                    "rc=%d err=%s\n",
                    (unsigned)node->physical_node_id,
                    (unsigned long long)node->node_instance_id, rc,
                    local_error[0] ? local_error : "(none)");
        } else {
            sent++;
        }
    }
    fprintf(stderr,
            "[wvm_ctl] N05: subscriber invalidate fanout failed_member=%u:%llu "
            "sent=%zu failed=%zu\n",
            (unsigned)physical_node_id, (unsigned long long)node_instance_id,
            sent, failed);
}


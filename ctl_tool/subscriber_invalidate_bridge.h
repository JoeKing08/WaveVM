#ifndef WVM_CTL_SUBSCRIBER_INVALIDATE_BRIDGE_H
#define WVM_CTL_SUBSCRIBER_INVALIDATE_BRIDGE_H

#include "../common_include/wavevm_admission_transport.h"
#include "../common_include/wavevm_membership_controller.h"

void wvm_ctl_subscriber_invalidate_bridge_bind(
    struct wvm_membership_controller *membership,
    struct wvm_admission_transport *transport,
    struct wvm_membership_controller_capture *capture);

#endif

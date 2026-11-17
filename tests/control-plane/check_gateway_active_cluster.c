#include <stdio.h>
#include <stdlib.h>

#include "wavevm_membership_controller.h"

/*
 * Offline check: gateway 901:902 is present with committed cluster
 * enrollment, desired ACTIVE and HEALTHY. Other members are ignored.
 * Used to serialize agent A start until the gateway enrollment proof
 * has committed (REGISTER accepted is not enough: A9 raced A against
 * a still-PREPARING gateway ACK and left 901:902 without an activation
 * id).
 */
int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[8];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    char error[256] = {0};
    int gateway_ok = 0;
    size_t i;

    if (argc != 2) {
        return 2;
    }
    wvm_membership_controller_init(&controller, members, 8, routes, 4,
                                    dependencies, 4, NULL, NULL);
    if (wvm_membership_controller_open(&controller, argv[1], error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "membership recovery failed: %s\n", error);
        return 1;
    }
    for (i = 0; i < controller.member_count; i++) {
        uint16_t enrollment_state = 0;

        if (!members[i].has_activation_enrollment_operation_id ||
            members[i].has_activation_route_operation_id) {
            continue;
        }
        if (wvm_membership_controller_cluster_enrollment_state(
                &controller, members[i].activation_enrollment_operation_id,
                &enrollment_state, error, sizeof(error)) != 0 ||
            enrollment_state != WVM_MEMBERSHIP_ENROLLMENT_COMMITTED) {
            continue;
        }
        if (members[i].kind == WVM_MEMBERSHIP_GATEWAY &&
            members[i].member_key.role_id == 901 &&
            members[i].member_key.instance_id == 902 &&
            members[i].gateway.desired_membership_state ==
                WVM_MANIFEST_MEMBER_ACTIVE &&
            members[i].gateway.observed_health_state ==
                WVM_MEMBERSHIP_HEALTHY) {
            gateway_ok = 1;
        }
    }
    {
        size_t n = controller.member_count;
        wvm_membership_controller_close(&controller);
        if (!gateway_ok) {
            fprintf(stderr, "gateway 901:902 not COMMITTED+ACTIVE (members=%zu)\n",
                    n);
            return 1;
        }
    }
    return 0;
}

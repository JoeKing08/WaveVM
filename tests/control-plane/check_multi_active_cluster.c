#include <stdio.h>
#include <stdlib.h>

#include "wavevm_membership_controller.h"

/*
 * Offline check: exactly one ACTIVE GATEWAY (901:902) and two ACTIVE compute
 * members (801:802, 811:812), each with committed cluster enrollment.
 */
int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[8];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    char error[256] = {0};
    int gateway_ok = 0;
    int compute_a = 0;
    int compute_b = 0;
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
    if (controller.member_count != 3 || controller.route_count != 0) {
        fprintf(stderr, "expected 3 members 0 routes, got %zu members %zu routes\n",
                controller.member_count, controller.route_count);
        wvm_membership_controller_close(&controller);
        return 1;
    }
    for (i = 0; i < controller.member_count; i++) {
        uint16_t enrollment_state = 0;

        if (!members[i].has_activation_enrollment_operation_id ||
            members[i].has_activation_route_operation_id) {
            fprintf(stderr, "member %zu missing enrollment activation id\n", i);
            wvm_membership_controller_close(&controller);
            return 1;
        }
        if (wvm_membership_controller_cluster_enrollment_state(
                &controller, members[i].activation_enrollment_operation_id,
                &enrollment_state, error, sizeof(error)) != 0 ||
            enrollment_state != WVM_MEMBERSHIP_ENROLLMENT_COMMITTED) {
            fprintf(stderr, "member %zu enrollment not COMMITTED\n", i);
            wvm_membership_controller_close(&controller);
            return 1;
        }
        if (members[i].kind == WVM_MEMBERSHIP_GATEWAY &&
            members[i].member_key.role_id == 901 &&
            members[i].member_key.instance_id == 902 &&
            members[i].gateway.desired_membership_state ==
                WVM_MANIFEST_MEMBER_ACTIVE &&
            members[i].gateway.observed_health_state ==
                WVM_MEMBERSHIP_HEALTHY) {
            gateway_ok = 1;
        } else if (members[i].kind == WVM_MEMBERSHIP_COMPUTE &&
                   members[i].member_key.role_id == 801 &&
                   members[i].member_key.instance_id == 802 &&
                   members[i].node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE &&
                   members[i].node.observed_health_state ==
                       WVM_MEMBERSHIP_HEALTHY) {
            compute_a = 1;
        } else if (members[i].kind == WVM_MEMBERSHIP_COMPUTE &&
                   members[i].member_key.role_id == 811 &&
                   members[i].member_key.instance_id == 812 &&
                   members[i].node.desired_membership_state ==
                       WVM_MANIFEST_MEMBER_ACTIVE &&
                   members[i].node.observed_health_state ==
                       WVM_MEMBERSHIP_HEALTHY) {
            compute_b = 1;
        }
    }
    wvm_membership_controller_close(&controller);
    if (!gateway_ok || !compute_a || !compute_b) {
        fprintf(stderr,
                "multi-ACTIVE cluster missing members (gw=%d a=%d b=%d)\n",
                gateway_ok, compute_a, compute_b);
        return 1;
    }
    return 0;
}

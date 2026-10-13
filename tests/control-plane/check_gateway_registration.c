#include <stdio.h>
#include <stdlib.h>

#include "wavevm_membership_controller.h"

int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[2];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_dependency dependencies[2];
    const struct wvm_gateway_record *gateway;
    unsigned long control_port;
    char *end;
    char error[256] = {0};
    int valid;
    uint16_t enrollment_state = 0;

    if (argc != 3) {
        return 2;
    }
    control_port = strtoul(argv[2], &end, 10);
    if (*end != '\0' || control_port == 0 || control_port > UINT16_MAX) {
        return 2;
    }
    wvm_membership_controller_init(&controller, members, 2, routes, 2,
                                    dependencies, 2, NULL, NULL);
    if (wvm_membership_controller_open(&controller, argv[1], error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "membership recovery failed: %s\n", error);
        return 1;
    }
    valid = controller.member_count == 1 &&
            members[0].kind == WVM_MEMBERSHIP_GATEWAY &&
            members[0].member_key.role_type == WVM_MANIFEST_ROLE_GATEWAY &&
            members[0].member_key.role_id == 901 &&
            members[0].member_key.instance_id == 902;
    if (valid) {
        gateway = &members[0].gateway;
        valid = gateway->desired_membership_state == WVM_MANIFEST_MEMBER_ACTIVE &&
                gateway->observed_health_state == WVM_MEMBERSHIP_HEALTHY &&
                gateway->endpoint.control_port == control_port &&
                gateway->gateway_id == 901 &&
                gateway->gateway_instance_id == 902 &&
                members[0].has_activation_enrollment_operation_id &&
                !members[0].has_activation_route_operation_id;
    }
    if (valid &&
        wvm_membership_controller_cluster_enrollment_state(
            &controller, members[0].activation_enrollment_operation_id,
            &enrollment_state, error, sizeof(error)) != 0) {
        fprintf(stderr, "enrollment state lookup failed: %s\n", error);
        valid = 0;
    }
    if (valid) {
        valid = enrollment_state == WVM_MEMBERSHIP_ENROLLMENT_COMMITTED;
    }
    wvm_membership_controller_close(&controller);
    if (!valid) {
        fprintf(stderr,
                "registration did not persist an ACTIVE enrolled gateway member\n");
        return 1;
    }
    return 0;
}

#include <stdio.h>
#include <stdlib.h>

#include "wavevm_membership_controller.h"

int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[2];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_dependency dependencies[2];
    const struct wvm_node_record *node;
    unsigned long control_port;
    char *end;
    char error[256] = {0};
    int valid;

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
    valid = controller.member_count == 1 && controller.route_count == 0 &&
            members[0].kind == WVM_MEMBERSHIP_COMPUTE &&
            members[0].member_key.role_type == WVM_MANIFEST_ROLE_NODE_RUNTIME &&
            members[0].member_key.role_id == 801 &&
            members[0].member_key.instance_id == 802;
    if (valid) {
        node = &members[0].node;
        valid = node->desired_membership_state == WVM_MANIFEST_MEMBER_PENDING &&
                node->observed_health_state == WVM_MEMBERSHIP_RECOVERING &&
                node->control_endpoint.control_port == control_port &&
                node->inventory.registered_vcpu_slots == 2 &&
                node->inventory.registered_memory_bytes == 1073741824ULL &&
                !members[0].has_activation_route_operation_id;
    }
    wvm_membership_controller_close(&controller);
    if (!valid) {
        fprintf(stderr, "registration did not persist a pending node\n");
        return 1;
    }
    return 0;
}

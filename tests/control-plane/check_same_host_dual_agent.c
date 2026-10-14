#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_control.h"
#include "wavevm_membership_controller.h"

/*
 * Offline check: two ACTIVE compute members share physical_host_id, distinct
 * namespaces/ports, and pass host aggregate (no double-count). Optional
 * gateway may also be present (ignored for host accounting of compute).
 */
int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[8];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_node_record host_nodes[4];
    size_t host_count = 0;
    size_t compute_active = 0;
    uint64_t host_id = 0;
    char error[256] = {0};
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
        if (members[i].kind != WVM_MEMBERSHIP_COMPUTE) {
            continue;
        }
        if (members[i].node.desired_membership_state !=
                WVM_MANIFEST_MEMBER_ACTIVE ||
            members[i].node.observed_health_state != WVM_MEMBERSHIP_HEALTHY ||
            !members[i].has_activation_enrollment_operation_id) {
            fprintf(stderr, "compute member %zu not ACTIVE via enrollment\n", i);
            wvm_membership_controller_close(&controller);
            return 1;
        }
        if (host_count == 0) {
            host_id = members[i].node.physical_host_id;
        } else if (members[i].node.physical_host_id != host_id) {
            fprintf(stderr, "compute members do not share physical_host_id\n");
            wvm_membership_controller_close(&controller);
            return 1;
        }
        if (host_id == 0) {
            fprintf(stderr, "physical_host_id must be non-zero\n");
            wvm_membership_controller_close(&controller);
            return 1;
        }
        host_nodes[host_count++] = members[i].node;
        compute_active++;
    }
    if (compute_active != 2) {
        fprintf(stderr, "expected 2 ACTIVE compute, got %zu\n", compute_active);
        wvm_membership_controller_close(&controller);
        return 1;
    }
    if (strcmp(host_nodes[0].node_instance_namespace.namespace_name,
               host_nodes[1].node_instance_namespace.namespace_name) == 0) {
        fprintf(stderr, "same-host namespaces must be distinct\n");
        wvm_membership_controller_close(&controller);
        return 1;
    }
    if (host_nodes[0].control_endpoint.control_port ==
            host_nodes[1].control_endpoint.control_port ||
        host_nodes[0].control_endpoint.data_port ==
            host_nodes[1].control_endpoint.data_port) {
        fprintf(stderr, "same-host listener ports must be distinct\n");
        wvm_membership_controller_close(&controller);
        return 1;
    }
    if (wvm_physical_host_aggregate_validate(host_nodes, host_count, error,
                                             sizeof(error)) != 0) {
        fprintf(stderr, "host aggregate failed: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }
    wvm_membership_controller_close(&controller);
    return 0;
}

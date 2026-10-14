#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <string.h>

#include "../../ctl_tool/gateway_drain_successor.h"
#include "wavevm_manifest.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "gateway-drain-successor test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_route_entry routes[2];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_ctl_gateway_drain_successor out;
    struct wvm_member_key departing;
    struct wvm_member_key successor;
    char error[256];

    memset(&controller, 0, sizeof(controller));
    wvm_membership_controller_init(&controller, members, 4, routes, 2,
                                   dependencies, 4, NULL, NULL);
    /* Not open — builder must still fail closed on missing members. */
    memset(&departing, 0, sizeof(departing));
    departing.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    departing.role_id = 901;
    departing.instance_id = 902;
    memset(&successor, 0, sizeof(successor));
    successor.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    successor.role_id = 911;
    successor.instance_id = 912;

    if (expect(wvm_ctl_gateway_drain_successor_build(
                   &out, &controller, &departing, &departing, error,
                   sizeof(error)) != 0,
               "reject identical departing and successor") != 0) {
        return 1;
    }
    if (expect(wvm_ctl_gateway_drain_successor_build(
                   &out, &controller, &departing, &successor, error,
                   sizeof(error)) != 0,
               "reject build without ACTIVE gateways/deps") != 0) {
        return 1;
    }
    if (expect(wvm_ctl_gateway_drain_successor_build(
                   NULL, &controller, &departing, &successor, error,
                   sizeof(error)) != 0,
               "reject null output") != 0) {
        return 1;
    }

    printf("gateway-drain-successor test: ok\n");
    return 0;
}

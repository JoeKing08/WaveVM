#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_membership_controller.h"

/*
 * Offline membership journal probe for production cordon/drain clients.
 * Prints: membership_revision topology_revision eligibility_revision
 *         member_count and one line per member: role_type role_id instance
 *         desired_state kind.
 */
int main(int argc, char **argv)
{
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[16];
    struct wvm_membership_controller_route_entry routes[8];
    struct wvm_membership_dependency dependencies[16];
    char error[256] = {0};
    size_t i;
    uint32_t filter_role_id = 0;
    uint64_t filter_instance_id = 0;
    int have_filter = 0;

    if (argc != 2 && argc != 4) {
        fprintf(stderr,
                "usage: %s JOURNAL [role_id instance_id]\n", argv[0]);
        return 2;
    }
    if (argc == 4) {
        filter_role_id = (uint32_t)strtoul(argv[2], NULL, 10);
        filter_instance_id = (uint64_t)strtoull(argv[3], NULL, 10);
        have_filter = 1;
    }
    wvm_membership_controller_init(&controller, members, 16, routes, 8,
                                    dependencies, 16, NULL, NULL);
    if (wvm_membership_controller_open(&controller, argv[1], error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "membership open failed: %s\n", error);
        return 1;
    }
    printf("revisions %llu %llu %llu\n",
           (unsigned long long)controller.membership_revision,
           (unsigned long long)controller.topology_revision,
           (unsigned long long)controller.admission_eligibility_revision);
    printf("member_count %zu\n", controller.member_count);
    for (i = 0; i < controller.member_count; i++) {
        const struct wvm_membership_controller_member_entry *entry = &members[i];
        uint16_t state;

        if (have_filter &&
            (entry->member_key.role_id != filter_role_id ||
             entry->member_key.instance_id != filter_instance_id)) {
            continue;
        }
        if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
            state = entry->node.desired_membership_state;
        } else {
            state = entry->gateway.desired_membership_state;
        }
        printf("member %u %u %llu state=%u kind=%u deps=%llu\n",
               (unsigned)entry->member_key.role_type,
               (unsigned)entry->member_key.role_id,
               (unsigned long long)entry->member_key.instance_id,
               (unsigned)state, (unsigned)entry->kind,
               (unsigned long long)entry->active_dependency_count);
    }
    wvm_membership_controller_close(&controller);
    return 0;
}

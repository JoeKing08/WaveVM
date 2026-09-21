#define _GNU_SOURCE
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_admission_slot_registry.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "admission-slot-registry test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_admission_receiver receiver = {0};
    struct wvm_admission_receiver_config receiver_config = {0};
    struct wvm_admission_slot_registry registry = {0};
    struct wvm_admission_slot_registry_config registry_config = {0};
    struct wvm_admission_receiver_slot slots[1];
    struct wvm_admission_receiver_slot *first = NULL;
    struct wvm_admission_receiver_slot *repeat = NULL;
    struct wvm_admission_receiver_slot *overflow = NULL;
    struct wvm_member_key controller = {
        .role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME,
        .role_id = 701,
        .instance_id = 702,
    };
    char directory[] = "/tmp/wavevm-admission-slot-registry.XXXXXX";
    char state_path[256];
    char runtime_path[256];
    char error[256] = {0};
    int status = 1;

    memset(slots, 0, sizeof(slots));
    if (!mkdtemp(directory) ||
        snprintf(state_path, sizeof(state_path), "%s/state", directory) < 0 ||
        snprintf(runtime_path, sizeof(runtime_path), "%s/runtime", directory) <
            0 ||
        mkdir(state_path, 0700) != 0 || mkdir(runtime_path, 0700) != 0) {
        return 1;
    }
    receiver_config.controller_member_key = controller;
    receiver_config.controller_physical_node_id = 701;
    receiver_config.controller_runtime_instance_id = 702;
    receiver_config.local_physical_node_id = 801;
    receiver_config.local_node_instance_id = 802;
    receiver_config.resolve_slot = wvm_admission_slot_registry_resolve;
    receiver_config.context = &registry;
    registry_config.receiver = &receiver;
    registry_config.slots = slots;
    registry_config.slot_capacity = 1;
    registry_config.state_directory = state_path;
    registry_config.runtime_directory = runtime_path;
    if (wvm_admission_receiver_init(&receiver, &receiver_config, error,
                                    sizeof(error)) != 0 ||
        wvm_admission_slot_registry_init(&registry, &registry_config, error,
                                         sizeof(error)) != 0 ||
        wvm_admission_slot_registry_resolve(
            &registry, 9001, 4, 7, &first, error, sizeof(error)) != 0 ||
        expect(first != NULL && first->vm_id == 9001 &&
                   first->vm_incarnation == 4 &&
                   first->manifest_generation == 7,
               "first identity opens one bounded slot") != 0 ||
        wvm_admission_slot_registry_resolve(
            &registry, 9001, 4, 7, &repeat, error, sizeof(error)) != 0 ||
        expect(repeat == first, "same identity reuses its slot") != 0 ||
        expect(first->state_path != NULL && first->runtime_manifest_path != NULL,
               "slot owns deterministic durable paths") != 0 ||
        wvm_admission_slot_registry_resolve(
            &registry, 9002, 4, 7, &overflow, error, sizeof(error)) != -ENOSPC) {
        fprintf(stderr, "admission-slot-registry test: %s\n",
                error[0] ? error : "registry assertion failed");
        goto out;
    }
    status = 0;
out:
    wvm_admission_slot_registry_destroy(&registry);
    wvm_admission_receiver_destroy(&receiver);
    unlink("/tmp/unused-wavevm-admission-slot-registry");
    {
        char command[512];

        snprintf(command, sizeof(command), "rm -rf '%s'", directory);
        (void)system(command);
    }
    return status;
}

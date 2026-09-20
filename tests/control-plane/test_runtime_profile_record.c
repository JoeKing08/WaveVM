#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_runtime_profile.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "runtime-profile-record test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_profile(struct wvm_node_runtime_profile *profile,
                         uint16_t data_ports[2], uint16_t service_ports[2])
{
    memset(profile, 0, sizeof(*profile));
    profile->physical_node_id = 17;
    profile->node_instance_id = 101;
    profile->inventory_revision = 3;
    profile->capability_profile_generation = 5;
    profile->runtime_profile_generation = 7;
    profile->node_runtime_control_port = 19001;
    profile->local_executor_control_port = 19002;
    profile->executor_worker_count = 4;
    profile->sync_batch_size = 64;
    profile->vcpu_handoff_record_capacity = 128;
    profile->node_runtime_data_ports = data_ports;
    profile->node_runtime_data_port_count = 2;
    profile->local_executor_service_ports = service_ports;
    profile->local_executor_service_port_count = 2;
}

int main(void)
{
    uint16_t data_ports[2] = {19100, 19101};
    uint16_t service_ports[2] = {19200, 19201};
    struct wvm_node_runtime_profile profile;
    struct wvm_node_runtime_profile decoded = {0};
    uint8_t *bytes;
    size_t encoded_bytes = 0;
    char error[256] = {0};
    int rc = 1;

    bytes = malloc(WVM_NODE_RUNTIME_PROFILE_MAX_BYTES + 1U);
    if (!bytes) {
        return 1;
    }
    fill_profile(&profile, data_ports, service_ports);
    if (expect(wvm_node_runtime_profile_encode(
                   &profile, bytes, WVM_NODE_RUNTIME_PROFILE_MAX_BYTES + 1U,
                   &encoded_bytes, error, sizeof(error)) == 0,
               "accept a large output buffer for a bounded record") ||
        expect(wvm_node_runtime_profile_decode(
                   bytes, encoded_bytes, &decoded, error, sizeof(error)) == 0,
               "decode an encoded profile") ||
        expect(decoded.physical_node_id == profile.physical_node_id &&
                   decoded.runtime_profile_generation == 7 &&
                   decoded.node_runtime_data_port_count == 2 &&
                   decoded.node_runtime_data_ports[1] == 19101 &&
                   decoded.local_executor_service_port_count == 2 &&
                   decoded.local_executor_service_ports[0] == 19200,
               "round trip all profile fields")) {
        goto out;
    }

    data_ports[1] = data_ports[0];
    memset(error, 0, sizeof(error));
    if (expect(wvm_node_runtime_profile_validate(
                   &profile, error, sizeof(error)) != 0,
               "reject an unsorted or duplicate data-port pool")) {
        goto out;
    }
    data_ports[1] = 19101;
    service_ports[0] = data_ports[1];
    memset(error, 0, sizeof(error));
    if (expect(wvm_node_runtime_profile_validate(
                   &profile, error, sizeof(error)) != 0,
               "reject a port collision between pools")) {
        goto out;
    }
    service_ports[0] = 19200;
    memset(error, 0, sizeof(error));
    if (expect(wvm_node_runtime_profile_decode(
                   bytes, encoded_bytes - 1U, &decoded, error,
                   sizeof(error)) != 0,
               "reject a truncated canonical record")) {
        goto out;
    }
    rc = 0;
out:
    wvm_node_runtime_profile_destroy(&decoded);
    free(bytes);
    if (rc == 0) {
        puts("runtime-profile-record tests: PASS");
    } else if (error[0]) {
        fprintf(stderr, "runtime-profile-record test detail: %s\n", error);
    }
    return rc;
}

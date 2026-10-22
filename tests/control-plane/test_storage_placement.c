#include <stdio.h>
#include <string.h>

#include "wavevm_canonical.h"
#include "wavevm_manifest.h"

static int failures;

static void expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "storage-placement test: %s\n", message);
        failures++;
    }
}

static void fill_request(struct wvm_vm_request *request)
{
    memset(request, 0, sizeof(*request));
    request->api_version = WVM_CANONICAL_SCHEMA;
    memset(request->request_id, 0x11, sizeof(request->request_id));
    request->requested_vcpus = 2;
    request->requested_memory_bytes = 2u * 1024u * 1024u;
    request->execution_backend_policy = WVM_MANIFEST_BACKEND_POLICY_AUTO;
    request->accelerator_policy = WVM_MANIFEST_ACCELERATOR_DISABLED;
    request->placement_policy = WVM_MANIFEST_PLACEMENT_COMPACT;
    request->guest_topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
    request->consistency_policy.dirty_batch_size = 1;
    request->consistency_policy.handoff_commit_policy = 1;
    request->consistency_policy.subscriber_delivery_policy = 1;
    request->consistency_policy.max_commit_latency_ms = 10;
    memset(request->storage_device_plan.qemu_device_configuration_digest, 0x33,
           sizeof(request->storage_device_plan.qemu_device_configuration_digest));
    request->lifecycle_policy.start_policy = 1;
    request->lifecycle_policy.failure_policy = 1;
    request->lifecycle_policy.completion_query_horizon_ms = 1000;
    request->lifecycle_policy.route_retention_horizon_ms = 2000;
}

int main(void)
{
    struct wvm_vm_request request;
    struct wvm_vm_request decoded;
    struct wvm_storage_assignment assignment;
    struct wvm_storage_assignment decoded_assignment;
    struct wvm_storage_assignment ordered[2];
    uint8_t bytes[4096];
    size_t encoded = 0;
    char error[256] = {0};

    fill_request(&request);
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) == 0,
           "an empty storage plan remains a valid request");

    memset(&assignment, 0, sizeof(assignment));
    assignment.device_index = 3;
    assignment.backend_kind = 1;
    memset(assignment.device_contract_digest, 0x44, 32);
    request.storage_device_plan.assignments.entries = &assignment;
    request.storage_device_plan.assignments.count = 1;
    request.storage_device_plan.assignments.capacity = 1;
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) == 0,
           "accept a zero-node storage device contract");
    expect(wvm_storage_device_plan_validate(&request.storage_device_plan, error,
                                            sizeof(error)) != 0,
           "strict plan validation still rejects unresolved contracts");

    expect(wvm_vm_request_encode(&request, bytes, sizeof(bytes), &encoded, error,
                                 sizeof(error)) == 0,
           "encode a request carrying a device contract");
    memset(&decoded, 0, sizeof(decoded));
    decoded.storage_device_plan.assignments.entries = &decoded_assignment;
    decoded.storage_device_plan.assignments.capacity = 1;
    expect(wvm_vm_request_decode(bytes, encoded, &decoded, error,
                                 sizeof(error)) == 0,
           "decode a request carrying a device contract");
    expect(decoded.storage_device_plan.assignments.count == 1 &&
               decoded.storage_device_plan.assignments.entries[0].device_index ==
                   3 &&
               decoded.storage_device_plan.assignments.entries[0]
                       .storage_physical_node_id == 0 &&
               memcmp(decoded.storage_device_plan.assignments.entries[0]
                          .device_contract_digest,
                      assignment.device_contract_digest, 32) == 0,
           "round-trip device index and contract digest");
    expect(wvm_vm_request_validate(&decoded, error, sizeof(error)) == 0,
           "decoded request validates");

    memset(ordered, 0, sizeof(ordered));
    ordered[0].device_index = 4;
    ordered[0].backend_kind = 1;
    memset(ordered[0].device_contract_digest, 0x51, 32);
    ordered[1].device_index = 3;
    ordered[1].backend_kind = 1;
    memset(ordered[1].device_contract_digest, 0x52, 32);
    request.storage_device_plan.assignments.entries = ordered;
    request.storage_device_plan.assignments.count = 2;
    request.storage_device_plan.assignments.capacity = 2;
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) != 0,
           "reject unordered device contracts");

    ordered[0].device_index = 0;
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) == 0,
           "accept ordered device contracts");
    ordered[0].backend_kind = 0;
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) != 0,
           "reject a zero backend kind");
    ordered[0].backend_kind = 1;
    memset(ordered[0].device_contract_digest, 0, 32);
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) != 0,
           "reject a zero contract digest");

    memset(ordered[0].device_contract_digest, 0x51, 32);
    ordered[0].storage_physical_node_id = 17;
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) == 0,
           "a concrete node hint is still a valid request");

    /* R02: default local disk when digest set and assignments empty. */
    {
        struct wvm_storage_assignment slot;
        struct wvm_storage_device_plan plan;

        memset(&plan, 0, sizeof(plan));
        memset(&slot, 0, sizeof(slot));
        memset(plan.qemu_device_configuration_digest, 0x33, 32);
        plan.assignments.entries = &slot;
        plan.assignments.capacity = 1;
        expect(wvm_storage_device_plan_ensure_default_local(
                   &plan, error, sizeof(error)) == 0 &&
                   plan.assignments.count == 1 &&
                   plan.assignments.entries[0].device_index == 0 &&
                   plan.assignments.entries[0].backend_kind == 1 &&
                   plan.assignments.entries[0].storage_physical_node_id == 0 &&
                   memcmp(plan.assignments.entries[0].device_contract_digest,
                          plan.qemu_device_configuration_digest, 32) == 0,
               "R02 synthesize default local disk from qemu digest");
        expect(wvm_storage_device_plan_ensure_default_local(
                   &plan, error, sizeof(error)) == 0 &&
                   plan.assignments.count == 1,
               "R02 ensure_default is idempotent when assignments exist");
        memset(&plan, 0, sizeof(plan));
        plan.assignments.entries = &slot;
        plan.assignments.capacity = 1;
        expect(wvm_storage_device_plan_ensure_default_local(
                   &plan, error, sizeof(error)) == 0 &&
                   plan.assignments.count == 0,
               "R02 zero digest stays diskless");
    }

    if (failures != 0) {
        fprintf(stderr, "storage-placement tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("storage-placement tests: PASS");
    return 0;
}

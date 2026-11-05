/*
 * Q01 directed: Minimum refuses a second WaveVM block device_index because
 * wavevm_block_chunk_store is identity+LBA only (no device→backend map).
 */
#include <stdio.h>
#include <string.h>

#include "wavevm_canonical.h"
#include "wavevm_manifest.h"

static int failures;

static void expect(int ok, const char *msg)
{
    if (!ok) {
        fprintf(stderr, "Q01 FAIL: %s\n", msg);
        failures++;
    }
}

int main(void)
{
    struct wvm_storage_assignment slots[2];
    struct wvm_storage_device_plan plan;
    struct wvm_vm_request request;
    char error[256] = {0};

    memset(&plan, 0, sizeof(plan));
    memset(slots, 0, sizeof(slots));
    memset(plan.qemu_device_configuration_digest, 0x41, 32);
    plan.assignments.entries = slots;
    plan.assignments.capacity = 2;

    slots[0].device_index = 0;
    slots[0].backend_kind = 1;
    memset(slots[0].device_contract_digest, 0x42, 32);
    plan.assignments.count = 1;
    expect(wvm_storage_device_plan_validate(&plan, error, sizeof(error)) != 0,
           "strict validate still needs resolved storage node");
    /* Request-path validate (allow_template) via vm_request. */
    memset(&request, 0, sizeof(request));
    request.api_version = WVM_CANONICAL_SCHEMA;
    memset(request.request_id, 0x11, sizeof(request.request_id));
    request.requested_vcpus = 1;
    request.requested_memory_bytes = 1024u * 1024u;
    request.execution_backend_policy = WVM_MANIFEST_BACKEND_POLICY_AUTO;
    request.accelerator_policy = WVM_MANIFEST_ACCELERATOR_DISABLED;
    request.placement_policy = WVM_MANIFEST_PLACEMENT_COMPACT;
    request.guest_topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
    request.consistency_policy.dirty_batch_size = 1;
    request.consistency_policy.handoff_commit_policy = 1;
    request.consistency_policy.subscriber_delivery_policy = 1;
    request.consistency_policy.max_commit_latency_ms = 10;
    memcpy(request.storage_device_plan.qemu_device_configuration_digest,
           plan.qemu_device_configuration_digest, 32);
    request.lifecycle_policy.start_policy = 1;
    request.lifecycle_policy.failure_policy = 1;
    request.lifecycle_policy.completion_query_horizon_ms = 1000;
    request.lifecycle_policy.route_retention_horizon_ms = 2000;
    request.storage_device_plan.assignments.entries = slots;
    request.storage_device_plan.assignments.count = 1;
    request.storage_device_plan.assignments.capacity = 2;
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) == 0,
           "single device_index request validates");

    slots[1].device_index = 1;
    slots[1].backend_kind = 1;
    memset(slots[1].device_contract_digest, 0x43, 32);
    request.storage_device_plan.assignments.count = 2;
    error[0] = '\0';
    expect(wvm_vm_request_validate(&request, error, sizeof(error)) != 0,
           "second device_index is refused");
    expect(strstr(error, "at most one WaveVM block device") != NULL,
           "error names the Minimum single-device bound");
    error[0] = '\0';
    expect(wvm_storage_device_plan_validate(
               &request.storage_device_plan, error, sizeof(error)) != 0 &&
               strstr(error, "at most one WaveVM block device") != NULL,
           "strict plan validate also refuses multi-disk");

    if (failures) {
        fprintf(stderr, "Q01 single-device-index: %d failure(s)\n", failures);
        return 1;
    }
    puts("Q01 single-device-index: PASS");
    return 0;
}

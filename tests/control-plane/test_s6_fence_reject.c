/*
 * remote_mem depth: memory_fence_result must be SUCCEEDED to encode a typed
 * VCPU_RUN handoff. Non-SUCCEEDED fence is rejected (no false production path).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_vcpu_handoff.h"
#include "wavevm_x86_context.h"
#include "wavevm_protocol.h"
#include "wavevm_envelope.h"

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "s6-fence-reject: %s\n", msg);
        return -1;
    }
    return 0;
}

int main(void)
{
    wvm_tcg_context_t legacy;
    uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES + sizeof(legacy)];
    uint8_t payload[WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES + sizeof(context)];
    size_t context_bytes = 0, payload_bytes = 0;
    struct wvm_vcpu_handoff_request request;
    char error[160];

    memset(&legacy, 0, sizeof(legacy));
    legacy.eip = 1;
    if (wvm_x86_context_encode(
            WVM_VCPU_BACKEND_TCG,
            WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
            &legacy, sizeof(legacy), context, sizeof(context), &context_bytes,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "context: %s\n", error);
        return 1;
    }

    memset(&request, 0, sizeof(request));
    request.protocol_version = WVM_VCPU_HANDOFF_REQUEST_VERSION;
    request.backend = WVM_VCPU_BACKEND_TCG;
    request.context_schema_version = WVM_VCPU_CONTEXT_SCHEMA_X86;
    request.memory_fence_result = 0; /* not SUCCEEDED */
    request.vm_id = 1;
    request.vm_incarnation = 1;
    request.manifest_generation = 1;
    request.origin_physical_node_id = 1;
    request.origin_runtime_instance_id = 1;
    request.vcpu_index = 0;
    request.destination_executor_id = 1;
    request.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE;
    request.reply_destination_scope = 0;
    request.reply_destination_vnode = 2;
    request.handoff_sequence = 1;
    request.memory_fence_id = 99;
    request.operation_id[15] = 1;
    request.context_valid_fields =
        WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
        WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE;
    request.context = context;
    request.context_bytes = context_bytes;

    if (expect(wvm_vcpu_handoff_request_encode(
                   &request, payload, sizeof(payload), &payload_bytes, error,
                   sizeof(error)) != 0,
               "reject encode when fence_result != SUCCEEDED") != 0)
        return 1;

    request.memory_fence_result = WVM_VCPU_MEMORY_FENCE_SUCCEEDED;
    if (expect(wvm_vcpu_handoff_request_encode(
                   &request, payload, sizeof(payload), &payload_bytes, error,
                   sizeof(error)) == 0,
               "accept encode when fence_result == SUCCEEDED") != 0)
        return 1;
    if (expect(payload_bytes > WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES,
               "encoded payload includes context") != 0)
        return 1;

    puts("s6 fence/version gate: PASS");
    printf("  fence_reject_nonzero_required=1 fence_id=%llu encoded_bytes=%zu\n",
           (unsigned long long)request.memory_fence_id, payload_bytes);
    return 0;
}

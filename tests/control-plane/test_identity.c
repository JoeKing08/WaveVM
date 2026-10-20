#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_identity.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "identity test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_vm_namespace_record records[4];
    struct wvm_vm_namespace_allocator allocator;
    struct wvm_local_name_identity identity;
    struct wvm_local_name_namespace namespaces[2];
    uint8_t retirement_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t vm_id;
    uint64_t incarnation;
    char error[256] = {0};

    memset(retirement_digest, 0xab, sizeof(retirement_digest));
    wvm_vm_namespace_allocator_init(&allocator, records,
                                    sizeof(records) / sizeof(records[0]), 7);
    if (expect(wvm_vm_namespace_allocate(&allocator,
                                         WVM_NAMESPACE_ABI_LEGACY, &vm_id,
                                         &incarnation, error,
                                         sizeof(error)) == 0,
               "allocate legacy namespace") ||
        expect(vm_id == 1 && incarnation == 1, "first legacy identity") ||
        expect(wvm_vm_namespace_activate(&allocator, vm_id, incarnation,
                                         error, sizeof(error)) == 0,
               "activate namespace") ||
        expect(wvm_vm_namespace_begin_retire(&allocator, vm_id, incarnation,
                                             error, sizeof(error)) == 0,
               "begin retirement") ||
        expect(wvm_vm_namespace_quarantine(&allocator, vm_id, incarnation,
                                            retirement_digest, 0, error,
                                            sizeof(error)) != 0,
               "reject incomplete retirement") ||
        expect(wvm_vm_namespace_quarantine(&allocator, vm_id, incarnation,
                                            retirement_digest, 1, error,
                                            sizeof(error)) == 0,
               "quarantine namespace") ||
        expect(wvm_vm_namespace_release(&allocator, vm_id, incarnation, error,
                                         sizeof(error)) == 0,
               "release namespace")) {
        return 1;
    }

    if (expect(wvm_vm_namespace_allocate(&allocator,
                                         WVM_NAMESPACE_ABI_LEGACY, &vm_id,
                                         &incarnation, error,
                                         sizeof(error)) == 0,
               "allocate second legacy namespace") ||
        expect(vm_id == 2, "legacy identity cannot be reused in epoch") ||
        expect(incarnation == 1, "new legacy namespace first incarnation")) {
        return 1;
    }

    if (expect(wvm_vm_namespace_allocate(&allocator, WVM_NAMESPACE_ABI_U32,
                                         &vm_id, &incarnation, error,
                                         sizeof(error)) == 0,
               "allocate V1 namespace") ||
        expect(vm_id == 256 && incarnation == 1, "first V1 identity >255")) {
        return 1;
    }

    /* V1 u32 quarantine: reuse only after retirement ACK (BASE-§16). */
    if (expect(wvm_vm_namespace_activate(&allocator, vm_id, incarnation, error,
                                         sizeof(error)) == 0,
               "activate V1 namespace") ||
        expect(wvm_vm_namespace_begin_retire(&allocator, vm_id, incarnation,
                                             error, sizeof(error)) == 0,
               "begin V1 retirement") ||
        expect(wvm_vm_namespace_quarantine(&allocator, vm_id, incarnation,
                                            retirement_digest, 0, error,
                                            sizeof(error)) != 0,
               "reject incomplete V1 retirement ACK") ||
        expect(wvm_vm_namespace_quarantine(&allocator, vm_id, incarnation,
                                            retirement_digest, 1, error,
                                            sizeof(error)) == 0,
               "quarantine V1 namespace after retirement ready") ||
        expect(wvm_vm_namespace_release(&allocator, vm_id, incarnation, error,
                                         sizeof(error)) == 0,
               "release quarantined V1 namespace")) {
        return 1;
    }

    /* Restore range gate: LEGACY cannot hold >255; U32 cannot hold <256. */
    if (expect(wvm_vm_namespace_restore(&allocator, WVM_NAMESPACE_ABI_LEGACY,
                                         300, 1, WVM_VM_NAMESPACE_ALLOCATED,
                                         error, sizeof(error)) != 0,
               "reject legacy restore of vm_id>255") ||
        expect(wvm_vm_namespace_restore(&allocator, WVM_NAMESPACE_ABI_U32, 42,
                                         1, WVM_VM_NAMESPACE_ALLOCATED, error,
                                         sizeof(error)) != 0,
               "reject U32 restore of vm_id<256") ||
        expect(wvm_vm_namespace_restore(&allocator, WVM_NAMESPACE_ABI_U32, 300,
                                         1, WVM_VM_NAMESPACE_ALLOCATED, error,
                                         sizeof(error)) == 0,
               "accept U32 restore of vm_id>255")) {
        return 1;
    }

    /* Fresh V1 allocation after quarantine still yields >255. */
    if (expect(wvm_vm_namespace_allocate(&allocator, WVM_NAMESPACE_ABI_U32,
                                         &vm_id, &incarnation, error,
                                         sizeof(error)) == 0,
               "allocate post-quarantine V1 namespace") ||
        expect(vm_id >= 256, "post-quarantine V1 id remains >255")) {
        return 1;
    }

    memset(&identity, 0, sizeof(identity));
    identity.vm_id = vm_id;
    identity.vm_incarnation = incarnation;
    identity.manifest_generation = 1;
    identity.physical_node_id = 17;
    memset(identity.manifest_id, 0xcd, sizeof(identity.manifest_id));
    memset(identity.admission_tx_id, 0xdc, sizeof(identity.admission_tx_id));
    if (expect(wvm_local_name_namespace_derive(&identity, &namespaces[0],
                                                error, sizeof(error)) == 0,
               "derive first local namespace") ||
        expect(wvm_local_name_namespace_derive(&identity, &namespaces[1],
                                                error, sizeof(error)) == 0,
               "derive repeated namespace") ||
        expect(strcmp(namespaces[0].namespace_name,
                      namespaces[1].namespace_name) == 0,
               "same identity has same namespace") ||
        expect(wvm_local_name_namespace_validate_unique(namespaces, 2, error,
                                                         sizeof(error)) != 0,
               "reject duplicate local namespace")) {
        return 1;
    }

    identity.physical_node_id = 99;
    if (expect(wvm_local_name_namespace_derive(&identity, &namespaces[1],
                                                error, sizeof(error)) == 0,
               "derive remote node namespace") ||
        expect(wvm_local_name_namespace_validate_unique(namespaces, 2, error,
                                                         sizeof(error)) == 0,
               "accept distinct local namespaces")) {
        return 1;
    }

    puts("identity tests: PASS");
    return 0;
}

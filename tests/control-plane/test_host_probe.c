#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wavevm_host_probe.h"

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "host-probe test: %s\n", msg);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_host_probe_result probe;
    struct wvm_capability_record records[8];
    size_t record_count = 0;
    char error[256] = {0};
    int saw_tcg = 0;
    int saw_mode_b = 0;
    int saw_vm_id = 0;
    size_t i;

    memset(&probe, 0, sizeof(probe));
    if (expect(wvm_host_probe_run(&probe, error, sizeof(error)) == 0,
               error[0] ? error : "probe run failed") != 0) {
        return 1;
    }
    if (expect(probe.tcg_state == WVM_CAPABILITY_AVAILABLE,
               "TCG must be AVAILABLE after restricted SIGSEGV probe") != 0 ||
        expect((probe.tcg_feature_bits &
                WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT) != 0,
               "TCG feature bits must include SIGSEGV/mprotect") != 0 ||
        expect((probe.tcg_feature_bits & WVM_HOST_PROBE_TCG_USERFAULTFD) == 0,
               "must not advertise unimplemented UFFD bit") != 0 ||
        expect(probe.observed_at_ms != 0, "probe timestamp required") != 0) {
        return 1;
    }

    /* KVM dirty/resync: when AVAILABLE, dirty-log bit must be set. */
    if (probe.kvm_state == WVM_CAPABILITY_AVAILABLE) {
        if (expect((probe.kvm_feature_bits & WVM_HOST_PROBE_KVM_API) != 0,
                   "KVM AVAILABLE requires API bit") != 0 ||
            expect((probe.kvm_feature_bits & WVM_HOST_PROBE_KVM_CREATE_VM) != 0,
                   "KVM AVAILABLE requires CREATE_VM bit") != 0 ||
            expect((probe.kvm_feature_bits & WVM_HOST_PROBE_KVM_DIRTY_LOG) != 0,
                   "KVM AVAILABLE requires dirty-log bit") != 0) {
            return 1;
        }
    }

    if (expect(wvm_host_probe_fill_records(
                   &probe, 801, 802, 9001, records, 8, &record_count, error,
                   sizeof(error)) == 0,
               error[0] ? error : "fill records failed") != 0 ||
        expect(record_count >= 3, "at least TCG+ModeB+VmId records") != 0) {
        return 1;
    }
    for (i = 0; i < record_count; i++) {
        if (records[i].capability_id == WVM_CAPABILITY_ID_EXECUTION_TCG) {
            saw_tcg = 1;
            if (expect(records[i].state == WVM_CAPABILITY_AVAILABLE,
                       "filled TCG record AVAILABLE") != 0 ||
                expect(records[i].probe_operation_id[0] != 0 ||
                           records[i].probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] !=
                               0,
                       "filled TCG record has probe_operation_id") != 0) {
                return 1;
            }
        }
        if (records[i].capability_id == WVM_CAPABILITY_ID_MODE_B_MEMORY) {
            saw_mode_b = 1;
            if (expect(records[i].state == WVM_CAPABILITY_AVAILABLE,
                       "MODE_B_MEMORY AVAILABLE only with SIGSEGV evidence") !=
                0) {
                return 1;
            }
        }
        if (records[i].capability_id == WVM_CAPABILITY_ID_VM_ID_U32) {
            saw_vm_id = 1;
        }
        if (records[i].capability_id == WVM_CAPABILITY_ID_EXECUTION_KVM) {
            if (expect(probe.kvm_state == WVM_CAPABILITY_AVAILABLE,
                       "KVM record only when probed AVAILABLE") != 0) {
                return 1;
            }
        }
    }
    if (expect(saw_tcg && saw_mode_b && saw_vm_id,
               "filled records missing baseline capabilities") != 0) {
        return 1;
    }

    printf("host-probe tests: PASS\n");

    /* §5: probe→profile selection — restricted TCG is production fallback. */
    {
        struct wvm_host_probe_execution_choice choice;
        char err[128];

        if (expect(wvm_host_probe_select_execution(
                       WVM_MANIFEST_BACKEND_POLICY_AUTO, 1, 1, 0, 0, &choice,
                       err, sizeof(err)) == 0,
                   "AUTO without KVM dirty selects TCG") != 0 ||
            expect(choice.backend == WVM_MANIFEST_BACKEND_TCG,
                   "AUTO incomplete KVM → TCG backend") != 0 ||
            expect(choice.fallback_decision == 2,
                   "fallback_decision=2 for AUTO KVM incomplete") != 0 ||
            expect(choice.read_fault_engine ==
                       WVM_FAULT_ENGINE_SIGSEGV_MPROTECT,
                   "no UFFD → SIGSEGV read engine") != 0 ||
            expect(choice.dirty_capture_engine ==
                       WVM_FAULT_ENGINE_SIGSEGV_MPROTECT,
                   "TCG dirty = SIGSEGV") != 0) {
            return 1;
        }
        if (expect(wvm_host_probe_select_execution(
                       WVM_MANIFEST_BACKEND_POLICY_AUTO, 1, 0, 0, 0, &choice,
                       err, sizeof(err)) == 0,
                   "AUTO without KVM selects restricted TCG") != 0 ||
            expect(choice.backend == WVM_MANIFEST_BACKEND_TCG,
                   "no KVM → TCG") != 0 ||
            expect(choice.fallback_decision == 3,
                   "fallback_decision=3 restricted SIGSEGV") != 0) {
            return 1;
        }
        if (expect(wvm_host_probe_select_execution(
                       WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM, 1, 1, 0, 0,
                       &choice, err, sizeof(err)) != 0,
                   "REQUIRE_KVM without dirty must fail-closed") != 0) {
            return 1;
        }
        if (expect(wvm_host_probe_select_execution(
                       WVM_MANIFEST_BACKEND_POLICY_AUTO, 1, 1, 1, 1, &choice,
                       err, sizeof(err)) == 0,
                   "AUTO complete KVM+dirty+UFFD") != 0 ||
            expect(choice.backend == WVM_MANIFEST_BACKEND_KVM,
                   "complete KVM selected") != 0 ||
            expect(choice.fallback_decision == 1, "primary selection") != 0 ||
            expect(choice.dirty_capture_engine ==
                       WVM_FAULT_ENGINE_KVM_DIRTY_LOG,
                   "KVM dirty engine") != 0) {
            return 1;
        }
        /* UFFD never selected — even when all_tcg_uffd is forced true. */
        if (expect(wvm_host_probe_select_execution(
                       WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG, 1, 0, 0, 0,
                       &choice, err, sizeof(err)) == 0,
                   "REQUIRE_TCG without UFFD") != 0 ||
            expect(choice.read_fault_engine != WVM_FAULT_ENGINE_USERFAULTFD,
                   "must not select unimplemented UFFD") != 0) {
            return 1;
        }
        if (expect(wvm_host_probe_select_execution(
                       WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG, 1, 0, 0, 1,
                       &choice, err, sizeof(err)) == 0,
                   "REQUIRE_TCG with all_tcg_uffd forced") != 0 ||
            expect(choice.read_fault_engine ==
                       WVM_FAULT_ENGINE_SIGSEGV_MPROTECT,
                   "forced uffd flag must still select SIGSEGV") != 0) {
            return 1;
        }
        printf("selection: AUTO dirty-miss→TCG(fb=2); no-KVM→TCG(fb=3); "
               "REQUIRE_KVM dirty-miss fail-closed; UFFD not advertised\n");
    }

    printf("NOTE: TCG SIGSEGV/mprotect restricted fallback probed; "
           "KVM state=%u bits=0x%llx; UFFD bit=%u; kernel_accel state=%u\n",
           (unsigned)probe.kvm_state,
           (unsigned long long)probe.kvm_feature_bits,
           (unsigned)((probe.tcg_feature_bits &
                       WVM_HOST_PROBE_TCG_USERFAULTFD) != 0),
           (unsigned)probe.kernel_accel_state);

    /* A10: probe records encode as a publishable CapabilityReport. */
    {
        uint8_t *bytes = NULL;
        size_t size = 0;
        struct wvm_capability_report decoded = {0};
        char err[256] = {0};

        if (expect(wvm_host_probe_encode_report(records, record_count, 42, &bytes,
                                                &size, err, sizeof(err)) == 0,
                   err[0] ? err : "encode_report failed") != 0) {
            return 1;
        }
        if (expect(size > 0 && bytes != NULL, "report bytes nonempty") != 0 ||
            expect(wvm_capability_report_decode(bytes, size, &decoded, err,
                                                sizeof(err)) == 0,
                   err[0] ? err : "decode report failed") != 0 ||
            expect(decoded.profile_generation == 42,
                   "report profile_generation preserved") != 0 ||
            expect(decoded.record_count == record_count,
                   "report record_count preserved") != 0) {
            free(bytes);
            wvm_capability_report_destroy(&decoded);
            return 1;
        }
        free(bytes);
        wvm_capability_report_destroy(&decoded);
        printf("encode_report→decode CapabilityReport: PASS\n");
    }
    return 0;
}

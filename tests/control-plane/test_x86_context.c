#include <stdio.h>
#include <string.h>

#include "wavevm_protocol.h"
#include "wavevm_x86_context.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "x86 context test: %s\n", message);
        return -1;
    }
    return 0;
}

static int check_round_trip(uint16_t backend, const void *source,
                            size_t source_bytes, uint64_t valid_fields,
                            uint8_t *encoded, size_t encoded_capacity)
{
    uint8_t restored[WVM_X86_CONTEXT_MAX_NATIVE_BYTES];
    uint8_t reencoded[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                      WVM_X86_CONTEXT_MAX_NATIVE_BYTES];
    size_t encoded_bytes = 0;
    size_t reencoded_bytes = 0;
    uint64_t decoded_fields = 0;
    char error[256] = {0};

    memset(restored, 0, sizeof(restored));
    if (expect(wvm_x86_context_encode(
                      backend, valid_fields, source, source_bytes, encoded,
                      encoded_capacity, &encoded_bytes, error,
                      sizeof(error)) == 0,
                  "encode context") ||
        expect(wvm_x86_context_decode(
                              backend, encoded, encoded_bytes, &decoded_fields,
                              restored, sizeof(restored), error,
                              sizeof(error)) == 0 &&
                              decoded_fields == valid_fields,
                          "decode context fields") ||
        expect(wvm_x86_context_encode(
                   backend, valid_fields, restored, source_bytes, reencoded,
                   sizeof(reencoded), &reencoded_bytes, error,
                   sizeof(error)) == 0 && reencoded_bytes == encoded_bytes &&
                   memcmp(encoded, reencoded, encoded_bytes) == 0 &&
                   encoded_bytes < WVM_X86_CONTEXT_WIRE_HEADER_BYTES + source_bytes,
               "canonical round trip excludes native padding")) {
        return -1;
    }
    if (backend == WVM_VCPU_BACKEND_KVM) {
        wvm_kvm_context_t copy;
        const wvm_kvm_context_t *original = source;

        memcpy(&copy, restored, sizeof(copy));
        return expect(copy.rip == original->rip &&
                          copy.tsc_deadline == original->tsc_deadline &&
                          copy.mp_state == original->mp_state &&
                          copy.io.port == original->io.port &&
                          copy.gs_base == original->gs_base &&
                          copy.cpuid_count == original->cpuid_count &&
                          copy.debug_address[0] == original->debug_address[0] &&
                          copy.debug_status == original->debug_status &&
                          copy.debug_control == original->debug_control &&
                          copy.debug_valid == original->debug_valid &&
                          copy.sysenter_cs == original->sysenter_cs &&
                          copy.sysenter_esp == original->sysenter_esp &&
                          copy.sysenter_eip == original->sysenter_eip &&
                          copy.pat == original->pat &&
                          copy.system_msrs_valid == original->system_msrs_valid &&
                          copy.profile_msr_count == original->profile_msr_count &&
                          copy.profile_msrs[1].index == original->profile_msrs[1].index &&
                          copy.profile_msrs[1].value == original->profile_msrs[1].value &&
                          memcmp(copy.cpuid, original->cpuid,
                                 sizeof(copy.cpuid)) == 0 &&
                          copy._pad0 == 0 && copy._pad5 == 0 &&
                          memcmp(copy.lapic_data, original->lapic_data,
                                 sizeof(copy.lapic_data)) == 0,
                      "KVM architectural values survive, padding is zero");
    } else {
        wvm_tcg_context_t copy;
        const wvm_tcg_context_t *original = source;

        memcpy(&copy, restored, sizeof(copy));
        return expect(copy.eip == original->eip &&
                          copy.lapic.timer_expiry == original->lapic.timer_expiry &&
                          copy.exception_nr == original->exception_nr &&
                          copy.mtrr_var[7].mask == original->mtrr_var[7].mask &&
                          copy.segs[1].flags == original->segs[1].flags &&
                          copy._pad0 == 0 && copy.segs[1]._pad == 0 &&
                          memcmp(copy.xsave_area, original->xsave_area,
                                 sizeof(copy.xsave_area)) == 0,
                      "TCG architectural values survive, padding is zero");
    }
}

int main(void)
{
    wvm_kvm_context_t kvm_context;
    wvm_tcg_context_t tcg_context;
    uint8_t encoded[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                    WVM_X86_CONTEXT_MAX_NATIVE_BYTES];
    size_t encoded_bytes = 0;
    uint64_t fields = WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                      WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE |
                      WVM_VCPU_CONTEXT_FIELD_TIMER_STATE |
                      WVM_VCPU_CONTEXT_FIELD_DEVICE_RESUME;
    uint64_t decoded_fields = 0;
    char error[256] = {0};

    memset(&kvm_context, 0xa5, sizeof(kvm_context));
    memset(&tcg_context, 0x5a, sizeof(tcg_context));
    kvm_context.rip = UINT64_C(0x0123456789abcdef);
    kvm_context.tsc_deadline = UINT64_C(0xfedcba9876543210);
    kvm_context.cpuid_count = 2;
    kvm_context.cpuid[1].function = 1;
    kvm_context.cpuid[1].eax = 0x663;
    kvm_context.profile_msr_count = 2;
    kvm_context.profile_msrs[1].index = 0xc0000103;
    kvm_context.profile_msrs[1].value = UINT64_C(0x12345678abcdef00);
    tcg_context.eip = UINT64_C(0x1122334455667788);
    tcg_context.lapic.timer_expiry = -123456789;

    if (check_round_trip(WVM_VCPU_BACKEND_KVM, &kvm_context,
                         sizeof(kvm_context), fields, encoded,
                         sizeof(encoded)) != 0 ||
        check_round_trip(WVM_VCPU_BACKEND_TCG, &tcg_context,
                         sizeof(tcg_context), fields, encoded,
                         sizeof(encoded)) != 0) {
        return 1;
    }
    {
        const uint8_t eip_be[] = {0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0x77, 0x88};
        if (expect(memcmp(encoded + WVM_X86_CONTEXT_WIRE_HEADER_BYTES + 16 * 8,
                          eip_be, sizeof(eip_be)) == 0,
                   "wire scalar is explicitly big endian")) {
            return 1;
        }
    }

    if (expect(wvm_x86_context_encode(
                   WVM_VCPU_BACKEND_KVM,
                   WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE, &kvm_context,
                   sizeof(kvm_context), encoded, sizeof(encoded),
                   &encoded_bytes, error, sizeof(error)) != 0,
               "reject context without architectural state") ||
        expect(wvm_x86_context_encode(
                   WVM_VCPU_BACKEND_TCG, fields, &tcg_context,
                   sizeof(tcg_context) - 1, encoded, sizeof(encoded),
                   &encoded_bytes, error, sizeof(error)) != 0,
               "reject truncated legacy container") ||
        expect(wvm_x86_context_encode(
                   WVM_VCPU_BACKEND_TCG, fields, &tcg_context,
                   sizeof(tcg_context), encoded, sizeof(encoded),
                   &encoded_bytes, error, sizeof(error)) == 0,
               "encode TCG context for negative checks")) {
        return 1;
    }

    if (expect(wvm_x86_context_decode(
                   WVM_VCPU_BACKEND_KVM, encoded, encoded_bytes,
                   &decoded_fields, &kvm_context, sizeof(kvm_context), error,
                   sizeof(error)) != 0,
               "reject backend profile mismatch")) {
        return 1;
    }
    encoded[WVM_X86_CONTEXT_WIRE_HEADER_BYTES - 1] = 1;
    if (expect(wvm_x86_context_decode(
                   WVM_VCPU_BACKEND_TCG, encoded, encoded_bytes,
                   &decoded_fields, &tcg_context, sizeof(tcg_context), error,
                   sizeof(error)) != 0,
               "reject nonzero reserved context bytes")) {
        return 1;
    }

    puts("x86 context tests: PASS");
    return 0;
}

#include "wavevm_x86_context.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_protocol.h"

enum {
    CONTEXT_MAGIC_OFFSET = 0,
    CONTEXT_SCHEMA_OFFSET = 4,
    CONTEXT_BACKEND_OFFSET = 6,
    CONTEXT_FIELDS_OFFSET = 8,
    CONTEXT_BODY_BYTES_OFFSET = 16,
    CONTEXT_RESERVED_OFFSET = 20,
};

struct context_field {
    size_t offset;
    uint16_t count;
    uint16_t stride;
    uint8_t bytes;
};

/* Table order is the wire schema. Offsets/strides describe local adapters only;
 * no C padding or sizeof(struct) is used to determine the network body. */
#define FIELD(type, member, width, elements) \
    { offsetof(type, member), elements, width, width }
#define K(member, width) FIELD(wvm_kvm_context_t, member, width, 1)
#define T(member, width) FIELD(wvm_tcg_context_t, member, width, 1)
#define TA(member, width, count) FIELD(wvm_tcg_context_t, member, width, count)
#define UAPI(blob, type, member, width, count) \
    { offsetof(wvm_kvm_context_t, blob) + offsetof(type, member), \
      count, width, width }
#define SEG(member) \
    UAPI(sregs_data, struct kvm_sregs, member.base, 8, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.limit, 4, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.selector, 2, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.type, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.present, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.dpl, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.db, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.s, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.l, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.g, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.avl, 1, 1), \
    UAPI(sregs_data, struct kvm_sregs, member.unusable, 1, 1)
#define SR(member, width, count) \
    UAPI(sregs_data, struct kvm_sregs, member, width, count)
#define EV(member, width) \
    UAPI(vcpu_events_data, struct kvm_vcpu_events, member, width, 1)
#define FP(member, width, count) \
    UAPI(fpu_data, struct kvm_fpu, member, width, count)
#define CP(member) \
    { offsetof(wvm_kvm_context_t, cpuid[0].member), \
      WVM_KVM_MAX_CPUID_ENTRIES, sizeof(wvm_kvm_cpuid_entry_t), 4 }

static const struct context_field kvm_fields[] = {
    K(rax, 8), K(rbx, 8), K(rcx, 8), K(rdx, 8), K(rsi, 8), K(rdi, 8),
    K(rsp, 8), K(rbp, 8), K(r8, 8), K(r9, 8), K(r10, 8), K(r11, 8),
    K(r12, 8), K(r13, 8), K(r14, 8), K(r15, 8), K(rip, 8), K(rflags, 8),
    SEG(cs), SEG(ds), SEG(es), SEG(fs), SEG(gs), SEG(ss), SEG(tr), SEG(ldt),
    SR(gdt.base, 8, 1), SR(gdt.limit, 2, 1),
    SR(idt.base, 8, 1), SR(idt.limit, 2, 1),
    SR(cr0, 8, 1), SR(cr2, 8, 1), SR(cr3, 8, 1), SR(cr4, 8, 1),
    SR(cr8, 8, 1), SR(efer, 8, 1), SR(apic_base, 8, 1),
    SR(interrupt_bitmap, 8, 4),
    K(tsc_value, 8), K(tsc_deadline, 8), K(kernel_gs_base, 8), K(tsc_valid, 4),
    /* LAPIC and x87/XMM register bytes have an explicit x86 image layout. */
    UAPI(lapic_data, struct kvm_lapic_state, regs, 1, 1024), K(lapic_valid, 4),
    EV(exception.injected, 1), EV(exception.nr, 1),
    EV(exception.has_error_code, 1), EV(exception.pending, 1),
    EV(exception.error_code, 4), EV(interrupt.injected, 1), EV(interrupt.nr, 1),
    EV(interrupt.soft, 1), EV(interrupt.shadow, 1), EV(nmi.injected, 1),
    EV(nmi.pending, 1), EV(nmi.masked, 1), EV(sipi_vector, 4), EV(flags, 4),
    EV(smi.smm, 1), EV(smi.pending, 1), EV(smi.smm_inside_nmi, 1),
    EV(smi.latched_init, 1),
    /* KVM added triple_fault.pending at the first former reserved byte.
     * Adapt either installed UAPI header to the same explicit one-byte field. */
    { offsetof(wvm_kvm_context_t, vcpu_events_data) +
      offsetof(struct kvm_vcpu_events, smi) + 4, 1, 1, 1 },
    EV(exception_has_payload, 1), EV(exception_payload, 8),
    K(vcpu_events_valid, 4),
    FP(fpr, 1, 128), FP(fcw, 2, 1), FP(fsw, 2, 1), FP(ftwx, 1, 1),
    FP(last_opcode, 2, 1), FP(last_ip, 8, 1), FP(last_dp, 8, 1),
    FP(xmm, 1, 256), FP(mxcsr, 4, 1), K(fpu_valid, 4),
    UAPI(xcrs_data, struct kvm_xcrs, nr_xcrs, 4, 1),
    UAPI(xcrs_data, struct kvm_xcrs, flags, 4, 1),
    { offsetof(wvm_kvm_context_t, xcrs_data) +
      offsetof(struct kvm_xcrs, xcrs[0].xcr), 16, sizeof(struct kvm_xcr), 4 },
    { offsetof(wvm_kvm_context_t, xcrs_data) +
      offsetof(struct kvm_xcrs, xcrs[0].value), 16, sizeof(struct kvm_xcr), 8 },
    K(xcrs_valid, 4), K(mp_state, 4), K(mp_state_valid, 4), K(exit_reason, 4),
    K(io.direction, 1), K(io.size, 1), K(io.port, 2), K(io.count, 4),
    FIELD(wvm_kvm_context_t, io.data, 1, 8),
    K(mmio.phys_addr, 8), K(mmio.len, 4), K(mmio.is_write, 1),
    FIELD(wvm_kvm_context_t, mmio.data, 1, 8),
    K(gs_base, 8), K(apic_base, 8), K(star, 8), K(lstar, 8), K(cstar, 8),
    K(sfmask, 8), K(msr_ext_valid, 4),
    K(cpuid_count, 4), CP(function), CP(index), CP(flags), CP(eax), CP(ebx),
    CP(ecx), CP(edx),
    FIELD(wvm_kvm_context_t, debug_address, 8, 4),
    K(debug_status, 8), K(debug_control, 8), K(debug_valid, 4),
    K(sysenter_cs, 8), K(sysenter_esp, 8), K(sysenter_eip, 8), K(pat, 8),
    K(system_msrs_valid, 4),
    K(profile_msr_count, 4),
    { offsetof(wvm_kvm_context_t, profile_msrs[0].index),
      WVM_KVM_MAX_PROFILE_MSRS, sizeof(wvm_kvm_msr_entry_t), 4 },
    { offsetof(wvm_kvm_context_t, profile_msrs[0].value),
      WVM_KVM_MAX_PROFILE_MSRS, sizeof(wvm_kvm_msr_entry_t), 8 },
};
#undef CP

#define TSEG(member) \
    T(member.base, 8), T(member.limit, 4), T(member.selector, 4), T(member.flags, 4)
static const struct context_field tcg_fields[] = {
    TA(regs, 8, 16), T(eip, 8), T(eflags, 8), TA(cr, 8, 5),
    TA(xmm_regs, 8, 32), T(mxcsr, 4), T(exit_reason, 4), T(halted, 4),
    T(interrupt_request, 4), T(fs_base, 8), T(gs_base, 8), T(gdt_base, 8),
    T(gdt_limit, 8), T(idt_base, 8), T(idt_limit, 8),
    TSEG(segs[0]), TSEG(segs[1]), TSEG(segs[2]), TSEG(segs[3]),
    TSEG(segs[4]), TSEG(segs[5]), TSEG(ldt), TSEG(tr),
    T(efer, 8), T(star, 8), T(lstar, 8), T(cstar, 8), T(fmask, 8),
    T(kernelgsbase, 8), T(sysenter_esp, 8), T(sysenter_eip, 8), T(pat, 8),
    T(sysenter_cs, 4), T(hflags, 4), T(hflags2, 4), T(a20_mask, 4),
    T(mp_state, 4), TA(dr, 8, 8), T(vm_hsave, 8), T(vm_vmcb, 8),
    T(intercept, 8), T(nested_cr3, 8), T(tsc_offset, 8),
    TA(mtrr_fixed, 8, 11), T(mtrr_deftype, 8),
    { offsetof(wvm_tcg_context_t, mtrr_var[0].base),
      8, sizeof(wvm_tcg_mtrr_var_t), 8 },
    { offsetof(wvm_tcg_context_t, mtrr_var[0].mask),
      8, sizeof(wvm_tcg_mtrr_var_t), 8 },
    T(system_time_msr, 8), T(wall_clock_msr, 8), T(steal_time_msr, 8),
    T(async_pf_en_msr, 8), T(async_pf_int_msr, 8), T(pv_eoi_en_msr, 8),
    T(poll_control_msr, 8), T(msr_bndcfgs, 8), T(exception_payload, 8),
    T(nested_pg_mode, 4), T(interrupt_injected, 4), T(exception_nr, 4),
    T(ins_len, 4), T(sipi_vector, 4), T(intercept_exceptions, 4),
    T(intercept_cr_read, 2), T(intercept_cr_write, 2),
    T(intercept_dr_read, 2), T(intercept_dr_write, 2), T(v_tpr, 1),
    T(soft_interrupt, 1), T(nmi_injected, 1), T(nmi_pending, 1),
    T(has_error_code, 1), T(exception_pending, 1), T(exception_injected, 1),
    T(exception_has_payload, 1), T(old_exception, 4), T(smbase, 8),
    T(tsc, 8), T(tsc_adjust, 8), T(tsc_deadline, 8), T(tsc_aux, 8), T(xcr0, 8),
    T(msr_ia32_misc_enable, 8), T(msr_ia32_feature_control, 8),
    T(spec_ctrl, 8), T(virt_ssbd, 8), T(exception_next_eip, 8),
    T(pkru, 4), T(tsx_ctrl, 4), T(df, 4), T(error_code, 4),
    T(exception_is_int, 4), T(lapic.valid, 4), T(lapic.apicbase, 4),
    T(lapic.initial_apic_id, 4), T(lapic.spurious_vec, 4),
    TA(lapic.isr, 4, 8), TA(lapic.tmr, 4, 8), TA(lapic.irr, 4, 8),
    TA(lapic.lvt, 4, 6), T(lapic.esr, 4), TA(lapic.icr, 4, 2),
    T(lapic.divide_conf, 4), T(lapic.initial_count, 4), T(lapic.count_shift, 4),
    T(lapic.initial_count_load_time, 8), T(lapic.next_time, 8),
    T(lapic.timer_expiry, 8), T(lapic.sipi_vector, 4), T(lapic.wait_for_sipi, 4),
    T(lapic.id, 1), T(lapic.arb_id, 1), T(lapic.tpr, 1), T(lapic.log_dest, 1),
    T(lapic.dest_mode, 1), T(lapic.version, 1), T(xsave_size, 4),
    T(slice_budget_us, 4), TA(xsave_area, 1, 0xb00),
};
#undef TSEG
#undef FP
#undef EV
#undef SR
#undef SEG
#undef UAPI
#undef TA
#undef T
#undef K
#undef FIELD

static const struct context_field *context_fields(uint16_t backend,
                                                  size_t *count)
{
    if (backend == WVM_VCPU_BACKEND_KVM) {
        *count = sizeof(kvm_fields) / sizeof(kvm_fields[0]);
        return kvm_fields;
    }
    if (backend == WVM_VCPU_BACKEND_TCG) {
        *count = sizeof(tcg_fields) / sizeof(tcg_fields[0]);
        return tcg_fields;
    }
    *count = 0;
    return NULL;
}

static size_t context_body_bytes(uint16_t backend)
{
    size_t count, bytes = 0;
    const struct context_field *fields = context_fields(backend, &count);

    for (size_t i = 0; i < count; i++) {
        bytes += (size_t)fields[i].bytes * fields[i].count;
    }
    return bytes;
}

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_be64(uint8_t *bytes, uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        bytes[7U - i] = (uint8_t)(value >> (i * 8U));
    }
}

static uint16_t read_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t read_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static int all_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int fields_valid(uint64_t valid_fields)
{
    return (valid_fields & WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE) != 0 &&
           (valid_fields & ~WVM_VCPU_CONTEXT_KNOWN_FIELDS) == 0;
}

size_t wvm_x86_context_legacy_bytes(uint16_t backend)
{
    switch (backend) {
    case WVM_VCPU_BACKEND_KVM:
        return sizeof(wvm_kvm_context_t);
    case WVM_VCPU_BACKEND_TCG:
        return sizeof(wvm_tcg_context_t);
    default:
        return 0;
    }
}

static void context_body_encode(uint16_t backend, const uint8_t *native,
                                 uint8_t *wire)
{
    size_t count;
    const struct context_field *fields = context_fields(backend, &count);

    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < fields[i].count; j++) {
            const uint8_t *value = native + fields[i].offset +
                                   j * fields[i].stride;

            switch (fields[i].bytes) {
            case 1:
                *wire = *value;
                break;
            case 2: {
                uint16_t v;
                memcpy(&v, value, sizeof(v));
                write_be16(wire, v);
                break;
            }
            case 4: {
                uint32_t v;
                memcpy(&v, value, sizeof(v));
                write_be32(wire, v);
                break;
            }
            case 8: {
                uint64_t v;
                memcpy(&v, value, sizeof(v));
                write_be64(wire, v);
                break;
            }
            }
            wire += fields[i].bytes;
        }
    }
}

static void context_body_decode(uint16_t backend, const uint8_t *wire,
                                 uint8_t *native)
{
    size_t count;
    const struct context_field *fields = context_fields(backend, &count);

    memset(native, 0, wvm_x86_context_legacy_bytes(backend));
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < fields[i].count; j++) {
            uint8_t *value = native + fields[i].offset + j * fields[i].stride;

            switch (fields[i].bytes) {
            case 1:
                *value = *wire;
                break;
            case 2: {
                uint16_t v = read_be16(wire);
                memcpy(value, &v, sizeof(v));
                break;
            }
            case 4: {
                uint32_t v = read_be32(wire);
                memcpy(value, &v, sizeof(v));
                break;
            }
            case 8: {
                uint64_t v = read_be64(wire);
                memcpy(value, &v, sizeof(v));
                break;
            }
            }
            wire += fields[i].bytes;
        }
    }
}

int wvm_x86_context_encode(uint16_t backend, uint64_t valid_fields,
                           const void *legacy_context,
                           size_t legacy_context_bytes, uint8_t *output,
                           size_t output_capacity, size_t *output_bytes,
                           char *error, size_t error_len)
{
    const size_t expected_bytes = wvm_x86_context_legacy_bytes(backend);
    const size_t body_bytes = context_body_bytes(backend);
    size_t required_bytes;

    if (expected_bytes == 0 || !fields_valid(valid_fields) ||
        !legacy_context || legacy_context_bytes != expected_bytes || !output ||
        !output_bytes || body_bytes > UINT32_MAX ||
        output_capacity < WVM_X86_CONTEXT_WIRE_HEADER_BYTES + body_bytes) {
        set_error(error, error_len, "x86 context encode input is invalid");
        return -1;
    }
    required_bytes = WVM_X86_CONTEXT_WIRE_HEADER_BYTES + body_bytes;
    memset(output, 0, WVM_X86_CONTEXT_WIRE_HEADER_BYTES);
    write_be32(output + CONTEXT_MAGIC_OFFSET, WVM_X86_CONTEXT_MAGIC);
    write_be16(output + CONTEXT_SCHEMA_OFFSET, WVM_X86_CONTEXT_SCHEMA_VERSION);
    write_be16(output + CONTEXT_BACKEND_OFFSET, backend);
    write_be64(output + CONTEXT_FIELDS_OFFSET, valid_fields);
    write_be32(output + CONTEXT_BODY_BYTES_OFFSET, (uint32_t)body_bytes);
    context_body_encode(backend, legacy_context,
                        output + WVM_X86_CONTEXT_WIRE_HEADER_BYTES);
    *output_bytes = required_bytes;
    return 0;
}

int wvm_x86_context_validate(uint16_t expected_backend,
                             const uint8_t *input, size_t input_bytes,
                             uint64_t *valid_fields_out, char *error,
                             size_t error_len)
{
    const size_t expected_bytes =
        context_body_bytes(expected_backend);
    uint16_t backend;
    uint64_t valid_fields;
    uint32_t body_bytes;

    if (expected_bytes == 0 || !input || !valid_fields_out ||
        input_bytes < WVM_X86_CONTEXT_WIRE_HEADER_BYTES ||
        read_be32(input + CONTEXT_MAGIC_OFFSET) != WVM_X86_CONTEXT_MAGIC ||
        read_be16(input + CONTEXT_SCHEMA_OFFSET) !=
            WVM_X86_CONTEXT_SCHEMA_VERSION ||
        !all_zero(input + CONTEXT_RESERVED_OFFSET, 4)) {
        set_error(error, error_len, "x86 context header is invalid");
        return -1;
    }
    backend = read_be16(input + CONTEXT_BACKEND_OFFSET);
    valid_fields = read_be64(input + CONTEXT_FIELDS_OFFSET);
    body_bytes = read_be32(input + CONTEXT_BODY_BYTES_OFFSET);
    if (backend != expected_backend || !fields_valid(valid_fields) ||
        body_bytes != expected_bytes ||
        input_bytes != WVM_X86_CONTEXT_WIRE_HEADER_BYTES + expected_bytes) {
        set_error(error, error_len, "x86 context profile does not match");
        return -1;
    }
    *valid_fields_out = valid_fields;
    return 0;
}

int wvm_x86_context_decode(uint16_t expected_backend,
                           const uint8_t *input, size_t input_bytes,
                           uint64_t *valid_fields_out, void *legacy_context,
                           size_t legacy_context_capacity, char *error,
                           size_t error_len)
{
    const size_t expected_bytes =
        wvm_x86_context_legacy_bytes(expected_backend);

    if (!legacy_context || legacy_context_capacity < expected_bytes ||
        wvm_x86_context_validate(expected_backend, input, input_bytes,
                                 valid_fields_out, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "x86 context decode output is invalid");
        }
        return -1;
    }
    context_body_decode(expected_backend,
                        input + WVM_X86_CONTEXT_WIRE_HEADER_BYTES,
                        legacy_context);
    return 0;
}

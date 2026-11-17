#ifndef WAVEVM_KVM_STATE_H
#define WAVEVM_KVM_STATE_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "wavevm_protocol.h"

struct wvm_kvm_cpuid_ioctl {
    struct kvm_cpuid2 header;
    struct kvm_cpuid_entry2 entries[WVM_KVM_MAX_CPUID_ENTRIES];
};

static inline int wvm_kvm_msr_has_named_field(uint32_t index)
{
    switch (index) {
    case 0x10: case 0x1b: case 0x174: case 0x175: case 0x176:
    case 0x277: case 0x6e0:
    case 0xc0000081: case 0xc0000082: case 0xc0000083: case 0xc0000084:
    case 0xc0000101: case 0xc0000102:
        return 1;
    default:
        return 0;
    }
}

/* The frontend selects these indices with QEMU's native CPU-model rules.
 * Executors capture the same list; they never substitute their own profile. */
static inline int wvm_kvm_profile_msrs_transfer(
    int fd, const wvm_kvm_context_t *source, wvm_kvm_context_t *captured)
{
    struct {
        struct kvm_msrs header;
        struct kvm_msr_entry entries[WVM_KVM_MAX_PROFILE_MSRS];
    } table = {0};
    int result;

    if (!source || source->profile_msr_count > WVM_KVM_MAX_PROFILE_MSRS)
        return -EPROTO;
    table.header.nmsrs = source->profile_msr_count;
    for (uint32_t i = 0; i < source->profile_msr_count; ++i) {
        uint32_t index = source->profile_msrs[i].index;

        if (wvm_kvm_msr_has_named_field(index)) return -EPROTO;
        for (uint32_t j = 0; j < i; ++j)
            if (source->profile_msrs[j].index == index) return -EPROTO;
        table.entries[i].index = index;
        if (!captured) table.entries[i].data = source->profile_msrs[i].value;
    }
    result = table.header.nmsrs ?
        ioctl(fd, captured ? KVM_GET_MSRS : KVM_SET_MSRS, &table) : 0;
    if (result < 0)
        return -errno;
    if (captured) {
        captured->profile_msr_count = source->profile_msr_count;
        memset(captured->profile_msrs, 0, sizeof(captured->profile_msrs));
        for (uint32_t i = 0; i < source->profile_msr_count; ++i) {
            captured->profile_msrs[i].index = source->profile_msrs[i].index;
            captured->profile_msrs[i].value = source->profile_msrs[i].value;
        }
    }
    if (result == (int)table.header.nmsrs) {
        if (captured) {
            for (uint32_t i = 0; i < table.header.nmsrs; ++i)
                captured->profile_msrs[i].value = table.entries[i].data;
        }
        return 0;
    }
    /*
     * KVM_SET/GET_MSRS returns a short count when an MSR is unsupported
     * or not writable on this vCPU (run-183152: IA32_MCG_CTL 0x17b).
     * Apply or capture the rest one-by-one; skip only those MSRs, and
     * keep protocol/hard ioctl errors fatal. The ACK still lists every
     * requested index so the frontend profile set continues to match.
     */
    fprintf(stderr,
            "[kvm-import] profile %s_MSRS partial nmsrs=%u ret=%d\n",
            captured ? "GET" : "SET", table.header.nmsrs, result);
    for (uint32_t i = 0; i < source->profile_msr_count; ++i) {
        struct {
            struct kvm_msrs header;
            struct kvm_msr_entry entries[1];
        } one = {0};
        int r;
        int err;

        one.header.nmsrs = 1;
        one.entries[0].index = source->profile_msrs[i].index;
        if (!captured)
            one.entries[0].data = source->profile_msrs[i].value;
        r = ioctl(fd, captured ? KVM_GET_MSRS : KVM_SET_MSRS, &one);
        err = errno;
        if (r == 1) {
            if (captured)
                captured->profile_msrs[i].value = one.entries[0].data;
            continue;
        }
        if (r < 0 && err != EINVAL && err != EAGAIN && err != ENXIO &&
            err != EOPNOTSUPP && err != ENOTTY) {
            fprintf(stderr,
                    "[kvm-import] profile %s hard-fail i=%u index=0x%x "
                    "value=0x%llx ret=%d errno=%d\n",
                    captured ? "GET" : "SET", i,
                    source->profile_msrs[i].index,
                    (unsigned long long)source->profile_msrs[i].value,
                    r, err);
            return -err;
        }
        fprintf(stderr,
                "[kvm-import] profile %s skipped i=%u index=0x%x "
                "value=0x%llx ret=%d errno=%d\n",
                captured ? "GET" : "SET", i,
                source->profile_msrs[i].index,
                (unsigned long long)source->profile_msrs[i].value,
                r, err);
    }
    return 0;
}

static inline int wvm_kvm_profile_msrs_match(
    const wvm_kvm_context_t *requested, const wvm_kvm_context_t *returned)
{
    if (!requested || !returned ||
        requested->profile_msr_count > WVM_KVM_MAX_PROFILE_MSRS ||
        requested->profile_msr_count != returned->profile_msr_count) return 0;
    for (uint32_t i = 0; i < requested->profile_msr_count; ++i)
        if (requested->profile_msrs[i].index != returned->profile_msrs[i].index)
            return 0;
    return 1;
}

static inline int wvm_kvm_cpuid_capture(int fd, wvm_kvm_context_t *context)
{
    struct wvm_kvm_cpuid_ioctl table;

    memset(&table, 0, sizeof(table));
    table.header.nent = WVM_KVM_MAX_CPUID_ENTRIES;
    context->cpuid_count = 0;
    memset(context->cpuid, 0, sizeof(context->cpuid));
    if (ioctl(fd, KVM_GET_CPUID2, &table) < 0) return -errno;
    if (table.header.nent == 0 ||
        table.header.nent > WVM_KVM_MAX_CPUID_ENTRIES) return -ENOTSUP;
    context->cpuid_count = table.header.nent;
    for (uint32_t i = 0; i < context->cpuid_count; ++i) {
        const struct kvm_cpuid_entry2 *src = &table.entries[i];
        wvm_kvm_cpuid_entry_t *dst = &context->cpuid[i];

        dst->function = src->function; dst->index = src->index;
        dst->flags = src->flags; dst->eax = src->eax; dst->ebx = src->ebx;
        dst->ecx = src->ecx; dst->edx = src->edx;
    }
    return 0;
}

static inline int wvm_kvm_cpuid_import(int fd,
                                       const wvm_kvm_context_t *context)
{
    struct wvm_kvm_cpuid_ioctl table;

    if (!context || context->cpuid_count == 0 ||
        context->cpuid_count > WVM_KVM_MAX_CPUID_ENTRIES) return -EPROTO;
    memset(&table, 0, sizeof(table));
    table.header.nent = context->cpuid_count;
    for (uint32_t i = 0; i < context->cpuid_count; ++i) {
        const wvm_kvm_cpuid_entry_t *src = &context->cpuid[i];
        struct kvm_cpuid_entry2 *dst = &table.entries[i];

        dst->function = src->function; dst->index = src->index;
        dst->flags = src->flags; dst->eax = src->eax; dst->ebx = src->ebx;
        dst->ecx = src->ecx; dst->edx = src->edx;
    }
    return ioctl(fd, KVM_SET_CPUID2, &table) < 0 ? -errno : 0;
}

/* KVM_SET_CPUID2 accepts feature bits it cannot execute. Check instruction
 * feature leaves against the destination, not vendor/model/topology numbers. */
static inline int wvm_kvm_cpuid_check_host(
    int kvm_fd, const wvm_kvm_context_t *context)
{
    struct wvm_kvm_cpuid_ioctl supported;

    if (!context || !context->cpuid_count ||
        context->cpuid_count > WVM_KVM_MAX_CPUID_ENTRIES) return -EPROTO;
    memset(&supported, 0, sizeof(supported));
    supported.header.nent = WVM_KVM_MAX_CPUID_ENTRIES;
    if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &supported) < 0) return -errno;
    if (supported.header.nent > WVM_KVM_MAX_CPUID_ENTRIES) return -ENOTSUP;
    for (uint32_t i = 0; i < context->cpuid_count; ++i) {
        const wvm_kvm_cpuid_entry_t *guest = &context->cpuid[i];
        const struct kvm_cpuid_entry2 zero = {0};
        const struct kvm_cpuid_entry2 *host = &zero;
        uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

        switch (guest->function) {
        case 1:
            ecx = UINT32_MAX & ~(1U << 31); /* Synthetic hypervisor flag. */
            edx = UINT32_MAX & ~(1U << 28); /* Guest logical topology. */
            break;
        case 7:
            eax = guest->index ? UINT32_MAX : 0; /* Subleaf zero is a count. */
            ebx = ecx = edx = UINT32_MAX;
            break;
        case 0x80000001:
            ecx = edx = UINT32_MAX;
            break;
        case 0x80000007:
            edx = UINT32_MAX;
            break;
        case 0x80000008:
            ebx = UINT32_MAX;
            break;
        default:
            continue;
        }
        for (uint32_t j = 0; j < supported.header.nent; ++j) {
            const struct kvm_cpuid_entry2 *candidate = &supported.entries[j];
            if (candidate->function == guest->function &&
                candidate->index == guest->index) {
                host = candidate;
                break;
            }
        }
        if ((guest->eax & eax & ~host->eax) ||
            (guest->ebx & ebx & ~host->ebx) ||
            (guest->ecx & ecx & ~host->ecx) ||
            (guest->edx & edx & ~host->edx)) return -ENOTSUP;
    }
    return 0;
}

/* Local KVM mechanics only; the manifest and context codec own the profile. */
static inline int wvm_kvm_extended_state_validate(
    const wvm_kvm_context_t *context)
{
    if (!context || context->fpu_valid != 1 ||
        context->lapic_valid != 1 || context->vcpu_events_valid != 1 ||
        context->mp_state_valid != 1 || context->xcrs_valid > 1 ||
        context->debug_valid != 1 || context->system_msrs_valid != 1 ||
        context->profile_msr_count > WVM_KVM_MAX_PROFILE_MSRS ||
        context->cpuid_count == 0 ||
        context->cpuid_count > WVM_KVM_MAX_CPUID_ENTRIES) {
        return -EPROTO;
    }
    for (uint32_t i = 0; i < context->cpuid_count; ++i) {
        const wvm_kvm_cpuid_entry_t *entry = &context->cpuid[i];
        if (entry->flags & ~(KVM_CPUID_FLAG_SIGNIFCANT_INDEX |
                             KVM_CPUID_FLAG_STATEFUL_FUNC |
                             KVM_CPUID_FLAG_STATE_READ_NEXT)) return -EPROTO;
        if (entry->function == 1 && (entry->ecx & (1U << 26))) {
            return -ENOTSUP;
        }
    }
    if (context->xcrs_valid) {
        struct kvm_xcrs xcrs;

        memcpy(&xcrs, context->xcrs_data, sizeof(xcrs));
        if (xcrs.nr_xcrs > KVM_MAX_XCRS || xcrs.flags != 0) {
            return -EPROTO;
        }
        for (uint32_t i = 0; i < xcrs.nr_xcrs; i++) {
            /* This profile carries FXSAVE state, not AVX/AMX/PKRU XSAVE. */
            if (xcrs.xcrs[i].xcr != 0 || (xcrs.xcrs[i].value & ~3ULL)) {
                return -ENOTSUP;
            }
        }
    }
    return 0;
}

static inline int wvm_kvm_extended_state_import(
    int fd, const wvm_kvm_context_t *context)
{
    struct kvm_mp_state mp;
    struct kvm_debugregs debug = {0};
    struct {
        struct kvm_msrs header;
        struct kvm_msr_entry entries[4];
    } msrs = { .header.nmsrs = 4 };
    int result = wvm_kvm_extended_state_validate(context);

    if (result != 0) {
        return result;
    }
    memcpy(debug.db, context->debug_address, sizeof(debug.db));
    debug.dr6 = context->debug_status;
    debug.dr7 = context->debug_control;
    msrs.entries[0].index = 0x174; /* SYSENTER_CS */
    msrs.entries[0].data = context->sysenter_cs;
    msrs.entries[1].index = 0x175; /* SYSENTER_ESP */
    msrs.entries[1].data = context->sysenter_esp;
    msrs.entries[2].index = 0x176; /* SYSENTER_EIP */
    msrs.entries[2].data = context->sysenter_eip;
    msrs.entries[3].index = 0x277; /* IA32_PAT */
    msrs.entries[3].data = context->pat;
    if (ioctl(fd, KVM_SET_DEBUGREGS, &debug) < 0) {
        int e = -errno;
        fprintf(stderr, "[kvm-import] SET_DEBUGREGS failed errno=%d\n", -e);
        return e;
    }
    result = ioctl(fd, KVM_SET_MSRS, &msrs);
    if (result != 4) {
        int e = result < 0 ? -errno : -EIO;
        fprintf(stderr,
                "[kvm-import] SET_MSRS sysenter/pat ret=%d errno=%d -> %d\n",
                result, errno, e);
        return e;
    }
    if (context->xcrs_valid) {
        struct kvm_xcrs xcrs;

        memcpy(&xcrs, context->xcrs_data, sizeof(xcrs));
        if (ioctl(fd, KVM_SET_XCRS, &xcrs) < 0) {
            int e = -errno;
            fprintf(stderr, "[kvm-import] SET_XCRS failed errno=%d\n", -e);
            return e;
        }
    }
    if (ioctl(fd, KVM_SET_FPU, context->fpu_data) < 0) {
        int e = -errno;
        fprintf(stderr, "[kvm-import] SET_FPU failed errno=%d\n", -e);
        return e;
    }
    if (ioctl(fd, KVM_SET_LAPIC, context->lapic_data) < 0) {
        int e = -errno;
        fprintf(stderr, "[kvm-import] SET_LAPIC failed errno=%d\n", -e);
        return e;
    }
    {
        struct kvm_vcpu_events ev;
        /*
         * QEMU's bundled linux-headers are older than the system
         * asm/kvm.h used by master/slave: they lack
         * KVM_VCPUEVENT_VALID_TRIPLE_FAULT and ev.triple_fault.
         * Keep the F10 retry path; treat missing bits as 0 so a
         * WaveVM QEMU rebuild still compiles.
         */
#ifndef KVM_VCPUEVENT_VALID_TRIPLE_FAULT
#define KVM_VCPUEVENT_VALID_TRIPLE_FAULT 0
#define WVM_KVM_EVENTS_HAS_TRIPLE_FAULT 0
#else
#define WVM_KVM_EVENTS_HAS_TRIPLE_FAULT 1
#endif
        const uint32_t ev_flags_mask =
            KVM_VCPUEVENT_VALID_NMI_PENDING |
            KVM_VCPUEVENT_VALID_SIPI_VECTOR |
            KVM_VCPUEVENT_VALID_SHADOW |
            KVM_VCPUEVENT_VALID_SMM |
            KVM_VCPUEVENT_VALID_PAYLOAD |
            KVM_VCPUEVENT_VALID_TRIPLE_FAULT;

        memcpy(&ev, context->vcpu_events_data, sizeof(ev));
        if (ioctl(fd, KVM_SET_VCPU_EVENTS, &ev) < 0) {
            int e = -errno;
            uint32_t orig_flags = ev.flags;
            fprintf(stderr,
                    "[kvm-import] SET_VCPU_EVENTS failed errno=%d flags=0x%x "
                    "exc inj=%u nr=%u has_err=%u pend=%u code=%u "
                    "int inj=%u nr=%u soft=%u shadow=%u "
                    "nmi inj=%u pend=%u mask=%u sipi=0x%x "
                    "smm=%u smm_pend=%u inside_nmi=%u latched=%u "
                    "tf=%u payload_valid=%u payload=0x%llx mp=%u\n",
                    -e, ev.flags,
                    ev.exception.injected, ev.exception.nr,
                    ev.exception.has_error_code, ev.exception.pending,
                    ev.exception.error_code,
                    ev.interrupt.injected, ev.interrupt.nr,
                    ev.interrupt.soft, ev.interrupt.shadow,
                    ev.nmi.injected, ev.nmi.pending, ev.nmi.masked,
                    ev.sipi_vector,
                    ev.smi.smm, ev.smi.pending, ev.smi.smm_inside_nmi,
                    ev.smi.latched_init,
#if WVM_KVM_EVENTS_HAS_TRIPLE_FAULT
                    ev.triple_fault.pending,
#else
                    0u,
#endif
                    ev.exception_has_payload,
                    (unsigned long long)ev.exception_payload,
                    context->mp_state);
            ev.flags &= ev_flags_mask;
            if (ev.exception.injected && ev.exception.pending)
                ev.exception.injected = 0;
            /* SIPI vector is only legal in INIT_RECEIVED; a freshly created
             * slave vCPU is RUNNABLE until SET_MP_STATE runs later. */
            if (context->mp_state != KVM_MP_STATE_INIT_RECEIVED)
                ev.flags &= ~KVM_VCPUEVENT_VALID_SIPI_VECTOR;
            if (ioctl(fd, KVM_SET_VCPU_EVENTS, &ev) < 0) {
                uint32_t mid_flags = ev.flags;
                ev.flags &= ~KVM_VCPUEVENT_VALID_PAYLOAD;
                ev.exception_has_payload = 0;
                ev.exception_payload = 0;
                if (ioctl(fd, KVM_SET_VCPU_EVENTS, &ev) < 0) {
                    e = -errno;
                    fprintf(stderr,
                            "[kvm-import] SET_VCPU_EVENTS retry failed errno=%d "
                            "flags=0x%x->0x%x->0x%x\n",
                            -e, orig_flags, mid_flags, ev.flags);
                    return e;
                }
                fprintf(stderr,
                        "[kvm-import] SET_VCPU_EVENTS retry ok after dropping PAYLOAD "
                        "flags=0x%x->0x%x\n",
                        orig_flags, ev.flags);
            } else {
                fprintf(stderr,
                        "[kvm-import] SET_VCPU_EVENTS retry ok flags=0x%x->0x%x\n",
                        orig_flags, ev.flags);
            }
        }
    }
    /* Profile MSRs after LAPIC/FPU/XCR/events so APIC-adjacent model MSRs
     * are not applied to a vCPU that has not imported local APIC state. */
    result = wvm_kvm_profile_msrs_transfer(fd, context, NULL);
    if (result) {
        fprintf(stderr, "[kvm-import] profile_msrs_transfer failed %d\n", result);
        return result;
    }
    mp.mp_state = context->mp_state;
    if (ioctl(fd, KVM_SET_MP_STATE, &mp) < 0) {
        int e = -errno;
        fprintf(stderr, "[kvm-import] SET_MP_STATE failed errno=%d mp=%u\n",
                -e, (unsigned)mp.mp_state);
        return e;
    }
    return 0;
}

static inline int wvm_kvm_extended_state_capture(
    int fd, wvm_kvm_context_t *context)
{
    struct kvm_mp_state mp;
    struct kvm_debugregs debug;
    struct {
        struct kvm_msrs header;
        struct kvm_msr_entry entries[4];
    } msrs = { .header.nmsrs = 4 };

    if (!context) {
        return -EINVAL;
    }
    context->fpu_valid = context->lapic_valid = 0;
    context->vcpu_events_valid = context->mp_state_valid = 0;
    context->xcrs_valid = 0;
    context->debug_valid = context->system_msrs_valid = 0;
    /* GET_MP_STATE may materialize SIPI effects in CS:RIP. */
    if (ioctl(fd, KVM_GET_MP_STATE, &mp) < 0 ||
        ioctl(fd, KVM_GET_FPU, context->fpu_data) < 0 ||
        ioctl(fd, KVM_GET_LAPIC, context->lapic_data) < 0 ||
        ioctl(fd, KVM_GET_VCPU_EVENTS, context->vcpu_events_data) < 0) {
        return -errno;
    }
    context->fpu_valid = context->lapic_valid = 1;
    context->vcpu_events_valid = context->mp_state_valid = 1;
    context->mp_state = mp.mp_state;
    memset(&debug, 0, sizeof(debug));
    if (ioctl(fd, KVM_GET_DEBUGREGS, &debug) < 0) return -errno;
    memcpy(context->debug_address, debug.db, sizeof(debug.db));
    context->debug_status = debug.dr6;
    context->debug_control = debug.dr7;
    context->debug_valid = 1;
    msrs.entries[0].index = 0x174;
    msrs.entries[1].index = 0x175;
    msrs.entries[2].index = 0x176;
    msrs.entries[3].index = 0x277;
    int result = ioctl(fd, KVM_GET_MSRS, &msrs);
    if (result != 4) return result < 0 ? -errno : -EIO;
    context->sysenter_cs = msrs.entries[0].data;
    context->sysenter_esp = msrs.entries[1].data;
    context->sysenter_eip = msrs.entries[2].data;
    context->pat = msrs.entries[3].data;
    context->system_msrs_valid = 1;
    if (ioctl(fd, KVM_GET_XCRS, context->xcrs_data) == 0) {
        context->xcrs_valid = 1;
    } else if (errno != ENOTTY && errno != EINVAL && errno != ENXIO) {
        return -errno;
    }
    result = wvm_kvm_cpuid_capture(fd, context);
    return result ? result : wvm_kvm_extended_state_validate(context);
}

#endif

#ifndef WAVEVM_KVM_STATE_H
#define WAVEVM_KVM_STATE_H

#include <errno.h>
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
    if (result != (int)table.header.nmsrs) return result < 0 ? -errno : -EIO;
    if (captured) {
        captured->profile_msr_count = table.header.nmsrs;
        memset(captured->profile_msrs, 0, sizeof(captured->profile_msrs));
        for (uint32_t i = 0; i < table.header.nmsrs; ++i) {
            captured->profile_msrs[i].index = table.entries[i].index;
            captured->profile_msrs[i].value = table.entries[i].data;
        }
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
    if (ioctl(fd, KVM_SET_DEBUGREGS, &debug) < 0) return -errno;
    result = ioctl(fd, KVM_SET_MSRS, &msrs);
    if (result != 4) return result < 0 ? -errno : -EIO;
    result = wvm_kvm_profile_msrs_transfer(fd, context, NULL);
    if (result) return result;
    if (context->xcrs_valid) {
        struct kvm_xcrs xcrs;

        memcpy(&xcrs, context->xcrs_data, sizeof(xcrs));
        if (ioctl(fd, KVM_SET_XCRS, &xcrs) < 0) {
            return -errno;
        }
    }
    if (ioctl(fd, KVM_SET_FPU, context->fpu_data) < 0 ||
        ioctl(fd, KVM_SET_LAPIC, context->lapic_data) < 0 ||
        ioctl(fd, KVM_SET_VCPU_EVENTS, context->vcpu_events_data) < 0) {
        return -errno;
    }
    mp.mp_state = context->mp_state;
    if (ioctl(fd, KVM_SET_MP_STATE, &mp) < 0) {
        return -errno;
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

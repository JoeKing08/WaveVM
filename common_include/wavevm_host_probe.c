#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "wavevm_host_probe.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_capability.h"
#include "wavevm_ioctl.h"

#ifndef __NR_userfaultfd
#if defined(__x86_64__)
#define __NR_userfaultfd 323
#elif defined(__aarch64__)
#define __NR_userfaultfd 282
#else
#define __NR_userfaultfd -1
#endif
#endif

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len > 0) {
        snprintf(error, error_len, "%s", message ? message : "host probe failed");
    }
}

static uint64_t now_unix_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec <= 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}

static void fill_probe_op_id(uint8_t out[WVM_IDENTITY_ID_BYTES], uint64_t stamp)
{
    memset(out, 0, WVM_IDENTITY_ID_BYTES);
    out[WVM_IDENTITY_ID_BYTES - 8] = (uint8_t)((stamp >> 56) & 0xffU);
    out[WVM_IDENTITY_ID_BYTES - 7] = (uint8_t)((stamp >> 48) & 0xffU);
    out[WVM_IDENTITY_ID_BYTES - 6] = (uint8_t)((stamp >> 40) & 0xffU);
    out[WVM_IDENTITY_ID_BYTES - 5] = (uint8_t)((stamp >> 32) & 0xffU);
    out[WVM_IDENTITY_ID_BYTES - 4] = (uint8_t)((stamp >> 24) & 0xffU);
    out[WVM_IDENTITY_ID_BYTES - 3] = (uint8_t)((stamp >> 16) & 0xffU);
    out[WVM_IDENTITY_ID_BYTES - 2] = (uint8_t)((stamp >> 8) & 0xffU);
    out[WVM_IDENTITY_ID_BYTES - 1] = (uint8_t)(stamp & 0xffU);
}

/*
 * Restricted-host TCG fallback: anonymous page mprotect PROT_NONE -> PROT_READ
 * must succeed. This is the Minimum no-root SIGSEGV/mprotect path evidence.
 */
static int probe_sigsegv_mprotect(void)
{
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *page_ptr;
    int rc = -1;

    if (page == 0 || page > (1U << 20)) {
        return -1;
    }
    page_ptr = mmap(NULL, page, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page_ptr == MAP_FAILED) {
        return -1;
    }
    ((volatile char *)page_ptr)[0] = 1;
    if (mprotect(page_ptr, page, PROT_NONE) != 0) {
        goto out;
    }
    if (mprotect(page_ptr, page, PROT_READ | PROT_WRITE) != 0) {
        goto out;
    }
    if (((volatile char *)page_ptr)[0] != 1) {
        goto out;
    }
    rc = 0;
out:
    munmap(page_ptr, page);
    return rc;
}

static int probe_userfaultfd(void)
{
    int fd;

    if (__NR_userfaultfd < 0) {
        return -1;
    }
    fd = (int)syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int probe_kvm(uint64_t *feature_bits, uint32_t *abi_version)
{
    int kvm_fd;
    int vm_fd = -1;
    int api;
    int rc = -1;

    *feature_bits = 0;
    *abi_version = 0;
    kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) {
        return -1;
    }
    api = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    if (api < 0) {
        goto out;
    }
    *abi_version = (uint32_t)api;
    *feature_bits |= WVM_HOST_PROBE_KVM_API;

    /*
     * Dirty-log capture needs a usable KVM VM + dirty-log related caps.
     * Probe CREATE_VM and at least one dirty-log-related extension when
     * present; absence of the extension still allows API+CREATE evidence
     * but leaves DIRTY_LOG bit clear so admission can fail-closed for KVM
     * dirty path until Extended engines land.
     */
    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (vm_fd >= 0) {
        *feature_bits |= WVM_HOST_PROBE_KVM_CREATE_VM;
#ifdef KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2
        if (ioctl(kvm_fd, KVM_CHECK_EXTENSION,
                  KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2) > 0) {
            *feature_bits |= WVM_HOST_PROBE_KVM_DIRTY_LOG;
        }
#endif
#ifdef KVM_CAP_DIRTY_LOG_RING
        if (ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_DIRTY_LOG_RING) > 0) {
            *feature_bits |= WVM_HOST_PROBE_KVM_DIRTY_LOG;
        }
#endif
        /*
         * Do NOT treat KVM_CAP_SYNC_MMU (>=0 including "unsupported returns 0")
         * as dirty-log proof (cross-review F8/F9). DIRTY_LOG bit stays clear
         * unless a real dirty-log extension probed above succeeded.
         */
        close(vm_fd);
        vm_fd = -1;
    }

    if ((*feature_bits & WVM_HOST_PROBE_KVM_API) != 0 &&
        (*feature_bits & WVM_HOST_PROBE_KVM_CREATE_VM) != 0 &&
        (*feature_bits & WVM_HOST_PROBE_KVM_DIRTY_LOG) != 0) {
        rc = 0;
    }
out:
    if (vm_fd >= 0) {
        close(vm_fd);
    }
    close(kvm_fd);
    return rc;
}

static int probe_kernel_accel(uint64_t *feature_bits, uint32_t *abi_version)
{
    int fd;
    struct wvm_ioctl_context_caps caps;

    *feature_bits = 0;
    *abi_version = 0;
    fd = open("/dev/wavevm", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    memset(&caps, 0, sizeof(caps));
    if (ioctl(fd, IOCTL_WVM_QUERY_CAPS, &caps) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if (caps.magic != WVM_KERNEL_CONTEXT_MAGIC) {
        return -1;
    }
    *abi_version = caps.version;
    *feature_bits = caps.feature_bits;
    if (caps.max_concurrent_contexts == 0) {
        return -1;
    }
    return 0;
}

int wvm_host_probe_run(struct wvm_host_probe_result *out, char *error,
                       size_t error_len)
{
    uint64_t stamp;

    if (!out) {
        set_error(error, error_len, "host probe output is null");
        return -1;
    }
    memset(out, 0, sizeof(*out));
    stamp = now_unix_ms();
    if (stamp == 0) {
        set_error(error, error_len, "cannot read host probe clock");
        return -1;
    }
    out->observed_at_ms = stamp;
    fill_probe_op_id(out->probe_operation_id, stamp);

    out->tcg_abi_version = 1;
    if (probe_sigsegv_mprotect() == 0) {
        out->tcg_feature_bits |= WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT;
    }
    /*
     * A11: opening userfaultfd is not enough to advertise UFFD. There is no
     * production UFFDIO_API/register/fault path wired into selection. Probe
     * the syscall only for diagnostics; never set TCG_USERFAULTFD.
     */
    (void)probe_userfaultfd();
    if ((out->tcg_feature_bits & WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT) != 0) {
        out->tcg_state = WVM_CAPABILITY_AVAILABLE;
        out->tcg_reason_code = 0;
    } else {
        out->tcg_state = WVM_CAPABILITY_UNAVAILABLE;
        out->tcg_reason_code = 1;
    }

    {
        uint64_t bits = 0;
        uint32_t abi = 0;

        if (probe_kvm(&bits, &abi) == 0) {
            out->kvm_state = WVM_CAPABILITY_AVAILABLE;
            out->kvm_feature_bits = bits;
            out->kvm_abi_version = abi;
            out->kvm_reason_code = 0;
        } else {
            out->kvm_state = WVM_CAPABILITY_UNAVAILABLE;
            out->kvm_feature_bits = bits;
            out->kvm_abi_version = abi;
            out->kvm_reason_code = 2;
        }
    }

    {
        uint64_t bits = 0;
        uint32_t abi = 0;

        if (probe_kernel_accel(&bits, &abi) == 0) {
            out->kernel_accel_state = WVM_CAPABILITY_AVAILABLE;
            out->kernel_accel_feature_bits = bits;
            out->kernel_accel_abi_version = abi;
            out->kernel_accel_reason_code = 0;
        } else {
            out->kernel_accel_state = WVM_CAPABILITY_UNAVAILABLE;
            out->kernel_accel_feature_bits = bits;
            out->kernel_accel_abi_version = abi;
            out->kernel_accel_reason_code = 3;
        }
    }

    if (out->tcg_state != WVM_CAPABILITY_AVAILABLE) {
        set_error(error, error_len,
                  "restricted TCG SIGSEGV/mprotect probe failed");
        return -1;
    }
    return 0;
}

static void fill_record(struct wvm_capability_record *record,
                        uint16_t capability_id, uint32_t node_id,
                        uint64_t instance_id, uint64_t provider,
                        enum wvm_capability_state state, uint32_t abi,
                        uint64_t features, uint64_t observed_at,
                        const uint8_t probe_op[WVM_IDENTITY_ID_BYTES],
                        uint16_t reason)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = node_id;
    record->node_instance_id = instance_id;
    record->provider_instance_id = provider;
    record->state = state;
    record->abi_version = abi;
    record->feature_bits = features;
    record->observed_at = observed_at;
    memcpy(record->probe_operation_id, probe_op, WVM_IDENTITY_ID_BYTES);
    record->reason_code = reason;
}


static int capability_record_id_compare(const void *left_value,
                                        const void *right_value)
{
    const struct wvm_capability_record *left = left_value;
    const struct wvm_capability_record *right = right_value;

    if (left->capability_id != right->capability_id) {
        return left->capability_id < right->capability_id ? -1 : 1;
    }
    if (left->provider_instance_id != right->provider_instance_id) {
        return left->provider_instance_id < right->provider_instance_id ? -1 : 1;
    }
    return 0;
}

int wvm_host_probe_fill_records(
    const struct wvm_host_probe_result *probe, uint32_t physical_node_id,
    uint64_t node_instance_id, uint64_t provider_instance_id,
    struct wvm_capability_record *records, size_t record_capacity,
    size_t *record_count, char *error, size_t error_len)
{
    size_t count = 0;

    if (!probe || !records || !record_count || physical_node_id == 0 ||
        node_instance_id == 0 || provider_instance_id == 0 ||
        record_capacity < 3) {
        set_error(error, error_len, "host probe fill records arguments invalid");
        return -1;
    }

    fill_record(&records[count++], WVM_CAPABILITY_ID_EXECUTION_TCG,
                physical_node_id, node_instance_id, provider_instance_id,
                probe->tcg_state, probe->tcg_abi_version, probe->tcg_feature_bits,
                probe->observed_at_ms, probe->probe_operation_id,
                probe->tcg_reason_code);
    /*
     * A11: Mode B memory is not unconditional AVAILABLE. Minimum evidence is
     * the same restricted SIGSEGV/mprotect probe used for TCG; without it the
     * record stays UNAVAILABLE (no false AVAILABLE).
     */
    fill_record(&records[count++], WVM_CAPABILITY_ID_MODE_B_MEMORY,
                physical_node_id, node_instance_id, provider_instance_id + 1,
                ((probe->tcg_feature_bits &
                  WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT) != 0)
                    ? WVM_CAPABILITY_AVAILABLE
                    : WVM_CAPABILITY_UNAVAILABLE,
                1,
                ((probe->tcg_feature_bits &
                  WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT) != 0)
                    ? 1ULL
                    : 0ULL,
                probe->observed_at_ms, probe->probe_operation_id,
                ((probe->tcg_feature_bits &
                  WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT) != 0)
                    ? 0U
                    : 1U);
    fill_record(&records[count++], WVM_CAPABILITY_ID_VM_ID_U32, physical_node_id,
                node_instance_id, provider_instance_id + 2,
                WVM_CAPABILITY_AVAILABLE, 1, 1, probe->observed_at_ms,
                probe->probe_operation_id, 0);

    if (probe->kvm_state == WVM_CAPABILITY_AVAILABLE) {
        if (count >= record_capacity) {
            set_error(error, error_len, "host probe record capacity too small");
            return -1;
        }
        fill_record(&records[count++], WVM_CAPABILITY_ID_EXECUTION_KVM,
                    physical_node_id, node_instance_id, provider_instance_id + 3,
                    probe->kvm_state, probe->kvm_abi_version,
                    probe->kvm_feature_bits, probe->observed_at_ms,
                    probe->probe_operation_id, probe->kvm_reason_code);
    }
    if (probe->kernel_accel_state == WVM_CAPABILITY_AVAILABLE) {
        if (count >= record_capacity) {
            set_error(error, error_len, "host probe record capacity too small");
            return -1;
        }
        fill_record(&records[count++], WVM_CAPABILITY_ID_KERNEL_ACCELERATION,
                    physical_node_id, node_instance_id, provider_instance_id + 4,
                    probe->kernel_accel_state, probe->kernel_accel_abi_version,
                    probe->kernel_accel_feature_bits, probe->observed_at_ms,
                    probe->probe_operation_id, probe->kernel_accel_reason_code);
    }

    /* Profile digest requires ascending capability_id/provider order (A10). */
    qsort(records, count, sizeof(*records), capability_record_id_compare);
    *record_count = count;
    return 0;
}

int wvm_host_probe_select_execution(
    enum wvm_manifest_backend_policy policy, int all_tcg, int all_kvm,
    int all_kvm_dirty, int all_tcg_uffd,
    struct wvm_host_probe_execution_choice *out, char *error, size_t error_len)
{
    int chose_kvm = 0;
    uint8_t fallback = 1;

    if (!out) {
        set_error(error, error_len, "execution choice output is null");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    if (policy == WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG && !all_tcg) {
        set_error(error, error_len, "no complete TCG capability set is published");
        return -1;
    }
    if (policy == WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM &&
        (!all_kvm || !all_kvm_dirty)) {
        set_error(error, error_len,
                  "no complete KVM dirty/resync capability set is published");
        return -1;
    }

    if (policy == WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM ||
        (policy == WVM_MANIFEST_BACKEND_POLICY_AUTO && all_kvm &&
         all_kvm_dirty)) {
        chose_kvm = 1;
    } else if (policy == WVM_MANIFEST_BACKEND_POLICY_AUTO && all_kvm &&
               !all_kvm_dirty) {
        fallback = 2; /* AUTO KVM incomplete → restricted TCG */
    }

    if (chose_kvm) {
        out->backend = WVM_MANIFEST_BACKEND_KVM;
        out->dirty_capture_engine = WVM_FAULT_ENGINE_KVM_DIRTY_LOG;
        out->read_fault_engine = WVM_FAULT_ENGINE_NODE_RUNTIME_RESYNC;
        out->invalidation_engine = WVM_FAULT_ENGINE_NODE_RUNTIME_RESYNC;
    } else {
        if (!all_tcg) {
            set_error(error, error_len,
                      "restricted TCG fallback requires TCG capability");
            return -1;
        }
        out->backend = WVM_MANIFEST_BACKEND_TCG;
        out->dirty_capture_engine = WVM_FAULT_ENGINE_SIGSEGV_MPROTECT;
        out->invalidation_engine = WVM_FAULT_ENGINE_SIGSEGV_MPROTECT;
        /* A11: never select unimplemented UFFD even if all_tcg_uffd is set. */
        (void)all_tcg_uffd;
        out->read_fault_engine = WVM_FAULT_ENGINE_SIGSEGV_MPROTECT;
        if (fallback == 1)
            fallback = 3;
    }
    out->fallback_decision = fallback;
    return 0;
}


int wvm_host_probe_encode_report(
    const struct wvm_capability_record *records, size_t record_count,
    uint64_t profile_generation, uint8_t **bytes_out, size_t *size_out,
    char *error, size_t error_len)
{
    struct wvm_capability_report report;
    uint8_t *bytes = NULL;
    size_t capacity = 8192;
    size_t encoded = 0;
    char local_error[256];

    if (!records || record_count == 0 || profile_generation == 0 || !bytes_out ||
        !size_out) {
        set_error(error, error_len, "host probe encode report arguments invalid");
        return -1;
    }
    *bytes_out = NULL;
    *size_out = 0;
    memset(&report, 0, sizeof(report));
    report.profile_generation = profile_generation;
    report.records = (struct wvm_capability_record *)(uintptr_t)records;
    report.record_count = record_count;

    while (capacity <= WVM_CAPABILITY_REPORT_MAX_BYTES) {
        bytes = malloc(capacity);
        if (!bytes) {
            set_error(error, error_len, "host probe report allocation failed");
            return -1;
        }
        local_error[0] = '\0';
        encoded = 0;
        if (wvm_capability_report_encode(&report, bytes, capacity, &encoded,
                                         local_error,
                                         sizeof(local_error)) == 0) {
            *bytes_out = bytes;
            *size_out = encoded;
            return 0;
        }
        free(bytes);
        bytes = NULL;
        if (strstr(local_error, "budget") != NULL ||
            strstr(local_error, "capacity") != NULL ||
            local_error[0] == '\0') {
            if (capacity > WVM_CAPABILITY_REPORT_MAX_BYTES / 2U) {
                set_error(error, error_len,
                          local_error[0] ? local_error
                                         : "capability report encode failed");
                return -1;
            }
            capacity *= 2U;
            continue;
        }
        set_error(error, error_len,
                  local_error[0] ? local_error : "capability report encode failed");
        return -1;
    }
    set_error(error, error_len, "capability report exceeds byte budget");
    return -1;
}

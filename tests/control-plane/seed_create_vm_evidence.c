#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "wavevm_capability.h"
#include "wavevm_canonical.h"
#include "wavevm_host_probe.h"
#include "wavevm_runtime_profile.h"
#include "wavevm_sha256.h"

static void fill_capability(struct wvm_capability_record *record,
                            uint16_t capability_id, uint32_t node_id,
                            uint64_t instance_id, uint64_t provider,
                            uint64_t observed_at, uint64_t feature_bits,
                            enum wvm_capability_state state)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = node_id;
    record->node_instance_id = instance_id;
    record->provider_instance_id = provider;
    record->state = state;
    record->abi_version = 1;
    record->feature_bits = feature_bits;
    record->observed_at = observed_at;
    record->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] = (uint8_t)provider;
}

static int write_bytes(const char *path, const uint8_t *bytes, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t offset = 0;

    if (fd < 0) {
        return -1;
    }
    while (offset < size) {
        ssize_t written = write(fd, bytes + offset, size - offset);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)written;
    }
    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++) {
        printf("%02x", bytes[i]);
    }
}

static int record_compare(const void *a, const void *b)
{
    const struct wvm_capability_record *left = a;
    const struct wvm_capability_record *right = b;

    if (left->capability_id != right->capability_id) {
        return left->capability_id < right->capability_id ? -1 : 1;
    }
    if (left->provider_instance_id != right->provider_instance_id) {
        return left->provider_instance_id < right->provider_instance_id ? -1
                                                                        : 1;
    }
    return 0;
}

static void force_state(struct wvm_capability_record *records, size_t count,
                        uint16_t capability_id, enum wvm_capability_state state,
                        uint64_t feature_bits)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (records[i].capability_id == capability_id) {
            records[i].state = state;
            if (state != WVM_CAPABILITY_AVAILABLE) {
                records[i].feature_bits = feature_bits;
                records[i].reason_code = 9;
            }
            return;
        }
    }
}

/*
 * usage: seed STATE_DIR NODE INSTANCE INV_REV PROFILE_GEN
 *             DATA0 DATA1 SVC0 SVC1 NODE_CTRL [PHYSICAL_HOST_ID]
 *             [--live-probe] [--deny-kvm] [--deny-kernel] [--deny-kvm-dirty]
 *
 * --live-probe: records come from wvm_host_probe_run (R2 live binding).
 * deny_*: force UNAVAILABLE for negative admission cases (still after probe
 * or on fixture). Fixture (default) invents AVAILABLE for controlled CP tests.
 */
int main(int argc, char **argv)
{
    uint32_t node_id;
    uint64_t instance_id;
    uint64_t inventory_revision;
    uint64_t profile_generation;
    uint16_t data_ports[4];
    uint16_t service_ports[4];
    uint16_t node_control_port;
    uint16_t executor_control_port;
    struct wvm_capability_record records[8];
    struct wvm_capability_report report;
    struct wvm_node_runtime_profile profile;
    struct wvm_host_probe_result probe;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t report_bytes[65536];
    uint8_t profile_bytes[65536];
    size_t report_size = 0;
    size_t profile_size = 0;
    size_t record_count = 0;
    char caps_path[512];
    char profile_path[512];
    char digest_path[512];
    char meta_path[512];
    char error[256] = {0};
    struct timespec now;
    uint64_t observed_at;
    FILE *digest_file;
    FILE *meta_file;
    uint64_t physical_host_id;
    int live_probe = 0;
    int deny_kvm = 0;
    int deny_kernel = 0;
    int deny_kvm_dirty = 0;
    int positional = 0;
    int i;
    char *pos[12];

    memset(pos, 0, sizeof(pos));
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--live-probe") == 0) {
            live_probe = 1;
        } else if (strcmp(argv[i], "--deny-kvm") == 0) {
            deny_kvm = 1;
        } else if (strcmp(argv[i], "--deny-kernel") == 0) {
            deny_kernel = 1;
        } else if (strcmp(argv[i], "--deny-kvm-dirty") == 0) {
            deny_kvm_dirty = 1;
        } else {
            if (positional >= 12) {
                fprintf(stderr, "seed evidence: too many positional args\n");
                return 2;
            }
            pos[positional++] = argv[i];
        }
    }
    if (positional != 10 && positional != 11) {
        fprintf(stderr,
                "usage: %s STATE_DIR NODE INSTANCE INV_REV PROFILE_GEN "
                "DATA0 DATA1 SVC0 SVC1 NODE_CTRL [PHYSICAL_HOST_ID] "
                "[--live-probe] [--deny-kvm] [--deny-kernel] "
                "[--deny-kvm-dirty]\n",
                argv[0]);
        return 2;
    }
    node_id = (uint32_t)strtoul(pos[1], NULL, 10);
    instance_id = strtoull(pos[2], NULL, 10);
    inventory_revision = strtoull(pos[3], NULL, 10);
    profile_generation = strtoull(pos[4], NULL, 10);
    data_ports[0] = (uint16_t)strtoul(pos[5], NULL, 10);
    data_ports[1] = (uint16_t)strtoul(pos[6], NULL, 10);
    data_ports[2] = (uint16_t)(data_ports[0] + 50U);
    data_ports[3] = (uint16_t)(data_ports[1] + 50U);
    service_ports[0] = (uint16_t)strtoul(pos[7], NULL, 10);
    service_ports[1] = (uint16_t)strtoul(pos[8], NULL, 10);
    service_ports[2] = (uint16_t)(service_ports[0] + 50U);
    service_ports[3] = (uint16_t)(service_ports[1] + 50U);
    node_control_port = (uint16_t)strtoul(pos[9], NULL, 10);
    executor_control_port = node_control_port + 1U;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec <= 0) {
        fprintf(stderr, "seed evidence: cannot read clock\n");
        return 1;
    }
    observed_at = (uint64_t)now.tv_sec * 1000U +
                  (uint64_t)now.tv_nsec / 1000000U;

    memset(records, 0, sizeof(records));
    if (live_probe) {
        memset(&probe, 0, sizeof(probe));
        if (wvm_host_probe_run(&probe, error, sizeof(error)) != 0) {
            fprintf(stderr, "seed evidence: live probe failed: %s\n", error);
            return 1;
        }
        if (wvm_host_probe_fill_records(&probe, node_id, instance_id,
                                        instance_id, records, 8, &record_count,
                                        error, sizeof(error)) != 0 ||
            record_count == 0) {
            fprintf(stderr, "seed evidence: fill records failed: %s\n", error);
            return 1;
        }
        fprintf(stderr,
                "seed evidence: live-probe tcg=%u kvm=%u kern=%u records=%zu\n",
                (unsigned)probe.tcg_state, (unsigned)probe.kvm_state,
                (unsigned)probe.kernel_accel_state, record_count);
    } else {
        fill_capability(&records[0], WVM_CAPABILITY_ID_EXECUTION_KVM, node_id,
                        instance_id, 305, observed_at,
                        WVM_HOST_PROBE_KVM_API | WVM_HOST_PROBE_KVM_DIRTY_LOG |
                            WVM_HOST_PROBE_KVM_CREATE_VM,
                        WVM_CAPABILITY_AVAILABLE);
        fill_capability(&records[1], WVM_CAPABILITY_ID_EXECUTION_TCG, node_id,
                        instance_id, 301, observed_at + 1,
                        WVM_HOST_PROBE_TCG_SIGSEGV_MPROTECT,
                        WVM_CAPABILITY_AVAILABLE);
        fill_capability(&records[2], WVM_CAPABILITY_ID_MODE_B_MEMORY, node_id,
                        instance_id, 302, observed_at + 2, 1,
                        WVM_CAPABILITY_AVAILABLE);
        fill_capability(&records[3], WVM_CAPABILITY_ID_VM_ID_U32, node_id,
                        instance_id, 303, observed_at + 3, 1,
                        WVM_CAPABILITY_AVAILABLE);
        fill_capability(&records[4], WVM_CAPABILITY_ID_KERNEL_ACCELERATION,
                        node_id, instance_id, 304, observed_at + 4, 1,
                        WVM_CAPABILITY_AVAILABLE);
        record_count = 5;
    }

    if (deny_kvm) {
        force_state(records, record_count, WVM_CAPABILITY_ID_EXECUTION_KVM,
                    WVM_CAPABILITY_UNAVAILABLE, 0);
        /* Ensure a KVM record exists so REQUIRE_KVM sees UNAVAILABLE. */
        {
            int saw = 0;
            size_t j;
            for (j = 0; j < record_count; j++) {
                if (records[j].capability_id == WVM_CAPABILITY_ID_EXECUTION_KVM) {
                    saw = 1;
                    break;
                }
            }
            if (!saw && record_count < 8) {
                fill_capability(&records[record_count++],
                                WVM_CAPABILITY_ID_EXECUTION_KVM, node_id,
                                instance_id, 305, observed_at, 0,
                                WVM_CAPABILITY_UNAVAILABLE);
            }
        }
    }
    if (deny_kvm_dirty) {
        size_t j;
        for (j = 0; j < record_count; j++) {
            if (records[j].capability_id == WVM_CAPABILITY_ID_EXECUTION_KVM) {
                records[j].feature_bits &= ~WVM_HOST_PROBE_KVM_DIRTY_LOG;
                if (records[j].feature_bits == 0 ||
                    (records[j].feature_bits & WVM_HOST_PROBE_KVM_DIRTY_LOG) ==
                        0) {
                    /* Keep AVAILABLE but without dirty — REQUIRE_KVM must reject. */
                }
            }
        }
    }
    if (deny_kernel) {
        force_state(records, record_count, WVM_CAPABILITY_ID_KERNEL_ACCELERATION,
                    WVM_CAPABILITY_UNAVAILABLE, 0);
        {
            int saw = 0;
            size_t j;
            for (j = 0; j < record_count; j++) {
                if (records[j].capability_id ==
                    WVM_CAPABILITY_ID_KERNEL_ACCELERATION) {
                    saw = 1;
                    break;
                }
            }
            if (!saw && record_count < 8) {
                fill_capability(&records[record_count++],
                                WVM_CAPABILITY_ID_KERNEL_ACCELERATION, node_id,
                                instance_id, 304, observed_at, 0,
                                WVM_CAPABILITY_UNAVAILABLE);
            }
        }
    }

    qsort(records, record_count, sizeof(records[0]), record_compare);

    memset(&report, 0, sizeof(report));
    report.profile_generation = profile_generation;
    report.records = records;
    report.record_count = record_count;
    if (wvm_capability_profile_digest(node_id, instance_id, profile_generation,
                                      records, record_count, digest, error,
                                      sizeof(error)) != 0 ||
        wvm_capability_report_encode(&report, report_bytes,
                                     sizeof(report_bytes), &report_size, error,
                                     sizeof(error)) != 0) {
        fprintf(stderr, "seed evidence: capability encode: %s\n", error);
        return 1;
    }

    memset(&profile, 0, sizeof(profile));
    profile.physical_node_id = node_id;
    profile.node_instance_id = instance_id;
    profile.inventory_revision = inventory_revision;
    profile.capability_profile_generation = profile_generation;
    profile.runtime_profile_generation = 1;
    profile.node_runtime_control_port = node_control_port;
    profile.local_executor_control_port = executor_control_port;
    profile.executor_worker_count = 2;
    profile.sync_batch_size = 8;
    profile.vcpu_handoff_record_capacity = 32;
    profile.node_runtime_data_ports = data_ports;
    profile.node_runtime_data_port_count = 4;
    profile.local_executor_service_ports = service_ports;
    profile.local_executor_service_port_count = 4;
    physical_host_id =
        (positional == 11) ? strtoull(pos[10], NULL, 10) : node_id;
    if (physical_host_id == 0) {
        fprintf(stderr, "seed evidence: physical_host_id must be non-zero\n");
        return 1;
    }
    profile.physical_host_id = physical_host_id;
    snprintf(profile.node_instance_namespace.namespace_name,
             sizeof(profile.node_instance_namespace.namespace_name),
             "ni-%u-%llu", (unsigned)node_id, (unsigned long long)instance_id);
    memset(profile.node_instance_namespace.derivation_salt_digest, 0xa5,
           sizeof(profile.node_instance_namespace.derivation_salt_digest));
    profile.node_instance_namespace.name_generation = 1;
    if (wvm_node_runtime_profile_encode(&profile, profile_bytes,
                                        sizeof(profile_bytes), &profile_size,
                                        error, sizeof(error)) != 0) {
        fprintf(stderr, "seed evidence: profile encode: %s\n", error);
        return 1;
    }

    snprintf(caps_path, sizeof(caps_path), "%s/capabilities-%" PRIu32 ".record",
             pos[0], node_id);
    snprintf(profile_path, sizeof(profile_path),
             "%s/runtime-profile-%" PRIu32 ".record", pos[0], node_id);
    snprintf(digest_path, sizeof(digest_path), "%s/capability-profile.digest",
             pos[0]);
    snprintf(meta_path, sizeof(meta_path), "%s/seed-meta.txt", pos[0]);
    if (write_bytes(caps_path, report_bytes, report_size) != 0 ||
        write_bytes(profile_path, profile_bytes, profile_size) != 0) {
        fprintf(stderr, "seed evidence: cannot write records\n");
        return 1;
    }
    digest_file = fopen(digest_path, "w");
    if (!digest_file) {
        fprintf(stderr, "seed evidence: cannot write digest file\n");
        return 1;
    }
    for (i = 0; i < (int)sizeof(digest); i++) {
        fprintf(digest_file, "%02x", digest[i]);
    }
    fputc('\n', digest_file);
    fclose(digest_file);
    meta_file = fopen(meta_path, "w");
    if (meta_file) {
        fprintf(meta_file, "live_probe=%d\n", live_probe);
        fprintf(meta_file, "deny_kvm=%d\n", deny_kvm);
        fprintf(meta_file, "deny_kernel=%d\n", deny_kernel);
        fprintf(meta_file, "deny_kvm_dirty=%d\n", deny_kvm_dirty);
        fprintf(meta_file, "record_count=%zu\n", record_count);
        for (i = 0; i < (int)record_count; i++) {
            fprintf(meta_file, "cap id=%u state=%u bits=0x%llx\n",
                    (unsigned)records[i].capability_id,
                    (unsigned)records[i].state,
                    (unsigned long long)records[i].feature_bits);
        }
        fclose(meta_file);
    }
    print_hex(digest, sizeof(digest));
    fputc('\n', stdout);
    return 0;
}

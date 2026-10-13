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
#include "wavevm_runtime_profile.h"
#include "wavevm_sha256.h"

static void fill_capability(struct wvm_capability_record *record,
                            uint16_t capability_id, uint32_t node_id,
                            uint64_t instance_id, uint64_t provider,
                            uint64_t observed_at)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = node_id;
    record->node_instance_id = instance_id;
    record->provider_instance_id = provider;
    record->state = WVM_CAPABILITY_AVAILABLE;
    record->abi_version = 1;
    record->feature_bits = 1;
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
    struct wvm_capability_record records[4];
    struct wvm_capability_report report;
    struct wvm_node_runtime_profile profile;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t report_bytes[65536];
    uint8_t profile_bytes[65536];
    size_t report_size = 0;
    size_t profile_size = 0;
    char caps_path[512];
    char profile_path[512];
    char digest_path[512];
    char error[256] = {0};
    struct timespec now;
    uint64_t observed_at;
    FILE *digest_file;

    if (argc != 11) {
        fprintf(stderr,
                "usage: %s STATE_DIR NODE INSTANCE INV_REV PROFILE_GEN "
                "DATA0 DATA1 SVC0 SVC1 NODE_CTRL\n",
                argv[0]);
        return 2;
    }
    node_id = (uint32_t)strtoul(argv[2], NULL, 10);
    instance_id = strtoull(argv[3], NULL, 10);
    inventory_revision = strtoull(argv[4], NULL, 10);
    profile_generation = strtoull(argv[5], NULL, 10);
    data_ports[0] = (uint16_t)strtoul(argv[6], NULL, 10);
    data_ports[1] = (uint16_t)strtoul(argv[7], NULL, 10);
    /* Extra ports so concurrent VMs can hash to distinct listener leases. */
    data_ports[2] = (uint16_t)(data_ports[0] + 50U);
    data_ports[3] = (uint16_t)(data_ports[1] + 50U);
    service_ports[0] = (uint16_t)strtoul(argv[8], NULL, 10);
    service_ports[1] = (uint16_t)strtoul(argv[9], NULL, 10);
    service_ports[2] = (uint16_t)(service_ports[0] + 50U);
    service_ports[3] = (uint16_t)(service_ports[1] + 50U);
    node_control_port = (uint16_t)strtoul(argv[10], NULL, 10);
    executor_control_port = node_control_port + 1U;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec <= 0) {
        fprintf(stderr, "seed evidence: cannot read clock\n");
        return 1;
    }
    observed_at = (uint64_t)now.tv_sec * 1000U +
                  (uint64_t)now.tv_nsec / 1000000U;

    fill_capability(&records[0], WVM_CAPABILITY_ID_EXECUTION_TCG, node_id,
                    instance_id, 301, observed_at);
    fill_capability(&records[1], WVM_CAPABILITY_ID_MODE_B_MEMORY, node_id,
                    instance_id, 302, observed_at + 1);
    fill_capability(&records[2], WVM_CAPABILITY_ID_VM_ID_U32, node_id,
                    instance_id, 303, observed_at + 2);
    /* Mode A multi-context admission publishes kernel acceleration capability.
     * CREATE_VM with ACCELERATOR_DISABLED still ignores it; REQUIRE_KERNEL uses it.
     * This does not claim /dev/wavevm guest E2E. */
    fill_capability(&records[3], WVM_CAPABILITY_ID_KERNEL_ACCELERATION, node_id,
                    instance_id, 304, observed_at + 3);
    memset(&report, 0, sizeof(report));
    report.profile_generation = profile_generation;
    report.records = records;
    report.record_count = 4;
    if (wvm_capability_profile_digest(node_id, instance_id, profile_generation,
                                      records, 4, digest, error,
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
    if (wvm_node_runtime_profile_encode(&profile, profile_bytes,
                                        sizeof(profile_bytes), &profile_size,
                                        error, sizeof(error)) != 0) {
        fprintf(stderr, "seed evidence: profile encode: %s\n", error);
        return 1;
    }

    snprintf(caps_path, sizeof(caps_path), "%s/capabilities-%" PRIu32 ".record",
             argv[1], node_id);
    snprintf(profile_path, sizeof(profile_path),
             "%s/runtime-profile-%" PRIu32 ".record", argv[1], node_id);
    snprintf(digest_path, sizeof(digest_path), "%s/capability-profile.digest",
             argv[1]);
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
    for (size_t i = 0; i < sizeof(digest); i++) {
        fprintf(digest_file, "%02x", digest[i]);
    }
    fputc('\n', digest_file);
    fclose(digest_file);
    print_hex(digest, sizeof(digest));
    fputc('\n', stdout);
    return 0;
}

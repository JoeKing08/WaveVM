#include <stdio.h>
#include <string.h>

#include "wavevm_canonical.h"
#include "wavevm_capability.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "capability-record test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_capability_limit limits[2];
    struct wvm_capability_constraint constraints[1];
    struct wvm_capability_record record;
    struct wvm_capability_limit decoded_limits[2];
    struct wvm_capability_constraint decoded_constraints[1];
    struct wvm_capability_record decoded;
    struct wvm_capability_report report;
    struct wvm_capability_report decoded_report;
    struct wvm_canonical_record canonical;
    uint8_t bytes[4096];
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t repeated_profile_digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    char error[256] = {0};

    memset(limits, 0, sizeof(limits));
    limits[0].limit_kind = 1;
    limits[0].value = 4096;
    limits[1].limit_kind = 2;
    limits[1].value = 128;
    memset(constraints, 0, sizeof(constraints));
    constraints[0].constraint_kind = 1;
    constraints[0].state = 1;
    strcpy(constraints[0].detail, "mode-b-only");

    memset(&record, 0, sizeof(record));
    record.capability_id = 1;
    record.capability_schema_version = WVM_CANONICAL_SCHEMA;
    record.physical_node_id = 17;
    record.node_instance_id = 101;
    record.provider_instance_id = 2001;
    record.state = WVM_CAPABILITY_AVAILABLE;
    record.abi_version = 1;
    record.feature_bits = 0x5;
    record.limits.entries = limits;
    record.limits.count = 2;
    record.limits.capacity = 2;
    record.constraints.entries = constraints;
    record.constraints.count = 1;
    record.constraints.capacity = 1;
    record.observed_at = 1234;
    record.probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x51;

    if (expect(wvm_capability_record_encode(&record, bytes, sizeof(bytes),
                                            &encoded_bytes, error,
                                            sizeof(error)) == 0,
               "encode capability record")) {
        return 1;
    }

    memset(&decoded, 0, sizeof(decoded));
    decoded.limits.entries = decoded_limits;
    decoded.limits.capacity = 2;
    decoded.constraints.entries = decoded_constraints;
    decoded.constraints.capacity = 1;
    if (expect(wvm_capability_record_decode(bytes, encoded_bytes, &decoded,
                                            error, sizeof(error)) == 0,
               "decode capability record") ||
        expect(decoded.state == WVM_CAPABILITY_AVAILABLE &&
                   decoded.limits.count == 2 &&
                   decoded.constraints.count == 1 &&
                   decoded.limits.entries[1].value == 128,
               "round trip capability record")) {
        return 1;
    }
    if (expect(wvm_capability_profile_digest(
                   record.physical_node_id, record.node_instance_id, 7, &record,
                   1, profile_digest, error, sizeof(error)) == 0,
               "derive capability profile digest") ||
        expect(wvm_capability_profile_digest(
                   record.physical_node_id, record.node_instance_id, 7, &record,
                   1, repeated_profile_digest, error,
                   sizeof(error)) == 0 &&
                   memcmp(profile_digest, repeated_profile_digest,
                          sizeof(profile_digest)) == 0,
               "derive stable capability profile digest")) {
        return 1;
    }

    memset(&report, 0, sizeof(report));
    report.profile_generation = 7;
    report.records = &record;
    report.record_count = 1;
    if (expect(wvm_capability_report_encode(
                   &report, bytes, sizeof(bytes), &encoded_bytes, error,
                   sizeof(error)) == 0,
               "encode capability report") ||
        expect(wvm_canonical_record_parse(bytes, encoded_bytes, &canonical) ==
                   0 &&
                   canonical.record_type == WVM_RECORD_CAPABILITY_REPORT,
               "use the registered capability-report record type")) {
        return 1;
    }
    memset(&decoded_report, 0, sizeof(decoded_report));
    if (expect(wvm_capability_report_decode(
                   bytes, encoded_bytes, &decoded_report, error,
                   sizeof(error)) == 0,
               "decode capability report") ||
        expect(decoded_report.profile_generation == 7 &&
                   decoded_report.record_count == 1 &&
                   decoded_report.records[0].physical_node_id == 17 &&
                   decoded_report.records[0].node_instance_id == 101 &&
                   decoded_report.records[0].limits.count == 2 &&
                   decoded_report.records[0].limits.entries[1].value == 128 &&
                   decoded_report.records[0].constraints.count == 1,
               "round trip owned capability-report records")) {
        wvm_capability_report_destroy(&decoded_report);
        return 1;
    }
    wvm_capability_report_destroy(&decoded_report);

    limits[1].limit_kind = limits[0].limit_kind;
    if (expect(wvm_capability_record_validate(&record, error, sizeof(error)) !=
                   0,
               "reject duplicate capability limit key")) {
        return 1;
    }

    puts("capability-record tests: PASS");
    return 0;
}

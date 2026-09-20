#ifndef WAVEVM_CAPABILITY_H
#define WAVEVM_CAPABILITY_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_identity.h"

#define WVM_RECORD_CAPABILITY_LIMIT 0x1021U
#define WVM_RECORD_CAPABILITY_CONSTRAINT 0x1022U
#define WVM_RECORD_CAPABILITY_RECORD 0x1023U
#define WVM_RECORD_CAPABILITY_REPORT 0x102fU
#define WVM_CAPABILITY_REPORT_MAX_BYTES (1024U * 1024U)

#define WVM_CAPABILITY_CONSTRAINT_DETAIL_MAX_BYTES 255U

/*
 * Capability IDs identify evidence classes, not arbitrary implementation
 * names. A node is eligible for a backend only when the corresponding
 * execution capability and Mode B semantic baseline are AVAILABLE.
 */
enum wvm_capability_id {
    WVM_CAPABILITY_ID_EXECUTION_KVM = 1,
    WVM_CAPABILITY_ID_EXECUTION_TCG = 2,
    WVM_CAPABILITY_ID_MODE_B_MEMORY = 3,
    WVM_CAPABILITY_ID_VM_ID_U32 = 4,
    WVM_CAPABILITY_ID_KERNEL_ACCELERATION = 5,
};

enum wvm_capability_state {
    WVM_CAPABILITY_UNPROBED = 1,
    WVM_CAPABILITY_PROBING = 2,
    WVM_CAPABILITY_AVAILABLE = 3,
    WVM_CAPABILITY_UNAVAILABLE = 4,
    WVM_CAPABILITY_DEGRADED = 5,
};

struct wvm_capability_limit {
    uint16_t limit_kind;
    uint64_t value;
};

struct wvm_capability_limit_list {
    struct wvm_capability_limit *entries;
    size_t count;
    size_t capacity;
};

struct wvm_capability_constraint {
    uint16_t constraint_kind;
    uint16_t state;
    char detail[WVM_CAPABILITY_CONSTRAINT_DETAIL_MAX_BYTES + 1U];
};

struct wvm_capability_constraint_list {
    struct wvm_capability_constraint *entries;
    size_t count;
    size_t capacity;
};

/*
 * This is immutable evidence from one capability provider/process instance.
 * Higher-level capability profiles reference digests of selected records.
 */
struct wvm_capability_record {
    uint16_t capability_id;
    uint16_t capability_schema_version;
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t provider_instance_id;
    enum wvm_capability_state state;
    uint32_t abi_version;
    uint64_t feature_bits;
    struct wvm_capability_limit_list limits;
    struct wvm_capability_constraint_list constraints;
    uint64_t observed_at;
    uint8_t probe_operation_id[WVM_IDENTITY_ID_BYTES];
    uint16_t reason_code;
};

/* One complete profile, emitted by the registered node's probe provider. */
struct wvm_capability_report {
    uint64_t profile_generation;
    struct wvm_capability_record *records;
    size_t record_count;
};

int wvm_capability_report_encode(
    const struct wvm_capability_report *report, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len);
/* Decode owns nested storage. Initialize output to zero; free with destroy. */
int wvm_capability_report_decode(
    const uint8_t *bytes, size_t byte_count, struct wvm_capability_report *report,
    char *error, size_t error_len);
void wvm_capability_report_destroy(struct wvm_capability_report *report);

int wvm_capability_limit_validate(const struct wvm_capability_limit *limit,
                                  char *error, size_t error_len);
int wvm_capability_limit_encode(const struct wvm_capability_limit *limit,
                                uint8_t *bytes, size_t capacity,
                                size_t *encoded_bytes, char *error,
                                size_t error_len);
int wvm_capability_limit_decode(const uint8_t *bytes, size_t encoded_bytes,
                                struct wvm_capability_limit *limit,
                                char *error, size_t error_len);

int wvm_capability_constraint_validate(
    const struct wvm_capability_constraint *constraint, char *error,
    size_t error_len);
int wvm_capability_constraint_encode(
    const struct wvm_capability_constraint *constraint, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_capability_constraint_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_capability_constraint *constraint, char *error,
    size_t error_len);

int wvm_capability_record_validate(
    const struct wvm_capability_record *record, char *error, size_t error_len);
int wvm_capability_record_encode(
    const struct wvm_capability_record *record, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_capability_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_capability_record *record, char *error, size_t error_len);

/*
 * A NodeRecord's CapabilityRef points to this deterministic profile digest,
 * not to one individual probe result. The input must contain the complete
 * sorted record set for one physical-node/node-instance/profile generation.
 */
int wvm_capability_profile_digest(
    uint32_t physical_node_id, uint64_t node_instance_id,
    uint64_t profile_generation, const struct wvm_capability_record *records,
    size_t record_count, uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len);

#endif /* WAVEVM_CAPABILITY_H */

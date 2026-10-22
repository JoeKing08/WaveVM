#ifndef WAVEVM_MANIFEST_H
#define WAVEVM_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_identity.h"

#define WVM_RECORD_VM_ROUTE_SCOPE_KEY 0x1003U
#define WVM_RECORD_ROUTE_SNAPSHOT_KEY 0x1004U
#define WVM_RECORD_CAPABILITY_REF 0x1005U
#define WVM_RECORD_MEMBER_KEY 0x1002U
#define WVM_RECORD_REQUIRED_MEMBER 0x1006U
#define WVM_RECORD_VCPU_ASSIGNMENT 0x100fU
#define WVM_RECORD_MEMORY_CHUNK_ASSIGNMENT 0x1010U
#define WVM_RECORD_STORAGE_ASSIGNMENT 0x1011U
#define WVM_RECORD_EXCLUSIVE_LEASE 0x1012U
#define WVM_RECORD_PLACEMENT_PLAN 0x1014U
#define WVM_RECORD_VM_REQUEST 0x1015U
#define WVM_RECORD_MACHINE_CONFIG 0x1016U
#define WVM_RECORD_GUEST_TOPOLOGY 0x1017U
#define WVM_RECORD_EXECUTION_FAULT_PROFILE 0x1018U
#define WVM_RECORD_CONSISTENCY_POLICY 0x1019U
#define WVM_RECORD_STORAGE_DEVICE_PLAN 0x101aU
#define WVM_RECORD_LOCAL_NAME_NAMESPACE 0x101bU
#define WVM_RECORD_LIFECYCLE_POLICY 0x101cU
#define WVM_RECORD_CANDIDATE_VM_MANIFEST 0x101dU
#define WVM_RECORD_HOST_CONSTRAINT 0x1024U
#define WVM_RECORD_STARTUP_DEPENDENCY 0x1025U
#define WVM_RECORD_RESERVATION_REQUIREMENT 0x1026U

#define WVM_MANIFEST_PAGE_BYTES 4096ULL
#define WVM_MANIFEST_LEASE_NAME_MAX_BYTES 255U
#define WVM_MANIFEST_ARCH_MAX_BYTES 32U
#define WVM_MANIFEST_MACHINE_TYPE_MAX_BYTES 64U
#define WVM_MANIFEST_DISPLAY_NAME_MAX_BYTES 255U
#define WVM_MANIFEST_CONSTRAINT_SUBJECT_MAX_BYTES 128U
#define WVM_MANIFEST_CONSTRAINT_VALUE_MAX_BYTES 255U

/* Exclusive resources owned by one admitted node-runtime instance. */
#define WVM_EXCLUSIVE_LEASE_KIND_NODE_RUNTIME_DATA_UDP 1U
#define WVM_EXCLUSIVE_LEASE_KIND_LOCAL_EXECUTOR_SERVICE_UDP 2U
#define WVM_EXCLUSIVE_LEASE_KIND_KERNEL_CONTEXT 3U

enum wvm_manifest_backend {
    WVM_MANIFEST_BACKEND_KVM = 1,
    WVM_MANIFEST_BACKEND_TCG = 2,
};

enum wvm_manifest_backend_policy {
    WVM_MANIFEST_BACKEND_POLICY_AUTO = 1,
    WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM = 2,
    WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG = 3,
};

enum wvm_manifest_accelerator_policy {
    WVM_MANIFEST_ACCELERATOR_DISABLED = 1,
    WVM_MANIFEST_ACCELERATOR_PREFER_KERNEL = 2,
    WVM_MANIFEST_ACCELERATOR_REQUIRE_KERNEL = 3,
};

enum wvm_manifest_placement_policy {
    WVM_MANIFEST_PLACEMENT_COMPACT = 1,
    WVM_MANIFEST_PLACEMENT_SPREAD = 2,
};

enum wvm_manifest_host_constraint_kind {
    WVM_MANIFEST_HOST_CONSTRAINT_PHYSICAL_NODE = 1,
    WVM_MANIFEST_HOST_CONSTRAINT_FAILURE_DOMAIN = 2,
    WVM_MANIFEST_HOST_CONSTRAINT_CAPABILITY = 3,
    WVM_MANIFEST_HOST_CONSTRAINT_LABEL = 4,
};

enum wvm_manifest_host_constraint_operator {
    WVM_MANIFEST_HOST_CONSTRAINT_EQUALS = 1,
    WVM_MANIFEST_HOST_CONSTRAINT_NOT_EQUALS = 2,
};

enum wvm_manifest_guest_topology_policy {
    WVM_MANIFEST_GUEST_TOPOLOGY_FLAT = 1,
    WVM_MANIFEST_GUEST_TOPOLOGY_PLACEMENT_NUMA = 2,
    WVM_MANIFEST_GUEST_TOPOLOGY_SYNTHETIC_NUMA = 3,
};

enum wvm_manifest_role_type {
    WVM_MANIFEST_ROLE_NODE_RUNTIME = 1,
    WVM_MANIFEST_ROLE_GATEWAY = 2,
    WVM_MANIFEST_ROLE_QEMU_FRONTEND = 3,
    WVM_MANIFEST_ROLE_EXECUTOR = 4,
    WVM_MANIFEST_ROLE_KERNEL_CONTEXT = 5,
};

enum wvm_manifest_member_state {
    WVM_MANIFEST_MEMBER_PENDING = 1,
    WVM_MANIFEST_MEMBER_VALIDATING = 2,
    WVM_MANIFEST_MEMBER_PREPARED = 3,
    WVM_MANIFEST_MEMBER_ACTIVE = 4,
    WVM_MANIFEST_MEMBER_CORDONED = 5,
    WVM_MANIFEST_MEMBER_DRAINING = 6,
    WVM_MANIFEST_MEMBER_REMOVED = 7,
    WVM_MANIFEST_MEMBER_FAILED = 8,
};

enum wvm_manifest_namespace_abi {
    WVM_MANIFEST_NAMESPACE_LEGACY = WVM_NAMESPACE_ABI_LEGACY,
    WVM_MANIFEST_NAMESPACE_U32 = WVM_NAMESPACE_ABI_U32,
};

struct wvm_vm_route_scope_key {
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t route_scope_id;
};

struct wvm_route_snapshot_key {
    struct wvm_vm_route_scope_key scope_key;
    uint64_t topology_revision;
    uint64_t route_generation;
    uint8_t snapshot_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_vcpu_assignment {
    uint32_t guest_vcpu_index;
    uint32_t executor_physical_node_id;
    enum wvm_manifest_backend backend;
    uint16_t executor_class;
    uint32_t executor_slot;
    uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
};

struct wvm_memory_chunk_assignment {
    uint64_t gpa_start;
    uint64_t bytes;
    uint32_t directory_physical_node_id;
    uint32_t executor_physical_node_id;
    uint16_t consistency_policy;
    uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
};

struct wvm_storage_assignment {
    uint32_t device_index;
    uint32_t storage_physical_node_id;
    uint16_t backend_kind;
    uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t device_contract_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_exclusive_lease {
    uint16_t lease_kind;
    char lease_name[WVM_MANIFEST_LEASE_NAME_MAX_BYTES + 1U];
    uint64_t lease_generation;
};

struct wvm_exclusive_lease_list {
    struct wvm_exclusive_lease *entries;
    size_t count;
    size_t capacity;
};

struct wvm_reservation_requirement {
    uint8_t reservation_id[WVM_IDENTITY_ID_BYTES];
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t inventory_revision;
    uint32_t guest_vcpu_slots;
    uint64_t guest_memory_bytes;
    uint32_t overhead_vcpu_slots;
    uint64_t overhead_memory_bytes;
    struct wvm_exclusive_lease_list exclusive_leases;
};

struct wvm_vcpu_assignment_list {
    struct wvm_vcpu_assignment *entries;
    size_t count;
    size_t capacity;
};

struct wvm_memory_chunk_assignment_list {
    struct wvm_memory_chunk_assignment *entries;
    size_t count;
    size_t capacity;
};

struct wvm_storage_assignment_list {
    struct wvm_storage_assignment *entries;
    size_t count;
    size_t capacity;
};

struct wvm_reservation_requirement_list {
    struct wvm_reservation_requirement *entries;
    size_t count;
    size_t capacity;
};

struct wvm_guest_topology {
    enum wvm_manifest_guest_topology_policy topology_policy;
    uint32_t guest_numa_nodes;
    int has_topology_layout_digest;
    uint8_t topology_layout_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_placement_plan {
    uint8_t plan_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t admission_tx_id[WVM_IDENTITY_ID_BYTES];
    uint8_t eligibility_fence_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t inventory_revision;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t capability_profile_generation;
    uint32_t host_node;
    struct wvm_vcpu_assignment_list vcpu_assignments;
    struct wvm_memory_chunk_assignment_list memory_assignments;
    struct wvm_storage_assignment_list storage_assignments;
    struct wvm_reservation_requirement_list reservation_requirements;
    struct wvm_guest_topology guest_topology;
    struct wvm_vm_route_scope_key route_scope_key;
};

struct wvm_member_key {
    enum wvm_manifest_role_type role_type;
    uint32_t role_id;
    uint64_t instance_id;
};

struct wvm_capability_ref {
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t profile_generation;
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_capability_ref_list {
    struct wvm_capability_ref *entries;
    size_t count;
    size_t capacity;
};

struct wvm_required_member {
    struct wvm_member_key member_key;
    uint32_t physical_node_id;
    uint64_t failure_domain_id;
    struct wvm_capability_ref capability;
    enum wvm_manifest_member_state required_state;
};

struct wvm_required_member_list {
    struct wvm_required_member *entries;
    size_t count;
    size_t capacity;
};

struct wvm_machine_config {
    char architecture[WVM_MANIFEST_ARCH_MAX_BYTES + 1U];
    char machine_type[WVM_MANIFEST_MACHINE_TYPE_MAX_BYTES + 1U];
    uint32_t qemu_compat_version;
    uint16_t firmware_policy;
};

struct wvm_execution_fault_profile {
    enum wvm_manifest_backend backend;
    uint32_t context_schema_version;
    uint16_t dirty_capture_engine;
    uint16_t read_fault_engine;
    uint16_t invalidation_engine;
    uint64_t kernel_accelerator_bits;
    struct wvm_capability_ref_list per_node_capabilities;
    uint8_t supported_memory_policies_digest[WVM_SHA256_DIGEST_BYTES];
    uint16_t fallback_decision;
};

struct wvm_consistency_policy {
    uint32_t dirty_batch_size;
    uint16_t handoff_commit_policy;
    uint16_t subscriber_delivery_policy;
    uint64_t max_commit_latency_ms;
};

struct wvm_storage_device_plan {
    struct wvm_storage_assignment_list assignments;
    uint8_t qemu_device_configuration_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_lifecycle_policy {
    uint16_t start_policy;
    uint16_t failure_policy;
    uint64_t completion_query_horizon_ms;
    uint64_t route_retention_horizon_ms;
};

struct wvm_host_constraint {
    enum wvm_manifest_host_constraint_kind constraint_kind;
    enum wvm_manifest_host_constraint_operator comparison_operator;
    char subject[WVM_MANIFEST_CONSTRAINT_SUBJECT_MAX_BYTES + 1U];
    char value[WVM_MANIFEST_CONSTRAINT_VALUE_MAX_BYTES + 1U];
};

struct wvm_host_constraint_list {
    struct wvm_host_constraint *entries;
    size_t count;
    size_t capacity;
};

struct wvm_vm_request {
    uint16_t api_version;
    uint8_t request_id[WVM_IDENTITY_ID_BYTES];
    int has_display_name;
    char display_name[WVM_MANIFEST_DISPLAY_NAME_MAX_BYTES + 1U];
    uint32_t requested_vcpus;
    uint64_t requested_memory_bytes;
    enum wvm_manifest_backend_policy execution_backend_policy;
    enum wvm_manifest_accelerator_policy accelerator_policy;
    enum wvm_manifest_placement_policy placement_policy;
    struct wvm_host_constraint_list host_constraints;
    enum wvm_manifest_guest_topology_policy guest_topology_policy;
    struct wvm_consistency_policy consistency_policy;
    struct wvm_storage_device_plan storage_device_plan;
    struct wvm_lifecycle_policy lifecycle_policy;
};

struct wvm_candidate_vm_manifest {
    uint8_t manifest_id[WVM_IDENTITY_ID_BYTES];
    uint16_t manifest_schema_version;
    uint8_t manifest_digest[WVM_SHA256_DIGEST_BYTES];
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t request_id[WVM_IDENTITY_ID_BYTES];
    uint8_t admission_tx_id[WVM_IDENTITY_ID_BYTES];
    uint8_t eligibility_fence_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t candidate_created_at;
    struct wvm_machine_config guest_machine;
    struct wvm_guest_topology guest_topology;
    struct wvm_execution_fault_profile execution_plan;
    struct wvm_consistency_policy consistency_policy;
    struct wvm_storage_device_plan storage_device_plan;
    uint32_t host_node;
    struct wvm_vcpu_assignment_list vcpu_placements;
    struct wvm_memory_chunk_assignment_list memory_placements;
    struct wvm_required_member_list required_members;
    struct wvm_capability_ref_list required_capabilities;
    struct wvm_reservation_requirement_list reservation_requirements;
    struct wvm_vm_route_scope_key route_scope_key;
    struct wvm_route_snapshot_key prepared_route_snapshot_key;
    uint8_t plan_digest[WVM_SHA256_DIGEST_BYTES];
    struct wvm_local_name_namespace local_name_namespace;
    struct wvm_lifecycle_policy lifecycle_policy;
    enum wvm_manifest_namespace_abi namespace_abi;
};

int wvm_vm_route_scope_key_validate(
    const struct wvm_vm_route_scope_key *scope_key, char *error,
    size_t error_len);

int wvm_vm_route_scope_key_encode(
    const struct wvm_vm_route_scope_key *scope_key, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_vm_route_scope_key_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_vm_route_scope_key *scope_key, char *error, size_t error_len);

int wvm_route_snapshot_key_validate(
    const struct wvm_route_snapshot_key *snapshot_key, char *error,
    size_t error_len);

int wvm_route_snapshot_key_encode(
    const struct wvm_route_snapshot_key *snapshot_key, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_route_snapshot_key_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_route_snapshot_key *snapshot_key, char *error,
    size_t error_len);

int wvm_local_name_namespace_encode(
    const struct wvm_local_name_namespace *namespace_value, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_local_name_namespace_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_local_name_namespace *namespace_value, char *error,
    size_t error_len);

int wvm_vcpu_assignment_validate(
    const struct wvm_vcpu_assignment *assignment, char *error,
    size_t error_len);

int wvm_vcpu_assignment_encode(
    const struct wvm_vcpu_assignment *assignment, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_vcpu_assignment_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_vcpu_assignment *assignment, char *error, size_t error_len);

int wvm_memory_chunk_assignment_validate(
    const struct wvm_memory_chunk_assignment *assignment, char *error,
    size_t error_len);

int wvm_memory_chunk_assignment_encode(
    const struct wvm_memory_chunk_assignment *assignment, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_memory_chunk_assignment_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_memory_chunk_assignment *assignment, char *error,
    size_t error_len);

int wvm_storage_assignment_validate(
    const struct wvm_storage_assignment *assignment, char *error,
    size_t error_len);

int wvm_storage_assignment_encode(
    const struct wvm_storage_assignment *assignment, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_storage_assignment_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_assignment *assignment, char *error, size_t error_len);

int wvm_exclusive_lease_validate(const struct wvm_exclusive_lease *lease,
                                 char *error, size_t error_len);

int wvm_exclusive_lease_encode(const struct wvm_exclusive_lease *lease,
                               uint8_t *bytes, size_t capacity,
                               size_t *encoded_bytes, char *error,
                               size_t error_len);

int wvm_exclusive_lease_decode(const uint8_t *bytes, size_t encoded_bytes,
                               struct wvm_exclusive_lease *lease, char *error,
                               size_t error_len);

int wvm_reservation_requirement_validate(
    const struct wvm_reservation_requirement *requirement, char *error,
    size_t error_len);

int wvm_reservation_requirement_encode(
    const struct wvm_reservation_requirement *requirement, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);

int wvm_reservation_requirement_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_reservation_requirement *requirement, char *error,
    size_t error_len);

int wvm_guest_topology_validate(const struct wvm_guest_topology *topology,
                                char *error, size_t error_len);

int wvm_guest_topology_encode(const struct wvm_guest_topology *topology,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len);

int wvm_guest_topology_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_guest_topology *topology,
                              char *error, size_t error_len);

/*
 * Encoding always calculates the V1 self-digest.  If plan->plan_digest is
 * nonzero, it must equal the result.  The final digest is returned separately
 * so a caller can persist it before deriving reservations or a candidate.
 */
int wvm_placement_plan_validate(const struct wvm_placement_plan *plan,
                                char *error, size_t error_len);

int wvm_placement_plan_encode(const struct wvm_placement_plan *plan,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes,
                              uint8_t plan_digest[WVM_SHA256_DIGEST_BYTES],
                              char *error, size_t error_len);

int wvm_placement_plan_decode(
    const uint8_t *bytes, size_t encoded_bytes, struct wvm_placement_plan *plan,
    char *error, size_t error_len);

int wvm_member_key_validate(const struct wvm_member_key *member_key,
                            char *error, size_t error_len);
int wvm_member_key_encode(const struct wvm_member_key *member_key,
                          uint8_t *bytes, size_t capacity,
                          size_t *encoded_bytes, char *error, size_t error_len);
int wvm_member_key_decode(const uint8_t *bytes, size_t encoded_bytes,
                          struct wvm_member_key *member_key, char *error,
                          size_t error_len);

int wvm_capability_ref_validate(const struct wvm_capability_ref *capability,
                                char *error, size_t error_len);
int wvm_capability_ref_encode(const struct wvm_capability_ref *capability,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len);
int wvm_capability_ref_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_capability_ref *capability,
                              char *error, size_t error_len);

int wvm_required_member_validate(const struct wvm_required_member *member,
                                 char *error, size_t error_len);
int wvm_required_member_encode(const struct wvm_required_member *member,
                               uint8_t *bytes, size_t capacity,
                               size_t *encoded_bytes, char *error,
                               size_t error_len);
int wvm_required_member_decode(const uint8_t *bytes, size_t encoded_bytes,
                               struct wvm_required_member *member,
                               char *error, size_t error_len);

int wvm_machine_config_validate(const struct wvm_machine_config *config,
                                char *error, size_t error_len);
int wvm_machine_config_encode(const struct wvm_machine_config *config,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len);
int wvm_machine_config_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_machine_config *config, char *error,
                              size_t error_len);

int wvm_execution_fault_profile_validate(
    const struct wvm_execution_fault_profile *profile, char *error,
    size_t error_len);
int wvm_execution_fault_profile_encode(
    const struct wvm_execution_fault_profile *profile, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_execution_fault_profile_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_execution_fault_profile *profile, char *error, size_t error_len);

int wvm_consistency_policy_validate(
    const struct wvm_consistency_policy *policy, char *error, size_t error_len);
int wvm_consistency_policy_encode(
    const struct wvm_consistency_policy *policy, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len);
int wvm_consistency_policy_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_consistency_policy *policy, char *error, size_t error_len);

int wvm_storage_device_plan_validate(
    const struct wvm_storage_device_plan *plan, char *error, size_t error_len);
int wvm_storage_device_plan_encode(
    const struct wvm_storage_device_plan *plan, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len);
int wvm_storage_device_plan_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_storage_device_plan *plan, char *error, size_t error_len);

/*
 * R02: when CREATE_VM carries a qemu device-config digest but no device
 * assignments, synthesize one local disk template (device_index=0,
 * backend_kind=1, contract digest = qemu digest). Intentionally empty plans
 * with a zero digest remain empty. STORAGE_PHYSICAL_NODE_ID 0 means "place on
 * VM host" for the admission planner.
 */
int wvm_storage_device_plan_ensure_default_local(
    struct wvm_storage_device_plan *plan, char *error, size_t error_len);

int wvm_lifecycle_policy_validate(
    const struct wvm_lifecycle_policy *policy, char *error, size_t error_len);
int wvm_lifecycle_policy_encode(
    const struct wvm_lifecycle_policy *policy, uint8_t *bytes, size_t capacity,
    size_t *encoded_bytes, char *error, size_t error_len);
int wvm_lifecycle_policy_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_lifecycle_policy *policy, char *error, size_t error_len);

int wvm_host_constraint_validate(
    const struct wvm_host_constraint *constraint, char *error,
    size_t error_len);
int wvm_host_constraint_encode(
    const struct wvm_host_constraint *constraint, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_host_constraint_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_host_constraint *constraint, char *error, size_t error_len);

int wvm_vm_request_validate(const struct wvm_vm_request *request, char *error,
                            size_t error_len);
int wvm_vm_request_encode(const struct wvm_vm_request *request, uint8_t *bytes,
                          size_t capacity, size_t *encoded_bytes, char *error,
                          size_t error_len);
int wvm_vm_request_decode(const uint8_t *bytes, size_t encoded_bytes,
                          struct wvm_vm_request *request, char *error,
                          size_t error_len);

int wvm_candidate_vm_manifest_validate(
    const struct wvm_candidate_vm_manifest *candidate, char *error,
    size_t error_len);
int wvm_candidate_vm_manifest_matches_plan(
    const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_placement_plan *plan, char *error, size_t error_len);
int wvm_candidate_vm_manifest_encode(
    const struct wvm_candidate_vm_manifest *candidate, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes,
    uint8_t manifest_digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len);
int wvm_candidate_vm_manifest_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_candidate_vm_manifest *candidate, char *error, size_t error_len);

#endif /* WAVEVM_MANIFEST_H */

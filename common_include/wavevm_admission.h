#ifndef WAVEVM_ADMISSION_H
#define WAVEVM_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_config.h"
#include "wavevm_manifest.h"

#define WVM_ADMISSION_ID_BYTES 16U
#define WVM_ADMISSION_PAGE_BYTES 4096ULL

enum wvm_admission_member_state {
    WVM_ADMISSION_MEMBER_PENDING = 1,
    WVM_ADMISSION_MEMBER_VALIDATING = 2,
    WVM_ADMISSION_MEMBER_PREPARED = 3,
    WVM_ADMISSION_MEMBER_ACTIVE = 4,
    WVM_ADMISSION_MEMBER_CORDONED = 5,
    WVM_ADMISSION_MEMBER_DRAINING = 6,
    WVM_ADMISSION_MEMBER_REMOVED = 7,
    WVM_ADMISSION_MEMBER_FAILED = 8,
};

enum wvm_admission_health_state {
    WVM_ADMISSION_HEALTHY = 1,
    WVM_ADMISSION_SUSPECT = 2,
    WVM_ADMISSION_UNREACHABLE = 3,
    WVM_ADMISSION_RECOVERING = 4,
};

enum wvm_admission_backend {
    WVM_ADMISSION_BACKEND_KVM = 1,
    WVM_ADMISSION_BACKEND_TCG = 2,
};

#define WVM_ADMISSION_BACKEND_CAP_KVM (1U << 0)
#define WVM_ADMISSION_BACKEND_CAP_TCG (1U << 1)

/*
 * A memory-only participant serves the Mode B page protocol without hosting
 * a vCPU executor. Keep this separate from KVM/TCG execution capabilities.
 */
#define WVM_ADMISSION_RUNTIME_CAP_MODE_B_MEMORY (1U << 0)

enum wvm_admission_placement_policy {
    WVM_ADMISSION_PLACEMENT_COMPACT = 1,
    WVM_ADMISSION_PLACEMENT_SPREAD = 2,
};

/*
 * This is a read-only, captured control-plane inventory.  It intentionally
 * does not reuse legacy NODE/vnode configuration: physical resource identity,
 * endpoint topology, and legacy DHT weight are separate concerns.
 */
struct wvm_admission_node {
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t inventory_revision;
    enum wvm_admission_member_state membership_state;
    enum wvm_admission_health_state health_state;
    uint32_t backend_capabilities;
    uint32_t runtime_capabilities;
    uint32_t registered_vcpu_slots;
    uint64_t registered_memory_bytes;
    uint32_t reserved_host_vcpu_slots;
    uint64_t reserved_host_memory_bytes;
    uint32_t reserved_gateway_vcpu_slots;
    uint64_t reserved_gateway_memory_bytes;
    uint32_t allocatable_vcpu_slots;
    uint64_t allocatable_memory_bytes;
    uint32_t prepared_vcpu_slots;
    uint64_t prepared_memory_bytes;
    uint32_t committed_vcpu_slots;
    uint64_t committed_memory_bytes;
};

struct wvm_admission_snapshot {
    uint64_t inventory_revision;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t capability_profile_generation;
    uint32_t node_count;
    uint32_t node_capacity;
    struct wvm_admission_node *nodes;
};

/*
 * A normalized request is already backend-resolved.  AUTO, KVM preference,
 * and host policy resolution belong to the coordinator before it asks this
 * validator to assess one proposed plan.
 */
struct wvm_admission_request {
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    enum wvm_admission_backend backend;
    enum wvm_admission_placement_policy placement_policy;
    uint32_t requested_vcpu_slots;
    uint64_t requested_memory_bytes;
    uint64_t memory_chunk_bytes;
    uint32_t host_overhead_vcpu_slots;
    uint64_t host_overhead_memory_bytes;
};

/*
 * One entry is the exact pre-activation reservation for one physical member.
 * The admission transaction and each expected instance/revision prevent a
 * prepared plan from being consumed after membership or inventory changes.
 */
struct wvm_admission_reservation {
    uint32_t physical_node_id;
    uint64_t expected_node_instance_id;
    uint64_t expected_inventory_revision;
    uint32_t guest_vcpu_slots;
    uint64_t guest_memory_bytes;
    uint32_t host_overhead_vcpu_slots;
    uint64_t host_overhead_memory_bytes;
};

struct wvm_admission_plan {
    uint8_t admission_tx_id[WVM_ADMISSION_ID_BYTES];
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t capability_profile_generation;
    uint32_t host_physical_node_id;
    uint32_t reservation_count;
    uint32_t reservation_capacity;
    struct wvm_admission_reservation *reservations;
};

/*
 * Controller-provided listener identity for one selected node. The lease
 * entries are caller-owned output storage; placement only fills them from
 * these admitted ports and never chooses a port range itself.
 */
struct wvm_admission_node_listener_plan {
    uint32_t physical_node_id;
    uint64_t expected_node_instance_id;
    uint16_t node_runtime_data_port;
    uint16_t local_executor_service_port;
    int kernel_accelerator_required;
    uint64_t lease_generation;
    struct wvm_exclusive_lease *lease_entries;
    size_t lease_capacity;
};

/*
 * The planner receives its route/fence identity from the control-plane
 * transaction.  It does not infer either from a gateway map or a launcher.
 */
struct wvm_admission_placement_options {
    uint16_t memory_consistency_policy;
    enum wvm_manifest_guest_topology_policy guest_topology_policy;
    uint32_t guest_numa_nodes;
    uint16_t executor_class;
    int kernel_accelerator_required;
    struct wvm_vm_route_scope_key route_scope_key;
    const struct wvm_admission_node_listener_plan *listener_plans;
    size_t listener_plan_count;
};

/*
 * Initialize snapshot with given initial capacity for nodes array.
 * Returns 0 on success, -1 on allocation failure.
 */
int wvm_admission_snapshot_init(struct wvm_admission_snapshot *snapshot,
                                uint32_t initial_capacity);

/*
 * Free dynamically allocated nodes array. Safe to call multiple times.
 */
void wvm_admission_snapshot_cleanup(struct wvm_admission_snapshot *snapshot);

/*
 * Create an independent deep copy of a snapshot, allocating new nodes array.
 * Release an existing destination before replacing it. Self-copy is a no-op.
 * Returns 0 on success, -1 on invalid input or allocation failure; failure
 * leaves the destination unchanged.
 */
int wvm_admission_snapshot_copy(const struct wvm_admission_snapshot *src,
                                struct wvm_admission_snapshot *dst);

int wvm_admission_snapshot_validate(const struct wvm_admission_snapshot *snapshot,
                                    char *error, size_t error_len);

int wvm_admission_request_validate(const struct wvm_admission_request *request,
                                   char *error, size_t error_len);

int wvm_admission_plan_validate(const struct wvm_admission_snapshot *snapshot,
                                const struct wvm_admission_request *request,
                                const struct wvm_admission_plan *plan,
                                char *error, size_t error_len);

/*
 * Select a complete resource reservation plan from one immutable snapshot.
 * The caller owns admission_tx_id; retries must use the same ID only while
 * the snapshot/fence remains valid.
 */
/*
 * On success, transfers an allocated reservation array to PLAN. The caller
 * releases it before reusing a successful output. Failure leaves PLAN intact.
 */
int wvm_admission_plan_propose(
    const struct wvm_admission_snapshot *snapshot,
    const struct wvm_admission_request *request,
    const uint8_t admission_tx_id[WVM_ADMISSION_ID_BYTES],
    struct wvm_admission_plan *plan, char *error, size_t error_len);

/*
 * Materialize the deterministic proposal into the canonical placement plan.
 * The eligibility-fence digest must be the digest of the selected members
 * from this proposal; the planner never invents a fence or route scope.
 * The output list buffers and capacities are supplied by the caller.
 */
int wvm_admission_placement_plan_build(
    const struct wvm_admission_snapshot *snapshot,
    const struct wvm_admission_request *request,
    const struct wvm_admission_plan *admission_plan,
    const uint8_t eligibility_fence_digest[WVM_SHA256_DIGEST_BYTES],
    const struct wvm_admission_placement_options *options,
    struct wvm_placement_plan *placement_plan, char *error,
    size_t error_len);

#endif /* WAVEVM_ADMISSION_H */

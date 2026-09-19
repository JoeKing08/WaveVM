#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_control_plane.h"
#include "wavevm_coordinator.h"
#include "wavevm_admission_orchestrator.h"
#include "wavevm_admission_receiver.h"
#include "wavevm_membership.h"
#include "wavevm_reservation_runtime.h"
#include "wavevm_runtime_names.h"

#define MIB (1024ULL * 1024ULL)

static int fail_fsync_after = -1;
static int fail_write_fd = -1;
static size_t write_budget;
ssize_t __real_write(int fd, const void *bytes, size_t count);
ssize_t __wrap_write(int fd, const void *bytes, size_t count)
{
    ssize_t result;

    if (fd != fail_write_fd) {
        return __real_write(fd, bytes, count);
    }
    if (write_budget == 0) {
        errno = EIO;
        return -1;
    }
    if (count > write_budget) {
        count = write_budget;
    }
    result = __real_write(fd, bytes, count);
    if (result > 0) {
        write_budget -= (size_t)result;
    }
    return result;
}

int __real_fsync(int fd);
int __wrap_fsync(int fd)
{
    if (fail_fsync_after == 0) {
        fail_fsync_after = -1;
        errno = EIO;
        return -1;
    }
    if (fail_fsync_after > 0) {
        fail_fsync_after--;
    }
    return __real_fsync(fd);
}

#include "../../ctl_tool/admission_workspace.h"

struct id_provider_context {
    uint8_t next_id;
    uint64_t next_route_scope_id;
};

struct prepared_buffers {
    struct wvm_required_member selected_members[4];
    struct wvm_vcpu_assignment vcpus[4];
    struct wvm_memory_chunk_assignment memory[4];
    struct wvm_reservation_requirement requirements[4];
    struct wvm_capability_ref required_capabilities[4];
    struct wvm_resource_reservation reservations[4];
    struct wvm_node_runtime_manifest runtimes[4];
    struct wvm_vcpu_assignment local_vcpus[4][4];
    struct wvm_memory_chunk_assignment local_memory[4][4];
    struct wvm_startup_dependency dependencies[4][4];
    struct wvm_exclusive_lease listener_leases[4][3];
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "coordinator test: %s\n", message);
        return -1;
    }
    return 0;
}

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 10;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_capability(struct wvm_capability_record *record,
                            uint16_t capability_id, uint32_t node_id,
                            uint64_t node_instance, uint64_t provider)
{
    memset(record, 0, sizeof(*record));
    record->capability_id = capability_id;
    record->capability_schema_version = WVM_CANONICAL_SCHEMA;
    record->physical_node_id = node_id;
    record->node_instance_id = node_instance;
    record->provider_instance_id = provider;
    record->state = WVM_CAPABILITY_AVAILABLE;
    record->abi_version = 1;
    record->observed_at = 1;
    record->probe_operation_id[WVM_IDENTITY_ID_BYTES - 1] =
        (uint8_t)provider;
}

static int refresh_node_profile(struct wvm_node_record *node,
                                struct wvm_capability_record *capabilities,
                                size_t capability_count)
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    if (wvm_capability_profile_digest(
            node->physical_node_id, node->node_instance_id,
            node->capability.profile_generation, capabilities, capability_count,
            digest, NULL, 0) != 0) {
        return -1;
    }
    memcpy(node->capability.profile_digest, digest,
           sizeof(node->capability.profile_digest));
    return 0;
}

static int fill_node(struct wvm_node_record *node, uint32_t node_id,
                     uint64_t node_instance, uint64_t failure_domain,
                     struct wvm_capability_record *capabilities,
                     size_t capability_count, uint32_t *gateway_ids,
                     size_t gateway_id_count)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = node_id;
    node->node_instance_id = node_instance;
    node->failure_domain_id = failure_domain;
    fill_endpoint(&node->control_endpoint, (uint8_t)node_id,
                  (uint16_t)(9000 + node_id), (uint16_t)(9100 + node_id));
    fill_endpoint(&node->sidecar_endpoint, (uint8_t)node_id,
                  (uint16_t)(9200 + node_id), (uint16_t)(9300 + node_id));
    node->role_bits = 1;
    node->local_vnode_first = node_id * 16;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = node_id;
    node->inventory.node_instance_id = node_instance;
    node->inventory.failure_domain_id = failure_domain;
    node->inventory.inventory_revision = 7;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * MIB;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = MIB;
    node->inventory.reserved_gateway_cpu_slots = gateway_id_count ? 1 : 0;
    node->inventory.reserved_gateway_memory_bytes = gateway_id_count ? MIB : 0;
    node->inventory.hosted_gateway_role_ids = gateway_ids;
    node->inventory.hosted_gateway_role_id_count = gateway_id_count;
    node->inventory.hosted_gateway_role_id_capacity = gateway_id_count;
    node->inventory.allocatable_vcpu_slots = gateway_id_count ? 6 : 7;
    node->inventory.allocatable_memory_bytes = gateway_id_count ? 14 * MIB
                                                                : 15 * MIB;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = node_id;
    node->capability.node_instance_id = node_instance;
    node->capability.profile_generation = 9;
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = 1;
    node->membership_revision = 5;
    node->topology_revision = 6;
    return refresh_node_profile(node, capabilities, capability_count);
}

static void admission_node_from_record(struct wvm_admission_node *admission,
                                       const struct wvm_node_record *record)
{
    memset(admission, 0, sizeof(*admission));
    admission->physical_node_id = record->physical_node_id;
    admission->node_instance_id = record->node_instance_id;
    admission->inventory_revision = record->inventory.inventory_revision;
    admission->allocatable_vcpu_slots =
        record->inventory.allocatable_vcpu_slots;
    admission->allocatable_memory_bytes =
        record->inventory.allocatable_memory_bytes;
}

static void fill_request(struct wvm_vm_request *request)
{
    memset(request, 0, sizeof(*request));
    request->api_version = WVM_CANONICAL_SCHEMA;
    request->request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x42;
    request->requested_vcpus = 2;
    request->requested_memory_bytes = 4 * MIB;
    request->execution_backend_policy = WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG;
    request->accelerator_policy = WVM_MANIFEST_ACCELERATOR_DISABLED;
    request->placement_policy = WVM_MANIFEST_PLACEMENT_SPREAD;
    request->guest_topology_policy = WVM_MANIFEST_GUEST_TOPOLOGY_FLAT;
    request->consistency_policy.dirty_batch_size = 1;
    request->consistency_policy.handoff_commit_policy = 1;
    request->consistency_policy.subscriber_delivery_policy = 1;
    request->consistency_policy.max_commit_latency_ms = 1000;
    memset(request->storage_device_plan.qemu_device_configuration_digest, 0x71,
           sizeof(request->storage_device_plan.qemu_device_configuration_digest));
    request->lifecycle_policy.start_policy = 1;
    request->lifecycle_policy.failure_policy = 1;
    request->lifecycle_policy.completion_query_horizon_ms = 5000;
    request->lifecycle_policy.route_retention_horizon_ms = 6000;
}

static void fill_options(
    struct wvm_coordinator_prepare_options *options,
    struct wvm_capability_ref profile_capabilities[2], uint8_t *placement_bytes,
    size_t placement_bytes_capacity, uint8_t *candidate_bytes,
    size_t candidate_bytes_capacity)
{
    memset(options, 0, sizeof(*options));
    strcpy(options->guest_machine.architecture, "x86_64");
    strcpy(options->guest_machine.machine_type, "pc-i440fx-5.2");
    options->guest_machine.qemu_compat_version = 502;
    options->guest_machine.firmware_policy = 1;
    options->execution_profile.backend = WVM_MANIFEST_BACKEND_TCG;
    options->execution_profile.context_schema_version = 1;
    options->execution_profile.dirty_capture_engine = 1;
    options->execution_profile.read_fault_engine = 1;
    options->execution_profile.invalidation_engine = 1;
    options->execution_profile.per_node_capabilities.entries =
        profile_capabilities;
    options->execution_profile.per_node_capabilities.count = 2;
    options->execution_profile.per_node_capabilities.capacity = 2;
    memset(options->execution_profile.supported_memory_policies_digest, 0x81,
           sizeof(options->execution_profile.supported_memory_policies_digest));
    options->execution_profile.fallback_decision = 1;
    options->memory_chunk_bytes = 2 * MIB;
    options->host_overhead_vcpu_slots = 1;
    options->host_overhead_memory_bytes = MIB;
    options->memory_consistency_policy = 1;
    options->guest_numa_nodes = 1;
    options->executor_class = 1;
    options->node_runtime_role_bits = 1;
    options->host_extra_role_bits = 2;
    options->candidate_created_at = 1;
    options->prepared_reservation_expiry_unix_time_ms = 1000;
    options->placement_plan_bytes = placement_bytes;
    options->placement_plan_bytes_capacity = placement_bytes_capacity;
    options->candidate_manifest_bytes = candidate_bytes;
    options->candidate_manifest_bytes_capacity = candidate_bytes_capacity;
}

static void fill_node_launch_plans(
    struct wvm_coordinator_prepare_options *options,
    struct wvm_coordinator_node_launch_plan launch_plans[2],
    const struct wvm_node_record nodes[2],
    struct wvm_admission_node_listener_plan listener_plans[2],
    struct wvm_exclusive_lease listener_leases[2][3])
{
    size_t i;

    memset(launch_plans, 0, 2 * sizeof(*launch_plans));
    memset(listener_plans, 0, 2 * sizeof(*listener_plans));
    memset(listener_leases, 0, 2 * sizeof(*listener_leases));
    for (i = 0; i < 2; i++) {
        struct wvm_node_runtime_launch_plan *launch_plan =
            &launch_plans[i].launch_plan;

        launch_plans[i].physical_node_id = nodes[i].physical_node_id;
        launch_plans[i].expected_node_instance_id = nodes[i].node_instance_id;
        launch_plan->plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
        launch_plan->node_runtime_data_port = (uint16_t)(19100 + i * 100);
        launch_plan->node_runtime_control_port = (uint16_t)(19121 + i * 100);
        launch_plan->local_executor_service_port =
            (uint16_t)(19105 + i * 100);
        launch_plan->local_executor_control_port =
            launch_plan->node_runtime_control_port;
        launch_plan->executor_worker_count = 1;
        launch_plan->vcpu_handoff_record_capacity = 16;
        launch_plan->sync_batch_size = 1;
        launch_plan->guest_total_memory_bytes = 4 * MIB;
        launch_plan->guest_machine = options->guest_machine;
        launch_plan->consistency_policy.dirty_batch_size = 1;
        launch_plan->consistency_policy.handoff_commit_policy = 1;
        launch_plan->consistency_policy.subscriber_delivery_policy = 1;
        launch_plan->consistency_policy.max_commit_latency_ms = 1000;
        listener_plans[i].physical_node_id = nodes[i].physical_node_id;
        listener_plans[i].expected_node_instance_id = nodes[i].node_instance_id;
        listener_plans[i].node_runtime_data_port =
            launch_plan->node_runtime_data_port;
        listener_plans[i].local_executor_service_port =
            launch_plan->local_executor_service_port;
        listener_plans[i].kernel_accelerator_required =
            options->execution_profile.kernel_accelerator_bits != 0;
        listener_plans[i].lease_generation = nodes[i].node_instance_id;
        listener_plans[i].lease_entries = listener_leases[i];
        listener_plans[i].lease_capacity = 3;
    }
    options->node_launch_plans = launch_plans;
    options->node_launch_plan_count = 2;
    options->node_listener_plans = listener_plans;
    options->node_listener_plan_count = 2;
}

static void initialize_prepared_vm(struct wvm_coordinator_prepared_vm *prepared,
                                   struct prepared_buffers *buffers)
{
    size_t i;

    wvm_coordinator_prepared_vm_cleanup(prepared);
    memset(prepared, 0, sizeof(*prepared));
    prepared->fence.selected_members.entries = buffers->selected_members;
    prepared->fence.selected_members.capacity =
        sizeof(buffers->selected_members) / sizeof(buffers->selected_members[0]);
    prepared->placement_plan.vcpu_assignments.entries = buffers->vcpus;
    prepared->placement_plan.vcpu_assignments.capacity =
        sizeof(buffers->vcpus) / sizeof(buffers->vcpus[0]);
    prepared->placement_plan.memory_assignments.entries = buffers->memory;
    prepared->placement_plan.memory_assignments.capacity =
        sizeof(buffers->memory) / sizeof(buffers->memory[0]);
    prepared->placement_plan.reservation_requirements.entries =
        buffers->requirements;
    prepared->placement_plan.reservation_requirements.capacity =
        sizeof(buffers->requirements) / sizeof(buffers->requirements[0]);
    prepared->candidate.required_capabilities.entries =
        buffers->required_capabilities;
    prepared->candidate.required_capabilities.capacity =
        sizeof(buffers->required_capabilities) /
        sizeof(buffers->required_capabilities[0]);
    prepared->reservations = buffers->reservations;
    prepared->reservation_capacity =
        sizeof(buffers->reservations) / sizeof(buffers->reservations[0]);
    prepared->node_runtime_manifests = buffers->runtimes;
    prepared->node_runtime_manifest_capacity =
        sizeof(buffers->runtimes) / sizeof(buffers->runtimes[0]);
    for (i = 0; i < prepared->node_runtime_manifest_capacity; i++) {
        prepared->node_runtime_manifests[i].local_vcpu_assignments.entries =
            buffers->local_vcpus[i];
        prepared->node_runtime_manifests[i].local_vcpu_assignments.capacity =
            sizeof(buffers->local_vcpus[i]) /
            sizeof(buffers->local_vcpus[i][0]);
        prepared->node_runtime_manifests[i].local_memory_assignments.entries =
            buffers->local_memory[i];
        prepared->node_runtime_manifests[i].local_memory_assignments.capacity =
            sizeof(buffers->local_memory[i]) /
            sizeof(buffers->local_memory[i][0]);
        prepared->node_runtime_manifests[i].startup_dependencies.entries =
            buffers->dependencies[i];
        prepared->node_runtime_manifests[i].startup_dependencies.capacity =
            sizeof(buffers->dependencies[i]) /
            sizeof(buffers->dependencies[i][0]);
    }
}

static int allocate_id16(void *context, enum wvm_coordinator_id_purpose purpose,
                         uint8_t id[WVM_IDENTITY_ID_BYTES], char *error,
                         size_t error_len)
{
    struct id_provider_context *provider = context;

    (void)purpose;
    (void)error;
    (void)error_len;
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = provider->next_id++;
    return 0;
}

static int allocate_route_scope_id(void *context, uint64_t *route_scope_id,
                                   char *error, size_t error_len)
{
    struct id_provider_context *provider = context;

    (void)error;
    (void)error_len;
    *route_scope_id = provider->next_route_scope_id++;
    return 0;
}

static int build_prepared_route(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    const struct wvm_gateway_record *gateway,
    struct wvm_route_rule_record route_rules[3],
    struct wvm_required_ack_entry ack_entries[1],
    struct wvm_route_snapshot_record *snapshot,
    struct wvm_coordinator_prepared_route *prepared_route, char *error,
    size_t error_len)
{
    uint8_t bytes[4096];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    if (!transaction || !records || records->node_count > 2 ||
        !gateway || !route_rules || !ack_entries ||
        !snapshot || !prepared_route) {
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key = transaction->route_scope_key;
    snapshot->route_snapshot_key.topology_revision = records->topology_revision;
    snapshot->route_snapshot_key.route_generation = 1;
    snapshot->membership_revision = records->membership_revision;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FLAT;
    snapshot->operation_retention_horizon_ms = 6000;
    snapshot->retirement_policy = 1;
    memset(route_rules, 0, 3 * sizeof(*route_rules));
    route_rules[0].destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    route_rules[0].destination_vnode_or_endpoint = gateway->gateway_id;
    route_rules[0].next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
    route_rules[0].next_hop_member.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    route_rules[0].next_hop_member.role_id = gateway->gateway_id;
    route_rules[0].next_hop_member.instance_id = gateway->gateway_instance_id;
    route_rules[0].next_hop_endpoint = gateway->endpoint;
    route_rules[0].hop_limit = 1;
    for (size_t i = 0; i < records->node_count; i++) {
        const struct wvm_node_record *node = &records->nodes[i];
        struct wvm_route_rule_record *rule = &route_rules[i + 1];

        rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
        rule->destination_vnode_or_endpoint = node->local_vnode_first;
        rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
        rule->next_hop_member = (struct wvm_member_key){
            WVM_MANIFEST_ROLE_NODE_RUNTIME, node->physical_node_id,
            node->node_instance_id};
        rule->next_hop_endpoint = node->sidecar_endpoint;
        rule->hop_limit = 1;
    }
    snapshot->next_hop_rules.entries = route_rules;
    snapshot->next_hop_rules.count = 1 + records->node_count;
    snapshot->next_hop_rules.capacity = 3;

    memset(ack_entries, 0, sizeof(*ack_entries));
    ack_entries[0].member_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    ack_entries[0].member_key.role_id = gateway->gateway_id;
    ack_entries[0].member_key.instance_id = gateway->gateway_instance_id;
    ack_entries[0].endpoint = gateway->endpoint;
    ack_entries[0].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    ack_entries[0].expected_snapshot_key = snapshot->route_snapshot_key;
    snapshot->required_ack_set.entries.entries = ack_entries;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    if (wvm_route_snapshot_record_decode(bytes, encoded_bytes, snapshot, error,
                                         error_len) != 0 ||
        memcmp(snapshot->route_snapshot_key.snapshot_digest, digest,
               sizeof(digest)) != 0 ||
        wvm_route_snapshot_record_validate(snapshot, error, error_len) != 0) {
        return -1;
    }
    prepared_route->route_snapshot_key = snapshot->route_snapshot_key;
    prepared_route->required_ack_set = &snapshot->required_ack_set;
    return 0;
}

static int build_route_transaction(
    const struct wvm_coordinator_prepared_route *prepared_route,
    uint8_t operation_suffix, struct wvm_route_transaction_record *transaction,
    char *error, size_t error_len)
{
    struct wvm_required_ack_set raw_ack_set;
    struct wvm_required_ack_set decoded_ack_set;
    uint8_t bytes[4096];
    size_t encoded_bytes;

    if (!prepared_route || !prepared_route->required_ack_set || !transaction) {
        return -1;
    }
    memset(transaction, 0, sizeof(*transaction));
    transaction->operation_id[WVM_IDENTITY_ID_BYTES - 1] = operation_suffix;
    transaction->route_snapshot_key = prepared_route->route_snapshot_key;
    transaction->required_ack_set = *prepared_route->required_ack_set;
    raw_ack_set = transaction->required_ack_set;
    memset(raw_ack_set.entries_digest, 0, sizeof(raw_ack_set.entries_digest));
    decoded_ack_set = transaction->required_ack_set;
    if (wvm_required_ack_set_encode(&raw_ack_set, bytes, sizeof(bytes),
                                    &encoded_bytes, error, error_len) != 0 ||
        wvm_required_ack_set_decode(bytes, encoded_bytes, &decoded_ack_set,
                                    error, error_len) != 0) {
        return -1;
    }
    transaction->required_ack_set = decoded_ack_set;
    transaction->operation_retention_horizon_ms = 6000;
    transaction->state = WVM_ROUTE_TRANSACTION_PREPARING;
    return wvm_route_transaction_record_validate(transaction, error, error_len);
}

static int persist_route_transaction_state(
    struct wvm_control_plane *plane,
    struct wvm_route_transaction_record *transaction, uint16_t state,
    char *error, size_t error_len)
{
    if (!transaction) {
        return -1;
    }
    transaction->state = state;
    return wvm_control_plane_record_route_transaction(plane, transaction, error,
                                                      error_len);
}

static int test_activation_durability(
    struct wvm_control_plane *plane,
    struct wvm_vm_namespace_allocator *allocator, const char *journal_path,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_activation_record *activation)
{
    const size_t torn_lengths[] = {1, 60, 65};
    const struct wvm_control_plane_entry *entry;
    struct wvm_activation_record changed = *activation;
    struct wvm_coordinator_activation_options metadata = {9, 8, 7};
    struct wvm_coordinator_activation_options old_metadata = metadata;
    uint64_t sequence = plane->next_journal_sequence;
    off_t prefix_size = lseek(plane->journal_fd, 0, SEEK_END);
    uint16_t original_state;
    uint16_t decided_state = activation->decision == WVM_ACTIVATION_ACTIVATE
                                 ? WVM_LIFECYCLE_ACTIVATION_DECIDED
                                 : WVM_LIFECYCLE_ABORTING;
    char error[256] = {0};
    size_t i;

    entry = wvm_control_plane_find_request(plane, transaction->request_id);
    if (!entry || prefix_size < 0) {
        return -1;
    }
    original_state = entry->transaction.state;
    changed.durable_decision_sequence++;
    if (expect(wvm_control_plane_record_activation(
                   plane, transaction, &changed, error, sizeof(error)) != 0 &&
                   lseek(plane->journal_fd, 0, SEEK_END) == prefix_size &&
                   plane->next_journal_sequence == sequence &&
                   !plane->journal_failed,
               "reject stale decision sequence without changing journal") ||
        expect(wvm_control_plane_activation_options(
                   plane, 0, &metadata, error, sizeof(error)) != 0 &&
                   memcmp(&metadata, &old_metadata, sizeof(metadata)) == 0,
               "missing owner preserves metadata output")) {
        return -1;
    }
    plane->next_journal_sequence = UINT64_MAX;
    if (expect(wvm_control_plane_activation_options(
                   plane, 9, &metadata, error, sizeof(error)) != 0 &&
                   memcmp(&metadata, &old_metadata, sizeof(metadata)) == 0,
               "reject exhausted journal sequence")) {
        return -1;
    }
    plane->next_journal_sequence = sequence;
    for (i = 0; i < sizeof(torn_lengths) / sizeof(torn_lengths[0]); i++) {
        fail_write_fd = plane->journal_fd;
        write_budget = torn_lengths[i];
        int result = wvm_control_plane_record_activation(
            plane, transaction, activation, error, sizeof(error));
        fail_write_fd = -1;
        if (expect(result != 0 && plane->journal_failed &&
                       plane->next_journal_sequence == sequence &&
                       wvm_control_plane_find_request(plane, transaction->request_id)
                               ->transaction.state == original_state,
                   "partial decision write fences writer without deciding") ||
            expect(wvm_control_plane_record_activation(
                       plane, transaction, activation, error, sizeof(error)) != 0 &&
                       wvm_control_plane_transition(
                           plane, transaction, original_state,
                           WVM_LIFECYCLE_ABORTING, error, sizeof(error)) != 0 &&
                       lseek(plane->journal_fd, 0, SEEK_END) ==
                           prefix_size + (off_t)torn_lengths[i],
                   "uncertain writer cannot append a second decision or transition")) {
            return -1;
        }
        wvm_control_plane_close(plane);
        wvm_vm_namespace_allocator_init(allocator, allocator->records,
                                        allocator->record_capacity, 1);
        if (expect(wvm_control_plane_open(plane, journal_path, allocator, error,
                                          sizeof(error)) == 0 &&
                       !plane->journal_failed &&
                       plane->next_journal_sequence == sequence &&
                       lseek(plane->journal_fd, 0, SEEK_END) == prefix_size &&
                       wvm_control_plane_find_request(plane, transaction->request_id)
                               ->transaction.state == original_state,
                   "reopen discards only torn decision and preserves prepared state")) {
            return -1;
        }
    }
    fail_fsync_after = 0;
    if (expect(wvm_control_plane_record_activation(
                   plane, transaction, activation, error, sizeof(error)) != 0 &&
                   plane->journal_failed &&
                   wvm_control_plane_activation_options(
                       plane, 9, &metadata, error, sizeof(error)) != 0 &&
                   wvm_control_plane_record_activation(
                       plane, transaction, activation, error, sizeof(error)) != 0,
               "complete write with failed fsync stays fenced until recovery")) {
        return -1;
    }
    wvm_control_plane_close(plane);
    wvm_vm_namespace_allocator_init(allocator, allocator->records,
                                    allocator->record_capacity, 1);
    for (i = 0; i < 2; i++) {
        fail_fsync_after = (int)i;
        if (expect(wvm_control_plane_open(plane, journal_path, allocator, error,
                                         sizeof(error)) != 0 &&
                       plane->journal_fd == -1 &&
                       allocator->record_count == 0 &&
                       wvm_control_plane_activation_options(
                           plane, 9, &metadata, error, sizeof(error)) != 0,
                   "recovery sync failure cannot reopen writer or restore namespaces")) {
            fail_fsync_after = -1;
            return -1;
        }
    }
    if (expect(wvm_control_plane_open(plane, journal_path, allocator, error,
                                      sizeof(error)) == 0 &&
                   !plane->journal_failed &&
                   plane->next_journal_sequence == sequence + 1 &&
                   wvm_control_plane_find_request(plane, transaction->request_id)
                           ->transaction.state == decided_state &&
                   wvm_control_plane_find_request(plane, transaction->request_id)
                           ->transaction.transaction_sequence == sequence,
               "decision frame alone restores lifecycle after uncertain fsync")) {
        fprintf(stderr, "activation recovery: %s\n", error);
        return -1;
    }
    prefix_size = lseek(plane->journal_fd, 0, SEEK_END);
    changed = *activation;
    changed.decided_at++;
    if (expect(wvm_control_plane_record_activation(
                   plane, transaction, activation, error, sizeof(error)) == 0 &&
                   wvm_control_plane_record_activation(
                       plane, transaction, &changed, error, sizeof(error)) != 0 &&
                   plane->next_journal_sequence == sequence + 1 &&
                   lseek(plane->journal_fd, 0, SEEK_END) == prefix_size,
               "exact decision replay succeeds without rewriting; conflicts reject")) {
        return -1;
    }
    return 0;
}

enum orchestrator_test_failure {
    ORCHESTRATOR_TEST_NO_FAILURE = 0,
    ORCHESTRATOR_TEST_RESERVATION_PREPARE = 1,
    ORCHESTRATOR_TEST_PARTICIPANT_COMMIT = 2,
    ORCHESTRATOR_TEST_ACTIVATION_FSYNC = 3,
};

struct orchestrator_test_hooks {
    const struct wvm_gateway_record *gateway;
    struct wvm_route_rule_record *route_rules;
    struct wvm_required_ack_entry *ack_entries;
    uint8_t route_operation_suffix;
    enum orchestrator_test_failure failure;
    unsigned route_prepares;
    unsigned route_commits;
    unsigned route_aborts;
    unsigned reservation_prepares;
    unsigned reservation_commits;
    unsigned reservation_aborts;
    unsigned participant_prepares;
    unsigned participant_commits;
    unsigned participant_aborts;
    unsigned participant_readies;
};

static int orchestrator_route_plan(
    void *opaque, const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    if (!records || records->node_count != 2 || records->gateway_count != 1) {
        return -1;
    }
    return build_prepared_route(transaction, records, hooks->gateway,
                                hooks->route_rules,
                                hooks->ack_entries, route_snapshot,
                                prepared_route, error, error_len) == 0 &&
                   build_route_transaction(prepared_route,
                                            hooks->route_operation_suffix,
                                            route_transaction, error,
                                            error_len) == 0
               ? 0
               : -1;
}

static int orchestrator_prepare_input(
    void *opaque, const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    (void)opaque;
    (void)request;
    (void)transaction;
    (void)input;
    (void)error;
    (void)error_len;
    return 0;
}

static int orchestrator_route_prepare(
    void *opaque, const struct wvm_coordinator_transaction *coordinator_transaction,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)coordinator_transaction;
    (void)transaction;
    (void)snapshot;
    (void)error;
    (void)error_len;
    hooks->route_prepares++;
    return 0;
}

static int orchestrator_route_commit(
    void *opaque, const struct wvm_coordinator_transaction *coordinator_transaction,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)coordinator_transaction;
    (void)transaction;
    (void)snapshot;
    (void)error;
    (void)error_len;
    hooks->route_commits++;
    return 0;
}

static int orchestrator_route_abort(
    void *opaque, const struct wvm_coordinator_transaction *coordinator_transaction,
    const struct wvm_route_transaction_record *transaction,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)coordinator_transaction;
    (void)transaction;
    (void)snapshot;
    (void)error;
    (void)error_len;
    hooks->route_aborts++;
    return 0;
}

static int orchestrator_reservation_prepare(
    void *opaque, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation,
    char *error, size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)candidate;
    (void)reservation;
    (void)error;
    (void)error_len;
    hooks->reservation_prepares++;
    return hooks->failure == ORCHESTRATOR_TEST_RESERVATION_PREPARE ? -1 : 0;
}

static int orchestrator_reservation_commit(
    void *opaque, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)candidate;
    (void)reservation;
    if (!activation || !activation->has_activation_fence) {
        return -1;
    }
    (void)error;
    (void)error_len;
    hooks->reservation_commits++;
    return 0;
}

static int orchestrator_reservation_abort(
    void *opaque, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_resource_reservation *reservation,
    char *error, size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)candidate;
    (void)reservation;
    (void)error;
    (void)error_len;
    hooks->reservation_aborts++;
    return 0;
}

static int orchestrator_participant_prepare(
    void *opaque, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *manifest,
    char *error, size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)candidate;
    (void)manifest;
    (void)error;
    (void)error_len;
    hooks->participant_prepares++;
    if (hooks->failure == ORCHESTRATOR_TEST_ACTIVATION_FSYNC) {
        /* Persist PARTICIPANTS_PREPARED, then fail the decision's fsync. */
        fail_fsync_after = 1;
    }
    return 0;
}

static int orchestrator_participant_commit(
    void *opaque, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *manifest,
    const struct wvm_activation_record *activation, char *error,
    size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)candidate;
    (void)manifest;
    if (!activation || !activation->has_activation_fence) {
        return -1;
    }
    (void)error;
    (void)error_len;
    hooks->participant_commits++;
    return hooks->failure == ORCHESTRATOR_TEST_PARTICIPANT_COMMIT ? -1 : 0;
}

static int orchestrator_participant_abort(
    void *opaque, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *manifest,
    char *error, size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)candidate;
    (void)manifest;
    (void)error;
    (void)error_len;
    hooks->participant_aborts++;
    return 0;
}

static int orchestrator_participant_ready(
    void *opaque, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *manifest,
    char *error, size_t error_len)
{
    struct orchestrator_test_hooks *hooks = opaque;

    (void)candidate;
    hooks->participant_readies++;
    return wvm_runtime_ready_publish(manifest,
                                      manifest->expected_node_instance_id,
                                      error, error_len);
}

static unsigned recovery_callback_count(const struct orchestrator_test_hooks *hooks)
{
    return hooks->route_commits + hooks->route_aborts +
           hooks->reservation_commits + hooks->reservation_aborts +
           hooks->participant_commits + hooks->participant_aborts +
           hooks->participant_readies;
}

static int test_recovery_guards(
    struct wvm_admission_recovery_input *input,
    const uint8_t other_route_operation[WVM_IDENTITY_ID_BYTES])
{
    const struct wvm_coordinator_transaction *original = input->transaction;
    struct wvm_coordinator_transaction wrong = *original;
    const struct orchestrator_test_hooks *hooks = input->callback_context;
    const unsigned calls = recovery_callback_count(hooks);
    struct wvm_route_transaction_record saved_route = *input->route_transaction;
    char error[256] = {0};
    int result;

    input->control_plane->journal_failed = 1;
    result = wvm_admission_orchestrator_recover(input, error, sizeof(error));
    input->control_plane->journal_failed = 0;
    if (expect(result != 0 && recovery_callback_count(hooks) == calls,
               "fenced recovery sends no stage or readiness callbacks")) {
        return -1;
    }
    wrong.manifest_generation++;
    input->transaction = &wrong;
    result = wvm_admission_orchestrator_recover(input, error, sizeof(error));
    input->transaction = original;
    if (expect(result != 0 && recovery_callback_count(hooks) == calls,
               "recovery rejects wrong generation before callbacks")) {
        return -1;
    }
    input->prepared_vm->candidate.candidate_created_at++;
    result = wvm_admission_orchestrator_recover(input, error, sizeof(error));
    input->prepared_vm->candidate.candidate_created_at--;
    if (expect(result != 0 && recovery_callback_count(hooks) == calls,
               "recovery rejects a modified candidate before callbacks")) {
        return -1;
    }
    memcpy(input->route_transaction->operation_id, other_route_operation,
           WVM_IDENTITY_ID_BYTES);
    result = wvm_admission_orchestrator_recover(input, error, sizeof(error));
    *input->route_transaction = saved_route;
    return expect(result != 0 && recovery_callback_count(hooks) == calls,
                  "another admission's durable route cannot authorize recovery");
}

static int test_abort_recovery(
    struct wvm_control_plane *plane,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_coordinator_prepared_vm *prepared,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *snapshot)
{
    struct orchestrator_test_hooks hooks = {0};
    struct wvm_admission_orchestrator_callbacks callbacks = {
        .route_commit = orchestrator_route_commit,
        .route_abort = orchestrator_route_abort,
        .reservation_commit = orchestrator_reservation_commit,
        .reservation_abort = orchestrator_reservation_abort,
        .participant_commit = orchestrator_participant_commit,
        .participant_abort = orchestrator_participant_abort,
        .participant_ready = orchestrator_participant_ready,
    };
    struct wvm_admission_recovery_input input = {
        .control_plane = plane,
        .transaction = transaction,
        .prepared_vm = prepared,
        .route_transaction = route_transaction,
        .route_snapshot = snapshot,
        .callbacks = &callbacks,
        .callback_context = &hooks,
    };
    char error[256] = {0};

    prepared->reservations[0].node_instance_id++;
    int result = wvm_admission_orchestrator_recover(&input, error, sizeof(error));
    prepared->reservations[0].node_instance_id--;
    if (expect(result != 0 && recovery_callback_count(&hooks) == 0,
               "ABORT recovery validates reservations before callbacks")) {
        return -1;
    }
    return expect(wvm_admission_orchestrator_recover(
                      &input, error, sizeof(error)) == 0 &&
                      wvm_control_plane_find_request(plane, transaction->request_id)
                              ->transaction.state == WVM_LIFECYCLE_ABORTED &&
                      hooks.route_aborts == 1 &&
                      hooks.reservation_aborts == prepared->reservation_count &&
                      hooks.participant_aborts == prepared->node_runtime_manifest_count &&
                      hooks.route_commits == 0 && hooks.reservation_commits == 0 &&
                      hooks.participant_commits == 0 && hooks.participant_readies == 0,
                  "recover durable ABORT without a caller-supplied decision");
}

static int receiver_slot(void *context, uint32_t vm_id, uint64_t incarnation,
                         uint64_t generation,
                         struct wvm_admission_receiver_slot **slot,
                         char *error, size_t error_len)
{
    (void)vm_id;
    (void)incarnation;
    (void)generation;
    (void)error;
    (void)error_len;
    *slot = context;
    return 0;
}

static int receiver_request(struct wvm_admission_receiver *receiver,
                            const struct wvm_candidate_vm_manifest *candidate,
                            uint16_t message_type, const uint8_t *bytes,
                            size_t count, uint16_t expected_status,
                            char *error, size_t error_len)
{
    struct wvm_envelope request = {0};
    struct wvm_control_result result;

    request.message_type = message_type;
    request.origin_physical_node_id = receiver->config.controller_physical_node_id;
    request.origin_runtime_instance_id = receiver->config.controller_runtime_instance_id;
    request.operation_id[0] = 1;
    request.delivery_attempt_id = 1;
    request.vm_id = candidate->vm_id;
    request.vm_incarnation = candidate->vm_incarnation;
    request.manifest_generation = candidate->manifest_generation;
    request.route_scope_id = candidate->route_scope_key.route_scope_id;
    request.topology_revision = candidate->prepared_route_snapshot_key.topology_revision;
    request.route_generation = candidate->prepared_route_snapshot_key.route_generation;
    memcpy(request.route_snapshot_digest,
           candidate->prepared_route_snapshot_key.snapshot_digest,
           sizeof(request.route_snapshot_digest));
    request.payload = bytes;
    request.payload_bytes = count;
    if (wvm_admission_receiver_apply(receiver, &request,
            &receiver->config.controller_member_key, &result, error, error_len) != 0 ||
        result.status_code != expected_status) {
        return -1;
    }
    return 0;
}

static int receiver_stage(struct wvm_admission_receiver *receiver,
                          const struct wvm_admission_reservation_stage *stage,
                          uint16_t expected_status, char *error, size_t error_len)
{
    uint8_t bytes[16384];
    size_t count;

    if (wvm_admission_reservation_stage_encode(stage, bytes, sizeof(bytes),
                                              &count, error, error_len) != 0) {
        return -1;
    }
    return receiver_request(receiver, stage->candidate, stage->message_type,
                             bytes, count, expected_status, error, error_len);
}

static int test_reservation_receiver(
    const struct wvm_coordinator_prepared_vm *prepared,
    const struct wvm_activation_record *activation)
{
    struct wvm_admission_receiver receiver = {0};
    struct wvm_admission_receiver_config config = {0};
    struct wvm_admission_receiver_slot slot = {0};
    struct wvm_admission_reservation_stage_storage scratch = {0};
    struct prepared_buffers buffers = {0};
    struct wvm_capability_ref execution_capabilities[4];
    struct wvm_exclusive_lease reservation_leases[3];
    struct wvm_route_snapshot_key activation_routes[4];
    struct wvm_local_reservation_registry registry = {0};
    struct wvm_resource_reservation stored[4];
    struct wvm_resource_reservation committed = prepared->reservations[0];
    struct wvm_admission_reservation_stage stage = {0};
    struct wvm_admission_node node = {0};
    const struct wvm_resource_reservation *reservation = &prepared->reservations[0];
    char directory[] = "/tmp/wavevm-receiver.XXXXXX";
    char path[128], state_path[128], lock_path[144], runtime_path[128];
    char error[256] = {0};
    int status = -1;
    uint64_t committed_bytes;

    if (!mkdtemp(directory)) {
        return -1;
    }
    snprintf(path, sizeof(path), "%s/reservations", directory);
    snprintf(state_path, sizeof(state_path), "%s/state", directory);
    snprintf(lock_path, sizeof(lock_path), "%s.lock", state_path);
    snprintf(runtime_path, sizeof(runtime_path), "%s/runtime", directory);
    node.physical_node_id = reservation->physical_node_id;
    node.node_instance_id = reservation->node_instance_id;
    node.inventory_revision = reservation->inventory_revision;
    node.allocatable_vcpu_slots = reservation->guest_vcpu_slots +
                                 reservation->overhead_vcpu_slots;
    node.allocatable_memory_bytes = reservation->guest_memory_bytes +
                                   reservation->overhead_memory_bytes;
    scratch.candidate_storage = (struct wvm_admission_candidate_stage_storage){
        .vcpu_placements = buffers.vcpus, .vcpu_placement_capacity = 4,
        .memory_placements = buffers.memory, .memory_placement_capacity = 4,
        .required_members = buffers.selected_members, .required_member_capacity = 4,
        .required_capabilities = buffers.required_capabilities, .required_capability_capacity = 4,
        .execution_capabilities = execution_capabilities, .execution_capability_capacity = 4,
        .reservation_requirements = buffers.requirements, .reservation_requirement_capacity = 4,
        .reservation_requirement_leases = &buffers.listener_leases[0][0],
        .reservation_requirement_lease_capacity = 3,
    };
    scratch.reservation_leases = reservation_leases;
    scratch.reservation_lease_capacity = 3;
    scratch.activation_route_snapshot_keys = activation_routes;
    scratch.activation_route_snapshot_key_capacity = 4;
    config.controller_member_key = (struct wvm_member_key){WVM_MANIFEST_ROLE_NODE_RUNTIME, 91, 92};
    config.controller_physical_node_id = 91;
    config.controller_runtime_instance_id = 92;
    config.local_physical_node_id = node.physical_node_id;
    config.local_node_instance_id = node.node_instance_id;
    config.reservation_registry = &registry;
    config.reservation_scratch_storage = &scratch;
    config.resolve_slot = receiver_slot;
    config.context = &slot;
    slot.runtime_manifest_path = runtime_path;
    stage.candidate = &prepared->candidate;
    stage.reservation = reservation;
    stage.message_type = WVM_ENVELOPE_MSG_PREPARE_RESERVATION;
    if (wvm_local_reservation_registry_init(&registry, &node, stored, 4,
                                            error, sizeof(error)) != 0 ||
        wvm_admission_receiver_init(&receiver, &config, error, sizeof(error)) != 0 ||
        receiver_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                        error, sizeof(error)) != 0 || registry.reservation_count != 0 ||
        wvm_local_reservation_registry_open(&registry, path, 1024 * 1024,
                                            error, sizeof(error)) != 0 ||
        wvm_admission_receiver_slot_open(&receiver, &slot, state_path,
            prepared->candidate.vm_id, prepared->candidate.vm_incarnation,
            prepared->candidate.manifest_generation, error, sizeof(error)) != 0 ||
        receiver_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS,
                        error, sizeof(error)) != 0 ||
        receiver_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS,
                        error, sizeof(error)) != 0 || registry.reservation_count != 1) {
        goto out;
    }
    wvm_local_reservation_registry_destroy(&registry);
    if (wvm_local_reservation_registry_init(&registry, &node, stored, 4,
                                            error, sizeof(error)) != 0 ||
        wvm_local_reservation_registry_open(&registry, path, 1024 * 1024,
                                            error, sizeof(error)) != 0 ||
        wvm_resource_reservation_commit(&committed, activation, error,
                                        sizeof(error)) != 0) {
        goto out;
    }
    stage.message_type = WVM_ENVELOPE_MSG_COMMIT_RESERVATION;
    stage.reservation = &committed;
    stage.activation = activation;
    if (receiver_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS,
                        error, sizeof(error)) != 0 ||
        stored[0].state != WVM_RESERVATION_COMMITTED ||
        registry.prepared_memory_bytes != 0 ||
        registry.committed_memory_bytes != node.allocatable_memory_bytes) {
        goto out;
    }
    committed_bytes = registry.journal_bytes;
    if (receiver_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS,
                        error, sizeof(error)) != 0 ||
        committed_bytes != registry.journal_bytes) {
        goto out;
    }
    stage.message_type = WVM_ENVELOPE_MSG_ABORT_RESERVATION;
    stage.reservation = reservation;
    stage.activation = NULL;
    stage.abort_reason = WVM_ADMISSION_ABORT_REASON_PRE_ACTIVATION_FAILURE;
    if (receiver_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                        error, sizeof(error)) != 0 ||
        stored[0].state != WVM_RESERVATION_COMMITTED ||
        committed_bytes != registry.journal_bytes) {
        goto out;
    }
    status = 0;
out:
    if (status != 0) {
        fprintf(stderr, "reservation receiver integration: %s\n", error);
    }
    wvm_admission_receiver_destroy(&receiver);
    wvm_admission_receiver_slot_close(&slot);
    wvm_local_reservation_registry_destroy(&registry);
    unlink(path);
    unlink(state_path);
    unlink(lock_path);
    rmdir(directory);
    return status;
}

struct participant_decode_buffers {
    struct prepared_buffers data;
    struct wvm_capability_ref execution_capabilities[4];
    struct wvm_capability_ref runtime_capabilities[4];
    struct wvm_route_snapshot_key activation_routes[4];
};

static void participant_storage_init(
    struct wvm_admission_participant_stage_storage *storage,
    struct participant_decode_buffers *buffers)
{
    memset(storage, 0, sizeof(*storage));
    storage->candidate_storage = (struct wvm_admission_candidate_stage_storage){
        .vcpu_placements = buffers->data.vcpus, .vcpu_placement_capacity = 4,
        .memory_placements = buffers->data.memory, .memory_placement_capacity = 4,
        .required_members = buffers->data.selected_members, .required_member_capacity = 4,
        .required_capabilities = buffers->data.required_capabilities, .required_capability_capacity = 4,
        .execution_capabilities = buffers->execution_capabilities, .execution_capability_capacity = 4,
        .reservation_requirements = buffers->data.requirements, .reservation_requirement_capacity = 4,
        .reservation_requirement_leases = &buffers->data.listener_leases[0][0],
        .reservation_requirement_lease_capacity = 3,
    };
    storage->runtime_vcpu_assignments = buffers->data.local_vcpus[0];
    storage->runtime_vcpu_assignment_capacity = 4;
    storage->runtime_memory_assignments = buffers->data.local_memory[0];
    storage->runtime_memory_assignment_capacity = 4;
    storage->runtime_capabilities = buffers->runtime_capabilities;
    storage->runtime_capability_capacity = 4;
    storage->runtime_dependencies = buffers->data.dependencies[0];
    storage->runtime_dependency_capacity = 4;
    storage->activation_route_snapshot_keys = buffers->activation_routes;
    storage->activation_route_snapshot_key_capacity = 4;
}

struct participant_receiver_context {
    struct wvm_admission_receiver_slot slot;
    const struct wvm_cluster_record_set *records;
    const struct wvm_route_snapshot_record *route;
    int reject_delivery;
};

static int participant_slot(void *context, uint32_t vm_id, uint64_t incarnation,
                             uint64_t generation,
                             struct wvm_admission_receiver_slot **slot,
                             char *error, size_t error_len)
{
    struct participant_receiver_context *owner = context;

    return receiver_slot(&owner->slot, vm_id, incarnation, generation, slot,
                          error, error_len);
}

static int participant_delivery_inputs(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime,
    const struct wvm_activation_record *activation,
    const struct wvm_cluster_record_set **records,
    const struct wvm_route_snapshot_record **route, char *error, size_t error_len)
{
    struct participant_receiver_context *owner = context;

    (void)candidate;
    (void)runtime;
    (void)activation;
    (void)error;
    (void)error_len;
    *records = owner->records;
    *route = owner->route;
    return owner->reject_delivery ? -1 : 0;
}

static int participant_stage(struct wvm_admission_receiver *receiver,
                              const struct wvm_admission_participant_stage *stage,
                              uint16_t expected_status, char *error, size_t error_len)
{
    uint8_t bytes[16384];
    size_t count;

    if (wvm_admission_participant_stage_encode(stage, bytes, sizeof(bytes),
                                               &count, error, error_len) != 0) {
        return -1;
    }
    return receiver_request(receiver, stage->candidate, stage->message_type,
                             bytes, count, expected_status, error, error_len);
}

static int participant_reopen(struct wvm_admission_receiver *receiver,
                               struct wvm_admission_receiver_slot *slot,
                               const char *path,
                               const struct wvm_candidate_vm_manifest *candidate,
                               char *error, size_t error_len)
{
    wvm_admission_receiver_slot_close(slot);
    return wvm_admission_receiver_slot_open(
        receiver, slot, path, candidate->vm_id, candidate->vm_incarnation,
        candidate->manifest_generation, error, error_len);
}

/* These exercise real stage codecs, durable participant state, reservation
 * authority and delivery files. They do not start a guest or a network peer. */
static int test_participant_receiver(
    const struct wvm_coordinator_prepared_vm *prepared,
    const struct wvm_activation_record *activation,
    const struct wvm_cluster_record_set *records,
    const struct wvm_route_snapshot_record *route, unsigned scenario)
{
    struct wvm_admission_receiver receiver = {0};
    struct wvm_admission_receiver_config config = {0};
    struct participant_receiver_context owner = {0};
    struct wvm_admission_receiver_slot *slot = &owner.slot;
    struct participant_decode_buffers retained_buffers = {0}, scratch_buffers = {0};
    struct wvm_admission_receiver_slot competitor = {0};
    struct wvm_local_reservation_registry registry = {0};
    struct wvm_resource_reservation stored[4];
    struct wvm_admission_node node = {0};
    struct wvm_admission_participant_stage stage = {0};
    struct wvm_activation_record conflicting_activation = *activation;
    struct wvm_node_runtime_manifest active = prepared->node_runtime_manifests[0];
    const struct wvm_candidate_vm_manifest *candidate = &prepared->candidate;
    const struct wvm_resource_reservation *reservation = &prepared->reservations[0];
    enum wvm_reservation_runtime_result reservation_result;
    char directory[] = "/tmp/wavevm-participant.XXXXXX";
    char state_path[160], lock_path[170], reservation_path[160], runtime_path[160];
    char route_path[256] = {0}, dispatch_path[256] = {0};
    char error[256] = {0};
    int status = -1, fd = -1;
    struct stat info;
    uint8_t byte;

    if (!mkdtemp(directory)) {
        return -1;
    }
    snprintf(state_path, sizeof(state_path), "%s/state", directory);
    snprintf(lock_path, sizeof(lock_path), "%s.lock", state_path);
    snprintf(reservation_path, sizeof(reservation_path), "%s/reservations", directory);
    snprintf(runtime_path, sizeof(runtime_path), "%s/runtime", directory);
    slot->runtime_manifest_path = runtime_path;
    competitor.runtime_manifest_path = runtime_path;
    participant_storage_init(&slot->prepared_storage, &retained_buffers);
    participant_storage_init(&slot->scratch_storage, &scratch_buffers);
    node.physical_node_id = reservation->physical_node_id;
    node.node_instance_id = reservation->node_instance_id;
    node.inventory_revision = reservation->inventory_revision;
    node.allocatable_vcpu_slots = reservation->guest_vcpu_slots + reservation->overhead_vcpu_slots;
    node.allocatable_memory_bytes = reservation->guest_memory_bytes + reservation->overhead_memory_bytes;
    config.controller_member_key = (struct wvm_member_key){WVM_MANIFEST_ROLE_NODE_RUNTIME, 91, 92};
    config.controller_physical_node_id = 91;
    config.controller_runtime_instance_id = 92;
    config.local_physical_node_id = node.physical_node_id;
    config.local_node_instance_id = node.node_instance_id;
    config.reservation_registry = &registry;
    config.resolve_slot = participant_slot;
    config.delivery_inputs = participant_delivery_inputs;
    config.context = &owner;
    owner.records = records;
    owner.route = route;
    stage.candidate = candidate;
    stage.runtime_manifest = &prepared->node_runtime_manifests[0];
    stage.message_type = WVM_ENVELOPE_MSG_PREPARE_MANIFEST;
    if (wvm_route_snapshot_path_from_manifest(runtime_path, route_path,
            sizeof(route_path), error, sizeof(error)) != 0 ||
        wvm_runtime_dispatch_path_from_manifest(runtime_path, dispatch_path,
            sizeof(dispatch_path), error, sizeof(error)) != 0 ||
        wvm_local_reservation_registry_init(&registry, &node, stored, 4, error, sizeof(error)) != 0 ||
        wvm_local_reservation_registry_open(&registry, reservation_path, 1024 * 1024,
                                            error, sizeof(error)) != 0 ||
        wvm_local_reservation_prepare(&registry, reservation, &reservation_result,
                                       error, sizeof(error)) != 0 ||
        wvm_admission_receiver_init(&receiver, &config, error, sizeof(error)) != 0 ||
        participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                           error, sizeof(error)) != 0 ||
        participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) != 0 ||
        wvm_admission_receiver_slot_open(&receiver, &competitor, state_path,
            candidate->vm_id, candidate->vm_incarnation, candidate->manifest_generation,
            error, sizeof(error)) == 0) {
        goto out;
    }
    if (scenario != 2 &&
        (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS, error, sizeof(error)) != 0 ||
         participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS, error, sizeof(error)) != 0 ||
         participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) != 0 ||
         !slot->has_prepared || slot->has_activated ||
         slot->gate.state != WVM_RUNTIME_GATE_PREPARED)) {
        goto out;
    }
    if (scenario == 1 || scenario == 2) {
        stage.message_type = WVM_ENVELOPE_MSG_ABORT_MANIFEST;
        stage.abort_reason = WVM_ADMISSION_ABORT_REASON_PRE_ACTIVATION_FAILURE;
        if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS, error, sizeof(error)) != 0 ||
            participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) != 0 ||
            participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS, error, sizeof(error)) != 0 ||
            !slot->has_aborted || slot->has_prepared || slot->gate.state != WVM_RUNTIME_GATE_EMPTY) {
            goto out;
        }
        stage.message_type = WVM_ENVELOPE_MSG_PREPARE_MANIFEST;
        stage.abort_reason = 0;
        if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                               error, sizeof(error)) != 0) {
            goto out;
        }
        status = 0;
        goto out;
    }
    active.has_activation_fence = 1;
    memcpy(active.activation_fence, activation->activation_fence, WVM_IDENTITY_ID_BYTES);
    stage.message_type = WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST;
    stage.runtime_manifest = &active;
    stage.activation = activation;
    if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                           error, sizeof(error)) != 0 || slot->has_activation_decision ||
        wvm_local_reservation_commit(&registry, reservation, activation, &reservation_result,
                                     error, sizeof(error)) != 0) {
        goto out;
    }
    conflicting_activation.activation_fence[0] ^= 1;
    memcpy(active.activation_fence, conflicting_activation.activation_fence, WVM_IDENTITY_ID_BYTES);
    stage.activation = &conflicting_activation;
    if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                           error, sizeof(error)) != 0 || slot->has_activation_decision) {
        goto out;
    }
    stage.activation = activation;
    memcpy(active.activation_fence, activation->activation_fence, WVM_IDENTITY_ID_BYTES);
    if (scenario == 3 || scenario == 4) {
        /* Fail either the snapshot fsync or the directory fsync after rename. */
        fail_fsync_after = (int)scenario - 3;
        if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                               error, sizeof(error)) != 0 || !slot->state_failed ||
            slot->has_activated || access(runtime_path, F_OK) == 0 ||
            participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                               error, sizeof(error)) != 0 ||
            participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) != 0 ||
            slot->has_activation_decision != (scenario == 4)) {
            goto out;
        }
    }
    owner.reject_delivery = 1;
    if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                           error, sizeof(error)) != 0 ||
        !slot->has_activation_decision || slot->has_activated ||
        participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) != 0 ||
        !slot->has_activation_decision || slot->gate.state != WVM_RUNTIME_GATE_PREPARED) {
        goto out;
    }
    stage.message_type = WVM_ENVELOPE_MSG_ABORT_MANIFEST;
    stage.activation = NULL;
    stage.runtime_manifest = &prepared->node_runtime_manifests[0];
    stage.abort_reason = WVM_ADMISSION_ABORT_REASON_PRE_ACTIVATION_FAILURE;
    if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_PRECONDITION_FAILED,
                           error, sizeof(error)) != 0) {
        goto out;
    }
    stage.message_type = WVM_ENVELOPE_MSG_ACTIVATE_MANIFEST;
    stage.activation = activation;
    stage.runtime_manifest = &active;
    stage.abort_reason = 0;
    owner.reject_delivery = 0;
    if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS, error, sizeof(error)) != 0 ||
        !slot->has_activated || slot->gate.state != WVM_RUNTIME_GATE_ACTIVE ||
        access(runtime_path, F_OK) != 0) {
        goto out;
    }
    slot->gate.next_connection_id = 123;
    if (participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS, error, sizeof(error)) != 0 ||
        slot->gate.next_connection_id != 123 ||
        participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) != 0 ||
        slot->has_activated ||
        participant_stage(&receiver, &stage, WVM_CONTROL_RESULT_SUCCESS, error, sizeof(error)) != 0) {
        goto out;
    }
    wvm_admission_receiver_slot_close(slot);
    if (wvm_admission_receiver_slot_open(&receiver, slot, state_path,
            candidate->vm_id + 1, candidate->vm_incarnation, candidate->manifest_generation,
            error, sizeof(error)) == 0) {
        goto out;
    }
    receiver.config.local_node_instance_id++;
    if (participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) == 0) {
        goto out;
    }
    receiver.config.local_node_instance_id--;
    fd = open(state_path, O_RDWR);
    if (fd < 0 || fstat(fd, &info) != 0 ||
        pread(fd, &byte, 1, info.st_size - 1) != 1) {
        goto out;
    }
    byte ^= 1;
    if (pwrite(fd, &byte, 1, info.st_size - 1) != 1 ||
        participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) == 0 ||
        ftruncate(fd, 13) != 0 ||
        participant_reopen(&receiver, slot, state_path, candidate, error, sizeof(error)) == 0) {
        goto out;
    }
    status = 0;
out:
    fail_fsync_after = -1;
    if (status != 0) {
        fprintf(stderr, "participant receiver scenario %u: %s\n", scenario, error);
    }
    if (fd >= 0) {
        close(fd);
    }
    wvm_admission_receiver_slot_close(&competitor);
    wvm_admission_receiver_slot_close(slot);
    wvm_admission_receiver_destroy(&receiver);
    wvm_local_reservation_registry_destroy(&registry);
    unlink(reservation_path);
    unlink(runtime_path);
    unlink(route_path);
    unlink(dispatch_path);
    unlink(state_path);
    unlink(lock_path);
    rmdir(directory);
    return status;
}

static int test_ctl_workspace(
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    const struct wvm_coordinator_prepared_route *route,
    const struct wvm_coordinator_prepare_options *template)
{
    struct wvm_ctl_admission_buffers buffers = {0};
    struct wvm_coordinator_prepared_vm prepared = {0};
    struct wvm_coordinator_prepared_vm saved;
    struct wvm_coordinator_prepare_options options = *template;
    struct wvm_activation_record activation = {0};
    struct wvm_coordinator_activation_options decision = {10, 11, 12};
    void *allocation;
    uint8_t *candidate_bytes;
    char error[256] = {0};
    size_t iteration;
    int result = -1;

    for (iteration = 0; iteration < 2; iteration++) {
        if (expect(wvm_ctl_admission_buffers_reset(
                       &buffers, request->requested_vcpus, records->node_count,
                       records->node_count + records->gateway_count,
                       WVM_CTL_ADMISSION_WORKSPACE_BYTES, &prepared, &options,
                       &activation, error, sizeof(error)) == 0,
                   "allocate and rebind controller transaction workspace") ||
            expect(!prepared.candidate_manifest_bytes &&
                       !prepared.node_runtime_manifest_count &&
                       !prepared.reservation_count &&
                       !activation.required_route_snapshot_count &&
                       prepared.reservations != records->resource_reservations,
                   "reset counts without aliasing published evidence") ||
            expect(wvm_coordinator_prepare(
                       request, transaction, records, route, &options,
                       &prepared, error, sizeof(error)) == 0,
                   "prepare with production-owned nested buffers") ||
            expect(wvm_coordinator_decide_abort(
                       transaction, &decision, &prepared, &activation,
                       error, sizeof(error)) == 0 &&
                       activation.required_route_snapshot_count == 1,
                   "activation output remains bound after reset")) {
            goto out;
        }
        saved = prepared;
        allocation = buffers.allocation;
        candidate_bytes = options.candidate_manifest_bytes;
        if (expect(wvm_ctl_admission_buffers_reset(
                       &buffers, UINT32_MAX, UINT32_MAX, UINT32_MAX, SIZE_MAX,
                       &prepared, &options, &activation, error,
                       sizeof(error)) != 0 &&
                       wvm_ctl_admission_buffers_reset(
                           &buffers, request->requested_vcpus, records->node_count,
                           records->node_count + records->gateway_count, 1,
                           &prepared, &options, &activation, error,
                           sizeof(error)) != 0,
                   "reject arithmetic overflow and exhausted byte budget") ||
            expect(buffers.allocation == allocation &&
                       options.candidate_manifest_bytes == candidate_bytes &&
                       memcmp(&saved, &prepared, sizeof(prepared)) == 0 &&
                       activation.required_route_snapshot_count == 1,
                   "failed reset leaves prior output valid")) {
            goto out;
        }
    }
    result = 0;
out:
    wvm_ctl_admission_buffers_destroy(&buffers, &prepared);
    wvm_ctl_admission_buffers_destroy(&buffers, &prepared);
    return result;
}

int main(void)
{
    struct wvm_capability_record capabilities[8];
    struct wvm_node_record nodes[2];
    struct wvm_gateway_record gateway;
    struct wvm_cluster_record_set records;
    struct wvm_vm_request request;
    struct wvm_vm_request abort_request;
    struct wvm_vm_namespace_record namespace_records[6];
    struct wvm_vm_namespace_allocator namespace_allocator;
    struct wvm_control_plane_entry control_plane_entries[6];
    struct wvm_control_plane_route_entry control_plane_route_entries[6];
    struct wvm_control_plane_runtime_manifest_entry
        control_plane_runtime_manifest_entries[12];
    struct wvm_control_plane control_plane;
    struct wvm_control_plane_entry recovered_control_plane_entries[6];
    struct wvm_control_plane_route_entry recovered_control_plane_route_entries[6];
    struct wvm_control_plane_runtime_manifest_entry
        recovered_runtime_manifest_entries[12];
    struct wvm_control_plane recovered_control_plane;
    struct wvm_vm_namespace_record recovered_namespace_records[6];
    struct wvm_vm_namespace_allocator recovered_namespace_allocator;
    struct id_provider_context provider_context = {
        .next_id = 1,
        .next_route_scope_id = 1,
    };
    struct wvm_coordinator_id_provider id_provider = {
        .context = &provider_context,
        .allocate_id16 = allocate_id16,
        .allocate_route_scope_id = allocate_route_scope_id,
    };
    struct wvm_coordinator_transaction transaction;
    struct wvm_coordinator_transaction abort_transaction;
    struct wvm_route_rule_record route_rules[3];
    struct wvm_route_rule_record abort_route_rules[3];
    struct wvm_required_ack_entry ack_entries[1];
    struct wvm_required_ack_entry abort_ack_entries[1];
    struct wvm_route_snapshot_record route_snapshot;
    struct wvm_route_snapshot_record abort_route_snapshot;
    struct wvm_coordinator_prepared_route prepared_route;
    struct wvm_coordinator_prepared_route abort_prepared_route;
    struct wvm_route_transaction_record route_transaction;
    struct wvm_route_transaction_record abort_route_transaction;
    struct wvm_coordinator_prepare_options options;
    struct wvm_coordinator_prepare_options abort_options;
    struct wvm_capability_ref profile_capabilities[2];
    struct wvm_coordinator_node_launch_plan launch_plans[2];
    struct wvm_coordinator_node_launch_plan abort_launch_plans[2];
    struct wvm_admission_node_listener_plan listener_plans[2];
    struct wvm_admission_node_listener_plan abort_listener_plans[2];
    struct wvm_exclusive_lease listener_leases[2][3];
    struct wvm_exclusive_lease abort_listener_leases[2][3];
    struct wvm_coordinator_prepared_vm prepared = {0};
    struct wvm_coordinator_prepared_vm rejected_prepared = {0};
    struct wvm_coordinator_prepared_vm abort_prepared = {0};
    struct prepared_buffers buffers;
    struct prepared_buffers rejected_buffers;
    struct prepared_buffers abort_buffers;
    struct wvm_admission_node reservation_nodes[2];
    struct wvm_resource_reservation registry_storage[2][4];
    struct wvm_local_reservation_registry registry_17;
    struct wvm_local_reservation_registry registry_99;
    struct wvm_local_reservation_registry *registries[2] = {
        &registry_99,
        &registry_17,
    };
    struct wvm_coordinator_activation_options activation_options = {
        .coordinator_instance_id = 77,
        .durable_decision_sequence = 1,
        .decided_at = 2000,
    };
    struct wvm_activation_record activation;
    struct wvm_activation_record replayed_activation;
    struct wvm_activation_record abort_activation;
    struct wvm_route_snapshot_key activation_route_keys[1];
    struct wvm_route_snapshot_key abort_route_keys[1];
    uint32_t gateway_ids[1] = {3};
    uint8_t placement_bytes[8192];
    uint8_t candidate_bytes[16384];
    uint8_t abort_placement_bytes[8192];
    uint8_t abort_candidate_bytes[16384];
    uint8_t replayed_candidate_bytes[16384];
    uint8_t replayed_activation_bytes[4096];
    uint8_t replayed_runtime_manifest_bytes[16384];
    uint8_t expected_runtime_manifest_bytes[16384];
    struct wvm_route_snapshot_key replayed_activation_route_keys[1];
    enum wvm_control_plane_submit_result submit_result;
    char control_plane_journal[] = "/tmp/wavevm-coordinator-journal.XXXXXX";
    char error[256] = {0};
    int control_plane_journal_fd;
    size_t replayed_candidate_byte_count;
    size_t replayed_activation_byte_count;
    size_t replayed_runtime_manifest_byte_count;
    size_t expected_runtime_manifest_byte_count;
    size_t i;

    fill_capability(&capabilities[0], WVM_CAPABILITY_ID_EXECUTION_KVM, 17, 101,
                    1);
    fill_capability(&capabilities[1], WVM_CAPABILITY_ID_EXECUTION_TCG, 17, 101,
                    2);
    fill_capability(&capabilities[2], WVM_CAPABILITY_ID_MODE_B_MEMORY, 17, 101,
                    3);
    fill_capability(&capabilities[3], WVM_CAPABILITY_ID_VM_ID_U32, 17, 101,
                    4);
    fill_capability(&capabilities[4], WVM_CAPABILITY_ID_EXECUTION_KVM, 99, 202,
                    1);
    fill_capability(&capabilities[5], WVM_CAPABILITY_ID_EXECUTION_TCG, 99, 202,
                    2);
    fill_capability(&capabilities[6], WVM_CAPABILITY_ID_MODE_B_MEMORY, 99, 202,
                    3);
    fill_capability(&capabilities[7], WVM_CAPABILITY_ID_VM_ID_U32, 99, 202,
                    4);
    if (expect(fill_node(&nodes[0], 17, 101, 1, capabilities, 4, gateway_ids,
                         1) == 0 &&
                   fill_node(&nodes[1], 99, 202, 2, capabilities + 4, 4, NULL,
                             0) == 0,
               "derive participant capability profiles")) {
        return 1;
    }

    memset(&gateway, 0, sizeof(gateway));
    gateway.gateway_id = 3;
    gateway.gateway_instance_id = 301;
    gateway.hosting_physical_node_id = 17;
    gateway.failure_domain_id = 1;
    fill_endpoint(&gateway.endpoint, 17, 9400, 9401);
    gateway.role_bits = 1;
    gateway.desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    gateway.observed_health_state = 1;
    gateway.membership_revision = 5;
    gateway.topology_revision = 6;

    memset(&records, 0, sizeof(records));
    records.nodes = nodes;
    records.node_count = 2;
    records.gateways = &gateway;
    records.gateway_count = 1;
    records.capability_records = capabilities;
    records.capability_record_count = 8;
    records.inventory_revision = 10;
    records.membership_revision = 5;
    records.topology_revision = 6;
    records.admission_eligibility_revision = 7;
    records.capability_profile_generation = 9;

    fill_request(&request);
    admission_node_from_record(&reservation_nodes[0], &nodes[0]);
    admission_node_from_record(&reservation_nodes[1], &nodes[1]);
    if (expect(wvm_local_reservation_registry_init(
                   &registry_17, &reservation_nodes[0], registry_storage[0],
                   sizeof(registry_storage[0]) / sizeof(registry_storage[0][0]),
                   error, sizeof(error)) == 0 &&
                   wvm_local_reservation_registry_init(
                       &registry_99, &reservation_nodes[1], registry_storage[1],
                       sizeof(registry_storage[1]) /
                           sizeof(registry_storage[1][0]),
                       error, sizeof(error)) == 0,
               "initialize node-local reservation authorities")) {
        return 1;
    }
    wvm_vm_namespace_allocator_init(&namespace_allocator, namespace_records,
                                    sizeof(namespace_records) /
                                        sizeof(namespace_records[0]),
                                    1);
    control_plane_journal_fd = mkstemp(control_plane_journal);
    if (control_plane_journal_fd < 0) {
        perror("mkstemp control-plane journal");
        return 1;
    }
    close(control_plane_journal_fd);
    wvm_control_plane_init(
        &control_plane, control_plane_entries,
        sizeof(control_plane_entries) / sizeof(control_plane_entries[0]));
    wvm_control_plane_set_route_transaction_entries(
        &control_plane, control_plane_route_entries,
        sizeof(control_plane_route_entries) /
            sizeof(control_plane_route_entries[0]));
    wvm_control_plane_set_runtime_manifest_entries(
        &control_plane, control_plane_runtime_manifest_entries,
        sizeof(control_plane_runtime_manifest_entries) /
            sizeof(control_plane_runtime_manifest_entries[0]));
    if (expect(wvm_control_plane_open(&control_plane, control_plane_journal,
                                      &namespace_allocator, error,
                                      sizeof(error)) == 0,
               "open coordinator durability journal") ||
        expect(wvm_control_plane_begin(
                   &control_plane, &request, &namespace_allocator,
                   &id_provider, &submit_result, &transaction, error,
                   sizeof(error)) == 0 &&
                   submit_result == WVM_CONTROL_PLANE_SUBMIT_NEW,
               "begin canonical V1 admission transaction") ||
        expect(transaction.vm_id == 256 && transaction.vm_incarnation == 1 &&
                   transaction.manifest_generation == 1 &&
                   transaction.route_scope_key.route_scope_id == 1,
               "allocate only V1 namespace identity")) {
        return 1;
    }

    profile_capabilities[0] = nodes[0].capability;
    profile_capabilities[1] = nodes[1].capability;
    fill_options(&options, profile_capabilities, placement_bytes,
                 sizeof(placement_bytes), candidate_bytes, sizeof(candidate_bytes));
    fill_node_launch_plans(&options, launch_plans, nodes, listener_plans,
                           listener_leases);
    if (expect(build_prepared_route(&transaction, &records, &gateway,
                                    route_rules,
                                    ack_entries, &route_snapshot,
                                    &prepared_route, error, sizeof(error)) == 0,
               "build prepared canonical route ACK set")) {
        return 1;
    }

    if (test_ctl_workspace(&request, &transaction, &records, &prepared_route,
                           &options) != 0) {
        return 1;
    }

    memset(&buffers, 0, sizeof(buffers));
    initialize_prepared_vm(&prepared, &buffers);
    prepared.reservation_registries = registries;
    prepared.reservation_registry_count =
        sizeof(registries) / sizeof(registries[0]);
    if (expect(wvm_coordinator_prepare(&request, &transaction, &records,
                                       &prepared_route, &options, &prepared,
                                       error, sizeof(error)) == 0,
               "prepare deterministic canonical VM proposal") ||
        expect(prepared.admission_plan.reservation_count == 2 &&
                   prepared.reservation_count == 2 &&
                   prepared.node_runtime_manifest_count == 2,
               "reserve and project both selected nodes") ||
        expect(prepared.fence.selected_members.count == 3 &&
                   prepared.candidate.required_capabilities.count == 2 &&
                   prepared.candidate.required_members.count == 3,
               "fence node and gateway participants") ||
        expect(prepared.candidate.execution_plan.backend ==
                   WVM_MANIFEST_BACKEND_TCG &&
                   prepared.candidate.namespace_abi ==
                       WVM_MANIFEST_NAMESPACE_U32 &&
                   !bytes_are_zero(prepared.candidate_manifest_digest,
                                   sizeof(prepared.candidate_manifest_digest)),
               "bind selected TCG profile to V1 candidate") ||
        expect(wvm_candidate_vm_manifest_matches_plan(
                   &prepared.candidate, &prepared.placement_plan, error,
                   sizeof(error)) == 0,
                   "candidate exactly matches placement plan")) {
        return 1;
    }
    if (expect(registry_17.reservation_count == 1 &&
                   registry_99.reservation_count == 1 &&
                   registry_17.prepared_memory_bytes != 0 &&
                   registry_99.prepared_memory_bytes != 0,
               "prepare registry lookup by physical node, not array order")) {
        return 1;
    }
    if (expect(wvm_control_plane_record_candidate(
                   &control_plane, &transaction, &prepared.candidate, error,
                   sizeof(error)) == 0,
               "persist immutable candidate before route preparation") ||
        expect(wvm_control_plane_transition(
                   &control_plane, &transaction, WVM_LIFECYCLE_PLANNED,
                   WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED, error,
                   sizeof(error)) != 0,
               "reject route lifecycle before exact route preparation") ||
        expect(build_route_transaction(&prepared_route, 0x51,
                                       &route_transaction, error,
                                       sizeof(error)) == 0 &&
                   wvm_control_plane_record_route_transaction(
                       &control_plane, &route_transaction, error,
                       sizeof(error)) == 0,
               "persist exact prepared route transaction") ||
        expect(wvm_control_plane_transition(
                   &control_plane, &transaction, WVM_LIFECYCLE_PLANNED,
                   WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED, error,
                   sizeof(error)) != 0,
               "reject transaction-only route preparation") ||
        expect(wvm_control_plane_record_route_snapshot(
                   &control_plane, route_transaction.operation_id,
                   &route_snapshot, error, sizeof(error)) == 0,
               "persist complete prepared route snapshot") ||
        expect(wvm_control_plane_transition(
                   &control_plane, &transaction, WVM_LIFECYCLE_PLANNED,
                   WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED, error,
                   sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                       &control_plane, &transaction,
                       WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED,
                       WVM_LIFECYCLE_RESERVATIONS_PREPARED, error,
                       sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                       &control_plane, &transaction,
                       WVM_LIFECYCLE_RESERVATIONS_PREPARED,
                       WVM_LIFECYCLE_PARTICIPANTS_PREPARED, error,
                       sizeof(error)) == 0,
               "persist prepared route, reservation, and participant phases") ||
        expect(wvm_control_plane_read_candidate(
                   &control_plane, &transaction, replayed_candidate_bytes,
                   sizeof(replayed_candidate_bytes),
                   &replayed_candidate_byte_count, error,
                   sizeof(error)) == 0,
               error[0] ? error : "recover candidate bytes from durable journal")) {
        return 1;
    }
    if (replayed_candidate_byte_count != prepared.candidate_manifest_bytes ||
        memcmp(replayed_candidate_bytes, prepared.candidate_manifest_record,
               replayed_candidate_byte_count) != 0) {
        fprintf(stderr,
                "coordinator test: candidate journal replay mismatch "
                "(journal=%zu prepared=%zu)\n",
                replayed_candidate_byte_count,
                prepared.candidate_manifest_bytes);
        return 1;
    }
    for (i = 0; i < prepared.node_runtime_manifest_count; i++) {
        if (expect(wvm_node_runtime_manifest_validate(
                       &prepared.node_runtime_manifests[i], error,
                       sizeof(error)) == 0 &&
                       !prepared.node_runtime_manifests[i].has_activation_fence &&
                       prepared.node_runtime_manifests[i]
                               .startup_dependencies.count == 2,
                   "project prepared runtime dependencies without activation")) {
            return 1;
        }
    }

    prepared_route.route_snapshot_key.scope_key.route_scope_id++;
    memset(&rejected_buffers, 0, sizeof(rejected_buffers));
    initialize_prepared_vm(&rejected_prepared, &rejected_buffers);
    if (expect(wvm_coordinator_prepare(&request, &transaction, &records,
                                       &prepared_route, &options,
                                       &rejected_prepared, error,
                                       sizeof(error)) != 0,
               "reject route snapshot from another transaction")) {
        return 1;
    }
    prepared_route.route_snapshot_key.scope_key.route_scope_id--;

    request.execution_backend_policy = WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM;
    initialize_prepared_vm(&rejected_prepared, &rejected_buffers);
    if (expect(wvm_coordinator_prepare(&request, &transaction, &records,
                                       &prepared_route, &options,
                                       &rejected_prepared, error,
                                       sizeof(error)) != 0,
               "reject TCG profile when request requires KVM")) {
        return 1;
    }
    request.execution_backend_policy = WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG;

    abort_request = request;
    abort_request.request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x43;
    if (expect(wvm_control_plane_begin(
                   &control_plane, &abort_request, &namespace_allocator,
                   &id_provider, &submit_result, &abort_transaction, error,
                   sizeof(error)) == 0 &&
                   submit_result == WVM_CONTROL_PLANE_SUBMIT_NEW,
               "begin independent abortable transaction") ||
        expect(abort_transaction.vm_id == 257 &&
                   abort_transaction.vm_incarnation == 1,
               "allocate a distinct aborted VM incarnation")) {
        return 1;
    }
    fill_options(&abort_options, profile_capabilities, abort_placement_bytes,
                 sizeof(abort_placement_bytes), abort_candidate_bytes,
                 sizeof(abort_candidate_bytes));
    fill_node_launch_plans(&abort_options, abort_launch_plans, nodes,
                           abort_listener_plans, abort_listener_leases);
    for (i = 0; i < 2; i++) {
        abort_launch_plans[i].launch_plan.node_runtime_data_port += 20;
        abort_launch_plans[i].launch_plan.local_executor_service_port += 20;
        abort_listener_plans[i].node_runtime_data_port =
            abort_launch_plans[i].launch_plan.node_runtime_data_port;
        abort_listener_plans[i].local_executor_service_port =
            abort_launch_plans[i].launch_plan.local_executor_service_port;
    }
    if (expect(build_prepared_route(
                   &abort_transaction, &records, &gateway, abort_route_rules,
                   abort_ack_entries, &abort_route_snapshot,
                   &abort_prepared_route, error, sizeof(error)) == 0,
               "build route for abortable transaction")) {
        return 1;
    }
    memset(&abort_buffers, 0, sizeof(abort_buffers));
    initialize_prepared_vm(&abort_prepared, &abort_buffers);
    abort_prepared.reservation_registries = registries;
    abort_prepared.reservation_registry_count =
        sizeof(registries) / sizeof(registries[0]);
    if (expect(wvm_coordinator_prepare(
                   &abort_request, &abort_transaction, &records,
                   &abort_prepared_route, &abort_options, &abort_prepared, error,
                   sizeof(error)) == 0,
               "prepare independent abortable transaction")) {
        return 1;
    }
    if (expect(wvm_control_plane_record_candidate(
                   &control_plane, &abort_transaction, &abort_prepared.candidate,
                   error, sizeof(error)) == 0 &&
                   build_route_transaction(&abort_prepared_route, 0x52,
                                           &abort_route_transaction, error,
                                           sizeof(error)) == 0 &&
                   wvm_control_plane_record_route_transaction(
                       &control_plane, &abort_route_transaction, error,
                       sizeof(error)) == 0 &&
                   wvm_control_plane_record_route_snapshot(
                       &control_plane, abort_route_transaction.operation_id,
                       &abort_route_snapshot, error, sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                       &control_plane, &abort_transaction,
                       WVM_LIFECYCLE_PLANNED,
                       WVM_LIFECYCLE_ROUTE_SCOPE_PREPARED, error,
                       sizeof(error)) == 0,
               "persist abort candidate and prepared route transaction")) {
        return 1;
    }
    memset(&abort_activation, 0, sizeof(abort_activation));
    abort_activation.required_route_snapshot_keys = abort_route_keys;
    abort_activation.required_route_snapshot_capacity =
        sizeof(abort_route_keys) / sizeof(abort_route_keys[0]);
    if (expect(wvm_control_plane_activation_options(
                   &control_plane, activation_options.coordinator_instance_id,
                   &activation_options, error, sizeof(error)) == 0 &&
                   wvm_coordinator_decide_abort(
                   &abort_transaction, &activation_options, &abort_prepared,
                   &abort_activation, error, sizeof(error)) == 0,
               "persist pre-activation abort decision") ||
        expect(abort_activation.decision == WVM_ACTIVATION_ABORT &&
                   !abort_activation.has_activation_fence,
               "abort carries no activation fence") ||
        expect(test_activation_durability(
                   &control_plane, &namespace_allocator, control_plane_journal,
                   &abort_transaction, &abort_activation) == 0,
               "abort decision journal faults and recovery") ||
        expect(wvm_control_plane_record_activation(
                   &control_plane, &abort_transaction, &abort_activation, error,
                   sizeof(error)) == 0,
               "persist pre-activation abort decision after route prepare") ||
        expect(wvm_control_plane_transition(
                   &control_plane, &abort_transaction,
                   WVM_LIFECYCLE_ABORTING, WVM_LIFECYCLE_ABORTED, error,
                   sizeof(error)) != 0,
               "reject abort completion before exact route abort") ||
        expect(test_abort_recovery(&control_plane, &abort_transaction,
                                   &abort_prepared, &abort_route_transaction,
                                   &abort_route_snapshot) == 0,
               "complete abort from the recovered durable decision") ||
        expect(wvm_coordinator_abort_local(
                   &abort_transaction, &abort_prepared, &abort_activation, error,
                   sizeof(error)) == 0,
               "release prepared local state after abort") ||
        expect(wvm_coordinator_abort_local(
                   &abort_transaction, &abort_prepared, &abort_activation, error,
                   sizeof(error)) == 0,
               "replay local abort after partial or completed release")) {
        return 1;
    }
    for (i = 0; i < abort_prepared.reservation_count; i++) {
        if (expect(abort_prepared.reservations[i].state ==
                       WVM_RESERVATION_RELEASED &&
                       bytes_are_zero(
                           abort_prepared.node_runtime_manifests[i]
                               .candidate_manifest_digest,
                           sizeof(abort_prepared.node_runtime_manifests[i]
                                      .candidate_manifest_digest)),
                   "abort releases reservation and clears runtime projection")) {
            return 1;
        }
    }

    memset(&activation, 0, sizeof(activation));
    activation.required_route_snapshot_keys = activation_route_keys;
    activation.required_route_snapshot_capacity =
        sizeof(activation_route_keys) / sizeof(activation_route_keys[0]);
    if (expect(wvm_control_plane_activation_options(
                   &control_plane, activation_options.coordinator_instance_id,
                   &activation_options, error, sizeof(error)) == 0,
               "capture decision metadata from the journal owner")) {
        return 1;
    }
    records.admission_eligibility_revision++;
    if (expect(wvm_coordinator_decide_activation(
                   &request, &transaction, &records, &prepared_route,
                   &id_provider, &activation_options, &prepared, &activation,
                   error, sizeof(error)) != 0,
               "reject activation after eligibility-only change")) {
        return 1;
    }
    records.admission_eligibility_revision--;
    nodes[1].observed_health_state = 2;
    if (expect(wvm_coordinator_decide_activation(
                   &request, &transaction, &records, &prepared_route,
                   &id_provider, &activation_options, &prepared, &activation,
                   error, sizeof(error)) != 0,
               "reject activation after required member health loss")) {
        return 1;
    }
    nodes[1].observed_health_state = 1;
    if (expect(wvm_coordinator_decide_activation(
                   &request, &transaction, &records, &prepared_route,
                   &id_provider, &activation_options, &prepared, &activation,
                   error, sizeof(error)) == 0,
               "decide activation only after current fence revalidation") ||
        expect(activation.decision == WVM_ACTIVATION_ACTIVATE &&
                   activation.required_route_snapshot_count == 1 &&
                   !bytes_are_zero(activation.activation_fence,
                                   sizeof(activation.activation_fence)),
               "bind durable activation fence to prepared candidate")) {
        return 1;
    }
    if (test_reservation_receiver(&prepared, &activation) != 0) {
        return 1;
    }
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        if (test_participant_receiver(&prepared, &activation, &records,
                                       &route_snapshot, scenario) != 0) {
            return 1;
        }
    }
    if (expect(test_activation_durability(
                   &control_plane, &namespace_allocator, control_plane_journal,
                   &transaction, &activation) == 0,
               "activation decision journal faults and recovery") ||
        expect(wvm_control_plane_record_activation(
                   &control_plane, &transaction, &activation, error,
                   sizeof(error)) == 0,
               "persist activation before local commit") ||
        expect(wvm_control_plane_read_activation(
                   &control_plane, &transaction, replayed_activation_bytes,
                   sizeof(replayed_activation_bytes),
                   &replayed_activation_byte_count, error,
                   sizeof(error)) == 0,
               "recover durable activation record") ||
        expect((memset(&replayed_activation, 0, sizeof(replayed_activation)),
                replayed_activation.required_route_snapshot_keys =
                    replayed_activation_route_keys,
                replayed_activation.required_route_snapshot_capacity =
                    sizeof(replayed_activation_route_keys) /
                    sizeof(replayed_activation_route_keys[0]),
                wvm_activation_record_decode(
                    replayed_activation_bytes, replayed_activation_byte_count,
                    &replayed_activation, error, sizeof(error)) == 0) &&
                   replayed_activation.decision == WVM_ACTIVATION_ACTIVATE &&
                   memcmp(replayed_activation.activation_fence,
                          activation.activation_fence,
                          sizeof(activation.activation_fence)) == 0,
               "recovered activation preserves the durable fence")) {
        return 1;
    }
    if (expect(wvm_control_plane_transition(
                   &control_plane, &transaction,
                   WVM_LIFECYCLE_ACTIVATION_DECIDED,
                   WVM_LIFECYCLE_COMMITTED, error, sizeof(error)) != 0,
               "reject commit before exact route activation") ||
        expect(persist_route_transaction_state(
                   &control_plane, &route_transaction,
                   WVM_ROUTE_TRANSACTION_ACTIVATED, error,
                   sizeof(error)) == 0,
               "persist exact route activation before commit")) {
        return 1;
    }
    if (expect(wvm_control_plane_record_runtime_manifest(
                   &control_plane, &transaction,
                   &prepared.node_runtime_manifests[0], error,
                   sizeof(error)) != 0,
               "reject runtime projection before local activation") ||
        expect(wvm_coordinator_commit_local(&transaction, &prepared, &activation,
                                            error, sizeof(error)) == 0 &&
                   wvm_coordinator_commit_local(
                       &transaction, &prepared, &activation, error,
                       sizeof(error)) == 0,
               "commit local reservations after durable activation decision") ||
        expect(wvm_control_plane_transition(
                   &control_plane, &transaction,
                   WVM_LIFECYCLE_ACTIVATION_DECIDED,
                   WVM_LIFECYCLE_COMMITTED, error, sizeof(error)) != 0,
               "reject commit before durable runtime projections")) {
        return 1;
    }
    for (i = 0; i < prepared.node_runtime_manifest_count; i++) {
        if (expect(wvm_control_plane_record_runtime_manifest(
                       &control_plane, &transaction,
                       &prepared.node_runtime_manifests[i], error,
                       sizeof(error)) == 0,
                   "persist activated runtime projection")) {
            return 1;
        }
    }
    if (expect(wvm_control_plane_record_runtime_manifest(
                   &control_plane, &transaction,
                   &prepared.node_runtime_manifests[0], error,
                   sizeof(error)) == 0,
               "replay identical runtime projection") ||
        expect((prepared.node_runtime_manifests[0].local_role_bits |= 4U,
                wvm_control_plane_record_runtime_manifest(
                    &control_plane, &transaction,
                    &prepared.node_runtime_manifests[0], error,
                    sizeof(error)) != 0),
               "reject conflicting runtime projection") ||
        expect((prepared.node_runtime_manifests[0].local_role_bits &= ~4U,
                wvm_node_runtime_manifest_encode(
                    &prepared.node_runtime_manifests[0],
                    expected_runtime_manifest_bytes,
                    sizeof(expected_runtime_manifest_bytes),
                    &expected_runtime_manifest_byte_count, error,
                    sizeof(error)) == 0 &&
                    wvm_control_plane_read_runtime_manifest(
                        &control_plane, &transaction,
                        prepared.node_runtime_manifests[0].physical_node_id,
                        prepared.node_runtime_manifests[0]
                            .expected_node_instance_id,
                        replayed_runtime_manifest_bytes,
                        sizeof(replayed_runtime_manifest_bytes),
                        &replayed_runtime_manifest_byte_count, error,
                        sizeof(error)) == 0 &&
                    replayed_runtime_manifest_byte_count ==
                        expected_runtime_manifest_byte_count &&
                    memcmp(replayed_runtime_manifest_bytes,
                           expected_runtime_manifest_bytes,
                           replayed_runtime_manifest_byte_count) == 0),
               "recover exact durable runtime projection")) {
        return 1;
    }
    if (expect(wvm_coordinator_commit_local(&transaction, &prepared, &activation,
                                            error, sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                   &control_plane, &transaction,
                   WVM_LIFECYCLE_ACTIVATION_DECIDED,
                   WVM_LIFECYCLE_COMMITTED, error, sizeof(error)) == 0,
               "persist committed lifecycle state after local promotion")) {
        return 1;
    }
    for (i = 0; i < prepared.reservation_count; i++) {
        if (expect(prepared.reservations[i].state == WVM_RESERVATION_COMMITTED &&
                       prepared.node_runtime_manifests[i].has_activation_fence &&
                       memcmp(prepared.node_runtime_manifests[i]
                                  .activation_fence,
                              activation.activation_fence,
                              sizeof(activation.activation_fence)) == 0,
                   "promote local reservation and runtime projection")) {
            return 1;
        }
    }
    if (expect(registry_17.prepared_vcpu_slots == 0 &&
                   registry_99.prepared_vcpu_slots == 0 &&
                   registry_17.committed_vcpu_slots != 0 &&
                   registry_99.committed_vcpu_slots != 0,
               "registry preserves committed VM while aborted VM is released")) {
        return 1;
    }
    if (expect(wvm_control_plane_start_if_ready(
                   &control_plane, &transaction,
                   prepared.node_runtime_manifests,
                   prepared.node_runtime_manifest_count, error,
                   sizeof(error)) == -EAGAIN,
               "reject start before runtime readiness evidence")) {
        return 1;
    }
    for (i = 0; i < prepared.node_runtime_manifest_count; i++) {
        if (expect(wvm_runtime_ready_publish(
                       &prepared.node_runtime_manifests[i],
                       prepared.node_runtime_manifests[i]
                           .expected_node_instance_id,
                       error, sizeof(error)) == 0,
                   "publish identity-bound runtime readiness")) {
            return 1;
        }
    }
    if (expect(wvm_control_plane_start_if_ready(
                   &control_plane, &transaction,
                   prepared.node_runtime_manifests,
                   prepared.node_runtime_manifest_count, error,
                   sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                       &control_plane, &transaction, WVM_LIFECYCLE_RUNNING,
                       WVM_LIFECYCLE_STOPPING, error, sizeof(error)) == 0,
               "start only after all runtime readiness evidence")) {
        return 1;
    }
    for (i = 0; i < prepared.node_runtime_manifest_count; i++) {
        if (expect(wvm_runtime_ready_remove(
                       &prepared.node_runtime_manifests[i], error,
                       sizeof(error)) == 0,
                   "remove runtime readiness after stop path begins")) {
            return 1;
        }
    }
    if (expect(wvm_control_plane_transition(
                   &control_plane, &transaction, WVM_LIFECYCLE_STOPPING,
                   WVM_LIFECYCLE_RETIRING, error, sizeof(error)) != 0,
               "reject retirement before exact route retirement") ||
        expect(persist_route_transaction_state(
                   &control_plane, &route_transaction,
                   WVM_ROUTE_TRANSACTION_RETIRING, error,
                   sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                       &control_plane, &transaction, WVM_LIFECYCLE_STOPPING,
                       WVM_LIFECYCLE_RETIRING, error, sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                       &control_plane, &transaction, WVM_LIFECYCLE_RETIRING,
                       WVM_LIFECYCLE_STOPPED, error, sizeof(error)) != 0,
               "persist route retirement before stopping lifecycle") ||
        expect(persist_route_transaction_state(
                   &control_plane, &route_transaction,
                   WVM_ROUTE_TRANSACTION_RETIRED, error,
                   sizeof(error)) == 0 &&
                   wvm_control_plane_transition(
                       &control_plane, &transaction, WVM_LIFECYCLE_RETIRING,
                       WVM_LIFECYCLE_STOPPED, error, sizeof(error)) == 0,
               "complete lifecycle only after exact route retirement")) {
        return 1;
    }

    {
        struct wvm_vm_request orchestrator_request = request;
        struct wvm_coordinator_prepare_options orchestrator_options;
        struct wvm_coordinator_node_launch_plan orchestrator_launch_plans[2];
        struct wvm_admission_node_listener_plan orchestrator_listener_plans[2];
        struct wvm_exclusive_lease orchestrator_listener_leases[2][3];
        struct wvm_capability_ref orchestrator_capabilities[2];
        struct prepared_buffers orchestrator_buffers;
        struct wvm_coordinator_prepared_vm orchestrator_prepared = {0};
        struct wvm_coordinator_prepared_route orchestrator_route;
        struct wvm_route_transaction_record orchestrator_route_transaction;
        struct wvm_route_snapshot_record orchestrator_route_snapshot;
        struct wvm_route_rule_record orchestrator_route_rules[3];
        struct wvm_required_ack_entry orchestrator_ack_entries[1];
        struct wvm_activation_record orchestrator_activation;
        struct wvm_route_snapshot_key orchestrator_activation_keys[1];
        struct orchestrator_test_hooks hooks;
        struct wvm_admission_orchestrator_callbacks callbacks;
        struct wvm_admission_orchestrator_input orchestrator_input;
        struct wvm_admission_recovery_input recovery_input;
        struct wvm_coordinator_transaction orchestrator_transaction;
        enum wvm_control_plane_submit_result orchestrator_submit_result;
        uint8_t orchestrator_placement_bytes[8192];
        uint8_t orchestrator_candidate_bytes[16384];

        orchestrator_request.request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x44;
        orchestrator_capabilities[0] = nodes[0].capability;
        orchestrator_capabilities[1] = nodes[1].capability;
        fill_options(&orchestrator_options, orchestrator_capabilities,
                     orchestrator_placement_bytes,
                     sizeof(orchestrator_placement_bytes),
                     orchestrator_candidate_bytes,
                     sizeof(orchestrator_candidate_bytes));
        fill_node_launch_plans(&orchestrator_options,
                               orchestrator_launch_plans, nodes,
                               orchestrator_listener_plans,
                               orchestrator_listener_leases);
        for (i = 0; i < 2; i++) {
            orchestrator_launch_plans[i]
                .launch_plan.node_runtime_data_port += 40;
            orchestrator_launch_plans[i]
                .launch_plan.local_executor_service_port += 40;
            orchestrator_listener_plans[i].node_runtime_data_port =
                orchestrator_launch_plans[i].launch_plan.node_runtime_data_port;
            orchestrator_listener_plans[i].local_executor_service_port =
                orchestrator_launch_plans[i]
                    .launch_plan.local_executor_service_port;
        }
        memset(&orchestrator_buffers, 0, sizeof(orchestrator_buffers));
        initialize_prepared_vm(&orchestrator_prepared, &orchestrator_buffers);
        orchestrator_prepared.reservation_registries = registries;
        orchestrator_prepared.reservation_registry_count =
            sizeof(registries) / sizeof(registries[0]);
        memset(&orchestrator_route, 0, sizeof(orchestrator_route));
        memset(&orchestrator_route_transaction, 0,
               sizeof(orchestrator_route_transaction));
        memset(&orchestrator_route_snapshot, 0,
               sizeof(orchestrator_route_snapshot));
        memset(&orchestrator_activation, 0, sizeof(orchestrator_activation));
        orchestrator_activation.required_route_snapshot_keys =
            orchestrator_activation_keys;
        orchestrator_activation.required_route_snapshot_capacity =
            sizeof(orchestrator_activation_keys) /
            sizeof(orchestrator_activation_keys[0]);
        memset(&hooks, 0, sizeof(hooks));
        hooks.gateway = &gateway;
        hooks.route_rules = orchestrator_route_rules;
        hooks.ack_entries = orchestrator_ack_entries;
        hooks.route_operation_suffix = 0x53;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.route_plan = orchestrator_route_plan;
        callbacks.route_prepare = orchestrator_route_prepare;
        callbacks.route_commit = orchestrator_route_commit;
        callbacks.route_abort = orchestrator_route_abort;
        callbacks.reservation_prepare = orchestrator_reservation_prepare;
        callbacks.reservation_commit = orchestrator_reservation_commit;
        callbacks.reservation_abort = orchestrator_reservation_abort;
        callbacks.participant_prepare = orchestrator_participant_prepare;
        callbacks.participant_commit = orchestrator_participant_commit;
        callbacks.participant_abort = orchestrator_participant_abort;
        callbacks.participant_ready = orchestrator_participant_ready;
        memset(&orchestrator_input, 0, sizeof(orchestrator_input));
        orchestrator_input.control_plane = &control_plane;
        orchestrator_input.namespace_allocator = &namespace_allocator;
        orchestrator_input.id_provider = &id_provider;
        orchestrator_input.request = &orchestrator_request;
        orchestrator_input.records = &records;
        orchestrator_input.prepared_route = &orchestrator_route;
        orchestrator_input.prepare_options = &orchestrator_options;
        orchestrator_input.prepared_vm = &orchestrator_prepared;
        orchestrator_input.coordinator_instance_id =
            activation_options.coordinator_instance_id;
        orchestrator_input.activation = &orchestrator_activation;
        orchestrator_input.route_transaction =
            &orchestrator_route_transaction;
        orchestrator_input.route_snapshot = &orchestrator_route_snapshot;
        orchestrator_input.callbacks = &callbacks;
        orchestrator_input.callback_context = &hooks;
        orchestrator_input.prepare_input = orchestrator_prepare_input;
        orchestrator_input.transaction_out = &orchestrator_transaction;
        orchestrator_input.submit_result_out = &orchestrator_submit_result;
        if (expect(wvm_admission_orchestrator_run(
                       &orchestrator_input, error, sizeof(error)) == 0 &&
                       orchestrator_submit_result ==
                           WVM_CONTROL_PLANE_SUBMIT_NEW &&
                       orchestrator_activation.has_activation_fence,
                   "run callback-driven admission orchestrator") ||
            expect(hooks.route_prepares == 1 && hooks.route_commits == 1 &&
                       hooks.reservation_prepares == 2 &&
                       hooks.reservation_commits == 2 &&
                       hooks.participant_prepares == 2 &&
                       hooks.participant_commits == 2 &&
                       hooks.participant_readies == 2,
                   "orchestrator executes every prepare and commit stage") ||
            expect(wvm_control_plane_find_request(
                       &control_plane, orchestrator_request.request_id)
                           ->transaction.state == WVM_LIFECYCLE_RUNNING,
                   "orchestrator reaches RUNNING only after readiness") ||
            expect(wvm_admission_orchestrator_run(
                       &orchestrator_input, error, sizeof(error)) == 0 &&
                       orchestrator_submit_result ==
                           WVM_CONTROL_PLANE_SUBMIT_REPLAY &&
                       hooks.route_prepares == 1,
                   "orchestrator replay does not repeat transport callbacks")) {
            return 1;
        }
        for (i = 0; i < orchestrator_prepared.node_runtime_manifest_count;
             i++) {
            if (expect(wvm_runtime_ready_remove(
                           &orchestrator_prepared.node_runtime_manifests[i],
                           error, sizeof(error)) == 0,
                       "remove orchestrator readiness evidence")) {
                return 1;
            }
        }

        {
            struct wvm_admission_node failure_nodes[2];
            struct wvm_resource_reservation failure_storage[2][4];
            struct wvm_local_reservation_registry failure_registries_storage[2];
            struct wvm_local_reservation_registry *failure_registries[2] = {
                &failure_registries_storage[1], &failure_registries_storage[0]};

            admission_node_from_record(&failure_nodes[0], &nodes[0]);
            admission_node_from_record(&failure_nodes[1], &nodes[1]);
            if (expect(wvm_local_reservation_registry_init(
                           &failure_registries_storage[0], &failure_nodes[0],
                           failure_storage[0],
                           sizeof(failure_storage[0]) /
                               sizeof(failure_storage[0][0]),
                           error, sizeof(error)) == 0 &&
                           wvm_local_reservation_registry_init(
                               &failure_registries_storage[1],
                               &failure_nodes[1], failure_storage[1],
                               sizeof(failure_storage[1]) /
                                   sizeof(failure_storage[1][0]),
                               error, sizeof(error)) == 0,
                       "initialize isolated orchestrator failure registries")) {
                return 1;
            }

        orchestrator_request.request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x45;
        hooks.failure = ORCHESTRATOR_TEST_RESERVATION_PREPARE;
        hooks.route_operation_suffix = 0x54;
        hooks.route_prepares = 0;
        hooks.route_commits = 0;
        hooks.route_aborts = 0;
        hooks.reservation_prepares = 0;
        hooks.reservation_commits = 0;
        hooks.reservation_aborts = 0;
        hooks.participant_prepares = 0;
        hooks.participant_commits = 0;
        hooks.participant_aborts = 0;
        hooks.participant_readies = 0;
        for (i = 0; i < 2; i++) {
            orchestrator_launch_plans[i]
                .launch_plan.node_runtime_data_port += 40;
            orchestrator_launch_plans[i]
                .launch_plan.local_executor_service_port += 40;
            orchestrator_listener_plans[i].node_runtime_data_port =
                orchestrator_launch_plans[i].launch_plan.node_runtime_data_port;
            orchestrator_listener_plans[i].local_executor_service_port =
                orchestrator_launch_plans[i]
                    .launch_plan.local_executor_service_port;
        }
        memset(&orchestrator_buffers, 0, sizeof(orchestrator_buffers));
        initialize_prepared_vm(&orchestrator_prepared, &orchestrator_buffers);
        orchestrator_prepared.reservation_registries = failure_registries;
        orchestrator_prepared.reservation_registry_count =
            sizeof(failure_registries) / sizeof(failure_registries[0]);
        memset(&orchestrator_route, 0, sizeof(orchestrator_route));
        memset(&orchestrator_route_transaction, 0,
               sizeof(orchestrator_route_transaction));
        memset(&orchestrator_route_snapshot, 0,
               sizeof(orchestrator_route_snapshot));
        memset(&orchestrator_activation, 0, sizeof(orchestrator_activation));
        orchestrator_activation.required_route_snapshot_keys =
            orchestrator_activation_keys;
        orchestrator_activation.required_route_snapshot_capacity = 1;
        if (expect(wvm_admission_orchestrator_run(
                       &orchestrator_input, error, sizeof(error)) != 0 &&
                       orchestrator_submit_result ==
                           WVM_CONTROL_PLANE_SUBMIT_NEW &&
                       wvm_control_plane_find_request(
                           &control_plane, orchestrator_request.request_id)
                               ->transaction.state == WVM_LIFECYCLE_ABORTED &&
                       wvm_control_plane_find_route_transaction(
                           &control_plane,
                           orchestrator_route_transaction.operation_id)
                               ->state == WVM_ROUTE_TRANSACTION_ABORTED &&
                       hooks.route_aborts == 1 &&
                       hooks.reservation_aborts == 2 &&
                       failure_registries_storage[0].prepared_vcpu_slots == 0 &&
                       failure_registries_storage[1].prepared_vcpu_slots == 0,
                   "pre-activation failure durably aborts and cleans up")) {
            return 1;
        }

        for (unsigned fault = 0; fault < 2; fault++) {
            orchestrator_request.request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x46 + fault;
            hooks.failure = fault ? ORCHESTRATOR_TEST_ACTIVATION_FSYNC
                                  : ORCHESTRATOR_TEST_PARTICIPANT_COMMIT;
            hooks.route_operation_suffix = 0x55 + fault;
            hooks.route_prepares = 0;
            hooks.route_commits = 0;
            hooks.route_aborts = 0;
            hooks.reservation_prepares = 0;
            hooks.reservation_commits = 0;
            hooks.reservation_aborts = 0;
            hooks.participant_prepares = 0;
            hooks.participant_commits = 0;
            hooks.participant_aborts = 0;
            hooks.participant_readies = 0;
            for (i = 0; i < 2; i++) {
                orchestrator_launch_plans[i]
                    .launch_plan.node_runtime_data_port += 40;
                orchestrator_launch_plans[i]
                    .launch_plan.local_executor_service_port += 40;
                orchestrator_listener_plans[i].node_runtime_data_port =
                    orchestrator_launch_plans[i].launch_plan.node_runtime_data_port;
                orchestrator_listener_plans[i].local_executor_service_port =
                    orchestrator_launch_plans[i]
                        .launch_plan.local_executor_service_port;
            }
            memset(&orchestrator_buffers, 0, sizeof(orchestrator_buffers));
            initialize_prepared_vm(&orchestrator_prepared, &orchestrator_buffers);
            orchestrator_prepared.reservation_registries = failure_registries;
            orchestrator_prepared.reservation_registry_count =
                sizeof(failure_registries) / sizeof(failure_registries[0]);
            memset(&orchestrator_route, 0, sizeof(orchestrator_route));
            memset(&orchestrator_route_transaction, 0,
                   sizeof(orchestrator_route_transaction));
            memset(&orchestrator_route_snapshot, 0,
                   sizeof(orchestrator_route_snapshot));
            memset(&orchestrator_activation, 0, sizeof(orchestrator_activation));
            orchestrator_activation.required_route_snapshot_keys =
                orchestrator_activation_keys;
            orchestrator_activation.required_route_snapshot_capacity = 1;
            if (expect(wvm_admission_orchestrator_run(
                           &orchestrator_input, error, sizeof(error)) != 0 &&
                           orchestrator_submit_result ==
                               WVM_CONTROL_PLANE_SUBMIT_NEW &&
                           orchestrator_activation.has_activation_fence &&
                           wvm_control_plane_find_request(
                               &control_plane, orchestrator_request.request_id)
                                   ->transaction.state ==
                               (fault ? WVM_LIFECYCLE_PARTICIPANTS_PREPARED
                                      : WVM_LIFECYCLE_ACTIVATION_DECIDED) &&
                           wvm_control_plane_find_route_transaction(
                               &control_plane,
                               orchestrator_route_transaction.operation_id)
                                   ->state == WVM_ROUTE_TRANSACTION_PREPARING &&
                           hooks.route_aborts == 0 &&
                           hooks.reservation_aborts == 0 &&
                           hooks.participant_aborts == 0 &&
                           (!fault || (control_plane.journal_failed &&
                                        hooks.reservation_commits == 0 &&
                                        hooks.participant_commits == 0)),
                       "post-activation failure remains recoverable")) {
                return 1;
            }
            if (fault) {
                wvm_control_plane_close(&control_plane);
                wvm_vm_namespace_allocator_init(
                    &namespace_allocator, namespace_records,
                    sizeof(namespace_records) / sizeof(namespace_records[0]), 1);
                if (expect(wvm_control_plane_open(
                               &control_plane, control_plane_journal,
                               &namespace_allocator, error, sizeof(error)) == 0 &&
                               wvm_control_plane_find_request(
                                   &control_plane, orchestrator_request.request_id)
                                       ->transaction.state ==
                                   WVM_LIFECYCLE_ACTIVATION_DECIDED,
                           "orchestrator resumes a surviving uncertain decision forward")) {
                    return 1;
                }
            }
            hooks.failure = ORCHESTRATOR_TEST_NO_FAILURE;
            memset(&recovery_input, 0, sizeof(recovery_input));
            recovery_input.control_plane = &control_plane;
            recovery_input.transaction = &orchestrator_transaction;
            recovery_input.prepared_vm = &orchestrator_prepared;
            recovery_input.route_transaction = &orchestrator_route_transaction;
            recovery_input.route_snapshot = &orchestrator_route_snapshot;
            recovery_input.callbacks = &callbacks;
            recovery_input.callback_context = &hooks;
            if (test_recovery_guards(&recovery_input,
                                     abort_route_transaction.operation_id) != 0) {
                return 1;
            }
            /* Recovery must not depend on the process's old decision or route state. */
            memset(&orchestrator_activation, 0, sizeof(orchestrator_activation));
            orchestrator_route_transaction.state = WVM_ROUTE_TRANSACTION_ABORTED;
            if (expect(wvm_admission_orchestrator_recover(
                           &recovery_input, error, sizeof(error)) == 0 &&
                           wvm_control_plane_find_request(
                               &control_plane, orchestrator_request.request_id)
                                   ->transaction.state == WVM_LIFECYCLE_RUNNING &&
                           hooks.reservation_aborts == 0 &&
                           hooks.participant_aborts == 0,
                       "recover durable activation to RUNNING")) {
                return 1;
            }
            for (i = 0; i < orchestrator_prepared.node_runtime_manifest_count;
                 i++) {
                if (expect(wvm_runtime_ready_remove(
                               &orchestrator_prepared.node_runtime_manifests[i],
                               error, sizeof(error)) == 0,
                           "remove recovered readiness evidence")) {
                    return 1;
                }
            }
        }
            wvm_local_reservation_registry_destroy(
                &failure_registries_storage[0]);
            wvm_local_reservation_registry_destroy(
                &failure_registries_storage[1]);
        }
        wvm_coordinator_prepared_vm_cleanup(&orchestrator_prepared);
    }

    capabilities[3].state = WVM_CAPABILITY_UNAVAILABLE;
    capabilities[3].reason_code = 1;
    capabilities[7].state = WVM_CAPABILITY_UNAVAILABLE;
    capabilities[7].reason_code = 1;
    if (expect(refresh_node_profile(&nodes[0], capabilities, 4) == 0 &&
                   refresh_node_profile(&nodes[1], capabilities + 4, 4) == 0,
               "refresh capability profile after probe change")) {
        return 1;
    }
    initialize_prepared_vm(&rejected_prepared, &rejected_buffers);
    if (expect(wvm_coordinator_prepare(&request, &transaction, &records,
                                       &prepared_route, &options,
                                       &rejected_prepared, error,
                                       sizeof(error)) != 0,
               "reject participants without V1 namespace capability")) {
        return 1;
    }

    wvm_control_plane_close(&control_plane);
    wvm_vm_namespace_allocator_init(
        &recovered_namespace_allocator, recovered_namespace_records,
        sizeof(recovered_namespace_records) /
            sizeof(recovered_namespace_records[0]),
        1);
    wvm_control_plane_init(
        &recovered_control_plane, recovered_control_plane_entries,
        sizeof(recovered_control_plane_entries) /
            sizeof(recovered_control_plane_entries[0]));
    wvm_control_plane_set_route_transaction_entries(
        &recovered_control_plane, recovered_control_plane_route_entries,
        sizeof(recovered_control_plane_route_entries) /
            sizeof(recovered_control_plane_route_entries[0]));
    wvm_control_plane_set_runtime_manifest_entries(
        &recovered_control_plane, recovered_runtime_manifest_entries,
        sizeof(recovered_runtime_manifest_entries) /
            sizeof(recovered_runtime_manifest_entries[0]));
    if (expect(wvm_control_plane_open(
                   &recovered_control_plane, control_plane_journal,
                   &recovered_namespace_allocator, error, sizeof(error)) == 0 &&
                   wvm_control_plane_read_runtime_manifest(
                       &recovered_control_plane, &transaction,
                       prepared.node_runtime_manifests[0].physical_node_id,
                       prepared.node_runtime_manifests[0]
                           .expected_node_instance_id,
                       replayed_runtime_manifest_bytes,
                       sizeof(replayed_runtime_manifest_bytes),
                       &replayed_runtime_manifest_byte_count, error,
                       sizeof(error)) == 0 &&
                   replayed_runtime_manifest_byte_count ==
                       expected_runtime_manifest_byte_count &&
                   memcmp(replayed_runtime_manifest_bytes,
                          expected_runtime_manifest_bytes,
                          replayed_runtime_manifest_byte_count) == 0,
               "recover exact runtime projection after journal restart")) {
        wvm_control_plane_close(&recovered_control_plane);
        wvm_local_reservation_registry_destroy(&registry_17);
        wvm_local_reservation_registry_destroy(&registry_99);
        unlink(control_plane_journal);
        return 1;
    }
    wvm_control_plane_close(&recovered_control_plane);
    wvm_local_reservation_registry_destroy(&registry_17);
    wvm_local_reservation_registry_destroy(&registry_99);
    wvm_coordinator_prepared_vm_cleanup(&prepared);
    wvm_coordinator_prepared_vm_cleanup(&rejected_prepared);
    wvm_coordinator_prepared_vm_cleanup(&abort_prepared);
    unlink(control_plane_journal);
    puts("coordinator tests: PASS");
    return 0;
}

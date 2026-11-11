/*
 * ACTIVATION_DECIDED cold-start live oracle.
 *
 * persist: run production orchestrator until a post-activation participant
 *          commit fault leaves the durable journal at ACTIVATION_DECIDED,
 *          close the coordinator, and exit.
 * recover: a new process reopens that journal, rebuilds the same prepare
 *          inputs, and calls wvm_admission_orchestrator_recover
 *          (replay commit/start toward COMMITTED/RUNNING, or fail-closed).
 */
#define WVM_SKIP_COORDINATOR_MAIN
#include "test_coordinator.c"

#include <limits.h>
#include <stdint.h>

struct cold_cluster {
    struct wvm_capability_record capabilities[8];
    struct wvm_node_record nodes[2];
    struct wvm_gateway_record gateway;
    struct wvm_cluster_record_set records;
    uint32_t gateway_ids[1];
};

static int cold_init_cluster(struct cold_cluster *c)
{
    char error[256];

    memset(c, 0, sizeof(*c));
    (void)error;
    c->gateway_ids[0] = 3;
    fill_capability(&c->capabilities[0], WVM_CAPABILITY_ID_EXECUTION_KVM, 17,
                    101, 1);
    fill_capability(&c->capabilities[1], WVM_CAPABILITY_ID_EXECUTION_TCG, 17,
                    101, 2);
    fill_capability(&c->capabilities[2], WVM_CAPABILITY_ID_MODE_B_MEMORY, 17,
                    101, 3);
    fill_capability(&c->capabilities[3], WVM_CAPABILITY_ID_VM_ID_U32, 17, 101,
                    4);
    fill_capability(&c->capabilities[4], WVM_CAPABILITY_ID_EXECUTION_KVM, 99,
                    202, 1);
    fill_capability(&c->capabilities[5], WVM_CAPABILITY_ID_EXECUTION_TCG, 99,
                    202, 2);
    fill_capability(&c->capabilities[6], WVM_CAPABILITY_ID_MODE_B_MEMORY, 99,
                    202, 3);
    fill_capability(&c->capabilities[7], WVM_CAPABILITY_ID_VM_ID_U32, 99, 202,
                    4);
    error[0] = '\0';
    if (fill_node(&c->nodes[0], 17, 101, 1, c->capabilities, 4, c->gateway_ids,
                  1) != 0 ||
        fill_node(&c->nodes[1], 99, 202, 2, c->capabilities + 4, 4, NULL, 0) !=
            0) {
        fprintf(stderr, "cold-start: cannot fill nodes\n");
        return -1;
    }
    c->gateway.gateway_id = 3;
    c->gateway.gateway_instance_id = 301;
    c->gateway.hosting_physical_node_id = 17;
    c->gateway.failure_domain_id = 1;
    fill_endpoint(&c->gateway.endpoint, 17, 9400, 9401);
    c->gateway.role_bits = 1;
    c->gateway.desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    c->gateway.observed_health_state = 1;
    c->gateway.membership_revision = 5;
    c->gateway.topology_revision = 6;
    c->records.nodes = c->nodes;
    c->records.node_count = 2;
    c->records.gateways = &c->gateway;
    c->records.gateway_count = 1;
    c->records.capability_records = c->capabilities;
    c->records.capability_record_count = 8;
    c->records.inventory_revision = 10;
    c->records.membership_revision = 5;
    c->records.topology_revision = 6;
    c->records.admission_eligibility_revision = 7;
    c->records.capability_profile_generation = 9;
    return 0;
}


static void format_id_hex(const uint8_t *id, char *out, size_t out_len)
{
    size_t i;

    if (!out || out_len < (WVM_IDENTITY_ID_BYTES * 2 + 1)) {
        if (out && out_len) {
            out[0] = '\0';
        }
        return;
    }
    for (i = 0; i < WVM_IDENTITY_ID_BYTES; i++) {
        sprintf(out + (i * 2), "%02x", id[i]);
    }
}

/*
 * Same lookup ctl uses in wvm_ctl_recover_midflight_admissions:
 * journal route entries matched by prepared_route_snapshot_key.
 */
static int cold_find_route_operation(
    const struct wvm_control_plane *plane,
    const struct wvm_route_snapshot_key *snapshot_key,
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error, size_t error_len)
{
    struct wvm_required_ack_entry acks[8];
    struct wvm_required_ack_entry drain[8];
    size_t i;
    int found = 0;

    if (!plane || !snapshot_key || !operation_id) {
        snprintf(error, error_len, "route snapshot lookup input is invalid");
        return -1;
    }
    for (i = 0; i < plane->route_entry_count; i++) {
        struct wvm_route_transaction_record decoded;
        const struct wvm_control_plane_route_entry *rent =
            &plane->route_entries[i];
        char decode_error[256];

        if (!rent->record_bytes || rent->record_byte_count == 0) {
            continue;
        }
        memset(&decoded, 0, sizeof(decoded));
        decoded.required_ack_set.entries.entries = acks;
        decoded.required_ack_set.entries.capacity = 8;
        decoded.optional_departure_drain_set.entries = drain;
        decoded.optional_departure_drain_set.capacity = 8;
        decode_error[0] = '\0';
        if (wvm_route_transaction_record_decode(
                rent->record_bytes, rent->record_byte_count, &decoded,
                decode_error, sizeof(decode_error)) != 0) {
            continue;
        }
        if (decoded.route_snapshot_key.scope_key.vm_id ==
                snapshot_key->scope_key.vm_id &&
            decoded.route_snapshot_key.scope_key.vm_incarnation ==
                snapshot_key->scope_key.vm_incarnation &&
            decoded.route_snapshot_key.scope_key.route_scope_id ==
                snapshot_key->scope_key.route_scope_id &&
            decoded.route_snapshot_key.topology_revision ==
                snapshot_key->topology_revision &&
            decoded.route_snapshot_key.route_generation ==
                snapshot_key->route_generation &&
            memcmp(decoded.route_snapshot_key.snapshot_digest,
                   snapshot_key->snapshot_digest,
                   WVM_SHA256_DIGEST_BYTES) == 0) {
            if (found) {
                snprintf(error, error_len,
                         "route snapshot maps to multiple operations");
                return -1;
            }
            memcpy(operation_id, decoded.operation_id, WVM_IDENTITY_ID_BYTES);
            found = 1;
        }
    }
    if (!found) {
        snprintf(error, error_len,
                 "route snapshot has no durable route operation "
                 "(route_entry_count=%zu)",
                 plane->route_entry_count);
        return -1;
    }
    return 0;
}

static int cold_persist(const char *journal_path)
{
    struct cold_cluster cluster;
    struct wvm_vm_request request;
    struct wvm_vm_namespace_record namespace_records[6];
    struct wvm_vm_namespace_allocator namespace_allocator;
    struct wvm_control_plane_entry entries[6];
    struct wvm_control_plane_route_entry route_entries[6];
    struct wvm_control_plane_runtime_manifest_entry runtime_entries[12];
    struct wvm_control_plane plane;
    struct id_provider_context provider_context = {
        .next_id = 1,
        .next_route_scope_id = 1,
    };
    struct wvm_coordinator_id_provider id_provider = {
        .context = &provider_context,
        .allocate_id16 = allocate_id16,
        .allocate_route_scope_id = allocate_route_scope_id,
    };
    struct wvm_admission_node reservation_nodes[2];
    struct wvm_resource_reservation registry_storage[2][4];
    struct wvm_local_reservation_registry registry_17;
    struct wvm_local_reservation_registry registry_99;
    struct wvm_local_reservation_registry *registries[2];
    struct wvm_coordinator_prepare_options options;
    struct wvm_coordinator_node_launch_plan launch_plans[2];
    struct wvm_admission_node_listener_plan listener_plans[2];
    struct wvm_exclusive_lease listener_leases[2][3];
    struct wvm_capability_ref profile_capabilities[2];
    struct prepared_buffers buffers;
    struct wvm_coordinator_prepared_vm prepared = {0};
    struct wvm_coordinator_prepared_route route;
    struct wvm_route_transaction_record route_transaction;
    struct wvm_route_snapshot_record route_snapshot;
    struct wvm_route_rule_record route_rules[3];
    struct wvm_required_ack_entry ack_entries[1];
    struct wvm_activation_record activation;
    struct wvm_route_snapshot_key activation_keys[1];
    struct orchestrator_test_hooks hooks;
    struct wvm_admission_orchestrator_callbacks callbacks;
    struct wvm_admission_orchestrator_input input;
    struct wvm_coordinator_transaction transaction;
    enum wvm_control_plane_submit_result submit_result;
    uint8_t placement_bytes[8192];
    uint8_t candidate_bytes[16384];
    const struct wvm_control_plane_entry *entry;
    char error[256];
    int fd;
    int rc = 1;

    error[0] = '\0';
    if (cold_init_cluster(&cluster) != 0) {
        return 1;
    }
    fd = open(journal_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        perror("cold-start persist journal");
        return 1;
    }
    close(fd);

    fill_request(&request);
    request.request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x44;
    admission_node_from_record(&reservation_nodes[0], &cluster.nodes[0]);
    admission_node_from_record(&reservation_nodes[1], &cluster.nodes[1]);
    if (wvm_local_reservation_registry_init(
            &registry_17, &reservation_nodes[0], registry_storage[0],
            sizeof(registry_storage[0]) / sizeof(registry_storage[0][0]), error,
            sizeof(error)) != 0 ||
        wvm_local_reservation_registry_init(
            &registry_99, &reservation_nodes[1], registry_storage[1],
            sizeof(registry_storage[1]) / sizeof(registry_storage[1][0]), error,
            sizeof(error)) != 0) {
        fprintf(stderr, "cold-start persist registry: %s\n", error);
        return 1;
    }
    registries[0] = &registry_99;
    registries[1] = &registry_17;
    wvm_vm_namespace_allocator_init(&namespace_allocator, namespace_records,
                                    6, 1);
    wvm_control_plane_init(&plane, entries, 6);
    wvm_control_plane_set_route_transaction_entries(&plane, route_entries, 6);
    wvm_control_plane_set_runtime_manifest_entries(&plane, runtime_entries, 12);
    if (wvm_control_plane_open(&plane, journal_path, &namespace_allocator,
                               error, sizeof(error)) != 0) {
        fprintf(stderr, "cold-start persist open: %s\n", error);
        goto out_reg;
    }

    profile_capabilities[0] = cluster.nodes[0].capability;
    profile_capabilities[1] = cluster.nodes[1].capability;
    fill_options(&options, profile_capabilities, placement_bytes,
                 sizeof(placement_bytes), candidate_bytes,
                 sizeof(candidate_bytes));
    fill_node_launch_plans(&options, launch_plans, cluster.nodes, listener_plans,
                           listener_leases);
    memset(&buffers, 0, sizeof(buffers));
    initialize_prepared_vm(&prepared, &buffers);
    prepared.reservation_registries = registries;
    prepared.reservation_registry_count = 2;
    memset(&route, 0, sizeof(route));
    memset(&route_transaction, 0, sizeof(route_transaction));
    memset(&route_snapshot, 0, sizeof(route_snapshot));
    memset(&activation, 0, sizeof(activation));
    activation.required_route_snapshot_keys = activation_keys;
    activation.required_route_snapshot_capacity = 1;
    memset(&hooks, 0, sizeof(hooks));
    hooks.gateway = &cluster.gateway;
    hooks.route_rules = route_rules;
    hooks.ack_entries = ack_entries;
    hooks.route_operation_suffix = 0x55;
    hooks.failure = ORCHESTRATOR_TEST_PARTICIPANT_COMMIT;
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
    memset(&input, 0, sizeof(input));
    input.control_plane = &plane;
    input.namespace_allocator = &namespace_allocator;
    input.id_provider = &id_provider;
    input.request = &request;
    input.records = &cluster.records;
    input.prepared_route = &route;
    input.prepare_options = &options;
    input.prepared_vm = &prepared;
    input.coordinator_instance_id = 77;
    input.activation = &activation;
    input.route_transaction = &route_transaction;
    input.route_snapshot = &route_snapshot;
    input.callbacks = &callbacks;
    input.callback_context = &hooks;
    input.prepare_input = orchestrator_prepare_input;
    input.transaction_out = &transaction;
    input.submit_result_out = &submit_result;

    if (wvm_admission_orchestrator_run(&input, error, sizeof(error)) == 0) {
        fprintf(stderr,
                "cold-start persist: expected post-activation commit fault\n");
        goto out_plane;
    }
    entry = wvm_control_plane_find_request(&plane, request.request_id);
    if (!entry ||
        entry->transaction.state != WVM_LIFECYCLE_ACTIVATION_DECIDED ||
        !activation.has_activation_fence) {
        fprintf(stderr,
                "cold-start persist: state=%u fence=%d err=%s\n",
                entry ? (unsigned)entry->transaction.state : 0U,
                activation.has_activation_fence, error[0] ? error : "(none)");
        goto out_plane;
    }
    {
        char op_hex[WVM_IDENTITY_ID_BYTES * 2 + 1];

        format_id_hex(route_transaction.operation_id, op_hex, sizeof(op_hex));
        printf("EVID ACTIVATION_DECIDED_persist: vm_id=%u incarnation=%llu "
               "state=%u fence=1 pid=%d journal=%s route_entries=%zu "
               "has_route_key=%d has_candidate=%d operation_id=%s\n",
               entry->transaction.vm_id,
               (unsigned long long)entry->transaction.vm_incarnation,
               (unsigned)entry->transaction.state, (int)getpid(), journal_path,
               plane.route_entry_count,
               entry->transaction.has_prepared_route_snapshot_key,
               entry->transaction.has_candidate_manifest_digest, op_hex);
    }
    fflush(stdout);
    rc = 0;

out_plane:
    wvm_control_plane_close(&plane);
    wvm_coordinator_prepared_vm_cleanup(&prepared);
out_reg:
    wvm_local_reservation_registry_destroy(&registry_17);
    wvm_local_reservation_registry_destroy(&registry_99);
    return rc;
}

static int cold_recover(const char *journal_path)
{
    struct cold_cluster cluster;
    struct wvm_vm_request request;
    struct wvm_vm_namespace_record namespace_records[6];
    struct wvm_vm_namespace_allocator namespace_allocator;
    struct wvm_control_plane_entry entries[6];
    struct wvm_control_plane_route_entry route_entries[6];
    struct wvm_control_plane_runtime_manifest_entry runtime_entries[12];
    struct wvm_control_plane plane;
    struct wvm_admission_node reservation_nodes[2];
    struct wvm_resource_reservation registry_storage[2][4];
    struct wvm_local_reservation_registry registry_17;
    struct wvm_local_reservation_registry registry_99;
    struct wvm_local_reservation_registry *registries[2];
    struct wvm_coordinator_prepare_options options;
    struct wvm_coordinator_node_launch_plan launch_plans[2];
    struct wvm_admission_node_listener_plan listener_plans[2];
    struct wvm_exclusive_lease listener_leases[2][3];
    struct wvm_capability_ref profile_capabilities[2];
    struct prepared_buffers buffers;
    struct wvm_coordinator_prepared_vm prepared = {0};
    struct wvm_coordinator_prepared_route route;
    struct wvm_route_transaction_record route_transaction;
    struct wvm_route_snapshot_record route_snapshot;
    struct wvm_route_rule_record route_rules[3];
    struct wvm_required_ack_entry ack_entries[1];
    struct wvm_required_ack_entry route_tx_acks[8];
    struct wvm_required_ack_entry route_tx_drain[8];
    struct wvm_activation_record activation;
    struct wvm_route_snapshot_key activation_keys[1];
    struct orchestrator_test_hooks hooks;
    struct wvm_admission_orchestrator_callbacks callbacks;
    struct wvm_admission_recovery_input recovery_input;
    struct wvm_coordinator_transaction transaction;
    const struct wvm_control_plane_entry *entry;
    uint8_t placement_bytes[8192];
    uint8_t candidate_bytes[16384];
    char error[256];
    int recover_rc;
    uint16_t state_before = 0;
    uint16_t state_after = 0;
    int rc = 1;

    error[0] = '\0';
    if (cold_init_cluster(&cluster) != 0) {
        return 1;
    }
    fill_request(&request);
    request.request_id[WVM_IDENTITY_ID_BYTES - 1] = 0x44;
    admission_node_from_record(&reservation_nodes[0], &cluster.nodes[0]);
    admission_node_from_record(&reservation_nodes[1], &cluster.nodes[1]);
    if (wvm_local_reservation_registry_init(
            &registry_17, &reservation_nodes[0], registry_storage[0],
            sizeof(registry_storage[0]) / sizeof(registry_storage[0][0]), error,
            sizeof(error)) != 0 ||
        wvm_local_reservation_registry_init(
            &registry_99, &reservation_nodes[1], registry_storage[1],
            sizeof(registry_storage[1]) / sizeof(registry_storage[1][0]), error,
            sizeof(error)) != 0) {
        fprintf(stderr, "cold-start recover registry: %s\n", error);
        return 1;
    }
    registries[0] = &registry_99;
    registries[1] = &registry_17;
    wvm_vm_namespace_allocator_init(&namespace_allocator, namespace_records,
                                    6, 1);
    wvm_control_plane_init(&plane, entries, 6);
    wvm_control_plane_set_route_transaction_entries(&plane, route_entries, 6);
    wvm_control_plane_set_runtime_manifest_entries(&plane, runtime_entries, 12);
    if (wvm_control_plane_open(&plane, journal_path, &namespace_allocator,
                               error, sizeof(error)) != 0) {
        fprintf(stderr, "cold-start recover open: %s\n", error);
        goto out_reg;
    }
    entry = wvm_control_plane_find_request(&plane, request.request_id);
    if (!entry ||
        entry->transaction.state != WVM_LIFECYCLE_ACTIVATION_DECIDED) {
        fprintf(stderr,
                "cold-start recover: journal is not ACTIVATION_DECIDED "
                "(entry=%p state=%u)\n",
                (void *)entry,
                entry ? (unsigned)entry->transaction.state : 0U);
        goto out_plane;
    }
    state_before = entry->transaction.state;
    memset(&transaction, 0, sizeof(transaction));
    memcpy(transaction.request_id, entry->transaction.request_id,
           sizeof(transaction.request_id));
    transaction.vm_id = entry->transaction.vm_id;
    transaction.vm_incarnation = entry->transaction.vm_incarnation;
    transaction.manifest_generation = entry->transaction.manifest_generation;
    memcpy(transaction.admission_tx_id, entry->transaction.admission_tx_id,
           sizeof(transaction.admission_tx_id));
    memcpy(transaction.manifest_id, entry->transaction.manifest_id,
           sizeof(transaction.manifest_id));
    transaction.route_scope_key = entry->transaction.route_scope_key;
    printf("EVID ACTIVATION_DECIDED_cold_open: vm_id=%u incarnation=%llu "
           "state=%u pid=%d journal=%s\n",
           transaction.vm_id, (unsigned long long)transaction.vm_incarnation,
           (unsigned)state_before, (int)getpid(), journal_path);
    fflush(stdout);

    profile_capabilities[0] = cluster.nodes[0].capability;
    profile_capabilities[1] = cluster.nodes[1].capability;
    fill_options(&options, profile_capabilities, placement_bytes,
                 sizeof(placement_bytes), candidate_bytes,
                 sizeof(candidate_bytes));
    fill_node_launch_plans(&options, launch_plans, cluster.nodes, listener_plans,
                           listener_leases);
    memset(&buffers, 0, sizeof(buffers));
    initialize_prepared_vm(&prepared, &buffers);
    prepared.reservation_registries = registries;
    prepared.reservation_registry_count = 2;
    memset(&route, 0, sizeof(route));
    memset(&route_transaction, 0, sizeof(route_transaction));
    memset(&route_snapshot, 0, sizeof(route_snapshot));
    if (build_prepared_route(&transaction, &cluster.records, &cluster.gateway,
                             route_rules, ack_entries, &route_snapshot, &route,
                             error, sizeof(error)) != 0) {
        fprintf(stderr, "cold-start recover route: %s\n", error);
        goto out_plane;
    }
    initialize_prepared_vm(&prepared, &buffers);
    prepared.reservation_registries = registries;
    prepared.reservation_registry_count = 2;
    error[0] = '\0';
    if (wvm_coordinator_prepare(&request, &transaction, &cluster.records, &route,
                                &options, &prepared, error,
                                sizeof(error)) != 0) {
        fprintf(stderr, "cold-start recover prepare: %s\n", error);
        goto out_plane;
    }

    memset(&activation, 0, sizeof(activation));
    activation.required_route_snapshot_keys = activation_keys;
    activation.required_route_snapshot_capacity = 1;
    memset(&hooks, 0, sizeof(hooks));
    hooks.gateway = &cluster.gateway;
    hooks.route_rules = route_rules;
    hooks.ack_entries = ack_entries;
    hooks.route_operation_suffix = 0x55;
    hooks.failure = ORCHESTRATOR_TEST_NO_FAILURE;
    hooks.defer_ready = 0;
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
    memset(&recovery_input, 0, sizeof(recovery_input));
    recovery_input.control_plane = &plane;
    recovery_input.transaction = &transaction;
    recovery_input.prepared_vm = &prepared;
    recovery_input.route_transaction = &route_transaction;
    recovery_input.route_snapshot = &route_snapshot;
    recovery_input.callbacks = &callbacks;
    recovery_input.callback_context = &hooks;
    recovery_input.membership_controller = NULL;

    if (!entry->transaction.has_prepared_route_snapshot_key) {
        fprintf(stderr,
                "cold-start recover: journal lacks prepared_route_snapshot_key\n");
        printf("EVID ACTIVATION_DECIDED_route_lookup: missing_key=1 "
               "route_entries=%zu\n",
               plane.route_entry_count);
        fflush(stdout);
        rc = 2;
        goto out_plane;
    }

    memset(route_tx_acks, 0, sizeof(route_tx_acks));
    memset(route_tx_drain, 0, sizeof(route_tx_drain));
    route_transaction.required_ack_set.entries.entries = route_tx_acks;
    route_transaction.required_ack_set.entries.capacity = 8;
    route_transaction.optional_departure_drain_set.entries = route_tx_drain;
    route_transaction.optional_departure_drain_set.capacity = 8;
    route_snapshot.next_hop_rules.entries = route_rules;
    route_snapshot.next_hop_rules.capacity = 3;
    route_snapshot.required_ack_set.entries.entries = ack_entries;
    route_snapshot.required_ack_set.entries.capacity = 1;
    error[0] = '\0';
    if (cold_find_route_operation(
            &plane, &entry->transaction.prepared_route_snapshot_key,
            route_transaction.operation_id, error, sizeof(error)) != 0) {
        fprintf(stderr, "cold-start recover route lookup: %s\n", error);
        printf("EVID ACTIVATION_DECIDED_route_lookup: found=0 route_entries=%zu "
               "err=%s\n",
               plane.route_entry_count, error[0] ? error : "(none)");
        fflush(stdout);
        rc = 2;
        goto out_plane;
    }
    {
        char op_hex[WVM_IDENTITY_ID_BYTES * 2 + 1];

        format_id_hex(route_transaction.operation_id, op_hex, sizeof(op_hex));
        printf("EVID ACTIVATION_DECIDED_route_lookup: found=1 route_entries=%zu "
               "operation_id=%s\n",
               plane.route_entry_count, op_hex);
        fflush(stdout);
    }

    /*
     * Recovery must not depend on leftover in-memory decision from this
     * process (there is none after a true restart). Prove that by leaving
     * the in-memory route transaction in a bogus state after supplying only
     * the journal-derived operation_id; reconstruct reads the journal.
     */
    route_transaction.state = WVM_ROUTE_TRANSACTION_ABORTED;
    error[0] = '\0';
    recover_rc = wvm_admission_orchestrator_recover(&recovery_input, error,
                                                    sizeof(error));
    entry = wvm_control_plane_find_request(&plane, request.request_id);
    state_after = entry ? entry->transaction.state : 0;
    printf("EVID ACTIVATION_DECIDED_recover: rc=%d err=%s state_before=%u "
           "state_after=%u pid=%d\n",
           recover_rc, error[0] ? error : "(none)", (unsigned)state_before,
           (unsigned)state_after, (int)getpid());
    fflush(stdout);

    /*
     * Contract: replay missing activate/start, or fail-closed without
     * inventing a false RUNNING. RUNNING or COMMITTED (ready may be
     * -EAGAIN) is success; a typed fail-closed that stays DECIDED is
     * reported honestly as PARTIAL by the shell if rc!=0 && rc!=-EAGAIN.
     */
    if ((recover_rc == 0 || recover_rc == -EAGAIN) &&
        (state_after == WVM_LIFECYCLE_RUNNING ||
         state_after == WVM_LIFECYCLE_COMMITTED ||
         (recover_rc == -EAGAIN &&
          state_after == WVM_LIFECYCLE_ACTIVATION_DECIDED))) {
        /* -EAGAIN still at DECIDED means start was deferred, not replayed. */
        if (state_after == WVM_LIFECYCLE_RUNNING ||
            state_after == WVM_LIFECYCLE_COMMITTED) {
            printf("EVID ACTIVATION_DECIDED_replay: forwarded=1\n");
            rc = 0;
        } else {
            printf("EVID ACTIVATION_DECIDED_replay: forwarded=0 still_decided=1\n");
            rc = 2;
        }
    } else if (recover_rc != 0 && recover_rc != -EAGAIN) {
        printf("EVID ACTIVATION_DECIDED_replay: fail_closed=1 rc=%d\n",
               recover_rc);
        rc = 2;
    }

out_plane:
    wvm_control_plane_close(&plane);
    wvm_coordinator_prepared_vm_cleanup(&prepared);
out_reg:
    wvm_local_reservation_registry_destroy(&registry_17);
    wvm_local_reservation_registry_destroy(&registry_99);
    return rc;
}

int main(int argc, char **argv)
{
    const char *journal;
    const char *mode;

    if (argc != 3) {
        fprintf(stderr,
                "usage: test_activation_decided_cold_start persist|recover "
                "JOURNAL\n");
        return 1;
    }
    mode = argv[1];
    journal = argv[2];
    if (strcmp(mode, "persist") == 0) {
        return cold_persist(journal);
    }
    if (strcmp(mode, "recover") == 0) {
        return cold_recover(journal);
    }
    fprintf(stderr, "unknown mode %s\n", mode);
    return 1;
}

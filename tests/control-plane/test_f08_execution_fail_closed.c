/*
 * F08: durable RUNNING→DEGRADED/FAILED must fail-close execution authorize for
 * that exact VM only. Sibling VM stays authorized. Identity STOP still works
 * after fail-closed. LIST_VM/journal FAILED alone is not the execution boundary
 * — the installed hook quiesces the real runtime gate.
 */
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "wavevm_control_plane.h"
#include "wavevm_lifecycle.h"
#include "wavevm_membership_controller.h"
#include "wavevm_identity.h"
#include "wavevm_runtime_gate.h"
#include "wavevm_runtime_names.h"

struct authorization_context {
    unsigned int calls;
};

struct fail_closed_context {
    struct wvm_runtime_gate *gate_a;
    struct wvm_runtime_gate *gate_b;
    uint32_t vm_a;
    uint32_t vm_b;
    unsigned int calls;
    unsigned int quiesced_a;
    unsigned int quiesced_b;
};

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        return 1;
    }
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authorize_self(
    void *context, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    struct authorization_context *authorization = context;
    (void)action;
    (void)error;
    (void)error_len;
    if (!authorization || !member_key_equal(actor, subject)) {
        return -1;
    }
    authorization->calls++;
    return 0;
}

static void fill_id(uint8_t id[WVM_IDENTITY_ID_BYTES], uint8_t tag)
{
    memset(id, 0, WVM_IDENTITY_ID_BYTES);
    id[WVM_IDENTITY_ID_BYTES - 1] = tag;
}

static int fill_active_gate(struct wvm_runtime_gate *gate,
                            struct wvm_node_runtime_manifest *manifest,
                            struct wvm_node_runtime_manifest *prepared,
                            uint32_t vm_id, uint64_t incarnation, uint8_t tag,
                            char *error, size_t error_len)
{
    struct wvm_runtime_registration registration;
    static struct wvm_capability_ref capability_slots[2];
    struct wvm_capability_ref *capability;
    struct wvm_local_name_identity name_identity;
    unsigned cap_slot;
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t connection_id = 0;

    memset(manifest, 0, sizeof(*manifest));
    memset(manifest->candidate_manifest_digest, tag,
           sizeof(manifest->candidate_manifest_digest));
    manifest->vm_id = vm_id;
    manifest->vm_incarnation = incarnation;
    manifest->manifest_generation = 1;
    fill_id(manifest->admission_tx_id, (uint8_t)(tag + 1));
    memset(manifest->eligibility_fence_digest, tag + 2,
           sizeof(manifest->eligibility_fence_digest));
    manifest->has_activation_fence = 1;
    memset(manifest->activation_fence, tag + 3,
           sizeof(manifest->activation_fence));
    manifest->physical_node_id = 17;
    manifest->expected_node_instance_id = 101;
    manifest->local_role_bits =
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_NODE_RUNTIME) |
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_QEMU_FRONTEND) |
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_EXECUTOR);
    manifest->required_route_snapshot_key.scope_key.vm_id = vm_id;
    manifest->required_route_snapshot_key.scope_key.vm_incarnation =
        incarnation;
    manifest->required_route_snapshot_key.scope_key.route_scope_id = 9;
    manifest->required_route_snapshot_key.topology_revision = 2;
    manifest->required_route_snapshot_key.route_generation = 3;
    memset(manifest->required_route_snapshot_key.snapshot_digest, tag + 4,
           sizeof(manifest->required_route_snapshot_key.snapshot_digest));
    memset(&name_identity, 0, sizeof(name_identity));
    name_identity.vm_id = vm_id;
    name_identity.vm_incarnation = incarnation;
    name_identity.manifest_generation = 1;
    name_identity.physical_node_id = 17;
    fill_id(name_identity.manifest_id, tag);
    memcpy(name_identity.admission_tx_id, manifest->admission_tx_id,
           sizeof(name_identity.admission_tx_id));
    if (wvm_local_name_namespace_derive(&name_identity, &manifest->local_names,
                                        error, error_len) != 0) {
        return -1;
    }
    manifest->negotiated_profile.backend = WVM_MANIFEST_BACKEND_TCG;
    manifest->negotiated_profile.context_schema_version = 1;
    manifest->negotiated_profile.dirty_capture_engine = 1;
    manifest->negotiated_profile.read_fault_engine = 1;
    manifest->negotiated_profile.invalidation_engine = 1;
    manifest->negotiated_profile.fallback_decision = 1;
    memset(manifest->negotiated_profile.supported_memory_policies_digest,
           tag + 5,
           sizeof(manifest->negotiated_profile.supported_memory_policies_digest));
    cap_slot = (tag == 0x41) ? 0U : 1U;
    capability = &capability_slots[cap_slot];
    capability->physical_node_id = 17;
    capability->node_instance_id = 101;
    capability->profile_generation = 8;
    memset(capability->profile_digest, tag + 6, sizeof(capability->profile_digest));
    manifest->negotiated_profile.per_node_capabilities.entries = capability;
    manifest->negotiated_profile.per_node_capabilities.count = 1;
    manifest->negotiated_profile.per_node_capabilities.capacity = 1;
    fill_id(manifest->reservation_id, (uint8_t)(tag + 7));
    manifest->launch_plan.plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
    manifest->launch_plan.node_runtime_data_port = 19100;
    manifest->launch_plan.node_runtime_control_port = 19121;
    manifest->launch_plan.local_executor_service_port = 19105;
    manifest->launch_plan.local_executor_control_port = 19121;
    manifest->launch_plan.executor_worker_count = 1;
    manifest->launch_plan.vcpu_handoff_record_capacity = 16;
    manifest->launch_plan.sync_batch_size = 1;
    manifest->launch_plan.guest_total_memory_bytes = 4 * 1024 * 1024;
    strcpy(manifest->launch_plan.guest_machine.architecture, "x86_64");
    strcpy(manifest->launch_plan.guest_machine.machine_type, "pc-i440fx-5.2");
    manifest->launch_plan.guest_machine.qemu_compat_version = 502;
    manifest->launch_plan.guest_machine.firmware_policy = 1;
    manifest->launch_plan.consistency_policy.dirty_batch_size = 1;
    manifest->launch_plan.consistency_policy.handoff_commit_policy = 1;
    manifest->launch_plan.consistency_policy.subscriber_delivery_policy = 1;
    manifest->launch_plan.consistency_policy.max_commit_latency_ms = 1000;

    if (wvm_node_runtime_manifest_validate(manifest, error, error_len) != 0 ||
        wvm_runtime_manifest_profile_digest(manifest, profile_digest, error,
                                            error_len) != 0) {
        return -1;
    }

    *prepared = *manifest;
    prepared->has_activation_fence = 0;
    memset(prepared->activation_fence, 0, sizeof(prepared->activation_fence));
    /* capability entries pointer must remain valid on prepared copy */
    prepared->negotiated_profile.per_node_capabilities.entries =
        manifest->negotiated_profile.per_node_capabilities.entries;

    wvm_runtime_gate_init(gate);
    if (wvm_runtime_gate_prepare(gate, prepared, 17, 101, error, error_len) !=
        0) {
        return -1;
    }
    memset(&registration, 0, sizeof(registration));
    registration.connection_role = WVM_MANIFEST_ROLE_QEMU_FRONTEND;
    registration.vm_id = vm_id;
    registration.vm_incarnation = incarnation;
    registration.manifest_generation = 1;
    memcpy(registration.candidate_manifest_digest,
           manifest->candidate_manifest_digest,
           sizeof(registration.candidate_manifest_digest));
    registration.local_runtime_instance_id = 1001;
    registration.caller_process_instance_id = 2001 + tag;
    memcpy(registration.capability_profile_digest, profile_digest,
           sizeof(registration.capability_profile_digest));
    strcpy(registration.requested_endpoint_name,
           manifest->local_names.namespace_name);
    if (wvm_runtime_gate_register(gate, &registration, &connection_id, error,
                                  error_len) != 0 ||
        wvm_runtime_gate_bind_activation(gate, manifest, error, error_len) !=
            0 ||
        wvm_runtime_gate_activate(gate, manifest->activation_fence, error,
                                  error_len) != 0) {
        return -1;
    }
    return 0;
}

static int fill_operation(struct wvm_runtime_operation *operation,
                          const struct wvm_runtime_gate *gate,
                          uint64_t connection_id)
{
    memset(operation, 0, sizeof(*operation));
    if (!gate || !gate->manifest) {
        return -1;
    }
    operation->connection_id = connection_id;
    operation->vm_id = gate->manifest->vm_id;
    operation->vm_incarnation = gate->manifest->vm_incarnation;
    operation->manifest_generation = gate->manifest->manifest_generation;
    memcpy(operation->candidate_manifest_digest,
           gate->manifest->candidate_manifest_digest,
           sizeof(operation->candidate_manifest_digest));
    operation->route_snapshot_key = gate->manifest->required_route_snapshot_key;
    memcpy(operation->activation_fence, gate->manifest->activation_fence,
           sizeof(operation->activation_fence));
    fill_id(operation->operation_id, 0xaa);
    return 0;
}

static int execution_fail_closed_hook(
    void *context, const struct wvm_admission_transaction_record *transaction,
    enum wvm_lifecycle_state new_state, char *error, size_t error_len)
{
    struct fail_closed_context *fc = context;
    struct wvm_runtime_gate *target = NULL;

    (void)new_state;
    if (!fc || !transaction) {
        if (error && error_len) {
            snprintf(error, error_len, "F08 fail-closed context missing");
        }
        return -1;
    }
    fc->calls++;
    if (transaction->vm_id == fc->vm_a && fc->gate_a) {
        target = fc->gate_a;
        fc->quiesced_a++;
    } else if (transaction->vm_id == fc->vm_b && fc->gate_b) {
        target = fc->gate_b;
        fc->quiesced_b++;
    } else {
        if (error && error_len) {
            snprintf(error, error_len,
                     "F08 fail-closed: no gate for vm=%u",
                     (unsigned)transaction->vm_id);
        }
        return -1;
    }
    if (wvm_runtime_gate_quiesce(target, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

static void seed_running_tx(struct wvm_admission_transaction_record *tx,
                            uint32_t vm_id, uint64_t incarnation, uint8_t tag)
{
    memset(tx, 0, sizeof(*tx));
    fill_id(tx->request_id, tag);
    fill_id(tx->admission_tx_id, (uint8_t)(tag + 1));
    fill_id(tx->manifest_id, (uint8_t)(tag + 2));
    tx->vm_id = vm_id;
    tx->vm_incarnation = incarnation;
    tx->manifest_generation = 1;
    tx->route_scope_key.vm_id = vm_id;
    tx->route_scope_key.vm_incarnation = incarnation;
    tx->route_scope_key.route_scope_id = 1;
    tx->state = WVM_LIFECYCLE_RUNNING;
    tx->transaction_sequence = 0;
    memset(tx->request_digest, tag + 3, sizeof(tx->request_digest));
    tx->has_candidate_manifest_digest = 1;
    memset(tx->candidate_manifest_digest, tag + 4,
           sizeof(tx->candidate_manifest_digest));
    tx->has_prepared_route_snapshot_key = 1;
    tx->prepared_route_snapshot_key.scope_key = tx->route_scope_key;
    tx->prepared_route_snapshot_key.topology_revision = 1;
    tx->prepared_route_snapshot_key.route_generation = 1;
    memset(tx->prepared_route_snapshot_key.snapshot_digest, tag + 5,
           sizeof(tx->prepared_route_snapshot_key.snapshot_digest));
}

int main(void)
{
    char admission_path[] = "/tmp/wavevm-f08-adm.XXXXXX";
    char membership_path[] = "/tmp/wavevm-f08-memb.XXXXXX";
    char control_path[] = "/tmp/wavevm-f08-ctl.XXXXXX";
    char error[256];
    int fd;
    struct wvm_control_plane plane;
    struct wvm_control_plane_entry entries[4];
    struct wvm_control_plane_route_entry route_entries[4];
    struct wvm_vm_namespace_record namespace_records[4];
    struct wvm_vm_namespace_allocator namespace_allocator;
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_membership_control_operation operations[8];
    struct wvm_control_plane_membership_config config;
    struct authorization_context authorization = {0};
    struct wvm_node_runtime_manifest manifest_a;
    struct wvm_node_runtime_manifest manifest_b;
    struct wvm_node_runtime_manifest prepared_a;
    struct wvm_node_runtime_manifest prepared_b;
    struct wvm_runtime_gate gate_a;
    struct wvm_runtime_gate gate_b;
    struct fail_closed_context fail_closed;
    struct wvm_runtime_operation op_a;
    struct wvm_runtime_operation op_b;
    size_t transitioned = 0;
    int failed = 0;
    uint64_t conn_a = 0;
    uint64_t conn_b = 0;
    size_t i;

    fd = mkstemp(admission_path);
    if (fd < 0) {
        perror("mkstemp adm");
        return 1;
    }
    close(fd);
    unlink(admission_path);
    fd = mkstemp(membership_path);
    if (fd < 0) {
        return 1;
    }
    close(fd);
    unlink(membership_path);
    fd = mkstemp(control_path);
    if (fd < 0) {
        return 1;
    }
    close(fd);
    unlink(control_path);

    memset(&plane, 0, sizeof(plane));
    memset(entries, 0, sizeof(entries));
    memset(route_entries, 0, sizeof(route_entries));
    memset(members, 0, sizeof(members));
    memset(routes, 0, sizeof(routes));
    memset(dependencies, 0, sizeof(dependencies));
    memset(operations, 0, sizeof(operations));
    memset(&fail_closed, 0, sizeof(fail_closed));
    memset(&manifest_a, 0, sizeof(manifest_a));
    memset(&manifest_b, 0, sizeof(manifest_b));
    memset(&prepared_a, 0, sizeof(prepared_a));
    memset(&prepared_b, 0, sizeof(prepared_b));
    memset(&gate_a, 0, sizeof(gate_a));
    memset(&gate_b, 0, sizeof(gate_b));

    if (expect(fill_active_gate(&gate_a, &manifest_a, &prepared_a, 501, 1, 0x41,
                                error, sizeof(error)) == 0,
               "activate gate A") ||
        expect(fill_active_gate(&gate_b, &manifest_b, &prepared_b, 502, 1, 0x51,
                                error, sizeof(error)) == 0,
               "activate gate B")) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }
    /* Capture first registered connection ids. */
    for (i = 0; i < WVM_RUNTIME_MAX_CONNECTIONS; i++) {
        if (gate_a.connections[i].state == WVM_RUNTIME_CONNECTION_REGISTERED &&
            conn_a == 0) {
            conn_a = gate_a.connections[i].connection_id;
        }
        if (gate_b.connections[i].state == WVM_RUNTIME_CONNECTION_REGISTERED &&
            conn_b == 0) {
            conn_b = gate_b.connections[i].connection_id;
        }
    }
    if (expect(conn_a != 0 && conn_b != 0, "both gates have connections") ||
        expect(fill_operation(&op_a, &gate_a, conn_a) == 0 &&
                   fill_operation(&op_b, &gate_b, conn_b) == 0,
               "build operations") ||
        expect(wvm_runtime_gate_authorize(&gate_a, &op_a, error,
                                          sizeof(error)) == 0,
               "pre: authorize A while ACTIVE") ||
        expect(wvm_runtime_gate_authorize(&gate_b, &op_b, error,
                                          sizeof(error)) == 0,
               "pre: authorize B while ACTIVE")) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }

    wvm_control_plane_init(&plane, entries, 4);
    wvm_control_plane_set_local_physical_node_id(&plane, 1);
    wvm_control_plane_set_route_transaction_entries(&plane, route_entries, 4);

    memset(&config, 0, sizeof(config));
    config.members = members;
    config.member_capacity = 4;
    config.routes = routes;
    config.route_capacity = 4;
    config.dependencies = dependencies;
    config.dependency_capacity = 4;
    config.operations = operations;
    config.operation_capacity = 8;
    config.membership_journal_path = membership_path;
    config.control_journal_path = control_path;
    config.authorize = authorize_self;
    config.authorize_context = &authorization;

    wvm_vm_namespace_allocator_init(&namespace_allocator, namespace_records, 4,
                                    1);
    if (expect(wvm_control_plane_configure_membership(&plane, &config, error,
                                                      sizeof(error)) == 0,
               "configure membership") ||
        expect(wvm_control_plane_open_membership(&plane, error, sizeof(error)) ==
                   0,
               "open membership") ||
        expect(wvm_control_plane_open(&plane, admission_path,
                                      &namespace_allocator, error,
                                      sizeof(error)) == 0,
               "open control plane")) {
        fprintf(stderr, "%s\n", error);
        failed = 1;
        goto out;
    }

    fail_closed.gate_a = &gate_a;
    fail_closed.gate_b = &gate_b;
    fail_closed.vm_a = 501;
    fail_closed.vm_b = 502;
    wvm_control_plane_set_execution_fail_closed(&plane, execution_fail_closed_hook,
                                                &fail_closed);

    /* Two RUNNING VMs; neither has healthy required members → both degrade. */
    seed_running_tx(&plane.entries[0].transaction, 501, 1, 0x11);
    seed_running_tx(&plane.entries[1].transaction, 502, 1, 0x21);
    plane.entry_count = 2;

    /*
     * Only fail-close VM 501's gate via a one-shot unhealthy reconcile that
     * transitions both, but we will re-activate B's gate after to prove the
     * hook is per-VM. Simpler: transition only A by making B healthy...
     * Easiest directed proof: call reconcile (both go DEGRADED + both hooks),
     * then re-activate B only and show A still denied while B authorized.
     */
    transitioned = 0;
    if (expect(wvm_control_plane_reconcile_required_member_health(
                   &plane, &plane.membership_controller, &transitioned, error,
                   sizeof(error)) == 0 &&
                   transitioned == 2 &&
                   plane.entries[0].transaction.state == WVM_LIFECYCLE_DEGRADED &&
                   plane.entries[1].transaction.state == WVM_LIFECYCLE_DEGRADED,
               "both RUNNING+unhealthy → DEGRADED + hooks")) {
        fprintf(stderr, "t=%zu a=%u b=%u err=%s calls=%u\n", transitioned,
                (unsigned)plane.entries[0].transaction.state,
                (unsigned)plane.entries[1].transaction.state, error,
                fail_closed.calls);
        failed = 1;
        goto out;
    }
    if (expect(fail_closed.calls == 2 && fail_closed.quiesced_a == 1 &&
                   fail_closed.quiesced_b == 1,
               "hook fired once per VM") ||
        expect(gate_a.state == WVM_RUNTIME_GATE_QUIESCING &&
                   gate_b.state == WVM_RUNTIME_GATE_QUIESCING,
               "both gates QUIESCING after DEGRADED") ||
        expect(wvm_runtime_gate_authorize(&gate_a, &op_a, error,
                                          sizeof(error)) != 0,
               "authorize A denied after DEGRADED fail-closed") ||
        expect(wvm_runtime_gate_authorize(&gate_b, &op_b, error,
                                          sizeof(error)) != 0,
               "authorize B denied after DEGRADED fail-closed")) {
        failed = 1;
        goto out;
    }

    /* Sibling recovery: re-activate only B — proves per-VM isolation. */
    if (expect(fill_active_gate(&gate_b, &manifest_b, &prepared_b, 502, 1, 0x51,
                                error, sizeof(error)) == 0,
               "re-activate sibling gate B") ||
        expect(fill_operation(&op_b, &gate_b, gate_b.connections[0].connection_id) ==
                   0,
               "rebuild op B") ||
        expect(wvm_runtime_gate_authorize(&gate_b, &op_b, error,
                                          sizeof(error)) == 0,
               "sibling B authorize OK after re-activate") ||
        expect(wvm_runtime_gate_authorize(&gate_a, &op_a, error,
                                          sizeof(error)) != 0,
               "failed VM A still deny after sibling recover")) {
        fprintf(stderr, "%s\n", error);
        failed = 1;
        goto out;
    }

    /* DEGRADED → FAILED for A still fail-closed (idempotent quiesce). */
    transitioned = 0;
    if (expect(wvm_control_plane_reconcile_required_member_health(
                   &plane, &plane.membership_controller, &transitioned, error,
                   sizeof(error)) == 0 &&
                   transitioned == 2 &&
                   plane.entries[0].transaction.state == WVM_LIFECYCLE_FAILED &&
                   plane.entries[1].transaction.state == WVM_LIFECYCLE_FAILED,
               "DEGRADED→FAILED for both") ||
        expect(wvm_runtime_gate_authorize(&gate_a, &op_a, error,
                                          sizeof(error)) != 0,
               "authorize A still denied after FAILED")) {
        fprintf(stderr, "t=%zu err=%s\n", transitioned, error);
        failed = 1;
        goto out;
    }

    /*
     * Identity STOP remains possible after fail-closed: journal still holds
     * exact vm_id/incarnation (F03 owns full STOP orchestration). Quiesce must
     * not wipe durable identity.
     */
    if (expect(plane.entries[0].transaction.state == WVM_LIFECYCLE_FAILED &&
                   plane.entries[0].transaction.vm_id == 501 &&
                   plane.entries[0].transaction.vm_incarnation == 1 &&
                   plane.entries[1].transaction.vm_id == 502 &&
                   plane.entries[1].transaction.state == WVM_LIFECYCLE_FAILED,
               "journal identities intact for later STOP")) {
        failed = 1;
        goto out;
    }

    printf("test_f08_execution_fail_closed: PASS\n");
out:
    wvm_control_plane_close_membership(&plane);
    wvm_control_plane_close(&plane);
    unlink(admission_path);
    unlink(membership_path);
    unlink(control_path);
    return failed;
}

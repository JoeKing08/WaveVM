#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wavevm_runtime_gate.h"
#include "wavevm_runtime_names.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "runtime-gate test: %s\n", message);
        return -1;
    }
    return 0;
}

int main(void)
{
    struct wvm_node_runtime_manifest manifest;
    struct wvm_node_runtime_manifest prepared_manifest;
    struct wvm_runtime_gate gate;
    struct wvm_runtime_registration registration;
    struct wvm_runtime_operation operation;
    struct wvm_runtime_registration invalid_registration;
    struct wvm_capability_ref capability;
    struct wvm_local_name_identity name_identity;
    struct wvm_runtime_name_set runtime_names;
    struct wvm_runtime_manifest_storage loaded_storage;
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t connection_id = 0;
    uint64_t second_connection_id = 0;
    char manifest_path[] = "/tmp/wavevm-runtime-manifest.XXXXXX";
    char error[256] = {0};
    int manifest_fd;

    memset(&manifest, 0, sizeof(manifest));
    memset(manifest.candidate_manifest_digest, 0x11,
           sizeof(manifest.candidate_manifest_digest));
    manifest.vm_id = 256;
    manifest.vm_incarnation = 4;
    manifest.manifest_generation = 1;
    memset(manifest.admission_tx_id, 0x22, sizeof(manifest.admission_tx_id));
    memset(manifest.eligibility_fence_digest, 0x33,
           sizeof(manifest.eligibility_fence_digest));
    manifest.has_activation_fence = 1;
    memset(manifest.activation_fence, 0x44, sizeof(manifest.activation_fence));
    manifest.physical_node_id = 17;
    manifest.expected_node_instance_id = 101;
    manifest.local_role_bits =
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_NODE_RUNTIME) |
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_QEMU_FRONTEND) |
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_EXECUTOR);
    manifest.required_route_snapshot_key.scope_key.vm_id = manifest.vm_id;
    manifest.required_route_snapshot_key.scope_key.vm_incarnation =
        manifest.vm_incarnation;
    manifest.required_route_snapshot_key.scope_key.route_scope_id = 9;
    manifest.required_route_snapshot_key.topology_revision = 2;
    manifest.required_route_snapshot_key.route_generation = 3;
    memset(manifest.required_route_snapshot_key.snapshot_digest, 0x55,
           sizeof(manifest.required_route_snapshot_key.snapshot_digest));
    memset(&name_identity, 0, sizeof(name_identity));
    name_identity.vm_id = manifest.vm_id;
    name_identity.vm_incarnation = manifest.vm_incarnation;
    name_identity.manifest_generation = manifest.manifest_generation;
    name_identity.physical_node_id = manifest.physical_node_id;
    memset(name_identity.manifest_id,
           (unsigned char)(getpid() & 0xff), sizeof(name_identity.manifest_id));
    memcpy(name_identity.admission_tx_id, manifest.admission_tx_id,
           sizeof(name_identity.admission_tx_id));
    if (expect(wvm_local_name_namespace_derive(
                   &name_identity, &manifest.local_names, error,
                   sizeof(error)) == 0,
               "derive local namespace")) {
        return 1;
    }
    manifest.negotiated_profile.backend = WVM_MANIFEST_BACKEND_TCG;
    manifest.negotiated_profile.context_schema_version = 1;
    manifest.negotiated_profile.dirty_capture_engine = 1;
    manifest.negotiated_profile.read_fault_engine = 1;
    manifest.negotiated_profile.invalidation_engine = 1;
    manifest.negotiated_profile.fallback_decision = 1;
    memset(manifest.negotiated_profile.supported_memory_policies_digest, 0x77,
           sizeof(manifest.negotiated_profile.supported_memory_policies_digest));
    capability.physical_node_id = 17;
    capability.node_instance_id = 101;
    capability.profile_generation = 8;
    memset(capability.profile_digest, 0x88,
           sizeof(capability.profile_digest));
    manifest.negotiated_profile.per_node_capabilities.entries = &capability;
    manifest.negotiated_profile.per_node_capabilities.count = 1;
    manifest.negotiated_profile.per_node_capabilities.capacity = 1;
    memset(manifest.reservation_id, 0x99, sizeof(manifest.reservation_id));
    manifest.launch_plan.plan_version = WVM_NODE_RUNTIME_LAUNCH_PLAN_VERSION;
    manifest.launch_plan.node_runtime_data_port = 19100;
    manifest.launch_plan.node_runtime_control_port = 19121;
    manifest.launch_plan.local_executor_service_port = 19105;
    manifest.launch_plan.local_executor_control_port = 19121;
    manifest.launch_plan.executor_worker_count = 1;
    manifest.launch_plan.vcpu_handoff_record_capacity = 16;
    manifest.launch_plan.sync_batch_size = 1;
    manifest.launch_plan.guest_total_memory_bytes = 4 * 1024 * 1024;
    strcpy(manifest.launch_plan.guest_machine.architecture, "x86_64");
    strcpy(manifest.launch_plan.guest_machine.machine_type, "pc-i440fx-5.2");
    manifest.launch_plan.guest_machine.qemu_compat_version = 502;
    manifest.launch_plan.guest_machine.firmware_policy = 1;
    manifest.launch_plan.consistency_policy.dirty_batch_size = 1;
    manifest.launch_plan.consistency_policy.handoff_commit_policy = 1;
    manifest.launch_plan.consistency_policy.subscriber_delivery_policy = 1;
    manifest.launch_plan.consistency_policy.max_commit_latency_ms = 1000;
    if (expect(wvm_node_runtime_manifest_validate(&manifest, error,
                                                  sizeof(error)) == 0,
               "validate runtime manifest") ||
        expect(wvm_runtime_manifest_profile_digest(
                   &manifest, profile_digest, error, sizeof(error)) == 0,
               "derive capability profile digest")) {
        return 1;
    }

    if (expect(wvm_runtime_name_set_derive(&manifest.local_names, &runtime_names,
                                           error, sizeof(error)) == 0,
               "derive runtime resource names") ||
        expect(wvm_runtime_ready_remove(&manifest, error, sizeof(error)) == 0,
               "clear only this test instance readiness")) {
        return 1;
    }
    if (expect(wvm_runtime_ready_publish(&manifest, manifest.expected_node_instance_id,
                                         error, sizeof(error)) == 0,
               "claim runtime readiness") ||
        expect(wvm_runtime_ready_validate(&manifest,
                                          manifest.expected_node_instance_id,
                                          error, sizeof(error)) == 0,
               "validate claimed runtime readiness") ||
        expect(wvm_runtime_ready_publish(&manifest,
                                         manifest.expected_node_instance_id,
                                         error, sizeof(error)) == 0,
               "allow idempotent readiness publish")) {
        wvm_runtime_ready_remove(&manifest, NULL, 0);
        return 1;
    }
    {
        struct wvm_node_runtime_manifest conflicting_manifest = manifest;

        conflicting_manifest.candidate_manifest_digest[0] ^= 0xffU;
        if (expect(wvm_runtime_ready_publish(
                       &conflicting_manifest,
                       conflicting_manifest.expected_node_instance_id, error,
                       sizeof(error)) != 0,
                   "reject readiness overwrite from a different manifest")) {
            wvm_runtime_ready_remove(&manifest, NULL, 0);
            return 1;
        }
        if (expect(wvm_runtime_ready_remove(&conflicting_manifest, error,
                                            sizeof(error)) != 0,
                   "reject readiness removal from a different manifest") ||
            expect(wvm_runtime_ready_validate(
                       &manifest, manifest.expected_node_instance_id, error,
                       sizeof(error)) == 0,
                   "retain readiness after rejected removal")) {
            wvm_runtime_ready_remove(&manifest, NULL, 0);
            return 1;
        }
        conflicting_manifest = manifest;
        conflicting_manifest.activation_fence[0] ^= 0xffU;
        if (expect(wvm_runtime_ready_validate(
                       &conflicting_manifest,
                       conflicting_manifest.expected_node_instance_id,
                       error, sizeof(error)) != 0,
                   "reject readiness from a different activation fence") ||
            expect(wvm_runtime_ready_remove(&conflicting_manifest, error,
                                            sizeof(error)) != 0,
                   "do not remove another activation's readiness")) {
            wvm_runtime_ready_remove(&manifest, NULL, 0);
            return 1;
        }
    }
    if (expect(wvm_runtime_ready_remove(&manifest, error, sizeof(error)) == 0,
               "release runtime readiness") ||
        expect(wvm_runtime_ready_validate(&manifest,
                                          manifest.expected_node_instance_id,
                                          error, sizeof(error)) != 0,
               "reject readiness after release")) {
        wvm_runtime_ready_remove(&manifest, NULL, 0);
        return 1;
    }
    {
        pid_t child = fork();
        int child_status = 0;

        if (child == 0) {
            _exit(wvm_runtime_ready_publish(
                      &manifest, manifest.expected_node_instance_id,
                      error, sizeof(error)) == 0
                      ? 0
                      : 1);
        }
        if (expect(child > 0 && waitpid(child, &child_status, 0) == child &&
                       WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
                   "child publishes readiness before exiting") ||
            expect(wvm_runtime_ready_validate(
                       &manifest, manifest.expected_node_instance_id,
                       error, sizeof(error)) == -EAGAIN,
                   "dead runtime cannot satisfy readiness") ||
            expect(wvm_runtime_ready_publish(
                       &manifest, manifest.expected_node_instance_id,
                       error, sizeof(error)) == 0 &&
                       wvm_runtime_ready_validate(
                           &manifest, manifest.expected_node_instance_id,
                           error, sizeof(error)) == 0,
                   "live runtime reclaims identity-matched stale readiness") ||
            expect(wvm_runtime_ready_remove(&manifest, error,
                                            sizeof(error)) == 0,
                   "remove reclaimed readiness")) {
            return 1;
        }
    }
    {
        int child_ready[2], child_exit[2], child_status;
        pid_t child;
        char signal_byte;

        if (pipe(child_ready) != 0 || pipe(child_exit) != 0) {
            return 1;
        }
        child = fork();
        if (child == 0) {
            close(child_ready[0]);
            close(child_exit[1]);
            signal_byte = wvm_runtime_ready_publish(
                              &manifest, manifest.expected_node_instance_id,
                              error, sizeof(error)) == 0
                              ? '1'
                              : '0';
            if (write(child_ready[1], &signal_byte, 1) != 1) {
                _exit(1);
            }
            if (read(child_exit[0], &signal_byte, 1) != 1) {
                _exit(1);
            }
            _exit(0);
        }
        close(child_ready[1]);
        close(child_exit[0]);
        if (child <= 0 || read(child_ready[0], &signal_byte, 1) != 1 ||
            signal_byte != '1') {
            return 1;
        }
        if (expect(wvm_runtime_ready_publish(
                       &manifest, manifest.expected_node_instance_id,
                       error, sizeof(error)) != 0,
                   "cannot overwrite another live runtime") ||
            expect(wvm_runtime_ready_remove(&manifest, error,
                                            sizeof(error)) != 0,
                   "cannot remove another live runtime")) {
            return 1;
        }
        signal_byte = 'x';
        if (write(child_exit[1], &signal_byte, 1) != 1 ||
            waitpid(child, &child_status, 0) != child ||
            !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
            expect(wvm_runtime_ready_remove(&manifest, error,
                                            sizeof(error)) == 0,
                   "remove identity-matched readiness after owner exits")) {
            return 1;
        }
        close(child_ready[0]);
        close(child_exit[1]);
    }

    manifest_fd = mkstemp(manifest_path);
    if (manifest_fd < 0) {
        perror("mkstemp runtime manifest");
        return 1;
    }
    close(manifest_fd);
    unlink(manifest_path);
    wvm_runtime_manifest_storage_init(&loaded_storage);
    if (expect(wvm_runtime_manifest_file_publish(
                   manifest_path, &manifest, error, sizeof(error)) == 0 &&
                   wvm_runtime_manifest_load_file(
                       manifest_path, &loaded_storage, error,
                       sizeof(error)) == 0 &&
                   loaded_storage.manifest.vm_id == manifest.vm_id &&
                   loaded_storage.manifest.expected_node_instance_id ==
                       manifest.expected_node_instance_id &&
                   memcmp(loaded_storage.manifest.candidate_manifest_digest,
                          manifest.candidate_manifest_digest,
                          sizeof(manifest.candidate_manifest_digest)) == 0 &&
                   memcmp(loaded_storage.manifest.activation_fence,
                          manifest.activation_fence,
                          sizeof(manifest.activation_fence)) == 0,
               "atomically publish and reload admitted runtime manifest")) {
        wvm_runtime_manifest_storage_free(&loaded_storage);
        unlink(manifest_path);
        return 1;
    }
    wvm_runtime_manifest_storage_free(&loaded_storage);
    unlink(manifest_path);

    wvm_runtime_gate_init(&gate);
    prepared_manifest = manifest;
    prepared_manifest.has_activation_fence = 0;
    memset(prepared_manifest.activation_fence, 0,
           sizeof(prepared_manifest.activation_fence));
    if (expect(wvm_runtime_gate_prepare(&gate, &prepared_manifest, 17, 101, error,
                                        sizeof(error)) == 0,
               "prepare exact local manifest")) {
        return 1;
    }

    memset(&registration, 0, sizeof(registration));
    registration.connection_role = WVM_MANIFEST_ROLE_QEMU_FRONTEND;
    registration.vm_id = manifest.vm_id;
    registration.vm_incarnation = manifest.vm_incarnation;
    registration.manifest_generation = manifest.manifest_generation;
    memcpy(registration.candidate_manifest_digest,
           manifest.candidate_manifest_digest,
           sizeof(registration.candidate_manifest_digest));
    registration.local_runtime_instance_id = 1001;
    registration.caller_process_instance_id = 2001;
    memcpy(registration.capability_profile_digest, profile_digest,
           sizeof(registration.capability_profile_digest));
    strcpy(registration.requested_endpoint_name,
           manifest.local_names.namespace_name);
    invalid_registration = registration;
    invalid_registration.candidate_manifest_digest[0] ^= 0xffU;
    if (expect(wvm_runtime_gate_register(&gate, &invalid_registration, NULL,
                                         error, sizeof(error)) != 0,
               "reject registration with a stale manifest digest")) {
        return 1;
    }
    invalid_registration = registration;
    invalid_registration.connection_role = WVM_MANIFEST_ROLE_GATEWAY;
    if (expect(wvm_runtime_gate_register(&gate, &invalid_registration, NULL,
                                         error, sizeof(error)) != 0,
               "reject registration for an unauthorized local role")) {
        return 1;
    }
    if (expect(wvm_runtime_gate_register(&gate, &registration, &connection_id,
                                         error, sizeof(error)) == 0 &&
                   connection_id != 0,
               "register QEMU before activation") ||
        expect(wvm_runtime_gate_register(&gate, &registration,
                                         &second_connection_id, error,
                                         sizeof(error)) == 0 &&
                   second_connection_id != 0 &&
                   second_connection_id != connection_id,
               "register separate local connection from same process") ||
        expect(wvm_runtime_gate_bind_activation(&gate, &manifest, error,
                                                sizeof(error)) == 0,
               "bind exact activation projection") ||
        expect(gate.manifest == &prepared_manifest &&
                   prepared_manifest.has_activation_fence &&
                   memcmp(prepared_manifest.activation_fence,
                          manifest.activation_fence,
                          sizeof(manifest.activation_fence)) == 0,
               "retain prepared storage while binding activation fence") ||
        expect(wvm_runtime_gate_activate(&gate, manifest.activation_fence, error,
                                         sizeof(error)) == 0,
               "activate exact fence")) {
        return 1;
    }

    memset(&operation, 0, sizeof(operation));
    operation.connection_id = connection_id;
    operation.vm_id = manifest.vm_id;
    operation.vm_incarnation = manifest.vm_incarnation;
    operation.manifest_generation = manifest.manifest_generation;
    memcpy(operation.candidate_manifest_digest,
           manifest.candidate_manifest_digest,
           sizeof(operation.candidate_manifest_digest));
    operation.route_snapshot_key = manifest.required_route_snapshot_key;
    memcpy(operation.activation_fence, manifest.activation_fence,
           sizeof(operation.activation_fence));
    operation.operation_id[15] = 1;
    if (expect(wvm_runtime_gate_authorize(&gate, &operation, error,
                                          sizeof(error)) == 0,
               "authorize matching semantic operation")) {
        return 1;
    }
    operation.route_snapshot_key.route_generation++;
    if (expect(wvm_runtime_gate_authorize(&gate, &operation, error,
                                          sizeof(error)) != 0,
               "reject stale route generation")) {
        return 1;
    }
    operation.connection_id = second_connection_id;
    operation.route_snapshot_key = manifest.required_route_snapshot_key;
    operation.operation_id[15] = 2;
    if (expect(wvm_runtime_gate_authorize(&gate, &operation, error,
                                          sizeof(error)) == 0,
               "authorize the second local connection")) {
        return 1;
    }
    operation.connection_id = connection_id;
    if (expect(wvm_runtime_gate_revoke(&gate, connection_id, error,
                                       sizeof(error)) == 0 &&
                   wvm_runtime_gate_authorize(&gate, &operation, error,
                                              sizeof(error)) != 0,
               "reject revoked connection")) {
        return 1;
    }
    operation.connection_id = second_connection_id;
    if (expect(wvm_runtime_gate_authorize(&gate, &operation, error,
                                          sizeof(error)) == 0 &&
                   wvm_runtime_gate_revoke(&gate, second_connection_id, error,
                                           sizeof(error)) == 0,
               "keep the second local connection authorized")) {
        return 1;
    }

    prepared_manifest = manifest;
    prepared_manifest.has_activation_fence = 0;
    memset(prepared_manifest.activation_fence, 0,
           sizeof(prepared_manifest.activation_fence));
    wvm_runtime_gate_init(&gate);
    if (expect(wvm_runtime_gate_prepare(&gate, &prepared_manifest, 17, 101,
                                        error, sizeof(error)) == 0,
               "prepare abortable projection")) {
        return 1;
    }
    {
        struct wvm_node_runtime_manifest conflicting_manifest =
            prepared_manifest;

        conflicting_manifest.local_role_bits ^=
            WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_GATEWAY);
        if (expect(wvm_runtime_gate_bind_activation(
                       &gate, &conflicting_manifest, error, sizeof(error)) != 0,
                   "reject activation projection with changed role") ||
            expect(wvm_runtime_gate_abort_prepared(
                       &gate, &conflicting_manifest, error, sizeof(error)) != 0,
                   "reject abort for a different prepared projection") ||
            expect(wvm_runtime_gate_abort_prepared(
                       &gate, &prepared_manifest, error, sizeof(error)) == 0 &&
                       gate.state == WVM_RUNTIME_GATE_EMPTY &&
                       gate.manifest == NULL,
                   "abort only the matching prepared projection")) {
            return 1;
        }
    }

    {
        char lock_path[WVM_RUNTIME_PATH_MAX + 6];

        if (snprintf(lock_path, sizeof(lock_path), "%s.lock",
                     runtime_names.ready_file) >= (int)sizeof(lock_path) ||
            unlink(lock_path) != 0) {
            return 1;
        }
    }
    puts("runtime-gate tests: PASS");
    return 0;
}

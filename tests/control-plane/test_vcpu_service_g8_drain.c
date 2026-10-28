#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * G8: fill QEMU reply socket so ACK send blocks; drain(short) must ETIMEDOUT
 * (not false success). After draining the peer buffer, drain() returns 0.
 */

#define main wvm_vcpu_coordinator_regression_main
#include "test_vcpu_coordinator.c"
#undef main

#include "vcpu_service.h"

static int service_expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "G8 drain test: %s\n", message);
        return -1;
    }
    return 0;
}

static int fill_until_eagain(int fd)
{
    uint8_t junk[8192];
    uint64_t filled = 0;
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    memset(junk, 0x5a, sizeof(junk));
    for (;;) {
        ssize_t n = send(fd, junk, sizeof(junk), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            filled += (uint64_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fprintf(stderr, "G8_FILL filled=%llu\n",
                    (unsigned long long)filled);
            return filled > 0 ? 0 : -1;
        }
        return -1;
    }
}

int main(void)
{
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[1];
    struct wvm_route_snapshot_record snapshot;
    struct wvm_node_runtime_manifest manifest;
    struct wvm_capability_ref capability;
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_cpu_dispatch cpu_entries[2];
    struct wvm_runtime_gate gate;
    struct wvm_runtime_registration registration;
    struct wvm_route_runtime routes;
    struct wvm_vcpu_handoff_coordinator_config coordinator_config;
    struct wvm_vcpu_handoff_coordinator coordinator;
    struct wvm_vcpu_service_config service_config;
    struct wvm_vcpu_service service;
    struct wvm_ipc_cpu_run_req legacy_request;
    struct wvm_ipc_cpu_run_ack legacy_reply;
    (void)legacy_reply;
    struct wvm_envelope exit_envelope;
    struct send_state sent;
    wvm_tcg_context_t remote_context;
    wvm_tcg_context_t decoded_context;
    uint8_t result_context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                           sizeof(remote_context)];
    uint8_t exit_payload[WVM_VCPU_HANDOFF_RESULT_HEADER_BYTES +
                         sizeof(result_context)];
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];
    size_t result_context_bytes = 0;
    uint64_t decoded_context_fields = 0;
    uint64_t connection_id = 0;
    int sockets[2] = {-1, -1};
    char error[256] = {0};

    memset(&coordinator, 0, sizeof(coordinator));
    memset(&service, 0, sizeof(service));
    memset(&sent, 0, sizeof(sent));
    fill_rule(&rules[0], 7, 17, 19017);
    fill_rule(&rules[1], 11, 18, 19018);
    if (service_expect(finalize_snapshot(&snapshot, rules, acks, 3, error,
                                         sizeof(error)) == 0,
                       "build route snapshot") ||
        service_expect(setup_manifest(&manifest, &capability,
                                      &snapshot.route_snapshot_key, error,
                                      sizeof(error)) == 0,
                       "build admitted manifest")) {
        return 1;
    }
    fill_projection(&projection, cpu_entries, &manifest);
    if (service_expect(wvm_runtime_dispatch_projection_validate(
                           &projection, error, sizeof(error)) == 0,
                       "build admitted dispatch projection")) {
        return 1;
    }
    wvm_route_runtime_init(&routes);
    if (service_expect(wvm_route_runtime_prepare(&routes, &snapshot, error,
                                                 sizeof(error)) == 0 &&
                           wvm_route_runtime_activate(
                               &routes, &snapshot.route_snapshot_key, error,
                               sizeof(error)) == 0,
                       "activate route snapshot")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    wvm_runtime_gate_init(&gate);
    if (service_expect(wvm_runtime_gate_prepare(
                           &gate, &manifest, manifest.physical_node_id,
                           manifest.expected_node_instance_id, error,
                           sizeof(error)) == 0 &&
                           wvm_runtime_manifest_profile_digest(
                               &manifest, profile_digest, error,
                               sizeof(error)) == 0,
                       "prepare admitted runtime gate")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&registration, 0, sizeof(registration));
    registration.connection_role = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    registration.vm_id = manifest.vm_id;
    registration.vm_incarnation = manifest.vm_incarnation;
    registration.manifest_generation = manifest.manifest_generation;
    memcpy(registration.candidate_manifest_digest,
           manifest.candidate_manifest_digest,
           sizeof(registration.candidate_manifest_digest));
    registration.local_runtime_instance_id = manifest.expected_node_instance_id;
    registration.caller_process_instance_id = 501;
    memcpy(registration.capability_profile_digest, profile_digest,
           sizeof(registration.capability_profile_digest));
    snprintf(registration.requested_endpoint_name,
             sizeof(registration.requested_endpoint_name), "%s",
             manifest.local_names.namespace_name);
    if (service_expect(wvm_runtime_gate_register(
                           &gate, &registration, &connection_id, error,
                           sizeof(error)) == 0 &&
                           wvm_runtime_gate_activate(
                               &gate, manifest.activation_fence, error,
                               sizeof(error)) == 0,
                       "activate runtime gate")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&coordinator_config, 0, sizeof(coordinator_config));
    coordinator_config.manifest = &manifest;
    coordinator_config.runtime_gate = &gate;
    coordinator_config.dispatch = &projection;
    coordinator_config.route_runtime = &routes;
    coordinator_config.local_runtime_instance_id =
        manifest.expected_node_instance_id;
    coordinator_config.runtime_connection_id = connection_id;
    coordinator_config.operation_retention_horizon_ms =
        snapshot.operation_retention_horizon_ms;
    coordinator_config.send_envelope = capture_send;
    coordinator_config.send_envelope_opaque = &sent;
    coordinator_config.complete = wvm_vcpu_service_complete;
    coordinator_config.complete_opaque = &service;
    if (service_expect(wvm_vcpu_handoff_coordinator_init(
                           &coordinator, &coordinator_config, error,
                           sizeof(error)) == 0,
                       "initialize vCPU coordinator")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&service_config, 0, sizeof(service_config));
    service_config.coordinator = &coordinator;
    service_config.record_capacity =
        manifest.launch_plan.vcpu_handoff_record_capacity;
    if (service_expect(wvm_vcpu_service_init(&service, &service_config, error,
                                              sizeof(error)) == 0,
                       "initialize local vCPU service") ||
        service_expect(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
                       "create QEMU IPC socket pair")) {
        wvm_vcpu_service_destroy(&service);
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (service_expect(fill_until_eagain(sockets[0]) == 0,
                       "fill QEMU reply socket until EAGAIN")) {
        close(sockets[0]);
        close(sockets[1]);
        wvm_vcpu_service_destroy(&service);
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&legacy_request, 0, sizeof(legacy_request));
    legacy_request.mode_tcg = 1;
    legacy_request.slave_id = WVM_NODE_AUTO_ROUTE;
    legacy_request.vcpu_index = 3;
    legacy_request.ctx.tcg.eip = UINT64_C(0x1122334455667788);
    legacy_request.ctx.tcg.interrupt_request = 0x20;
    if (service_expect(wvm_vcpu_service_submit(&service, sockets[0],
                                                &legacy_request, error,
                                                sizeof(error)) == 0 &&
                           sent.count == 1 &&
                           sent.envelope.message_type ==
                               WVM_ENVELOPE_MSG_VCPU_RUN &&
                           sent.request.backend == WVM_VCPU_BACKEND_TCG &&
                           sent.request.memory_fence_id != 0 &&
                           sent.request.local_interrupt_watermark == 0 &&
                           sent.request.device_event_watermark == 0 &&
                           sent.request.destination_executor_id == 11,
                       "adapt QEMU request through admitted placement")) {
        close(sockets[0]);
        close(sockets[1]);
        wvm_vcpu_service_destroy(&service);
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&decoded_context, 0, sizeof(decoded_context));
    if (service_expect(wvm_x86_context_decode(
                           WVM_VCPU_BACKEND_TCG, sent.request.context,
                           sent.request.context_bytes,
                           &decoded_context_fields,
                           &decoded_context, sizeof(decoded_context), error,
                           sizeof(error)) == 0 &&
                           decoded_context_fields ==
                               (WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                                WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE |
                                WVM_VCPU_CONTEXT_FIELD_TIMER_STATE) &&
                           decoded_context.eip ==
                               legacy_request.ctx.tcg.eip &&
                           decoded_context.interrupt_request ==
                               legacy_request.ctx.tcg.interrupt_request,
                       "encode the complete local TCG context")) {
        close(sockets[0]);
        close(sockets[1]);
        wvm_vcpu_service_destroy(&service);
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&remote_context, 0, sizeof(remote_context));
    remote_context.eip = UINT64_C(0x8877665544332211);
    remote_context.interrupt_request = 0x40;
    if (service_expect(wvm_x86_context_encode(
                           WVM_VCPU_BACKEND_TCG,
                           WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE |
                               WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE,
                           &remote_context, sizeof(remote_context),
                           result_context, sizeof(result_context),
                           &result_context_bytes, error, sizeof(error)) == 0 &&
                           build_success_exit(
                               &sent, 1, result_context, result_context_bytes,
                               exit_payload, sizeof(exit_payload),
                               &exit_envelope, error, sizeof(error)) == 0 &&
                           wvm_vcpu_handoff_coordinator_dispatch(
                               &coordinator, &exit_envelope, error,
                               sizeof(error)) == 0,
                       "queue typed VCPU_EXIT toward blocked reply socket")) {
        close(sockets[0]);
        close(sockets[1]);
        wvm_vcpu_service_destroy(&service);
        wvm_vcpu_handoff_coordinator_destroy(&coordinator);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    usleep(80000);
    error[0] = '\0';
    {
        int drain_rc = wvm_vcpu_service_drain(&service, 50, error, sizeof(error));
        fprintf(stderr, "G8_DRAIN_BLOCKED rc=%d err=%s\n", drain_rc, error);
        if (service_expect(drain_rc == -ETIMEDOUT,
                           "drain must ETIMEDOUT while ACK send blocked")) {
            close(sockets[0]);
            close(sockets[1]);
            wvm_vcpu_service_destroy(&service);
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }
    }

    {
        uint8_t sink[16384];
        int rf = fcntl(sockets[1], F_GETFL, 0);
        fcntl(sockets[1], F_SETFL, rf | O_NONBLOCK);
        while (recv(sockets[1], sink, sizeof(sink), 0) > 0) {
        }
    }
    usleep(150000);
    error[0] = '\0';
    {
        int drain_rc = wvm_vcpu_service_drain(&service, 2000, error,
                                              sizeof(error));
        fprintf(stderr, "G8_DRAIN_AFTER_UNBLOCK rc=%d err=%s\n", drain_rc,
                error);
        if (service_expect(drain_rc == 0,
                           "drain succeeds after receiver makes room")) {
            close(sockets[0]);
            close(sockets[1]);
            wvm_vcpu_service_destroy(&service);
            wvm_vcpu_handoff_coordinator_destroy(&coordinator);
            wvm_route_runtime_destroy(&routes);
            return 1;
        }
    }

    close(sockets[0]);
    close(sockets[1]);
    wvm_vcpu_service_destroy(&service);
    wvm_vcpu_handoff_coordinator_destroy(&coordinator);
    wvm_route_runtime_destroy(&routes);
    fprintf(stderr, "G8_VCPU_SERVICE_DRAIN PASS\n");
    return 0;
}

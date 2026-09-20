#include "wavevm_admission_authority_owner.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t error_len, const char *format, ...)
{
    va_list arguments;

    if (!error || error_len == 0) {
        return;
    }
    va_start(arguments, format);
    vsnprintf(error, error_len, format, arguments);
    va_end(arguments);
}

static int owner_config_valid(
    const struct wvm_admission_authority_owner_config *config, char *error,
    size_t error_len)
{
    if (!config || !config->membership_controller ||
        !config->membership_capture || !config->evidence_owner ||
        !config->plan_provider || !config->route_compiler ||
        !config->transport || !config->prepared_route ||
        !config->prepared_vm ||
        !config->activation || !config->route_transaction ||
        !config->route_snapshot || !config->reset_workspace ||
        !config->membership_capture->nodes ||
        config->membership_capture->node_capacity == 0 ||
        !config->membership_capture->gateways ||
        config->membership_capture->gateway_capacity == 0 ||
        !config->evidence_owner->initialized ||
        !config->plan_provider->initialized ||
        wvm_admission_route_compiler_validate(config->route_compiler, error,
                                              error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "admission authority owner configuration is incomplete");
        }
        return -1;
    }
    return 0;
}

static int owner_prepare_input(
    void *context, const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    struct wvm_admission_authority_owner *owner = context;

    if (!owner || !owner->initialized || !request || !transaction || !input ||
        owner_config_valid(&owner->config, error, error_len) != 0) {
        set_error(error, error_len,
                  "admission authority owner is not configured");
        return -1;
    }
    if (owner->config.reset_workspace(
            owner->config.workspace_context, request, owner->config.prepared_route,
            owner->config.prepared_vm,
            owner->config.activation, owner->config.route_transaction,
            owner->config.route_snapshot, error, error_len) != 0 ||
        !owner->config.plan_provider->published ||
        !owner->config.plan_provider->options_template_published ||
        wvm_admission_evidence_owner_validate(owner->config.evidence_owner,
                                              error, error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "admission authority has no complete published input");
        }
        return -1;
    }
    input->membership_controller = owner->config.membership_controller;
    input->membership_capture = owner->config.membership_capture;
    input->prepared_route = owner->config.prepared_route;
    input->prepared_vm = owner->config.prepared_vm;
    input->coordinator_instance_id =
        owner->config.transport->controller_instance_id;
    input->activation = owner->config.activation;
    input->route_transaction = owner->config.route_transaction;
    input->route_snapshot = owner->config.route_snapshot;
    return wvm_admission_plan_provider_prepare_input(
        owner->config.plan_provider, request, transaction, input, error,
        error_len);
}

static int owner_refresh_input(
    void *context, enum wvm_admission_input_phase phase,
    const struct wvm_vm_request *request,
    const struct wvm_coordinator_transaction *transaction,
    struct wvm_admission_orchestrator_input *input, char *error,
    size_t error_len)
{
    struct wvm_admission_authority_owner *owner = context;

    if (!owner || !owner->initialized ||
        wvm_admission_evidence_owner_refresh_input(
            owner->config.evidence_owner, phase, request, transaction, input,
            error, error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "admission authority owner cannot capture evidence");
        }
        return -1;
    }
    return 0;
}

static int owner_route_plan(
    void *context, const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len)
{
    struct wvm_admission_authority_owner *owner = context;

    if (!owner || !owner->initialized ||
        wvm_admission_plan_provider_validate(owner->config.plan_provider,
                                             records, error, error_len) != 0 ||
        wvm_admission_route_compile(owner->config.route_compiler, transaction,
                                    records, prepared_route,
                                    route_transaction, route_snapshot, error,
                                    error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "admission authority owner cannot compile route plan");
        }
        return -1;
    }
    return 0;
}

#define DEFINE_STAGE_FORWARDER(name, arguments, call_arguments)                 \
    static int owner_##name arguments                                            \
    {                                                                            \
        struct wvm_admission_authority_owner *owner = context;                  \
        struct wvm_admission_orchestrator_callbacks callbacks;                  \
                                                                                 \
        if (!owner || !owner->initialized ||                                    \
            wvm_admission_transport_callbacks(owner->config.transport,          \
                                              &callbacks, error, error_len) != 0) { \
            if (error && error[0] == '\0') {                                    \
                set_error(error, error_len,                                     \
                          "admission authority transport is unavailable");      \
            }                                                                    \
            return -1;                                                           \
        }                                                                        \
        return callbacks.name call_arguments;                                    \
    }

DEFINE_STAGE_FORWARDER(
    route_prepare,
    (void *context, const struct wvm_coordinator_transaction *transaction,
     const struct wvm_route_transaction_record *route_transaction,
     const struct wvm_route_snapshot_record *route_snapshot, char *error,
     size_t error_len),
    (owner->config.transport, transaction, route_transaction, route_snapshot,
     error, error_len))

DEFINE_STAGE_FORWARDER(
    route_commit,
    (void *context, const struct wvm_coordinator_transaction *transaction,
     const struct wvm_route_transaction_record *route_transaction,
     const struct wvm_route_snapshot_record *route_snapshot, char *error,
     size_t error_len),
    (owner->config.transport, transaction, route_transaction, route_snapshot,
     error, error_len))

DEFINE_STAGE_FORWARDER(
    route_abort,
    (void *context, const struct wvm_coordinator_transaction *transaction,
     const struct wvm_route_transaction_record *route_transaction,
     const struct wvm_route_snapshot_record *route_snapshot, char *error,
     size_t error_len),
    (owner->config.transport, transaction, route_transaction, route_snapshot,
     error, error_len))

DEFINE_STAGE_FORWARDER(
    reservation_prepare,
    (void *context, const struct wvm_candidate_vm_manifest *candidate,
     const struct wvm_resource_reservation *reservation, char *error,
     size_t error_len),
    (owner->config.transport, candidate, reservation, error, error_len))

DEFINE_STAGE_FORWARDER(
    reservation_commit,
    (void *context, const struct wvm_candidate_vm_manifest *candidate,
     const struct wvm_resource_reservation *reservation,
     const struct wvm_activation_record *activation, char *error,
     size_t error_len),
    (owner->config.transport, candidate, reservation, activation, error,
     error_len))

DEFINE_STAGE_FORWARDER(
    reservation_abort,
    (void *context, const struct wvm_candidate_vm_manifest *candidate,
     const struct wvm_resource_reservation *reservation, char *error,
     size_t error_len),
    (owner->config.transport, candidate, reservation, error, error_len))

DEFINE_STAGE_FORWARDER(
    participant_prepare,
    (void *context, const struct wvm_candidate_vm_manifest *candidate,
     const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
     size_t error_len),
    (owner->config.transport, candidate, runtime_manifest, error, error_len))

DEFINE_STAGE_FORWARDER(
    participant_commit,
    (void *context, const struct wvm_candidate_vm_manifest *candidate,
     const struct wvm_node_runtime_manifest *runtime_manifest,
     const struct wvm_activation_record *activation, char *error,
     size_t error_len),
    (owner->config.transport, candidate, runtime_manifest, activation, error,
     error_len))

DEFINE_STAGE_FORWARDER(
    participant_abort,
    (void *context, const struct wvm_candidate_vm_manifest *candidate,
     const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
     size_t error_len),
    (owner->config.transport, candidate, runtime_manifest, error, error_len))

DEFINE_STAGE_FORWARDER(
    participant_ready,
    (void *context, const struct wvm_candidate_vm_manifest *candidate,
     const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
     size_t error_len),
    (owner->config.transport, candidate, runtime_manifest, error, error_len))

#undef DEFINE_STAGE_FORWARDER

int wvm_admission_authority_owner_init(
    struct wvm_admission_authority_owner *owner,
    const struct wvm_admission_authority_owner_config *config, char *error,
    size_t error_len)
{
    struct wvm_admission_orchestrator_callbacks transport_callbacks;

    if (!owner || owner_config_valid(config, error, error_len) != 0 ||
        wvm_admission_transport_callbacks(config->transport,
                                          &transport_callbacks, error,
                                          error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len,
                      "admission authority owner initialization is invalid");
        }
        return -1;
    }
    memset(owner, 0, sizeof(*owner));
    owner->config = *config;
    owner->authority.prepare_input = owner_prepare_input;
    owner->authority.refresh_input = owner_refresh_input;
    owner->authority.callbacks.route_plan = owner_route_plan;
    owner->authority.callbacks.route_prepare = owner_route_prepare;
    owner->authority.callbacks.route_commit = owner_route_commit;
    owner->authority.callbacks.route_abort = owner_route_abort;
    owner->authority.callbacks.reservation_prepare = owner_reservation_prepare;
    owner->authority.callbacks.reservation_commit = owner_reservation_commit;
    owner->authority.callbacks.reservation_abort = owner_reservation_abort;
    owner->authority.callbacks.participant_prepare = owner_participant_prepare;
    owner->authority.callbacks.participant_commit = owner_participant_commit;
    owner->authority.callbacks.participant_abort = owner_participant_abort;
    owner->authority.callbacks.participant_ready = owner_participant_ready;
    owner->authority.context = owner;
    if (wvm_admission_authority_validate(&owner->authority, error, error_len) !=
        0) {
        memset(owner, 0, sizeof(*owner));
        return -1;
    }
    owner->initialized = 1;
    return 0;
}

const struct wvm_admission_authority *wvm_admission_authority_owner_binding(
    const struct wvm_admission_authority_owner *owner)
{
    return owner && owner->initialized ? &owner->authority : NULL;
}

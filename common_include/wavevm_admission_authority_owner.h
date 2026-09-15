#ifndef WAVEVM_ADMISSION_AUTHORITY_OWNER_H
#define WAVEVM_ADMISSION_AUTHORITY_OWNER_H

/*
 * Caller-owned composition of the inputs required by one production admission
 * transaction. This module does not discover members, create endpoints, or
 * manufacture capacity. It binds control-plane providers to the orchestrator's
 * single authority interface; publication readiness is checked per admission.
 */

#include <stddef.h>

#include "wavevm_admission_evidence.h"
#include "wavevm_admission_orchestrator.h"
#include "wavevm_admission_provider.h"
#include "wavevm_admission_route.h"
#include "wavevm_admission_transport.h"
#include "wavevm_membership_controller.h"

/*
 * Reset all per-transaction workspace while retaining its caller-provided
 * bounded allocations. The callback is invoked only for a new transaction,
 * after durable BEGIN and before any evidence capture or participant stage.
 */
typedef int (*wvm_admission_workspace_reset_fn)(
    void *context, struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_coordinator_activation_options *activation_options,
    struct wvm_activation_record *activation,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len);

struct wvm_admission_authority_owner_config {
    struct wvm_membership_controller *membership_controller;
    struct wvm_membership_controller_capture *membership_capture;
    struct wvm_admission_evidence_owner *evidence_owner;
    struct wvm_admission_plan_provider *plan_provider;
    struct wvm_admission_route_compiler *route_compiler;
    struct wvm_admission_transport *transport;
    struct wvm_coordinator_prepared_route *prepared_route;
    struct wvm_coordinator_prepared_vm *prepared_vm;
    struct wvm_coordinator_activation_options *activation_options;
    struct wvm_activation_record *activation;
    struct wvm_route_transaction_record *route_transaction;
    struct wvm_route_snapshot_record *route_snapshot;
    void *workspace_context;
    wvm_admission_workspace_reset_fn reset_workspace;
};

/*
 * All storage remains owned by CONFIG's caller. One owner workspace represents
 * one in-flight admission, so its caller must serialize new transactions or
 * provide independent owner/workspace instances. Initialization may happen
 * before membership/evidence/plan publication; the first transaction remains
 * fail-closed until all three publications are complete and current.
 */
struct wvm_admission_authority_owner {
    struct wvm_admission_authority_owner_config config;
    struct wvm_admission_authority authority;
    int initialized;
};

int wvm_admission_authority_owner_init(
    struct wvm_admission_authority_owner *owner,
    const struct wvm_admission_authority_owner_config *config, char *error,
    size_t error_len);

const struct wvm_admission_authority *wvm_admission_authority_owner_binding(
    const struct wvm_admission_authority_owner *owner);

#endif /* WAVEVM_ADMISSION_AUTHORITY_OWNER_H */

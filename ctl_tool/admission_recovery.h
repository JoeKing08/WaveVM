#ifndef WVM_CTL_ADMISSION_RECOVERY_H
#define WVM_CTL_ADMISSION_RECOVERY_H

#include <stddef.h>
#include <stdint.h>

#include "../common_include/wavevm_control_plane.h"
#include "../common_include/wavevm_control_transport.h"
#include "../common_include/wavevm_admission_orchestrator.h"
#include "../common_include/wavevm_membership_controller.h"

/*
 * After durable journals are open, resume mid-flight CREATE_VM admissions
 * via wvm_admission_orchestrator_recover (runtime-manifest-lifecycle §5.3).
 * RUNNING/ABORTED/terminal states are skipped. Failures are fail-closed:
 * the entry stays durable and readiness is not opened. Does not invent
 * live migration, RECOVERY_REBIND, or coordinator HA.
 *
 * ACTIVATION_DECIDED without durable runtime manifests rebuilds projections
 * from on-disk node runtime profiles → launch plans (same port binding as
 * live prepare). Missing profiles/plans remain fail-closed.
 * COMMITTED still requires durable runtime manifests.
 *
 * member_capacity / max_vcpus / route_rule_capacity / route_ack_capacity size
 * reconstruction scratch; use the same serve --capacity bounds.
 */
int wvm_ctl_recover_midflight_admissions(
    struct wvm_control_plane *plane,
    struct wvm_vm_namespace_allocator *namespace_allocator,
    struct wvm_membership_controller *membership_controller,
    const struct wvm_admission_authority *authority,
    const char *state_directory,
    const struct wvm_membership_controller_capture *membership_capture,
    size_t member_capacity, uint32_t max_vcpus, size_t route_rule_capacity,
    size_t route_ack_capacity, char *error, size_t error_len);

/*
 * STOP_VM production entry (goal §2 / runtime-manifest-lifecycle §6.1):
 * locate durable RUNNING|STOPPING|RETIRING|STOPPED by vm_id+incarnation
 * (+ optional manifest_generation), rebuild prepared_vm/route from journals,
 * promote reservations to COMMITTED via durable activation, then call
 * wvm_admission_orchestrator_stop. STOPPED is idempotent SUCCESS.
 * Unknown VM / wrong incarnation → NOT_FOUND / PRECONDITION fail-closed.
 */
int wvm_ctl_stop_vm(
    struct wvm_control_plane *plane,
    struct wvm_vm_namespace_allocator *namespace_allocator,
    struct wvm_membership_controller *membership_controller,
    const struct wvm_admission_authority *authority,
    const char *state_directory,
    const struct wvm_membership_controller_capture *membership_capture,
    uint32_t vm_id, uint64_t vm_incarnation, uint64_t manifest_generation,
    size_t member_capacity, uint32_t max_vcpus, size_t route_rule_capacity,
    size_t route_ack_capacity, struct wvm_control_result *result, char *error,
    size_t error_len);

/*
 * Continuous production health loop (goal §1 / membership §5.6 /
 * runtime-manifest-lifecycle §6.2): scan durable RUNNING|DEGRADED VMs and
 * fail-closed when required members are unhealthy.
 *   RUNNING + unhealthy -> DEGRADED
 *   DEGRADED + still unhealthy -> FAILED
 * Does not invent RECOVERY_REBIND / silent rebind. CREATE-time degrade alone
 * is not sufficient; ctl serve must call this periodically.
 * transitioned_out may be NULL. Returns 0 even when some VMs transition;
 * returns -1 only on invalid input / hard plane errors.
 */
int wvm_ctl_reconcile_required_member_health(
    struct wvm_control_plane *plane,
    struct wvm_membership_controller *membership_controller,
    size_t *transitioned_out, char *error, size_t error_len);

#endif

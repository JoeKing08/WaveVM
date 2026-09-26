#ifndef WAVEVM_ADMISSION_ROUTE_H
#define WAVEVM_ADMISSION_ROUTE_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_control.h"
#include "wavevm_coordinator.h"
#include "wavevm_membership.h"

/*
 * Bounded storage for one admission route compilation. The compiler emits
 * canonical route records only; it does not install them or treat compilation
 * as a participant acknowledgement.
 */
struct wvm_admission_route_compiler {
    enum wvm_route_topology_kind topology_kind;
    uint64_t route_generation;
    uint64_t operation_retention_horizon_ms;
    uint16_t retirement_policy;
    struct wvm_route_rule_record *route_rules;
    size_t route_rule_capacity;
    size_t route_rule_count;
    struct wvm_required_ack_entry *ack_entries;
    size_t ack_entry_capacity;
    size_t ack_entry_count;
    uint8_t *snapshot_bytes;
    size_t snapshot_byte_capacity;
    uint8_t *ack_set_bytes;
    size_t ack_set_byte_capacity;
};

int wvm_admission_route_compiler_init(
    struct wvm_admission_route_compiler *compiler,
    enum wvm_route_topology_kind topology_kind, uint64_t route_generation,
    uint64_t operation_retention_horizon_ms, uint16_t retirement_policy,
    struct wvm_route_rule_record *route_rules, size_t route_rule_capacity,
    struct wvm_required_ack_entry *ack_entries, size_t ack_entry_capacity,
    uint8_t *snapshot_bytes, size_t snapshot_byte_capacity,
    uint8_t *ack_set_bytes, size_t ack_set_byte_capacity, char *error,
    size_t error_len);

int wvm_admission_route_compiler_validate(
    const struct wvm_admission_route_compiler *compiler, char *error,
    size_t error_len);

/* Signature-compatible with wvm_admission_route_plan_fn. */
int wvm_admission_route_compile(
    void *context, const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len);

#endif /* WAVEVM_ADMISSION_ROUTE_H */

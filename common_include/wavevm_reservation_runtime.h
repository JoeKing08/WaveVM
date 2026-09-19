#ifndef WAVEVM_RESERVATION_RUNTIME_H
#define WAVEVM_RESERVATION_RUNTIME_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "wavevm_admission.h"
#include "wavevm_lifecycle.h"

enum wvm_reservation_runtime_result {
    WVM_RESERVATION_RUNTIME_NEW = 1,
    WVM_RESERVATION_RUNTIME_REPLAY = 2,
};

struct wvm_local_reservation_registry {
    pthread_mutex_t lock;
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t inventory_revision;
    uint32_t allocatable_vcpu_slots;
    uint64_t allocatable_memory_bytes;
    uint32_t prepared_vcpu_slots;
    uint64_t prepared_memory_bytes;
    uint32_t committed_vcpu_slots;
    uint64_t committed_memory_bytes;
    struct wvm_resource_reservation *reservations;
    size_t reservation_count;
    size_t reservation_capacity;
    /* Lease lists are registry-owned copies, including released tombstones. */
    int initialized;
    int journal_fd;
    int journal_failed;
    uint64_t journal_bytes;
    uint64_t journal_byte_limit;
    uint64_t next_journal_sequence;
};

int wvm_local_reservation_registry_init(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_admission_node *node,
    struct wvm_resource_reservation *reservations,
    size_t reservation_capacity, char *error, size_t error_len);

void wvm_local_reservation_registry_destroy(
    struct wvm_local_reservation_registry *registry);

/* Open/replay into an empty initialized registry before accepting traffic.
 * A failed open or uncertain write fences mutations until destroy/reopen.
 * Byte and entry exhaustion reject explicitly; tombstones are not evicted. */
int wvm_local_reservation_registry_open(
    struct wvm_local_reservation_registry *registry, const char *path,
    uint64_t byte_limit, char *error, size_t error_len);

int wvm_local_reservation_registry_is_durable(
    struct wvm_local_reservation_registry *registry);

int wvm_local_reservation_prepare(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *reservation,
    enum wvm_reservation_runtime_result *result, char *error,
    size_t error_len);

/* EXPECTED binds the full immutable reservation, not just its ID. */
int wvm_local_reservation_commit(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *expected,
    const struct wvm_activation_record *activation,
    enum wvm_reservation_runtime_result *result, char *error,
    size_t error_len);

/* Unknown aborts install tombstones; committed reservations cannot abort. */
int wvm_local_reservation_abort(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *expected,
    enum wvm_reservation_runtime_result *result, char *error,
    size_t error_len);

size_t wvm_local_reservation_reap_expired(
    struct wvm_local_reservation_registry *registry,
    uint64_t now_unix_time_ms);

const struct wvm_resource_reservation *wvm_local_reservation_find(
    const struct wvm_local_reservation_registry *registry,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES]);

#endif

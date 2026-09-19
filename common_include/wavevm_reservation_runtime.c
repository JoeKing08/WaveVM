#include "wavevm_reservation_runtime.h"

#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_envelope.h"

#define RESERVATION_JOURNAL_HEADER_BYTES 96U
#define RESERVATION_RECORD_BASE_BYTES 512U
#define RESERVATION_LEASE_BUFFER_BYTES 512U

static const uint8_t reservation_journal_magic[8] = {'W', 'V', 'M', 'R', 'S', 'V', 0, 0};

static int persist_reservation(struct wvm_local_reservation_registry *registry,
                               const struct wvm_resource_reservation *record,
                               char *error, size_t error_len);

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static int id_equal(const uint8_t left[WVM_IDENTITY_ID_BYTES],
                    const uint8_t right[WVM_IDENTITY_ID_BYTES])
{
    return memcmp(left, right, WVM_IDENTITY_ID_BYTES) == 0;
}

static uint64_t reservation_cpu(const struct wvm_resource_reservation *reservation)
{
    return (uint64_t)reservation->guest_vcpu_slots +
           reservation->overhead_vcpu_slots;
}

static uint64_t reservation_memory(
    const struct wvm_resource_reservation *reservation)
{
    return reservation->guest_memory_bytes + reservation->overhead_memory_bytes;
}

/* A replay must preserve the complete immutable lease record. */
static int lease_record_equal(const struct wvm_exclusive_lease *left,
                              const struct wvm_exclusive_lease *right)
{
    return left->lease_kind == right->lease_kind &&
           left->lease_generation == right->lease_generation &&
           strcmp(left->lease_name, right->lease_name) == 0;
}

/* Generation identifies an acquisition epoch, not a different local resource. */
static int lease_resource_equal(const struct wvm_exclusive_lease *left,
                                const struct wvm_exclusive_lease *right)
{
    return left->lease_kind == right->lease_kind &&
           strcmp(left->lease_name, right->lease_name) == 0;
}

static int reservation_equal(
    const struct wvm_resource_reservation *left,
    const struct wvm_resource_reservation *right)
{
    size_t i;

    if (!id_equal(left->reservation_id, right->reservation_id) ||
        memcmp(left->plan_digest, right->plan_digest,
               sizeof(left->plan_digest)) != 0 ||
        memcmp(left->candidate_manifest_digest,
               right->candidate_manifest_digest,
               sizeof(left->candidate_manifest_digest)) != 0 ||
        memcmp(left->admission_tx_id, right->admission_tx_id,
               sizeof(left->admission_tx_id)) != 0 ||
        memcmp(left->eligibility_fence_digest,
               right->eligibility_fence_digest,
               sizeof(left->eligibility_fence_digest)) != 0 ||
        left->vm_id != right->vm_id ||
        left->vm_incarnation != right->vm_incarnation ||
        left->physical_node_id != right->physical_node_id ||
        left->node_instance_id != right->node_instance_id ||
        left->inventory_revision != right->inventory_revision ||
        left->guest_vcpu_slots != right->guest_vcpu_slots ||
        left->guest_memory_bytes != right->guest_memory_bytes ||
        left->overhead_vcpu_slots != right->overhead_vcpu_slots ||
        left->overhead_memory_bytes != right->overhead_memory_bytes ||
        left->state != right->state ||
        left->has_prepared_expiry != right->has_prepared_expiry ||
        left->prepared_expiry_unix_time_ms !=
            right->prepared_expiry_unix_time_ms ||
        left->has_activation_fence != right->has_activation_fence ||
        memcmp(left->activation_fence, right->activation_fence,
               sizeof(left->activation_fence)) != 0 ||
        left->exclusive_leases.count != right->exclusive_leases.count) {
        return 0;
    }
    for (i = 0; i < left->exclusive_leases.count; i++) {
        if (!lease_record_equal(&left->exclusive_leases.entries[i],
                                &right->exclusive_leases.entries[i])) {
            return 0;
        }
    }
    return 1;
}

static struct wvm_resource_reservation *find_mutable(
    struct wvm_local_reservation_registry *registry,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    for (i = 0; i < registry->reservation_count; i++) {
        if (id_equal(registry->reservations[i].reservation_id,
                     reservation_id)) {
            return &registry->reservations[i];
        }
    }
    return NULL;
}

static int copy_reservation(const struct wvm_resource_reservation *source,
                            struct wvm_resource_reservation *owned,
                            char *error, size_t error_len)
{
    *owned = *source;
    owned->exclusive_leases.entries = NULL;
    owned->exclusive_leases.capacity = owned->exclusive_leases.count;
    if (!owned->exclusive_leases.count) {
        return 0;
    }
    if (owned->exclusive_leases.count >
        (WVM_ENVELOPE_MAX_LOCAL_PAYLOAD - RESERVATION_RECORD_BASE_BYTES) /
            RESERVATION_LEASE_BUFFER_BYTES) {
        set_error(error, error_len, "reservation lease storage is too large");
        return -1;
    }
    owned->exclusive_leases.entries = malloc(
        owned->exclusive_leases.count * sizeof(*owned->exclusive_leases.entries));
    if (!owned->exclusive_leases.entries) {
        set_error(error, error_len, "cannot copy reservation leases");
        return -1;
    }
    memcpy(owned->exclusive_leases.entries, source->exclusive_leases.entries,
           owned->exclusive_leases.count * sizeof(*owned->exclusive_leases.entries));
    return 0;
}

const struct wvm_resource_reservation *wvm_local_reservation_find(
    const struct wvm_local_reservation_registry *registry,
    const uint8_t reservation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!registry || !reservation_id) {
        return NULL;
    }
    for (i = 0; i < registry->reservation_count; i++) {
        if (id_equal(registry->reservations[i].reservation_id,
                     reservation_id)) {
            return &registry->reservations[i];
        }
    }
    return NULL;
}

static int leases_conflict(
    const struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *candidate)
{
    size_t i;
    size_t j;

    for (i = 0; i < registry->reservation_count; i++) {
        const struct wvm_resource_reservation *existing =
            &registry->reservations[i];

        if (existing->state == WVM_RESERVATION_RELEASED ||
            id_equal(existing->reservation_id, candidate->reservation_id)) {
            continue;
        }
        for (j = 0; j < candidate->exclusive_leases.count; j++) {
            size_t k;

            for (k = 0; k < existing->exclusive_leases.count; k++) {
                if (lease_resource_equal(
                        &candidate->exclusive_leases.entries[j],
                        &existing->exclusive_leases.entries[k])) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int capacity_allows(
    const struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *reservation)
{
    uint64_t used_cpu = (uint64_t)registry->prepared_vcpu_slots +
                        registry->committed_vcpu_slots;
    uint64_t used_memory = registry->prepared_memory_bytes +
                           registry->committed_memory_bytes;
    uint64_t cpu;
    uint64_t memory;

    if (reservation->overhead_vcpu_slots >
            UINT32_MAX - reservation->guest_vcpu_slots ||
        reservation->overhead_memory_bytes >
            UINT64_MAX - reservation->guest_memory_bytes ||
        used_cpu > registry->allocatable_vcpu_slots ||
        used_memory > registry->allocatable_memory_bytes) {
        return 0;
    }
    cpu = reservation_cpu(reservation);
    memory = reservation_memory(reservation);

    return cpu <= (uint64_t)registry->allocatable_vcpu_slots - used_cpu &&
           memory <= registry->allocatable_memory_bytes - used_memory;
}

static int reservation_account_units(
    const struct wvm_resource_reservation *reservation, uint32_t *cpu,
    uint64_t *memory)
{
    if (!reservation || !cpu || !memory ||
        reservation->overhead_vcpu_slots >
            UINT32_MAX - reservation->guest_vcpu_slots ||
        reservation->overhead_memory_bytes >
            UINT64_MAX - reservation->guest_memory_bytes) {
        return -1;
    }
    *cpu = reservation->guest_vcpu_slots + reservation->overhead_vcpu_slots;
    *memory = reservation->guest_memory_bytes +
              reservation->overhead_memory_bytes;
    return 0;
}

static int account_add(struct wvm_local_reservation_registry *registry,
                       const struct wvm_resource_reservation *reservation)
{
    uint32_t cpu;
    uint64_t memory;

    if (!registry || reservation_account_units(reservation, &cpu, &memory) !=
                         0) {
        return -1;
    }

    if (reservation->state == WVM_RESERVATION_PREPARED) {
        if (registry->prepared_vcpu_slots >
                UINT32_MAX - cpu ||
            registry->prepared_memory_bytes >
                UINT64_MAX - memory) {
            return -1;
        }
        registry->prepared_vcpu_slots += cpu;
        registry->prepared_memory_bytes += memory;
    } else if (reservation->state == WVM_RESERVATION_COMMITTED) {
        if (registry->committed_vcpu_slots >
                UINT32_MAX - cpu ||
            registry->committed_memory_bytes >
                UINT64_MAX - memory) {
            return -1;
        }
        registry->committed_vcpu_slots += cpu;
        registry->committed_memory_bytes += memory;
    }
    return 0;
}

static int account_remove(struct wvm_local_reservation_registry *registry,
                          const struct wvm_resource_reservation *reservation)
{
    uint32_t cpu;
    uint64_t memory;

    if (!registry || reservation_account_units(reservation, &cpu, &memory) !=
                         0) {
        return -1;
    }

    if (reservation->state == WVM_RESERVATION_PREPARED) {
        if (registry->prepared_vcpu_slots < cpu ||
            registry->prepared_memory_bytes < memory) {
            return -1;
        }
        registry->prepared_vcpu_slots -= cpu;
        registry->prepared_memory_bytes -= memory;
    } else if (reservation->state == WVM_RESERVATION_COMMITTED) {
        if (registry->committed_vcpu_slots < cpu ||
            registry->committed_memory_bytes < memory) {
            return -1;
        }
        registry->committed_vcpu_slots -= cpu;
        registry->committed_memory_bytes -= memory;
    }
    return 0;
}

static int account_remove_possible(
    const struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *reservation)
{
    uint32_t cpu;
    uint64_t memory;

    if (!registry || reservation_account_units(reservation, &cpu, &memory) !=
                         0) {
        return -1;
    }
    if (reservation->state == WVM_RESERVATION_PREPARED) {
        return registry->prepared_vcpu_slots >= cpu &&
                       registry->prepared_memory_bytes >= memory
                   ? 0
                   : -1;
    }
    if (reservation->state == WVM_RESERVATION_COMMITTED) {
        return registry->committed_vcpu_slots >= cpu &&
                       registry->committed_memory_bytes >= memory
                   ? 0
                   : -1;
    }
    return 0;
}

int wvm_local_reservation_registry_init(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_admission_node *node,
    struct wvm_resource_reservation *reservations,
    size_t reservation_capacity, char *error, size_t error_len)
{
    if (!registry || !node || !reservations || reservation_capacity == 0 ||
        reservation_capacity > SIZE_MAX / sizeof(*reservations) ||
        node->physical_node_id == 0 || node->node_instance_id == 0 ||
        node->inventory_revision == 0 ||
        node->allocatable_memory_bytes == 0) {
        set_error(error, error_len, "reservation registry input is invalid");
        return -1;
    }
    memset(registry, 0, sizeof(*registry));
    registry->journal_fd = -1;
    registry->next_journal_sequence = 1;
    if (pthread_mutex_init(&registry->lock, NULL) != 0) {
        set_error(error, error_len, "cannot initialize reservation registry lock");
        return -1;
    }
    registry->initialized = 1;
    registry->physical_node_id = node->physical_node_id;
    registry->node_instance_id = node->node_instance_id;
    registry->inventory_revision = node->inventory_revision;
    registry->allocatable_vcpu_slots = node->allocatable_vcpu_slots;
    registry->allocatable_memory_bytes = node->allocatable_memory_bytes;
    registry->reservations = reservations;
    registry->reservation_capacity = reservation_capacity;
    memset(reservations, 0,
           reservation_capacity * sizeof(*registry->reservations));
    return 0;
}

void wvm_local_reservation_registry_destroy(
    struct wvm_local_reservation_registry *registry)
{
    size_t i;

    if (!registry || !registry->initialized) {
        return;
    }
    if (registry->journal_fd >= 0) {
        close(registry->journal_fd);
    }
    for (i = 0; i < registry->reservation_count; i++) {
        free(registry->reservations[i].exclusive_leases.entries);
    }
    memset(registry->reservations, 0,
           registry->reservation_capacity * sizeof(*registry->reservations));
    pthread_mutex_destroy(&registry->lock);
    memset(registry, 0, sizeof(*registry));
    registry->journal_fd = -1;
}

int wvm_local_reservation_prepare(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *reservation,
    enum wvm_reservation_runtime_result *result, char *error,
    size_t error_len)
{
    struct wvm_resource_reservation *existing;
    struct wvm_resource_reservation owned;
    size_t insertion_index;

    if (!registry || !registry->initialized || !reservation ||
        wvm_resource_reservation_validate(reservation, error, error_len) != 0 ||
        reservation->state != WVM_RESERVATION_PREPARED ||
        reservation->physical_node_id != registry->physical_node_id ||
        reservation->node_instance_id != registry->node_instance_id ||
        reservation->inventory_revision != registry->inventory_revision) {
        set_error(error, error_len, "reservation prepare identity is invalid");
        return -1;
    }
    pthread_mutex_lock(&registry->lock);
    if (registry->journal_failed) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation journal requires recovery");
        return -1;
    }
    existing = find_mutable(registry, reservation->reservation_id);
    if (existing) {
        int equal = reservation_equal(existing, reservation);

        pthread_mutex_unlock(&registry->lock);
        if (!equal) {
            set_error(error, error_len,
                      "reservation ID is reused with different contents");
            return -1;
        }
        if (result) {
            *result = WVM_RESERVATION_RUNTIME_REPLAY;
        }
        return 0;
    }
    insertion_index = registry->reservation_count;
    if (insertion_index == registry->reservation_capacity ||
        leases_conflict(registry, reservation) ||
        !capacity_allows(registry, reservation)) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len,
                  "reservation conflicts with local capacity or lease");
        return -1;
    }
    if (copy_reservation(reservation, &owned, error, error_len) != 0) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }
    if (persist_reservation(registry, &owned, error, error_len) != 0) {
        free(owned.exclusive_leases.entries);
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }
    if (account_add(registry, reservation) != 0) {
        free(owned.exclusive_leases.entries);
        registry->journal_failed = 1;
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation accounting overflow");
        return -1;
    }
    registry->reservations[insertion_index] = owned;
    registry->reservation_count++;
    pthread_mutex_unlock(&registry->lock);
    if (result) {
        *result = WVM_RESERVATION_RUNTIME_NEW;
    }
    return 0;
}

int wvm_local_reservation_commit(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *expected,
    const struct wvm_activation_record *activation,
    enum wvm_reservation_runtime_result *result, char *error,
    size_t error_len)
{
    struct wvm_resource_reservation *reservation;
    struct wvm_resource_reservation updated;
    struct wvm_resource_reservation expected_commit;
    uint32_t cpu;
    uint64_t memory;

    if (!registry || !registry->initialized || !expected || !activation ||
        wvm_resource_reservation_validate(expected, error, error_len) != 0 ||
        wvm_activation_record_validate(activation, error, error_len) != 0 ||
        activation->decision != WVM_ACTIVATION_ACTIVATE ||
        !id_equal(expected->admission_tx_id, activation->admission_tx_id) ||
        memcmp(expected->candidate_manifest_digest,
               activation->candidate_manifest_digest,
               sizeof(expected->candidate_manifest_digest)) != 0) {
        set_error(error, error_len, "reservation commit input is invalid");
        return -1;
    }
    expected_commit = *expected;
    if (expected_commit.state == WVM_RESERVATION_PREPARED &&
        wvm_resource_reservation_commit(&expected_commit, activation, error,
                                        error_len) != 0) {
        return -1;
    }
    if (expected_commit.state != WVM_RESERVATION_COMMITTED ||
        memcmp(expected_commit.activation_fence, activation->activation_fence,
               sizeof(expected_commit.activation_fence)) != 0) {
        set_error(error, error_len, "reservation commit stage is invalid");
        return -1;
    }
    pthread_mutex_lock(&registry->lock);
    if (registry->journal_failed) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation journal requires recovery");
        return -1;
    }
    reservation = find_mutable(registry, expected->reservation_id);
    if (!reservation) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation is not prepared locally");
        return -1;
    }
    if (reservation->state == WVM_RESERVATION_COMMITTED) {
        int matches = reservation_equal(reservation, &expected_commit);

        pthread_mutex_unlock(&registry->lock);
        if (!matches) {
            set_error(error, error_len,
                      "reservation already committed by another fence");
            return -1;
        }
        if (result) {
            *result = WVM_RESERVATION_RUNTIME_REPLAY;
        }
        return 0;
    }
    if (reservation->state != WVM_RESERVATION_PREPARED ||
        memcmp(reservation->admission_tx_id, activation->admission_tx_id,
               sizeof(reservation->admission_tx_id)) != 0 ||
        memcmp(reservation->candidate_manifest_digest,
               activation->candidate_manifest_digest,
               sizeof(reservation->candidate_manifest_digest)) != 0) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation commit does not match prepare");
        return -1;
    }
    if (reservation_account_units(reservation, &cpu, &memory) != 0 ||
        registry->prepared_vcpu_slots < cpu ||
        registry->prepared_memory_bytes < memory ||
        registry->committed_vcpu_slots > UINT32_MAX - cpu ||
        registry->committed_memory_bytes > UINT64_MAX - memory) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation accounting is inconsistent");
        return -1;
    }
    updated = *reservation;
    if (wvm_resource_reservation_commit(&updated, activation, error,
                                        error_len) != 0 ||
        !reservation_equal(&updated, &expected_commit)) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation commit does not match prepare");
        return -1;
    }
    if (persist_reservation(registry, &updated, error, error_len) != 0) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }
    *reservation = updated;
    registry->prepared_vcpu_slots -= cpu;
    registry->prepared_memory_bytes -= memory;
    registry->committed_vcpu_slots += cpu;
    registry->committed_memory_bytes += memory;
    pthread_mutex_unlock(&registry->lock);
    if (result) {
        *result = WVM_RESERVATION_RUNTIME_NEW;
    }
    return 0;
}

int wvm_local_reservation_abort(
    struct wvm_local_reservation_registry *registry,
    const struct wvm_resource_reservation *expected,
    enum wvm_reservation_runtime_result *result, char *error,
    size_t error_len)
{
    struct wvm_resource_reservation *reservation;
    struct wvm_resource_reservation accounted_reservation;
    struct wvm_resource_reservation updated;
    struct wvm_resource_reservation expected_release;

    if (!registry || !registry->initialized || !expected ||
        wvm_resource_reservation_validate(expected, error, error_len) != 0 ||
        expected->physical_node_id != registry->physical_node_id ||
        expected->node_instance_id != registry->node_instance_id ||
        expected->inventory_revision != registry->inventory_revision ||
        expected->has_activation_fence ||
        (expected->state != WVM_RESERVATION_PREPARED &&
         expected->state != WVM_RESERVATION_RELEASED)) {
        set_error(error, error_len, "reservation abort input is invalid");
        return -1;
    }
    expected_release = *expected;
    if (expected_release.state == WVM_RESERVATION_PREPARED &&
        (wvm_resource_reservation_begin_release(&expected_release, error,
                                                error_len) != 0 ||
         wvm_resource_reservation_release(&expected_release, error, error_len) != 0)) {
        return -1;
    }
    pthread_mutex_lock(&registry->lock);
    if (registry->journal_failed) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation journal requires recovery");
        return -1;
    }
    reservation = find_mutable(registry, expected->reservation_id);
    if (!reservation) {
        /* An abort may overtake a prepare; retain its identity durably. */
        if (registry->reservation_count == registry->reservation_capacity) {
            pthread_mutex_unlock(&registry->lock);
            set_error(error, error_len, "no capacity for reservation abort marker");
            return -1;
        }
        if (copy_reservation(&expected_release, &updated, error, error_len) != 0) {
            pthread_mutex_unlock(&registry->lock);
            return -1;
        }
        if (persist_reservation(registry, &updated, error, error_len) != 0) {
            free(updated.exclusive_leases.entries);
            pthread_mutex_unlock(&registry->lock);
            return -1;
        }
        registry->reservations[registry->reservation_count++] = updated;
        pthread_mutex_unlock(&registry->lock);
        if (result) {
            *result = WVM_RESERVATION_RUNTIME_NEW;
        }
        return 0;
    }
    if (reservation->state == WVM_RESERVATION_RELEASED) {
        int matches = reservation_equal(reservation, &expected_release);

        pthread_mutex_unlock(&registry->lock);
        if (!matches) {
            set_error(error, error_len, "reservation abort conflicts with retained marker");
            return -1;
        }
        if (result) {
            *result = WVM_RESERVATION_RUNTIME_REPLAY;
        }
        return 0;
    }
    if (reservation->state != WVM_RESERVATION_PREPARED ||
        !reservation_equal(reservation, expected)) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation abort does not match local prepare");
        return -1;
    }
    accounted_reservation = *reservation;
    if (account_remove_possible(registry, &accounted_reservation) != 0) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation accounting is inconsistent");
        return -1;
    }
    updated = *reservation;
    if (wvm_resource_reservation_begin_release(&updated, error,
                                               error_len) != 0 ||
        wvm_resource_reservation_release(&updated, error, error_len) != 0 ||
        persist_reservation(registry, &updated, error, error_len) != 0) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }
    *reservation = updated;
    if (account_remove(registry, &accounted_reservation) != 0) {
        pthread_mutex_unlock(&registry->lock);
        set_error(error, error_len, "reservation accounting is inconsistent");
        return -1;
    }
    pthread_mutex_unlock(&registry->lock);
    if (result) {
        *result = WVM_RESERVATION_RUNTIME_NEW;
    }
    return 0;
}

size_t wvm_local_reservation_reap_expired(
    struct wvm_local_reservation_registry *registry,
    uint64_t now_unix_time_ms)
{
    size_t i;
    size_t reaped = 0;

    if (!registry || !registry->initialized || now_unix_time_ms == 0) {
        return 0;
    }
    pthread_mutex_lock(&registry->lock);
    if (registry->journal_failed) {
        pthread_mutex_unlock(&registry->lock);
        return 0;
    }
    for (i = 0; i < registry->reservation_count; i++) {
        struct wvm_resource_reservation *reservation =
            &registry->reservations[i];

        if (reservation->state == WVM_RESERVATION_PREPARED &&
            reservation->has_prepared_expiry &&
            reservation->prepared_expiry_unix_time_ms <= now_unix_time_ms &&
            account_remove_possible(registry, reservation) == 0) {
            struct wvm_resource_reservation accounted_reservation = *reservation;
            struct wvm_resource_reservation updated = *reservation;

            if (wvm_resource_reservation_begin_release(&updated, NULL, 0) ==
                    0 &&
                wvm_resource_reservation_release(&updated, NULL, 0) == 0 &&
                persist_reservation(registry, &updated, NULL, 0) == 0 &&
                account_remove(registry, &accounted_reservation) == 0) {
                *reservation = updated;
                reaped++;
            }
            if (registry->journal_failed) {
                break;
            }
        }
    }
    pthread_mutex_unlock(&registry->lock);
    return reaped;
}

static void journal_write_u64(uint8_t *bytes, uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        bytes[7 - i] = (uint8_t)(value >> (i * 8));
    }
}

static uint64_t journal_read_u64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static int journal_write_all(int fd, const uint8_t *bytes, size_t count)
{
    size_t offset = 0;

    while (offset < count) {
        ssize_t written = write(fd, bytes + offset, count - offset);

        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int journal_read_all(int fd, uint8_t *bytes, size_t count, off_t start)
{
    size_t offset = 0;

    while (offset < count) {
        ssize_t received = pread(fd, bytes + offset, count - offset,
                                 start + (off_t)offset);

        if (received > 0) {
            offset += (size_t)received;
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static void journal_digest(const uint8_t *header, const uint8_t *payload,
                            size_t count, uint8_t *digest)
{
    struct wvm_sha256_ctx hash;

    wvm_sha256_init(&hash);
    wvm_sha256_update(&hash, header, 32);
    wvm_sha256_update(&hash, payload, count);
    wvm_sha256_final(&hash, digest);
}

static int persist_reservation(struct wvm_local_reservation_registry *registry,
                               const struct wvm_resource_reservation *record,
                               char *error, size_t error_len)
{
    uint8_t header[RESERVATION_JOURNAL_HEADER_BYTES] = {0};
    uint8_t *payload;
    size_t capacity;
    size_t count;
    int result = -1;

    if (registry->journal_failed) {
        set_error(error, error_len, "reservation journal requires recovery");
        return -1;
    }
    if (registry->journal_fd < 0) {
        return 0;
    }
    if (record->exclusive_leases.count >
            (WVM_ENVELOPE_MAX_LOCAL_PAYLOAD - RESERVATION_RECORD_BASE_BYTES) /
                RESERVATION_LEASE_BUFFER_BYTES ||
        registry->next_journal_sequence == UINT64_MAX) {
        set_error(error, error_len, "reservation journal record limit reached");
        return -1;
    }
    capacity = RESERVATION_RECORD_BASE_BYTES + record->exclusive_leases.count *
                   RESERVATION_LEASE_BUFFER_BYTES;
    payload = malloc(capacity);
    if (!payload) {
        set_error(error, error_len, "cannot allocate reservation journal record");
        return -1;
    }
    if (wvm_resource_reservation_encode(record, payload, capacity, &count,
                                        error, error_len) != 0) {
        goto out;
    }
    if (registry->journal_bytes > registry->journal_byte_limit ||
        count + sizeof(header) >
            registry->journal_byte_limit - registry->journal_bytes) {
        set_error(error, error_len, "reservation journal byte budget exhausted");
        goto out;
    }
    memcpy(header, reservation_journal_magic, sizeof(reservation_journal_magic));
    journal_write_u64(header + 8, count);
    journal_write_u64(header + 16, record->exclusive_leases.count);
    journal_write_u64(header + 24, registry->next_journal_sequence);
    journal_digest(header, payload, count, header + 32);
    /* Protect the length independently, before recovery trusts frame bounds. */
    wvm_sha256_digest(header, 64, header + 64);
    if (lseek(registry->journal_fd, 0, SEEK_END) < 0 ||
        journal_write_all(registry->journal_fd, header, sizeof(header)) != 0 ||
        journal_write_all(registry->journal_fd, payload, count) != 0 ||
        fsync(registry->journal_fd) != 0) {
        registry->journal_failed = 1;
        set_error(error, error_len, "cannot persist reservation journal: %s",
                  strerror(errno));
        goto out;
    }
    registry->journal_bytes += sizeof(header) + count;
    registry->next_journal_sequence++;
    result = 0;
out:
    free(payload);
    return result;
}

/* The decoded record owns its leases until installed. Validate a complete
 * transition before publishing it or changing accounting during replay. */
static int replay_reservation(struct wvm_local_reservation_registry *registry,
                              struct wvm_resource_reservation *record,
                              char *error, size_t error_len)
{
    struct wvm_resource_reservation *existing;
    struct wvm_resource_reservation expected;

    if (record->physical_node_id != registry->physical_node_id ||
        record->node_instance_id != registry->node_instance_id ||
        record->inventory_revision != registry->inventory_revision) {
        goto invalid;
    }
    existing = find_mutable(registry, record->reservation_id);
    if (!existing) {
        if ((record->state != WVM_RESERVATION_PREPARED &&
             (record->state != WVM_RESERVATION_RELEASED ||
              record->has_activation_fence || record->has_prepared_expiry)) ||
            registry->reservation_count == registry->reservation_capacity ||
            (record->state == WVM_RESERVATION_PREPARED &&
             (leases_conflict(registry, record) || !capacity_allows(registry, record))) ||
            account_add(registry, record) != 0) {
            goto invalid;
        }
        registry->reservations[registry->reservation_count++] = *record;
        record->exclusive_leases.entries = NULL;
        return 0;
    }
    expected = *existing;
    if (record->state == WVM_RESERVATION_COMMITTED &&
        existing->state == WVM_RESERVATION_PREPARED) {
        expected.state = WVM_RESERVATION_COMMITTED;
        expected.has_prepared_expiry = 0;
        expected.prepared_expiry_unix_time_ms = 0;
        expected.has_activation_fence = 1;
        memcpy(expected.activation_fence, record->activation_fence,
               sizeof(expected.activation_fence));
    } else if (record->state == WVM_RESERVATION_RELEASED &&
               existing->state == WVM_RESERVATION_PREPARED) {
        if (wvm_resource_reservation_begin_release(&expected, error, error_len) != 0 ||
            wvm_resource_reservation_release(&expected, error, error_len) != 0) {
            return -1;
        }
    } else {
        goto invalid;
    }
    if (!reservation_equal(&expected, record) ||
        account_remove(registry, existing) != 0 ||
        account_add(registry, record) != 0) {
        goto invalid;
    }
    free(existing->exclusive_leases.entries);
    *existing = *record;
    record->exclusive_leases.entries = NULL;
    return 0;
invalid:
    set_error(error, error_len, "reservation journal identity or transition is invalid");
    return -1;
}

static int sync_journal_directory(const char *path)
{
    char *parent = strdup(path);
    char *slash;
    int fd;
    int result;

    if (!parent) {
        return -1;
    }
    slash = strrchr(parent, '/');
    if (slash) {
        slash[slash == parent ? 1 : 0] = '\0';
    } else {
        free(parent);
        parent = strdup(".");
        if (!parent) {
            return -1;
        }
    }
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(parent);
    if (fd < 0) {
        return -1;
    }
    result = fsync(fd);
    close(fd);
    return result;
}

int wvm_local_reservation_registry_open(
    struct wvm_local_reservation_registry *registry, const char *path,
    uint64_t byte_limit, char *error, size_t error_len)
{
    struct stat status;
    uint8_t header[RESERVATION_JOURNAL_HEADER_BYTES];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    uint64_t offset = 0;
    uint8_t *payload = NULL;
    struct wvm_resource_reservation record = {0};
    int fd = -1;
    int result = -1;
    size_t i;

    if (!registry || !registry->initialized || !path || !path[0] || !byte_limit) {
        set_error(error, error_len, "invalid reservation journal configuration");
        return -1;
    }
    pthread_mutex_lock(&registry->lock);
    if (registry->reservation_count || registry->journal_fd >= 0 ||
        registry->journal_failed) {
        set_error(error, error_len, "reservation journal requires an empty registry");
        goto out;
    }
    registry->journal_failed = 1;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0 ||
        fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0 || (uint64_t)status.st_size > byte_limit) {
        set_error(error, error_len, "cannot open/lock bounded reservation journal");
        goto fail;
    }
    while (offset < (uint64_t)status.st_size) {
        uint64_t count;
        uint64_t leases;

        if ((uint64_t)status.st_size - offset < sizeof(header)) {
            break;
        }
        if (journal_read_all(fd, header, sizeof(header), (off_t)offset) != 0) {
            goto fail;
        }
        wvm_sha256_digest(header, 64, digest);
        if (memcmp(digest, header + 64, sizeof(digest)) != 0) {
            set_error(error, error_len, "reservation journal header checksum mismatch");
            goto fail;
        }
        count = journal_read_u64(header + 8);
        leases = journal_read_u64(header + 16);
        if (memcmp(header, reservation_journal_magic,
                   sizeof(reservation_journal_magic)) != 0 ||
            count == 0 || count > WVM_ENVELOPE_MAX_LOCAL_PAYLOAD ||
            leases > (WVM_ENVELOPE_MAX_LOCAL_PAYLOAD - RESERVATION_RECORD_BASE_BYTES) /
                         RESERVATION_LEASE_BUFFER_BYTES ||
            journal_read_u64(header + 24) != registry->next_journal_sequence ||
            registry->next_journal_sequence == UINT64_MAX) {
            set_error(error, error_len, "reservation journal header is invalid");
            goto fail;
        }
        if (count > (uint64_t)status.st_size - offset - sizeof(header)) {
            break;
        }
        payload = malloc((size_t)count);
        if (!payload || journal_read_all(fd, payload, (size_t)count,
                                         (off_t)(offset + sizeof(header))) != 0) {
            goto fail;
        }
        journal_digest(header, payload, (size_t)count, digest);
        if (memcmp(digest, header + 32, sizeof(digest)) != 0) {
            set_error(error, error_len, "reservation journal checksum mismatch");
            goto fail;
        }
        if (leases) {
            record.exclusive_leases.entries = calloc((size_t)leases,
                sizeof(*record.exclusive_leases.entries));
            if (!record.exclusive_leases.entries) {
                goto fail;
            }
        }
        record.exclusive_leases.capacity = (size_t)leases;
        if (wvm_resource_reservation_decode(payload, (size_t)count, &record,
                                            error, error_len) != 0 ||
            record.exclusive_leases.count != leases ||
            replay_reservation(registry, &record, error, error_len) != 0) {
            goto fail;
        }
        free(payload);
        payload = NULL;
        memset(&record, 0, sizeof(record));
        offset += sizeof(header) + count;
        registry->next_journal_sequence++;
    }
    /* Only an incomplete final write is discarded, never a corrupt record. */
    if (ftruncate(fd, (off_t)offset) != 0 || fsync(fd) != 0 ||
        sync_journal_directory(path) != 0) {
        set_error(error, error_len, "cannot finalize reservation journal recovery");
        goto fail;
    }
    registry->journal_fd = fd;
    registry->journal_bytes = offset;
    registry->journal_byte_limit = byte_limit;
    registry->journal_failed = 0;
    result = 0;
    goto out;
fail:
    if (fd >= 0) {
        close(fd);
    }
    free(payload);
    free(record.exclusive_leases.entries);
    for (i = 0; i < registry->reservation_count; i++) {
        free(registry->reservations[i].exclusive_leases.entries);
    }
    memset(registry->reservations, 0,
           registry->reservation_capacity * sizeof(*registry->reservations));
    registry->reservation_count = 0;
    registry->prepared_vcpu_slots = 0;
    registry->prepared_memory_bytes = 0;
    registry->committed_vcpu_slots = 0;
    registry->committed_memory_bytes = 0;
    registry->next_journal_sequence = 1;
    if (error && error_len && !error[0]) {
        set_error(error, error_len, "cannot recover reservation journal");
    }
out:
    pthread_mutex_unlock(&registry->lock);
    return result;
}

int wvm_local_reservation_registry_is_durable(
    struct wvm_local_reservation_registry *registry)
{
    int durable;

    if (!registry || !registry->initialized) {
        return 0;
    }
    pthread_mutex_lock(&registry->lock);
    durable = registry->journal_fd >= 0 && !registry->journal_failed;
    pthread_mutex_unlock(&registry->lock);
    return durable;
}

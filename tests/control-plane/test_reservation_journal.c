#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_reservation_runtime.h"

#define JOURNAL_LIMIT (1024U * 1024U)
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "reservation-journal:%d: %s (%s)\n", \
                __LINE__, #condition, f->error); \
        return -1; \
    } \
} while (0)

static int fail_sync_fd = -1;
static int fail_write_fd = -1;

int __real_fsync(int fd);
ssize_t __real_write(int fd, const void *bytes, size_t count);

int __wrap_fsync(int fd)
{
    if (fd == fail_sync_fd) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

ssize_t __wrap_write(int fd, const void *bytes, size_t count)
{
    if (fd == fail_write_fd) {
        errno = ENOSPC;
        return -1;
    }
    return __real_write(fd, bytes, count);
}

struct fixture {
    struct wvm_local_reservation_registry registry;
    struct wvm_local_reservation_registry contender;
    struct wvm_admission_node node;
    struct wvm_resource_reservation stored[4];
    struct wvm_resource_reservation contender_stored[4];
    struct wvm_resource_reservation reservation;
    struct wvm_exclusive_lease lease;
    struct wvm_activation_record activation;
    struct wvm_route_snapshot_key route_key;
    char error[256];
};

static void init_fixture(struct fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->node.physical_node_id = 17;
    f->node.node_instance_id = 9;
    f->node.inventory_revision = 4;
    f->node.allocatable_vcpu_slots = 8;
    f->node.allocatable_memory_bytes = 65536;
    f->reservation.reservation_id[0] = 1;
    f->reservation.plan_digest[0] = 2;
    f->reservation.candidate_manifest_digest[0] = 3;
    f->reservation.admission_tx_id[0] = 4;
    f->reservation.eligibility_fence_digest[0] = 5;
    f->reservation.vm_id = 100;
    f->reservation.vm_incarnation = 1;
    f->reservation.physical_node_id = f->node.physical_node_id;
    f->reservation.node_instance_id = f->node.node_instance_id;
    f->reservation.inventory_revision = f->node.inventory_revision;
    f->reservation.guest_vcpu_slots = 2;
    f->reservation.guest_memory_bytes = 4096;
    f->reservation.overhead_memory_bytes = 4096;
    f->reservation.state = WVM_RESERVATION_PREPARED;
    f->reservation.has_prepared_expiry = 1;
    f->reservation.prepared_expiry_unix_time_ms = 100;
    f->lease.lease_kind = WVM_EXCLUSIVE_LEASE_KIND_KERNEL_CONTEXT;
    f->lease.lease_generation = 1;
    memset(f->lease.lease_name, 'x', sizeof(f->lease.lease_name) - 1);
    f->reservation.exclusive_leases.entries = &f->lease;
    f->reservation.exclusive_leases.count = 1;
    f->reservation.exclusive_leases.capacity = 1;
    memcpy(f->activation.admission_tx_id, f->reservation.admission_tx_id,
           sizeof(f->activation.admission_tx_id));
    memcpy(f->activation.candidate_manifest_digest,
           f->reservation.candidate_manifest_digest,
           sizeof(f->activation.candidate_manifest_digest));
    f->activation.has_activation_fence = 1;
    f->activation.activation_fence[0] = 6;
    f->activation.coordinator_instance_id = 1;
    f->activation.required_participant_set_digest[0] = 7;
    f->activation.required_route_snapshot_keys = &f->route_key;
    f->activation.required_route_snapshot_count = 1;
    f->activation.required_route_snapshot_capacity = 1;
    f->activation.decision = WVM_ACTIVATION_ACTIVATE;
    f->activation.durable_decision_sequence = 1;
    f->activation.decided_at = 50;
    f->route_key.scope_key.vm_id = f->reservation.vm_id;
    f->route_key.scope_key.vm_incarnation = f->reservation.vm_incarnation;
    f->route_key.scope_key.route_scope_id = 1;
    f->route_key.topology_revision = 1;
    f->route_key.route_generation = 1;
    f->route_key.snapshot_digest[0] = 8;
}

static int reopen(struct fixture *f, const char *path, size_t capacity,
                  uint64_t limit)
{
    wvm_local_reservation_registry_destroy(&f->registry);
    f->error[0] = '\0';
    if (wvm_local_reservation_registry_init(&f->registry, &f->node,
            f->stored, capacity, f->error, sizeof(f->error)) != 0) {
        return -1;
    }
    return wvm_local_reservation_registry_open(&f->registry, path, limit,
                                               f->error, sizeof(f->error));
}

static int prepare(struct fixture *f)
{
    return wvm_local_reservation_prepare(&f->registry, &f->reservation,
                                         NULL, f->error, sizeof(f->error));
}

static int commit(struct fixture *f)
{
    return wvm_local_reservation_commit(&f->registry,
            &f->reservation, &f->activation,
            NULL, f->error, sizeof(f->error));
}

static int abort_reservation(struct fixture *f)
{
    return wvm_local_reservation_abort(&f->registry,
            &f->reservation, NULL, f->error, sizeof(f->error));
}

static int test_recovery(struct fixture *f, const char *path)
{
    uint64_t bytes;

    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(wvm_local_reservation_registry_is_durable(&f->registry));
    CHECK(f->registry.journal_bytes == 0);
    CHECK(prepare(f) == 0);
    bytes = f->registry.journal_bytes;
    CHECK(prepare(f) == 0 && f->registry.journal_bytes == bytes);
    f->lease.lease_name[0] = 'z';
    CHECK(f->stored[0].exclusive_leases.entries != &f->lease);
    CHECK(f->stored[0].exclusive_leases.entries[0].lease_name[0] == 'x');
    CHECK(prepare(f) != 0);
    f->lease.lease_name[0] = 'x';
    CHECK(wvm_local_reservation_registry_init(&f->contender, &f->node,
            f->contender_stored, 4, f->error, sizeof(f->error)) == 0);
    CHECK(wvm_local_reservation_registry_open(&f->contender, path,
            JOURNAL_LIMIT, f->error, sizeof(f->error)) != 0);
    CHECK(!wvm_local_reservation_registry_is_durable(&f->contender));
    wvm_local_reservation_registry_destroy(&f->contender);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(f->registry.prepared_vcpu_slots == 2);
    CHECK(f->registry.prepared_memory_bytes == 8192);
    CHECK(prepare(f) == 0 && f->registry.journal_bytes == bytes);
    f->reservation.reservation_id[0] = 2;
    CHECK(prepare(f) != 0);
    f->reservation.reservation_id[0] = 1;
    f->reservation.vm_incarnation++;
    CHECK(commit(f) != 0 && abort_reservation(f) != 0);
    CHECK(f->registry.journal_bytes == bytes);
    CHECK(f->stored[0].state == WVM_RESERVATION_PREPARED);
    f->reservation.vm_incarnation--;
    CHECK(commit(f) == 0);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(f->registry.prepared_vcpu_slots == 0);
    CHECK(f->registry.committed_vcpu_slots == 2);
    CHECK(f->registry.committed_memory_bytes == 8192);
    bytes = f->registry.journal_bytes;
    CHECK(commit(f) == 0 && f->registry.journal_bytes == bytes);
    f->activation.admission_tx_id[0]++;
    CHECK(commit(f) != 0);
    f->activation.admission_tx_id[0]--;
    f->activation.candidate_manifest_digest[0]++;
    CHECK(commit(f) != 0);
    f->activation.candidate_manifest_digest[0]--;
    f->activation.activation_fence[0]++;
    CHECK(commit(f) != 0);
    f->activation.activation_fence[0]--;
    CHECK(abort_reservation(f) != 0);
    CHECK(f->registry.journal_bytes == bytes);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(f->registry.committed_vcpu_slots == 2);
    f->reservation.reservation_id[0] = 2;
    f->lease.lease_name[0] = 'y';
    CHECK(prepare(f) == 0);
    CHECK(wvm_local_reservation_reap_expired(&f->registry, 99) == 0);
    CHECK(wvm_local_reservation_reap_expired(&f->registry, 100) == 1);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(f->registry.reservation_count == 2);
    CHECK(f->registry.prepared_memory_bytes == 0);
    CHECK(prepare(f) != 0);
    CHECK(abort_reservation(f) == 0);
    CHECK(f->stored[1].state == WVM_RESERVATION_RELEASED);
    f->reservation.reservation_id[0] = 3;
    CHECK(abort_reservation(f) == 0);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(prepare(f) != 0 && abort_reservation(f) == 0);
    CHECK(f->registry.reservation_count == 3);
    CHECK(f->registry.prepared_vcpu_slots == 0);
    f->node.node_instance_id++;
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) != 0);
    CHECK(f->registry.reservation_count == 0);
    CHECK(!wvm_local_reservation_registry_is_durable(&f->registry));
    f->node.node_instance_id--;
    f->node.inventory_revision++;
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) != 0);
    f->node.inventory_revision--;
    f->node.physical_node_id++;
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) != 0);
    f->node.physical_node_id--;
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    return 0;
}

static int test_limits(struct fixture *f, const char *path)
{
    CHECK(reopen(f, path, 1, 1) == 0);
    CHECK(prepare(f) != 0);
    CHECK(f->registry.journal_bytes == 0 && f->registry.reservation_count == 0);
    CHECK(f->registry.prepared_vcpu_slots == 0);
    CHECK(reopen(f, path, 1, JOURNAL_LIMIT) == 0);
    CHECK(prepare(f) == 0 && abort_reservation(f) == 0);
    CHECK(reopen(f, path, 1, JOURNAL_LIMIT) == 0);
    f->reservation.reservation_id[0] = 2;
    CHECK(prepare(f) != 0);
    CHECK(f->registry.prepared_vcpu_slots == 0);
    CHECK(f->registry.reservation_count == 1);
    f->reservation.reservation_id[0] = 1;
    CHECK(prepare(f) != 0);
    return 0;
}

static int test_torn_tail(struct fixture *f, const char *path, off_t bytes_left)
{
    off_t valid_bytes;
    off_t committed_bytes;
    struct stat status;
    int fd;

    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(prepare(f) == 0);
    valid_bytes = (off_t)f->registry.journal_bytes;
    CHECK(commit(f) == 0);
    committed_bytes = (off_t)f->registry.journal_bytes;
    wvm_local_reservation_registry_destroy(&f->registry);
    fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    CHECK(ftruncate(fd, bytes_left < 0 ? committed_bytes - 1 :
                                       valid_bytes + bytes_left) == 0);
    CHECK(close(fd) == 0);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(f->registry.journal_bytes == (uint64_t)valid_bytes);
    CHECK(stat(path, &status) == 0 && status.st_size == valid_bytes);
    CHECK(f->registry.prepared_vcpu_slots == 2);
    CHECK(f->registry.committed_vcpu_slots == 0);
    CHECK(commit(f) == 0);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(f->registry.committed_vcpu_slots == 2);
    return 0;
}

static int test_corruption(struct fixture *f, const char *path, off_t position)
{
    uint8_t byte;
    int fd;
    struct stat before, after;

    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(prepare(f) == 0 && commit(f) == 0);
    wvm_local_reservation_registry_destroy(&f->registry);
    fd = open(path, O_RDWR);
    CHECK(fd >= 0 && fstat(fd, &before) == 0);
    if (position < 0) {
        position = before.st_size - 1;
    }
    CHECK(pread(fd, &byte, 1, position) == 1);
    byte ^= 0x40;
    CHECK(pwrite(fd, &byte, 1, position) == 1 && close(fd) == 0);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) != 0);
    CHECK(stat(path, &after) == 0 && after.st_size == before.st_size);
    CHECK(!wvm_local_reservation_registry_is_durable(&f->registry));
    CHECK(f->registry.reservation_count == 0);
    CHECK(f->registry.prepared_vcpu_slots == 0);
    CHECK(prepare(f) != 0);
    return 0;
}

static int test_io_failure(struct fixture *f, const char *path, int sync_failure)
{
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    CHECK(prepare(f) == 0);
    if (sync_failure) {
        fail_sync_fd = f->registry.journal_fd;
    } else {
        fail_write_fd = f->registry.journal_fd;
    }
    CHECK(commit(f) != 0);
    fail_sync_fd = fail_write_fd = -1;
    CHECK(f->registry.prepared_vcpu_slots == 2);
    CHECK(f->registry.committed_vcpu_slots == 0);
    CHECK(f->stored[0].state == WVM_RESERVATION_PREPARED);
    CHECK(!wvm_local_reservation_registry_is_durable(&f->registry));
    CHECK(prepare(f) != 0 && commit(f) != 0 && abort_reservation(f) != 0);
    CHECK(wvm_local_reservation_reap_expired(&f->registry, 100) == 0);
    CHECK(reopen(f, path, 4, JOURNAL_LIMIT) == 0);
    /* A failed fsync is uncertain, not evidence that the write vanished. */
    CHECK(f->stored[0].state == (sync_failure ? WVM_RESERVATION_COMMITTED :
                                               WVM_RESERVATION_PREPARED));
    CHECK(commit(f) == 0);
    return 0;
}

int main(int argc, char **argv)
{
    struct fixture fixture;
    int result = 0;
    int i;

    if (argc != 2) {
        return 2;
    }
    for (i = 0; i < 9 && result == 0; i++) {
        init_fixture(&fixture);
        switch (i) {
        case 0: result = test_recovery(&fixture, argv[1]); break;
        case 1: result = test_limits(&fixture, argv[1]); break;
        case 2: result = test_torn_tail(&fixture, argv[1], 1); break;
        case 3: result = test_torn_tail(&fixture, argv[1], -1); break;
        case 4: result = test_corruption(&fixture, argv[1], -1); break;
        case 5: result = test_corruption(&fixture, argv[1], 15); break;
        case 6: result = test_corruption(&fixture, argv[1], 24); break;
        case 7: result = test_io_failure(&fixture, argv[1], 0); break;
        case 8: result = test_io_failure(&fixture, argv[1], 1); break;
        }
        fail_sync_fd = fail_write_fd = -1;
        wvm_local_reservation_registry_destroy(&fixture.contender);
        wvm_local_reservation_registry_destroy(&fixture.registry);
        wvm_local_reservation_registry_destroy(&fixture.registry);
        if (unlink(argv[1]) != 0 && errno != ENOENT) {
            result = -1;
        }
    }
    if (result != 0) {
        return 1;
    }
    puts("reservation journal recovery/fault tests: PASS");
    return 0;
}

#define _GNU_SOURCE

#include "wavevm_runtime_names.h"

#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

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

static int format_name(char *destination, size_t destination_bytes,
                       const char *format, const char *namespace_name)
{
    int written;

    written = snprintf(destination, destination_bytes, format, namespace_name);
    return written < 0 || (size_t)written >= destination_bytes ? -1 : 0;
}

static int write_ready_bytes(int fd, const void *bytes, size_t byte_count)
{
    const uint8_t *cursor = bytes;
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t written = write(fd, cursor + offset, byte_count - offset);

        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int read_ready_bytes(int fd, void *bytes, size_t byte_count)
{
    uint8_t *cursor = bytes;
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t received = read(fd, cursor + offset, byte_count - offset);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static int read_boot_id(char boot_id[37])
{
    char line[64];
    FILE *file = fopen("/proc/sys/kernel/random/boot_id", "r");
    int result = -1;

    if (file && fgets(line, sizeof(line), file) &&
        strlen(line) >= 36 && (line[36] == '\n' || line[36] == '\0')) {
        memcpy(boot_id, line, 36);
        boot_id[36] = '\0';
        result = 0;
    }
    if (file) {
        fclose(file);
    }
    return result;
}

static int read_task_start_time(uint64_t pid, uint64_t tid,
                                uint64_t *start_time)
{
    char path[96], line[4096];
    char *cursor, *end, *next;
    unsigned field;
    FILE *file;

    if (!pid || !tid || pid > INT_MAX || tid > INT_MAX ||
        snprintf(path, sizeof(path), "/proc/%llu/task/%llu/stat",
                 (unsigned long long)pid, (unsigned long long)tid) >=
            (int)sizeof(path)) {
        return -1;
    }
    file = fopen(path, "r");
    if (!file) {
        return -1;
    }
    cursor = fgets(line, sizeof(line), file);
    fclose(file);
    end = cursor ? strrchr(cursor, ')') : NULL;
    if (!end || end[1] != ' ' || end[3] != ' ' ||
        end[2] == 'Z' || end[2] == 'X') {
        return -1;
    }
    /* Field 2 (comm) is parenthesized and may contain spaces. Field 22 is
     * the task start time; PID/TID alone can be reused after a crash. */
    cursor = end + 4;
    for (field = 4; field < 22; field++) {
        cursor = strchr(cursor, ' ');
        if (!cursor) {
            return -1;
        }
        while (*cursor == ' ') {
            cursor++;
        }
    }
    errno = 0;
    *start_time = strtoull(cursor, &next, 10);
    return errno == 0 && next != cursor &&
                   (*next == ' ' || *next == '\n' || *next == '\0') &&
                   *start_time != 0
               ? 0
               : -1;
}

static int ready_owner_alive(const struct wvm_runtime_ready_record *record)
{
    char boot_id[37];
    uint64_t start_time;

    return record->owner_boot_id[36] == '\0' &&
           read_boot_id(boot_id) == 0 &&
           memcmp(record->owner_boot_id, boot_id, sizeof(boot_id)) == 0 &&
           read_task_start_time(record->owner_pid, record->owner_tid,
                                &start_time) == 0 &&
           start_time == record->owner_start_time_ticks;
}

static int read_ready_record(const char *path,
                             struct wvm_runtime_ready_record *record)
{
    struct stat info;
    uint8_t extra;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int result;

    if (fd < 0) {
        return -1;
    }
    result = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
             info.st_size == (off_t)sizeof(*record) &&
             read_ready_bytes(fd, record, sizeof(*record)) == 0 &&
             read(fd, &extra, sizeof(extra)) == 0
                 ? 0
                 : -1;
    close(fd);
    if (result != 0) {
        errno = EINVAL;
    }
    return result;
}

static int lock_ready_namespace(const char *ready_path)
{
    char path[WVM_RUNTIME_PATH_MAX + 6];
    struct stat info;
    int fd;

    if (snprintf(path, sizeof(path), "%s.lock", ready_path) >=
        (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int ready_identity_matches(const struct wvm_runtime_ready_record *actual,
                                  const struct wvm_runtime_ready_record *expected)
{
    struct wvm_runtime_ready_record identity = *actual;

    identity.owner_pid = 0;
    identity.owner_tid = 0;
    identity.owner_start_time_ticks = 0;
    memset(identity.owner_boot_id, 0, sizeof(identity.owner_boot_id));
    return memcmp(&identity, expected, sizeof(identity)) == 0;
}

static int runtime_ready_record_fill(
    const struct wvm_node_runtime_manifest *manifest,
    uint64_t node_instance_id, struct wvm_runtime_ready_record *record,
    char *error, size_t error_len)
{
    if (!manifest || !record || node_instance_id == 0 ||
        node_instance_id != manifest->expected_node_instance_id ||
        !manifest->has_activation_fence ||
        wvm_node_runtime_manifest_validate(manifest, error, error_len) != 0) {
        set_error(error, error_len,
                  "runtime readiness identity is not an admitted manifest");
        return -1;
    }
    memset(record, 0, sizeof(*record));
    record->magic = WVM_RUNTIME_READY_MAGIC;
    record->version = WVM_RUNTIME_READY_VERSION;
    record->vm_id = manifest->vm_id;
    record->physical_node_id = manifest->physical_node_id;
    record->vm_incarnation = manifest->vm_incarnation;
    record->manifest_generation = manifest->manifest_generation;
    record->node_instance_id = node_instance_id;
    memcpy(record->candidate_manifest_digest,
           manifest->candidate_manifest_digest,
           sizeof(record->candidate_manifest_digest));
    memcpy(record->activation_fence, manifest->activation_fence,
           sizeof(record->activation_fence));
    return 0;
}

int wvm_runtime_name_set_validate(const struct wvm_runtime_name_set *names,
                                  char *error, size_t error_len)
{
    const char *values[] = {
        names ? names->runtime_socket : NULL,
        names ? names->executor_socket : NULL,
        names ? names->worker_socket : NULL,
        names ? names->monitor_socket : NULL,
        names ? names->ready_file : NULL,
        names ? names->shm_name : NULL,
        names ? names->log_directory : NULL,
        names ? names->temporary_directory : NULL,
    };
    size_t i;
    size_t j;

    if (!names) {
        set_error(error, error_len, "runtime name set is missing");
        return -1;
    }
    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        if (!values[i] || values[i][0] == '\0' ||
            strnlen(values[i], WVM_RUNTIME_PATH_MAX) >=
                WVM_RUNTIME_PATH_MAX) {
            set_error(error, error_len, "runtime name %zu is invalid", i);
            return -1;
        }
        for (j = 0; j < i; j++) {
            if (strcmp(values[i], values[j]) == 0) {
                set_error(error, error_len,
                          "runtime name collision between entries %zu and %zu",
                          j, i);
                return -1;
            }
        }
    }
    if (names->shm_name[0] != '/' ||
        strchr(names->shm_name + 1, '/') != NULL) {
        set_error(error, error_len, "SHM name is not a valid POSIX name");
        return -1;
    }
    return 0;
}

int wvm_runtime_name_set_derive(
    const struct wvm_local_name_namespace *namespace_value,
    struct wvm_runtime_name_set *names, char *error, size_t error_len)
{
    if (!namespace_value || !names) {
        set_error(error, error_len, "runtime namespace or name set is missing");
        return -1;
    }
    if (wvm_local_name_namespace_validate(namespace_value, error, error_len) !=
        0) {
        return -1;
    }
    memset(names, 0, sizeof(*names));
    if (format_name(names->runtime_socket, sizeof(names->runtime_socket),
                    "/tmp/wvm_user_%s.sock", namespace_value->namespace_name) !=
            0 ||
        format_name(names->executor_socket, sizeof(names->executor_socket),
                    "/tmp/%s-executor.sock", namespace_value->namespace_name) !=
            0 ||
        format_name(names->worker_socket, sizeof(names->worker_socket),
                    "/tmp/%s-worker.sock", namespace_value->namespace_name) !=
            0 ||
        format_name(names->monitor_socket, sizeof(names->monitor_socket),
                    "/tmp/%s-monitor.sock", namespace_value->namespace_name) !=
            0 ||
        format_name(names->ready_file, sizeof(names->ready_file),
                    "/tmp/%s-ready", namespace_value->namespace_name) != 0 ||
        format_name(names->shm_name, sizeof(names->shm_name),
                    "/wavevm_ram_%s", namespace_value->namespace_name) != 0 ||
        format_name(names->log_directory, sizeof(names->log_directory),
                    "/tmp/wavevm-%s-logs", namespace_value->namespace_name) !=
            0 ||
        format_name(names->temporary_directory,
                    sizeof(names->temporary_directory),
                    "/tmp/wavevm-%s-tmp", namespace_value->namespace_name) !=
            0) {
        set_error(error, error_len, "derived runtime name is too long");
        return -1;
    }
    return wvm_runtime_name_set_validate(names, error, error_len);
}

int wvm_runtime_ready_publish(
    const struct wvm_node_runtime_manifest *manifest,
    uint64_t node_instance_id, char *error, size_t error_len)
{
    struct wvm_runtime_name_set names;
    struct wvm_runtime_ready_record record;
    char temporary_path[WVM_RUNTIME_PATH_MAX + 12];
    struct wvm_runtime_ready_record existing, expected;
    int fd = -1, lock_fd = -1, result = -1;

    if (wvm_runtime_name_set_derive(
            manifest ? &manifest->local_names : NULL, &names, error,
            error_len) != 0 ||
        runtime_ready_record_fill(manifest, node_instance_id, &record, error,
                                   error_len) != 0) {
        return -1;
    }
    record.owner_pid = (uint64_t)getpid();
    record.owner_tid = (uint64_t)syscall(SYS_gettid);
    if (read_boot_id(record.owner_boot_id) != 0 ||
        read_task_start_time(record.owner_pid, record.owner_tid,
                             &record.owner_start_time_ticks) != 0) {
        set_error(error, error_len, "cannot identify live runtime task");
        return -1;
    }
    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp.XXXXXX",
                 names.ready_file) >= (int)sizeof(temporary_path)) {
        set_error(error, error_len, "runtime readiness temporary path is too long");
        return -1;
    }
    lock_fd = lock_ready_namespace(names.ready_file);
    if (lock_fd < 0) {
        set_error(error, error_len, "cannot lock runtime readiness: %s",
                  strerror(errno));
        return -1;
    }
    fd = mkstemp(temporary_path);
    if (fd < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
        write_ready_bytes(fd, &record, sizeof(record)) != 0 || fsync(fd) != 0) {
        set_error(error, error_len, "cannot write runtime readiness: %s",
                  strerror(errno));
        goto out;
    }
    if (link(temporary_path, names.ready_file) != 0) {
        if (errno != EEXIST ||
            read_ready_record(names.ready_file, &existing) != 0) {
            set_error(error, error_len, "cannot inspect existing runtime readiness");
            goto out;
        }
        expected = record;
        expected.owner_pid = 0;
        expected.owner_tid = 0;
        expected.owner_start_time_ticks = 0;
        memset(expected.owner_boot_id, 0, sizeof(expected.owner_boot_id));
        if (!ready_identity_matches(&existing, &expected)) {
            set_error(error, error_len, "runtime readiness belongs to another manifest");
            goto out;
        }
        if (ready_owner_alive(&existing)) {
            if (memcmp(&existing, &record, sizeof(record)) == 0) {
                result = 0;
            } else {
                set_error(error, error_len, "runtime readiness is owned by another live task");
            }
            goto out;
        }
        if (unlink(names.ready_file) != 0 ||
            link(temporary_path, names.ready_file) != 0) {
            set_error(error, error_len, "cannot replace stale runtime readiness: %s",
                      strerror(errno));
            goto out;
        }
    }
    result = 0;
out:
    if (fd >= 0) {
        close(fd);
    }
    if (fd >= 0 && unlink(temporary_path) != 0 && errno != ENOENT) {
        set_error(error, error_len,
                  "cannot remove runtime readiness temporary file: %s",
                  strerror(errno));
        result = -1;
    }
    close(lock_fd);
    return result;
}

int wvm_runtime_ready_validate(
    const struct wvm_node_runtime_manifest *manifest,
    uint64_t node_instance_id, char *error, size_t error_len)
{
    struct wvm_runtime_name_set names;
    struct wvm_runtime_ready_record expected;
    struct wvm_runtime_ready_record actual;

    if (wvm_runtime_name_set_derive(
            manifest ? &manifest->local_names : NULL, &names, error,
            error_len) != 0 ||
        runtime_ready_record_fill(manifest, node_instance_id, &expected, error,
                                   error_len) != 0) {
        return -1;
    }
    if (read_ready_record(names.ready_file, &actual) != 0) {
        set_error(error, error_len, "runtime readiness is unavailable: %s",
                  strerror(errno));
        return errno == ENOENT ? -EAGAIN : -1;
    }
    if (!ready_identity_matches(&actual, &expected)) {
        set_error(error, error_len,
                  "runtime readiness does not match admitted manifest");
        return -1;
    }
    if (!ready_owner_alive(&actual)) {
        set_error(error, error_len, "runtime readiness owner is not alive");
        return -EAGAIN;
    }
    return 0;
}

int wvm_runtime_ready_remove(
    const struct wvm_node_runtime_manifest *manifest, char *error,
    size_t error_len)
{
    struct wvm_runtime_name_set names;
    struct wvm_runtime_ready_record actual, expected;
    int lock_fd, result = 0;

    if (wvm_runtime_name_set_derive(
            manifest ? &manifest->local_names : NULL, &names, error,
            error_len) != 0) {
        return -1;
    }
    lock_fd = lock_ready_namespace(names.ready_file);
    if (lock_fd < 0) {
        set_error(error, error_len, "cannot lock runtime readiness: %s",
                  strerror(errno));
        return -1;
    }
    if (read_ready_record(names.ready_file, &actual) == 0) {
        if (runtime_ready_record_fill(manifest,
                                      manifest->expected_node_instance_id,
                                      &expected, error, error_len) != 0 ||
            !ready_identity_matches(&actual, &expected)) {
            set_error(error, error_len,
                      "runtime readiness is owned by another manifest");
            result = -1;
            goto out;
        }
        if (ready_owner_alive(&actual) &&
            (actual.owner_pid != (uint64_t)getpid() ||
             actual.owner_tid != (uint64_t)syscall(SYS_gettid))) {
            set_error(error, error_len,
                      "runtime readiness is owned by another live task");
            result = -1;
            goto out;
        }
    } else if (errno != ENOENT) {
        set_error(error, error_len, "cannot inspect runtime readiness: %s",
                  strerror(errno));
        result = -1;
        goto out;
    }
    if (unlink(names.ready_file) != 0 && errno != ENOENT) {
        set_error(error, error_len, "cannot remove runtime readiness: %s",
                  strerror(errno));
        result = -1;
    }
out:
    close(lock_fd);
    return result;
}

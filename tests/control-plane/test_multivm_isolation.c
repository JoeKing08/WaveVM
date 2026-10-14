#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <unistd.h>

#include "wavevm_identity.h"
#include "wavevm_runtime_names.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "multi-vm-isolation test: %s\n", message);
        return -1;
    }
    return 0;
}

static int make_namespace(struct wvm_local_name_namespace *value,
                          uint32_t vm_id, uint8_t salt, char *error,
                          size_t error_len)
{
    struct wvm_local_name_identity identity;

    memset(&identity, 0, sizeof(identity));
    identity.vm_id = vm_id;
    identity.vm_incarnation = 1;
    identity.manifest_generation = 1;
    identity.physical_node_id = 17;
    memset(identity.manifest_id, salt, sizeof(identity.manifest_id));
    memset(identity.admission_tx_id, (uint8_t)(salt + 1U),
           sizeof(identity.admission_tx_id));
    return wvm_local_name_namespace_derive(&identity, value, error,
                                           error_len);
}

static int bind_unix_socket(const char *path)
{
    struct sockaddr_un address;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    strcpy(address.sun_path, path);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int create_vm_resources(const struct wvm_runtime_name_set *names,
                               int sockets[4], int *shm_fd, uint32_t marker)
{
    const char *socket_paths[4];
    int ready_fd;
    size_t i;

    socket_paths[0] = names->runtime_socket;
    socket_paths[1] = names->executor_socket;
    socket_paths[2] = names->worker_socket;
    socket_paths[3] = names->monitor_socket;
    for (i = 0; i < 4; i++) {
        sockets[i] = bind_unix_socket(socket_paths[i]);
        if (sockets[i] < 0) {
            return -1;
        }
    }
    if (mkdir(names->log_directory, 0700) != 0 ||
        mkdir(names->temporary_directory, 0700) != 0) {
        return -1;
    }
    ready_fd = open(names->ready_file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    0600);
    if (ready_fd < 0) {
        return -1;
    }
    close(ready_fd);
    *shm_fd = shm_open(names->shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (*shm_fd < 0) {
        return -1;
    }
    if (ftruncate(*shm_fd, (off_t)sizeof(marker)) != 0 ||
        write(*shm_fd, &marker, sizeof(marker)) != (ssize_t)sizeof(marker)) {
        return -1;
    }
    return 0;
}

static void remove_vm_resources(const struct wvm_runtime_name_set *names,
                                int sockets[4], int shm_fd)
{
    size_t i;

    for (i = 0; i < 4; i++) {
        if (sockets[i] >= 0) {
            close(sockets[i]);
            sockets[i] = -1;
        }
    }
    if (shm_fd >= 0) {
        close(shm_fd);
    }
    unlink(names->runtime_socket);
    unlink(names->executor_socket);
    unlink(names->worker_socket);
    unlink(names->monitor_socket);
    unlink(names->ready_file);
    shm_unlink(names->shm_name);
    rmdir(names->log_directory);
    rmdir(names->temporary_directory);
}

static int resource_set_exists(const struct wvm_runtime_name_set *names)
{
    int fd;

    if (access(names->runtime_socket, F_OK) != 0 ||
        access(names->executor_socket, F_OK) != 0 ||
        access(names->worker_socket, F_OK) != 0 ||
        access(names->monitor_socket, F_OK) != 0 ||
        access(names->ready_file, F_OK) != 0 ||
        access(names->log_directory, F_OK) != 0 ||
        access(names->temporary_directory, F_OK) != 0) {
        return 0;
    }
    fd = shm_open(names->shm_name, O_RDWR, 0);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}

static int shm_marker_equals(const char *shm_name, uint32_t expected)
{
    int fd;
    uint32_t value = 0;
    ssize_t got;

    fd = shm_open(shm_name, O_RDONLY, 0);
    if (fd < 0) {
        return 0;
    }
    got = read(fd, &value, sizeof(value));
    close(fd);
    return got == (ssize_t)sizeof(value) && value == expected;
}

static int name_sets_disjoint(const struct wvm_runtime_name_set *left,
                              const struct wvm_runtime_name_set *right)
{
    const char *a[] = {
        left->runtime_socket, left->executor_socket, left->worker_socket,
        left->monitor_socket, left->ready_file, left->shm_name,
        left->log_directory, left->temporary_directory,
    };
    const char *b[] = {
        right->runtime_socket, right->executor_socket, right->worker_socket,
        right->monitor_socket, right->ready_file, right->shm_name,
        right->log_directory, right->temporary_directory,
    };
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(a) / sizeof(a[0]); i++) {
        for (j = 0; j < sizeof(b) / sizeof(b[0]); j++) {
            if (strcmp(a[i], b[j]) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

int main(void)
{
    struct wvm_local_name_namespace namespace_a;
    struct wvm_local_name_namespace namespace_b;
    struct wvm_local_name_namespace namespace_dup;
    struct wvm_runtime_name_set names_a;
    struct wvm_runtime_name_set names_b;
    int sockets_a[4] = {-1, -1, -1, -1};
    int sockets_b[4] = {-1, -1, -1, -1};
    int shm_a = -1;
    int shm_b = -1;
    char error[256] = {0};
    const uint32_t marker_a = 0xA11CE001U;
    const uint32_t marker_b = 0xB22CE002U;

    if (expect(make_namespace(&namespace_a, 256, 0x41, error,
                              sizeof(error)) == 0,
               "derive VM A admitted identity") ||
        expect(make_namespace(&namespace_b, 257, 0x42, error,
                              sizeof(error)) == 0,
               "derive VM B admitted identity") ||
        expect(make_namespace(&namespace_dup, 256, 0x41, error,
                              sizeof(error)) == 0,
               "derive duplicate of VM A identity") ||
        expect(wvm_local_name_namespace_validate_unique(
                   (const struct wvm_local_name_namespace[]){namespace_a,
                                                              namespace_b},
                   2, error, sizeof(error)) == 0,
               "same physical node has distinct VM namespaces") ||
        expect(wvm_local_name_namespace_validate_unique(
                   (const struct wvm_local_name_namespace[]){namespace_a,
                                                              namespace_dup},
                   2, error, sizeof(error)) != 0,
               "fail-closed: identical namespaces are not unique") ||
        expect(wvm_runtime_name_set_derive(&namespace_a, &names_a, error,
                                           sizeof(error)) == 0 &&
                   wvm_runtime_name_set_validate(&names_a, error,
                                                 sizeof(error)) == 0,
               "derive+validate VM A name set") ||
        expect(wvm_runtime_name_set_derive(&namespace_b, &names_b, error,
                                           sizeof(error)) == 0 &&
                   wvm_runtime_name_set_validate(&names_b, error,
                                                 sizeof(error)) == 0,
               "derive+validate VM B name set") ||
        expect(name_sets_disjoint(&names_a, &names_b),
               "Mode B dual-VM name sets share no socket/shm/path") ||
        expect(create_vm_resources(&names_a, sockets_a, &shm_a, marker_a) == 0,
               "create VM A resources") ||
        expect(create_vm_resources(&names_b, sockets_b, &shm_b, marker_b) == 0,
               "create VM B resources") ||
        expect(resource_set_exists(&names_a), "VM A resources exist") ||
        expect(resource_set_exists(&names_b), "VM B resources exist") ||
        expect(shm_marker_equals(names_a.shm_name, marker_a),
               "VM A SHM holds its marker") ||
        expect(shm_marker_equals(names_b.shm_name, marker_b),
               "VM B SHM holds its marker")) {
        remove_vm_resources(&names_a, sockets_a, shm_a);
        remove_vm_resources(&names_b, sockets_b, shm_b);
        return 1;
    }

    {
        int duplicate_socket = bind_unix_socket(names_a.runtime_socket);
        int duplicate_monitor = bind_unix_socket(names_a.monitor_socket);
        int duplicate_shm = shm_open(names_a.shm_name,
                                     O_CREAT | O_RDWR | O_EXCL, 0600);

        if (duplicate_socket >= 0) {
            close(duplicate_socket);
            unlink(names_a.runtime_socket);
        }
        if (duplicate_monitor >= 0) {
            close(duplicate_monitor);
            unlink(names_a.monitor_socket);
        }
        if (duplicate_shm >= 0) {
            close(duplicate_shm);
            shm_unlink(names_a.shm_name);
        }
        if (expect(duplicate_socket < 0,
                   "reject duplicate runtime socket ownership") ||
            expect(duplicate_monitor < 0,
                   "reject duplicate monitor socket ownership") ||
            expect(duplicate_shm < 0 && errno == EEXIST,
                   "reject duplicate SHM ownership")) {
            remove_vm_resources(&names_a, sockets_a, shm_a);
            remove_vm_resources(&names_b, sockets_b, shm_b);
            return 1;
        }
    }

    /* Teardown VM A only — roadmap Phase 6: deleting one VM must not unlink
     * or truncate the other VM's resources (Mode B local-name slice). */
    remove_vm_resources(&names_a, sockets_a, shm_a);
    shm_a = -1;
    if (expect(!resource_set_exists(&names_a),
               "VM A resources are removed") ||
        expect(resource_set_exists(&names_b),
               "removing VM A preserves VM B resources") ||
        expect(shm_marker_equals(names_b.shm_name, marker_b),
               "VM B SHM marker intact after VM A teardown")) {
        remove_vm_resources(&names_b, sockets_b, shm_b);
        return 1;
    }
    remove_vm_resources(&names_b, sockets_b, shm_b);
    puts("multi-vm-isolation tests: PASS");
    puts("NOTE: Mode B Phase 6 local-name slice — namespace/socket/shm/path");
    puts("      uniqueness, exclusive bind, and one-VM teardown isolation.");
    puts("      Does not load /dev/wavevm, drive dual kernel contexts, or run guest E2E.");
    return 0;
}

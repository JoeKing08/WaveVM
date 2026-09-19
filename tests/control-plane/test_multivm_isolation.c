#define _POSIX_C_SOURCE 200809L

#include <errno.h>
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
                               int sockets[3], int *shm_fd)
{
    const char *socket_paths[3];
    int ready_fd;

    socket_paths[0] = names->runtime_socket;
    socket_paths[1] = names->executor_socket;
    socket_paths[2] = names->worker_socket;
    sockets[0] = bind_unix_socket(socket_paths[0]);
    sockets[1] = bind_unix_socket(socket_paths[1]);
    sockets[2] = bind_unix_socket(socket_paths[2]);
    if (sockets[0] < 0 || sockets[1] < 0 || sockets[2] < 0 ||
        mkdir(names->log_directory, 0700) != 0 ||
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
    return 0;
}

static void remove_vm_resources(const struct wvm_runtime_name_set *names,
                                int sockets[3], int shm_fd)
{
    size_t i;

    for (i = 0; i < 3; i++) {
        if (sockets[i] >= 0) {
            close(sockets[i]);
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

int main(void)
{
    struct wvm_local_name_namespace namespace_a;
    struct wvm_local_name_namespace namespace_b;
    struct wvm_runtime_name_set names_a;
    struct wvm_runtime_name_set names_b;
    int sockets_a[3] = {-1, -1, -1};
    int sockets_b[3] = {-1, -1, -1};
    int shm_a = -1;
    int shm_b = -1;
    char error[256] = {0};

    if (expect(make_namespace(&namespace_a, 256, 0x41, error,
                              sizeof(error)) == 0,
               "derive VM A admitted identity") ||
        expect(make_namespace(&namespace_b, 257, 0x42, error,
                              sizeof(error)) == 0,
               "derive VM B admitted identity") ||
        expect(wvm_local_name_namespace_validate_unique(
                   (const struct wvm_local_name_namespace[]){namespace_a,
                                                              namespace_b},
                   2, error, sizeof(error)) == 0,
               "same physical node has distinct VM namespaces") ||
        expect(wvm_runtime_name_set_derive(&namespace_a, &names_a, error,
                                           sizeof(error)) == 0,
               "derive VM A names") ||
        expect(wvm_runtime_name_set_derive(&namespace_b, &names_b, error,
                                           sizeof(error)) == 0,
               "derive VM B names") ||
        expect(create_vm_resources(&names_a, sockets_a, &shm_a) == 0,
               "create VM A resources") ||
        expect(create_vm_resources(&names_b, sockets_b, &shm_b) == 0,
               "create VM B resources") ||
        expect(resource_set_exists(&names_a), "VM A resources exist") ||
        expect(resource_set_exists(&names_b), "VM B resources exist")) {
        remove_vm_resources(&names_a, sockets_a, shm_a);
        remove_vm_resources(&names_b, sockets_b, shm_b);
        return 1;
    }

    {
        int duplicate_socket = bind_unix_socket(names_a.runtime_socket);
        int duplicate_shm = shm_open(names_a.shm_name,
                                     O_CREAT | O_RDWR | O_EXCL, 0600);

        if (duplicate_socket >= 0) {
            close(duplicate_socket);
            unlink(names_a.runtime_socket);
        }
        if (duplicate_shm >= 0) {
            close(duplicate_shm);
            shm_unlink(names_a.shm_name);
        }
        if (expect(duplicate_socket < 0,
                   "reject duplicate runtime socket ownership") ||
            expect(duplicate_shm < 0 && errno == EEXIST,
                   "reject duplicate SHM ownership")) {
            remove_vm_resources(&names_a, sockets_a, shm_a);
            remove_vm_resources(&names_b, sockets_b, shm_b);
            return 1;
        }
    }

    remove_vm_resources(&names_a, sockets_a, shm_a);
    if (expect(!resource_set_exists(&names_a),
               "VM A resources are removed") ||
        expect(resource_set_exists(&names_b),
               "removing VM A preserves VM B resources")) {
        remove_vm_resources(&names_b, sockets_b, shm_b);
        return 1;
    }
    remove_vm_resources(&names_b, sockets_b, shm_b);
    puts("multi-vm-isolation tests: PASS");
    puts("NOTE: This test validates local namespace/socket/shm naming and cleanup isolation.");
    puts("      It does not load /dev/wavevm or drive dual kernel contexts.");
    return 0;
}

#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "wavevm_identity.h"
#include "wavevm_runtime_names.h"

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "runtime-names tests: %s\n", message);
        return 1;
    }
    return 0;
}

static void make_namespace(struct wvm_local_name_namespace *value,
                           const char *name, unsigned char salt)
{
    memset(value, 0, sizeof(*value));
    snprintf(value->namespace_name, sizeof(value->namespace_name), "%s", name);
    memset(value->derivation_salt_digest, salt,
           sizeof(value->derivation_salt_digest));
    value->name_generation = 1;
}

int main(void)
{
    struct wvm_local_name_namespace first;
    struct wvm_local_name_namespace second;
    struct wvm_runtime_name_set first_names;
    struct wvm_runtime_name_set second_names;
    char error[256] = {0};

    make_namespace(&first, "wvm-v7-i11-g2-n3-0123456789abcdef", 0x11);
    make_namespace(&second, "wvm-v7-i12-g2-n3-fedcba9876543210", 0x22);
    if (expect(wvm_runtime_name_set_derive(&first, &first_names, error,
                                           sizeof(error)) == 0,
               "derive first namespace") ||
        expect(wvm_runtime_name_set_derive(&second, &second_names, error,
                                           sizeof(error)) == 0,
               "derive second namespace")) {
        return 1;
    }
    if (expect(strcmp(first_names.shm_name, second_names.shm_name) != 0,
               "SHM names are disjoint") ||
        expect(strcmp(first_names.runtime_socket,
                      second_names.runtime_socket) != 0,
               "QEMU IPC names are disjoint") ||
        expect(strcmp(first_names.executor_socket,
                      second_names.executor_socket) != 0,
               "executor names are disjoint") ||
        expect(strcmp(first_names.ready_file, second_names.ready_file) != 0,
               "readiness fences are disjoint") ||
        expect(strcmp(first_names.log_directory,
                      second_names.log_directory) != 0,
               "log directories are disjoint") ||
        expect(strcmp(first_names.temporary_directory,
                      second_names.temporary_directory) != 0,
               "temporary directories are disjoint") ||
        expect(first_names.shm_name[0] == '/', "SHM name has POSIX prefix")) {
        return 1;
    }
    first_names.executor_socket[0] = '\0';
    if (expect(wvm_runtime_name_set_validate(&first_names, error,
                                             sizeof(error)) != 0,
               "invalid derived set is rejected")) {
        return 1;
    }
    {
        struct wvm_runtime_name_set retire_names;
        int ready_fd;
        int shm_fd;

        if (expect(wvm_runtime_name_set_derive(&first, &retire_names, error,
                                               sizeof(error)) == 0,
                   "re-derive valid set for retire")) {
            return 1;
        }
        ready_fd = open(retire_names.ready_file,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (ready_fd < 0) {
            fprintf(stderr, "runtime-names test: cannot create ready file\n");
            return 1;
        }
        close(ready_fd);
        shm_fd = shm_open(retire_names.shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (shm_fd < 0) {
            fprintf(stderr, "runtime-names test: cannot create SHM\n");
            unlink(retire_names.ready_file);
            return 1;
        }
        close(shm_fd);
        if (expect(wvm_runtime_name_set_retire(&retire_names, error,
                                               sizeof(error)) == 0,
                   "retire removes ready+SHM") ||
            expect(access(retire_names.ready_file, F_OK) != 0,
                   "ready fence gone after retire") ||
            expect(shm_open(retire_names.shm_name, O_RDONLY, 0) < 0,
                   "SHM gone after retire") ||
            expect(wvm_runtime_name_set_retire(&retire_names, error,
                                               sizeof(error)) == 0,
                   "retire is ENOENT-idempotent")) {
            return 1;
        }
    }
    puts("runtime-names tests: PASS");
    return 0;
}

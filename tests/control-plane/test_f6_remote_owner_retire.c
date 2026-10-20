/*
 * Codex F6 / GOAL-2 / SPEC-runtime-stop-cleanup:
 * Participant-host STOP must retire sockets + ready fence + SHM (not sockets
 * only). Production path: admission_runtime_agent clear_stale_admitted_endpoints
 * → wvm_runtime_name_set_retire; receiver lifecycle STOP also retires owner
 * names after stop_runtime.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "wavevm_identity.h"
#include "wavevm_runtime_names.h"

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "f6-remote-owner-retire: %s\n", msg);
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
    struct wvm_local_name_namespace ns;
    struct wvm_runtime_name_set names;
    char error[256] = {0};
    int ready_fd, shm_fd;
    int sock_fds[4];
    size_t i;
    const char *sockets[4];

    make_namespace(&ns, "wvm-f6-v9-i3-g1-n2-aabbccddeeff0011", 0xF6);
    if (expect(wvm_runtime_name_set_derive(&ns, &names, error, sizeof(error)) ==
                   0,
               "derive owner names"))
        return 1;

    sockets[0] = names.runtime_socket;
    sockets[1] = names.executor_socket;
    sockets[2] = names.worker_socket;
    sockets[3] = names.monitor_socket;
    for (i = 0; i < 4; i++) {
        sock_fds[i] = open(sockets[i], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                           0600);
        if (sock_fds[i] < 0) {
            fprintf(stderr, "f6: cannot create socket stub %s\n", sockets[i]);
            return 1;
        }
        close(sock_fds[i]);
    }
    ready_fd = open(names.ready_file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    0600);
    if (ready_fd < 0) {
        fprintf(stderr, "f6: cannot create ready\n");
        return 1;
    }
    close(ready_fd);
    shm_fd = shm_open(names.shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (shm_fd < 0) {
        fprintf(stderr, "f6: cannot create shm\n");
        return 1;
    }
    close(shm_fd);

    /* Simulate socket-only cleanup (pre-F6 bug): leave ready+SHM. */
    for (i = 0; i < 4; i++)
        (void)unlink(sockets[i]);
    if (expect(access(names.ready_file, F_OK) == 0,
               "pre-F6: ready would still exist after socket-only unlink") ||
        expect(shm_open(names.shm_name, O_RDONLY, 0) >= 0,
               "pre-F6: SHM would still exist after socket-only unlink"))
        return 1;
    /* close the probe fd from shm_open success check */
    {
        int probe = shm_open(names.shm_name, O_RDONLY, 0);
        if (probe >= 0)
            close(probe);
    }

    /* F6 owner contract: full retire on participant host. */
    if (expect(wvm_runtime_name_set_retire(&names, error, sizeof(error)) == 0,
               "owner retire succeeds") ||
        expect(access(names.runtime_socket, F_OK) != 0, "runtime socket gone") ||
        expect(access(names.executor_socket, F_OK) != 0, "executor socket gone") ||
        expect(access(names.worker_socket, F_OK) != 0, "worker socket gone") ||
        expect(access(names.monitor_socket, F_OK) != 0, "monitor socket gone") ||
        expect(access(names.ready_file, F_OK) != 0, "ready fence gone") ||
        expect(shm_open(names.shm_name, O_RDONLY, 0) < 0, "SHM gone"))
        return 1;

    puts("PASS F6 remote-owner retire (sockets+ready+SHM; not sockets-only)");
    puts("NOTE: agent clear_stale_admitted_endpoints + receiver lifecycle STOP "
         "both call wvm_runtime_name_set_retire on participant host");
    return 0;
}

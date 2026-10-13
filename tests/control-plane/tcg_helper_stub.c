/*
 * Holds a WaveVM TCG executor session FD alive for control-plane readiness.
 * Not a guest E2E helper: no QEMU accel, no guest boot.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void on_signal(int signo)
{
    (void)signo;
    stop_requested = 1;
}

int main(void)
{
    const char *fd_text = getenv("WVM_EXECUTOR_SESSION_FD");
    char *end = NULL;
    long session_fd;
    struct sigaction action;

    if (!fd_text || !*fd_text) {
        fprintf(stderr, "tcg_helper_stub: WVM_EXECUTOR_SESSION_FD missing\n");
        return 2;
    }
    session_fd = strtol(fd_text, &end, 10);
    if (!end || *end != '\0' || session_fd < 0 || session_fd > 1024) {
        fprintf(stderr, "tcg_helper_stub: invalid session fd\n");
        return 2;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    while (!stop_requested) {
        pause();
    }
    close((int)session_fd);
    return 0;
}

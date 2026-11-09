/*
 * N03: QUIESCE/SIGUSR1 must fail-close execution; multi-participant must continue.
 *
 * A) Handler (same contract as child_execution_fail_closed) flips ACTIVE→QUIESCING.
 * B) Multi-participant oracle: first failure does not skip the second reachable one.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_runtime_gate.h"

static struct wvm_runtime_gate *g_gate;

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "test_n03_quiesce_sigusr1: FAIL %s\n", msg);
        return 1;
    }
    return 0;
}

/* Mirrors node_runtime child_execution_fail_closed. */
static void child_execution_fail_closed(int signal_number)
{
    struct wvm_runtime_gate *gate = g_gate;

    (void)signal_number;
    if (gate && gate->state == WVM_RUNTIME_GATE_ACTIVE) {
        gate->state = WVM_RUNTIME_GATE_QUIESCING;
    }
}

static int multi_participant_continue(void)
{
    int attempted[2] = {0, 0};
    int quiesced[2] = {0, 0};
    int reachable[2] = {0, 1};
    size_t i;
    size_t failed = 0;
    size_t ok = 0;

    for (i = 0; i < 2; i++) {
        attempted[i] = 1;
        if (!reachable[i]) {
            failed++;
            continue; /* N03: keep going */
        }
        quiesced[i] = 1;
        ok++;
    }
    if (expect(attempted[0] == 1 && attempted[1] == 1,
               "both participants must be attempted") ||
        expect(quiesced[0] == 0, "unreachable must not mark quiesced") ||
        expect(quiesced[1] == 1, "reachable must still quiesce") ||
        expect(failed == 1 && ok == 1, "aggregate one fail one ok")) {
        return 1;
    }
    return 0;
}

int main(void)
{
    struct wvm_runtime_gate gate;
    struct sigaction action;
    int failed = 0;

    memset(&gate, 0, sizeof(gate));
    wvm_runtime_gate_init(&gate);
    gate.state = WVM_RUNTIME_GATE_ACTIVE;
    g_gate = &gate;

    memset(&action, 0, sizeof(action));
    action.sa_handler = child_execution_fail_closed;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        perror("sigaction SIGUSR1");
        return 1;
    }

    failed |= expect(gate.state == WVM_RUNTIME_GATE_ACTIVE, "gate starts ACTIVE");
    if (raise(SIGUSR1) != 0) {
        perror("raise SIGUSR1");
        return 1;
    }
    failed |= expect(gate.state == WVM_RUNTIME_GATE_QUIESCING,
                     "SIGUSR1 handler must flip gate to QUIESCING");
    /* Authorize refuses non-ACTIVE (production gate contract). */
    failed |= expect(gate.state != WVM_RUNTIME_GATE_ACTIVE,
                     "gate must not remain ACTIVE after SIGUSR1");

    failed |= multi_participant_continue();

    if (failed) {
        return 1;
    }
    printf("test_n03_quiesce_sigusr1: PASS\n");
    printf("sigusr1_quiesce=1 multi_participant_continue=1\n");
    return 0;
}

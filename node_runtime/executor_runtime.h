#ifndef WAVEVM_NODE_RUNTIME_EXECUTOR_RUNTIME_H
#define WAVEVM_NODE_RUNTIME_EXECUTOR_RUNTIME_H

#include <stddef.h>

#include "../common_include/wavevm_vcpu_handoff.h"

/*
 * Execute one admitted vCPU handoff through the local executor manager. The
 * caller owns the result buffer and supplies it to avoid borrowing
 * transient executor storage across the asynchronous handoff boundary.
 */
int wvm_executor_runtime_execute_handoff(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    struct wvm_vcpu_handoff_result *result, uint8_t *result_context,
    size_t result_context_capacity, char *error, size_t error_len);

/* Wait for the admitted local executor listener to accept typed handoffs. */
int wvm_executor_runtime_wait_ready(void);

#endif

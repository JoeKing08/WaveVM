#ifndef WAVEVM_NODE_RUNTIME_EXECUTOR_RUNTIME_H
#define WAVEVM_NODE_RUNTIME_EXECUTOR_RUNTIME_H

#include <stddef.h>

#include "../common_include/wavevm_vcpu_handoff.h"
#include "runtime_context.h"

/*
 * Execute one admitted vCPU handoff through the local executor manager. The
 * caller owns the result buffer and supplies it to avoid borrowing
 * transient executor storage across the asynchronous handoff boundary.
 *
 * When opaque is a live wvm_node_runtime_context whose admitted projection
 * names a remote directory page and the V1 memory service is installed, this
 * entry performs one remote memory fault for that page before the local
 * run-once (production "true executor + remote memory" path). Guest OS/SSH
 * remains goal §7.
 */
int wvm_executor_runtime_execute_handoff(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    struct wvm_vcpu_handoff_result *result, uint8_t *result_context,
    size_t result_context_capacity, char *error, size_t error_len);

/* Wait for the admitted local executor listener to accept typed handoffs. */
int wvm_executor_runtime_wait_ready(void);

/*
 * Bind an already-admitted runtime context to the local typed executor so
 * wvm_executor_runtime_execute_handoff can accept matching handoffs. Used by
 * the production executor role and by Minimum evidence harnesses that drive
 * the same symbol through executor_bridge without claiming guest OS/SSH.
 */
int wvm_executor_runtime_bind_admitted(
    const struct wvm_node_runtime_context *runtime, char *error,
    size_t error_len);

/* Attach one local TCG executor session FD for vcpu_index (takes ownership). */
int wvm_executor_runtime_attach_tcg_session(uint32_t vcpu_index,
                                           int session_fd);

/* Publish EXECUTOR_READY after bind + required sessions are attached. */
void wvm_executor_runtime_publish_ready(void);

/* Tear down bind/session state published by the helpers above. */
void wvm_executor_runtime_unbind(void);

#endif

#ifndef WAVEVM_NODE_RUNTIME_VCPU_SERVICE_H
#define WAVEVM_NODE_RUNTIME_VCPU_SERVICE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "vcpu_coordinator.h"
#include "../common_include/wavevm_protocol.h"

/*
 * This is the sole adapter between the local QEMU CPU_RUN IPC and the typed
 * node-runtime handoff coordinator. It never routes to an executor directly.
 */
struct wvm_vcpu_service_config {
    struct wvm_vcpu_handoff_coordinator *coordinator;
    size_t record_capacity;
};

struct wvm_vcpu_service {
    struct wvm_vcpu_service_config config;
    pthread_mutex_t lock;
    pthread_cond_t reply_available;
    void *entries;
    size_t capacity;
    uint64_t operation_epoch;
    uint64_t next_operation_sequence;
    uint64_t last_memory_fence_id;
    pthread_t reply_thread;
    int stopping;
    int initialized;
};

int wvm_vcpu_service_init(struct wvm_vcpu_service *service,
                          const struct wvm_vcpu_service_config *config,
                          char *error, size_t error_len);
void wvm_vcpu_service_destroy(struct wvm_vcpu_service *service);

/*
 * G8: wait until no PENDING / REPLY_QUEUED / REPLY_SENDING entries remain.
 * reply_sending covers ACK bytes still being written — drain must not return
 * success while write_reply is blocked on a full/disconnected socket.
 * Timeout is a failed STOP (bounded); never poll forever.
 */
int wvm_vcpu_service_drain(struct wvm_vcpu_service *service,
                           uint32_t timeout_ms, char *error,
                           size_t error_len);

/*
 * Submit one already-drained local QEMU run request. Success means that the
 * typed VCPU_RUN is now owned by the coordinator; its typed VCPU_EXIT is
 * returned asynchronously on the supplied QEMU IPC connection.
 */
int wvm_vcpu_service_submit(struct wvm_vcpu_service *service, int qemu_fd,
                            const struct wvm_ipc_cpu_run_req *request,
                            char *error, size_t error_len);

/*
 * This callback is installed on the handoff coordinator. It queues the
 * legacy ACK only after the coordinator has verified a terminal VCPU_EXIT.
 */
int wvm_vcpu_service_complete(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result, char *error,
    size_t error_len);

/*
 * The node runtime exposes one installed local service to the legacy master
 * role compiled into the same process image. No cross-node legacy fallback is
 * available when this service is absent.
 */
int wvm_vcpu_service_global_install(struct wvm_vcpu_service *service,
                                    char *error, size_t error_len);
void wvm_vcpu_service_global_uninstall(struct wvm_vcpu_service *service);
int wvm_vcpu_service_global_submit(
    int qemu_fd, const struct wvm_ipc_cpu_run_req *request, char *error,
    size_t error_len);

#endif /* WAVEVM_NODE_RUNTIME_VCPU_SERVICE_H */

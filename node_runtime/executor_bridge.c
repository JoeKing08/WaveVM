#define _GNU_SOURCE

#include "executor_bridge.h"

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../common_include/wavevm_executor_abi.h"
#include "kvm_page_cache.h"
#include "../common_include/wavevm_vcpu_handoff_cache.h"
#include "../common_include/wavevm_vcpu_handoff.h"
#include "../common_include/wavevm_x86_context.h"

struct bridge_state {
    struct wvm_executor_bridge_config config;
    struct wvm_vcpu_handoff_cache handoff_cache;
    pthread_mutex_t task_lock;
    pthread_cond_t task_available;
    pthread_cond_t task_idle;
    pthread_t task_worker;
    struct bridge_task *tasks;
    size_t task_capacity;
    size_t task_head;
    size_t task_count;
    int task_busy;
    int stopping;
    int task_worker_started;
};

struct bridge_task {
    struct wvm_envelope envelope;
    uint8_t *payload;
};

static int authorize_cpu_run(const struct bridge_state *state,
                             const struct wvm_executor_abi_frame *request,
                             char *error, size_t error_len);

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

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    if ((uint64_t)now.tv_sec > UINT64_MAX / 1000U) {
        return UINT64_MAX;
    }
    return (uint64_t)now.tv_sec * 1000U +
           (uint64_t)now.tv_nsec / 1000000U;
}

static int route_key_equal(const struct wvm_route_snapshot_key *left,
                           const struct wvm_route_snapshot_key *right)
{
    return left && right &&
           left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  sizeof(left->snapshot_digest)) == 0;
}

static int route_destination_equal(
    const struct wvm_runtime_route_destination *destination,
    const struct wvm_envelope_route *route)
{
    return destination && route &&
           destination->destination_kind == route->destination_kind &&
           destination->destination_scope == route->destination_scope &&
           destination->destination_vnode ==
               route->destination_vnode_or_endpoint;
}

static int config_is_admitted(const struct wvm_executor_bridge_config *config,
                              char *error, size_t error_len)
{
    if (!config || !config->manifest || !config->runtime_gate ||
        !config->dispatch || !config->route_runtime ||
        !config->execute_handoff || !config->send_envelope ||
        config->operation_retention_horizon_ms == 0 ||
        config->runtime_gate->state != WVM_RUNTIME_GATE_ACTIVE ||
        config->runtime_gate->manifest != config->manifest ||
        config->local_runtime_instance_id == 0 ||
        config->runtime_connection_id == 0 ||
        config->manifest->launch_plan.vcpu_handoff_record_capacity == 0 ||
        config->dispatch->vm_id != config->manifest->vm_id ||
        config->dispatch->vm_incarnation != config->manifest->vm_incarnation ||
        config->dispatch->manifest_generation !=
            config->manifest->manifest_generation ||
        config->dispatch->physical_node_id != config->manifest->physical_node_id ||
        config->dispatch->expected_node_instance_id !=
            config->local_runtime_instance_id ||
        memcmp(config->dispatch->candidate_manifest_digest,
               config->manifest->candidate_manifest_digest,
               sizeof(config->dispatch->candidate_manifest_digest)) != 0 ||
        memcmp(config->dispatch->activation_fence,
               config->manifest->activation_fence,
               sizeof(config->dispatch->activation_fence)) != 0 ||
        !route_key_equal(&config->dispatch->required_route_snapshot_key,
                         &config->manifest->required_route_snapshot_key) ||
        wvm_runtime_dispatch_projection_validate(config->dispatch, error,
                                                 error_len) != 0 ||
        !wvm_route_runtime_has_snapshot(
            config->route_runtime,
            &config->dispatch->required_route_snapshot_key)) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "executor bridge configuration is not admitted");
        }
        return -EINVAL;
    }
    return 0;
}

static int authorize_local_handoff(
    const struct bridge_state *state,
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    if (!state || !request || !envelope ||
        !route_destination_equal(&state->config.dispatch->local_primary,
                                 &envelope->route) ||
        request->destination_executor_id !=
            state->config.dispatch->local_primary.destination_vnode) {
        set_error(error, error_len,
                  "typed vCPU handoff does not target this admitted executor");
        return -EPERM;
    }
    return 0;
}

static void handoff_result_from_request(
    const struct wvm_vcpu_handoff_request *request, uint16_t status,
    struct wvm_vcpu_handoff_result *result)
{
    memset(result, 0, sizeof(*result));
    result->protocol_version = WVM_VCPU_HANDOFF_RESULT_VERSION;
    result->status = status;
    result->exit_class =
        status == WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE
            ? WVM_VCPU_EXIT_EXECUTOR_ERROR
            : status == WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE
                  ? WVM_VCPU_EXIT_MEMORY_ERROR
                  : WVM_VCPU_EXIT_NONE;
    result->backend = request->backend;
    result->vm_id = request->vm_id;
    result->vm_incarnation = request->vm_incarnation;
    result->manifest_generation = request->manifest_generation;
    result->origin_physical_node_id = request->origin_physical_node_id;
    result->origin_runtime_instance_id = request->origin_runtime_instance_id;
    result->vcpu_index = request->vcpu_index;
    result->handoff_sequence = request->handoff_sequence;
    memcpy(result->operation_id, request->operation_id,
           sizeof(result->operation_id));
    result->context_schema_version = request->context_schema_version;
}

static int resolve_reply_route(
    const struct bridge_state *state,
    const struct wvm_vcpu_handoff_request *request,
    struct wvm_envelope_route *route, char *error, size_t error_len)
{
    struct wvm_route_runtime_next_hop next_hop;

    if (!state || !request || !route ||
        wvm_route_runtime_lookup_destination(
            state->config.route_runtime,
            &state->config.dispatch->required_route_snapshot_key,
            request->reply_destination_kind, request->reply_destination_scope,
            request->reply_destination_vnode, &next_hop, error,
            error_len) != 0) {
        return -ESTALE;
    }
    memset(route, 0, sizeof(*route));
    route->destination_kind = request->reply_destination_kind;
    route->destination_scope = request->reply_destination_scope;
    route->destination_vnode_or_endpoint = request->reply_destination_vnode;
    route->hop_limit = next_hop.hop_limit;
    return 0;
}

static int send_typed_result(
    const struct bridge_state *state, const struct wvm_envelope *request_envelope,
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result, char *error,
    size_t error_len)
{
    struct wvm_envelope_route reply_route;
    struct wvm_envelope response;
    uint8_t *payload;
    size_t payload_bytes = 0;
    int send_result;

    if (!state || !request_envelope || !request || !result ||
        request_envelope->delivery_attempt_id == UINT64_MAX) {
        set_error(error, error_len,
                  "typed vCPU response delivery attempt is invalid");
        return -ERANGE;
    }
    if (resolve_reply_route(state, request, &reply_route, error, error_len) !=
        0) {
        return -ESTALE;
    }
    payload = malloc(WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD);
    if (!payload) {
        set_error(error, error_len, "cannot allocate typed vCPU exit payload");
        return -ENOMEM;
    }
    if (wvm_vcpu_handoff_exit_envelope_build(
            request_envelope, request, &reply_route,
            request_envelope->delivery_attempt_id + 1U, result, payload,
            WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD, &payload_bytes, &response,
            error, error_len) != 0) {
        free(payload);
        return -EINVAL;
    }
    send_result = state->config.send_envelope(
        state->config.send_envelope_opaque, &response, error, error_len);
    free(payload);
    return send_result;
}

static int cache_terminal_and_send(
    struct bridge_state *state, const struct wvm_envelope *envelope,
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result, char *error,
    size_t error_len)
{
    if (wvm_vcpu_handoff_cache_complete(
            &state->handoff_cache, request, envelope, result,
            monotonic_milliseconds(), error, error_len) != 0) {
        return -EIO;
    }
    return send_typed_result(state, envelope, request, result, error,
                             error_len);
}

static int execute_typed_task(struct bridge_state *state,
                              const struct bridge_task *task, char *error,
                              size_t error_len)
{
    struct wvm_vcpu_handoff_request request;
    struct wvm_vcpu_handoff_result result;
    uint8_t result_context[WVM_VCPU_HANDOFF_MAX_RESULT_CONTEXT_BYTES];
    int execute_result;

    if (!state || !task ||
        wvm_vcpu_handoff_request_decode(
            task->envelope.payload, task->envelope.payload_bytes, &request,
            error, error_len) != 0) {
        return -EINVAL;
    }

    if (request.backend == WVM_VCPU_BACKEND_KVM &&
        !wvm_kvm_page_cache_global_active()) {
        handoff_result_from_request(
            &request, WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE, &result);
        return cache_terminal_and_send(state, &task->envelope, &request,
                                       &result, error, error_len);
    }

    memset(&result, 0, sizeof(result));
    execute_result = state->config.execute_handoff(
        state->config.execute_handoff_opaque, &request, &result,
        result_context, sizeof(result_context), error, error_len);
    if (execute_result != 0 ||
        wvm_vcpu_handoff_result_validate_request(&request, &result, error,
                                                  error_len) != 0) {
        handoff_result_from_request(
            &request, WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE, &result);
        return cache_terminal_and_send(state, &task->envelope, &request,
                                       &result, error, error_len);
    }
    return cache_terminal_and_send(state, &task->envelope, &request, &result,
                                   error, error_len);
}

static void task_release(struct bridge_task *task)
{
    if (!task) {
        return;
    }
    free(task->payload);
    memset(task, 0, sizeof(*task));
}

static void *typed_task_worker(void *opaque)
{
    struct bridge_state *state = opaque;

    for (;;) {
        struct bridge_task task;
        char error[256] = {0};

        memset(&task, 0, sizeof(task));
        pthread_mutex_lock(&state->task_lock);
        while (!state->stopping && state->task_count == 0) {
            pthread_cond_wait(&state->task_available, &state->task_lock);
        }
        if (state->stopping) {
            pthread_mutex_unlock(&state->task_lock);
            break;
        }
        task = state->tasks[state->task_head];
        memset(&state->tasks[state->task_head], 0,
               sizeof(state->tasks[state->task_head]));
        state->task_head = (state->task_head + 1U) % state->task_capacity;
        state->task_count--;
        state->task_busy = 1;
        pthread_mutex_unlock(&state->task_lock);

        (void)execute_typed_task(state, &task, error, sizeof(error));
        task_release(&task);

        pthread_mutex_lock(&state->task_lock);
        state->task_busy = 0;
        pthread_cond_broadcast(&state->task_idle);
        pthread_mutex_unlock(&state->task_lock);
    }
    return NULL;
}

static int enqueue_typed_task(struct bridge_state *state,
                              const struct wvm_envelope *envelope)
{
    struct bridge_task task;
    size_t tail;

    memset(&task, 0, sizeof(task));
    task.payload = malloc(envelope->payload_bytes);
    if (!task.payload) {
        return -ENOMEM;
    }
    memcpy(task.payload, envelope->payload, envelope->payload_bytes);
    task.envelope = *envelope;
    task.envelope.payload = task.payload;

    pthread_mutex_lock(&state->task_lock);
    if (state->stopping || state->task_count == state->task_capacity) {
        pthread_mutex_unlock(&state->task_lock);
        task_release(&task);
        return state->stopping ? -ESHUTDOWN : -ENOBUFS;
    }
    tail = (state->task_head + state->task_count) % state->task_capacity;
    state->tasks[tail] = task;
    state->task_count++;
    pthread_cond_signal(&state->task_available);
    pthread_mutex_unlock(&state->task_lock);
    return 0;
}

int wvm_executor_bridge_dispatch(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len)
{
    struct bridge_state *state = opaque;
    struct wvm_vcpu_handoff_request request;
    struct wvm_executor_abi_frame operation;
    struct wvm_vcpu_handoff_result result;
    enum wvm_vcpu_handoff_cache_decision cache_decision;
    uint8_t *replay = NULL;
    uint64_t encoded_context_fields = 0;
    size_t replay_bytes = 0;
    int cache_result;

    if (!state || !envelope ||
        wvm_vcpu_handoff_request_decode(
            envelope->payload, envelope->payload_bytes, &request, error,
            error_len) != 0 ||
        wvm_vcpu_handoff_request_validate_envelope(
            &request, envelope, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "typed vCPU handoff input is invalid");
        }
        return -EINVAL;
    }
    if (wvm_x86_context_validate(
            request.backend, request.context, request.context_bytes,
            &encoded_context_fields, error, error_len) != 0 ||
        encoded_context_fields != request.context_valid_fields) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "typed vCPU handoff context does not match its schema");
        }
        return -EINVAL;
    }
    if (authorize_local_handoff(state, &request, envelope, error,
                                error_len) != 0) {
        return -EPERM;
    }

    memset(&operation, 0, sizeof(operation));
    operation.identity.vm_id = envelope->vm_id;
    operation.identity.vm_incarnation = envelope->vm_incarnation;
    operation.identity.manifest_generation = envelope->manifest_generation;
    operation.identity.local_runtime_instance_id =
        state->config.local_runtime_instance_id;
    memcpy(operation.identity.operation_id, envelope->operation_id,
           sizeof(operation.identity.operation_id));
    memcpy(operation.identity.candidate_manifest_digest,
           state->config.manifest->candidate_manifest_digest,
           sizeof(operation.identity.candidate_manifest_digest));
    operation.identity.route_snapshot_key.scope_key.vm_id = envelope->vm_id;
    operation.identity.route_snapshot_key.scope_key.vm_incarnation =
        envelope->vm_incarnation;
    operation.identity.route_snapshot_key.scope_key.route_scope_id =
        envelope->route_scope_id;
    operation.identity.route_snapshot_key.topology_revision =
        envelope->topology_revision;
    operation.identity.route_snapshot_key.route_generation =
        envelope->route_generation;
    memcpy(operation.identity.route_snapshot_key.snapshot_digest,
           envelope->route_snapshot_digest,
           sizeof(operation.identity.route_snapshot_key.snapshot_digest));
    memcpy(operation.identity.activation_fence,
           state->config.manifest->activation_fence,
           sizeof(operation.identity.activation_fence));
    operation.message_type = WVM_EXECUTOR_ABI_CPU_RUN;
    if (authorize_cpu_run(state, &operation, error, error_len) != 0) {
        return -EPERM;
    }

    replay = malloc(WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD);
    if (!replay) {
        set_error(error, error_len, "cannot allocate typed vCPU replay buffer");
        return -ENOMEM;
    }
    cache_result = wvm_vcpu_handoff_cache_begin(
        &state->handoff_cache, &request, envelope, monotonic_milliseconds(),
        &cache_decision, replay, WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD,
        &replay_bytes, error, error_len);
    if (cache_result == 0) {
        switch (cache_decision) {
        case WVM_VCPU_HANDOFF_CACHE_EXECUTE:
            /*
             * user_backend owns the RX buffer and releases it immediately
             * after ingress returns. The worker therefore receives an
             * immutable payload copy and never blocks the RX thread on local
             * execution or a legacy executor response.
             */
            cache_result = enqueue_typed_task(state, envelope);
            if (cache_result != 0) {
                handoff_result_from_request(
                    &request, WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE,
                    &result);
                cache_result = cache_terminal_and_send(
                    state, envelope, &request, &result, error, error_len);
            }
            free(replay);
            return cache_result;
        case WVM_VCPU_HANDOFF_CACHE_IN_PROGRESS:
            handoff_result_from_request(
                &request, WVM_VCPU_HANDOFF_RESULT_IN_PROGRESS, &result);
            cache_result = send_typed_result(state, envelope, &request, &result,
                                             error, error_len);
            free(replay);
            return cache_result;
        case WVM_VCPU_HANDOFF_CACHE_REPLAY:
            if (wvm_vcpu_handoff_result_decode(replay, replay_bytes, &result,
                                               error, error_len) != 0 ||
                wvm_vcpu_handoff_result_validate_request(
                    &request, &result, error, error_len) != 0) {
                free(replay);
                return -EPROTO;
            }
            cache_result = send_typed_result(state, envelope, &request, &result,
                                             error, error_len);
            free(replay);
            return cache_result;
        case WVM_VCPU_HANDOFF_CACHE_RESULT_EXPIRED:
            handoff_result_from_request(
                &request, WVM_VCPU_HANDOFF_RESULT_EXPIRED, &result);
            cache_result = send_typed_result(state, envelope, &request, &result,
                                             error, error_len);
            free(replay);
            return cache_result;
        default:
            free(replay);
            set_error(error, error_len,
                      "vCPU handoff cache returned an unknown decision");
            return -EPROTO;
        }
    }

    if (cache_result == -EALREADY) {
        handoff_result_from_request(&request,
                                    WVM_VCPU_HANDOFF_RESULT_IN_PROGRESS,
                                    &result);
        cache_result = send_typed_result(state, envelope, &request, &result,
                                         error, error_len);
        free(replay);
        return cache_result;
    }
    if (cache_result == -ENOSPC || cache_result == -EAGAIN ||
        cache_result == -ENOBUFS) {
        handoff_result_from_request(&request,
                                    WVM_VCPU_HANDOFF_RESULT_BACKPRESSURE,
                                    &result);
        cache_result = send_typed_result(state, envelope, &request, &result,
                                         error, error_len);
        free(replay);
        return cache_result;
    }
    free(replay);
    return cache_result;
}

int wvm_executor_bridge_dispatch_init(
    const struct wvm_executor_bridge_config *config, void **dispatch_opaque,
    char *error, size_t error_len)
{
    struct bridge_state *state;
    int initialization_result;
    int mutex_initialized = 0;
    int condition_initialized = 0;
    int idle_initialized = 0;
    int cache_initialized = 0;
    int worker_result;

    if (!dispatch_opaque) {
        set_error(error, error_len, "executor bridge dispatch output is missing");
        return -EINVAL;
    }
    *dispatch_opaque = NULL;
    if (config_is_admitted(config, error, error_len) != 0) {
        return -EINVAL;
    }
    state = calloc(1, sizeof(*state));
    if (!state) {
        set_error(error, error_len, "cannot allocate executor bridge state");
        return -ENOMEM;
    }
    state->config = *config;
    state->task_capacity =
        config->manifest->launch_plan.vcpu_handoff_record_capacity;
    state->tasks = calloc(state->task_capacity, sizeof(*state->tasks));
    if (!state->tasks) {
        initialization_result = -ENOMEM;
        set_error(error, error_len, "cannot allocate typed executor queue");
        goto fail;
    }
    initialization_result = pthread_mutex_init(&state->task_lock, NULL);
    if (initialization_result != 0) {
        initialization_result = -initialization_result;
        set_error(error, error_len, "cannot initialize typed executor lock");
        goto fail;
    }
    mutex_initialized = 1;
    initialization_result = pthread_cond_init(&state->task_available, NULL);
    if (initialization_result != 0) {
        initialization_result = -initialization_result;
        set_error(error, error_len,
                  "cannot initialize typed executor work condition");
        goto fail;
    }
    condition_initialized = 1;
    initialization_result = wvm_vcpu_handoff_cache_init(
        &state->handoff_cache, state->task_capacity,
        config->operation_retention_horizon_ms,
        WVM_ENVELOPE_MAX_NETWORK_LOGICAL_PAYLOAD, error, error_len);
    if (initialization_result != 0) {
        goto fail;
    }
    cache_initialized = 1;
    initialization_result = pthread_cond_init(&state->task_idle, NULL);
    if (initialization_result == 0) {
        idle_initialized = 1;
    }
    if (initialization_result != 0) {
        set_error(error, error_len, "cannot initialize executor idle condition");
        pthread_cond_destroy(&state->task_available);
        pthread_mutex_destroy(&state->task_lock);
        wvm_vcpu_handoff_cache_destroy(&state->handoff_cache);
        free(state);
        return -initialization_result;
    }

    worker_result = pthread_create(&state->task_worker, NULL,
                                   typed_task_worker, state);
    if (worker_result != 0) {
        set_error(error, error_len, "cannot start typed executor worker");
        initialization_result = -worker_result;
        goto fail;
    }
    state->task_worker_started = 1;
    *dispatch_opaque = state;
    return 0;

fail:
    if (cache_initialized) {
        wvm_vcpu_handoff_cache_destroy(&state->handoff_cache);
    }
    if (idle_initialized) {
        pthread_cond_destroy(&state->task_idle);
    }
    if (condition_initialized) {
        pthread_cond_destroy(&state->task_available);
    }
    if (mutex_initialized) {
        pthread_mutex_destroy(&state->task_lock);
    }
    free(state->tasks);
    free(state);
    return initialization_result;
}

void wvm_executor_bridge_dispatch_destroy(void *dispatch_opaque)
{
    struct bridge_state *state = dispatch_opaque;
    size_t i;

    if (!state) {
        return;
    }
    pthread_mutex_lock(&state->task_lock);
    state->stopping = 1;
    pthread_cond_broadcast(&state->task_available);
    pthread_mutex_unlock(&state->task_lock);
    if (state->task_worker_started) {
        pthread_join(state->task_worker, NULL);
    }
    for (i = 0; i < state->task_capacity; i++) {
        task_release(&state->tasks[i]);
    }
    wvm_vcpu_handoff_cache_destroy(&state->handoff_cache);
    pthread_cond_destroy(&state->task_idle);
    pthread_cond_destroy(&state->task_available);
    pthread_mutex_destroy(&state->task_lock);
    free(state->tasks);
    free(state);
}

int wvm_executor_bridge_dispatch_drain(void *dispatch_opaque,
                                       uint32_t timeout_ms, char *error,
                                       size_t error_len)
{
    struct bridge_state *state = dispatch_opaque;
    uint64_t start = monotonic_milliseconds();

    if (!state) {
        set_error(error, error_len, "executor bridge is not initialized");
        return -EINVAL;
    }
    for (;;) {
        int idle;

        pthread_mutex_lock(&state->task_lock);
        idle = state->task_count == 0 && !state->task_busy;
        if (idle) {
            pthread_mutex_unlock(&state->task_lock);
            return 0;
        }
        pthread_mutex_unlock(&state->task_lock);
        if (monotonic_milliseconds() - start >= timeout_ms) {
            set_error(error, error_len,
                      "executor bridge did not drain in %u ms", timeout_ms);
            return -ETIMEDOUT;
        }
        usleep(10000);
    }
}

static int authorize_cpu_run(const struct bridge_state *state,
                             const struct wvm_executor_abi_frame *request,
                             char *error, size_t error_len)
{
    struct wvm_runtime_operation operation;

    if (!state || !request) {
        return -EINVAL;
    }
    memset(&operation, 0, sizeof(operation));
    operation.connection_id = state->config.runtime_connection_id;
    operation.vm_id = request->identity.vm_id;
    operation.vm_incarnation = request->identity.vm_incarnation;
    operation.manifest_generation = request->identity.manifest_generation;
    memcpy(operation.candidate_manifest_digest,
           request->identity.candidate_manifest_digest,
           sizeof(operation.candidate_manifest_digest));
    operation.route_snapshot_key = request->identity.route_snapshot_key;
    memcpy(operation.activation_fence, request->identity.activation_fence,
           sizeof(operation.activation_fence));
    memcpy(operation.operation_id, request->identity.operation_id,
           sizeof(operation.operation_id));
    return wvm_runtime_gate_authorize(state->config.runtime_gate, &operation,
                                      error, error_len);
}

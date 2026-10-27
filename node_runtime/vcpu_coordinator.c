#define _POSIX_C_SOURCE 200809L

#include "vcpu_coordinator.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../common_include/wavevm_x86_context.h"

enum coordinator_entry_state {
    COORDINATOR_ENTRY_EMPTY = 0,
    COORDINATOR_ENTRY_REMOTE_IN_FLIGHT = 1,
    COORDINATOR_ENTRY_COMPLETED = 2,
    COORDINATOR_ENTRY_FAILED = 3,
};

struct coordinator_entry {
    enum coordinator_entry_state state;
    uint32_t vcpu_index;
    uint64_t handoff_sequence;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    uint8_t *request_payload;
    size_t request_payload_bytes;
    struct wvm_envelope request_envelope;
    uint8_t *result_payload;
    size_t result_payload_bytes;
    uint64_t retained_until_ms;
    uint64_t in_flight_deadline_ms;
    int route_ref_held;
    int timed_out;
};

struct coordinator_lane {
    int used;
    uint32_t vcpu_index;
    uint64_t next_handoff_sequence;
};

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

static uint64_t retained_until(uint64_t now_ms, uint64_t horizon_ms)
{
    return horizon_ms > UINT64_MAX - now_ms ? UINT64_MAX
                                             : now_ms + horizon_ms;
}

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    if (!bytes) {
        return 1;
    }
    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
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

static struct coordinator_entry *entries(
    const struct wvm_vcpu_handoff_coordinator *coordinator)
{
    return (struct coordinator_entry *)coordinator->entries;
}

static struct coordinator_lane *lanes(
    const struct wvm_vcpu_handoff_coordinator *coordinator)
{
    return (struct coordinator_lane *)coordinator->lanes;
}

static void entry_clear(struct coordinator_entry *entry)
{
    if (!entry) {
        return;
    }
    free(entry->request_payload);
    free(entry->result_payload);
    memset(entry, 0, sizeof(*entry));
}

/*
 * R03: an in-flight handoff pins the route scope so retirement cannot complete
 * under a send that is still outstanding. The pin is released on terminal
 * completion, on the in-flight timeout (degraded to a timed-out result), and
 * on coordinator destruction.
 */
static void entry_release_route_ref_locked(
    struct wvm_vcpu_handoff_coordinator *coordinator,
    struct coordinator_entry *entry)
{
    if (!entry || !entry->route_ref_held) {
        return;
    }
    (void)wvm_route_runtime_operation_ref_put(
        (struct wvm_route_runtime *)coordinator->config.route_runtime,
        &coordinator->config.manifest->required_route_snapshot_key.scope_key,
        NULL, 0);
    entry->route_ref_held = 0;
}

static void prune_locked(struct wvm_vcpu_handoff_coordinator *coordinator,
                         uint64_t now_ms)
{
    struct coordinator_entry *entry_array = entries(coordinator);
    size_t i;

    for (i = 0; i < coordinator->capacity; i++) {
        struct coordinator_entry *entry = &entry_array[i];

        if (entry->state == COORDINATOR_ENTRY_REMOTE_IN_FLIGHT &&
            !entry->timed_out && entry->in_flight_deadline_ms <= now_ms) {
            entry_release_route_ref_locked(coordinator, entry);
            entry->timed_out = 1;
            entry->in_flight_deadline_ms = UINT64_MAX;
            entry->retained_until_ms = retained_until(
                now_ms, coordinator->config.operation_retention_horizon_ms);
        }
        if (((entry->state == COORDINATOR_ENTRY_COMPLETED ||
              entry->state == COORDINATOR_ENTRY_FAILED) ||
             entry->timed_out) &&
            entry->retained_until_ms <= now_ms) {
            entry_clear(entry);
        }
    }
}

static int config_is_admitted(
    const struct wvm_vcpu_handoff_coordinator_config *config, char *error,
    size_t error_len)
{
    if (!config || !config->manifest || !config->runtime_gate ||
        !config->dispatch || !config->route_runtime || !config->send_envelope ||
        config->local_runtime_instance_id == 0 ||
        config->runtime_connection_id == 0 ||
        config->operation_retention_horizon_ms == 0 ||
        config->manifest->launch_plan.vcpu_handoff_record_capacity == 0 ||
        config->runtime_gate->state != WVM_RUNTIME_GATE_ACTIVE ||
        config->runtime_gate->manifest != config->manifest ||
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
                      "vCPU handoff coordinator configuration is not admitted");
        }
        return -EINVAL;
    }
    return 0;
}

static int authorize_operation(
    const struct wvm_vcpu_handoff_coordinator *coordinator,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_runtime_operation operation;

    memset(&operation, 0, sizeof(operation));
    operation.connection_id = coordinator->config.runtime_connection_id;
    operation.vm_id = coordinator->config.manifest->vm_id;
    operation.vm_incarnation = coordinator->config.manifest->vm_incarnation;
    operation.manifest_generation =
        coordinator->config.manifest->manifest_generation;
    memcpy(operation.candidate_manifest_digest,
           coordinator->config.manifest->candidate_manifest_digest,
           sizeof(operation.candidate_manifest_digest));
    operation.route_snapshot_key =
        coordinator->config.dispatch->required_route_snapshot_key;
    memcpy(operation.activation_fence,
           coordinator->config.manifest->activation_fence,
           sizeof(operation.activation_fence));
    memcpy(operation.operation_id, operation_id, sizeof(operation.operation_id));
    return wvm_runtime_gate_authorize(coordinator->config.runtime_gate,
                                      &operation, error, error_len);
}

static int resolve_route(
    const struct wvm_vcpu_handoff_coordinator *coordinator,
    const struct wvm_runtime_route_destination *destination,
    struct wvm_envelope_route *route, char *error, size_t error_len)
{
    struct wvm_route_runtime_next_hop next_hop;

    if (!destination || !route ||
        wvm_route_runtime_lookup_destination(
            coordinator->config.route_runtime,
            &coordinator->config.dispatch->required_route_snapshot_key,
            destination->destination_kind, destination->destination_scope,
            destination->destination_vnode, &next_hop, error, error_len) !=
            0) {
        return -ESTALE;
    }
    memset(route, 0, sizeof(*route));
    route->destination_kind = destination->destination_kind;
    route->destination_scope = destination->destination_scope;
    route->destination_vnode_or_endpoint = destination->destination_vnode;
    route->hop_limit = next_hop.hop_limit;
    return 0;
}

static struct coordinator_lane *find_lane_locked(
    struct wvm_vcpu_handoff_coordinator *coordinator, uint32_t vcpu_index,
    int create)
{
    struct coordinator_lane *lane_array = lanes(coordinator);
    struct coordinator_lane *free_lane = NULL;
    size_t i;

    for (i = 0; i < coordinator->capacity; i++) {
        if (lane_array[i].used && lane_array[i].vcpu_index == vcpu_index) {
            return &lane_array[i];
        }
        if (!lane_array[i].used && !free_lane) {
            free_lane = &lane_array[i];
        }
    }
    if (!create || !free_lane) {
        return NULL;
    }
    free_lane->used = 1;
    free_lane->vcpu_index = vcpu_index;
    free_lane->next_handoff_sequence = 1;
    return free_lane;
}

static struct coordinator_entry *find_operation_locked(
    struct wvm_vcpu_handoff_coordinator *coordinator, uint32_t vcpu_index,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    struct coordinator_entry *entry_array = entries(coordinator);
    size_t i;

    for (i = 0; i < coordinator->capacity; i++) {
        if (entry_array[i].state != COORDINATOR_ENTRY_EMPTY &&
            entry_array[i].vcpu_index == vcpu_index &&
            memcmp(entry_array[i].operation_id, operation_id,
                   sizeof(entry_array[i].operation_id)) == 0) {
            return &entry_array[i];
        }
    }
    return NULL;
}

static struct coordinator_entry *find_empty_locked(
    struct wvm_vcpu_handoff_coordinator *coordinator)
{
    struct coordinator_entry *entry_array = entries(coordinator);
    size_t i;

    for (i = 0; i < coordinator->capacity; i++) {
        if (entry_array[i].state == COORDINATOR_ENTRY_EMPTY) {
            return &entry_array[i];
        }
    }
    return NULL;
}

static int lane_has_inflight_locked(
    const struct wvm_vcpu_handoff_coordinator *coordinator,
    uint32_t vcpu_index)
{
    const struct coordinator_entry *entry_array = entries(coordinator);
    size_t i;

    for (i = 0; i < coordinator->capacity; i++) {
        if (entry_array[i].state == COORDINATOR_ENTRY_REMOTE_IN_FLIGHT &&
            entry_array[i].vcpu_index == vcpu_index) {
            return 1;
        }
    }
    return 0;
}

static int request_matches_submit(
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_submit *submit)
{
    return request && submit && request->backend == submit->backend &&
           request->vcpu_index == submit->vcpu_index &&
           request->memory_fence_result == submit->memory_fence_result &&
           request->memory_fence_id == submit->memory_fence_id &&
           request->local_interrupt_watermark ==
               submit->local_interrupt_watermark &&
           request->device_event_watermark == submit->device_event_watermark &&
           request->context_schema_version == submit->context_schema_version &&
           request->context_valid_fields == submit->context_valid_fields &&
           request->context_bytes == submit->context_bytes &&
           memcmp(request->operation_id, submit->operation_id,
                  sizeof(request->operation_id)) == 0 &&
           memcmp(request->context, submit->context, request->context_bytes) ==
               0;
}

static int envelope_from_projection(
    const struct wvm_vcpu_handoff_coordinator *coordinator,
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_envelope_route *route, const uint8_t *payload,
    size_t payload_bytes, struct wvm_envelope *envelope)
{
    const struct wvm_runtime_dispatch_projection *projection =
        coordinator->config.dispatch;

    if (!route || !payload || !envelope) {
        return -EINVAL;
    }
    memset(envelope, 0, sizeof(*envelope));
    envelope->message_type = WVM_ENVELOPE_MSG_VCPU_RUN;
    envelope->vm_id = projection->vm_id;
    envelope->vm_incarnation = projection->vm_incarnation;
    envelope->manifest_generation = projection->manifest_generation;
    envelope->origin_physical_node_id = projection->physical_node_id;
    envelope->origin_runtime_instance_id =
        coordinator->config.local_runtime_instance_id;
    memcpy(envelope->operation_id, request->operation_id,
           sizeof(envelope->operation_id));
    envelope->delivery_attempt_id = 1;
    envelope->route_scope_id =
        projection->required_route_snapshot_key.scope_key.route_scope_id;
    envelope->topology_revision =
        projection->required_route_snapshot_key.topology_revision;
    envelope->route_generation =
        projection->required_route_snapshot_key.route_generation;
    memcpy(envelope->route_snapshot_digest,
           projection->required_route_snapshot_key.snapshot_digest,
           sizeof(envelope->route_snapshot_digest));
    envelope->route = *route;
    envelope->payload = payload;
    envelope->payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(payload, payload_bytes,
                                 envelope->semantic_payload_digest);
    return 0;
}

static int terminal_status(uint16_t status)
{
    return status == WVM_VCPU_HANDOFF_RESULT_SUCCESS ||
           status == WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE ||
           status == WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE ||
           status == WVM_VCPU_HANDOFF_RESULT_EXPIRED;
}

int wvm_vcpu_handoff_coordinator_init(
    struct wvm_vcpu_handoff_coordinator *coordinator,
    const struct wvm_vcpu_handoff_coordinator_config *config, char *error,
    size_t error_len)
{
    size_t capacity;

    if (!coordinator || config_is_admitted(config, error, error_len) != 0) {
        return -EINVAL;
    }
    capacity = config->manifest->launch_plan.vcpu_handoff_record_capacity;
    memset(coordinator, 0, sizeof(*coordinator));
    coordinator->entries = calloc(capacity, sizeof(struct coordinator_entry));
    coordinator->lanes = calloc(capacity, sizeof(struct coordinator_lane));
    if (!coordinator->entries || !coordinator->lanes ||
        pthread_mutex_init(&coordinator->lock, NULL) != 0) {
        free(coordinator->entries);
        free(coordinator->lanes);
        memset(coordinator, 0, sizeof(*coordinator));
        set_error(error, error_len,
                  "cannot allocate vCPU handoff coordinator state");
        return -ENOMEM;
    }
    if (pthread_cond_init(&coordinator->drain_progress, NULL) != 0) {
        pthread_mutex_destroy(&coordinator->lock);
        free(coordinator->entries);
        free(coordinator->lanes);
        memset(coordinator, 0, sizeof(*coordinator));
        set_error(error, error_len,
                  "cannot allocate vCPU handoff coordinator state");
        return -ENOMEM;
    }
    coordinator->config = *config;
    coordinator->capacity = capacity;
    coordinator->completions_in_progress = 0;
    coordinator->initialized = 1;
    return 0;
}

int wvm_vcpu_handoff_coordinator_drain(
    struct wvm_vcpu_handoff_coordinator *coordinator, uint32_t timeout_ms,
    char *error, size_t error_len)
{
    struct coordinator_entry *entry_array;
    uint64_t start = monotonic_milliseconds();

    if (!coordinator || !coordinator->initialized) {
        set_error(error, error_len, "vCPU handoff coordinator is not active");
        return -EINVAL;
    }
    entry_array = entries(coordinator);
    pthread_mutex_lock(&coordinator->lock);
    for (;;) {
        size_t i;
        int active = 0;

        for (i = 0; i < coordinator->capacity; i++) {
            if (entry_array[i].state ==
                COORDINATOR_ENTRY_REMOTE_IN_FLIGHT) {
                active = 1;
                break;
            }
        }
        if (!active && coordinator->completions_in_progress == 0) {
            pthread_mutex_unlock(&coordinator->lock);
            return 0;
        }
        if (monotonic_milliseconds() - start >= timeout_ms) {
            pthread_mutex_unlock(&coordinator->lock);
            set_error(error, error_len,
                      "vCPU handoff coordinator did not drain in %u ms "
                      "(in_flight=%d completions_in_progress=%zu)",
                      timeout_ms, active,
                      coordinator->completions_in_progress);
            return -ETIMEDOUT;
        }
        {
            struct timespec abstime;
            uint64_t remaining = timeout_ms -
                                (monotonic_milliseconds() - start);
            uint64_t wait_ms = remaining < 10 ? remaining : 10;

            if (clock_gettime(CLOCK_REALTIME, &abstime) != 0) {
                pthread_mutex_unlock(&coordinator->lock);
                set_error(error, error_len,
                          "vCPU handoff drain clock_gettime failed");
                return -errno;
            }
            abstime.tv_nsec += (long)wait_ms * 1000000L;
            if (abstime.tv_nsec >= 1000000000L) {
                abstime.tv_sec += abstime.tv_nsec / 1000000000L;
                abstime.tv_nsec %= 1000000000L;
            }
            pthread_cond_timedwait(&coordinator->drain_progress,
                                  &coordinator->lock, &abstime);
        }
    }
}

void wvm_vcpu_handoff_coordinator_destroy(
    struct wvm_vcpu_handoff_coordinator *coordinator)
{
    struct coordinator_entry *entry_array;
    size_t i;

    if (!coordinator) {
        return;
    }
    entry_array = entries(coordinator);
    if (entry_array && coordinator->initialized) {
        pthread_mutex_lock(&coordinator->lock);
        for (i = 0; i < coordinator->capacity; i++) {
            entry_release_route_ref_locked(coordinator, &entry_array[i]);
        }
        pthread_mutex_unlock(&coordinator->lock);
    }
    for (i = 0; entry_array && i < coordinator->capacity; i++) {
        entry_clear(&entry_array[i]);
    }
    if (coordinator->initialized) {
        pthread_mutex_destroy(&coordinator->lock);
    pthread_cond_destroy(&coordinator->drain_progress);
    }
    free(coordinator->entries);
    free(coordinator->lanes);
    memset(coordinator, 0, sizeof(*coordinator));
}

int wvm_vcpu_handoff_coordinator_submit(
    struct wvm_vcpu_handoff_coordinator *coordinator,
    const struct wvm_vcpu_handoff_submit *submit, char *error,
    size_t error_len)
{
    const struct wvm_runtime_cpu_dispatch *cpu;
    struct coordinator_entry *entry;
    struct coordinator_lane *lane;
    struct wvm_vcpu_handoff_request decoded;
    struct wvm_vcpu_handoff_request request;
    struct wvm_envelope_route route;
    struct wvm_envelope outgoing;
    uint8_t *payload = NULL;
    size_t payload_bytes = 0;
    uint64_t encoded_context_fields = 0;
    int result;

    if (!coordinator || !coordinator->initialized || !submit ||
        submit->backend == 0 ||
        submit->memory_fence_result != WVM_VCPU_MEMORY_FENCE_SUCCEEDED ||
        submit->memory_fence_id == 0 ||
        bytes_are_zero(submit->operation_id, sizeof(submit->operation_id)) ||
        submit->backend !=
            coordinator->config.manifest->negotiated_profile.backend ||
        submit->context_schema_version !=
            coordinator->config.manifest->negotiated_profile
                .context_schema_version ||
        submit->context_valid_fields == 0 || !submit->context ||
        submit->context_bytes == 0 ||
        submit->context_bytes > WVM_VCPU_HANDOFF_MAX_CONTEXT_BYTES ||
        wvm_x86_context_validate(
            submit->backend, submit->context, submit->context_bytes,
            &encoded_context_fields, error, error_len) != 0 ||
        encoded_context_fields != submit->context_valid_fields ||
        authorize_operation(coordinator, submit->operation_id, error,
                            error_len) != 0 ||
        !(cpu = wvm_runtime_dispatch_find_cpu(coordinator->config.dispatch,
                                               submit->vcpu_index))) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "vCPU handoff submission is invalid");
        }
        return -EINVAL;
    }

    pthread_mutex_lock(&coordinator->lock);
    prune_locked(coordinator, monotonic_milliseconds());
    entry = find_operation_locked(coordinator, submit->vcpu_index,
                                  submit->operation_id);
    if (entry) {
        const struct wvm_runtime_dispatch_projection *projection =
            coordinator->config.dispatch;
        struct wvm_envelope_route refreshed_route;

        if (wvm_vcpu_handoff_request_decode(
                entry->request_payload, entry->request_payload_bytes, &decoded,
                error, error_len) != 0 ||
            !request_matches_submit(&decoded, submit)) {
            pthread_mutex_unlock(&coordinator->lock);
            set_error(error, error_len,
                      "vCPU handoff reuses operation ID with another request");
            return -EPROTO;
        }
        if (entry->state == COORDINATOR_ENTRY_COMPLETED ||
            entry->state == COORDINATOR_ENTRY_FAILED) {
            /*
             * Terminal result is retained under operation_id. A lost upper-layer
             * notification must query the cache — never mint a second sequence.
             */
            pthread_mutex_unlock(&coordinator->lock);
            set_error(error, error_len,
                      "vCPU handoff result is cached; query instead of resubmit");
            return -EALREADY;
        }
        if (entry->timed_out) {
            pthread_mutex_unlock(&coordinator->lock);
            set_error(error, error_len,
                      "vCPU handoff exceeded its in-flight deadline");
            return -ETIMEDOUT;
        }
        if (entry->state != COORDINATOR_ENTRY_REMOTE_IN_FLIGHT ||
            entry->request_envelope.delivery_attempt_id == UINT64_MAX) {
            pthread_mutex_unlock(&coordinator->lock);
            set_error(error, error_len,
                      "vCPU handoff cannot retry a completed operation");
            return -EALREADY;
        }
        /*
         * Phase 7 / identity-routing: route-generation change refreshes only the
         * forwarding key. operation_id, semantic digest, and handoff_sequence
         * stay fixed so a dropped VCPU_EXIT still completes one semantic op.
         */
        if (resolve_route(coordinator, &cpu->executor, &refreshed_route, error,
                          error_len) != 0) {
            pthread_mutex_unlock(&coordinator->lock);
            if (!error || error[0] == '\0') {
                set_error(error, error_len,
                          "vCPU handoff reroute cannot resolve destination");
            }
            return -ESTALE;
        }
        if (entry->request_envelope.delivery_attempt_id == UINT64_MAX) {
            pthread_mutex_unlock(&coordinator->lock);
            set_error(error, error_len, "vCPU handoff delivery attempts exhausted");
            return -EAGAIN;
        }
        entry->request_envelope.delivery_attempt_id++;
        entry->request_envelope.route_scope_id =
            projection->required_route_snapshot_key.scope_key.route_scope_id;
        entry->request_envelope.topology_revision =
            projection->required_route_snapshot_key.topology_revision;
        entry->request_envelope.route_generation =
            projection->required_route_snapshot_key.route_generation;
        memcpy(entry->request_envelope.route_snapshot_digest,
               projection->required_route_snapshot_key.snapshot_digest,
               sizeof(entry->request_envelope.route_snapshot_digest));
        entry->request_envelope.route = refreshed_route;
        entry->request_envelope.payload = entry->request_payload;
        entry->request_envelope.payload_bytes = entry->request_payload_bytes;
        outgoing = entry->request_envelope;
        pthread_mutex_unlock(&coordinator->lock);
        return coordinator->config.send_envelope(
            coordinator->config.send_envelope_opaque, &outgoing, error,
            error_len);
    }
    lane = find_lane_locked(coordinator, submit->vcpu_index, 1);
    entry = find_empty_locked(coordinator);
    if (!lane || !entry) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len, "vCPU handoff coordinator is full");
        return -EAGAIN;
    }
    if (lane_has_inflight_locked(coordinator, submit->vcpu_index)) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len,
                  "vCPU has a remote handoff already in flight");
        return -EALREADY;
    }
    memset(&request, 0, sizeof(request));
    request.protocol_version = WVM_VCPU_HANDOFF_REQUEST_VERSION;
    request.backend = submit->backend;
    request.context_schema_version = submit->context_schema_version;
    request.memory_fence_result = submit->memory_fence_result;
    request.vm_id = coordinator->config.manifest->vm_id;
    request.vm_incarnation = coordinator->config.manifest->vm_incarnation;
    request.manifest_generation =
        coordinator->config.manifest->manifest_generation;
    request.origin_physical_node_id =
        coordinator->config.dispatch->physical_node_id;
    request.origin_runtime_instance_id =
        coordinator->config.local_runtime_instance_id;
    request.vcpu_index = submit->vcpu_index;
    request.destination_executor_id = cpu->executor.destination_vnode;
    request.reply_destination_kind =
        coordinator->config.dispatch->local_primary.destination_kind;
    request.reply_destination_scope =
        coordinator->config.dispatch->local_primary.destination_scope;
    request.reply_destination_vnode =
        coordinator->config.dispatch->local_primary.destination_vnode;
    request.handoff_sequence = lane->next_handoff_sequence;
    request.memory_fence_id = submit->memory_fence_id;
    request.local_interrupt_watermark = submit->local_interrupt_watermark;
    request.device_event_watermark = submit->device_event_watermark;
    memcpy(request.operation_id, submit->operation_id,
           sizeof(request.operation_id));
    request.context_valid_fields = submit->context_valid_fields;
    request.context = submit->context;
    request.context_bytes = submit->context_bytes;
    if (resolve_route(coordinator, &cpu->executor, &route, error, error_len) !=
        0) {
        pthread_mutex_unlock(&coordinator->lock);
        return -ESTALE;
    }
    payload = malloc(WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES +
                     submit->context_bytes);
    if (!payload ||
        wvm_vcpu_handoff_request_encode(
            &request, payload,
            WVM_VCPU_HANDOFF_REQUEST_HEADER_BYTES + submit->context_bytes,
            &payload_bytes, error, error_len) != 0 ||
        envelope_from_projection(coordinator, &request, &route, payload,
                                 payload_bytes, &entry->request_envelope) !=
            0) {
        free(payload);
        pthread_mutex_unlock(&coordinator->lock);
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "cannot compile typed vCPU handoff");
        }
        return -EINVAL;
    }
    entry->state = COORDINATOR_ENTRY_REMOTE_IN_FLIGHT;
    entry->vcpu_index = request.vcpu_index;
    entry->handoff_sequence = request.handoff_sequence;
    memcpy(entry->operation_id, request.operation_id,
           sizeof(entry->operation_id));
    entry->request_payload = payload;
    entry->request_payload_bytes = payload_bytes;
    entry->in_flight_deadline_ms = retained_until(
        monotonic_milliseconds(),
        coordinator->config.operation_retention_horizon_ms);
    if (wvm_route_runtime_operation_ref_get(
            (struct wvm_route_runtime *)coordinator->config.route_runtime,
            &coordinator->config.manifest->required_route_snapshot_key
                 .scope_key,
            error, error_len) != 0) {
        entry_clear(entry);
        pthread_mutex_unlock(&coordinator->lock);
        return -ESTALE;
    }
    entry->route_ref_held = 1;
    lane->next_handoff_sequence++;
    outgoing = entry->request_envelope;
    pthread_mutex_unlock(&coordinator->lock);
    result = coordinator->config.send_envelope(
        coordinator->config.send_envelope_opaque, &outgoing, error, error_len);
    return result;
}

int wvm_vcpu_handoff_coordinator_dispatch(
    void *opaque, const struct wvm_envelope *envelope, char *error,
    size_t error_len)
{
    struct wvm_vcpu_handoff_coordinator *coordinator = opaque;
    struct coordinator_entry *entry;
    struct wvm_vcpu_handoff_request request;
    struct wvm_vcpu_handoff_result result;
    uint8_t *result_copy = NULL;
    uint64_t encoded_context_fields = 0;
    uint64_t now_ms;
    int complete_result = 0;

    if (!coordinator || !coordinator->initialized || !envelope ||
        envelope->message_type != WVM_ENVELOPE_MSG_VCPU_EXIT ||
        wvm_vcpu_handoff_result_decode(
            envelope->payload, envelope->payload_bytes, &result, error,
            error_len) != 0 ||
        !route_destination_equal(&coordinator->config.dispatch->local_primary,
                                 &envelope->route) ||
        authorize_operation(coordinator, envelope->operation_id, error,
                            error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "typed vCPU exit is invalid");
        }
        return -EINVAL;
    }
    if (result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS &&
        (wvm_x86_context_validate(result.backend, result.context,
                                  result.context_bytes,
                                  &encoded_context_fields, error,
                                  error_len) != 0 ||
         encoded_context_fields != result.context_valid_fields)) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "typed vCPU exit context does not match its schema");
        }
        return -EINVAL;
    }

    now_ms = monotonic_milliseconds();
    pthread_mutex_lock(&coordinator->lock);
    prune_locked(coordinator, now_ms);
    entry = find_operation_locked(coordinator, result.vcpu_index,
                                  result.operation_id);
    if (!entry ||
        wvm_vcpu_handoff_request_decode(
            entry->request_payload, entry->request_payload_bytes, &request,
            error, error_len) != 0 ||
        wvm_vcpu_handoff_exit_validate_envelope(&request, &result, envelope,
                                                error, error_len) != 0) {
        pthread_mutex_unlock(&coordinator->lock);
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "typed vCPU exit has no matching local handoff");
        }
        return -ENOENT;
    }
    if (entry->timed_out) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len,
                  "typed vCPU exit arrived after its in-flight deadline");
        return -ETIMEDOUT;
    }
    if (!terminal_status(result.status)) {
        pthread_mutex_unlock(&coordinator->lock);
        return 0;
    }
    if (entry->state == COORDINATOR_ENTRY_COMPLETED ||
        entry->state == COORDINATOR_ENTRY_FAILED) {
        int same_result = entry->result_payload_bytes == envelope->payload_bytes &&
                          entry->result_payload &&
                          memcmp(entry->result_payload, envelope->payload,
                                 envelope->payload_bytes) == 0;

        pthread_mutex_unlock(&coordinator->lock);
        if (!same_result) {
            set_error(error, error_len,
                      "typed vCPU exit conflicts with completed handoff");
            return -EPROTO;
        }
        return 0;
    }
    if (entry->state != COORDINATOR_ENTRY_REMOTE_IN_FLIGHT) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len, "typed vCPU handoff is not active");
        return -EPROTO;
    }
    result_copy = malloc(envelope->payload_bytes);
    if (!result_copy) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len, "cannot retain typed vCPU exit");
        return -ENOMEM;
    }
    memcpy(result_copy, envelope->payload, envelope->payload_bytes);
    entry->result_payload = result_copy;
    entry->result_payload_bytes = envelope->payload_bytes;
    entry->retained_until_ms = retained_until(
        now_ms, coordinator->config.operation_retention_horizon_ms);
    entry->state = result.status == WVM_VCPU_HANDOFF_RESULT_SUCCESS
                       ? COORDINATOR_ENTRY_COMPLETED
                       : COORDINATOR_ENTRY_FAILED;
    entry_release_route_ref_locked(coordinator, entry);
    complete_result = coordinator->config.complete != NULL;
    if (complete_result) {
        /*
         * Flip out of REMOTE_IN_FLIGHT before the callback so a concurrent
         * drain cannot observe "idle" while complete() still touches the
         * service/opaque. Drain waits on completions_in_progress too.
         */
        coordinator->completions_in_progress++;
    }
    pthread_mutex_unlock(&coordinator->lock);

    if (complete_result) {
        int complete_rc = coordinator->config.complete(
            coordinator->config.complete_opaque, &request, &result, error,
            error_len);

        pthread_mutex_lock(&coordinator->lock);
        if (coordinator->completions_in_progress > 0) {
            coordinator->completions_in_progress--;
        }
        /*
         * G5: keep the terminal record through operation_retention_horizon_ms.
         * complete() only queues the ACK; duplicate exits, lookup_completed, and
         * resubmit-as-EALREADY all need the cached result. Capacity pressure is
         * handled by prune_locked + submit backpressure (-EAGAIN when full);
         * production profiles publish a large vcpu_handoff_record_capacity.
         */
        pthread_cond_broadcast(&coordinator->drain_progress);
        pthread_mutex_unlock(&coordinator->lock);
        return complete_rc;
    }
    pthread_mutex_lock(&coordinator->lock);
    pthread_cond_broadcast(&coordinator->drain_progress);
    pthread_mutex_unlock(&coordinator->lock);
    return 0;
}

int wvm_vcpu_handoff_coordinator_lookup_completed(
    struct wvm_vcpu_handoff_coordinator *coordinator, uint32_t vcpu_index,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    struct wvm_vcpu_handoff_request *request_out,
    struct wvm_vcpu_handoff_result *result_out, char *error, size_t error_len)
{
    struct coordinator_entry *entry;

    if (!coordinator || !coordinator->initialized || !operation_id ||
        !request_out || !result_out) {
        set_error(error, error_len, "vCPU handoff lookup arguments are invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&coordinator->lock);
    prune_locked(coordinator, monotonic_milliseconds());
    entry = find_operation_locked(coordinator, vcpu_index, operation_id);
    if (!entry) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len, "vCPU handoff operation is unknown");
        return -ENOENT;
    }
    if (entry->timed_out) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len,
                  "vCPU handoff exceeded its in-flight deadline");
        return -ETIMEDOUT;
    }
    if (entry->state == COORDINATOR_ENTRY_REMOTE_IN_FLIGHT) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len, "vCPU handoff operation is still in flight");
        return -EINPROGRESS;
    }
    if (entry->state != COORDINATOR_ENTRY_COMPLETED &&
        entry->state != COORDINATOR_ENTRY_FAILED) {
        pthread_mutex_unlock(&coordinator->lock);
        set_error(error, error_len, "vCPU handoff operation has no cached result");
        return -ENOENT;
    }
    if (wvm_vcpu_handoff_request_decode(entry->request_payload,
                                        entry->request_payload_bytes,
                                        request_out, error, error_len) != 0 ||
        wvm_vcpu_handoff_result_decode(entry->result_payload,
                                       entry->result_payload_bytes, result_out,
                                       error, error_len) != 0) {
        pthread_mutex_unlock(&coordinator->lock);
        return -EPROTO;
    }
    pthread_mutex_unlock(&coordinator->lock);
    return 0;
}

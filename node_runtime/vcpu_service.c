#define _POSIX_C_SOURCE 200809L

#include "vcpu_service.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../common_include/wavevm_x86_context.h"

enum vcpu_service_entry_state {
    VCPU_SERVICE_ENTRY_EMPTY = 0,
    VCPU_SERVICE_ENTRY_PENDING = 1,
    VCPU_SERVICE_ENTRY_REPLY_QUEUED = 2,
};

struct vcpu_service_entry {
    enum vcpu_service_entry_state state;
    int qemu_fd;
    struct wvm_ipc_cpu_run_req legacy_request;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_ipc_cpu_run_ack reply;
};

static struct {
    pthread_mutex_t lock;
    struct wvm_vcpu_service *service;
} g_global_vcpu_service = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
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

static struct vcpu_service_entry *entries(
    const struct wvm_vcpu_service *service)
{
    return (struct vcpu_service_entry *)service->entries;
}

static void entry_clear(struct vcpu_service_entry *entry)
{
    if (!entry) {
        return;
    }
    if (entry->qemu_fd >= 0) {
        close(entry->qemu_fd);
    }
    memset(entry, 0, sizeof(*entry));
    entry->qemu_fd = -1;
}

static struct vcpu_service_entry *find_empty_locked(
    struct wvm_vcpu_service *service)
{
    struct vcpu_service_entry *entry_array = entries(service);
    size_t i;

    for (i = 0; i < service->capacity; i++) {
        if (entry_array[i].state == VCPU_SERVICE_ENTRY_EMPTY) {
            return &entry_array[i];
        }
    }
    return NULL;
}

static struct vcpu_service_entry *find_operation_locked(
    struct wvm_vcpu_service *service, uint32_t vcpu_index,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    struct vcpu_service_entry *entry_array = entries(service);
    size_t i;

    for (i = 0; i < service->capacity; i++) {
        if (entry_array[i].state != VCPU_SERVICE_ENTRY_EMPTY &&
            entry_array[i].legacy_request.vcpu_index == vcpu_index &&
            memcmp(entry_array[i].operation_id, operation_id,
                   sizeof(entry_array[i].operation_id)) == 0) {
            return &entry_array[i];
        }
    }
    return NULL;
}

static struct vcpu_service_entry *find_reply_locked(
    struct wvm_vcpu_service *service)
{
    struct vcpu_service_entry *entry_array = entries(service);
    size_t i;

    for (i = 0; i < service->capacity; i++) {
        if (entry_array[i].state == VCPU_SERVICE_ENTRY_REPLY_QUEUED) {
            return &entry_array[i];
        }
    }
    return NULL;
}

static int write_reply(int fd, const struct wvm_ipc_cpu_run_ack *reply)
{
    const uint8_t *bytes = (const uint8_t *)reply;
    size_t written = 0;

    if (fd < 0 || !reply) {
        return -EINVAL;
    }
    while (written < sizeof(*reply)) {
        ssize_t result = send(fd, bytes + written, sizeof(*reply) - written,
                              MSG_NOSIGNAL | MSG_DONTWAIT);

        if (result > 0) {
            written += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pollfd = {
                .fd = fd,
                .events = POLLOUT,
            };

            if (poll(&pollfd, 1, -1) > 0) {
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
        }
        return result < 0 ? -errno : -EPIPE;
    }
    return 0;
}

static void *reply_worker(void *opaque)
{
    struct wvm_vcpu_service *service = opaque;

    for (;;) {
        struct vcpu_service_entry *entry;
        struct wvm_ipc_cpu_run_ack reply;
        int qemu_fd;

        pthread_mutex_lock(&service->lock);
        while (!service->stopping &&
               (entry = find_reply_locked(service)) == NULL) {
            pthread_cond_wait(&service->reply_available, &service->lock);
        }
        if (service->stopping) {
            pthread_mutex_unlock(&service->lock);
            break;
        }
        qemu_fd = entry->qemu_fd;
        reply = entry->reply;
        entry->qemu_fd = -1;
        memset(entry, 0, sizeof(*entry));
        entry->qemu_fd = -1;
        pthread_mutex_unlock(&service->lock);

        (void)write_reply(qemu_fd, &reply);
        close(qemu_fd);
    }
    return NULL;
}

static void make_operation_identity(struct wvm_vcpu_service *service,
                                    uint8_t operation_id
                                        [WVM_IDENTITY_ID_BYTES],
                                    uint64_t *memory_fence_id)
{
    uint64_t sequence;

    sequence = service->next_operation_sequence++;
    if (sequence == 0) {
        sequence = service->next_operation_sequence++;
    }
    memcpy(operation_id, &service->operation_epoch,
           sizeof(service->operation_epoch));
    memcpy(operation_id + sizeof(service->operation_epoch), &sequence,
           sizeof(sequence));
    *memory_fence_id = sequence;
}

static uint16_t backend_from_legacy_request(
    const struct wvm_ipc_cpu_run_req *request)
{
    return request->mode_tcg ? WVM_VCPU_BACKEND_TCG : WVM_VCPU_BACKEND_KVM;
}

static uint64_t context_fields_for_legacy_request(
    const struct wvm_ipc_cpu_run_req *request)
{
    uint64_t fields = WVM_VCPU_CONTEXT_FIELD_ARCHITECTURAL_STATE;

    if (request->mode_tcg || request->ctx.kvm.lapic_valid ||
        request->ctx.kvm.vcpu_events_valid) {
        fields |= WVM_VCPU_CONTEXT_FIELD_INTERRUPT_STATE;
    }
    if (request->mode_tcg || request->ctx.kvm.tsc_valid) {
        fields |= WVM_VCPU_CONTEXT_FIELD_TIMER_STATE;
    }
    return fields;
}

static int legacy_status_from_result(
    const struct wvm_vcpu_handoff_result *result)
{
    switch (result->status) {
    case WVM_VCPU_HANDOFF_RESULT_SUCCESS:
        return 0;
    case WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE:
        return -EFAULT;
    case WVM_VCPU_HANDOFF_RESULT_EXECUTOR_FAILURE:
        return -EIO;
    case WVM_VCPU_HANDOFF_RESULT_EXPIRED:
        return -ETIMEDOUT;
    default:
        return -EPROTO;
    }
}

static int reply_from_result(
    const struct vcpu_service_entry *entry,
    const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result,
    struct wvm_ipc_cpu_run_ack *reply, char *error, size_t error_len)
{
    uint64_t valid_fields = 0;
    size_t legacy_bytes;
    void *legacy_context;

    if (!entry || !request || !result || !reply ||
        entry->legacy_request.vcpu_index != request->vcpu_index ||
        entry->legacy_request.mode_tcg !=
            (request->backend == WVM_VCPU_BACKEND_TCG) ||
        memcmp(entry->operation_id, request->operation_id,
               sizeof(entry->operation_id)) != 0) {
        set_error(error, error_len,
                  "typed vCPU completion does not match local IPC request");
        return -EPROTO;
    }
    memset(reply, 0, sizeof(*reply));
    reply->status = legacy_status_from_result(result);
    reply->mode_tcg = entry->legacy_request.mode_tcg;
    reply->error_gpa = result->error_gpa;
    if (reply->status != 0) {
        return 0;
    }

    legacy_bytes = wvm_x86_context_legacy_bytes(request->backend);
    legacy_context = request->backend == WVM_VCPU_BACKEND_TCG
                         ? (void *)&reply->ctx.tcg
                         : (void *)&reply->ctx.kvm;
    if (legacy_bytes == 0 ||
        wvm_x86_context_decode(request->backend, result->context,
                               result->context_bytes, &valid_fields,
                               legacy_context, legacy_bytes, error,
                               error_len) != 0 ||
        valid_fields != result->context_valid_fields) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len,
                      "typed vCPU completion context cannot populate QEMU ACK");
        }
        return -EPROTO;
    }
    return 0;
}

int wvm_vcpu_service_init(struct wvm_vcpu_service *service,
                          const struct wvm_vcpu_service_config *config,
                          char *error, size_t error_len)
{
    struct timespec now;
    int worker_started = 0;

    if (!service || !config || !config->coordinator ||
        !config->coordinator->initialized || config->record_capacity == 0) {
        set_error(error, error_len, "vCPU service configuration is invalid");
        return -EINVAL;
    }
    memset(service, 0, sizeof(*service));
    service->entries = calloc(config->record_capacity,
                              sizeof(struct vcpu_service_entry));
    if (!service->entries ||
        pthread_mutex_init(&service->lock, NULL) != 0 ||
        pthread_cond_init(&service->reply_available, NULL) != 0) {
        free(service->entries);
        memset(service, 0, sizeof(*service));
        set_error(error, error_len, "cannot allocate vCPU service state");
        return -ENOMEM;
    }
    service->config = *config;
    service->capacity = config->record_capacity;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        service->operation_epoch =
            ((uint64_t)now.tv_sec << 32) ^ (uint64_t)now.tv_nsec ^
            ((uint64_t)getpid() << 16);
    }
    if (service->operation_epoch == 0) {
        service->operation_epoch = 1;
    }
    service->next_operation_sequence = 1;
    {
        size_t i;
        struct vcpu_service_entry *entry_array = entries(service);

        for (i = 0; i < service->capacity; i++) {
            entry_array[i].qemu_fd = -1;
        }
    }
    service->initialized = 1;
    if (pthread_create(&service->reply_thread, NULL, reply_worker, service) ==
        0) {
        worker_started = 1;
    }
    if (!worker_started) {
        service->initialized = 0;
        pthread_cond_destroy(&service->reply_available);
        pthread_mutex_destroy(&service->lock);
        free(service->entries);
        memset(service, 0, sizeof(*service));
        set_error(error, error_len, "cannot start vCPU reply worker");
        return -errno;
    }
    return 0;
}

void wvm_vcpu_service_destroy(struct wvm_vcpu_service *service)
{
    struct vcpu_service_entry *entry_array;
    size_t i;

    if (!service || !service->initialized) {
        return;
    }
    pthread_mutex_lock(&service->lock);
    service->stopping = 1;
    pthread_cond_broadcast(&service->reply_available);
    pthread_mutex_unlock(&service->lock);
    pthread_join(service->reply_thread, NULL);

    entry_array = entries(service);
    for (i = 0; i < service->capacity; i++) {
        entry_clear(&entry_array[i]);
    }
    pthread_cond_destroy(&service->reply_available);
    pthread_mutex_destroy(&service->lock);
    free(service->entries);
    memset(service, 0, sizeof(*service));
}

int wvm_vcpu_service_submit(struct wvm_vcpu_service *service, int qemu_fd,
                            const struct wvm_ipc_cpu_run_req *request,
                            char *error, size_t error_len)
{
    struct vcpu_service_entry *entry;
    struct wvm_vcpu_handoff_submit submit;
    uint8_t context[WVM_X86_CONTEXT_WIRE_HEADER_BYTES +
                    sizeof(((struct wvm_ipc_cpu_run_req *)0)->ctx)];
    uint16_t backend;
    uint64_t memory_fence_id;
    size_t legacy_bytes;
    size_t context_bytes = 0;
    const void *legacy_context;
    int duplicated_fd;
    int result;

    if (!service || !service->initialized || qemu_fd < 0 || !request ||
        request->mode_tcg > 1) {
        set_error(error, error_len, "local vCPU IPC request is invalid");
        return -EINVAL;
    }
    backend = backend_from_legacy_request(request);
    legacy_bytes = wvm_x86_context_legacy_bytes(backend);
    legacy_context = backend == WVM_VCPU_BACKEND_TCG
                         ? (const void *)&request->ctx.tcg
                         : (const void *)&request->ctx.kvm;
    if (legacy_bytes == 0 ||
        wvm_x86_context_encode(
            backend, context_fields_for_legacy_request(request),
            legacy_context, legacy_bytes, context, sizeof(context),
            &context_bytes, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "cannot encode local x86 vCPU context");
        }
        return -EPROTO;
    }
    duplicated_fd = dup(qemu_fd);
    if (duplicated_fd < 0) {
        set_error(error, error_len, "cannot retain QEMU IPC reply channel");
        return -errno;
    }

    pthread_mutex_lock(&service->lock);
    entry = find_empty_locked(service);
    if (!entry || service->stopping) {
        int stopping = service->stopping;

        pthread_mutex_unlock(&service->lock);
        close(duplicated_fd);
        set_error(error, error_len,
                  stopping ? "vCPU service is stopping"
                           : "vCPU service is at capacity");
        return stopping ? -ESHUTDOWN : -EAGAIN;
    }
    memset(entry, 0, sizeof(*entry));
    entry->qemu_fd = duplicated_fd;
    entry->legacy_request = *request;
    make_operation_identity(service, entry->operation_id, &memory_fence_id);
    service->last_memory_fence_id = memory_fence_id;
    entry->state = VCPU_SERVICE_ENTRY_PENDING;
    memset(&submit, 0, sizeof(submit));
    submit.backend = backend;
    submit.vcpu_index = request->vcpu_index;
    submit.memory_fence_result = WVM_VCPU_MEMORY_FENCE_SUCCEEDED;
    submit.memory_fence_id = memory_fence_id;
    submit.context_schema_version = WVM_VCPU_CONTEXT_SCHEMA_X86;
    submit.context_valid_fields = context_fields_for_legacy_request(request);
    memcpy(submit.operation_id, entry->operation_id,
           sizeof(submit.operation_id));
    submit.context = context;
    submit.context_bytes = context_bytes;
    pthread_mutex_unlock(&service->lock);

    /*
     * This call follows the master IPC connection's dirty-commit drain. Its
     * freshly generated nonzero fence therefore names that exact local memory
     * boundary, rather than an arbitrary timer or target-node value.
     */
    result = wvm_vcpu_handoff_coordinator_submit(
        service->config.coordinator, &submit, error, error_len);
    if (result != 0) {
        pthread_mutex_lock(&service->lock);
        entry = find_operation_locked(service, request->vcpu_index,
                                      submit.operation_id);
        if (entry && entry->state == VCPU_SERVICE_ENTRY_PENDING) {
            entry_clear(entry);
        }
        pthread_mutex_unlock(&service->lock);
    }
    return result;
}

int wvm_vcpu_service_complete(
    void *opaque, const struct wvm_vcpu_handoff_request *request,
    const struct wvm_vcpu_handoff_result *result, char *error,
    size_t error_len)
{
    struct wvm_vcpu_service *service = opaque;
    struct vcpu_service_entry *entry;
    struct wvm_ipc_cpu_run_ack reply;
    int reply_result;

    if (!service || !service->initialized || !request || !result) {
        set_error(error, error_len, "vCPU service completion input is invalid");
        return -EINVAL;
    }
    pthread_mutex_lock(&service->lock);
    entry = find_operation_locked(service, request->vcpu_index,
                                  request->operation_id);
    if (!entry || entry->state != VCPU_SERVICE_ENTRY_PENDING) {
        pthread_mutex_unlock(&service->lock);
        set_error(error, error_len,
                  "typed vCPU completion has no pending QEMU IPC request");
        return -ENOENT;
    }
    reply_result = reply_from_result(entry, request, result, &reply, error,
                                     error_len);
    if (reply_result != 0) {
        memset(&reply, 0, sizeof(reply));
        reply.status = reply_result;
        reply.mode_tcg = entry->legacy_request.mode_tcg;
        reply.error_gpa = result->error_gpa;
    }
    entry->reply = reply;
    entry->state = VCPU_SERVICE_ENTRY_REPLY_QUEUED;
    pthread_cond_signal(&service->reply_available);
    pthread_mutex_unlock(&service->lock);
    return 0;
}

int wvm_vcpu_service_global_install(struct wvm_vcpu_service *service,
                                    char *error, size_t error_len)
{
    if (!service || !service->initialized) {
        set_error(error, error_len,
                  "cannot install an uninitialized vCPU service");
        return -EINVAL;
    }
    pthread_mutex_lock(&g_global_vcpu_service.lock);
    if (g_global_vcpu_service.service) {
        pthread_mutex_unlock(&g_global_vcpu_service.lock);
        set_error(error, error_len, "vCPU service is already installed");
        return -EALREADY;
    }
    g_global_vcpu_service.service = service;
    pthread_mutex_unlock(&g_global_vcpu_service.lock);
    return 0;
}

void wvm_vcpu_service_global_uninstall(struct wvm_vcpu_service *service)
{
    pthread_mutex_lock(&g_global_vcpu_service.lock);
    if (g_global_vcpu_service.service == service) {
        g_global_vcpu_service.service = NULL;
    }
    pthread_mutex_unlock(&g_global_vcpu_service.lock);
}

int wvm_vcpu_service_global_submit(
    int qemu_fd, const struct wvm_ipc_cpu_run_req *request, char *error,
    size_t error_len)
{
    struct wvm_vcpu_service *service;

    pthread_mutex_lock(&g_global_vcpu_service.lock);
    service = g_global_vcpu_service.service;
    pthread_mutex_unlock(&g_global_vcpu_service.lock);
    if (!service) {
        set_error(error, error_len, "typed vCPU service is not installed");
        return -ENOTCONN;
    }
    return wvm_vcpu_service_submit(service, qemu_fd, request, error,
                                   error_len);
}

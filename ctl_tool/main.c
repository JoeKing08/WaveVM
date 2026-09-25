#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../common_include/wavevm_canonical.h"
#include "../common_include/wavevm_control_plane.h"
#include "../common_include/wavevm_control_service.h"
#include "../common_include/wavevm_admission_orchestrator.h"
#include "../common_include/wavevm_admission_authority_owner.h"
#include "../common_include/wavevm_admission_provider.h"
#include "../common_include/wavevm_admission_route.h"
#include "../common_include/wavevm_coordinator.h"
#include "../common_include/wavevm_fault_engine.h"
#include "../common_include/wavevm_runtime_gate.h"
#include "../common_include/wavevm_sha256.h"
#include "../common_include/wavevm_admission_stream_transport.h"
#include "../common_include/wavevm_unix_control_connector.h"
#include "admission_workspace.h"
#include "admission_readiness.h"
#include "capability_publication.h"
#include "runtime_profile_publication.h"

struct local_authentication;

/* Admission authority workspace owned by the control-plane service. */
struct admission_workspace {
    struct wvm_admission_evidence_owner evidence_owner;
    struct wvm_admission_plan_provider plan_provider;
    struct wvm_admission_route_compiler route_compiler;
    struct wvm_admission_transport transport;
    struct wvm_unix_control_connector unix_connector;
    struct wvm_control_stream_connector control_connector;
    struct wvm_admission_stream_transport stream_transport;
    struct wvm_admission_authority_owner authority_owner;
    struct wvm_membership_controller_capture membership_capture;
    struct wvm_coordinator_prepared_route prepared_route;
    struct wvm_coordinator_prepared_vm prepared_vm;
    struct wvm_activation_record activation;
    struct wvm_route_transaction_record route_transaction;
    struct wvm_route_snapshot_record route_snapshot;
    struct wvm_ctl_admission_buffers transaction_buffers;
    struct wvm_membership_controller *membership_controller;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    const char *state_directory;
    struct wvm_ctl_capability_evidence capability_evidence;
    struct wvm_ctl_runtime_profile_set runtime_profile_set;
    struct wvm_capability_ref *profile_capabilities;
    struct wvm_exclusive_lease *lease_storage;
    struct wvm_resource_reservation *reservations;
    struct wvm_coordinator_node_launch_plan *launch_plans;
    struct wvm_admission_node_listener_plan *listener_plans;
    struct wvm_route_rule_record *route_rules;
    struct wvm_required_ack_entry *route_ack_entries;
    struct wvm_node_record *capture_nodes;
    struct wvm_gateway_record *capture_gateways;
    uint32_t *capture_hosted_gateways;
    uint32_t *capture_parent_gateways;
    uint32_t *capture_child_gateways;
    uint8_t *route_snapshot_bytes;
    uint8_t *route_ack_set_bytes;
    size_t capacity;
    size_t route_snapshot_bytes_capacity;
    size_t route_ack_set_bytes_capacity;
    int initialized;
};

struct control_context {
    struct wvm_control_plane *plane;
    const char *state_directory;
    struct wvm_vm_namespace_allocator *namespace_allocator;
    size_t request_list_capacity;
    pthread_mutex_t lock;
    int lock_initialized;
};

struct local_principal {
    uid_t uid;
    struct wvm_member_key member_key;
};

struct local_authentication {
    struct local_principal *principals;
    size_t count;
};

struct service_options {
    const char *state_directory;
    const char *socket_path;
    const char *principal_file;
    uint32_t local_physical_node_id;
    uint64_t local_runtime_instance_id;
    size_t capacity;
};

static int read_random_bytes(uint8_t *bytes, size_t byte_count, char *error,
                             size_t error_len)
{
    size_t offset = 0;
    int fd;

    if (!bytes || byte_count == 0) {
        return -1;
    }
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(error, error_len, "cannot open random source: %s",
                 strerror(errno));
        return -1;
    }
    while (offset < byte_count) {
        ssize_t received = read(fd, bytes + offset, byte_count - offset);

        if (received > 0) {
            offset += (size_t)received;
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            snprintf(error, error_len, "cannot read random source: %s",
                     received == 0 ? "unexpected EOF" : strerror(errno));
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
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

static int id16_in_use(const struct control_context *context,
                       const uint8_t id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!context || !context->plane || !id) {
        return 1;
    }
    for (i = 0; i < context->plane->entry_count; i++) {
        const struct wvm_admission_transaction_record *transaction =
            &context->plane->entries[i].transaction;

        if (memcmp(transaction->admission_tx_id, id, WVM_IDENTITY_ID_BYTES) ==
                0 ||
            memcmp(transaction->manifest_id, id, WVM_IDENTITY_ID_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

static int route_scope_in_use(const struct control_context *context,
                              uint64_t route_scope_id)
{
    size_t i;

    if (!context || !context->plane || route_scope_id == 0) {
        return 1;
    }
    for (i = 0; i < context->plane->entry_count; i++) {
        if (context->plane->entries[i].transaction.route_scope_key
                .route_scope_id == route_scope_id) {
            return 1;
        }
    }
    return 0;
}

static int allocate_random_id16(void *opaque,
                                enum wvm_coordinator_id_purpose purpose,
                                uint8_t id[WVM_IDENTITY_ID_BYTES], char *error,
                                size_t error_len)
{
    struct control_context *context = opaque;
    size_t i;

    (void)purpose;
    for (i = 0; i < 64; i++) {
        if (read_random_bytes(id, WVM_IDENTITY_ID_BYTES, error, error_len) !=
            0) {
            return -1;
        }
        if (!bytes_are_zero(id, WVM_IDENTITY_ID_BYTES) &&
            !id16_in_use(context, id)) {
            return 0;
        }
    }
    snprintf(error, error_len, "random ID source returned only conflicting IDs");
    return -1;
}

static int allocate_random_route_scope_id(void *opaque, uint64_t *route_scope_id,
                                           char *error, size_t error_len)
{
    struct control_context *context = opaque;
    size_t i;

    if (!route_scope_id) {
        return -1;
    }
    for (i = 0; i < 64; i++) {
        if (read_random_bytes((uint8_t *)route_scope_id,
                              sizeof(*route_scope_id), error, error_len) != 0) {
            return -1;
        }
        if (!route_scope_in_use(context, *route_scope_id)) {
            return 0;
        }
    }
    snprintf(error, error_len, "random source returned conflicting route scopes");
    return -1;
}

static void initialize_control_result(
    const struct wvm_envelope *request, uint16_t status,
    struct wvm_control_result *result)
{
    memset(result, 0, sizeof(*result));
    result->status_code = status;
    if (request) {
        memcpy(result->in_reply_to_operation_id, request->operation_id,
               sizeof(result->in_reply_to_operation_id));
        memcpy(result->record_digest, request->semantic_payload_digest,
               sizeof(result->record_digest));
    }
}

static int apply_create_vm(void *opaque, const struct wvm_envelope *request,
                           const struct wvm_member_key *authenticated_actor,
                           struct wvm_control_result *result, char *error,
                           size_t error_len)
{
    struct control_context *context = opaque;
    struct wvm_host_constraint *constraints = NULL;
    struct wvm_storage_assignment *storage_assignments = NULL;
    struct wvm_vm_request vm_request;
    struct wvm_coordinator_transaction transaction;
    struct wvm_admission_orchestrator_input admission_input;
    const struct wvm_admission_authority *admission_authority;
    struct wvm_coordinator_id_provider id_provider;
    enum wvm_control_plane_submit_result submit_result;
    const struct wvm_control_plane_entry *entry;
    size_t list_capacity;
    enum wvm_control_plane_request_disposition request_disposition;
    int admission_result;

    if (!result) {
        snprintf(error, error_len, "CREATE_VM result storage is missing");
        return -EINVAL;
    }
    initialize_control_result(request, WVM_CONTROL_RESULT_INTERNAL_FAILURE,
                              result);
    if (!context || !context->plane || !context->namespace_allocator ||
        !request || !authenticated_actor ||
        authenticated_actor->role_type != WVM_MANIFEST_ROLE_EXECUTOR ||
        wvm_member_key_validate(authenticated_actor, error, error_len) != 0) {
        result->status_code = WVM_CONTROL_RESULT_UNAUTHORIZED_ROLE;
        return 0;
    }
    if (request->message_type != WVM_ENVELOPE_MSG_CREATE_VM ||
        request->vm_id != 0 || request->vm_incarnation != 0 ||
        request->manifest_generation != 0 ||
        request->payload_bytes == 0) {
        result->status_code = WVM_CONTROL_RESULT_INVALID_ENVELOPE;
        return 0;
    }
    list_capacity = context->request_list_capacity;
    if (list_capacity == 0 ||
        list_capacity > SIZE_MAX / sizeof(*constraints) ||
        list_capacity > SIZE_MAX / sizeof(*storage_assignments)) {
        result->status_code = WVM_CONTROL_RESULT_BACKPRESSURE;
        return 0;
    }
    constraints = calloc(list_capacity, sizeof(*constraints));
    storage_assignments = calloc(list_capacity, sizeof(*storage_assignments));
    if (!constraints || !storage_assignments) {
        free(storage_assignments);
        free(constraints);
        snprintf(error, error_len, "cannot allocate VM request decode storage");
        return -ENOMEM;
    }
    memset(&vm_request, 0, sizeof(vm_request));
    vm_request.host_constraints.entries = constraints;
    vm_request.host_constraints.capacity = list_capacity;
    vm_request.storage_device_plan.assignments.entries = storage_assignments;
    vm_request.storage_device_plan.assignments.capacity = list_capacity;
    if (wvm_vm_request_decode(request->payload, request->payload_bytes,
                              &vm_request, error, error_len) != 0) {
        result->status_code = WVM_CONTROL_RESULT_INVALID_REQUEST;
        free(storage_assignments);
        free(constraints);
        return 0;
    }
    memset(&id_provider, 0, sizeof(id_provider));
    id_provider.context = context;
    id_provider.allocate_id16 = allocate_random_id16;
    id_provider.allocate_route_scope_id = allocate_random_route_scope_id;
    memset(&admission_input, 0, sizeof(admission_input));
    admission_input.control_plane = context->plane;
    admission_input.namespace_allocator = context->namespace_allocator;
    admission_input.id_provider = &id_provider;
    admission_input.request = &vm_request;
    admission_authority = context->plane->admission_authority;
    if (admission_authority) {
        admission_input.membership_controller =
            &context->plane->membership_controller;
        admission_input.callbacks = &admission_authority->callbacks;
        admission_input.callback_context = admission_authority->context;
        admission_input.prepare_input = admission_authority->prepare_input;
        admission_input.prepare_input_context = admission_authority->context;
        admission_input.refresh_input = admission_authority->refresh_input;
        admission_input.refresh_input_context = admission_authority->context;
    }
    admission_input.transaction_out = &transaction;
    admission_input.submit_result_out = &submit_result;
    pthread_mutex_lock(&context->lock);
    if (wvm_control_plane_classify_request(
            context->plane, &vm_request, &request_disposition, error,
            error_len) != 0) {
        pthread_mutex_unlock(&context->lock);
        free(storage_assignments);
        free(constraints);
        return -EIO;
    }
    if (request_disposition == WVM_CONTROL_PLANE_REQUEST_CONFLICT) {
        pthread_mutex_unlock(&context->lock);
        result->status_code = WVM_CONTROL_RESULT_OPERATION_ID_CONFLICT;
        free(storage_assignments);
        free(constraints);
        return 0;
    }
    admission_result =
        wvm_admission_orchestrator_run(&admission_input, error, error_len);
    entry =
        wvm_control_plane_find_request(context->plane, vm_request.request_id);
    if (admission_result == 0 &&
        request_disposition == WVM_CONTROL_PLANE_REQUEST_REPLAY &&
        entry && entry->transaction.state == WVM_LIFECYCLE_COMMITTED &&
        admission_authority) {
        admission_result = wvm_ctl_resume_runtime_readiness(
            context->plane, &transaction, list_capacity,
            vm_request.requested_vcpus,
            admission_authority->callbacks.participant_ready,
            admission_authority->context, error, error_len);
    }
    if (!entry && context->plane->entry_count == context->plane->entry_capacity) {
        pthread_mutex_unlock(&context->lock);
        result->status_code = WVM_CONTROL_RESULT_BACKPRESSURE;
        free(storage_assignments);
        free(constraints);
        return 0;
    }
    if (!entry) {
        pthread_mutex_unlock(&context->lock);
        snprintf(error, error_len, "durable VM transaction disappeared");
        free(storage_assignments);
        free(constraints);
        return -EIO;
    }
    if (entry->transaction.state == WVM_LIFECYCLE_COMMITTED &&
        admission_result == -EAGAIN) {
        result->status_code = WVM_CONTROL_RESULT_IN_PROGRESS;
    } else if (admission_result != 0 ||
               entry->transaction.state != WVM_LIFECYCLE_RUNNING) {
        pthread_mutex_unlock(&context->lock);
        result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
        free(storage_assignments);
        free(constraints);
        return 0;
    }
    if (result->status_code != WVM_CONTROL_RESULT_IN_PROGRESS) {
        result->status_code = WVM_CONTROL_RESULT_SUCCESS;
    }
    result->recorded_state = (uint16_t)entry->transaction.state;
    result->applied_revision = entry->transaction.transaction_sequence;
    result->vm_id = transaction.vm_id;
    result->vm_incarnation = transaction.vm_incarnation;
    result->manifest_generation = transaction.manifest_generation;
    memcpy(result->record_digest, entry->transaction.request_digest,
           sizeof(result->record_digest));
    memcpy(result->admission_tx_id, transaction.admission_tx_id,
           sizeof(result->admission_tx_id));
    memcpy(result->manifest_id, transaction.manifest_id,
           sizeof(result->manifest_id));
    result->route_scope_id = transaction.route_scope_key.route_scope_id;
    pthread_mutex_unlock(&context->lock);
    (void)submit_result;
    free(storage_assignments);
    free(constraints);
    return 0;
}

static int apply_control_request(
    void *opaque, const struct wvm_envelope *request,
    const struct wvm_member_key *actor, struct wvm_control_result *result,
    char *error, size_t error_len)
{
    struct control_context *context = opaque;
    int rc;

    if (request->message_type == WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES ||
        request->message_type == WVM_ENVELOPE_MSG_PUBLISH_RUNTIME_PROFILE) {
        pthread_mutex_lock(&context->lock);
        if (request->message_type == WVM_ENVELOPE_MSG_PUBLISH_CAPABILITIES) {
            rc = wvm_ctl_publish_capabilities(
                context->state_directory,
                &context->plane->membership_controller, request, actor, result,
                error, error_len);
        } else {
            rc = wvm_ctl_publish_runtime_profile(
                context->state_directory,
                &context->plane->membership_controller, request, actor, result,
                error, error_len);
        }
        pthread_mutex_unlock(&context->lock);
        return rc;
    }
    return apply_create_vm(opaque, request, actor, result, error, error_len);
}

static volatile sig_atomic_t shutdown_requested;

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s serve --state-dir DIR --socket PATH --local-node-id N "
            "--local-instance-id N --principals FILE --capacity N\n\n"
            "FILE contains one local authenticated principal per line:\n"
            "  UID ROLE ROLE_ID INSTANCE_ID\n"
            "ROLE is node-runtime, gateway, or executor. The Unix peer UID is "
            "the identity authority; payload fields never establish a caller "
            "identity.\n",
            program);
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!text || text[0] == '\0' || !value) {
        return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0') {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_u32(const char *text, uint32_t *value)
{
    uint64_t parsed;

    if (!value || parse_u64(text, &parsed) != 0 || parsed == 0 ||
        parsed > UINT32_MAX) {
        return -1;
    }
    *value = (uint32_t)parsed;
    return 0;
}

static int parse_size(const char *text, size_t *value)
{
    uint64_t parsed;

    if (!value || parse_u64(text, &parsed) != 0 || parsed == 0 ||
        parsed > SIZE_MAX) {
        return -1;
    }
    *value = (size_t)parsed;
    return 0;
}

static int parse_role(const char *text, enum wvm_manifest_role_type *role)
{
    if (!text || !role) {
        return -1;
    }
    if (strcmp(text, "node-runtime") == 0) {
        *role = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    } else if (strcmp(text, "gateway") == 0) {
        *role = WVM_MANIFEST_ROLE_GATEWAY;
    } else if (strcmp(text, "executor") == 0) {
        *role = WVM_MANIFEST_ROLE_EXECUTOR;
    } else {
        return -1;
    }
    return 0;
}

static int parse_options(int argc, char **argv, struct service_options *options)
{
    int i;
    int have_state_directory = 0;
    int have_socket = 0;
    int have_node = 0;
    int have_instance = 0;
    int have_principals = 0;
    int have_capacity = 0;

    if (!options || argc < 2 || strcmp(argv[1], "serve") != 0) {
        return -1;
    }
    memset(options, 0, sizeof(*options));
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc &&
            !have_state_directory) {
            options->state_directory = argv[++i];
            have_state_directory = 1;
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc &&
                   !have_socket) {
            options->socket_path = argv[++i];
            have_socket = 1;
        } else if (strcmp(argv[i], "--local-node-id") == 0 && i + 1 < argc &&
                   !have_node &&
                   parse_u32(argv[++i], &options->local_physical_node_id) ==
                       0) {
            have_node = 1;
        } else if (strcmp(argv[i], "--local-instance-id") == 0 &&
                   i + 1 < argc && !have_instance &&
                   parse_u64(argv[++i], &options->local_runtime_instance_id) ==
                       0 &&
                   options->local_runtime_instance_id != 0) {
            have_instance = 1;
        } else if (strcmp(argv[i], "--principals") == 0 && i + 1 < argc &&
                   !have_principals) {
            options->principal_file = argv[++i];
            have_principals = 1;
        } else if (strcmp(argv[i], "--capacity") == 0 && i + 1 < argc &&
                   !have_capacity &&
                   parse_size(argv[++i], &options->capacity) == 0) {
            have_capacity = 1;
        } else {
            return -1;
        }
    }
    return have_state_directory && have_socket && have_node && have_instance &&
                   have_principals && have_capacity
               ? 0
               : -1;
}

static int make_state_path(const char *directory, const char *name,
                           char *output, size_t output_capacity)
{
    int written;

    if (!directory || directory[0] == '\0' || !name || !output ||
        output_capacity == 0) {
        return -1;
    }
    written = snprintf(output, output_capacity, "%s/%s", directory, name);
    return written < 0 || (size_t)written >= output_capacity ? -1 : 0;
}

static int ensure_state_directory(const char *directory)
{
    struct stat status;

    if (!directory || directory[0] == '\0') {
        return -1;
    }
    if (mkdir(directory, S_IRWXU) != 0 && errno != EEXIST) {
        return -1;
    }
    if (stat(directory, &status) != 0 || !S_ISDIR(status.st_mode)) {
        return -1;
    }
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authorize_unix_control_peer(
    void *opaque, const struct wvm_member_key *expected_peer,
    const struct wvm_unix_peer_credentials *credentials, char *error,
    size_t error_len)
{
    const struct local_authentication *auth = opaque;
    size_t i;

    if (!auth || !expected_peer || !credentials || credentials->process_id <= 0) {
        snprintf(error, error_len, "Unix control peer credentials are invalid");
        return -1;
    }
    for (i = 0; i < auth->count; i++) {
        if (member_key_equal(&auth->principals[i].member_key, expected_peer)) {
            if (auth->principals[i].uid == credentials->user_id) {
                return 0;
            }
            break;
        }
    }
    snprintf(error, error_len,
             "Unix peer UID is not bound to the expected member identity");
    return -EACCES;
}

static int load_principals(const char *path, struct local_authentication *auth,
                           char *error, size_t error_len)
{
    char line[512];
    FILE *input;
    size_t capacity = 0;

    if (!path || !auth) {
        return -1;
    }
    memset(auth, 0, sizeof(*auth));
    input = fopen(path, "r");
    if (!input) {
        snprintf(error, error_len, "cannot open principal file: %s",
                 strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof(line), input)) {
        char uid_text[64];
        char role_text[64];
        char role_id_text[64];
        char instance_text[64];
        char trailing[2];
        struct local_principal principal;
        uint64_t parsed_uid;
        size_t i;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        if (sscanf(line, " %63s %63s %63s %63s %1s", uid_text, role_text,
                   role_id_text, instance_text, trailing) != 4 ||
            parse_u64(uid_text, &parsed_uid) != 0 || parsed_uid > UINT_MAX ||
            parse_role(role_text, &principal.member_key.role_type) != 0 ||
            parse_u32(role_id_text, &principal.member_key.role_id) != 0 ||
            parse_u64(instance_text, &principal.member_key.instance_id) != 0 ||
            principal.member_key.instance_id == 0 ||
            wvm_member_key_validate(&principal.member_key, error, error_len) !=
                0) {
            snprintf(error, error_len, "principal file contains an invalid line");
            fclose(input);
            free(auth->principals);
            memset(auth, 0, sizeof(*auth));
            return -1;
        }
        principal.uid = (uid_t)parsed_uid;
        for (i = 0; i < auth->count; i++) {
            if (auth->principals[i].uid == principal.uid ||
                member_key_equal(&auth->principals[i].member_key,
                                 &principal.member_key)) {
                snprintf(error, error_len,
                         "principal file reuses a UID or member identity");
                fclose(input);
                free(auth->principals);
                memset(auth, 0, sizeof(*auth));
                return -1;
            }
        }
        if (auth->count == capacity) {
            size_t next_capacity = capacity == 0 ? 4 : capacity * 2U;
            struct local_principal *expanded;

            if (next_capacity < capacity ||
                next_capacity > SIZE_MAX / sizeof(*auth->principals)) {
                snprintf(error, error_len, "principal file is too large");
                fclose(input);
                free(auth->principals);
                memset(auth, 0, sizeof(*auth));
                return -1;
            }
            expanded = realloc(auth->principals,
                               next_capacity * sizeof(*auth->principals));
            if (!expanded) {
                snprintf(error, error_len, "cannot allocate principal map");
                fclose(input);
                free(auth->principals);
                memset(auth, 0, sizeof(*auth));
                return -1;
            }
            auth->principals = expanded;
            capacity = next_capacity;
        }
        auth->principals[auth->count++] = principal;
    }
    if (ferror(input) || fclose(input) != 0 || auth->count == 0) {
        snprintf(error, error_len, "principal file is empty or unreadable");
        free(auth->principals);
        memset(auth, 0, sizeof(*auth));
        return -1;
    }
    return 0;
}

static void destroy_principals(struct local_authentication *auth)
{
    if (!auth) {
        return;
    }
    free(auth->principals);
    memset(auth, 0, sizeof(*auth));
}

static int authenticate_local_peer(void *opaque, int stream_fd,
                                   struct wvm_member_key *actor, char *error,
                                   size_t error_len)
{
    const struct local_authentication *auth = opaque;
    struct ucred credentials;
    socklen_t credential_size = sizeof(credentials);
    size_t i;

    if (!auth || !actor || stream_fd < 0 ||
        getsockopt(stream_fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credential_size) != 0 ||
        credential_size != sizeof(credentials)) {
        snprintf(error, error_len, "cannot authenticate local control peer");
        return -1;
    }
    for (i = 0; i < auth->count; i++) {
        if (auth->principals[i].uid == credentials.uid) {
            *actor = auth->principals[i].member_key;
            return 0;
        }
    }
    snprintf(error, error_len, "local control peer has no configured principal");
    return -1;
}

static int capability_ref_compare(const void *left_value,
                                  const void *right_value)
{
    const struct wvm_capability_ref *left = left_value;
    const struct wvm_capability_ref *right = right_value;

    if (left->physical_node_id != right->physical_node_id) {
        return left->physical_node_id < right->physical_node_id ? -1 : 1;
    }
    if (left->node_instance_id != right->node_instance_id) {
        return left->node_instance_id < right->node_instance_id ? -1 : 1;
    }
    return 0;
}

static int capability_available_for_node(
    const struct wvm_ctl_capability_evidence *evidence,
    const struct wvm_node_record *node, uint16_t capability_id)
{
    size_t i;

    for (i = 0; i < evidence->record_count; i++) {
        const struct wvm_capability_record *record = &evidence->records[i];

        if (record->physical_node_id == node->physical_node_id &&
            record->node_instance_id == node->node_instance_id &&
            record->capability_id == capability_id &&
            record->state == WVM_CAPABILITY_AVAILABLE) {
            return 1;
        }
    }
    return 0;
}

static uint64_t current_unix_time_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec <= 0) {
        return 0;
    }
    if ((uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec / 1000000U) /
                                 1000U) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000U +
           (uint64_t)now.tv_nsec / 1000000U;
}

static int admission_workspace_prepare_template(
    struct admission_workspace *workspace,
    const struct wvm_vm_request *request,
    const struct wvm_ctl_capability_evidence *evidence,
    char *error, size_t error_len)
{
    struct wvm_coordinator_prepare_options options;
    uint64_t now;
    int all_kvm = 1;
    int all_tcg = 1;
    int all_kernel = 1;
    size_t i;

    if (!workspace || !request || !evidence ||
        !workspace->profile_capabilities ||
        workspace->membership_capture.node_count == 0 ||
        workspace->membership_capture.node_count > workspace->capacity) {
        snprintf(error, error_len, "cannot build admission options template");
        return -1;
    }
    for (i = 0; i < workspace->membership_capture.node_count; i++) {
        const struct wvm_node_record *node =
            &workspace->membership_capture.nodes[i];

        workspace->profile_capabilities[i] = node->capability;
        all_kvm = all_kvm && capability_available_for_node(
                                  evidence, node,
                                  WVM_CAPABILITY_ID_EXECUTION_KVM);
        all_tcg = all_tcg && capability_available_for_node(
                                  evidence, node,
                                  WVM_CAPABILITY_ID_EXECUTION_TCG);
        all_kernel = all_kernel && capability_available_for_node(
                                      evidence, node,
                                      WVM_CAPABILITY_ID_KERNEL_ACCELERATION);
    }
    qsort(workspace->profile_capabilities,
          workspace->membership_capture.node_count,
          sizeof(*workspace->profile_capabilities), capability_ref_compare);
    for (i = 1; i < workspace->membership_capture.node_count; i++) {
        if (workspace->profile_capabilities[i - 1].physical_node_id ==
            workspace->profile_capabilities[i].physical_node_id) {
            snprintf(error, error_len,
                     "membership contains duplicate capability node IDs");
            return -1;
        }
    }

    memset(&options, 0, sizeof(options));
    snprintf(options.guest_machine.architecture,
             sizeof(options.guest_machine.architecture), "%s", "x86_64");
    snprintf(options.guest_machine.machine_type,
             sizeof(options.guest_machine.machine_type), "%s",
             "pc-i440fx-5.2");
    options.guest_machine.qemu_compat_version = 502;
    options.guest_machine.firmware_policy = 1;
    if (request->execution_backend_policy ==
            WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM ||
        (request->execution_backend_policy == WVM_MANIFEST_BACKEND_POLICY_AUTO &&
         all_kvm)) {
        options.execution_profile.backend = WVM_MANIFEST_BACKEND_KVM;
        options.execution_profile.dirty_capture_engine =
            WVM_FAULT_ENGINE_KVM_DIRTY_LOG;
        options.execution_profile.read_fault_engine =
            WVM_FAULT_ENGINE_NODE_RUNTIME_RESYNC;
        options.execution_profile.invalidation_engine =
            WVM_FAULT_ENGINE_NODE_RUNTIME_RESYNC;
    } else {
        options.execution_profile.backend = WVM_MANIFEST_BACKEND_TCG;
        options.execution_profile.dirty_capture_engine =
            WVM_FAULT_ENGINE_SIGSEGV_MPROTECT;
        options.execution_profile.read_fault_engine =
            WVM_FAULT_ENGINE_USERFAULTFD;
        options.execution_profile.invalidation_engine =
            WVM_FAULT_ENGINE_SIGSEGV_MPROTECT;
    }
    if (request->execution_backend_policy ==
            WVM_MANIFEST_BACKEND_POLICY_REQUIRE_TCG && !all_tcg) {
        snprintf(error, error_len, "no complete TCG capability set is published");
        return -1;
    }
    if (request->execution_backend_policy ==
            WVM_MANIFEST_BACKEND_POLICY_REQUIRE_KVM && !all_kvm) {
        snprintf(error, error_len, "no complete KVM capability set is published");
        return -1;
    }
    if (request->accelerator_policy == WVM_MANIFEST_ACCELERATOR_REQUIRE_KERNEL &&
        !all_kernel) {
        snprintf(error, error_len,
                 "required kernel acceleration is unavailable on a member");
        return -1;
    }
    if (request->accelerator_policy != WVM_MANIFEST_ACCELERATOR_DISABLED &&
        all_kernel) {
        options.execution_profile.kernel_accelerator_bits = 1;
        options.execution_profile.invalidation_engine =
            WVM_FAULT_ENGINE_KERNEL_ACCELERATION;
        if (options.execution_profile.backend == WVM_MANIFEST_BACKEND_TCG) {
            options.execution_profile.dirty_capture_engine =
                WVM_FAULT_ENGINE_KERNEL_ACCELERATION;
        }
    }
    options.execution_profile.context_schema_version = 1;
    options.execution_profile.per_node_capabilities.entries =
        workspace->profile_capabilities;
    options.execution_profile.per_node_capabilities.count =
        workspace->membership_capture.node_count;
    options.execution_profile.per_node_capabilities.capacity = workspace->capacity;
    wvm_sha256_digest("wavevm/memory-policy/1", sizeof("wavevm/memory-policy/1") - 1U,
                      options.execution_profile.supported_memory_policies_digest);
    options.execution_profile.fallback_decision = 1;
    options.memory_chunk_bytes = request->requested_memory_bytes;
    options.host_overhead_vcpu_slots = 1;
    options.host_overhead_memory_bytes = WVM_MANIFEST_PAGE_BYTES;
    options.memory_consistency_policy = 1;
    options.guest_numa_nodes = workspace->membership_capture.node_count;
    options.executor_class = 1;
    options.node_runtime_role_bits =
        WVM_RUNTIME_ROLE_BIT(WVM_MANIFEST_ROLE_NODE_RUNTIME);
    options.candidate_created_at = now = current_unix_time_ms();
    if (now == 0 || now > UINT64_MAX - 60000U) {
        snprintf(error, error_len, "cannot obtain admission timestamp");
        return -1;
    }
    options.prepared_reservation_expiry_unix_time_ms = now + 60000U;
    if (wvm_admission_plan_provider_set_options_template(
            &workspace->plan_provider, &options, error, error_len) != 0) {
        return -1;
    }
    return 0;
}

static int admission_workspace_reset(
    void *context, const struct wvm_vm_request *request,
    struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_activation_record *activation,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len)
{
    struct admission_workspace *workspace = context;
    struct wvm_membership_controller_capture *capture;
    struct wvm_ctl_capability_evidence evidence = {0};
    struct wvm_ctl_runtime_profile_set runtime_profiles = {0};
    struct wvm_admission_evidence_owner evidence_owner;

    if (!workspace || !request || !prepared_route || !prepared_vm ||
        !activation || !route_transaction || !route_snapshot ||
        !workspace->state_directory) {
        snprintf(error, error_len, "admission workspace is not configured");
        return -1;
    }
    capture = &workspace->membership_capture;
    if (wvm_membership_controller_capture(workspace->membership_controller,
                                          capture, error, error_len) != 0 ||
        capture->node_count > SIZE_MAX - capture->gateway_count ||
        wvm_ctl_load_capability_evidence(
            workspace->state_directory, capture, &evidence, error,
            error_len) != 0 ||
        wvm_ctl_load_runtime_profile_set(
            workspace->state_directory, capture, &runtime_profiles, error,
            error_len) != 0 ||
        admission_workspace_prepare_template(
            workspace, request, &evidence, error, error_len) != 0 ||
        wvm_admission_evidence_owner_init(
            &evidence_owner, evidence.records, evidence.record_capacity,
            workspace->reservations, workspace->capacity, error,
            error_len) != 0 ||
        wvm_admission_evidence_owner_publish(
            &evidence_owner, evidence.records, evidence.record_count, NULL, 0,
            evidence.inventory_revision, evidence.profile_generation, error,
            error_len) != 0 ||
        wvm_ctl_admission_buffers_reset(
            &workspace->transaction_buffers, request->requested_vcpus,
            capture->node_count, capture->node_count + capture->gateway_count,
            WVM_CTL_ADMISSION_WORKSPACE_BYTES, prepared_vm,
            &workspace->plan_provider.options_template, activation, error,
            error_len) != 0 ||
        wvm_admission_plan_provider_publish_runtime_profiles(
            &workspace->plan_provider, capture, runtime_profiles.profiles,
            runtime_profiles.profile_count, error, error_len) != 0) {
        wvm_ctl_capability_evidence_destroy(&evidence);
        wvm_ctl_runtime_profile_set_destroy(&runtime_profiles);
        return -1;
    }
    wvm_ctl_capability_evidence_destroy(&workspace->capability_evidence);
    wvm_ctl_runtime_profile_set_destroy(&workspace->runtime_profile_set);
    workspace->capability_evidence = evidence;
    workspace->runtime_profile_set = runtime_profiles;
    workspace->evidence_owner = evidence_owner;
    memset(prepared_route, 0, sizeof(*prepared_route));
    memset(route_transaction, 0, sizeof(*route_transaction));
    memset(route_snapshot, 0, sizeof(*route_snapshot));
    return 0;
}

static int admission_transport_resolve_node(
    void *context, uint32_t physical_node_id, uint64_t node_instance_id,
    struct wvm_admission_transport_target *target, char *error,
    size_t error_len)
{
    struct admission_workspace *workspace = context;
    struct wvm_membership_controller_member_status status;
    struct wvm_member_key key = {
        .role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME,
        .role_id = physical_node_id,
        .instance_id = node_instance_id,
    };

    if (!workspace || !workspace->membership_controller || !target) {
        snprintf(error, error_len, "invalid transport resolve arguments");
        return -1;
    }

    if (wvm_membership_controller_member_status(workspace->membership_controller,
                                                &key, &status, error,
                                                error_len) != 0) {
        return -1;
    }
    memset(target, 0, sizeof(*target));
    target->member_key = status.member_key;
    target->endpoint = status.endpoint;
    return 0;
}

static int admission_transport_submit(
    void *context, const struct wvm_admission_transport_target *target,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    struct admission_workspace *workspace = context;

    if (!workspace || !target || !envelope ||
        !workspace->stream_transport.initialized) {
        snprintf(error, error_len,
                 "authenticated admission stream is not initialized");
        return -EINVAL;
    }
    if (target->member_key.role_type != WVM_MANIFEST_ROLE_NODE_RUNTIME ||
        target->member_key.role_id != workspace->local_physical_node_id ||
        target->member_key.instance_id !=
            workspace->local_runtime_instance_id) {
        snprintf(error, error_len,
                 "Unix admission transport requires the exact local runtime instance");
        return -EXDEV;
    }
    if (target->endpoint.control_transport != WVM_CONTROL_TRANSPORT_UNIX_STREAM) {
        snprintf(error, error_len,
                 "TLS/TCP and QUIC admission connectors are not configured");
        return -EOPNOTSUPP;
    }
    return wvm_admission_stream_transport_submit(
        &workspace->stream_transport, target, envelope, error, error_len);
}

static int authorize_self_registration(
    void *opaque, enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    (void)opaque;
    (void)action;
    if (!member_key_equal(actor, subject)) {
        snprintf(error, error_len,
                 "member registration must use the authenticated self identity");
        return -1;
    }
    return 0;
}

static int authorize_executor_gateway_management(
    void *opaque, enum wvm_gateway_drain_action action,
    const struct wvm_member_key *actor,
    const struct wvm_member_key *target_gateway, char *error, size_t error_len)
{
    (void)opaque;
    (void)action;
    (void)target_gateway;
    if (!actor || actor->role_type != WVM_MANIFEST_ROLE_EXECUTOR) {
        snprintf(error, error_len,
                 "gateway management requires an authenticated executor");
        return -1;
    }
    return 0;
}

static int authorize_executor_membership_management(
    void *opaque, enum wvm_membership_control_membership_action action,
    const struct wvm_member_key *actor,
    const struct wvm_member_key *target_member, char *error, size_t error_len)
{
    (void)opaque;
    (void)action;
    (void)target_member;
    if (!actor || actor->role_type != WVM_MANIFEST_ROLE_EXECUTOR) {
        snprintf(error, error_len,
                 "membership management requires an authenticated executor");
        return -1;
    }
    return 0;
}

static void request_shutdown(int signal_number)
{
    (void)signal_number;
    shutdown_requested = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = request_shutdown;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 &&
                   sigaction(SIGTERM, &action, NULL) == 0
               ? 0
               : -1;
}

int main(int argc, char **argv)
{
    struct service_options options;
    struct local_authentication auth;
    struct wvm_control_plane plane;
    struct wvm_control_service service;
    struct wvm_control_plane_entry *entries = NULL;
    struct wvm_control_plane_route_entry *route_entries = NULL;
    struct wvm_control_plane_runtime_manifest_entry *runtime_entries = NULL;
    struct wvm_vm_namespace_record *namespace_records = NULL;
    struct wvm_membership_controller_member_entry *members = NULL;
    struct wvm_membership_controller_route_entry *membership_routes = NULL;
    struct wvm_membership_dependency *dependencies = NULL;
    struct wvm_membership_control_operation *operations = NULL;
    struct wvm_vm_namespace_allocator namespace_allocator;
    struct wvm_control_plane_membership_config membership_config;
    struct wvm_control_service_config service_config;
    struct control_context control_context;
    struct admission_workspace admission_workspace;
    struct wvm_admission_authority_owner_config authority_config;
    char admission_journal[WVM_CONTROL_PLANE_PATH_MAX];
    char membership_journal[WVM_CONTROL_PLANE_PATH_MAX];
    char membership_control_journal[WVM_CONTROL_PLANE_PATH_MAX];
    char error[256] = {0};
    int result = 1;

    if (argc > 1 && strcmp(argv[1], "publish-capabilities") == 0) {
        return wvm_ctl_capability_publish_command(argc, argv);
    }
    if (argc > 1 && strcmp(argv[1], "publish-runtime-profile") == 0) {
        return wvm_ctl_runtime_profile_publish_command(argc, argv);
    }
    if (parse_options(argc, argv, &options) != 0) {
        print_usage(argv[0]);
        return 2;
    }
    memset(&service, 0, sizeof(service));
    memset(&control_context, 0, sizeof(control_context));
    memset(&admission_workspace, 0, sizeof(admission_workspace));
    shutdown_requested = 0;
    if (ensure_state_directory(options.state_directory) != 0 ||
        make_state_path(options.state_directory, "admission.journal",
                        admission_journal, sizeof(admission_journal)) != 0 ||
        make_state_path(options.state_directory, "membership.journal",
                        membership_journal, sizeof(membership_journal)) != 0 ||
        make_state_path(options.state_directory, "membership-control.journal",
                        membership_control_journal,
                        sizeof(membership_control_journal)) != 0 ||
        load_principals(options.principal_file, &auth, error, sizeof(error)) !=
            0) {
        fprintf(stderr, "wvm_ctl: %s\n",
                error[0] ? error : "invalid control-plane configuration");
        return 1;
    }

    entries = calloc(options.capacity, sizeof(*entries));
    route_entries = calloc(options.capacity, sizeof(*route_entries));
    runtime_entries = calloc(options.capacity, sizeof(*runtime_entries));
    namespace_records = calloc(options.capacity, sizeof(*namespace_records));
    members = calloc(options.capacity, sizeof(*members));
    membership_routes = calloc(options.capacity, sizeof(*membership_routes));
    dependencies = calloc(options.capacity, sizeof(*dependencies));
    operations = calloc(options.capacity, sizeof(*operations));

    /* Allocate admission authority workspace storage. */
    admission_workspace.capacity = options.capacity;
    if (options.capacity > SIZE_MAX / 3U ||
        options.capacity > SIZE_MAX / sizeof(*admission_workspace.profile_capabilities) ||
        options.capacity > SIZE_MAX / sizeof(*admission_workspace.lease_storage)) {
        fprintf(stderr, "wvm_ctl: admission capacity is too large\n");
        goto out;
    }
    admission_workspace.route_snapshot_bytes_capacity = options.capacity * 512;
    admission_workspace.route_ack_set_bytes_capacity = options.capacity * 64;
    admission_workspace.capability_evidence.records =
        calloc(options.capacity,
               sizeof(*admission_workspace.capability_evidence.records));
    admission_workspace.capability_evidence.record_capacity = options.capacity;
    admission_workspace.profile_capabilities = calloc(
        options.capacity, sizeof(*admission_workspace.profile_capabilities));
    admission_workspace.lease_storage = calloc(
        options.capacity * 3U, sizeof(*admission_workspace.lease_storage));
    admission_workspace.reservations = calloc(options.capacity, sizeof(*admission_workspace.reservations));
    admission_workspace.launch_plans = calloc(options.capacity, sizeof(*admission_workspace.launch_plans));
    admission_workspace.listener_plans = calloc(options.capacity, sizeof(*admission_workspace.listener_plans));
    admission_workspace.route_rules = calloc(options.capacity, sizeof(*admission_workspace.route_rules));
    admission_workspace.route_ack_entries = calloc(options.capacity, sizeof(*admission_workspace.route_ack_entries));
    admission_workspace.capture_nodes = calloc(options.capacity, sizeof(*admission_workspace.capture_nodes));
    admission_workspace.capture_gateways = calloc(options.capacity, sizeof(*admission_workspace.capture_gateways));
    admission_workspace.capture_hosted_gateways = calloc(options.capacity, sizeof(*admission_workspace.capture_hosted_gateways));
    admission_workspace.capture_parent_gateways = calloc(options.capacity, sizeof(*admission_workspace.capture_parent_gateways));
    admission_workspace.capture_child_gateways = calloc(options.capacity, sizeof(*admission_workspace.capture_child_gateways));
    admission_workspace.route_snapshot_bytes = calloc(admission_workspace.route_snapshot_bytes_capacity, 1);
    admission_workspace.route_ack_set_bytes = calloc(admission_workspace.route_ack_set_bytes_capacity, 1);

    if (!entries || !route_entries || !runtime_entries || !namespace_records ||
        !members || !membership_routes || !dependencies || !operations ||
        !admission_workspace.capability_evidence.records ||
        !admission_workspace.profile_capabilities ||
        !admission_workspace.lease_storage ||
        !admission_workspace.reservations ||
        !admission_workspace.launch_plans || !admission_workspace.listener_plans ||
        !admission_workspace.route_rules || !admission_workspace.route_ack_entries ||
        !admission_workspace.capture_nodes || !admission_workspace.capture_gateways ||
        !admission_workspace.capture_hosted_gateways ||
        !admission_workspace.capture_parent_gateways ||
        !admission_workspace.capture_child_gateways ||
        !admission_workspace.route_snapshot_bytes || !admission_workspace.route_ack_set_bytes) {
        fprintf(stderr, "wvm_ctl: cannot allocate bounded control-plane state\n");
        goto out;
    }
    wvm_control_plane_init(&plane, entries, options.capacity);
    wvm_control_plane_set_route_transaction_entries(&plane, route_entries,
                                                    options.capacity);
    wvm_control_plane_set_runtime_manifest_entries(&plane, runtime_entries,
                                                   options.capacity);
    wvm_vm_namespace_allocator_init(&namespace_allocator, namespace_records,
                                    options.capacity, 1);
    control_context.plane = &plane;
    control_context.state_directory = options.state_directory;
    control_context.namespace_allocator = &namespace_allocator;
    control_context.request_list_capacity = options.capacity;
    if (pthread_mutex_init(&control_context.lock, NULL) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize control-plane lock\n");
        goto out;
    }
    control_context.lock_initialized = 1;

    /*
     * Bind the admission authority before membership opens: the control plane
     * refuses the binding once its journals are live, so every component must
     * be constructed and the authority registered here.
     */
    admission_workspace.membership_capture.nodes = admission_workspace.capture_nodes;
    admission_workspace.membership_capture.node_capacity = admission_workspace.capacity;
    admission_workspace.membership_capture.gateways = admission_workspace.capture_gateways;
    admission_workspace.membership_capture.gateway_capacity = admission_workspace.capacity;
    admission_workspace.membership_capture.hosted_gateway_role_ids = admission_workspace.capture_hosted_gateways;
    admission_workspace.membership_capture.hosted_gateway_role_id_capacity = admission_workspace.capacity;
    admission_workspace.membership_capture.gateway_parent_ids = admission_workspace.capture_parent_gateways;
    admission_workspace.membership_capture.gateway_parent_id_capacity = admission_workspace.capacity;
    admission_workspace.membership_capture.gateway_child_ids = admission_workspace.capture_child_gateways;
    admission_workspace.membership_capture.gateway_child_id_capacity = admission_workspace.capacity;
    admission_workspace.membership_controller = &plane.membership_controller;
    admission_workspace.state_directory = options.state_directory;
    if (wvm_admission_evidence_owner_init(
            &admission_workspace.evidence_owner,
            admission_workspace.capability_evidence.records,
            admission_workspace.capability_evidence.record_capacity,
            admission_workspace.reservations, admission_workspace.capacity,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize evidence owner: %s\n", error);
        goto close_plane;
    }
    if (wvm_admission_plan_provider_init_with_lease_storage(
            &admission_workspace.plan_provider,
            admission_workspace.launch_plans, admission_workspace.capacity,
            admission_workspace.listener_plans, admission_workspace.capacity,
            admission_workspace.lease_storage, options.capacity * 3U,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize plan provider: %s\n", error);
        goto close_plane;
    }
    if (wvm_admission_route_compiler_init(
            &admission_workspace.route_compiler,
            WVM_ROUTE_TOPOLOGY_FLAT, 1, 6000, 1,
            admission_workspace.route_rules, admission_workspace.capacity,
            admission_workspace.route_ack_entries, admission_workspace.capacity,
            admission_workspace.route_snapshot_bytes,
            admission_workspace.route_snapshot_bytes_capacity,
            admission_workspace.route_ack_set_bytes,
            admission_workspace.route_ack_set_bytes_capacity,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize route compiler: %s\n", error);
        goto close_plane;
    }
    admission_workspace.local_physical_node_id = options.local_physical_node_id;
    admission_workspace.local_runtime_instance_id =
        options.local_runtime_instance_id;
    if (wvm_unix_control_connector_bind(
            &admission_workspace.unix_connector, authorize_unix_control_peer,
            &auth, 10000U, &admission_workspace.control_connector,
            error, sizeof(error)) != 0 ||
        wvm_admission_stream_transport_init(
            &admission_workspace.stream_transport,
            &admission_workspace.control_connector,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize Unix admission connector: %s\n",
                error);
        goto close_plane;
    }
    if (wvm_admission_transport_init(
            &admission_workspace.transport,
            options.local_physical_node_id,
            options.local_runtime_instance_id,
            &admission_workspace,
            admission_transport_resolve_node,
            admission_transport_submit,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize admission transport: %s\n", error);
        goto close_plane;
    }

    memset(&authority_config, 0, sizeof(authority_config));
    authority_config.membership_controller = &plane.membership_controller;
    authority_config.membership_capture = &admission_workspace.membership_capture;
    authority_config.evidence_owner = &admission_workspace.evidence_owner;
    authority_config.plan_provider = &admission_workspace.plan_provider;
    authority_config.route_compiler = &admission_workspace.route_compiler;
    authority_config.transport = &admission_workspace.transport;
    authority_config.prepared_route = &admission_workspace.prepared_route;
    authority_config.prepared_vm = &admission_workspace.prepared_vm;
    authority_config.activation = &admission_workspace.activation;
    authority_config.route_transaction = &admission_workspace.route_transaction;
    authority_config.route_snapshot = &admission_workspace.route_snapshot;
    authority_config.workspace_context = &admission_workspace;
    authority_config.reset_workspace = admission_workspace_reset;

    if (wvm_admission_authority_owner_init(
            &admission_workspace.authority_owner,
            &authority_config,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize admission authority: %s\n", error);
        goto close_plane;
    }
    if (wvm_control_plane_set_admission_authority(
            &plane,
            wvm_admission_authority_owner_binding(&admission_workspace.authority_owner),
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot bind admission authority: %s\n", error);
        goto close_plane;
    }
    admission_workspace.initialized = 1;

    memset(&membership_config, 0, sizeof(membership_config));
    membership_config.members = members;
    membership_config.member_capacity = options.capacity;
    membership_config.routes = membership_routes;
    membership_config.route_capacity = options.capacity;
    membership_config.dependencies = dependencies;
    membership_config.dependency_capacity = options.capacity;
    membership_config.operations = operations;
    membership_config.operation_capacity = options.capacity;
    membership_config.membership_journal_path = membership_journal;
    membership_config.control_journal_path = membership_control_journal;
    membership_config.authorize = authorize_self_registration;
    membership_config.authorize_management = authorize_executor_gateway_management;
    membership_config.authorize_membership =
        authorize_executor_membership_management;
    if (wvm_control_plane_configure_membership(&plane, &membership_config,
                                               error, sizeof(error)) != 0 ||
        wvm_control_plane_open_membership(&plane, error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot open control-plane state: %s\n",
                error[0] ? error : "unknown error");
        goto close_plane;
    }

    /* Compute membership and evidence come from registered node runtimes. */

    /* Open admission journal after authority is bound. */
    if (wvm_control_plane_open(&plane, admission_journal, &namespace_allocator,
                               error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot open admission journal: %s\n",
                error[0] ? error : "unknown error");
        goto close_plane;
    }

    memset(&service_config, 0, sizeof(service_config));
    service_config.plane = &plane;
    service_config.socket_path = options.socket_path;
    service_config.socket_mode = S_IRUSR | S_IWUSR;
    service_config.listen_backlog = 32;
    service_config.local_physical_node_id = options.local_physical_node_id;
    service_config.local_runtime_instance_id = options.local_runtime_instance_id;
    service_config.authenticate = authenticate_local_peer;
    service_config.authenticate_opaque = &auth;
    service_config.control_apply = apply_control_request;
    service_config.control_apply_opaque = &control_context;
    /* Node-runtime admission is a separate owner; ctl_tool must not accept
     * participant stages as ordinary CREATE_VM control requests. */
    service_config.admission_apply = NULL;
    service_config.admission_apply_opaque = NULL;
    if (install_signal_handlers() != 0) {
        fprintf(stderr, "wvm_ctl: cannot install signal handlers: %s\n",
                strerror(errno));
        goto close_plane;
    }
    if (wvm_control_service_init(&service, &service_config, error,
                                 sizeof(error)) != 0 ||
        wvm_control_service_start(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot start control-plane service: %s\n",
                error[0] ? error : strerror(errno));
        wvm_control_service_destroy(&service);
        goto close_plane;
    }
    while (!shutdown_requested) {
        if (pause() < 0 && errno != EINTR) {
            fprintf(stderr, "wvm_ctl: wait for shutdown failed: %s\n",
                    strerror(errno));
            break;
        }
    }
    if (wvm_control_service_stop(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot stop control-plane service: %s\n",
                error[0] ? error : "unknown error");
    } else {
        result = 0;
    }
    wvm_control_service_destroy(&service);

close_plane:
    wvm_control_plane_close(&plane);
out:
    wvm_admission_stream_transport_destroy(
        &admission_workspace.stream_transport);
    if (control_context.lock_initialized) {
        pthread_mutex_destroy(&control_context.lock);
    }
    destroy_principals(&auth);
    wvm_ctl_admission_buffers_destroy(&admission_workspace.transaction_buffers,
                                      &admission_workspace.prepared_vm);
    free(admission_workspace.route_ack_set_bytes);
    free(admission_workspace.route_snapshot_bytes);
    free(admission_workspace.capture_gateways);
    free(admission_workspace.capture_nodes);
    free(admission_workspace.capture_child_gateways);
    free(admission_workspace.capture_parent_gateways);
    free(admission_workspace.capture_hosted_gateways);
    free(admission_workspace.route_ack_entries);
    free(admission_workspace.route_rules);
    free(admission_workspace.listener_plans);
    free(admission_workspace.launch_plans);
    free(admission_workspace.reservations);
    free(admission_workspace.lease_storage);
    free(admission_workspace.profile_capabilities);
    wvm_ctl_runtime_profile_set_destroy(&admission_workspace.runtime_profile_set);
    wvm_ctl_capability_evidence_destroy(
        &admission_workspace.capability_evidence);
    free(operations);
    free(dependencies);
    free(membership_routes);
    free(members);
    free(namespace_records);
    free(runtime_entries);
    free(route_entries);
    free(entries);
    return result;
}

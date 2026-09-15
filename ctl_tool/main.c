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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../common_include/wavevm_control_plane.h"
#include "../common_include/wavevm_control_service.h"
#include "../common_include/wavevm_admission_orchestrator.h"
#include "../common_include/wavevm_admission_authority_owner.h"
#include "../common_include/wavevm_admission_provider.h"
#include "../common_include/wavevm_admission_route.h"
#include "../common_include/wavevm_coordinator.h"

/* Admission authority workspace owned by the control-plane service. */
struct admission_workspace {
    struct wvm_admission_evidence_owner evidence_owner;
    struct wvm_admission_plan_provider plan_provider;
    struct wvm_admission_route_compiler route_compiler;
    struct wvm_admission_transport transport;
    struct wvm_admission_authority_owner authority_owner;
    struct wvm_membership_controller_capture membership_capture;
    struct wvm_coordinator_prepare_options prepare_options;
    struct wvm_coordinator_prepared_route prepared_route;
    struct wvm_coordinator_prepared_vm prepared_vm;
    struct wvm_coordinator_activation_options activation_options;
    struct wvm_activation_record activation;
    struct wvm_route_transaction_record route_transaction;
    struct wvm_route_snapshot_record route_snapshot;
    struct wvm_capability_record *capabilities;
    struct wvm_resource_reservation *reservations;
    struct wvm_coordinator_node_launch_plan *launch_plans;
    struct wvm_admission_node_listener_plan *listener_plans;
    struct wvm_route_rule_record *route_rules;
    struct wvm_required_ack_entry *route_ack_entries;
    struct wvm_node_record *capture_nodes;
    struct wvm_gateway_record *capture_gateways;
    uint8_t *route_snapshot_bytes;
    uint8_t *route_ack_set_bytes;
    size_t capacity;
    size_t route_snapshot_bytes_capacity;
    size_t route_ack_set_bytes_capacity;
    int initialized;
};

struct control_context {
    struct wvm_control_plane *plane;
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
    if (admission_result != 0 ||
        entry->transaction.state != WVM_LIFECYCLE_RUNNING) {
        pthread_mutex_unlock(&context->lock);
        result->status_code = WVM_CONTROL_RESULT_PRECONDITION_FAILED;
        free(storage_assignments);
        free(constraints);
        return 0;
    }
    pthread_mutex_unlock(&context->lock);
    result->status_code = WVM_CONTROL_RESULT_SUCCESS;
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
    (void)submit_result;
    free(storage_assignments);
    free(constraints);
    return 0;
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

static int admission_workspace_reset(
    void *context, struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_coordinator_prepared_vm *prepared_vm,
    struct wvm_coordinator_activation_options *activation_options,
    struct wvm_activation_record *activation,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len)
{
    (void)context;
    (void)error;
    (void)error_len;
    if (!prepared_route || !prepared_vm || !activation_options ||
        !activation || !route_transaction || !route_snapshot) {
        return -1;
    }
    memset(prepared_route, 0, sizeof(*prepared_route));
    memset(prepared_vm, 0, sizeof(*prepared_vm));
    memset(activation_options, 0, sizeof(*activation_options));
    memset(activation, 0, sizeof(*activation));
    memset(route_transaction, 0, sizeof(*route_transaction));
    memset(route_snapshot, 0, sizeof(*route_snapshot));
    return 0;
}

static int admission_transport_resolve_node(
    void *context, uint32_t physical_node_id, uint64_t node_instance_id,
    struct wvm_admission_transport_target *target, char *error,
    size_t error_len)
{
    (void)context;
    (void)physical_node_id;
    (void)node_instance_id;
    (void)target;
    snprintf(error, error_len,
             "admission transport not yet connected to real network");
    return -1;
}

static int admission_transport_submit(
    void *context, const struct wvm_admission_transport_target *target,
    const struct wvm_envelope *envelope, char *error, size_t error_len)
{
    (void)context;
    (void)target;
    (void)envelope;
    snprintf(error, error_len,
             "admission transport not yet connected to real network");
    return -1;
}

static int admission_transport_ready(
    void *context, const struct wvm_candidate_vm_manifest *candidate,
    const struct wvm_node_runtime_manifest *runtime_manifest, char *error,
    size_t error_len)
{
    (void)context;
    (void)candidate;
    (void)runtime_manifest;
    snprintf(error, error_len,
             "admission transport not yet connected to real network");
    return -1;
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
    admission_workspace.route_snapshot_bytes_capacity = options.capacity * 512;
    admission_workspace.route_ack_set_bytes_capacity = options.capacity * 64;
    admission_workspace.capabilities = calloc(options.capacity, sizeof(*admission_workspace.capabilities));
    admission_workspace.reservations = calloc(options.capacity, sizeof(*admission_workspace.reservations));
    admission_workspace.launch_plans = calloc(options.capacity, sizeof(*admission_workspace.launch_plans));
    admission_workspace.listener_plans = calloc(options.capacity, sizeof(*admission_workspace.listener_plans));
    admission_workspace.route_rules = calloc(options.capacity, sizeof(*admission_workspace.route_rules));
    admission_workspace.route_ack_entries = calloc(options.capacity, sizeof(*admission_workspace.route_ack_entries));
    admission_workspace.capture_nodes = calloc(options.capacity, sizeof(*admission_workspace.capture_nodes));
    admission_workspace.capture_gateways = calloc(options.capacity, sizeof(*admission_workspace.capture_gateways));
    admission_workspace.route_snapshot_bytes = calloc(admission_workspace.route_snapshot_bytes_capacity, 1);
    admission_workspace.route_ack_set_bytes = calloc(admission_workspace.route_ack_set_bytes_capacity, 1);

    if (!entries || !route_entries || !runtime_entries || !namespace_records ||
        !members || !membership_routes || !dependencies || !operations ||
        !admission_workspace.capabilities || !admission_workspace.reservations ||
        !admission_workspace.launch_plans || !admission_workspace.listener_plans ||
        !admission_workspace.route_rules || !admission_workspace.route_ack_entries ||
        !admission_workspace.capture_nodes || !admission_workspace.capture_gateways ||
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
    if (wvm_admission_evidence_owner_init(
            &admission_workspace.evidence_owner,
            admission_workspace.capabilities, admission_workspace.capacity,
            admission_workspace.reservations, admission_workspace.capacity,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "wvm_ctl: cannot initialize evidence owner: %s\n", error);
        goto close_plane;
    }
    if (wvm_admission_plan_provider_init(
            &admission_workspace.plan_provider,
            admission_workspace.launch_plans, admission_workspace.capacity,
            admission_workspace.listener_plans, admission_workspace.capacity,
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
    if (wvm_admission_transport_init(
            &admission_workspace.transport,
            options.local_physical_node_id,
            options.local_runtime_instance_id,
            NULL,
            admission_transport_resolve_node,
            admission_transport_submit,
            admission_transport_ready,
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
    authority_config.activation_options = &admission_workspace.activation_options;
    authority_config.activation = &admission_workspace.activation;
    authority_config.route_transaction = &admission_workspace.route_transaction;
    authority_config.route_snapshot = &admission_workspace.route_snapshot;
    authority_config.workspace_context = NULL;
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
    service_config.control_apply = apply_create_vm;
    service_config.control_apply_opaque = &control_context;
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
    if (control_context.lock_initialized) {
        pthread_mutex_destroy(&control_context.lock);
    }
    destroy_principals(&auth);
    free(admission_workspace.route_ack_set_bytes);
    free(admission_workspace.route_snapshot_bytes);
    free(admission_workspace.capture_gateways);
    free(admission_workspace.capture_nodes);
    free(admission_workspace.route_ack_entries);
    free(admission_workspace.route_rules);
    free(admission_workspace.listener_plans);
    free(admission_workspace.launch_plans);
    free(admission_workspace.reservations);
    free(admission_workspace.capabilities);
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

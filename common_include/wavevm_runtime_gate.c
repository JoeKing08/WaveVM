#include "wavevm_runtime_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_canonical.h"
#include "wavevm_config.h"
#include "wavevm_sha256.h"

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

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t i;

    for (i = 0; i < byte_count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int route_snapshot_key_equal(
    const struct wvm_route_snapshot_key *left,
    const struct wvm_route_snapshot_key *right)
{
    return left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id == right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  sizeof(left->snapshot_digest)) == 0;
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static int list_count(const uint8_t *bytes, size_t byte_count,
                      size_t max_count, size_t *count_out)
{
    uint32_t count;

    if (!bytes || byte_count < sizeof(uint32_t) || !count_out) {
        return -1;
    }
    count = read_be32(bytes);
    if ((size_t)count > max_count) {
        return -1;
    }
    *count_out = count;
    return 0;
}

static int find_list_counts(
    const uint8_t *bytes, size_t byte_count, size_t *vcpu_count,
    size_t *memory_count, size_t *storage_count, size_t *capability_count,
    size_t *dependency_count)
{
    struct wvm_canonical_record record;
    struct wvm_canonical_field field;
    size_t offset = 0;
    int next;

    if (!bytes || !vcpu_count || !memory_count || !storage_count ||
        !capability_count || !dependency_count ||
        wvm_canonical_record_parse(bytes, byte_count, &record) != 0 ||
        record.record_type != WVM_RECORD_NODE_RUNTIME_MANIFEST) {
        return -1;
    }

    *vcpu_count = 0;
    *memory_count = 0;
    *storage_count = 0;
    *capability_count = 0;
    *dependency_count = 0;
    while ((next = wvm_canonical_record_next(&record, &offset, &field)) == 1) {
        if (field.tag == 11 &&
            list_count(field.value, field.value_bytes, WVM_CPU_ROUTE_TABLE_SIZE,
                       vcpu_count) != 0) {
            return -1;
        }
        if (field.tag == 12 &&
            list_count(field.value, field.value_bytes,
                       WVM_MEMORY_ROUTE_TABLE_SIZE, memory_count) != 0) {
            return -1;
        }
        if (field.tag == 13 &&
            list_count(field.value, field.value_bytes,
                       WVM_MEMORY_ROUTE_TABLE_SIZE, storage_count) != 0) {
            return -1;
        }
        if (field.tag == 16) {
            struct wvm_canonical_record profile;
            struct wvm_canonical_field profile_field;
            size_t profile_offset = 0;
            int profile_next;

            if (wvm_canonical_record_parse(field.value, field.value_bytes,
                                           &profile) != 0 ||
                profile.record_type != WVM_RECORD_EXECUTION_FAULT_PROFILE) {
                return -1;
            }
            while ((profile_next = wvm_canonical_record_next(
                        &profile, &profile_offset, &profile_field)) == 1) {
                if (profile_field.tag == 7 &&
                    list_count(profile_field.value, profile_field.value_bytes,
                               WVM_RUNTIME_MAX_CAPABILITIES,
                               capability_count) != 0) {
                    return -1;
                }
            }
            if (profile_next < 0) {
                return -1;
            }
        }
        if (field.tag == 18 &&
            list_count(field.value, field.value_bytes,
                       WVM_RUNTIME_MAX_DEPENDENCIES, dependency_count) != 0) {
            return -1;
        }
    }
    return next < 0 ? -1 : 0;
}

void wvm_runtime_manifest_storage_init(
    struct wvm_runtime_manifest_storage *storage)
{
    if (storage) {
        memset(storage, 0, sizeof(*storage));
    }
}

void wvm_runtime_manifest_storage_free(
    struct wvm_runtime_manifest_storage *storage)
{
    if (!storage) {
        return;
    }
    free(storage->local_vcpus);
    free(storage->local_memory);
    free(storage->local_storage);
    free(storage->capabilities);
    free(storage->dependencies);
    memset(storage, 0, sizeof(*storage));
}

static int read_file(const char *path, uint8_t **bytes_out, size_t *bytes_count,
                     char *error, size_t error_len)
{
    struct stat st;
    uint8_t *bytes;
    size_t offset = 0;
    int fd;

    if (!path || !bytes_out || !bytes_count ||
        stat(path, &st) != 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > WVM_RUNTIME_MANIFEST_MAX_BYTES) {
        set_error(error, error_len, "manifest file size is invalid");
        return -1;
    }
    bytes = malloc((size_t)st.st_size);
    if (!bytes) {
        set_error(error, error_len, "cannot allocate manifest file buffer");
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        free(bytes);
        set_error(error, error_len, "cannot open manifest: %s", strerror(errno));
        return -1;
    }
    while (offset < (size_t)st.st_size) {
        ssize_t received = read(fd, bytes + offset,
                                (size_t)st.st_size - offset);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            close(fd);
            free(bytes);
            set_error(error, error_len, "cannot read manifest: %s",
                      received == 0 ? "unexpected EOF" : strerror(errno));
            return -1;
        }
        offset += (size_t)received;
    }
    close(fd);
    *bytes_out = bytes;
    *bytes_count = offset;
    return 0;
}

static int write_full(int fd, const uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t written = write(fd, bytes + offset, byte_count - offset);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int path_parent(const char *path, char *parent, size_t capacity)
{
    const char *slash;
    size_t length;

    if (!path || !parent || capacity == 0) {
        return -1;
    }
    slash = strrchr(path, '/');
    if (!slash) {
        return snprintf(parent, capacity, ".") < (int)capacity ? 0 : -1;
    }
    length = (size_t)(slash - path);
    if (length == 0) {
        length = 1;
    }
    if (length + 1 > capacity) {
        return -1;
    }
    memcpy(parent, path, length);
    parent[length] = '\0';
    return 0;
}

static int encode_runtime_manifest_alloc(
    const struct wvm_node_runtime_manifest *manifest, uint8_t **bytes_out,
    size_t *byte_count_out, char *error, size_t error_len)
{
    size_t capacity = 4096;

    if (!manifest || !bytes_out || !byte_count_out) {
        set_error(error, error_len, "runtime manifest publish input is invalid");
        return -1;
    }
    while (capacity <= WVM_RUNTIME_MANIFEST_MAX_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate runtime manifest");
            return -1;
        }
        if (wvm_node_runtime_manifest_encode(manifest, bytes, capacity,
                                             &byte_count, error,
                                             error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_RUNTIME_MANIFEST_MAX_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_RUNTIME_MANIFEST_MAX_BYTES) {
            capacity = WVM_RUNTIME_MANIFEST_MAX_BYTES;
        }
    }
    set_error(error, error_len, "runtime manifest exceeds delivery limit");
    return -1;
}

int wvm_runtime_manifest_file_publish(
    const char *path, const struct wvm_node_runtime_manifest *manifest,
    char *error, size_t error_len)
{
    uint8_t *bytes = NULL;
    size_t byte_count = 0;
    char temporary[4096];
    char parent[4096];
    int fd = -1;
    int directory_fd = -1;
    int result = -1;
    int written;

    temporary[0] = '\0';
    if (!path || path[0] == '\0' || !manifest || !manifest->has_activation_fence ||
        wvm_node_runtime_manifest_validate(manifest, error, error_len) != 0 ||
        encode_runtime_manifest_alloc(manifest, &bytes, &byte_count, error,
                                     error_len) != 0 ||
        path_parent(path, parent, sizeof(parent)) != 0) {
        set_error(error, error_len, "runtime manifest publish input is invalid");
        goto out;
    }
    written = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
                       (long)getpid());
    if (written < 0 || (size_t)written >= sizeof(temporary)) {
        set_error(error, error_len,
                  "temporary runtime manifest path is too long");
        goto out;
    }
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        set_error(error, error_len, "cannot create runtime manifest: %s",
                  strerror(errno));
        goto out;
    }
    if (write_full(fd, bytes, byte_count) != 0 || fsync(fd) != 0 ||
        close(fd) != 0) {
        fd = -1;
        set_error(error, error_len, "cannot fsync runtime manifest: %s",
                  strerror(errno));
        goto out;
    }
    fd = -1;
    if (rename(temporary, path) != 0) {
        set_error(error, error_len, "cannot activate runtime manifest: %s",
                  strerror(errno));
        goto out;
    }
    directory_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || fsync(directory_fd) != 0) {
        set_error(error, error_len,
                  "cannot fsync runtime manifest directory: %s",
                  strerror(errno));
        goto out;
    }
    result = 0;

out:
    if (fd >= 0) {
        close(fd);
    }
    if (directory_fd >= 0) {
        close(directory_fd);
    }
    if (result != 0 && temporary[0] != '\0') {
        unlink(temporary);
    }
    free(bytes);
    return result;
}

int wvm_runtime_manifest_load_file(
    const char *path, struct wvm_runtime_manifest_storage *storage,
    char *error, size_t error_len)
{
    uint8_t *bytes = NULL;
    size_t byte_count = 0;
    size_t vcpu_count;
    size_t memory_count;
    size_t storage_count;
    size_t capability_count;
    size_t dependency_count;
    int result = -1;

    if (!storage) {
        set_error(error, error_len, "manifest storage is missing");
        return -1;
    }
    if (read_file(path, &bytes, &byte_count, error, error_len) != 0) {
        if (bytes) {
            free(bytes);
        }
        wvm_runtime_manifest_storage_free(storage);
        return -1;
    }
    if (find_list_counts(bytes, byte_count, &vcpu_count, &memory_count,
                         &storage_count, &capability_count,
                         &dependency_count) != 0) {
        if (bytes) {
            free(bytes);
        }
        wvm_runtime_manifest_storage_free(storage);
        set_error(error, error_len, "manifest list layout is invalid");
        return -1;
    }

    wvm_runtime_manifest_storage_free(storage);
    storage->local_vcpus = calloc(vcpu_count ? vcpu_count : 1,
                                  sizeof(*storage->local_vcpus));
    storage->local_memory = calloc(memory_count ? memory_count : 1,
                                   sizeof(*storage->local_memory));
    storage->local_storage = calloc(storage_count ? storage_count : 1,
                                    sizeof(*storage->local_storage));
    storage->capabilities = calloc(capability_count ? capability_count : 1,
                                   sizeof(*storage->capabilities));
    storage->dependencies = calloc(dependency_count ? dependency_count : 1,
                                   sizeof(*storage->dependencies));
    if (!storage->local_vcpus || !storage->local_memory ||
        !storage->local_storage || !storage->capabilities ||
        !storage->dependencies) {
        set_error(error, error_len, "cannot allocate manifest list storage");
        goto out;
    }

    storage->manifest.local_vcpu_assignments.entries = storage->local_vcpus;
    storage->manifest.local_vcpu_assignments.capacity = vcpu_count;
    storage->manifest.local_memory_assignments.entries = storage->local_memory;
    storage->manifest.local_memory_assignments.capacity = memory_count;
    storage->manifest.local_storage_assignments.entries = storage->local_storage;
    storage->manifest.local_storage_assignments.capacity = storage_count;
    storage->manifest.negotiated_profile.per_node_capabilities.entries =
        storage->capabilities;
    storage->manifest.negotiated_profile.per_node_capabilities.capacity =
        capability_count;
    storage->manifest.startup_dependencies.entries = storage->dependencies;
    storage->manifest.startup_dependencies.capacity = dependency_count;
    if (wvm_node_runtime_manifest_decode(
            bytes, byte_count, &storage->manifest, error, error_len) != 0) {
        goto out;
    }
    result = 0;

out:
    free(bytes);
    if (result != 0) {
        wvm_runtime_manifest_storage_free(storage);
    }
    return result;
}

int wvm_runtime_manifest_profile_digest(
    const struct wvm_node_runtime_manifest *manifest,
    uint8_t digest[WVM_SHA256_DIGEST_BYTES], char *error, size_t error_len)
{
    uint8_t *bytes;
    size_t encoded_bytes;

    if (!manifest || !digest ||
        wvm_execution_fault_profile_validate(&manifest->negotiated_profile,
                                             error, error_len) != 0) {
        return -1;
    }
    bytes = malloc(WVM_RUNTIME_MANIFEST_MAX_BYTES);
    if (!bytes) {
        set_error(error, error_len, "cannot allocate profile digest buffer");
        return -1;
    }
    if (wvm_execution_fault_profile_encode(
            &manifest->negotiated_profile, bytes, WVM_RUNTIME_MANIFEST_MAX_BYTES,
            &encoded_bytes, error, error_len) != 0) {
        free(bytes);
        return -1;
    }
    wvm_sha256_digest(bytes, encoded_bytes, digest);
    free(bytes);
    return 0;
}

void wvm_runtime_gate_init(struct wvm_runtime_gate *gate)
{
    if (gate) {
        memset(gate, 0, sizeof(*gate));
        gate->state = WVM_RUNTIME_GATE_EMPTY;
        gate->next_connection_id = 1;
    }
}

static int runtime_manifest_equal(
    const struct wvm_node_runtime_manifest *left,
    const struct wvm_node_runtime_manifest *right, char *error,
    size_t error_len)
{
    size_t capacity = 4096U;

    while (capacity <= WVM_RUNTIME_MANIFEST_MAX_BYTES) {
        uint8_t *left_bytes = malloc(capacity);
        uint8_t *right_bytes = malloc(capacity);
        size_t left_count = 0;
        size_t right_count = 0;
        int equal;

        if (!left_bytes || !right_bytes) {
            free(left_bytes);
            free(right_bytes);
            set_error(error, error_len,
                      "cannot allocate runtime manifest comparison");
            return -1;
        }
        if (wvm_node_runtime_manifest_encode(left, left_bytes, capacity,
                                             &left_count, error, error_len) ==
                0 &&
            wvm_node_runtime_manifest_encode(right, right_bytes, capacity,
                                             &right_count, error, error_len) ==
                0) {
            equal = left_count == right_count &&
                    memcmp(left_bytes, right_bytes, left_count) == 0;
            free(right_bytes);
            free(left_bytes);
            return equal;
        }
        free(right_bytes);
        free(left_bytes);
        if (capacity == WVM_RUNTIME_MANIFEST_MAX_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_RUNTIME_MANIFEST_MAX_BYTES) {
            capacity = WVM_RUNTIME_MANIFEST_MAX_BYTES;
        }
    }
    set_error(error, error_len, "runtime manifest exceeds gate comparison limit");
    return -1;
}

static int runtime_manifest_same_prepared_projection(
    const struct wvm_node_runtime_manifest *prepared,
    const struct wvm_node_runtime_manifest *activated, char *error,
    size_t error_len)
{
    struct wvm_node_runtime_manifest normalized_prepared;
    struct wvm_node_runtime_manifest normalized_activated;

    if (!prepared || !activated || prepared->has_activation_fence ||
        !activated->has_activation_fence) {
        set_error(error, error_len,
                  "runtime manifest activation transition is invalid");
        return -1;
    }
    normalized_prepared = *prepared;
    normalized_activated = *activated;
    normalized_prepared.has_activation_fence = 0;
    normalized_activated.has_activation_fence = 0;
    memset(normalized_prepared.activation_fence, 0,
           sizeof(normalized_prepared.activation_fence));
    memset(normalized_activated.activation_fence, 0,
           sizeof(normalized_activated.activation_fence));
    return runtime_manifest_equal(&normalized_prepared, &normalized_activated,
                                  error, error_len);
}

int wvm_runtime_gate_prepare(
    struct wvm_runtime_gate *gate,
    struct wvm_node_runtime_manifest *manifest,
    uint32_t local_physical_node_id, uint64_t local_node_instance_id,
    char *error, size_t error_len)
{
    if (!gate || !manifest ||
        wvm_node_runtime_manifest_validate(manifest, error, error_len) != 0 ||
        local_physical_node_id == 0 || local_node_instance_id == 0 ||
        manifest->physical_node_id != local_physical_node_id ||
        manifest->expected_node_instance_id != local_node_instance_id ||
        (gate->state != WVM_RUNTIME_GATE_EMPTY &&
         gate->manifest != manifest)) {
        set_error(error, error_len,
                  "local manifest does not match runtime participant");
        return -1;
    }
    gate->manifest = manifest;
    gate->local_physical_node_id = local_physical_node_id;
    gate->local_node_instance_id = local_node_instance_id;
    gate->state = WVM_RUNTIME_GATE_PREPARED;
    return 0;
}

int wvm_runtime_gate_bind_activation(
    struct wvm_runtime_gate *gate,
    const struct wvm_node_runtime_manifest *activated_manifest, char *error,
    size_t error_len)
{
    if (!gate || !gate->manifest || !activated_manifest ||
        (gate->state != WVM_RUNTIME_GATE_PREPARED &&
         gate->state != WVM_RUNTIME_GATE_ACTIVE) ||
        wvm_node_runtime_manifest_validate(activated_manifest, error,
                                           error_len) != 0 ||
        activated_manifest->physical_node_id != gate->local_physical_node_id ||
        activated_manifest->expected_node_instance_id !=
            gate->local_node_instance_id) {
        set_error(error, error_len,
                  "activation manifest does not match prepared projection");
        return -1;
    }
    if (gate->state == WVM_RUNTIME_GATE_ACTIVE) {
        if (runtime_manifest_equal(gate->manifest, activated_manifest, error,
                                   error_len) != 1) {
            set_error(error, error_len,
                      "activation replay does not match active projection");
            return -1;
        }
        return 0;
    }
    if (runtime_manifest_same_prepared_projection(
            gate->manifest, activated_manifest, error, error_len) != 1) {
        set_error(error, error_len,
                  "activation manifest does not match prepared projection");
        return -1;
    }
    gate->manifest->has_activation_fence = 1;
    memcpy(gate->manifest->activation_fence, activated_manifest->activation_fence,
           sizeof(gate->manifest->activation_fence));
    return 0;
}

int wvm_runtime_gate_activate(
    struct wvm_runtime_gate *gate,
    const uint8_t activation_fence[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    if (!gate || !gate->manifest ||
        (gate->state != WVM_RUNTIME_GATE_PREPARED &&
         gate->state != WVM_RUNTIME_GATE_ACTIVE) ||
        !activation_fence || bytes_are_zero(activation_fence,
                                             WVM_IDENTITY_ID_BYTES) ||
        !gate->manifest->has_activation_fence ||
        memcmp(activation_fence, gate->manifest->activation_fence,
               WVM_IDENTITY_ID_BYTES) != 0) {
        set_error(error, error_len,
                  "activation fence does not match admitted manifest");
        return -1;
    }
    if (gate->state == WVM_RUNTIME_GATE_ACTIVE) {
        return 0;
    }
    gate->state = WVM_RUNTIME_GATE_ACTIVE;
    return 0;
}

int wvm_runtime_gate_abort_prepared(
    struct wvm_runtime_gate *gate,
    const struct wvm_node_runtime_manifest *prepared_manifest, char *error,
    size_t error_len)
{
    int equal;

    if (!gate || !gate->manifest || !prepared_manifest ||
        gate->state != WVM_RUNTIME_GATE_PREPARED ||
        prepared_manifest->has_activation_fence) {
        set_error(error, error_len, "runtime gate is not abortable");
        return -1;
    }
    equal = runtime_manifest_equal(gate->manifest, prepared_manifest, error,
                                   error_len);
    if (equal != 1) {
        if (equal == 0) {
            set_error(error, error_len,
                      "runtime abort does not match prepared projection");
        }
        return -1;
    }
    wvm_runtime_gate_init(gate);
    return 0;
}

int wvm_runtime_gate_quiesce(struct wvm_runtime_gate *gate, char *error,
                             size_t error_len)
{
    size_t i;

    if (!gate || gate->state != WVM_RUNTIME_GATE_ACTIVE) {
        set_error(error, error_len, "runtime gate is not active");
        return -1;
    }
    gate->state = WVM_RUNTIME_GATE_QUIESCING;
    for (i = 0; i < WVM_RUNTIME_MAX_CONNECTIONS; i++) {
        if (gate->connections[i].state ==
            WVM_RUNTIME_CONNECTION_REGISTERED) {
            gate->connections[i].state = WVM_RUNTIME_CONNECTION_REVOKED;
        }
    }
    return 0;
}

static int registration_matches_manifest(
    const struct wvm_runtime_gate *gate,
    const struct wvm_runtime_registration *registration, char *error,
    size_t error_len)
{
    uint8_t profile_digest[WVM_SHA256_DIGEST_BYTES];

    if (!gate || !gate->manifest || !registration ||
        registration->connection_role < WVM_MANIFEST_ROLE_NODE_RUNTIME ||
        registration->connection_role > WVM_MANIFEST_ROLE_KERNEL_CONTEXT ||
        !(gate->manifest->local_role_bits &
          WVM_RUNTIME_ROLE_BIT(registration->connection_role)) ||
        registration->vm_id != gate->manifest->vm_id ||
        registration->vm_incarnation != gate->manifest->vm_incarnation ||
        registration->manifest_generation != gate->manifest->manifest_generation ||
        memcmp(registration->candidate_manifest_digest,
               gate->manifest->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        registration->local_runtime_instance_id == 0 ||
        registration->caller_process_instance_id == 0 ||
        strcmp(registration->requested_endpoint_name,
               gate->manifest->local_names.namespace_name) != 0 ||
        bytes_are_zero(registration->capability_profile_digest,
                       WVM_SHA256_DIGEST_BYTES) ||
        wvm_runtime_manifest_profile_digest(gate->manifest, profile_digest,
                                            error, error_len) != 0 ||
        memcmp(registration->capability_profile_digest, profile_digest,
               sizeof(profile_digest)) != 0) {
        set_error(error, error_len,
                  "local registration does not match admitted manifest");
        return -1;
    }
    return 0;
}

int wvm_runtime_gate_register(
    struct wvm_runtime_gate *gate,
    const struct wvm_runtime_registration *registration,
    uint64_t *connection_id_out, char *error, size_t error_len)
{
    size_t i;

    if (!gate || !registration) {
        set_error(error, error_len, "runtime registration rejected");
        return -1;
    }
    if (gate->state != WVM_RUNTIME_GATE_PREPARED &&
        gate->state != WVM_RUNTIME_GATE_ACTIVE) {
        set_error(error, error_len, "runtime gate is not open for registration");
        return -1;
    }
    if (registration_matches_manifest(gate, registration, error, error_len) !=
        0) {
        /* Keep the specific mismatch reason from registration_matches_manifest. */
        if (!error || error_len == 0 || error[0] == '\0') {
            set_error(error, error_len, "runtime registration rejected");
        }
        return -1;
    }
    /* One registration represents one local transport connection. */
    for (i = 0; i < WVM_RUNTIME_MAX_CONNECTIONS; i++) {
        struct wvm_runtime_connection *connection = &gate->connections[i];

        if (connection->state == WVM_RUNTIME_CONNECTION_REVOKED ||
            connection->connection_id == 0) {
            if (gate->next_connection_id == 0) {
                set_error(error, error_len, "runtime connection ID exhausted");
                return -1;
            }
            connection->connection_id = gate->next_connection_id++;
            connection->role = registration->connection_role;
            connection->caller_process_instance_id =
                registration->caller_process_instance_id;
            connection->state = WVM_RUNTIME_CONNECTION_REGISTERED;
            if (connection_id_out) {
                *connection_id_out = connection->connection_id;
            }
            return 0;
        }
    }
    set_error(error, error_len, "runtime connection table is full");
    return -1;
}

int wvm_runtime_gate_revoke(struct wvm_runtime_gate *gate,
                            uint64_t connection_id, char *error,
                            size_t error_len)
{
    size_t i;

    if (!gate || connection_id == 0) {
        set_error(error, error_len, "runtime connection ID is invalid");
        return -1;
    }
    for (i = 0; i < WVM_RUNTIME_MAX_CONNECTIONS; i++) {
        if (gate->connections[i].connection_id == connection_id &&
            gate->connections[i].state ==
                WVM_RUNTIME_CONNECTION_REGISTERED) {
            gate->connections[i].state = WVM_RUNTIME_CONNECTION_REVOKED;
            return 0;
        }
    }
    set_error(error, error_len, "runtime connection is not registered");
    return -1;
}

int wvm_runtime_gate_authorize(
    const struct wvm_runtime_gate *gate,
    const struct wvm_runtime_operation *operation, char *error,
    size_t error_len)
{
    size_t i;
    int found = 0;

    if (!gate || !operation || gate->state != WVM_RUNTIME_GATE_ACTIVE ||
        !gate->manifest || operation->connection_id == 0 ||
        operation->vm_id != gate->manifest->vm_id ||
        operation->vm_incarnation != gate->manifest->vm_incarnation ||
        operation->manifest_generation != gate->manifest->manifest_generation ||
        memcmp(operation->candidate_manifest_digest,
               gate->manifest->candidate_manifest_digest,
               WVM_SHA256_DIGEST_BYTES) != 0 ||
        !route_snapshot_key_equal(&operation->route_snapshot_key,
                                  &gate->manifest->required_route_snapshot_key) ||
        memcmp(operation->activation_fence, gate->manifest->activation_fence,
               WVM_IDENTITY_ID_BYTES) != 0 ||
        bytes_are_zero(operation->operation_id, WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len, "semantic operation failed manifest gate");
        return -1;
    }
    for (i = 0; i < WVM_RUNTIME_MAX_CONNECTIONS; i++) {
        if (gate->connections[i].connection_id == operation->connection_id &&
            gate->connections[i].state ==
                WVM_RUNTIME_CONNECTION_REGISTERED) {
            found = 1;
            break;
        }
    }
    if (!found) {
        set_error(error, error_len, "semantic operation uses unknown connection");
        return -1;
    }
    return 0;
}

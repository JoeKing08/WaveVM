#define _POSIX_C_SOURCE 200809L

#include "wavevm_membership_controller.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "wavevm_sha256.h"

#define WVM_MEMBERSHIP_JOURNAL_VERSION 1U
#define WVM_MEMBERSHIP_JOURNAL_HEADER_BYTES 56U

enum wvm_membership_journal_kind {
    WVM_MEMBERSHIP_JOURNAL_REGISTER_NODE = 1,
    WVM_MEMBERSHIP_JOURNAL_REGISTER_GATEWAY = 2,
    WVM_MEMBERSHIP_JOURNAL_MEMBER_STATE = 3,
    WVM_MEMBERSHIP_JOURNAL_ROUTE_BEGIN = 4,
    WVM_MEMBERSHIP_JOURNAL_ROUTE_ACK = 5,
    WVM_MEMBERSHIP_JOURNAL_ROUTE_STATE = 6,
    WVM_MEMBERSHIP_JOURNAL_DEPENDENCY = 7,
    WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_PREPARE = 8,
    WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_COMMIT = 9,
    WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_ABORT = 10,
    WVM_MEMBERSHIP_JOURNAL_MEMBER_ACTIVATION_BINDING = 11,
};

static const uint8_t membership_journal_magic[8] = {
    'W', 'V', 'M', 'M', 'C', 'T', 'L', '1',
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

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_be32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_be64(uint8_t *bytes, uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        bytes[7U - i] = (uint8_t)(value >> (8U * i));
    }
}

static uint16_t read_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t read_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
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

/*
 * Returns one for a complete read, zero for clean EOF, and minus one for a
 * torn record.  Torn journal tails are discarded by open().
 */
static int read_full(int fd, uint8_t *bytes, size_t byte_count)
{
    size_t offset = 0;

    while (offset < byte_count) {
        ssize_t received = read(fd, bytes + offset, byte_count - offset);

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            return offset == 0 ? 0 : -1;
        }
        offset += (size_t)received;
    }
    return 1;
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

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int member_role_equal(const struct wvm_member_key *left,
                             const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id;
}

static int route_snapshot_key_equal(
    const struct wvm_route_snapshot_key *left,
    const struct wvm_route_snapshot_key *right)
{
    return left && right &&
           left->scope_key.vm_id == right->scope_key.vm_id &&
           left->scope_key.vm_incarnation == right->scope_key.vm_incarnation &&
           left->scope_key.route_scope_id ==
               right->scope_key.route_scope_id &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int dependency_equal(const struct wvm_membership_dependency *left,
                            const struct wvm_membership_dependency *right)
{
    return left && right && member_key_equal(&left->member_key,
                                              &right->member_key) &&
           left->vm_id == right->vm_id &&
           left->vm_incarnation == right->vm_incarnation &&
           left->manifest_generation == right->manifest_generation &&
           left->dependency_kind == right->dependency_kind;
}

static int valid_health(enum wvm_membership_health_state health_state)
{
    return health_state >= WVM_MEMBERSHIP_HEALTHY &&
           health_state <= WVM_MEMBERSHIP_RECOVERING;
}

static int valid_member_state(enum wvm_manifest_member_state state)
{
    return state >= WVM_MANIFEST_MEMBER_PENDING &&
           state <= WVM_MANIFEST_MEMBER_FAILED;
}

static enum wvm_manifest_member_state
entry_state(const struct wvm_membership_controller_member_entry *entry)
{
    return entry->kind == WVM_MEMBERSHIP_COMPUTE
               ? entry->node.desired_membership_state
               : entry->gateway.desired_membership_state;
}

static enum wvm_membership_health_state
entry_health(const struct wvm_membership_controller_member_entry *entry)
{
    return (enum wvm_membership_health_state)(
        entry->kind == WVM_MEMBERSHIP_COMPUTE
            ? entry->node.observed_health_state
            : entry->gateway.observed_health_state);
}

static void entry_set_state(
    struct wvm_membership_controller_member_entry *entry,
    enum wvm_manifest_member_state state,
    enum wvm_membership_health_state health, uint64_t membership_revision,
    uint64_t topology_revision)
{
    if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
        entry->node.desired_membership_state = state;
        entry->node.observed_health_state = (uint16_t)health;
        entry->node.membership_revision = membership_revision;
        entry->node.topology_revision = topology_revision;
    } else {
        entry->gateway.desired_membership_state = state;
        entry->gateway.observed_health_state = (uint16_t)health;
        entry->gateway.membership_revision = membership_revision;
        entry->gateway.topology_revision = topology_revision;
    }
}

static uint64_t entry_membership_revision(
    const struct wvm_membership_controller_member_entry *entry)
{
    return entry->kind == WVM_MEMBERSHIP_COMPUTE
               ? entry->node.membership_revision
               : entry->gateway.membership_revision;
}

static uint64_t entry_topology_revision(
    const struct wvm_membership_controller_member_entry *entry)
{
    return entry->kind == WVM_MEMBERSHIP_COMPUTE
               ? entry->node.topology_revision
               : entry->gateway.topology_revision;
}

static void stamp_all_members(struct wvm_membership_controller *controller,
                              uint64_t membership_revision,
                              uint64_t topology_revision)
{
    size_t i;

    for (i = 0; i < controller->member_count; i++) {
        struct wvm_membership_controller_member_entry *entry =
            &controller->members[i];

        entry_set_state(entry, entry_state(entry), entry_health(entry),
                        membership_revision, topology_revision);
    }
}

static void entry_free(struct wvm_membership_controller_member_entry *entry)
{
    if (!entry) {
        return;
    }
    free(entry->node.inventory.hosted_gateway_role_ids);
    free(entry->gateway.parent_gateway_ids);
    free(entry->gateway.child_gateway_ids);
    memset(entry, 0, sizeof(*entry));
}

static void route_entry_free(
    struct wvm_membership_controller_route_entry *entry)
{
    if (!entry) {
        return;
    }
    free(entry->required_ack_entries);
    free(entry->optional_departure_entries);
    free(entry->required_ack_states);
    memset(entry, 0, sizeof(*entry));
}

static struct wvm_membership_controller_member_entry *find_member_mutable(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key)
{
    size_t i;

    if (!controller || !member_key) {
        return NULL;
    }
    for (i = 0; i < controller->member_count; i++) {
        if (member_key_equal(&controller->members[i].member_key, member_key)) {
            return &controller->members[i];
        }
    }
    return NULL;
}

const struct wvm_membership_controller_member_entry *
wvm_membership_controller_find(
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key)
{
    size_t i;

    if (!controller || !member_key) {
        return NULL;
    }
    for (i = 0; i < controller->member_count; i++) {
        if (member_key_equal(&controller->members[i].member_key, member_key)) {
            return &controller->members[i];
        }
    }
    return NULL;
}

static struct wvm_membership_controller_member_entry *find_member_role(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key)
{
    size_t i;

    if (!controller || !member_key) {
        return NULL;
    }
    for (i = 0; i < controller->member_count; i++) {
        if (member_role_equal(&controller->members[i].member_key, member_key)) {
            return &controller->members[i];
        }
    }
    return NULL;
}

static struct wvm_membership_controller_route_entry *find_route_mutable(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    size_t i;

    if (!controller || !operation_id) {
        return NULL;
    }
    for (i = 0; i < controller->route_count; i++) {
        if (memcmp(controller->routes[i].transaction.operation_id, operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return &controller->routes[i];
        }
    }
    return NULL;
}

static struct wvm_membership_controller_route_entry *
find_activated_route_by_snapshot_key(
    struct wvm_membership_controller *controller,
    const struct wvm_route_snapshot_key *route_snapshot_key)
{
    size_t i;

    if (!controller || !route_snapshot_key) {
        return NULL;
    }
    for (i = 0; i < controller->route_count; i++) {
        struct wvm_membership_controller_route_entry *route =
            &controller->routes[i];

        if (route->transaction.state == WVM_ROUTE_TRANSACTION_ACTIVATED &&
            route_snapshot_key_equal(&route->transaction.route_snapshot_key,
                                     route_snapshot_key)) {
            return route;
        }
    }
    return NULL;
}

static void node_member_key(const struct wvm_node_record *node,
                            struct wvm_member_key *member_key)
{
    memset(member_key, 0, sizeof(*member_key));
    member_key->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    member_key->role_id = node->physical_node_id;
    member_key->instance_id = node->node_instance_id;
}

static void gateway_member_key(const struct wvm_gateway_record *gateway,
                               struct wvm_member_key *member_key)
{
    memset(member_key, 0, sizeof(*member_key));
    member_key->role_type = WVM_MANIFEST_ROLE_GATEWAY;
    member_key->role_id = gateway->gateway_id;
    member_key->instance_id = gateway->gateway_instance_id;
}

static int clone_node_entry(
    struct wvm_membership_controller_member_entry *destination,
    const struct wvm_node_record *node, char *error, size_t error_len)
{
    uint32_t *gateway_ids = NULL;
    size_t count;

    if (!destination || !node) {
        return -1;
    }
    count = node->inventory.hosted_gateway_role_id_count;
    if (count != 0) {
        gateway_ids = calloc(count, sizeof(*gateway_ids));
        if (!gateway_ids) {
            set_error(error, error_len, "cannot allocate node gateway roles");
            return -1;
        }
        memcpy(gateway_ids, node->inventory.hosted_gateway_role_ids,
               count * sizeof(*gateway_ids));
    }
    memset(destination, 0, sizeof(*destination));
    destination->kind = WVM_MEMBERSHIP_COMPUTE;
    destination->node = *node;
    destination->node.inventory.hosted_gateway_role_ids = gateway_ids;
    destination->node.inventory.hosted_gateway_role_id_count = count;
    destination->node.inventory.hosted_gateway_role_id_capacity = count;
    node_member_key(node, &destination->member_key);
    return 0;
}

static int clone_gateway_entry(
    struct wvm_membership_controller_member_entry *destination,
    const struct wvm_gateway_record *gateway, char *error, size_t error_len)
{
    uint32_t *parents = NULL;
    uint32_t *children = NULL;
    size_t parent_count;
    size_t child_count;

    if (!destination || !gateway) {
        return -1;
    }
    parent_count = gateway->parent_gateway_id_count;
    child_count = gateway->child_gateway_id_count;
    if (parent_count != 0) {
        parents = calloc(parent_count, sizeof(*parents));
        if (!parents) {
            set_error(error, error_len, "cannot allocate gateway parents");
            return -1;
        }
        memcpy(parents, gateway->parent_gateway_ids,
               parent_count * sizeof(*parents));
    }
    if (child_count != 0) {
        children = calloc(child_count, sizeof(*children));
        if (!children) {
            free(parents);
            set_error(error, error_len, "cannot allocate gateway children");
            return -1;
        }
        memcpy(children, gateway->child_gateway_ids,
               child_count * sizeof(*children));
    }
    memset(destination, 0, sizeof(*destination));
    destination->kind = WVM_MEMBERSHIP_GATEWAY;
    destination->gateway = *gateway;
    destination->gateway.parent_gateway_ids = parents;
    destination->gateway.parent_gateway_id_count = parent_count;
    destination->gateway.parent_gateway_id_capacity = parent_count;
    destination->gateway.child_gateway_ids = children;
    destination->gateway.child_gateway_id_count = child_count;
    destination->gateway.child_gateway_id_capacity = child_count;
    gateway_member_key(gateway, &destination->member_key);
    return 0;
}

static int clone_route_entry(
    struct wvm_membership_controller_route_entry *destination,
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len)
{
    size_t required_count;
    size_t optional_count;

    if (!destination || !transaction) {
        return -1;
    }
    required_count = transaction->required_ack_set.entries.count;
    optional_count = transaction->optional_departure_drain_set.count;
    memset(destination, 0, sizeof(*destination));
    destination->required_ack_entries =
        calloc(required_count, sizeof(*destination->required_ack_entries));
    destination->required_ack_states =
        calloc(required_count, sizeof(*destination->required_ack_states));
    if (!destination->required_ack_entries ||
        !destination->required_ack_states) {
        route_entry_free(destination);
        set_error(error, error_len, "cannot allocate required route ACK set");
        return -1;
    }
    if (optional_count != 0) {
        destination->optional_departure_entries =
            calloc(optional_count,
                   sizeof(*destination->optional_departure_entries));
        if (!destination->optional_departure_entries) {
            route_entry_free(destination);
            set_error(error, error_len,
                      "cannot allocate optional route drain set");
            return -1;
        }
    }
    memcpy(destination->required_ack_entries,
           transaction->required_ack_set.entries.entries,
           required_count * sizeof(*destination->required_ack_entries));
    {
        size_t i;

        for (i = 0; i < required_count; i++) {
            destination->required_ack_states[i].member_key =
                transaction->required_ack_set.entries.entries[i].member_key;
        }
    }
    if (optional_count != 0) {
        memcpy(destination->optional_departure_entries,
               transaction->optional_departure_drain_set.entries,
               optional_count * sizeof(*destination->optional_departure_entries));
    }
    destination->transaction = *transaction;
    destination->transaction.required_ack_set.entries.entries =
        destination->required_ack_entries;
    destination->transaction.required_ack_set.entries.count = required_count;
    destination->transaction.required_ack_set.entries.capacity = required_count;
    destination->transaction.optional_departure_drain_set.entries =
        destination->optional_departure_entries;
    destination->transaction.optional_departure_drain_set.count = optional_count;
    destination->transaction.optional_departure_drain_set.capacity =
        optional_count;
    return 0;
}

static int encode_node_alloc(const struct wvm_node_record *node,
                             uint8_t **bytes_out, size_t *byte_count_out,
                             char *error, size_t error_len)
{
    size_t capacity = 1024;

    while (capacity <= WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate node record");
            return -1;
        }
        if (wvm_node_record_encode(node, bytes, capacity, &byte_count, error,
                                   error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
            capacity = WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len, "node record exceeds controller limit");
    return -1;
}

static int encode_gateway_alloc(const struct wvm_gateway_record *gateway,
                                uint8_t **bytes_out, size_t *byte_count_out,
                                char *error, size_t error_len)
{
    size_t capacity = 1024;

    while (capacity <= WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate gateway record");
            return -1;
        }
        if (wvm_gateway_record_encode(gateway, bytes, capacity, &byte_count,
                                      error, error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
            capacity = WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len, "gateway record exceeds controller limit");
    return -1;
}

static int encode_route_alloc(const struct wvm_route_transaction_record *route,
                              uint8_t **bytes_out, size_t *byte_count_out,
                              char *error, size_t error_len)
{
    size_t capacity = 1024;

    while (capacity <= WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
        uint8_t *bytes = malloc(capacity);
        size_t byte_count = 0;

        if (!bytes) {
            set_error(error, error_len, "cannot allocate route transaction");
            return -1;
        }
        if (wvm_route_transaction_record_encode(route, bytes, capacity,
                                                &byte_count, error,
                                                error_len) == 0) {
            *bytes_out = bytes;
            *byte_count_out = byte_count;
            return 0;
        }
        free(bytes);
        if (capacity == WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
            break;
        }
        capacity *= 2U;
        if (capacity > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
            capacity = WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES;
        }
    }
    set_error(error, error_len, "route transaction exceeds controller limit");
    return -1;
}

static int node_record_equal(const struct wvm_node_record *left,
                             const struct wvm_node_record *right,
                             char *error, size_t error_len)
{
    uint8_t *left_bytes = NULL;
    uint8_t *right_bytes = NULL;
    size_t left_count = 0;
    size_t right_count = 0;
    int equal = 0;

    if (encode_node_alloc(left, &left_bytes, &left_count, error, error_len) ==
            0 &&
        encode_node_alloc(right, &right_bytes, &right_count, error,
                          error_len) == 0 &&
        left_count == right_count &&
        memcmp(left_bytes, right_bytes, left_count) == 0) {
        equal = 1;
    }
    free(left_bytes);
    free(right_bytes);
    return equal;
}

static int gateway_record_equal(const struct wvm_gateway_record *left,
                                const struct wvm_gateway_record *right,
                                char *error, size_t error_len)
{
    uint8_t *left_bytes = NULL;
    uint8_t *right_bytes = NULL;
    size_t left_count = 0;
    size_t right_count = 0;
    int equal = 0;

    if (encode_gateway_alloc(left, &left_bytes, &left_count, error,
                             error_len) == 0 &&
        encode_gateway_alloc(right, &right_bytes, &right_count, error,
                             error_len) == 0 &&
        left_count == right_count &&
        memcmp(left_bytes, right_bytes, left_count) == 0) {
        equal = 1;
    }
    free(left_bytes);
    free(right_bytes);
    return equal;
}

static int route_transaction_core_equal(
    const struct wvm_route_transaction_record *left,
    const struct wvm_route_transaction_record *right, char *error,
    size_t error_len)
{
    struct wvm_route_transaction_record normalized_left;
    struct wvm_route_transaction_record normalized_right;
    uint8_t *left_bytes = NULL;
    uint8_t *right_bytes = NULL;
    size_t left_count = 0;
    size_t right_count = 0;
    int equal = 0;

    if (!left || !right) {
        return 0;
    }
    normalized_left = *left;
    normalized_right = *right;
    normalized_left.state = WVM_ROUTE_TRANSACTION_PREPARING;
    normalized_right.state = WVM_ROUTE_TRANSACTION_PREPARING;
    if (encode_route_alloc(&normalized_left, &left_bytes, &left_count, error,
                           error_len) == 0 &&
        encode_route_alloc(&normalized_right, &right_bytes, &right_count,
                           error, error_len) == 0 &&
        left_count == right_count &&
        memcmp(left_bytes, right_bytes, left_count) == 0) {
        equal = 1;
    }
    free(left_bytes);
    free(right_bytes);
    return equal;
}

static int journal_append_locked(struct wvm_membership_controller *controller,
                                 enum wvm_membership_journal_kind kind,
                                 const uint8_t *payload, size_t payload_bytes,
                                 char *error, size_t error_len)
{
    uint8_t header[WVM_MEMBERSHIP_JOURNAL_HEADER_BYTES];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];

    if (!controller || controller->journal_fd < 0 || !payload ||
        payload_bytes == 0 ||
        payload_bytes > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES ||
        controller->next_journal_sequence == 0) {
        set_error(error, error_len, "membership journal input is invalid");
        return -1;
    }
    memset(header, 0, sizeof(header));
    memcpy(header, membership_journal_magic, sizeof(membership_journal_magic));
    write_be16(header + 8, WVM_MEMBERSHIP_JOURNAL_VERSION);
    write_be16(header + 10, (uint16_t)kind);
    write_be64(header + 12, controller->next_journal_sequence);
    write_be32(header + 20, (uint32_t)payload_bytes);
    wvm_sha256_digest(payload, payload_bytes, digest);
    memcpy(header + 24, digest, sizeof(digest));
    if (lseek(controller->journal_fd, 0, SEEK_END) < 0 ||
        write_full(controller->journal_fd, header, sizeof(header)) != 0 ||
        write_full(controller->journal_fd, payload, payload_bytes) != 0 ||
        fsync(controller->journal_fd) != 0) {
        set_error(error, error_len, "cannot persist membership journal: %s",
                  strerror(errno));
        return -1;
    }
    controller->next_journal_sequence++;
    return 0;
}

static int authorization_check(
    struct wvm_membership_controller *controller,
    enum wvm_membership_controller_authorization_action action,
    const struct wvm_member_key *actor, const struct wvm_member_key *subject,
    char *error, size_t error_len)
{
    if (!controller || !controller->authorize || !actor || !subject ||
        !member_key_equal(actor, subject) ||
        wvm_member_key_validate(actor, error, error_len) != 0 ||
        controller->authorize(controller->authorize_context, action, actor,
                              subject, error, error_len) != 0) {
        set_error(error, error_len, "membership actor is not authorized");
        return -1;
    }
    return 0;
}

static int entry_route_eligible(
    const struct wvm_membership_controller_member_entry *entry)
{
    enum wvm_manifest_member_state state;

    if (!entry) {
        return 0;
    }
    state = entry_state(entry);
    return entry_health(entry) == WVM_MEMBERSHIP_HEALTHY &&
           (state == WVM_MANIFEST_MEMBER_ACTIVE ||
            state == WVM_MANIFEST_MEMBER_PREPARED);
}

static int endpoint_matches_entry(
    const struct wvm_membership_controller_member_entry *entry,
    const struct wvm_required_ack_entry *ack)
{
    const struct wvm_endpoint *endpoint;

    if (!entry || !ack || ack->role_type != entry->member_key.role_type ||
        !member_key_equal(&entry->member_key, &ack->member_key)) {
        return 0;
    }
    endpoint = entry->kind == WVM_MEMBERSHIP_COMPUTE
                   ? &entry->node.control_endpoint
                   : &entry->gateway.endpoint;
    return endpoint->data_transport == ack->endpoint.data_transport &&
           endpoint->data_address_bytes == ack->endpoint.data_address_bytes &&
           memcmp(endpoint->data_address, ack->endpoint.data_address,
                  endpoint->data_address_bytes) == 0 &&
           endpoint->data_port == ack->endpoint.data_port &&
           endpoint->control_transport == ack->endpoint.control_transport &&
           endpoint->has_control_address == ack->endpoint.has_control_address &&
           (!endpoint->has_control_address ||
            (endpoint->control_address_bytes ==
                 ack->endpoint.control_address_bytes &&
             memcmp(endpoint->control_address, ack->endpoint.control_address,
                    endpoint->control_address_bytes) == 0)) &&
           endpoint->control_port == ack->endpoint.control_port &&
           endpoint->has_server_name == ack->endpoint.has_server_name &&
           (!endpoint->has_server_name ||
            strcmp(endpoint->server_name, ack->endpoint.server_name) == 0);
}

static int required_ack_entry_equal(const struct wvm_required_ack_entry *left,
                                    const struct wvm_required_ack_entry *right)
{
    if (!left || !right || left->role_type != right->role_type ||
        !member_key_equal(&left->member_key, &right->member_key) ||
        !route_snapshot_key_equal(&left->expected_snapshot_key,
                                  &right->expected_snapshot_key)) {
        return 0;
    }
    return left->endpoint.data_transport == right->endpoint.data_transport &&
           left->endpoint.data_address_bytes ==
               right->endpoint.data_address_bytes &&
           memcmp(left->endpoint.data_address, right->endpoint.data_address,
                  left->endpoint.data_address_bytes) == 0 &&
           left->endpoint.data_port == right->endpoint.data_port &&
           left->endpoint.control_transport == right->endpoint.control_transport &&
           left->endpoint.has_control_address ==
               right->endpoint.has_control_address &&
           (!left->endpoint.has_control_address ||
            (left->endpoint.control_address_bytes ==
                 right->endpoint.control_address_bytes &&
             memcmp(left->endpoint.control_address,
                    right->endpoint.control_address,
                    left->endpoint.control_address_bytes) == 0)) &&
           left->endpoint.control_port == right->endpoint.control_port &&
           left->endpoint.has_server_name == right->endpoint.has_server_name &&
           (!left->endpoint.has_server_name ||
            strcmp(left->endpoint.server_name, right->endpoint.server_name) ==
                0);
}

static int required_ack_set_equal(const struct wvm_required_ack_set *left,
                                  const struct wvm_required_ack_set *right)
{
    size_t i;

    if (!left || !right || left->entries.count != right->entries.count) {
        return 0;
    }
    for (i = 0; i < left->entries.count; i++) {
        if (!required_ack_entry_equal(&left->entries.entries[i],
                                      &right->entries.entries[i])) {
            return 0;
        }
    }
    return 1;
}

static const struct wvm_required_ack_entry *required_ack_find_member(
    const struct wvm_required_ack_entry_list *entries,
    const struct wvm_member_key *member_key)
{
    size_t i;

    if (!entries || !member_key) {
        return NULL;
    }
    for (i = 0; i < entries->count; i++) {
        if (member_key_equal(&entries->entries[i].member_key, member_key)) {
            return &entries->entries[i];
        }
    }
    return NULL;
}

static int route_ack_index(
    const struct wvm_membership_controller_route_entry *route,
    const struct wvm_member_key *member_key)
{
    size_t i;

    if (!route || !member_key) {
        return -1;
    }
    for (i = 0; i < route->transaction.required_ack_set.entries.count; i++) {
        if (member_key_equal(&route->required_ack_states[i].member_key,
                             member_key)) {
            return (int)i;
        }
    }
    return -1;
}

static int route_all_required_acks_prepared(
    const struct wvm_membership_controller_route_entry *route)
{
    size_t i;

    if (!route) {
        return 0;
    }
    for (i = 0; i < route->transaction.required_ack_set.entries.count; i++) {
        if (!route->required_ack_states[i].prepared) {
            return 0;
        }
    }
    return 1;
}

static int gateway_drain_matches_operation(
    const struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    return controller && operation_id && controller->gateway_drain.active &&
           memcmp(controller->gateway_drain.route_operation_id, operation_id,
                  WVM_IDENTITY_ID_BYTES) == 0;
}

static int gateway_drain_topology_reserved(
    const struct wvm_membership_controller *controller)
{
    return controller && controller->gateway_drain.active;
}

static int persist_member_state_locked(
    struct wvm_membership_controller *controller,
    struct wvm_membership_controller_member_entry *entry,
    enum wvm_manifest_member_state state,
    enum wvm_membership_health_state health, int topology_changed, char *error,
    size_t error_len)
{
    uint8_t payload[50];
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t eligibility_revision;

    if (!controller || !entry || !valid_member_state(state) ||
        !valid_health(health) ||
        controller->membership_revision == UINT64_MAX ||
        controller->admission_eligibility_revision == UINT64_MAX ||
        (topology_changed && controller->topology_revision == UINT64_MAX)) {
        set_error(error, error_len, "membership revision cannot advance");
        return -1;
    }
    membership_revision = controller->membership_revision + 1U;
    topology_revision = controller->topology_revision +
                        (topology_changed ? 1U : 0U);
    eligibility_revision = controller->admission_eligibility_revision + 1U;
    write_be16(payload, entry->member_key.role_type);
    write_be32(payload + 2, entry->member_key.role_id);
    write_be64(payload + 6, entry->member_key.instance_id);
    write_be16(payload + 14, (uint16_t)state);
    write_be16(payload + 16, (uint16_t)health);
    write_be64(payload + 18, membership_revision);
    write_be64(payload + 26, topology_revision);
    write_be64(payload + 34, eligibility_revision);
    write_be64(payload + 42, entry->active_dependency_count);
    if (journal_append_locked(controller, WVM_MEMBERSHIP_JOURNAL_MEMBER_STATE,
                              payload, sizeof(payload), error, error_len) !=
        0) {
        return -1;
    }
    entry_set_state(entry, state, health, membership_revision,
                    topology_revision);
    controller->membership_revision = membership_revision;
    controller->topology_revision = topology_revision;
    controller->admission_eligibility_revision = eligibility_revision;
    stamp_all_members(controller, membership_revision, topology_revision);
    return 0;
}

static int apply_member_state_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_member_key member_key;
    struct wvm_membership_controller_member_entry *entry;
    enum wvm_manifest_member_state state;
    enum wvm_membership_health_state health;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t eligibility_revision;
    uint64_t dependency_count;

    if (payload_bytes != 50) {
        set_error(error, error_len, "membership state journal payload is invalid");
        return -1;
    }
    memset(&member_key, 0, sizeof(member_key));
    member_key.role_type = (enum wvm_manifest_role_type)read_be16(payload);
    member_key.role_id = read_be32(payload + 2);
    member_key.instance_id = read_be64(payload + 6);
    state = (enum wvm_manifest_member_state)read_be16(payload + 14);
    health = (enum wvm_membership_health_state)read_be16(payload + 16);
    membership_revision = read_be64(payload + 18);
    topology_revision = read_be64(payload + 26);
    eligibility_revision = read_be64(payload + 34);
    dependency_count = read_be64(payload + 42);
    entry = find_member_mutable(controller, &member_key);
    if (!entry || !valid_member_state(state) || !valid_health(health) ||
        membership_revision <= controller->membership_revision ||
        topology_revision < controller->topology_revision ||
        eligibility_revision <= controller->admission_eligibility_revision) {
        set_error(error, error_len, "membership journal state is inconsistent");
        return -1;
    }
    entry_set_state(entry, state, health, membership_revision,
                    topology_revision);
    entry->active_dependency_count = dependency_count;
    controller->membership_revision = membership_revision;
    controller->topology_revision = topology_revision;
    controller->admission_eligibility_revision = eligibility_revision;
    stamp_all_members(controller, membership_revision, topology_revision);
    return 0;
}

static int persist_activation_binding_locked(
    struct wvm_membership_controller *controller,
    struct wvm_membership_controller_member_entry *entry,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    uint8_t payload[30];

    if (!controller || !entry || !route_operation_id ||
        bytes_are_zero(route_operation_id, WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len, "member activation binding is invalid");
        return -1;
    }
    if (entry->has_activation_route_operation_id) {
        if (memcmp(entry->activation_route_operation_id, route_operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            return 0;
        }
        set_error(error, error_len,
                  "member activation is already bound to another route");
        return -1;
    }
    write_be16(payload, entry->member_key.role_type);
    write_be32(payload + 2, entry->member_key.role_id);
    write_be64(payload + 6, entry->member_key.instance_id);
    memcpy(payload + 14, route_operation_id, WVM_IDENTITY_ID_BYTES);
    if (journal_append_locked(
            controller, WVM_MEMBERSHIP_JOURNAL_MEMBER_ACTIVATION_BINDING,
            payload, sizeof(payload), error, error_len) != 0) {
        return -1;
    }
    entry->has_activation_route_operation_id = 1;
    memcpy(entry->activation_route_operation_id, route_operation_id,
           WVM_IDENTITY_ID_BYTES);
    return 0;
}

static int apply_activation_binding_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_member_key member_key;
    struct wvm_membership_controller_member_entry *entry;

    if (!controller || !payload || payload_bytes != 30 ||
        bytes_are_zero(payload + 14, WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len,
                  "member activation journal payload is invalid");
        return -1;
    }
    memset(&member_key, 0, sizeof(member_key));
    member_key.role_type = (enum wvm_manifest_role_type)read_be16(payload);
    member_key.role_id = read_be32(payload + 2);
    member_key.instance_id = read_be64(payload + 6);
    entry = find_member_mutable(controller, &member_key);
    if (!entry) {
        set_error(error, error_len,
                  "member activation journal names an unknown member");
        return -1;
    }
    if (entry->has_activation_route_operation_id &&
        memcmp(entry->activation_route_operation_id, payload + 14,
               WVM_IDENTITY_ID_BYTES) != 0) {
        set_error(error, error_len,
                  "member activation journal changes its route binding");
        return -1;
    }
    entry->has_activation_route_operation_id = 1;
    memcpy(entry->activation_route_operation_id, payload + 14,
           WVM_IDENTITY_ID_BYTES);
    return 0;
}

static int member_transition_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    enum wvm_manifest_member_state expected,
    enum wvm_manifest_member_state next, int topology_changed, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *entry =
        find_member_mutable(controller, member_key);

    if (!entry || entry_state(entry) != expected) {
        if (entry && entry_state(entry) == next) {
            return 0;
        }
        set_error(error, error_len, "membership transition is not allowed");
        return -1;
    }
    return persist_member_state_locked(controller, entry, next, entry_health(entry),
                                       topology_changed, error, error_len);
}

static int route_state_change_locked(
    struct wvm_membership_controller *controller,
    struct wvm_membership_controller_route_entry *route, uint16_t next_state,
    char *error, size_t error_len)
{
    uint8_t payload[18];

    write_be16(payload, next_state);
    memcpy(payload + 2, route->transaction.operation_id,
           WVM_IDENTITY_ID_BYTES);
    if (journal_append_locked(controller, WVM_MEMBERSHIP_JOURNAL_ROUTE_STATE,
                              payload, sizeof(payload), error, error_len) !=
        0) {
        return -1;
    }
    route->transaction.state = next_state;
    return 0;
}

static int apply_route_state_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;
    uint16_t next_state;
    size_t i;

    if (payload_bytes != 18) {
        set_error(error, error_len, "route state journal payload is invalid");
        return -1;
    }
    next_state = read_be16(payload);
    route = find_route_mutable(controller, payload + 2);
    if (!route) {
        set_error(error, error_len, "route state names unknown transaction");
        return -1;
    }
    if ((route->transaction.state == WVM_ROUTE_TRANSACTION_PREPARING &&
         (next_state == WVM_ROUTE_TRANSACTION_ACTIVATED ||
          next_state == WVM_ROUTE_TRANSACTION_ABORTED)) ||
        (route->transaction.state == WVM_ROUTE_TRANSACTION_ACTIVATED &&
         next_state == WVM_ROUTE_TRANSACTION_RETIRING) ||
        (route->transaction.state == WVM_ROUTE_TRANSACTION_RETIRING &&
         next_state == WVM_ROUTE_TRANSACTION_RETIRED)) {
        route->transaction.state = next_state;
        if (next_state == WVM_ROUTE_TRANSACTION_ACTIVATED) {
            for (i = 0; i < route->transaction.required_ack_set.entries.count;
                 i++) {
                route->required_ack_states[i].activated = 1;
            }
        }
        return 0;
    }
    set_error(error, error_len, "route journal state transition is invalid");
    return -1;
}

static int route_ack_persist_locked(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    uint8_t payload[30];

    memcpy(payload, operation_id, WVM_IDENTITY_ID_BYTES);
    write_be16(payload + 16, member_key->role_type);
    write_be32(payload + 18, member_key->role_id);
    write_be64(payload + 22, member_key->instance_id);
    return journal_append_locked(controller, WVM_MEMBERSHIP_JOURNAL_ROUTE_ACK,
                                 payload, sizeof(payload), error, error_len);
}

static int apply_route_ack_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_member_key member_key;
    struct wvm_membership_controller_route_entry *route;
    int index;

    if (payload_bytes != 30) {
        set_error(error, error_len, "route ACK journal payload is invalid");
        return -1;
    }
    route = find_route_mutable(controller, payload);
    memset(&member_key, 0, sizeof(member_key));
    member_key.role_type =
        (enum wvm_manifest_role_type)read_be16(payload + 16);
    member_key.role_id = read_be32(payload + 18);
    member_key.instance_id = read_be64(payload + 22);
    index = route_ack_index(route, &member_key);
    if (!route || route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
        index < 0) {
        set_error(error, error_len, "route ACK journal is inconsistent");
        return -1;
    }
    route->required_ack_states[index].prepared = 1;
    return 0;
}

static int gateway_drain_prepare_persist_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_controller_gateway_drain *drain, char *error,
    size_t error_len)
{
    uint8_t payload[54];

    if (!controller || !drain || !drain->active) {
        set_error(error, error_len, "gateway drain plan is invalid");
        return -1;
    }
    write_be16(payload, drain->gateway_member_key.role_type);
    write_be32(payload + 2, drain->gateway_member_key.role_id);
    write_be64(payload + 6, drain->gateway_member_key.instance_id);
    memcpy(payload + 14, drain->route_operation_id,
           sizeof(drain->route_operation_id));
    write_be64(payload + 30, drain->prepared_membership_revision);
    write_be64(payload + 38, drain->prepared_admission_eligibility_revision);
    write_be64(payload + 46, drain->reserved_topology_revision);
    return journal_append_locked(
        controller, WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_PREPARE, payload,
        sizeof(payload), error, error_len);
}

static int apply_gateway_drain_prepare_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_membership_controller_gateway_drain drain;
    struct wvm_membership_controller_member_entry *gateway;
    struct wvm_membership_controller_route_entry *route;

    if (!controller || !payload || payload_bytes != 54) {
        set_error(error, error_len,
                  "gateway drain prepare journal payload is invalid");
        return -1;
    }
    memset(&drain, 0, sizeof(drain));
    drain.active = 1;
    drain.gateway_member_key.role_type =
        (enum wvm_manifest_role_type)read_be16(payload);
    drain.gateway_member_key.role_id = read_be32(payload + 2);
    drain.gateway_member_key.instance_id = read_be64(payload + 6);
    memcpy(drain.route_operation_id, payload + 14,
           sizeof(drain.route_operation_id));
    drain.prepared_membership_revision = read_be64(payload + 30);
    drain.prepared_admission_eligibility_revision = read_be64(payload + 38);
    drain.reserved_topology_revision = read_be64(payload + 46);
    gateway = find_member_mutable(controller, &drain.gateway_member_key);
    route = find_route_mutable(controller, drain.route_operation_id);
    if (controller->gateway_drain.active ||
        bytes_are_zero(drain.route_operation_id,
                       sizeof(drain.route_operation_id)) ||
        !gateway || gateway->kind != WVM_MEMBERSHIP_GATEWAY ||
        entry_state(gateway) != WVM_MANIFEST_MEMBER_ACTIVE ||
        entry_health(gateway) != WVM_MEMBERSHIP_HEALTHY || !route ||
        route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
        controller->membership_revision != drain.prepared_membership_revision ||
        controller->admission_eligibility_revision == UINT64_MAX ||
        drain.prepared_admission_eligibility_revision !=
            controller->admission_eligibility_revision + 1U ||
        controller->topology_revision == UINT64_MAX ||
        drain.reserved_topology_revision !=
            controller->topology_revision + 1U ||
        route->transaction.route_snapshot_key.topology_revision !=
            drain.reserved_topology_revision ||
        route->prepared_membership_revision !=
            drain.prepared_membership_revision ||
        route->prepared_admission_eligibility_revision == UINT64_MAX ||
        route->prepared_admission_eligibility_revision + 1U !=
            drain.prepared_admission_eligibility_revision) {
        set_error(error, error_len,
                  "gateway drain prepare journal is inconsistent");
        return -1;
    }
    controller->gateway_drain = drain;
    controller->admission_eligibility_revision =
        drain.prepared_admission_eligibility_revision;
    return 0;
}

static int gateway_drain_commit_persist_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_controller_gateway_drain *drain,
    uint64_t membership_revision, uint64_t topology_revision,
    uint64_t eligibility_revision, char *error, size_t error_len)
{
    uint8_t payload[54];

    if (!controller || !drain || !drain->active) {
        set_error(error, error_len, "gateway drain commit is invalid");
        return -1;
    }
    write_be16(payload, drain->gateway_member_key.role_type);
    write_be32(payload + 2, drain->gateway_member_key.role_id);
    write_be64(payload + 6, drain->gateway_member_key.instance_id);
    memcpy(payload + 14, drain->route_operation_id,
           sizeof(drain->route_operation_id));
    write_be64(payload + 30, membership_revision);
    write_be64(payload + 38, topology_revision);
    write_be64(payload + 46, eligibility_revision);
    return journal_append_locked(
        controller, WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_COMMIT, payload,
        sizeof(payload), error, error_len);
}

static int apply_gateway_drain_commit_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_member_key gateway_member_key;
    struct wvm_membership_controller_member_entry *gateway;
    struct wvm_membership_controller_route_entry *route;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t eligibility_revision;
    size_t i;

    if (!controller || !payload || payload_bytes != 54) {
        set_error(error, error_len,
                  "gateway drain commit journal payload is invalid");
        return -1;
    }
    memset(&gateway_member_key, 0, sizeof(gateway_member_key));
    gateway_member_key.role_type =
        (enum wvm_manifest_role_type)read_be16(payload);
    gateway_member_key.role_id = read_be32(payload + 2);
    gateway_member_key.instance_id = read_be64(payload + 6);
    membership_revision = read_be64(payload + 30);
    topology_revision = read_be64(payload + 38);
    eligibility_revision = read_be64(payload + 46);
    gateway = find_member_mutable(controller, &gateway_member_key);
    route = find_route_mutable(controller, payload + 14);
    if (!gateway_drain_matches_operation(controller, payload + 14) ||
        !member_key_equal(&controller->gateway_drain.gateway_member_key,
                          &gateway_member_key) ||
        !gateway || gateway->kind != WVM_MEMBERSHIP_GATEWAY ||
        entry_state(gateway) != WVM_MANIFEST_MEMBER_ACTIVE ||
        entry_health(gateway) != WVM_MEMBERSHIP_HEALTHY || !route ||
        route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
        !route_all_required_acks_prepared(route) ||
        controller->membership_revision == UINT64_MAX ||
        membership_revision != controller->membership_revision + 1U ||
        controller->topology_revision == UINT64_MAX ||
        topology_revision != controller->topology_revision + 1U ||
        topology_revision != controller->gateway_drain.reserved_topology_revision ||
        controller->admission_eligibility_revision == UINT64_MAX ||
        eligibility_revision !=
            controller->admission_eligibility_revision + 1U ||
        route->transaction.route_snapshot_key.topology_revision !=
            topology_revision) {
        set_error(error, error_len,
                  "gateway drain commit journal is inconsistent");
        return -1;
    }
    route->transaction.state = WVM_ROUTE_TRANSACTION_ACTIVATED;
    for (i = 0; i < route->transaction.required_ack_set.entries.count; i++) {
        route->required_ack_states[i].activated = 1;
    }
    entry_set_state(gateway, WVM_MANIFEST_MEMBER_DRAINING,
                    entry_health(gateway), membership_revision,
                    topology_revision);
    controller->membership_revision = membership_revision;
    controller->topology_revision = topology_revision;
    controller->admission_eligibility_revision = eligibility_revision;
    stamp_all_members(controller, membership_revision, topology_revision);
    memset(&controller->gateway_drain, 0, sizeof(controller->gateway_drain));
    return 0;
}

static int gateway_drain_abort_persist_locked(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    return journal_append_locked(
        controller, WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_ABORT, operation_id,
        WVM_IDENTITY_ID_BYTES, error, error_len);
}

static int apply_gateway_drain_abort_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;

    if (!controller || !payload || payload_bytes != WVM_IDENTITY_ID_BYTES) {
        set_error(error, error_len,
                  "gateway drain abort journal payload is invalid");
        return -1;
    }
    route = find_route_mutable(controller, payload);
    if (!gateway_drain_matches_operation(controller, payload) || !route ||
        route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING) {
        set_error(error, error_len,
                  "gateway drain abort journal is inconsistent");
        return -1;
    }
    route->transaction.state = WVM_ROUTE_TRANSACTION_ABORTED;
    memset(&controller->gateway_drain, 0, sizeof(controller->gateway_drain));
    return 0;
}

static int dependency_validate(const struct wvm_membership_dependency *dependency,
                               char *error, size_t error_len)
{
    if (!dependency ||
        wvm_member_key_validate(&dependency->member_key, error, error_len) !=
            0 ||
        dependency->vm_id == 0 || dependency->vm_incarnation == 0 ||
        dependency->manifest_generation == 0 ||
        dependency->dependency_kind == 0) {
        set_error(error, error_len, "membership dependency is invalid");
        return -1;
    }
    return 0;
}

static int dependency_persist_locked(
    struct wvm_membership_controller *controller, uint16_t action,
    const struct wvm_membership_dependency *dependency, char *error,
    size_t error_len)
{
    uint8_t payload[38];

    write_be16(payload, action);
    write_be16(payload + 2, dependency->member_key.role_type);
    write_be32(payload + 4, dependency->member_key.role_id);
    write_be64(payload + 8, dependency->member_key.instance_id);
    write_be32(payload + 16, dependency->vm_id);
    write_be64(payload + 20, dependency->vm_incarnation);
    write_be64(payload + 28, dependency->manifest_generation);
    write_be16(payload + 36, dependency->dependency_kind);
    return journal_append_locked(controller, WVM_MEMBERSHIP_JOURNAL_DEPENDENCY,
                                 payload, sizeof(payload), error, error_len);
}

static int apply_dependency(
    struct wvm_membership_controller *controller, uint16_t action,
    const struct wvm_membership_dependency *dependency, int replaying,
    char *error, size_t error_len)
{
    struct wvm_membership_controller_member_entry *entry;
    size_t i;

    if (dependency_validate(dependency, error, error_len) != 0) {
        return -1;
    }
    entry = find_member_mutable(controller, &dependency->member_key);
    if (!entry) {
        set_error(error, error_len, "dependency names an unknown member");
        return -1;
    }
    for (i = 0; i < controller->dependency_count; i++) {
        if (dependency_equal(&controller->dependencies[i], dependency)) {
            break;
        }
    }
    if (action == 1) {
        if (i != controller->dependency_count) {
            return 0;
        }
        if ((controller->gateway_drain.active &&
             member_key_equal(
                 &controller->gateway_drain.gateway_member_key,
                 &dependency->member_key)) ||
            !entry_route_eligible(entry) ||
            entry_state(entry) != WVM_MANIFEST_MEMBER_ACTIVE ||
            controller->dependency_count == controller->dependency_capacity ||
            entry->active_dependency_count == UINT64_MAX) {
            set_error(error, error_len, "dependency acquisition is not allowed");
            return -1;
        }
        if (!replaying &&
            dependency_persist_locked(controller, action, dependency, error,
                                      error_len) != 0) {
            return -1;
        }
        controller->dependencies[controller->dependency_count++] = *dependency;
        entry->active_dependency_count++;
        return 0;
    }
    if (action != 2) {
        set_error(error, error_len, "dependency journal action is invalid");
        return -1;
    }
    if (i == controller->dependency_count) {
        return 0;
    }
    if (entry->active_dependency_count == 0) {
        set_error(error, error_len, "dependency accounting underflow");
        return -1;
    }
    if (!replaying &&
        dependency_persist_locked(controller, action, dependency, error,
                                  error_len) != 0) {
        return -1;
    }
    entry->active_dependency_count--;
    if (i + 1U < controller->dependency_count) {
        memmove(&controller->dependencies[i], &controller->dependencies[i + 1U],
                (controller->dependency_count - i - 1U) *
                    sizeof(*controller->dependencies));
    }
    controller->dependency_count--;
    memset(&controller->dependencies[controller->dependency_count], 0,
           sizeof(*controller->dependencies));
    return 0;
}

static int apply_dependency_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_membership_dependency dependency;

    if (payload_bytes != 38) {
        set_error(error, error_len, "dependency journal payload is invalid");
        return -1;
    }
    memset(&dependency, 0, sizeof(dependency));
    dependency.member_key.role_type =
        (enum wvm_manifest_role_type)read_be16(payload + 2);
    dependency.member_key.role_id = read_be32(payload + 4);
    dependency.member_key.instance_id = read_be64(payload + 8);
    dependency.vm_id = read_be32(payload + 16);
    dependency.vm_incarnation = read_be64(payload + 20);
    dependency.manifest_generation = read_be64(payload + 28);
    dependency.dependency_kind = read_be16(payload + 36);
    return apply_dependency(controller, read_be16(payload), &dependency, 1,
                            error, error_len);
}

static int decode_node_registration(
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_membership_controller_member_entry *entry, char *error,
    size_t error_len)
{
    uint32_t hosted_count;
    size_t record_bytes;

    if (!payload || !entry || payload_bytes <= 4) {
        return -1;
    }
    hosted_count = read_be32(payload);
    record_bytes = payload_bytes - 4U;
    if (hosted_count > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES /
                           sizeof(uint32_t)) {
        set_error(error, error_len, "node registration list is oversized");
        return -1;
    }
    memset(entry, 0, sizeof(*entry));
    if (hosted_count != 0) {
        entry->node.inventory.hosted_gateway_role_ids =
            calloc(hosted_count,
                   sizeof(*entry->node.inventory.hosted_gateway_role_ids));
        if (!entry->node.inventory.hosted_gateway_role_ids) {
            set_error(error, error_len, "cannot restore node gateway list");
            return -1;
        }
    }
    entry->node.inventory.hosted_gateway_role_id_capacity = hosted_count;
    if (wvm_node_record_decode(payload + 4, record_bytes, &entry->node, error,
                               error_len) != 0 ||
        entry->node.inventory.hosted_gateway_role_id_count != hosted_count) {
        entry_free(entry);
        set_error(error, error_len, "node registration record is invalid");
        return -1;
    }
    entry->kind = WVM_MEMBERSHIP_COMPUTE;
    node_member_key(&entry->node, &entry->member_key);
    return 0;
}

static int decode_gateway_registration(
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_membership_controller_member_entry *entry, char *error,
    size_t error_len)
{
    uint32_t parent_count;
    uint32_t child_count;
    size_t record_bytes;

    if (!payload || !entry || payload_bytes <= 8) {
        return -1;
    }
    parent_count = read_be32(payload);
    child_count = read_be32(payload + 4);
    record_bytes = payload_bytes - 8U;
    if (parent_count > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES /
                           sizeof(uint32_t) ||
        child_count > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES /
                          sizeof(uint32_t)) {
        set_error(error, error_len, "gateway registration list is oversized");
        return -1;
    }
    memset(entry, 0, sizeof(*entry));
    if (parent_count != 0) {
        entry->gateway.parent_gateway_ids =
            calloc(parent_count, sizeof(*entry->gateway.parent_gateway_ids));
        if (!entry->gateway.parent_gateway_ids) {
            set_error(error, error_len, "cannot restore gateway parents");
            return -1;
        }
    }
    if (child_count != 0) {
        entry->gateway.child_gateway_ids =
            calloc(child_count, sizeof(*entry->gateway.child_gateway_ids));
        if (!entry->gateway.child_gateway_ids) {
            entry_free(entry);
            set_error(error, error_len, "cannot restore gateway children");
            return -1;
        }
    }
    entry->gateway.parent_gateway_id_capacity = parent_count;
    entry->gateway.child_gateway_id_capacity = child_count;
    if (wvm_gateway_record_decode(payload + 8, record_bytes, &entry->gateway,
                                  error, error_len) != 0 ||
        entry->gateway.parent_gateway_id_count != parent_count ||
        entry->gateway.child_gateway_id_count != child_count) {
        entry_free(entry);
        set_error(error, error_len, "gateway registration record is invalid");
        return -1;
    }
    entry->kind = WVM_MEMBERSHIP_GATEWAY;
    gateway_member_key(&entry->gateway, &entry->member_key);
    return 0;
}

static int apply_registration_entry(
    struct wvm_membership_controller *controller,
    struct wvm_membership_controller_member_entry *candidate, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *existing;
    size_t slot;

    existing = find_member_role(controller, &candidate->member_key);
    if (existing) {
        if (member_key_equal(&existing->member_key, &candidate->member_key)) {
            entry_free(candidate);
            return 0;
        }
        if ((entry_state(existing) != WVM_MANIFEST_MEMBER_REMOVED &&
             entry_state(existing) != WVM_MANIFEST_MEMBER_FAILED) ||
            existing->active_dependency_count != 0) {
            entry_free(candidate);
            set_error(error, error_len, "registered role cannot be replaced");
            return -1;
        }
        slot = (size_t)(existing - controller->members);
        entry_free(existing);
    } else {
        if (controller->member_count == controller->member_capacity) {
            entry_free(candidate);
            set_error(error, error_len, "membership entry capacity is full");
            return -1;
        }
        slot = controller->member_count++;
    }
    controller->members[slot] = *candidate;
    memset(candidate, 0, sizeof(*candidate));
    if (entry_membership_revision(&controller->members[slot]) >
        controller->membership_revision) {
        controller->membership_revision =
            entry_membership_revision(&controller->members[slot]);
    }
    if (entry_topology_revision(&controller->members[slot]) >
        controller->topology_revision) {
        controller->topology_revision =
            entry_topology_revision(&controller->members[slot]);
    }
    if (controller->admission_eligibility_revision <
        controller->membership_revision) {
        controller->admission_eligibility_revision =
            controller->membership_revision;
    }
    stamp_all_members(controller, controller->membership_revision,
                      controller->topology_revision);
    return 0;
}

static int apply_route_begin_replay(
    struct wvm_membership_controller *controller, const uint8_t *payload,
    size_t payload_bytes, char *error, size_t error_len)
{
    struct wvm_membership_controller_route_entry candidate;
    uint32_t required_count;
    uint32_t optional_count;
    uint64_t prepared_membership_revision;
    uint64_t prepared_eligibility_revision;
    size_t record_bytes;

    if (payload_bytes <= 24) {
        set_error(error, error_len, "route begin journal payload is invalid");
        return -1;
    }
    required_count = read_be32(payload);
    optional_count = read_be32(payload + 4);
    prepared_membership_revision = read_be64(payload + 8);
    prepared_eligibility_revision = read_be64(payload + 16);
    record_bytes = payload_bytes - 24U;
    if (required_count == 0 ||
        required_count > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES /
                             sizeof(*candidate.required_ack_entries) ||
        optional_count > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES /
                             sizeof(*candidate.optional_departure_entries) ||
        controller->route_count == controller->route_capacity) {
        set_error(error, error_len, "route begin journal capacity is invalid");
        return -1;
    }
    memset(&candidate, 0, sizeof(candidate));
    candidate.required_ack_entries =
        calloc(required_count, sizeof(*candidate.required_ack_entries));
    candidate.required_ack_states =
        calloc(required_count, sizeof(*candidate.required_ack_states));
    if (!candidate.required_ack_entries || !candidate.required_ack_states) {
        route_entry_free(&candidate);
        set_error(error, error_len, "cannot restore route ACK set");
        return -1;
    }
    if (optional_count != 0) {
        candidate.optional_departure_entries =
            calloc(optional_count,
                   sizeof(*candidate.optional_departure_entries));
        if (!candidate.optional_departure_entries) {
            route_entry_free(&candidate);
            set_error(error, error_len, "cannot restore route drain set");
            return -1;
        }
    }
    candidate.transaction.required_ack_set.entries.entries =
        candidate.required_ack_entries;
    candidate.transaction.required_ack_set.entries.capacity = required_count;
    candidate.transaction.optional_departure_drain_set.entries =
        candidate.optional_departure_entries;
    candidate.transaction.optional_departure_drain_set.capacity = optional_count;
    if (wvm_route_transaction_record_decode(payload + 24, record_bytes,
                                            &candidate.transaction, error,
                                            error_len) != 0 ||
        candidate.transaction.required_ack_set.entries.count != required_count ||
        candidate.transaction.optional_departure_drain_set.count !=
            optional_count ||
        candidate.transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
        find_route_mutable(controller, candidate.transaction.operation_id)) {
        route_entry_free(&candidate);
        set_error(error, error_len, "route begin record is invalid");
        return -1;
    }
    {
        size_t i;

        for (i = 0; i < required_count; i++) {
            candidate.required_ack_states[i].member_key =
                candidate.required_ack_entries[i].member_key;
        }
    }
    candidate.prepared_membership_revision = prepared_membership_revision;
    candidate.prepared_admission_eligibility_revision =
        prepared_eligibility_revision;
    controller->routes[controller->route_count++] = candidate;
    return 0;
}

static int replay_journal_frame(struct wvm_membership_controller *controller,
                                uint16_t kind, const uint8_t *payload,
                                size_t payload_bytes, char *error,
                                size_t error_len)
{
    struct wvm_membership_controller_member_entry candidate;

    switch (kind) {
    case WVM_MEMBERSHIP_JOURNAL_REGISTER_NODE:
        if (decode_node_registration(payload, payload_bytes, &candidate, error,
                                     error_len) != 0) {
            return -1;
        }
        return apply_registration_entry(controller, &candidate, error,
                                        error_len);
    case WVM_MEMBERSHIP_JOURNAL_REGISTER_GATEWAY:
        if (decode_gateway_registration(payload, payload_bytes, &candidate,
                                        error, error_len) != 0) {
            return -1;
        }
        return apply_registration_entry(controller, &candidate, error,
                                        error_len);
    case WVM_MEMBERSHIP_JOURNAL_MEMBER_STATE:
        return apply_member_state_replay(controller, payload, payload_bytes,
                                         error, error_len);
    case WVM_MEMBERSHIP_JOURNAL_MEMBER_ACTIVATION_BINDING:
        return apply_activation_binding_replay(controller, payload,
                                               payload_bytes, error, error_len);
    case WVM_MEMBERSHIP_JOURNAL_ROUTE_BEGIN:
        return apply_route_begin_replay(controller, payload, payload_bytes,
                                        error, error_len);
    case WVM_MEMBERSHIP_JOURNAL_ROUTE_ACK:
        return apply_route_ack_replay(controller, payload, payload_bytes, error,
                                      error_len);
    case WVM_MEMBERSHIP_JOURNAL_ROUTE_STATE:
        return apply_route_state_replay(controller, payload, payload_bytes,
                                        error, error_len);
    case WVM_MEMBERSHIP_JOURNAL_DEPENDENCY:
        return apply_dependency_replay(controller, payload, payload_bytes,
                                       error, error_len);
    case WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_PREPARE:
        return apply_gateway_drain_prepare_replay(controller, payload,
                                                  payload_bytes, error,
                                                  error_len);
    case WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_COMMIT:
        return apply_gateway_drain_commit_replay(controller, payload,
                                                 payload_bytes, error,
                                                 error_len);
    case WVM_MEMBERSHIP_JOURNAL_GATEWAY_DRAIN_ABORT:
        return apply_gateway_drain_abort_replay(controller, payload,
                                                payload_bytes, error,
                                                error_len);
    default:
        set_error(error, error_len, "membership journal kind is unknown");
        return -1;
    }
}

void wvm_membership_controller_init(
    struct wvm_membership_controller *controller,
    struct wvm_membership_controller_member_entry *members,
    size_t member_capacity,
    struct wvm_membership_controller_route_entry *routes,
    size_t route_capacity, struct wvm_membership_dependency *dependencies,
    size_t dependency_capacity,
    wvm_membership_controller_authorize_fn authorize, void *authorize_context)
{
    if (!controller) {
        return;
    }
    memset(controller, 0, sizeof(*controller));
    controller->journal_fd = -1;
    controller->members = members;
    controller->member_capacity = member_capacity;
    controller->routes = routes;
    controller->route_capacity = route_capacity;
    controller->dependencies = dependencies;
    controller->dependency_capacity = dependency_capacity;
    controller->membership_revision = 1;
    controller->topology_revision = 1;
    controller->admission_eligibility_revision = 1;
    controller->authorize = authorize;
    controller->authorize_context = authorize_context;
    pthread_mutex_init(&controller->lock, NULL);
    if (members && member_capacity != 0) {
        memset(members, 0, member_capacity * sizeof(*members));
    }
    if (routes && route_capacity != 0) {
        memset(routes, 0, route_capacity * sizeof(*routes));
    }
    if (dependencies && dependency_capacity != 0) {
        memset(dependencies, 0, dependency_capacity * sizeof(*dependencies));
    }
}

int wvm_membership_controller_open(
    struct wvm_membership_controller *controller, const char *journal_path,
    char *error, size_t error_len)
{
    uint64_t expected_sequence = 1;
    off_t valid_end = 0;

    if (!controller || !journal_path || journal_path[0] == '\0' ||
        controller->journal_fd >= 0 || !controller->members ||
        controller->member_capacity == 0 || !controller->routes ||
        controller->route_capacity == 0 || !controller->dependencies ||
        controller->dependency_capacity == 0) {
        set_error(error, error_len, "membership controller initialization invalid");
        return -1;
    }
    controller->journal_fd =
        open(journal_path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (controller->journal_fd < 0) {
        set_error(error, error_len, "cannot open membership journal: %s",
                  strerror(errno));
        return -1;
    }
    for (;;) {
        uint8_t header[WVM_MEMBERSHIP_JOURNAL_HEADER_BYTES];
        uint8_t digest[WVM_SHA256_DIGEST_BYTES];
        uint8_t *payload = NULL;
        uint16_t kind;
        uint32_t payload_bytes;
        int result =
            read_full(controller->journal_fd, header, sizeof(header));

        if (result == 0) {
            break;
        }
        if (result < 0 ||
            memcmp(header, membership_journal_magic,
                   sizeof(membership_journal_magic)) != 0 ||
            read_be16(header + 8) != WVM_MEMBERSHIP_JOURNAL_VERSION ||
            read_be64(header + 12) != expected_sequence ||
            read_be32(header + 20) == 0 ||
            read_be32(header + 20) > WVM_MEMBERSHIP_CONTROLLER_MAX_RECORD_BYTES) {
            if (result < 0) {
                break;
            }
            set_error(error, error_len, "membership journal header is invalid");
            wvm_membership_controller_close(controller);
            return -1;
        }
        kind = read_be16(header + 10);
        payload_bytes = read_be32(header + 20);
        payload = malloc(payload_bytes);
        if (!payload || read_full(controller->journal_fd, payload, payload_bytes) !=
                            1) {
            free(payload);
            break;
        }
        wvm_sha256_digest(payload, payload_bytes, digest);
        if (memcmp(digest, header + 24, sizeof(digest)) != 0 ||
            replay_journal_frame(controller, kind, payload, payload_bytes,
                                 error, error_len) != 0) {
            free(payload);
            wvm_membership_controller_close(controller);
            return -1;
        }
        free(payload);
        valid_end = lseek(controller->journal_fd, 0, SEEK_CUR);
        expected_sequence++;
    }
    if (ftruncate(controller->journal_fd, valid_end) != 0 ||
        lseek(controller->journal_fd, 0, SEEK_END) < 0) {
        set_error(error, error_len, "cannot finalize membership journal: %s",
                  strerror(errno));
        wvm_membership_controller_close(controller);
        return -1;
    }
    controller->next_journal_sequence = expected_sequence;
    return 0;
}

void wvm_membership_controller_close(
    struct wvm_membership_controller *controller)
{
    size_t i;

    if (!controller) {
        return;
    }
    if (controller->journal_fd >= 0) {
        close(controller->journal_fd);
        controller->journal_fd = -1;
    }
    for (i = 0; i < controller->member_count; i++) {
        entry_free(&controller->members[i]);
    }
    for (i = 0; i < controller->route_count; i++) {
        route_entry_free(&controller->routes[i]);
    }
    controller->member_count = 0;
    controller->route_count = 0;
    controller->dependency_count = 0;
    if (controller->dependencies && controller->dependency_capacity != 0) {
        memset(controller->dependencies, 0,
               controller->dependency_capacity * sizeof(*controller->dependencies));
    }
    pthread_mutex_destroy(&controller->lock);
    memset(controller, 0, sizeof(*controller));
    controller->journal_fd = -1;
}

static int register_node_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *actor, const struct wvm_node_record *node,
    char *error, size_t error_len)
{
    struct wvm_node_record normalized;
    struct wvm_membership_controller_member_entry candidate;
    struct wvm_membership_controller_member_entry *existing;
    struct wvm_member_key member_key;
    uint8_t *record = NULL;
    uint8_t *payload = NULL;
    size_t record_bytes = 0;
    size_t payload_bytes;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t eligibility_revision;
    int result = -1;

    if (!node || gateway_drain_topology_reserved(controller) ||
        controller->membership_revision == UINT64_MAX ||
        controller->topology_revision == UINT64_MAX ||
        controller->admission_eligibility_revision == UINT64_MAX) {
        set_error(error, error_len, "node registration cannot change topology");
        return -1;
    }
    normalized = *node;
    node_member_key(&normalized, &member_key);
    membership_revision = controller->membership_revision + 1U;
    topology_revision = controller->topology_revision + 1U;
    eligibility_revision = controller->admission_eligibility_revision + 1U;
    normalized.desired_membership_state = WVM_MANIFEST_MEMBER_PENDING;
    normalized.observed_health_state = WVM_MEMBERSHIP_RECOVERING;
    normalized.membership_revision = membership_revision;
    normalized.topology_revision = topology_revision;
    if (wvm_node_record_validate(&normalized, error, error_len) != 0 ||
        authorization_check(
            controller, WVM_MEMBERSHIP_CONTROLLER_AUTHORIZE_REGISTER_NODE,
            actor, &member_key, error, error_len) != 0) {
        return -1;
    }
    existing = find_member_role(controller, &member_key);
    if (existing && member_key_equal(&existing->member_key, &member_key)) {
        normalized.desired_membership_state = entry_state(existing);
        normalized.observed_health_state = entry_health(existing);
        normalized.membership_revision = entry_membership_revision(existing);
        normalized.topology_revision = entry_topology_revision(existing);
        if (node_record_equal(&normalized, &existing->node, error, error_len)) {
            return 0;
        }
        set_error(error, error_len,
                  "node registration reuses an instance with different data");
        return -1;
    }
    if (existing &&
        (entry_state(existing) != WVM_MANIFEST_MEMBER_REMOVED &&
         entry_state(existing) != WVM_MANIFEST_MEMBER_FAILED)) {
        set_error(error, error_len, "node role already has a live instance");
        return -1;
    }
    if (!existing && controller->member_count == controller->member_capacity) {
        set_error(error, error_len, "membership entry capacity is full");
        return -1;
    }
    if (clone_node_entry(&candidate, &normalized, error, error_len) != 0 ||
        encode_node_alloc(&normalized, &record, &record_bytes, error,
                          error_len) != 0) {
        entry_free(&candidate);
        free(record);
        return -1;
    }
    payload_bytes = 4U + record_bytes;
    payload = malloc(payload_bytes);
    if (!payload) {
        entry_free(&candidate);
        free(record);
        set_error(error, error_len, "cannot allocate node registration journal");
        return -1;
    }
    write_be32(payload, (uint32_t)normalized.inventory.hosted_gateway_role_id_count);
    memcpy(payload + 4, record, record_bytes);
    if (journal_append_locked(controller, WVM_MEMBERSHIP_JOURNAL_REGISTER_NODE,
                              payload, payload_bytes, error, error_len) == 0) {
        result = apply_registration_entry(controller, &candidate, error,
                                          error_len);
        if (result == 0) {
            controller->membership_revision = membership_revision;
            controller->topology_revision = topology_revision;
            controller->admission_eligibility_revision = eligibility_revision;
        }
    }
    entry_free(&candidate);
    free(payload);
    free(record);
    return result;
}

int wvm_membership_controller_register_node(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_node_record *node, char *error, size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        set_error(error, error_len, "membership controller is not open");
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = register_node_locked(controller, authenticated_actor, node, error,
                                  error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

static int register_gateway_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *actor,
    const struct wvm_gateway_record *gateway, char *error, size_t error_len)
{
    struct wvm_gateway_record normalized;
    struct wvm_membership_controller_member_entry candidate;
    struct wvm_membership_controller_member_entry *existing;
    struct wvm_member_key member_key;
    uint8_t *record = NULL;
    uint8_t *payload = NULL;
    size_t record_bytes = 0;
    size_t payload_bytes;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t eligibility_revision;
    int result = -1;

    if (!gateway || gateway_drain_topology_reserved(controller) ||
        controller->membership_revision == UINT64_MAX ||
        controller->topology_revision == UINT64_MAX ||
        controller->admission_eligibility_revision == UINT64_MAX) {
        set_error(error, error_len,
                  "gateway registration cannot change topology");
        return -1;
    }
    normalized = *gateway;
    gateway_member_key(&normalized, &member_key);
    membership_revision = controller->membership_revision + 1U;
    topology_revision = controller->topology_revision + 1U;
    eligibility_revision = controller->admission_eligibility_revision + 1U;
    normalized.desired_membership_state = WVM_MANIFEST_MEMBER_PENDING;
    normalized.observed_health_state = WVM_MEMBERSHIP_RECOVERING;
    normalized.membership_revision = membership_revision;
    normalized.topology_revision = topology_revision;
    if (wvm_gateway_record_validate(&normalized, error, error_len) != 0 ||
        authorization_check(
            controller, WVM_MEMBERSHIP_CONTROLLER_AUTHORIZE_REGISTER_GATEWAY,
            actor, &member_key, error, error_len) != 0) {
        return -1;
    }
    existing = find_member_role(controller, &member_key);
    if (existing && member_key_equal(&existing->member_key, &member_key)) {
        normalized.desired_membership_state = entry_state(existing);
        normalized.observed_health_state = entry_health(existing);
        normalized.membership_revision = entry_membership_revision(existing);
        normalized.topology_revision = entry_topology_revision(existing);
        if (gateway_record_equal(&normalized, &existing->gateway, error,
                                 error_len)) {
            return 0;
        }
        set_error(error, error_len,
                  "gateway registration reuses an instance with different data");
        return -1;
    }
    if (existing &&
        (entry_state(existing) != WVM_MANIFEST_MEMBER_REMOVED &&
         entry_state(existing) != WVM_MANIFEST_MEMBER_FAILED)) {
        set_error(error, error_len, "gateway role already has a live instance");
        return -1;
    }
    if (!existing && controller->member_count == controller->member_capacity) {
        set_error(error, error_len, "membership entry capacity is full");
        return -1;
    }
    if (clone_gateway_entry(&candidate, &normalized, error, error_len) != 0 ||
        encode_gateway_alloc(&normalized, &record, &record_bytes, error,
                             error_len) != 0) {
        entry_free(&candidate);
        free(record);
        return -1;
    }
    payload_bytes = 8U + record_bytes;
    payload = malloc(payload_bytes);
    if (!payload) {
        entry_free(&candidate);
        free(record);
        set_error(error, error_len,
                  "cannot allocate gateway registration journal");
        return -1;
    }
    write_be32(payload, (uint32_t)normalized.parent_gateway_id_count);
    write_be32(payload + 4, (uint32_t)normalized.child_gateway_id_count);
    memcpy(payload + 8, record, record_bytes);
    if (journal_append_locked(controller,
                              WVM_MEMBERSHIP_JOURNAL_REGISTER_GATEWAY,
                              payload, payload_bytes, error, error_len) == 0) {
        result = apply_registration_entry(controller, &candidate, error,
                                          error_len);
        if (result == 0) {
            controller->membership_revision = membership_revision;
            controller->topology_revision = topology_revision;
            controller->admission_eligibility_revision = eligibility_revision;
        }
    }
    entry_free(&candidate);
    free(payload);
    free(record);
    return result;
}

int wvm_membership_controller_register_gateway(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *authenticated_actor,
    const struct wvm_gateway_record *gateway, char *error, size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        set_error(error, error_len, "membership controller is not open");
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = register_gateway_locked(controller, authenticated_actor, gateway,
                                     error, error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_begin_validation(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = member_transition_locked(controller, member_key,
                                      WVM_MANIFEST_MEMBER_PENDING,
                                      WVM_MANIFEST_MEMBER_VALIDATING, 0, error,
                                      error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_prepare_member(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = member_transition_locked(controller, member_key,
                                      WVM_MANIFEST_MEMBER_VALIDATING,
                                      WVM_MANIFEST_MEMBER_PREPARED, 0, error,
                                      error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_prepare_member_for_route(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *member;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !member_key ||
        !route_operation_id ||
        bytes_are_zero(route_operation_id, WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len, "member route preparation input is invalid");
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    member = find_member_mutable(controller, member_key);
    if (!member) {
        set_error(error, error_len, "member route preparation names no member");
        goto out;
    }
    if (entry_state(member) == WVM_MANIFEST_MEMBER_ACTIVE) {
        if (member->has_activation_route_operation_id &&
            memcmp(member->activation_route_operation_id, route_operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            result = 0;
        } else {
            set_error(error, error_len,
                      "active member belongs to another route operation");
        }
        goto out;
    }
    if (entry_state(member) == WVM_MANIFEST_MEMBER_PENDING &&
        member_transition_locked(controller, member_key,
                                 WVM_MANIFEST_MEMBER_PENDING,
                                 WVM_MANIFEST_MEMBER_VALIDATING, 0, error,
                                 error_len) != 0) {
        goto out;
    }
    member = find_member_mutable(controller, member_key);
    if (member && entry_state(member) == WVM_MANIFEST_MEMBER_VALIDATING &&
        member_transition_locked(controller, member_key,
                                 WVM_MANIFEST_MEMBER_VALIDATING,
                                 WVM_MANIFEST_MEMBER_PREPARED, 0, error,
                                 error_len) != 0) {
        goto out;
    }
    member = find_member_mutable(controller, member_key);
    if (!member || entry_state(member) != WVM_MANIFEST_MEMBER_PREPARED ||
        entry_health(member) != WVM_MEMBERSHIP_HEALTHY) {
        set_error(error, error_len,
                  "member is not healthy and prepared for route publication");
        goto out;
    }
    result = 0;
out:
    pthread_mutex_unlock(&controller->lock);
    return result;
}

static int route_begin_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_route_transaction_record *transaction,
    uint64_t expected_topology_revision, char *error, size_t error_len)
{
    struct wvm_membership_controller_route_entry candidate;
    struct wvm_membership_controller_route_entry *existing;
    uint8_t *record = NULL;
    uint8_t *payload = NULL;
    size_t record_bytes = 0;
    size_t payload_bytes;
    size_t i;
    int result = -1;

    if (!transaction ||
        transaction->state != WVM_ROUTE_TRANSACTION_PREPARING ||
        wvm_route_transaction_record_validate(transaction, error, error_len) !=
            0 ||
        transaction->route_snapshot_key.topology_revision !=
            expected_topology_revision) {
        set_error(error, error_len, "route transaction cannot begin");
        return -1;
    }
    existing = find_route_mutable(controller, transaction->operation_id);
    if (existing) {
        if (route_transaction_core_equal(&existing->transaction, transaction,
                                         error, error_len)) {
            return 0;
        }
        set_error(error, error_len,
                  "route operation ID conflicts with another transaction");
        return -1;
    }
    if (controller->route_count == controller->route_capacity) {
        set_error(error, error_len, "route transaction capacity is full");
        return -1;
    }
    for (i = 0; i < transaction->required_ack_set.entries.count; i++) {
        const struct wvm_required_ack_entry *ack =
            &transaction->required_ack_set.entries.entries[i];
        struct wvm_membership_controller_member_entry *member =
            find_member_mutable(controller, &ack->member_key);

        if (!entry_route_eligible(member) ||
            !endpoint_matches_entry(member, ack)) {
            set_error(error, error_len,
                      "route transaction has an ineligible ACK member");
            return -1;
        }
    }
    if (clone_route_entry(&candidate, transaction, error, error_len) != 0 ||
        encode_route_alloc(transaction, &record, &record_bytes, error,
                           error_len) != 0) {
        route_entry_free(&candidate);
        free(record);
        return -1;
    }
    candidate.prepared_membership_revision = controller->membership_revision;
    candidate.prepared_admission_eligibility_revision =
        controller->admission_eligibility_revision;
    payload_bytes = 24U + record_bytes;
    payload = malloc(payload_bytes);
    if (!payload) {
        route_entry_free(&candidate);
        free(record);
        set_error(error, error_len, "cannot allocate route journal");
        return -1;
    }
    write_be32(payload, (uint32_t)transaction->required_ack_set.entries.count);
    write_be32(payload + 4,
               (uint32_t)transaction->optional_departure_drain_set.count);
    write_be64(payload + 8, candidate.prepared_membership_revision);
    write_be64(payload + 16, candidate.prepared_admission_eligibility_revision);
    memcpy(payload + 24, record, record_bytes);
    if (journal_append_locked(controller, WVM_MEMBERSHIP_JOURNAL_ROUTE_BEGIN,
                              payload, payload_bytes, error, error_len) == 0) {
        controller->routes[controller->route_count++] = candidate;
        memset(&candidate, 0, sizeof(candidate));
        result = 0;
    }
    route_entry_free(&candidate);
    free(payload);
    free(record);
    return result;
}

int wvm_membership_controller_route_begin(
    struct wvm_membership_controller *controller,
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = route_begin_locked(controller, transaction,
                                controller->topology_revision, error,
                                error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_route_ack_prepare(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;
    struct wvm_membership_controller_member_entry *member;
    int index;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !operation_id ||
        !member_key || bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES)) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    route = find_route_mutable(controller, operation_id);
    member = find_member_mutable(controller, member_key);
    index = route_ack_index(route, member_key);
    if (!route || !member || index < 0) {
        set_error(error, error_len, "route prepare ACK is not allowed");
    } else if (route->transaction.state == WVM_ROUTE_TRANSACTION_ACTIVATED &&
               route->required_ack_states[index].prepared &&
               route->required_ack_states[index].activated) {
        result = 0;
    } else if (route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
               !entry_route_eligible(member) ||
        (route->transaction.route_snapshot_key.topology_revision !=
             controller->topology_revision &&
         (!gateway_drain_matches_operation(controller, operation_id) ||
          route->transaction.route_snapshot_key.topology_revision !=
              controller->gateway_drain.reserved_topology_revision))) {
        set_error(error, error_len, "route prepare ACK is not allowed");
    } else if (route->required_ack_states[index].prepared) {
        result = 0;
    } else if (route_ack_persist_locked(controller, operation_id, member_key,
                                        error, error_len) == 0) {
        route->required_ack_states[index].prepared = 1;
        result = 0;
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_route_state(
    const struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], uint16_t *state_out,
    char *error, size_t error_len)
{
    struct wvm_membership_controller *mutable_controller;
    struct wvm_membership_controller_route_entry *route;

    if (!controller || controller->journal_fd < 0 || !operation_id ||
        !state_out || bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES)) {
        set_error(error, error_len, "route state query input is invalid");
        return -1;
    }
    mutable_controller = (struct wvm_membership_controller *)controller;
    pthread_mutex_lock(&mutable_controller->lock);
    route = find_route_mutable(mutable_controller, operation_id);
    if (!route) {
        set_error(error, error_len, "route state names an unknown transaction");
        pthread_mutex_unlock(&mutable_controller->lock);
        return -1;
    }
    *state_out = route->transaction.state;
    pthread_mutex_unlock(&mutable_controller->lock);
    return 0;
}

int wvm_membership_controller_route_commit(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;
    size_t i;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !operation_id) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    route = find_route_mutable(controller, operation_id);
    if (!route) {
        set_error(error, error_len, "route commit names an unknown transaction");
    } else if (gateway_drain_matches_operation(controller, operation_id) ||
               route->transaction.route_snapshot_key.topology_revision !=
                   controller->topology_revision) {
        set_error(error, error_len,
                  "route transaction requires gateway drain publication");
    } else if (route->transaction.state == WVM_ROUTE_TRANSACTION_ACTIVATED) {
        result = 0;
    } else if (route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
               route->prepared_membership_revision !=
                   controller->membership_revision ||
               route->prepared_admission_eligibility_revision !=
                   controller->admission_eligibility_revision) {
        set_error(error, error_len,
                  "route transaction eligibility changed before commit");
    } else {
        if (!route_all_required_acks_prepared(route)) {
            set_error(error, error_len,
                      "route transaction is missing a required ACK");
            goto out;
        }
        if (route_state_change_locked(controller, route,
                                      WVM_ROUTE_TRANSACTION_ACTIVATED, error,
                                      error_len) == 0) {
            for (i = 0; i < route->transaction.required_ack_set.entries.count;
                 i++) {
                route->required_ack_states[i].activated = 1;
            }
            result = 0;
        }
    }
out:
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_route_begin_retire(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t active_operation_refs, int retention_horizon_complete, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !operation_id) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    route = find_route_mutable(controller, operation_id);
    if (!route || route->transaction.state != WVM_ROUTE_TRANSACTION_ACTIVATED ||
        active_operation_refs != 0 || !retention_horizon_complete) {
        set_error(error, error_len, "route transaction cannot start retirement");
    } else {
        result = route_state_change_locked(controller, route,
                                           WVM_ROUTE_TRANSACTION_RETIRING,
                                           error, error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_route_retire(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !operation_id) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    route = find_route_mutable(controller, operation_id);
    if (!route || route->transaction.state != WVM_ROUTE_TRANSACTION_RETIRING) {
        set_error(error, error_len, "route transaction is not retiring");
    } else {
        result = route_state_change_locked(controller, route,
                                           WVM_ROUTE_TRANSACTION_RETIRED,
                                           error, error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_route_abort(
    struct wvm_membership_controller *controller,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !operation_id) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    route = find_route_mutable(controller, operation_id);
    if (!route || route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
        gateway_drain_matches_operation(controller, operation_id)) {
        set_error(error, error_len, "route transaction cannot abort");
    } else {
        result = route_state_change_locked(controller, route,
                                           WVM_ROUTE_TRANSACTION_ABORTED,
                                           error, error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

static int gateway_drain_successor_validate_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *gateway_member_key,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *gateway;
    const struct wvm_required_ack_entry *departure_ack;
    size_t dependency_count = 0;
    size_t i;

    if (!controller || !gateway_member_key || !successor_transaction ||
        !successor_snapshot || controller->gateway_drain.active ||
        controller->topology_revision == UINT64_MAX ||
        controller->admission_eligibility_revision == UINT64_MAX ||
        controller->membership_revision == UINT64_MAX ||
        wvm_member_key_validate(gateway_member_key, error, error_len) != 0 ||
        wvm_route_transaction_record_validate(successor_transaction, error,
                                              error_len) != 0 ||
        wvm_route_snapshot_record_validate(successor_snapshot, error,
                                           error_len) != 0) {
        set_error(error, error_len, "gateway drain successor is invalid");
        return -1;
    }
    gateway = find_member_mutable(controller, gateway_member_key);
    if (!gateway || gateway->kind != WVM_MEMBERSHIP_GATEWAY ||
        entry_state(gateway) != WVM_MANIFEST_MEMBER_ACTIVE ||
        entry_health(gateway) != WVM_MEMBERSHIP_HEALTHY ||
        gateway->active_dependency_count != 1 ||
        successor_transaction->state != WVM_ROUTE_TRANSACTION_PREPARING ||
        !successor_transaction->has_predecessor_snapshot_key ||
        successor_transaction->route_snapshot_key.topology_revision !=
            controller->topology_revision + 1U ||
        successor_transaction->predecessor_snapshot_key.topology_revision !=
            controller->topology_revision ||
        successor_transaction->optional_departure_drain_set.count != 1 ||
        required_ack_find_member(
            &successor_transaction->required_ack_set.entries,
            gateway_member_key) != NULL ||
        !route_snapshot_key_equal(&successor_snapshot->route_snapshot_key,
                                  &successor_transaction->route_snapshot_key) ||
        successor_snapshot->membership_revision !=
            controller->membership_revision ||
        !successor_snapshot->has_predecessor_snapshot_key ||
        !route_snapshot_key_equal(&successor_snapshot->predecessor_snapshot_key,
                                  &successor_transaction
                                       ->predecessor_snapshot_key) ||
        !required_ack_set_equal(&successor_snapshot->required_ack_set,
                                &successor_transaction->required_ack_set) ||
        !find_activated_route_by_snapshot_key(
            controller, &successor_transaction->predecessor_snapshot_key)) {
        set_error(error, error_len, "gateway drain successor is not safe");
        return -1;
    }
    departure_ack = required_ack_find_member(
        &successor_transaction->optional_departure_drain_set,
        gateway_member_key);
    if (!departure_ack || !endpoint_matches_entry(gateway, departure_ack)) {
        set_error(error, error_len,
                  "gateway drain lacks the departing predecessor evidence");
        return -1;
    }
    for (i = 0; i < successor_snapshot->next_hop_rules.count; i++) {
        if (member_key_equal(
                &successor_snapshot->next_hop_rules.entries[i].next_hop_member,
                gateway_member_key)) {
            set_error(error, error_len,
                      "gateway drain successor still forwards to departure");
            return -1;
        }
    }
    for (i = 0; i < controller->dependency_count; i++) {
        const struct wvm_membership_dependency *dependency =
            &controller->dependencies[i];

        if (!member_key_equal(&dependency->member_key, gateway_member_key)) {
            continue;
        }
        dependency_count++;
        if (dependency->vm_id !=
                successor_transaction->route_snapshot_key.scope_key.vm_id ||
            dependency->vm_incarnation != successor_transaction
                                            ->route_snapshot_key.scope_key
                                            .vm_incarnation) {
            set_error(error, error_len,
                      "gateway drain dependency does not match route scope");
            return -1;
        }
    }
    if (dependency_count != 1) {
        set_error(error, error_len,
                  "gateway drain dependency accounting is inconsistent");
        return -1;
    }
    return 0;
}

static int gateway_drain_begin_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *gateway_member_key,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_gateway_drain drain;
    int result = -1;

    if (gateway_drain_successor_validate_locked(
            controller, gateway_member_key, successor_transaction,
            successor_snapshot, error, error_len) == 0 &&
        route_begin_locked(controller, successor_transaction,
                           controller->topology_revision + 1U, error,
                           error_len) == 0) {
        memset(&drain, 0, sizeof(drain));
        drain.active = 1;
        drain.gateway_member_key = *gateway_member_key;
        memcpy(drain.route_operation_id, successor_transaction->operation_id,
               sizeof(drain.route_operation_id));
        drain.prepared_membership_revision = controller->membership_revision;
        drain.prepared_admission_eligibility_revision =
            controller->admission_eligibility_revision + 1U;
        drain.reserved_topology_revision =
            successor_transaction->route_snapshot_key.topology_revision;
        if (gateway_drain_prepare_persist_locked(controller, &drain, error,
                                                 error_len) == 0) {
            controller->gateway_drain = drain;
            controller->admission_eligibility_revision =
                drain.prepared_admission_eligibility_revision;
            result = 0;
        }
    }
    return result;
}

int wvm_membership_controller_gateway_drain_begin(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *gateway_member_key,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot, char *error,
    size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        set_error(error, error_len, "membership controller is not open");
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = gateway_drain_begin_locked(controller, gateway_member_key,
                                        successor_transaction,
                                        successor_snapshot, error, error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

static int gateway_drain_commit_locked(
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *gateway;
    struct wvm_membership_controller_route_entry *route;
    const struct wvm_required_ack_entry *departure_ack;
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t eligibility_revision;
    size_t i;
    int result = -1;

    route = find_route_mutable(controller, route_operation_id);
    if (!gateway_drain_matches_operation(controller, route_operation_id)) {
        if (route && route->transaction.state ==
                         WVM_ROUTE_TRANSACTION_ACTIVATED &&
            route->transaction.route_snapshot_key.topology_revision ==
                controller->topology_revision &&
            route->transaction.has_predecessor_snapshot_key &&
            route->transaction.optional_departure_drain_set.count == 1) {
            departure_ack =
                &route->transaction.optional_departure_drain_set.entries[0];
            gateway = find_member_mutable(controller,
                                          &departure_ack->member_key);
            if (gateway && gateway->kind == WVM_MEMBERSHIP_GATEWAY &&
                entry_state(gateway) == WVM_MANIFEST_MEMBER_DRAINING) {
                result = 0;
                goto out;
            }
        }
        set_error(error, error_len, "gateway drain cannot publish successor");
        goto out;
    }
    gateway = find_member_mutable(
        controller, &controller->gateway_drain.gateway_member_key);
    if (!gateway || gateway->kind != WVM_MEMBERSHIP_GATEWAY ||
        entry_state(gateway) != WVM_MANIFEST_MEMBER_ACTIVE ||
        entry_health(gateway) != WVM_MEMBERSHIP_HEALTHY || !route ||
        route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING ||
        !route_all_required_acks_prepared(route) ||
        route->prepared_membership_revision !=
            controller->gateway_drain.prepared_membership_revision ||
        route->prepared_admission_eligibility_revision == UINT64_MAX ||
        route->prepared_admission_eligibility_revision + 1U !=
            controller->gateway_drain.prepared_admission_eligibility_revision ||
        controller->membership_revision !=
            controller->gateway_drain.prepared_membership_revision ||
        controller->topology_revision == UINT64_MAX ||
        controller->gateway_drain.reserved_topology_revision !=
            controller->topology_revision + 1U ||
        route->transaction.route_snapshot_key.topology_revision !=
            controller->gateway_drain.reserved_topology_revision ||
        controller->admission_eligibility_revision !=
            controller->gateway_drain.prepared_admission_eligibility_revision ||
        controller->membership_revision == UINT64_MAX ||
        controller->admission_eligibility_revision == UINT64_MAX) {
        set_error(error, error_len, "gateway drain cannot publish successor");
        goto out;
    }
    membership_revision = controller->membership_revision + 1U;
    topology_revision = controller->topology_revision + 1U;
    eligibility_revision = controller->admission_eligibility_revision + 1U;
    if (gateway_drain_commit_persist_locked(
            controller, &controller->gateway_drain, membership_revision,
            topology_revision, eligibility_revision, error, error_len) != 0) {
        goto out;
    }
    route->transaction.state = WVM_ROUTE_TRANSACTION_ACTIVATED;
    for (i = 0; i < route->transaction.required_ack_set.entries.count; i++) {
        route->required_ack_states[i].activated = 1;
    }
    entry_set_state(gateway, WVM_MANIFEST_MEMBER_DRAINING,
                    entry_health(gateway), membership_revision,
                    topology_revision);
    controller->membership_revision = membership_revision;
    controller->topology_revision = topology_revision;
    controller->admission_eligibility_revision = eligibility_revision;
    stamp_all_members(controller, membership_revision, topology_revision);
    memset(&controller->gateway_drain, 0, sizeof(controller->gateway_drain));
    result = 0;
out:
    return result;
}

int wvm_membership_controller_gateway_drain_commit(
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0 || !route_operation_id) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = gateway_drain_commit_locked(controller, route_operation_id, error,
                                         error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

static int gateway_drain_abort_locked(
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;
    int result = -1;

    route = find_route_mutable(controller, route_operation_id);
    if (!gateway_drain_matches_operation(controller, route_operation_id)) {
        if (route &&
            route->transaction.state == WVM_ROUTE_TRANSACTION_ABORTED &&
            route->transaction.has_predecessor_snapshot_key &&
            route->transaction.optional_departure_drain_set.count == 1) {
            result = 0;
        } else {
            set_error(error, error_len, "gateway drain cannot abort");
        }
    } else if (!route ||
               route->transaction.state != WVM_ROUTE_TRANSACTION_PREPARING) {
        set_error(error, error_len, "gateway drain cannot abort");
    } else if (gateway_drain_abort_persist_locked(controller, route_operation_id,
                                                   error, error_len) == 0) {
        route->transaction.state = WVM_ROUTE_TRANSACTION_ABORTED;
        memset(&controller->gateway_drain, 0,
               sizeof(controller->gateway_drain));
        result = 0;
    }
    return result;
}

int wvm_membership_controller_gateway_drain_abort(
    struct wvm_membership_controller *controller,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0 || !route_operation_id) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = gateway_drain_abort_locked(controller, route_operation_id, error,
                                        error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

static int gateway_drain_terminal_matches_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *gateway_member_key,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES],
    uint16_t route_state)
{
    struct wvm_membership_controller_member_entry *gateway;
    struct wvm_membership_controller_route_entry *route;

    route = find_route_mutable(controller, route_operation_id);
    gateway = find_member_mutable(controller, gateway_member_key);
    return route && gateway && gateway->kind == WVM_MEMBERSHIP_GATEWAY &&
           route->transaction.state == route_state &&
           route->transaction.optional_departure_drain_set.count == 1 &&
           member_key_equal(
               &route->transaction.optional_departure_drain_set.entries[0]
                    .member_key,
               gateway_member_key);
}

static int gateway_drain_prepare_replay_matches_locked(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *gateway_member_key,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t expected_membership_revision,
    uint64_t expected_topology_revision,
    uint64_t expected_admission_eligibility_revision, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_route_entry *route;

    if (!controller->gateway_drain.active ||
        expected_admission_eligibility_revision == UINT64_MAX ||
        controller->membership_revision != expected_membership_revision ||
        controller->topology_revision != expected_topology_revision ||
        controller->admission_eligibility_revision !=
            expected_admission_eligibility_revision + 1U ||
        !member_key_equal(&controller->gateway_drain.gateway_member_key,
                          gateway_member_key) ||
        !gateway_drain_matches_operation(controller, route_operation_id)) {
        return 0;
    }
    route = find_route_mutable(controller, route_operation_id);
    return route && route->transaction.state == WVM_ROUTE_TRANSACTION_PREPARING &&
           route_transaction_core_equal(&route->transaction,
                                        successor_transaction, error,
                                        error_len) &&
           route_snapshot_key_equal(
               &route->transaction.route_snapshot_key,
               &successor_snapshot->route_snapshot_key);
}

int wvm_membership_controller_gateway_drain_apply(
    struct wvm_membership_controller *controller,
    enum wvm_gateway_drain_action action,
    const struct wvm_member_key *gateway_member_key,
    const struct wvm_route_transaction_record *successor_transaction,
    const struct wvm_route_snapshot_record *successor_snapshot,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t expected_membership_revision,
    uint64_t expected_topology_revision,
    uint64_t expected_admission_eligibility_revision, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *gateway;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !gateway_member_key ||
        gateway_member_key->role_type != WVM_MANIFEST_ROLE_GATEWAY ||
        wvm_member_key_validate(gateway_member_key, error, error_len) != 0 ||
        !route_operation_id ||
        bytes_are_zero(route_operation_id, WVM_IDENTITY_ID_BYTES) ||
        expected_membership_revision == 0 || expected_topology_revision == 0 ||
        expected_admission_eligibility_revision == 0 ||
        (action != WVM_GATEWAY_DRAIN_ACTION_PREPARE &&
         action != WVM_GATEWAY_DRAIN_ACTION_COMMIT &&
         action != WVM_GATEWAY_DRAIN_ACTION_ABORT) ||
        (action == WVM_GATEWAY_DRAIN_ACTION_PREPARE &&
         (!successor_transaction || !successor_snapshot ||
          memcmp(successor_transaction->operation_id, route_operation_id,
                 WVM_IDENTITY_ID_BYTES) != 0))) {
        set_error(error, error_len, "gateway drain action input is invalid");
        return -1;
    }

    pthread_mutex_lock(&controller->lock);
    switch (action) {
    case WVM_GATEWAY_DRAIN_ACTION_PREPARE:
        if (controller->membership_revision == expected_membership_revision &&
            controller->topology_revision == expected_topology_revision &&
            controller->admission_eligibility_revision ==
                expected_admission_eligibility_revision) {
            result = gateway_drain_begin_locked(
                controller, gateway_member_key, successor_transaction,
                successor_snapshot, error, error_len);
        } else if (gateway_drain_prepare_replay_matches_locked(
                       controller, gateway_member_key, successor_transaction,
                       successor_snapshot, route_operation_id,
                       expected_membership_revision,
                       expected_topology_revision,
                       expected_admission_eligibility_revision, error,
                       error_len)) {
            result = 0;
        } else {
            set_error(error, error_len, "gateway drain revision fence is stale");
        }
        break;
    case WVM_GATEWAY_DRAIN_ACTION_COMMIT:
        if (controller->gateway_drain.active &&
            controller->membership_revision == expected_membership_revision &&
            controller->topology_revision == expected_topology_revision &&
            expected_admission_eligibility_revision != UINT64_MAX &&
            controller->admission_eligibility_revision ==
                expected_admission_eligibility_revision + 1U &&
            member_key_equal(&controller->gateway_drain.gateway_member_key,
                             gateway_member_key) &&
            gateway_drain_matches_operation(controller, route_operation_id)) {
            result = gateway_drain_commit_locked(controller, route_operation_id,
                                                 error, error_len);
        } else if (expected_membership_revision != UINT64_MAX &&
                   expected_topology_revision != UINT64_MAX &&
                   expected_admission_eligibility_revision <= UINT64_MAX - 2U &&
                   controller->membership_revision ==
                       expected_membership_revision + 1U &&
                   controller->topology_revision ==
                       expected_topology_revision + 1U &&
                   controller->admission_eligibility_revision ==
                       expected_admission_eligibility_revision + 2U &&
                   gateway_drain_terminal_matches_locked(
                       controller, gateway_member_key, route_operation_id,
                       WVM_ROUTE_TRANSACTION_ACTIVATED) &&
                   (gateway = find_member_mutable(controller,
                                                   gateway_member_key)) != NULL &&
                   entry_state(gateway) == WVM_MANIFEST_MEMBER_DRAINING) {
            result = 0;
        } else {
            set_error(error, error_len, "gateway drain revision fence is stale");
        }
        break;
    case WVM_GATEWAY_DRAIN_ACTION_ABORT:
        if (controller->gateway_drain.active &&
            controller->membership_revision == expected_membership_revision &&
            controller->topology_revision == expected_topology_revision &&
            expected_admission_eligibility_revision != UINT64_MAX &&
            controller->admission_eligibility_revision ==
                expected_admission_eligibility_revision + 1U &&
            member_key_equal(&controller->gateway_drain.gateway_member_key,
                             gateway_member_key) &&
            gateway_drain_matches_operation(controller, route_operation_id)) {
            result = gateway_drain_abort_locked(controller, route_operation_id,
                                                error, error_len);
        } else if (!controller->gateway_drain.active &&
                   controller->membership_revision ==
                       expected_membership_revision &&
                   controller->topology_revision == expected_topology_revision &&
                   expected_admission_eligibility_revision != UINT64_MAX &&
                   controller->admission_eligibility_revision ==
                       expected_admission_eligibility_revision + 1U &&
                   gateway_drain_terminal_matches_locked(
                       controller, gateway_member_key, route_operation_id,
                       WVM_ROUTE_TRANSACTION_ABORTED)) {
            result = 0;
        } else {
            set_error(error, error_len, "gateway drain revision fence is stale");
        }
        break;
    default:
        break;
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_activate_member(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    const uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES], char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *member;
    struct wvm_membership_controller_route_entry *route;
    int index;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !member_key ||
        !route_operation_id) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    member = find_member_mutable(controller, member_key);
    route = find_route_mutable(controller, route_operation_id);
    index = route_ack_index(route, member_key);
    if (!member || !route || index < 0 ||
        member->member_key.role_type != member_key->role_type ||
        route->transaction.state != WVM_ROUTE_TRANSACTION_ACTIVATED ||
        !route->required_ack_states[index].prepared ||
        !route->required_ack_states[index].activated) {
        set_error(error, error_len,
                  "member activation lacks committed route authorization");
    } else if (entry_state(member) == WVM_MANIFEST_MEMBER_ACTIVE) {
        if (member->has_activation_route_operation_id &&
            memcmp(member->activation_route_operation_id, route_operation_id,
                   WVM_IDENTITY_ID_BYTES) == 0) {
            result = 0;
        } else {
            set_error(error, error_len,
                      "active member belongs to another route operation");
        }
    } else if (entry_state(member) != WVM_MANIFEST_MEMBER_PREPARED ||
               entry_health(member) != WVM_MEMBERSHIP_HEALTHY) {
        set_error(error, error_len,
                  "member activation requires a healthy prepared member");
    } else if (persist_activation_binding_locked(
                   controller, member, route_operation_id, error,
                   error_len) != 0) {
        /* The binding is durable before the ACTIVE state is made visible. */
    } else {
        result = persist_member_state_locked(controller, member,
                                             WVM_MANIFEST_MEMBER_ACTIVE,
                                             WVM_MEMBERSHIP_HEALTHY, 0, error,
                                             error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_cordon(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = member_transition_locked(controller, member_key,
                                      WVM_MANIFEST_MEMBER_ACTIVE,
                                      WVM_MANIFEST_MEMBER_CORDONED, 0, error,
                                      error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_cordon_apply(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    uint64_t expected_membership_revision,
    uint64_t expected_topology_revision,
    uint64_t expected_admission_eligibility_revision, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *entry;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !member_key ||
        (member_key->role_type != WVM_MANIFEST_ROLE_NODE_RUNTIME &&
         member_key->role_type != WVM_MANIFEST_ROLE_GATEWAY) ||
        wvm_member_key_validate(member_key, error, error_len) != 0 ||
        expected_membership_revision == 0 ||
        expected_topology_revision == 0 ||
        expected_admission_eligibility_revision == 0) {
        set_error(error, error_len, "member cordon action input is invalid");
        return -1;
    }

    pthread_mutex_lock(&controller->lock);
    entry = find_member_mutable(controller, member_key);
    if (!entry) {
        set_error(error, error_len, "member cordon names an unknown member");
    } else if (controller->membership_revision ==
                   expected_membership_revision &&
               controller->topology_revision == expected_topology_revision &&
               controller->admission_eligibility_revision ==
                   expected_admission_eligibility_revision) {
        if (entry_state(entry) != WVM_MANIFEST_MEMBER_ACTIVE) {
            set_error(error, error_len,
                      "member cordon transition requires ACTIVE state");
        } else {
            result = persist_member_state_locked(
                controller, entry, WVM_MANIFEST_MEMBER_CORDONED,
                entry_health(entry), 0, error, error_len);
        }
    } else if (expected_membership_revision != UINT64_MAX &&
               expected_topology_revision != UINT64_MAX &&
               expected_admission_eligibility_revision != UINT64_MAX &&
               controller->membership_revision ==
                   expected_membership_revision + 1U &&
               controller->topology_revision == expected_topology_revision &&
               controller->admission_eligibility_revision ==
                   expected_admission_eligibility_revision + 1U &&
               entry_state(entry) == WVM_MANIFEST_MEMBER_CORDONED &&
               entry_membership_revision(entry) ==
                   expected_membership_revision + 1U &&
               entry_topology_revision(entry) == expected_topology_revision) {
        /*
         * The membership journal may already contain the state transition
         * while the control-result journal write was interrupted. Replaying
         * the same fenced operation is successful without a second revision.
         */
        result = 0;
    } else {
        set_error(error, error_len, "member cordon revision fence is stale");
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_begin_drain(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    struct wvm_membership_controller_member_entry *entry;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !member_key) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    entry = find_member_mutable(controller, member_key);
    if (gateway_drain_topology_reserved(controller)) {
        set_error(error, error_len,
                  "member drain cannot change a reserved topology");
    } else if (!entry || entry->kind == WVM_MEMBERSHIP_GATEWAY) {
        set_error(error, error_len,
                  "gateway drain requires successor route publication");
    } else if (
        (entry_state(entry) != WVM_MANIFEST_MEMBER_ACTIVE &&
         entry_state(entry) != WVM_MANIFEST_MEMBER_CORDONED) ||
        entry->active_dependency_count != 0) {
        set_error(error, error_len, "member cannot drain with dependencies");
    } else {
        result = persist_member_state_locked(controller, entry,
                                             WVM_MANIFEST_MEMBER_DRAINING,
                                             entry_health(entry), 1, error,
                                             error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_remove(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key, char *error, size_t error_len)
{
    struct wvm_membership_controller_member_entry *entry;
    int result = -1;

    if (!controller || controller->journal_fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    entry = find_member_mutable(controller, member_key);
    if (gateway_drain_topology_reserved(controller)) {
        set_error(error, error_len,
                  "member removal cannot change a reserved topology");
    } else if (!entry ||
               entry_state(entry) != WVM_MANIFEST_MEMBER_DRAINING ||
               entry->active_dependency_count != 0) {
        set_error(error, error_len, "member removal has active dependencies");
    } else {
        result = persist_member_state_locked(
            controller, entry, WVM_MANIFEST_MEMBER_REMOVED, entry_health(entry),
            1, error, error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_member_status(
    const struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    struct wvm_membership_controller_member_status *status, char *error,
    size_t error_len)
{
    const struct wvm_membership_controller_member_entry *entry;
    struct wvm_membership_controller *mutable_controller;

    if (!controller || controller->journal_fd < 0 || !member_key || !status ||
        wvm_member_key_validate(member_key, error, error_len) != 0) {
        set_error(error, error_len, "member status input is invalid");
        return -1;
    }
    mutable_controller = (struct wvm_membership_controller *)controller;
    pthread_mutex_lock(&mutable_controller->lock);
    entry = find_member_mutable(mutable_controller, member_key);
    if (!entry) {
        set_error(error, error_len, "member status names an unknown member");
        pthread_mutex_unlock(&mutable_controller->lock);
        return -1;
    }
    memset(status, 0, sizeof(*status));
    status->kind = entry->kind;
    status->member_key = entry->member_key;
    status->endpoint = entry->kind == WVM_MEMBERSHIP_COMPUTE
                           ? entry->node.control_endpoint
                           : entry->gateway.endpoint;
    status->desired_membership_state = entry_state(entry);
    status->observed_health_state = entry_health(entry);
    status->active_dependency_count = entry->active_dependency_count;
    status->membership_revision = mutable_controller->membership_revision;
    status->topology_revision = mutable_controller->topology_revision;
    status->admission_eligibility_revision =
        mutable_controller->admission_eligibility_revision;
    pthread_mutex_unlock(&mutable_controller->lock);
    return 0;
}

int wvm_membership_controller_report_self_health(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *authenticated_actor,
    enum wvm_membership_health_state health_state, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *entry;
    int result = -1;

    if (!controller || controller->journal_fd < 0 ||
        (health_state != WVM_MEMBERSHIP_HEALTHY &&
         health_state != WVM_MEMBERSHIP_RECOVERING)) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    entry = find_member_mutable(controller, authenticated_actor);
    if (!entry || entry_state(entry) == WVM_MANIFEST_MEMBER_REMOVED ||
        entry_state(entry) == WVM_MANIFEST_MEMBER_FAILED ||
        authorization_check(
            controller, WVM_MEMBERSHIP_CONTROLLER_AUTHORIZE_REPORT_SELF_HEALTH,
            authenticated_actor, &entry->member_key, error, error_len) != 0) {
        set_error(error, error_len, "self health report is not allowed");
    } else if (entry_health(entry) == health_state) {
        result = 0;
    } else {
        result = persist_member_state_locked(controller, entry,
                                             entry_state(entry), health_state,
                                             0, error, error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_mark_monitor_health(
    struct wvm_membership_controller *controller,
    const struct wvm_member_key *member_key,
    enum wvm_membership_health_state health_state, char *error,
    size_t error_len)
{
    struct wvm_membership_controller_member_entry *entry;
    int result = -1;

    if (!controller || controller->journal_fd < 0 || !member_key ||
        (health_state != WVM_MEMBERSHIP_SUSPECT &&
         health_state != WVM_MEMBERSHIP_UNREACHABLE)) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    entry = find_member_mutable(controller, member_key);
    if (!entry || entry_state(entry) == WVM_MANIFEST_MEMBER_REMOVED ||
        entry_state(entry) == WVM_MANIFEST_MEMBER_FAILED) {
        set_error(error, error_len, "monitor health update is not allowed");
    } else if (entry_health(entry) == health_state) {
        result = 0;
    } else {
        result = persist_member_state_locked(controller, entry,
                                             entry_state(entry), health_state,
                                             0, error, error_len);
    }
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_dependency_acquire(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_dependency *dependency, char *error,
    size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = apply_dependency(controller, 1, dependency, 0, error, error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

int wvm_membership_controller_dependency_release(
    struct wvm_membership_controller *controller,
    const struct wvm_membership_dependency *dependency, char *error,
    size_t error_len)
{
    int result;

    if (!controller || controller->journal_fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&controller->lock);
    result = apply_dependency(controller, 2, dependency, 0, error, error_len);
    pthread_mutex_unlock(&controller->lock);
    return result;
}

static int snapshot_unlocked(
    const struct wvm_membership_controller *controller,
    struct wvm_node_record *nodes, size_t node_capacity, size_t *node_count,
    struct wvm_gateway_record *gateways, size_t gateway_capacity,
    size_t *gateway_count, uint64_t *membership_revision,
    uint64_t *topology_revision, uint64_t *admission_eligibility_revision,
    char *error, size_t error_len)
{
    size_t nodes_used = 0;
    size_t gateways_used = 0;
    size_t i;

    if (!controller || !nodes || !gateways || !node_count || !gateway_count ||
        !membership_revision || !topology_revision ||
        !admission_eligibility_revision) {
        set_error(error, error_len, "membership snapshot input is invalid");
        return -1;
    }
    for (i = 0; i < controller->member_count; i++) {
        const struct wvm_membership_controller_member_entry *entry =
            &controller->members[i];

        if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
            if (nodes_used == node_capacity) {
                set_error(error, error_len, "membership snapshot node capacity");
                return -1;
            }
            nodes[nodes_used++] = entry->node;
        } else {
            if (gateways_used == gateway_capacity) {
                set_error(error, error_len,
                          "membership snapshot gateway capacity");
                return -1;
            }
            gateways[gateways_used++] = entry->gateway;
        }
    }
    *node_count = nodes_used;
    *gateway_count = gateways_used;
    *membership_revision = controller->membership_revision;
    *topology_revision = controller->topology_revision;
    *admission_eligibility_revision =
        controller->admission_eligibility_revision;
    return 0;
}

int wvm_membership_controller_snapshot(
    const struct wvm_membership_controller *controller,
    struct wvm_node_record *nodes, size_t node_capacity, size_t *node_count,
    struct wvm_gateway_record *gateways, size_t gateway_capacity,
    size_t *gateway_count, uint64_t *membership_revision,
    uint64_t *topology_revision, uint64_t *admission_eligibility_revision,
    char *error, size_t error_len)
{
    int result;

    if (!controller) {
        set_error(error, error_len, "membership snapshot input is invalid");
        return -1;
    }
    pthread_mutex_lock((pthread_mutex_t *)&controller->lock);
    result = snapshot_unlocked(
        controller, nodes, node_capacity, node_count, gateways,
        gateway_capacity, gateway_count, membership_revision, topology_revision,
        admission_eligibility_revision, error, error_len);
    pthread_mutex_unlock((pthread_mutex_t *)&controller->lock);
    return result;
}

static int capture_unlocked(
    const struct wvm_membership_controller *controller,
    struct wvm_membership_controller_capture *capture, char *error,
    size_t error_len)
{
    size_t node_count = 0;
    size_t gateway_count = 0;
    size_t hosted_gateway_role_id_count = 0;
    size_t gateway_parent_id_count = 0;
    size_t gateway_child_id_count = 0;
    size_t node_index = 0;
    size_t gateway_index = 0;
    size_t hosted_gateway_role_id_index = 0;
    size_t gateway_parent_id_index = 0;
    size_t gateway_child_id_index = 0;
    size_t i;

    if (!controller || !capture || !capture->nodes || !capture->gateways) {
        set_error(error, error_len, "membership capture input is invalid");
        return -1;
    }
    for (i = 0; i < controller->member_count; i++) {
        const struct wvm_membership_controller_member_entry *entry =
            &controller->members[i];

        if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
            size_t count =
                entry->node.inventory.hosted_gateway_role_id_count;

            if (count > SIZE_MAX - hosted_gateway_role_id_count) {
                set_error(error, error_len,
                          "membership capture node list overflows");
                return -1;
            }
            node_count++;
            hosted_gateway_role_id_count += count;
        } else if (entry->kind == WVM_MEMBERSHIP_GATEWAY) {
            size_t parent_count = entry->gateway.parent_gateway_id_count;
            size_t child_count = entry->gateway.child_gateway_id_count;

            if (parent_count > SIZE_MAX - gateway_parent_id_count ||
                child_count > SIZE_MAX - gateway_child_id_count) {
                set_error(error, error_len,
                          "membership capture gateway list overflows");
                return -1;
            }
            gateway_count++;
            gateway_parent_id_count += parent_count;
            gateway_child_id_count += child_count;
        } else {
            set_error(error, error_len, "membership capture member kind invalid");
            return -1;
        }
    }
    if (node_count > capture->node_capacity ||
        gateway_count > capture->gateway_capacity ||
        hosted_gateway_role_id_count >
            capture->hosted_gateway_role_id_capacity ||
        gateway_parent_id_count > capture->gateway_parent_id_capacity ||
        gateway_child_id_count > capture->gateway_child_id_capacity ||
        (hosted_gateway_role_id_count != 0 &&
         !capture->hosted_gateway_role_ids) ||
        (gateway_parent_id_count != 0 && !capture->gateway_parent_ids) ||
        (gateway_child_id_count != 0 && !capture->gateway_child_ids)) {
        set_error(error, error_len, "membership capture storage is too small");
        return -1;
    }
    for (i = 0; i < controller->member_count; i++) {
        const struct wvm_membership_controller_member_entry *entry =
            &controller->members[i];

        if (entry->kind == WVM_MEMBERSHIP_COMPUTE) {
            struct wvm_node_record *node = &capture->nodes[node_index++];
            size_t count =
                entry->node.inventory.hosted_gateway_role_id_count;

            *node = entry->node;
            if (count != 0) {
                memcpy(capture->hosted_gateway_role_ids +
                           hosted_gateway_role_id_index,
                       entry->node.inventory.hosted_gateway_role_ids,
                       count * sizeof(*capture->hosted_gateway_role_ids));
                node->inventory.hosted_gateway_role_ids =
                    capture->hosted_gateway_role_ids +
                    hosted_gateway_role_id_index;
                hosted_gateway_role_id_index += count;
            } else {
                node->inventory.hosted_gateway_role_ids = NULL;
            }
            node->inventory.hosted_gateway_role_id_count = count;
            node->inventory.hosted_gateway_role_id_capacity = count;
        } else {
            struct wvm_gateway_record *gateway =
                &capture->gateways[gateway_index++];
            size_t parent_count = entry->gateway.parent_gateway_id_count;
            size_t child_count = entry->gateway.child_gateway_id_count;

            *gateway = entry->gateway;
            if (parent_count != 0) {
                memcpy(capture->gateway_parent_ids + gateway_parent_id_index,
                       entry->gateway.parent_gateway_ids,
                       parent_count * sizeof(*capture->gateway_parent_ids));
                gateway->parent_gateway_ids =
                    capture->gateway_parent_ids + gateway_parent_id_index;
                gateway_parent_id_index += parent_count;
            } else {
                gateway->parent_gateway_ids = NULL;
            }
            if (child_count != 0) {
                memcpy(capture->gateway_child_ids + gateway_child_id_index,
                       entry->gateway.child_gateway_ids,
                       child_count * sizeof(*capture->gateway_child_ids));
                gateway->child_gateway_ids =
                    capture->gateway_child_ids + gateway_child_id_index;
                gateway_child_id_index += child_count;
            } else {
                gateway->child_gateway_ids = NULL;
            }
            gateway->parent_gateway_id_count = parent_count;
            gateway->parent_gateway_id_capacity = parent_count;
            gateway->child_gateway_id_count = child_count;
            gateway->child_gateway_id_capacity = child_count;
        }
    }
    capture->node_count = node_count;
    capture->gateway_count = gateway_count;
    capture->hosted_gateway_role_id_count = hosted_gateway_role_id_count;
    capture->gateway_parent_id_count = gateway_parent_id_count;
    capture->gateway_child_id_count = gateway_child_id_count;
    capture->membership_revision = controller->membership_revision;
    capture->topology_revision = controller->topology_revision;
    capture->admission_eligibility_revision =
        controller->admission_eligibility_revision;
    return 0;
}

int wvm_membership_controller_capture(
    const struct wvm_membership_controller *controller,
    struct wvm_membership_controller_capture *capture, char *error,
    size_t error_len)
{
    int result;

    if (!controller) {
        set_error(error, error_len, "membership capture input is invalid");
        return -1;
    }
    pthread_mutex_lock((pthread_mutex_t *)&controller->lock);
    result = capture_unlocked(controller, capture, error, error_len);
    pthread_mutex_unlock((pthread_mutex_t *)&controller->lock);
    return result;
}

int wvm_membership_controller_capture_cluster_records(
    const struct wvm_membership_controller_capture *capture,
    const struct wvm_capability_record *capability_records,
    size_t capability_record_count,
    const struct wvm_resource_reservation *resource_reservations,
    size_t resource_reservation_count, uint64_t inventory_revision,
    uint64_t capability_profile_generation,
    struct wvm_cluster_record_set *records_out, char *error, size_t error_len)
{
    if (!capture || !records_out || !capture->nodes || capture->node_count == 0 ||
        capture->node_count > capture->node_capacity ||
        capture->gateway_count > capture->gateway_capacity ||
        (capture->gateway_count != 0 && !capture->gateways) ||
        capture->membership_revision == 0 || capture->topology_revision == 0 ||
        inventory_revision == 0 || capability_profile_generation == 0) {
        set_error(error, error_len,
                  "captured membership record input is invalid");
        return -1;
    }
    if ((capture->hosted_gateway_role_id_count != 0 &&
         (!capture->hosted_gateway_role_ids ||
          capture->hosted_gateway_role_id_count >
              capture->hosted_gateway_role_id_capacity)) ||
        (capture->gateway_parent_id_count != 0 &&
         (!capture->gateway_parent_ids ||
          capture->gateway_parent_id_count >
              capture->gateway_parent_id_capacity)) ||
        (capture->gateway_child_id_count != 0 &&
         (!capture->gateway_child_ids ||
          capture->gateway_child_id_count >
              capture->gateway_child_id_capacity)) ||
        (capability_record_count != 0 && !capability_records) ||
        (resource_reservation_count != 0 && !resource_reservations)) {
        set_error(error, error_len,
                  "captured membership record storage is invalid");
        return -1;
    }
    memset(records_out, 0, sizeof(*records_out));
    records_out->nodes = capture->nodes;
    records_out->node_count = capture->node_count;
    records_out->gateways = capture->gateways;
    records_out->gateway_count = capture->gateway_count;
    records_out->capability_records = capability_records;
    records_out->capability_record_count = capability_record_count;
    records_out->resource_reservations = resource_reservations;
    records_out->resource_reservation_count = resource_reservation_count;
    records_out->inventory_revision = inventory_revision;
    records_out->membership_revision = capture->membership_revision;
    records_out->topology_revision = capture->topology_revision;
    records_out->admission_eligibility_revision =
        capture->admission_eligibility_revision;
    records_out->capability_profile_generation =
        capability_profile_generation;
    return 0;
}

int wvm_membership_controller_capture_current_cluster_records(
    const struct wvm_membership_controller *controller,
    struct wvm_membership_controller_capture *capture,
    const struct wvm_capability_record *capability_records,
    size_t capability_record_count,
    const struct wvm_resource_reservation *resource_reservations,
    size_t resource_reservation_count, uint64_t inventory_revision,
    uint64_t capability_profile_generation,
    struct wvm_cluster_record_set *records_out, char *error, size_t error_len)
{
    if (wvm_membership_controller_capture(controller, capture, error,
                                          error_len) != 0) {
        return -1;
    }
    return wvm_membership_controller_capture_cluster_records(
        capture, capability_records, capability_record_count,
        resource_reservations, resource_reservation_count, inventory_revision,
        capability_profile_generation, records_out, error, error_len);
}

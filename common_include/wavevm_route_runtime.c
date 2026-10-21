#include "wavevm_route_runtime.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct route_snapshot_copy {
    struct wvm_route_snapshot_key key;
    struct wvm_route_rule_record *rules;
    size_t rule_count;
    uint64_t operation_retention_horizon_ms;
};

struct route_scope_slot {
    struct wvm_vm_route_scope_key scope_key;
    struct route_snapshot_copy active;
    struct route_snapshot_copy prepared;
    struct route_snapshot_copy predecessor;
    int has_active;
    int has_prepared;
    int has_predecessor;
    uint64_t outstanding_operation_refs;
    /*
     * R03: the latest instant at which a completed operation's result may
     * still be queried or retried.  This is a deadline, not a count: it is
     * derived from the admitted snapshot horizon and expires with wall time
     * (monotonic clock), so a finished operation cannot pin retirement
     * forever.
     */
    uint64_t result_query_deadline_ms;
    uint64_t operation_retention_horizon_ms;
};

static uint64_t route_now_ms(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

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

static int scope_key_equal(const struct wvm_vm_route_scope_key *left,
                           const struct wvm_vm_route_scope_key *right)
{
    return left && right && left->vm_id == right->vm_id &&
           left->vm_incarnation == right->vm_incarnation &&
           left->route_scope_id == right->route_scope_id;
}

static int snapshot_key_equal(const struct wvm_route_snapshot_key *left,
                              const struct wvm_route_snapshot_key *right)
{
    return left && right && scope_key_equal(&left->scope_key, &right->scope_key) &&
           left->topology_revision == right->topology_revision &&
           left->route_generation == right->route_generation &&
           memcmp(left->snapshot_digest, right->snapshot_digest,
                  WVM_SHA256_DIGEST_BYTES) == 0;
}

static int route_rule_compare(const struct wvm_route_rule_record *left,
                              const struct wvm_route_rule_record *right)
{
    if (left->destination_kind != right->destination_kind) {
        return left->destination_kind < right->destination_kind ? -1 : 1;
    }
    if (left->destination_scope != right->destination_scope) {
        return left->destination_scope < right->destination_scope ? -1 : 1;
    }
    if (left->destination_vnode_or_endpoint !=
        right->destination_vnode_or_endpoint) {
        return left->destination_vnode_or_endpoint <
                       right->destination_vnode_or_endpoint
                   ? -1
                   : 1;
    }
    return 0;
}

static void snapshot_clear(struct route_snapshot_copy *snapshot)
{
    if (!snapshot) {
        return;
    }
    free(snapshot->rules);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void scope_clear(struct route_scope_slot *scope)
{
    if (!scope) {
        return;
    }
    snapshot_clear(&scope->active);
    snapshot_clear(&scope->prepared);
    snapshot_clear(&scope->predecessor);
    memset(scope, 0, sizeof(*scope));
}

static struct route_scope_slot *scope_slots(struct wvm_route_runtime *runtime)
{
    return runtime ? runtime->scopes : NULL;
}

static const struct route_scope_slot *scope_slots_const(
    const struct wvm_route_runtime *runtime)
{
    return runtime ? runtime->scopes : NULL;
}

static struct route_scope_slot *find_scope(struct wvm_route_runtime *runtime,
                                           const struct wvm_vm_route_scope_key
                                               *scope_key)
{
    struct route_scope_slot *scopes = scope_slots(runtime);
    size_t i;

    for (i = 0; scopes && i < runtime->scope_count; i++) {
        if (scope_key_equal(&scopes[i].scope_key, scope_key)) {
            return &scopes[i];
        }
    }
    return NULL;
}

static const struct route_scope_slot *find_scope_const(
    const struct wvm_route_runtime *runtime,
    const struct wvm_vm_route_scope_key *scope_key)
{
    const struct route_scope_slot *scopes = scope_slots_const(runtime);
    size_t i;

    for (i = 0; scopes && i < runtime->scope_count; i++) {
        if (scope_key_equal(&scopes[i].scope_key, scope_key)) {
            return &scopes[i];
        }
    }
    return NULL;
}

static int add_scope(struct wvm_route_runtime *runtime,
                     const struct wvm_vm_route_scope_key *scope_key,
                     struct route_scope_slot **scope_out, char *error,
                     size_t error_len)
{
    struct route_scope_slot *scopes;
    size_t new_capacity;

    if (runtime->scope_count == WVM_ROUTE_RUNTIME_MAX_SCOPES) {
        set_error(error, error_len, "route scope capacity is exhausted");
        return -1;
    }
    if (runtime->scope_count == runtime->scope_capacity) {
        new_capacity = runtime->scope_capacity ? runtime->scope_capacity * 2U
                                                : 8U;
        if (new_capacity > WVM_ROUTE_RUNTIME_MAX_SCOPES) {
            new_capacity = WVM_ROUTE_RUNTIME_MAX_SCOPES;
        }
        scopes = realloc(runtime->scopes, new_capacity * sizeof(*scopes));
        if (!scopes) {
            set_error(error, error_len, "cannot allocate route scope table");
            return -1;
        }
        runtime->scopes = scopes;
        runtime->scope_capacity = new_capacity;
    }
    scopes = scope_slots(runtime);
    memset(&scopes[runtime->scope_count], 0,
           sizeof(scopes[runtime->scope_count]));
    scopes[runtime->scope_count].scope_key = *scope_key;
    *scope_out = &scopes[runtime->scope_count++];
    return 0;
}

static int snapshot_copy_from_record(
    const struct wvm_route_snapshot_record *record,
    struct route_snapshot_copy *copy, char *error, size_t error_len)
{
    size_t rule_bytes;

    if (!record || !copy ||
        wvm_route_snapshot_record_validate(record, error, error_len) != 0 ||
        record->next_hop_rules.count > WVM_ROUTE_RUNTIME_MAX_ENTRIES ||
        record->next_hop_rules.count >
            SIZE_MAX / sizeof(*copy->rules)) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "route snapshot is invalid");
        }
        return -1;
    }
    memset(copy, 0, sizeof(*copy));
    rule_bytes = record->next_hop_rules.count * sizeof(*copy->rules);
    copy->rules = malloc(rule_bytes);
    if (!copy->rules) {
        set_error(error, error_len, "cannot allocate route snapshot rules");
        return -1;
    }
    memcpy(copy->rules, record->next_hop_rules.entries, rule_bytes);
    copy->key = record->route_snapshot_key;
    copy->rule_count = record->next_hop_rules.count;
    copy->operation_retention_horizon_ms = record->operation_retention_horizon_ms;
    return 0;
}

static int route_destination_fields_valid(uint16_t destination_kind,
                                          uint64_t destination_scope,
                                          uint32_t destination_vnode_or_endpoint,
                                          char *error, size_t error_len)
{
    if (destination_vnode_or_endpoint ==
        WVM_ENVELOPE_ROUTE_DESTINATION_UNSPECIFIED) {
        set_error(error, error_len, "route destination is unspecified");
        return -1;
    }
    if (destination_kind ==
        WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE) {
        if (destination_scope == 0) {
            return 0;
        }
        set_error(error, error_len,
                  "flat route destination has a nonzero scope");
        return -1;
    }
    if (destination_kind ==
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE &&
        destination_scope != 0) {
        return 0;
    }
    set_error(error, error_len, "routed envelope destination is invalid");
    return -1;
}

static int route_destination_valid(const struct wvm_envelope *envelope,
                                   char *error, size_t error_len)
{
    if (!envelope || envelope->vm_id == 0 || envelope->vm_incarnation == 0 ||
        envelope->route_scope_id == 0 || envelope->topology_revision == 0 ||
        envelope->route_generation == 0 ||
        bytes_are_zero(envelope->route_snapshot_digest,
                       sizeof(envelope->route_snapshot_digest)) ||
        envelope->route.hop_limit == 0 ||
        envelope->route.hop_count > envelope->route.hop_limit) {
        set_error(error, error_len, "routed envelope identity is incomplete");
        return -1;
    }
    return route_destination_fields_valid(
        envelope->route.destination_kind, envelope->route.destination_scope,
        envelope->route.destination_vnode_or_endpoint, error, error_len);
}

static const struct wvm_route_rule_record *find_rule(
    const struct route_snapshot_copy *snapshot, uint16_t destination_kind,
    uint64_t destination_scope, uint32_t destination_vnode_or_endpoint)
{
    struct wvm_route_rule_record needle;
    size_t left = 0;
    size_t right;

    if (!snapshot || !snapshot->rules) {
        return NULL;
    }
    memset(&needle, 0, sizeof(needle));
    needle.destination_kind = destination_kind;
    needle.destination_scope = destination_scope;
    needle.destination_vnode_or_endpoint = destination_vnode_or_endpoint;
    right = snapshot->rule_count;
    while (left < right) {
        size_t middle = left + (right - left) / 2U;
        int comparison = route_rule_compare(&snapshot->rules[middle], &needle);

        if (comparison == 0) {
            return &snapshot->rules[middle];
        }
        if (comparison < 0) {
            left = middle + 1U;
        } else {
            right = middle;
        }
    }
    return NULL;
}

void wvm_route_runtime_init(struct wvm_route_runtime *runtime)
{
    if (!runtime) {
        return;
    }
    memset(runtime, 0, sizeof(*runtime));
    pthread_rwlock_init(&runtime->lock, NULL);
}

void wvm_route_runtime_destroy(struct wvm_route_runtime *runtime)
{
    struct route_scope_slot *scopes;
    size_t i;

    if (!runtime) {
        return;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    scopes = scope_slots(runtime);
    for (i = 0; scopes && i < runtime->scope_count; i++) {
        scope_clear(&scopes[i]);
    }
    free(scopes);
    runtime->scopes = NULL;
    runtime->scope_count = 0;
    runtime->scope_capacity = 0;
    pthread_rwlock_unlock(&runtime->lock);
    pthread_rwlock_destroy(&runtime->lock);
}

int wvm_route_runtime_prepare(
    struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len)
{
    struct route_snapshot_copy candidate;
    struct route_scope_slot *scope;

    if (!runtime ||
        snapshot_copy_from_record(snapshot, &candidate, error, error_len) !=
            0) {
        return -1;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    scope = find_scope(runtime, &candidate.key.scope_key);
    if (!scope &&
        add_scope(runtime, &candidate.key.scope_key, &scope, error,
                  error_len) != 0) {
        pthread_rwlock_unlock(&runtime->lock);
        snapshot_clear(&candidate);
        return -1;
    }
    if (scope->has_active && snapshot_key_equal(&scope->active.key,
                                                &candidate.key)) {
        pthread_rwlock_unlock(&runtime->lock);
        snapshot_clear(&candidate);
        return 0;
    }
    if (scope->has_prepared && snapshot_key_equal(&scope->prepared.key,
                                                  &candidate.key)) {
        pthread_rwlock_unlock(&runtime->lock);
        snapshot_clear(&candidate);
        return 0;
    }
    snapshot_clear(&scope->prepared);
    scope->prepared = candidate;
    scope->has_prepared = 1;
    pthread_rwlock_unlock(&runtime->lock);
    return 0;
}

int wvm_route_runtime_activate(struct wvm_route_runtime *runtime,
                               const struct wvm_route_snapshot_key *key,
                               char *error, size_t error_len)
{
    struct route_scope_slot *scope;

    if (!runtime || !key ||
        wvm_route_snapshot_key_validate(key, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "route activation key is invalid");
        }
        return -1;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    scope = find_scope(runtime, &key->scope_key);
    if (scope && scope->has_active &&
        snapshot_key_equal(&scope->active.key, key)) {
        pthread_rwlock_unlock(&runtime->lock);
        return 0;
    }
    if (!scope || !scope->has_prepared ||
        !snapshot_key_equal(&scope->prepared.key, key)) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "route activation key is not prepared");
        return -1;
    }
    if (scope->has_active && snapshot_key_equal(&scope->active.key, key)) {
        snapshot_clear(&scope->prepared);
        scope->has_prepared = 0;
        pthread_rwlock_unlock(&runtime->lock);
        return 0;
    }
    if (scope->has_predecessor) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len,
                  "route predecessor must retire before another replacement");
        return -1;
    }
    if (scope->has_active) {
        scope->predecessor = scope->active;
        memset(&scope->active, 0, sizeof(scope->active));
        scope->has_predecessor = 1;
    }
    scope->active = scope->prepared;
    memset(&scope->prepared, 0, sizeof(scope->prepared));
    scope->has_active = 1;
    scope->has_prepared = 0;
    scope->operation_retention_horizon_ms =
        scope->active.operation_retention_horizon_ms;
    pthread_rwlock_unlock(&runtime->lock);
    return 0;
}

int wvm_route_runtime_abort_prepared(
    struct wvm_route_runtime *runtime, const struct wvm_route_snapshot_key *key,
    char *error, size_t error_len)
{
    struct route_scope_slot *scopes;
    struct route_scope_slot *scope;
    size_t scope_index;

    if (!runtime || !key ||
        wvm_route_snapshot_key_validate(key, error, error_len) != 0) {
        if (!error || error[0] == '\0') {
            set_error(error, error_len, "route abort key is invalid");
        }
        return -1;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    scope = find_scope(runtime, &key->scope_key);
    if (!scope || !scope->has_prepared ||
        !snapshot_key_equal(&scope->prepared.key, key)) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "route abort key is not prepared");
        return -1;
    }
    if (scope->has_active && snapshot_key_equal(&scope->active.key, key)) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "active route cannot be aborted");
        return -1;
    }
    snapshot_clear(&scope->prepared);
    scope->has_prepared = 0;
    if (!scope->has_active && !scope->has_predecessor) {
        scopes = scope_slots(runtime);
        scope_index = (size_t)(scope - scopes);
        if (scope_index + 1U != runtime->scope_count) {
            scopes[scope_index] = scopes[runtime->scope_count - 1U];
        }
        memset(&scopes[runtime->scope_count - 1U], 0,
               sizeof(scopes[runtime->scope_count - 1U]));
        runtime->scope_count--;
    }
    pthread_rwlock_unlock(&runtime->lock);
    return 0;
}

int wvm_route_runtime_has_prepared_snapshot(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key)
{
    const struct route_scope_slot *scope;
    int found;

    if (!runtime || !key) {
        return 0;
    }
    pthread_rwlock_rdlock((pthread_rwlock_t *)&runtime->lock);
    scope = find_scope_const(runtime, &key->scope_key);
    found = scope && scope->has_prepared &&
            snapshot_key_equal(&scope->prepared.key, key);
    pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
    return found;
}

int wvm_route_runtime_retire(struct wvm_route_runtime *runtime,
                             const struct wvm_route_snapshot_key *key,
                             char *error, size_t error_len)
{
    struct route_scope_slot *scopes;
    struct route_scope_slot *scope;
    size_t scope_index;

    if (!runtime || !key) {
        set_error(error, error_len, "route retirement key is missing");
        return -1;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    scope = find_scope(runtime, &key->scope_key);
    if (!scope) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "route retirement key is not retained");
        return -1;
    }
    if (scope->outstanding_operation_refs != 0) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len,
                  "route retirement blocked: outstanding operation refs remain");
        return -1;
    }
    if (scope->result_query_deadline_ms != 0 &&
        route_now_ms() < scope->result_query_deadline_ms) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len,
                  "route retirement blocked: result retention window is open");
        return -1;
    }
    if (scope->has_predecessor &&
        snapshot_key_equal(&scope->predecessor.key, key)) {
        snapshot_clear(&scope->predecessor);
        scope->has_predecessor = 0;
    } else if (scope->has_active && snapshot_key_equal(&scope->active.key, key) &&
               !scope->has_predecessor) {
        snapshot_clear(&scope->active);
        scope->has_active = 0;
    } else {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "route retirement key is not retired safely");
        return -1;
    }
    if (!scope->has_active && !scope->has_prepared && !scope->has_predecessor) {
        scopes = scope_slots(runtime);
        scope_index = (size_t)(scope - scopes);
        if (scope_index + 1U != runtime->scope_count) {
            scopes[scope_index] = scopes[runtime->scope_count - 1U];
        }
        memset(&scopes[runtime->scope_count - 1U], 0,
               sizeof(scopes[runtime->scope_count - 1U]));
        runtime->scope_count--;
    }
    pthread_rwlock_unlock(&runtime->lock);
    return 0;
}

int wvm_route_runtime_lookup_destination(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key, uint16_t destination_kind,
    uint64_t destination_scope, uint32_t destination_vnode_or_endpoint,
    struct wvm_route_runtime_next_hop *next_hop_out, char *error,
    size_t error_len)
{
    const struct route_scope_slot *scope;
    const struct wvm_route_rule_record *rule;

    if (!runtime || !next_hop_out ||
        !key ||
        wvm_route_snapshot_key_validate(key, error, error_len) != 0 ||
        route_destination_fields_valid(
            destination_kind, destination_scope,
            destination_vnode_or_endpoint, error, error_len) != 0) {
        return -1;
    }

    pthread_rwlock_rdlock((pthread_rwlock_t *)&runtime->lock);
    scope = find_scope_const(runtime, &key->scope_key);
    if (!scope || !scope->has_active ||
        !snapshot_key_equal(&scope->active.key, key)) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
        set_error(error, error_len, "route snapshot is unavailable or stale");
        return -1;
    }
    rule = find_rule(&scope->active, WVM_ROUTE_DESTINATION_EXACT_VNODE,
                     destination_scope, destination_vnode_or_endpoint);
    if (!rule && destination_kind ==
                     WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE) {
        rule = find_rule(&scope->active, WVM_ROUTE_DESTINATION_PREFIX,
                         destination_scope, 0);
    }
    if (!rule) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
        set_error(error, error_len, "route destination is unknown");
        return -1;
    }
    memset(next_hop_out, 0, sizeof(*next_hop_out));
    next_hop_out->matched_destination_kind = rule->destination_kind;
    next_hop_out->next_hop_kind = rule->next_hop_kind;
    next_hop_out->hop_limit = rule->hop_limit;
    next_hop_out->next_hop_member = rule->next_hop_member;
    next_hop_out->next_hop_endpoint = rule->next_hop_endpoint;
    pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
    return 0;
}

int wvm_route_runtime_lookup(
    const struct wvm_route_runtime *runtime,
    const struct wvm_envelope *envelope,
    struct wvm_route_runtime_next_hop *next_hop_out, char *error,
    size_t error_len)
{
    struct wvm_route_snapshot_key key;

    if (!envelope ||
        route_destination_valid(envelope, error, error_len) != 0) {
        return -1;
    }
    memset(&key, 0, sizeof(key));
    key.scope_key.vm_id = envelope->vm_id;
    key.scope_key.vm_incarnation = envelope->vm_incarnation;
    key.scope_key.route_scope_id = envelope->route_scope_id;
    key.topology_revision = envelope->topology_revision;
    key.route_generation = envelope->route_generation;
    memcpy(key.snapshot_digest, envelope->route_snapshot_digest,
           sizeof(key.snapshot_digest));
    if (wvm_route_runtime_lookup_destination(
            runtime, &key, envelope->route.destination_kind,
            envelope->route.destination_scope,
            envelope->route.destination_vnode_or_endpoint, next_hop_out, error,
            error_len) != 0) {
        return -1;
    }
    if (envelope->route.hop_count >= next_hop_out->hop_limit) {
        set_error(error, error_len, "route rule hop budget is exhausted");
        return -1;
    }
    return 0;
}
int wvm_route_runtime_current_key(
    const struct wvm_route_runtime *runtime,
    const struct wvm_vm_route_scope_key *scope_key,
    struct wvm_route_snapshot_key *key_out)
{
    const struct route_scope_slot *scope;

    if (!runtime || !scope_key || !key_out) {
        return -1;
    }
    pthread_rwlock_rdlock((pthread_rwlock_t *)&runtime->lock);
    scope = find_scope_const(runtime, scope_key);
    if (!scope || !scope->has_active) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
        return -1;
    }
    *key_out = scope->active.key;
    pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
    return 0;
}

int wvm_route_runtime_predecessor_key(
    const struct wvm_route_runtime *runtime,
    const struct wvm_vm_route_scope_key *scope_key,
    struct wvm_route_snapshot_key *key_out)
{
    const struct route_scope_slot *scope;

    if (!runtime || !scope_key || !key_out) {
        return -1;
    }
    pthread_rwlock_rdlock((pthread_rwlock_t *)&runtime->lock);
    scope = find_scope_const(runtime, scope_key);
    if (!scope || !scope->has_predecessor) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
        return -1;
    }
    *key_out = scope->predecessor.key;
    pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
    return 0;
}

int wvm_route_runtime_has_snapshot(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key)
{
    const struct route_scope_slot *scope;
    int found;

    if (!runtime || !key) {
        return 0;
    }
    pthread_rwlock_rdlock((pthread_rwlock_t *)&runtime->lock);
    scope = find_scope_const(runtime, &key->scope_key);
    found = scope &&
            ((scope->has_active && snapshot_key_equal(&scope->active.key, key)) ||
             (scope->has_predecessor &&
              snapshot_key_equal(&scope->predecessor.key, key)));
    pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
    return found;
}


int wvm_route_runtime_operation_ref_get(
    struct wvm_route_runtime *runtime, const struct wvm_vm_route_scope_key *scope,
    char *error, size_t error_len)
{
    struct route_scope_slot *slot;

    if (!runtime || !scope) {
        set_error(error, error_len, "route operation ref get input is invalid");
        return -1;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    slot = find_scope(runtime, scope);
    if (!slot || !slot->has_active) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len,
                  "route operation ref requires an active scope");
        return -1;
    }
    if (slot->outstanding_operation_refs == UINT64_MAX) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "route operation ref count overflow");
        return -1;
    }
    slot->outstanding_operation_refs++;
    pthread_rwlock_unlock(&runtime->lock);
    return 0;
}

int wvm_route_runtime_operation_ref_put(
    struct wvm_route_runtime *runtime, const struct wvm_vm_route_scope_key *scope,
    char *error, size_t error_len)
{
    struct route_scope_slot *slot;

    if (!runtime || !scope) {
        set_error(error, error_len, "route operation ref put input is invalid");
        return -1;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    slot = find_scope(runtime, scope);
    if (!slot || slot->outstanding_operation_refs == 0) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "route operation ref put underflow");
        return -1;
    }
    slot->outstanding_operation_refs--;
    /*
     * R03: a completed operation keeps its result queryable only until the
     * admitted retention horizon elapses.  Record the latest deadline; the
     * proof query compares it with the monotonic clock instead of waiting for
     * a counter that nothing would ever decrement.
     */
    if (slot->operation_retention_horizon_ms > 0) {
        uint64_t now = route_now_ms();
        uint64_t deadline =
            now > UINT64_MAX - slot->operation_retention_horizon_ms
                ? UINT64_MAX
                : now + slot->operation_retention_horizon_ms;

        if (deadline > slot->result_query_deadline_ms)
            slot->result_query_deadline_ms = deadline;
    }
    pthread_rwlock_unlock(&runtime->lock);
    return 0;
}

int wvm_route_runtime_query_retire_proof(
    const struct wvm_route_runtime *runtime,
    const struct wvm_route_snapshot_key *key, uint64_t *active_operation_refs,
    int *retention_horizon_complete, char *error, size_t error_len)
{
    const struct route_scope_slot *slot;

    if (!runtime || !key || !active_operation_refs ||
        !retention_horizon_complete) {
        set_error(error, error_len, "route retire proof query input is invalid");
        return -1;
    }
    pthread_rwlock_rdlock((pthread_rwlock_t *)&runtime->lock);
    slot = find_scope_const(runtime, &key->scope_key);
    if (!slot) {
        /* Already gone: no retained work for this scope. */
        pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
        *active_operation_refs = 0;
        *retention_horizon_complete = 1;
        return 0;
    }
    *active_operation_refs = slot->outstanding_operation_refs;
    /*
     * R03: horizon complete when no operation is in flight AND the result
     * query window has actually elapsed.  refs==0 alone is not enough while
     * the admitted horizon keeps completions queryable.
     */
    *retention_horizon_complete =
        (slot->outstanding_operation_refs == 0 &&
         (slot->result_query_deadline_ms == 0 ||
          route_now_ms() >= slot->result_query_deadline_ms))
            ? 1
            : 0;
    pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
    return 0;
}

int wvm_route_runtime_drain_result_deadlines(
    struct wvm_route_runtime *runtime,
    const struct wvm_vm_route_scope_key *scope, char *error, size_t error_len)
{
    struct route_scope_slot *slot;

    if (!runtime || !scope) {
        set_error(error, error_len, "route deadline drain input is invalid");
        return -1;
    }
    pthread_rwlock_wrlock(&runtime->lock);
    slot = find_scope(runtime, scope);
    if (!slot) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len, "route deadline drain scope missing");
        return -1;
    }
    if (slot->outstanding_operation_refs != 0) {
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len,
                  "cannot drain result deadlines while ops outstanding");
        return -1;
    }
    /*
     * Expire only what time has already made unreachable.  Unconditionally
     * zeroing the window would let a caller retire a scope while a client can
     * still legitimately query its completion.
     */
    if (slot->result_query_deadline_ms != 0 &&
        route_now_ms() < slot->result_query_deadline_ms) {
        uint64_t remaining = slot->result_query_deadline_ms - route_now_ms();
        pthread_rwlock_unlock(&runtime->lock);
        set_error(error, error_len,
                  "result retention window is still open for %llu ms",
                  (unsigned long long)remaining);
        return -1;
    }
    slot->result_query_deadline_ms = 0;
    pthread_rwlock_unlock(&runtime->lock);
    return 0;
}

uint64_t wvm_route_runtime_operation_retention_horizon_ms(
    const struct wvm_route_runtime *runtime,
    const struct wvm_vm_route_scope_key *scope)
{
    const struct route_scope_slot *slot;
    uint64_t ms = 0;

    if (!runtime || !scope)
        return 0;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&runtime->lock);
    slot = find_scope_const(runtime, scope);
    if (slot)
        ms = slot->operation_retention_horizon_ms;
    pthread_rwlock_unlock((pthread_rwlock_t *)&runtime->lock);
    return ms;
}

#include "wavevm_admission_route.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "wavevm_cluster.h"
#include "wavevm_membership.h"
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

static int member_key_compare(const struct wvm_member_key *left,
                              const struct wvm_member_key *right)
{
    if (left->role_type != right->role_type) {
        return left->role_type < right->role_type ? -1 : 1;
    }
    if (left->role_id != right->role_id) {
        return left->role_id < right->role_id ? -1 : 1;
    }
    if (left->instance_id != right->instance_id) {
        return left->instance_id < right->instance_id ? -1 : 1;
    }
    return 0;
}

static int valid_topology(enum wvm_route_topology_kind topology_kind)
{
    return topology_kind == WVM_ROUTE_TOPOLOGY_FLAT ||
           topology_kind == WVM_ROUTE_TOPOLOGY_FRACTAL;
}

static int compiler_storage_valid(
    const struct wvm_admission_route_compiler *compiler, char *error,
    size_t error_len)
{
    if (!compiler || !valid_topology(compiler->topology_kind) ||
        compiler->route_generation == 0 ||
        compiler->operation_retention_horizon_ms == 0 ||
        compiler->retirement_policy == 0 || !compiler->route_rules ||
        compiler->route_rule_capacity == 0 || !compiler->ack_entries ||
        compiler->ack_entry_capacity == 0 || !compiler->snapshot_bytes ||
        compiler->snapshot_byte_capacity == 0 || !compiler->ack_set_bytes ||
        compiler->ack_set_byte_capacity == 0) {
        set_error(error, error_len, "admission route compiler storage is invalid");
        return -1;
    }
    return 0;
}

int wvm_admission_route_compiler_init(
    struct wvm_admission_route_compiler *compiler,
    enum wvm_route_topology_kind topology_kind, uint64_t route_generation,
    uint64_t operation_retention_horizon_ms, uint16_t retirement_policy,
    struct wvm_route_rule_record *route_rules, size_t route_rule_capacity,
    struct wvm_required_ack_entry *ack_entries, size_t ack_entry_capacity,
    uint8_t *snapshot_bytes, size_t snapshot_byte_capacity,
    uint8_t *ack_set_bytes, size_t ack_set_byte_capacity, char *error,
    size_t error_len)
{
    if (!compiler) {
        set_error(error, error_len, "admission route compiler is missing");
        return -1;
    }
    memset(compiler, 0, sizeof(*compiler));
    compiler->topology_kind = topology_kind;
    compiler->route_generation = route_generation;
    compiler->operation_retention_horizon_ms =
        operation_retention_horizon_ms;
    compiler->retirement_policy = retirement_policy;
    compiler->route_rules = route_rules;
    compiler->route_rule_capacity = route_rule_capacity;
    compiler->ack_entries = ack_entries;
    compiler->ack_entry_capacity = ack_entry_capacity;
    compiler->snapshot_bytes = snapshot_bytes;
    compiler->snapshot_byte_capacity = snapshot_byte_capacity;
    compiler->ack_set_bytes = ack_set_bytes;
    compiler->ack_set_byte_capacity = ack_set_byte_capacity;
    return compiler_storage_valid(compiler, error, error_len);
}

int wvm_admission_route_compiler_validate(
    const struct wvm_admission_route_compiler *compiler, char *error,
    size_t error_len)
{
    return compiler_storage_valid(compiler, error, error_len);
}

static const struct wvm_gateway_record *select_gateway(
    const struct wvm_cluster_record_set *records,
    enum wvm_route_topology_kind topology_kind)
{
    const struct wvm_gateway_record *selected = NULL;
    size_t i;

    for (i = 0; i < records->gateway_count; i++) {
        const struct wvm_gateway_record *gateway = &records->gateways[i];

        if (gateway->desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE ||
            gateway->observed_health_state != WVM_MEMBERSHIP_HEALTHY ||
            (topology_kind == WVM_ROUTE_TOPOLOGY_FRACTAL &&
             gateway->parent_gateway_id_count != 0)) {
            continue;
        }
        if (!selected || gateway->gateway_id < selected->gateway_id) {
            selected = gateway;
        }
    }
    return selected;
}

static int append_route_rule(
    struct wvm_admission_route_compiler *compiler,
    const struct wvm_route_rule_record *rule, char *error, size_t error_len)
{
    size_t insert_at;
    size_t i;

    if (!compiler || !rule || !compiler->route_rules ||
        compiler->route_rule_count == compiler->route_rule_capacity) {
        set_error(error, error_len, "route compiler rule storage is missing");
        return -1;
    }
    insert_at = compiler->route_rule_count;
    for (i = 0; i < compiler->route_rule_count; i++) {
        if (route_rule_compare(&compiler->route_rules[i], rule) == 0) {
            set_error(error, error_len, "route compiler produced duplicate rule");
            return -1;
        }
        if (route_rule_compare(&compiler->route_rules[i], rule) > 0) {
            insert_at = i;
            break;
        }
    }
    for (i = compiler->route_rule_count; i > insert_at; i--) {
        compiler->route_rules[i] = compiler->route_rules[i - 1U];
    }
    compiler->route_rules[insert_at] = *rule;
    compiler->route_rule_count++;
    return 0;
}

static int append_flat_rules(struct wvm_admission_route_compiler *compiler,
                             const struct wvm_cluster_record_set *records,
                             const struct wvm_gateway_record *gateway,
                             char *error, size_t error_len)
{
    size_t i;

    for (i = 0; i < records->node_count; i++) {
        const struct wvm_node_record *node = &records->nodes[i];
        uint64_t vnode_end;
        uint64_t vnode;

        if (node->desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE ||
            node->observed_health_state != WVM_MEMBERSHIP_HEALTHY) {
            continue;
        }
        if (node->local_vnode_first == UINT32_MAX ||
            node->local_vnode_count >
                UINT32_MAX - node->local_vnode_first) {
            set_error(error, error_len, "flat route vnode range is invalid");
            return -1;
        }
        vnode_end = (uint64_t)node->local_vnode_first +
                    node->local_vnode_count;
        for (vnode = node->local_vnode_first;
             vnode < vnode_end; vnode++) {
            struct wvm_route_rule_record rule;

            if (vnode > UINT32_MAX) {
                set_error(error, error_len, "flat route vnode exceeds u32");
                return -1;
            }
            memset(&rule, 0, sizeof(rule));
            rule.destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
            rule.destination_vnode_or_endpoint = (uint32_t)vnode;
            rule.next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
            rule.next_hop_member.role_type = WVM_MANIFEST_ROLE_GATEWAY;
            rule.next_hop_member.role_id = gateway->gateway_id;
            rule.next_hop_member.instance_id = gateway->gateway_instance_id;
            rule.next_hop_endpoint = gateway->endpoint;
            rule.hop_limit = 1;
            if (append_route_rule(compiler, &rule, error, error_len) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

static int append_fractal_rules(
    struct wvm_admission_route_compiler *compiler,
    const struct wvm_cluster_record_set *records,
    const struct wvm_gateway_record *gateway, char *error, size_t error_len)
{
    size_t i;

    for (i = 0; i < records->node_count; i++) {
        const struct wvm_node_record *node = &records->nodes[i];
        struct wvm_route_rule_record rule;
        size_t j;

        if (node->desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE ||
            node->observed_health_state != WVM_MEMBERSHIP_HEALTHY ||
            node->pod_id == 0) {
            continue;
        }
        for (j = 0; j < compiler->route_rule_count; j++) {
            if (compiler->route_rules[j].destination_scope == node->pod_id) {
                break;
            }
        }
        if (j != compiler->route_rule_count) {
            continue;
        }
        memset(&rule, 0, sizeof(rule));
        rule.destination_kind = WVM_ROUTE_DESTINATION_PREFIX;
        rule.destination_scope = node->pod_id;
        rule.next_hop_kind = WVM_ROUTE_NEXT_HOP_GATEWAY;
        rule.next_hop_member.role_type = WVM_MANIFEST_ROLE_GATEWAY;
        rule.next_hop_member.role_id = gateway->gateway_id;
        rule.next_hop_member.instance_id = gateway->gateway_instance_id;
        rule.next_hop_endpoint = gateway->endpoint;
        rule.hop_limit = 1;
        if (append_route_rule(compiler, &rule, error, error_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int build_operation_id(
    const struct wvm_coordinator_transaction *transaction,
    const struct wvm_admission_route_compiler *compiler,
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES])
{
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t input[WVM_IDENTITY_ID_BYTES + 8U];
    size_t i;

    memcpy(input, transaction->admission_tx_id, WVM_IDENTITY_ID_BYTES);
    for (i = 0; i < 8; i++) {
        input[WVM_IDENTITY_ID_BYTES + 7U - i] =
            (uint8_t)(compiler->route_generation >> (8U * i));
    }
    wvm_sha256_digest(input, sizeof(input), digest);
    memcpy(operation_id, digest, WVM_IDENTITY_ID_BYTES);
    return bytes_are_zero(operation_id, WVM_IDENTITY_ID_BYTES) ? -1 : 0;
}

int wvm_admission_route_compile(
    void *context, const struct wvm_coordinator_transaction *transaction,
    const struct wvm_cluster_record_set *records,
    struct wvm_coordinator_prepared_route *prepared_route,
    struct wvm_route_transaction_record *route_transaction,
    struct wvm_route_snapshot_record *route_snapshot, char *error,
    size_t error_len)
{
    struct wvm_admission_route_compiler *compiler = context;
    struct wvm_cluster_snapshot snapshot = {0};
    const struct wvm_gateway_record *gateway;
    uint8_t snapshot_digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;
    size_t rule_count;
    size_t i;

    if (compiler_storage_valid(compiler, error, error_len) != 0 ||
        !transaction || !records || !prepared_route || !route_transaction ||
        !route_snapshot || records->gateway_count == 0 ||
        wvm_vm_route_scope_key_validate(&transaction->route_scope_key, error,
                                        error_len) != 0 ||
        wvm_cluster_snapshot_build(records, &snapshot,
                                   error, error_len) != 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len, "admission route compiler input is invalid");
        }
        return -1;
    }
    wvm_admission_snapshot_cleanup(&snapshot.admission);
    gateway = select_gateway(records, compiler->topology_kind);
    if (!gateway) {
        set_error(error, error_len,
                  "admission route compiler has no eligible gateway");
        return -1;
    }
    memset(compiler->route_rules, 0,
           compiler->route_rule_capacity * sizeof(*compiler->route_rules));
    compiler->route_rule_count = 0;
    if ((compiler->topology_kind == WVM_ROUTE_TOPOLOGY_FLAT
             ? append_flat_rules(compiler, records, gateway, error, error_len)
             : append_fractal_rules(compiler, records, gateway, error,
                                    error_len)) != 0 ||
        (rule_count = compiler->route_rule_count) == 0) {
        if (error && error[0] == '\0') {
            set_error(error, error_len, "admission route compiler produced no rules");
        }
        return -1;
    }

    memset(route_snapshot, 0, sizeof(*route_snapshot));
    route_snapshot->route_snapshot_key.scope_key = transaction->route_scope_key;
    route_snapshot->route_snapshot_key.topology_revision =
        records->topology_revision;
    route_snapshot->route_snapshot_key.route_generation =
        compiler->route_generation;
    route_snapshot->membership_revision = records->membership_revision;
    route_snapshot->topology_kind = compiler->topology_kind;
    route_snapshot->next_hop_rules.entries = compiler->route_rules;
    route_snapshot->next_hop_rules.count = rule_count;
    route_snapshot->next_hop_rules.capacity = compiler->route_rule_capacity;
    route_snapshot->required_ack_set.entries.entries = compiler->ack_entries;
    route_snapshot->required_ack_set.entries.count = 1;
    route_snapshot->required_ack_set.entries.capacity =
        compiler->ack_entry_capacity;
    route_snapshot->operation_retention_horizon_ms =
        compiler->operation_retention_horizon_ms;
    route_snapshot->retirement_policy = compiler->retirement_policy;
    memset(compiler->ack_entries, 0,
           compiler->ack_entry_capacity * sizeof(*compiler->ack_entries));
    compiler->ack_entries[0].member_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    compiler->ack_entries[0].member_key.role_id = gateway->gateway_id;
    compiler->ack_entries[0].member_key.instance_id = gateway->gateway_instance_id;
    compiler->ack_entries[0].endpoint = gateway->endpoint;
    compiler->ack_entries[0].role_type = WVM_MANIFEST_ROLE_GATEWAY;
    compiler->ack_entries[0].expected_snapshot_key =
        route_snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(
            route_snapshot, compiler->snapshot_bytes,
            compiler->snapshot_byte_capacity, &encoded_bytes, snapshot_digest,
            error, error_len) != 0 ||
        wvm_route_snapshot_record_decode(
            compiler->snapshot_bytes, encoded_bytes, route_snapshot, error,
            error_len) != 0) {
        return -1;
    }

    memset(route_transaction, 0, sizeof(*route_transaction));
    route_transaction->required_ack_set = route_snapshot->required_ack_set;
    /* A route snapshot stores the self-normalized ACK digest. The transaction
     * carries the ordinary full-key ACK digest, so recalculate it explicitly. */
    memset(route_transaction->required_ack_set.entries_digest, 0,
           sizeof(route_transaction->required_ack_set.entries_digest));
    if (build_operation_id(transaction, compiler, route_transaction->operation_id) !=
            0 ||
        wvm_required_ack_set_encode(
            &route_transaction->required_ack_set, compiler->ack_set_bytes,
            compiler->ack_set_byte_capacity, &encoded_bytes, error,
            error_len) != 0 ||
        wvm_required_ack_set_decode(
            compiler->ack_set_bytes, encoded_bytes,
            &route_transaction->required_ack_set, error, error_len) != 0) {
        return -1;
    }
    route_transaction->route_snapshot_key = route_snapshot->route_snapshot_key;
    route_transaction->optional_departure_drain_set.entries = NULL;
    route_transaction->optional_departure_drain_set.count = 0;
    route_transaction->optional_departure_drain_set.capacity = 0;
    route_transaction->operation_retention_horizon_ms =
        compiler->operation_retention_horizon_ms;
    route_transaction->state = WVM_ROUTE_TRANSACTION_PREPARING;
    if (wvm_route_snapshot_record_binds_transaction(
            route_snapshot, route_transaction, error, error_len) != 0) {
        return -1;
    }
    for (i = 1; i < route_snapshot->required_ack_set.entries.count; i++) {
        if (member_key_compare(
                &route_snapshot->required_ack_set.entries.entries[i - 1]
                     .member_key,
                &route_snapshot->required_ack_set.entries.entries[i].member_key) >=
            0) {
            set_error(error, error_len, "admission route ACK set is not ordered");
            return -1;
        }
    }
    prepared_route->route_snapshot_key = route_snapshot->route_snapshot_key;
    prepared_route->required_ack_set = &route_snapshot->required_ack_set;
    return 0;
}

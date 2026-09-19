#include "wavevm_cluster.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int endpoint_equal(const struct wvm_endpoint *left,
                          const struct wvm_endpoint *right)
{
    return left->data_transport == right->data_transport &&
           left->data_address_bytes == right->data_address_bytes &&
           memcmp(left->data_address, right->data_address,
                  left->data_address_bytes) == 0 &&
           left->data_port == right->data_port &&
           left->control_transport == right->control_transport &&
           left->has_control_address == right->has_control_address &&
           (!left->has_control_address ||
            (left->control_address_bytes == right->control_address_bytes &&
             memcmp(left->control_address, right->control_address,
                    left->control_address_bytes) == 0)) &&
           left->control_port == right->control_port &&
           left->has_server_name == right->has_server_name &&
           (!left->has_server_name ||
            strcmp(left->server_name, right->server_name) == 0);
}

static const struct wvm_node_record *
find_node(const struct wvm_cluster_record_set *records, uint32_t node_id)
{
    size_t i;

    for (i = 0; i < records->node_count; i++) {
        if (records->nodes[i].physical_node_id == node_id) {
            return &records->nodes[i];
        }
    }
    return NULL;
}

static const struct wvm_gateway_record *
find_gateway(const struct wvm_cluster_record_set *records, uint32_t gateway_id)
{
    size_t i;

    for (i = 0; i < records->gateway_count; i++) {
        if (records->gateways[i].gateway_id == gateway_id) {
            return &records->gateways[i];
        }
    }
    return NULL;
}

static int u32_list_contains(const uint32_t *entries, size_t count,
                             uint32_t value)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (entries[i] == value) {
            return 1;
        }
    }
    return 0;
}

static int capability_record_compare(
    const struct wvm_capability_record *left,
    const struct wvm_capability_record *right)
{
    if (left->physical_node_id != right->physical_node_id) {
        return left->physical_node_id < right->physical_node_id ? -1 : 1;
    }
    if (left->node_instance_id != right->node_instance_id) {
        return left->node_instance_id < right->node_instance_id ? -1 : 1;
    }
    if (left->capability_id != right->capability_id) {
        return left->capability_id < right->capability_id ? -1 : 1;
    }
    if (left->provider_instance_id != right->provider_instance_id) {
        return left->provider_instance_id < right->provider_instance_id ? -1 : 1;
    }
    return 0;
}

static int capability_set_validate(const struct wvm_cluster_record_set *records,
                                   char *error, size_t error_len)
{
    size_t i;

    if ((records->capability_record_count != 0 &&
         !records->capability_records) ||
        records->capability_record_count == 0) {
        set_error(error, error_len, "cluster snapshot has no capability records");
        return -1;
    }
    for (i = 0; i < records->capability_record_count; i++) {
        if (wvm_capability_record_validate(&records->capability_records[i], error,
                                           error_len) != 0 ||
            (i != 0 &&
             capability_record_compare(&records->capability_records[i - 1],
                                       &records->capability_records[i]) >= 0)) {
            set_error(error, error_len,
                      "capability record set is not strictly ordered");
            return -1;
        }
    }
    return 0;
}

static int node_capability_profile(
    const struct wvm_cluster_record_set *records,
    const struct wvm_node_record *node, uint32_t *backend_capabilities,
    uint32_t *runtime_capabilities, char *error, size_t error_len)
{
    size_t start = records->capability_record_count;
    size_t end = records->capability_record_count;
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    int kvm_available = 0;
    int tcg_available = 0;
    int mode_b_available = 0;
    size_t i;

    for (i = 0; i < records->capability_record_count; i++) {
        const struct wvm_capability_record *record =
            &records->capability_records[i];

        if (record->physical_node_id == node->physical_node_id &&
            record->node_instance_id == node->node_instance_id) {
            if (start == records->capability_record_count) {
                start = i;
            }
            end = i + 1U;
            if (record->state == WVM_CAPABILITY_AVAILABLE) {
                if (record->capability_id == WVM_CAPABILITY_ID_EXECUTION_KVM) {
                    kvm_available = 1;
                } else if (record->capability_id ==
                           WVM_CAPABILITY_ID_EXECUTION_TCG) {
                    tcg_available = 1;
                } else if (record->capability_id ==
                           WVM_CAPABILITY_ID_MODE_B_MEMORY) {
                    mode_b_available = 1;
                }
            }
        } else if (start != records->capability_record_count) {
            break;
        }
    }
    if (start == records->capability_record_count ||
        wvm_capability_profile_digest(
            node->physical_node_id, node->node_instance_id,
            records->capability_profile_generation,
            records->capability_records + start, end - start, digest, error,
            error_len) != 0 ||
        node->capability.profile_generation !=
            records->capability_profile_generation ||
        memcmp(node->capability.profile_digest, digest, sizeof(digest)) != 0) {
        set_error(error, error_len,
                  "node %u capability profile does not match evidence",
                  node->physical_node_id);
        return -1;
    }
    *backend_capabilities = 0;
    *runtime_capabilities = 0;
    if (mode_b_available) {
        *runtime_capabilities |= WVM_ADMISSION_RUNTIME_CAP_MODE_B_MEMORY;
    }
    if (mode_b_available && kvm_available) {
        *backend_capabilities |= WVM_ADMISSION_BACKEND_CAP_KVM;
    }
    if (mode_b_available && tcg_available) {
        *backend_capabilities |= WVM_ADMISSION_BACKEND_CAP_TCG;
    }
    return 0;
}

static void sorted_node_indices(const struct wvm_cluster_record_set *records,
                                size_t *indices)
{
    size_t i;

    for (i = 0; i < records->node_count; i++) {
        size_t cursor = i;
        size_t value = i;

        while (cursor != 0 &&
               records->nodes[indices[cursor - 1U]].physical_node_id >
                   records->nodes[value].physical_node_id) {
            indices[cursor] = indices[cursor - 1U];
            cursor--;
        }
        indices[cursor] = value;
    }
}

static int validate_gateway_graph(const struct wvm_cluster_record_set *records,
                                  char *error, size_t error_len)
{
    size_t *indegree = NULL;
    size_t *queue = NULL;
    size_t queue_head = 0;
    size_t queue_tail = 0;
    size_t processed = 0;
    size_t i;
    int ret = -1;

    if (records->gateway_count > SIZE_MAX / sizeof(*indegree)) {
        set_error(error, error_len, "gateway count would overflow allocation");
        return -1;
    }

    indegree = calloc(records->gateway_count, sizeof(*indegree));
    queue = calloc(records->gateway_count, sizeof(*queue));
    if (!indegree || !queue) {
        set_error(error, error_len, "failed to allocate gateway graph arrays");
        free(indegree);
        free(queue);
        return -1;
    }

    for (i = 0; i < records->gateway_count; i++) {
        const struct wvm_gateway_record *gateway = &records->gateways[i];
        const struct wvm_node_record *host;
        size_t j;

        if (wvm_gateway_record_validate(gateway, error, error_len) != 0 ||
            (find_gateway(records, gateway->gateway_id) != gateway)) {
            set_error(error, error_len, "gateway record set has duplicate ID");
            return -1;
        }
        host = find_node(records, gateway->hosting_physical_node_id);
        if (!host || gateway->failure_domain_id != host->failure_domain_id ||
            !u32_list_contains(host->inventory.hosted_gateway_role_ids,
                               host->inventory.hosted_gateway_role_id_count,
                               gateway->gateway_id)) {
            set_error(error, error_len, "gateway %u has invalid host relation",
                      gateway->gateway_id);
            return -1;
        }
        if (gateway->membership_revision != records->membership_revision ||
            gateway->topology_revision != records->topology_revision) {
            set_error(error, error_len, "gateway %u has stale revisions",
                      gateway->gateway_id);
            return -1;
        }
        for (j = 0; j < gateway->parent_gateway_id_count; j++) {
            const struct wvm_gateway_record *parent =
                find_gateway(records, gateway->parent_gateway_ids[j]);

            if (!parent || parent == gateway ||
                !u32_list_contains(parent->child_gateway_ids,
                                   parent->child_gateway_id_count,
                                   gateway->gateway_id)) {
                set_error(error, error_len,
                          "gateway %u has asymmetric parent relation",
                          gateway->gateway_id);
                return -1;
            }
        }
        for (j = 0; j < gateway->child_gateway_id_count; j++) {
            const struct wvm_gateway_record *child =
                find_gateway(records, gateway->child_gateway_ids[j]);

            if (!child || child == gateway ||
                !u32_list_contains(child->parent_gateway_ids,
                                   child->parent_gateway_id_count,
                                   gateway->gateway_id)) {
                set_error(error, error_len,
                          "gateway %u has asymmetric child relation",
                          gateway->gateway_id);
                return -1;
            }
        }
        indegree[i] = gateway->parent_gateway_id_count;
        if (indegree[i] == 0) {
            queue[queue_tail++] = i;
        }
    }
    while (queue_head != queue_tail) {
        const struct wvm_gateway_record *gateway =
            &records->gateways[queue[queue_head++]];
        size_t i;

        processed++;
        for (i = 0; i < gateway->child_gateway_id_count; i++) {
            const struct wvm_gateway_record *child =
                find_gateway(records, gateway->child_gateway_ids[i]);
            size_t child_index = (size_t)(child - records->gateways);

            if (--indegree[child_index] == 0) {
                queue[queue_tail++] = child_index;
            }
        }
    }
    if (processed != records->gateway_count) {
        set_error(error, error_len, "gateway topology contains a cycle");
        ret = -1;
        goto cleanup;
    }
    ret = 0;

cleanup:
    free(indegree);
    free(queue);
    return ret;
}

static int admission_node_index(const struct wvm_admission_snapshot *snapshot,
                                uint32_t node_id)
{
    uint32_t i;

    for (i = 0; i < snapshot->node_count; i++) {
        if (snapshot->nodes[i].physical_node_id == node_id) {
            return (int)i;
        }
    }
    return -1;
}

static int apply_reservation_occupancy(
    const struct wvm_cluster_record_set *records,
    struct wvm_cluster_snapshot *snapshot, char *error, size_t error_len)
{
    size_t i;

    if (records->resource_reservation_count != 0 &&
        !records->resource_reservations) {
        set_error(error, error_len, "cluster reservations are invalid");
        return -1;
    }
    for (i = 0; i < records->resource_reservation_count; i++) {
        const struct wvm_resource_reservation *reservation =
            &records->resource_reservations[i];
        int index;
        struct wvm_admission_node *node;
        uint64_t cpu;
        uint64_t memory;
        int prepared;

        if (wvm_resource_reservation_validate(reservation, error, error_len) !=
            0) {
            return -1;
        }
        if (reservation->state == WVM_RESERVATION_RELEASED) {
            continue;
        }
        index = admission_node_index(&snapshot->admission,
                                     reservation->physical_node_id);
        if (index < 0) {
            set_error(error, error_len,
                      "reservation references an unregistered node");
            return -1;
        }
        node = &snapshot->admission.nodes[index];
        if (reservation->node_instance_id != node->node_instance_id ||
            reservation->inventory_revision != node->inventory_revision) {
            set_error(error, error_len,
                      "reservation references a stale node instance or inventory");
            return -1;
        }
        cpu = (uint64_t)reservation->guest_vcpu_slots +
              reservation->overhead_vcpu_slots;
        memory = reservation->guest_memory_bytes +
                 reservation->overhead_memory_bytes;
        prepared = reservation->state == WVM_RESERVATION_PREPARED;
        if (cpu > UINT32_MAX ||
            (prepared &&
             (cpu > UINT32_MAX - node->prepared_vcpu_slots ||
              memory > UINT64_MAX - node->prepared_memory_bytes)) ||
            (!prepared &&
             (cpu > UINT32_MAX - node->committed_vcpu_slots ||
              memory > UINT64_MAX - node->committed_memory_bytes))) {
            set_error(error, error_len, "reservation occupancy overflows");
            return -1;
        }
        if (prepared) {
            node->prepared_vcpu_slots += (uint32_t)cpu;
            node->prepared_memory_bytes += memory;
        } else {
            node->committed_vcpu_slots += (uint32_t)cpu;
            node->committed_memory_bytes += memory;
        }
    }
    return 0;
}

int wvm_cluster_snapshot_build(
    const struct wvm_cluster_record_set *records,
    struct wvm_cluster_snapshot *snapshot, char *error, size_t error_len)
{
    struct wvm_cluster_snapshot built = {0};
    struct wvm_cluster_snapshot *output = snapshot;
    size_t *indices = NULL;
    size_t i;
    int ret = -1;

    if (!records || !snapshot || !records->nodes || records->node_count == 0 ||
        records->node_count > UINT32_MAX ||
        records->gateway_count > UINT32_MAX ||
        (records->gateway_count != 0 && !records->gateways) ||
        records->inventory_revision == 0 || records->membership_revision == 0 ||
        records->topology_revision == 0 ||
        records->admission_eligibility_revision == 0 ||
        records->capability_profile_generation == 0 ||
        capability_set_validate(records, error, error_len) != 0) {
        set_error(error, error_len, "cluster record set is invalid");
        return -1;
    }

    /* Keep failed validation and allocation local to this build. */
    snapshot = &built;
    indices = calloc(records->node_count, sizeof(*indices));
    if (!indices) {
        set_error(error, error_len, "failed to allocate index array");
        return -1;
    }
    for (i = 0; i < records->node_count; i++) {
        if (wvm_node_record_validate(&records->nodes[i], error, error_len) != 0 ||
            find_node(records, records->nodes[i].physical_node_id) !=
                &records->nodes[i] ||
            records->nodes[i].membership_revision !=
                records->membership_revision ||
            records->nodes[i].topology_revision != records->topology_revision) {
            set_error(error, error_len, "node record set is invalid");
            goto out;
        }
    }
    if (validate_gateway_graph(records, error, error_len) != 0) {
        goto out;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->admission.inventory_revision = records->inventory_revision;
    snapshot->admission.membership_revision = records->membership_revision;
    snapshot->admission.topology_revision = records->topology_revision;
    snapshot->admission.capability_profile_generation =
        records->capability_profile_generation;
    snapshot->admission.node_count = (uint32_t)records->node_count;
    snapshot->admission.node_capacity = (uint32_t)records->node_count;
    snapshot->admission.nodes = calloc(records->node_count,
                                       sizeof(*snapshot->admission.nodes));
    if (!snapshot->admission.nodes) {
        set_error(error, error_len, "failed to allocate admission node array");
        goto out;
    }
    sorted_node_indices(records, indices);
    for (i = 0; i < records->node_count; i++) {
        const struct wvm_node_record *node = &records->nodes[indices[i]];
        struct wvm_admission_node *admission_node =
            &snapshot->admission.nodes[i];
        uint32_t backend_capabilities;
        uint32_t runtime_capabilities;

        if (node_capability_profile(records, node, &backend_capabilities,
                                    &runtime_capabilities, error,
                                    error_len) != 0) {
            goto out;
        }
        admission_node->physical_node_id = node->physical_node_id;
        admission_node->node_instance_id = node->node_instance_id;
        admission_node->inventory_revision = node->inventory.inventory_revision;
        admission_node->membership_state =
            (enum wvm_admission_member_state)node->desired_membership_state;
        admission_node->health_state =
            (enum wvm_admission_health_state)node->observed_health_state;
        admission_node->backend_capabilities = backend_capabilities;
        admission_node->runtime_capabilities = runtime_capabilities;
        admission_node->registered_vcpu_slots =
            node->inventory.registered_vcpu_slots;
        admission_node->registered_memory_bytes =
            node->inventory.registered_memory_bytes;
        admission_node->reserved_host_vcpu_slots =
            node->inventory.reserved_host_cpu_slots;
        admission_node->reserved_host_memory_bytes =
            node->inventory.reserved_host_memory_bytes;
        admission_node->reserved_gateway_vcpu_slots =
            node->inventory.reserved_gateway_cpu_slots;
        admission_node->reserved_gateway_memory_bytes =
            node->inventory.reserved_gateway_memory_bytes;
        admission_node->allocatable_vcpu_slots =
            node->inventory.allocatable_vcpu_slots;
        admission_node->allocatable_memory_bytes =
            node->inventory.allocatable_memory_bytes;
    }
    if (apply_reservation_occupancy(records, snapshot, error, error_len) != 0 ||
        wvm_admission_snapshot_validate(&snapshot->admission, error,
                                        error_len) != 0) {
        goto out;
    }
    for (i = 0; i < records->gateway_count; i++) {
        if (records->gateways[i].desired_membership_state ==
                WVM_MANIFEST_MEMBER_ACTIVE &&
            records->gateways[i].observed_health_state == 1) {
            snapshot->active_gateway_count++;
        }
    }
    ret = 0;

out:
    free(indices);
    if (ret == 0) {
        *output = built;
    } else {
        wvm_admission_snapshot_cleanup(&built.admission);
    }
    return ret;
}

static int parse_decimal_u64(const char *text, uint64_t *value_out)
{
    uint64_t value = 0;
    size_t i;

    if (!text || !*text || !value_out) {
        return -1;
    }
    for (i = 0; text[i] != '\0'; i++) {
        uint8_t digit;

        if (text[i] < '0' || text[i] > '9') {
            return -1;
        }
        digit = (uint8_t)(text[i] - '0');
        if (value > (UINT64_MAX - digit) / 10U) {
            return -1;
        }
        value = value * 10U + digit;
    }
    *value_out = value;
    return 0;
}

static int node_has_available_capability(
    const struct wvm_cluster_record_set *records,
    const struct wvm_admission_node *admission_node, uint16_t capability_id)
{
    size_t i;

    for (i = 0; i < records->capability_record_count; i++) {
        const struct wvm_capability_record *capability =
            &records->capability_records[i];

        if (capability->physical_node_id ==
                admission_node->physical_node_id &&
            capability->node_instance_id == admission_node->node_instance_id &&
            capability->capability_id == capability_id &&
            capability->state == WVM_CAPABILITY_AVAILABLE) {
            return 1;
        }
    }
    return 0;
}

static int node_matches_constraint(
    const struct wvm_cluster_record_set *records,
    const struct wvm_admission_node *admission_node,
    const struct wvm_host_constraint *constraint, char *error,
    size_t error_len)
{
    const struct wvm_node_record *node;
    uint64_t expected;
    int matches;

    if (wvm_host_constraint_validate(constraint, error, error_len) != 0 ||
        !(node = find_node(records, admission_node->physical_node_id))) {
        return -1;
    }
    if (constraint->constraint_kind == WVM_MANIFEST_HOST_CONSTRAINT_LABEL) {
        set_error(error, error_len,
                  "LABEL constraints require canonical NodeMetadata records");
        return -1;
    }
    if (strcmp(constraint->subject, "id") != 0 ||
        parse_decimal_u64(constraint->value, &expected) != 0) {
        set_error(error, error_len,
                  "host constraint requires subject=id and decimal value");
        return -1;
    }
    if (constraint->constraint_kind ==
        WVM_MANIFEST_HOST_CONSTRAINT_PHYSICAL_NODE) {
        matches = expected == admission_node->physical_node_id;
    } else if (constraint->constraint_kind ==
               WVM_MANIFEST_HOST_CONSTRAINT_FAILURE_DOMAIN) {
        matches = expected == node->failure_domain_id;
    } else if (constraint->constraint_kind ==
               WVM_MANIFEST_HOST_CONSTRAINT_CAPABILITY) {
        if (expected == 0 || expected > UINT16_MAX) {
            set_error(error, error_len, "capability constraint ID is invalid");
            return -1;
        }
        matches = node_has_available_capability(
            records, admission_node, (uint16_t)expected);
    } else {
        return -1;
    }
    return constraint->comparison_operator ==
                   WVM_MANIFEST_HOST_CONSTRAINT_EQUALS
               ? matches
               : !matches;
}

int wvm_cluster_snapshot_apply_host_constraints(
    const struct wvm_cluster_record_set *records,
    const struct wvm_cluster_snapshot *snapshot,
    const struct wvm_host_constraint_list *constraints,
    struct wvm_cluster_snapshot *constrained_snapshot, char *error,
    size_t error_len)
{
    struct wvm_cluster_snapshot filtered = {0};
    struct wvm_cluster_snapshot *output = constrained_snapshot;
    uint32_t i;

    if (!records || !snapshot || !constraints || !constrained_snapshot ||
        snapshot == constrained_snapshot ||
        wvm_admission_snapshot_validate(&snapshot->admission, error,
                                        error_len) != 0 ||
        (constraints->count != 0 && !constraints->entries) ||
        constraints->count > constraints->capacity) {
        set_error(error, error_len, "host constraint snapshot input is invalid");
        return -1;
    }

    constrained_snapshot = &filtered;
    constrained_snapshot->active_gateway_count = snapshot->active_gateway_count;
    if (wvm_admission_snapshot_copy(&snapshot->admission,
                                    &constrained_snapshot->admission) != 0) {
        set_error(error, error_len, "failed to allocate constrained snapshot");
        return -1;
    }

    for (i = 0; i < constrained_snapshot->admission.node_count; i++) {
        struct wvm_admission_node *node =
            &constrained_snapshot->admission.nodes[i];
        size_t j;

        for (j = 0; j < constraints->count; j++) {
            int matches = node_matches_constraint(records, node,
                                                  &constraints->entries[j],
                                                  error, error_len);

            if (matches < 0) {
                wvm_admission_snapshot_cleanup(&constrained_snapshot->admission);
                return -1;
            }
            if (!matches) {
                node->membership_state = WVM_ADMISSION_MEMBER_CORDONED;
                break;
            }
        }
    }

    if (wvm_admission_snapshot_validate(&constrained_snapshot->admission,
                                        error, error_len) != 0) {
        wvm_admission_snapshot_cleanup(&constrained_snapshot->admission);
        return -1;
    }
    *output = filtered;
    return 0;
}

static int required_member_add(
    struct wvm_required_member_list *members,
    const struct wvm_required_member *member, char *error, size_t error_len)
{
    size_t insert_at;
    size_t i;

    if (!members || !member || !members->entries ||
        members->count >= members->capacity ||
        wvm_required_member_validate(member, error, error_len) != 0) {
        set_error(error, error_len, "cannot add required member");
        return -1;
    }
    for (insert_at = 0; insert_at < members->count; insert_at++) {
        int comparison = member_key_compare(
            &members->entries[insert_at].member_key, &member->member_key);

        if (comparison == 0) {
            if (memcmp(&members->entries[insert_at], member, sizeof(*member)) !=
                0) {
                set_error(error, error_len,
                          "conflicting required member identity");
                return -1;
            }
            return 0;
        }
        if (comparison > 0) {
            break;
        }
    }
    for (i = members->count; i > insert_at; i--) {
        members->entries[i] = members->entries[i - 1U];
    }
    members->entries[insert_at] = *member;
    members->count++;
    return 0;
}

static int make_node_required_member(
    const struct wvm_node_record *node, struct wvm_required_member *member)
{
    memset(member, 0, sizeof(*member));
    member->member_key.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    member->member_key.role_id = node->physical_node_id;
    member->member_key.instance_id = node->node_instance_id;
    member->physical_node_id = node->physical_node_id;
    member->failure_domain_id = node->failure_domain_id;
    member->capability = node->capability;
    member->required_state = WVM_MANIFEST_MEMBER_ACTIVE;
    return 0;
}

static int make_gateway_required_member(
    const struct wvm_cluster_record_set *records,
    const struct wvm_gateway_record *gateway,
    struct wvm_required_member *member)
{
    const struct wvm_node_record *host =
        find_node(records, gateway->hosting_physical_node_id);

    if (!host) {
        return -1;
    }
    memset(member, 0, sizeof(*member));
    member->member_key.role_type = WVM_MANIFEST_ROLE_GATEWAY;
    member->member_key.role_id = gateway->gateway_id;
    member->member_key.instance_id = gateway->gateway_instance_id;
    member->physical_node_id = gateway->hosting_physical_node_id;
    member->failure_domain_id = gateway->failure_domain_id;
    member->capability = host->capability;
    member->required_state = WVM_MANIFEST_MEMBER_ACTIVE;
    return 0;
}

static int add_route_ack_members(
    const struct wvm_cluster_record_set *records,
    const struct wvm_cluster_snapshot *snapshot,
    const struct wvm_vm_route_scope_key *route_scope_key,
    const struct wvm_required_ack_set *required_ack_set,
    struct wvm_required_member_list *selected_members, char *error,
    size_t error_len)
{
    size_t i;

    for (i = 0; i < required_ack_set->entries.count; i++) {
        const struct wvm_required_ack_entry *entry =
            &required_ack_set->entries.entries[i];
        struct wvm_required_member member;

        if (entry->role_type != entry->member_key.role_type ||
            entry->expected_snapshot_key.scope_key.vm_id !=
                route_scope_key->vm_id ||
            entry->expected_snapshot_key.scope_key.vm_incarnation !=
                route_scope_key->vm_incarnation ||
            entry->expected_snapshot_key.scope_key.route_scope_id !=
                route_scope_key->route_scope_id ||
            entry->expected_snapshot_key.topology_revision !=
                snapshot->admission.topology_revision) {
            set_error(error, error_len, "route ACK entry has wrong scope");
            return -1;
        }
        if (entry->member_key.role_type == WVM_MANIFEST_ROLE_NODE_RUNTIME) {
            const struct wvm_node_record *node =
                find_node(records, entry->member_key.role_id);

            if (!node || entry->member_key.instance_id != node->node_instance_id ||
                !endpoint_equal(&entry->endpoint, &node->control_endpoint) ||
                node->desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE ||
                node->observed_health_state != 1) {
                set_error(error, error_len, "route ACK names invalid node member");
                return -1;
            }
            make_node_required_member(node, &member);
        } else if (entry->member_key.role_type == WVM_MANIFEST_ROLE_GATEWAY) {
            const struct wvm_gateway_record *gateway =
                find_gateway(records, entry->member_key.role_id);

            if (!gateway ||
                entry->member_key.instance_id != gateway->gateway_instance_id ||
                !endpoint_equal(&entry->endpoint, &gateway->endpoint) ||
                gateway->desired_membership_state !=
                    WVM_MANIFEST_MEMBER_ACTIVE ||
                gateway->observed_health_state != 1 ||
                make_gateway_required_member(records, gateway, &member) != 0) {
                set_error(error, error_len,
                          "route ACK names invalid gateway member");
                return -1;
            }
        } else {
            set_error(error, error_len,
                      "route ACK has unsupported member role");
            return -1;
        }
        if (required_member_add(selected_members, &member, error, error_len) !=
            0) {
            return -1;
        }
    }
    return 0;
}

int wvm_cluster_admission_fence_build(
    const struct wvm_cluster_record_set *records,
    const struct wvm_cluster_snapshot *snapshot,
    const struct wvm_admission_request *request,
    const struct wvm_admission_plan *plan,
    const struct wvm_vm_route_scope_key *route_scope_key,
    const struct wvm_required_ack_set *required_ack_set,
    struct wvm_admission_eligibility_fence *fence, char *error,
    size_t error_len)
{
    struct wvm_required_member_list selected_members;
    uint8_t *fence_bytes;
    size_t fence_capacity;
    size_t fence_bytes_used;
    size_t i;

    if (!records || !snapshot || !request || !plan || !route_scope_key ||
        !required_ack_set || !fence ||
        wvm_admission_snapshot_validate(&snapshot->admission, error,
                                        error_len) != 0 ||
        wvm_admission_plan_validate(&snapshot->admission, request, plan, error,
                                    error_len) != 0 ||
        wvm_vm_route_scope_key_validate(route_scope_key, error, error_len) !=
            0 ||
        route_scope_key->vm_id != request->vm_id ||
        route_scope_key->vm_incarnation != request->vm_incarnation ||
        wvm_required_ack_set_validate(required_ack_set, error, error_len) != 0 ||
        !fence->selected_members.entries || fence->selected_members.capacity == 0) {
        set_error(error, error_len, "cannot build admission fence");
        return -1;
    }
    selected_members = fence->selected_members;
    selected_members.count = 0;
    for (i = 0; i < plan->reservation_count; i++) {
        const struct wvm_node_record *node =
            find_node(records, plan->reservations[i].physical_node_id);
        struct wvm_required_member member;

        if (!node ||
            node->desired_membership_state != WVM_MANIFEST_MEMBER_ACTIVE ||
            node->observed_health_state != 1) {
            set_error(error, error_len,
                      "placement uses unavailable node member");
            return -1;
        }
        make_node_required_member(node, &member);
        if (required_member_add(&selected_members, &member, error, error_len) !=
            0) {
            return -1;
        }
    }
    if (add_route_ack_members(records, snapshot, route_scope_key,
                              required_ack_set, &selected_members, error,
                              error_len) != 0) {
        return -1;
    }
    if (selected_members.count >
        (SIZE_MAX - 1024U) / 256U) {
        set_error(error, error_len, "admission fence is too large");
        return -1;
    }
    fence_capacity = 1024U + selected_members.count * 256U;
    fence_bytes = malloc(fence_capacity);
    if (!fence_bytes) {
        set_error(error, error_len, "cannot allocate admission fence");
        return -1;
    }
    memset(fence, 0, sizeof(*fence));
    fence->selected_members = selected_members;
    memcpy(fence->admission_tx_id, plan->admission_tx_id,
           sizeof(fence->admission_tx_id));
    fence->membership_revision = snapshot->admission.membership_revision;
    fence->topology_revision = snapshot->admission.topology_revision;
    fence->admission_eligibility_revision =
        records->admission_eligibility_revision;
    fence->inventory_revision = snapshot->admission.inventory_revision;
    fence->capability_profile_generation =
        snapshot->admission.capability_profile_generation;
    fence->required_route_scope_key = *route_scope_key;
    memcpy(fence->required_ack_set_digest, required_ack_set->entries_digest,
           sizeof(fence->required_ack_set_digest));
    if (wvm_admission_eligibility_fence_encode(
            fence, fence_bytes, fence_capacity, &fence_bytes_used,
            fence->fence_digest, error, error_len) != 0) {
        free(fence_bytes);
        return -1;
    }
    free(fence_bytes);
    return wvm_admission_eligibility_fence_validate(fence, error, error_len);
}

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "wavevm_membership.h"
#include "memory_service.h"
#include "directory_store.h"

struct test_state {
    pthread_mutex_t lock;
    pthread_cond_t sent_ready;
    int read_count;
    int commit_count;
    int commit_result;
    uint64_t commit_result_version;
    uint64_t committed_gpa;
    uint64_t committed_base_version;
    uint16_t committed_offset;
    size_t committed_data_bytes;
    uint8_t committed_data[WVM_MEMORY_PAGE_BYTES];
    struct wvm_directory_store *directory_store;
    int commit_completion_count;
    int commit_complete_through_global;
    uint64_t completed_commit_gpa;
    uint64_t completed_commit_version;
    uint16_t completed_commit_status;
    uint32_t completed_commit_directory;
    uint64_t completed_commit_instance;
    int completion_count;
    int send_count;
    int complete_through_global;
    uint64_t completed_gpa;
    uint64_t completed_version;
    uint16_t completed_status;
    uint8_t completed_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_envelope sent[12];
    uint8_t sent_payload[12][WVM_MEM_ACK_HEADER_BYTES +
                             WVM_MEMORY_PAGE_BYTES];
    size_t sent_payload_bytes[12];
};

struct global_fault_thread {
    uint64_t gpa;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    int result;
    struct wvm_mem_ack ack;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    atomic_int completed;
};

struct global_commit_thread {
    uint64_t gpa;
    uint64_t base_version;
    uint16_t offset;
    const uint8_t *data;
    size_t data_bytes;
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    int result;
    struct wvm_mem_commit_ack ack;
    atomic_int completed;
};

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "memory-service test: %s\n", message);
        return -1;
    }
    return 0;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = (uint16_t)(port + 1000U);
}

static void fill_rule(struct wvm_route_rule_record *rule, uint64_t scope,
                      uint32_t vnode, uint32_t physical_node_id,
                      uint64_t node_instance_id, uint8_t address_tail)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE;
    rule->destination_scope = scope;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = physical_node_id;
    rule->next_hop_member.instance_id = node_instance_id;
    fill_endpoint(&rule->next_hop_endpoint, address_tail,
                  (uint16_t)(19000U + address_tail));
    rule->hop_limit = 4;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record rules[2],
                             struct wvm_required_ack_entry acks[1],
                             char *error, size_t error_len)
{
    uint8_t bytes[4096];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded_bytes;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->route_snapshot_key.scope_key.vm_id = 256;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = 7;
    snapshot->route_snapshot_key.scope_key.route_scope_id = 33;
    snapshot->route_snapshot_key.topology_revision = 11;
    snapshot->route_snapshot_key.route_generation = 4;
    snapshot->membership_revision = 3;
    snapshot->topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = 2;
    snapshot->next_hop_rules.capacity = 2;
    snapshot->required_ack_set.entries.entries = acks;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;
    memset(acks, 0, sizeof(*acks));
    acks[0].member_key = rules[0].next_hop_member;
    acks[0].endpoint = rules[0].next_hop_endpoint;
    acks[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    acks[0].expected_snapshot_key = snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded_bytes, digest, error,
                                         error_len) != 0) {
        return -1;
    }
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    memcpy(acks[0].expected_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int read_page(void *opaque, uint64_t gpa,
                     uint8_t data[WVM_MEMORY_PAGE_BYTES],
                     uint64_t *version_out, char *error, size_t error_len)
{
    struct test_state *state = opaque;

    (void)error;
    (void)error_len;
    if (!state || gpa != 0 || !version_out) {
        return -ENOENT;
    }
    memset(data, 0xa5, WVM_MEMORY_PAGE_BYTES);
    *version_out = 7;
    state->read_count++;
    return 0;
}

static int complete_fault(
    void *opaque, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t gpa, uint64_t version, uint16_t status,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    const uint8_t *data, size_t data_bytes, char *error, size_t error_len)
{
    struct test_state *state = opaque;

    (void)operation_id;
    (void)directory_physical_node_id;
    (void)directory_node_instance_id;
    (void)error;
    (void)error_len;
    if (!state ||
        (status == WVM_MEM_ACK_SUCCESS &&
         (!data || data_bytes != WVM_MEMORY_PAGE_BYTES))) {
        return -EINVAL;
    }
    state->completion_count++;
    state->completed_gpa = gpa;
    state->completed_version = version;
    state->completed_status = status;
    if (data_bytes != 0) {
        memcpy(state->completed_page, data, data_bytes);
    }
    if (state->complete_through_global) {
        return wvm_memory_service_global_complete(
            operation_id, gpa, version, status, directory_physical_node_id,
            directory_node_instance_id, data, data_bytes, error, error_len);
    }
    return 0;
}

static int commit_page(void *opaque, uint64_t gpa, uint64_t base_version,
                       uint16_t offset, const uint8_t *data,
                       size_t data_bytes, uint64_t *result_version,
                       char *error, size_t error_len)
{
    struct test_state *state = opaque;

    (void)error;
    (void)error_len;
    if (!state || !data || !result_version ||
        data_bytes > sizeof(state->committed_data)) {
        return -EINVAL;
    }
    state->commit_count++;
    state->committed_gpa = gpa;
    state->committed_base_version = base_version;
    state->committed_offset = offset;
    state->committed_data_bytes = data_bytes;
    memcpy(state->committed_data, data, data_bytes);
    if (state->directory_store) {
        return wvm_directory_store_commit_page(
            state->directory_store, gpa, base_version, offset, data,
            data_bytes, result_version, error, error_len);
    }
    if (state->commit_result == 0) {
        *result_version = state->commit_result_version;
    }
    return state->commit_result;
}

static int complete_commit(
    void *opaque, const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    uint64_t gpa, uint16_t status, uint64_t result_version,
    uint32_t directory_physical_node_id, uint64_t directory_node_instance_id,
    char *error, size_t error_len)
{
    struct test_state *state = opaque;

    (void)error;
    if (!state) {
        return -EINVAL;
    }
    state->commit_completion_count++;
    state->completed_commit_gpa = gpa;
    state->completed_commit_status = status;
    state->completed_commit_version = result_version;
    state->completed_commit_directory = directory_physical_node_id;
    state->completed_commit_instance = directory_node_instance_id;
    if (state->commit_complete_through_global) {
        return wvm_memory_service_global_complete_commit(
            operation_id, gpa, status, result_version,
            directory_physical_node_id, directory_node_instance_id, error,
            error_len);
    }
    return 0;
}

static int send_envelope(void *opaque, const struct wvm_envelope *envelope,
                         char *error, size_t error_len)
{
    struct test_state *state = opaque;
    size_t index;

    (void)error;
    (void)error_len;
    if (!state || !envelope ||
        envelope->payload_bytes > sizeof(state->sent_payload[0])) {
        return -EAGAIN;
    }
    pthread_mutex_lock(&state->lock);
    if (state->send_count >= 12) {
        pthread_mutex_unlock(&state->lock);
        return -EAGAIN;
    }
    index = (size_t)state->send_count++;
    state->sent[index] = *envelope;
    state->sent_payload_bytes[index] = envelope->payload_bytes;
    memcpy(state->sent_payload[index], envelope->payload,
           envelope->payload_bytes);
    state->sent[index].payload = state->sent_payload[index];
    pthread_cond_broadcast(&state->sent_ready);
    pthread_mutex_unlock(&state->lock);
    return 0;
}

static int wait_for_sends(struct test_state *state, int expected_count)
{
    struct timespec deadline;
    int result = 0;

    if (!state || clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += 2;
    pthread_mutex_lock(&state->lock);
    while (state->send_count < expected_count && result == 0) {
        result = pthread_cond_timedwait(&state->sent_ready, &state->lock,
                                        &deadline);
    }
    pthread_mutex_unlock(&state->lock);
    return result == 0 ? 0 : -1;
}

static int dispatch_remote_ack(struct wvm_memory_service *service,
                               const struct wvm_envelope *request,
                               const uint8_t page[WVM_MEMORY_PAGE_BYTES],
                               char *error, size_t error_len)
{
    struct wvm_mem_ack ack;
    struct wvm_envelope_route reply_route;
    struct wvm_envelope response;
    uint8_t payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    size_t payload_bytes = 0;

    if (!service || !request || !page) {
        return -1;
    }
    memset(&ack, 0, sizeof(ack));
    ack.gpa = WVM_MEMORY_PAGE_BYTES;
    ack.version = 12;
    ack.status = WVM_MEM_ACK_SUCCESS;
    ack.directory_physical_node_id = 99;
    ack.directory_node_instance_id = 202;
    ack.data = page;
    ack.data_bytes = WVM_MEMORY_PAGE_BYTES;
    memset(&reply_route, 0, sizeof(reply_route));
    reply_route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    reply_route.destination_scope = 41;
    reply_route.destination_vnode_or_endpoint = 0;
    reply_route.hop_limit = 4;
    return wvm_mem_ack_envelope_build(
               request, &reply_route, request->delivery_attempt_id + 1U,
               &ack, payload, sizeof(payload), &payload_bytes, &response,
               error, error_len) == 0
               ? wvm_memory_service_dispatch(service, &response, error,
                                                error_len)
               : -1;
}

static void *run_global_fault(void *opaque)
{
    struct global_fault_thread *thread = opaque;
    char error[256] = {0};

    thread->result = wvm_memory_service_global_request_fault(
        thread->gpa, thread->operation_id, 1, &thread->ack, thread->page,
        error, sizeof(error));
    atomic_store_explicit(&thread->completed, 1, memory_order_release);
    return NULL;
}

static void *run_global_commit(void *opaque)
{
    struct global_commit_thread *thread = opaque;
    char error[256] = {0};

    thread->result = wvm_memory_service_global_request_commit(
        thread->gpa, thread->base_version, thread->offset, thread->data,
        thread->data_bytes, thread->operation_id, 1, &thread->ack, error,
        sizeof(error));
    atomic_store_explicit(&thread->completed, 1, memory_order_release);
    return NULL;
}

static void fill_projection(
    struct wvm_runtime_dispatch_projection *projection,
    struct wvm_runtime_memory_dispatch memory[2],
    const struct wvm_route_snapshot_key *route_key)
{
    memset(projection, 0, sizeof(*projection));
    memset(projection->candidate_manifest_digest, 0x51,
           sizeof(projection->candidate_manifest_digest));
    projection->vm_id = 256;
    projection->vm_incarnation = 7;
    projection->manifest_generation = 3;
    projection->physical_node_id = 17;
    projection->expected_node_instance_id = 101;
    memset(projection->activation_fence, 0x52,
           sizeof(projection->activation_fence));
    projection->required_route_snapshot_key = *route_key;
    projection->route_topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    projection->local_primary.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    projection->local_primary.destination_scope = 41;
    projection->local_primary.destination_vnode = 0;
    fill_endpoint(&projection->local_sidecar_endpoint, 17, 19017);
    projection->memory_dispatch.entries = memory;
    projection->memory_dispatch.count = 2;
    projection->memory_dispatch.capacity = 2;
    memset(memory, 0, 2 * sizeof(*memory));
    memory[0].gpa_start = 0;
    memory[0].bytes = WVM_MEMORY_PAGE_BYTES;
    memory[0].directory = projection->local_primary;
    memory[0].executor = projection->local_primary;
    memory[0].directory_physical_node_id = 17;
    memory[0].directory_node_instance_id = 101;
    memory[0].consistency_policy = 1;
    memory[1] = memory[0];
    memory[1].gpa_start = WVM_MEMORY_PAGE_BYTES;
    memory[1].directory.destination_scope = 99;
    memory[1].directory.destination_vnode = 1;
    memory[1].executor = memory[1].directory;
    memory[1].directory_physical_node_id = 99;
    memory[1].directory_node_instance_id = 202;
}

static void fill_remote_read_request(
    const struct wvm_runtime_dispatch_projection *projection,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_envelope *request)
{
    memset(request, 0, sizeof(*request));
    request->message_type = WVM_ENVELOPE_MSG_MEM_READ;
    request->vm_id = projection->vm_id;
    request->vm_incarnation = projection->vm_incarnation;
    request->manifest_generation = projection->manifest_generation;
    request->origin_physical_node_id = 99;
    request->origin_runtime_instance_id = 2020;
    memcpy(request->operation_id, operation_id, WVM_IDENTITY_ID_BYTES);
    request->delivery_attempt_id = 1;
    request->route_scope_id =
        projection->required_route_snapshot_key.scope_key.route_scope_id;
    request->topology_revision =
        projection->required_route_snapshot_key.topology_revision;
    request->route_generation =
        projection->required_route_snapshot_key.route_generation;
    memcpy(request->route_snapshot_digest,
           projection->required_route_snapshot_key.snapshot_digest,
           sizeof(request->route_snapshot_digest));
    request->route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    request->route.destination_scope = 41;
    request->route.destination_vnode_or_endpoint = 0;
    request->route.hop_limit = 4;
    request->payload = payload;
    request->payload_bytes = payload_bytes;
}

static void fill_remote_commit_request(
    const struct wvm_runtime_dispatch_projection *projection,
    const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
    const uint8_t *payload, size_t payload_bytes,
    struct wvm_envelope *request)
{
    fill_remote_read_request(projection, operation_id, payload, payload_bytes,
                             request);
    request->message_type = WVM_ENVELOPE_MSG_COMMIT_DIFF;
}

int main(void)
{
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[1];
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_runtime routes;
    struct wvm_runtime_memory_dispatch memory[2];
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_memory_service_config config;
    struct wvm_memory_service service;
    struct test_state state;
    struct wvm_mem_read read;
    struct wvm_mem_ack ack;
    struct wvm_envelope_route reply_route;
    struct wvm_envelope response;
    struct wvm_envelope inbound;
    uint8_t operation_one[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_two[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_three[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_four[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_five[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_six[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_seven[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_eight[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_nine[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_ten[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_eleven[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_twelve[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_thirteen[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t operation_fourteen[WVM_IDENTITY_ID_BYTES] = {0};
    uint8_t read_payload[WVM_MEM_READ_PAYLOAD_BYTES];
    uint8_t ack_payload[WVM_MEM_ACK_HEADER_BYTES +
                        WVM_MEMORY_PAGE_BYTES];
    uint8_t commit_payload[WVM_MEM_COMMIT_HEADER_BYTES + 16U];
    uint8_t commit_data[3] = {0x81, 0x82, 0x83};
    uint8_t conflicting_commit_data[3] = {0x91, 0x92, 0x93};
    uint8_t commit_ack_payload[WVM_MEM_COMMIT_ACK_BYTES];
    uint8_t remote_page[WVM_MEMORY_PAGE_BYTES];
    uint8_t local_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_mem_commit commit;
    struct wvm_mem_commit_ack commit_ack;
    struct wvm_envelope outgoing_commit_ack;
    struct wvm_directory_store directory_store;
    struct wvm_directory_store_config directory_store_config = {
        .initial_epoch = 4,
        .max_page_records = 2,
    };
    struct global_fault_thread remote_fault_one;
    struct global_fault_thread remote_fault_two;
    pthread_t remote_thread_one;
    pthread_t remote_thread_two;
    size_t ack_payload_bytes;
    size_t commit_payload_bytes;
    char error[256] = {0};

    operation_one[15] = 1;
    operation_two[15] = 2;
    operation_three[15] = 3;
    operation_four[15] = 4;
    operation_five[15] = 5;
    operation_six[15] = 6;
    operation_seven[15] = 7;
    operation_eight[15] = 8;
    operation_nine[15] = 9;
    operation_ten[15] = 10;
    operation_eleven[15] = 11;
    operation_twelve[15] = 12;
    operation_thirteen[15] = 13;
    operation_fourteen[15] = 14;
    memset(remote_page, 0x3c, sizeof(remote_page));
    fill_rule(&rules[0], 41, 0, 17, 101, 17);
    fill_rule(&rules[1], 99, 1, 99, 202, 99);
    if (finalize_snapshot(&snapshot, rules, acks, error, sizeof(error)) != 0) {
        fprintf(stderr, "memory-service setup: %s\n", error);
        return 1;
    }
    fill_projection(&projection, memory, &snapshot.route_snapshot_key);
    if (expect(wvm_runtime_dispatch_projection_validate(
                   &projection, error, sizeof(error)) == 0,
               "build admitted dispatch projection")) {
        return 1;
    }
    wvm_route_runtime_init(&routes);
    if (expect(wvm_route_runtime_prepare(&routes, &snapshot, error,
                                         sizeof(error)) == 0 &&
                   wvm_route_runtime_activate(
                       &routes, &snapshot.route_snapshot_key, error,
                       sizeof(error)) == 0,
               "activate admitted route runtime")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&state, 0, sizeof(state));
    if (pthread_mutex_init(&state.lock, NULL) != 0 ||
        pthread_cond_init(&state.sent_ready, NULL) != 0) {
        fprintf(stderr, "memory-service setup: cannot initialize test lock\n");
        return 1;
    }
    memset(&config, 0, sizeof(config));
    config.dispatch = &projection;
    config.route_runtime = &routes;
    config.local_physical_node_id = 17;
    config.local_node_instance_id = 101;
    config.local_runtime_instance_id = 1001;
    config.completion_timeout_ms = 5000;
    config.read_page = read_page;
    config.commit_page = commit_page;
    config.complete_commit = complete_commit;
    config.complete_fault = complete_fault;
    config.send_envelope = send_envelope;
    config.opaque = &state;
    if (expect(wvm_memory_service_init(&service, &config, error,
                                          sizeof(error)) == 0,
               "initialize admitted V1 memory service")) {
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_memory_service_request_fault(
                   &service, WVM_MEMORY_PAGE_BYTES, operation_one, 1,
                   error, sizeof(error)) == 0 &&
                   state.send_count == 1 &&
                   state.sent[0].message_type ==
                       WVM_ENVELOPE_MSG_MEM_READ &&
                   state.sent[0].route.destination_scope == 99 &&
                   state.sent[0].route.destination_vnode_or_endpoint == 1 &&
                   state.sent[0].route.hop_limit == 4 &&
                   wvm_mem_read_decode(
                       state.sent[0].payload, state.sent_payload_bytes[0],
                       &read, error, sizeof(error)) == 0 &&
                   read.gpa == WVM_MEMORY_PAGE_BYTES &&
                   read.reply_destination_scope == 41 &&
                   read.reply_destination_vnode == 0,
               "send remote fault only through a resolved sidecar route")) {
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&ack, 0, sizeof(ack));
    ack.gpa = WVM_MEMORY_PAGE_BYTES;
    ack.version = 9;
    ack.status = WVM_MEM_ACK_SUCCESS;
    ack.directory_physical_node_id = 98;
    ack.directory_node_instance_id = 202;
    ack.data = remote_page;
    ack.data_bytes = sizeof(remote_page);
    memset(&reply_route, 0, sizeof(reply_route));
    reply_route.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    reply_route.destination_scope = 41;
    reply_route.destination_vnode_or_endpoint = 0;
    reply_route.hop_limit = 4;
    if (expect(wvm_mem_ack_envelope_build(
                   &state.sent[0], &reply_route, 2, &ack, ack_payload,
                   sizeof(ack_payload), &ack_payload_bytes, &response, error,
                   sizeof(error)) == 0 &&
                   wvm_memory_service_dispatch(&service, &response, error,
                                                  sizeof(error)) == -EPERM &&
                   state.completion_count == 0,
               "reject ACK from the wrong directory authority")) {
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    ack.directory_physical_node_id = 99;
    if (expect(wvm_mem_ack_envelope_build(
                   &state.sent[0], &reply_route, 2, &ack, ack_payload,
                   sizeof(ack_payload), &ack_payload_bytes, &response, error,
                   sizeof(error)) == 0 &&
                   wvm_memory_service_dispatch(&service, &response, error,
                                                  sizeof(error)) == 0 &&
                   state.completion_count == 1 &&
                   state.completed_gpa == WVM_MEMORY_PAGE_BYTES &&
                   state.completed_version == 9 &&
                   state.completed_status == WVM_MEM_ACK_SUCCESS &&
                   memcmp(state.completed_page, remote_page,
                          sizeof(remote_page)) == 0 &&
                   wvm_memory_service_dispatch(&service, &response, error,
                                                  sizeof(error)) == 0 &&
                   state.completion_count == 1,
               "complete and deduplicate the remote memory ACK")) {
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&read, 0, sizeof(read));
    read.gpa = 0;
    read.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    read.reply_destination_scope = 99;
    read.reply_destination_vnode = 1;
    if (expect(wvm_mem_read_encode(&read, read_payload, error,
                                      sizeof(error)) == 0,
               "encode remote read to local directory")) {
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    fill_remote_read_request(&projection, operation_two, read_payload,
                             sizeof(read_payload), &inbound);
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == 0 &&
                   state.read_count == 1 && state.send_count == 2 &&
                   state.sent[1].message_type ==
                       WVM_ENVELOPE_MSG_MEM_ACK &&
                   state.sent[1].route.destination_scope == 99 &&
                   state.sent[1].route.destination_vnode_or_endpoint == 1 &&
                   wvm_mem_ack_decode(
                       state.sent[1].payload, state.sent_payload_bytes[1],
                       &ack, error, sizeof(error)) == 0 &&
                   ack.directory_physical_node_id == 17 &&
                   ack.directory_node_instance_id == 101 &&
                   ack.version == 7 &&
                   ack.data_bytes == WVM_MEMORY_PAGE_BYTES &&
                   state.sent[1].origin_physical_node_id == 99 &&
                   state.sent[1].origin_runtime_instance_id == 2020,
               "serve a remote read through local directory and reply route")) {
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_memory_service_request_fault(
                   &service, 0, operation_three, 1, error,
                   sizeof(error)) == 0 &&
                   state.read_count == 2 && state.completion_count == 2 &&
                   state.completed_gpa == 0 && state.completed_version == 7 &&
                   state.send_count == 2,
               "complete a local directory fault without fabric traffic")) {
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_memory_service_global_install(
                   &service, error, sizeof(error)) == 0,
               "install the admitted service at the local QEMU boundary")) {
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    state.complete_through_global = 1;
    memset(&ack, 0, sizeof(ack));
    memset(local_page, 0, sizeof(local_page));
    if (expect(wvm_memory_service_global_request_fault(
                   0, operation_four, 1, &ack, local_page, error,
                   sizeof(error)) == 0 &&
                   ack.gpa == 0 && ack.status == WVM_MEM_ACK_SUCCESS &&
                   ack.version == 7 && ack.data == local_page &&
                   ack.data_bytes == WVM_MEMORY_PAGE_BYTES &&
                   local_page[0] == 0xa5 && state.send_count == 2,
               "complete a local typed QEMU fault without fabric traffic")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&remote_fault_one, 0, sizeof(remote_fault_one));
    remote_fault_one.gpa = WVM_MEMORY_PAGE_BYTES;
    memcpy(remote_fault_one.operation_id, operation_five,
           sizeof(operation_five));
    atomic_init(&remote_fault_one.completed, 0);
    if (pthread_create(&remote_thread_one, NULL, run_global_fault,
                       &remote_fault_one) != 0 ||
        expect(wait_for_sends(&state, 3) == 0,
               "submit the first remote typed QEMU fault")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&remote_fault_two, 0, sizeof(remote_fault_two));
    remote_fault_two.gpa = WVM_MEMORY_PAGE_BYTES;
    memcpy(remote_fault_two.operation_id, operation_six,
           sizeof(operation_six));
    atomic_init(&remote_fault_two.completed, 0);
    if (pthread_create(&remote_thread_two, NULL, run_global_fault,
                       &remote_fault_two) != 0 ||
        expect(wait_for_sends(&state, 4) == 0,
               "submit a second operation for the same GPA")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_memory_service_global_request_fault(
                   remote_fault_one.gpa, remote_fault_one.operation_id, 1,
                   &ack, local_page, error, sizeof(error)) == -EALREADY &&
                   dispatch_remote_ack(&service, &state.sent[3], remote_page,
                                       error, sizeof(error)) == 0,
               "reject a duplicate local waiter without sharing its condvar")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    pthread_join(remote_thread_two, NULL);
    if (expect(remote_fault_two.result == 0 &&
                   remote_fault_two.ack.status ==
                       WVM_MEM_ACK_SUCCESS &&
                   remote_fault_two.ack.version == 12 &&
                   remote_fault_two.page[0] == remote_page[0] &&
                   atomic_load_explicit(&remote_fault_one.completed,
                                        memory_order_acquire) == 0 &&
                   dispatch_remote_ack(&service, &state.sent[2], remote_page,
                                       error, sizeof(error)) == 0,
               "complete only the matching operation for a shared GPA")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    pthread_join(remote_thread_one, NULL);
    if (expect(remote_fault_one.result == 0 &&
                   remote_fault_one.ack.status ==
                       WVM_MEM_ACK_SUCCESS &&
                   remote_fault_one.ack.version == 12 &&
                   remote_fault_one.page[0] == remote_page[0],
               "complete the remaining remote operation by its own identity")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&ack, 0, sizeof(ack));
    if (expect(wvm_memory_service_global_request_fault(
                   remote_fault_one.gpa, remote_fault_one.operation_id, 2,
                   &ack, local_page, error, sizeof(error)) == 0 &&
                   ack.status == WVM_MEM_ACK_SUCCESS &&
                   ack.version == 12 && local_page[0] == remote_page[0] &&
                   state.send_count == 4,
               "replay a retained remote fault completion without resending")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(wvm_memory_service_global_request_fault(
                   0, remote_fault_one.operation_id, 2, &ack, local_page,
                   error, sizeof(error)) == -EEXIST &&
                   state.send_count == 4,
               "reject a retained fault ID reused for another GPA")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&commit, 0, sizeof(commit));
    commit.gpa = 0;
    commit.base_version = 7;
    commit.offset = 12;
    commit.size = sizeof(commit_data);
    commit.reply_destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    commit.reply_destination_scope = 99;
    commit.reply_destination_vnode = 1;
    commit.data = commit_data;
    commit.data_bytes = sizeof(commit_data);
    state.commit_result = 0;
    state.commit_result_version = 8;
    if (expect(wvm_mem_commit_encode(
                   &commit, commit_payload, sizeof(commit_payload),
                   &commit_payload_bytes, error, sizeof(error)) == 0,
               "encode remote V1 dirty commit")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    fill_remote_commit_request(&projection, operation_seven, commit_payload,
                               commit_payload_bytes, &inbound);
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == 0 &&
                   state.commit_count == 1 && state.committed_gpa == 0 &&
                   state.committed_base_version == 7 &&
                   state.committed_offset == 12 &&
                   state.committed_data_bytes == sizeof(commit_data) &&
                   memcmp(state.committed_data, commit_data,
                          sizeof(commit_data)) == 0 &&
                   state.send_count == 5 &&
                   state.sent[4].message_type ==
                       WVM_ENVELOPE_MSG_MEM_COMMIT_ACK &&
                   state.sent[4].route.destination_scope == 99 &&
                   state.sent[4].route.destination_vnode_or_endpoint == 1 &&
                   wvm_mem_commit_ack_decode(
                       state.sent[4].payload, &commit_ack, error,
                       sizeof(error)) == 0 &&
                   commit_ack.gpa == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                   commit_ack.result_version == 8 &&
                   commit_ack.directory_physical_node_id == 17 &&
                   commit_ack.directory_node_instance_id == 101,
               "apply a remote V1 dirty commit and return a typed result")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == 0 &&
                   state.commit_count == 1 && state.send_count == 6 &&
                   wvm_mem_commit_ack_decode(
                       state.sent[5].payload, &commit_ack, error,
                       sizeof(error)) == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                   commit_ack.result_version == 8,
               "replay a completed V1 dirty commit without another apply")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    commit_data[0] ^= 0xffU;
    commit.data = commit_data;
    if (expect(wvm_mem_commit_encode(
                   &commit, commit_payload, sizeof(commit_payload),
                   &commit_payload_bytes, error, sizeof(error)) == 0,
               "encode conflicting V1 dirty commit")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    fill_remote_commit_request(&projection, operation_seven, commit_payload,
                               commit_payload_bytes, &inbound);
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == -EEXIST &&
                   state.commit_count == 1 && state.send_count == 6,
               "reject a reused commit operation ID with changed bytes")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    state.commit_result = -ESTALE;
    commit.base_version = 8;
    if (expect(wvm_mem_commit_encode(
                   &commit, commit_payload, sizeof(commit_payload),
                   &commit_payload_bytes, error, sizeof(error)) == 0,
               "encode stale-base V1 dirty commit")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    fill_remote_commit_request(&projection, operation_eight, commit_payload,
                               commit_payload_bytes, &inbound);
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == 0 &&
                   state.commit_count == 2 && state.send_count == 7 &&
                   wvm_mem_commit_ack_decode(
                       state.sent[6].payload, &commit_ack, error,
                       sizeof(error)) == 0 &&
                   commit_ack.status ==
                       WVM_MEM_COMMIT_ACK_STALE_BASE_VERSION &&
                   commit_ack.result_version == 0,
               "return a typed stale-base result without a false success")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    state.commit_result = -EAGAIN;
    commit.base_version = 9;
    if (expect(wvm_mem_commit_encode(
                   &commit, commit_payload, sizeof(commit_payload),
                   &commit_payload_bytes, error, sizeof(error)) == 0,
               "encode backpressured V1 dirty commit")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    fill_remote_commit_request(&projection, operation_nine, commit_payload,
                               commit_payload_bytes, &inbound);
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == 0 &&
                   state.commit_count == 3 && state.send_count == 8 &&
                   wvm_mem_commit_ack_decode(
                       state.sent[7].payload, &commit_ack, error,
                       sizeof(error)) == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_BACKPRESSURE,
               "report bounded directory backpressure")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    state.commit_result = 0;
    state.commit_result_version = 10;
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == 0 &&
                   state.commit_count == 4 && state.send_count == 9 &&
                   wvm_mem_commit_ack_decode(
                       state.sent[8].payload, &commit_ack, error,
                       sizeof(error)) == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                   commit_ack.result_version == 10,
               "retry the same backpressured operation without changing bytes")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    commit.gpa = WVM_MEMORY_PAGE_BYTES;
    commit.base_version = 10;
    if (expect(wvm_mem_commit_encode(
                   &commit, commit_payload, sizeof(commit_payload),
                   &commit_payload_bytes, error, sizeof(error)) == 0,
               "encode nonlocal-directory V1 dirty commit")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    fill_remote_commit_request(&projection, operation_ten, commit_payload,
                               commit_payload_bytes, &inbound);
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == -EPERM &&
                   state.commit_count == 4 && state.send_count == 9,
               "reject a V1 dirty commit sent to a nonlocal directory")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    state.commit_completion_count = 0;
    state.commit_complete_through_global = 1;
    struct global_commit_thread global_commit;
    pthread_t global_commit_thread;
    memset(&global_commit, 0, sizeof(global_commit));
    global_commit.gpa = WVM_MEMORY_PAGE_BYTES;
    global_commit.base_version = 12;
    global_commit.offset = 8;
    global_commit.data = commit_data;
    global_commit.data_bytes = sizeof(commit_data);
    memcpy(global_commit.operation_id, operation_eleven,
           sizeof(operation_eleven));
    atomic_init(&global_commit.completed, 0);
    if (pthread_create(&global_commit_thread, NULL, run_global_commit,
                       &global_commit) != 0 ||
        expect(wait_for_sends(&state, 10) == 0,
               "submit a remote dirty commit at the local QEMU boundary")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&commit_ack, 0, sizeof(commit_ack));
    commit_ack.gpa = WVM_MEMORY_PAGE_BYTES;
    commit_ack.result_version = 13;
    commit_ack.status = WVM_MEM_COMMIT_ACK_SUCCESS;
    commit_ack.directory_physical_node_id = 99;
    commit_ack.directory_node_instance_id = 202;
    if (expect(wvm_mem_commit_ack_envelope_build(
                   &state.sent[9], &reply_route, 2, &commit_ack,
                   commit_ack_payload, &outgoing_commit_ack, error,
                   sizeof(error)) == 0 &&
                   wvm_memory_service_dispatch(
                       &service, &outgoing_commit_ack, error,
                       sizeof(error)) == 0,
               "deliver the remote dirty commit ACK to the local waiter")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    pthread_join(global_commit_thread, NULL);
    if (expect(global_commit.result == 0 &&
                   global_commit.ack.gpa == WVM_MEMORY_PAGE_BYTES &&
                   global_commit.ack.status ==
                       WVM_MEM_COMMIT_ACK_SUCCESS &&
                   global_commit.ack.result_version == 13 &&
                   global_commit.ack.directory_physical_node_id == 99 &&
                   global_commit.ack.directory_node_instance_id == 202,
               "wake the matching local dirty-commit waiter exactly once")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&commit_ack, 0, sizeof(commit_ack));
    if (expect(wvm_memory_service_global_request_commit(
                   WVM_MEMORY_PAGE_BYTES, 12, 8, commit_data,
                   sizeof(commit_data), operation_eleven, 2, &commit_ack,
                   error, sizeof(error)) == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                   commit_ack.result_version == 13 &&
                   state.send_count == 10 &&
                   state.commit_completion_count == 1,
               "replay a retained remote commit completion without resending")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(wvm_memory_service_global_request_commit(
                   WVM_MEMORY_PAGE_BYTES, 12, 8,
                   conflicting_commit_data, sizeof(conflicting_commit_data),
                   operation_eleven, 2, &commit_ack, error,
                   sizeof(error)) == -EEXIST &&
                   state.send_count == 10 && state.commit_completion_count == 1,
               "reject a retained commit ID reused with different bytes")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    state.commit_result = 0;
    state.commit_result_version = 8;
    state.commit_complete_through_global = 1;
    state.commit_completion_count = 0;
    memset(&commit_ack, 0, sizeof(commit_ack));
    if (expect(wvm_memory_service_global_request_commit(
                   0, 7, 12, commit_data, sizeof(commit_data),
                   operation_fourteen, 1, &commit_ack, error,
                   sizeof(error)) == 0 &&
                   state.commit_count == 5 &&
                   state.send_count == 10 &&
                   state.commit_completion_count == 1 &&
                   commit_ack.gpa == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                   commit_ack.result_version == 8 &&
                   commit_ack.directory_physical_node_id == 17 &&
                   commit_ack.directory_node_instance_id == 101,
               "apply a local dirty commit through the typed completion waiter")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&commit_ack, 0, sizeof(commit_ack));
    if (expect(wvm_memory_service_global_request_commit(
                   0, 7, 12, commit_data, sizeof(commit_data),
                   operation_fourteen, 2, &commit_ack, error,
                   sizeof(error)) == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                   commit_ack.result_version == 8 &&
                   state.commit_count == 5 &&
                   state.commit_completion_count == 1 &&
                   state.send_count == 10,
               "replay a retained local commit without applying twice")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(wvm_memory_service_global_request_commit(
                   0, 7, 12, conflicting_commit_data,
                   sizeof(conflicting_commit_data), operation_fourteen, 2,
                   &commit_ack, error, sizeof(error)) == -EEXIST &&
                   state.commit_count == 5 && state.commit_completion_count == 1,
               "reject a retained local commit ID reused with different bytes")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    state.commit_complete_through_global = 0;
    state.commit_completion_count = 0;
    if (expect(wvm_memory_service_request_commit(
                   &service, WVM_MEMORY_PAGE_BYTES, 12, 8, commit_data,
                   sizeof(commit_data), operation_twelve, 1, error,
                   sizeof(error)) == 0 &&
                   state.send_count == 11 &&
                   state.sent[10].message_type ==
                       WVM_ENVELOPE_MSG_COMMIT_DIFF &&
                   wvm_mem_commit_decode(
                       state.sent[10].payload, state.sent_payload_bytes[10],
                       &commit, error, sizeof(error)) == 0 &&
                   commit.gpa == WVM_MEMORY_PAGE_BYTES &&
                   commit.base_version == 12 && commit.offset == 8 &&
                   commit.size == sizeof(commit_data) &&
                   commit.reply_destination_scope == 41 &&
                   commit.reply_destination_vnode == 0,
               "submit a remote dirty commit through the admitted route")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&commit_ack, 0, sizeof(commit_ack));
    commit_ack.gpa = WVM_MEMORY_PAGE_BYTES;
    commit_ack.result_version = 13;
    commit_ack.status = WVM_MEM_COMMIT_ACK_SUCCESS;
    commit_ack.directory_physical_node_id = 99;
    commit_ack.directory_node_instance_id = 202;
    if (expect(wvm_mem_commit_ack_envelope_build(
                   &state.sent[10], &reply_route, 2, &commit_ack,
                   commit_ack_payload, &outgoing_commit_ack, error,
                   sizeof(error)) == 0 &&
                   wvm_memory_service_dispatch(
                       &service, &outgoing_commit_ack, error,
                       sizeof(error)) == 0 &&
                   state.commit_completion_count == 1 &&
                   state.completed_commit_gpa == WVM_MEMORY_PAGE_BYTES &&
                   state.completed_commit_status ==
                       WVM_MEM_COMMIT_ACK_SUCCESS &&
                   state.completed_commit_version == 13 &&
                   state.completed_commit_directory == 99 &&
                   state.completed_commit_instance == 202,
               "complete a remote dirty commit by operation identity")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(wvm_memory_service_dispatch(
                   &service, &outgoing_commit_ack, error,
                   sizeof(error)) == 0 &&
                   state.commit_completion_count == 1,
               "deduplicate a repeated dirty commit ACK")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    commit_ack.result_version = 14;
    if (expect(wvm_mem_commit_ack_envelope_build(
                   &state.sent[10], &reply_route, 3, &commit_ack,
                   commit_ack_payload, &outgoing_commit_ack, error,
                   sizeof(error)) == 0 &&
                   wvm_memory_service_dispatch(
                       &service, &outgoing_commit_ack, error,
                       sizeof(error)) == -EEXIST &&
                   state.commit_completion_count == 1,
               "reject a conflicting dirty commit ACK")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    commit_ack.result_version = 13;
    commit_ack.directory_physical_node_id = 98;
    if (expect(wvm_mem_commit_ack_envelope_build(
                   &state.sent[10], &reply_route, 4, &commit_ack,
                   commit_ack_payload, &outgoing_commit_ack, error,
                   sizeof(error)) == 0 &&
                   wvm_memory_service_dispatch(
                       &service, &outgoing_commit_ack, error,
                       sizeof(error)) == -EPERM &&
                   state.commit_completion_count == 1,
               "reject a dirty commit ACK from the wrong directory")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    if (expect(wvm_directory_store_init(
                   &directory_store, &directory_store_config, error,
                   sizeof(error)) == 0 &&
                   wvm_directory_store_read_page(
                       &directory_store, 0, local_page,
                       &state.commit_result_version, error,
                       sizeof(error)) == 0,
               "initialize a V1 local directory for commit integration")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    state.directory_store = &directory_store;
    commit.gpa = 0;
    commit.base_version = state.commit_result_version;
    commit.offset = 31;
    commit.size = sizeof(commit_data);
    commit.data = commit_data;
    commit.data_bytes = sizeof(commit_data);
    if (expect(wvm_mem_commit_encode(
                   &commit, commit_payload, sizeof(commit_payload),
                   &commit_payload_bytes, error, sizeof(error)) == 0,
               "encode a V1 directory-store dirty commit")) {
        state.directory_store = NULL;
        wvm_directory_store_destroy(&directory_store);
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    fill_remote_commit_request(&projection, operation_thirteen, commit_payload,
                               commit_payload_bytes, &inbound);
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                              sizeof(error)) == 0 &&
                   state.send_count == 12 &&
                   wvm_mem_commit_ack_decode(
                       state.sent[11].payload, &commit_ack, error,
                       sizeof(error)) == 0 &&
                   commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                   commit_ack.result_version ==
                       UINT64_C(0x0000000400000002) &&
                   wvm_directory_store_read_page(
                       &directory_store, 0, local_page,
                       &state.commit_result_version, error,
                       sizeof(error)) == 0 &&
                   local_page[31] == commit_data[0] &&
                   local_page[32] == commit_data[1] &&
                   local_page[33] == commit_data[2],
               "apply a remote V1 commit to the V1 authoritative directory")) {
        state.directory_store = NULL;
        wvm_directory_store_destroy(&directory_store);
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    state.directory_store = NULL;
    wvm_directory_store_destroy(&directory_store);

    wvm_memory_service_global_uninstall(&service);
    wvm_memory_service_destroy(&service);
    wvm_route_runtime_destroy(&routes);
    pthread_cond_destroy(&state.sent_ready);
    pthread_mutex_destroy(&state.lock);
    printf("EVID memory_service: dirty_commit base_version=7->result_version=8 "
           "STALE_BASE_VERSION=1 ack_version_path=9\n");
    puts("memory-service tests: PASS");
    return 0;
}

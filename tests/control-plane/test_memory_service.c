#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wavevm_membership.h"
#include "memory_service.h"
#include "directory_store.h"
#include "kernel_memory.h"

struct test_state {
    pthread_mutex_t lock;
    pthread_cond_t sent_ready;
    int read_count;
    uint64_t readable_bytes;
    struct wvm_memory_service *commit_during_read;
    int concurrent_commit_result;
    int commit_count;
    int commit_source_shared_backing;
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
    int push_count;
    uint32_t last_push_directory;
    uint64_t last_push_directory_instance;
    int last_push_full;
    uint64_t last_push_gpa;
    uint64_t last_push_version;
    uint16_t last_push_offset;
    size_t last_push_bytes;
    uint8_t last_push_data[WVM_MEMORY_PAGE_BYTES];
    int complete_through_global;
    uint64_t completed_gpa;
    uint64_t completed_version;
    uint16_t completed_status;
    uint8_t completed_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_envelope sent[12];
    uint8_t sent_payload[12][WVM_MEM_ACK_HEADER_BYTES +
                             WVM_MEMORY_PAGE_BYTES];
    size_t sent_payload_bytes[12];
    struct wvm_memory_service *drain_during_send;
    struct wvm_memory_service *snapshot_reader;
    uint64_t snapshot_version;
    uint8_t snapshot_byte;
    int snapshot_inject_stale;
    int snapshot_stale_completed;
    int callback_drain_result;
    uint64_t callback_route_refs;
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
    if (!state || (gpa != 0 && gpa >= state->readable_bytes) || !version_out) {
        return -ENOENT;
    }
    memset(data, 0xa5, WVM_MEMORY_PAGE_BYTES);
    *version_out = 7;
    state->read_count++;
    if (state->commit_during_read) {
        struct wvm_memory_service *service = state->commit_during_read;
        uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xed};

        state->commit_during_read = NULL;
        state->concurrent_commit_result = wvm_memory_service_request_commit(
            service, gpa, *version_out, 0, (const uint8_t *)"z", 1,
            operation_id, 1, error, error_len);
    }
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
                       size_t data_bytes, int source_shared_backing,
                       uint64_t *result_version, char *error,
                       size_t error_len)
{
    struct test_state *state = opaque;

    (void)error;
    (void)error_len;
    if (!state || !data || !result_version ||
        data_bytes > sizeof(state->committed_data)) {
        return -EINVAL;
    }
    state->commit_count++;
    state->commit_source_shared_backing = source_shared_backing;
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

static int apply_push(void *opaque, uint32_t directory_physical_node_id,
                      uint64_t directory_node_instance_id, uint64_t gpa,
                      uint64_t base_version, uint64_t version,
                      uint16_t offset, const uint8_t *data, size_t data_bytes,
                      int full_page, char *error, size_t error_len)
{
    struct test_state *state = opaque;

    (void)base_version;
    (void)error;
    (void)error_len;
    if (!state || !data || version == 0 || data_bytes == 0 ||
        data_bytes > sizeof(state->last_push_data) ||
        offset > WVM_MEMORY_PAGE_BYTES - data_bytes ||
        (full_page && (offset != 0 || data_bytes != WVM_MEMORY_PAGE_BYTES))) {
        return -EINVAL;
    }
    state->push_count++;
    state->last_push_directory = directory_physical_node_id;
    state->last_push_directory_instance = directory_node_instance_id;
    state->last_push_full = full_page;
    state->last_push_gpa = gpa;
    state->last_push_version = version;
    state->last_push_offset = offset;
    state->last_push_bytes = data_bytes;
    memcpy(state->last_push_data, data, data_bytes);
    return 0;
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
    if (state->drain_during_send) {
        int horizon_complete;
        struct wvm_memory_service *service = state->drain_during_send;

        state->callback_drain_result =
            wvm_memory_service_drain(service, 0, error, error_len);
        if (wvm_route_runtime_query_retire_proof(
                service->config.route_runtime,
                &service->config.dispatch->required_route_snapshot_key,
                &state->callback_route_refs, &horizon_complete, error,
                error_len) != 0) {
            return -EIO;
        }
    }
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

static int test_subscriber_capacity(
    const struct wvm_memory_service_config *base, char *error, size_t error_len)
{
    struct wvm_memory_service_config config = *base;
    struct wvm_runtime_dispatch_projection projection = *base->dispatch;
    struct wvm_runtime_memory_dispatch memory =
        base->dispatch->memory_dispatch.entries[0];
    struct wvm_memory_service *service = calloc(1, sizeof(*service));
    struct test_state state = {0};
    struct wvm_mem_read read = {0};
    struct wvm_mem_ack ack;
    struct wvm_envelope request;
    uint8_t payload[WVM_MEM_READ_PAYLOAD_BYTES];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xee};
    uint64_t subscriber_last_validated = 0;
    uint64_t subscriber_epoch = 0;
    int result = -1;

    if (!service) return -1;
    memory.bytes = UINT64_C(8192) * WVM_MEMORY_PAGE_BYTES;
    projection.memory_dispatch.entries = &memory;
    projection.memory_dispatch.count = projection.memory_dispatch.capacity = 1;
    config.dispatch = &projection;
    config.opaque = &state;
    pthread_mutex_init(&state.lock, NULL);
    pthread_cond_init(&state.sent_ready, NULL);
    state.readable_bytes = memory.bytes;
    if (wvm_memory_service_init(service, &config, error, error_len)) goto out;
    service->config.enable_typed_subscriber_delivery = 1;
    read.reply_destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    read.reply_destination_scope = 99;
    read.reply_destination_vnode = 1;
    read.reply_node_instance_id = 303;
    for (uint32_t page = 0; page <= 4096; ++page) {
        read.gpa = (uint64_t)page * WVM_MEMORY_PAGE_BYTES;
        memcpy(operation_id + 8, &page, sizeof(page));
        state.send_count = 0;
        if (wvm_mem_read_encode(&read, payload, error, error_len)) goto out;
        fill_remote_read_request(&projection, operation_id, payload,
                                 sizeof(payload), &request);
        if (wvm_memory_service_dispatch(service, &request, error, error_len) ||
            wvm_mem_ack_decode(state.sent[0].payload,
                               state.sent[0].payload_bytes, &ack,
                               error, error_len) ||
            expect(ack.status == WVM_MEM_ACK_SUCCESS &&
                       service->subscriber_count == (uint64_t)page + 1,
                   "every successful read retains its subscriber beyond 4096 pages"))
            goto out;
    }
    state.send_count = 0;
    if (wvm_memory_service_dispatch(service, &request, error, error_len) ||
        expect(service->subscriber_count == 4097 &&
                   service->subscriber_bucket_count > 256 &&
                   service->subscriber_count <= service->subscriber_limit,
               "rehash preserves subscriber identity and admitted resource bound"))
        goto out;
    {
        struct wvm_memory_subscriber *subscriber = NULL;

        for (size_t bucket = 0; bucket < service->subscriber_bucket_count &&
                                !subscriber; ++bucket) {
            for (struct wvm_memory_subscriber *entry =
                     service->subscriber_buckets[bucket];
                 entry; entry = entry->next) {
                if (entry->gpa == read.gpa &&
                    entry->subscriber_physical_node_id == 99 &&
                    entry->subscriber_node_instance_id == 303) {
                    subscriber = entry;
                    break;
                }
            }
        }
        if (!subscriber) goto out;
        subscriber_last_validated = subscriber->last_validated_at;
        subscriber_epoch = subscriber->lease_or_observed_epoch;
    }
    state.send_count = 0;
    state.commit_result_version = 8;
    operation_id[0] = 0xef;
    if (wvm_memory_service_request_commit(
            service, read.gpa, 7, 0, (const uint8_t *)"x", 1, operation_id,
            1, error, error_len) ||
        expect(state.send_count == 1 && state.sent[0].message_type ==
                   WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF,
               "subscriber beyond the old limit receives its canonical update"))
        goto out;
    {
        struct wvm_memory_subscriber *subscriber = NULL;

        for (size_t bucket = 0; bucket < service->subscriber_bucket_count &&
                                !subscriber; ++bucket) {
            for (struct wvm_memory_subscriber *entry =
                     service->subscriber_buckets[bucket];
                 entry; entry = entry->next) {
                if (entry->gpa == read.gpa &&
                    entry->subscriber_physical_node_id == 99 &&
                    entry->subscriber_node_instance_id == 303) {
                    subscriber = entry;
                    break;
                }
            }
        }
        if (expect(subscriber && subscriber->observed_version == 7 &&
                       subscriber->last_validated_at == subscriber_last_validated &&
                       subscriber->lease_or_observed_epoch == subscriber_epoch,
                   "local push submission cannot advance observed version or lease"))
            goto out;
    }
    puts("EVID memory_subscriber_capacity: pages=4097 repeated_read_deduplicated=1 "
         "last_page_push=1 admitted_bound=1");
    read.gpa += WVM_MEMORY_PAGE_BYTES;
    state.send_count = 0;
    state.commit_during_read = service;
    operation_id[0] = 0xf0;
    if (wvm_mem_read_encode(&read, payload, error, error_len)) goto out;
    fill_remote_read_request(&projection, operation_id, payload,
                             sizeof(payload), &request);
    if (wvm_memory_service_dispatch(service, &request, error, error_len) ||
        expect(state.concurrent_commit_result == 0 && state.send_count == 2 &&
                   state.sent[0].message_type == WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF &&
                   state.sent[1].message_type == WVM_ENVELOPE_MSG_MEM_ACK,
               "commit racing the first read cannot miss the provisional subscriber"))
        goto out;
    service->subscriber_limit = service->subscriber_count;
    read.gpa += WVM_MEMORY_PAGE_BYTES;
    state.send_count = 0;
    int reads_before = state.read_count;
    if (wvm_mem_read_encode(&read, payload, error, error_len)) goto out;
    fill_remote_read_request(&projection, operation_id, payload,
                             sizeof(payload), &request);
    if (wvm_memory_service_dispatch(service, &request, error, error_len) ||
        wvm_mem_ack_decode(state.sent[0].payload, state.sent[0].payload_bytes,
                           &ack, error, error_len) ||
        expect(ack.status == WVM_MEM_ACK_INTERNAL_FAILURE &&
                   state.read_count == reads_before && ack.data_bytes == 0,
               "subscription pressure cannot return an untracked CLEAN snapshot"))
        goto out;
    puts("EVID memory_subscriber_read: commit_during_snapshot_delivered=1 "
         "untracked_success_rejected=1");
    result = 0;
out:
    wvm_memory_service_destroy(service);
    free(service);
    pthread_cond_destroy(&state.sent_ready);
    pthread_mutex_destroy(&state.lock);
    return result;
}

static int send_snapshot_read(void *opaque, const struct wvm_envelope *request,
                               char *error, size_t error_len)
{
    struct test_state *state = opaque;
    struct wvm_mem_read read;
    struct wvm_mem_ack ack = {0};
    struct wvm_envelope response;
    uint8_t page[WVM_MEMORY_PAGE_BYTES];
    uint8_t payload[WVM_MEM_ACK_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    size_t bytes;
    struct wvm_envelope_route route = {
        .destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE,
        .destination_scope = 41, .destination_vnode_or_endpoint = 0,
        .hop_limit = 4,
    };

    if (request->message_type != WVM_ENVELOPE_MSG_MEM_READ ||
        wvm_mem_read_decode(request->payload, request->payload_bytes, &read,
                            error, error_len)) return -EINVAL;
    ack.gpa = read.gpa;
    ack.version = state->snapshot_version;
    ack.status = WVM_MEM_ACK_SUCCESS;
    ack.directory_physical_node_id = 99;
    ack.directory_node_instance_id = 202;
    ack.data = page;
    ack.data_bytes = sizeof(page);
    memset(page, state->snapshot_byte, sizeof(page));
    state->send_count++;
    if (state->snapshot_inject_stale) {
        int completions = state->completion_count;

        ack.version--;
        if (wvm_mem_ack_envelope_build(
                request, &route,
                request->delivery_attempt_id + 1, &ack, payload, sizeof(payload),
                &bytes, &response, error, error_len)) return -EINVAL;
        if (wvm_memory_service_dispatch(state->snapshot_reader, &response,
                                        error, error_len)) return -EINVAL;
        state->snapshot_stale_completed = state->completion_count - completions;
        ack.version++;
        state->snapshot_inject_stale = 0;
    }
    if (wvm_mem_ack_envelope_build(request, &route,
            request->delivery_attempt_id + 1, &ack, payload, sizeof(payload),
            &bytes, &response, error, error_len)) return -EINVAL;
    return wvm_memory_service_dispatch(state->snapshot_reader, &response,
                                       error, error_len);
}

static int test_read_receipt_capacity(const struct wvm_memory_service_config *base,
                                      char *error, size_t error_len)
{
    struct wvm_runtime_dispatch_projection projection = *base->dispatch;
    struct wvm_runtime_memory_dispatch memory =
        base->dispatch->memory_dispatch.entries[1];
    struct wvm_memory_service_config config = *base;
    struct wvm_memory_service *service = calloc(1, sizeof(*service));
    struct test_state state = {0};
    struct wvm_mem_ack ack;
    uint8_t data[WVM_MEMORY_PAGE_BYTES];
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xf2};
    const uint32_t pages = 8192;
    struct timespec start, end;
    int result = -1;
    int installed = 0;

    if (!service) return -1;
    memory.gpa_start = 0;
    memory.bytes = (uint64_t)pages * WVM_MEMORY_PAGE_BYTES;
    projection.memory_dispatch.entries = &memory;
    projection.memory_dispatch.count = projection.memory_dispatch.capacity = 1;
    config.dispatch = &projection;
    config.completion_timeout_ms = 60000;
    config.enable_typed_subscriber_delivery = 0;
    config.send_envelope = send_snapshot_read;
    config.opaque = &state;
    state.snapshot_reader = service;
    state.snapshot_version = 7;
    state.snapshot_byte = 0xa5;
    state.complete_through_global = 1;
    if (wvm_memory_service_init(service, &config, error, error_len) ||
        wvm_memory_service_global_install(service, error, error_len)) goto out;
    installed = 1;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (uint32_t i = 0; i < pages; ++i) {
        memcpy(operation_id + 8, &i, sizeof(i));
        if (wvm_memory_service_global_request_fault(
                (uint64_t)i * WVM_MEMORY_PAGE_BYTES, operation_id, 1, &ack,
                data, error, error_len) ||
            expect(ack.status == WVM_MEM_ACK_SUCCESS && ack.version == 7 &&
                       data[0] == 0xa5 && service->pending_active == 0,
                   "cold snapshot releases active capacity after each read")) goto out;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (expect(service->pending_count == pages,
               "compact receipts retain all identities without retaining all pages")) goto out;
    memset(operation_id + 8, 0, sizeof(uint32_t));
    if (expect(wvm_memory_service_global_request_fault(
                   WVM_MEMORY_PAGE_BYTES, operation_id, 2, &ack, data, error,
                   error_len) == -EEXIST && state.send_count == (int)pages,
               "evicted read payload still rejects the same ID with another GPA")) goto out;
    state.snapshot_version = 8;
    state.snapshot_byte = 0x3c;
    if (wvm_memory_service_global_request_fault(0, operation_id, 2, &ack,
            data, error, error_len) ||
        expect(ack.version == 8 && data[0] == 0x3c && state.send_count == (int)pages + 1,
               "evicted payload is refetched with the same identity and newer version")) goto out;
    state.complete_through_global = 0;
    state.snapshot_inject_stale = 1;
    int completions = state.completion_count;
    if (wvm_memory_service_request_fault(service, 0, operation_id, 3,
            error, error_len) ||
        expect(state.snapshot_stale_completed == 0 &&
                   state.completion_count == completions + 1,
               "late older reply cannot complete a reissued read")) goto out;
    state.snapshot_byte = 0x55;
    if (expect(wvm_memory_service_request_fault(service, 0, operation_id, 4,
                   error, error_len) == -EEXIST &&
                   state.completion_count == completions + 1,
               "same-version changed bytes are rejected after payload eviction")) goto out;
    int sends = state.send_count;
    if (expect(wvm_memory_service_global_request_fault_before(
                   0, operation_id, 5, 1, &ack, data, error, error_len) == -ETIMEDOUT &&
                   state.send_count == sends,
               "an expired shared snapshot deadline cannot start another read")) goto out;
    printf("EVID memory_read_receipts: pages=%u bytes=%llu elapsed_ms=%lld "
           "retention_ms=60000 same_id_newer_snapshot=1 stale_reply_ignored=1 "
           "identity_and_digest_conflicts_rejected=1\n", pages,
           (unsigned long long)memory.bytes,
           (long long)(end.tv_sec - start.tv_sec) * 1000 +
           (end.tv_nsec - start.tv_nsec) / 1000000);
    result = 0;
out:
    if (installed) wvm_memory_service_global_uninstall(service);
    wvm_memory_service_destroy(service);
    free(service);
    return result;
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
    uint8_t push_payload[WVM_MEM_PUSH_HEADER_BYTES + WVM_MEMORY_PAGE_BYTES];
    uint8_t remote_page[WVM_MEMORY_PAGE_BYTES];
    uint8_t local_page[WVM_MEMORY_PAGE_BYTES];
    struct wvm_mem_commit commit;
    struct wvm_mem_commit_ack commit_ack;
    struct wvm_envelope outgoing_commit_ack;
    struct wvm_mem_push push;
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
    config.apply_push = apply_push;
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
                   state.completion_count == 0 &&
                   service.remote_read_completions == 0,
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
                   state.completion_count == 1 &&
                   service.remote_read_completions == 1,
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
    read.reply_node_instance_id = 202;
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
    commit.reply_node_instance_id = 202;
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
    if (expect(wvm_memory_service_global_request_commit_from_shared_backing(
                   0, 7, 12, commit_data, sizeof(commit_data),
                   operation_fourteen, 1, 1, &commit_ack, error,
                   sizeof(error)) == 0 &&
                   state.commit_count == 5 &&
                   state.commit_source_shared_backing == 1 &&
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
    if (expect(wvm_memory_service_global_request_commit_from_shared_backing(
                   0, 7, 12, commit_data, sizeof(commit_data),
                   operation_fourteen, 2, 1, &commit_ack, error,
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
    if (expect(wvm_memory_service_global_request_commit_from_shared_backing(
                   0, 7, 12, conflicting_commit_data,
                   sizeof(conflicting_commit_data), operation_fourteen, 2, 1,
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

    /* Typed subscriber delivery: full snapshot, ordered diff, and identity. */
    memset(&push, 0, sizeof(push));
    push.gpa = WVM_MEMORY_PAGE_BYTES;
    push.version = 14;
    push.size = WVM_MEMORY_PAGE_BYTES;
    push.flags = WVM_MEM_PUSH_FLAG_FULL;
    push.directory_physical_node_id = 99;
    push.directory_node_instance_id = 202;
    push.data = remote_page;
    push.data_bytes = sizeof(remote_page);
    if (expect(wvm_mem_push_encode(&push, push_payload, sizeof(push_payload),
                                   &ack_payload_bytes, error,
                                   sizeof(error)) == 0,
               "encode typed full subscriber push")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&inbound, 0, sizeof(inbound));
    inbound.message_type = WVM_ENVELOPE_MSG_PAGE_PUSH_FULL;
    inbound.vm_id = projection.vm_id;
    inbound.vm_incarnation = projection.vm_incarnation;
    inbound.manifest_generation = projection.manifest_generation;
    inbound.origin_physical_node_id = 99;
    inbound.origin_runtime_instance_id = 202;
    inbound.operation_id[15] = 15;
    inbound.delivery_attempt_id = 1;
    inbound.route_scope_id =
        projection.required_route_snapshot_key.scope_key.route_scope_id;
    inbound.topology_revision =
        projection.required_route_snapshot_key.topology_revision;
    inbound.route_generation =
        projection.required_route_snapshot_key.route_generation;
    memcpy(inbound.route_snapshot_digest,
           projection.required_route_snapshot_key.snapshot_digest,
           sizeof(inbound.route_snapshot_digest));
    inbound.route.destination_kind =
        projection.local_primary.destination_kind;
    inbound.route.destination_scope = projection.local_primary.destination_scope;
    inbound.route.destination_vnode_or_endpoint =
        projection.local_primary.destination_vnode;
    inbound.route.hop_limit = 4;
    inbound.payload = push_payload;
    inbound.payload_bytes = ack_payload_bytes;
    service.config.enable_typed_subscriber_delivery = 1;
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                           sizeof(error)) == 0 &&
                   state.push_count == 1 && state.last_push_full &&
                   state.last_push_gpa == WVM_MEMORY_PAGE_BYTES &&
                   state.last_push_directory == 99 &&
                   state.last_push_directory_instance == 202 &&
                   state.last_push_version == 14 &&
                   state.last_push_bytes == WVM_MEMORY_PAGE_BYTES &&
                   state.last_push_data[0] == remote_page[0],
               "apply an admitted typed full subscriber push")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                           sizeof(error)) == 0 &&
                   state.push_count == 1,
               "deduplicate a repeated typed subscriber push")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    memset(&push, 0, sizeof(push));
    push.gpa = WVM_MEMORY_PAGE_BYTES;
    push.base_version = 14;
    push.version = 15;
    push.offset = 4;
    push.size = 3;
    push.directory_physical_node_id = 99;
    push.directory_node_instance_id = 202;
    push.data = commit_data;
    push.data_bytes = sizeof(commit_data);
    if (expect(wvm_mem_push_encode(&push, push_payload, sizeof(push_payload),
                                   &ack_payload_bytes, error,
                                   sizeof(error)) == 0,
               "encode typed ordered diff subscriber push")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    inbound.message_type = WVM_ENVELOPE_MSG_PAGE_PUSH_DIFF;
    inbound.operation_id[15] = 16;
    inbound.payload = push_payload;
    inbound.payload_bytes = ack_payload_bytes;
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                           sizeof(error)) == 0 &&
                   state.push_count == 2 && !state.last_push_full &&
                   state.last_push_version == 15 &&
                   state.last_push_offset == 4 &&
                   state.last_push_bytes == sizeof(commit_data) &&
                   state.last_push_data[0] == commit_data[0],
               "apply the next typed subscriber diff")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    inbound.origin_runtime_instance_id = 203;
    if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                           sizeof(error)) == -EPERM &&
                   state.push_count == 2,
               "reject typed push from a stale directory runtime")) {
        wvm_memory_service_global_uninstall(&service);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    {
        uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xf1};
        int complete_through_global = state.complete_through_global;
        int found = 0;

        state.send_count = 0;
        state.complete_through_global = 0;
        if (wvm_memory_service_request_fault(
                &service, WVM_MEMORY_PAGE_BYTES, operation_id, 1,
                error, sizeof(error)) ||
            dispatch_remote_ack(&service, &state.sent[0], remote_page,
                                 error, sizeof(error))) return 1;
        state.complete_through_global = complete_through_global;
        for (size_t i = 0; i < WVM_MEMORY_SERVICE_MAX_CACHE_ENTRIES; ++i) {
            if (service.cache[i].gpa == WVM_MEMORY_PAGE_BYTES && service.cache[i].valid) {
                if (expect(service.cache[i].version == 15,
                           "late read ACK cannot roll back a newer push qualification"))
                    return 1;
                found = 1;
            }
        }
        if (expect(found, "newer pushed page remains cache-qualified")) return 1;
    }

    {
        struct wvm_ioctl_memory_operation operation = {0};
        int commits_before;

        state.complete_through_global = 1;
        state.commit_complete_through_global = 1;
        operation.kind = WVM_KERNEL_MEMORY_READ;
        operation.operation_id[0] = 0xc1;
        if (expect(wvm_kernel_memory_execute(&operation) == 0 &&
                       operation.status == 0 && operation.result_version == 7 &&
                       operation.data_bytes == WVM_MEMORY_PAGE_BYTES &&
                       operation.data[0] == 0xa5,
                   "kernel fault uses the installed canonical memory authority"))
            return 1;
        memset(&operation, 0, sizeof(operation));
        operation.kind = WVM_KERNEL_MEMORY_COMMIT;
        operation.operation_id[0] = 0xc2;
        operation.base_version = 7;
        operation.offset = 17;
        operation.data_bytes = 1;
        operation.data[0] = 0xbc;
        state.commit_result = 0;
        state.commit_result_version = 20;
        if (expect(wvm_kernel_memory_execute(&operation) == 0 &&
                       operation.result_version == 20 &&
                       state.committed_offset == 17 &&
                       state.committed_data[0] == 0xbc,
                   "kernel commit settles only the canonical result version"))
            return 1;
        operation.operation_id[0] = 0xc3;
        state.commit_result = -ESTALE;
        if (expect(wvm_kernel_memory_execute(&operation) == -ESTALE &&
                       operation.status == -ESTALE &&
                       operation.result_version == 0,
                   "kernel commit preserves authority rejection"))
            return 1;
        commits_before = state.commit_count;
        operation.offset = WVM_MEMORY_PAGE_BYTES;
        operation.operation_id[0] = 0xc4;
        if (expect(wvm_kernel_memory_execute(&operation) == -EINVAL &&
                       state.commit_count == commits_before,
                   "kernel malformed write is rejected before applying bytes"))
            return 1;
    }

    {
        uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xd7};
        int found = 0;

        state.send_count = 0;
        memset(&read, 0, sizeof(read));
        read.reply_destination_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
        read.reply_destination_scope = 99;
        read.reply_destination_vnode = 1;
        read.reply_node_instance_id = 303;
        if (expect(wvm_mem_read_encode(&read, read_payload, error,
                                       sizeof(error)) == 0,
                   "encode reader identity distinct from gateway next hop"))
            return 1;
        fill_remote_read_request(&projection, operation_id, read_payload,
                                 sizeof(read_payload), &inbound);
        if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                               sizeof(error)) == 0,
                   "read through the fractal return route"))
            return 1;
        for (size_t i = 0; i < service.subscriber_bucket_count; i++) {
          for (const struct wvm_memory_subscriber *s = service.subscriber_buckets[i];
               s; s = s->next) {

            if (s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE &&
                s->subscriber_physical_node_id == 99 &&
                s->subscriber_runtime_instance_id == 2020) {
                if (expect(s->subscriber_node_instance_id == 303,
                           "subscriber uses leaf instance, not gateway instance"))
                    return 1;
                found = 1;
            }
          }
        }
        if (expect(found, "typed read registers its leaf subscriber"))
            return 1;
        puts("EVID memory_service_subscriber: leaf_instance=303 next_hop_instance=202");
    }

    /* F07: ACTIVE lease → STALE via invalidate API + membership hook + lease reap. */
    {
        struct wvm_memory_subscriber *target = NULL;
        uint64_t rev_before = 0;
        int found_active = 0;
        int found_stale = 0;

        for (size_t i = 0; i < service.subscriber_bucket_count && !target; i++) {
            for (struct wvm_memory_subscriber *s = service.subscriber_buckets[i];
                 s; s = s->next) {
                if (s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE &&
                    s->subscriber_physical_node_id == 99 &&
                    s->subscriber_node_instance_id == 303 &&
                    s->subscriber_runtime_instance_id == 2020) {
                    target = s;
                    break;
                }
            }
        }
        if (expect(target != NULL, "F07 precondition: ACTIVE leaf subscriber"))
            return 1;
        rev_before = target->qualification_revision;
        if (expect(wvm_memory_service_invalidate_subscriber_instance(
                       &service, 99, 303, 2020, NULL, error,
                       sizeof(error)) == 0 &&
                       target->state == WVM_MEMORY_SUBSCRIBER_STALE &&
                       target->qualification_revision == rev_before + 1,
                   "F07 invalidate_subscriber_instance ACTIVE→STALE"))
            return 1;
        puts("EVID F07_invalidate_instance: ACTIVE_to_STALE=1");

        /* Re-qualify same leaf via typed read on local directory GPA 0. */
        {
            uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xf7};
            state.send_count = 0;
            memset(&read, 0, sizeof(read));
            read.gpa = 0;
            read.reply_destination_kind =
                WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
            read.reply_destination_scope = 99;
            read.reply_destination_vnode = 1;
            read.reply_node_instance_id = 303;
            if (expect(wvm_mem_read_encode(&read, read_payload, error,
                                           sizeof(error)) == 0,
                       "F07 encode read for membership invalidate"))
                return 1;
            fill_remote_read_request(&projection, operation_id, read_payload,
                                     sizeof(read_payload), &inbound);
            if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                                   sizeof(error)) == 0,
                       "F07 read re-qualifies subscriber for membership hook"))
                return 1;
        }
        found_active = 0;
        for (size_t i = 0; i < service.subscriber_bucket_count; i++) {
            for (const struct wvm_memory_subscriber *s =
                     service.subscriber_buckets[i];
                 s; s = s->next) {
                if (s->subscriber_physical_node_id == 99 &&
                    s->subscriber_node_instance_id == 303 &&
                    s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE) {
                    found_active = 1;
                }
            }
        }
        if (expect(found_active, "F07 re-qualified ACTIVE before membership hook"))
            return 1;

        /* Global service already installed earlier in main for QEMU boundary. */
        wvm_memory_service_membership_failure_invalidate_hook(
            NULL, 99, 303, /*desired*/ 0, /*health*/ 0);
        found_active = 0;
        found_stale = 0;
        for (size_t i = 0; i < service.subscriber_bucket_count; i++) {
            for (const struct wvm_memory_subscriber *s =
                     service.subscriber_buckets[i];
                 s; s = s->next) {
                if (s->subscriber_physical_node_id != 99 ||
                    s->subscriber_node_instance_id != 303) {
                    continue;
                }
                if (s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE ||
                    s->state == WVM_MEMORY_SUBSCRIBER_READING) {
                    found_active = 1;
                }
                if (s->state == WVM_MEMORY_SUBSCRIBER_STALE) {
                    found_stale = 1;
                }
            }
        }
        if (expect(!found_active && found_stale,
                   "F07 membership_failure_invalidate_hook → STALE"))
            return 1;
        puts("EVID F07_membership_hook: global_invalidate_all_runtimes=1");

        /* Lease expire: re-qualify, force last_validated past horizon, scope-invalidate+reap. */
        {
            struct wvm_memory_subscriber *lease = NULL;
            struct wvm_vm_route_scope_key scope_key;
            uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xf8};
            uint32_t short_timeout;
            int still_active = 0;
            int saw_stale_or_gone = 0;

            state.send_count = 0;
            memset(&read, 0, sizeof(read));
            read.gpa = 0;
            read.reply_destination_kind =
                WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
            read.reply_destination_scope = 99;
            read.reply_destination_vnode = 1;
            read.reply_node_instance_id = 303;
            if (wvm_mem_read_encode(&read, read_payload, error, sizeof(error)))
                return 1;
            fill_remote_read_request(&projection, operation_id, read_payload,
                                     sizeof(read_payload), &inbound);
            if (wvm_memory_service_dispatch(&service, &inbound, error,
                                            sizeof(error)))
                return 1;
            for (size_t i = 0; i < service.subscriber_bucket_count && !lease;
                 i++) {
                for (struct wvm_memory_subscriber *s =
                         service.subscriber_buckets[i];
                     s; s = s->next) {
                    if (s->gpa == 0 &&
                        s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE &&
                        s->subscriber_physical_node_id == 99) {
                        lease = s;
                        break;
                    }
                }
            }
            if (expect(lease != NULL, "F07 lease subject ACTIVE"))
                return 1;
            scope_key = lease->route_scope_key;
            short_timeout = service.config.completion_timeout_ms;
            lease->last_validated_at = 1;
            service.config.completion_timeout_ms = 1;
            if (expect(wvm_memory_service_invalidate_subscribers_for_scope(
                           &service, &scope_key, error, sizeof(error)) == 0,
                       "F07 scope invalidate + reap path"))
                return 1;
            for (size_t i = 0; i < service.subscriber_bucket_count; i++) {
                for (const struct wvm_memory_subscriber *s =
                         service.subscriber_buckets[i];
                     s; s = s->next) {
                    if (s->gpa != 0 || s->subscriber_physical_node_id != 99)
                        continue;
                    if (s->state == WVM_MEMORY_SUBSCRIBER_ACTIVE ||
                        s->state == WVM_MEMORY_SUBSCRIBER_READING)
                        still_active = 1;
                    if (s->state == WVM_MEMORY_SUBSCRIBER_STALE)
                        saw_stale_or_gone = 1;
                }
            }
            if (!still_active)
                saw_stale_or_gone = 1;
            if (expect(saw_stale_or_gone && !still_active,
                       "F07 lease horizon ACTIVE→STALE/freed"))
                return 1;
            service.config.completion_timeout_ms = short_timeout;
            puts("EVID F07_lease_reap: ACTIVE_past_horizon_STALE_or_freed=1");
        }
        puts("EVID F07_subscriber_lease: invalidate=1 membership_hook=1 "
             "lease_reap=1");
    }

    if (test_subscriber_capacity(&config, error, sizeof(error))) {
        fprintf(stderr, "subscriber capacity: %s\n", error);
        return 1;
    }

    {
        const uint8_t byte = 0x9c;
        uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xd8};
        uint8_t oldest_operation_id[WVM_IDENTITY_ID_BYTES] = {0xd8};
        int commits_before = state.commit_count;
        uint8_t remote_operation_id[WVM_IDENTITY_ID_BYTES] = {0xda};

        /* Keep the remote receipt inside its 5-second replay horizon. */
        struct global_commit_thread remote_commit = {0};
        pthread_t remote_commit_thread;
        remote_commit.gpa = WVM_MEMORY_PAGE_BYTES;
        remote_commit.base_version = 12;
        remote_commit.offset = 8;
        remote_commit.data = commit_data;
        remote_commit.data_bytes = sizeof(commit_data);
        memcpy(remote_commit.operation_id, remote_operation_id,
               sizeof(remote_operation_id));
        atomic_init(&remote_commit.completed, 0);
        int sends_before = state.send_count;
        if (pthread_create(&remote_commit_thread, NULL, run_global_commit,
                           &remote_commit) != 0 ||
            wait_for_sends(&state, sends_before + 1) != 0) {
            fprintf(stderr, "memory-service test: start pressure remote commit: %s\n",
                    error);
            return 1;
        }
        memset(&commit_ack, 0, sizeof(commit_ack));
        commit_ack.gpa = WVM_MEMORY_PAGE_BYTES;
        commit_ack.result_version = 13;
        commit_ack.status = WVM_MEM_COMMIT_ACK_SUCCESS;
        commit_ack.directory_physical_node_id = 99;
        commit_ack.directory_node_instance_id = 202;
        if (wvm_mem_commit_ack_envelope_build(
                &state.sent[sends_before], &reply_route, 2, &commit_ack,
                commit_ack_payload, &outgoing_commit_ack, error,
                sizeof(error)) != 0 ||
            wvm_memory_service_dispatch(&service, &outgoing_commit_ack,
                                        error, sizeof(error)) != 0) {
            pthread_join(remote_commit_thread, NULL);
            fprintf(stderr, "memory-service test: complete pressure remote commit: %s\n",
                    error);
            return 1;
        }
        pthread_join(remote_commit_thread, NULL);
        if (expect(remote_commit.result == 0,
                   "retain a fresh remote commit receipt before local pressure"))
            return 1;

        state.commit_result = 0;
        state.commit_complete_through_global = 1;
        for (uint32_t i = 0; i <= WVM_MEMORY_SERVICE_MAX_PENDING; i++) {
            memcpy(operation_id + 8, &i, sizeof(i));
            state.commit_result_version = 32U + i;
            if (expect(wvm_memory_service_global_request_commit(
                           0, 7, 0, &byte, 1, operation_id, 1, &commit_ack,
                           error, sizeof(error)) == 0 &&
                           commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                           commit_ack.result_version == 32U + i,
                       "local commit receipt capacity grows without eviction")) {
                fprintf(stderr, "commit capacity operation=%u: %s\n", i, error);
                return 1;
            }
        }
        if (expect(state.commit_count - commits_before ==
                       WVM_MEMORY_SERVICE_MAX_PENDING + 1,
                   "local receipt pressure does not stall completed commits"))
            return 1;
        state.commit_result = -ESTALE;
        state.commit_result_version = 0;
        if (expect(wvm_memory_service_global_request_commit(
                       0, 7, 0, &byte, 1, oldest_operation_id, 1,
                       &commit_ack, error, sizeof(error)) == 0 &&
                       commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                       commit_ack.result_version == 32 &&
                       state.commit_count - commits_before ==
                           WVM_MEMORY_SERVICE_MAX_PENDING + 1,
                   "local commit replay returns the retained original ACK"))
            return 1;
        if (expect(wvm_memory_service_global_request_commit(
                       0, 7, 0, conflicting_commit_data,
                       sizeof(conflicting_commit_data), oldest_operation_id,
                       1, &commit_ack, error, sizeof(error)) == -EEXIST &&
                       state.commit_count - commits_before ==
                           WVM_MEMORY_SERVICE_MAX_PENDING + 1,
                   "local commit receipt rejects conflicting ID reuse"))
            return 1;
        state.commit_result = 0;
        state.commit_result_version = 8;
        int sends_before_replay = state.send_count;
        int replay_result = wvm_memory_service_global_request_commit(
            WVM_MEMORY_PAGE_BYTES, 12, 8, commit_data, sizeof(commit_data),
            remote_operation_id, 2, &commit_ack, error, sizeof(error));
        if (expect(replay_result == 0 &&
                       commit_ack.status == WVM_MEM_COMMIT_ACK_SUCCESS &&
                       commit_ack.result_version == 13 &&
                       state.send_count == sends_before_replay,
                   "local pressure preserves remote ACK replay receipts"))
            return 1;
        puts("EVID memory_service_capacity: commits=1025 local_receipts_retained=1 remote_receipt_retained=1");
    }

    {
        uint8_t operation_id[WVM_IDENTITY_ID_BYTES] = {0xd9};
        int reads_before;

        state.send_count = 0;
        state.drain_during_send = &service;
        fill_remote_read_request(&projection, operation_id, read_payload,
                                 sizeof(read_payload), &inbound);
        if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                               sizeof(error)) == 0 &&
                       state.callback_drain_result == -ETIMEDOUT &&
                       state.callback_route_refs > 0,
                   "STOP cannot retire an active read/delivery callback"))
            return 1;
        state.drain_during_send = NULL;
        reads_before = state.read_count;
        operation_id[0]++;
        if (expect(wvm_memory_service_request_fault(
                       &service, 0, operation_id, 1, error,
                       sizeof(error)) == -ESHUTDOWN &&
                       state.read_count == reads_before &&
                       wvm_memory_service_drain(&service, 100, error,
                                                sizeof(error)) == 0,
                   "STOP rejects new work and retires after the callback returns"))
            return 1;
        for (size_t i = 0; i < service.subscriber_bucket_count; i++) {
          for (const struct wvm_memory_subscriber *s = service.subscriber_buckets[i];
               s; s = s->next) {
            if (expect(s->state == WVM_MEMORY_SUBSCRIBER_REMOVED,
                       "STOP removes this VM's subscriber registry"))
                return 1;
          }
        }
        for (size_t i = 0; i < WVM_MEMORY_SERVICE_MAX_CACHE_ENTRIES; i++) {
            if (expect(!service.cache[i].valid && !service.cache[i].resync_in_flight,
                       "STOP revokes cached page eligibility"))
                return 1;
        }
        if (expect(wvm_memory_service_dispatch(&service, &inbound, error,
                                               sizeof(error)) == -ESHUTDOWN,
                   "retired service cannot accept a late routed operation"))
            return 1;
        puts("EVID memory_service_retire: callback_pinned=1 new_work_rejected=1 subscribers_removed=1");
    }

    wvm_memory_service_global_uninstall(&service);
    wvm_memory_service_destroy(&service);
    if (test_read_receipt_capacity(&config, error, sizeof(error))) {
        fprintf(stderr, "read receipt capacity: %s\n", error);
        return 1;
    }
    wvm_route_runtime_destroy(&routes);
    pthread_cond_destroy(&state.sent_ready);
    pthread_mutex_destroy(&state.lock);
    printf("EVID memory_service: dirty_commit base_version=7->result_version=8 "
           "STALE_BASE_VERSION=1 ack_version_path=9\n");
    puts("memory-service tests: PASS");
    return 0;
}

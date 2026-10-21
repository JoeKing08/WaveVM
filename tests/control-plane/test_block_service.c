/* R02: production block-service dispatch oracle.
 *
 * Drives the real wvm_block_service_dispatch() against the real file-backed
 * chunk store.  Coverage: first READ, duplicate READ (same bytes, one
 * execution), concurrent replay, WRITE+FUA/FLUSH, digest conflict, exact
 * header capacity, per-queue ordering, and the two retention rules that make
 * a retried write safe (capacity backpressure before execution, tombstone
 * after the window).
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "block_service.h"
#include "wavevm_block_chunk_store.h"
#include "wavevm_block_wire.h"
#include "wavevm_envelope.h"

#define TEST_VM_ID 7U
#define TEST_INCARNATION 0x1122334455667788ULL
#define TEST_GENERATION 3ULL
#define TEST_LOCAL_NODE 11U
#define TEST_LOCAL_RUNTIME 22U
#define TEST_REPLY_VNODE 5U
#define TEST_SECTORS 8U
#define TEST_BYTES (TEST_SECTORS * WVM_BLOCK_SECTOR_BYTES)

struct capture {
    pthread_mutex_t lock;
    unsigned int sends;
    uint16_t last_status;
    size_t last_bytes;
    uint8_t last_data[WVM_BLOCK_MAX_DATA_BYTES];
};

struct execute_state {
    pthread_mutex_t lock;
    unsigned int calls;
    unsigned int sleep_ms;
    uint32_t last_flags;
    uint32_t last_device;
};

static struct capture g_capture;
static struct execute_state g_execute;
static int g_failures;

static void fail(const char *message)
{
    fprintf(stderr, "block-service FAIL: %s\n", message);
    g_failures++;
}

static void expect(int condition, const char *message)
{
    if (!condition)
        fail(message);
}

static int execute_block(void *opaque, uint32_t device_index,
                         uint16_t operation, uint32_t flags, uint64_t lba_512,
                         uint32_t sector_count, const uint8_t *data,
                         size_t data_bytes, uint8_t *out, size_t out_capacity,
                         size_t *out_bytes, char *error, size_t error_len)
{
    unsigned int sleep_ms;
    int rc;

    (void)opaque;
    pthread_mutex_lock(&g_execute.lock);
    g_execute.calls++;
    g_execute.last_flags = flags;
    g_execute.last_device = device_index;
    sleep_ms = g_execute.sleep_ms;
    pthread_mutex_unlock(&g_execute.lock);
    if (sleep_ms != 0) {
        struct timespec delay;

        delay.tv_sec = (time_t)(sleep_ms / 1000U);
        delay.tv_nsec = (long)(sleep_ms % 1000U) * 1000000L;
        nanosleep(&delay, NULL);
    }

    if (operation == WVM_BLOCK_OPERATION_READ) {
        rc = wvm_block_chunk_read(lba_512, sector_count, out, out_capacity,
                                  out_bytes, error, error_len);
    } else if (operation == WVM_BLOCK_OPERATION_WRITE) {
        rc = wvm_block_chunk_write(lba_512, sector_count, data, data_bytes,
                                   (flags & WVM_BLOCK_ORDER_FUA) != 0, error,
                                   error_len);
        *out_bytes = 0;
    } else {
        if (sector_count == 0)
            rc = wvm_block_chunk_flush_all(error, error_len);
        else
            rc = wvm_block_chunk_flush_range(lba_512, sector_count, error,
                                             error_len);
        *out_bytes = 0;
    }
    return rc;
}

static int resolve_route(void *opaque, uint16_t destination_kind,
                         uint64_t destination_scope,
                         uint32_t destination_vnode,
                         struct wvm_envelope_route *route, char *error,
                         size_t error_len)
{
    (void)opaque;
    (void)error;
    (void)error_len;
    memset(route, 0, sizeof(*route));
    route->destination_kind = destination_kind;
    route->destination_scope = destination_scope;
    route->destination_vnode_or_endpoint = destination_vnode;
    route->hop_limit = 8;
    return 0;
}

static int send_envelope(void *opaque, const struct wvm_envelope *envelope,
                         char *error, size_t error_len)
{
    struct wvm_block_completion completion;
    const uint8_t *data = NULL;
    size_t data_bytes = 0;

    (void)opaque;
    if (envelope->message_type != WVM_ENVELOPE_MSG_BLOCK_ACK) {
        fail("service emitted a non-ACK block envelope");
        return -1;
    }
    if (wvm_block_completion_decode(envelope->payload, envelope->payload_bytes,
                                    &completion, &data, &data_bytes, error,
                                    error_len) != 0) {
        fail("completion payload did not decode");
        return -1;
    }
    pthread_mutex_lock(&g_capture.lock);
    g_capture.sends++;
    g_capture.last_status = completion.status;
    g_capture.last_bytes = data_bytes;
    if (data_bytes <= sizeof(g_capture.last_data))
        memcpy(g_capture.last_data, data, data_bytes);
    pthread_mutex_unlock(&g_capture.lock);
    return 0;
}

static void fill_operation_id(uint8_t operation_id[16], unsigned int seed,
                              unsigned int variant)
{
    memset(operation_id, 0, 16);
    operation_id[0] = (uint8_t)seed;
    operation_id[1] = (uint8_t)(seed >> 8);
    operation_id[2] = (uint8_t)variant;
    operation_id[15] = 0x5a;
}

struct request_builder {
    struct wvm_envelope envelope;
    struct wvm_block_request request;
    uint8_t payload[WVM_BLOCK_REQUEST_HEADER_BYTES + TEST_BYTES];
};

static void build_request(struct request_builder *builder, uint16_t operation,
                          uint32_t flags, uint64_t lba_512,
                          uint32_t sector_count, const uint8_t *data,
                          size_t data_bytes, unsigned int seed,
                          unsigned int variant, uint32_t queue_id,
                          uint32_t sequence)
{
    size_t payload_bytes = 0;

    memset(builder, 0, sizeof(*builder));
    builder->request.payload_version = WVM_BLOCK_WIRE_VERSION;
    builder->request.operation = operation;
    builder->request.flags = flags;
    builder->request.lba_512 = lba_512;
    builder->request.sector_count = sector_count;
    builder->request.payload_bytes = (uint32_t)data_bytes;
    builder->request.reply_destination_kind = 1;
    builder->request.reply_destination_scope = 0;
    builder->request.reply_destination_vnode = TEST_REPLY_VNODE;
    builder->request.queue_id = queue_id;
    builder->request.queue_sequence = sequence;
    builder->request.device_index = 2;

    if (wvm_block_request_encode(&builder->request, data, data_bytes,
                                 builder->payload, sizeof(builder->payload),
                                 &payload_bytes, NULL, 0) != 0) {
        fail("request did not encode");
        return;
    }

    builder->envelope.message_type =
        operation == WVM_BLOCK_OPERATION_READ
            ? WVM_ENVELOPE_MSG_BLOCK_READ
            : operation == WVM_BLOCK_OPERATION_WRITE
                  ? WVM_ENVELOPE_MSG_BLOCK_WRITE
                  : WVM_ENVELOPE_MSG_BLOCK_FLUSH;
    builder->envelope.vm_id = TEST_VM_ID;
    builder->envelope.vm_incarnation = TEST_INCARNATION;
    builder->envelope.manifest_generation = TEST_GENERATION;
    builder->envelope.origin_physical_node_id = 3;
    builder->envelope.origin_runtime_instance_id = 4;
    fill_operation_id(builder->envelope.operation_id, seed, variant);
    builder->envelope.delivery_attempt_id = 1;
    builder->envelope.route_scope_id = 9;
    builder->envelope.topology_revision = 2;
    builder->envelope.route_generation = 1;
    memset(builder->envelope.route_snapshot_digest, 0x42, 32);
    builder->envelope.route.destination_kind = 1;
    builder->envelope.route.destination_vnode_or_endpoint = TEST_REPLY_VNODE;
    builder->envelope.route.hop_limit = 8;
    builder->envelope.payload = builder->payload;
    builder->envelope.payload_bytes = payload_bytes;
    wvm_envelope_semantic_digest(builder->payload, payload_bytes,
                                 builder->envelope.semantic_payload_digest);
}

static int dispatch(struct wvm_block_service *service,
                    struct request_builder *builder)
{
    char error[160] = {0};
    int rc = wvm_block_service_dispatch(service, &builder->envelope, error,
                                        sizeof(error));
    if (rc != 0 && error[0] != '\0')
        fprintf(stderr, "  dispatch error: %s\n", error);
    return rc;
}

struct concurrent_arg {
    struct wvm_block_service *service;
    struct request_builder *builder;
    int result;
};

static void *concurrent_dispatch(void *opaque)
{
    struct concurrent_arg *arg = opaque;
    arg->result = dispatch(arg->service, arg->builder);
    return NULL;
}

static void configure(struct wvm_block_service_config *config,
                      uint32_t retention_ms)
{
    memset(config, 0, sizeof(*config));
    config->vm_id = TEST_VM_ID;
    config->vm_incarnation = TEST_INCARNATION;
    config->manifest_generation = TEST_GENERATION;
    config->local_physical_node_id = TEST_LOCAL_NODE;
    config->local_runtime_instance_id = TEST_LOCAL_RUNTIME;
    config->retention_ms = retention_ms;
    config->execute = execute_block;
    config->resolve_route = resolve_route;
    config->send_envelope = send_envelope;
}

int main(void)
{
    const char *tmp_root = getenv("TMPDIR");
    char directory[512];
    struct wvm_block_service service;
    struct wvm_block_service service_pressure;
    struct wvm_block_service service_expiry;
    struct wvm_block_service_config config;
    char error[160] = {0};
    struct request_builder first;
    struct request_builder duplicate;
    struct request_builder concurrent_a;
    struct request_builder concurrent_b;
    struct request_builder write_req;
    struct request_builder flush_req;
    struct request_builder reread;
    struct request_builder conflict;
    struct request_builder invalid;
    struct request_builder gap;
    struct request_builder ordered;
    uint8_t pattern[TEST_BYTES];
    uint8_t written[TEST_BYTES];
    unsigned int baseline;
    pthread_t threads[2];
    struct concurrent_arg args[2];
    uint8_t guard[WVM_BLOCK_REQUEST_HEADER_BYTES + 2];
    size_t encoded = 0;
    unsigned int i;

    snprintf(directory, sizeof(directory), "%s/wavevm-block-service-XXXXXX",
             tmp_root && tmp_root[0] ? tmp_root : "/tmp");
    if (!mkdtemp(directory)) {
        fprintf(stderr, "block-service FAIL: cannot create temp dir\n");
        return 1;
    }
    if (wvm_block_chunk_store_set_dir(directory, error, sizeof(error)) != 0) {
        fprintf(stderr, "block-service FAIL: chunk dir: %s\n", error);
        return 1;
    }
    if (wvm_block_chunk_store_set_identity("svc-test", error, sizeof(error)) !=
        0) {
        fprintf(stderr, "block-service FAIL: chunk identity: %s\n", error);
        return 1;
    }
    pthread_mutex_init(&g_capture.lock, NULL);
    pthread_mutex_init(&g_execute.lock, NULL);

    configure(&config, 0);
    if (wvm_block_service_init(&service, &config, error, sizeof(error)) != 0) {
        fprintf(stderr, "block-service FAIL: init: %s\n", error);
        return 1;
    }

    for (i = 0; i < TEST_BYTES; i++)
        pattern[i] = (uint8_t)(i * 7U + 3U);
    if (wvm_block_chunk_write(0, TEST_SECTORS, pattern, sizeof(pattern), 1,
                              error, sizeof(error)) != 0) {
        fprintf(stderr, "block-service FAIL: seed write: %s\n", error);
        return 1;
    }

    /* 1. First READ executes once and returns the stored bytes. */
    build_request(&first, WVM_BLOCK_OPERATION_READ, 0, 0, TEST_SECTORS, NULL,
                  0, 1, 0, 1, 1);
    expect(dispatch(&service, &first) == 0, "first READ dispatched");
    expect(g_capture.sends == 1, "first READ sent one completion");
    expect(g_capture.last_status == WVM_BLOCK_WIRE_SUCCESS,
           "first READ succeeded");
    expect(g_capture.last_bytes == TEST_BYTES, "first READ returned full data");
    expect(memcmp(g_capture.last_data, pattern, TEST_BYTES) == 0,
           "first READ returned the stored bytes");
    expect(g_execute.calls == 1, "first READ executed exactly once");

    /* 2. Duplicate READ returns the retained result without re-executing. */
    build_request(&duplicate, WVM_BLOCK_OPERATION_READ, 0, 0, TEST_SECTORS,
                  NULL, 0, 1, 0, 1, 1);
    expect(dispatch(&service, &duplicate) == 0, "duplicate READ dispatched");
    expect(g_capture.sends == 2, "duplicate READ sent a completion");
    expect(g_capture.last_bytes == TEST_BYTES, "duplicate READ kept the data");
    expect(memcmp(g_capture.last_data, pattern, TEST_BYTES) == 0,
           "duplicate READ replayed the original bytes");
    expect(g_execute.calls == 1, "duplicate READ did not re-execute");

    /* 3. Concurrent duplicates: one execution, both requests completed. */
    g_execute.sleep_ms = 200;
    build_request(&concurrent_a, WVM_BLOCK_OPERATION_READ, 0, 0, TEST_SECTORS,
                  NULL, 0, 2, 0, 1, 2);
    build_request(&concurrent_b, WVM_BLOCK_OPERATION_READ, 0, 0, TEST_SECTORS,
                  NULL, 0, 2, 0, 1, 2);
    args[0].service = &service;
    args[0].builder = &concurrent_a;
    args[0].result = -1;
    args[1].service = &service;
    args[1].builder = &concurrent_b;
    args[1].result = -1;
    pthread_create(&threads[0], NULL, concurrent_dispatch, &args[0]);
    pthread_create(&threads[1], NULL, concurrent_dispatch, &args[1]);
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    g_execute.sleep_ms = 0;
    expect(args[0].result == 0 && args[1].result == 0,
           "concurrent duplicates both completed");
    expect(g_execute.calls == 2, "concurrent duplicates executed once");
    expect(g_capture.sends == 4, "concurrent duplicates both sent completions");

    /* 4. WRITE with FUA + FLUSH, then read the written range back. */
    for (i = 0; i < TEST_BYTES; i++)
        written[i] = (uint8_t)(0xa5U ^ (i & 0xffU));
    build_request(&write_req, WVM_BLOCK_OPERATION_WRITE, WVM_BLOCK_ORDER_FUA,
                  64, TEST_SECTORS, written, sizeof(written), 3, 0, 1, 3);
    expect(dispatch(&service, &write_req) == 0, "WRITE dispatched");
    expect(g_capture.last_status == WVM_BLOCK_WIRE_SUCCESS, "WRITE succeeded");
    expect((g_execute.last_flags & WVM_BLOCK_ORDER_FUA) != 0,
           "executor observed the FUA ordering flag");
    expect(g_execute.last_device == 2,
           "executor observed the admitted device identity");
    build_request(&flush_req, WVM_BLOCK_OPERATION_FLUSH, 0, 64, TEST_SECTORS,
                  NULL, 0, 4, 0, 1, 4);
    expect(dispatch(&service, &flush_req) == 0, "FLUSH dispatched");
    expect(g_capture.last_status == WVM_BLOCK_WIRE_SUCCESS, "FLUSH succeeded");
    build_request(&reread, WVM_BLOCK_OPERATION_READ, 0, 64, TEST_SECTORS, NULL,
                  0, 5, 0, 1, 5);
    expect(dispatch(&service, &reread) == 0, "re-READ dispatched");
    expect(g_capture.last_bytes == TEST_BYTES &&
               memcmp(g_capture.last_data, written, TEST_BYTES) == 0,
           "re-READ returned the written bytes");

    /* 5. Reusing an operation id with different bytes is rejected. */
    baseline = g_execute.calls;
    build_request(&conflict, WVM_BLOCK_OPERATION_READ, 0, 16, TEST_SECTORS,
                  NULL, 0, 1, 0, 1, 6);
    expect(dispatch(&service, &conflict) == 0, "conflict completion delivered");
    expect(g_capture.last_status == WVM_BLOCK_WIRE_CONFLICT,
           "conflicting reuse completion says CONFLICT");
    expect(g_execute.calls == baseline,
           "conflicting reuse never reaches the executor");

    /*
     * 6. Per-queue ordering: the head executes, a gap is retryable
     * backpressure, and the missing predecessor then runs in order.
     */
    baseline = g_execute.calls;
    build_request(&ordered, WVM_BLOCK_OPERATION_READ, 0, 0, TEST_SECTORS, NULL,
                  0, 9, 0, 2, 1);
    expect(dispatch(&service, &ordered) == 0, "queue head executes");
    build_request(&gap, WVM_BLOCK_OPERATION_READ, 0, 0, TEST_SECTORS, NULL, 0, 8,
                  0, 2, 3);
    expect(dispatch(&service, &gap) == -EAGAIN, "sequence gap is backpressure");
    expect(g_execute.calls == baseline + 1, "sequence gap did not execute");
    build_request(&gap, WVM_BLOCK_OPERATION_READ, 0, 0, TEST_SECTORS, NULL, 0, 8,
                  0, 2, 2);
    expect(dispatch(&service, &gap) == 0, "the queued successor now executes");

    /* 7. Exact header capacity writes nothing past the declared end. */
    memset(guard, 0xa5, sizeof(guard));
    memset(&ordered.request, 0, sizeof(ordered.request));
    ordered.request.payload_version = WVM_BLOCK_WIRE_VERSION;
    ordered.request.operation = WVM_BLOCK_OPERATION_FLUSH;
    ordered.request.sector_count = 1;
    ordered.request.reply_destination_vnode = TEST_REPLY_VNODE;
    ordered.request.queue_sequence = 1;
    expect(wvm_block_request_encode(&ordered.request, NULL, 0, guard,
                                    WVM_BLOCK_REQUEST_HEADER_BYTES, &encoded,
                                    NULL, 0) == 0,
           "exact-capacity encode succeeds");
    expect(encoded == WVM_BLOCK_REQUEST_HEADER_BYTES,
           "exact-capacity encode reports the header size");
    expect(guard[WVM_BLOCK_REQUEST_HEADER_BYTES] == 0xa5 &&
               guard[WVM_BLOCK_REQUEST_HEADER_BYTES + 1] == 0xa5,
           "encode did not write past the header");

    /* 8. Malformed request never reaches the executor or the wire. */
    baseline = g_capture.sends;
    memset(&invalid, 0, sizeof(invalid));
    invalid.payload[1] = WVM_BLOCK_WIRE_VERSION;
    invalid.payload[3] = WVM_BLOCK_OPERATION_READ;
    invalid.envelope.message_type = WVM_ENVELOPE_MSG_BLOCK_READ;
    invalid.envelope.vm_id = TEST_VM_ID;
    invalid.envelope.vm_incarnation = TEST_INCARNATION;
    invalid.envelope.manifest_generation = TEST_GENERATION;
    invalid.envelope.origin_physical_node_id = 3;
    invalid.envelope.origin_runtime_instance_id = 4;
    fill_operation_id(invalid.envelope.operation_id, 10, 0);
    invalid.envelope.delivery_attempt_id = 1;
    invalid.envelope.route_scope_id = 9;
    invalid.envelope.route_generation = 1;
    invalid.envelope.route.hop_limit = 8;
    invalid.envelope.payload = invalid.payload;
    invalid.envelope.payload_bytes = WVM_BLOCK_REQUEST_HEADER_BYTES;
    wvm_envelope_semantic_digest(invalid.payload, invalid.envelope.payload_bytes,
                                 invalid.envelope.semantic_payload_digest);
    expect(dispatch(&service, &invalid) != 0, "malformed READ is rejected");
    expect(g_capture.sends == baseline,
           "malformed READ never produced a completion");

    /*
     * 9. Table pressure must reject new work BEFORE executing it and must not
     * sacrifice a completed operation inside its retention window.
     */
    configure(&config, 0);
    if (wvm_block_service_init(&service_pressure, &config, error,
                               sizeof(error)) != 0) {
        fprintf(stderr, "block-service FAIL: pressure init: %s\n", error);
        return 1;
    }
    baseline = g_execute.calls;
    for (i = 0; i < WVM_BLOCK_SERVICE_MAX_ENTRIES; i++) {
        build_request(&write_req, WVM_BLOCK_OPERATION_WRITE, 0, 256 + i, 1,
                      written, WVM_BLOCK_SECTOR_BYTES, 100 + i, 0, 7,
                      i + 1);
        if (dispatch(&service_pressure, &write_req) != 0) {
            fail("pressure fill rejected a request that should fit");
            break;
        }
    }
    expect(g_execute.calls == baseline + WVM_BLOCK_SERVICE_MAX_ENTRIES,
           "table filled with exactly one execution per operation");
    build_request(&write_req, WVM_BLOCK_OPERATION_WRITE, 0, 999, 1, written,
                  WVM_BLOCK_SECTOR_BYTES, 500, 0, 7,
                  WVM_BLOCK_SERVICE_MAX_ENTRIES + 1);
    baseline = g_execute.calls;
    expect(dispatch(&service_pressure, &write_req) == -EAGAIN,
           "full table returns backpressure");
    expect(g_execute.calls == baseline,
           "full table never executed the rejected write");
    build_request(&write_req, WVM_BLOCK_OPERATION_WRITE, 0, 256, 1, written,
                  WVM_BLOCK_SECTOR_BYTES, 100, 0, 7, 1);
    expect(dispatch(&service_pressure, &write_req) == 0,
           "retry of the first write is answered from retention");
    expect(g_execute.calls == baseline,
           "retry of the first write was not executed again");

    /*
     * 10. After the result window the identity is a tombstone: the retry is
     * told the result expired and is never re-executed.
     */
    configure(&config, 50);
    if (wvm_block_service_init(&service_expiry, &config, error,
                               sizeof(error)) != 0) {
        fprintf(stderr, "block-service FAIL: expiry init: %s\n", error);
        return 1;
    }
    build_request(&write_req, WVM_BLOCK_OPERATION_WRITE, 0, 4096, 1, written,
                  WVM_BLOCK_SECTOR_BYTES, 700, 0, 8, 1);
    expect(dispatch(&service_expiry, &write_req) == 0, "expiry WRITE dispatched");
    baseline = g_execute.calls;
    {
        struct timespec delay = {0, 120000000L};
        nanosleep(&delay, NULL);
    }
    build_request(&write_req, WVM_BLOCK_OPERATION_WRITE, 0, 4096, 1, written,
                  WVM_BLOCK_SECTOR_BYTES, 700, 0, 8, 1);
    expect(dispatch(&service_expiry, &write_req) == 0,
           "expired retry still receives a typed completion");
    expect(g_capture.last_status == WVM_BLOCK_WIRE_EXPIRED,
           "expired retry reports EXPIRED");
    expect(g_execute.calls == baseline,
           "expired retry was not executed again");

    wvm_block_service_destroy(&service);
    wvm_block_service_destroy(&service_pressure);
    wvm_block_service_destroy(&service_expiry);
    pthread_mutex_destroy(&g_capture.lock);
    pthread_mutex_destroy(&g_execute.lock);
    if (g_failures == 0) {
        printf("block-service: PASS (READ/replay/concurrent/FUA/conflict/"
               "ordering/capacity/expiry)\n");
        return 0;
    }
    return 1;
}

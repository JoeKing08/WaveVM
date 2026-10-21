/* R02 flat/fractal storage contract.
 *
 * Drives the real block client/service pair through the real route runtime and
 * the real canonical envelope.  Storage and reply leaves are resolved by the
 * same function the node runtime uses
 * (wvm_route_runtime_lookup_destination) against a FLAT exact-vnode snapshot
 * and a FRACTAL scoped-vnode snapshot.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "block_client.h"
#include "block_service.h"
#include "wavevm_block_chunk_store.h"
#include "wavevm_block_wire.h"
#include "wavevm_control.h"
#include "wavevm_envelope.h"
#include "wavevm_membership.h"
#include "wavevm_route_runtime.h"

#define VM_ID 7U
#define INCARNATION 0x1122334455667788ULL
#define GENERATION 3ULL
#define SCOPE_ID 9ULL
#define TOPOLOGY_REV 2ULL
#define ROUTE_GEN 1ULL
#define DEVICE 0U
#define STORAGE_NODE 11U
#define STORAGE_INSTANCE 33ULL
#define REQUESTER_NODE 3U
#define REQUESTER_RUNTIME 4U
#define SECTORS 8U
#define BYTES (SECTORS * 512U)

struct route_context {
    struct wvm_route_runtime *runtime;
    const struct wvm_route_snapshot_key *key;
};

struct topology_case {
    const char *name;
    uint16_t topology_kind;
    uint16_t storage_envelope_kind;
    uint64_t storage_scope;
    uint32_t storage_vnode;
    uint16_t local_envelope_kind;
    uint64_t local_scope;
    uint32_t local_vnode;
    uint16_t local_rule_kind;
};

static struct wvm_block_client g_client;
static struct wvm_block_service g_service;
static struct wvm_envelope_route g_seen_route;
static int g_seen_route_valid;
static int g_failures;

static void fail(const char *message)
{
    fprintf(stderr, "block-topology FAIL: %s\n", message);
    g_failures++;
}

static void expect(int condition, const char *message)
{
    if (!condition)
        fail(message);
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

static void fill_rule(struct wvm_route_rule_record *rule, uint16_t kind,
                      uint64_t scope, uint32_t vnode, uint8_t address_tail,
                      uint16_t port)
{
    memset(rule, 0, sizeof(*rule));
    rule->destination_kind = kind;
    rule->destination_scope = scope;
    rule->destination_vnode_or_endpoint = vnode;
    rule->next_hop_kind = WVM_ROUTE_NEXT_HOP_ENDPOINT;
    rule->next_hop_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    rule->next_hop_member.role_id = address_tail;
    rule->next_hop_member.instance_id = 1000U + address_tail;
    fill_endpoint(&rule->next_hop_endpoint, address_tail, port);
    rule->hop_limit = 8;
}

static int finalize_snapshot(struct wvm_route_snapshot_record *snapshot,
                             struct wvm_route_rule_record *rules,
                             size_t rule_count,
                             struct wvm_required_ack_entry *ack,
                             uint16_t topology_kind, char *error,
                             size_t error_len)
{
    uint8_t bytes[16384];
    uint8_t digest[WVM_SHA256_DIGEST_BYTES];
    size_t encoded = 0;

    memset(snapshot, 0, sizeof(*snapshot));
    memset(ack, 0, sizeof(*ack));
    snapshot->route_snapshot_key.scope_key.vm_id = VM_ID;
    snapshot->route_snapshot_key.scope_key.vm_incarnation = INCARNATION;
    snapshot->route_snapshot_key.scope_key.route_scope_id = SCOPE_ID;
    snapshot->route_snapshot_key.topology_revision = TOPOLOGY_REV;
    snapshot->route_snapshot_key.route_generation = ROUTE_GEN;
    snapshot->membership_revision = TOPOLOGY_REV;
    snapshot->topology_kind = topology_kind;
    snapshot->next_hop_rules.entries = rules;
    snapshot->next_hop_rules.count = rule_count;
    snapshot->next_hop_rules.capacity = rule_count;
    snapshot->required_ack_set.entries.entries = ack;
    snapshot->required_ack_set.entries.count = 1;
    snapshot->required_ack_set.entries.capacity = 1;
    snapshot->operation_retention_horizon_ms = 5000;
    snapshot->retirement_policy = 1;

    ack->member_key = rules[0].next_hop_member;
    ack->endpoint = rules[0].next_hop_endpoint;
    ack->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    ack->expected_snapshot_key = snapshot->route_snapshot_key;
    if (wvm_route_snapshot_record_encode(snapshot, bytes, sizeof(bytes),
                                         &encoded, digest, error,
                                         error_len) != 0)
        return -1;
    memcpy(snapshot->route_snapshot_key.snapshot_digest, digest,
           sizeof(digest));
    memcpy(ack->expected_snapshot_key.snapshot_digest, digest, sizeof(digest));
    return wvm_route_snapshot_record_validate(snapshot, error, error_len);
}

static int resolve_route(void *opaque, uint16_t destination_kind,
                         uint64_t destination_scope,
                         uint32_t destination_vnode,
                         struct wvm_envelope_route *route, char *error,
                         size_t error_len)
{
    struct route_context *context = opaque;
    struct wvm_route_runtime_next_hop next_hop;

    if (wvm_route_runtime_lookup_destination(
            context->runtime, context->key, destination_kind,
            destination_scope, destination_vnode, &next_hop, error,
            error_len) != 0)
        return -1;
    memset(route, 0, sizeof(*route));
    route->destination_kind = destination_kind;
    route->destination_scope = destination_scope;
    route->destination_vnode_or_endpoint = destination_vnode;
    route->hop_limit = next_hop.hop_limit;
    return 0;
}

static int execute_block(void *opaque, uint32_t device_index,
                         uint16_t operation, uint32_t flags, uint64_t lba_512,
                         uint32_t sector_count, const uint8_t *data,
                         size_t data_bytes, uint8_t *out, size_t out_capacity,
                         size_t *out_bytes, char *error, size_t error_len)
{
    (void)opaque;
    if (device_index != DEVICE) {
        if (error && error_len)
            snprintf(error, error_len, "unexpected device %u", device_index);
        return -1;
    }
    if (operation == WVM_BLOCK_OPERATION_READ)
        return wvm_block_chunk_read(lba_512, sector_count, out, out_capacity,
                                    out_bytes, error, error_len);
    if (operation == WVM_BLOCK_OPERATION_WRITE) {
        int rc = wvm_block_chunk_write(lba_512, sector_count, data, data_bytes,
                                       (flags & WVM_BLOCK_ORDER_FUA) != 0,
                                       error, error_len);
        *out_bytes = 0;
        return rc;
    }
    *out_bytes = 0;
    return wvm_block_chunk_flush_range(lba_512, sector_count, error, error_len);
}

static int service_send(void *opaque, const struct wvm_envelope *envelope,
                        char *error, size_t error_len)
{
    (void)opaque;
    return wvm_block_client_dispatch_ack(&g_client, envelope, error,
                                         error_len);
}

static int client_send(void *opaque, const struct wvm_envelope *envelope,
                       char *error, size_t error_len)
{
    (void)opaque;
    g_seen_route = envelope->route;
    g_seen_route_valid = 1;
    return wvm_block_service_dispatch(&g_service, envelope, error, error_len);
}

static int run_case(const struct topology_case *test_case)
{
    struct wvm_route_runtime runtime;
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry ack;
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_runtime_storage_dispatch storage;
    struct wvm_block_service_config service_config;
    struct wvm_block_client_config client_config;
    struct route_context route_context;
    char error[256] = {0};
    char identity[64];
    uint8_t written[BYTES];
    uint8_t readback[BYTES];
    size_t out_bytes = 0;
    uint16_t status = 0;
    unsigned int i;

    snprintf(identity, sizeof(identity), "topo-%s", test_case->name);
    if (wvm_block_chunk_store_set_identity(identity, error, sizeof(error)) !=
        0) {
        fail("chunk identity");
        return -1;
    }

    /*
     * Snapshot rules are canonical and must be ordered by destination.  The
     * local reply leaf sorts before the storage leaf in both topologies.
     */
    fill_rule(&rules[0], test_case->local_rule_kind, test_case->local_scope,
              test_case->local_vnode, 10, 9400);
    fill_rule(&rules[1], WVM_ROUTE_DESTINATION_EXACT_VNODE,
              test_case->storage_scope, test_case->storage_vnode, 20, 9500);
    if (finalize_snapshot(&snapshot, rules, 2, &ack, test_case->topology_kind,
                          error, sizeof(error)) != 0) {
        fprintf(stderr, "block-topology %s: snapshot: %s\n", test_case->name,
                error);
        fail("snapshot build");
        return -1;
    }

    wvm_route_runtime_init(&runtime);
    if (wvm_route_runtime_prepare(&runtime, &snapshot, error,
                                  sizeof(error)) != 0 ||
        wvm_route_runtime_activate(&runtime,
                                   &snapshot.route_snapshot_key, error,
                                   sizeof(error)) != 0) {
        fprintf(stderr, "block-topology %s: activate: %s\n", test_case->name,
                error);
        fail("snapshot activate");
        wvm_route_runtime_destroy(&runtime);
        return -1;
    }

    memset(&projection, 0, sizeof(projection));
    projection.vm_id = VM_ID;
    projection.vm_incarnation = INCARNATION;
    projection.manifest_generation = GENERATION;
    projection.local_primary.destination_kind = test_case->local_envelope_kind;
    projection.local_primary.destination_scope = test_case->local_scope;
    projection.local_primary.destination_vnode = test_case->local_vnode;
    projection.required_route_snapshot_key = snapshot.route_snapshot_key;
    memset(&storage, 0, sizeof(storage));
    storage.device_index = DEVICE;
    storage.storage_physical_node_id = STORAGE_NODE;
    storage.storage_node_instance_id = STORAGE_INSTANCE;
    storage.storage.destination_kind = test_case->storage_envelope_kind;
    storage.storage.destination_scope = test_case->storage_scope;
    storage.storage.destination_vnode = test_case->storage_vnode;
    projection.storage_dispatch.entries = &storage;
    projection.storage_dispatch.count = 1;
    projection.storage_dispatch.capacity = 1;

    route_context.runtime = &runtime;
    route_context.key = &snapshot.route_snapshot_key;

    memset(&service_config, 0, sizeof(service_config));
    service_config.vm_id = VM_ID;
    service_config.vm_incarnation = INCARNATION;
    service_config.manifest_generation = GENERATION;
    service_config.local_physical_node_id = STORAGE_NODE;
    service_config.local_runtime_instance_id = STORAGE_INSTANCE;
    service_config.execute = execute_block;
    service_config.resolve_route = resolve_route;
    service_config.send_envelope = service_send;
    service_config.opaque = &route_context;
    service_config.scope_opaque = &route_context;
    if (wvm_block_service_init(&g_service, &service_config, error,
                               sizeof(error)) != 0) {
        fail("service init");
        wvm_route_runtime_destroy(&runtime);
        return -1;
    }
    memset(&client_config, 0, sizeof(client_config));
    client_config.dispatch = &projection;
    client_config.local_physical_node_id = REQUESTER_NODE;
    client_config.local_runtime_instance_id = REQUESTER_RUNTIME;
    client_config.timeout_ms = 2000;
    client_config.send_envelope = client_send;
    client_config.resolve_route = resolve_route;
    client_config.opaque = &route_context;
    client_config.scope_opaque = &route_context;
    if (wvm_block_client_init(&g_client, &client_config, error,
                              sizeof(error)) != 0) {
        fail("client init");
        wvm_block_service_destroy(&g_service);
        wvm_route_runtime_destroy(&runtime);
        return -1;
    }

    for (i = 0; i < BYTES; i++)
        written[i] =
            (uint8_t)(i ^ (test_case->topology_kind == 1 ? 0x11 : 0x77));
    g_seen_route_valid = 0;
    expect(wvm_block_client_request(&g_client, DEVICE, WVM_BLOCK_OPERATION_WRITE,
                                    WVM_BLOCK_ORDER_FUA, 0, SECTORS, written,
                                    sizeof(written), NULL, 0, &out_bytes,
                                    &status, error, sizeof(error)) == 0,
           "topology WRITE completed");
    expect(status == WVM_BLOCK_WIRE_SUCCESS, "topology WRITE succeeded");
    expect(g_seen_route_valid &&
               g_seen_route.destination_kind ==
                   test_case->storage_envelope_kind &&
               g_seen_route.destination_scope == test_case->storage_scope &&
               g_seen_route.destination_vnode_or_endpoint ==
                   test_case->storage_vnode,
           "request envelope carried the admitted route leaf");

    memset(readback, 0, sizeof(readback));
    expect(wvm_block_client_request(&g_client, DEVICE, WVM_BLOCK_OPERATION_READ,
                                    0, 0, SECTORS, NULL, 0, readback,
                                    sizeof(readback), &out_bytes, &status,
                                    error, sizeof(error)) == 0,
           "topology READ completed");
    expect(status == WVM_BLOCK_WIRE_SUCCESS, "topology READ succeeded");
    expect(out_bytes == BYTES && memcmp(readback, written, BYTES) == 0,
           "topology READ returned the written bytes");

    wvm_block_client_destroy(&g_client);
    wvm_block_service_destroy(&g_service);
    wvm_route_runtime_destroy(&runtime);
    return 0;
}

int main(void)
{
    const char *tmp_root = getenv("TMPDIR");
    char directory[512];
    char error[256] = {0};
    static const struct topology_case flat = {
        .name = "flat",
        .topology_kind = WVM_ROUTE_TOPOLOGY_FLAT,
        .storage_envelope_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE,
        .storage_scope = 0,
        .storage_vnode = 5,
        .local_envelope_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FLAT_VNODE,
        .local_scope = 0,
        .local_vnode = 1,
        .local_rule_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE,
    };
    static const struct topology_case fractal = {
        .name = "fractal",
        .topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL,
        .storage_envelope_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE,
        .storage_scope = 77,
        .storage_vnode = 9,
        .local_envelope_kind = WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE,
        .local_scope = 77,
        .local_vnode = 1,
        .local_rule_kind = WVM_ROUTE_DESTINATION_EXACT_VNODE,
    };

    snprintf(directory, sizeof(directory), "%s/wavevm-block-topo-XXXXXX",
             tmp_root && tmp_root[0] ? tmp_root : "/tmp");
    if (!mkdtemp(directory)) {
        fprintf(stderr, "block-topology FAIL: cannot create temp dir\n");
        return 1;
    }
    if (wvm_block_chunk_store_set_dir(directory, error, sizeof(error)) != 0) {
        fprintf(stderr, "block-topology FAIL: chunk dir: %s\n", error);
        return 1;
    }
    run_case(&flat);
    run_case(&fractal);
    if (g_failures == 0) {
        printf("block-topology: PASS (flat + fractal route leaves, "
               "client->service->executor->client)\n");
        return 0;
    }
    return 1;
}

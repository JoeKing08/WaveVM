/*
 * N05 directory / memory-service process.
 *
 * Owns a global V1 memory service, plants one ACTIVE subscriber for the
 * failed compute instance, then listens on a Unix socket for a 0x0307
 * envelope delivered by the ctl-side bridge.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_membership.h"
#include "memory_service.h"
#include "wavevm_memory.h"
#include "wavevm_route_runtime.h"
#include "wavevm_runtime_dispatch.h"
#include "wavevm_envelope.h"

#include "test_n05_subscriber_crossproc.h"

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "test_n05_directory: FAIL %s\n", msg);
        return 1;
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

static void fill_projection(struct wvm_runtime_dispatch_projection *projection,
                            struct wvm_runtime_memory_dispatch memory[2],
                            const struct wvm_route_snapshot_key *route_key)
{
    memset(projection, 0, sizeof(*projection));
    memset(projection->candidate_manifest_digest, 0x51,
           sizeof(projection->candidate_manifest_digest));
    projection->vm_id = 256;
    projection->vm_incarnation = 7;
    projection->manifest_generation = 3;
    projection->physical_node_id = N05_DIR_PHYS;
    projection->expected_node_instance_id = N05_DIR_INST;
    memset(projection->activation_fence, 0x52,
           sizeof(projection->activation_fence));
    projection->required_route_snapshot_key = *route_key;
    projection->route_topology_kind = WVM_ROUTE_TOPOLOGY_FRACTAL;
    projection->local_primary.destination_kind =
        WVM_ENVELOPE_ROUTE_DESTINATION_FRACTAL_VNODE;
    projection->local_primary.destination_scope = 41;
    projection->local_primary.destination_vnode = 0;
    fill_endpoint(&projection->local_sidecar_endpoint, (uint8_t)N05_DIR_PHYS,
                  19017);
    projection->memory_dispatch.entries = memory;
    projection->memory_dispatch.count = 2;
    projection->memory_dispatch.capacity = 2;
    memset(memory, 0, 2 * sizeof(*memory));
    memory[0].gpa_start = 0;
    memory[0].bytes = WVM_MEMORY_PAGE_BYTES;
    memory[0].directory = projection->local_primary;
    memory[0].executor = projection->local_primary;
    memory[0].directory_physical_node_id = N05_DIR_PHYS;
    memory[0].directory_node_instance_id = N05_DIR_INST;
    memory[0].consistency_policy = 1;
    memory[1] = memory[0];
    memory[1].gpa_start = WVM_MEMORY_PAGE_BYTES;
    memory[1].directory.destination_scope = 99;
    memory[1].directory.destination_vnode = 1;
    memory[1].executor = memory[1].directory;
    memory[1].directory_physical_node_id = 99;
    memory[1].directory_node_instance_id = 202;
}

static int read_page(void *opaque, uint64_t gpa,
                     uint8_t data[WVM_MEMORY_PAGE_BYTES],
                     uint64_t *version_out, char *error, size_t error_len)
{
    (void)opaque;
    (void)gpa;
    (void)error;
    (void)error_len;
    memset(data, 0xa5, WVM_MEMORY_PAGE_BYTES);
    if (version_out) {
        *version_out = 1;
    }
    return 0;
}

static int complete_fault(void *opaque,
                          const uint8_t operation_id[WVM_IDENTITY_ID_BYTES],
                          uint64_t gpa, uint64_t version, uint16_t status,
                          uint32_t directory_physical_node_id,
                          uint64_t directory_node_instance_id,
                          const uint8_t *data, size_t data_bytes, char *error,
                          size_t error_len)
{
    (void)opaque;
    (void)operation_id;
    (void)gpa;
    (void)version;
    (void)status;
    (void)directory_physical_node_id;
    (void)directory_node_instance_id;
    (void)data;
    (void)data_bytes;
    (void)error;
    (void)error_len;
    return 0;
}

static int send_envelope(void *opaque, const struct wvm_envelope *envelope,
                         char *error, size_t error_len)
{
    (void)opaque;
    (void)envelope;
    (void)error;
    (void)error_len;
    return 0;
}

/* Same bucket function as node_runtime/memory_service.c::subscriber_bucket. */
static size_t n05_subscriber_bucket(uint64_t gpa, size_t buckets)
{
    uint64_t page = gpa / WVM_MEMORY_PAGE_BYTES;

    page ^= page >> 33;
    page *= UINT64_C(0xff51afd7ed558ccd);
    page ^= page >> 33;
    return (size_t)(page & (buckets - 1));
}

static int plant_active_subscriber(struct wvm_memory_service *service,
                                   char *error, size_t error_len)
{
    struct wvm_memory_subscriber *subscriber;
    size_t bucket;

    if (!service || !service->initialized ||
        service->subscriber_bucket_count == 0 ||
        service->subscriber_limit == 0) {
        snprintf(error, error_len, "memory service subscriber table is empty");
        return -1;
    }
    subscriber = calloc(1, sizeof(*subscriber));
    if (!subscriber) {
        snprintf(error, error_len, "cannot allocate subscriber");
        return -1;
    }
    subscriber->gpa = N05_GPA;
    subscriber->subscriber_physical_node_id = N05_FAILED_PHYS;
    subscriber->subscriber_node_instance_id = N05_FAILED_INST;
    subscriber->subscriber_runtime_instance_id = N05_FAILED_RUNTIME;
    subscriber->state = WVM_MEMORY_SUBSCRIBER_ACTIVE;
    subscriber->qualification_revision = 1;
    subscriber->last_validated_at = 1;
    subscriber->subscription_id[0] = 0x05;
    pthread_mutex_lock(&service->subscriber_lock);
    bucket = n05_subscriber_bucket(N05_GPA, service->subscriber_bucket_count);
    subscriber->next = service->subscriber_buckets[bucket];
    service->subscriber_buckets[bucket] = subscriber;
    service->subscriber_count++;
    pthread_mutex_unlock(&service->subscriber_lock);
    return 0;
}

static uint32_t count_state_for_failed(struct wvm_memory_service *service,
                                       uint8_t state)
{
    uint32_t count = 0;
    size_t i;

    pthread_mutex_lock(&service->subscriber_lock);
    for (i = 0; i < service->subscriber_bucket_count; i++) {
        const struct wvm_memory_subscriber *s = service->subscriber_buckets[i];

        for (; s; s = s->next) {
            if (s->subscriber_physical_node_id == N05_FAILED_PHYS &&
                s->subscriber_node_instance_id == N05_FAILED_INST &&
                s->state == state) {
                count++;
            }
        }
    }
    pthread_mutex_unlock(&service->subscriber_lock);
    return count;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int write_text_file(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");

    if (!fp) {
        return -1;
    }
    if (fputs(text, fp) == EOF) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    const char *sock_path = getenv("N05_SOCK");
    const char *ready_path = getenv("N05_READY");
    const char *evid_path = getenv("N05_EVID");
    struct wvm_route_rule_record rules[2];
    struct wvm_required_ack_entry acks[1];
    struct wvm_route_snapshot_record snapshot;
    struct wvm_route_runtime routes;
    struct wvm_runtime_memory_dispatch memory[2];
    struct wvm_runtime_dispatch_projection projection;
    struct wvm_memory_service_config config;
    struct wvm_memory_service service;
    struct sockaddr_un addr;
    char error[256];
    char evid[1024];
    int listen_fd = -1;
    int client_fd = -1;
    int rc = 1;
    uint32_t active_before;
    uint32_t stale_after = 0;
    struct n05_wire_req req;
    struct n05_wire_ack ack;
    uint32_t failed_node = 0;
    uint64_t failed_instance = 0;
    int inv = 0;

    error[0] = '\0';
    if (!sock_path || !ready_path || !evid_path) {
        fprintf(stderr, "test_n05_directory: N05_SOCK/READY/EVID required\n");
        return 1;
    }

    fill_rule(&rules[0], 41, 0, N05_DIR_PHYS, N05_DIR_INST,
              (uint8_t)N05_DIR_PHYS);
    fill_rule(&rules[1], 99, 1, 99, 202, 99);
    if (finalize_snapshot(&snapshot, rules, acks, error, sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_directory: snapshot: %s\n", error);
        return 1;
    }
    fill_projection(&projection, memory, &snapshot.route_snapshot_key);
    if (expect(wvm_runtime_dispatch_projection_validate(
                   &projection, error, sizeof(error)) == 0,
               "admitted dispatch projection")) {
        return 1;
    }
    wvm_route_runtime_init(&routes);
    if (wvm_route_runtime_prepare(&routes, &snapshot, error, sizeof(error)) !=
            0 ||
        wvm_route_runtime_activate(&routes, &snapshot.route_snapshot_key, error,
                                   sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_directory: route: %s\n", error);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }

    memset(&config, 0, sizeof(config));
    config.dispatch = &projection;
    config.route_runtime = &routes;
    config.local_physical_node_id = N05_DIR_PHYS;
    config.local_node_instance_id = N05_DIR_INST;
    config.local_runtime_instance_id = N05_DIR_RUNTIME;
    config.completion_timeout_ms = 5000;
    config.read_page = read_page;
    config.complete_fault = complete_fault;
    config.send_envelope = send_envelope;
    if (wvm_memory_service_init(&service, &config, error, sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_directory: init: %s\n", error);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (wvm_memory_service_global_install(&service, error, sizeof(error)) !=
        0) {
        fprintf(stderr, "test_n05_directory: install: %s\n", error);
        wvm_memory_service_destroy(&service);
        wvm_route_runtime_destroy(&routes);
        return 1;
    }
    if (plant_active_subscriber(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_directory: plant: %s\n", error);
        goto out;
    }
    active_before = count_state_for_failed(&service, WVM_MEMORY_SUBSCRIBER_ACTIVE);
    if (expect(active_before == 1, "precondition: one ACTIVE failed-member lease")) {
        goto out;
    }
    fprintf(stderr,
            "test_n05_directory: planted ACTIVE subscriber failed=%u:%llu "
            "runtime=%llu pid=%d\n",
            N05_FAILED_PHYS, (unsigned long long)N05_FAILED_INST,
            (unsigned long long)N05_FAILED_RUNTIME, (int)getpid());

    unlink(sock_path);
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        goto out;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "test_n05_directory: sock path too long\n");
        goto out;
    }
    memcpy(addr.sun_path, sock_path, strlen(sock_path) + 1);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listen_fd, 4) != 0) {
        perror("bind/listen");
        goto out;
    }
    if (write_text_file(ready_path, "ready\n") != 0) {
        perror("ready");
        goto out;
    }

    /* Bounded wait: the ctl process should connect promptly after ready. */
    {
        struct timeval tv;
        fd_set rfds;
        int sel;

        tv.tv_sec = 15;
        tv.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        sel = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) {
            fprintf(stderr, "test_n05_directory: timed out waiting for 0x0307\n");
            snprintf(evid, sizeof(evid),
                     "EVID N05_directory_recv: timeout=1 pid=%d\n",
                     (int)getpid());
            write_text_file(evid_path, evid);
            goto out;
        }
    }
    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        goto out;
    }
    if (read_all(client_fd, &req, sizeof(req)) != 0) {
        fprintf(stderr, "test_n05_directory: short request\n");
        goto out;
    }
    if (req.magic != N05_MAGIC ||
        req.message_type != WVM_ENVELOPE_MSG_INVALIDATE_SUBSCRIBERS ||
        req.payload_bytes < 12) {
        fprintf(stderr,
                "test_n05_directory: bad request magic=0x%x type=0x%x bytes=%u\n",
                req.magic, req.message_type, req.payload_bytes);
        goto out;
    }
    failed_node = (uint32_t)req.payload[0] | ((uint32_t)req.payload[1] << 8) |
                  ((uint32_t)req.payload[2] << 16) |
                  ((uint32_t)req.payload[3] << 24);
    failed_instance = (uint64_t)req.payload[4] | ((uint64_t)req.payload[5] << 8) |
                      ((uint64_t)req.payload[6] << 16) |
                      ((uint64_t)req.payload[7] << 24) |
                      ((uint64_t)req.payload[8] << 32) |
                      ((uint64_t)req.payload[9] << 40) |
                      ((uint64_t)req.payload[10] << 48) |
                      ((uint64_t)req.payload[11] << 56);
    fprintf(stderr,
            "test_n05_directory: recv opcode=0x%04x failed=%u:%llu bytes=%u\n",
            (unsigned)req.message_type, (unsigned)failed_node,
            (unsigned long long)failed_instance, req.payload_bytes);

    /*
     * Production admission_receiver 0x0307 case calls this same function
     * with runtime_instance=0 and scope=NULL after decoding the 12-byte
     * payload. Linking the full receiver is avoided; the apply contract is
     * identical.
     */
    error[0] = '\0';
    inv = wvm_memory_service_global_invalidate_subscriber_instance(
        failed_node, failed_instance, 0, NULL, error, sizeof(error));
    stale_after = count_state_for_failed(&service, WVM_MEMORY_SUBSCRIBER_STALE);
    memset(&ack, 0, sizeof(ack));
    ack.magic = N05_MAGIC;
    ack.status = inv;
    ack.stale_count = stale_after;
    ack.directory_pid = (uint32_t)getpid();
    (void)write_all(client_fd, &ack, sizeof(ack));

    snprintf(evid, sizeof(evid),
             "EVID N05_directory_recv: opcode=0x%04x failed_node=%u "
             "failed_inst=%llu payload_bytes=%u pid=%d\n"
             "EVID N05_global_invalidate: rc=%d err=%s\n"
             "EVID N05_ACTIVE_to_STALE=%u\n",
             (unsigned)req.message_type, (unsigned)failed_node,
             (unsigned long long)failed_instance, req.payload_bytes,
             (int)getpid(), inv, error[0] ? error : "(none)", stale_after);
    if (write_text_file(evid_path, evid) != 0) {
        perror("evid");
        goto out;
    }
    fputs(evid, stdout);
    fflush(stdout);

    if (inv == 0 && stale_after >= 1 && failed_node == N05_FAILED_PHYS &&
        failed_instance == N05_FAILED_INST) {
        printf("test_n05_directory: PASS\n");
        rc = 0;
    } else {
        fprintf(stderr,
                "test_n05_directory: FAIL inv=%d stale=%u node=%u inst=%llu\n",
                inv, stale_after, (unsigned)failed_node,
                (unsigned long long)failed_instance);
    }

out:
    if (client_fd >= 0) {
        close(client_fd);
    }
    if (listen_fd >= 0) {
        close(listen_fd);
    }
    unlink(sock_path);
    wvm_memory_service_global_uninstall(&service);
    wvm_memory_service_destroy(&service);
    wvm_route_runtime_destroy(&routes);
    return rc;
}

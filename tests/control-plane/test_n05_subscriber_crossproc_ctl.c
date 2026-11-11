/*
 * N05 ctl-side process.
 *
 * Builds a real membership_controller with two ACTIVE compute members,
 * binds the production subscriber_invalidate_bridge, then marks the leaf
 * UNREACHABLE so the strong hook fans out 0x0307 to the directory process.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "wavevm_membership_controller.h"
#include "wavevm_admission_transport.h"
#include "wavevm_envelope.h"
#include "wavevm_canonical.h"

#include "../../ctl_tool/subscriber_invalidate_bridge.h"
#include "test_n05_subscriber_crossproc.h"

#define MIB (1024ULL * 1024ULL)

static int expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "test_n05_ctl: FAIL %s\n", msg);
        return 1;
    }
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authorize(void *context,
                     enum wvm_membership_controller_authorization_action action,
                     const struct wvm_member_key *actor,
                     const struct wvm_member_key *subject, char *error,
                     size_t error_len)
{
    (void)context;
    (void)action;
    (void)error;
    (void)error_len;
    return member_key_equal(actor, subject) ? 0 : -1;
}

static void fill_endpoint(struct wvm_endpoint *endpoint, uint8_t last_octet,
                          uint16_t data_port, uint16_t control_port)
{
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_address_bytes = 4;
    endpoint->data_address[0] = 192;
    endpoint->data_address[1] = 0;
    endpoint->data_address[2] = 2;
    endpoint->data_address[3] = last_octet;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->control_port = control_port;
}

static void fill_capability(struct wvm_capability_ref *capability,
                            uint32_t node_id, uint64_t instance,
                            uint8_t digest)
{
    memset(capability, 0, sizeof(*capability));
    capability->physical_node_id = node_id;
    capability->node_instance_id = instance;
    capability->profile_generation = 1;
    memset(capability->profile_digest, digest,
           sizeof(capability->profile_digest));
}

static void fill_node(struct wvm_node_record *node, uint32_t phys,
                      uint64_t inst, uint8_t last_octet, uint16_t data_port,
                      uint16_t control_port)
{
    memset(node, 0, sizeof(*node));
    node->physical_node_id = phys;
    node->node_instance_id = inst;
    node->failure_domain_id = 3;
    fill_endpoint(&node->control_endpoint, last_octet, data_port, control_port);
    fill_endpoint(&node->sidecar_endpoint, last_octet,
                  (uint16_t)(data_port + 20U), (uint16_t)(control_port + 20U));
    node->role_bits = 1;
    node->pod_id = 1;
    node->local_vnode_first = 0;
    node->local_vnode_count = 16;
    node->inventory.physical_node_id = phys;
    node->inventory.node_instance_id = inst;
    node->inventory.failure_domain_id = node->failure_domain_id;
    node->inventory.inventory_revision = 1;
    node->inventory.registered_vcpu_slots = 8;
    node->inventory.registered_memory_bytes = 16 * MIB;
    node->inventory.reserved_host_cpu_slots = 1;
    node->inventory.reserved_host_memory_bytes = 1 * MIB;
    node->inventory.reserved_gateway_cpu_slots = 1;
    node->inventory.reserved_gateway_memory_bytes = 1 * MIB;
    node->inventory.allocatable_vcpu_slots = 6;
    node->inventory.allocatable_memory_bytes = 14 * MIB;
    memset(node->inventory.storage_capabilities_digest, 0x11,
           sizeof(node->inventory.storage_capabilities_digest));
    memset(node->inventory.accelerator_fault_capabilities_digest, 0x12,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memset(node->inventory.exclusive_resource_inventory_digest, 0x13,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    fill_capability(&node->capability, phys, inst, 0x21);
    node->desired_membership_state = WVM_MANIFEST_MEMBER_ACTIVE;
    node->observed_health_state = WVM_MEMBERSHIP_HEALTHY;
    node->membership_revision = 1;
    node->topology_revision = 1;
    wvm_node_record_init_single_host_defaults(node);
}

static void node_key(const struct wvm_node_record *node,
                     struct wvm_member_key *key)
{
    memset(key, 0, sizeof(*key));
    key->role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    key->role_id = node->physical_node_id;
    key->instance_id = node->node_instance_id;
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

struct n05_transport_ctx {
    const char *sock_path;
    size_t sent;
    size_t failed;
    uint32_t last_type;
    uint32_t last_role;
    uint32_t ack_stale;
    uint32_t directory_pid;
    int saw_0307;
};

static int n05_transport_submit(void *context,
                                const struct wvm_admission_transport_target *target,
                                const struct wvm_envelope *envelope,
                                char *error, size_t error_len)
{
    struct n05_transport_ctx *ctx = context;
    struct sockaddr_un addr;
    struct n05_wire_req req;
    struct n05_wire_ack ack;
    int fd;
    int rc = -1;

    if (!ctx || !ctx->sock_path || !target || !envelope) {
        snprintf(error, error_len, "n05 transport is not initialized");
        return -EINVAL;
    }
    ctx->last_type = envelope->message_type;
    ctx->last_role = target->member_key.role_id;

    /*
     * Only the directory process is listening. Fanout to the failed leaf
     * is best-effort and should not stop the directory delivery.
     */
    if (target->member_key.role_id != N05_DIR_PHYS ||
        target->member_key.instance_id != N05_DIR_INST) {
        ctx->failed++;
        snprintf(error, error_len,
                 "no listener for node=%u inst=%llu (best-effort skip)",
                 (unsigned)target->member_key.role_id,
                 (unsigned long long)target->member_key.instance_id);
        return -EHOSTUNREACH;
    }

    memset(&req, 0, sizeof(req));
    req.magic = N05_MAGIC;
    req.message_type = envelope->message_type;
    req.payload_bytes =
        envelope->payload_bytes > sizeof(req.payload)
            ? (uint32_t)sizeof(req.payload)
            : (uint32_t)envelope->payload_bytes;
    if (envelope->payload && req.payload_bytes > 0) {
        memcpy(req.payload, envelope->payload, req.payload_bytes);
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ctx->failed++;
        snprintf(error, error_len, "socket: %s", strerror(errno));
        return -errno;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(ctx->sock_path) >= sizeof(addr.sun_path)) {
        close(fd);
        ctx->failed++;
        snprintf(error, error_len, "sock path too long");
        return -ENAMETOOLONG;
    }
    memcpy(addr.sun_path, ctx->sock_path, strlen(ctx->sock_path) + 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;

        close(fd);
        ctx->failed++;
        snprintf(error, error_len, "connect: %s", strerror(saved));
        return -saved;
    }
    if (write_all(fd, &req, sizeof(req)) != 0 ||
        read_all(fd, &ack, sizeof(ack)) != 0) {
        close(fd);
        ctx->failed++;
        snprintf(error, error_len, "short 0x0307 exchange");
        return -EIO;
    }
    close(fd);
    if (ack.magic != N05_MAGIC) {
        ctx->failed++;
        snprintf(error, error_len, "bad directory ack magic");
        return -EBADMSG;
    }
    ctx->sent++;
    ctx->ack_stale = ack.stale_count;
    ctx->directory_pid = ack.directory_pid;
    if (envelope->message_type == WVM_ENVELOPE_MSG_INVALIDATE_SUBSCRIBERS) {
        ctx->saw_0307 = 1;
    }
    rc = ack.status;
    if (rc != 0) {
        snprintf(error, error_len, "directory invalidate status=%d", rc);
    }
    fprintf(stderr,
            "test_n05_ctl: submit type=0x%x to %u:%llu rc=%d stale=%u "
            "dir_pid=%u\n",
            (unsigned)envelope->message_type,
            (unsigned)target->member_key.role_id,
            (unsigned long long)target->member_key.instance_id, rc,
            ack.stale_count, ack.directory_pid);
    return rc;
}

static int activate_two_nodes(struct wvm_membership_controller *controller,
                              const struct wvm_member_key *dir_member,
                              const struct wvm_endpoint *dir_endpoint,
                              const struct wvm_member_key *failed_member,
                              const struct wvm_endpoint *failed_endpoint,
                              char *error, size_t error_len)
{
    struct wvm_route_snapshot_key route_key;
    struct wvm_required_ack_entry entries[2];
    struct wvm_required_ack_entry decoded[2];
    struct wvm_required_ack_set source;
    struct wvm_required_ack_set ack_set;
    struct wvm_route_transaction_record transaction;
    uint8_t bytes[4096];
    size_t encoded_bytes;

    if (wvm_membership_controller_begin_validation(controller, dir_member,
                                                   error, error_len) != 0 ||
        wvm_membership_controller_begin_validation(controller, failed_member,
                                                   error, error_len) != 0) {
        return -1;
    }
    if (wvm_membership_controller_report_self_health(
            controller, dir_member, WVM_MEMBERSHIP_HEALTHY, error,
            error_len) != 0 ||
        wvm_membership_controller_report_self_health(
            controller, failed_member, WVM_MEMBERSHIP_HEALTHY, error,
            error_len) != 0) {
        return -1;
    }
    if (wvm_membership_controller_prepare_member(controller, dir_member, error,
                                                 error_len) != 0 ||
        wvm_membership_controller_prepare_member(controller, failed_member,
                                                 error, error_len) != 0) {
        return -1;
    }

    memset(&route_key, 0, sizeof(route_key));
    route_key.scope_key.vm_id = 256;
    route_key.scope_key.vm_incarnation = 1;
    route_key.scope_key.route_scope_id = 1;
    route_key.topology_revision = controller->topology_revision;
    route_key.route_generation = 1;
    memset(route_key.snapshot_digest, 0x5a, sizeof(route_key.snapshot_digest));

    /* required ACK entries must be strictly ordered by member_key. */
    memset(entries, 0, sizeof(entries));
    entries[0].member_key = *failed_member;
    entries[0].endpoint = *failed_endpoint;
    entries[0].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    entries[0].expected_snapshot_key = route_key;
    entries[1].member_key = *dir_member;
    entries[1].endpoint = *dir_endpoint;
    entries[1].role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    entries[1].expected_snapshot_key = route_key;
    memset(&source, 0, sizeof(source));
    source.entries.entries = entries;
    source.entries.count = 2;
    source.entries.capacity = 2;
    if (wvm_required_ack_set_encode(&source, bytes, sizeof(bytes),
                                    &encoded_bytes, error, error_len) != 0) {
        return -1;
    }
    memset(&ack_set, 0, sizeof(ack_set));
    ack_set.entries.entries = decoded;
    ack_set.entries.capacity = 2;
    if (wvm_required_ack_set_decode(bytes, encoded_bytes, &ack_set, error,
                                    error_len) != 0) {
        return -1;
    }

    memset(&transaction, 0, sizeof(transaction));
    transaction.operation_id[WVM_IDENTITY_ID_BYTES - 1] = 0x41;
    transaction.route_snapshot_key = route_key;
    transaction.required_ack_set = ack_set;
    transaction.operation_retention_horizon_ms = 5000;
    transaction.state = WVM_ROUTE_TRANSACTION_PREPARING;
    if (wvm_membership_controller_route_begin(controller, &transaction, error,
                                              error_len) != 0 ||
        wvm_membership_controller_route_ack_prepare(
            controller, transaction.operation_id, dir_member, error,
            error_len) != 0 ||
        wvm_membership_controller_route_ack_prepare(
            controller, transaction.operation_id, failed_member, error,
            error_len) != 0 ||
        wvm_membership_controller_route_commit(controller,
                                               transaction.operation_id, error,
                                               error_len) != 0 ||
        wvm_membership_controller_activate_member(
            controller, dir_member, transaction.operation_id, error,
            error_len) != 0 ||
        wvm_membership_controller_activate_member(
            controller, failed_member, transaction.operation_id, error,
            error_len) != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    const char *sock_path = getenv("N05_SOCK");
    const char *journal_path = getenv("N05_JOURNAL");
    struct wvm_membership_controller controller;
    struct wvm_membership_controller_member_entry members[4];
    struct wvm_membership_controller_route_entry routes[4];
    struct wvm_membership_dependency dependencies[4];
    struct wvm_node_record dir_node;
    struct wvm_node_record failed_node;
    struct wvm_member_key dir_member;
    struct wvm_member_key failed_member;
    struct wvm_node_record captured_nodes[4];
    struct wvm_gateway_record captured_gateways[2];
    uint32_t hosted_ids[4];
    uint32_t parent_ids[4];
    uint32_t child_ids[4];
    struct wvm_membership_controller_capture capture;
    struct wvm_admission_transport transport;
    struct n05_transport_ctx tctx;
    char error[256];
    int failed = 0;

    error[0] = '\0';
    if (!sock_path || !journal_path) {
        fprintf(stderr, "test_n05_ctl: N05_SOCK and N05_JOURNAL required\n");
        return 1;
    }

    fill_node(&dir_node, N05_DIR_PHYS, N05_DIR_INST, (uint8_t)N05_DIR_PHYS,
              19100, 19101);
    fill_node(&failed_node, N05_FAILED_PHYS, N05_FAILED_INST,
              (uint8_t)N05_FAILED_PHYS, 19200, 19201);
    node_key(&dir_node, &dir_member);
    node_key(&failed_node, &failed_member);

    memset(&controller, 0, sizeof(controller));
    memset(members, 0, sizeof(members));
    memset(routes, 0, sizeof(routes));
    memset(dependencies, 0, sizeof(dependencies));
    wvm_membership_controller_init(&controller, members, 4, routes, 4,
                                   dependencies, 4, authorize, NULL);
    if (wvm_membership_controller_open(&controller, journal_path, error,
                                       sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_ctl: open journal: %s\n", error);
        return 1;
    }
    if (wvm_membership_controller_register_node(&controller, &dir_member,
                                                &dir_node, error,
                                                sizeof(error)) != 0 ||
        wvm_membership_controller_register_node(&controller, &failed_member,
                                                &failed_node, error,
                                                sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_ctl: register: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }
    if (activate_two_nodes(&controller, &dir_member,
                           &dir_node.control_endpoint, &failed_member,
                           &failed_node.control_endpoint, error,
                           sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_ctl: activate: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }

    memset(&capture, 0, sizeof(capture));
    capture.nodes = captured_nodes;
    capture.node_capacity = 4;
    capture.gateways = captured_gateways;
    capture.gateway_capacity = 2;
    capture.hosted_gateway_role_ids = hosted_ids;
    capture.hosted_gateway_role_id_capacity = 4;
    capture.gateway_parent_ids = parent_ids;
    capture.gateway_parent_id_capacity = 4;
    capture.gateway_child_ids = child_ids;
    capture.gateway_child_id_capacity = 4;

    memset(&tctx, 0, sizeof(tctx));
    tctx.sock_path = sock_path;
    memset(&transport, 0, sizeof(transport));
    /* Bridge only uses submit+context; do not require full stream transport. */
    transport.controller_physical_node_id = 1;
    transport.controller_instance_id = 1;
    transport.context = &tctx;
    transport.submit = n05_transport_submit;

    /* Production bind: ctl fans out through the strong hook. */
    wvm_ctl_subscriber_invalidate_bridge_bind(&controller, &transport,
                                              &capture);

    error[0] = '\0';
    if (wvm_membership_controller_mark_monitor_health(
            &controller, &failed_member, WVM_MEMBERSHIP_UNREACHABLE, error,
            sizeof(error)) != 0) {
        fprintf(stderr, "test_n05_ctl: mark UNREACHABLE: %s\n", error);
        wvm_membership_controller_close(&controller);
        return 1;
    }

    printf("EVID N05_membership_unreachable: node=%u inst=%llu\n",
           N05_FAILED_PHYS, (unsigned long long)N05_FAILED_INST);
    printf("EVID N05_bridge_fanout: sent=%zu failed=%zu opcode=%s "
           "last_type=0x%x dir_pid=%u stale=%u ctl_pid=%d\n",
           tctx.sent, tctx.failed, tctx.saw_0307 ? "0x0307" : "NONE",
           tctx.last_type, tctx.directory_pid, tctx.ack_stale, (int)getpid());
    fflush(stdout);

    failed |= expect(tctx.saw_0307, "bridge must fan out opcode 0x0307");
    failed |= expect(tctx.sent >= 1, "directory must receive at least one 0x0307");
    failed |= expect(tctx.ack_stale >= 1, "directory must report STALE>=1");
    failed |= expect(tctx.directory_pid != 0 &&
                         tctx.directory_pid != (uint32_t)getpid(),
                     "directory pid must differ from ctl pid");

    wvm_membership_controller_close(&controller);
    if (failed) {
        fprintf(stderr, "test_n05_ctl: FAIL\n");
        return 1;
    }
    printf("test_n05_ctl: PASS\n");
    return 0;
}

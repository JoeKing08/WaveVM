#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wavevm_admission_node_service.h"
#include "wavevm_admission_receiver.h"
#include "wavevm_control.h"
#include "wavevm_envelope.h"
#include "wavevm_manifest.h"
#include "wavevm_membership_control.h"
#include "wavevm_sha256.h"
#include "wavevm_tls_control_connector.h"

#define ENROLLMENT_SLOTS 4
#define PROOF_CAPACITY WVM_ADMISSION_ENROLLMENT_DEFAULT_PROOF_BYTES

struct agent_options {
    const char *state_dir;
    const char *socket_path;
    uint32_t gateway_id;
    uint64_t gateway_instance_id;
    uint32_t hosting_physical_node_id;
    uint64_t failure_domain_id;
    uint64_t pod_id_or_scope;
    uint64_t role_bits;
    uint32_t controller_node_id;
    uint64_t controller_instance_id;
    const char *control_address;
    uint16_t control_port;
    uint16_t data_port;
    const char *tls_ca;
    const char *tls_cert;
    const char *tls_key;
    const char *register_controller_address;
    uint16_t register_controller_port;
};

struct agent_authentication {
    struct wvm_member_key controller;
};

static volatile sig_atomic_t g_stop;

static void request_stop(int signo)
{
    (void)signo;
    g_stop = 1;
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !value || text[0] == '\0') {
        return -1;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || end == text || *end != '\0') {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_u32(const char *text, uint32_t *value)
{
    uint64_t parsed;

    if (!value || parse_u64(text, &parsed) != 0 || parsed == 0 ||
        parsed > UINT32_MAX) {
        return -1;
    }
    *value = (uint32_t)parsed;
    return 0;
}

static int parse_u16(const char *text, uint16_t *value)
{
    uint64_t parsed;

    if (!value || parse_u64(text, &parsed) != 0 || parsed == 0 ||
        parsed > UINT16_MAX) {
        return -1;
    }
    *value = (uint16_t)parsed;
    return 0;
}

static int parse_options(int argc, char **argv, struct agent_options *options)
{
    static const struct option long_options[] = {
        {"state-dir", required_argument, 0, 1},
        {"socket", required_argument, 0, 2},
        {"gateway-id", required_argument, 0, 3},
        {"instance-id", required_argument, 0, 4},
        {"hosting-node-id", required_argument, 0, 5},
        {"failure-domain-id", required_argument, 0, 6},
        {"pod-id", required_argument, 0, 7},
        {"role-bits", required_argument, 0, 8},
        {"controller-node-id", required_argument, 0, 9},
        {"controller-instance-id", required_argument, 0, 10},
        {"control-address", required_argument, 0, 11},
        {"control-port", required_argument, 0, 12},
        {"data-port", required_argument, 0, 13},
        {"tls-ca", required_argument, 0, 14},
        {"tls-cert", required_argument, 0, 15},
        {"tls-key", required_argument, 0, 16},
        {"register-controller-address", required_argument, 0, 17},
        {"register-controller-port", required_argument, 0, 18},
        {0, 0, 0, 0},
    };
    int opt;
    int seen = 0;

    memset(options, 0, sizeof(*options));
    while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        switch (opt) {
        case 1: options->state_dir = optarg; seen |= 1 << 0; break;
        case 2: options->socket_path = optarg; seen |= 1 << 1; break;
        case 3:
            if (parse_u32(optarg, &options->gateway_id) != 0) {
                return -1;
            }
            seen |= 1 << 2;
            break;
        case 4:
            if (parse_u64(optarg, &options->gateway_instance_id) != 0 ||
                options->gateway_instance_id == 0) {
                return -1;
            }
            seen |= 1 << 3;
            break;
        case 5:
            if (parse_u32(optarg, &options->hosting_physical_node_id) != 0) {
                return -1;
            }
            seen |= 1 << 4;
            break;
        case 6:
            if (parse_u64(optarg, &options->failure_domain_id) != 0 ||
                options->failure_domain_id == 0) {
                return -1;
            }
            seen |= 1 << 5;
            break;
        case 7:
            if (parse_u64(optarg, &options->pod_id_or_scope) != 0 ||
                options->pod_id_or_scope == 0) {
                return -1;
            }
            seen |= 1 << 6;
            break;
        case 8:
            if (parse_u64(optarg, &options->role_bits) != 0 ||
                options->role_bits == 0) {
                return -1;
            }
            seen |= 1 << 7;
            break;
        case 9:
            if (parse_u32(optarg, &options->controller_node_id) != 0) {
                return -1;
            }
            seen |= 1 << 8;
            break;
        case 10:
            if (parse_u64(optarg, &options->controller_instance_id) != 0 ||
                options->controller_instance_id == 0) {
                return -1;
            }
            seen |= 1 << 9;
            break;
        case 11: options->control_address = optarg; seen |= 1 << 10; break;
        case 12:
            if (parse_u16(optarg, &options->control_port) != 0) {
                return -1;
            }
            seen |= 1 << 11;
            break;
        case 13:
            if (parse_u16(optarg, &options->data_port) != 0) {
                return -1;
            }
            seen |= 1 << 12;
            break;
        case 14: options->tls_ca = optarg; seen |= 1 << 13; break;
        case 15: options->tls_cert = optarg; seen |= 1 << 14; break;
        case 16: options->tls_key = optarg; seen |= 1 << 15; break;
        case 17:
            options->register_controller_address = optarg;
            seen |= 1 << 16;
            break;
        case 18:
            if (parse_u16(optarg, &options->register_controller_port) != 0) {
                return -1;
            }
            seen |= 1 << 17;
            break;
        default:
            return -1;
        }
    }
    return optind == argc && seen == ((1 << 18) - 1) ? 0 : -1;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authenticate_controller(void *opaque, int stream_fd,
                                   struct wvm_member_key *actor, char *error,
                                   size_t error_len)
{
    const struct agent_authentication *authentication = opaque;

    (void)stream_fd;
    if (!authentication || !actor) {
        if (error && error_len) {
            snprintf(error, error_len, "gateway enrollment Unix auth missing");
        }
        return -EACCES;
    }
    *actor = authentication->controller;
    return 0;
}

static int authenticate_controller_io(void *opaque, int stream_fd,
                                      const struct wvm_control_io *io,
                                      struct wvm_member_key *actor, char *error,
                                      size_t error_len)
{
    const struct agent_authentication *authentication = opaque;
    struct wvm_member_key peer;

    (void)stream_fd;
    if (!authentication || !actor ||
        wvm_tls_control_peer_identity(io, &peer, error, error_len) != 0 ||
        !member_key_equal(&peer, &authentication->controller)) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "TLS peer is not the configured controller identity");
        }
        return -EACCES;
    }
    *actor = peer;
    return 0;
}

static int make_tls_endpoint(const char *address, uint16_t data_port,
                             uint16_t control_port,
                             struct wvm_endpoint *endpoint, char *error,
                             size_t error_len)
{
    struct in_addr ipv4;

    if (!address || !endpoint || data_port == 0 || control_port == 0) {
        return -1;
    }
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->has_control_address = 1;
    endpoint->control_port = control_port;
    if (inet_pton(AF_INET, address, &ipv4) != 1) {
        if (error && error_len) {
            snprintf(error, error_len, "control address must be IPv4");
        }
        return -1;
    }
    endpoint->data_address_bytes = 4;
    endpoint->control_address_bytes = 4;
    memcpy(endpoint->data_address, &ipv4, 4);
    memcpy(endpoint->control_address, &ipv4, 4);
    return wvm_endpoint_validate(endpoint, error, error_len);
}

static int bytes_are_zero(const uint8_t *bytes, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int register_gateway(const struct agent_options *options,
                            const struct wvm_endpoint *local_endpoint,
                            char *error, size_t error_len)
{
    struct wvm_tls_control_connector tls_connector;
    struct wvm_control_stream_connector connector;
    struct wvm_gateway_record gateway;
    struct wvm_endpoint controller_endpoint;
    struct wvm_member_key controller_member;
    struct wvm_membership_control_result result;
    struct wvm_envelope request;
    uint8_t gateway_bytes[WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES];
    uint8_t operation_digest[WVM_SHA256_DIGEST_BYTES];
    size_t gateway_byte_count = 0;
    int status;

    memset(&gateway, 0, sizeof(gateway));
    gateway.gateway_id = options->gateway_id;
    gateway.gateway_instance_id = options->gateway_instance_id;
    gateway.hosting_physical_node_id = options->hosting_physical_node_id;
    gateway.failure_domain_id = options->failure_domain_id;
    gateway.endpoint = *local_endpoint;
    gateway.role_bits = options->role_bits;
    gateway.pod_id_or_scope = options->pod_id_or_scope;
    gateway.desired_membership_state = WVM_MANIFEST_MEMBER_PENDING;
    gateway.observed_health_state = WVM_MEMBERSHIP_RECOVERING;
    gateway.membership_revision = 1;
    gateway.topology_revision = 1;
    if (wvm_gateway_record_validate(&gateway, error, error_len) != 0 ||
        wvm_gateway_record_encode(&gateway, gateway_bytes, sizeof(gateway_bytes),
                                  &gateway_byte_count, error, error_len) != 0 ||
        make_tls_endpoint(options->register_controller_address,
                          options->register_controller_port,
                          options->register_controller_port,
                          &controller_endpoint, error, error_len) != 0) {
        return -1;
    }
    memset(&controller_member, 0, sizeof(controller_member));
    controller_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    controller_member.role_id = options->controller_node_id;
    controller_member.instance_id = options->controller_instance_id;
    memset(&request, 0, sizeof(request));
    request.message_type = WVM_ENVELOPE_MSG_REGISTER_MEMBER;
    request.origin_physical_node_id = gateway.hosting_physical_node_id;
    request.origin_runtime_instance_id = gateway.gateway_instance_id;
    request.delivery_attempt_id = 1;
    request.payload = gateway_bytes;
    request.payload_bytes = gateway_byte_count;
    wvm_envelope_semantic_digest(gateway_bytes, gateway_byte_count,
                                 request.semantic_payload_digest);
    wvm_sha256_digest(gateway_bytes, gateway_byte_count, operation_digest);
    memcpy(request.operation_id, operation_digest, sizeof(request.operation_id));
    if (bytes_are_zero(request.operation_id, sizeof(request.operation_id))) {
        request.operation_id[sizeof(request.operation_id) - 1U] = 1;
    }
    memset(&tls_connector, 0, sizeof(tls_connector));
    memset(&connector, 0, sizeof(connector));
    if (wvm_tls_control_connector_bind(
            &tls_connector, options->tls_ca, options->tls_cert, options->tls_key,
            10000U, &connector, error, error_len) != 0) {
        return -1;
    }
    memset(&result, 0, sizeof(result));
    status = wvm_tls_control_membership_exchange(
        &tls_connector, &controller_member, options->controller_node_id,
        options->controller_instance_id, &controller_endpoint, &request, &result,
        error, error_len);
    wvm_tls_control_connector_destroy(&tls_connector);
    if (status != 0) {
        return -1;
    }
    if (result.status_code != WVM_MEMBERSHIP_CONTROL_SUCCESS ||
        result.recorded_state != WVM_MANIFEST_MEMBER_PENDING ||
        result.applied_revision == 0 ||
        memcmp(result.in_reply_to_operation_id, request.operation_id,
               sizeof(request.operation_id)) != 0 ||
        bytes_are_zero(result.record_digest, sizeof(result.record_digest))) {
        if (error && error_len != 0) {
            snprintf(error, error_len,
                     "controller rejected durable gateway registration");
        }
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct agent_options options;
    struct agent_authentication authentication;
    struct wvm_admission_node_service_config service_config;
    struct wvm_admission_receiver_config receiver_config;
    struct wvm_admission_node_service service;
    struct wvm_endpoint network_endpoint;
    struct wvm_admission_enrollment_slot slots[ENROLLMENT_SLOTS];
    uint8_t proof_storage[ENROLLMENT_SLOTS][PROOF_CAPACITY];
    uint8_t proof_scratch[PROOF_CAPACITY];
    struct wvm_cluster_admission_ack_entry ack_scratch[8];
    char enrollment_dir[512];
    char error[256] = {0};
    struct sigaction action = {.sa_handler = request_stop};
    size_t i;
    int started = 0;

    if (parse_options(argc, argv, &options) != 0) {
        fprintf(stderr,
                "Usage: %s --state-dir DIR --socket PATH "
                "--gateway-id N --instance-id N --hosting-node-id N "
                "--failure-domain-id N --pod-id N --role-bits N "
                "--controller-node-id N --controller-instance-id N "
                "--control-address IP --control-port PORT --data-port PORT "
                "--tls-ca FILE --tls-cert FILE --tls-key FILE "
                "--register-controller-address IP "
                "--register-controller-port PORT\n",
                argv[0]);
        return 2;
    }
    if (snprintf(enrollment_dir, sizeof(enrollment_dir), "%s/enrollment",
                 options.state_dir) >= (int)sizeof(enrollment_dir) ||
        (mkdir(options.state_dir, 0700) != 0 && errno != EEXIST) ||
        (mkdir(enrollment_dir, 0700) != 0 && errno != EEXIST)) {
        fprintf(stderr, "gateway-enrollment-agent: cannot create state dirs\n");
        return 1;
    }
    if (make_tls_endpoint(options.control_address, options.data_port,
                          options.control_port, &network_endpoint, error,
                          sizeof(error)) != 0) {
        fprintf(stderr, "gateway-enrollment-agent: endpoint: %s\n", error);
        return 1;
    }
    memset(&authentication, 0, sizeof(authentication));
    authentication.controller.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    authentication.controller.role_id = options.controller_node_id;
    authentication.controller.instance_id = options.controller_instance_id;
    memset(slots, 0, sizeof(slots));
    for (i = 0; i < ENROLLMENT_SLOTS; i++) {
        slots[i].proof_bytes = proof_storage[i];
        slots[i].proof_capacity = PROOF_CAPACITY;
    }
    memset(&receiver_config, 0, sizeof(receiver_config));
    receiver_config.controller_member_key = authentication.controller;
    receiver_config.controller_physical_node_id = options.controller_node_id;
    receiver_config.controller_runtime_instance_id =
        options.controller_instance_id;
    receiver_config.local_physical_node_id = options.gateway_id;
    receiver_config.local_node_instance_id = options.gateway_instance_id;
    receiver_config.local_role_type = WVM_MANIFEST_ROLE_GATEWAY;
    receiver_config.local_endpoint = &network_endpoint;
    receiver_config.enrollment_state_directory = enrollment_dir;
    receiver_config.enrollment_slots = slots;
    receiver_config.enrollment_slot_capacity = ENROLLMENT_SLOTS;
    receiver_config.enrollment_proof_storage = &proof_storage[0][0];
    receiver_config.enrollment_proof_capacity = PROOF_CAPACITY;
    receiver_config.enrollment_proof_scratch = proof_scratch;
    receiver_config.enrollment_proof_scratch_capacity = PROOF_CAPACITY;
    receiver_config.enrollment_ack_scratch = ack_scratch;
    receiver_config.enrollment_ack_scratch_capacity =
        sizeof(ack_scratch) / sizeof(ack_scratch[0]);
    memset(&service_config, 0, sizeof(service_config));
    service_config.socket_path = options.socket_path;
    service_config.socket_mode = S_IRUSR | S_IWUSR;
    service_config.listen_backlog = 8;
    service_config.local_physical_node_id = options.gateway_id;
    service_config.local_runtime_instance_id = options.gateway_instance_id;
    service_config.max_frame_bytes =
        WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    service_config.network_endpoint = &network_endpoint;
    service_config.tls_ca_file = options.tls_ca;
    service_config.tls_certificate_file = options.tls_cert;
    service_config.tls_private_key_file = options.tls_key;
    service_config.authenticate = authenticate_controller;
    service_config.authenticate_io = authenticate_controller_io;
    service_config.authenticate_opaque = &authentication;
    service_config.receiver = receiver_config;
    memset(&service, 0, sizeof(service));
    if (wvm_admission_node_service_init(&service, &service_config, error,
                                        sizeof(error)) != 0 ||
        wvm_admission_node_service_start(&service, error, sizeof(error)) != 0) {
        fprintf(stderr, "gateway-enrollment-agent: listen: %s\n", error);
        wvm_admission_node_service_destroy(&service);
        return 1;
    }
    started = 1;
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        fprintf(stderr, "gateway-enrollment-agent: cannot install signals\n");
        goto out;
    }
    if (register_gateway(&options, &network_endpoint, error, sizeof(error)) !=
        0) {
        fprintf(stderr, "gateway-enrollment-agent: register: %s\n", error);
        goto out;
    }
    fprintf(stderr,
            "gateway-enrollment-agent: REGISTER accepted; waiting for stop\n");
    while (!g_stop) {
        sleep(1);
    }
    (void)wvm_admission_node_service_stop(&service, error, sizeof(error));
    wvm_admission_node_service_destroy(&service);
    return 0;

out:
    if (started) {
        (void)wvm_admission_node_service_stop(&service, error, sizeof(error));
        wvm_admission_node_service_destroy(&service);
    }
    return 1;
}

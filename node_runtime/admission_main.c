#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common_include/wavevm_admission_runtime_agent.h"
#include "../common_include/wavevm_membership_control.h"
#include "../common_include/wavevm_sha256.h"
#include "../common_include/wavevm_tls_control_connector.h"

enum agent_option {
    OPT_STATE_DIR = 1000,
    OPT_RUNTIME_DIR,
    OPT_SOCKET,
    OPT_NODE_ID,
    OPT_INSTANCE_ID,
    OPT_INVENTORY_REVISION,
    OPT_VCPU_SLOTS,
    OPT_MEMORY_BYTES,
    OPT_CONTROLLER_NODE_ID,
    OPT_CONTROLLER_INSTANCE_ID,
    OPT_CONTROLLER_UID,
    OPT_SLOTS,
    OPT_MAX_VCPUS,
    OPT_MAX_MEMORY_CHUNKS,
    OPT_MAX_STORAGE,
    OPT_MAX_MEMBERS,
    OPT_MAX_LEASES,
    OPT_CONTROL_ADDRESS,
    OPT_CONTROL_PORT,
    OPT_TLS_CA,
    OPT_TLS_CERT,
    OPT_TLS_KEY,
    OPT_DATA_PORT,
    OPT_REGISTER_CONTROLLER_ADDRESS,
    OPT_REGISTER_CONTROLLER_PORT,
    OPT_FAILURE_DOMAIN_ID,
    OPT_POD_ID,
    OPT_VNODE_FIRST,
    OPT_VNODE_COUNT,
    OPT_SIDECAR_ADDRESS,
    OPT_SIDECAR_DATA_PORT,
    OPT_SIDECAR_CONTROL_PORT,
    OPT_ROLE_BITS,
    OPT_CAPABILITY_PROFILE_GENERATION,
    OPT_CAPABILITY_PROFILE_DIGEST,
    OPT_STORAGE_CAPABILITIES_DIGEST,
    OPT_ACCELERATOR_FAULT_CAPABILITIES_DIGEST,
    OPT_EXCLUSIVE_RESOURCE_DIGEST,
};

struct agent_options {
    const char *state_dir;
    const char *runtime_dir;
    const char *socket_path;
    uint64_t node_id;
    uint64_t instance_id;
    uint64_t inventory_revision;
    uint64_t vcpu_slots;
    uint64_t memory_bytes;
    uint64_t controller_node_id;
    uint64_t controller_instance_id;
    uint64_t controller_uid;
    uint64_t slots;
    uint64_t max_vcpus;
    uint64_t max_memory_chunks;
    uint64_t max_storage;
    uint64_t max_members;
    uint64_t max_leases;
    const char *control_address;
    uint64_t control_port;
    const char *tls_ca_file;
    const char *tls_certificate_file;
    const char *tls_private_key_file;
    uint64_t data_port;
    const char *registration_controller_address;
    uint64_t registration_controller_port;
    uint64_t failure_domain_id;
    uint64_t pod_id;
    uint64_t vnode_first;
    uint64_t vnode_count;
    const char *sidecar_address;
    uint64_t sidecar_data_port;
    uint64_t sidecar_control_port;
    uint64_t role_bits;
    uint64_t capability_profile_generation;
    uint8_t capability_profile_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t storage_capabilities_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t accelerator_fault_capabilities_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t exclusive_resource_inventory_digest[WVM_SHA256_DIGEST_BYTES];
};

struct agent_authentication {
    uid_t controller_uid;
    struct wvm_member_key controller;
};

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void child_exited(int signal_number)
{
    (void)signal_number;
}

static int parse_number(const char *text, uint64_t *output)
{
    char *end;
    unsigned long long value;

    if (!text || !*text || *text == '-' || *text == '+' || !output) {
        return -1;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }
    *output = value;
    return 0;
}

static int parse_hex_digest(const char *text,
                            uint8_t output[WVM_SHA256_DIGEST_BYTES])
{
    size_t index;

    if (!text || !output || strlen(text) != WVM_SHA256_DIGEST_BYTES * 2U) {
        return -1;
    }
    for (index = 0; index < WVM_SHA256_DIGEST_BYTES; index++) {
        unsigned char high;
        unsigned char low;

        if (text[index * 2U] >= '0' && text[index * 2U] <= '9') {
            high = (unsigned char)(text[index * 2U] - '0');
        } else if (text[index * 2U] >= 'a' && text[index * 2U] <= 'f') {
            high = (unsigned char)(text[index * 2U] - 'a' + 10U);
        } else if (text[index * 2U] >= 'A' && text[index * 2U] <= 'F') {
            high = (unsigned char)(text[index * 2U] - 'A' + 10U);
        } else {
            return -1;
        }
        if (text[index * 2U + 1U] >= '0' && text[index * 2U + 1U] <= '9') {
            low = (unsigned char)(text[index * 2U + 1U] - '0');
        } else if (text[index * 2U + 1U] >= 'a' &&
                   text[index * 2U + 1U] <= 'f') {
            low = (unsigned char)(text[index * 2U + 1U] - 'a' + 10U);
        } else if (text[index * 2U + 1U] >= 'A' &&
                   text[index * 2U + 1U] <= 'F') {
            low = (unsigned char)(text[index * 2U + 1U] - 'A' + 10U);
        } else {
            return -1;
        }
        output[index] = (uint8_t)((high << 4U) | low);
    }
    return 0;
}

static int bytes_are_zero(const uint8_t *bytes, size_t byte_count)
{
    size_t index;

    if (!bytes) {
        return 1;
    }
    for (index = 0; index < byte_count; index++) {
        if (bytes[index] != 0) {
            return 0;
        }
    }
    return 1;
}

#define OPTION_SEEN(option) (UINT64_C(1) << ((option) - OPT_STATE_DIR))

static int option_set_complete(uint64_t seen, uint64_t required)
{
    return (seen & required) == 0 || (seen & required) == required;
}

static int parse_options(int argc, char **argv, struct agent_options *options)
{
    static const struct option long_options[] = {
        {"state-dir", required_argument, NULL, OPT_STATE_DIR},
        {"runtime-dir", required_argument, NULL, OPT_RUNTIME_DIR},
        {"socket", required_argument, NULL, OPT_SOCKET},
        {"node-id", required_argument, NULL, OPT_NODE_ID},
        {"instance-id", required_argument, NULL, OPT_INSTANCE_ID},
        {"inventory-revision", required_argument, NULL, OPT_INVENTORY_REVISION},
        {"vcpu-slots", required_argument, NULL, OPT_VCPU_SLOTS},
        {"memory-bytes", required_argument, NULL, OPT_MEMORY_BYTES},
        {"controller-node-id", required_argument, NULL, OPT_CONTROLLER_NODE_ID},
        {"controller-instance-id", required_argument, NULL, OPT_CONTROLLER_INSTANCE_ID},
        {"controller-uid", required_argument, NULL, OPT_CONTROLLER_UID},
        {"slots", required_argument, NULL, OPT_SLOTS},
        {"max-vcpus", required_argument, NULL, OPT_MAX_VCPUS},
        {"max-memory-chunks", required_argument, NULL, OPT_MAX_MEMORY_CHUNKS},
        {"max-storage", required_argument, NULL, OPT_MAX_STORAGE},
        {"max-members", required_argument, NULL, OPT_MAX_MEMBERS},
        {"max-leases", required_argument, NULL, OPT_MAX_LEASES},
        {"control-address", required_argument, NULL, OPT_CONTROL_ADDRESS},
        {"control-port", required_argument, NULL, OPT_CONTROL_PORT},
        {"tls-ca", required_argument, NULL, OPT_TLS_CA},
        {"tls-cert", required_argument, NULL, OPT_TLS_CERT},
        {"tls-key", required_argument, NULL, OPT_TLS_KEY},
        {"data-port", required_argument, NULL, OPT_DATA_PORT},
        {"register-controller-address", required_argument, NULL,
         OPT_REGISTER_CONTROLLER_ADDRESS},
        {"register-controller-port", required_argument, NULL,
         OPT_REGISTER_CONTROLLER_PORT},
        {"failure-domain-id", required_argument, NULL, OPT_FAILURE_DOMAIN_ID},
        {"pod-id", required_argument, NULL, OPT_POD_ID},
        {"vnode-first", required_argument, NULL, OPT_VNODE_FIRST},
        {"vnode-count", required_argument, NULL, OPT_VNODE_COUNT},
        {"sidecar-address", required_argument, NULL, OPT_SIDECAR_ADDRESS},
        {"sidecar-data-port", required_argument, NULL, OPT_SIDECAR_DATA_PORT},
        {"sidecar-control-port", required_argument, NULL,
         OPT_SIDECAR_CONTROL_PORT},
        {"role-bits", required_argument, NULL, OPT_ROLE_BITS},
        {"capability-profile-generation", required_argument, NULL,
         OPT_CAPABILITY_PROFILE_GENERATION},
        {"capability-profile-digest", required_argument, NULL,
         OPT_CAPABILITY_PROFILE_DIGEST},
        {"storage-capabilities-digest", required_argument, NULL,
         OPT_STORAGE_CAPABILITIES_DIGEST},
        {"accelerator-fault-capabilities-digest", required_argument, NULL,
         OPT_ACCELERATOR_FAULT_CAPABILITIES_DIGEST},
        {"exclusive-resource-digest", required_argument, NULL,
         OPT_EXCLUSIVE_RESOURCE_DIGEST},
        {0, 0, 0, 0},
    };
    const uint64_t local_network_options =
        OPTION_SEEN(OPT_CONTROL_ADDRESS) | OPTION_SEEN(OPT_CONTROL_PORT) |
        OPTION_SEEN(OPT_TLS_CA) | OPTION_SEEN(OPT_TLS_CERT) |
        OPTION_SEEN(OPT_TLS_KEY) | OPTION_SEEN(OPT_DATA_PORT);
    const uint64_t registration_options =
        OPTION_SEEN(OPT_REGISTER_CONTROLLER_ADDRESS) |
        OPTION_SEEN(OPT_REGISTER_CONTROLLER_PORT) |
        OPTION_SEEN(OPT_FAILURE_DOMAIN_ID) | OPTION_SEEN(OPT_POD_ID) |
        OPTION_SEEN(OPT_VNODE_FIRST) | OPTION_SEEN(OPT_VNODE_COUNT) |
        OPTION_SEEN(OPT_SIDECAR_ADDRESS) |
        OPTION_SEEN(OPT_SIDECAR_DATA_PORT) |
        OPTION_SEEN(OPT_SIDECAR_CONTROL_PORT) | OPTION_SEEN(OPT_ROLE_BITS) |
        OPTION_SEEN(OPT_CAPABILITY_PROFILE_GENERATION) |
        OPTION_SEEN(OPT_CAPABILITY_PROFILE_DIGEST) |
        OPTION_SEEN(OPT_STORAGE_CAPABILITIES_DIGEST) |
        OPTION_SEEN(OPT_ACCELERATOR_FAULT_CAPABILITIES_DIGEST) |
        OPTION_SEEN(OPT_EXCLUSIVE_RESOURCE_DIGEST);
    uint64_t seen = 0;
    int option;

    memset(options, 0, sizeof(*options));
    optind = 2;
    opterr = 0;
    while ((option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        uint64_t *number = NULL;
        uint64_t bit;

        if (option < OPT_STATE_DIR || option > OPT_EXCLUSIVE_RESOURCE_DIGEST) {
            return -1;
        }
        bit = OPTION_SEEN(option);
        if (seen & bit) {
            return -1;
        }
        seen |= bit;
        switch (option) {
        case OPT_STATE_DIR: options->state_dir = optarg; break;
        case OPT_RUNTIME_DIR: options->runtime_dir = optarg; break;
        case OPT_SOCKET: options->socket_path = optarg; break;
        case OPT_NODE_ID: number = &options->node_id; break;
        case OPT_INSTANCE_ID: number = &options->instance_id; break;
        case OPT_INVENTORY_REVISION: number = &options->inventory_revision; break;
        case OPT_VCPU_SLOTS: number = &options->vcpu_slots; break;
        case OPT_MEMORY_BYTES: number = &options->memory_bytes; break;
        case OPT_CONTROLLER_NODE_ID: number = &options->controller_node_id; break;
        case OPT_CONTROLLER_INSTANCE_ID: number = &options->controller_instance_id; break;
        case OPT_CONTROLLER_UID: number = &options->controller_uid; break;
        case OPT_SLOTS: number = &options->slots; break;
        case OPT_MAX_VCPUS: number = &options->max_vcpus; break;
        case OPT_MAX_MEMORY_CHUNKS: number = &options->max_memory_chunks; break;
        case OPT_MAX_STORAGE: number = &options->max_storage; break;
        case OPT_MAX_MEMBERS: number = &options->max_members; break;
        case OPT_MAX_LEASES: number = &options->max_leases; break;
        case OPT_CONTROL_ADDRESS: options->control_address = optarg; break;
        case OPT_CONTROL_PORT: number = &options->control_port; break;
        case OPT_TLS_CA: options->tls_ca_file = optarg; break;
        case OPT_TLS_CERT: options->tls_certificate_file = optarg; break;
        case OPT_TLS_KEY: options->tls_private_key_file = optarg; break;
        case OPT_DATA_PORT: number = &options->data_port; break;
        case OPT_REGISTER_CONTROLLER_ADDRESS:
            options->registration_controller_address = optarg;
            break;
        case OPT_REGISTER_CONTROLLER_PORT:
            number = &options->registration_controller_port;
            break;
        case OPT_FAILURE_DOMAIN_ID: number = &options->failure_domain_id; break;
        case OPT_POD_ID: number = &options->pod_id; break;
        case OPT_VNODE_FIRST: number = &options->vnode_first; break;
        case OPT_VNODE_COUNT: number = &options->vnode_count; break;
        case OPT_SIDECAR_ADDRESS: options->sidecar_address = optarg; break;
        case OPT_SIDECAR_DATA_PORT: number = &options->sidecar_data_port; break;
        case OPT_SIDECAR_CONTROL_PORT:
            number = &options->sidecar_control_port;
            break;
        case OPT_ROLE_BITS: number = &options->role_bits; break;
        case OPT_CAPABILITY_PROFILE_GENERATION:
            number = &options->capability_profile_generation;
            break;
        case OPT_CAPABILITY_PROFILE_DIGEST:
            if (parse_hex_digest(optarg, options->capability_profile_digest) != 0) {
                return -1;
            }
            break;
        case OPT_STORAGE_CAPABILITIES_DIGEST:
            if (parse_hex_digest(optarg, options->storage_capabilities_digest) !=
                0) {
                return -1;
            }
            break;
        case OPT_ACCELERATOR_FAULT_CAPABILITIES_DIGEST:
            if (parse_hex_digest(optarg,
                                 options->accelerator_fault_capabilities_digest) !=
                0) {
                return -1;
            }
            break;
        case OPT_EXCLUSIVE_RESOURCE_DIGEST:
            if (parse_hex_digest(optarg,
                                 options->exclusive_resource_inventory_digest) !=
                0) {
                return -1;
            }
            break;
        default: return -1;
        }
        if ((number && parse_number(optarg, number) != 0) || !*optarg) {
            return -1;
        }
    }
    if (!option_set_complete(seen, local_network_options) ||
        !option_set_complete(seen, registration_options) ||
        ((seen & registration_options) != 0 &&
         (seen & local_network_options) != local_network_options)) {
        return -1;
    }
    return optind == argc &&
           (seen & ((UINT64_C(1) << (OPT_MAX_LEASES - OPT_STATE_DIR + 1)) -
                    UINT64_C(1))) ==
               ((UINT64_C(1) << (OPT_MAX_LEASES - OPT_STATE_DIR + 1)) -
                UINT64_C(1)) &&
           options->node_id > 0 && options->node_id <= UINT32_MAX &&
           options->instance_id > 0 && options->inventory_revision > 0 &&
           options->vcpu_slots > 0 && options->vcpu_slots <= UINT32_MAX &&
           options->memory_bytes > 0 &&
           options->controller_node_id > 0 &&
           options->controller_node_id <= UINT32_MAX &&
           options->controller_instance_id > 0 &&
           options->controller_uid <= (uint64_t)(uid_t)-1 &&
           options->slots > 0 && options->slots <= SIZE_MAX &&
           options->max_vcpus > 0 && options->max_vcpus <= SIZE_MAX &&
           options->max_memory_chunks > 0 && options->max_memory_chunks <= SIZE_MAX &&
           options->max_storage <= SIZE_MAX &&
           options->max_members > 0 && options->max_members <= SIZE_MAX &&
           options->max_leases > 0 && options->max_leases <= SIZE_MAX &&
           (!options->control_address ||
            (options->control_port <= UINT16_MAX &&
             options->control_port != 0 && options->data_port <= UINT16_MAX &&
             options->data_port != 0)) &&
           (!(seen & registration_options) ||
            (options->registration_controller_port <= UINT16_MAX &&
             options->registration_controller_port != 0 &&
             options->failure_domain_id > 0 &&
             options->vnode_first <= UINT32_MAX &&
             options->vnode_count > 0 && options->vnode_count <= UINT32_MAX &&
             options->sidecar_data_port <= UINT16_MAX &&
             options->sidecar_data_port != 0 &&
             options->sidecar_control_port <= UINT16_MAX &&
             options->sidecar_control_port != 0 &&
             options->role_bits != 0 &&
             options->capability_profile_generation != 0 &&
             options->memory_bytes % WVM_MANIFEST_PAGE_BYTES == 0 &&
             !bytes_are_zero(options->capability_profile_digest,
                             sizeof(options->capability_profile_digest)) &&
             !bytes_are_zero(options->storage_capabilities_digest,
                             sizeof(options->storage_capabilities_digest)) &&
             !bytes_are_zero(options->accelerator_fault_capabilities_digest,
                             sizeof(options->accelerator_fault_capabilities_digest)) &&
             !bytes_are_zero(options->exclusive_resource_inventory_digest,
                             sizeof(options->exclusive_resource_inventory_digest))))
               ? 0
               : -1;
}

static int authenticate_controller(void *opaque, int stream_fd,
                                   struct wvm_member_key *actor, char *error,
                                   size_t error_len)
{
    const struct agent_authentication *authentication = opaque;
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (!authentication || !actor || stream_fd < 0 ||
        getsockopt(stream_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials) || credentials.pid <= 0 ||
        credentials.uid != authentication->controller_uid) {
        if (error && error_len) {
            snprintf(error, error_len, "Unix peer is not the configured controller UID");
        }
        return -EACCES;
    }
    *actor = authentication->controller;
    return 0;
}

static int member_key_equal(const struct wvm_member_key *left,
                            const struct wvm_member_key *right)
{
    return left && right && left->role_type == right->role_type &&
           left->role_id == right->role_id &&
           left->instance_id == right->instance_id;
}

static int authenticate_controller_io(
    void *opaque, int stream_fd, const struct wvm_control_io *io,
    struct wvm_member_key *actor, char *error, size_t error_len)
{
    const struct agent_authentication *authentication = opaque;
    struct wvm_member_key peer;

    (void)stream_fd;
    if (!authentication || !actor ||
        wvm_tls_control_peer_identity(io, &peer, error, error_len) != 0 ||
        !member_key_equal(&peer, &authentication->controller)) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
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
    struct in6_addr ipv6;

    if (!address || !endpoint || data_port == 0 || control_port == 0) {
        return -1;
    }
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->data_transport = WVM_DATA_TRANSPORT_UDP;
    endpoint->data_port = data_port;
    endpoint->control_transport = WVM_CONTROL_TRANSPORT_TLS_TCP;
    endpoint->has_control_address = 1;
    endpoint->control_port = control_port;
    if (inet_pton(AF_INET, address, &ipv4) == 1) {
        endpoint->data_address_bytes = 4;
        endpoint->control_address_bytes = 4;
        memcpy(endpoint->data_address, &ipv4, sizeof(ipv4));
        memcpy(endpoint->control_address, &ipv4, sizeof(ipv4));
    } else if (inet_pton(AF_INET6, address, &ipv6) == 1) {
        endpoint->data_address_bytes = 16;
        endpoint->control_address_bytes = 16;
        memcpy(endpoint->data_address, &ipv6, sizeof(ipv6));
        memcpy(endpoint->control_address, &ipv6, sizeof(ipv6));
    } else {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len, "endpoint address is not an IP literal");
        }
        return -1;
    }
    return wvm_endpoint_validate(endpoint, error, error_len);
}

static int build_registration_record(
    const struct agent_options *options,
    const struct wvm_endpoint *control_endpoint,
    struct wvm_node_record *node, char *error, size_t error_len)
{
    struct wvm_endpoint sidecar_endpoint;

    if (!options || !control_endpoint || !node ||
        make_tls_endpoint(options->sidecar_address,
                          (uint16_t)options->sidecar_data_port,
                          (uint16_t)options->sidecar_control_port,
                          &sidecar_endpoint, error, error_len) != 0) {
        if (error && error[0] == '\0') {
            (void)snprintf(error, error_len,
                           "node registration sidecar endpoint is invalid");
        }
        return -1;
    }
    memset(node, 0, sizeof(*node));
    node->physical_node_id = (uint32_t)options->node_id;
    node->node_instance_id = options->instance_id;
    node->failure_domain_id = options->failure_domain_id;
    node->control_endpoint = *control_endpoint;
    node->sidecar_endpoint = sidecar_endpoint;
    node->role_bits = options->role_bits;
    node->pod_id = options->pod_id;
    node->local_vnode_first = (uint32_t)options->vnode_first;
    node->local_vnode_count = (uint32_t)options->vnode_count;
    node->inventory.physical_node_id = node->physical_node_id;
    node->inventory.node_instance_id = node->node_instance_id;
    node->inventory.failure_domain_id = node->failure_domain_id;
    node->inventory.inventory_revision = options->inventory_revision;
    node->inventory.registered_vcpu_slots = (uint32_t)options->vcpu_slots;
    node->inventory.registered_memory_bytes = options->memory_bytes;
    node->inventory.allocatable_vcpu_slots = (uint32_t)options->vcpu_slots;
    node->inventory.allocatable_memory_bytes = options->memory_bytes;
    memcpy(node->inventory.storage_capabilities_digest,
           options->storage_capabilities_digest,
           sizeof(node->inventory.storage_capabilities_digest));
    memcpy(node->inventory.accelerator_fault_capabilities_digest,
           options->accelerator_fault_capabilities_digest,
           sizeof(node->inventory.accelerator_fault_capabilities_digest));
    memcpy(node->inventory.exclusive_resource_inventory_digest,
           options->exclusive_resource_inventory_digest,
           sizeof(node->inventory.exclusive_resource_inventory_digest));
    node->capability.physical_node_id = node->physical_node_id;
    node->capability.node_instance_id = node->node_instance_id;
    node->capability.profile_generation = options->capability_profile_generation;
    memcpy(node->capability.profile_digest, options->capability_profile_digest,
           sizeof(node->capability.profile_digest));
    node->desired_membership_state = WVM_MANIFEST_MEMBER_PENDING;
    node->observed_health_state = WVM_MEMBERSHIP_RECOVERING;
    /* Registration normalizes revisions under the controller's durable lock. */
    node->membership_revision = 1;
    node->topology_revision = 1;
    return wvm_node_record_validate(node, error, error_len);
}

static int register_local_node(const struct agent_options *options,
                               const struct wvm_endpoint *control_endpoint,
                               char *error, size_t error_len)
{
    struct wvm_tls_control_connector tls_connector;
    struct wvm_control_stream_connector connector;
    struct wvm_node_record node;
    struct wvm_endpoint controller_endpoint;
    struct wvm_member_key controller_member;
    struct wvm_membership_control_result result;
    struct wvm_envelope request;
    uint8_t node_bytes[WVM_MEMBERSHIP_CONTROL_MAX_RECORD_BYTES];
    uint8_t operation_digest[WVM_SHA256_DIGEST_BYTES];
    size_t node_byte_count = 0;
    int status;

    if (!options || !control_endpoint ||
        build_registration_record(options, control_endpoint, &node, error,
                                  error_len) != 0 ||
        wvm_node_record_encode(&node, node_bytes, sizeof(node_bytes),
                               &node_byte_count, error, error_len) != 0 ||
        make_tls_endpoint(options->registration_controller_address,
                          (uint16_t)options->registration_controller_port,
                          (uint16_t)options->registration_controller_port,
                          &controller_endpoint, error, error_len) != 0) {
        return -1;
    }
    memset(&controller_member, 0, sizeof(controller_member));
    controller_member.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    controller_member.role_id = (uint32_t)options->controller_node_id;
    controller_member.instance_id = options->controller_instance_id;
    memset(&request, 0, sizeof(request));
    request.message_type = WVM_ENVELOPE_MSG_REGISTER_MEMBER;
    request.origin_physical_node_id = node.physical_node_id;
    request.origin_runtime_instance_id = node.node_instance_id;
    request.delivery_attempt_id = 1;
    request.payload = node_bytes;
    request.payload_bytes = node_byte_count;
    wvm_envelope_semantic_digest(node_bytes, node_byte_count,
                                 request.semantic_payload_digest);
    wvm_sha256_digest(node_bytes, node_byte_count, operation_digest);
    memcpy(request.operation_id, operation_digest, sizeof(request.operation_id));
    if (bytes_are_zero(request.operation_id, sizeof(request.operation_id))) {
        request.operation_id[sizeof(request.operation_id) - 1U] = 1;
    }
    memset(&tls_connector, 0, sizeof(tls_connector));
    memset(&connector, 0, sizeof(connector));
    if (wvm_tls_control_connector_bind(
            &tls_connector, options->tls_ca_file,
            options->tls_certificate_file, options->tls_private_key_file,
            10000U, &connector, error, error_len) != 0) {
        return -1;
    }
    memset(&result, 0, sizeof(result));
    status = wvm_tls_control_membership_exchange(
        &tls_connector, &controller_member,
        (uint32_t)options->controller_node_id,
        options->controller_instance_id, &controller_endpoint, &request,
        &result, error, error_len);
    wvm_tls_control_connector_destroy(&tls_connector);
    if (status != 0) {
        return -1;
    }
    if (result.status_code != WVM_MEMBERSHIP_CONTROL_SUCCESS ||
        memcmp(result.in_reply_to_operation_id, request.operation_id,
               sizeof(request.operation_id)) != 0 ||
        bytes_are_zero(result.record_digest, sizeof(result.record_digest))) {
        if (error && error_len != 0) {
            (void)snprintf(error, error_len,
                           "controller rejected durable node registration");
        }
        return -1;
    }
    return 0;
}

int wavevm_admission_agent_main(int argc, char **argv)
{
    struct agent_options options;
    struct agent_authentication authentication;
    struct wvm_admission_runtime_agent_config config;
    struct wvm_admission_runtime_agent agent;
    struct sigaction action = {.sa_handler = request_stop};
    struct sigaction child_action = {.sa_handler = child_exited};
    struct sigaction ignore_pipe = {.sa_handler = SIG_IGN};
    sigset_t blocked_signals;
    sigset_t previous_signals;
    char route_journal[WVM_ADMISSION_SLOT_PATH_MAX];
    char reservation_journal[WVM_ADMISSION_SLOT_PATH_MAX];
    char runtime_executable[PATH_MAX];
    struct wvm_endpoint network_endpoint;
    const struct wvm_endpoint *network_endpoint_ptr = NULL;
    char error[256] = {0};
    int result = 1;

    if (parse_options(argc, argv, &options) != 0) {
        fprintf(stderr, "Usage: %s agent --state-dir DIR --runtime-dir DIR --socket PATH "
                "--node-id N --instance-id N --inventory-revision N "
                "--vcpu-slots N --memory-bytes N --controller-node-id N "
                "--controller-instance-id N --controller-uid UID --slots N "
                "--max-vcpus N --max-memory-chunks N --max-storage N "
                "--max-members N --max-leases N "
                "[--control-address ADDR --control-port PORT "
                "--tls-ca FILE --tls-cert FILE --tls-key FILE --data-port PORT] "
                "[--register-controller-address ADDR "
                "--register-controller-port PORT --failure-domain-id N "
                "--pod-id N --vnode-first N --vnode-count N "
                "--sidecar-address ADDR --sidecar-data-port PORT "
                "--sidecar-control-port PORT --role-bits N "
                "--capability-profile-generation N "
                "--capability-profile-digest HEX64 "
                "--storage-capabilities-digest HEX64 "
                "--accelerator-fault-capabilities-digest HEX64 "
                "--exclusive-resource-digest HEX64]\n",
                argv[0]);
        return 2;
    }
    {
        ssize_t executable_bytes = readlink("/proc/self/exe",
                                            runtime_executable,
                                            sizeof(runtime_executable) - 1U);

        if (executable_bytes <= 0 ||
            (size_t)executable_bytes >= sizeof(runtime_executable) - 1U) {
            fprintf(stderr, "[node-runtime] cannot resolve agent executable\n");
            return 1;
        }
        runtime_executable[executable_bytes] = '\0';
    }
    if (snprintf(route_journal, sizeof(route_journal), "%s/route.journal",
                 options.state_dir) >= (int)sizeof(route_journal) ||
        snprintf(reservation_journal, sizeof(reservation_journal),
                 "%s/reservation.journal", options.state_dir) >=
            (int)sizeof(reservation_journal)) {
        fprintf(stderr, "[node-runtime] agent state path is too long\n");
        return 2;
    }
    if (options.control_address) {
        if (make_tls_endpoint(options.control_address,
                              (uint16_t)options.data_port,
                              (uint16_t)options.control_port,
                              &network_endpoint, error, sizeof(error)) != 0) {
            fprintf(stderr, "[node-runtime] invalid TLS control endpoint: %s\n",
                    error);
            return 2;
        }
        network_endpoint_ptr = &network_endpoint;
    }
    memset(&authentication, 0, sizeof(authentication));
    authentication.controller_uid = (uid_t)options.controller_uid;
    authentication.controller.role_type = WVM_MANIFEST_ROLE_NODE_RUNTIME;
    authentication.controller.role_id = (uint32_t)options.controller_node_id;
    authentication.controller.instance_id = options.controller_instance_id;
    memset(&config, 0, sizeof(config));
    config.runtime_executable = runtime_executable;
    config.socket_path = options.socket_path;
    config.network_endpoint = network_endpoint_ptr;
    config.tls_ca_file = options.tls_ca_file;
    config.tls_certificate_file = options.tls_certificate_file;
    config.tls_private_key_file = options.tls_private_key_file;
    config.state_directory = options.state_dir;
    config.runtime_directory = options.runtime_dir;
    config.route_journal_path = route_journal;
    config.reservation_journal_path = reservation_journal;
    config.socket_mode = S_IRUSR | S_IWUSR;
    config.listen_backlog = 32;
    config.max_frame_bytes = WVM_CONTROL_TRANSPORT_DEFAULT_MAX_FRAME_BYTES;
    config.slot_capacity = (size_t)options.slots;
    config.max_vcpus = (size_t)options.max_vcpus;
    config.max_memory_chunks = (size_t)options.max_memory_chunks;
    config.max_storage_assignments = (size_t)options.max_storage;
    config.max_members = (size_t)options.max_members;
    config.max_leases_per_requirement = (size_t)options.max_leases;
    config.local_physical_node_id = (uint32_t)options.node_id;
    config.local_node_instance_id = options.instance_id;
    config.inventory_revision = options.inventory_revision;
    config.allocatable_vcpu_slots = (uint32_t)options.vcpu_slots;
    config.allocatable_memory_bytes = options.memory_bytes;
    config.controller_member_key = authentication.controller;
    config.controller_physical_node_id = (uint32_t)options.controller_node_id;
    config.controller_runtime_instance_id = options.controller_instance_id;
    config.authenticate = authenticate_controller;
    config.authenticate_io = authenticate_controller_io;
    config.authenticate_opaque = &authentication;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigemptyset(&ignore_pipe.sa_mask) != 0 ||
        sigaction(SIGPIPE, &ignore_pipe, NULL) != 0 ||
        sigemptyset(&child_action.sa_mask) != 0 ||
        sigaction(SIGCHLD, &child_action, NULL) != 0 ||
        sigemptyset(&blocked_signals) != 0 ||
        sigaddset(&blocked_signals, SIGINT) != 0 ||
        sigaddset(&blocked_signals, SIGTERM) != 0 ||
        sigaddset(&blocked_signals, SIGCHLD) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked_signals, &previous_signals) != 0) {
        fprintf(stderr, "[node-runtime] cannot install agent signal handlers\n");
        return 1;
    }
    memset(&agent, 0, sizeof(agent));
    if (wvm_admission_runtime_agent_init(&agent, &config, error, sizeof(error)) != 0 ||
        wvm_admission_runtime_agent_start(&agent, error, sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] cannot start admission agent: %s\n", error);
        wvm_admission_runtime_agent_destroy(&agent);
        (void)sigprocmask(SIG_SETMASK, &previous_signals, NULL);
        return result;
    }
    if (options.registration_controller_address &&
        register_local_node(&options, &network_endpoint, error,
                            sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] cannot register local node: %s\n",
                error[0] ? error : "unknown error");
        if (wvm_admission_runtime_agent_stop(&agent, error, sizeof(error)) != 0) {
            fprintf(stderr, "[node-runtime] cannot stop admission agent: %s\n",
                    error);
        }
        wvm_admission_runtime_agent_destroy(&agent);
        (void)sigprocmask(SIG_SETMASK, &previous_signals, NULL);
        return result;
    }
    while (!stop_requested) {
        (void)sigsuspend(&previous_signals);
        wvm_admission_runtime_agent_reap(&agent);
    }
    result = 0;
    if (wvm_admission_runtime_agent_stop(&agent, error, sizeof(error)) != 0) {
        fprintf(stderr, "[node-runtime] cannot stop admission agent: %s\n", error);
        result = 1;
    }
    wvm_admission_runtime_agent_destroy(&agent);
    (void)sigprocmask(SIG_SETMASK, &previous_signals, NULL);
    return result;
}

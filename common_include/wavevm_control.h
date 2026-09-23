#ifndef WAVEVM_CONTROL_H
#define WAVEVM_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_manifest.h"

#define WVM_RECORD_ENDPOINT 0x1001U
#define WVM_RECORD_REQUIRED_ACK_ENTRY 0x1007U
#define WVM_RECORD_REQUIRED_ACK_SET 0x1008U
#define WVM_RECORD_ROUTE_RULE 0x1009U
#define WVM_RECORD_ROUTE_SNAPSHOT 0x100aU
#define WVM_RECORD_NODE_INVENTORY 0x100bU
#define WVM_RECORD_NODE_RECORD 0x100cU
#define WVM_RECORD_GATEWAY_RECORD 0x100dU
#define WVM_RECORD_ADMISSION_ELIGIBILITY_FENCE 0x100eU
#define WVM_RECORD_ROUTE_TRANSACTION 0x1020U
#define WVM_RECORD_GATEWAY_DRAIN_REQUEST 0x102bU
#define WVM_RECORD_MEMBER_CORDON_REQUEST 0x102cU

#define WVM_ENDPOINT_ADDRESS_MAX_BYTES 16U
#define WVM_ENDPOINT_SERVER_NAME_MAX_BYTES 253U
#define WVM_ENDPOINT_CONTROL_SOCKET_PATH_MAX_BYTES 107U

enum wvm_data_transport {
    WVM_DATA_TRANSPORT_UDP = 1,
    WVM_DATA_TRANSPORT_QUIC_DATAGRAM = 2,
};

enum wvm_control_transport {
    WVM_CONTROL_TRANSPORT_UNIX_STREAM = 1,
    WVM_CONTROL_TRANSPORT_TLS_TCP = 2,
    WVM_CONTROL_TRANSPORT_QUIC_STREAM = 3,
};

enum wvm_route_destination_kind {
    WVM_ROUTE_DESTINATION_EXACT_VNODE = 1,
    WVM_ROUTE_DESTINATION_PREFIX = 2,
};

enum wvm_route_next_hop_kind {
    WVM_ROUTE_NEXT_HOP_ENDPOINT = 1,
    WVM_ROUTE_NEXT_HOP_GATEWAY = 2,
};

enum wvm_gateway_drain_action {
    WVM_GATEWAY_DRAIN_ACTION_PREPARE = 1,
    WVM_GATEWAY_DRAIN_ACTION_COMMIT = 2,
    WVM_GATEWAY_DRAIN_ACTION_ABORT = 3,
};

struct wvm_endpoint {
    enum wvm_data_transport data_transport;
    uint8_t data_address[WVM_ENDPOINT_ADDRESS_MAX_BYTES];
    uint8_t data_address_bytes;
    uint16_t data_port;
    enum wvm_control_transport control_transport;
    int has_control_address;
    uint8_t control_address[WVM_ENDPOINT_ADDRESS_MAX_BYTES];
    uint8_t control_address_bytes;
    uint16_t control_port;
    int has_server_name;
    char server_name[WVM_ENDPOINT_SERVER_NAME_MAX_BYTES + 1U];
    int has_control_socket_path;
    char control_socket_path[WVM_ENDPOINT_CONTROL_SOCKET_PATH_MAX_BYTES + 1U];
};

struct wvm_required_ack_entry {
    struct wvm_member_key member_key;
    struct wvm_endpoint endpoint;
    enum wvm_manifest_role_type role_type;
    struct wvm_route_snapshot_key expected_snapshot_key;
};

struct wvm_required_ack_entry_list {
    struct wvm_required_ack_entry *entries;
    size_t count;
    size_t capacity;
};

struct wvm_required_ack_set {
    struct wvm_required_ack_entry_list entries;
    uint8_t entries_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_route_rule_record {
    uint16_t destination_kind;
    uint64_t destination_scope;
    uint32_t destination_vnode_or_endpoint;
    uint16_t next_hop_kind;
    struct wvm_member_key next_hop_member;
    struct wvm_endpoint next_hop_endpoint;
    uint16_t hop_limit;
};

struct wvm_route_rule_record_list {
    struct wvm_route_rule_record *entries;
    size_t count;
    size_t capacity;
};

struct wvm_route_snapshot_record {
    struct wvm_route_snapshot_key route_snapshot_key;
    uint64_t membership_revision;
    uint16_t topology_kind;
    struct wvm_route_rule_record_list next_hop_rules;
    struct wvm_required_ack_set required_ack_set;
    int has_predecessor_snapshot_key;
    struct wvm_route_snapshot_key predecessor_snapshot_key;
    uint64_t operation_retention_horizon_ms;
    uint16_t retirement_policy;
};

struct wvm_node_inventory_record {
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t failure_domain_id;
    uint64_t inventory_revision;
    uint32_t registered_vcpu_slots;
    uint64_t registered_memory_bytes;
    uint32_t reserved_host_cpu_slots;
    uint64_t reserved_host_memory_bytes;
    uint32_t reserved_gateway_cpu_slots;
    uint64_t reserved_gateway_memory_bytes;
    uint32_t *hosted_gateway_role_ids;
    size_t hosted_gateway_role_id_count;
    size_t hosted_gateway_role_id_capacity;
    uint32_t allocatable_vcpu_slots;
    uint64_t allocatable_memory_bytes;
    uint8_t storage_capabilities_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t accelerator_fault_capabilities_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t exclusive_resource_inventory_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_node_record {
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t failure_domain_id;
    struct wvm_endpoint control_endpoint;
    struct wvm_endpoint sidecar_endpoint;
    uint64_t role_bits;
    uint64_t pod_id;
    uint32_t local_vnode_first;
    uint32_t local_vnode_count;
    struct wvm_node_inventory_record inventory;
    struct wvm_capability_ref capability;
    enum wvm_manifest_member_state desired_membership_state;
    uint16_t observed_health_state;
    uint64_t membership_revision;
    uint64_t topology_revision;
};

struct wvm_gateway_record {
    uint32_t gateway_id;
    uint64_t gateway_instance_id;
    uint32_t hosting_physical_node_id;
    uint64_t failure_domain_id;
    struct wvm_endpoint endpoint;
    uint64_t role_bits;
    uint64_t pod_id_or_scope;
    uint32_t *parent_gateway_ids;
    size_t parent_gateway_id_count;
    size_t parent_gateway_id_capacity;
    uint32_t *child_gateway_ids;
    size_t child_gateway_id_count;
    size_t child_gateway_id_capacity;
    enum wvm_manifest_member_state desired_membership_state;
    uint16_t observed_health_state;
    uint64_t membership_revision;
    uint64_t topology_revision;
};

struct wvm_admission_eligibility_fence {
    uint8_t admission_tx_id[WVM_IDENTITY_ID_BYTES];
    uint64_t membership_revision;
    uint64_t topology_revision;
    uint64_t admission_eligibility_revision;
    uint64_t inventory_revision;
    uint64_t capability_profile_generation;
    struct wvm_required_member_list selected_members;
    struct wvm_vm_route_scope_key required_route_scope_key;
    uint8_t required_ack_set_digest[WVM_SHA256_DIGEST_BYTES];
    uint8_t fence_digest[WVM_SHA256_DIGEST_BYTES];
};

struct wvm_route_transaction_record {
    uint8_t operation_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_route_snapshot_key route_snapshot_key;
    int has_predecessor_snapshot_key;
    struct wvm_route_snapshot_key predecessor_snapshot_key;
    struct wvm_required_ack_set required_ack_set;
    struct wvm_required_ack_entry_list optional_departure_drain_set;
    uint64_t operation_retention_horizon_ms;
    uint16_t state;
};

/*
 * PREPARE embeds the complete immutable successor material. COMMIT and ABORT
 * carry the same target, revision fence, and route operation ID, but omit
 * successor_transaction and successor_snapshot.
 *
 * Decode callers provide storage for the nested list fields in the two
 * successor records before calling wvm_gateway_drain_request_decode().
 */
struct wvm_gateway_drain_request {
    enum wvm_gateway_drain_action action;
    struct wvm_member_key target_gateway_member_key;
    uint64_t expected_membership_revision;
    uint64_t expected_topology_revision;
    uint64_t expected_admission_eligibility_revision;
    uint8_t route_operation_id[WVM_IDENTITY_ID_BYTES];
    struct wvm_route_transaction_record successor_transaction;
    struct wvm_route_snapshot_record successor_snapshot;
};

struct wvm_member_cordon_request {
    struct wvm_member_key target_member_key;
    uint64_t expected_membership_revision;
    uint64_t expected_topology_revision;
    uint64_t expected_admission_eligibility_revision;
    uint16_t reason_code;
};

int wvm_endpoint_validate(const struct wvm_endpoint *endpoint, char *error,
                          size_t error_len);
int wvm_endpoint_encode(const struct wvm_endpoint *endpoint, uint8_t *bytes,
                        size_t capacity, size_t *encoded_bytes, char *error,
                        size_t error_len);
int wvm_endpoint_decode(const uint8_t *bytes, size_t encoded_bytes,
                        struct wvm_endpoint *endpoint, char *error,
                        size_t error_len);

int wvm_required_ack_set_validate(const struct wvm_required_ack_set *ack_set,
                                  char *error, size_t error_len);
int wvm_required_ack_set_encode(const struct wvm_required_ack_set *ack_set,
                                uint8_t *bytes, size_t capacity,
                                size_t *encoded_bytes, char *error,
                                size_t error_len);
int wvm_required_ack_set_decode(const uint8_t *bytes, size_t encoded_bytes,
                                struct wvm_required_ack_set *ack_set,
                                char *error, size_t error_len);

int wvm_route_snapshot_record_validate(
    const struct wvm_route_snapshot_record *snapshot, char *error,
    size_t error_len);
/*
 * A route transaction may publish only the immutable snapshot body it names.
 * This checks predecessor, retention, and required-ACK binding as well as the
 * snapshot key.
 */
int wvm_route_snapshot_record_binds_transaction(
    const struct wvm_route_snapshot_record *snapshot,
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len);
int wvm_route_snapshot_record_encode(
    const struct wvm_route_snapshot_record *snapshot, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes,
    uint8_t snapshot_digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len);
int wvm_route_snapshot_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_route_snapshot_record *snapshot, char *error, size_t error_len);

int wvm_node_inventory_record_validate(
    const struct wvm_node_inventory_record *inventory, char *error,
    size_t error_len);
int wvm_node_inventory_record_encode(
    const struct wvm_node_inventory_record *inventory, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_node_inventory_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_node_inventory_record *inventory, char *error, size_t error_len);

int wvm_node_record_validate(const struct wvm_node_record *node, char *error,
                             size_t error_len);
int wvm_node_record_encode(const struct wvm_node_record *node, uint8_t *bytes,
                           size_t capacity, size_t *encoded_bytes, char *error,
                           size_t error_len);
int wvm_node_record_decode(const uint8_t *bytes, size_t encoded_bytes,
                           struct wvm_node_record *node, char *error,
                           size_t error_len);

int wvm_gateway_record_validate(const struct wvm_gateway_record *gateway,
                                char *error, size_t error_len);
int wvm_gateway_record_encode(const struct wvm_gateway_record *gateway,
                              uint8_t *bytes, size_t capacity,
                              size_t *encoded_bytes, char *error,
                              size_t error_len);
int wvm_gateway_record_decode(const uint8_t *bytes, size_t encoded_bytes,
                              struct wvm_gateway_record *gateway, char *error,
                              size_t error_len);

int wvm_admission_eligibility_fence_validate(
    const struct wvm_admission_eligibility_fence *fence, char *error,
    size_t error_len);
int wvm_admission_eligibility_fence_encode(
    const struct wvm_admission_eligibility_fence *fence, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes,
    uint8_t fence_digest[WVM_SHA256_DIGEST_BYTES], char *error,
    size_t error_len);
int wvm_admission_eligibility_fence_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_admission_eligibility_fence *fence, char *error,
    size_t error_len);

int wvm_route_transaction_record_validate(
    const struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len);
int wvm_route_transaction_record_encode(
    const struct wvm_route_transaction_record *transaction, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_route_transaction_record_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_route_transaction_record *transaction, char *error,
    size_t error_len);

int wvm_gateway_drain_request_validate(
    const struct wvm_gateway_drain_request *request, char *error,
    size_t error_len);
int wvm_gateway_drain_request_encode(
    const struct wvm_gateway_drain_request *request, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_gateway_drain_request_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_gateway_drain_request *request, char *error, size_t error_len);

int wvm_member_cordon_request_validate(
    const struct wvm_member_cordon_request *request, char *error,
    size_t error_len);
int wvm_member_cordon_request_encode(
    const struct wvm_member_cordon_request *request, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
int wvm_member_cordon_request_decode(
    const uint8_t *bytes, size_t encoded_bytes,
    struct wvm_member_cordon_request *request, char *error, size_t error_len);

#endif /* WAVEVM_CONTROL_H */

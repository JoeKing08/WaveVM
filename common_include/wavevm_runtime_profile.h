#ifndef WAVEVM_RUNTIME_PROFILE_H
#define WAVEVM_RUNTIME_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#define WVM_RECORD_NODE_RUNTIME_PROFILE 0x1030U
#define WVM_NODE_RUNTIME_PROFILE_MAX_BYTES (1024U * 1024U)

/* Node-static runtime inputs. Per-VM launch values are intentionally absent. */
struct wvm_node_runtime_profile {
    uint32_t physical_node_id;
    uint64_t node_instance_id;
    uint64_t inventory_revision;
    uint64_t capability_profile_generation;
    uint64_t runtime_profile_generation;
    uint16_t node_runtime_control_port;
    uint16_t local_executor_control_port;
    uint32_t executor_worker_count;
    uint32_t sync_batch_size;
    uint32_t vcpu_handoff_record_capacity;
    uint16_t *node_runtime_data_ports;
    size_t node_runtime_data_port_count;
    uint16_t *local_executor_service_ports;
    size_t local_executor_service_port_count;
};

int wvm_node_runtime_profile_validate(
    const struct wvm_node_runtime_profile *profile, char *error,
    size_t error_len);
int wvm_node_runtime_profile_encode(
    const struct wvm_node_runtime_profile *profile, uint8_t *bytes,
    size_t capacity, size_t *encoded_bytes, char *error, size_t error_len);
/* Decode owns both port arrays. Initialize output to zero; free with destroy. */
int wvm_node_runtime_profile_decode(
    const uint8_t *bytes, size_t byte_count,
    struct wvm_node_runtime_profile *profile, char *error, size_t error_len);
void wvm_node_runtime_profile_destroy(struct wvm_node_runtime_profile *profile);

#endif /* WAVEVM_RUNTIME_PROFILE_H */

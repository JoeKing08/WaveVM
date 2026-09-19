#ifndef WAVEVM_RESOURCES_H
#define WAVEVM_RESOURCES_H

#include <stddef.h>
#include <stdint.h>

#include "wavevm_config.h"

#define WVM_RESOURCE_MEMORY_CHUNK_MB 1024U
#define WVM_RESOURCE_MAX_MEMORY_CHUNKS WVM_CPU_ROUTE_TABLE_SIZE

enum wvm_resource_policy {
    WVM_RESOURCE_POLICY_COMPACT = 0,
    WVM_RESOURCE_POLICY_SPREAD = 1,
};

struct wvm_resource_node {
    uint32_t phys_id;
    char ip[64];
    uint16_t port;
    uint32_t cpu_capacity;
    uint64_t memory_mb;
    uint32_t dht_slots;
    uint32_t vnode_start;
};

struct wvm_resource_vm {
    uint8_t vm_id;
    uint32_t vcpu_count;
    uint64_t memory_mb;
    enum wvm_resource_policy policy;
    uint32_t host_phys_id;
    uint32_t memory_chunk_count;
    uint32_t vcpu_nodes[WVM_CPU_ROUTE_TABLE_SIZE];
    uint32_t memory_nodes[WVM_RESOURCE_MAX_MEMORY_CHUNKS];
    uint32_t node_capacity;
    uint16_t *vcpus_per_node;
    uint64_t *memory_mb_per_node;
};

struct wvm_resource_plan {
    struct wvm_resource_node *nodes;
    uint32_t node_capacity;
    struct wvm_resource_vm vms[WVM_MAX_VMS];
    uint8_t vm_present[WVM_MAX_VMS];
    uint32_t node_count;
    uint32_t total_vnodes;
    uint32_t vm_count;
};

/*
 * Old NODE lines remain valid:
 *   NODE <id> <ip> <port> <cpu_capacity> <memory_gib>
 *
 * The optional final dht_slots field separates DHT topology weight from
 * physical capacity:
 *   NODE <id> <ip> <port> <cpu_capacity> <memory_gib> [dht_slots]
 *
 * New resource requests must include a placement policy.  Legacy three-field
 * VM lines are deliberately ignored for backward compatibility.
 *   VM <vm_id> <vcpus> <memory_mb> <compact|spread>
 */
int wvm_resource_plan_load(const char *path, struct wvm_resource_plan *plan,
                           char *error, size_t error_len);

/*
 * Validate a fully materialized compatibility plan.  The validator is pure:
 * it does not modify the plan and does not reserve runtime resources.
 */
int wvm_resource_plan_validate(const struct wvm_resource_plan *plan,
                               char *error, size_t error_len);

const struct wvm_resource_node *
wvm_resource_plan_find_node(const struct wvm_resource_plan *plan,
                            uint32_t phys_id);

const struct wvm_resource_vm *
wvm_resource_plan_get_vm(const struct wvm_resource_plan *plan, uint8_t vm_id);

uint32_t wvm_resource_plan_local_vcpus(const struct wvm_resource_plan *plan,
                                       uint8_t vm_id, uint32_t phys_id);

uint64_t wvm_resource_plan_local_memory_mb(
    const struct wvm_resource_plan *plan, uint8_t vm_id, uint32_t phys_id);

uint32_t wvm_resource_plan_host_node(const struct wvm_resource_plan *plan,
                                     uint8_t vm_id);

void wvm_resource_plan_print(const struct wvm_resource_plan *plan,
                             int vm_id_filter);

#endif /* WAVEVM_RESOURCES_H */

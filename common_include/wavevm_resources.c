#include "wavevm_resources.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct wvm_resource_vm_request {
    uint8_t vm_id;
    uint32_t vcpu_count;
    uint64_t memory_mb;
    enum wvm_resource_policy policy;
};

static void set_error(char *error, size_t error_len, const char *fmt, ...)
{
    va_list ap;

    if (!error || error_len == 0) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(error, error_len, fmt, ap);
    va_end(ap);
}

static int node_index_by_id(const struct wvm_resource_plan *plan,
                            uint32_t phys_id)
{
    uint32_t i;

    for (i = 0; i < plan->node_count; i++) {
        if (plan->nodes[i].phys_id == phys_id) {
            return (int)i;
        }
    }
    return -1;
}

static int select_compact_cpu_node(const struct wvm_resource_plan *plan,
                                   const uint32_t *used_cpu,
                                   const uint32_t *vm_cpu)
{
    int best = -1;
    uint32_t i;

    for (i = 0; i < plan->node_count; i++) {
        const struct wvm_resource_node *node = &plan->nodes[i];

        if (used_cpu[i] >= node->cpu_capacity ||
            vm_cpu[i] >= node->cpu_capacity - used_cpu[i]) {
            continue;
        }
        if (best < 0 || node->phys_id < plan->nodes[best].phys_id) {
            best = (int)i;
        }
    }
    return best;
}

static int select_compact_memory_node(const struct wvm_resource_plan *plan,
                                      const uint64_t *used_memory,
                                      const uint64_t *vm_memory,
                                      uint64_t chunk_mb)
{
    int best = -1;
    uint32_t i;

    for (i = 0; i < plan->node_count; i++) {
        const struct wvm_resource_node *node = &plan->nodes[i];

        if (used_memory[i] > node->memory_mb ||
            vm_memory[i] > node->memory_mb - used_memory[i] ||
            chunk_mb > node->memory_mb - used_memory[i] - vm_memory[i]) {
            continue;
        }
        if (best < 0 || node->phys_id < plan->nodes[best].phys_id) {
            best = (int)i;
        }
    }
    return best;
}

static int select_spread_cpu_node(const struct wvm_resource_plan *plan,
                                  const uint32_t *used_cpu,
                                  const uint32_t *vm_cpu)
{
    int best = -1;
    uint32_t i;

    for (i = 0; i < plan->node_count; i++) {
        const struct wvm_resource_node *node = &plan->nodes[i];
        uint64_t lhs;
        uint64_t rhs;

        if (used_cpu[i] >= node->cpu_capacity ||
            vm_cpu[i] >= node->cpu_capacity - used_cpu[i]) {
            continue;
        }
        if (best < 0) {
            best = (int)i;
            continue;
        }

        lhs = (uint64_t)(used_cpu[i] + vm_cpu[i]) *
              plan->nodes[best].cpu_capacity;
        rhs = (uint64_t)(used_cpu[best] + vm_cpu[best]) * node->cpu_capacity;
        if (lhs < rhs ||
            (lhs == rhs && node->phys_id < plan->nodes[best].phys_id)) {
            best = (int)i;
        }
    }
    return best;
}

static int select_spread_memory_node(const struct wvm_resource_plan *plan,
                                     const uint64_t *used_memory,
                                     const uint64_t *vm_memory,
                                     uint64_t chunk_mb)
{
    int best = -1;
    uint32_t i;

    for (i = 0; i < plan->node_count; i++) {
        const struct wvm_resource_node *node = &plan->nodes[i];
        uint64_t lhs;
        uint64_t rhs;

        if (used_memory[i] > node->memory_mb ||
            vm_memory[i] > node->memory_mb - used_memory[i] ||
            chunk_mb > node->memory_mb - used_memory[i] - vm_memory[i]) {
            continue;
        }
        if (best < 0) {
            best = (int)i;
            continue;
        }

        lhs = (used_memory[i] + vm_memory[i]) *
              plan->nodes[best].memory_mb;
        rhs = (used_memory[best] + vm_memory[best]) * node->memory_mb;
        if (lhs < rhs ||
            (lhs == rhs && node->phys_id < plan->nodes[best].phys_id)) {
            best = (int)i;
        }
    }
    return best;
}

static void sort_vm_requests(struct wvm_resource_vm_request *requests,
                             uint32_t count)
{
    uint32_t i;

    for (i = 1; i < count; i++) {
        struct wvm_resource_vm_request value = requests[i];
        uint32_t j = i;

        while (j > 0 && requests[j - 1].vm_id > value.vm_id) {
            requests[j] = requests[j - 1];
            j--;
        }
        requests[j] = value;
    }
}

static int reserve_vm(struct wvm_resource_plan *plan,
                      const struct wvm_resource_vm_request *request,
                      uint32_t *used_cpu, uint64_t *used_memory, char *error,
                      size_t error_len)
{
    struct wvm_resource_vm *vm = &plan->vms[request->vm_id];
    uint32_t *vm_cpu = NULL;
    uint64_t *vm_memory = NULL;
    uint32_t remaining_cpu = request->vcpu_count;
    uint64_t remaining_memory = request->memory_mb;
    uint32_t i;
    uint32_t chunk = 0;
    int ret = -1;

    vm_cpu = calloc(plan->node_count, sizeof(*vm_cpu));
    vm_memory = calloc(plan->node_count, sizeof(*vm_memory));
    if (!vm_cpu || !vm_memory) {
        set_error(error, error_len, "failed to allocate VM placement arrays");
        free(vm_cpu);
        free(vm_memory);
        return -1;
    }

    vm->vm_id = request->vm_id;
    vm->vcpu_count = request->vcpu_count;
    vm->memory_mb = request->memory_mb;
    vm->policy = request->policy;
    vm->node_capacity = plan->node_count;
    vm->vcpus_per_node = calloc(plan->node_count, sizeof(*vm->vcpus_per_node));
    vm->memory_mb_per_node = calloc(plan->node_count, sizeof(*vm->memory_mb_per_node));
    if (!vm->vcpus_per_node || !vm->memory_mb_per_node) {
        set_error(error, error_len, "failed to allocate VM per-node arrays");
        free(vm->vcpus_per_node);
        free(vm->memory_mb_per_node);
        vm->vcpus_per_node = NULL;
        vm->memory_mb_per_node = NULL;
        vm->node_capacity = 0;
        free(vm_cpu);
        free(vm_memory);
        return -1;
    }

    while (remaining_cpu > 0) {
        int node_index;

        if (request->policy == WVM_RESOURCE_POLICY_COMPACT) {
            node_index = select_compact_cpu_node(plan, used_cpu, vm_cpu);
        } else {
            node_index = select_spread_cpu_node(plan, used_cpu, vm_cpu);
        }

        if (node_index < 0) {
            set_error(error, error_len,
                      "VM %u requests %u vCPUs, but cluster CPU capacity is exhausted",
                      request->vm_id, request->vcpu_count);
            goto out;
        }

        vm_cpu[node_index]++;
        remaining_cpu--;
    }

    while (remaining_memory > 0) {
        uint64_t chunk_mb = remaining_memory > WVM_RESOURCE_MEMORY_CHUNK_MB
                                ? WVM_RESOURCE_MEMORY_CHUNK_MB
                                : remaining_memory;
        int node_index;

        if (chunk >= WVM_RESOURCE_MAX_MEMORY_CHUNKS) {
            set_error(error, error_len,
                      "VM %u needs more than %u memory routing chunks",
                      request->vm_id, WVM_RESOURCE_MAX_MEMORY_CHUNKS);
            goto out;
        }

        if (request->policy == WVM_RESOURCE_POLICY_COMPACT) {
            node_index = select_compact_memory_node(plan, used_memory,
                                                    vm_memory, chunk_mb);
        } else {
            node_index = select_spread_memory_node(plan, used_memory,
                                                    vm_memory, chunk_mb);
        }

        if (node_index < 0) {
            set_error(error, error_len,
                      "VM %u requests %llu MB, but cluster memory capacity is exhausted",
                      request->vm_id,
                      (unsigned long long)request->memory_mb);
            goto out;
        }

        vm_memory[node_index] += chunk_mb;
        remaining_memory -= chunk_mb;
        chunk++;
    }

    /*
     * The front end can only treat a contiguous vCPU prefix as local.  Keep
     * each node's allocation in a stable physical-ID block; the first block
     * is the QEMU host's local prefix and later blocks are remote routes.
     */
    {
        uint32_t vcpu = 0;
        uint32_t memory_chunk = 0;
        uint32_t *ordered_indices = NULL;
        uint32_t ordered_count = 0;

        ordered_indices = calloc(plan->node_count, sizeof(*ordered_indices));
        if (!ordered_indices) {
            set_error(error, error_len, "failed to allocate ordered index array");
            goto out;
        }

        for (i = 0; i < plan->node_count; i++) {
            uint32_t insert_at = ordered_count;

            while (insert_at > 0 &&
                   plan->nodes[ordered_indices[insert_at - 1]].phys_id >
                       plan->nodes[i].phys_id) {
                ordered_indices[insert_at] = ordered_indices[insert_at - 1];
                insert_at--;
            }
            ordered_indices[insert_at] = i;
            ordered_count++;
        }

        for (i = 0; i < ordered_count; i++) {
            uint32_t node_index = ordered_indices[i];
            const struct wvm_resource_node *node = &plan->nodes[node_index];
            uint32_t local_vcpus = vm_cpu[node_index];
            uint64_t local_memory = vm_memory[node_index];
            uint64_t assigned_memory = 0;

            for (uint32_t vcpu_offset = 0; vcpu_offset < local_vcpus;
                 vcpu_offset++) {
                vm->vcpu_nodes[vcpu++] = node->vnode_start;
            }
            while (assigned_memory < local_memory) {
                uint64_t assigned =
                    local_memory - assigned_memory >
                            WVM_RESOURCE_MEMORY_CHUNK_MB
                        ? WVM_RESOURCE_MEMORY_CHUNK_MB
                        : local_memory - assigned_memory;

                vm->memory_nodes[memory_chunk++] = node->vnode_start;
                assigned_memory += assigned;
            }
        }
        vm->memory_chunk_count = memory_chunk;

        /*
         * The compatibility runtime currently treats the first vCPU route as
         * the QEMU-host local prefix.  Publish that deterministic choice
         * explicitly so later manifest work can consume it without guessing.
         */
        for (i = 0; i < ordered_count; i++) {
            uint32_t node_index = ordered_indices[i];

            if (vm_cpu[node_index] != 0) {
                vm->host_phys_id = plan->nodes[node_index].phys_id;
                break;
            }
        }

        free(ordered_indices);
    }

    for (i = 0; i < plan->node_count; i++) {
        vm->vcpus_per_node[i] = (uint16_t)vm_cpu[i];
        vm->memory_mb_per_node[i] = vm_memory[i];
        used_cpu[i] += vm_cpu[i];
        used_memory[i] += vm_memory[i];
    }

    plan->vm_present[request->vm_id] = 1;
    plan->vm_count++;
    ret = 0;

out:
    free(vm_cpu);
    free(vm_memory);
    return ret;
}

int wvm_resource_plan_validate(const struct wvm_resource_plan *plan,
                               char *error, size_t error_len)
{
    uint32_t *used_cpu = NULL;
    uint64_t *used_memory = NULL;
    uint32_t observed_vm_count = 0;
    uint32_t i;
    int ret = -1;

    if (!plan || plan->node_count == 0) {
        set_error(error, error_len, "resource plan has invalid node count");
        return -1;
    }
    if (plan->node_count > UINT32_MAX) {
        set_error(error, error_len, "resource plan node count exceeds u32");
        return -1;
    }

    used_cpu = calloc(plan->node_count, sizeof(*used_cpu));
    used_memory = calloc(plan->node_count, sizeof(*used_memory));
    if (!used_cpu || !used_memory) {
        set_error(error, error_len, "failed to allocate validation arrays");
        goto out;
    }

    for (i = 0; i < plan->node_count; i++) {
        const struct wvm_resource_node *node = &plan->nodes[i];

        if (node->phys_id == UINT32_MAX || node->port == 0 ||
            node->cpu_capacity == 0 || node->memory_mb == 0 ||
            node->dht_slots == 0) {
            set_error(error, error_len,
                      "resource plan has invalid node at index %u", i);
            goto out;
        }
        if (node_index_by_id(plan, node->phys_id) != (int)i) {
            set_error(error, error_len,
                      "resource plan has duplicate node id %u", node->phys_id);
            goto out;
        }
    }

    for (i = 0; i < WVM_MAX_VMS; i++) {
        const struct wvm_resource_vm *vm;
        uint32_t *per_vm_cpu = NULL;
        uint64_t *per_vm_memory = NULL;
        uint64_t assigned_memory = 0;
        uint32_t vcpu;
        uint32_t chunk;
        int host_index;

        if (plan->vm_present[i] != 0 && plan->vm_present[i] != 1) {
            set_error(error, error_len,
                      "resource plan has invalid VM presence flag at %u", i);
            goto out;
        }
        if (!plan->vm_present[i]) {
            continue;
        }
        observed_vm_count++;
        vm = &plan->vms[i];

        if (vm->vm_id != i || vm->vcpu_count == 0 ||
            vm->vcpu_count > WVM_CPU_ROUTE_TABLE_SIZE ||
            vm->memory_mb == 0 ||
            vm->memory_chunk_count == 0 ||
            vm->memory_chunk_count > WVM_RESOURCE_MAX_MEMORY_CHUNKS ||
            (vm->policy != WVM_RESOURCE_POLICY_COMPACT &&
             vm->policy != WVM_RESOURCE_POLICY_SPREAD)) {
            set_error(error, error_len, "VM %u has invalid plan metadata", i);
            goto out;
        }

        host_index = node_index_by_id(plan, vm->host_phys_id);
        if (host_index < 0) {
            set_error(error, error_len, "VM %u has no valid host node", i);
            goto out;
        }

        per_vm_cpu = calloc(plan->node_count, sizeof(*per_vm_cpu));
        per_vm_memory = calloc(plan->node_count, sizeof(*per_vm_memory));
        if (!per_vm_cpu || !per_vm_memory) {
            set_error(error, error_len, "failed to allocate per-VM validation arrays");
            free(per_vm_cpu);
            free(per_vm_memory);
            goto out;
        }

        for (vcpu = 0; vcpu < vm->vcpu_count; vcpu++) {
            int node_index = -1;

            for (uint32_t n = 0; n < plan->node_count; n++) {
                if (plan->nodes[n].vnode_start == vm->vcpu_nodes[vcpu]) {
                    node_index = (int)n;
                    break;
                }
            }
            if (node_index < 0) {
                set_error(error, error_len,
                          "VM %u vCPU %u has no registered executor node",
                          i, vcpu);
                free(per_vm_cpu);
                free(per_vm_memory);
                goto out;
            }
            per_vm_cpu[node_index]++;
        }
        if (per_vm_cpu[host_index] == 0) {
            set_error(error, error_len,
                      "VM %u host node has no local vCPU assignment", i);
            free(per_vm_cpu);
            free(per_vm_memory);
            goto out;
        }

        for (chunk = 0; chunk < vm->memory_chunk_count; chunk++) {
            uint64_t chunk_mb =
                vm->memory_mb - assigned_memory > WVM_RESOURCE_MEMORY_CHUNK_MB
                    ? WVM_RESOURCE_MEMORY_CHUNK_MB
                    : vm->memory_mb - assigned_memory;
            int node_index = -1;

            if (chunk_mb == 0) {
                set_error(error, error_len,
                          "VM %u has excess memory chunks", i);
                free(per_vm_cpu);
                free(per_vm_memory);
                goto out;
            }
            for (uint32_t n = 0; n < plan->node_count; n++) {
                if (plan->nodes[n].vnode_start == vm->memory_nodes[chunk]) {
                    node_index = (int)n;
                    break;
                }
            }
            if (node_index < 0) {
                set_error(error, error_len,
                          "VM %u memory chunk %u has no registered owner",
                          i, chunk);
                free(per_vm_cpu);
                free(per_vm_memory);
                goto out;
            }
            per_vm_memory[node_index] += chunk_mb;
            assigned_memory += chunk_mb;
        }
        if (assigned_memory != vm->memory_mb) {
            set_error(error, error_len,
                      "VM %u memory chunks cover %llu MB, expected %llu MB",
                      i, (unsigned long long)assigned_memory,
                      (unsigned long long)vm->memory_mb);
            free(per_vm_cpu);
            free(per_vm_memory);
            goto out;
        }

        for (uint32_t n = 0; n < plan->node_count; n++) {
            if (vm->vcpus_per_node[n] != per_vm_cpu[n] ||
                vm->memory_mb_per_node[n] != per_vm_memory[n]) {
                set_error(error, error_len,
                          "VM %u per-node summary does not match assignments",
                          i);
                free(per_vm_cpu);
                free(per_vm_memory);
                goto out;
            }
            used_cpu[n] += per_vm_cpu[n];
            used_memory[n] += per_vm_memory[n];
        }

        free(per_vm_cpu);
        free(per_vm_memory);
    }

    if (observed_vm_count != plan->vm_count) {
        set_error(error, error_len,
                  "resource plan VM count does not match presence map");
        goto out;
    }

    for (i = 0; i < plan->node_count; i++) {
        if (used_cpu[i] > plan->nodes[i].cpu_capacity ||
            used_memory[i] > plan->nodes[i].memory_mb) {
            set_error(error, error_len,
                      "resource plan overcommits node %u",
                      plan->nodes[i].phys_id);
            goto out;
        }
    }

    ret = 0;

out:
    free(used_cpu);
    free(used_memory);
    return ret;
}

int wvm_resource_plan_load(const char *path, struct wvm_resource_plan *plan,
                           char *error, size_t error_len)
{
    struct wvm_resource_vm_request requests[WVM_MAX_VMS];
    uint32_t *used_cpu = NULL;
    uint64_t *used_memory = NULL;
    uint32_t request_count = 0;
    FILE *fp;
    char line[256];
    int ret = -1;

    if (!path || !plan) {
        set_error(error, error_len, "resource planner received an invalid argument");
        return -1;
    }

    memset(plan, 0, sizeof(*plan));
    plan->node_capacity = 64;
    plan->nodes = calloc(plan->node_capacity, sizeof(*plan->nodes));
    if (!plan->nodes) {
        set_error(error, error_len, "failed to allocate initial node array");
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        set_error(error, error_len, "cannot open %s: %s", path, strerror(errno));
        free(plan->nodes);
        plan->nodes = NULL;
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char keyword[16];

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        if (sscanf(line, "%15s", keyword) != 1) {
            continue;
        }

        if (strcmp(keyword, "NODE") == 0) {
            struct wvm_resource_node *node;
            unsigned int id, port, cores, memory_gib, dht_slots = 0;
            int fields;

            if (plan->node_count >= UINT32_MAX) {
                set_error(error, error_len, "NODE count exceeds u32 maximum");
                goto fail;
            }

            if (plan->node_count >= plan->node_capacity) {
                uint32_t new_capacity = plan->node_capacity * 2;
                struct wvm_resource_node *new_nodes;

                if (new_capacity > UINT32_MAX / sizeof(*new_nodes)) {
                    set_error(error, error_len, "NODE capacity allocation would overflow");
                    goto fail;
                }
                new_nodes = realloc(plan->nodes, new_capacity * sizeof(*new_nodes));
                if (!new_nodes) {
                    set_error(error, error_len, "failed to grow NODE array");
                    goto fail;
                }
                plan->nodes = new_nodes;
                plan->node_capacity = new_capacity;
            }

            node = &plan->nodes[plan->node_count];
            fields = sscanf(line, "%*s %u %63s %u %u %u %u", &id, node->ip,
                            &port, &cores, &memory_gib, &dht_slots);
            if (fields != 5 && fields != 6) {
                set_error(error, error_len, "invalid NODE line: %s", line);
                goto fail;
            }
            if (id == UINT32_MAX || port == 0 || port > UINT16_MAX ||
                cores == 0 || memory_gib == 0) {
                set_error(error, error_len, "invalid NODE capacity or identity: %s",
                          line);
                goto fail;
            }
            if (node_index_by_id(plan, id) >= 0) {
                set_error(error, error_len, "duplicate physical NODE id %u", id);
                goto fail;
            }

            if (fields == 5) {
                dht_slots = memory_gib / 4;
                if (dht_slots == 0) {
                    dht_slots = 1;
                }
            }
            if (dht_slots == 0) {
                set_error(error, error_len, "invalid DHT slot count for NODE %u", id);
                goto fail;
            }
            if (plan->total_vnodes > UINT32_MAX - dht_slots) {
                set_error(error, error_len, "total vnode count would overflow u32 for NODE %u", id);
                goto fail;
            }

            node->phys_id = id;
            node->port = (uint16_t)port;
            node->cpu_capacity = cores;
            node->memory_mb = (uint64_t)memory_gib * 1024U;
            node->dht_slots = dht_slots;
            node->vnode_start = plan->total_vnodes;
            plan->total_vnodes += dht_slots;
            plan->node_count++;
            continue;
        }

        if (strcmp(keyword, "VM") == 0) {
            unsigned int vm_id, vcpus, memory_mb;
            char policy[16] = {0};
            int fields;
            struct wvm_resource_vm_request *request;

            fields = sscanf(line, "%*s %u %u %u %15s", &vm_id, &vcpus,
                            &memory_mb, policy);
            if (fields == 3) {
                /* Legacy VM <id> <start_vnode> <vnode_count>. */
                continue;
            }
            if (fields != 4 || vm_id >= WVM_MAX_VMS || vcpus == 0 ||
                vcpus > WVM_CPU_ROUTE_TABLE_SIZE || memory_mb == 0) {
                set_error(error, error_len, "invalid VM resource request: %s",
                          line);
                goto fail;
            }
            if (request_count >= WVM_MAX_VMS ||
                plan->vm_present[vm_id] != 0) {
                set_error(error, error_len, "duplicate VM id %u", vm_id);
                goto fail;
            }

            request = &requests[request_count++];
            request->vm_id = (uint8_t)vm_id;
            request->vcpu_count = vcpus;
            request->memory_mb = memory_mb;
            if (strcmp(policy, "compact") == 0) {
                request->policy = WVM_RESOURCE_POLICY_COMPACT;
            } else if (strcmp(policy, "spread") == 0) {
                request->policy = WVM_RESOURCE_POLICY_SPREAD;
            } else {
                set_error(error, error_len, "VM %u has unknown policy '%s'",
                          vm_id, policy);
                goto fail;
            }

            /*
             * Use the presence map as a parser-only duplicate guard.  The
             * full placement is installed only after all requests are parsed.
             */
            plan->vm_present[vm_id] = 1;
        }
    }
    fclose(fp);

    if (plan->node_count == 0) {
        set_error(error, error_len, "configuration contains no NODE entries");
        return -1;
    }

    used_cpu = calloc(plan->node_count, sizeof(*used_cpu));
    used_memory = calloc(plan->node_count, sizeof(*used_memory));
    if (!used_cpu || !used_memory) {
        set_error(error, error_len, "failed to allocate placement arrays");
        free(used_cpu);
        free(used_memory);
        return -1;
    }

    memset(plan->vm_present, 0, sizeof(plan->vm_present));
    sort_vm_requests(requests, request_count);
    for (uint32_t i = 0; i < request_count; i++) {
        if (reserve_vm(plan, &requests[i], used_cpu, used_memory, error,
                       error_len) != 0) {
            free(used_cpu);
            free(used_memory);
            return -1;
        }
    }

    ret = wvm_resource_plan_validate(plan, error, error_len);
    free(used_cpu);
    free(used_memory);
    return ret;

fail:
    fclose(fp);
    free(plan->nodes);
    plan->nodes = NULL;
    plan->node_capacity = 0;
    plan->node_count = 0;
    return -1;
}

const struct wvm_resource_node *
wvm_resource_plan_find_node(const struct wvm_resource_plan *plan,
                            uint32_t phys_id)
{
    int index;

    if (!plan) {
        return NULL;
    }
    index = node_index_by_id(plan, phys_id);
    return index >= 0 ? &plan->nodes[index] : NULL;
}

const struct wvm_resource_vm *
wvm_resource_plan_get_vm(const struct wvm_resource_plan *plan, uint8_t vm_id)
{
    if (!plan || !plan->vm_present[vm_id]) {
        return NULL;
    }
    return &plan->vms[vm_id];
}

uint32_t wvm_resource_plan_local_vcpus(const struct wvm_resource_plan *plan,
                                       uint8_t vm_id, uint32_t phys_id)
{
    const struct wvm_resource_vm *vm = wvm_resource_plan_get_vm(plan, vm_id);
    int index;

    if (!vm) {
        return 0;
    }
    index = node_index_by_id(plan, phys_id);
    return index < 0 ? 0 : vm->vcpus_per_node[index];
}

uint64_t wvm_resource_plan_local_memory_mb(
    const struct wvm_resource_plan *plan, uint8_t vm_id, uint32_t phys_id)
{
    const struct wvm_resource_vm *vm = wvm_resource_plan_get_vm(plan, vm_id);
    int index;

    if (!vm) {
        return 0;
    }
    index = node_index_by_id(plan, phys_id);
    return index < 0 ? 0 : vm->memory_mb_per_node[index];
}

uint32_t wvm_resource_plan_host_node(const struct wvm_resource_plan *plan,
                                     uint8_t vm_id)
{
    const struct wvm_resource_vm *vm = wvm_resource_plan_get_vm(plan, vm_id);

    return vm ? vm->host_phys_id : 0;
}

void wvm_resource_plan_print(const struct wvm_resource_plan *plan,
                             int vm_id_filter)
{
    uint32_t i;

    if (!plan) {
        return;
    }

    printf("WVM_PLAN_NODES=%u\n", plan->node_count);
    printf("WVM_PLAN_DHT_SLOTS=%u\n", plan->total_vnodes);
    for (i = 0; i < plan->node_count; i++) {
        const struct wvm_resource_node *node = &plan->nodes[i];

        printf("NODE id=%u cpu=%u memory_mb=%llu dht_slots=%u vnode_start=%u\n",
               node->phys_id, node->cpu_capacity,
               (unsigned long long)node->memory_mb, node->dht_slots,
               node->vnode_start);
        printf("WVM_PLAN_NODE%u_VNODE=%u\n", node->phys_id,
               node->vnode_start);
    }

    for (i = 0; i < WVM_MAX_VMS; i++) {
        const struct wvm_resource_vm *vm;
        uint32_t node_index;
        int host_index;

        if (!plan->vm_present[i] ||
            (vm_id_filter >= 0 && i != (uint32_t)vm_id_filter)) {
            continue;
        }

        vm = &plan->vms[i];
        host_index = node_index_by_id(plan, vm->host_phys_id);
        printf("VM id=%u policy=%s vcpus=%u memory_mb=%llu chunks=%u\n",
               vm->vm_id,
               vm->policy == WVM_RESOURCE_POLICY_COMPACT ? "compact" : "spread",
               vm->vcpu_count, (unsigned long long)vm->memory_mb,
               vm->memory_chunk_count);
        printf("WVM_PLAN_VM%u_VCPUS=%u\n", vm->vm_id, vm->vcpu_count);
        printf("WVM_PLAN_VM%u_MEMORY_MB=%llu\n", vm->vm_id,
               (unsigned long long)vm->memory_mb);
        printf("WVM_PLAN_VM%u_HOST_NODE=%u\n", vm->vm_id,
               vm->host_phys_id);
        for (node_index = 0; node_index < plan->node_count; node_index++) {
            if (vm->vcpus_per_node[node_index] == 0 &&
                vm->memory_mb_per_node[node_index] == 0) {
                continue;
            }
            printf("VM_NODE vm=%u node=%u vcpus=%u memory_mb=%llu\n",
                   vm->vm_id, plan->nodes[node_index].phys_id,
                   vm->vcpus_per_node[node_index],
                   (unsigned long long)vm->memory_mb_per_node[node_index]);
            printf("WVM_PLAN_VM%u_NODE%u_VCPUS=%u\n", vm->vm_id,
                   plan->nodes[node_index].phys_id,
                   vm->vcpus_per_node[node_index]);
            printf("WVM_PLAN_VM%u_NODE%u_MEMORY_MB=%llu\n", vm->vm_id,
                   plan->nodes[node_index].phys_id,
                   (unsigned long long)vm->memory_mb_per_node[node_index]);
        }
        if (host_index >= 0) {
            printf("WVM_PLAN_VM%u_LOCAL_VCPUS=%u\n", vm->vm_id,
                   vm->vcpus_per_node[host_index]);
        }
    }
}

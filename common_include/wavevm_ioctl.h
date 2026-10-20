#ifndef WAVEVM_IOCTL_H
#define WAVEVM_IOCTL_H

#include <linux/ioctl.h>
#include "../common_include/wavevm_protocol.h"

struct wvm_ioctl_gateway {
    uint32_t gw_id;
    uint32_t ip;   // Network byte order
    uint16_t port; // Network byte order
};

// Control Plane Injection
#define IOCTL_SET_GATEWAY _IOW('G', 1, struct wvm_ioctl_gateway)

#define IOCTL_WVM_REMOTE_RUN _IOWR('G', 2, struct wvm_ioctl_remote_run)

// 路由表更新结构体
struct wvm_ioctl_route_update {
    uint32_t start_index;
    uint32_t count;
    // 柔性数组，用户态需分配足够的空间
    // 对于 CPU 表是 uint32_t，对于 MEM 表是 uint16_t，这里统一用 u32 传输方便对齐
    uint32_t entries[0]; 
};

#define IOCTL_UPDATE_CPU_ROUTE _IOW('G', 3, struct wvm_ioctl_route_update)
#define IOCTL_UPDATE_MEM_ROUTE _IOW('G', 4, struct wvm_ioctl_route_update)
#define IOCTL_WAIT_IRQ _IOR('G', 5, uint32_t) 
// 返回值是触发中断的 IRQ 号 (简化起见，返回 1 表示有中断)

#include <linux/types.h>

struct wvm_mem_range {
    uint64_t start;
    uint64_t size;
};

// 动态内存布局结构体：支持最多 32 个不连续的 RAM 槽位
struct wvm_ioctl_mem_layout {
    uint32_t count;
    struct wvm_mem_range slots[32];
};

#define IOCTL_SET_MEM_LAYOUT   _IOW('G', 10, struct wvm_ioctl_mem_layout)
#define IOCTL_RPC_SYNC_ACK     _IOW('G', 11, uint8_t)
#define IOCTL_UPDATE_EPOCH _IOW('G', 20, uint32_t)
/* 1 GiB guest-memory chunk -> raw directory vnode placement table. */
#define IOCTL_UPDATE_MEMORY_PLACEMENT _IOW('G', 21, struct wvm_ioctl_route_update)
/* Keep the kernel Logic Core's composite-ID namespace aligned with the master. */
/* Retired: returns -EOPNOTSUPP. Use IOCTL_WVM_BIND_CONTEXT. */
#define IOCTL_SET_VM_ID _IOW('G', 22, uint32_t)

/*
 * Context-bound Mode A admission.
 *
 * Manifest-gated launch must BIND its VM identity before using /dev/wavevm.
 * Mode A second-VM gate is restored (A01–A04 open): QUERY_CAPS advertises
 * SINGLE_CONTEXT with max_concurrent_contexts=1. Per-VM context registry code
 * remains, but admission+caps must not claim multi-context until isolation
 * evidence closes those gaps. BIND still enforces the advertised max (-ENOSPC).
 * SET_VM_ID is retired (-EOPNOTSUPP).
 */
#define WVM_KERNEL_CONTEXT_MAGIC       0x574b4358U /* "WKCX" */
#define WVM_KERNEL_CONTEXT_ABI_VERSION 3U /* F11: +node_instance_id; needs new ko */
#define WVM_KERNEL_DIGEST_BYTES        32U
#define WVM_KERNEL_FENCE_BYTES         16U
/* Registry hard cap (code); QUERY_CAPS advertises 1 while the gate is closed. */
#define WVM_KERNEL_MAX_CONCURRENT_CONTEXTS 64U

#define WVM_KERNEL_CAP_CONTEXT_BIND    (1ULL << 0)
#define WVM_KERNEL_CAP_SINGLE_CONTEXT  (1ULL << 1) /* set while second-VM gate closed */

struct wvm_ioctl_route_snapshot_key {
    struct {
        uint32_t vm_id;
        uint64_t vm_incarnation;
        uint64_t route_scope_id;
    } scope_key;
    uint64_t topology_revision;
    uint64_t route_generation;
    uint8_t snapshot_digest[WVM_KERNEL_DIGEST_BYTES];
};

struct wvm_ioctl_context_bind {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t vm_id;
    uint32_t physical_node_id;
    /* F11: same-host multi compute instance identity (ABI v3). */
    uint64_t node_instance_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t candidate_manifest_digest[WVM_KERNEL_DIGEST_BYTES];
    uint8_t capability_profile_digest[WVM_KERNEL_DIGEST_BYTES];
    uint8_t activation_fence[WVM_KERNEL_FENCE_BYTES];
    struct wvm_ioctl_route_snapshot_key route_snapshot_key;
};

struct wvm_ioctl_context_caps {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint32_t max_concurrent_contexts;
    uint32_t active_contexts;
    uint64_t feature_bits;
};

#define IOCTL_WVM_BIND_CONTEXT  _IOW('G', 30, struct wvm_ioctl_context_bind)
#define IOCTL_WVM_UNBIND_CONTEXT _IOW('G', 31, struct wvm_ioctl_context_bind)
#define IOCTL_WVM_QUERY_CAPS    _IOR('G', 32, struct wvm_ioctl_context_caps)

#endif // WAVEVM_IOCTL_H

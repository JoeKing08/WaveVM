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
 * After A01–A04 isolation evidence, QUERY_CAPS advertises CONTEXT_BIND with
 * max_concurrent_contexts=WVM_KERNEL_MAX_CONCURRENT_CONTEXTS (no SINGLE_CONTEXT).
 * BIND enforces the advertised max (-ENOSPC). SET_VM_ID is retired (-EOPNOTSUPP).
 */
#define WVM_KERNEL_CONTEXT_MAGIC       0x574b4358U /* "WKCX" */
#define WVM_KERNEL_CONTEXT_ABI_VERSION 4U
#define WVM_KERNEL_DIGEST_BYTES        32U
#define WVM_KERNEL_FENCE_BYTES         16U
/* Registry + QUERY_CAPS advertised concurrent Mode A context limit. */
#define WVM_KERNEL_MAX_CONCURRENT_CONTEXTS 64U

#define WVM_KERNEL_CAP_CONTEXT_BIND    (1ULL << 0)
#define WVM_KERNEL_CAP_SINGLE_CONTEXT  (1ULL << 1) /* legacy; unset when multi-context open */

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
    uint8_t attach_capability[WVM_KERNEL_DIGEST_BYTES];
};

struct wvm_ioctl_context_caps {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint32_t max_concurrent_contexts;
    uint32_t active_contexts;
    uint64_t feature_bits;
};

#define IOCTL_WVM_BIND_CONTEXT  _IOWR('G', 30, struct wvm_ioctl_context_bind)
#define IOCTL_WVM_UNBIND_CONTEXT _IOW('G', 31, struct wvm_ioctl_context_bind)
#define IOCTL_WVM_QUERY_CAPS    _IOR('G', 32, struct wvm_ioctl_context_caps)

/*
 * R04: userspace consumer for permanent Mode A diff-commit failures.
 * Bound context reports retained failed_diffs / last errno so the runtime can
 * pause or fail the VM instead of silently continuing after pre-image park.
 */
#define WVM_KERNEL_DIFF_STATUS_MAGIC 0x574b4453U /* "WKDS" */
#define WVM_KERNEL_DIFF_STATUS_VERSION 1U

struct wvm_ioctl_diff_status {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    int32_t last_failure; /* 0 = none; else negated errno or send_rc */
    uint32_t failed_diff_count;
    uint64_t oldest_failed_gpa; /* 0 when count==0 */
    uint32_t oldest_send_retries;
    uint32_t reserved2;
};

#define IOCTL_WVM_QUERY_DIFF_STATUS     _IOR('G', 33, struct wvm_ioctl_diff_status)

/* Local capture/completion boundary. Only the context's runtime owner may
 * dequeue or complete requests; routing and version decisions stay in it. */
#define WVM_KERNEL_MEMORY_READ   1U
#define WVM_KERNEL_MEMORY_COMMIT 2U
#define WVM_KERNEL_MEMORY_PAGE_BYTES 4096U
#define WVM_KERNEL_MEMORY_MAX_PENDING 256U

struct wvm_ioctl_memory_operation {
    uint64_t request_id;
    uint8_t operation_id[16];
    uint64_t gpa;
    uint64_t base_version;
    uint64_t result_version;
    int32_t status;
    uint16_t kind;
    uint16_t offset;
    uint32_t data_bytes;
    uint32_t reserved;
    uint8_t data[WVM_KERNEL_MEMORY_PAGE_BYTES];
};

struct wvm_ioctl_memory_config {
    struct wvm_ioctl_context_bind identity;
    /* Entire admitted GPA extent; holes remain excluded by RAM registration. */
    uint64_t guest_physical_limit;
    uint32_t local_vnode;
    uint32_t range_count;
    struct wvm_mem_range ranges[32];
};

struct wvm_ioctl_memory_invalidate {
    uint64_t gpa;
    uint64_t result_version;
};

#define IOCTL_WVM_MEMORY_OWNER _IOW('G', 34, struct wvm_ioctl_memory_config)
#define IOCTL_WVM_MEMORY_DEQUEUE _IOR('G', 35, struct wvm_ioctl_memory_operation)
#define IOCTL_WVM_MEMORY_COMPLETE _IOW('G', 36, struct wvm_ioctl_memory_operation)
#define IOCTL_WVM_MEMORY_STOP _IO('G', 37)
#define IOCTL_WVM_MEMORY_DRAIN _IO('G', 38)
#define IOCTL_WVM_MEMORY_INVALIDATE _IOW('G', 39, struct wvm_ioctl_memory_invalidate)
#define IOCTL_WVM_MEMORY_QUIESCE _IO('G', 40)

#endif // WAVEVM_IOCTL_H

#ifndef LOGIC_CORE_H
#define LOGIC_CORE_H

#include "unified_driver.h"
#include "../common_include/wavevm_protocol.h"
#ifdef __KERNEL__
struct wvm_vm_route_scope_key {
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t route_scope_id;
};

struct wvm_route_snapshot_key {
    struct wvm_vm_route_scope_key scope_key;
    uint64_t topology_revision;
    uint64_t route_generation;
    uint8_t snapshot_digest[32];
};
#else
#include "../common_include/wavevm_manifest.h"
#endif
#ifdef __KERNEL__
#include <linux/in.h>
#else
#include <stdint.h>
#include <netinet/in.h>
#endif

#ifndef MAKE_VERSION
#define MAKE_VERSION(epoch, counter) (((uint64_t)(epoch) << 32) | (counter))
#endif
#ifndef GET_COUNTER
#define GET_COUNTER(version) ((uint32_t)((version) & 0xFFFFFFFF))
#endif

extern int g_my_node_id;
extern uint32_t g_curr_epoch;
extern uint8_t g_my_node_state;
#ifdef __KERNEL__
uint32_t wvm_kernel_current_vm_id(void);
void *wvm_kernel_active_dir_table(void);
void *wvm_kernel_active_dir_locks(void);
void *wvm_kernel_active_route_context(void);
void *wvm_logic_alloc_dir_table(void);
void wvm_logic_free_dir_table(void *table);
void *wvm_logic_alloc_dir_locks(void);
void wvm_logic_free_dir_locks(void *locks);
void *wvm_logic_alloc_route_context(void);
void wvm_logic_free_route_context(void *route);
#define WVM_CURRENT_VM_ID() wvm_kernel_current_vm_id()
#else
extern uint32_t g_my_vm_id;
#define WVM_CURRENT_VM_ID() g_my_vm_id
#endif

// --- 初始化与配置 ---
int wvm_core_init(struct dsm_driver_ops *ops, int total_nodes_hint);
void wvm_set_total_nodes(int count);
void wvm_set_my_node_id(int id);

// --- 核心处理逻辑 (被 User/Kernel Backend 调用) ---
// 处理收到的网络包
void wvm_logic_process_packet(struct wvm_header *hdr, void *payload, uint32_t source_node_id);

// --- 缺页处理逻辑 (被 Fault Handler 调用) ---
// V28 兜底：拉取全页
// 返回 0 成功 (page_buffer 已填充), <0 失败
// version_out: 用于回传版本号给 V29 Wavelet 引擎
int wvm_handle_page_fault_logic(uint64_t gpa, void *page_buffer, uint64_t *version_out);

// [V29] 本地缺页快速路径 (内核态专用)
int wvm_handle_local_fault_fastpath(uint64_t gpa, void* page_buffer, uint64_t *version_out);

/*
 * Apply one V1 version-checked diff to the local directory page. This is a
 * local semantic adapter only: it does not emit network traffic or push
 * notifications. Completion and subscriber delivery stay above this layer.
 */
int wvm_handle_local_commit(uint64_t gpa, uint64_t base_version,
                               uint16_t offset, const uint8_t *data,
                               size_t data_bytes, uint64_t *result_version);

/*
 * Publish an already-applied V1 commit to the captured subscriber set.
 * Queueing is performed after the page lock is released; the directory
 * mutation remains authoritative even if a best-effort HINT push is dropped.
 */
int wvm_publish_local_commit(uint64_t gpa, uint64_t result_version,
                                uint16_t offset, const uint8_t *data,
                                size_t data_bytes, uint32_t writer_node_id);

// [V29] 宣告兴趣 (异步)
void wvm_declare_interest_in_neighborhood(uint64_t gpa);

// --- RPC 接口 ---
int wvm_rpc_call(uint16_t msg_type, void *payload, int len, uint32_t target_id, void *rx_buffer, int rx_len);

// --- 路由接口 ---
uint32_t wvm_get_directory_node_id(uint64_t gpa);
uint32_t wvm_get_storage_node_id(uint64_t lba);

void update_local_topology_view(uint32_t src_id, uint32_t src_epoch, uint8_t src_state, struct sockaddr_in *src_addr, uint16_t src_ctrl_port);
void wvm_logic_update_local_version(uint64_t gpa);
void wvm_logic_broadcast_rpc(void *full_pkt_data, int full_pkt_len, uint16_t msg_type);

// 计算任务路由 (V27 遗留，用于 RPC 调度)
uint32_t wvm_get_compute_slave_id(int vcpu_index);
uint32_t wvm_get_cpu_mapping_raw(int vcpu_index);

// 导出 CPU 路由表（供内核态注入）
const uint32_t* wvm_get_cpu_route_table(void);
const uint32_t* wvm_get_memory_route_table(void);

void wvm_set_mem_mapping(int slot, uint32_t value);
void wvm_set_memory_mapping(int chunk_index, uint32_t node_id);
/*
 * Canonical runtime manifests assign arbitrary non-overlapping GPA ranges.
 * The old 1 GiB table remains a compatibility cache; this ordered range map
 * is the user-space authority for admitted launches.
 */
int wvm_set_memory_range_mapping(uint64_t gpa_start, uint64_t bytes,
                                 uint32_t node_id);
void wvm_clear_memory_mappings(void);

void wvm_set_cpu_mapping(int vcpu_index, uint32_t slave_id);
void wvm_clear_cpu_mappings(void);

int wvm_logic_bind_route_snapshot(
    const struct wvm_route_snapshot_key *snapshot_key);
int wvm_logic_route_snapshot_valid(void);
int wvm_logic_get_route_snapshot_key(
    struct wvm_route_snapshot_key *snapshot_key);
void wvm_logic_unbind_route_snapshot(void);

#endif // LOGIC_CORE_H

/*
 * [IDENTITY] Protocol Stack - The Wavelet Law
 * ---------------------------------------------------------------------------
 * 物理角色：系统的"通用语言"和逻辑时钟定义。
 * 职责边界：
 * 1. 定义 Wavelet (MSG_COMMIT/PUSH) 与 V28 MESI (MSG_INVALIDATE) 兼容指令集。
 * 2. 规定 wvm_header 结构，集成 QoS 分级与端到端 CRC32。
 * 3. 提供 is_next_version 版本判定算法，解决 UDP 乱序真理冲突。
 * 
 * [禁止事项]
 * - 严禁删除 Header 中的 epoch 字段 (它是解决网络分区脑裂的唯一钥匙)。
 * - 严禁在 Payload 结构体中添加非对齐字段。
 * ---------------------------------------------------------------------------
 */
#ifndef WAVEVM_PROTOCOL_H
#define WAVEVM_PROTOCOL_H

#include "wavevm_config.h"
#include "platform_defs.h"
#include <linux/kvm.h>

#ifndef WVM_CPU_RUN_STATUS_MEMORY_FAILURE
#define WVM_CPU_RUN_STATUS_MEMORY_FAILURE (-117)
#endif

/*
 * WaveVM V29.5 "Wavelet" Protocol Definition (FINAL FIXED)
 * Includes V28 MESI Fallback & V29 Prophet Extensions
 */

// --- 1. 网络消息类型 (Network Message Types) ---
enum {
    // [Core] 基础通信
    MSG_PING           = 0,
    MSG_MEM_READ       = 1, // Pull Request
    MSG_MEM_WRITE      = 2, // Push / Direct Write
    MSG_MEM_ACK        = 3, // Pull Response / Sync ACK
    
    // [VCPU] 远程调度
    MSG_VCPU_RUN       = 5,
    MSG_VCPU_EXIT      = 6,
    MSG_VFIO_IRQ       = 7,

    // [V28 MESI] 一致性协议 
    MSG_INVALIDATE              = 10, // Directory -> Owner: Revoke permission
    MSG_DOWNGRADE             = 11, // Directory -> Owner: M -> S
    MSG_FETCH_AND_INVALIDATE  = 12, // Directory -> Owner: Fetch data & Invalid
    MSG_WRITE_BACK             = 13, // Owner -> Directory: Data writeback

    // [V29 Wavelet] 主动推送与版本控制
    MSG_DECLARE_INTEREST   = 25, // Client -> Directory: Subscribe
    MSG_PAGE_PUSH_FULL     = 26, // Directory -> Client: Full Page Update
    MSG_PAGE_PUSH_DIFF      = 27, // Directory -> Client: Diff Update
    MSG_COMMIT_DIFF         = 28, // Client -> Directory: Diff Commit
    MSG_FORCE_SYNC          = 29, // Directory -> Client: Version Conflict

    // [V29 Prophet] 语义透传
    MSG_RPC_BATCH_MEMSET   = 31, // Scatter-Gather Batch Command

    // [自治集群扩展]
    MSG_HEARTBEAT       = 40, // 周期性存活宣告与 Epoch Gossip
    MSG_VIEW_PULL        = 41, // 获取邻居的局部视图
    MSG_VIEW_ACK         = 42, // 返回局部视图数据
    MSG_NODE_ANNOUNCE  = 43, // 新节点上线宣告 (Warm-plug)

    // [STORAGE] 分布式块存储物理原语
    MSG_BLOCK_READ     = 50, // Master -> Slave (Pull Chunk)
    MSG_BLOCK_WRITE    = 51, // Master -> Slave (Push/Commit Chunk)
    MSG_BLOCK_ACK      = 52, // Slave -> Master
    MSG_BLOCK_FLUSH    = 53
};

// --- 2. 通用包头 (Header) ---
struct wvm_header {
    uint32_t magic;
    uint16_t msg_type;
    uint16_t payload_len; 
    uint32_t slave_id;      // Source Node ID
    uint32_t target_id;     // Destination Node ID (network order); AUTO_ROUTE means fallback
    union {
        uint64_t req_id;      // 给 ACK, VCPU_RUN 等事务 ID 用
        uint64_t target_gpa;  // 给 INVALIDATE, READ, WRITE 等地址指令用（旧版遗留）
    };
    uint8_t  qos_level;     // 1=Fast, 0=Slow
    uint8_t  flags;
    uint8_t  mode_tcg;
    uint8_t  node_state;    // 发送者当前的生命周期状态
    uint32_t epoch;         // 发送者所处的逻辑周期
    uint32_t crc32;         // End-to-End Integrity Check
} __attribute__((packed));

#define WVM_FLAG_ZERO 0x01
#define WVM_FLAG_ERROR 0x02
#define WVM_FLAG_NEED_ACK 0x04

// --- 3. Payload 结构体 (Data Structures) ---

// [V29] 增量更新日志
struct wvm_diff_log {
    uint64_t gpa;
    uint64_t version;     
    uint16_t offset;
    uint16_t size;
    uint8_t  data[0];     // Variable length data
} __attribute__((packed));

// [V29] 全页推送
struct wvm_full_page_push {
    uint64_t gpa;
    uint64_t version;
    uint8_t  data[4096];
} __attribute__((packed));

// [V29] 带版本的读响应
struct wvm_mem_ack_payload {
    uint64_t gpa;
    uint64_t version;
    uint8_t  data[4096];
} __attribute__((packed));

// [V29] 物理段描述符
struct wvm_rpc_region {
    uint64_t gpa;
    uint64_t len;
} __attribute__((packed));

// [V29] 批量操作指令
struct wvm_rpc_batch_memset {
    uint32_t val;
    uint32_t count;
    // Followed by: struct wvm_rpc_region regions[];
} __attribute__((packed));

// 节点生命周期状态语义
enum {
    NODE_STATE_SHADOW   = 0, // 刚启动，对拓扑不可见
    NODE_STATE_WARMING  = 1, // 预热中，同步元数据与热点页
    NODE_STATE_ACTIVE   = 2, // 活跃，承载 Owner 权限
    NODE_STATE_DRAINING = 3, // 准备下线，只读不写
    NODE_STATE_OFFLINE  = 4  // 已失效 (本地判定)
};

// 心跳 Payload：用于实现无中心的 Epoch 共识
struct wvm_heartbeat_payload {
    uint32_t local_epoch;
    uint32_t active_node_count; // 本地观察到的活跃节点数
    uint16_t load_factor;       // 负载情况
    uint32_t peer_epoch_sum;    // 用于快速计算均值或直方图的特征值
    uint16_t ctrl_port;
} __attribute__((packed));

// 视图交换结构：用于发现新邻居
struct wvm_view_entry {
    uint32_t node_id;
    uint32_t ip_addr;
    uint16_t port;
    uint8_t  state;
    uint16_t ctrl_port; 
} __attribute__((packed));

struct wvm_view_payload {
    uint32_t entry_count;
    struct wvm_view_entry entries[0];
} __attribute__((packed));

// --- 4. IPC 消息定义 (Local QEMU <-> Daemon) ---

typedef struct wvm_ipc_header_t {
    uint32_t type;
    uint32_t len;
} wvm_ipc_header_t;

#define WVM_IPC_TYPE_MEM_FAULT      1
#define WVM_IPC_TYPE_MEM_WRITE      2
#define WVM_IPC_TYPE_CPU_RUN         3
#define WVM_IPC_TYPE_IRQ               4
#define WVM_IPC_TYPE_COMMIT_DIFF     5
#define WVM_IPC_TYPE_COMMIT_DIFF_SYNC 8
#define WVM_IPC_TYPE_INVALIDATE       6 
#define WVM_IPC_TYPE_BLOCK_IO         7
#define WVM_IPC_TYPE_PUSH_BARRIER     9
#define WVM_IPC_TYPE_PUSH_BARRIER_ACK 10
#define WVM_IPC_TYPE_REGISTER         11
#define WVM_IPC_TYPE_TYPED_MEM_FAULT  12
#define WVM_IPC_TYPE_TYPED_MEM_COMMIT 13

/* Local IPC connection roles.  Registration removes any dependency on
 * connection arrival order when a QEMU instance opens several sockets. */
#define WVM_IPC_ROLE_ASYNC_PUSH       1
#define WVM_IPC_ROLE_SYNC             2

/*
 * Manifest-bound local registration.  The legacy four-byte role payload is
 * accepted only by compatibility launches that do not activate the runtime
 * gate.  A gated node runtime requires every QEMU connection to present the
 * same VM lifetime, candidate manifest, and capability profile.
 */
#define WVM_IPC_REGISTRATION_MAGIC   0x57565247U /* "WVRG" */
#define WVM_IPC_REGISTRATION_VERSION 1U
#define WVM_IPC_ENDPOINT_NAME_BYTES  128U

struct wvm_ipc_runtime_registration {
    uint32_t magic;
    uint16_t version;
    uint16_t ipc_role;
    uint32_t connection_role;
    uint32_t vm_id;
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint8_t candidate_manifest_digest[32];
    uint64_t local_runtime_instance_id;
    uint64_t caller_process_instance_id;
    uint8_t capability_profile_digest[32];
    char requested_endpoint_name[WVM_IPC_ENDPOINT_NAME_BYTES];
};

// [V29 Fix] 正式定义 RPC 透传类型
#define WVM_IPC_TYPE_RPC_PASSTHROUGH 99

// 前后端分离路由占位符
#define WVM_NODE_AUTO_ROUTE 0xFFFFFFFF  // 旧值 0x3FFFFFFF，改为全 1 避免与 vm_id 编码冲突

// --- Multi-VM Resource Pooling: VM ID 编解码 ---
// slave_id / target_id 的高 8 位编码 vm_id，低 24 位编码 node_id
// 协议头 48 字节不变，向后兼容：vm_id=0 时 ENCODE_ID(0,n) == n
#define WVM_VMID_SHIFT    24
#define WVM_VMID_MASK     (0xFFu << WVM_VMID_SHIFT)    // 0xFF000000
#define WVM_NODEID_MASK   ((1u << WVM_VMID_SHIFT) - 1)  // 0x00FFFFFF

#define WVM_ENCODE_ID(vm, node) (((uint32_t)(vm) << WVM_VMID_SHIFT) | ((node) & WVM_NODEID_MASK))
#define WVM_GET_VMID(id)        (((uint32_t)(id) >> WVM_VMID_SHIFT) & 0xFF)
#define WVM_GET_NODEID(id)      ((uint32_t)(id) & WVM_NODEID_MASK)

// [Fix #3] AUTO_ROUTE 是 sentinel 值 (0xFFFFFFFF)，不能做 GET_NODEID 后参与普通比较
// 所有需要判断"是否是有效路由目标"的地方必须先过此检查
#define WVM_IS_VALID_TARGET(id) ((uint32_t)(id) != WVM_NODE_AUTO_ROUTE)

#define WVM_CTRL_MAGIC 0x57564D43

#define SYNC_MAGIC 0x53594E43 

struct wvm_ipc_fault_req {
    uint64_t gpa;
    uint32_t len;
    uint32_t vcpu_id;
};

struct wvm_ipc_fault_ack {
    int status;
    uint32_t reserved;
    uint64_t version;
    /*
     * Local QEMU<->master IPC must carry page bytes explicitly: guest GPA is
     * not a flat offset into the master SHM when QEMU exposes multiple RAM
     * regions (for example NUMA high memory).
     */
    uint8_t data[4096];
};

struct wvm_ipc_write_req {
    uint64_t gpa;
    uint32_t len;
};

#define WVM_EXIT_PREEMPT 0x10000u

typedef struct {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint8_t sregs_data[512];
    /* [V30 TSC/kvmclock 同步]
     * 远程执行后必须把 slave 端的 TSC 值带回 master，否则 master 本地
     * KVM_RUN 恢复时 kvmclock 算出负 delta，导致内核时间戳溢出到
     * 18446744071s (接近 UINT64_MAX ns)，Guest 内核 hang 在 X.509
     * 证书解析等时间敏感路径。 */
    uint64_t tsc_value;           /* MSR_IA32_TSC (0x10) */
    uint64_t tsc_deadline;        /* MSR_IA32_TSCDEADLINE (0x6e0) */
    uint64_t kernel_gs_base;      /* MSR_KERNEL_GS_BASE (0xC0000102) */
    uint32_t tsc_valid;           /* 非零表示 tsc_value 字段有效 */
    uint32_t _pad0;               /* 8 字节对齐填充 */
    /* In-kernel LAPIC state must move with remote KVM execution, otherwise
     * post-SIPI parked APs lose timer/IPI wake state when the vCPU context
     * returns to the master-side KVM instance. */
    uint8_t lapic_data[sizeof(struct kvm_lapic_state)];
    uint32_t lapic_valid;
    uint32_t _pad1;
    uint8_t vcpu_events_data[sizeof(struct kvm_vcpu_events)];
    uint32_t vcpu_events_valid;
    uint32_t _pad2;
    uint8_t fpu_data[sizeof(struct kvm_fpu)];
    uint32_t fpu_valid;
    uint32_t _pad3;
    uint8_t xcrs_data[sizeof(struct kvm_xcrs)];
    uint32_t xcrs_valid;
    uint32_t _pad4;
    uint32_t mp_state;
    uint32_t mp_state_valid;
    uint32_t exit_reason;
    struct {
        uint8_t direction;
        uint8_t size;
        uint16_t port;
        uint32_t count;
        uint8_t data[8];
    } io;
    struct {
        uint64_t phys_addr;
        uint32_t len;
        uint8_t is_write;
        uint8_t data[8];
    } mmio;
} wvm_kvm_context_t;

/* Per-segment descriptor state (mirrors QEMU SegmentCache / KVM kvm_segment) */
typedef struct {
    uint64_t base;
    uint32_t limit;
    uint32_t selector;
    uint32_t flags;       /* QEMU SegmentCache.flags (DESC_* bits) */
    uint32_t _pad;
} wvm_seg_reg_t;

#define WVM_TCG_APIC_LVT_NB 6
#define WVM_TCG_XSAVE_AREA_SIZE 0xB00U
#define WVM_TCG_MTRR_FIXED_NB 11
#define WVM_TCG_MTRR_VAR_NB 8

typedef struct {
    uint32_t valid;
    uint32_t apicbase;
    uint32_t initial_apic_id;
    uint32_t spurious_vec;
    uint32_t isr[8];
    uint32_t tmr[8];
    uint32_t irr[8];
    uint32_t lvt[WVM_TCG_APIC_LVT_NB];
    uint32_t esr;
    uint32_t icr[2];
    uint32_t divide_conf;
    uint32_t initial_count;
    int32_t count_shift;
    /*
     * Offsets from the exporting QEMU_CLOCK_VIRTUAL.  WaveVM hands a TCG
     * vCPU between independent QEMU processes, whose virtual clock epochs
     * differ; raw APIC timer timestamps would otherwise expire immediately.
     */
    int64_t initial_count_load_time;
    int64_t next_time;
    int64_t timer_expiry;
    int32_t sipi_vector;
    int32_t wait_for_sipi;
    uint8_t id;
    uint8_t arb_id;
    uint8_t tpr;
    uint8_t log_dest;
    uint8_t dest_mode;
    uint8_t version;
    uint8_t _pad0[2];
} wvm_tcg_lapic_state_t;

typedef struct {
    uint64_t base;
    uint64_t mask;
} wvm_tcg_mtrr_var_t;

typedef struct {
    uint64_t regs[16];
    uint64_t eip;
    uint64_t eflags;
    uint64_t cr[5];
    uint64_t xmm_regs[32];
    uint32_t mxcsr;
    uint32_t exit_reason;
    uint32_t halted;
    uint32_t interrupt_request;
    uint32_t _pad0;
    uint64_t fs_base, gs_base;
    uint64_t gdt_base, gdt_limit;
    uint64_t idt_base, idt_limit;
    /* --- V31: Full segment register state for TCG execution --- */
    wvm_seg_reg_t segs[6];  /* ES=0, CS=1, SS=2, DS=3, FS=4, GS=5 */
    wvm_seg_reg_t ldt;
    wvm_seg_reg_t tr;
    uint64_t efer;
    /*
     * TCG x86 state that is not covered by KVM regs/sregs but is required
     * once APs leave the trampoline and execute kernel long-mode code.
     */
    uint64_t star, lstar, cstar, fmask, kernelgsbase;
    uint64_t sysenter_esp, sysenter_eip;
    uint64_t pat;
    uint32_t sysenter_cs;
    uint32_t hflags;
    uint32_t hflags2;
    uint32_t a20_mask;
    uint32_t mp_state;
    uint64_t dr[8];
    uint64_t vm_hsave, vm_vmcb, intercept, nested_cr3;
    /*
     * TCG handoff encodes the current absolute guest TSC here.  Each QEMU
     * process has its own elapsed-ticks epoch, so the receiver derives its
     * local QEMU tsc_offset from this value.
     */
    uint64_t tsc_offset;
    uint64_t mtrr_fixed[WVM_TCG_MTRR_FIXED_NB];
    uint64_t mtrr_deftype;
    wvm_tcg_mtrr_var_t mtrr_var[WVM_TCG_MTRR_VAR_NB];
    uint64_t system_time_msr, wall_clock_msr, steal_time_msr;
    uint64_t async_pf_en_msr, async_pf_int_msr, pv_eoi_en_msr;
    uint64_t poll_control_msr;
    uint64_t msr_bndcfgs;
    uint64_t exception_payload;
    uint32_t nested_pg_mode;
    uint32_t interrupt_injected;
    int32_t exception_nr;
    uint32_t ins_len;
    uint32_t sipi_vector;
    uint32_t intercept_exceptions;
    uint16_t intercept_cr_read, intercept_cr_write;
    uint16_t intercept_dr_read, intercept_dr_write;
    uint8_t v_tpr;
    uint8_t soft_interrupt;
    uint8_t nmi_injected, nmi_pending;
    uint8_t has_error_code;
    uint8_t exception_pending, exception_injected, exception_has_payload;
    uint8_t _pad2;
    int32_t old_exception;
    uint64_t smbase;
    uint64_t tsc, tsc_adjust, tsc_deadline, tsc_aux;
    uint64_t xcr0;
    uint64_t msr_ia32_misc_enable, msr_ia32_feature_control;
    uint64_t spec_ctrl, virt_ssbd;
    uint64_t exception_next_eip;
    uint32_t pkru;
    uint32_t tsx_ctrl;
    int32_t df;
    int32_t error_code;
    int32_t exception_is_int;
    /*
     * TCG runs the emulated local APIC in QEMU device state, not in
     * CPUX86State.  A remote TCG slice must carry the vCPU's LAPIC state with
     * the CPU context, otherwise timer/IPI delivery diverges between master
     * and slave QEMU processes after SMP bring-up.
     */
    wvm_tcg_lapic_state_t lapic;
    /*
     * QEMU TCG keeps guest x87/MMX/SSE/AVX/MPX/PKRU state outside the general
     * registers.  Carry the native xsave image so remote slices are equivalent
     * to local TCG execution when Linux uses FPU/SIMD in kernel threads.
     */
    uint32_t xsave_size;
    uint32_t _pad1;
    uint8_t xsave_area[WVM_TCG_XSAVE_AREA_SIZE];
} wvm_tcg_context_t;

struct wvm_ipc_cpu_run_req {
    uint32_t mode_tcg;
    uint32_t slave_id;   // 如果设为 WVM_NODE_AUTO_ROUTE (0xFFFFFFFF)，由后端决定
    uint32_t vcpu_index; // 传递 vCPU 序号用于查表路由
    union {
        wvm_kvm_context_t kvm;
        wvm_tcg_context_t tcg;
    } ctx;
};

struct wvm_ipc_cpu_run_ack {
    int status;
    uint32_t mode_tcg;
    uint64_t error_gpa;
    union {
        wvm_kvm_context_t kvm;
        wvm_tcg_context_t tcg;
    } ctx;
};

/*
 * Mode A transfers CPU_RUN through an ioctl.  The response is larger than
 * the request, so it must use an explicit request/response container rather
 * than overwriting a request-sized userspace object with an ACK.
 */
struct wvm_ioctl_remote_run {
    struct wvm_ipc_cpu_run_req req;
    struct wvm_ipc_cpu_run_ack ack;
};

static inline uint64_t wvm_get_u64_unaligned(const void *ptr) {
    uint64_t val;
    memcpy(&val, ptr, 8);
    return WVM_NTOHLL(val);
}

// 物理块 Payload，严格对齐 512B 扇区
struct wvm_block_payload {
    uint64_t lba;       // 逻辑块地址 (512B 扇区索引)
    uint32_t count;     // 扇区数量
    uint32_t padding;   // 8字节对齐填充
    uint8_t  data[0];   // 变长数据
} __attribute__((packed));

/* Typed block request envelope (storage-device-authority.md compliant).
 * Replaces legacy {lba,len,is_write} with operation identity, queue ordering,
 * flush/FUA semantics, and typed completion. */
#define WVM_BLOCK_OP_READ         1
#define WVM_BLOCK_OP_WRITE        2
#define WVM_BLOCK_OP_FLUSH        3
#define WVM_BLOCK_OP_DISCARD      4
#define WVM_BLOCK_OP_WRITE_ZEROES 5

#define WVM_BLOCK_FLAG_FUA        0x01  /* Force Unit Access */
#define WVM_BLOCK_FLAG_SYNC       0x02  /* Synchronous completion required */

struct wvm_typed_block_request {
    uint32_t protocol_version;
    uint8_t vm_id;
    uint8_t reserved1[3];
    uint64_t vm_incarnation;
    uint64_t manifest_generation;
    uint32_t origin_physical_node_id;
    uint32_t origin_runtime_instance_id;
    uint64_t operation_id;
    uint8_t semantic_payload_digest[32];
    uint32_t queue_id;
    uint32_t queue_sequence;
    uint32_t operation;
    uint32_t flags;
    uint64_t lba_512;
    uint32_t sector_count;
    uint32_t payload_bytes;
    uint8_t data[0];
} __attribute__((packed));

#define WVM_BLOCK_STATUS_SUCCESS           0
#define WVM_BLOCK_STATUS_IO_ERROR          1
#define WVM_BLOCK_STATUS_INVALID_OPERATION 2
#define WVM_BLOCK_STATUS_OUT_OF_BOUNDS     3
#define WVM_BLOCK_STATUS_DUPLICATE_ID      4

struct wvm_typed_block_completion {
    uint64_t operation_id;
    uint32_t status;
    uint32_t transferred_bytes;
    uint8_t data[0];
} __attribute__((packed));

#define WVM_IPC_TYPE_TYPED_BLOCK_REQUEST   14
#define WVM_IPC_TYPE_TYPED_BLOCK_COMPLETION 15


// 版本判定
static inline int is_next_version(uint64_t local, uint64_t push) {
    uint32_t l_epoch = (uint32_t)(local >> 32);
    uint32_t l_cnt   = (uint32_t)(local & 0xFFFFFFFF);
    uint32_t p_epoch = (uint32_t)(push >> 32);
    uint32_t p_cnt   = (uint32_t)(push & 0xFFFFFFFF);

    if (l_epoch == p_epoch) return p_cnt == l_cnt + 1;
    if (p_epoch == l_epoch + 1) return p_cnt == 1; // 跨纪元判定
    return 0;
}

static inline int is_newer_version(uint64_t local, uint64_t push) {
    uint32_t l_epoch = (uint32_t)(local >> 32);
    uint32_t p_epoch = (uint32_t)(push >> 32);
    if (p_epoch > l_epoch) return 1;
    if (p_epoch < l_epoch) return 0;
    return (uint32_t)(push & 0xFFFFFFFF) > (uint32_t)(local & 0xFFFFFFFF);
}

extern int g_ctrl_port;

#define POOL_ITEM_SIZE 4200

#include "crc32.h"

//[V30 异构适配器] 提取并转换 TCG 与 KVM 之间的寄存器状态（含关键段寄存器）

/* Helper: convert QEMU SegmentCache.flags (packed) → KVM kvm_segment fields */
static inline void wvm_seg_to_kvm(const wvm_seg_reg_t *seg, struct kvm_segment *ks) {
    ks->base     = seg->base;
    ks->limit    = seg->limit;
    ks->selector = (uint16_t)seg->selector;
    /* QEMU flags layout: type[11:8] S[12] DPL[14:13] P[15] AVL[20] L[21] DB[22] G[23] */
    ks->type    = (seg->flags >> 8) & 0xF;
    ks->s       = (seg->flags >> 12) & 1;
    ks->dpl     = (seg->flags >> 13) & 3;
    ks->present = (seg->flags >> 15) & 1;
    ks->avl     = (seg->flags >> 20) & 1;
    ks->l       = (seg->flags >> 21) & 1;
    ks->db      = (seg->flags >> 22) & 1;
    ks->g       = (seg->flags >> 23) & 1;
    ks->unusable = (seg->flags == 0) ? 1 : 0;
}

/* Helper: convert KVM kvm_segment fields → QEMU SegmentCache.flags (packed) */
static inline void wvm_kvm_to_seg(const struct kvm_segment *ks, wvm_seg_reg_t *seg) {
    seg->base     = ks->base;
    seg->limit    = ks->limit;
    seg->selector = ks->selector;
    if (ks->unusable) {
        seg->flags = 0;
    } else {
        seg->flags = ((uint32_t)ks->type << 8)
                   | ((uint32_t)ks->s    << 12)
                   | ((uint32_t)ks->dpl  << 13)
                   | ((uint32_t)ks->present << 15)
                   | ((uint32_t)ks->avl  << 20)
                   | ((uint32_t)ks->l    << 21)
                   | ((uint32_t)ks->db   << 22)
                   | ((uint32_t)ks->g    << 23);
    }
}

static __attribute__((unused)) void wvm_translate_tcg_to_kvm(wvm_tcg_context_t *t, struct kvm_regs *k, struct kvm_sregs *s) {
    k->rax = t->regs[0]; k->rcx = t->regs[1]; k->rdx = t->regs[2]; k->rbx = t->regs[3];
    k->rsp = t->regs[4]; k->rbp = t->regs[5]; k->rsi = t->regs[6]; k->rdi = t->regs[7];
    k->r8  = t->regs[8]; k->r9  = t->regs[9]; k->r10 = t->regs[10];k->r11 = t->regs[11];
    k->r12 = t->regs[12];k->r13 = t->regs[13];k->r14 = t->regs[14];k->r15 = t->regs[15];
    k->rip = t->eip; k->rflags = t->eflags;
    // 控制寄存器
    s->cr0 = t->cr[0]; s->cr2 = t->cr[2]; s->cr3 = t->cr[3]; s->cr4 = t->cr[4];
    s->gdt.base = t->gdt_base; s->gdt.limit = t->gdt_limit;
    s->idt.base = t->idt_base; s->idt.limit = t->idt_limit;
    s->efer = t->efer;
    // V31: 完整段寄存器（ES=0 CS=1 SS=2 DS=3 FS=4 GS=5）
    wvm_seg_to_kvm(&t->segs[0], &s->es);
    wvm_seg_to_kvm(&t->segs[1], &s->cs);
    wvm_seg_to_kvm(&t->segs[2], &s->ss);
    wvm_seg_to_kvm(&t->segs[3], &s->ds);
    wvm_seg_to_kvm(&t->segs[4], &s->fs);
    wvm_seg_to_kvm(&t->segs[5], &s->gs);
    wvm_seg_to_kvm(&t->ldt, &s->ldt);
    wvm_seg_to_kvm(&t->tr,  &s->tr);
}

static __attribute__((unused)) void wvm_translate_kvm_to_tcg(struct kvm_regs *k, struct kvm_sregs *s, wvm_tcg_context_t *t) {
    memset(t, 0, sizeof(*t));
    t->regs[0] = k->rax; t->regs[1] = k->rcx; t->regs[2] = k->rdx; t->regs[3] = k->rbx;
    t->regs[4] = k->rsp; t->regs[5] = k->rbp; t->regs[6] = k->rsi; t->regs[7] = k->rdi;
    t->regs[8] = k->r8;  t->regs[9] = k->r9;  t->regs[10]= k->r10; t->regs[11]= k->r11;
    t->regs[12]= k->r12; t->regs[13]= k->r13; t->regs[14]= k->r14; t->regs[15]= k->r15;
    t->eip = k->rip; t->eflags = k->rflags;
    // 控制寄存器
    t->cr[0] = s->cr0; t->cr[2] = s->cr2; t->cr[3] = s->cr3; t->cr[4] = s->cr4;
    t->gdt_base = s->gdt.base; t->gdt_limit = s->gdt.limit;
    t->idt_base = s->idt.base; t->idt_limit = s->idt.limit;
    t->efer = s->efer;
    // V31: 完整段寄存器
    wvm_kvm_to_seg(&s->es, &t->segs[0]);
    wvm_kvm_to_seg(&s->cs, &t->segs[1]);
    wvm_kvm_to_seg(&s->ss, &t->segs[2]);
    wvm_kvm_to_seg(&s->ds, &t->segs[3]);
    wvm_kvm_to_seg(&s->fs, &t->segs[4]);
    wvm_kvm_to_seg(&s->gs, &t->segs[5]);
    wvm_kvm_to_seg(&s->ldt, &t->ldt);
    wvm_kvm_to_seg(&s->tr,  &t->tr);
    // 保持 legacy 兼容
    t->fs_base = s->fs.base; t->gs_base = s->gs.base;
    t->exit_reason = 0;
    t->halted = 0;
    t->interrupt_request = 0;
    t->_pad0 = 0;
}

#endif // WAVEVM_PROTOCOL_H

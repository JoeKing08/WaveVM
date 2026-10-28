/*
 * [IDENTITY] Infrastructure - The Physical Axioms
 * ---------------------------------------------------------------------------
 * 物理角色：定义整个系统的"物理常数"和寻址边界。
 * 职责边界：
 * 1. 设定 WVM_SLAVE_BITS（默认 12 位单 Pod 空间）。
 * 2. 规定内存粒度 (1GB 路由 / 2MB 订阅 / 4KB 一致性)。
 * 3. 设定物理 MTU (1400)，规避 Overlay 网络的 IP 分片。
 * 
 * [禁止事项]
 * - 严禁在不修改 Gateway 内存映射逻辑的情况下增大 WVM_SLAVE_BITS。
 * - 严禁将 MTU_SIZE 设为 1500 以上，否则公网环境 PPS 性能将下降 90%。
 * ---------------------------------------------------------------------------
 */
#ifndef WAVEVM_CONFIG_H
#define WAVEVM_CONFIG_H

/* 
 * [集群规模上限] 定义节点 ID 的位宽。
 * 默认设定为 12 位，意味着单 Pod 支持 2^12 = 4096 个逻辑节点 ID。
 * 注意：若后续调大，需要同步调整网关路由表和相关内存分配策略。
 */
#ifndef WVM_SLAVE_BITS
/*
 * Default node-id bit width (shared by user/kernel paths).
 * Keep this bounded for predictable memory footprint in gateway/master.
 */
#ifdef __KERNEL__
#define WVM_SLAVE_BITS 12
#else
#define WVM_SLAVE_BITS 12
#endif
#endif

// --- 网络字节序转换宏 ---
/*
 * [跨架构兼容性] 64位整数的主机序(Host)到网络序(Network)转换。
 * 物理意义：
 * 1. WaveVM 协议强制使用大端序 (Big-Endian) 在网络传输。
 * 2. 这里的实现兼容了 x86 (Little-Endian) 和其他架构。
 * 3. 若不转换，跨架构通信时 GPA 地址会解析错误，导致读写错误的物理内存。
 */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define WVM_HTONLL(x) __builtin_bswap64((unsigned long long)(x))
    #define WVM_NTOHLL(x) __builtin_bswap64((unsigned long long)(x))
#else
    #define WVM_HTONLL(x) (x)
    #define WVM_NTOHLL(x) (x)
#endif

// --- 核心常量定义 ---
#define WVM_MAX_SLAVES (1UL << WVM_SLAVE_BITS)
#define WVM_MAX_GATEWAYS (WVM_MAX_SLAVES)
/*
 * LEGACY resource-plan table capacity (indexed by uint8_t/legacy vm slot).
 * This is NOT the V1 u32 VM namespace limit (see identity allocator / baseline §14:
 * UINT32_MAX nonzero namespaces with WVM_CAP_VM_ID_U32). Production u32 identities
 * (allocator next_vm_id starts at 256) must not use this table as a dense index;
 * callers must fail-closed or use the typed identity/admission path instead.
 */
#define WVM_MAX_VMS 256
#define WVM_LEGACY_RESOURCE_MAX_VMS WVM_MAX_VMS
/*
 * [协议特征与物理限制]
 * WVM_MAGIC: 数据包特征码 "WVMX"，用于在接收端快速识别并丢弃非法/垃圾流量。
 * MTU_SIZE: 设定为 1400 字节（低于标准以太网 1500）。
 *           原因：预留 100 字节给 Overlay 网络（如 VXLAN/Geneve）的隧道头。
 *           后果：防止底层网络进行 IP 分片。IP 分片会引发 CPU 软中断飙升，是高性能网络的杀手。
 */
#define WVM_MAGIC 0x57564D58 // "WVMX"
#define WVM_SERVICE_PORT 9000
#define MTU_SIZE  1400       
#define WVM_MAX_PACKET_SIZE 65536
#define MAX_VCPUS 4096
#define WVM_CPU_ROUTE_TABLE_SIZE MAX_VCPUS

/*
 * Static placement routes memory in 1 GiB chunks.  The entry count is kept
 * aligned with the CPU route table: 4096 GiB covers the current supported
 * guest address range without changing any packet-level ID widths.
 */
#define WVM_MEMORY_ROUTE_TABLE_SIZE WVM_CPU_ROUTE_TABLE_SIZE

// --- 内存粒度定义 ---
/*
 * [一级：DHT 路由粒度] 1GB (2^30)。
 * 物理意义：决定哪个节点是 Directory Owner。
 * 作用：我们不对每个 4KB 页面做哈希路由，而是每 1GB 数据块归属同一个 Owner。
 * 效果：极大减少了哈希计算频率，利用了程序的空间局部性。
 */
#define WVM_ROUTING_SHIFT 30 
/*
 * [二级：兴趣订阅粒度] 2MB (2^21)。
 * 物理意义：HugePage 对齐的订阅单元。
 * 作用：当节点发送 DECLARE_INTEREST 时，是一次性订阅 2MB 范围内的所有页面。
 * 效果：减少了 512 倍的订阅信令交互 (相比 4KB)。
 */
#define WVM_AFFINITY_SHIFT 21
/*
 * [三级：MESI 一致性粒度] 4KB (2^12)。
 * 物理意义：最小的原子数据同步单元。
 * 作用：Diff 计算、版本号校验、写冲突检测都精确到 4KB。
 */
#define WVM_PAGE_SHIFT 12
#define WVM_PAGE_BYTES (1UL << WVM_PAGE_SHIFT)

#define WVM_DEFAULT_SHM_PATH "/wavevm_ram"

#endif // WAVEVM_CONFIG_H

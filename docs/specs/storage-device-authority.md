# WaveVM 存储与设备权威规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：客户机可见设备权威、远端块 I/O 派发、读写排序、flush/FUA 语义、幂等性、错误映射以及与远端 vCPU 退出的交互。本 Minimum 文档仅规范远端块存储原语，不宣称对任意 PCI、VFIO 或 GPU 设备提供完整分布式所有权。存储参与方由已准入清单与资源计划选定，传输信封由 `wire-ipc-abi.md` 定义。

## 子系统边界契约

下表索引本子系统的核心归属规则，不重复其详细定义。边界变更须遵循[基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 必选契约 |
| --- | --- |
| 职责与权威 | QEMU 宿主机拥有客户机设备语义；清单选定的块服务执行经授权的 I/O。二者均不拥有 VM 生命周期、CPU 放置或页一致性。 |
| 状态与变更 | 设备、队列与操作身份共同界定排序与去重范围。后端仅可变更其获授权的资源；缓存结果须在必需的查询窗口内保留载荷与生命周期。 |
| 允许的实现依赖 | 公共 QEMU 设备桥、块操作记录、传输/身份/路由及已准入资源/能力接口。禁止访问私有 vCPU 协调器、内存目录或生命周期数据结构。 |
| 交互与生命周期 | 第 4 至 6 节负责块操作成功及 flush/设备排序；[vCPU 退出语义](vcpu-handoff.md#7-退出与设备中断时间语义)将设备退出归还至设备权威；[生命周期回收](runtime-manifest-lifecycle.md#63-跨子系统资源回收)确保 I/O 缓冲区与句柄保留至完成或隔离栅栏之后。 |
| 并发与成本 | 在保持每队列有序的同时支持独立队列与跨 VM 并发推进。须显式声明拷贝/I/O 开销、在途预算与结果保留预算；必需的完成记录容量须在产生副作用之前预留，而非事后分配。 |
| 故障与验证 | 第 5 节与第 9 节要求强类型 I/O/flush/不确定错误及去重重试。资源 ID 本身不代表授权；须明确定义资源作用域与撤销机制，但不强制所有调用都套用统一能力封装器。 |

## 1. 目标与非目标

客户机仅观测到单一的 QEMU 虚拟机与一致的设备模型。远端资源节点可执行块数据读写，但不成为独立的客户机设备权威。无论选中哪台物理存储执行器，一次已完成的写、flush 或错误都必须具备相同的客户机可见语义。

Minimum 轮廓的非目标：

- 活跃块后端或任意设备模型的在线透明迁移。
- 将缺少状态、排序或持久化完成证明的 `MSG_BLOCK_ACK` 当作客户机 flush 成功。
- 从本地执行器向任意远端执行器发起直接的跨节点存储流量。
- 在无独立设备规范的情况下，赋予远端 VFIO/GPU 代码客户机中断路由或设备生命周期权威。

## 2. 权威与放置

| 状态或决策 | 权威所有者 |
| --- | --- |
| 客户机可见磁盘/控制器/virtqueue 语义 | 权威 QEMU 前端。 |
| VM 身份、存储放置与选定执行器 | 已准入 VM 清单与控制面。 |
| 请求排序及向客户机汇报完成 | QEMU 前端经由其节点运行时。 |
| 物理块数据访问 | 仅限指派的本地存储执行器。 |
| 网络路由 | 源/目标节点运行时经由 Sidecar/Gateway 路由织网。 |
| 设备 MMIO/PIO 退出完成 | 权威 QEMU 前端。 |

远端存储执行固定遵循以下路径：

```text
QEMU device authority -> local node runtime -> sidecar/gateway fabric
                      -> remote node runtime -> local storage executor
                      -> remote node runtime -> origin node runtime -> QEMU
```

远端存储执行器严禁绕过节点运行时直接向 QEMU 或其他远端执行器发送客户机完成响应。

### 2.1 Minimum WaveVM 块服务设备基数

Minimum 轮廓下，每个 VM **至多准入一个** WaveVM 块服务设备分配（涵盖 `storage_device_plan`、放置存储模板与本地运行时分配）。出现第二个 `device_index` 时，必须在计划校验、准入放置及本地块执行阶段显式拒绝，不得静默别名为同一组 chunk 文件。不进入该块服务路径的普通 QEMU 本地磁盘在 Minimum 中依然合法；远端多盘后端映射超出 Minimum 范围，须由 Extended 设备到后端映射契约提供逐设备的独立授权、排序、持久化命名与故障语义。

## 3. 块请求模型

语义请求与结果模型如下：

```text
BlockRequest {
    protocol_version;
    vm_id;
    vm_incarnation;
    manifest_generation;
    origin_physical_node_id;
    origin_runtime_instance_id;
    operation_id;
    semantic_payload_digest;
    queue_id;
    queue_sequence;
    operation;            // READ, WRITE, FLUSH, DISCARD, WRITE_ZEROES if supported
    lba_512;
    sector_count;
    flags;                // FUA, barrier, no-cache, discard semantics
    data_or_data_reference;
    checksum_or_digest;
}

BlockResult {
    origin_physical_node_id;
    origin_runtime_instance_id;
    operation_id;
    queue_id;
    queue_sequence;
    status;
    durable;              // required for successful FLUSH/FUA
    data_for_read;
    error_class;
}

BlockForwardingMetadata {
    route_snapshot_key;
    delivery_attempt_id;
}
```

`operation_id` 是由源运行时分配的不回绕 128 位幂等标识。语义操作键为 `{vm_id, vm_incarnation, origin_physical_node_id, origin_runtime_instance_id, operation_id}`。`queue_sequence` 用于维持 virtqueue 或等价排序域内必需的客户机顺序。后续设备规范可定义多个独立排序域，但 Minimum 严禁静默重排 QEMU 前端已串行化的写入。

`BlockForwardingMetadata` 不参与语义载荷摘要计算。路由替换后，重试或查询可更新转发元数据，但必须保持相同的语义键、`queue_sequence`、标志位与数据摘要。存储执行器依据语义键去重，绝不因 G -> G+1 路由替换改变了转发字段而执行第二次写入。

存储操作缓存须在最大路由前驱完成查询/重试窗口内保留每个语义键及结果；期满后返回 `RESULT_EXPIRED` / 强类型 I/O 失败，绝不将丢失的结果转化为新的写操作或 flush。

缺乏实例代次、队列序号、FUA/屏障标志、强类型状态及显式持久化完成语义的无类型载荷（例如 `{ lba, count, data[] }` 或 `{ lba, len, is_write, data[] }`）无法满足本契约，不属于受支持的生产方案。

## 4. 常规操作

### 4.1 读操作

1. QEMU 生成携带唯一操作 ID 与队列序号的读请求。
2. 源节点运行时校验存储放置，并将请求发送至选定的存储节点运行时。
3. 存储执行器精确读取请求区间，返回数据、校验和与强类型状态。
4. QEMU 校验身份、序号、长度与校验和后，方才完成客户机请求。

重试保持同一语义操作键。重复读可返回相同数据或所选后端排序快照允许的结果，但绝不得错误归属至其他 VM 或请求。

### 4.2 写操作

1. QEMU 分配唯一操作 ID、队列序号、LBA/范围、标志位及载荷摘要。
2. 存储执行器在应用数据前先记录去重检测状态。
3. 执行器在所请求的排序域内应用写入，并在回复前记录完成结果。
4. 身份与摘要一致的重复请求重放已记录结果；字节或标志位不一致的重复请求按协议损坏拒绝。
5. 仅当满足规定的写完成条件时，QEMU 方可向客户机回报完成。

除非后端契约明确保证已抵达选定的持久化边界，否则写确认（ACK）本身不代表持久化完成。

### 4.3 Flush 与 FUA

`FLUSH` 将同一队列/排序域中此前的所有写入排序在其之前，并要求指派的存储后端在返回成功前完成真实的持久化刷盘。`FUA` 写对该次写入施加同等的持久化要求，即便后续没有额外的 flush。

若后端无法提供所请求的 flush/FUA 语义，操作必须显式失败，不得仅因数据进入本地缓冲区或 UDP 发送队列就回报成功。

### 4.4 不支持的操作

在标志位、排序、幂等性、恢复与客户机错误映射明确规范之前，discard、write-zeroes、resize、snapshot 与缓存模式语义默认禁用。不支持的请求须向权威 QEMU 前端返回强类型的不支持/错误结果。

## 5. 排序、重试与故障

| 条件 | 必选行为 |
| --- | --- |
| 重复写/flush | 存储执行器查询操作缓存，仅重放匹配的完成结果。 |
| 写入后结果丢失 | 源端按同一语义操作键查询或重试；仅转发元数据可变更，绝不生成第二个写操作 ID。 |
| 乱序到达的队列序号 | 执行器按显式队列排序策略暂存或拒绝，绝不静默以不安全顺序应用。 |
| 存储路由不可用 | 返回强类型 I/O 失败或 VM 降级状态，禁止回退至任意本地节点。 |
| 持久化完成前执行器故障 | 按后端能力返回不确定或错误状态，不得宣称客户机完成。 |
| 记录持久化完成后执行器故障 | 仅当操作缓存/持久化契约可证明已完成时，恢复后方可重放结果。 |
| QEMU/设备权威故障 | 由 VM 生命周期接管故障处理；远端执行器不得继续独立接受客户机可见写入。 |

设备权威可使用有界队列与批处理，但必须严格维护各队列/排序域的有序契约；不得为简化正确性而全局串行化无关队列，亦不得在过载时丢弃写或 flush 操作。

## 6. vCPU 与中断交互

远端 vCPU 执行可能触发存储相关的 PIO/MMIO 退出。远端执行器通过节点运行时路径向权威 QEMU 前端返回强类型退出；由 QEMU 执行设备模拟，并按 `vcpu-handoff.md` 定义向下一个 vCPU 执行区间提供读结果。

远端设备/VFIO 中断属于事件通知，而非设备完成的凭证。它们必须携带 VM 身份、源设备身份、投递序号及强类型状态经由节点运行时传递；QEMU 始终负责客户机 IRQ/APIC 投递与去重抑制。

## 7. 实现触点与要求

| 文件、符号或边界 | 必选职责 |
| --- | --- |
| `wavevm-qemu/.../wavevm-all.c:wvm_send_ipc_block_io` | 补充请求身份、队列排序、标志位、强类型完成与清单校验。 |
| `slave_daemon/slave_hybrid.c:handle_block_io_phys` | 在规范 schema 下实现操作缓存、真实后端持久化、状态/错误映射与边界检查。 |
| `common_include/wavevm_protocol.h` | 定义规范块信封，拒绝不支持的无类型载荷。 |
| Gateway/节点运行时路径 | 维护节点运行时权威、队列 QoS 与严格的 VM 路由身份校验。 |
| VFIO 路径 | 保留为未来设备事件源，不宣称 Minimum 分布式设备权威。 |

## 8. 兼容性边界

生产环境不支持历史块请求、隐式 ACK 或执行器直连前端路由。块操作必须遵循强类型身份、有序完成、后端持久化结果及 QEMU 设备权威契约；不支持的操作一律返回显式错误。

## 9. 验收测试

- 读、写与 flush 经过远端存储执行并将结果返回至权威 QEMU 前端。
- 相同操作 ID 的重复写仅应用一次字节；携带不同字节的重复写被拒绝。
- 持久化写入后丢失结果时，可安全重放且不产生重复后端变更。
- 持久化结果丢失期间发生路由替换时，保持单一语义写/flush，并返回缓存结果或有界 `RESULT_EXPIRED` 错误。
- Flush 与 FUA 成功必须由经观测验证的真实持久化后端完成作为前提。
- 存储执行器过载与路由丢失产生有界的客户机可见错误，不发生挂死或伪成功。
- 相互独立的队列可并发推进，而同一队列内的有序写入保持声明顺序。
- MMIO/PIO 与 IRQ 路径保持 QEMU 设备权威，且不绕过节点运行时。
- 即使原始 node/vnode 数值重叠，一个 VM 的存储操作也无法完成另一个 VM 的请求。

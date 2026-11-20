# WaveVM 运行时清单与生命周期规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：面向用户的 VM 请求、不可变的已准入启动清单、每节点运行时清单、清单发布、VM 生命周期状态、启动、停止、回滚及恢复边界。资源选择归属 `resource-placement-admission.md`；成员与路由变更归属 `cluster-membership-topology-lifecycle.md`；线协议标识归属 `identity-routing.md` 和 `wire-ipc-abi.md`。

本规范对所有 VM 生命周期工作具有规范效力。现有启动脚本、环境变量、`NODE`/`ROUTE` 文件及位置进程参数均非生产输入，仅作为历史测试资产予以移除或重写为清单渲染器。

## 子系统边界契约

本摘要仅索引各归属规则，不重复其定义。涉及边界变更时适用[架构基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 必需契约 |
| --- | --- |
| 职责与权威 | 负责 VM 标识生命周期、候选/已准入清单、持久化激活及整体生命周期协调。各领域操作及其内部回收仍归属各自子系统所有者。 |
| 状态与变更 | 协调器 API 负责变更事务/生命周期记录；参与者持久化与标识绑定的观测记录和幂等决策。参与者与缓存清单均不得单方面宣告 `RUNNING`。 |
| 允许的实现依赖 | 公共成员关系/快照、放置/资源预留、规范记录及参与者控制契约。编排层仅通过这些公开接口交互，禁止访问领域私有队列、全局状态或内部结构。 |
| 交互与生命周期 | 第 5.2 节与第 6.3 节分别负责跨领域激活与跨子系统资源回收。准入栅栏、路由引用、引擎/上下文引用及名称租约保留其各自所有者。 |
| 并发与开销 | 第 7 节负责单个事务的串行化，独立 VM 与参与者可并发推进。禁止在远程 prepare/ACK/排空等待期间持有共享权威锁，也禁止在每次内存或 vCPU 操作路径中插入控制面开销。 |
| 故障与验证 | 第 5.3、6 和 10 节定义重启对账、不确定结果处理、部分清理及档位验收要求。基础重放与补偿属于 Minimum；高可用（HA）与透明恢复属于 Extended。 |

## 1. 目标与非目标

目标是让每次成功的 VM 创建产出唯一一份不可变、带版本且可审计的描述，准确刻画集群实际准入的 VM。每个 QEMU 前端、节点运行时、执行器、Sidecar、Gateway 缓存及可选内核加速器，都必须能依据该描述识别出相同的 VM 实例代次（`vm_incarnation`）、相同的资源计划以及相同的本地名称。

正常控制流如下：

```text
VmRequest
  -> 校验 + 确定性放置 + 资源预留
  -> AdmittedVmManifest
  -> 每节点 RuntimeManifest prepare
  -> 经确认的 commit/start
  -> RUNNING 或明确的 failed/aborted 终态
```

Minimum 非目标：

- 运行中 VM 的热迁移、热添加、热移除或隐式再均衡。
- 原地修改运行中 VM 的资源、执行后端或一致性语义。
- 在准入完成后将启动命令行、进程环境变量或路由文件作为第二权威来源。
- 仅凭端口已绑定、进程存活或单次心跳推断启动成功。
- 在停止后、尚未满足标识/线协议规则对延迟流量的代次拒绝条件前立即复用 `vm_id`。
- 借节点重启原地重建放置方案、后端或本地名称已改变的 VM。

## 2. 权威归属与版本域

| 状态或决策 | 权威所有者 | 允许的缓存/消费者 |
| --- | --- | --- |
| 用户请求与请求幂等记录 | 集群控制面 | CLI/API 客户端可保留副本。 |
| `vm_id` 与 `vm_incarnation` 分配 | 集群控制面 | 所有运行时依据已准入清单进行校验。 |
| 候选 vCPU、内存、宿主、存储、设备及本地名称计划 | 不可变候选清单 | 仅限已准备的资源预留与参与者。 |
| 准入/激活决策 | 生命周期协调器的持久化事务记录 | 参与者保留幂等的本地决策记录。 |
| 解析后的 vCPU、内存、宿主、存储、设备及本地名称计划 | 已准入 VM 清单 + 激活记录 | 每节点清单及进程内本地缓存。 |
| 当前 VM 生命周期状态 | 控制面生命周期协调器 | 节点代理仅上报观测到的子状态。 |
| 路由下一跳 | 成员关系/拓扑控制面发布的带版本路由快照 | 清单仅引用所需作用域/代次，不复制可变路由表。 |
| 页、vCPU、存储操作及中断状态 | 各自子系统权威 | 清单仅选择其策略与参与方。 |

以下标识与版本值彼此独立，严禁混用或重载：

| 字段 | 含义 |
| --- | --- |
| `request_id` | 单次用户创建/更新请求的幂等键。 |
| `vm_id` | 仅在安全回收后可复用的逻辑 VM 命名空间。 |
| `vm_incarnation` | `vm_id` 命名空间内单次成功的 VM 生命周期代次。 |
| `admission_tx_id` | 针对新 VM 实例代次的一次创建/激活/中止事务标识。 |
| `manifest_generation` | 单一实例代次内不可变候选/已准入清单的代次编号。 |
| `activation_fence` | 将单份候选清单转化为已准入分配的唯一持久化决策栅栏。 |
| `eligibility_fence` | 单次准入事务采纳的精确合格成员、能力、路由及节点实例集合。 |
| `membership_revision` / `topology_revision` | 集群期望成员关系与拓扑状态修订号。 |
| `route_scope_id` | 单个 VM 实例代次的路由命名空间或叶级作用域。 |
| `route_generation` | 单个路由作用域标识内不可变路由快照的代次号。 |
| `operation_id` | 单次数据面或生命周期操作标识。 |

`route_generation` 可通过合法的 Gateway 替换向前推进，而不变更 VM 的资源计划。拓扑或路由更新绝不会改变 `vm_incarnation`、页版本号、vCPU 交接序列号或存储顺序。路由操作生命周期及其独立的转发元数据由 `identity-routing.md` 和 `wire-ipc-abi.md` 定义。

## 3. 清单数据模型

所有清单形态均采用 `canonical-record-schema.md` 中定义的精确规范化版本序列化格式，并封装于 `wire-ipc-abi.md` 的消息信封内。JSON、Shell 片段与环境变量仅可作为调试渲染视图，不得作为独立语义格式。候选清单在 prepare 阶段保持不可变，但在其独立持久化的激活记录落盘前，不构成已准入的资源分配。

### 3.1 面向用户的 VM 请求

```text
VmRequest {
    api_version;
    request_id;
    display_name;                 // 可选，不作为路由键
    requested_vcpus;              // 正整数
    requested_memory_bytes;       // 正整数，校验后需页对齐
    execution_backend_policy;     // AUTO、REQUIRE_KVM 或 REQUIRE_TCG
    accelerator_policy;           // DISABLED、PREFER 或 REQUIRE_KERNEL_ACCEL
    placement_policy;             // COMPACT 或 SPREAD
    host_constraints;
    guest_topology_policy;        // FLAT、PLACEMENT_NUMA 或 SYNTHETIC_NUMA
    consistency_policy;
    storage_and_device_requirements;
    requested_lifecycle_options;  // 仅包含文档化的启停策略字段
}
```

用户仅提供期望资源与约束，不提供物理节点 ID、vnode ID、Gateway 端口、套接字路径、`WVM_INSTANCE_ID`、原始路由条目或猜测的 QEMU 宿主。管理接口可出于诊断或策略需要暴露显式放置约束，但仍须通过标准准入流程，禁止绕过资源预留或能力校验。

`AUTO` 是请求策略而非运行时降级许可。准入流程先尝试构造完整的 KVM 放置方案（包含前端及所有必需的 vCPU 执行器）；若该候选不可准入且请求允许回退，准入可构造一份全新的完整 TCG 放置方案。TCG 方案必须具备独立的计划摘要、资源预留、能力档位以及解释回退原因的清单诊断信息；已部分预留的 KVM 候选必须中止清理，禁止原地修改。

`REQUIRE_KVM` 在无法准入完整 KVM 放置方案时直接失败；`REQUIRE_TCG` 直接选择 TCG。执行后端一旦写入已准入清单，Guest 在整个运行代次内不得静默在 KVM 与 TCG 之间或 Mode A 与 Mode B 之间切换。

### 3.2 候选与已准入 VM 清单

```text
CandidateVmManifest {
    schema_version;
    manifest_id;
    manifest_digest;
    vm_id;
    vm_incarnation;
    manifest_generation;
    request_id;
    admission_tx_id;
    eligibility_fence_digest;
    plan_digest;
    namespace_abi;                 // LEGACY 或 V1_U32
    candidate_created_at;

    guest_machine;
    guest_topology;
    execution_plan;
    consistency_policy;
    storage_and_device_plan;
    host_node;
    vcpu_placements;
    memory_placements;
    required_members;
    required_capability_profiles;
    reservation_requirements;
    route_scope_key;
    prepared_route_snapshot_key;
    derived_local_name_namespace;
    lifecycle_policy;
}

ActivationRecord {
    admission_tx_id;
    candidate_manifest_digest;
    activation_fence;
    coordinator_instance_id;
    required_participant_set_digest;
    required_route_snapshot_keys;
    decision;                     // ACTIVATE 或 ABORT
    durable_decision_sequence;
    decided_at;
}

AdmittedVmManifest = CandidateVmManifest + ActivationRecord(decision=ACTIVATE)
```

必需语义：

- `vm_id`、`vm_incarnation`、`admission_tx_id` 与 `manifest_generation` 必须在发出任何资源预留之前分配。每个实例代次的 `manifest_generation` 从 1 开始。中止的尝试绝不复用其 `vm_incarnation`。
- 候选清单必须在任何 `PREPARE_MANIFEST` 参与者准备本地 VM 状态之前完整、不可变且可计算摘要。它在激活前不构成已准入分配；只要所有资源预留仍处于 `PREPARED` 状态，均可中止。
- 从候选清单转为已准入清单的唯一条件是持久化的 `ActivationRecord(decision=ACTIVATE)`。参与者不得依据进程存活、预留 ACK 或路由监听状态推断激活。
- `host_node` 必须显式指定，指明承载权威 QEMU 前端的物理节点，而非 API 提交端或放置列表的首个节点。
- `vcpu_placements` 必须精确覆盖每个 Guest vCPU 一次，每项包含执行器物理节点、本地执行器角色/槽位、后端类型及容量预留需求引用。
- `memory_placements` 必须精确覆盖每个 Guest RAM 页/块一次，每项包含目录/执行节点、地址范围、容量预留引用及适用的页一致性策略。
- `reservation_requirements` 是与放置计划共享的不可变每节点/排他资源意图。实际的 `ResourceReservation` 记录在放置计划和候选清单自摘要定稿后派生，并由 `PREPARE_RESERVATION` 创建；因预留记录需绑定候选清单摘要，故不可将其反向嵌入候选清单，以免形成摘要环。
- `guest_topology` 面向 Guest 可见且独立于物理放置；即使资源跨节点分布，Flat 拓扑依然合法。
- `required_members` 仅列出精确匹配 `eligibility_fence` 准入条件的成员，包括物理/角色标识、节点实例 ID、能力档位及必需状态。后续成员变更不得静默并入尚未激活的候选清单。
- `route_scope_key` 与 `prepared_route_snapshot_key` 标识不可变的 VM 实例代次路由作用域及快照，绝不内嵌可变逐包路由表；其标识包含作用域、拓扑修订号、代次与摘要（详见 `identity-routing.md`）。
- 每节点运行时清单是在候选清单摘要确定后生成的确定性过滤投影，携带候选清单摘要，但其自身摘要不作为候选清单字段，以避免两类记录构成哈希环。
- `derived_local_name_namespace` 是 QEMU IPC、共享内存（SHM）、工作线程套接字、监视器、日志及临时名称派生的唯一输入，避免同宿主上的两个 VM 仅凭节点 ID 派生出冲突名称。其派生盐在计算候选清单自摘要前由 `manifest_id`、`admission_tx_id`、VM 标识/代次及物理节点标识共同导出，因自身属于候选清单字段，不得依赖最终候选清单摘要。
- 清单不得包含私钥、访问令牌或可变进程凭据；此类信息通过独立受保护的本地凭据通道下发，不属于 VM 标识。

### 3.3 每节点运行时清单

每个参与的 `{vm_incarnation, physical_node_id}` 均接收一份经过过滤的清单，其中包含足够校验流量的全局标识，但仅暴露本地分配与必需对端信息：

```text
NodeRuntimeManifest {
    manifest_identity;            // id、digest、VM 标识、generation
    admission_tx_id;
    eligibility_fence_digest;
    activation_fence_when_committed;
    physical_node_id;
    expected_node_instance_id;
    local_roles;                  // QEMU host、node runtime、executor、gateway
    local_vcpu_assignments;
    local_memory_assignments;
    local_storage_assignments;
    required_route_snapshot_key;
    local_endpoint_names;
    launch_plan {
        plan_version;
        node_runtime_data_port;
        node_runtime_control_port;
        local_executor_service_port; // 仅 loopback
        local_executor_control_port; // 仅 loopback
        executor_worker_count;
        vcpu_handoff_record_capacity;
        sync_batch_size;
        guest_total_memory_bytes;
        guest_machine;
        consistency_policy;
    };
    negotiated_capabilities;
    reservation_lease;
    startup_dependencies;
}
```

节点运行时必须拒绝任何标识、清单摘要、代次、路由作用域、资格栅栏或本地角色与已接受每节点清单不匹配的本地执行器、QEMU 连接、Sidecar 输入或内核上下文。在收到激活记录前，节点运行时仅可准备本地资源，必须拒绝 Guest 流量；若在租约过期前未观测到 `activation_fence`，可释放已准备状态。

控制面必须为候选清单中的每一项 `ReservationRequirement` 持久化存储一份已激活的规范 `NodeRuntimeManifest` 投影，按候选摘要、物理节点 ID、期望节点实例 ID 和预留 ID 索引。重复写入仅在规范字节完全一致时幂等成功；同一候选/节点下若标识、预留、栅栏、路由键、角色或本地分配发生变化，必须拒绝。恢复流程必须精确取回对应节点的投影，严禁以其他物理节点上的相似清单替代。

进入 `COMMITTED` 还需要持久化投影集合完整无缺：每项候选预留需求都必须恰好对应一份已存储投影，且其候选绑定与 `activation_fence` 与已落盘的 `ACTIVATE` 决策一致。仅在内存中生成的投影、重启后存活的本地进程或缺少对应持久化投影的预留提交均不足以支撑 `COMMITTED`。

`launch_plan` 是由控制器选定、属于本地投影的规范组成部分，将进程级端口租约与执行器并发配置绑定到与放置方案一致的已准入 VM 标识上。其中内嵌的机型与一致性配置必须与候选清单完全一致，总内存大小必须与候选清单中已准入内存放置总量精确相等。本地执行器服务端口和控制端口仅为 loopback 实现端点，不得作为集群成员或 Gateway 端点。

节点运行时数据监听 UDP 端口与本地执行器服务监听 UDP 端口必须在激活前物化为预留记录的排他租约：前者使用通配绑定作用域，后者使用 loopback 绑定作用域。`launch_plan` 中的控制端口仅在对应运行时实现实际绑定它时才成为排他租约。租约代次仅作为所有者纪元凭证，不改变资源标识。

`wavevm_node_runtime` 仅接受运行时清单路径与期望节点实例 ID 作为启动输入，其余用于当前 master 角色与 executor 角色实现的适配参数一律在内部依据已接受清单及其分发投影派生。准入后，启动器不得独立传入内存大小、工作线程数、端口、VM ID、静态拓扑或角色特定参数组。

在每个物理节点上，经认证的本地控制接收器需将已接受的激活投影原子写入运行时清单路径，并在返回成功前对文件及其父目录执行 `fsync`。随后基于该激活清单、规范节点记录及精确路由快照派生出 `RuntimeDispatchProjection`，原子发布至 `<runtime-manifest-path>.dispatch`。路由快照与分发产物必须在最终运行时清单发布使启动可见之前就位。节点运行时只加载该完整清单、对应路由快照及绑定的分发投影，不得读取协调器日志或从环境变量重建放置与路由。网络传输投递仍由 `PREPARE_MANIFEST`/`ACTIVATE_MANIFEST` 负责，该本地落盘流程仅作为向运行时进程移交的崩溃安全衔接。

### 3.4 不可变性与变更分类

候选清单一旦下发进入 prepare 即不可变；已准入清单是同一候选清单与单条激活记录的绑定。以下变更在 Minimum 中不支持原地更新，除非后续规范定义显式确认的重配置协议，否则必须先停止 VM 再创建新实例代次：

- vCPU 数量、CPU 放置方案或执行后端。
- 内存容量、内存放置方案、目录归属或一致性策略。
- QEMU 宿主、Guest 拓扑、存储/设备权威或本地命名空间。
- 必需的内核加速或缺页引擎（fault engine）选择。

以下状态在满足各自规范的 prepare/commit 规则前提下可演进，而不改变资源计划：

- 保持相同 VM 命名空间和端点语义的新 `route_generation`。
- 健康观测与有界恢复证据。
- 诊断信息、日志及不透明的进程实例 ID。

## 4. 准入事务与 VM 生命周期

单次创建请求独占一个 `admission_tx_id`。正常事务状态推进如下：

```text
REQUESTED -> VALIDATING -> IDENTITY_ALLOCATED -> PLANNED
  -> ROUTE_SCOPE_PREPARED -> RESERVATIONS_PREPARED
  -> PARTICIPANTS_PREPARED -> ACTIVATION_DECIDED -> COMMITTED
  -> STARTING -> RUNNING
```

在进入 `ACTIVATION_DECIDED` 之前，任何非成功结果均转入 `ABORTING -> ABORTED`。一旦激活决策落盘，恢复流程只能推进完成激活或执行补偿拆卸，严禁仅凭超时就推定已提交预留可以安全回收。

| 状态 | 含义 | 允许的下一状态 |
| --- | --- | --- |
| `ABSENT` | 不存在生命周期或命名空间分配记录。 | `REQUESTED` |
| `REQUESTED` | 幂等请求已记录。 | `VALIDATING`、`ABORTING` |
| `VALIDATING` | 正在进行请求与策略校验。 | `IDENTITY_ALLOCATED`、`ABORTING` |
| `IDENTITY_ALLOCATED` | 新的 VM 命名空间/实例代次与事务 ID 已持久化，但尚不可运行。 | `PLANNED`、`ABORTING` |
| `PLANNED` | 完整的确定性放置方案与资格栅栏已生成。 | `ROUTE_SCOPE_PREPARED`、`ABORTING` |
| `ROUTE_SCOPE_PREPARED` | 候选 VM 路由作用域/快照及其必需 ACK 集合已完成准备，尚未对常规流量激活。 | `RESERVATIONS_PREPARED`、`ABORTING` |
| `RESERVATIONS_PREPARED` | 所有必需的资源与排他名称租约均已带过期时间持有，禁止 Guest 流量。 | `PARTICIPANTS_PREPARED`、`ABORTING` |
| `PARTICIPANTS_PREPARED` | 所有必需的节点/QEMU/执行器/内核参与者均已针对同一候选清单与栅栏完成准备。 | `ACTIVATION_DECIDED`、`ABORTING` |
| `ACTIVATION_DECIDED` | 唯一持久化 `activation_fence` 已落盘。参与者必须查询/重放该决策，不得让已准备租约自行过期。 | `COMMITTED`、`STOPPING` |
| `COMMITTED` | 必需参与者已将清单与资源预留提升至已提交状态；组件可启动，但 Guest 流量仍受门控。 | `STARTING`、`STOPPING` |
| `STARTING` | 组件正在依据已提交清单启动。 | `RUNNING`、`STOPPING`、`FAILED` |
| `RUNNING` | Guest 执行已准入。 | `PAUSING`、`STOPPING`、`DEGRADED`、`FAILED` |
| `PAUSING` | 阻塞新的 vCPU 交接，等待当前工作到达明确边界。 | `PAUSED`、`STOPPING`、`FAILED` |
| `PAUSED` | Guest 执行已静默，但标识与资源预留继续保持。 | `RUNNING`、`STOPPING`、`FAILED` |
| `DEGRADED` | 必需组件或路径故障；Minimum 必须暂停或置失败，禁止静默重绑定。 | `PAUSING`、`STOPPING`、`FAILED` |
| `STOPPING` | 正在执行静默、刷盘与补偿拆卸。 | `RETIRING`、`FAILED` |
| `RETIRING` | 正在回收路由作用域、订阅者状态、完成缓存、本地名称、上下文及资源预留。 | `STOPPED`、`FAILED` |
| `STOPPED` | 回收确认与资源释放已落盘；命名空间交由分配器进入隔离期。 | 仅在满足命名空间安全复用条件后转入 `ABSENT` |
| `ABORTING` | 正在清理激活前的候选资源。 | `ABORTED`、`FAILED` |
| `ABORTED` | 候选资源与路由作用域已释放，期间未产生任何 Guest 流量。 | 命名空间隔离期结束后转入 `ABSENT` |
| `FAILED` | 已提交 VM 无法继续安全运行。 | `STOPPING`、`RETIRING`、`STOPPED` |

仅生命周期协调器有权变更权威状态。节点运行时仅上报幂等的本地观测状态（如 `LOCAL_PREPARED`、`ROUTE_PREPARED`、`QEMU_READY`、`EXECUTOR_READY`、`ACTIVATED`、`QUIESCED`、`LOCAL_STOPPED`），不得自行将 VM 提升至 `RUNNING`。

持久化准入事务必须保存候选清单完整的 `prepared_route_snapshot_key`（含拓扑修订号、路由代次与快照摘要）。由于多个不可变代次可合法共享同一路由作用域，单独的路由作用域不足以作为生命周期权威。因此协调器强制校验对应精确路由事务的状态：`PLANNED -> ROUTE_SCOPE_PREPARED` 要求路由事务为 `PREPARING`；`ACTIVATION_DECIDED -> COMMITTED` 要求为 `ACTIVATED`；`STOPPING -> RETIRING` 要求为 `RETIRING`；`RETIRING -> STOPPED` 要求为 `RETIRED`；`ABORTING -> ABORTED` 要求为 `ABORTED`。落盘任何激活或中止决策时，该精确路由事务亦须仍处于 `PREPARING`。

## 5. 准入、激活与恢复

### 5.1 准入资格栅栏

每份放置计划均包含一个不可变的资格栅栏：

```text
AdmissionEligibilityFence {
    admission_tx_id;
    membership_revision;
    topology_revision;
    admission_eligibility_revision;
    inventory_revision;
    capability_profile_generation;
    selected_member_records[];    // 角色、物理 ID、节点/Gateway 实例 ID、
                                  // ACTIVE/健康资格、能力摘要
    required_route_scope_key;
    required_ack_set_digest;
    fence_digest;
}
```

`PREPARE_ROUTE_SCOPE`、`PREPARE_RESERVATION`、`PREPARE_MANIFEST` 以及有序激活对（`COMMIT_RESERVATION` + `ACTIVATE_MANIFEST`）均校验同一资格栅栏。节点隔离（cordon）、健康剔除、Gateway 排空、必需能力/档位变更、节点/Gateway 实例变更或拓扑变更，都会使所有尚未进入 `ACTIVATION_DECIDED` 且依赖该对象的事务失效，协调器须中止或重新规划这些事务。

已进入 `ACTIVATION_DECIDED` 的事务即便尚未收齐全部参与者的本地 `COMMITTED` 确认，也构成决策后依赖。成员排空、宿主移除与故障处理必须等待其完成，或先执行规范的补偿拆卸，方可移除其选中成员。只有在收齐全部必需提升 ACK 后，VM 生命周期状态才进入 `COMMITTED`。已 `COMMITTED` 的分配不会被静默重规划，而是遵循其既定的排空/降级策略。

### 5.2 创建与激活时序

1. 对 `request_id` 去重。规范内容相同的重复请求直接返回既有事务/结果；同一 ID 下语义字段不同则拒绝。
2. 校验用户策略，随后在发出任何预留或清单摘要前分配 `vm_id`、全新的 `vm_incarnation` 和 `admission_tx_id`。
3. 捕获成员关系/拓扑/资源库存/能力快照，派生 `eligibility_fence`，并计算完整的确定性放置计划。
4. 依据放置计划创建 VM 实例代次路由作用域，编译候选路由快照，持久化其 `RequiredAckSet`，并严格在该存活集合上完成 prepare（此时不向常规流量激活）。
5. 构造不可变候选清单及其每节点投影，绑定已准备的路由快照键与摘要。
6. 向所有选中的资源/宿主/排他名称所有者发送 `PREPARE_RESERVATION`。各方校验 `eligibility_fence`，并按 VM 标识与事务 ID 存储带过期时间的 `PREPARED` 预留记录。
7. 向所有必需的节点运行时、QEMU 宿主、执行器、Sidecar/Gateway 及可选内核上下文发送 `PREPARE_MANIFEST`。各方校验候选清单摘要、资源预留、能力档位、路由快照与资格栅栏，仅准备本地状态，不接纳 Guest 流量。
8. 重新校验 `eligibility_fence` 与全部已记录的 prepare 确认；在进入下一步前出现任何变更均中止或重新规划候选方案。
9. 在向任何参与者发送 `COMMIT_RESERVATION` 或 `ACTIVATE_MANIFEST` 之前，携带全新 `activation_fence` 持久化唯一的 `ActivationRecord(decision=ACTIVATE)`。这是整个准入流程的唯一线性化点。
10. 向所有必需参与者依次发送幂等的 `COMMIT_RESERVATION` 与 `ACTIVATE_MANIFEST`（二者合称通用激活动作）。参与者仅在事务 ID、清单摘要、栅栏与必需路由快照全部匹配其已准备记录时，才提升预留与清单。
11. 持久化全部已激活的每节点运行时清单投影，并等待收齐所有必需激活 ACK。仅在持久化投影集合完整后记录 `COMMITTED`。组件此时可依据已准入清单启动，但须继续门控 Guest 流量。
12. 启动 QEMU、节点运行时与执行器；待必需本地端点以及已准入路由/能力检查全部就绪后，进入 `RUNNING`。

在已准入执行路径与内存路径所需的全部参与者就绪检查完成之前，任何 Guest vCPU 不得开始执行。分布式启动验收门控还要求观测到真实的远端 vCPU 与远端内存工作，不能仅以 SSH 监听建立或进程存活为准。

### 5.3 中止、崩溃恢复与补偿拆卸

在 `ACTIVATION_DECIDED` 之前发生拒绝、租约过期或栅栏失效时，协调器持久化 `ABORT`，向已准备参与者发送幂等的中止/拆卸指令，对已准备路由作用域发送 `ROUTE_ABORT`，并释放全部已准备预留。已准备记录仅可在确认未观测到 `activation_fence` 后随租约过期释放。

进入 `ACTIVATION_DECIDED` 后，协调器重启必须遵循如下查询恢复规则：

1. 读取持久化事务记录与激活记录。
2. 按 `admission_tx_id`、候选清单摘要与 `activation_fence` 查询所有参与者；参与者重放其持久化记录的 prepare/activate 结果。
3. 若持久化决策为 `ACTIVATE`，则重放缺失的激活/启动动作，或发起显式补偿拆卸；禁止参与者仅因协调器暂时不可达就回收预留。
4. 若不存在激活记录，则待已准备租约过期并清理全部已准备路由与预留记录后，事务可完成中止。

Minimum 不要求协调器自动故障转移，但协调器重启必须恢复同一份持久化事务记录。激活后但在产生任何 Guest 流量前发生的故障，仅在所有参与者确认拆卸完成后方可进入 `ABORTED`；进入 `RUNNING` 后的故障走 `FAILED -> STOPPING -> RETIRING`。已中止的实例代次仍须遵守分配器隔离规则，绝不用于后续重试。

## 6. 暂停、停止、故障与恢复

### 6.1 暂停与停止

正常停止流程中，协调器执行以下步骤：

1. 将 VM 置为 `PAUSING` 或 `STOPPING`，在 QEMU 权威侧阻断新的 vCPU 交接与新的设备请求，并通知节点运行时拒绝该实例代次的新外部工作。
2. 等待在途的 vCPU、内存及存储操作到达各自规范定义的完成、中止或不确定结果状态；不得仅因墙钟超时而丢弃未决操作。
3. 执行必需的内存栅栏与存储刷盘，随后按依赖顺序停止 Guest 工作生产者与执行单元。在未决完成确认、结果查询、栅栏同步与回收 ACK 结束前，必须保留所需的内存/存储服务、Sidecar/控制绑定及上下文引用；停止 Guest 执行并不意味着可以立即拆除传输通道。
4. 仅在所有者停止后删除本地名称，并解绑所有清单绑定的文件描述符与内存映射。
5. 进入 `RETIRING`，清除该实例代次的全部目录订阅者，待活动操作引用与查询/重试时间窗结束后回收 VM 路由作用域，并收齐全部必需的路由回收 ACK。
6. 仅在路由、本地名称、上下文、完成缓存与订阅者拆卸记录全部完成后，释放剩余服务绑定/上下文及资源预留，随后记录 `STOPPED`，将 `vm_id` 复用控制权交还 `identity-routing.md` 中的命名空间分配器。

即使 VM A 与 VM B 共享同一 Gateway 或物理节点，停止 VM A 绝不影响 VM B 的路由作用域、前序路由代次、订阅者记录、本地名称或资源预留。

### 6.2 故障与重启

进入 `COMMITTED` 之后的故障不属于启动中止。协调器须依据受影响子系统的契约将 VM 记录为 `DEGRADED`、`PAUSED` 或 `FAILED`，保留现有清单与实例代次并收集恢复证据。

Minimum 对各类故障的处理区分如下：

| 事件 | Minimum 处理结果 |
| --- | --- |
| 非关键本地子进程重启（已注册节点实例 ID 未变） | 仅可依据精确清单与本地角色重启；新的 `local_runtime_instance_id` 必须重新注册后方可服务流量。 |
| 必需执行器或 QEMU 进程丢失状态 | 暂停或置失败 VM，除非对应执行器规范后续提供经证明的状态安全本地恢复机制。 |
| 已注册节点代理或物理宿主机替换 | 产生新的 `node_instance_id`；依赖该节点的既有 VM 进入 `PAUSED` 或 `FAILED`，不执行自动重绑定。 |
| 存在已准备备用路由的 Gateway 替换 | 仅通过成员关系/路由事务平滑继续，不改变清单捕获的资源成员标识。 |

`vm_incarnation` 仅在控制面创建新 VM 生命周期时变化。节点、节点代理、QEMU、执行器、Sidecar 或 Gateway 重启只会产生新的进程/节点/Gateway 实例标识，绝不生成新 VM 实例代次，也不得静默切换执行后端、缺页引擎、存储权威、宿主机、放置方案或期望成员实例。

未来若支持必需成员原地重启，必须定义具名的 `RECOVERY_REBIND` 事务，涵盖新旧实例标识、预留归属、能力校验、精确清单/路由引用、内存/vCPU/存储状态恢复证明以及旧进程隔离（fencing）规则。心跳或端口监听成功不构成重绑定协议。

### 6.3 跨子系统资源回收

本节规定生命周期、IPC、内存、vCPU、存储与内核的跨子系统回收契约。以下逻辑阶段用于细化 `STOPPING` 与 `RETIRING`，不引入额外线协议状态，也不要求所有子系统采用相同钩子 API。

| 阶段 | 协调器职责 | 子系统职责 |
| --- | --- | --- |
| 静默（Quiesce） | 关闭受影响 VM 实例代次的新 Guest 工作准入，并收集本地关门确认。 | 拒绝新的无关工作，在安全边界停止工作生产者，并保留既有在途操作所需资源。 |
| 排空（Drain） | 对已捕获的在途操作集发起完成、取消或隔离请求。 | 核算排队中工作、执行中工作、回调、映射引用及结果/查询留存，上报已确认或不确定结果。 |
| 终结（Finalize） | 在收齐必需证明后授权释放依赖资源。 | 按依赖顺序解绑引用并释放资源，返回幂等且绑定标识的拆卸结果。 |

静默期间仍须放行必需的完成 ACK、内存栅栏、失效确认、结果查询、取消指令及拆卸流量，严禁在排空前粗暴关闭整个 IPC。关门前准入的操作必须原子性地纳入排空集合或被明确拒绝，不可在准入检查与在途记账之间丢失。

每个子系统拥有各自的内部排空算法，并向生命周期层暴露完成契约；生命周期层只协调这些契约，不直接操作子系统私有队列、页结构、设备状态或内核链表。独立操作与无关 VM 可并发排空，仅真实引用与语义依赖施加先后顺序。

在途请求必须持有其清单/路由引用、结果目标以及借用或移交的缓冲区，直至其完成/取消契约允许释放。本地计数归零、超时、传输关闭或仅发出取消请求本身均不能证明远端副作用已停止；对不可达参与者必须具备明确的实例/操作隔离（fencing）证明，确保迟到响应不会修改已回收实例代次或被复用的本地对象。

当无法取得上述证明时，必须返回 `TEARDOWN_INCOMPLETE` 或对应的不确定操作错误，保持必要的标识与资源隔离（quarantine），并保留有界的重试/对账元数据；禁止为了满足截止时间而提前宣告 `STOPPED`、将不确定分配重新放出或释放仍可能被本地工作访问的对象。日志与重试均须有界。资源预留的释放必须待必需的路由、订阅者、进程、映射、上下文及名称所有者确认完成后，再通过准入所有者的 API 执行。

暂停（Pause）使用相同的安全执行边界，但保留恢复所需的预留与资源，不属于最终回收。Minimum 的重启对账遵循第 5.3 节。HA、透明恢复与迁移属于 Extended，不影响本故障封闭回收规则的落地。

## 7. 并发、幂等性与错误处理

- 生命周期串行化以单个 VM 实例代次为粒度；无关 VM 的准入与本地参与者准备可并发执行。
- 协调器不得在发起网络 RPC 或等待进程退出时持有全局成员、放置或 VM 锁。
- 每次生命周期操作携带唯一 `operation_id`。参与者保留有界完成记录，覆盖协调器的重试/查询时间窗。
- 每次 prepare/activate/abort 查询必须标明 `admission_tx_id`、候选清单摘要、资格栅栏摘要及已存在的 `activation_fence`。重复请求返回先前记录的结果，不得重新做本地推断。
- 资源预留获取顺序由准入规范统一定义；清单逻辑必须调用其原子预留 API，禁止临时自行对节点加锁。
- 过期的清单代次、摘要不匹配、错误节点实例、已过期的准备租约、过期资格栅栏、命名空间冲突或能力不匹配，均须返回具类型拒绝错误，禁止通过接受邻近节点、原始路由 ID 或猜测本地路径来“兜底修复”。

必需的生命周期错误类别包括：

```text
INVALID_REQUEST, UNSUPPORTED_CAPABILITY, INSUFFICIENT_CAPACITY,
PLACEMENT_CONSTRAINT, MEMBER_NOT_ACTIVE, TOPOLOGY_NOT_READY,
ROUTE_GENERATION_UNAVAILABLE, RESERVATION_CONFLICT, NAME_CONFLICT,
MANIFEST_MISMATCH, STALE_INSTANCE, ELIGIBILITY_FENCE_STALE,
ACTIVATION_FENCE_UNKNOWN, PREPARE_REJECTED, START_FAILED, QUIESCE_TIMEOUT,
UNCERTAIN_OPERATION, RESULT_EXPIRED, TEARDOWN_INCOMPLETE
```

超时只是控制面观测现象，不证明远端副作用未发生。重试 prepare、commit 或 stop 时必须携带相同的 `operation_id`，先查询已记录结果再决定后续动作。

## 8. 实现触点与要求

| 文件、符号或边界 | 必需职责 |
| --- | --- |
| `ctl_tool/main.c` 与 `common_include/wavevm_resources.[ch]` | 解析/校验请求、调用准入并生成规范清单，不再充当唯一运行时事实来源。 |
| `artifacts/*/run.sh` 与 CI 脚本 | 生成测试清单与派生脚本；仅作为测试夹具保留，不作为策略权威。 |
| `master_core/main_wrapper.c` / `user_backend.c` | 在已准入启动路径中，仅消费经校验的每节点清单、匹配路由快照及派生分发投影，完成后方提供本地 QEMU 或织网流量服务。 |
| `slave_daemon/slave_hybrid.c` | 仅注册清单分配的本地执行器角色，并上报生命周期就绪状态。 |
| `wavevm-qemu/accel/wavevm/` | 将每条连接、SHM 注册与加速器操作绑定到清单标识与摘要。 |
| `master_core/kernel_backend.c` | 仅挂接到按 `kernel-accelerator.md` 准备的每 VM 内核上下文。 |

## 9. 兼容性边界

任何历史环境变量、静态路由或启动脚本配置均不构成生产输入。QEMU、节点运行时、执行器、Gateway 与内核上下文统一消费绑定标识的清单、路由快照与强类型生命周期记录。本地名称全部由已准入清单派生；不受支持或过期的记录必须在开启 Guest 流量前拒绝。

## 10. 验收测试

Minimum 覆盖常规创建/激活、幂等性、部分启动清理、基础持久化重启对账、过期资格拒绝、必需进程丢失时的故障封闭处理以及 VM 作用域安全回收，均须由针对性检查验证。穷举崩溃/竞态/故障矩阵、HA 及透明替换归属 Extended，但不得因此推迟 Minimum 基础规则的实现。

- 相同的规范请求、成员快照与能力集合必须产出完全一致的清单摘要与放置计划。
- 双节点 Flat 夹具与多跳 Fractal 夹具可完全依据生成的清单启动，无需任何隐藏的每 VM 路由或端口输入。
- 重复的创建请求返回原始结果，不得分配第二个 VM 或重复资源预留。
- 任一参与者拒绝 prepare 时，系统不得遗留活动的 QEMU、执行器、路由绑定、内核上下文、端口、SHM 文件或资源预留。
- 携带错误清单摘要、实例代次、本地角色或节点实例 ID 的进程必须在提供流量服务前被拒绝。
- 停止操作在释放 VM 命名空间与本地名称前，必须排空或明确上报所有未决内存、vCPU 及存储操作。
- 同一合格物理节点上的两个 VM 必须拥有互不重叠的本地名称、资源预留、路由标识、日志及运行时状态。
- 活动 Gateway 路径的 `route_generation` 替换不得变更 VM 的放置方案或清单摘要。
- **Extended：** 在每条预留、参与者 prepare、激活、提交、中止与启动消息之后注入协调器崩溃/重启，结果必须严格收敛为单一完整运行/已提交 VM（全部预留保持），或完整补偿拆卸（无泄漏路由作用域、端口、SHM 名称、上下文或容量）。
- **Minimum 可用：** 代表性的激活前隔离（cordon）、Gateway 排空、健康剔除、能力变更以及节点/Gateway 实例替换，必须在进入 `RUNNING` 前使捕获的资格栅栏失效；所有边界的穷举交错归属 Extended。
- **Minimum 可用：** 非关键子进程重启须完成同角色重新注册；必需 QEMU/执行器丢失或必需成员替换须暂停/置失败，不得静默重绑定。全面的独立宿主/进程故障矩阵与透明替换归属 Extended。
- **Minimum 可用：** 静默阶段拒绝新 Guest 工作同时放行必需的 ACK/栅栏/查询/清理流量；迟到回调或不确定远端操作不得访问已释放资源，也不得授权复用命名空间。
- **Minimum 可用：** 当 VM A 与 VM B 共享 Gateway 时，回收 VM A 路由作用域不得影响 VM B 的当前路由、排空中路由、本地名称、预留及订阅者状态。
- **Minimum 可用：** KVM Guest 验收要求可登录或 SSH，且证明已实际走过已准入的远端 vCPU 与远端内存路径；TCG 契约验收要求完成有界的真实指令执行、经校验的 CPU 与远端内存结果以及干净停止（TCG Guest OS 启动/登录/SSH 与持续多 vCPU 可用性归属 Extended，见 `vcpu-handoff.md` 第 8.1 节）。两类后端均不得以进程存活替代门控；运行时就绪与生命周期 `RUNNING` 仅代表清单绑定的服务状态，不可将其混同为 Guest OS 登录证明。

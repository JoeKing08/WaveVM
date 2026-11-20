# WaveVM 资源放置与准入规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：已注册可分配容量、VM 资源请求、确定性放置、宿主机选择、资源预留、准入、多 VM 隔离以及资源释放。运行时清单负责已准入结果；成员关系负责成员资格判定；能力选择负责校验有效的执行后端与缺页引擎。

本规范对所有新的规划与准入工作具有规范效力，不支持隐式热迁移、动态资源借用、宿主机 CPU 超卖或将手工编写的路由表用作放置机制。

## 子系统边界契约

本摘要仅索引各归属规则，不重复其定义。涉及边界变更时适用[架构基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 必需契约 |
| --- | --- |
| 职责与权威 | 负责确定性资源规划与原子资源预留变更。成员关系提供合格成员输入；生命周期负责持久化激活与最终准入结果。 |
| 状态与变更 | 规划器读取一致的库存/能力档位快照。预留所有者按节点、物理宿主机、名称预算及事务粒度串行化冲突；副本无权独立授予容量。 |
| 允许的实现依赖 | 规范请求/计划记录、不可变成员/能力/路由投影、公开预留存储及生命周期事务接口。禁止依赖具体控制器布局、运行时队列或私有页状态。 |
| 交互与生命周期 | 第 6 节负责资源获取与释放。[生命周期规范第 5.2 节](runtime-manifest-lifecycle.md#52-创建与激活时序)负责从 prepare 到激活的顺序；该规范第 6.3 节负责复用前的安全回收。 |
| 并发与开销 | 独立规划可并发执行，冲突快照通过重校验与原子预留解决，禁止使用进程全局临时工作区耦合并发创建。锁与事务域须明确，存储与传输等待须有界。 |
| 故障与验证 | 第 8 与 11 节规范过期资格、补偿、四路并发创建争用及物理宿主机聚合记账。超时绝不证明预留未被激活。 |

## 1. 目标与非目标

目标是让普通 VM 请求只需声明 vCPU、内存与策略，而无需指定物理节点或 Guest NUMA 节点，由控制面确定性地选择并预留合法的跨节点放置方案。

```text
已注册可分配库存 + ACTIVE 成员/能力快照
  + VmRequest 约束
  -> 确定性完整的 PlacementPlan
  -> 原子资源预留
  -> 不可变 AdmittedVmManifest
```

WaveVM 在物理节点之间池化资源容量。已注册节点是资源提供者，既非强制的 Guest NUMA 节点，也不要求单个 VM 独占整节点资源：单个 VM 可使用多个节点的部分资源；只要预留容得下，单个物理节点也可同时承载多个 VM 的分配。

多个已注册资源提供者可共享同一 `physical_host_id`。这属于受支持的逻辑节点细分，绝不允许重复计算宿主机容量。规划器先校验每个节点的独立可分配预算，再校验该宿主机组内所有节点与 Gateway 记录的聚合预算（涵盖 CPU、内存、加速器上下文及宿主机/Gateway 开销）。宿主机级冲突必须返回结构化准入拒绝。每个节点实例还拥有显式的端口/套接字/名称命名空间与排他租约，规划器与运行时不得假设一台宿主机仅运行单个节点代理，也不得复用宿主机全局默认端口或路径。

Minimum 非目标：

- CPU、内存或存储超卖（未来若引入可配置超卖策略，须独立定义记账、驱逐及 Guest 可见故障契约）。
- 运行中 VM 的热添加、热移除、自动再均衡或驱逐。
- 未经显式注册与预留余量核算，直接将宿主机原始核数、物理内存总量或 vnode 数量当作可分配容量。
- 仅因物理放置变化而改变 Guest 可见 NUMA 拓扑。
- 在启动后仅凭可达性或路由学习缓存改选其他成员。

## 2. 权威归属与输入

| 状态或决策 | 权威所有者 | 必需输入 |
| --- | --- | --- |
| 已注册物理容量与能力 | 成员/控制面记录 | 经校验的成员注册与健康状态。 |
| 可分配容量 | 扣除预留余量后的控制面库存 | 已注册容量减去非 WaveVM 与角色开销预留。 |
| 候选资格 | 控制面 | `ACTIVE` 成员状态、健康状态、路由、能力及约束。 |
| 放置计划与预留事务 | 准入协调器 | 单份不可变库存/成员/能力快照。 |
| 宿主机与 Guest 拓扑选择 | 已准入 VM 清单 | 完整放置计划与请求策略。 |
| 运行时队列调度 | 节点运行时与本地执行器 | 已准入计划（非本规范定义）。 |

每次放置尝试必须同步捕获 `membership_revision`、`topology_revision`、`admission_eligibility_revision`、`capability_profile_generation` 与 `inventory_revision`。生成的 `AdmissionEligibilityFence` 列出所有必需的节点/Gateway 角色、实例 ID、能力档位、路由作用域及 ACK 集合摘要。规划器不得将节点 A 的旧容量与节点 B 的新能力档位拼凑为所谓原子计划。

在事务落盘持久化激活决策之前，节点隔离（cordon）、健康剔除、Gateway 排空、选中能力/档位变更或节点/Gateway 实例变更均会使资格栅栏失效。因此，隔离前准备的预留不能让新 VM 越过隔离继续落盘到该节点；而已提交的既有分配由生命周期与排空规则管辖，不会被静默重规划。

## 3. 资源与预留模型

### 3.1 容量单位

Minimum 采用保守、整型、非超卖记账：

| 资源 | 单位 | 含义 |
| --- | --- | --- |
| Guest CPU | `vcpu_slot` | 一个已注册的并发 Guest vCPU 执行容量单位，不自动等同于宿主机硬件线程。 |
| Guest RAM | 字节（bytes） | 扣除宿主机与角色余量后可供 WaveVM 分配的页对齐字节数。 |
| QEMU/节点运行时/执行器开销 | 字节与可选 `vcpu_slot` | 独立于 Guest 请求单独预留，不隐藏在 Guest 容量之内。 |
| 存储 | 后端特定容量/IO 能力 | 必须满足设备计划；容量充足本身不证明刷盘语义达标。 |
| 排他本地资源 | 具名租约 | 端口、套接字路径、SHM 名称、加速器上下文、GPU/VFIO 分配及其他不可共享资源。 |

`ExclusiveLease` 以 `(lease_kind, lease_name)` 唯一标识本地资源。`lease_generation` 记录获取/所有者纪元并参与精确重放比对，但不使同一资源的两次使用变得互不冲突——同一种类与名称的租约即便代次不同也构成冲突。规范租约列表须按 `lease_kind/lease_name` 严格排序且去重。

针对节点运行时启动计划，放置阶段为当前运行时路径实际绑定的两个监听器签发租约：通配 UDP 节点运行时数据监听器和 loopback UDP 本地执行器服务监听器。仅作为适配器元数据的控制端口字段，在对应实现实际创建监听器之前不视为已绑定资源。监听端口与绑定作用域源自控制器选定的启动计划，规划器不硬编码端口段。

每条 `NodeRecord` 暴露如下库存视图：

```text
NodeInventory {
    physical_node_id;
    node_instance_id;
    failure_domain_id;
    inventory_revision;
    registered_vcpu_slots;
    registered_memory_bytes;
    reserved_host_cpu_slots;
    reserved_host_memory_bytes;
    reserved_gateway_cpu_slots;
    reserved_gateway_memory_bytes;
    hosted_gateway_role_ids;
    allocatable_vcpu_slots;
    allocatable_memory_bytes;
    storage_capabilities;
    accelerator_and_fault_capabilities;
    exclusive_resource_inventory;
}
```

除上述库存外，节点记录还暴露 `physical_host_id` 与 `node_instance_namespace`：前者将独立可调度提供者归组，用于聚合记账与关联故障判定；后者限定节点代理的本地套接字、共享内存、日志、临时文件与实例级监听租约的作用域。这些字段均属权威注册/配置输入，不得由启动脚本推断。

`allocatable_*` 必须为显式字段或确定性派生值，绝不在创建 VM 时依据远端 `nproc`、物理总内存或任意 vnode 数量临时推算。承载 Sidecar/Gateway 或控制面角色的节点在参与 Guest 放置前必须先扣除对应开销余量；Gateway 开销归属于对应 `GatewayRecord` 声明的 `hosting_physical_node_id`，不得随意计入其他端点，也不可因 Gateway 拥有独立逻辑成员记录而遗漏。

### 3.2 VM 请求规范化

规划器接收来自 `runtime-manifest-lifecycle.md` 的规范化 `VmRequest`，仅补充规划器自有的派生字段：

```text
NormalizedRequest {
    requested_vcpus;
    requested_memory_bytes;
    memory_chunk_bytes;
    placement_policy;             // COMPACT 或 SPREAD
    host_constraints;
    backend_policy;
    accelerator_policy;
    guest_topology_policy;
    consistency_policy;
    storage_and_device_requirements;
    required_roles_and_capabilities;
}
```

`memory_chunk_bytes` 在规划前选定，为集群支持的 4 KiB 的 2 的幂次倍数。Guest RAM 的每一字节均精确归属一个页对齐的放置块（chunk）。该块可小于物理 NUMA 域——物理 NUMA 仅作优化输入，并非用户可见的分配单位。

执行后端与内存放置是两个独立的规划维度。内存块可分配给任何具备所需内存服务能力、容量及清单有效路由的 `ACTIVE` 参与者，无论其是否具备 KVM 能力；而 vCPU 后端统一约束 VM 内的所有 vCPU 分配，不从内存块所在节点推断。

规划器在输出最终放置前先解析后端策略：

1. 对于 `AUTO`，先尝试构造完整 KVM 候选方案：所有 vCPU 分配必须使用具备 KVM 能力的执行器，内存块可使用任意合格内存参与者。
2. 若完整 KVM 候选失败，丢弃其临时预留并尝试构造全新的完整 TCG 候选方案；TCG 执行器可以是无 KVM 节点，也可以是其 TCG 辅助能力已获准入的 KVM 节点。
3. 对于 `REQUIRE_KVM`，不尝试 TCG 候选；对于 `REQUIRE_TCG`，直接规划 TCG。

最终方案的 vCPU 后端必须同构：同时包含 KVM 与 TCG vCPU 分配的计划无效，即便单项分配在本地各自合法。因此后端回退属于激活前的整体重规划，而非放置后的部分 CPU 降级。

后端容量包含在捕获的库存中。节点可分别暴露 KVM 与 TCG 两类 vCPU 容量，但二者共同扣减该节点的共享宿主机 CPU 与开销预算；规划器不得将 KVM 槽位直接复制为 TCG 容量，也不得让 KVM 与 TCG 预留叠加超卖同一宿主机预算。

对于未页对齐的内存请求，规划器直接拒绝，或仅通过写入规范化请求与清单的文档化 API 默认规则向上取整，绝不静默截断 Guest RAM。

`host_constraints` 约束新 VM 选中的全部物理资源参与者（包括 QEMU 宿主、vCPU 执行器、内存目录/执行器及存储所有者）。Minimum 将 `PHYSICAL_NODE`、`FAILURE_DOMAIN` 与 `CAPABILITY` 约束解析为 `subject=id` 加十进制 `value`，所有约束按逻辑与（合取）生效。在规范 `NodeMetadata` 记录引入前，直接拒绝 `LABEL` 约束，禁止回退读取 Shell 标签、环境变量、主机名启发式或历史配置。

### 3.3 放置计划

```text
PlacementPlan {
    plan_digest;
    admission_tx_id;
    eligibility_fence_digest;
    inventory_revision;
    membership_revision;
    topology_revision;
    capability_profile_generation;
    host_node;
    vcpu_assignments[];           // 每个 Guest vCPU 索引恰好出现一次
    memory_chunk_assignments[];   // 每个 Guest 内存块恰好出现一次
    storage_assignments[];
    reservation_requirements[];
    guest_topology;
    route_scope_requirements;
}
```

每条 vCPU 分配包含 Guest vCPU 索引、物理执行器节点、执行后端、本地执行器类别/槽位及预留键；每条内存块分配包含 Guest 物理地址范围、目录/执行节点、页一致性策略及预留键；`reservation_requirements[]` 携带上述预留键引用的精确每节点 Guest/开销额度与排他租约。凡存在空洞、重叠、重复 vCPU 索引、重复预留键或包含捕获快照中不合格参与者的计划均视为无效。

`host_node` 必须独立且显式选定，并预留：

- QEMU 前端 CPU 与内存开销。
- 宿主节点运行时、本地 IPC 及必需的 Sidecar/Gateway 开销。
- QEMU monitor/串口/网络转发资源与清单派生的本地名称。
- 所选前端后端所需的执行/缺页/加速器能力。

`host_node` 可以兼任 Guest vCPU 执行或 Guest 内存归属，但二者均非隐含前提；从某节点提交的请求完全可以托管在另一台合格节点上。

## 4. 资格判定与校验

物理节点仅在同时满足以下全部条件时具备分配资格：

1. 所需的计算、存储或 Gateway 角色处于 `ACTIVE`，且依据成员规范其健康状态允许新放置。
2. 其 `node_instance_id`、容量档位与端点在捕获快照中为最新值。
3. 满足 `capability-fault-engines.md` 规定的执行后端、缺页引擎、加速器策略、设备/存储能力及 ABI 兼容性。
4. 拓扑中存在已准备/已提交的路由作用域，能够连通该分配所需的全部参与者（仅存在 UDP 监听端口不足以证明连通）。
5. 具备充足的未预留容量及全部必需的排他资源。
6. 满足规范化请求中的显式宿主、亲和、反亲和、局部性或安全约束。

规划器还必须对完整方案执行全局校验：

- KVM 与 TCG vCPU 放置符合已准入后端计划的同构要求，不通过隐式上下文转换掩盖后端失配。
- 若要求内核加速，每个需要它的已分配组件均须具备支持；`PREFER` 仅可在启动前解析为正确的 Mode B 路径。
- 每个远端内存目录/执行器与远端 vCPU 执行器均通过 Sidecar/Gateway 路由织网具备清单有效路由。
- 所有目标专属端口、套接字、SHM 名称、内核上下文及设备租约均与既有预留互不冲突。
- 候选方案不得依赖处于移除、隔离（cordon）或 `DRAINING` 状态的成员。

校验失败时返回首个稳定的具类型原因及有界的被拒约束列表，严禁将任意部分成功的节点子集作为已准入 VM 暴露。

## 5. 确定性放置

规划器基于不可变快照确定性地生成放置计划：对于相同的规范化请求、快照与策略，总是返回相同的 `plan_digest` 或相同的拒绝结果。节点 ID 用作稳定的决胜序（tie-breaker），不意味着编号顺序代表性能高低。

### 5.1 候选排序

1. 评分前先过滤不合格节点。
2. 按稳定的物理节点标识对候选节点排序。
3. 扣除已选分配与必需开销预留后，按可分配单位计算预期利用率。
4. 评分相同时依次按物理节点 ID、本地执行器类别/槽位打破平局。

### 5.2 紧凑策略（Compact）

`COMPACT` 策略在满足全部约束的前提下尽量减少参与的物理节点数。每项分配按如下优先级选择：

1. 已入选且剩余容量充足的合格节点。
2. 能满足最大剩余兼容资源需求的节点。
3. 分配后预期综合利用率较低的节点。
4. 稳定的物理节点 ID。

规划器在为宿主机上的 Guest 分配打分前必须先扣除宿主开销，避免误选仅装得下 Guest RAM 却装不下 QEMU 或节点运行时余量的节点。

### 5.3 分散策略（Spread）

`SPREAD` 策略在多个物理节点间均衡分散兼容需求。每项分配按如下优先级选择：

1. 预期 CPU 与内存利用率两者最大值最低的合格节点。
2. 在不违反资源或局部性约束的前提下，本 VM 已分配项最少的节点。
3. 稳定的物理节点 ID。

在内存、vCPU 或存储契约未配置副本时，`SPREAD` 不承诺容错，仅在容量与拓扑允许时避免不必要的集中。

### 5.4 规划失败

实现可采用有界回溯搜索完整合法方案，但必须限制搜索时间，超限时返回 `PLACEMENT_CONSTRAINT` 或 `INSUFFICIENT_CAPACITY`，不得执行无界调度调用，也禁止在继续搜索剩余部分的同时先预留或启动 VM 子集。

当 `AUTO` 从 KVM 回退至 TCG 时，返回的诊断信息必须明确说明已尝试 KVM、为何无法准入完整 KVM 候选以及最终提交方案采用 TCG。这是一项显式的后端选择结果，而非隐藏的性能折中。

## 6. 原子资源预留与准入

### 6.1 资源预留记录

```text
ResourceReservation {
    reservation_id;
    plan_digest;
    candidate_manifest_digest;
    admission_tx_id;
    eligibility_fence_digest;
    vm_id;
    vm_incarnation;
    physical_node_id;
    node_instance_id;
    inventory_revision;
    guest_vcpu_slots;
    guest_memory_bytes;
    overhead_vcpu_slots;
    overhead_memory_bytes;
    exclusive_leases;
    state;                        // PREPARED、COMMITTED、RELEASING、RELEASED
    prepared_expiry;
    activation_fence_when_committed;
}
```

`PREPARED` 预留带有有界过期时间，仅在持有者尚未观测到匹配的持久化 `activation_fence` 时方可过期回收。一旦激活，预留归生命周期记录管辖直至正常停止或故障拆卸，禁止借任意租约超时从仍在运行的 Guest 回收内存或 vCPU 容量。

`ResourceReservation` 是节点局部派生记录，不作为自摘要放置计划或候选清单的内嵌字段。协调器先定稿上述不可变记录，再基于单条 `ReservationRequirement` 以及最终计划/候选/栅栏摘要构造并发送预留请求；该顺序既避免了哈希环，又保留了从预留需求到实际预留的完整审计链。

### 6.2 预留/提交/中止时序

1. 生命周期协调器在请求预留之前，已完成 VM 标识分配并构造候选清单与资格栅栏。
2. 协调器向每个受影响节点发送 `PREPARE_RESERVATION`，携带事务 ID、候选摘要、栅栏摘要、期望节点实例 ID 及精确本地资源量；每条请求均重新校验成员资格与能力档位。
3. 节点原子性地校验库存与排他租约，记录带过期时间的 `PREPARED` 预留，并返回幂等 ACK 或具类型冲突错误。
4. 路由作用域与参与者准备完成后，协调器持久化 `runtime-manifest-lifecycle.md` 定义的唯一 `activation_fence`。
5. `COMMIT_RESERVATION` 仅在事务 ID、候选摘要、栅栏摘要与 `activation_fence` 全部匹配时将已准备预留提升至 `COMMITTED`；重复请求重放先前记录的结果。
6. 若不存在激活决策，协调器中止所有已准备预留；若已存在激活决策，崩溃恢复流程必须在释放前完成激活推进或补偿拆卸。

### 6.3 持久化准入编排

协调器自有的准入编排器是创建事务的唯一组合点。传输适配器仅作为显式阶段边界的回调，无权建立第二放置或生命周期权威。正常编排顺序如下：

```text
CONTROL_PLANE_BEGIN
  -> ROUTE_PLAN（在 route_scope_id 分配之后）
  -> COORDINATOR_PREPARE
  -> 持久化候选清单 + PREPARING 路由
  -> 路由 prepare
  -> 持久化 ROUTE_SCOPE_PREPARED
  -> 资源预留 prepare
  -> 持久化 RESERVATIONS_PREPARED
  -> 参与者 prepare
  -> 持久化 PARTICIPANTS_PREPARED
  -> 持久化 ACTIVATE 决策
  -> 本地/远端预留与参与者 commit
  -> 持久化每节点运行时投影
  -> 路由 commit + 持久化路由激活
  -> 持久化 COMMITTED
  -> 绑定标识的就绪检查
  -> STARTING -> RUNNING
```

每项路由、预留与参与者回调针对同一准入事务与清单标识均具幂等性。路由 prepare、commit 与 abort 使用由不可变路由事务、阶段及目标成员派生的独立 `operation_id`，而 `RouteTransaction.operation_id` 保持为规范记录承载的稳定事务标识。持久化 `ACTIVATE` 决策前发生的故障记录 `ABORT`，仅调用已准备资源清理，并在路由、参与者、预留及本地清理全部成功后进入 `ABORTED`。`ACTIVATE` 之后发生的故障绝不回退为激活前中止：持久化状态保持 `ACTIVATION_DECIDED`（或更后阶段）以供恢复推进或补偿拆卸。进程异常重启后，恢复执行器仅接受从持久化候选/运行时记录重建且通过标识校验的投影，将 `ACTIVATION_DECIDED` 向前推进、将 `ABORTING` 清理至 `ABORTED`，绝不重选放置方案或路由。

任何节点不得仅凭本地进程已启动、旧路由存在或套接字存活就自行将预留提升为 `COMMITTED`，任何进程也不得在激活前消费 `PREPARED` 预留来承载 Guest 流量。

### 6.4 并发准入

准入协调按物理节点串行化冲突的库存变更，同时允许互不相交的放置计划与 VM 生命周期操作并发推进，且不得在等待网络应答时持有集群全局互斥锁。

节点本地预留实现可使用锁或事务原语，但必须在同一本地原子操作内校验所有资源额度与排他名称。两个仅在对方尚未预留时各自可容纳的并发计划绝不能同时成功。重试仅在其资格栅栏仍然有效时沿用原 `plan_digest`；一旦栅栏失效，必须在全新事务与全新 VM 实例代次下中止并重规划。

## 7. Guest 拓扑与运行时调度

Guest 可见 NUMA 在物理放置完成后选定：

- `FLAT` 为默认兼容呈现模式。
- `PLACEMENT_NUMA` 仅在请求显式选择且所有 Guest 设备/RAM 范围均有效时，暴露与物理放置关联的映射。
- `SYNTHETIC_NUMA` 为策略生成的 Guest 布局，须对其 CPU/RAM 映射提供显式文档说明。

任何 Guest 拓扑选项都不会改变内存页、vCPU、存储请求或路由的归属。Guest vCPU 的运行时交接队列以及节点执行器的批处理/QoS 均归常规运行时管辖；规划器不得为了简化记账而将数据面退化为全局串行执行器。

## 8. 故障、释放与成员交互

| 条件 | 必需行为 |
| --- | --- |
| 激活前容量、成员、路由或能力变更 | 使资格栅栏失效，中止/重规划，禁止提交过期额度。 |
| 节点拒绝资源预留 | 中止所有已准备对端，并返回具类型准入失败。 |
| 准备后节点/Gateway 实例变更 | 判定栅栏过期并中止/重规划。 |
| 激活决策前 VM 启动失败 | 经有界清理后仅释放已准备预留。 |
| 激活决策后 VM 启动失败 | 在生命周期完成激活恢复或补偿拆卸前保留预留，禁止静默复用。 |
| 计算节点被隔离（cordon）或 Gateway 开始排空 | 从新准入及未完成准入中剔除；既有已提交分配按独立排空策略处理。 |
| 待移除计算节点/Gateway 存在活动依赖 | Minimum 中成员控制器拒绝移除，规划器亦不得将其用于新计划。 |
| 运行中 VM 超出已预留容量 | 显式上报运行时/准入缺陷，禁止随意借用容量或静默降级其他 VM。 |

新增成员仅使新库存对后续准入可用，不会修改运行中清单或扩容既有 VM。移除空闲成员可在路由/成员规则完成后释放其库存；移除仍承载活动 VM 分配的成员受 `cluster-membership-topology-lifecycle.md` 中的排空限制约束。

## 9. 实现触点与要求

| 文件、符号或边界 | 必需职责 |
| --- | --- |
| `common_include/wavevm_resources.[ch]` | 解析与校验规范库存、资格栅栏、完整计划、显式预留及宿主机开销，不引入历史配置适配器。 |
| `common_include/wavevm_admission.[ch]` | 在驱动线上预留 RPC 之前，演进为协调器自有的准入模型与规范记录渲染器。 |
| `common_include/wavevm_admission_orchestrator.[ch]` | 接入生产控制传输与恢复对账，禁止通过启动脚本策略绕过持久化协调器。 |
| `common_include/wavevm_admission_recovery.c` | 用生产日志/恢复加载器与参与者查询协议替换夹具自有重建逻辑。 |
| `ctl_tool/main.c` | 提交规范化 VM 请求、回报确定性计划或拒绝原因，并驱动预留/生命周期 API。 |
| `master_core/logic_core.c` | 仅消费清单派生的每 VM 放置方案，拒绝未预留分配。 |
| `gateway_service/aggregator.c` | 消费为已准入参与者生成的路由快照，不参与容量或放置决策。 |
| `artifacts/*/run.sh` 与 CI 夹具 | 保持为由请求/清单夹具渲染的测试输入，不充当容量事实来源。 |

## 10. 兼容性边界

手工编写的静态库存、隐式请求宿主放置及历史预留输入均不构成生产权威。准入统一采用经校验的成员快照、规范请求、显式宿主机开销、排他本地名称租约及持久化预留/生命周期记录。不支持的请求必须返回结构化错误，禁止回退隐式默认值。

## 11. 验收测试

- 请求 32 vCPU 与 64 GiB 内存时，可跨多个已注册节点分片放置，既不强制暴露 Guest NUMA，也不要求用户指定节点。
- 超出聚合合格容量、单节点剩余容量或宿主机开销的请求，必须在任何 QEMU/执行器启动前失败。
- 4 个并发的 20 vCPU / 40 GiB 请求要么获得互不重叠的完整预留，要么返回结构化拒绝；任何请求不得共享排他名称或超出容量上限。
- `COMPACT` 与 `SPREAD` 夹具在同一快照下重复运行必须产出稳定的 `plan_digest`，且两者差异严格符合文档化评分规则。
- 放置计划的 vCPU 表与内存表必须精确覆盖全部请求的 Guest 资源一次、满足页对齐，且仅引用兼容的 `ACTIVE` 参与者。
- `AUTO` 请求优先生成完整 KVM 计划；当 KVM 容量或能力不足时生成全新的完整 TCG 计划，绝不产出混合后端 vCPU 计划。
- `REQUIRE_KVM` 请求在任一必需 vCPU 无法放置于 KVM 执行器时拒绝整个集群，但其内存块仍可放置于合格的非 KVM 内存参与者。
- 具备 KVM 能力的节点仅能通过其已准入 TCG 执行器容量承载 TCG vCPU，且受共享宿主机 CPU 预留约束以防止超卖。
- 预留冲突或过期节点实例必须中止所有已准备对端，不得遗留容量、端口、SHM 文件或加速器上下文泄漏。
- 在每个准入阶段并发触发计算节点隔离（cordon）、Gateway 排空、健康剔除、能力变更与节点实例替换，任何通过已失效资格栅栏的新 VM 均不得进入 `RUNNING`。
- 在每条 prepare、激活、提交、中止与启动消息之后注入协调器崩溃/重启，每个事务必须严格收敛为完整提交/运行的 VM（全部预留保持），或完整补偿拆卸（全部资源释放）。
- 新增节点仅影响后续 VM 请求，绝不修改已准入 VM 的宿主机、vCPU/内存计划或 Guest 拓扑。
- 混合 Mode A / Mode B 集群仅在所有选中组件均支持清单所需能力档位时准入，否则必须在启动前返回明确的能力错误。

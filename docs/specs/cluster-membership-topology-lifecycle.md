# WaveVM 集群成员关系与拓扑生命周期规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：集群成员关系、物理节点与 Gateway 注册、健康监测、Flat/Fractal 拓扑、Pod 成员关系、路由快照发布、调度资格、受控排空/移除以及故障处置结果。本规范不定义页一致性、vCPU 状态传输、热迁移或精确线协议报文编码，这些分别归属内存、vCPU 及标识/线协议规范。VM 清单与资源预留归属 `runtime-manifest-lifecycle.md` 和 `resource-placement-admission.md`，本规范向其提供合格成员与路由快照输入。

本规范对所有成员关系与拓扑工作具有规范效力。`NODE`、`ROUTE`、心跳及历史 Gateway 控制路径均非生产输入，拓扑记录与经认证的成员控制消息是唯一权威来源。

## 子系统边界契约

本摘要仅索引各归属规则，不重复其定义。涉及边界变更时适用[架构基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 必需契约 |
| --- | --- |
| 职责与权威 | 负责已注册成员、拓扑、调度/路由资格及权威快照发布。健康上报仅为证据；转发缓存无权准入成员。 |
| 状态与变更 | 控制面 API 负责变更成员/拓扑修订号与事务。不可变快照与节点/Gateway 观测属于带有实例/代次生命周期的投影，而非替代注册表。 |
| 允许的实现依赖 | 规范记录、公开的标识/路由编译器及快照 API、能力证据、经认证控制传输以及生命周期/准入通知。禁止直接修改页/vCPU 状态或访问规划器私有状态。 |
| 交互与生命周期 | 第 4.1、5 和 7 节绑定资格、准入及发布/回收规则。[路由操作生命周期](identity-routing.md#61-路由替换与操作生命周期)负责在途路由代次保留；[生命周期回收](runtime-manifest-lifecycle.md#63-跨子系统资源回收)负责 VM 清理。 |
| 并发与开销 | 在声明的域内串行化冲突的成员/快照转换；读取端消费一致的不可变快照。禁止在每条页/vCPU RPC 路径上访问注册表，也禁止在持有全局数据面锁时等待网络 ACK。 |
| 故障与验证 | 第 5、7 和 10 节规范排空拒绝、唯一路径故障、过期栅栏及 ACK 集合。宿主机关联故障须整体上报，禁止隐式重绑定 Guest 状态。 |

## 1. 目标与非目标

目标是使集群成员变更成为受控的控制面操作。增加或移除计算节点或 Gateway，绝不得使路由、容量记账、VM 放置或 Guest 可见状态陷入含糊的中间态。

期望控制流如下：

```text
运维期望拓扑 + 观测到的成员健康状态
  -> 控制面校验与规划
  -> 生成不可变路由快照
  -> 向节点运行时与 Gateway 发布并收集确认
  -> 获得调度/路由资格
```

Minimum 非目标：

- 成员加入或离开时自动对运行中 VM 执行热迁移、热添加或透明再均衡。
- 必需资源节点故障后仅靠重试恢复 Guest 内存、vCPU 状态或设备状态。
- 将 Gateway 路由表视为成员权威。
- 将心跳、源地址或学习到的路由视为完整的成员注册或移除操作。
- 在状态与转换规则明确之前强制绑定特定的控制面数据库、共识实现或认证机制。

### 1.1 Minimum 可用边界

Minimum 可用系统涵盖成员加入、计算节点隔离（cordon）、安全排空以及 Gateway 替换的常规控制面路径。新加入成员仅在通过标识/能力校验并完成经确认的路由快照后才获得资格。隔离（cordon）阻断新放置，计算节点排空拒绝存在活动 VM 依赖的请求，Gateway 替换在发布前必须具备经验证的备用路径。

Minimum 不包含自动热迁移、协调器高可用（HA）、丢失 Guest 状态的透明恢复或跨多作用域宿主机聚合事务。这些属于 Extended 加固工作，不得削弱基础操作的故障封闭特性。

## 2. 权威归属与版本域

| 状态或决策 | 权威所有者 | 允许的消费者/缓存 |
| --- | --- | --- |
| 期望的计算/Gateway 成员关系与角色分配 | 集群控制面 | 节点代理与 Gateway 仅上报观测状态。 |
| 观测到的健康状态与端点可达性 | 已注册成员代理 + 控制面健康监控 | Gateway 可上报证据，但无权将其提升为成员资格。 |
| 角色间的宿主机/故障域关联 | 集群控制面 | 节点与 Gateway 记录消费显式注册的关联关系。 |
| Pod 图与 Flat/Fractal 拓扑策略 | 集群控制面 | Gateway 消费不可变拓扑快照。 |
| 调度资格与可分配容量 | 集群控制面 | 调度器仅读取健康且容量经校验的 `ACTIVE` 成员。 |
| 路由快照与下一跳规则 | 集群控制面 | 节点运行时、Sidecar、Gateway 及可选内核缓存消费同一带版本快照。 |
| 运行中 VM 的 CPU/内存/存储分配 | 已准入 VM 清单与生命周期协调器 | 成员变更不得隐式改写该分配。 |

以下版本域语义各异，严禁相互替代：

| 版本域 | 含义 |
| --- | --- |
| `membership_revision` | 期望成员记录及其生命周期状态的单调修订号。 |
| `topology_revision` | Pod 与 Gateway 拓扑图的单调修订号。 |
| `admission_eligibility_revision` | 有资格参与新 VM 激活的成员/角色/能力集合的单调修订号。 |
| `route_scope_id` | 单个 VM 实例代次的路由命名空间或叶级作用域。 |
| `route_generation` | 单个完整路由快照键内的不可变下一跳代次号。 |
| `vm_incarnation` | 单次成功的 VM 生命周期代次，防止旧 VM 延迟流量进入复用命名空间。 |
| 节点启动/进程实例 ID | 单个成员代理进程生命周期，防止旧进程冒充新注册记录。 |
| 既有的节点、请求、页及 CPU 纪元（epoch） | 语义归属各自子系统，均不代表成员关系新鲜度。 |

## 3. 数据模型

精确序列化 schema 归属 `canonical-record-schema.md`，以下为必需的逻辑字段。

### 3.1 计算节点记录

```text
NodeRecord {
    physical_node_id;
    physical_host_id;
    node_instance_id;
    failure_domain_id;
    control_endpoint;
    sidecar_endpoint;
    roles;
    pod_id;
    local_vnode_range;
    capacity;
    capabilities;
    desired_membership_state;
    observed_health_state;
    membership_revision;
    topology_revision;
    node_instance_namespace;
}
```

`physical_node_id` 标识一个独立可调度的资源提供者；`physical_host_id` 标识承载它的物理宿主机，并非网络地址，也不得从端点推断。同一 `physical_host_id` 下可存在多个计算 `NodeRecord`，但其 `physical_node_id`、`node_instance_id`、资源预留、监听端点及 `node_instance_namespace` 必须各不相同。当节点代理实例或其宿主机实例被替换时，`node_instance_id` 随之变更。单台物理宿主机亦可拥有多个本地 vnode，但 vnode 分配属于路由职责，并不意味着每个 vnode 是独立可调度机器。

控制器在节点与宿主机两级进行容量核算：每条节点记录拥有各自的可分配预算，同时宿主机聚合上限约束 CPU、内存、加速器及宿主机开销预留，避免同一份物理容量被每个逻辑节点重复计数。宿主机故障会使该宿主机上托管的所有节点与 Gateway 角色同时失效，而进程或节点实例故障可能仅影响单个成员。因此节点级隔离（cordon）与排空同宿主机级移除保持分离。

`node_instance_namespace` 是节点代理的本地 Unix 套接字、共享内存名称、日志及临时路径的规范实例级命名空间。网络数据/控制端口与本地套接字路径从已注册的节点实例配置中选取，并由显式租约持有；任何节点启动路径都不得回退到宿主机全局默认值（如 9000 端口或宿主机全局套接字名）。

### 3.2 Gateway 记录

```text
GatewayRecord {
    gateway_id;
    gateway_instance_id;
    hosting_physical_node_id;
    failure_domain_id;
    endpoint;
    roles;                  // leaf sidecar、intermediate、root 或组合角色
    pod_id_or_scope;
    parent_gateway_ids;
    child_gateway_ids;
    desired_membership_state;
    observed_health_state;
    membership_revision;
    topology_revision;
}
```

Gateway 与计算节点可共享同一台物理宿主机，但两类记录互不为别名。`hosting_physical_node_id` 与 `failure_domain_id` 必须作为注册字段显式填写，不得依据端点地址推断。只要 Gateway 端点与宿主机侧资源预留不重叠，Gateway 可与一条或多条计算节点记录共享 `physical_host_id`。存活宿主机可能仅出现计算侧或 Gateway 侧的局部进程故障，而宿主机故障则会触发其托管全部角色的关联故障。

### 3.3 路由快照

```text
VmRouteScopeKey {
    vm_id;
    vm_incarnation;
    route_scope_id;
}

RouteSnapshotKey {
    vm_route_scope_key;
    topology_revision;
    route_generation;
    snapshot_digest;
}

RouteSnapshot {
    route_snapshot_key;
    membership_revision;
    flat_or_fractal_scope;
    next_hop_rules;
    required_ack_set;
    required_ack_set_digest;
    predecessor_snapshot_key;
    operation_retention_horizon;
    activation_and_retirement_policy;
}
```

拓扑图是集群全局的，但路由快照是结合该拓扑图与候选放置计划编译生成的每 VM 实例代次/作用域叠加视图；随后的不可变候选清单再绑定该已准备的快照键。因此同一 Gateway 可在保留 VM A 排空中前序快照的同时，独立处理 VM B 的启动、停止或路由演进。快照一旦准备完成即不可变；Gateway 可并发保留当前快照与排空中前序快照，但每次数据包查找必须基于单一完整快照，严禁访问部分修改的路由表。

`route_generation` 仅在 `RouteSnapshotKey` 内唯一，接收端必须校验完整键与摘要。作用域的创建、激活与回收均为生命周期操作，不是成员加入的隐式副产物。

### 3.4 无 VM 作用域时的集群准入证明

成员准入拥有独立于 VM 路由作用域发布的集群级阶段。当集群尚无任何 VM 实例代次时，不得伪造 `VmRouteScopeKey`、`RouteSnapshot` 或测试 VM ID 来激活节点或 Gateway。控制器应在校验经认证的成员记录、端点与能力证据、宿主机与 Pod 分配以及当前成员/拓扑/资格修订号后，生成 `ClusterAdmissionProof`（`0x1032`）。

该证明包含成员标识与规范记录摘要、三项修订号栅栏、能力与拓扑证据摘要，以及独立的 `ClusterAdmissionAckSet`（`0x1034`，其条目为 `ClusterAdmissionAckEntry`，`0x1033`）。必需对端准备并确认该证明；仅当证明持久化提交且收齐全部必需对端确认后，成员方可从 `VALIDATING`/`PREPARED` 转为 `ACTIVE`。仅凭注册、TLS 可达或心跳绝不能完成激活。

当首个 VM 创建时，放置阶段为其分配真实的 VM 实例代次与路由作用域，随后走标准的每 VM `RouteSnapshot` prepare/commit 流程。集群准入证明绝不携带 VM 标识，也不演变为路由快照。若证明准备或提交失败，成员保持不可调度，且该证明可在同一操作标识下重试或持久化中止。

## 4. 成员与健康状态机

成员状态分别独立作用于计算节点记录与 Gateway 记录：

| 状态 | 含义 | 可调度 | 可路由 |
| --- | --- | --- | --- |
| `PENDING` | 注册请求已存在，但标识与端点尚未验证。 | 否 | 否 |
| `VALIDATING` | 正在校验能力、标识、端点及拓扑约束。 | 否 | 否 |
| `PREPARED` | 必需路由快照已加载并确认，但尚未提交。 | 否 | 否 |
| `ACTIVE` | 成员资格与路由代次均已提交。 | 仅计算节点 | 仅 Gateway/Sidecar |
| `CORDONED` | 禁止新计算放置；既有分配保持不变。 | 否 | 仅既有路径 |
| `DRAINING` | 正在按显式排空计划执行受控移除。 | 否 | 仅旧代次排空流量 |
| `REMOVED` | 成员已回收，其标识不得立即复用。 | 否 | 否 |
| `FAILED` | 控制面已记录不可恢复或非计划故障。 | 否 | 否（即便显式保留排空路径，亦不可假定其健康） |

健康状态仅作为观测信号，不替代成员状态：

| 健康状态 | 含义 |
| --- | --- |
| `HEALTHY` | 有效心跳及必需的端点/能力检查均处于有效期内。 |
| `SUSPECT` | 超出有界监控阈值；检查期间从新放置中剔除该成员。 |
| `UNREACHABLE` | 达到更长超时阈值或观测到显式传输故障。 |
| `RECOVERING` | 成员重新上线，但必须重新校验实例标识与当前快照后方可使用。 |

处于 `ACTIVE` 的记录一旦转为 `SUSPECT` 或 `UNREACHABLE`，立即丧失新调度资格，但不会自动转入 `REMOVED`、自动释放资源或授权路由学习对其进行替换。

### 4.1 准入线性化

控制面维护覆盖所有合格成员、Gateway 角色、节点/Gateway 实例、能力档位、健康剔除及路由作用域的 `admission_eligibility_revision`。候选 VM 在规划阶段捕获该值及完整的 `AdmissionEligibilityFence`。

以下操作会使所有尚未到达持久化 `activation_fence` 且存在依赖的候选事务失效：

- 计算节点隔离（cordon）、健康剔除、排空、移除或节点实例变更。
- Gateway 排空、故障、移除、拓扑替换或 Gateway 实例变更。
- 必需能力/档位变更或路由作用域 ACK 集合变更。

线性化规则采用单一控制面决策序：

```text
成员/拓扑资格变更早于 ACTIVATE
  -> 候选 ACTIVATE 因 ELIGIBILITY_FENCE_STALE 被拒绝并中止/重规划

持久化 ActivationRecord(decision=ACTIVATE) 早于成员/拓扑变更
  -> 事务成为决策后依赖；排空须等待激活完成，或在移除选中成员前驱动补偿拆卸
```

每条资源预留、参与者 prepare、路由 prepare、`COMMIT_RESERVATION` 及 `ACTIVATE_MANIFEST` 请求均校验精确栅栏；节点不得仅因自身实例 ID 仍匹配就接受过期预留。处于 `DRAINING` 的 Gateway 仅服务前序代次排空流量，不可用于满足新候选的常规路由 ACK 集合。

`AdmissionEligibilityFence` 除成员与拓扑修订号外，还独立携带规范字段 `admission_eligibility_revision`。因此即便已注册拓扑未变，健康状态、能力或待排空状态的变化也会使未完成候选失效。

## 5. 受控运维操作

### 5.1 加入计算节点

1. 节点代理注册稳定的物理标识、全新的实例 ID、端点、可提供容量、能力声明、请求角色及引导拓扑信息。
2. 控制面校验标识、端点可达性、能力声明、排他名称、Pod 容量及准入策略。
3. 控制面在不与活动标识冲突的前提下分配 Pod 与本地 vnode 范围，将成员记录为 `VALIDATING`。
4. 若当前无受影响的 VM 路由作用域，控制面创建集群级 `ClusterAdmissionProof`（含当前成员/拓扑/资格栅栏及 `ClusterAdmissionAckSet`），绝不伪造 VM 作用域或路由快照；若影响既有 VM 作用域，则各作用域分别执行独立的不可变路由快照事务与 ACK 集合。
5. 各必需集群证明对端校验标识、记录摘要、能力/拓扑证据与修订号栅栏，确认已准备证明（不用于常规流量）。路由作用域 ACK 独立执行，校验各自快照键与下一跳规则。
6. 待全部必需集群 ACK 持久化后，控制器持久化提交集群证明，并在该入网授权下将加入的计算角色标记为 `ACTIVE`。VM 作用域路由激活独立提交，两类事务互不替代。调度器仅在相关持久化准入与路由决策全部完成后方可使用新容量。
7. 任一 prepare 失败即中止操作；候选节点保持不可路由且不可调度，不遗留部分生效路由。

新增容量不会修改已运行 VM 的不可变已准入清单；运行中 VM 的在线扩容属于独立的未来能力，需另行定义内存、vCPU、设备及 Guest 拓扑契约。

### 5.2 加入 Gateway

Gateway 加入遵循相同的注册与 prepare 流程，并增加以下要求：

- 控制面校验目标父/子拓扑图，拒绝成环或存在歧义的下一跳。
- 校验每条必需链路的双向可达性。
- 一并准备所有受影响的子级、父级及叶级下一跳规则。
- 记录 Gateway 的托管物理节点与故障域，并在其获得资格前预留宿主机侧控制/Gateway 开销。
- 仅在已提交快照为每个新路由目标提供到达目标节点运行时的完整路径后，Gateway 方可转为 `ACTIVE`。

Gateway 仅凭 UDP 监听端口绑定成功不足以宣告就绪；就绪必须包含路由快照校验与必需对端确认。

### 5.3 隔离（Cordon）与排空计算节点

对计算成员而言，`CORDONED` 立即推进准入资格修订号，阻断未完成候选准入继续选中该计算角色，同时允许既有分配继续运行或接受检查。对 Gateway 成员而言，`CORDONED` 阻止新准入或后继路由选择该 Gateway，同时保留既有流量已提交的路由快照而不改写之。请求进入 `DRAINING` 时，必须完整枚举所有依赖该成员的 VM 分配，包括 vCPU 执行、内存所有者/目录职责、存储工作、必需本地控制职责，以及（若移除整台物理宿主机时）所有托管的 Gateway 角色。

Minimum 仅在该依赖集合为空时允许移除；若非空，则携带结构化原因拒绝。控制器严禁静默改写 CPU 路由、内存放置、目录归属或 Guest NUMA 布局来制造节点“可移除”的假象。

### 5.4 排空与移除 Gateway

在 Gateway 进入 `DRAINING` 之前，控制器必须创建包含全部受影响目标经验证后继路径的路由事务。待离场 Gateway 排除在后继 `RequiredAckSet` 之外；它可上报可选的前序排空状态，但其失联不得阻塞后继提交。仅当所有存活必需源端完成同一快照键/摘要的 prepare 后，新常规流量才切换。

Minimum 的 Gateway 排空原语采用故障封闭设计，限定作用于单个受影响 VM 路由作用域。仅在满足以下全部条件时接受排空：待离场 Gateway 健康且处于 `ACTIVE`、在该 VM 实例代次上恰好存在一条已注册依赖、后继快照满足 `topology_revision = current + 1`、前序快照为该作用域当前已激活快照、待离场 Gateway 在可选前序排空集合中恰好出现一次，且任何后继下一跳或必需 ACK 均不再引用该 Gateway。跨多作用域排空必须表达为显式聚合事务，禁止只发布部分替代路径。

控制器先持久化后继 `RouteTransaction`，再在 Gateway 排空计划中持久化预留下一拓扑修订号并推进 `admission_eligibility_revision`。该预留存活期间，拒绝任何成员注册、移除或其他变更拓扑的排空操作，仅放行该预留后继对应的 ACK。其复合提交作为单条持久化帧执行：同步激活后继快照及其必需 ACK 状态、将 Gateway 置为 `DRAINING`、推进成员/拓扑/资格修订号并为所有记录盖章。若崩溃发生在常规路由 prepare 之后、排空计划落盘之前，会留下无法 ACK 或提交的孤立未来拓扑路由，恢复路径仅允许对其进行显式中止。

中止操作回收已准备的后继路由并清除存活拓扑预留，不修改成员或拓扑修订号，且不回退 `admission_eligibility_revision`——该单调推进确保排空准备期间捕获的准入资格失效不可因后续中止重放而“复活”。

前序快照须持续保留，直至每条操作引用完成或其文档化查询/重试时间窗到期并返回具类型结果，固定任意定时器不足以作为回收条件。若任一存活必需 ACK 持有者不可达，控制器必须隔离（fence）该发送方并将依赖 VM 置为降级/失败，或者维持前序快照活动；严禁在存活发送方仍只能使用失效下一跳时全局发布新路由。

若该 Gateway 是通往任一活动目标的唯一经验证路径，直接拒绝移除。仅杀死进程、关闭套接字或删除单条路由表项不构成排空。

### 5.5 宿主机级角色排空与移除

宿主机移除是覆盖所有共享同一 `hosting_physical_node_id` 或故障域宿主机标识的计算、Sidecar 及 Gateway 角色的事务。各角色记录在常规角色局部故障中保持独立，但宿主机停机/移除不得只处理其中单一角色：

1. 对宿主机上所有计算放置执行隔离（cordon），使依赖其资源或 Gateway 路由的未完成准入失效。
2. 枚举所有托管角色上的全部决策后或已提交计算分配、本地控制职责、Gateway 路由作用域及前序代次排空。凡携带 `activation_fence` 的事务在达到 `COMMITTED` 或其补偿拆卸全局落盘前，均视为有效依赖。
3. 按必需存活者 ACK 规则为每个待离场 Gateway 准备并提交不含该 Gateway 的后继路由。
4. 排空并回收前序路由代次，随后确认无任何活动快照或常规发送方仍引用该宿主机。
5. 仅在所有计算角色的资源依赖集合为空后移除计算角色，至此方可停止宿主机或其剩余角色。

### 5.6 非计划故障

非计划角色故障按以下顺序处置：

1. 将故障角色标记为 `SUSPECT` 或 `UNREACHABLE`，推进准入资格修订号，将其剔除出新调度与新激活。
2. 若为非计划物理宿主机故障，在单次关联故障观测下原子性地将所有托管角色标记为 `SUSPECT`/`UNREACHABLE`，避免因独立的 `GatewayRecord` 尚未过期而保留失效 Gateway 路由。
3. 判定每项受影响 VM 依赖是否存在已经过验证的备用路由或资源副本。
4. 若存在安全备用 Gateway 路径，使用其持久化的必需存活者 ACK 集合发布替代路由。
5. 若必需资源节点或唯一路径缺乏明确定义的替代方案，如实上报 VM 既定的降级、暂停或失败结果，不得伪报健康或臆造 Guest 状态恢复路径。
6. 重新出现的成员须携带新实例 ID 重新进入校验，不得仅凭心跳恢复 `ACTIVE`。Minimum 中，既有必需 VM 不自动重绑定至新成员实例。

## 6. Flat 与 Fractal 路由作用域

成员捕获与准入不得依据单一域的 vnode 上限来确定所有成员记录或临时缓冲区的尺寸。集群成员、Flat/叶级域 vnode、Gateway 邻接/路由表以及每 VM 工作区均拥有独立、显式的资源预算，按实际记录分配有界存储；记录数与字节数上限（含序列化快照上限）在发布或激活前强制校验。

正式路由帧前缀使用 `u32` 表示 vnode/端点，并配有独立的 `u64` 目标作用域。`0xffffffff` 为保留值，可表示的 vnode 范围为 `0..0xfffffffe`；该地址空间不代表物理宿主机容量承诺。详细预算与稀疏 ID 契约见 `identity-routing.md` 第 3.1 节。逻辑目标形式如下：

```text
flat:    { vm namespace, local vnode }
fractal: { vm namespace, pod or prefix, local vnode }
```

在 Fractal 部署中：

- 叶级 Sidecar 仅将本地 vnode 映射到本地节点运行时端点。
- 中间层 Gateway 将已准入的 Pod/前缀作用域映射到子级或父级下一跳。
- 根级或上层 Gateway 将目标 Pod/前缀映射到子树下一跳。
- 每一层均严格维持相同的 VM 命名空间与实例代次规则。

控制面依据连通性、路由聚合策略及各独立容量预算选择 `flat`、`fractal` 或 `auto` 等策略。只要消费者具备充足资源，Flat 域即可使用其独立声明的容量；单纯的高 vnode ID 或容量阈值本身不强制引入层级。Fractal 拓扑可将多个独立预算的叶级域聚合为更大集群，且全局成员与准入容量绝不继承单个叶级域的预算。

用户仅请求 VM 资源与策略，不手工编写逐目标 Gateway 路由。预算变更不会绕过常规成员/准入与快照事务直接激活成员、改写既有 VM 放置或替换活动路由。容量不足时必须显式拒绝，禁止截断捕获数据、静默变更拓扑或发布残缺路由集。

### 6.1 VM 路由作用域生命周期

生命周期协调器在获得候选放置后、资源与参与者激活前，创建一个或多个 `VmRouteScopeKey`。路由编译器将该 VM 作用域叠加视图与当前集群拓扑结合，生成初始 `RouteSnapshotKey`；随后的不可变候选清单再绑定该键。任何操作均不得原地修改全局 Gateway 路由表。

针对初始 VM 作用域，`RequiredAckSet` 仅包含已在运行的存活 Sidecar/Gateway 及任何新引入的 Gateway 角色。尚未准备就绪的每 VM 节点运行时不属于路由事务存活者；它通过 `PREPARE_MANIFEST` 获取精确的已准备快照，并在自身完成激活 ACK 前不得发送常规流量。这使得路由作用域准备可在 VM 资源预留之前完成，而不必将未启动的 QEMU/执行器误判为缺失的 Gateway ACK 来源。

```text
作用域不存在
  -> ROUTE_SCOPE_PREPARED（仅候选，已确认但无常规流量）
  -> ROUTE_SCOPE_ACTIVE（与已准入 VM 共享同一 activation_fence）
  -> ROUTE_SCOPE_RETIRING（拒绝新操作，保留前序与查询窗）
  -> ROUTE_SCOPE_RETIRED（作用域全部专属状态已释放）
```

反向流程属于 VM `RETIRING` 的一部分：仅在收齐路由回收 ACK、完成订阅者清理且活动操作引用归零后，移除被停止 VM 的作用域。共享 Gateway 可并发保留多个当前与排空中的作用域快照；原始 vnode ID 重叠绝不构成共享命名空间条目的依据。

## 7. 发布、并发与故障规则

每次路由更新对应一条持久化事务：

```text
RouteTransaction {
    operation_id;
    route_snapshot_key;
    predecessor_snapshot_key;
    required_ack_set[];           // 角色 ID、实例 ID、期望端点
    required_ack_set_digest;
    optional_departure_drain_set[];
    operation_retention_horizon;
    state;                        // PREPARING、ACTIVATED、RETIRING、RETIRED、ABORTED
}
```

`required_ack_set` 仅包含在发送 `G+1` 常规流量前必须安装 `G+1` 的当前合格存活者，以及本事务正在激活的新 Gateway；处于 `FAILED`、`REMOVED` 或待离场 `DRAINING` 的 Gateway 均被排除（即便它仍位于前序排空集合中）。离场确认仅作为可选诊断/排空证据，不作为提交前置条件。

路由更新语义如下：

```text
持久化 RouteTransaction 与 RequiredAckSet
  -> 在每个必需存活者上 prepare 不可变快照 G+1
  -> 通过独立于 G 的控制路径仅收集已持久化的必需 ACK
  -> 在这些存活者上原子激活 G+1
  -> 在活动操作引用或查询/重试时间窗未结束前保留 G
  -> 回收 G，随后记录路由作用域/代次已回收
```

每条 ACK 均携带 `operation_id`、完整路由快照键与摘要、角色标识、角色实例标识以及 prepared/activated 状态。协调器重启必须复用已持久化的 ACK 集合与已记录应答，禁止在事务中途重新计算法定集合。若某个必需存活者变得不可达，控制器要么隔离其常规流量并使受影响 VM 降级/失败，要么中止事务并继续保留 `G`，严禁静默发布不可用的后继快照。

路由转发元数据仅可在满足 `wire-ipc-abi.md` 重试规则的前提下从 `G` 切换为 `G+1`：内层语义操作键与摘要保持不变，目标端去重不受影响。前序快照按活动操作引用及内存、vCPU、块存储操作的最大完成查询/重试时间窗保留；超过该时间窗的查询返回具类型的 `RESULT_EXPIRED` 或失败，绝不触发第二次 Guest 可见执行或写入。

控制面串行化冲突的拓扑与成员操作，但该串行化严格局限于控制面。常规内存/vCPU 数据路径继续使用本地队列、批处理、QoS 及不可变路由快照查找，不得在逐包路径上获取全局成员锁。

快照替换必须采用安全的生命周期所有权机制（如引用计数或等效的 RCU 方案），确保接收工作线程仍可能访问前序快照时 Gateway 不会释放它。具体机制由实现选定，但其读/写排序与拆卸行为必须经过测试验证。

Minimum 不提供控制面自动持久化故障转移。成员操作具备有界的准备租约与操作标识；协调器重启后须依据持久化事务/ACK 集合与参与者对账，推进完成已知的激活/回收或执行中止，不得仅凭成员进程存活就推断操作已完成。

## 8. 实现触点与要求

| 文件、符号或边界 | 必需职责 |
| --- | --- |
| `common_include/wavevm_resources.c` | 仅作为控制面注册表的引导导入输入，不得成为长期权威。 |
| `common_include/wavevm_membership_controller.c` 与 `wavevm_membership_control.c` | 将拓扑感知入网证明绑定到经认证传输、不可变成员/修订号证据及受影响拓扑的必需 ACK 集合；将两个管理授权回调绑定至执行器/控制面信任域；对控制器记录深拷贝捕获并与能力及预留证据结合，禁止依据 `NODE`/`ROUTE` 文件构建成员关系。多作用域 Gateway 或宿主机排空须具备显式聚合事务后方可移除。 |
| `common_include/wavevm_control_transport.[ch]` | 将适配器绑定至真实控制面所有者及其经认证流监听生命周期。适配器仅负责传输，不得建立第二成员权威，也不得从包字段、源地址或载荷推断操作者身份。 |
| `common_include/wavevm_control_owner.[ch]` | 嵌入提供持久化成员面与真实认证策略的用户态控制面服务中。远端经认证流可复用同一传输契约，但不得绕过所有者或建立第二成员缓存。 |
| `common_include/wavevm_membership_coordinator.c` | 将协调器接入真实控制面传输及清单/拓扑规划器；在允许生产移除前聚合多个受影响 VM 作用域与宿主机角色排空。 |
| `gateway_service/aggregator.c` | 消费已准备的不可变快照，禁止依据包源地址推断成员关系或原地修改活动路由表充当成员操作。 |
| `master_core/user_backend.c` | 在节点运行时中仅保留本地 Sidecar/派生下一跳状态；路由作用域契约落地后移除全局 Flat 目标假设。 |
| `master_core/kernel_backend.c` | 按 `kernel-accelerator.md` 改造为带版本的每 VM 加速器缓存，不得作为成员事实来源。 |
| `common_include/wavevm_cluster.c` 与 `wavevm_admission.[ch]` | 使用调用方持有的有界成员、Gateway 与准入存储（按实际记录定容），不得继承单一域的 vnode 预算。 |
| 测试脚本 | 依据清单与拓扑记录生成有界测试夹具。 |

单纯的 `DEL_ROUTE` 操作码不能构成成员移除。无论 Gateway 的包控制接口如何设计，移除操作都必须遵守本规范的状态、确认、排空及 VM 依赖规则。

## 9. 兼容性边界

静态 `NODE`/`ROUTE` 输入、学习路由、心跳及历史 Flat 缓存均非生产成员或路由权威。生产环境的成员与路由变更统一通过经认证注册表与已准备/确认的快照契约执行。缺失作用域路由时按故障封闭处理，严禁剥离 VM 标识。

## 10. 验收测试

节点加入、隔离（cordon）、安全排空、路由快照发布以及经验证 Gateway 替换测试构成 Minimum 可用拓扑门控。本节未标注 Extended 的验收项均属于 Minimum（包括 Flat 超过 4096 节点与多 Pod 预算夹具）。故障竞态与多作用域宿主机恢复属于 Extended 加固项，不阻塞首个正确成员生命周期的落地。

- 计算节点在所有必需的路由快照 prepare 确认成功之前，始终保持不可路由且不可调度。
- 控制所有者在接受客户端前发布受保护的本地流；并发客户端收到各自独立关联的强类型结果，单客户端 EOF 仅关闭该客户端，所有者停止时回收全部客户端线程并移除监听器。
- Gateway 加入必须拒绝成环、不完整或单向拓扑链路。
- 活动流量下的快照更新绝不暴露部分填充的路由表，也不改变 VM 命名空间。
- 新激活的计算节点仅影响后续放置；既有 VM 的清单、vCPU 路由、内存放置与 Guest NUMA 视图保持不变。
- 隔离（cordon）阻断新放置，且不中断允许继续运行的既有分配。
- Minimum 拒绝移除仍存在活动 VM 依赖的计算节点。
- Gateway 排空仅在存在经验证备用路径时成功，并维持有界的在途请求行为。
- 尝试移除唯一 Gateway 路径必须失败，不得产生路由黑洞。
- **Extended：** 在后继 prepare 之前、期间与之后杀死待离场 Gateway，路由事务须严格依据持久化的存活者 ACK 集合提交或返回有界失败，绝不等待已离场 Gateway 的 ACK。
- **Extended：** 在每个候选准入阶段并发触发隔离（cordon）、Gateway 排空、健康故障与节点/Gateway 实例变更，任何已失效候选不得进入 `RUNNING`，同时既有已提交分配不被静默重规划。
- **Extended：** 承载空闲计算角色及另一个 VM 的 Gateway 的宿主机，在后继路由生效与前序排空完成前不得移除；宿主机故障须同步将所有托管角色标记为不可用。
- 同一 Gateway 上并行执行 VM A 路由作用域回收与 VM B 路由激活时，即便原始 vnode ID 重叠，双方仍保持各自独立的当前与前序快照。
- **Extended：** 非计划计算节点或 Gateway 故障必须如实产出规范定义的 VM 降级/暂停/失败结果，不得伪报成功。
- **Extended：** 携带过期实例 ID 重新上线的成员不得覆盖更新记录，也不得未经重新校验变为 `ACTIVE`。
- Flat 与 Fractal 夹具保持相同的 VM 命名空间与路由代次语义，同时各叶级路由域维持在其声明的扇出上限之内。
- **Minimum：** 单个 Flat 成员/准入夹具在配备充足独立工作区与路由预算时可突破 4096 规模并编译/使用路由而无需切换层级；多 Pod 夹具总规模突破该值，同时每个 Pod 维持在各自预算内且重叠的本地 vnode ID 彼此区分。两项均须实际执行捕获、准入与路由操作，而非仅构造记录。
- 捕获或 prepare 期间容量耗尽必须明确拒绝，不得产生残缺成员快照、部分路由发布或预留泄漏；稀疏高 ID 仅占用其实际记录空间，并与占用率预算分开校验。

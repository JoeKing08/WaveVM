# WaveVM vCPU 交接规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：QEMU 前端、节点运行时、本地执行运行时、KVM 工作线程与 TCG 辅助 QEMU 进程之间的远端 vCPU 执行。本文档定义所有权、状态导出/导入、交接顺序、重复请求处理、中断与定时器合并、退出语义及故障行为。页栅栏依赖 `memory-consistency.md`，传输封装依赖 `wire-ipc-abi.md`，执行器放置与后端轮廓由已准入清单提供，已验证的本地机制由 `capability-fault-engines.md` 提供。

本规范对 vCPU 变更具有约束力。源码结构体名称或宿主机原生内存布局不构成稳定 ABI；公共上下文与交接记录必须满足下述字段、所有权与编码规则。

## 子系统边界契约

下表索引本子系统的核心归属规则，不重复其详细定义。边界变更须遵循[基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 必选契约 |
| --- | --- |
| 职责与权威 | 源端每 VM/每 vCPU 协调器拥有交接序号与执行所有权；执行器运行已准入执行片；权威 QEMU 拥有设备副作用与中断合并权。 |
| 状态与变更 | 单个 vCPU 执行区间仅有一个执行所有者。导出/导入与结果缓存按实例代次、vCPU、序号与操作键索引；传输或执行器状态不能授予第二个执行区间。 |
| 允许的实现依赖 | 公共内存栅栏、传输/身份/路由、已选能力轮廓、本地执行器及 QEMU 设备接口。禁止直接访问私有目录/控制器状态，禁止直接路由至远端执行器。 |
| 交互与生命周期 | [内存第 4.6 节](memory-consistency.md#46-交接栅栏)负责内存可见性；本文档第 7 节负责设备退出；[生命周期回收](runtime-manifest-lifecycle.md#63-跨子系统资源回收)确保 CPU 对象与完成引用在安全前保持存活。 |
| 并发与成本 | 第 8 节要求细粒度互斥、独立推进、有界工作线程/缓存及 QoS；须显式声明上下文拷贝、回调上下文与交接等待成本。第 8.1 节区分 Minimum 有界 TCG 执行与 Extended 持续客户机运行。 |
| 故障与验证 | 第 6 节与第 11 节要求至多一次执行、结果查询、中断保留及强类型不确定态。超时绝不授权第二个执行区间。 |

## 1. 目标与非目标

目标是使远端执行片具有与本地执行片完全一致的客户机可见语义：单个 vCPU 精确执行一个有序指令区间一次，观测到所需的内存版本与中断状态，返回无歧义的退出原因，且不抹除远端执行期间本地投递的事件。

核心不变量：

```text
For one {vm_id, vm_incarnation, vcpu_index, handoff_sequence},
the guest instruction interval executes at most once.
```

Minimum 轮廓的非目标：

- 同一运行中 VM 内的 KVM 与 TCG 混合跨后端 vCPU 交接。
- 权威 QEMU 前端的在线热迁移。
- 将固定 sleep、定时器信号或 RPC 超时当作语义上的 vCPU 同步边界。
- 通过重新发送可执行请求来重试超时的 `VCPU_RUN`。
- 允许本地执行器成为直接的跨节点 vCPU 通信端点。

## 2. 权威与状态模型

| 状态或决策 | 权威所有者 |
| --- | --- |
| VM 身份、实例代次、所选后端、vCPU 放置与路由作用域 | 不可变的已准入 VM 清单。 |
| 当前 vCPU 交接序号与所有权状态 | 源节点运行时的每 VM vCPU 协调器。 |
| 交接前必需的内存栅栏 | `memory-consistency.md` 与源节点运行时。 |
| 执行机制与导入的 CPU 对象 | 目标端本地执行器。 |
| 客户机设备模型与 MMIO/PIO 权威 | 权威 QEMU 前端。 |
| 跨节点传输 | 节点运行时之间的 Sidecar/Gateway 路由织网。 |

每 vCPU 所有权状态机如下：

```text
LOCAL_OWNED
  -> FENCING_MEMORY
  -> REQUEST_PREPARED
  -> REMOTE_IN_FLIGHT
  -> REMOTE_RUNNING
  -> RETURN_VALIDATING
  -> LOCAL_OWNED

Any state -> FAILED  // 记录到不可恢复的契约错误时
```

仅当前所有者可提交下一次 `VCPU_RUN`。处于 `REMOTE_IN_FLIGHT` 或 `REMOTE_RUNNING` 时，禁止对同一 vCPU 发起另一次可执行交接。目标执行器必须在开始执行前记录该操作，使重复请求返回缓存的完成结果或等待状态，而不会再次执行客户机指令。

## 3. 交接身份与数据模型

语义交接记录如下：

```text
VcpuHandoffRequest {
    protocol_version;
    vm_id;
    vm_incarnation;
    manifest_generation;
    origin_physical_node_id;
    origin_runtime_instance_id;
    vcpu_index;
    handoff_sequence;
    operation_id;
    backend;                 // KVM or TCG
    destination_executor_id;
    reply_destination_kind;
    reply_destination_scope;
    reply_destination_vnode;
    memory_fence_id;
    memory_fence_result;
    local_interrupt_watermark;
    device_event_watermark;
    context_schema_version;
    context_valid_fields;
    exported_cpu_context;
}

VcpuHandoffResult {
    origin_physical_node_id;
    origin_runtime_instance_id;
    operation_id;
    vcpu_index;
    handoff_sequence;
    status;
    exit_class;
    error_gpa_if_any;
    exported_cpu_context;
    produced_memory_fence_or_dirty_reference;
    remote_interrupt_and_device_events;
}

ForwardingMetadata {
    route_snapshot_key;
    delivery_attempt_id;
}
```

`handoff_sequence` 在每个 `{VM incarnation, vCPU}` 维度单调递增，区别于报文 `req_id`、节点 epoch、路由代次或定时器值。语义去重键为 `{vm_id, vm_incarnation, origin_physical_node_id, origin_runtime_instance_id, vcpu_index, handoff_sequence, operation_id}`。`operation_id` 是由源运行时分配的不回绕 128 位值；新运行时实例永不复用前驱实例的身份。

外层 `WVM` 信封承载完整规范交接记录的语义摘要；记录自身另行携带 `exported_cpu_context` 的独立摘要，既避免载荷摘要自引用，又可在不依赖转发元数据的前提下检测上下文篡改。

`ForwardingMetadata` 不参与语义载荷摘要计算。重试必须保持相同的去重键、上下文与语义载荷摘要，但可在 G -> G+1 路由替换后更新路由快照与投递尝试号；重路由绝不能派生出第二个可执行请求。

本地 CPU 请求必须携带上述语义身份及经过校验的后端/上下文描述；仅凭模式标志、原始 slave ID、vCPU 索引与原生上下文联合体不能构成已准入请求。

### 3.1 强类型请求编码

`wavevm_vcpu_handoff` 将请求序列化为显式大端序头部，后接 `context_bytes` 字节的不透明上下文数据。头部固定为 168 字节；所有保留字节必须为零，否则拒绝。

| 偏移 | 字节数 | 字段 |
| --- | --- | --- |
| 0 | 2 | `protocol_version` |
| 2 | 2 | `backend`（`KVM` 或 `TCG`） |
| 4 | 2 | `context_schema_version` |
| 6 | 2 | `memory_fence_result` |
| 8 | 4 | `vm_id` |
| 12 | 4 | `origin_physical_node_id` |
| 16 | 4 | `vcpu_index` |
| 20 | 2 | `reply_destination_kind`（`FLAT_VNODE` 或 `FRACTAL_VNODE`） |
| 22 | 2 | 保留（全零） |
| 24 | 8 | `vm_incarnation` |
| 32 | 8 | `manifest_generation` |
| 40 | 8 | `origin_runtime_instance_id` |
| 48 | 8 | `destination_executor_id` |
| 56 | 8 | `handoff_sequence` |
| 64 | 8 | `memory_fence_id` |
| 72 | 8 | `local_interrupt_watermark` |
| 80 | 8 | `device_event_watermark` |
| 88 | 8 | `reply_destination_scope` |
| 96 | 4 | `reply_destination_vnode` |
| 100 | 4 | 保留（全零） |
| 104 | 16 | `operation_id` |
| 120 | 8 | `context_valid_fields` |
| 128 | 4 | `context_bytes` |
| 132 | 4 | 保留（全零） |
| 136 | 32 | `exported_cpu_context` 的 SHA-256 摘要 |
| 168 | 可变 | `exported_cpu_context` |

请求体重复携带了信封中的不可变操作身份。目标节点运行时必须校验 `vm_id`、实例代次、清单代次、源物理/运行时身份、操作 ID 及目标执行器均与已准入信封严格一致，否则拒绝。执行器接受操作前，`memory_fence_result` 必须为成功。上下文结构版本与有效字段位图为必填项；当前接受的 schema 为 `WVM_VCPU_CONTEXT_SCHEMA_X86`，接收方不得将全零填充字节推断为缺失的 CPU、中断、定时器或设备恢复状态。

请求还携带完整的回包叶 `RouteKey`。该字段属于语义载荷而非可变转发元数据：Flat 目标要求 scope 为零，Fractal 目标要求 scope 非零，未指定 vnode 一律拒绝。目标节点运行时在构造 `VCPU_EXIT` 前，须使用同一份已准入的不可变路由快照解析该精确键，不得从发送方地址、物理节点 ID、历史 `slave_id` 或反向路由查询推断回包路径。

## 4. 上下文契约

导出上下文属于面向统一语义交接的后端特定捕获数据，须附带显式的上下文结构版本与有效字段位图。接收方遇到不支持的 schema 或缺失必选字段时必须拒绝，不得静默清零。

### 4.1 KVM 上下文

KVM 契约至少涵盖以下状态：

- 通用寄存器、调试寄存器、指令指针、标志寄存器以及段/控制状态（包括所选轮廓的 SYSENTER 与 PAT 值）。
- 所选 KVM 能力集所需的 FPU 与扩展状态。
- 客户机 CPUID 表（包含带索引叶标志及每 vCPU 拓扑值）。导入时须先安装 CPUID 表，再设置控制寄存器与挂起事件；执行器不得替换为宿主机 CPU 模型。所选轮廓须被所有已准入 CPU 执行器支持，任何状态未包含在上下文中的特性须在执行前拒绝。
- LAPIC 状态、vCPU 事件、MP 状态及中断注入状态。
- 客户机 TSC、TSC deadline、kernel GS base 及所有必需的时钟/MSR 值。前端按 QEMU CPU 模型状态规则选定额外 MSR 索引；执行器必须导入并导出完全一致的索引集合，拒绝不完整的 KVM MSR 传输，并为每个索引保留对应值。固定的常见 MSR 列表不能替代所选轮廓的完整状态。
- 当 QEMU 设备权威须在下次 KVM 运行前完成上一次退出时所需的挂起 PIO/MMIO 完成数据与退出上下文。
- 退出类别、错误详情及有效字段指示。

`wvm_kvm_context_t` 的导出/导入须通过显式版本化 schema 保留所需的寄存器、sregs、LAPIC、事件、FPU、XCRS、MP、TSC/MSR 与 IO/MMIO 状态；原生 `sizeof(wvm_kvm_context_t)` 原始报文不构成可移植契约。

### 4.2 TCG 上下文

TCG 契约至少涵盖以下状态：

- 通用、控制、调试、段、描述符表及 EFER 状态。
- 通过版本化 xsave 表示传递的 x87/MMX/SSE/AVX/扩展状态。
- LAPIC 状态、中断请求/挂起/注入状态、halted/MP/SIPI 状态、异常状态及（在选用时的）嵌套/拦截字段。
- 相对于显式标识的客户机虚拟时钟 epoch 表示的 TSC 与 APIC 定时器值，而非直接拷贝无关的宿主机/QEMU 时间戳。
- 退出类别与设备完成状态。

`wvm_tcg_context_t` 的导出/导入须通过 schema 版本化与能力协商保留必需状态，不得依赖固定宿主机布局或跨构建的 QEMU 内部假设。

### 4.3 后端兼容性

Minimum 仅支持同构后端配对：

```text
KVM frontend -> KVM local executor
TCG frontend -> TCG local executor/helper QEMU
```

由于内核加速并非执行后端，Mode A 与 Mode B 可独立于上述选择自由组合。后端不匹配属于 VM 启动前的能力校验失败，绝不进行隐式上下文转换。

## 5. 常规交接时序

1. 源节点运行时确认目标 vCPU 处于 `LOCAL_OWNED`、清单为当前有效版本、转发快照已接受，且所选目标支持已准入后端。
2. 源端在排除该 vCPU 其他本地执行所有者的同时捕获所需 CPU 上下文。
3. 完成内存交接栅栏：

   ```text
   capture dirty pages
     -> submit versioned commits
     -> receive required commit acknowledgements
     -> deliver required local corrections
     -> record memory_fence_id = success
   ```

4. 将所有权切换为 `REMOTE_IN_FLIGHT`，分配唯一的操作 ID 与交接序号，并通过本地 Sidecar/Gateway 发送请求。
5. 目标节点运行时在将请求交付本地执行器之前，依次校验源身份、语义操作键/摘要、清单身份、转发快照、后端类型、交接序号及内存栅栏成功状态。
6. 执行器对操作去重，按后端规定的顺序导入上下文，执行直至到达定义的退出点，捕获脏页影响与所需 CPU/设备状态，并在发送回包前记录完成结果。
7. 目标端使用已准入的不可变路由快照解析请求中的显式回包叶 `RouteKey`，携带原操作身份构造强类型 `VCPU_EXIT`，并通过本地 Sidecar/Gateway 边界发送。
8. 源端校验结果身份、序号、后端、上下文 schema 及返回叶 `RouteKey`，在合并返回状态时保留发送水位之后本地到达的事件。
9. 完成所需的返回内存处理，按需在 QEMU 权威侧执行设备/MMIO/PIO 工作，并将 vCPU 状态恢复为 `LOCAL_OWNED`。

网络发送、等待、缺页拉取及设备操作期间均不得持有全局 VM 锁。vCPU 协调器仅在状态切换时锁定该 vCPU 的所有权记录，在进入可能耗时的远端执行区间前即须释放。

## 6. 重复、重试与超时规则

目标端维护一个有界、VM 实例代次作用域的完成缓存，按第 3 节定义的完整语义去重键索引。条目至少保留至最大路由前驱/查询窗口期满；期满后的查询返回 `RESULT_EXPIRED`，绝不授予重新执行许可。

`vcpu_handoff_record_capacity` 是已准入的节点运行时启动计划上限，独立于执行器工作线程并发度，用于限定本地 VM 实例代次的在途与保留完成记录总数。容量耗尽时必须在运行任何客户机指令之前返回强类型背压错误，且不得淘汰路由重试/查询窗口尚未过期的结果。

| 条件 | 必选行为 |
| --- | --- |
| 完成前收到重复请求 | 返回 `IN_PROGRESS` 或进入等待/查询结果，不得执行第二个执行片。 |
| 完成后收到重复请求 | 若身份与载荷摘要匹配，重放缓存的 `VCPU_EXIT` 结果。 |
| 同一操作 ID 携带不同上下文或身份 | 按协议损坏拒绝。 |
| 源端丢失响应 | 查询/等待已记录的完成结果，或走有界结果重放路径。 |
| 首次投递丢失 | 在有界投递窗口内重传完全相同的语义请求；仅在路由刷新后允许更新转发元数据。 |
| 执行超过看门狗时长 | 按执行器记录状态将操作标为不确定/进行中；绝不发送第二次可执行请求。 |
| 持久化完成前目标/进程故障 | 返回失败/降级的 vCPU 操作；恢复须依赖另行规范化的 VM 故障策略。 |

`IN_PROGRESS`、`BACKPRESSURE`、`STALE` 与 `RESULT_EXPIRED` 属于强类型非退出状态：退出类别固定为 `NONE`，且不携带 CPU 上下文、内存栅栏结果或事件水位。`EXECUTOR_FAILURE` 对应 `EXECUTOR_ERROR`，`MEMORY_FAILURE` 对应 `MEMORY_ERROR`。

超时与重试窗口仅用于界定活性边界；除非目标端完成缓存严格执行上述去重契约，否则重复 UDP 发送在语义上并不安全。

## 7. 退出与设备中断时间语义

`VCPU_EXIT` 必须报告明确的强类型退出类别：

| 退出类别 | 必选所有者与处理动作 |
| --- | --- |
| `BUDGET` / 协作抢占 | 返回 CPU 上下文；源端可调度下一次交接。 |
| `HALTED` / 等待事件 | 保留 halted 与定时器/APIC 状态；源端不得为推进测试而强行置为可运行。 |
| `PIO` / `MMIO` | 由权威 QEMU 前端执行设备动作并记录完成数据，之后才允许继续执行。 |
| `INTERRUPT` / IPI / 定时器 | 按水位与后端特定状态合并，不得抹除发送后本地到达的中断。 |
| `EXCEPTION` / 关机 / 复位 | 返回精确的架构状态并映射到权威 QEMU 生命周期。 |
| `MEMORY_ERROR` | 附带受影响的 GPA 与状态；源端须先完成一致性恢复，再启动依赖它的下一个执行区间。 |
| `EXECUTOR_ERROR` | 返回强类型非成功状态，禁止伪造 CPU 完成结果。 |

回包信封保留原请求的 VM/实例代次、清单代次、源运行时身份、操作 ID、路由快照键及语义结果载荷，并新生成可变的投递尝试号与路由跳数状态。其路由叶必须等于请求中的显式回包 `RouteKey`，初始跳数为零，跳数上限由当前活跃快照解析且非零。

定时器与 TSC 属于客户机架构状态。KVM 使用所选 MSR/LAPIC 机制，TCG 则相对于其虚拟时钟 epoch 转换数值。现有实现中的固定 sleep、宿主机挂钟截止时间或信号仅可作为看门狗/逃生阀，不能定义客户机的逻辑交接边界或替代导出定时器状态。

INIT/SIPI、LAPIC、IPI、NMI 及本地中断排序需要显式合并策略。源端在交接前记录本地中断水位，导入结果时按后端规则将返回状态与该水位之后本地投递的事件合并，绝不得重放过期的 INIT/SIPI 位导致已初始化的 AP 被重启。

## 8. 并发与背压

- 所有权互斥粒度为每 `{VM, incarnation, vCPU}`，禁止使用全局执行锁。
- 当内存栅栏、已准入资源与执行器队列允许时，独立 vCPU 必须支持并发交接与推进。第 8.1 节的 Minimum 有界执行门禁与 Extended 持续客户机门禁仅区分验证工作负载范围，均不允许采用全局所有权锁。
- 本地执行器管理器维护有界工作队列并报告显式过载，不得静默丢弃 vCPU 请求或使其陷入无界等待。
- `VCPU_RUN`、`VCPU_EXIT`、必需的内存栅栏确认与设备完成流量保持快速 QoS 优先级。
- 允许短时的本地同步操作用于所有权转移或有界背压，但不得永久串行化全部客户机 vCPU。
- 完成缓存淘汰策略须至少将条目保留至源端声明的重试/查询窗口期满，否则必须返回明确的 `RESULT_EXPIRED` 错误。
- 须显式声明每次交接的拷贝、队列、IPC/网络跳数及阻塞开销；上下文导出/导入与每 vCPU 所有权切换不得持有会阻塞无关 vCPU 或 VM 推进的锁。

### 8.1 同机一致 SHM 并发 TCG 与有界 `force_local`

本小节遵循架构基线第 16 节，将 **Minimum** TCG 执行契约测试与 **Extended** 可用分布式多 vCPU TCG 客户机验收加以区分。Minimum 不要求 TCG 客户机操作系统完成启动或登录/SSH，但仍要求真实的有界指令执行，以及共享的 CPU、内存、设备、身份与生命周期语义。

#### Minimum 执行契约验收

- 绑定清单的远端 TCG 在 Flat 与 Fractal 测试中执行真实指令，并返回经校验的 CPU 状态与内存结果；KVM、桩实现或全本地替代方案不能充当远端 TCG 执行器。
- 独立 vCPU 在有界测试中以每 vCPU 所有权推进；栅栏、中断、设备权威退出及原子步骤退出须遵守本规范契约。失败操作返回有界强类型错误，而非携带错误状态的成功结果。
- 远端读、写/提交、过期版本重同步、队列承压与 STOP 均通过显式字节/版本/所有权结果校验。本地共享 RAM 优化须证明实际参与方共享同一底层后备内存。
- 若启用 `force_local`，下文规定的每 vCPU 作用域、30 s / 90 s / 25 s 边界、设备回弹及排序规则同样作为 Minimum 可测约束。持续客户机运行及其远端/本地执行比例由 Extended 客户机门禁验证，而不以契约测试中的登录为前提。

本小节其余客户机可用性要求归属 Extended 范围，用于维护既定的并发常规路径；延后验收不意味着允许永久全局串行化或削弱 TCG 语义校验。

**契约意图**

- 并发多 vCPU 推进（BSP 本地 + AP 远端，以及在放置允许时的多远端并行）是**主常规路径**。
- 基线第 15 节定义的有界本地同步回退（`force_local`）**仅**作为面向 softlock / IPI / NEED_LOCAL 窗口的例外性、每 vCPU、挂钟有界兜底，**不是**常规执行模式，且绝不能主导日常客户机进度。
- 契约要求可用的客户机可见多 vCPU 并发正确性，**不**要求达到完整上游 QEMU 进程内 MTTCG 性能、调度优化或辅助线程 MTTCG 对等能力。
- 故障注入、协调器高可用（HA）、热迁移、自动重分片、透明恢复及完整可插拔缺页引擎均**不在**本小节 TCG 客户机验收范围内，既非 Minimum 契约测试的前置条件，也非本 Extended 客户机门禁的前置条件。

可彻底消除该回退需求的跨进程/完整上游 MTTCG 仍属延后架构工作（见基线第 16 节延后清单）。

#### 角色定位

`force_local` 是并发 SHM TCG 路径上对基线第 15 节有界本地同步回退的具名 Minimum 实现。其契约职责是在远端 AP 执行片无法像原生 MTTCG 那样与本地 BSP 细粒度交错执行时，保障 stop_machine / text_poke / softlock 类 IPI 窗口的客户机正确性，并承接 NEED_LOCAL 设备权威回弹。它严禁：

- 将并发常规路径静默替换为全部 vCPU 的永久全局串行化；
- 在健康客户机推进下成为常规统计的主体（远端并发执行片须保持为主路径）；
- 被等同宣称为完整上游 MTTCG 等价或性能对等；
- 演变为无界或贯穿整个启动周期的粘性本地保持。

#### 并发路径选择

当同机客户机 RAM 为一致 SHM 时，已准入的**主路径**为并发 BSP 本地 + AP 远端 TCG。配置项 `WVM_TCG_SHM_CONCURRENT=0` 用于显式切换至 stop-the-world（非并发）调度。该开关属于正式契约接口：两种模式均须遵守内存与交接契约，而仅并发模式需要提供下述 `force_local` 回退，以在并发主路径之上覆盖 softlock/IPI 例外窗口。

#### 触发条件

在以下任一条件成立时，前端可为单个 vCPU 武装（arm）`force_local`：

1. **自旋 / softlock 信号**：远端 AP 在与本地 BSP 并发运行期间反复在相同客户机 RIP（或等价的高自旋信号）上结束执行片，表明出现需要本地交错执行的 softlock 类等待。
2. **NEED_LOCAL 设备回弹**：远端 TCG 辅助进程返回强类型 `NEED_LOCAL` / 设备权威退出（MMIO/PIO 或等价退出），须在权威 QEMU 前端完成；源端武装 `force_local`，使下一区间在本地穿过该回弹窗口。

武装作用域限定为单个 `{vm_incarnation, vcpu_index}`，不得全局锁定其他 vCPU。在无客户机可见 softlock/IPI 需求的情况下，禁止通过持续重武装把主路径退化为纯本地执行。

#### 时间边界（挂钟时间）

并发路径下武装 `force_local` 后，须遵守以下挂钟边界：

| 参数 | 契约值 | 含义 |
| --- | --- | --- |
| 单次保持片（Hold slice） | 30 s | 武装或续期后的本地保持窗口。 |
| 硬上限（Hard cap） | 90 s | 自本次事件首次武装起的最大连续保持时长。 |
| 重武装冷却（Re-arm cooldown） | 25 s | 硬上限到期（或等价清除）后，在冷却期届满前抑制自旋触发的重武装。 |

续期规则：

- 保持生效期间，若已武装的 RIP 仍停滞或自旋信号保持高位，前端可在硬上限内续期保持片。
- 当自旋信号仍处高位时，仅 RIP 轻微抖动不得提前清除活跃的 softlock 保持。
- 触达硬上限后，清除保持、重置该次事件的自旋状态并进入冷却期；此后按常规放置与冷却规则恢复远端执行。

非 softlock 保持的设备回弹武装同样须消耗有界本地预算，并在客户机取得进展（RIP 变化 / 本地成功完成）时清除，不得演变为粘性保持。

#### 禁用回退配置

`WVM_TCG_DISABLE_FORCE_LOCAL=1` 禁用 `force_local` 武装及耦合的 NEED_LOCAL 设备回弹路径。在该配置下，并发路径不再提供本小节针对上述 softlock/IPI 窗口的正确性覆盖，依赖该覆盖的客户机因此无法满足本规范的并发路径验收标准。禁用回退须作为显式契约选择，不得作为静默生产默认项。

#### 排序与内存耦合

`force_local` 仅改变下一区间的执行位置（本地 vs 远端），不放宽以下任何规则：

- 每 vCPU 所有权互斥；
- `VCPU_RUN` 之前必需的内存栅栏；
- 导入时的中断水位合并；
- QEMU 设备权威对 PIO/MMIO 完成的所有权。

QEMU `EXCP_ATOMIC` 是进程局部机制：辅助进程不得自行调用 `cpu_exec_step_atomic()` 并假设前端或其他辅助进程已暂停。远端 TCG 辅助进程须在未执行的指令处返回原子步骤必需退出；前端阻断新的远端执行片、排空在途执行片，并在本地执行原生 QEMU 原子步骤后再恢复远端执行片。普通 TCG 执行片保持并发。

处于 `force_local` 下的本地区间在后续重新交接时，仍须经由常规 `VCPU_EXIT` / 导入路径返回。

#### Extended 客户机验收证据（要求形态）

Extended TCG 客户机验收证据必须呈现以下形态（带日期的通过/失败统计归入持久计划或验证记录，不写入本规范）：

1. **客户机登录**：多 vCPU 一致 SHM TCG 客户机在并发主路径下达到登录（或等价交互就绪）。
2. **CPU 压力**：客户机内多 vCPU 工作取得可见推进（至少准入并使用 >= 2 个 vCPU）。
3. **远端 vCPU 与远端内存活动证据**：并发路径下可观测到远端执行片与远端内存推进，且远端并发执行是主路径，而非被 `force_local` 主导下的象征性零星调用。
4. **干净停止（STOP）**：停机完成且无归属于该次运行的 vCPU 所有权、SHM 或执行器租约泄漏。
5. **回退边界验证**：回退触发时，`force_local` 的武装/续期/硬上限到期/冷却严格遵守挂钟边界（单次 30 s、硬上限 90 s、冷却 25 s）；NEED_LOCAL 设备退出回弹至权威 QEMU 前端且仅对受影响 vCPU 武装本地执行。
6. **显式禁用语义**：禁用回退配置（`WVM_TCG_DISABLE_FORCE_LOCAL=1`）须显式启用，且在该配置下不宣称并发路径覆盖 softlock/IPI 窗口。
7. **范围声明清晰**：不得因存在 `force_local` 或并发路径通过上述验收，而宣称达到完整上游 QEMU MTTCG 性能或等价能力。

本 Extended TCG 客户机验收形态**不**要求故障注入矩阵、协调器 HA、热迁移、自动重分片、透明恢复或完整可插拔缺页引擎。

带日期的运行结果、客户机镜像通过/失败统计及审计裁决 ID 归档于持久计划或验证记录，不置于本规范中。

## 9. 实现触点与要求

| 文件、符号或边界 | 必选职责 |
| --- | --- |
| `wavevm-qemu/.../wavevm-cpu.c` | 将捕获/导入绑定至显式交接序号、栅栏结果、事件水位与版本化上下文 schema；实现第 8.1 节并发 SHM 选择与有界 `force_local` / NEED_LOCAL 回退。 |
| `master_core/main_wrapper.c` | 节点运行时校验清单/路由代次，维护每 vCPU 所有权与关联关系。 |
| `master_core/logic_core.c` | 解耦投递重试与执行完成，采用去重结果查询/重放模型。 |
| `slave_daemon/slave_hybrid.c` | 将缓存键与生命周期限定在 VM 实例代次内，暴露强类型 `IN_PROGRESS`/完成状态。 |
| `wavevm-qemu/.../wavevm-all.c` | 保留必需的设备/IRQ 语义，不将串行执行固化为通用常规路径。 |
| `common_include/wavevm_protocol.h` | 定义版本化字段映射与能力协商机制。 |

## 10. 兼容性边界

生产环境不支持截断的请求 ID、无类型上下文传输或独立部署的 master/slave 直连路径。所有交接与完成操作均须使用完整的 VM 作用域语义键与强类型本地执行器 ABI；参与方遇到不支持的上下文 schema 必须直接拒绝，不得猜测或隐式转换。

## 11. 验收测试

- 重复 `VCPU_RUN` 仅执行一次客户机区间，并返回同一缓存结果。
- 执行开始后的丢包不能针对同一交接序号触发第二次 `KVM_RUN` 或 TCG 执行片。
- 丢失 `VCPU_EXIT` 同时发生路由代次替换时，结果查询与重路由保持同一语义键，且仅执行一个执行片。
- 内存栅栏失败将阻止 `VCPU_RUN` 发送。
- KVM 与 TCG 在跨远端执行片时完整保留必需的寄存器、段、扩展状态、LAPIC、定时器/TSC、MP、中断及 halted 状态。
- 远端执行期间本地投递的中断在结果导入后得以保留。
- PIO/MMIO 完成由 QEMU 设备权威执行，并精确向下一个执行区间提供一次完成数据。
- 后端不匹配在准入/能力协商阶段即被拒绝。
- 相互独立的 vCPU 可在无全局交接锁的情况下并发推进。
- 执行器过载与完成缓存过期产生有界强类型错误，不会返回伪成功或陷入无限重试循环。
- **Minimum**：TCG 满足第 8.1 节有界执行契约验收，涵盖真实远端指令执行、独立 vCPU 推进、已校验的内存/上下文结果、有界回退/错误行为及 STOP；TCG 客户机操作系统登录/SSH 不属于本门禁。
- **Extended**：同机一致 SHM 并发 TCG 满足第 8.1 节客户机验收形态：并发主路径下完成客户机登录、CPU 压测、远端 vCPU/内存实证及 STOP（>= 2 vCPU）；`force_local` 保持为例外有界回退（武装/续期/硬上限/冷却）；NEED_LOCAL 回弹限于单 vCPU；禁用回退为显式选择并撤回 softlock/IPI 覆盖声明；本门禁不要求完整上游 QEMU MTTCG 性能及 Extended 故障/HA/迁移能力。

# WaveVM 内核加速器规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：可选的 `wavevm.ko` / `/dev/wavevm` 加速器、按 VM 隔离的内核上下文、IOCTL 与 mmap 边界、上下文生命周期、缓存发布、并发控制、故障行为，以及从当前全局模块状态的迁移。用户态节点运行时始终是语义权威；内存、vCPU、身份、清单与能力语义由各自对应的规范定义。

本规范对所有新的 Mode A 实现具有规范效力。它定义的是规范 Mode B 语义的本地加速器，而非第二套分布式控制面。

## 子系统边界契约

本摘要仅索引各归属规则，不重复其完整定义。涉及边界变更时，适用[架构基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 必需契约 |
| --- | --- |
| 职责与权威 | 仅加速经授权的节点运行时操作；用户态保留 VM、路由、一致性、放置与生命周期语义权威。 |
| 状态与变更 | 每个 VM 上下文拥有自身的映射、请求与派生缓存。IOCTL、mmap 与异步工作访问均须验证已挂载身份、权限及有效引用；共享工作线程上的任务须携带显式上下文标签。 |
| 允许的实现依赖 | 公共内核/用户态 ABI 记录、已准入清单/配置投影及本地 OS 数据面原语；不得依赖私有控制面状态或建立第二套逻辑权威。 |
| 交互与生命周期 | 挂载、发布与引用安全由第 3、4、7 节规范。上下文释放遵循[生命周期资源回收](runtime-manifest-lifecycle.md#63-跨子系统资源回收)，涵盖延迟 TX、VMA 与完成回调。 |
| 并发与成本 | 第 6 节要求按上下文独立推进、有界队列/公平性以及显式阻塞与锁序约束。须明确拷贝、唤醒与模式切换成本；全局基础设施不得串行化无关 VM 的执行。 |
| 故障与验证 | 第 1.2、7、10 节规范如实的能力通告、故障传播及多 VM 准入前的真实双上下文隔离验证。 |

## 1. 目标与非目标

本规范的目标是在内核模块可用时加速选定的本地数据面操作，同时不改变 VM 身份、路由权威、页版本规则、vCPU 交接语义、生命周期归属或错误含义：

```text
candidate/admitted user-space manifest + capability profile（候选/准入用户态清单与能力画像）
  -> explicit wvm_kernel_ctx create/attach（显式创建/挂载 wvm_kernel_ctx）
  -> manifest-derived cache/configuration prepare（准备由清单派生的缓存与配置）
  -> optional local acceleration（可选本地加速）
  -> typed completion through the same node-runtime contract（经统一节点运行时契约返回类型化完成结果）
```

因此，Mode A 的定义为：

```text
Mode B 规范运行时 + 可选的按 VM 内核加速
```

### 1.1 发布优先级

按 VM 隔离的上下文是 Minimum 可用系统的强制准入门槛。当内核模块或宿主机无法提供该隔离能力时，节点可拒绝 Mode A，但严禁在状态、请求 ID、映射、路由缓存或清理逻辑仍为全局单例所有时通告多 VM Mode A 能力。

本规范也涵盖了后续加固工作（如完整缺页路径迁移与详尽工作线程故障测试），这些改进用于增强加速器，但绝不将无模块 Mode B 基线降格为次等路径。

### 1.2 上下文隔离准入门槛

多 VM Mode A 要求在可睡眠路径上明确上下文归属、明确提交器发送所有权、保障 TX/VMA/销毁阶段的引用安全，并保留完整的 u32 VM 身份。在提高对外通告的上下文数量上限之前，实现必须满足以下全部条件：

- `IOCTL_WVM_QUERY_CAPS` 须上报受支持的上下文 ABI 与能力位。在多上下文隔离通过验证前，仅可通告 `WVM_KERNEL_CAP_CONTEXT_BIND` 与 `WVM_KERNEL_CAP_SINGLE_CONTEXT`，且 `max_concurrent_contexts = 1`。BIND 必须对超限请求返回 `-ENOSPC`，准入层须拒绝该节点上的第二个 Mode A VM。
- `IOCTL_WVM_BIND_CONTEXT` / `IOCTL_WVM_UNBIND_CONTEXT` 须将打开的 `/dev/wavevm` 文件描述符绑定至清单身份（包含 `node_instance_id`）、VM 实例代次、清单代次、能力画像及激活栅栏。
- 同一 VM 下受清单门控的节点运行时、QEMU 前端与 KVM 执行器文件描述符，在使用加速器前必须绑定至同一已准入上下文。
- 每个内核上下文须独立拥有身份信息、epoch 缓存、RAM 槽位、私有 `address_space`/映射、IRQ 等待状态、请求 ID 池与完成表、页元数据基数树（radix tree）、`dir_table` 及 `route_context`。目录与路由状态均为用户态权威之下的派生加速缓存。禁止使用模块全局 VM 身份及 RX 遗留 VM 回退；缺少正确上下文时，目录/路由访问器必须闭环失败。
- VMA 缺页与写保护回调须从所映射文件解析上下文；异步失效/脏页提交任务及 TX 槽位须持有显式上下文引用。身份编码必须无截断地保留完整 u32 VM ID。
- 模块级 UDP socket 与 TX 环仅在严格执行引用生命周期与请求命名空间隔离时，方可作为共享传输底层。脏页提交队列与 GPA 分片锁必须按上下文隔离。`IOCTL_SET_VM_ID` 须返回 `-EOPNOTSUPP` 予以拒绝；BIND 是唯一的生产级上下文挂载边界，禁止通过逐字段注入绕过。

在通告多上下文能力之前，必须通过同 GPA、多 FD、异步清理及故障注入测试验证上述不变量。仅凭桩化的 CREATE 到 RUNNING/READY 流程不能替代 Minimum 阶段的 KVM 客户机登录/SSH、TCG 执行契约测试或远端资源验收标准。完整 TCG 客户机验收属于 Extended 范围，其延后不削弱上下文隔离要求。

Minimum 非目标：

- 要求正确的 Mode B VM 依赖内核模块、root 权限或定制内核。
- 将模块全局 socket、VM ID、路由表、映射或请求表作为所有 VM 的权威状态。
- 允许内核代码分配 VM 身份、决定放置、准入成员、创建路由或主导 VM 生命周期转换。
- 允许内核直接向任意远端执行器发包，绕过本地/远端节点运行时及 Sidecar/Gateway 路由织网。
- 每次 `open("/dev/wavevm")` 自动创建新的语义 VM 上下文。
- 用全局同步内核调用取代正常的异步队列、批处理、QoS 与有界背压。

## 2. 权威与能力边界

| 状态或决策 | 权威所有者 | 内核角色 |
| --- | --- | --- |
| VM ID、实例代次、清单摘要/代次、激活栅栏、生命周期 | 用户态控制面与已准入清单 | 校验并缓存一份已接受的快照。 |
| 路由拓扑与下一跳 | 控制面路由快照 | 仅缓存并使用一份完整的派生快照。 |
| 页目录、版本、副本集与提交结果 | 用户态节点运行时/目录 | 仅加速本地捕获、失效与唤醒。 |
| vCPU 所有权、交接序号、上下文 schema | 用户态节点运行时/QEMU 契约 | 可选加速本地上下文传输与运行机制。 |
| KVM 对象与 TCG 辅助进程生命周期 | 本地执行器/QEMU | 不得建立第二套执行器权威。 |
| 内核上下文句柄及其引用 | 内核模块 | 为已挂载本地调用方强制执行隔离与生命周期安全。 |

`capability-fault-engines.md` 中定义的能力报告是选择 Mode A 的唯一依据；模块已加载并不意味着自动可选。能力报告必须包含加速器 ABI 版本、支持的上下文 schema 版本、按 VM 上下文能力、特性位、资源上限以及当前模块/设备实例身份。

## 3. 按 VM 隔离的上下文模型

### 3.1 上下文身份

每个 `wvm_kernel_ctx` 精确对应唯一一组 `{vm_id, vm_incarnation, physical_node_id}` 的内核加速状态。它基于已准备的按节点运行时清单显式创建，并拥有内核签发的不透明上下文句柄及挂载能力凭据（attach capability）。挂载能力凭据不得使用原始 `vm_id` 或用户自选整数。

```text
wvm_kernel_ctx {
    context_handle;
    attach_capability;
    refcount;
    state;

    vm_id;
    vm_incarnation;
    admission_tx_id;
    eligibility_fence_digest;
    activation_fence;
    physical_node_id;
    expected_node_instance_id;
    manifest_digest;
    manifest_generation;
    capability_profile_digest;
    route_snapshot_key;

    immutable_config_snapshot;
    ram_mapping_registry;
    page_or_dirty_acceleration_state;
    vcpu_acceleration_state;
    request_and_completion_state;
    local_sidecar_transport_binding;
    workqueues_and_pending_operations;
    attached_fd_and_role_records;
}
```

所有 mmap、绑定上下文的 IOCTL、页/脏页回调、等待队列及工作项都必须先解析出活跃上下文。任何无法证明上下文隔离的请求、路由、页元数据、socket 或共享队列路径，均禁止按第 1.2 节通告多上下文能力。

### 3.2 上下文状态机

| 状态 | 含义 | 允许的下一状态 |
| --- | --- | --- |
| `NEW` | 已分配，尚未接受清单快照。 | `PREPARING`、`DEAD` |
| `PREPARING` | 正在校验候选清单、能力与配置。 | `PREPARED`、`QUIESCING`、`DEAD` |
| `PREPARED` | 候选快照与本地资源就绪；尚无客户机流量，若未激活可过期回收。 | `ACTIVE`、`QUIESCING`、`DEAD` |
| `ACTIVE` | 匹配的激活栅栏将候选提升为活跃态，允许接受清单绑定的加速操作。 | `QUIESCING`、`FAILED` |
| `QUIESCING` | 拒绝新任务；排空归属任务或返回类型化失败。 | `DETACHING`、`FAILED` |
| `DETACHING` | 在确认无新任务进入后解绑映射与文件描述符。 | `DEAD` |
| `FAILED` | 加速器无法安全继续运行。 | `QUIESCING`、`DEAD` |
| `DEAD` | 上下文已取消发布，最终引用释放。 | 无 |

关闭单个文件描述符仅移除该次挂载及其引用，只要其他经授权的 QEMU、节点运行时、执行器或控制面描述符仍存在，就不得销毁上下文。`QUIESCING` 与销毁流程由生命周期协调器在 VM 清理阶段发起，而非由最先关闭的进程触发。

### 3.3 挂载与权限模型

`CREATE_CTX` 仅对本地清单/生命周期权威或显式委派的本地控制端点开放。它在返回句柄前须校验已准备清单、预期节点实例、资格栅栏摘要、加速器能力画像、已准备资源预留租约以及节点角色分配。

`ATTACH_CTX` 须同时满足以下全部条件：

- 提供有效的不透明上下文句柄与挂载能力凭据。
- 清单摘要/代次与 VM 实例代次完全匹配。
- 调用方角色受按节点清单允许（例如 QEMU 前端、节点运行时或指定本地执行器）。
- 通过部署定义的本地凭据/对端校验；当存在无关本地进程可能尝试挂载时，仅靠文件系统权限位不足以保证安全。

具体凭据传递机制可采用受保护的本地控制 socket、继承的密封描述符或其他显式本地通道，严禁使用硬编码共享令牌或写入全局原始 `vm_id`。

## 4. IOCTL 与 mmap ABI

当前数值型 IOCTL 定义不作为生产配置 ABI。上下文 ABI 统一采用 `wire-ipc-abi.md` 定义的类型化信封；每个请求须包含上下文句柄、清单身份、操作 ID、载荷长度、标志位与类型化结果状态。

### 4.1 必需 ABI 分组

| 分组 | 操作 | 必需语义 |
| --- | --- | --- |
| 能力发现 | `GET_CAPS`、`GET_ABI_VERSION` | 只读；返回模块/设备实例与能力上限。 |
| 上下文生命周期 | `CREATE_CTX`、`ATTACH_CTX`、`DETACH_CTX`、`QUIESCE_CTX`、`DESTROY_CTX` | 显式状态转换与引用计数规则。 |
| 配置管理 | `PREPARE_MANIFEST`、`COMMIT_CONFIG`、`QUERY_CONFIG` | 接受完整的清单派生快照，禁止注入独立事实源。 |
| RAM 与映射 | `REGISTER_RAM`、`UNREGISTER_RAM`、`QUERY_MAPPING` | 仅注册清单授权的 QEMU RAM 区间及归属元数据。 |
| 加速操作 | `CAPTURE_DIRTY`、`FAST_INVALIDATE`、`REMOTE_RUN`、`WAIT_IRQ`、`FAST_LOCAL_FORWARD` | 绑定单个上下文、请求与栅栏的类型化加速操作。 |
| 诊断 | `QUERY_OPERATION`、`QUERY_STATS`、`FAULT_INJECT_TEST_ONLY` | 有界可观测性；故障注入受构建/测试门控，不得影响生产语义。 |

`PREPARE_MANIFEST` 校验完整的候选身份/能力/配置快照，但尚不将其用于客户机流量。`COMMIT_CONFIG` 要求携带生命周期激活栅栏，并在用户态激活后原子发布唯一不可变快照。逐字段调用 `SET_VM_ID`、`SET_ROUTE`、`SET_GATEWAY`、`SET_MEM_LAYOUT` 或 epoch 写入的方式不得作为新的生产配置路径。

### 4.2 遗留 IOCTL 分类

| 现有遗留 IOCTL 族 | 迁移定位 |
| --- | --- |
| `IOCTL_WVM_REMOTE_RUN` | 绑定上下文的已校验 vCPU 交接加速，不构成独立远端执行协议。 |
| `IOCTL_SET_MEM_LAYOUT` | 若保留暴露，仅限绑定上下文且经清单授权的 RAM 注册，不提供未绑定遗留适配器。 |
| `IOCTL_WAIT_IRQ` | 绑定上下文的本地中断等待/通知，带类型化超时与错误结果。 |
| VM ID、epoch、路由、放置、网关 setter | 废弃的逐字段注入接口，替换为完整的派生清单/路由快照 prepare/commit。 |
| `IOCTL_RPC_SYNC_ACK` | 在稳定 ABI 暴露前予以移除或明确归属与类型定义；未处理的数值命令不构成语义特性。 |

任何 IOCTL 均不得为非零 VM 流量接收裸路由目标并反推身份。所有路由目标必须保留 `identity-routing.md` 定义的 VM 与实例代次作用域。

### 4.3 mmap 规则

mmap 仅对已挂载上下文且经清单授权的 RAM 或显式加速器缓冲区有效。映射注册表记录如下信息：

```text
MappingRecord {
    context_handle;
    manifest_digest;
    gpa_range;
    qemu_ramblock_identity;
    host_mapping_identity;
    access_permissions;
    mapping_generation;
    attached_vma_reference;
}
```

模块须拒绝属于其他 VM 上下文或过期清单的重叠映射。VMA 关闭时仅递减对应映射与上下文的引用计数。清理流程须先阻断新映射与新操作进入，再排空现有引用、失效并注销区间，最后释放上下文内存。过期的用户态映射绝不能解析到复用相同原始 ID 的新建 VM 上。

## 5. 数据面规则

### 5.1 内存与脏页加速

内核仅在操作显式指定有效上下文、页/区间、操作 ID 及所需内存栅栏时，方可执行脏页区间捕获、本地缓存/映射失效或本地等待者唤醒。内核严禁：

- 在用户态目录记录 `memory-consistency.md` 要求的幂等结果前，提前宣告内存提交成功。
- 将来自其他 VM/上下文的页面字节装入当前上下文。
- 在清单、实例代次或配置代次失效后继续保留页缓存或路由缓存。
- 将脏页捕获失败转换为空的成功脏页日志。

KVM Mode A 同样禁止使用宿主机 `PROT_NONE` 作为客户机 RAM 访问陷阱。内核脏页捕获仅是加速提供者，不改变 KVM 的页重同步语义。

### 5.2 vCPU 与中断加速

`REMOTE_RUN` 仅接受经节点运行时校验、携带当前 `{vm_incarnation, vcpu_index, handoff_sequence, operation_id}` 且已完成内存栅栏的交接请求。内核返回唯一的类型化完成结果或“执行中/结果可查询”状态；发生应答丢失时，严禁重复执行同一次交接。

`WAIT_IRQ` 与唤醒仅为本地加速原语。QEMU 仍是客户机中断与设备权威，节点运行时负责投递身份、水位线与跨节点传输。内核唤醒本身并不等同于客户机 IRQ 已注入或远端设备操作已完成。

### 5.3 Sidecar/Gateway 边界

所有生产跨节点流量仍严格遵循统一路径：

```text
local QEMU/executor -> local node runtime -> local sidecar -> gateway fabric
                    -> remote sidecar -> remote node runtime -> executor
```

可选的 `FAST_PACKET_TX` 或 `FAST_LOCAL_FORWARD` 仅接受完整且已经节点运行时校验的信封，并仅能经由清单绑定的本地 Sidecar 传输绑定进行投递。它不得自行选择远端执行器、创建路由、剥离 VM 身份、绕过远端节点运行时，或将单个内核 socket 变成全局路由事实源。

## 6. 并发、锁序与背压

实现必须使用按上下文隔离的队列与引用。仅当每个入队任务都持有有效上下文引用且不会混淆请求命名空间时，方可使用模块级共享工作线程。

同时需要多把锁时，必须严格遵循以下加锁顺序：

```text
context registry lock（上下文注册表锁）
  -> context lifecycle lock（上下文生命周期锁）
  -> immutable configuration publication/read lock（不可变配置发布/读锁）
  -> mapping registry lock（映射注册表锁）
  -> per-vCPU / per-page / per-request lock（按 vCPU / 页 / 请求锁）
```

注册表锁仅用于查找与发布。网络发送、QEMU 回调、用户态等待、可能阻塞的内存分配以及工作队列刷新，都必须在释放会阻塞上下文清理或其他 VM 独立执行的锁之后进行。

- 在获取长生命周期操作引用前后，均须检查上下文状态。
- 按页锁与按 vCPU 锁绝不可退化为模块全局 VM 锁。
- 所有队列均须具备明确上限与 QoS 策略。过载时应返回类型化背压结果或在安全边界暂停受影响操作，严禁丢弃 vCPU、脏页、IRQ 或内存完成任务。
- 配置与路由快照替换须按上下文使用单一完整不可变对象；读者只能看到完整的旧快照或完整的新快照，绝不会读到逐字段混合状态。
- 必须实现上下文间独立推进与有界的共享工作线程公平性；若未消除全局执行或等待瓶颈，仅增加按上下文数据结构并不构成真正的并行加速。队列、拷贝、唤醒与上下文切换成本须显式量化，并在相同宿主机条件下与等价 Mode B 契约负载对比验证。

上下文清理须参与[生命周期资源回收](runtime-manifest-lifecycle.md#63-跨子系统资源回收)；本地引用计数是对其中操作栅栏与迟到完成处理的补充，而非替代。

## 7. 故障、清理与回退

| 故障条件 | 必需行为 |
| --- | --- |
| 准入前模块缺失或不可用 | `PREFER` 在满足条件时解析为 Mode B；`REQUIRE_KERNEL_ACCEL` 在启动前拒绝。 |
| 创建/挂载/配置校验失败 | 拒绝本地生命周期准备，不得遗留部分配置的全局状态。 |
| 资格栅栏或激活栅栏不匹配 | 拒绝准备态或活跃态操作；内核上下文不得基于监听器或进程存活自行提升状态。 |
| 上下文工作线程失败或设备消失 | 将上下文标记为 `FAILED`，拒绝新加速操作，并向用户态生命周期上报类型化状态。 |
| 某个已挂载进程退出 | 仅释放其角色与 FD 引用，在其他引用或生命周期仍需要时保留上下文。 |
| 静默超时 | 返回未决操作身份与状态；在仍有任务可能引用期间，不得释放映射或复用上下文身份。 |
| 上下文销毁 | 须经生命周期清理、确认无活跃映射与操作引用，并从注册表完全移除后再释放内存。 |
| 路由/配置代次不匹配 | 拒绝该操作并请求用户态刷新，严禁借用相近或全局缓存条目。 |

VM 启动运行后发生 Mode A 故障时，不得在未定义状态下继续执行。Minimum 阶段须依据内存与 vCPU 契约暂停或失败受影响 VM。未来若支持热回退至 Mode B，必须通过经静默且清单校验的转换流程，证明不存在脏页、交接或中断状态丢失。

能力探测与准入必须严格执行第 1.2 节的隔离门槛。上下文生命周期测试仅验证加速器边界；Minimum 阶段的 KVM 客户机登录/SSH、TCG 执行契约及远端资源标准仍需独立的端到端验收证据。

## 8. 实现触点与要求

| 文件、符号或边界 | 必需职责 |
| --- | --- |
| `master_core/kernel_backend.c` | 确保页元数据、路由缓存、请求、socket 与共享队列按上下文归属或显式携带上下文标签；强制执行第 1.2 节隔离门槛。 |
| `master_core/module-common.[ch]` | 仅保留携带显式上下文引用的模块级注册表与工作线程。 |
| `common_include/wavevm_ioctl.h` | 定义上下文生命周期、配置与操作信封；拒绝未绑定遗留 setter，不保留第二套配置路径。 |
| 模块 `g_module_transport`（UDP socket + TX 环）及按上下文 `diff_queue`/`dir_locks` | 共享传输槽位与工作线程须持有显式上下文引用；脏页队列与 GPA 分片锁保持按上下文隔离。 |
| `wavevm-qemu/accel/wavevm/` | 仅通过本地已准备清单创建与挂载上下文，并在每次操作时校验上下文身份。 |
| `master_core/logic_core.c` / 节点运行时 | 维持语义权威；内核完成结果回归该契约，不另建并行 RPC 路径。 |

## 9. 兼容性边界

无需保留遗留模块全局 VM 状态、未绑定 setter 或第二套配置 ABI。所有操作均使用显式创建并挂载的按 VM 上下文、清单派生配置及生命周期安全的引用。仅当第 1.2 节隔离验收条件全部通过后，方可通告多上下文能力。

## 10. 验收测试

- 同一物理节点上的两个 Mode A VM 拥有各自独立的上下文句柄、映射、路由缓存、页/脏页记录、请求 ID、等待队列与本地名称；任一 VM 的流量均不影响另一 VM。
- 多个 QEMU/节点运行时描述符可挂载至同一上下文，关闭其中一个描述符不会销毁其他描述符持有的活跃状态。
- 错误的实例代次、清单摘要、能力画像、角色或挂载能力凭据在 mmap 或数据面操作前即被拒绝。
- 原子配置/路由快照替换过程绝不向并发读者暴露不完整表项。
- `REMOTE_RUN` 应答丢失后返回文档化的执行中或缓存结果，不触发第二次执行区间。
- 相同负载下，脏页捕获与失效产出的页版本和交接栅栏结果与 Mode B 一致。
- KVM Mode A 不安装宿主机 `PROT_NONE` 客户机 RAM 陷阱，且在存在版本缺口时于依赖执行前显式重同步。
- 强制工作线程故障以及并发解绑/销毁不会触发上下文内存释放后使用（UAF）、映射泄漏、无关 VM 上下文死锁或虚假成功上报。
- 跨节点报文插桩证实所有经加速的远端操作均完整经过节点运行时与 Sidecar/Gateway 路径进出。

# WaveVM 能力与缺页引擎规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：宿主机能力探测、版本化能力画像（capability profile）、执行与缺页引擎选择、userfaultfd 与 SIGSEGV/mprotect 行为、KVM 脏页日志、故障处理，以及 Mode A 与 Mode B 之间的兼容性。内存正确性契约仍归属 `memory-consistency.md`，可选内核实现边界仍归属 `kernel-accelerator.md`。

本规范对运行时机制的选择具有规范效力。缺少高速特性时可选用较慢但正确的替代机制，但严禁采用仅为了让测试继续推进的语义变通方案。

## 子系统边界契约

本摘要仅索引各归属规则，不重复其完整定义。涉及边界变更时，适用[架构基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 必需契约 |
| --- | --- |
| 职责与权威 | 负责真实的本地能力探测及已准入的执行/缺页机制；内存版本、VM 放置与生命周期仍归各自子系统权威所有。 |
| 状态与变更 | 探测证据限定于成员实例与画像代次范围内。引擎本地映射与脏页捕获状态是已准入画像的授权实现，而非独立的目录状态。 |
| 允许的实现依赖 | 公共 OS/后端探测适配器、规范画像、内存操作契约及内核能力 API；不得依赖规划器/控制器内部实现，也不得修改已准入策略。 |
| 交互与生命周期 | 画像选择见第 3 节；脏页捕获与发布顺序见第 4、5 节。引擎解绑遵循[生命周期资源回收](runtime-manifest-lifecycle.md#63-跨子系统资源回收)，须在回调及 RAM/memslot 引用安全释放后执行。 |
| 并发与成本 | 须声明信号/工作线程上下文、阻塞行为、脏页队列、拷贝/页保护成本与发布屏障。须实现独立页面并行推进；受限宿主机回退路径不得退化为全局同步串行路径。 |
| 故障与验证 | 不支持的能力、不确定的脏页捕获与引擎校验由第 5 节和第 9 节规范。Minimum 要求具备正确的回退路径与 KVM 路径；更广泛的跨引擎等价性属于 Extended 范围。 |

## 1. 目标与非目标

本规范的目标是在 VM 启动前显式确定所有依赖宿主机能力的行为：

```text
probe actual host behavior（真实探测宿主机行为）
  -> publish versioned capability profile（发布版本化能力画像）
  -> resolve one admitted execution/fault profile（解析唯一准入执行/缺页画像）
  -> prepare per-VM engine state（准备按 VM 隔离的引擎状态）
  -> run the same memory/vCPU semantics（执行一致的内存/vCPU 语义）
```

WaveVM 支持受限宿主机环境。root 权限、定制内核、`/dev/kvm`、userfaultfd 或 `wavevm.ko` 可提供性能加速，但均非无条件基线。Mode B 提供规范的用户态语义；Mode A 是针对部分本地数据面操作的可选加速实现。

### 1.1 发布优先级

Minimum 可用系统要求具备一条正确的受限宿主机 TCG 回退路径，并在 KVM 可用时具备一条正确的 KVM 脏页/重同步路径。完整的 `fault_engine_ops` 矩阵、UFFD 选择以及详尽的跨引擎等价性与故障注入测试属于 Extended 加固工作，不应阻塞正确的 Mode B 交付，也不得引入第二套页一致性权威。

Minimum 阶段的 TCG 能力与回退验收覆盖有界真实执行以及共享内存/vCPU 契约。完整的 TCG 客户机启动/登录/SSH 以及持续多 vCPU 客户机可用性属于 Extended 范围（见 `vcpu-handoff.md` 第 8.1 节）。选择 TCG（包括经 `AUTO` 回退）时，必须明确暴露该交付边界，不得声称 TCG 客户机 OS 已通过完整验收；该边界同样不放宽探测要求，也不允许运行时在线切换后端。

Minimum 非目标：

- 未经真实探测，仅依据内核版本、容器镜像名或设备路径存在性即宣称具备某项能力。
- 在客户机运行期间，仅因超时即在线切换缺页引擎、执行后端或内存保护模式。
- 在信号处理函数中执行网络 RPC、阻塞加锁、内存分配或修改 QEMU/全局状态。
- 将 KVM 脏页日志当作完整的远端内存一致性协议。
- 要求所有部署环境都必须具备 userfaultfd、root 权限或内核模块。
- 通过仅限测试的环境变量掩盖不受支持的引擎。

## 2. 能力权威与画像模型

### 2.1 能力状态

能力证据绑定于单个物理节点及其节点实例（`node_instance_id`）生命周期：

```text
UNPROBED -> PROBING -> AVAILABLE
                  -> UNAVAILABLE
                  -> DEGRADED
```

`AVAILABLE` 表示探测实际完成了 WaveVM 所需的操作，而不仅仅是确认 API 符号存在。`DEGRADED` 表示已知存在部分实现，但无法满足一项或多项已声明限制，严禁被隐式视为 `AVAILABLE`。

| 状态 | 规范含义 |
| --- | --- |
| `UNPROBED` | 当前节点实例尚无有效观测记录。 |
| `PROBING` | 有界探测正在执行，该特性尚不可选。 |
| `AVAILABLE` | 所需的 ABI、版本、权限与操作探测均已通过。 |
| `UNAVAILABLE` | 探测或策略证实不可用，须附带类型化原因码。 |
| `DEGRADED` | 部分行为可用，但存在已声明语义限制，不能满足本画像要求。 |

### 2.2 能力记录

```text
CapabilityRecord {
    capability_id;
    capability_schema_version;
    physical_node_id;
    node_instance_id;
    provider_instance_id;         // 相关进程/模块/设备实例标识
    state;
    abi_version;
    feature_bits;
    limits;
    constraints;
    observed_at;
    probe_operation_id;
    reason_code;
}
```

`limits` 记录关键上限值，例如支持的 RAM 注册大小、最大上下文数、队列深度、支持的上下文 schema 版本、userfaultfd 特性、KVM 脏页日志模式或可安全处理的最大缺页积压量。`constraints` 记录相关约束条件，例如容器策略、禁用的非特权 userfaultfd、不兼容的 QEMU 构建、缺失权限或不支持的宿主机架构。

成员管理/控制面负责发布能力画像；进程仅可在绑定 `node_instance_id`、代次与过期/重探测策略的前提下缓存该画像。即使物理节点 ID 不变，来自前一次容器或宿主机重启的画像也一律无效。

### 2.3 能力类别

Minimum 阶段至少须对以下类别生成能力记录：

| 类别 | 示例 |
| --- | --- |
| 执行后端 | KVM 可用性、TCG 可用性、必需的 QEMU 构建与上下文 schema。 |
| 缺页捕获与解析 | userfaultfd API/特性、SIGSEGV/mprotect 有效性、QEMU 脏页日志、KVM 脏页日志。 |
| 可选加速 | `/dev/wavevm`、内核 ABI、按 VM 隔离的上下文支持、快速失效/脏页/唤醒能力。 |
| 本地传输 | Unix socket、共享内存、eventfd、报文大小与分片支持。 |
| 平台限制 | 页大小、大页策略、NUMA 信息可用性、资源配额上限。 |
| 设备与存储 | 选定块/设备后端、flush/FUA 支持，以及按需请求的 VFIO/GPU 限制。 |

能力模型须完整刻画正确执行路径所需的必要条件，而非仅罗列宿主机碰巧具备的性能特性。

## 3. 准入执行与缺页画像

控制面将一份不可变画像解析并写入 VM 清单：

```text
ExecutionFaultProfile {
    backend;                      // Minimum 阶段为 KVM 或 TCG
    context_schema_version;
    dirty_capture_engine;
    read_fault_or_resync_engine;
    invalidation_engine;
    optional_kernel_accelerators;
    per_node_capability_digest;
    supported_memory_policies;
    fallback_decision;            // 仅允许在 PREPARED 之前确定
}
```

画像取自已准入宿主机、节点运行时与执行器所需能力的交集。无论最终选定哪种引擎，高层的页版本、目录权威、交接栅栏、请求身份与错误语义都必须完全一致。

### 3.1 选择规则

1. `REQUIRE_KVM` 仅在宿主机/前端及所有必需执行器路径均通过文档化的 KVM 与上下文 schema 探测时选择 KVM。
2. `REQUIRE_TCG` 仅在每个必需的辅助进程/执行器都支持相同的 TCG 上下文 schema 且具备有效内存缺页/重同步路径时选择 TCG。
3. `AUTO` 在准入阶段完成解析并固化到清单中，不允许运行时在线切换后端。
4. `REQUIRE_KERNEL_ACCEL` 要求每个必需挂载组件都具备兼容的按 VM 内核上下文能力，否则准入失败；`PREFER` 可在启动前选择 Mode B，并须记录该决策。
5. 首选缺页引擎仅允许在准入阶段回退，且回退引擎必须通过自身探测并满足相同的内存契约。
6. 每次选定的引擎与回退决策都必须具备明确原因码与画像摘要，可供诊断与 CI 查验。

### 3.1.1 异构计算集群

执行能力按节点通告，而非互斥的节点标签。具备可用 KVM 的节点在通过 TCG 辅助进程/上下文探测后，可同时通告 `EXECUTION_KVM` 与 `EXECUTION_TCG`；无 KVM 节点通常仅通告 TCG。执行能力本身不决定节点能否提供客户机内存，内存参与资格由节点的内存服务能力、容量、路由作用域及协商的内存画像决定。

对单个 VM 实例代次（`vm_incarnation`），所有 vCPU 分配必须统一使用准入执行画像中记录的单一后端。因此，具备 KVM 能力的节点可以为 TCG VM 贡献 TCG vCPU 算力，但须通过其 TCG 辅助进程执行，不得生成 KVM/TCG 混布的 vCPU 计划。后端选择属于激活前准入决策，不存在运行时降级或上下文转换。

`AUTO` 采用确定性的 KVM 优先语义：

1. 协调器首先尝试构建完整的 KVM 计划，要求前端及所有必需 vCPU 执行器均满足 KVM 能力与上下文 schema 要求。
2. 若无法形成可准入的完整 KVM 计划，且请求允许回退、所有选定 TCG 执行器均通过探测，则重新构建一份完整的 TCG 计划。
3. 回退属于全新的规划与资源预留尝试，不得复用已部分预留的 KVM 计划；选定后端与回退原因须写入候选及已准入清单。

`REQUIRE_KVM` 绝不触发上述降级：若无法准入完整 KVM 计划，请求在任何进程启动前即失败。`REQUIRE_TCG` 直接选择 TCG。VM 进入 `RUNNING` 后的 KVM/TCG 互转不属于 Minimum 范围。

KVM 能力节点上的 TCG 容量属于独立通告和独立记账的容量类别，不得通过复制 KVM vCPU 容量来推导；同时，KVM 与 TCG 的资源预留仍须共同服从节点的共享宿主机 CPU 与开销预算。

### 3.2 引擎矩阵

| 后端/路径 | 脏页捕获 | 读缺页/重同步 | 失效规则 |
| --- | --- | --- | --- |
| TCG Mode B | QEMU 脏页追踪 + 选定缺页引擎 | 可用时选 userfaultfd，否则选有效 SIGSEGV/mprotect 路径 | 区间/页保护结合显式版本化推送/重同步。 |
| KVM Mode B | KVM/QEMU 脏页日志或等价已验证捕获机制 | 在存在依赖的运行区间开始前，由节点运行时/QEMU 显式拉取页面 | 严禁对 KVM 客户机 RAM 使用 `mprotect(PROT_NONE)` 作为 EPT 缺页触发器。 |
| Mode A 可选加速 | 仅在协商后启用绑定上下文的内核脏页/失效/唤醒 | 与 Mode B 相同的用户态权威与类型化操作契约 | 内核操作仅为缓存/快速路径，绝不改变页状态规则。 |

KVM 脏页日志仅负责识别写操作，不负责拉取过期页、建立目录所有权、消除版本缺口或保证远端写持久化；这些职责仍归节点运行时与内存契约所有。

## 4. 缺页引擎契约

每个可选引擎均须实现版本化的 `fault_engine_ops` 契约：

```text
fault_engine_ops {
    probe(node_scope) -> CapabilityRecord;
    prepare_vm(manifest, profile) -> engine_ctx;
    register_ram_range(engine_ctx, RAMBlock, gpa_range) -> result;
    arm_range(engine_ctx, gpa_range, mode) -> result;
    capture_dirty(engine_ctx, handoff_or_flush_boundary) -> DirtyJournal;
    resolve_read_or_resync(engine_ctx, page_key, required_version) -> result;
    invalidate(engine_ctx, page_key, target_version) -> result;
    complete_fence(engine_ctx, fence_id, status) -> result;
    disarm_range(engine_ctx, gpa_range) -> result;
    teardown_vm(engine_ctx) -> result;
}
```

具体 C ABI 可因后端而异，但操作语义必须一致。每次调用都须携带或解析出 VM 实例代次、清单代次、RAM 区间及操作/栅栏标识。引擎无权选择目录、修改页版本或绕过本地节点运行时。

### 4.1 Userfaultfd 引擎

探测必须实际验证 `userfaultfd` 系统调用与策略、请求的 API 特性、典型 RAM 区间注册、事件投递以及资源清理；仅读取 sysctl 或假设具备 root 权限均不构成有效证明。

缺页处理运行在专用缺页线程或等价事件循环中。它须先校验地址属于清单绑定的 WaveVM RAM 区间，再通过本地节点运行时请求带版本号的页面或重同步。等待网络或目录操作期间，严禁持有 QEMU 全局锁。

### 4.2 SIGSEGV/mprotect 引擎

SIGSEGV/mprotect 仅允许用于经验证兼容的 Mode B TCG 内存区间。异步信号处理函数仅可执行异步信号安全（async-signal-safe）操作，例如向预分配的无锁缓冲区写入最小缺页信息并通过允许的原语唤醒专用处理线程；严禁调用 `malloc`、`printf`、pthread 锁、QEMU API、IPC RPC 或网络发送。

处理逻辑必须先确认访问地址落在清单绑定的 RAM 区间内，方可将其认领为 WaveVM 缺页。非 WaveVM 地址、非法访问或引擎状态不匹配的情况必须转发给先前安装的信号处理器或正常缺页策略，不得吞没为远端缺页请求。

### 4.3 KVM 脏页/重同步引擎

KVM 客户机 RAM 严禁依赖宿主机 `mprotect(PROT_NONE)` 拦截读写，否则会引发 EPT 违例及错误的 KVM 退出。KVM 须通过经验证的脏页捕获机制记录写入，并在存在依赖的客户机执行区间启动前，通过 QEMU/节点运行时显式拉取或重同步版本缺口页。

引擎须将脏页日志采样与交接/刷新边界关联。在脏页日志进入内存协议且所需栅栏结果确定之前，不得清除脏页位或将页面标记为已同步。

### 4.4 内核加速引擎

仅在清单绑定的 `wvm_kernel_ctx` 准备完成后，方可选用可选内核引擎。它可加速脏页捕获、失效、本地唤醒或本地报文准备，但每项操作必须返回与 Mode B 相同的类型化结果。它不得发起独立的跨节点路由、伪造内存 ACK，或在清单/路由失效后继续缓存路由或页面。

## 5. 排序、背压与故障处理

### 5.1 排序

- 脏页捕获返回的日志绑定于发起请求的交接/栅栏，不得被重新解释为后续客户机执行区间的写集合。
- 页失效操作使缓存页立即不可用，直至内存契约返回下一版本更新或权威重同步结果。
- 仅在内存规范要求的目录 ACK 与本地投递屏障全部完成后，方可达到 `complete_fence(success)`。
- 引擎锁粒度应在可行范围内按 VM、区间或页划分；严禁使用全局缺页锁串行化所有 VM 或彼此独立的页面。

### 5.2 有界背压

缺页队列、脏页日志与重同步请求均须有界。引擎过载时，仅可在文档化安全边界阻塞受影响的区间/vCPU，或向生命周期/运行时返回类型化失败；严禁丢弃缺页事件、静默丢失脏页记录或无界消耗内存。

控制、vCPU 交接、必需内存 ACK 以及缺页恢复流量须维持既定 QoS。大批量脏页传输不得无限期饿死恢复客户机执行所需的页面请求。

### 5.3 故障规则

| 故障条件 | 必需行为 |
| --- | --- |
| 准入前探测失败 | 若策略允许则选择文档化兼容回退方案，否则在启动前失败。 |
| 引擎准备失败 | 拒绝或中止生命周期准备，仅清理该清单对应的本地状态。 |
| 缺页队列溢出或处理失败 | 将受影响操作/区间标记为失败或暂停，严禁静默放行过期执行。 |
| 页拉取或版本重同步失败 | 保持页面无效并返回类型化内存失败，不得恢复对旧字节的访问。 |
| 脏页捕获结果不确定 | 阻止依赖该捕获的交接/刷新成功，仅通过其操作身份保留或重试日志。 |
| 内核加速器消失 | 停止使用快速路径，随后暂停/失败，除非已显式实现经静默且清单有效的 Mode B 切换。 |
| 本地子进程/画像重启（已注册节点实例不变） | 使旧画像与引擎上下文失效，在重新接受流量前基于同一清单重新准备。 |
| 已注册节点代理或宿主机替换 | 新节点实例使已准入成员身份失效；Minimum 阶段暂停或失败该 VM，不隐式准备替换或重绑定。 |

Minimum 阶段不支持 VM 进入 `RUNNING` 后在线切换引擎实现。未来若实现运行时切换，必须先静默所有受影响 vCPU、完成或失败在途栅栏、基于同一清单校验替换引擎、原子发布新画像代次，并在所有参与方达成一致后方可恢复执行。

## 6. 诊断与安全边界

能力记录与缺页诊断输出须结构化且有界，包含 VM/实例代次、画像摘要、引擎类型、操作 ID、安全前提下的页/区间信息、结果/错误分类、队列深度及节点实例身份；不得记录页面内容、私密凭据、无限制报文转储或持续无界打印每一次缺页。

探测与上报路径仅可检查宿主机策略，严禁修改全局宿主机安全配置、系统级开启 userfaultfd、隐式加载内核模块或放宽容器隔离。此类策略变更属于本规范之外的显式运维操作。

## 7. 实现触点与要求

| 文件、符号或边界 | 必需职责 |
| --- | --- |
| `wavevm-qemu/accel/wavevm/wavevm-user-mem.c` | 将逻辑拆分为清单绑定的缺页引擎上下文；保持 KVM 禁用 `PROT_NONE` 规则，并将非异步信号安全工作移出信号处理函数。 |
| `wavevm-qemu/accel/wavevm/wavevm-cpu.c` | 在 vCPU 交接契约下消费选定引擎产出的 `DirtyJournal` 与栅栏结果。 |
| QEMU KVM 脏页日志代码 | 仅作为脏页捕获提供者，不充当页目录或重同步权威。 |
| `master_core/kernel_backend.c` 与 `common_include/wavevm_ioctl.h` | 发布能力证据并将所有加速操作绑定至按 VM 隔离的上下文。 |
| CI/运行脚本 | 记录探测结果与画像选择，并在无可用正确引擎时尽早失败。 |

## 8. 兼容性边界

无需保留遗留宿主机能力输入或旧引擎选择路径。准入完全基于真实宿主机探测与规范能力画像；不支持或降级的画像必须闭环失败，或仅走显式允许的准入前回退路径。测试夹具不得覆写探测证据。

## 9. 验收测试

- 能力报告能够准确区分 KVM 缺失、KVM 无权限访问、KVM 可用，以及 userfaultfd 缺失、受策略拦截与可用等状态。
- TCG 仅在完整注册/事件探测通过时启用 userfaultfd，仅在有界测试通过时启用 SIGSEGV/mprotect。
- KVM 绝不对客户机 RAM 安装 `PROT_NONE` 访问陷阱；出现版本缺口时，在恢复依赖执行前必须触发显式页拉取。
- 在交接边界捕获的脏页记录要么抵达所需内存栅栏，要么导致该次交接失败，队列施压下不得静默丢弃。
- 落在已注册 WaveVM RAM 之外的缺页交由正常 QEMU/进程机制处理，不触发远端缺页 RPC。
- 内核模块不可用或不支持按 VM 隔离的上下文时，`PREFER` 选择 Mode B，`REQUIRE_KERNEL_ACCEL` 在启动前被拒绝。
- 拥有不同能力画像的两个 VM 无法相互挂载对方的缺页队列、RAM 区间、页版本或内核上下文。
- 缺页风暴下能力与引擎日志保持有界，且包含足够身份与结果证据以区分能力故障、页一致性故障与传输故障。

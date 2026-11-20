# WaveVM 线协议与本地 IPC ABI 规范

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：网络分帧、报头校验、字节序、载荷边界、请求身份、QoS、去重与重试语义、本地 QEMU 至节点运行时 IPC、节点运行时至执行器 IPC、兼容性规则以及 Mode A IOCTL 边界。本文档仅定义传输契约；页状态、vCPU 状态、成员管理、放置与块存储语义归各自所属子系统规范。参与者与 ABI 特性的合法性由已准入清单与能力画像决定，本文档不承担准入决策。

旧版报头、宿主原生本地 IPC、`SYNC_MAGIC`、原始 ID 回退及无类型完成标记均不满足生产所需的身份与幂等契约。所有生产流量必须满足下文的分帧与语义校验要求，任何旧版解码器均受迁移约束限制。

## 子系统边界契约

本节仅索引归属规则，不重复其详细定义。任何边界变更须遵守[架构基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 契约要求 |
| --- | --- |
| 职责与权威 | 负责分帧、报头校验、传输与控制信道认证以及本地 IPC 机制。语义完成判定、序关系与错误含义归操作所属业务域。 |
| 状态与变更 | 信道、重组缓冲区与投递尝试均为传输层本地状态。语义操作 ID 与结果归业务域持有；收到的流量绝不因源地址或分帧本身获得权限。 |
| 允许的实现依赖 | 共享身份与标量编码、有界校验和与传输原语，以及入口组合层调用的公开载荷编解码/校验接口。分帧层不得引入生命周期、规划器、页目录或执行器的具体内部实现。 |
| 交互与生命周期 | 第 5.1 节规范缓冲区与完成上下文；[路由操作生命周期](identity-routing.md#61-路由替换与操作生命周期)规范重路由时的身份保持；[生命周期回收](runtime-manifest-lifecycle.md#63-跨子系统资源回收)约束排空与信道关闭顺序。 |
| 并发与开销 | 第 5 节与第 6 节要求有界并行分发、拷贝与跳数核算、优先级调度与背压机制。传输协议选型须保持语义不变，并以适用实测数据为依据。 |
| 故障与验证 | 第 2、3、9 节要求在状态变更前拒绝非法、过期或未授权流量。本地入队或发送返回绝不等同于持久化成功或 Guest 可见的完成结果。 |

## 1. 分帧与版本控制

每条网络报文与本地 IPC 记录都必须具备显式带版本的信封。接收方必须在解析消息特定字段前完成整个信封的校验。

### 1.1 旧版网络报头

旧版紧凑结构 `struct wvm_header` 布局如下：

```text
magic, msg_type, payload_len,
slave_id, target_id, req_id/target_gpa,
qos_level, flags, mode_tcg, node_state, epoch, crc32
```

该旧版外层报头虽使用网络字节序，但未对所有载荷规定可移植编码，无法作为生产环境的线协议契约。

针对该报头的解码器仅限处理旧版输入。新语义流量统一采用下文的定长 V1 信封；接收方严禁仅凭载荷长度推断协议版本。

### 1.2 旧版本地 IPC 报头

旧版 QEMU IPC 前缀为：

```text
wvm_ipc_header_t { uint32_t type; uint32_t len; }
```

该前缀仅描述旧版分帧。新版本地 IPC 采用与网络流量一致的语义信封，在流式传输时可选前置 4 字节大端帧长度。本地 Unix 套接字、共享内存、进程内调用与内核 ioctl 的底层传输机制可以不同，但必须暴露一致的字段与校验结果。连接到达顺序绝不代表身份：QEMU 在使用信道前必须显式注册 `SYNC` 与 `ASYNC_PUSH` 角色。

### 1.3 WVM Envelope V1

所有整数字段均为无符号大端序。固定 V1 报头为紧凑排列的 164 字节序列，无编译器填充；`operation_id` 与各类摘要均为网络序原始字节。

| 偏移 | 类型 | 字段 | 规范含义 |
| --- | --- | --- | --- |
| 0 | `u32` | `magic` | ASCII `WVM1`（`0x57564d31`）。 |
| 4 | `u16` | `protocol_version` | 此布局恒为 `1`。 |
| 6 | `u16` | `header_bytes` | 恒为 `164`。 |
| 8 | `u16` | `message_type` | 注册表定义的数据/控制/本地操作类型。 |
| 10 | `u16` | `flags` | 类型化且互不重叠的标志位；置入未知位直接拒绝。 |
| 12 | `u32` | `payload_bytes` | 本帧/分片紧随报头之后的字节数（适用时包含必需的路由帧前缀）。 |
| 16 | `u32` | `vm_id` | 逻辑命名空间；仅经过认证的集群控制流量可为 0。 |
| 20 | `u64` | `vm_incarnation` | 所有 VM 操作必填。 |
| 28 | `u64` | `manifest_generation` | 候选/已准入清单代次；仅集群注册时可为 0。 |
| 36 | `u32` | `origin_physical_node_id` | 已注册源宿主机身份。 |
| 40 | `u64` | `origin_runtime_instance_id` | 源运行时/进程的全新实例身份。 |
| 48 | `u8[16]` | `operation_id` | 非零 128 位操作/控制事务标识。 |
| 64 | `u64` | `delivery_attempt_id` | 可变转发尝试序号；单个语义操作从 1 开始计数。 |
| 72 | `u64` | `route_scope_id` | 路由 VM 流量必填；非路由控制记录为 0。 |
| 80 | `u64` | `topology_revision` | 所选路由快照的拓扑版本。 |
| 88 | `u64` | `route_generation` | 路由作用域内的快照代次。 |
| 96 | `u8[32]` | `route_snapshot_digest` | 完整路由快照的 SHA-256 摘要；仅无路由适用时为全零。 |
| 128 | `u8[32]` | `semantic_payload_digest` | 未分片完整语义载荷的 SHA-256，不含转发元数据。 |
| 160 | `u32` | `crc32c` | 覆盖字节 0–159 及本帧载荷字节的 CRC32C。 |

完整的语义操作键为 `{vm_id, vm_incarnation, origin_physical_node_id, origin_runtime_instance_id, operation_id}`。源运行时通过不回绕的 128 位单调序列或密码学安全 128 位随机源生成 `operation_id`，且新运行时实例绝不复用前驱的 `origin_runtime_instance_id`。UDP 源地址与端口仅作传输层诊断证据，不可充当此身份。

`delivery_attempt_id`、`route_scope_id`、`topology_revision`、`route_generation` 与 `route_snapshot_digest` 属于转发元数据，不计入 `semantic_payload_digest`；路由刷新可替换这些字段，而不改变语义去重键、请求载荷或操作结果。

### 1.3.1 路由帧前缀

每条需路由的数据消息在固定 V1 报头之后、分片前缀或语义载荷之前，必须紧跟此精确的 24 字节前缀。本地与网络传输均强制携带。帧 CRC32C 覆盖该前缀，但 `semantic_payload_digest` 刻意将其排除。

| 偏移 | 类型 | 字段 | 规范含义 |
| --- | --- | --- | --- |
| 0 | `u16` | `route_prefix_version` | 恒为 `1`。 |
| 2 | `u16` | `route_prefix_bytes` | 恒为 `24`。 |
| 4 | `u16` | `destination_kind` | `1=FLAT_VNODE`，`2=FRACTAL_VNODE`。 |
| 6 | `u16` | `flags` | 保留字段；V1 恒为 0。 |
| 8 | `u64` | `destination_scope` | `FLAT_VNODE` 为 0；`FRACTAL_VNODE` 必须为非零 Pod/前缀。 |
| 16 | `u32` | `destination_vnode_or_endpoint` | 指定作用域内的目标 vnode 或节点运行时端点。`0` 为合法首个 vnode；`0xffffffff` 为 V1 唯一未指定哨兵值，必须拒绝。 |
| 20 | `u16` | `hop_limit` | 路由编译器提供的最大转发跳数；必须非零。 |
| 22 | `u16` | `hop_count` | 初始为 0；每个转发 Sidecar/网关将其加 1，超过 `hop_limit` 时拒绝转发。 |

该前缀补全了每条路由帧所需的完整 `RouteKey`：固定信封提供协议版本、VM 身份/代次与路由作用域，前缀提供目标作用域与 vnode/端点。网关必须使用该完整键查询其已准入的不可变快照，严禁以 UDP 源地址、物理节点 ID、`target_id` 或旧版原始路由项替代。

路由快照规则受对应的规范约束：Flat 快照仅允许 `destination_scope=0` 的 `EXACT_VNODE` 规则；Fractal 的 `PREFIX` 规则表示子树而非叶子节点，其 vnode 字段为 0、作用域非零且下一跳必须是已准入网关；Fractal 精确叶子规则必须具有非零作用域。上述校验确保畸形路由记录在发布给 V1 消费端前即被拒绝。

### 1.4 V1 内存载荷

`MSG_MEM_READ`、`MSG_MEM_ACK`、`MSG_COMMIT_DIFF` 与 `MSG_MEM_COMMIT_ACK` 使用定长/规范大端语义载荷。信封的路由前缀标明当前接收方；读请求载荷还须独立携带应答叶子 `RouteKey`，确保 ACK 路径绝不从 UDP 源地址、物理节点 ID、`target_id` 或旧版请求表反向推断目标。页目录在自身已准入的不可变路由快照中解析该应答键，并构造外层路由前缀指向该应答目标的 ACK。读/提交载荷同时携带请求方的非零 `node_instance_id`，与信封源物理节点及运行时实例 ID 共同标识订阅者，绝不能以中间网关的下一跳成员实例替代叶子身份。

```text
MemReadPayload {
    u64 gpa;                       // 4 KiB 对齐
    u16 reply_destination_kind;    // 1=FLAT_VNODE, 2=FRACTAL_VNODE
    u16 reserved_zero;
    u64 reply_destination_scope;   // 仅 FLAT_VNODE 为 0
    u32 reply_destination_vnode;   // 0 合法；0xffffffff 拒绝
    u64 reply_node_instance_id;    // 非零叶子节点实例，非网关
}

MemAckPayload {
    u64 gpa;                       // 同一 4 KiB 对齐页
    u64 version;                   // 仅 SUCCESS 时非零
    u16 status;                    // 0=SUCCESS, 1=STALE, 2=NOT_FOUND,
                                   // 3=BACKPRESSURE, 4=INTERNAL_FAILURE
    u16 reserved_zero;
    u32 directory_physical_node_id;
    u64 directory_node_instance_id;
    u8[4096] data;                 // 仅 status=SUCCESS 时存在
}
```

成功 ACK 的载荷严格为 `32 + 4096` 字节并携带权威完整页；非成功终态 ACK 严格为 32 字节，`version` 为 0 且无页数据。两种形式均在信封中保留请求的完整语义操作键，仅针对回程更新可变转发元数据与外层路由目标。构造外层 ACK 前缀前，页目录节点运行时必须通过已准入不可变快照解析载荷中的应答目标并获取新的非零 `hop_limit`，拒绝缺失、不匹配或过期的应答路由。请求方在安装页数据前，必须校验 ACK 中的页目录物理节点与节点实例身份与本地已准入内存分发投影一致。

`MSG_COMMIT_DIFF` 承载单次常规脏页提交，绝不与旧版宿主原生 `wvm_diff_log` 布局混叠。出于与 `MSG_MEM_READ` 相同的原因，请求内含完整应答叶子 `RouteKey`：页目录仅经由已准入快照回送应答。

```text
MemCommitPayload {
    u64 gpa;                       // 4 KiB 对齐
    u64 base_version;              // 写方观测到的非零页目录版本
    u16 offset;                    // 页内字节偏移
    u16 size;                      // 1..4096，且 offset + size <= 4096
    u16 reply_destination_kind;    // 1=FLAT_VNODE, 2=FRACTAL_VNODE
    u16 reserved_zero;
    u64 reply_destination_scope;   // 仅 FLAT_VNODE 为 0
    u32 reply_destination_vnode;   // 0 合法；0xffffffff 拒绝
    u64 reply_node_instance_id;    // 非零叶子节点实例，非网关
    u8[size] data;
}

MemCommitAckPayload {
    u64 gpa;
    u64 result_version;            // 仅 SUCCESS 时非零
    u16 status;                    // 0=SUCCESS, 1=STALE_BASE_VERSION,
                                   // 2=NOT_FOUND, 3=BACKPRESSURE,
                                   // 4=INTERNAL_FAILURE
    u16 reserved_zero;
    u32 directory_physical_node_id;
    u64 directory_node_instance_id;
}
```

提交 ACK 严格为 32 字节，保留请求的完整语义操作键，仅变更转发元数据与外层路由目标。收到重复 `MSG_COMMIT_DIFF` 时，页目录在同一源节点/运行时与操作键下比对完整的 `semantic_payload_digest`：摘要一致则返回已记录的 `MemCommitAckPayload`；摘要不同则判定为 `OPERATION_ID_CONFLICT`，绝不重复应用写入字节。

### 1.5 规范记录、大小限制与分片

清单、路由快照与控制载荷均采用规范 WVM-TLV 记录：

```text
CanonicalRecord {
    u16 schema_version;
    u16 record_type;
    u32 body_bytes;
    CanonicalField fields[];      // field_tag 严格升序，无重复
}

CanonicalField {
    u16 field_tag;
    u16 field_flags;
    u32 value_bytes;
    u8[value_bytes] value;
}
```

所有标量字段均与信封采用相同的大端编码。嵌套记录使用规范字节流，列表按显式键严格排序。精确的记录类型注册表、标签号、标量位宽、列表键、跨字段约束、自摘要规则及互操作夹具均在 `canonical-record-schema.md` 中规范定义。未知必填字段及重复/乱序标签一律拒绝。`manifest_digest` 与 `route_snapshot_digest` 为完整规范记录（含记录头）的 SHA-256，计算时仅将规范指定的自摘要字段清零。

以下 V1 限制为协议级安全上限，而非隐式测试参数：

| 项目 | 上限 |
| --- | --- |
| 本地流/进程内帧载荷 | 最大 4 MiB。 |
| 逻辑网络载荷 | 最大 1 MiB。 |
| 网络数据报/帧（含 V1 报头） | 最大 1280 字节。 |
| 单片分片数据 | 最大 1024 字节。 |
| 单个逻辑载荷的分片数 | 最多 1024 片。 |
| 并发未完成重组数 | 单 VM 实例代次最多 64 个，且单源总计不超过 8 MiB。 |
| 重组存活时长 | 5 秒；超时后丢弃/返回有界 `FRAGMENT_EXPIRED` 诊断。 |

当置位 `FLAG_FRAGMENTED` 时，路由帧前缀后紧跟下述 40 字节分片前缀，其后为最多 1024 字节的逻辑载荷片段；非路由控制帧省略路由帧前缀，直接以该分片前缀起始：

```text
FragmentPrefix {
    u32 logical_payload_bytes;
    u16 fragment_index;
    u16 fragment_count;
    u32 fragment_offset;
    u8[28] reserved_zero;
}
```

重组键为完整语义操作键加上 `message_type` 与 `delivery_attempt_id`。接收方必须在分发前校验边界、无重叠、完整逻辑摘要及全部片段齐备。任何路径均不得依赖 IP 分片。超出上限的消息返回 `PAYLOAD_TOO_LARGE`，除非所选可靠传输已在能力画像中显式协商并记录了更大的上限。

## 2. 通用校验规则

在解码具体载荷字段之前，每个接收方必须依次验证：

1. 精确的 V1 报头长度、声明长度、协议上限，以及报头加载荷长度计算无整数溢出。
2. `magic`、`protocol_version`、已知 `message_type` 与合法的 `flags` 组合。
3. 在产生任何状态变更前完成 CRC32C 完整性校验；分片消息还须在重组完成后校验完整逻辑载荷的 SHA-256 `semantic_payload_digest`。
4. 操作所需的 VM 命名空间/`vm_incarnation`、`manifest_generation`、源物理节点/运行时身份以及非零 `operation_id`。
5. 路由投递适用时的完整路由快照键/摘要及本地已接受代次。路由刷新仅改变转发元数据，不构成新语义操作。
6. 源与目标角色的合法性（例如网关只负责路由，不能成为目标执行器）。
7. 访问前校验具体载荷的规范记录结构、最小/最大长度及精确字段 schema。

畸形、未知版本、命名空间不匹配或非法长度的流量一律丢弃并输出有界诊断，严禁进入 `logic_core`、QEMU RAM、KVM、TCG、块后端或内核缓存。

所有新网络载荷字段必须采用规范化的固定字节序。紧凑 C 结构体仅在明确定义各字段尺寸、对齐、填充与字节序转换后方可作为固定 ABI 的实现载体。宿主原生本地 IPC 仅允许在双端协商一致的构建 ABI 时使用，其最终稳定形态仍须可移植。

## 3. 操作身份与响应规则

所有可能修改 Guest 可见状态的操作都必须携带作用域绑定至 `{vm_id, vm_incarnation, origin_physical_node_id, origin_runtime_instance_id}` 的非零 128 位 `operation_id`（现有 `req_id` 为其兼容前身）。接收方须以该完整元组连同操作类别与 `semantic_payload_digest` 作为去重与结果查找键。

| 操作类别 | 身份规则 | 重复请求行为 |
| --- | --- | --- |
| 读/缺页查找 | 重试保持相同语义键与摘要。 | 返回相同或更新的权威结果。 |
| 带版本内存提交 | 重试保持相同语义键与摘要。 | 返回缓存的完成结果；同键不同载荷则拒绝。 |
| `VCPU_RUN` | 每个 `{VM, vCPU}` 唯一交接序号加单一语义键。 | 查询等待或重放缓存的 `VCPU_EXIT`；绝不执行两次。 |
| 块写入/刷盘 | 重试保持相同语义键与有序写序号。 | 仅在所需后端完成后返回缓存的完成结果。 |
| 成员/路由/清单控制 | 单一控制器事务 `operation_id`。 | 幂等确认已记录状态与记录摘要。 |

任何 ACK 或结果报文必须回显完整的语义/控制操作键、携带类型化状态码，并包含该操作所需的结果字段。单字节通用 ACK 或 `SYNC_MAGIC` 不可作为内存、vCPU、块存储、路由、预留或生命周期操作的稳定完成信号。

## 4. 网络消息族

下表规定各类消息的目标方向与归属，精确载荷 schema 见对应引用规范。

| 消息族 | 现有消息 | 方向 | 契约归属 |
| --- | --- | --- | --- |
| 内存读 | `MSG_MEM_READ`、`MSG_MEM_ACK` | 节点运行时 -> 页目录 -> 节点运行时 | `memory-consistency.md` |
| 内存提交/推送 | `MSG_COMMIT_DIFF`、`MSG_PAGE_PUSH_DIFF`、`MSG_PAGE_PUSH_FULL`、`MSG_FORCE_SYNC` | 客户端/页目录（按规范） | `memory-consistency.md` |
| 旧版一致性 | `MSG_MEM_WRITE`、`MSG_INVALIDATE`、`MSG_DOWNGRADE`、`MSG_FETCH_AND_INVALIDATE`、`MSG_WRITE_BACK` | 仅作映射前兼容 | `memory-consistency.md` |
| vCPU 交接 | `MSG_VCPU_RUN`、`MSG_VCPU_EXIT` | 源节点运行时 -> 目标节点运行时/执行器 -> 源端 | `vcpu-handoff.md` |
| 中断 | `MSG_VFIO_IRQ` 与本地 IRQ IPC | 执行器/设备 -> 节点运行时 -> QEMU 权威 | `vcpu-handoff.md` 与 `storage-device-authority.md` |
| 块 I/O | `MSG_BLOCK_READ`、`MSG_BLOCK_WRITE`、`MSG_BLOCK_FLUSH`、`MSG_BLOCK_ACK` | QEMU 权威 -> 节点运行时 -> 指定存储执行器 -> 返回 | `storage-device-authority.md` |
| 成员/视图 | `MSG_HEARTBEAT`、`MSG_VIEW_PULL`、`MSG_VIEW_ACK`、`MSG_NODE_ANNOUNCE` | 仅诊断/兼容 | `cluster-membership-topology-lifecycle.md` |
| 网关控制 | 现有 `WVMC` 添加/更新包 | 控制面 -> 网关 | `cluster-membership-topology-lifecycle.md` |

`MSG_PING` 与 `SYNC_MAGIC` 仅属旧版兼容机制，不得充当类型化 vCPU 栅栏、路由提交或权威成员变更信号。

### 4.1 控制传输与结果记录

控制 RPC 复用同一 V1 信封，通过独立于待排空/待替换网关的可靠有序控制信道传输。远端控制信道采用已配置的认证流传输，同宿主机控制可采用受保护的 Unix 套接字。数据面 UDP 下一跳绝不可作为获取控制 ACK 以替换该下一跳自身的唯一通路。

每个控制请求以报头 `operation_id` 作为事务 ID，并携带单条规范请求记录。响应统一使用 `CTRL_RESULT`（`0x01ff`）及下述定长 72 字节载荷：

```text
ControlResult {
    u16 status_code;
    u16 recorded_state;
    u32 result_flags;
    u8[16] in_reply_to_operation_id;
    u8[32] record_digest;
    u64 applied_revision;
    u64 expiry_or_retention_deadline;
}
```

`status_code=SUCCESS` 表示接收方已持久化记录该结果，而非仅入队待办。携带相同 `operation_id` 与语义摘要的重复请求重放同一结果；同一 ID 对应不同摘要、不同控制消息类型或不同已认证成员身份时返回 `OPERATION_ID_CONFLICT`。V1 中 `result_flags` 恒为 0。`expiry_or_retention_deadline` 为 0 表示该结果按成员生命周期/隔离窗口保留，而非固定墙钟过期时间。

| 状态码 | 状态名 |
| --- | --- |
| `0` | `SUCCESS` |
| `1` | `INVALID_ENVELOPE` |
| `2` | `INVALID_RECORD` |
| `3` | `UNAUTHORIZED_ROLE` |
| `4` | `STALE_INSTANCE` |
| `5` | `ELIGIBILITY_FENCE_STALE` |
| `6` | `PRECONDITION_FAILED` |
| `7` | `OPERATION_ID_CONFLICT` |
| `8` | `NOT_FOUND` |
| `9` | `RESULT_EXPIRED` |
| `10` | `BACKPRESSURE` |
| `11` | `UNSUPPORTED` |
| `12` | `INTERNAL_FAILURE` |

### 4.2 规范控制消息结构定义

控制载荷均为 `CanonicalRecord`。`ID16`、`Digest32`、`Endpoint`、`MemberKey`、`SnapshotKey` 及全部引用记录的精确结构定义见 `canonical-record-schema.md`。按顺序列出的字段采用从 1 起始的升序规范标签；未标注可选的字段均为必填。

| 类型码 | 消息名 | 必填请求字段 | 前置条件 | 成功结果与保留策略 |
| --- | --- | --- | --- | --- |
| `0x0101` | `REGISTER_MEMBER` | 完整规范 `NodeRecord` 或 `GatewayRecord` 载荷；接收方由此派生 `MemberKey` | `vm_id=0`、全新成员实例、已认证注册方 | 登记 `PENDING`/`RECOVERING` 期望状态记录；保留至成员移除/隔离完成。 |
| `0x0102` | `CORDON` | 完整规范 `MemberCordonRequest`（`0x102c`） | 已认证主体为经独立配置的成员管理授权器认可的 `EXECUTOR` 主体。目标为已注册的 `NODE_RUNTIME` 或 `GATEWAY`，三个期望版本号精确匹配。 | 目标进入 `CORDONED`；成员版本与准入资格版本各递增 1，拓扑版本不变；持久化可重放结果保留至移除/隔离完成。 |
| `0x0103` | `DRAIN` | 完整规范 `GatewayDrainRequest`（`0x102b`） | 已认证主体为经独立配置的管理授权回调认可的 `EXECUTOR` 主体；未配置回调则默认拒绝（fail-closed）。`PREPARE` 要求当前成员/拓扑/资格三版本精确匹配，并附带 `topology_revision = current + 1` 的完整后继路由；`COMMIT` 与 `ABORT` 携带相同的准备前栅栏，控制器校验持久化准备后资格状态。 | 每操作保留一条持久化可重放结果。`PREPARE` 仅推进资格版本；`COMMIT` 原子激活后继路由、标记目标网关为 `DRAINING` 并推进全部三个版本；`ABORT` 保持成员/拓扑版本不变，但保留 `PREPARE` 产生的单调资格失效。 |
| `0x0106` | `DRAIN_COMPUTE` | 完整规范 `MemberCordonRequest`（`0x102c`）栅栏载荷（与 `CORDON` 同结构，V1 计算节点排空请求） | 已认证主体为经成员管理授权器认可的 `EXECUTOR` 主体（授权 `DRAIN_COMPUTE`）。目标为已处于 `CORDONED` 且依赖集为空的已注册 `NODE_RUNTIME`，三版本精确匹配。 | 目标进入 `DRAINING`；成员、拓扑与准入资格三版本各递增 1；保留持久化可重放结果。网关排空仅使用 `0x0103`。 |
| `0x0201` | `PREPARE_RESERVATION` | 完整规范 `AdmissionReservationStage`（`0x102d`），仅含候选清单与 `PREPARED` 预留 | 成员/能力/栅栏仍具资格且本地容量与命名租约空闲 | 返回已准备的预留 ID/摘要/过期时间；无激活栅栏时保留至中止或过期。 |
| `0x0202` | `COMMIT_RESERVATION` | 完整规范 `AdmissionReservationStage`，含候选清单、已提交预留与持久化 `ActivationRecord` | 存在匹配的未过期准备记录与持久化激活决策 | 返回已提交预留摘要；保留至 VM 回收完成。 |
| `0x0203` | `ABORT_RESERVATION` | 完整规范 `AdmissionReservationStage`，含候选清单、未激活预留与非零中止原因 | 无匹配激活栅栏，或存在显式补偿清理记录 | 返回已释放/待清理结果；保留至清理窗口结束。 |
| `0x0301` | `PREPARE_MANIFEST` | 完整规范 `AdmissionParticipantStage`（`0x102e`），含候选清单与未激活本地投影 | 成员实例、路由快照、能力画像与已准备预留精确匹配 | 返回本地清单准备记录/过期时间；保留至中止或激活。 |
| `0x0302` | `ACTIVATE_MANIFEST` | 完整规范 `AdmissionParticipantStage`，含带激活栅栏的投影与持久化 `ActivationRecord` | 存在匹配的准备记录且栅栏未变 | 返回已激活本地清单结果；保留至 VM 回收完成。 |
| `0x0303` | `ABORT_MANIFEST` | 完整规范 `AdmissionParticipantStage`，含未激活投影与非零中止原因 | 未激活，或激活后的补偿清理 | 返回已移除/待清理结果；保留至清理窗口结束。 |
| `0x0304` | `QUERY_TX` | 目标 `operation_id:ID16`，候选摘要（可选），激活栅栏（可选） | 调用方仅可查询其有权检视的角色/事务 | 返回记录的事务状态/摘要/过期时间；保留期同目标记录。 |
| `0x0401` | `ROUTE_PREPARE` | `SnapshotKey`、规范快照记录、前驱键（可选）、`RequiredAckSet` 记录/摘要、资格栅栏摘要、操作保留窗口 | ACK 集合全部成员均为存活且具备资格的成员；退出/故障网关不在必选集中 | 返回已准备快照结果；保留至激活或中止。 |
| `0x0402` | `ROUTE_COMMIT` | `SnapshotKey`、路由事务 ID、必选 ACK 集合摘要 | 存在匹配的已准备快照及持久化必选 ACK 集合 | 返回已激活快照结果；保留至前驱快照回收完成。 |
| `0x0403` | `ROUTE_RETIRE` | 待回收 `SnapshotKey`、后继键（可选）、路由事务 ID | 无活跃操作引用且查询/重试窗口已满，或已记录类型化终态结果 | 返回已回收快照结果；保留至 VM 命名空间隔离期结束。 |
| `0x0404` | `ROUTE_ABORT` | `state=ABORTED` 的完整规范 `RouteTransaction` | 存在匹配的已准备快照、事务 ID 与必选 ACK 集合摘要，且该事务无持久化激活 | 仅移除匹配的已准备快照，并在操作窗口内保留幂等中止结果。 |
| `0x0501` | `REJOIN` | 完整规范 `RejoinMemberRequest`（`0x102a`），含 `NodeRecord` 或 `GatewayRecord`、可选前驱 `MemberKey` 与恢复证据摘要 | 仅限全新注册，绝不隐式沿用旧实例身份 | 返回 `VALIDATING` 成员结果；绝不重绑运行中的 V1 VM。 |
| `0x0502` | `RECOVERY_REBIND` | 新旧 `MemberKey`、清单/快照摘要、预留证明、内存/vCPU/存储恢复证明 | 无独立验收的恢复规范前 V1 不支持 | V1 返回 `UNSUPPORTED` 并保留作审计证据。 |
| `0x0701` | `CLUSTER_ENROLLMENT_PREPARE` | 完整规范 `ClusterAdmissionProof`；不含 VM 身份或 `RouteSnapshot` | 已认证主体为已配置的控制器成员；证明操作 ID 等于信封 `operation_id`；本地节点运行时成员及其配置端点出现在必选 ACK 集合中；版本号与规范证明摘要合法 | 返回参与者持久化 `PREPARED` ACK/结果；仅作有界重放状态，绝非 VM 路由状态或控制器 `ACTIVE`。 |
| `0x0702` | `CLUSTER_ENROLLMENT_COMMIT` | 与对应准备阶段一致的完整规范 `ClusterAdmissionProof` | 与参与者持久化候选记录的证明和操作身份一致；仅 `PREPARED` 可提交；重复提交幂等 | 返回参与者持久化 `COMMITTED` ACK/结果；不直接改变控制器成员状态。 |
| `0x0703` | `CLUSTER_ENROLLMENT_ABORT` | 与对应准备阶段一致的完整规范 `ClusterAdmissionProof` | 与参与者持久化候选记录的证明和操作身份一致；仅 `PREPARED` 可中止；重复中止幂等 | 返回参与者持久化 `ABORTED` 终态结果；拒绝提交/中止冲突。 |

在无 VM 集群场景下，控制器主导的成员激活路径采用 `ClusterAdmissionProof`（`0x1032`）。其内嵌的 `ClusterAdmissionAckSet`（`0x1034`）用于集群拓扑级确认，不得按单 VM 路由 `RequiredAckSet`（`0x1008`）解码。该证明不创建也不激活 VM 路由作用域；在证明事务集齐全部必需对端 ACK 并持久化提交之前，该成员始终不可调度。

`RequiredAckSet` 是由 `MemberKey`、期望端点、角色与快照键组成的规范有序列表，仅包含必须安装后继快照后常规流量方可使用它的存活合规节点运行时与网关，以及正在激活的新网关。正在退出的 `DRAINING`、`FAILED` 或 `REMOVED` 网关可发送可选排空状态，但绝不纳入必选后继 ACK 集合。

### 4.2.1 注册与重加入载荷绑定

`REGISTER_MEMBER` 以单条完整的规范 `NodeRecord`（`0x100c`）或 `GatewayRecord`（`0x100d`）作为全部语义载荷。报文中的期望状态、观测健康状态、成员版本与拓扑版本仅作结构输入，控制器将其归一化为本地持久化的 `PENDING`/`RECOVERING` 记录与当前版本号。

`REJOIN` 携带规范 `RejoinMemberRequest`（`0x102a`）。字段 1 为完整的新 `NodeRecord` 或 `GatewayRecord`，新 `MemberKey` 唯一由此内嵌记录派生；字段 2（若存在）指明同一稳定角色的较早实例；字段 3 为非零恢复证据摘要，仅作审计保留，不授权恢复重绑。

对上述两种消息，已认证的控制信道主体必须与派生出的 `MemberKey` 一致；V1 信封的源物理节点与运行时实例必须等于节点记录的 `(physical_node_id, node_instance_id)` 或网关记录的 `(hosting_physical_node_id, gateway_instance_id)`。这彻底防止任何已注册节点、网关、源地址或载荷字段冒充其他成员。

### 4.2.2 网关排空授权、栅栏与重放

`DRAIN`（`0x0103`）保持为规范的单作用域 `GatewayDrainRequest`；`DRAIN_COMPUTE`（`0x0106`）采用 `MemberCordonRequest` 载荷形态处理带栅栏的计算成员排空，并拒绝网关目标。传输层在调用接收器前必须认证 `EXECUTOR` 主体；接收器随后向独立配置的管理授权器传入操作类型、已认证执行主体与目标网关。网关自身或节点运行时主体不可替代该管理主体。授权回调缺失、非 `EXECUTOR` 主体或授权拒绝均返回 `UNAUTHORIZED_ROLE`，且不修改控制器状态或结果日志。

`PREPARE` 携带绑定至同一路由操作 ID 的完整后继 `RouteTransaction` 与 `RouteSnapshot`，其成员、拓扑与准入资格版本必须与控制器当前值完全一致。成功后控制器持久化预留后继拓扑代次，且仅递增资格版本。`COMMIT` 与 `ABORT` 省略后继记录，携带相同的准备前成员/拓扑/资格栅栏；控制器在执行前核验 `PREPARE` 已将资格版本精确推进 1 步。`COMMIT` 原子激活后继路由、将目标网关标记为 `DRAINING` 并推进全部三个版本号；`ABORT` 将后继路由记为已中止、保持成员与拓扑版本不变，但保留单步资格失效——由此维持资格版本严格单调，防止在废弃排空期间捕获的准入凭据重新生效。

每次成功操作均按信封 `operation_id` 与语义摘要写入结果日志。若控制器帧已持久化但在写结果日志前崩溃，重试仅在目标、路由操作 ID、动作及精确终态/准备版本号完全匹配时被接受；载荷变化或栅栏过期一律拒绝，接收器绝不单凭目标网关当前状态推断排空匹配。

### 4.2.3 成员隔离授权、栅栏与重放

`CORDON` 携带完整的规范 `MemberCordonRequest` 记录。传输层在调用接收器前必须认证 `EXECUTOR` 主体；接收器调用独立配置的成员管理授权器，而不复用网关排空授权器，因为隔离属于成员准入资格变更而非路由替换决策。回调缺失、非 `EXECUTOR` 主体或授权拒绝均返回 `UNAUTHORIZED_ROLE`，且不产生状态或日志变更。

请求目标必须是已存在的计算节点或网关成员。在控制器线性化点，成员、拓扑与准入资格版本必须等于请求栅栏，且目标处于 `ACTIVE`。成功后持久化将目标记为 `CORDONED`，成员与资格版本各递增 1，拓扑版本不变，并在成员投影上盖章新版本号。若成员日志已落盘但结果日志写入中断，旧栅栏重试仅在目标状态与全部三个后置版本精确一致时被接受，且不再二次递增版本号。常规结果重放仍要求信封 `operation_id`、已认证主体与语义载荷摘要一致；仅控制器级重试会独立重验新请求的授权及目标/栅栏，`reason_code` 仅作审计输入，绝不触发二次状态转换。

### 4.3 清单与路由记录

`PREPARE_MANIFEST`、`ACTIVATE_MANIFEST` 与 `ABORT_MANIFEST` 携带 `canonical-record-schema.md` 定义的精确 `AdmissionParticipantStage` 结构定义；`PREPARE_RESERVATION`、`COMMIT_RESERVATION` 与 `ABORT_RESERVATION` 携带对应的 `AdmissionReservationStage` 结构定义。内嵌候选清单摘要覆盖全部语义字段并遵循自摘要清零规则，避免接收方依据本地可变状态自行构造候选清单、资源预留、运行时投影或激活决策。

`ROUTE_PREPARE` 携带 `canonical-record-schema.md` 定义的精确 `RouteSnapshot` 结构定义。接收方不得将逐字段路由更新视作 V1 路由事务。

## 5. 本地 IPC 与执行器 ABI

规范本地消息族如下：

| 现有类型 | 目标语义操作 | 必需响应 |
| --- | --- | --- |
| `WVM_IPC_TYPE_REGISTER` | 绑定 QEMU 连接角色与身份。 | 含已接受版本与角色的注册 ACK。 |
| `WVM_IPC_TYPE_TYPED_MEM_FAULT` | 经已准入本地节点运行时请求权威页。 | 类型化页数据/状态响应。 |
| `WVM_IPC_TYPE_TYPED_MEM_COMMIT` | 经已准入本地节点运行时提交带操作标识的脏页修改。 | 含权威页版本与状态的类型化提交结果。 |
| `WVM_IPC_TYPE_MEM_FAULT` / `MEM_WRITE` / `COMMIT_DIFF` | 不支持的无类型本地内存路径。 | 直接拒绝，绝不替代类型化已准入路径。 |
| `WVM_IPC_TYPE_COMMIT_DIFF_SYNC` | 完成交接作用域的内存栅栏。 | 绑定操作序号的栅栏结果。 |
| `WVM_IPC_TYPE_CPU_RUN` | 请求本地或远端 vCPU 交接。 | 携带精确状态与上下文的 `wvm_ipc_cpu_run_ack` 后继响应。 |
| `WVM_IPC_TYPE_IRQ` / `INVALIDATE` | 投递类型化 Guest 事件或一致性修正。 | 在影响 Guest 推进处返回显式投递/背压结果。 |
| `WVM_IPC_TYPE_BLOCK_IO` | 向设备权威提交块 I/O 请求。 | 类型化块完成结果。 |
| `PUSH_BARRIER` / `PUSH_BARRIER_ACK` | 兼容性屏障。 | 替换为类型化 VM 作用域栅栏记录。 |
| `RPC_PASSTHROUGH` | 仅作过渡包装。 | 必须声明内嵌类型/长度/版本，禁止盲目透传。 |

节点运行时至执行器 ABI 是上述操作的本地变体，必须包含 VM 身份/`vm_incarnation`、清单与路由代次、`operation_id`、目标执行器角色、取消状态、序/栅栏引用以及类型化完成结果。进程内执行器可采用函数调用实现，但不得省去这些校验，也不得将常规流量串行化为全局同步临界区。

执行器 ABI 携带候选清单摘要、完整必需路由快照键（作用域、拓扑版本、路由代次与快照摘要）以及激活栅栏。这是唯一的已准入格式 ABI，旧格式帧在解码阶段直接拒绝，不保留兼容分支。

本地注册载荷为规范 `LocalRegister` 记录，必填字段包括：`connection_role:u16`、`vm_id:u32`、`vm_incarnation:u64`、`manifest_generation:u64`、候选/已准入清单摘要、`local_runtime_instance_id:u64`、调用方进程实例 ID、能力画像摘要以及请求的本地端点名。注册响应返回兼容 `ControlResult` 的状态以及已接受的角色和本地连接 ID。在注册获批前，本地 QEMU 或执行器连接不得发送任何语义流量。

对于 IOCTL，V1 信封前须前置 24 字节内核上下文前缀 `{context_handle:u64, attach_capability:u8[16]}`。内核在解析信封前先校验上下文与清单角色；该前缀不替代信封中的 VM、实例代次与操作身份字段。

### 5.1 缓冲区所有权与完成上下文

每个公开的发送与分发接口必须明确声明其对缓冲区是借用、拷贝还是转移所有权，何方有权修改或释放缓冲区，以及哪个事件终止该引用。入队成功绝不等同于语义完成。异步完成回调必须保留操作身份与代次，严禁访问已释放或复用的对象。取消与清理流程遵循[生命周期第 6.3 节](runtime-manifest-lifecycle.md#63-跨子系统资源回收)。

接口契约须明确回调所在线程/事件循环、可重入性、允许的阻塞行为与锁约束。调用方不得依赖传输层私有锁或特定回调时机；除非公开契约明确允许双上下文执行，否则原本排队执行的回调不得意外变为同步内联调用。

进程内发布、进程间共享内存、网络投递与设备可见性各自依赖不同的同步机制，须明确声明生产者、传输层与消费方在发布与生命周期上的职责。本地队列上的 release/acquire 内存序并不证明远端内存可见性、设备完成或持久化落盘，这些成功条件归各操作所属业务域判定。

对于热路径，必须说明常规的拷贝次数与进程/网络跳数开销、在途并发上限及批处理策略。应实现有界并行队列以及所需的优先级与公平性调度，避免将所有操作汇聚到单一同步全局分发器。任何传输层替换均须提供可比实测数据并保持操作语义不变，不得仅凭协议名称判定 UDP 或流协议孰优孰劣。

## 6. QoS、尺寸与背压

`qos_level` 仅为调度提示，绝不豁免任何正确性校验。保留对 vCPU 运行/退出与控制 ACK 的快速通道作为常规 QoS 策略，但任何高优先级消息均不得跳过身份、校验和、幂等或序关系检查。

V1 尺寸与分片上限见第 1.5 节；各能力画像还须发布受该协议上限约束的实际本地队列容量与传输限制。分消息类别的背压与排序规则如下：

- 控制、路由、注册、vCPU 运行/退出、必需内存栅栏及持久化块完成均不可丢弃；队列饱和时必须返回类型化有界背压或错误结果。
- 独立页差异与非栅栏 HINT 推送仅在页版本序保持有效的前提下允许批处理或合并；可触发页/订阅者转入 `RESYNC`/`STALE`，绝不可在仍标为有效时静默丢弃。
- 仅允许在不同独立操作键之间乱序；执行器或设备队列必须保持各自规范的 vCPU 或 virtqueue 顺序域。
- 分片与重组承压时须在超出 V1 上限前拒绝新帧，绝不可驱逐部分收齐的语义消息却向上层报告成功。

现有的 `WVM_MAX_PACKET_SIZE` 与 `MTU_SIZE` 仅为实现常量，不构成充分的 ABI 契约。完整 4 KiB 页或大型上下文绝不可依赖偶然的 IP 分片作为正确性保障。

## 7. Mode A IOCTL 边界

Mode A 是同一本地 ABI 的内核加速实现，而非另一套分布式协议。现有 IOCTL 职责归类如下：

| IOCTL | 目标职责 |
| --- | --- |
| `IOCTL_WVM_REMOTE_RUN` | 可选的、绑定上下文的 vCPU 交接加速路径。 |
| `IOCTL_SET_MEM_LAYOUT` | 按 VM 隔离的 QEMU RAM 注册缓存。 |
| `IOCTL_WAIT_IRQ` | 按 VM 隔离的本地中断等待与通知。 |
| `IOCTL_SET_GATEWAY` 及路由、放置、VM ID、epoch 更新 | 仅作派生清单/路由缓存刷新，绝不注入真值。 |
| `IOCTL_RPC_SYNC_ACK` | 拒绝并移除无归属的 ACK 路径；语义栅栏完成必须遵循对应操作所有者的类型化契约。 |

每次 ioctl 与 mmap 均须解析已绑定的 `wvm_kernel_ctx`，并校验 VM 身份、`vm_incarnation`、`manifest_generation` 与生命周期状态。在 `kernel-accelerator.md` 正式验收前，IOCTL 编号与载荷布局均不视为稳定 ABI。

## 8. 兼容性边界

本文定义的 V1 信封与规范结构定义即生产环境的线协议契约。不要求兼容旧版报头、猜测载荷格式、原始 ID 回退、`SYNC_MAGIC`、无类型 ACK 或盲目透传。各端点在激活前直接拒绝不支持的协议或 schema 能力；本地测试夹具须与生产路径采用完全相同的规范记录。

## 9. 验收测试

- 每种受支持消息均具备针对截断、超长、未知版本、CRC 错误、非法标志位及命名空间不匹配输入的解码拒绝测试。
- 本地 QEMU 连接在角色注册成功前无法发送任何语义流量。
- 携带非零 `vm_id` 的报文绝不会回退执行原始路由查找。
- 重复的内存提交、vCPU 运行、块写入与路由准备请求均返回规范定义的幂等结果。
- 超过单数据报安全上限的载荷遵循声明的分片或传输规则，不依赖偶然 IP 分片。
- 每个 V1 网络/本地/控制解码器均能拒绝错误报头长度、错误源身份、错误快照摘要、乱序规范字段、缺失必填字段、同操作 ID 不同摘要以及超限分片。
- 协调器在每条 `PREPARE_*`、`ACTIVATE_*`、`COMMIT_RESERVATION`、`ABORT_*`、`ROUTE_*`、`CORDON` 与 `DRAIN` 消息之后崩溃重启，均能重放唯一已记录结果，不产生孤立预留或半发布路由；在网关排空预留前落盘的未来拓扑路由必须默认安全失败（fail-closed），恢复后不得 ACK 或提交，只能显式中止。
- 故障或退出中的网关绝不会被当作必选后继路由 ACK 等待；所有存活成员的 ACK 均通过独立控制路径获取，否则操作返回有界降级或失败结果。
- QoS 队列在数据面高负载下仍保障高优先级 vCPU/控制流量投递，同时保持有界背压与完整校验。
- KVM、TCG、Mode A 与 Mode B 即使底层捕获或加速机制不同，仍使用等价的本地操作信封。

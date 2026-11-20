# WaveVM 规范记录结构定义（Canonical Record Schema）

状态：规范性实现规范。

本规范适用[文档维护规则](../wavevm-refactor-roadmap.md#文档维护规则)。

范围：控制面、成员管理、路由、准入、清单及本地运行时记录的精确 V1 WVM-TLV 结构定义。本规范补全 `wire-ipc-abi.md` 定义的通用容器；内存、vCPU 与块存储数据面载荷仍沿用各自子系统规范定义的结构定义。

任何实现均不得为本文列出的记录构造第二套 JSON、环境变量或宿主原生结构体作为语义承载形式。可读文本渲染仅用于诊断。

## 子系统边界契约

本节仅索引归属规则，不重复其详细定义。任何边界变更须遵守[架构基线第 0 节](../wavevm-architecture-baseline.md#0-架构权威与维护契约)。

| 边界 | 契约要求 |
| --- | --- |
| 职责与权威 | 本文档负责规范字段、标签、类型、顺序与摘要规则，不负责成员、放置或生命周期决策。语义校验仍归各记录所属域的权威模块。 |
| 状态与变更 | 编解码缓冲区与解码结果由调用方或所属操作持有；编解码器绝不修改资源清册、资源预留、路由表或 VM 状态。完整记录校验通过后方可交由业务域执行状态变更。 |
| 允许的实现依赖 | 共享标量/TLV 原语、有界内存分配与摘要工具。不得依赖运行时/控制器私有结构、在解码期间回调策略逻辑，或引入第二套 JSON/原生布局 schema。 |
| 交互与生命周期 | [线协议容器](wire-ipc-abi.md#13-wvm-envelope-v1)提供分帧，本文档提供记录体。公开的编解码 API 必须声明拷贝/借用所有权与结果生命周期；域语义校验须在解码成功后执行。 |
| 并发与开销 | 独立记录必须支持并发编解码。须对字节数、嵌套深度/列表计数、工作区与大块拷贝施加界限；禁止在操作间共享全局编解码工作区。 |
| 故障与验证 | 按第 1 节与第 3 节原子拒绝畸形记录，并通过[Schema 一致性要求](#5-schema-一致性要求)验证；规范编码合法不等同于已获授权或准入。 |

## 1. 通用编码规则

每条记录均采用 `wire-ipc-abi.md` 定义的 `CanonicalRecord` 与 `CanonicalField`，且 `schema_version=1`。所有存在的字段必须按 `field_tag` 严格升序排列且仅出现一次。V1 中 `field_flags` 恒为零。标记为可选（`?`）的字段缺失时直接省略；除非本文明确指定，省略字段无隐式默认值。出现未知字段、重复字段、乱序字段、长度错误或非法枚举值时，必须在产生任何状态变更前整条拒绝。

标量类型别名定义如下：

| 别名 | 规范编码值 |
| --- | --- |
| `U8`、`U16`、`U32`、`U64` | 精确位宽的无符号大端整数。 |
| `Bool` | `U8`，取值严格为 `0` 或 `1`。 |
| `ID16`、`Digest32` | 精确 16 字节或 32 字节原始字节序列。 |
| `Addr` | 精确 4 字节 IPv4 地址或 16 字节 IPv6 地址。 |
| `Text<N>` | UTF-8 字符串，长度在 `1..N` 字节之间，禁止包含 NUL 字节。 |
| `Record<T>` | 类型 `T` 的完整规范字节序列。 |
| `List<T, key>` | `U32 count`，后接 `count` 组 `U32 element_bytes` 与单个规范标量值或完整 `T` 记录，按声明的 `key` 严格升序排列且无重复键。 |
| `Set<T, key>` | 元素无位置语义的 `List<T, key>`。 |

本文中所有整数范围均含上下界。`vm_id=0` 保留给经过认证的集群级控制记录；VM 记录取值为 `1..UINT32_MAX`。时间戳使用 `U64 unix_time_ms`，时长与保留窗口使用 `U64 milliseconds`。

### 1.1 摘要计算规则

记录摘要为完整规范字节序列（含 8 字节记录头）的 SHA-256。由于记录无法对自身最终摘要字节求哈希，计算自摘要字段时须先将该字段编码为 32 字节全零，计算完成后仅在传输或持久化记录中填入最终摘要值。接收方须先将该精确字段清零再重新计算校验。

V1 规范中的自摘要字段如下：

- `AdmissionEligibilityFence.tag=9`（`fence_digest`）。
- `PlacementPlan.tag=1`（`plan_digest`）。
- `CandidateVmManifest.tag=3`（`manifest_digest`）。
- 单个 `RouteSnapshot` 中所有内嵌 `RouteSnapshotKey` 的 `snapshot_digest` 字段——前提是该键的 `{scope_key, topology_revision, route_generation}` 与该快照 `RouteSnapshot.tag=1` 的身份一致。这既包含顶层键，也包含其必选/可选 ACK 集合中同代次的 `RequiredAckEntry.expected_snapshot_key` 引用。前驱键及指向其他身份的键保留其最终摘要不变。

前驱 `RouteSnapshotKey`、其他记录中的路由键以及所有普通摘要字段均携带其最终非零摘要，并在计算外层记录摘要时原样计入。

## 2. 记录注册表

下表穷举了 V1 规范的全部控制面记录。字段列采用 `tag:type:name` 格式，`?` 表示可选字段；嵌套记录与列表遵循第 1 节规则。

V1 枚举注册表：

| 字段族 | 合法取值 |
| --- | --- |
| `data_transport` | `1=UDP`, `2=QUIC_DATAGRAM`。 |
| `control_transport` | `1=UNIX_STREAM`, `2=TLS_TCP`, `3=QUIC_STREAM`。 |
| `role_type` | `1=NODE_RUNTIME`, `2=GATEWAY`, `3=QEMU_FRONTEND`, `4=EXECUTOR`, `5=KERNEL_CONTEXT`。 |
| membership state | `1=PENDING`, `2=VALIDATING`, `3=PREPARED`, `4=ACTIVE`, `5=CORDONED`, `6=DRAINING`, `7=REMOVED`, `8=FAILED`。 |
| health state | `1=HEALTHY`, `2=SUSPECT`, `3=UNREACHABLE`, `4=RECOVERING`。 |
| backend / backend policy | Backend: `1=KVM`, `2=TCG`。Policy: `1=AUTO`, `2=REQUIRE_KVM`, `3=REQUIRE_TCG`。 |
| accelerator policy | `1=DISABLED`, `2=PREFER_KERNEL_ACCEL`, `3=REQUIRE_KERNEL_ACCEL`。 |
| placement policy | `1=COMPACT`, `2=SPREAD`。 |
| host constraint kind | `1=PHYSICAL_NODE`, `2=FAILURE_DOMAIN`, `3=CAPABILITY`, `4=LABEL`。 |
| host constraint operator | `1=EQUALS`, `2=NOT_EQUALS`。 |
| guest topology policy | `1=FLAT`, `2=PLACEMENT_NUMA`, `3=SYNTHETIC_NUMA`。 |
| namespace ABI | `1=LEGACY`, `2=V1_U32`。 |
| reservation state | `1=PREPARED`, `2=COMMITTED`, `3=RELEASING`, `4=RELEASED`。 |
| activation decision | `1=ACTIVATE`, `2=ABORT`。 |
| startup dependency kind | `1=REQUIRED_MEMBER`。 |
| capability state | `1=UNPROBED`, `2=PROBING`, `3=AVAILABLE`, `4=UNAVAILABLE`, `5=DEGRADED`。 |
| capability ID | `1=EXECUTION_KVM`, `2=EXECUTION_TCG`, `3=MODE_B_MEMORY`, `4=V1_VM_ID_U32`, `5=KERNEL_ACCELERATION`。 |
| route topology kind | `1=FLAT`, `2=FRACTAL`。 |
| route transaction state | `1=PREPARING`, `2=ACTIVATED`, `3=RETIRING`, `4=RETIRED`, `5=ABORTED`。 |
| gateway drain action | `1=PREPARE`, `2=COMMIT`, `3=ABORT`。 |

| 类型码 | 记录名 | 字段定义 |
| --- | --- | --- |
| `0x1001` | `Endpoint` | `1:U16:data_transport`, `2:Addr:data_address`, `3:U16:data_port`, `4:U16:control_transport`, `5:Addr:control_address?`, `6:U16:control_port`, `7:Text<253>:server_name?`, `8:Text<107>:control_socket_path?` |
| `0x1002` | `MemberKey` | `1:U16:role_type`, `2:U32:role_id`, `3:U64:instance_id` |
| `0x1003` | `VmRouteScopeKey` | `1:U32:vm_id`, `2:U64:vm_incarnation`, `3:U64:route_scope_id` |
| `0x1004` | `RouteSnapshotKey` | `1:Record<VmRouteScopeKey>:scope_key`, `2:U64:topology_revision`, `3:U64:route_generation`, `4:Digest32:snapshot_digest` |
| `0x1005` | `CapabilityRef` | `1:U32:physical_node_id`, `2:U64:node_instance_id`, `3:U64:profile_generation`, `4:Digest32:profile_digest` |
| `0x1006` | `RequiredMember` | `1:Record<MemberKey>:member_key`, `2:U32:physical_node_id`, `3:U64:failure_domain_id`, `4:Record<CapabilityRef>:capability`, `5:U16:required_state` |
| `0x1007` | `RequiredAckEntry` | `1:Record<MemberKey>:member_key`, `2:Record<Endpoint>:endpoint`, `3:U16:role_type`, `4:Record<RouteSnapshotKey>:expected_snapshot_key` |
| `0x1008` | `RequiredAckSet` | `1:List<RequiredAckEntry, member_key>:entries`, `2:Digest32:entries_digest` |
| `0x1009` | `RouteRule` | `1:U16:destination_kind`, `2:U64:destination_scope`, `3:U32:destination_vnode_or_endpoint`, `4:U16:next_hop_kind`, `5:Record<MemberKey>:next_hop_member`, `6:Record<Endpoint>:next_hop_endpoint`, `7:U16:hop_limit` |
| `0x100a` | `RouteSnapshot` | `1:Record<RouteSnapshotKey>:route_snapshot_key`, `2:U64:membership_revision`, `3:U16:topology_kind`, `4:List<RouteRule, destination_kind/destination_scope/destination_vnode_or_endpoint>:next_hop_rules`, `5:Record<RequiredAckSet>:required_ack_set`, `6:Record<RouteSnapshotKey>:predecessor_snapshot_key?`, `7:U64:operation_retention_horizon_ms`, `8:U16:retirement_policy` |
| `0x100b` | `NodeInventory` | `1:U32:physical_node_id`, `2:U64:node_instance_id`, `3:U64:failure_domain_id`, `4:U64:inventory_revision`, `5:U32:registered_vcpu_slots`, `6:U64:registered_memory_bytes`, `7:U32:reserved_host_cpu_slots`, `8:U64:reserved_host_memory_bytes`, `9:U32:reserved_gateway_cpu_slots`, `10:U64:reserved_gateway_memory_bytes`, `11:List<U32, value>:hosted_gateway_role_ids`, `12:U32:allocatable_vcpu_slots`, `13:U64:allocatable_memory_bytes`, `14:Digest32:storage_capabilities_digest`, `15:Digest32:accelerator_fault_capabilities_digest`, `16:Digest32:exclusive_resource_inventory_digest` |
| `0x100c` | `NodeRecord` | `1:U32:physical_node_id`, `2:U64:node_instance_id`, `3:U64:failure_domain_id`, `4:Record<Endpoint>:control_endpoint`, `5:Record<Endpoint>:sidecar_endpoint`, `6:U64:role_bits`, `7:U64:pod_id`, `8:U32:local_vnode_first`, `9:U32:local_vnode_count`, `10:Record<NodeInventory>:inventory`, `11:Record<CapabilityRef>:capability`, `12:U16:desired_membership_state`, `13:U16:observed_health_state`, `14:U64:membership_revision`, `15:U64:topology_revision`, `16:U64:physical_host_id`, `17:Record<NodeInstanceNamespace>:node_instance_namespace` |
| `0x100d` | `GatewayRecord` | `1:U32:gateway_id`, `2:U64:gateway_instance_id`, `3:U32:hosting_physical_node_id`, `4:U64:failure_domain_id`, `5:Record<Endpoint>:endpoint`, `6:U64:role_bits`, `7:U64:pod_id_or_scope`, `8:List<U32, value>:parent_gateway_ids`, `9:List<U32, value>:child_gateway_ids`, `10:U16:desired_membership_state`, `11:U16:observed_health_state`, `12:U64:membership_revision`, `13:U64:topology_revision` |
| `0x100e` | `AdmissionEligibilityFence` | `1:ID16:admission_tx_id`, `2:U64:membership_revision`, `3:U64:topology_revision`, `4:U64:inventory_revision`, `5:U64:capability_profile_generation`, `6:List<RequiredMember, member_key>:selected_members`, `7:Record<VmRouteScopeKey>:required_route_scope_key`, `8:Digest32:required_ack_set_digest`, `9:Digest32:fence_digest`, `10:U64:admission_eligibility_revision` |
| `0x100f` | `VcpuAssignment` | `1:U32:guest_vcpu_index`, `2:U32:executor_physical_node_id`, `3:U16:backend`, `4:U16:executor_class`, `5:U32:executor_slot`, `6:ID16:reservation_id` |
| `0x1010` | `MemoryChunkAssignment` | `1:U64:gpa_start`, `2:U64:bytes`, `3:U32:directory_physical_node_id`, `4:U32:executor_physical_node_id`, `5:U16:consistency_policy`, `6:ID16:reservation_id` |
| `0x1011` | `StorageAssignment` | `1:U32:device_index`, `2:U32:storage_physical_node_id`, `3:U16:backend_kind`, `4:ID16:reservation_id`, `5:Digest32:device_contract_digest` |
| `0x1012` | `ExclusiveLease` | `1:U16:lease_kind`, `2:Text<255>:lease_name`, `3:U64:lease_generation` |
| `0x1013` | `ResourceReservation` | `1:ID16:reservation_id`, `2:Digest32:plan_digest`, `3:Digest32:candidate_manifest_digest`, `4:ID16:admission_tx_id`, `5:Digest32:eligibility_fence_digest`, `6:U32:vm_id`, `7:U64:vm_incarnation`, `8:U32:physical_node_id`, `9:U64:node_instance_id`, `10:U64:inventory_revision`, `11:U32:guest_vcpu_slots`, `12:U64:guest_memory_bytes`, `13:U32:overhead_vcpu_slots`, `14:U64:overhead_memory_bytes`, `15:List<ExclusiveLease, lease_kind/lease_name>:exclusive_leases`, `16:U16:state`, `17:U64:prepared_expiry_unix_time_ms?`, `18:ID16:activation_fence?` |
| `0x1014` | `PlacementPlan` | `1:Digest32:plan_digest`, `2:ID16:admission_tx_id`, `3:Digest32:eligibility_fence_digest`, `4:U64:inventory_revision`, `5:U64:membership_revision`, `6:U64:topology_revision`, `7:U64:capability_profile_generation`, `8:U32:host_node`, `9:List<VcpuAssignment, guest_vcpu_index>:vcpu_assignments`, `10:List<MemoryChunkAssignment, gpa_start>:memory_assignments`, `11:List<StorageAssignment, device_index>:storage_assignments`, `12:List<ReservationRequirement, reservation_id>:reservation_requirements`, `13:Record<GuestTopology>:guest_topology`, `14:Record<VmRouteScopeKey>:route_scope_key` |
| `0x1015` | `VmRequest` | `1:U16:api_version`, `2:ID16:request_id`, `3:Text<255>:display_name?`, `4:U32:requested_vcpus`, `5:U64:requested_memory_bytes`, `6:U16:execution_backend_policy`, `7:U16:accelerator_policy`, `8:U16:placement_policy`, `9:List<HostConstraint, constraint_kind/subject/operator/value>:host_constraints`, `10:U16:guest_topology_policy`, `11:Record<ConsistencyPolicy>:consistency_policy`, `12:Record<StorageDevicePlan>:storage_device_plan`, `13:Record<LifecyclePolicy>:lifecycle_policy` |
| `0x1016` | `MachineConfig` | `1:Text<32>:architecture`, `2:Text<64>:machine_type`, `3:U32:qemu_compat_version`, `4:U16:firmware_policy` |
| `0x1017` | `GuestTopology` | `1:U16:topology_policy`, `2:U32:guest_numa_nodes`, `3:Digest32:topology_layout_digest?` |
| `0x1018` | `ExecutionFaultProfile` | `1:U16:backend`, `2:U32:context_schema_version`, `3:U16:dirty_capture_engine`, `4:U16:read_fault_engine`, `5:U16:invalidation_engine`, `6:U64:kernel_accelerator_bits`, `7:List<CapabilityRef, physical_node_id>:per_node_capabilities`, `8:Digest32:supported_memory_policies_digest`, `9:U16:fallback_decision` |
| `0x1019` | `ConsistencyPolicy` | `1:U32:dirty_batch_size`, `2:U16:handoff_commit_policy`, `3:U16:subscriber_delivery_policy`, `4:U64:max_commit_latency_ms` |
| `0x101a` | `StorageDevicePlan` | `1:List<StorageAssignment, device_index>:assignments`, `2:Digest32:qemu_device_configuration_digest` |
| `0x101b` | `LocalNameNamespace` | `1:Text<128>:namespace`, `2:Digest32:derivation_salt_digest`, `3:U64:name_generation` |
| `0x101c` | `LifecyclePolicy` | `1:U16:start_policy`, `2:U16:failure_policy`, `3:U64:completion_query_horizon_ms`, `4:U64:route_retention_horizon_ms` |
| `0x101d` | `CandidateVmManifest` | `1:ID16:manifest_id`, `2:U16:manifest_schema_version`, `3:Digest32:manifest_digest`, `4:U32:vm_id`, `5:U64:vm_incarnation`, `6:U64:manifest_generation`, `7:ID16:request_id`, `8:ID16:admission_tx_id`, `9:Digest32:eligibility_fence_digest`, `10:U64:candidate_created_at`, `11:Record<MachineConfig>:guest_machine`, `12:Record<GuestTopology>:guest_topology`, `13:Record<ExecutionFaultProfile>:execution_plan`, `14:Record<ConsistencyPolicy>:consistency_policy`, `15:Record<StorageDevicePlan>:storage_device_plan`, `16:U32:host_node`, `17:List<VcpuAssignment, guest_vcpu_index>:vcpu_placements`, `18:List<MemoryChunkAssignment, gpa_start>:memory_placements`, `19:List<RequiredMember, member_key>:required_members`, `20:List<CapabilityRef, physical_node_id>:required_capabilities`, `21:List<ReservationRequirement, reservation_id>:reservation_requirements`, `22:Record<VmRouteScopeKey>:route_scope_key`, `23:Record<RouteSnapshotKey>:prepared_route_snapshot_key`, `24:Digest32:plan_digest`, `25:Record<LocalNameNamespace>:local_name_namespace`, `26:Record<LifecyclePolicy>:lifecycle_policy`, `27:U16:namespace_abi` |
| `0x101e` | `NodeRuntimeManifest` | `1:Digest32:candidate_manifest_digest`, `2:U32:vm_id`, `3:U64:vm_incarnation`, `4:U64:manifest_generation`, `5:ID16:admission_tx_id`, `6:Digest32:eligibility_fence_digest`, `7:ID16:activation_fence?`, `8:U32:physical_node_id`, `9:U64:expected_node_instance_id`, `10:U64:local_role_bits`, `11:List<VcpuAssignment, guest_vcpu_index>:local_vcpu_assignments`, `12:List<MemoryChunkAssignment, gpa_start>:local_memory_assignments`, `13:List<StorageAssignment, device_index>:local_storage_assignments`, `14:Record<RouteSnapshotKey>:required_route_snapshot_key`, `15:Record<LocalNameNamespace>:local_names`, `16:Record<ExecutionFaultProfile>:negotiated_profile`, `17:ID16:reservation_id`, `18:List<StartupDependency, dependency_kind/member_key>:startup_dependencies`, `19:Record<NodeRuntimeLaunchPlan>:launch_plan` |
| `0x101f` | `ActivationRecord` | `1:ID16:admission_tx_id`, `2:Digest32:candidate_manifest_digest`, `3:ID16:activation_fence?`, `4:U64:coordinator_instance_id`, `5:Digest32:required_participant_set_digest`, `6:List<RouteSnapshotKey, scope_key/topology_revision/route_generation>:required_route_snapshot_keys`, `7:U16:decision`, `8:U64:durable_decision_sequence`, `9:U64:decided_at` |
| `0x1020` | `RouteTransaction` | `1:ID16:operation_id`, `2:Record<RouteSnapshotKey>:route_snapshot_key`, `3:Record<RouteSnapshotKey>:predecessor_snapshot_key?`, `4:Record<RequiredAckSet>:required_ack_set`, `5:List<RequiredAckEntry, member_key>:optional_departure_drain_set`, `6:U64:operation_retention_horizon_ms`, `7:U16:state` |
| `0x1021` | `CapabilityLimit` | `1:U16:limit_kind`, `2:U64:value` |
| `0x1022` | `CapabilityConstraint` | `1:U16:constraint_kind`, `2:U16:state`, `3:Text<255>:detail` |
| `0x1023` | `CapabilityRecord` | `1:U16:capability_id`, `2:U16:capability_schema_version`, `3:U32:physical_node_id`, `4:U64:node_instance_id`, `5:U64:provider_instance_id`, `6:U16:state`, `7:U32:abi_version`, `8:U64:feature_bits`, `9:List<CapabilityLimit, limit_kind>:limits`, `10:List<CapabilityConstraint, constraint_kind>:constraints`, `11:U64:observed_at`, `12:ID16:probe_operation_id`, `13:U16:reason_code` |
| `0x1024` | `HostConstraint` | `1:U16:constraint_kind`, `2:U16:operator`, `3:Text<128>:subject`, `4:Text<255>:value` |
| `0x1025` | `StartupDependency` | `1:U16:dependency_kind`, `2:Record<MemberKey>:member_key`, `3:U16:required_state`, `4:Digest32:dependency_digest` |
| `0x1026` | `ReservationRequirement` | `1:ID16:reservation_id`, `2:U32:physical_node_id`, `3:U64:node_instance_id`, `4:U64:inventory_revision`, `5:U32:guest_vcpu_slots`, `6:U64:guest_memory_bytes`, `7:U32:overhead_vcpu_slots`, `8:U64:overhead_memory_bytes`, `9:List<ExclusiveLease, lease_kind/lease_name>:exclusive_leases` |
| `0x1027` | `AdmissionTransaction` | `1:ID16:request_id`, `2:Digest32:request_digest`, `3:U32:vm_id`, `4:U64:vm_incarnation`, `5:U64:manifest_generation`, `6:ID16:admission_tx_id`, `7:ID16:manifest_id`, `8:Record<VmRouteScopeKey>:route_scope_key`, `9:U16:lifecycle_state`, `10:Digest32:candidate_manifest_digest?`, `11:Digest32:activation_record_digest?`, `12:U64:transaction_sequence` |
| `0x1028` | `RuntimeDispatchProjection` | `1:Digest32:candidate_manifest_digest`, `2:U32:vm_id`, `3:U64:vm_incarnation`, `4:U64:manifest_generation`, `5:U32:physical_node_id`, `6:U64:expected_node_instance_id`, `7:ID16:activation_fence`, `8:Record<RouteSnapshotKey>:required_route_snapshot_key`, `9:U16:route_topology_kind`, `10:U16:local_destination_kind`, `11:U64:local_destination_scope`, `12:U32:local_destination_vnode`, `13:Record<Endpoint>:local_sidecar_endpoint`, `14:List<(U32 guest_vcpu_index,U16 executor_destination_kind,U64 executor_destination_scope,U32 executor_destination_vnode), guest_vcpu_index>:cpu_dispatch`, `15:List<(U64 gpa_start,U64 bytes,U16 directory_destination_kind,U64 directory_destination_scope,U32 directory_destination_vnode,U16 executor_destination_kind,U64 executor_destination_scope,U32 executor_destination_vnode,U32 directory_physical_node_id,U64 directory_node_instance_id,U16 consistency_policy), gpa_start>:memory_dispatch` |
| `0x1029` | `NodeRuntimeLaunchPlan` | `1:U16:plan_version`, `2:U16:node_runtime_data_port`, `3:U16:node_runtime_control_port`, `4:U16:local_executor_service_port`, `5:U16:local_executor_control_port`, `6:U32:executor_worker_count`, `7:U32:sync_batch_size`, `8:U64:guest_total_memory_bytes`, `9:Record<MachineConfig>:guest_machine`, `10:Record<ConsistencyPolicy>:consistency_policy`, `11:U32:vcpu_handoff_record_capacity` |
| `0x102a` | `RejoinMemberRequest` | `1:Record<NodeRecord or GatewayRecord>:member_record`, `2:Record<MemberKey>:prior_member_key?`, `3:Digest32:recovery_evidence_digest` |
| `0x102b` | `GatewayDrainRequest` | `1:U16:action`, `2:Record<MemberKey>:target_gateway_member_key`, `3:U64:expected_membership_revision`, `4:U64:expected_topology_revision`, `5:U64:expected_admission_eligibility_revision`, `6:Record<RouteTransaction>:successor_transaction?`, `7:Record<RouteSnapshot>:successor_snapshot?`, `8:ID16:route_operation_id` |
| `0x102c` | `MemberCordonRequest` | `1:Record<MemberKey>:target_member_key`, `2:U64:expected_membership_revision`, `3:U64:expected_topology_revision`, `4:U64:expected_admission_eligibility_revision`, `5:U16:reason_code` |
| `0x102d` | `AdmissionReservationStage` | `1:Record<CandidateVmManifest>:candidate`, `2:Record<ResourceReservation>:reservation`, `3:Record<ActivationRecord>:activation?`, `4:U16:abort_reason?` |
| `0x102e` | `AdmissionParticipantStage` | `1:Record<CandidateVmManifest>:candidate`, `2:Record<NodeRuntimeManifest>:runtime_manifest`, `3:Record<ActivationRecord>:activation?`, `4:U16:abort_reason?` |
| `0x102f` | `CapabilityReport` | `1:U64:profile_generation`, `2:List<CapabilityRecord, capability_id/provider_instance_id>:records` |
| `0x1030` | `NodeRuntimeProfile` | `1:U32:physical_node_id`, `2:U64:node_instance_id`, `3:U64:inventory_revision`, `4:U64:capability_profile_generation`, `5:U64:runtime_profile_generation`, `6:U16:node_runtime_control_port`, `7:U16:local_executor_control_port`, `8:U32:executor_worker_count`, `9:U32:sync_batch_size`, `10:U32:vcpu_handoff_record_capacity`, `11:List<U16>:node_runtime_data_ports`, `12:List<U16>:local_executor_service_ports`, `13:U64:physical_host_id`, `14:Record<NodeInstanceNamespace>:node_instance_namespace` |
| `0x1031` | `NodeInstanceNamespace` | `1:Text<128>:namespace`, `2:Digest32:derivation_salt_digest`, `3:U64:name_generation` |
| `0x1032` | `ClusterAdmissionProof` | `1:ID16:operation_id`, `2:Record<MemberKey>:member_key`, `3:U64:membership_revision`, `4:U64:topology_revision`, `5:U64:admission_eligibility_revision`, `6:Digest32:canonical_member_record_digest`, `7:Digest32:capability_evidence_digest`, `8:Digest32:topology_assignment_digest`, `9:Record<ClusterAdmissionAckSet>:required_ack_set` |
| `0x1033` | `ClusterAdmissionAckEntry` | `1:Record<MemberKey>:member_key`, `2:Record<Endpoint>:endpoint`, `3:U16:role_type` |
| `0x1034` | `ClusterAdmissionAckSet` | `1:List<ClusterAdmissionAckEntry, member_key>:entries` |

## 3. 跨记录约束

- `Endpoint.data_transport` 与 `Endpoint.control_transport` 必须从传输枚举注册表中显式选取，且 `data_port` 与 `control_port` 均非零。`control_address` 省略时仅默认回退到已存在的 `data_address`，不得回退到无关主机名或报文源地址。`UNIX_STREAM` 端点要求携带绝对路径 `control_socket_path`（文件系统 Unix 套接字路径，上限 107 UTF-8 字节），网络流传输则必须拒绝该字段；该路径不可替代 `server_name`，也不使远端节点变为本地可达。
- `RequiredAckSet.entries_digest` 为完整 `entries` 列表值的 SHA-256。当该集合内嵌于 `RouteSnapshot` 中时，凡 `expected_snapshot_key` 指向外层快照本身的表项，均须先将 `snapshot_digest` 置零，再计算此列表哈希与外层快照自摘要；实际传输的表项仍携带最终快照摘要。独立 ACK 集合或路由事务中的 ACK 集合直接保留最终期望键摘要。`RouteSnapshot.required_ack_set` 必须与准备该快照的事务及资格栅栏摘要一致。
- `RuntimeDispatchProjection` 是由单个已准入 `CandidateVmManifest`、已激活 `NodeRuntimeManifest`、规范节点记录集和不可变路由快照共同派生的节点本地分发缓存，不是独立的放置、成员或路由权威。其候选摘要、节点实例、激活栅栏与路由快照键必须与本地节点运行时接受的清单完全一致。其拓扑类型以及所有本地、CPU、目录和执行器目标均为完整 V1 路由键：Flat 目标使用 `{FLAT_VNODE, 0, vnode}`，Fractal 目标使用 `{FRACTAL_VNODE, pod_or_prefix, vnode}`。发布、加载或查找此投影时不得丢弃路由作用域。每条内存映射还须保留所选页目录的物理节点与节点实例权威信息，接收内存 ACK 安装权威页前必须核验匹配。
- 生产分发消费端必须接受受支持的完整 Flat/Fractal 路由键，或在激活前拒绝不支持的投影。仅支持 Flat 的适配器不得拍平层级路由、猜测端点或另起独立的生产启动路径。
- `CandidateVmManifest.execution_plan.backend` 与每条 `PlacementPlan.vcpu_assignments[].backend` 必须一致。单个已准入 VM 实例代次只能统一使用 KVM 或统一使用 TCG，严禁混用 vCPU 后端。`VmRequest.execution_backend_policy=AUTO` 按 KVM 优先解析，仅可在激活前生成新的 TCG 计划，并由 `fallback_decision` 记录结果及诊断原因。`MemoryChunkAssignment` 不含 KVM/TCG 后端字段，因为内存放置在满足所选内存能力/画像及路由约束的前提下与执行后端无关。
- `GatewayDrainRequest.target_gateway_member_key` 必须是 `GATEWAY` 键，三个期望版本号均为非零精确栅栏。字段 6 与字段 7 仅在 `action=PREPARE` 时存在，在 `COMMIT` 与 `ABORT` 时必须省略。准备事务的 `operation_id` 必须等于字段 8，事务与快照的键必须一致，且后继快照的 `membership_revision` 必须等于字段 3。后继材料必须是完整的不可变替换路由，而非对网关可变缓存状态的引用。
- `MemberCordonRequest.target_member_key` 必须是 `NODE_RUNTIME` 或 `GATEWAY` 键，三个期望版本号均为非零精确栅栏，`reason_code` 为非零且实现无关的审计码。隔离（cordon）操作使成员版本与准入资格版本各递增 1，保持拓扑版本不变，且仅允许将 `ACTIVE` 成员转为 `CORDONED`；使用旧栅栏重试仅在目标已处于 `CORDONED` 且三个后置版本号完全匹配时接受。
- `RouteSnapshotKey.snapshot_digest` 仅在标识外层 `RouteSnapshot` 时作为自摘要处理：先按第 1.1 节清零所有自引用，计算后将最终摘要回填至每一处自引用。这既避免哈希环，又确保每个 ACK 表项精确绑定最终快照键。前驱或无关快照键不得清零。
- `GatewayRecord.hosting_physical_node_id` 必须指向已存在的 `NodeRecord`。共置部署的网关其 `failure_domain_id` 须与宿主节点故障域一致；仅当网关托管于独立注册的外部网关宿主机时，才允许使用不同的故障域值。
- `NodeRecord.physical_host_id` 是用于关联故障域与聚合资源核算的稳定物理主机组标识。多个计算节点记录与网关记录可共享同一 `physical_host_id`，但 `physical_node_id` 在每个资源提供者维度保持唯一。`physical_host_id` 绝不由 IP 地址、主机名或端点相等性推导。
- `NodeRecord.node_instance_namespace` 与 `NodeRuntimeProfile.node_instance_namespace` 必须一致。分配给节点实例的每个端点、端口池表项、本地 Unix 套接字、共享内存名、日志路径与临时路径均须受该命名空间与显式租约所有者约束。宿主机范围内出现重复端口/路径或缺失实例参数时直接拒绝注册或准入；硬编码默认值不可作为生产输入。
- `AdmissionEligibilityFence.selected_members` 是计划所用的完整成员集合。计划的每个参与者、路由 ACK 成员、资源预留所有者、QEMU 宿主机与执行器均须以精确的实例 ID 与能力摘要出现在该集合中。
- `PlacementPlan` 与 `CandidateVmManifest` 必须描述一致的身份、栅栏、宿主机、分配方案、预留需求/ID 以及路由作用域。每个 Guest vCPU 索引恰好出现一次；内存分配须页对齐、互不重叠，且精确覆盖全部请求内存。
- `CandidateVmManifest.plan_digest` 必须等于完整放置计划的摘要。`namespace_abi=V1_U32` 要求所有选定参与者均已声明 `WVM_CAP_VM_ID_U32`；`LEGACY` 要求 `vm_id <= 255`。
- `LocalNameNamespace.derivation_salt_digest` 必须在 `CandidateVmManifest.manifest_digest` 之前，依据已分配的 `manifest_id`、`admission_tx_id`、VM 身份/代次及目标物理节点计算得出。最终候选摘要用于校验生成结果，不得反过来作为同一命名空间派生的输入。
- `ReservationRequirement` 是不可变的计划/候选输入，在父记录自摘要定型前即确定预留 ID、期望节点/清册版本、容量额度及独占租约。`ResourceReservation` 仅在最终计划摘要与候选摘要确定后派生，并须与某条需求精确匹配。这既避免了计划/候选之间的自引用环，又保持了预留与清单的持久化绑定。
- `NodeRuntimeManifest` 在候选摘要定型后派生，其内部携带该候选摘要，但自身摘要不纳入候选清单字段，从而避免候选清单与节点清单之间的哈希环。
- `ResourceReservation` 仅可通过 `COMMIT_RESERVATION` 操作配合匹配的 `ActivationRecord` 从 `PREPARED` 转为 `COMMITTED`。该转换前必须省略 `activation_fence`，转换后则必填。
- `ActivationRecord.decision=ACTIVATE` 必填 `activation_fence`，代表持久化的准入决策；`ActivationRecord.decision=ABORT` 省略 `activation_fence`，且仅在尚无持久化激活栅栏时合法。`COMMITTED` 则是后续生命周期状态，须在全部必需参与者提升确认完成后方可到达。
- `AdmissionReservationStage` 与 `AdmissionParticipantStage` 仅为信封载荷载体，不具备独立准入权威。`PREPARE_*` 携带 `PREPARED` 预留或未激活的运行时投影，且同时省略字段 3 与字段 4；`COMMIT_RESERVATION` 携带已提交预留与精确的持久化 `ACTIVATE` 记录；`ACTIVATE_MANIFEST` 携带含激活栅栏的运行时投影与同一 `ACTIVATE` 记录；`ABORT_*` 携带未激活对象与非零且实现无关的中止原因，且不含激活记录。每条内嵌候选清单均须与预留/投影的身份、事务、候选摘要、资格栅栏和 VM 身份严格一致。
- `NodeRuntimeManifest` 是单个候选清单的过滤投影，仅包含归属 `physical_node_id` 的分配项；其 `candidate_manifest_digest`、路由键、能力画像与预留 ID 须与权威候选清单匹配。其 `launch_plan` 由控制器选定：机型与一致性字段与候选清单完全一致，Guest 总内存等于已准入放置总和，本地执行器端口属于本地实现参数而非路由或成员身份。
- 控制面持久化投影集须为候选清单中的每条 `ReservationRequirement` 保存恰好一条已激活的 `NodeRuntimeManifest`，按候选摘要、物理节点、期望节点实例与预留 ID 联合索引。完全一致的规范重放具备幂等性，冲突重复项直接拒绝。生命周期进入 `COMMITTED` 必须具备该完整持久化集合及匹配的持久化 `ACTIVATE` 栅栏，而不仅依赖内存态投影。
- `StartupDependency.dependency_digest` 为规范 `StartupDependency` 记录将 tag 4 置为 32 字节全零后的 SHA-256，最终记录填入该计算值。节点运行时据此将本地准备好的对端状态证据精确绑定到依赖记录。
- `CapabilityRef.profile_digest` 是依次对 `WVM-CAPABILITY-PROFILE-V1`、大端 `physical_node_id`、`node_instance_id`、`profile_generation`、记录计数以及该节点完整且严格排序的 `CapabilityRecord` 集合各条摘要计算得到的 SHA-256，集合按 `(capability_id, provider_instance_id)` 升序排列。能力画像同时包含不可用/降级与可用证据；调度器仅从匹配画像中选用所需的 `AVAILABLE` 记录。
- 在无独立注册子进程时，V1 成员键派生规则如下：计算节点 `NodeRecord` 映射为 `{role_type=NODE_RUNTIME, role_id=physical_node_id, instance_id=node_instance_id}`；网关 `GatewayRecord` 映射为 `{role_type=GATEWAY, role_id=gateway_id, instance_id=gateway_instance_id}`。QEMU、执行器与内核进程身份仅在清单准备阶段创建，不得替换进入路由 ACK 集合。
- `RejoinMemberRequest.member_record` 唯一决定新成员键，绝不接受调用方另行指定的当前身份。当 `prior_member_key` 存在时，其 `role_type` 与稳定 `role_id` 须与新派生键一致，但 `instance_id` 必须不同。`recovery_evidence_digest` 仅为非零审计证据，不能将运行中的 V1 VM、路由、资源预留或运行时清单重新绑定到新实例。

## 4. 规范示例

以下双节点 VM 为可读的规范测试夹具：

```text
VmRequest:
  request_id: 00000000000000000000000000000001
  requested_vcpus: 2
  requested_memory_bytes: 4194304
  backend: REQUIRE_TCG
  placement: SPREAD

CandidateVmManifest:
  vm_id: 256
  vm_incarnation: 1
  host_node: 1
  vcpu_placements: [ { index: 0, executor: 1 }, { index: 1, executor: 2 } ]
  memory_placements:
    [ { gpa_start: 0, bytes: 2097152, directory: 1, executor: 1 },
      { gpa_start: 2097152, bytes: 2097152, directory: 2, executor: 2 } ]
  prepared_route_snapshot_key: { scope: { vm: 256, incarnation: 1, id: 1 },
                                 topology_revision: 7, generation: 1 }
```

该夹具中数据面为 UDP `10.0.0.1:9000`、独立控制面为 TLS/TCP `10.0.0.1:9001` 的 `Endpoint` 精确 TLV 原像编码如下：

```text
00 01 10 01 00 00 00 40
00 01 00 00 00 00 00 02 00 01
00 02 00 00 00 00 00 04 0a 00 00 01
00 03 00 00 00 00 00 02 23 28
00 04 00 00 00 00 00 02 00 02
00 05 00 00 00 00 00 04 0a 00 00 01
00 06 00 00 00 00 00 02 23 29
```

常规网关替换使用如下路由事务夹具：

```text
RouteTransaction:
  operation_id: 00000000000000000000000000000002
  predecessor: { vm: 256, incarnation: 1, scope: 1, topology: 7, generation: 1 }
  successor:   { vm: 256, incarnation: 1, scope: 1, topology: 8, generation: 2 }
  required_ack_set:
    [ { member: node-runtime/1/instance-11, endpoint: node1-control },
      { member: gateway/3/instance-31, endpoint: gateway3-control } ]
  optional_departure_drain_set:
    [ { member: gateway/2/instance-21, endpoint: gateway2-control } ]
```

后继快照的 `RequiredAckSet` 刻意排除了正在退出的网关 2。在 `ROUTE_COMMIT` 时，所有发送方均按稳定作用域解析当前路由，可将转发元数据刷新至代次 2，同时保留原有的语义操作键与载荷摘要。

## 5. Schema 一致性要求

测试套件至少须覆盖以下验证：

1. 使用两套独立实现分别编码注册表中的全部记录，并比对输出字节流与摘要完全一致。
2. 拒绝所有重复字段、乱序字段、未知字段、位宽错误、非法枚举及列表排序违规输入。
3. 验证候选清单与路由快照的自摘要清零计算规则。
4. 验证常规 G 到 G+1 路由替换在保留语义操作身份的同时，生成合法的后继端点与控制面 ACK 集合。
5. 验证仅当全部必需参与者均已声明 V1 `u32` `vm_id` 能力时，才允许分配大于 255 的 V1 `vm_id`。

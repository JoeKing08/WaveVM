# WaveVM Canonical Record Schema

Status: normative implementation specification.

Scope: exact V1 WVM-TLV schemas for control-plane, membership, route,
admission, manifest, and local-runtime records. It completes the generic
container defined by `wire-ipc-abi.md`. Memory, vCPU, and block data-plane
payloads retain the schemas owned by their subsystem specifications.

No implementation may invent a second JSON, environment-variable, or
host-native structure as the semantic form of a record listed here. Human
readable renderings are diagnostics only.

## 1. Common Encoding Rules

Every record uses `CanonicalRecord` and `CanonicalField` from
`wire-ipc-abi.md`, with `schema_version=1`. All fields appear in ascending tag
order exactly once when present. `field_flags` is zero in V1. A field marked
optional is omitted when absent; an omitted field has no implicit value unless
this document explicitly gives one. Unknown, duplicate, out-of-order, wrong
length, or invalid-enum fields reject the complete record before state changes.

The scalar aliases are:

| Alias | Canonical value |
| --- | --- |
| `U8`, `U16`, `U32`, `U64` | Exact-width unsigned big-endian integer. |
| `Bool` | `U8`, exactly zero or one. |
| `ID16`, `Digest32` | Exactly 16 or 32 raw bytes. |
| `Addr` | Exactly 4 IPv4 bytes or 16 IPv6 bytes. |
| `Text<N>` | UTF-8, at least one and at most `N` bytes, no NUL. |
| `Record<T>` | Complete canonical bytes of record type `T`. |
| `List<T, key>` | `U32 count`, followed by `count` pairs of `U32 element_bytes` and one canonical scalar value or complete `T` record, strictly ascending by the stated key with no duplicate key. |
| `Set<T, key>` | `List<T, key>` whose members carry no positional meaning. |

Every integer range in this document is inclusive. `vm_id=0` is reserved for
cluster-scoped control and explicit legacy compatibility records; a VM record
uses `1..UINT32_MAX`. Timestamps use `U64 unix_time_ms`. Durations and
retention horizons use `U64 milliseconds`.

### 1.1 Digest Rule

A record digest is SHA-256 over its full canonical bytes, including the
eight-byte record header. A record cannot hash its own final digest bytes.
Therefore, a self-digest field is encoded as 32 zero bytes while calculating
the digest and is replaced by the calculated value only in the transmitted or
persisted record. Receivers zero that exact field before recomputing.

The V1 self-digest fields are:

- `AdmissionEligibilityFence.tag=9` (`fence_digest`).
- `PlacementPlan.tag=1` (`plan_digest`).
- `CandidateVmManifest.tag=3` (`manifest_digest`).
- The `snapshot_digest` field of every `RouteSnapshotKey` embedded by one
  `RouteSnapshot` whose `{scope_key, topology_revision, route_generation}`
  equals that snapshot's `RouteSnapshot.tag=1` identity. This includes the
  top-level key and same-generation `RequiredAckEntry.expected_snapshot_key`
  references in its required/optional ACK sets. Predecessor keys and keys for
  a different identity retain their final digest unchanged.

A predecessor `RouteSnapshotKey`, a route key in another record, and every
ordinary digest field contain their final nonzero digest and are included
unchanged in the enclosing digest.

## 2. Record Registry

The following registry is exhaustive for V1 control-plane records. The field
column gives `tag:type:name`; `?` denotes an optional field. Nested records and
lists use the rules in Section 1.

The V1 enum registry is:

| Field family | Values |
| --- | --- |
| `data_transport` | `1=UDP`, `2=QUIC_DATAGRAM`. |
| `control_transport` | `1=UNIX_STREAM`, `2=TLS_TCP`, `3=QUIC_STREAM`. |
| `role_type` | `1=NODE_RUNTIME`, `2=GATEWAY`, `3=QEMU_FRONTEND`, `4=EXECUTOR`, `5=KERNEL_CONTEXT`. |
| membership state | `1=PENDING`, `2=VALIDATING`, `3=PREPARED`, `4=ACTIVE`, `5=CORDONED`, `6=DRAINING`, `7=REMOVED`, `8=FAILED`. |
| health state | `1=HEALTHY`, `2=SUSPECT`, `3=UNREACHABLE`, `4=RECOVERING`. |
| backend / backend policy | Backend: `1=KVM`, `2=TCG`. Policy: `1=AUTO`, `2=REQUIRE_KVM`, `3=REQUIRE_TCG`. |
| accelerator policy | `1=DISABLED`, `2=PREFER_KERNEL_ACCEL`, `3=REQUIRE_KERNEL_ACCEL`. |
| placement policy | `1=COMPACT`, `2=SPREAD`. |
| host constraint kind | `1=PHYSICAL_NODE`, `2=FAILURE_DOMAIN`, `3=CAPABILITY`, `4=LABEL`. |
| host constraint operator | `1=EQUALS`, `2=NOT_EQUALS`. |
| guest topology policy | `1=FLAT`, `2=PLACEMENT_NUMA`, `3=SYNTHETIC_NUMA`. |
| namespace ABI | `1=LEGACY`, `2=V1_U32`. |
| reservation state | `1=PREPARED`, `2=COMMITTED`, `3=RELEASING`, `4=RELEASED`. |
| activation decision | `1=ACTIVATE`, `2=ABORT`. |
| startup dependency kind | `1=REQUIRED_MEMBER`. |
| capability state | `1=UNPROBED`, `2=PROBING`, `3=AVAILABLE`, `4=UNAVAILABLE`, `5=DEGRADED`. |
| capability ID | `1=EXECUTION_KVM`, `2=EXECUTION_TCG`, `3=MODE_B_MEMORY`, `4=V1_VM_ID_U32`, `5=KERNEL_ACCELERATION`. |
| route topology kind | `1=FLAT`, `2=FRACTAL`. |
| route transaction state | `1=PREPARING`, `2=ACTIVATED`, `3=RETIRING`, `4=RETIRED`, `5=ABORTED`. |
| gateway drain action | `1=PREPARE`, `2=COMMIT`, `3=ABORT`. |

| Type | Record | Fields |
| --- | --- | --- |
| `0x1001` | `Endpoint` | `1:U16:data_transport`, `2:Addr:data_address`, `3:U16:data_port`, `4:U16:control_transport`, `5:Addr:control_address?`, `6:U16:control_port`, `7:Text<253>:server_name?` |
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
| `0x100c` | `NodeRecord` | `1:U32:physical_node_id`, `2:U64:node_instance_id`, `3:U64:failure_domain_id`, `4:Record<Endpoint>:control_endpoint`, `5:Record<Endpoint>:sidecar_endpoint`, `6:U64:role_bits`, `7:U64:pod_id`, `8:U32:local_vnode_first`, `9:U32:local_vnode_count`, `10:Record<NodeInventory>:inventory`, `11:Record<CapabilityRef>:capability`, `12:U16:desired_membership_state`, `13:U16:observed_health_state`, `14:U64:membership_revision`, `15:U64:topology_revision` |
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
| `0x1030` | `NodeRuntimeProfile` | `1:U32:physical_node_id`, `2:U64:node_instance_id`, `3:U64:inventory_revision`, `4:U64:capability_profile_generation`, `5:U64:runtime_profile_generation`, `6:U16:node_runtime_control_port`, `7:U16:local_executor_control_port`, `8:U32:executor_worker_count`, `9:U32:sync_batch_size`, `10:U32:vcpu_handoff_record_capacity`, `11:List<U16>:node_runtime_data_ports`, `12:List<U16>:local_executor_service_ports` |

## 3. Cross-Record Constraints

- `Endpoint.data_transport` and `Endpoint.control_transport` are explicitly
  selected from the transport registry. `data_port` and `control_port` are
  nonzero. `control_address` defaults only to the already present
  `data_address`; it may not default to an unrelated hostname or source address.
- `RequiredAckSet.entries_digest` is SHA-256 over the complete entries list
  value. When the set is embedded by a `RouteSnapshot`, any entry whose
  expected key identifies that enclosing snapshot is normalized by zeroing its
  `snapshot_digest` before this list hash and before the enclosing snapshot
  self-digest are calculated. The transmitted entry still carries the final
  snapshot digest. A standalone ACK set or a route transaction's ACK set uses
  final expected-key digests unchanged. `RouteSnapshot.required_ack_set` must
  match the transaction and eligibility-fence digest that prepared it.
- `RuntimeDispatchProjection` is a node-local dispatch cache derived from
  exactly one admitted `CandidateVmManifest`, activated
  `NodeRuntimeManifest`, canonical node-record set, and immutable route
  snapshot. It is not an additional placement, membership, or route authority.
  Its candidate digest, node instance, activation fence, and route snapshot key
  must exactly equal the manifest accepted by the local node runtime. Its
  topology kind and every local, CPU, directory, and executor destination are
  complete V1 route keys: flat destinations use `{FLAT_VNODE, 0, vnode}` and
  fractal destinations use `{FRACTAL_VNODE, pod_or_prefix, vnode}`. A route
  scope must not be discarded while publishing, loading, or looking up this
  projection. Every memory mapping also retains its selected directory's
  physical-node and node-instance authority, which a returned memory ACK must
  match before it can install an authoritative page.
- The current legacy logic-core adapter consumes only flat exact-vnode routes
  with IPv4/UDP local-sidecar endpoints. It must reject a non-flat projection
  at legacy startup rather than flattening a hierarchical route into guessed
  endpoints; the typed node-runtime path consumes both flat and fractal
  projections.
- `CandidateVmManifest.execution_plan.backend` and every
  `PlacementPlan.vcpu_assignments[].backend` must agree. A VM may use KVM or
  TCG, but never a mixed vCPU backend in one admitted incarnation.
  `VmRequest.execution_backend_policy=AUTO` is resolved KVM-first and may
  produce a new TCG plan only before activation; `fallback_decision` records
  that result and its diagnostic reason. `MemoryChunkAssignment` has no KVM or
  TCG backend field because memory placement is backend-neutral subject to the
  selected memory capability/profile and route.
- `GatewayDrainRequest.target_gateway_member_key` is a `GATEWAY` key and all
  three expected revisions are nonzero exact fences. Fields six and seven are
  present exactly for `action=PREPARE`; they are absent for `COMMIT` and
  `ABORT`. The prepare transaction operation ID must equal field eight, the
  transaction and snapshot keys must be identical, and the successor snapshot's
  membership revision must equal field three. The successor material is a
  complete immutable replacement route, not a reference to mutable gateway
  cache state.
- `MemberCordonRequest.target_member_key` is a `NODE_RUNTIME` or `GATEWAY`
  key. All three expected revisions are nonzero exact fences, and
  `reason_code` is a nonzero implementation-independent audit code. Cordon
  advances membership and admission-eligibility revisions by one while
  leaving topology revision unchanged. It changes only an `ACTIVE` member to
  `CORDONED`; a retry with the old fence is accepted only when the target is
  already `CORDONED` and all three post-state revisions match exactly.
- `RouteSnapshotKey.snapshot_digest` is a self-digest only when it identifies
  the enclosing `RouteSnapshot`. Its digest preimage zeros every self-reference
  described in Section 1.1, then inserts one final digest into each such
  reference. This avoids a hash cycle while requiring every ACK entry to bind
  the exact final snapshot key. A predecessor or unrelated snapshot key is not
  zeroed.
- `GatewayRecord.hosting_physical_node_id` names an existing `NodeRecord`.
  `failure_domain_id` must equal that host's failure domain for a co-located
  gateway role; a distinct value is valid only for a separately registered
  external gateway host.
- `AdmissionEligibilityFence.selected_members` is the complete member set used
  by the plan. Every plan participant, route-ACK member, reservation owner,
  QEMU host, and executor must appear in it with its exact instance and
  capability digest.
- `PlacementPlan` and `CandidateVmManifest` must describe the same identity,
  fence, host, assignments, reservation requirements/IDs, and route scope.
  Each guest vCPU index appears once; memory assignments are page-aligned,
  nonoverlapping, and cover the requested memory exactly once.
- `CandidateVmManifest.plan_digest` must equal the complete placement-plan
  digest. `namespace_abi=V1_U32` requires every selected participant to
  advertise `WVM_CAP_VM_ID_U32`; `LEGACY` requires `vm_id <= 255`.
- `LocalNameNamespace.derivation_salt_digest` is calculated before
  `CandidateVmManifest.manifest_digest` from the allocated `manifest_id`,
  `admission_tx_id`, VM identity/generation, and target physical node. The
  final candidate digest validates the resulting namespace; it must not be an
  input to that same namespace derivation.
- `ReservationRequirement` is immutable plan/candidate input. It names the
  reservation ID, exact expected node/inventory, capacity amounts, and leases
  before either parent self-digest is finalized. A `ResourceReservation` is
  derived only after the final plan and candidate digests exist; it must match
  one requirement exactly. This avoids a plan/candidate self-reference cycle
  while retaining durable reservation-to-manifest binding.
- `NodeRuntimeManifest` records are derived after the candidate digest is
  final. They carry that digest but their own digests are not fields of the
  candidate, which prevents a candidate/node-manifest hash cycle.
- A `ResourceReservation` changes from `PREPARED` to `COMMITTED` only through
  the `COMMIT_RESERVATION` operation and a matching `ActivationRecord`.
  `activation_fence` is absent before that transition and mandatory afterwards.
- `ActivationRecord.decision=ACTIVATE` requires `activation_fence` and is the
  durable admission decision. `ActivationRecord.decision=ABORT` omits
  `activation_fence` and is valid only before one is durable. `COMMITTED` is a
  later lifecycle state reached after all required participant promotions have
  been acknowledged.
- `AdmissionReservationStage` and `AdmissionParticipantStage` are envelope
  payload carriers, not independent admission authorities. `PREPARE_*` carries
  a `PREPARED` reservation or a non-activated runtime projection with neither
  field three nor field four. `COMMIT_RESERVATION` carries the committed
  reservation and the exact durable `ACTIVATE` record. `ACTIVATE_MANIFEST`
  carries the activation-fenced runtime projection and that same exact
  `ACTIVATE` record. `ABORT_*` carries the unactivated object and a nonzero
  implementation-independent abort reason, without an activation record.
  Every embedded candidate must match the reservation/projection identity,
  transaction, candidate digest, eligibility fence, and VM identity exactly.
- `NodeRuntimeManifest` is a filtered projection of exactly one candidate
  manifest. It contains only assignments on `physical_node_id`; its
  `candidate_manifest_digest`, route key, profile, and reservation must match
  the authoritative candidate. Its `launch_plan` is controller-selected:
  machine and consistency fields exactly equal the candidate, guest memory
  equals the complete admitted placement total, and local executor ports are
  implementation-local rather than route or membership identities.
- The durable control-plane projection set contains exactly one activated
  `NodeRuntimeManifest` for each candidate `ReservationRequirement`, keyed by
  candidate digest plus physical node, expected node instance, and reservation
  ID. Identical canonical replay is idempotent; a conflicting duplicate is
  rejected. Lifecycle `COMMITTED` requires that complete set and matching
  durable `ACTIVATE` fence, not merely in-memory projections.
- `StartupDependency.dependency_digest` is SHA-256 over the canonical
  `StartupDependency` record with tag 4 encoded as 32 zero bytes. The final
  record carries the calculated digest. A node runtime uses this digest to bind
  its prepared peer-state evidence to the exact dependency record.
- `CapabilityRef.profile_digest` is SHA-256 over
  `WVM-CAPABILITY-PROFILE-V1`, the big-endian physical-node ID,
  node-instance ID, profile generation, record count, and the SHA-256
  digests of the complete strictly ordered `CapabilityRecord` set for that
  node. The set order is `(capability_id, provider_instance_id)`. A profile
  contains unavailable/degraded evidence as well as available evidence; a
  scheduler chooses only the required `AVAILABLE` records from the matched
  profile.
- The V1 member-key derivation is explicit where no independently registered
  child process exists: a compute `NodeRecord` is represented as
  `{role_type=NODE_RUNTIME, role_id=physical_node_id,
  instance_id=node_instance_id}`. A `GatewayRecord` is represented as
  `{role_type=GATEWAY, role_id=gateway_id,
  instance_id=gateway_instance_id}`. QEMU/executor/kernel process identities
  are created only during manifest preparation and cannot be substituted into
  a route ACK set.
- `RejoinMemberRequest.member_record` derives the new member key; it never
  carries a second caller-selected current identity. When
  `prior_member_key` is present, it has the same role type and stable role ID
  as the derived key but a different instance ID. `recovery_evidence_digest`
  is nonzero audit evidence only: it cannot rebind a running V1 VM, route,
  reservation, or runtime manifest to the new instance.

## 4. Canonical Examples

The following two-node VM is the normative human-readable fixture:

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

An `Endpoint` in that fixture, with data UDP `10.0.0.1:9000` and independent
control TLS/TCP `10.0.0.1:9001`, has this exact preimage TLV encoding:

```text
00 01 10 01 00 00 00 40
00 01 00 00 00 00 00 02 00 01
00 02 00 00 00 00 00 04 0a 00 00 01
00 03 00 00 00 00 00 02 23 28
00 04 00 00 00 00 00 02 00 02
00 05 00 00 00 00 00 04 0a 00 00 01
00 06 00 00 00 00 00 02 23 29
```

A normal gateway replacement uses the following route transaction fixture:

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

The successor's `RequiredAckSet` deliberately excludes departing gateway 2.
At `ROUTE_COMMIT`, every sender resolves the current route for the stable
scope; it may refresh its forwarding metadata to generation 2 while retaining
the original semantic operation key and payload digest.

## 5. Schema Conformance Requirements

At minimum, tests must:

1. Encode every registry record in two independent implementations and compare
   bytes and digests.
2. Reject every duplicate, reordered, unknown, wrong-width, invalid-enum, and
   invalid-list-order field.
3. Verify the self-digest zeroing rule for candidate manifests and route
   snapshots.
4. Verify that a normal G to G+1 replacement preserves semantic operation
   identity while producing a valid successor endpoint/control ACK set.
5. Verify V1 allocation above 255 only when all required participants advertise
   the V1 U32 VM-ID capability.

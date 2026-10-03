# WaveVM Wire and Local IPC ABI Specification

Status: proposed implementation specification.

Scope: network framing, header validation, byte order, payload bounds, request
identity, QoS, duplicate/retry semantics, local QEMU-to-node-runtime IPC,
node-runtime-to-executor IPC, compatibility rules, and Mode A IOCTL boundary.
This document defines transport contracts only; page state, vCPU state,
membership, placement, and block semantics belong to their owning subsystem
specifications. The admitted manifest and capability profile decide which
participants and ABI features are valid; this document does not make those
admission decisions.

The current ABI is not a stable production ABI. It contains legacy overloads,
fixed-layout host-native local IPC, `SYNC_MAGIC`, raw-ID fallback, and messages
whose payload or idempotency semantics are incomplete. New work must target the
contract below and retain current decoding only as bounded compatibility.

## 1. Framing and Versioning

Every network packet and local IPC record has an explicit versioned envelope.
Receivers validate the full envelope before interpreting message-specific data.

### 1.1 Current Network Header

The current packed `struct wvm_header` contains:

```text
magic, msg_type, payload_len,
slave_id, target_id, req_id/target_gpa,
qos_level, flags, mode_tcg, node_state, epoch, crc32
```

Current multi-byte network fields are network byte order except fields inside
some legacy payloads. That inconsistency is not a valid future contract.

The current header remains a legacy decoder only. New semantic traffic uses the
fixed V1 envelope below. No receiver may infer version from payload length
alone.

### 1.2 Current Local IPC Header

Current QEMU IPC starts with:

```text
wvm_ipc_header_t { uint32_t type; uint32_t len; }
```

The current local header remains a compatibility framing prefix. New local IPC
uses the same semantic envelope as network traffic, optionally preceded by a
four-byte big-endian stream frame length. Local Unix sockets, shared memory,
an in-process call, and a kernel ioctl may use different transport mechanics,
but they must expose the same fields and validation result. Connection arrival
order is never identity: QEMU explicitly registers `SYNC` and `ASYNC_PUSH`
roles before using a channel.

### 1.3 WVM Envelope V1

All integer fields are unsigned big-endian values. The fixed V1 header is a
packed 164-byte sequence with no compiler padding. `operation_id` and digests
are raw bytes in network order.

| Offset | Type | Field | Required meaning |
| --- | --- | --- | --- |
| 0 | `u32` | `magic` | ASCII `WVM1` (`0x57564d31`). |
| 4 | `u16` | `protocol_version` | Exactly `1` for this layout. |
| 6 | `u16` | `header_bytes` | Exactly `164`. |
| 8 | `u16` | `message_type` | Registry-defined data/control/local operation. |
| 10 | `u16` | `flags` | Typed non-overlapping flags; unknown set bits reject. |
| 12 | `u32` | `payload_bytes` | Bytes following this header in this frame/fragment, including the required routed-frame prefix when one applies. |
| 16 | `u32` | `vm_id` | Logical namespace; zero only for explicitly legacy/control traffic. |
| 20 | `u64` | `vm_incarnation` | Required for all nonlegacy VM operations. |
| 28 | `u64` | `manifest_generation` | Candidate/admitted manifest generation; zero only for cluster registration. |
| 36 | `u32` | `origin_physical_node_id` | Registered source host identity. |
| 40 | `u64` | `origin_runtime_instance_id` | Fresh source runtime/process identity. |
| 48 | `u8[16]` | `operation_id` | Nonzero 128-bit operation/control transaction identity. |
| 64 | `u64` | `delivery_attempt_id` | Mutable forwarding attempt; begins at one for a semantic operation. |
| 72 | `u64` | `route_scope_id` | Required for routed VM traffic; zero for non-route control records. |
| 80 | `u64` | `topology_revision` | Topology revision of the selected route snapshot. |
| 88 | `u64` | `route_generation` | Generation within the route scope. |
| 96 | `u8[32]` | `route_snapshot_digest` | SHA-256 digest of the full route snapshot; zero only when no route applies. |
| 128 | `u8[32]` | `semantic_payload_digest` | SHA-256 of the unfragmented semantic payload, excluding forwarding metadata. |
| 160 | `u32` | `crc32c` | CRC32C over bytes 0-159 and the frame payload bytes. |

The complete semantic operation key is `{vm_id, vm_incarnation,
origin_physical_node_id, origin_runtime_instance_id, operation_id}`. An origin
runtime creates `operation_id` values from a nonwrapping 128-bit sequence or a
cryptographically random 128-bit source; a new runtime instance must never
reuse its predecessor's `origin_runtime_instance_id`. UDP source address and
port are transport evidence only, never this identity.

`delivery_attempt_id`, `route_scope_id`, topology revision, route generation,
and route digest are forwarding metadata. They are excluded from
`semantic_payload_digest`; route refresh may replace them without changing the
semantic deduplication key, request bytes, or operation result.

### 1.3.1 Routed-Frame Prefix

Every routed data message has this exact 24-byte prefix immediately after the
fixed V1 header and before either the fragment prefix or the semantic payload.
It is mandatory for both local and network transport. The frame CRC32C covers
it; the semantic payload digest deliberately excludes it.

| Offset | Type | Field | Required meaning |
| --- | --- | --- | --- |
| 0 | `u16` | `route_prefix_version` | Exactly `1`. |
| 2 | `u16` | `route_prefix_bytes` | Exactly `24`. |
| 4 | `u16` | `destination_kind` | `1=FLAT_VNODE`, `2=FRACTAL_VNODE`. |
| 6 | `u16` | `flags` | Reserved; exactly zero in V1. |
| 8 | `u64` | `destination_scope` | Zero for `FLAT_VNODE`; required nonzero Pod/prefix for `FRACTAL_VNODE`. |
| 16 | `u32` | `destination_vnode_or_endpoint` | Target vnode or node-runtime endpoint within the stated scope. Zero is a valid first vnode; `0xffffffff` is the only V1 unspecified sentinel and rejects. |
| 20 | `u16` | `hop_limit` | Route-compiler supplied maximum forwarding hops; required nonzero. |
| 22 | `u16` | `hop_count` | Starts at zero; each forwarding sidecar/gateway increments once and rejects forwarding beyond `hop_limit`. |

The prefix completes the required `RouteKey` carried by every routed frame:
the fixed envelope supplies protocol version, VM identity/incarnation, and
route scope; the prefix supplies destination scope and vnode/endpoint. A
gateway must use that complete key with its admitted immutable snapshot. It
must not substitute the UDP source, a physical-node ID, `target_id`, or a raw
legacy route entry.

Route-snapshot rules have matching canonical constraints. A flat snapshot uses
only `EXACT_VNODE` rules with scope zero. A fractal `PREFIX` rule represents a
subtree rather than a leaf: its vnode field is zero, its scope is nonzero, and
its next hop is an admitted gateway. A fractal exact leaf rule has a nonzero
scope. These checks reject malformed route records before they can be
published to a V1 consumer.

### 1.4 V1 Memory Payloads

`MSG_MEM_READ`, `MSG_MEM_ACK`, `MSG_COMMIT_DIFF`, and `MSG_MEM_COMMIT_ACK` use
fixed big-endian semantic payloads. The
envelope's route prefix names the current receiver. A read payload separately
carries the reply leaf RouteKey because the ACK path must not infer it from a
UDP source address, physical node ID, `target_id`, or a legacy request table.
The directory resolves that key against its admitted immutable route snapshot
and creates an ACK whose outer route prefix targets that reply destination.

```text
MemReadPayload {
    u64 gpa;                       // 4 KiB aligned
    u16 reply_destination_kind;    // 1=FLAT_VNODE, 2=FRACTAL_VNODE
    u16 reserved_zero;
    u64 reply_destination_scope;   // zero only for FLAT_VNODE
    u32 reply_destination_vnode;   // 0 is valid; 0xffffffff rejects
}

MemAckPayload {
    u64 gpa;                       // same 4 KiB aligned page
    u64 version;                   // nonzero only for SUCCESS
    u16 status;                    // 0=SUCCESS, 1=STALE, 2=NOT_FOUND,
                                    // 3=BACKPRESSURE, 4=INTERNAL_FAILURE
    u16 reserved_zero;
    u32 directory_physical_node_id;
    u64 directory_node_instance_id;
    u8[4096] data;                 // present exactly when status=SUCCESS
}
```

A successful ACK has exactly `32 + 4096` payload bytes and carries the
authoritative full page. A terminal non-success ACK has exactly 32 bytes,
version zero, and no page data. Both forms preserve the request's complete
semantic operation key in their envelope; only mutable forwarding metadata
and the outer route destination change for the reply. Before creating the
outer ACK prefix, the directory node runtime must resolve the payload's reply
destination against its admitted immutable snapshot and obtain a fresh
nonzero hop limit. It must reject an absent, mismatched, or stale reply route.
The requester must match the ACK's directory physical-node and node-instance
identity against its admitted memory dispatch projection before installing
page data.

`MSG_COMMIT_DIFF` carries one normal dirty commit. It never aliases the legacy
host-native `wvm_diff_log` layout. The request includes a complete reply leaf
RouteKey for the same reason as `MSG_MEM_READ`: a directory returns only through
the admitted snapshot, never by reversing a UDP source or consulting a legacy
request map.

```text
MemCommitPayload {
    u64 gpa;                       // 4 KiB aligned
    u64 base_version;              // nonzero directory version observed by writer
    u16 offset;                    // byte offset within page
    u16 size;                      // 1..4096, offset + size <= 4096
    u16 reply_destination_kind;    // 1=FLAT_VNODE, 2=FRACTAL_VNODE
    u16 reserved_zero;
    u64 reply_destination_scope;   // zero only for FLAT_VNODE
    u32 reply_destination_vnode;   // 0 is valid; 0xffffffff rejects
    u8[size] data;
}

MemCommitAckPayload {
    u64 gpa;
    u64 result_version;            // nonzero only for SUCCESS
    u16 status;                    // 0=SUCCESS, 1=STALE_BASE_VERSION,
                                    // 2=NOT_FOUND, 3=BACKPRESSURE,
                                    // 4=INTERNAL_FAILURE
    u16 reserved_zero;
    u32 directory_physical_node_id;
    u64 directory_node_instance_id;
}
```

A commit ACK has exactly 32 bytes. It preserves the request's complete
semantic operation key; only forwarding metadata and outer route destination
change. On a duplicate `MSG_COMMIT_DIFF`, the directory compares the complete
semantic payload digest under the same origin/runtime and operation key. The
same digest returns the recorded `MemCommitAckPayload`; a different digest is
an `OPERATION_ID_CONFLICT` and never reapplies bytes.

### 1.5 Canonical Records, Size Limits, and Fragmentation

Manifest, route snapshot, and control payloads use canonical WVM-TLV records:

```text
CanonicalRecord {
    u16 schema_version;
    u16 record_type;
    u32 body_bytes;
    CanonicalField fields[];      // strictly ascending field_tag, no duplicate
}

CanonicalField {
    u16 field_tag;
    u16 field_flags;
    u32 value_bytes;
    u8[value_bytes] value;
}
```

All scalar field values use the same big-endian encoding as the envelope.
Nested records use canonical bytes; lists are ordered by their explicit key.
The exact record-type registry, tag numbers, scalar widths, list keys,
cross-field constraints, self-digest rule, and interoperation fixtures are
normative in `canonical-record-schema.md`. Unknown required fields and
duplicate/out-of-order tags reject. A `manifest_digest` or
`route_snapshot_digest` is SHA-256 over the complete canonical record,
including its header, with only the documented self-digest field zeroed during
calculation.

V1 limits are protocol safety limits, not hidden test parameters:

| Item | Limit |
| --- | --- |
| Local stream/in-process frame payload | 4 MiB maximum. |
| Logical network payload | 1 MiB maximum. |
| Network datagram/frame | 1280 bytes maximum, including V1 header. |
| Fragment data | 1024 bytes maximum. |
| Fragments per logical payload | 1024 maximum. |
| Concurrent incomplete reassemblies | 64 per VM incarnation and 8 MiB aggregate per origin. |
| Reassembly lifetime | 5 seconds; expiry returns/drops with bounded `FRAGMENT_EXPIRED` diagnostics. |

When `FLAG_FRAGMENTED` is set, the routed-frame prefix is followed by this
40-byte fragment prefix, then at most 1024 bytes of logical payload. A
non-routed control frame omits the routed-frame prefix and begins directly with
this fragment prefix:

```text
FragmentPrefix {
    u32 logical_payload_bytes;
    u16 fragment_index;
    u16 fragment_count;
    u32 fragment_offset;
    u8[28] reserved_zero;
}
```

The reassembly key is the complete semantic operation key plus message type and
delivery attempt. Receivers validate bounds, nonoverlap, full logical digest,
and all fragments before dispatch. No path relies on IP fragmentation. A
message that exceeds the limits fails with `PAYLOAD_TOO_LARGE` unless a selected
reliable transport with an explicitly negotiated larger limit is documented in
the capability profile.

## 2. Common Validation Rules

Before decoding payload fields, every receiver verifies:

1. Exact V1 header length, declared length, protocol limits, and no integer
   overflow in header-plus-payload calculation.
2. Magic, protocol version, known message type, and known flag combination.
3. CRC32C/integrity check before state mutation; fragmented messages additionally
   validate their completed SHA-256 semantic payload digest.
4. VM namespace/incarnation, manifest generation, origin physical/runtime
   identity, and nonzero operation ID where the operation requires them.
5. Full route snapshot key/digest and local accepted generation where routed
   delivery applies. A refreshed route is forwarding metadata, not a new
   semantic operation.
6. Source and target role validity; a gateway routes but does not become a
   destination executor.
7. Payload-specific canonical-record structure, minimum/maximum length, and
   exact field schema before access.

Malformed, unknown-version, wrong-namespace, or impossible-length traffic is
dropped with bounded diagnostics. It must not reach `logic_core`, QEMU RAM,
KVM, TCG, a block backend, or a kernel cache.

All new network payload fields use a documented fixed byte order. Packed C
structures may be an implementation of a fixed ABI only after their field
sizes, alignment, padding, and endian conversion are explicitly specified.
Host-native local IPC is allowed only when both endpoints negotiate the same
build ABI; its eventual stable replacement must be portable.

## 3. Operation Identity and Response Rules

Every operation that can mutate guest-visible state has a nonzero 128-bit
`operation_id` scoped to `{vm_id, vm_incarnation, origin_physical_node_id,
origin_runtime_instance_id}`. The current `req_id` is its compatibility
predecessor. A receiver keys deduplication and result lookup on that complete
tuple plus operation class and semantic payload digest.

| Operation class | Identity rule | Duplicate behavior |
| --- | --- | --- |
| Read/fault lookup | Same semantic key/digest for retry. | Return the same or a newer authoritative result. |
| Versioned memory commit | Same semantic key/digest for retry. | Return cached completion; reject same key with different payload. |
| `VCPU_RUN` | One handoff sequence per `{VM, vCPU}` plus one semantic key. | Query/wait or replay cached `VCPU_EXIT`; never execute twice. |
| Block write/flush | Same semantic key for retry and ordered write sequence. | Return cached completion only after required backend completion. |
| Membership/route/manifest control | One controller transaction operation ID. | Idempotently acknowledge the recorded state and record digest. |

An ACK/result must echo the complete semantic/control operation key, include a
typed status, and carry the result fields required by that operation. A one-byte
generic ACK or `SYNC_MAGIC` cannot be a stable completion signal for a memory,
vCPU, block, route, reservation, or lifecycle operation.

## 4. Network Message Families

The following table defines target direction and status. Exact payload schemas
belong to the referenced specifications.

| Family | Current messages | Direction | Contract owner |
| --- | --- | --- | --- |
| Memory read | `MSG_MEM_READ`, `MSG_MEM_ACK` | node runtime -> directory -> node runtime | `memory-consistency.md` |
| Memory commit/push | `MSG_COMMIT_DIFF`, `MSG_PAGE_PUSH_DIFF`, `MSG_PAGE_PUSH_FULL`, `MSG_FORCE_SYNC` | client/directory as specified | `memory-consistency.md` |
| Legacy coherence | `MSG_MEM_WRITE`, `MSG_INVALIDATE`, `MSG_DOWNGRADE`, `MSG_FETCH_AND_INVALIDATE`, `MSG_WRITE_BACK` | Compatibility only until mapped | `memory-consistency.md` |
| vCPU handoff | `MSG_VCPU_RUN`, `MSG_VCPU_EXIT` | origin node runtime -> destination node runtime/executor -> origin | `vcpu-handoff.md` |
| Interrupt | `MSG_VFIO_IRQ` and local IRQ IPC | executor/device -> node runtime -> QEMU authority | `vcpu-handoff.md` and `storage-device-authority.md` |
| Block I/O | `MSG_BLOCK_READ`, `MSG_BLOCK_WRITE`, `MSG_BLOCK_FLUSH`, `MSG_BLOCK_ACK` | QEMU authority -> node runtime -> assigned storage executor -> return | `storage-device-authority.md` |
| Membership/view | `MSG_HEARTBEAT`, `MSG_VIEW_PULL`, `MSG_VIEW_ACK`, `MSG_NODE_ANNOUNCE` | Diagnostic/compatibility only | `cluster-membership-topology-lifecycle.md` |
| Gateway control | Current `WVMC` add/update packet | Control plane -> gateway | `cluster-membership-topology-lifecycle.md` |

`MSG_PING` and `SYNC_MAGIC` are legacy compatibility mechanisms. They cannot
serve as typed vCPU fences, route commits, or authoritative membership changes.

### 4.1 Control Transport and Result Record

Control RPCs use the same V1 envelope over a reliable, ordered control channel
that is independent of the gateway being drained or replaced. A remote control
channel may be a configured authenticated stream transport; same-host control
may use a protected Unix socket. A data-plane UDP next hop is never the sole
way to obtain a control ACK for replacing that next hop.

Every control request uses one header `operation_id` as its transaction ID and
one canonical request record. The response uses `CTRL_RESULT` (`0x01ff`) and
this fixed 72-byte payload:

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

`status_code=SUCCESS` means the receiver durably recorded the stated result,
not merely that it queued work. A duplicate request with the same operation ID
and semantic digest replays the same result. The same ID with a different
digest, control message type, or authenticated member identity is
`OPERATION_ID_CONFLICT`. `result_flags` is zero in V1. A zero
`expiry_or_retention_deadline` means that the operation result is retained by
the member lifecycle/quarantine policy rather than a fixed wall-clock expiry.

| Code | Status |
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

### 4.2 Normative Control Message Schemas

Control payloads are `CanonicalRecord`s. `ID16`, `Digest32`, `Endpoint`,
`MemberKey`, `SnapshotKey`, and every referenced record have the exact schema
in `canonical-record-schema.md`. Fields listed in order use ascending canonical
tags starting at one; no listed field is optional unless marked optional.

| Type | Message | Mandatory request fields | Preconditions | Success result / retention |
| --- | --- | --- | --- | --- |
| `0x0101` | `REGISTER_MEMBER` | Exact canonical `NodeRecord` or `GatewayRecord` payload; the receiver derives `MemberKey` from that record | `vm_id=0`, fresh member instance, authenticated registrar | Registered `PENDING`/`RECOVERING` desired-state record; retained through member removal/quarantine. |
| `0x0102` | `CORDON` | Exact canonical `MemberCordonRequest` (`0x102c`) | Authenticated actor is an `EXECUTOR` principal accepted by the separately configured membership-management authorizer. Target is a registered `NODE_RUNTIME` or `GATEWAY`; all three expected revisions are exact. | Target enters `CORDONED`; membership and admission-eligibility revisions advance by one, topology revision is unchanged; one durable replayable result is retained through removal/quarantine. |
| `0x0103` | `DRAIN` | Exact canonical `GatewayDrainRequest` (`0x102b`) | Authenticated actor is an `EXECUTOR` principal accepted by the receiver's separately configured management-authorizer callback. A missing callback fails closed. `PREPARE` requires exact current membership/topology/eligibility revisions and one complete successor route at `topology_revision = current + 1`; `COMMIT` and `ABORT` carry the same pre-prepare fence and the controller validates the durable post-prepare eligibility state. | One durable replayable result per operation. `PREPARE` advances eligibility only; `COMMIT` atomically activates the successor, marks the target gateway `DRAINING`, and advances all three revisions; `ABORT` leaves membership/topology unchanged but retains the monotonic eligibility invalidation from `PREPARE`. |
| `0x0201` | `PREPARE_RESERVATION` | Exact canonical `AdmissionReservationStage` (`0x102d`) with candidate and `PREPARED` reservation only | Member/capability/fence still eligible and local capacity/name lease free | Prepared reservation ID/digest/expiry; retained until abort or expiry if no activation fence. |
| `0x0202` | `COMMIT_RESERVATION` | Exact canonical `AdmissionReservationStage` with candidate, committed reservation, and durable `ActivationRecord` | Matching unexpired prepared record and durable activation decision | Committed reservation digest; retained through VM retirement. |
| `0x0203` | `ABORT_RESERVATION` | Exact canonical `AdmissionReservationStage` with candidate, unactivated reservation, and nonzero abort reason | No matching activation fence, or explicit compensating-teardown record | Released/teardown-pending result; retained through cleanup horizon. |
| `0x0301` | `PREPARE_MANIFEST` | Exact canonical `AdmissionParticipantStage` (`0x102e`) with candidate and non-activated local projection | Exact member instance, route snapshot, capability profile, and prepared reservation | Prepared local-manifest record/expiry; retained until abort/activation. |
| `0x0302` | `ACTIVATE_MANIFEST` | Exact canonical `AdmissionParticipantStage` with activation-fenced projection and durable `ActivationRecord` | Matching prepared record and unchanged fence | Activated local-manifest result; retained through VM retirement. |
| `0x0303` | `ABORT_MANIFEST` | Exact canonical `AdmissionParticipantStage` with non-activated projection and nonzero abort reason | No activation, or compensating teardown after activation | Removed/teardown-pending result; retained through cleanup horizon. |
| `0x0304` | `QUERY_TX` | target `operation_id:ID16`, candidate digest optional, activation fence optional | Caller may query only a role/transaction it is authorized to inspect | Recorded transaction state/digest/expiry; retained as the target record requires. |
| `0x0401` | `ROUTE_PREPARE` | `SnapshotKey`, snapshot canonical record, predecessor key optional, `RequiredAckSet` record/digest, eligibility-fence digest, operation-retention horizon | All ACK-set entries are surviving eligible members; departing/failed gateway absent from required set | Prepared snapshot result; retained until activate/abort. |
| `0x0402` | `ROUTE_COMMIT` | `SnapshotKey`, route transaction ID, required-ACK-set digest | Matching prepared snapshot and persisted required ACK set | Activated snapshot result; retained through predecessor retirement. |
| `0x0403` | `ROUTE_RETIRE` | retiring `SnapshotKey`, successor key optional, route transaction ID | No active operation reference and query/retry horizon complete, or typed terminal outcome recorded | Retired snapshot result; retained through VM namespace quarantine. |
| `0x0404` | `ROUTE_ABORT` | Exact canonical `RouteTransaction` with `state=ABORTED` | Matching prepared snapshot, transaction ID, and required-ACK-set digest; no durable activation of that transaction | Removes only the matching prepared snapshot and retains the idempotent abort result through the operation horizon. |
| `0x0501` | `REJOIN` | Exact canonical `RejoinMemberRequest` (`0x102a`), containing a `NodeRecord` or `GatewayRecord`, optional prior `MemberKey`, and recovery evidence digest | Fresh registration only; no implicit use of old instance identity | `VALIDATING` membership result. It never rebinds a running V1 VM. |
| `0x0502` | `RECOVERY_REBIND` | old/new `MemberKey`, manifest/snapshot digests, reservation proof, memory/vCPU/storage recovery proof | Not supported in V1 without a separately accepted recovery specification | `UNSUPPORTED` in V1; retained as audit evidence. |

The controller-owned member activation path uses `ClusterAdmissionProof`
(`0x1032`) for the no-VM cluster case. Its nested
`ClusterAdmissionAckSet` (`0x1034`) is a cluster-topology acknowledgement and
must not be decoded as the per-VM route `RequiredAckSet` (`0x1008`). The proof
does not create or activate a VM route scope. A member remains non-schedulable
until the proof transaction is durably committed with every required peer ACK.

`RequiredAckSet` is a canonical ordered list of `MemberKey`, expected endpoint,
role, and snapshot key. It includes only surviving eligible node runtimes and
gateways that must install a successor before normal traffic can use it, plus a
new gateway being activated. A departing `DRAINING`, `FAILED`, or `REMOVED`
gateway may send optional drain status but is never a required successor ACK.

### 4.2.1 Registration and Rejoin Payload Binding

`REGISTER_MEMBER` carries one complete canonical `NodeRecord` (`0x100c`) or
`GatewayRecord` (`0x100d`) as its complete semantic payload. The desired-state,
observed-health, membership-revision, and topology-revision fields are
structural input only; the controller normalizes them to its durable
`PENDING`/`RECOVERING` record and current revisions.

`REJOIN` carries canonical `RejoinMemberRequest` (`0x102a`). Field one is the
complete new `NodeRecord` or `GatewayRecord`; the new `MemberKey` is derived
only from that nested record. Field two, when present, names an earlier
instance of the same stable role. Field three is a nonzero recovery-evidence
digest retained for audit. It does not authorize recovery rebind.

For either message, the authenticated control-channel principal must equal the
derived member key. The V1 envelope origin physical node and runtime instance
must equal the node record's physical-node/node-instance pair, or the gateway
record's hosting-physical-node/gateway-instance pair. These checks prevent a
registered node, gateway, source address, or free-form payload field from
impersonating another member.

### 4.2.2 Gateway Drain Authorization, Fences, and Replay

`DRAIN` is currently the canonical one-scope `GatewayDrainRequest` only; a
generic member drain payload is not accepted through this receiver. The
transport must authenticate an `EXECUTOR` actor before calling the receiver.
The receiver then calls its separately provisioned management-authorizer with
the action, authenticated executor, and target gateway. Gateway/self and
node-runtime principals cannot substitute for that management actor. A missing
callback, a non-executor actor, or an authorization denial is
`UNAUTHORIZED_ROLE` and makes no controller or result-journal mutation.

`PREPARE` carries a complete successor `RouteTransaction` and
`RouteSnapshot`, both bound to the same route operation ID. Its membership,
topology, and admission-eligibility revisions must exactly equal the current
controller values. On success the controller durably reserves the successor
topology generation and advances eligibility only. `COMMIT` and `ABORT` omit
the successor records and carry the same pre-prepare membership/topology/
eligibility fence. The controller checks that `PREPARE` has durably advanced
eligibility by exactly one before applying either action. Commit atomically
activates the successor, marks the target gateway `DRAINING`, and advances
membership, topology, and eligibility revisions. Abort records the successor
as aborted, leaves membership/topology unchanged, and retains the one-step
eligibility invalidation. This keeps the eligibility revision monotonic and
prevents an admission captured during the abandoned drain from becoming valid
again.

Every successful action is stored in the result journal under the envelope
operation ID and semantic digest. A retry after the controller frame became
durable but before that result record was written is accepted only for the
same target, route operation, action, and exact terminal/prepare revisions.
Any changed payload or stale fence is rejected; the receiver must not infer a
matching drain from a target gateway's current state alone.

### 4.2.3 Member Cordon Authorization, Fences, and Replay

`CORDON` carries the complete canonical `MemberCordonRequest` record. The
transport must authenticate an `EXECUTOR` actor before calling the receiver.
The receiver invokes a separately configured membership-management authorizer;
the gateway-drain authorizer is not reused because cordon is a membership
eligibility operation rather than a route replacement decision. A missing
callback, non-executor actor, or denied decision returns `UNAUTHORIZED_ROLE`
without changing the controller or result journal.

The request's target must be an existing compute or gateway member. At the
controller linearization point, the membership, topology, and
admission-eligibility revisions must equal the request fence. The target must
be `ACTIVE`. Success durably records the target as `CORDONED`, advances
membership and admission eligibility exactly once, leaves topology unchanged,
and stamps the resulting revisions on the membership projection. If the
membership journal already contains that exact transition but the result
journal write was interrupted, a retry with the old fence is accepted only
when the target state and all three post-state revisions match exactly; it
does not advance a revision a second time. Normal result replay still requires
the same envelope operation ID, authenticated actor, and semantic payload
digest; a controller-only retry independently rechecks the new request's
authorization and exact target/fence, while `reason_code` remains audit input
and never authorizes a second state transition.

### 4.3 Manifest and Route Records

`PREPARE_MANIFEST`, `ACTIVATE_MANIFEST`, and `ABORT_MANIFEST` carry the exact
`AdmissionParticipantStage` schema from `canonical-record-schema.md`.
`PREPARE_RESERVATION`, `COMMIT_RESERVATION`, and `ABORT_RESERVATION` carry the
corresponding `AdmissionReservationStage`. The embedded candidate's digest
covers every semantic field and uses the documented self-digest preimage rule;
the carrier prevents a receiver from inventing a candidate, reservation,
runtime projection, or activation decision from mutable local state.

`ROUTE_PREPARE` carries the exact `RouteSnapshot` schema from
`canonical-record-schema.md`. No receiver accepts a field-by-field route update
as a V1 route transaction.

## 5. Local IPC and Executor ABI

The canonical local message families are:

| Current type | Target semantic operation | Required response |
| --- | --- | --- |
| `WVM_IPC_TYPE_REGISTER` | Bind QEMU connection role and identity. | Registration ACK with accepted versions/roles. |
| `WVM_IPC_TYPE_TYPED_MEM_FAULT` | Request an authoritative page through the admitted local node runtime. | Typed page/status response. |
| `WVM_IPC_TYPE_TYPED_MEM_COMMIT` | Submit an operation-identified dirty-page commit through the admitted local node runtime. | Typed commit result with authoritative page version/status. |
| `WVM_IPC_TYPE_MEM_FAULT` / `MEM_WRITE` / `COMMIT_DIFF` | Legacy local-memory paths. They must not substitute for the typed admitted path. | Legacy/compatibility handling only. |
| `WVM_IPC_TYPE_COMMIT_DIFF_SYNC` | Complete a handoff-scoped memory fence. | Fence result tied to operation sequence. |
| `WVM_IPC_TYPE_CPU_RUN` | Request local/remote vCPU handoff. | `wvm_ipc_cpu_run_ack` successor with exact status and context. |
| `WVM_IPC_TYPE_IRQ` / `INVALIDATE` | Deliver a typed guest event or correction. | Explicit delivery/backpressure result where guest progress depends on it. |
| `WVM_IPC_TYPE_BLOCK_IO` | Submit block request to device authority. | Typed block completion. |
| `PUSH_BARRIER` / `PUSH_BARRIER_ACK` | Compatibility barrier. | Replace with typed VM-scoped fence record. |
| `RPC_PASSTHROUGH` | Transitional wrapper only. | Must declare embedded type/length/version; no blind forwarding. |

The node-runtime-to-executor ABI is a local variant of these operations. It
must include VM identity/incarnation, manifest and route generation, operation
identity, target executor role, cancellation state, ordering/fence reference,
and typed completion. An in-process executor may use a function call, but it
must not lose those checks or turn normal traffic into a global synchronous
critical section.

The executor ABI carries the candidate manifest digest, the full required
route-snapshot key (scope, topology revision, route generation, and snapshot
digest), and the activation fence. It is a single admitted-format ABI; older
frames are rejected at decode time rather than retained as a compatibility
path.

The local registration payload is a canonical `LocalRegister` record with
these mandatory fields: `connection_role:u16`, `vm_id:u32`,
`vm_incarnation:u64`, `manifest_generation:u64`, candidate/admitted manifest
digest, `local_runtime_instance_id:u64`, caller process instance ID,
capability-profile digest, and requested local endpoint name. The registration
result is a `ControlResult`-compatible status plus accepted role and local
connection ID. No local QEMU/executor connection may send semantic traffic
until this registration is accepted.

For an IOCTL, a 24-byte kernel-context prefix
`{context_handle:u64, attach_capability:u8[16]}` precedes the V1 envelope.
The kernel validates the context/manifest role before parsing the envelope;
the prefix does not replace VM/incarnation/operation identity fields.

## 6. QoS, Size, and Backpressure

`qos_level` is a scheduling hint, not a correctness exemption. The current
fast handling of vCPU run/exit and control ACKs is retained as a normal-path QoS
rule. It must not let a message bypass identity, checksum, idempotency, or
ordering validation.

The V1 size/fragmentation limits are defined in Section 1.4. Each capability
profile additionally publishes actual local queue capacities and transport
limits bounded by those maxima. Per-message rules are:

- Control, route, registration, vCPU run/exit, required memory fence, and
  durable block completion are non-droppable. Queue saturation yields a typed
  bounded backpressure/error result.
- Independent page diffs and non-fence HINT pushes may batch/coalesce only when
  page version order remains valid. They may transition a page/subscriber to
  `RESYNC`/`STALE`; they may not be silently dropped while marked valid.
- Reordering is allowed only between independent operation keys. An executor or
  device queue preserves its specified vCPU/virtqueue order domain.
- Fragment/reassembly pressure rejects new frames before exceeding V1 bounds;
  it never evicts a partially received semantic message and reports success.

The current `WVM_MAX_PACKET_SIZE` and `MTU_SIZE` are implementation constants,
not sufficient ABI documentation. A full 4 KiB page or large context must not
depend on accidental IP fragmentation as a correctness mechanism.

## 7. Mode A IOCTL Boundary

Mode A is an accelerator implementation of the same local ABI, not another
distributed protocol. Current IOCTLs are classified as follows:

| IOCTL | Target role |
| --- | --- |
| `IOCTL_WVM_REMOTE_RUN` | Optional context-bound acceleration of the vCPU handoff contract. |
| `IOCTL_SET_MEM_LAYOUT` | Per-VM QEMU RAM registration cache. |
| `IOCTL_WAIT_IRQ` | Per-VM local interrupt wait/notification. |
| `IOCTL_SET_GATEWAY`, route, placement, VM ID, epoch updates | Derived manifest/route cache refresh only; never truth injection. |
| `IOCTL_RPC_SYNC_ACK` | Remove or give a typed owner before stable ABI claim; no current handler exists. |

Every ioctl and mmap must resolve an attached `wvm_kernel_ctx` with VM identity,
incarnation, manifest generation, and lifetime validation. The ioctl number and
payload layout are not stable until `kernel-accelerator.md` accepts them.

## 8. Compatibility and Migration

1. Inventory all current message producers and consumers before changing an
   existing numeric message type.
2. Add protocol-version negotiation and typed error decoding before emitting a
   next-format packet on a mixed deployment.
3. Introduce new envelopes in parallel with legacy readers; never reinterpret
   a legacy payload based solely on a flag or a guessed size.
4. Move memory, vCPU, block, and membership operations to typed completions.
5. Retire `SYNC_MAGIC`, raw-ID fallback, untyped one-byte ACKs, and blind
   passthrough only after all corresponding contract tests pass.

## 9. Acceptance Tests

- Every supported message has a decoder test for truncated, oversized,
  unknown-version, bad-CRC, invalid-flag, and namespace-mismatch input.
- A local QEMU connection cannot send semantic traffic before successful role
  registration.
- A packet with a nonzero VM ID cannot fall back to a raw route lookup.
- Duplicate memory commits, vCPU runs, block writes, and route prepares return
  their documented idempotent result.
- A payload larger than one safe datagram follows the declared fragmentation or
  transport rule without accidental IP-fragmentation dependence.
- Every V1 network/local/control decoder rejects a wrong header length, origin
  identity, snapshot digest, canonical field order, missing mandatory field,
  duplicate operation ID with changed digest, and oversized fragment.
- Coordinator crash/restart after each `PREPARE_*`, `ACTIVATE_*`,
  `COMMIT_RESERVATION`, `ABORT_*`, `ROUTE_*`, `CORDON`, and `DRAIN` message
  replays one recorded result; it cannot create an orphaned reservation or a
  partially published route. A future-topology route journaled before its
  gateway-drain reservation is intentionally fail-closed: it cannot ACK or
  commit after recovery and must be explicitly aborted.
- A failed/departing gateway is never awaited as a required successor route ACK;
  every survivor ACK is received over the independent control path or the
  operation returns a bounded degraded/failed result.
- QoS queues preserve high-priority vCPU/control delivery under data load while
  retaining bounded backpressure and validation.
- KVM, TCG, Mode A, and Mode B use equivalent local-operation envelopes even
  when their capture/acceleration mechanics differ.

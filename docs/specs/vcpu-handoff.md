# WaveVM vCPU Handoff Specification

Status: normative implementation specification.

RM-3.1 gate (2026-10-19): accepted — document already defines goal/non-goals,
semantic authority, structures/ABI, state/sequences, concurrency/backpressure,
failure/recovery, compatibility/migration, and acceptance tests per roadmap §3.1.

Scope: remote vCPU execution between a QEMU frontend, node runtimes, local
execution runtimes, KVM workers, and TCG helper QEMU processes. This document
defines ownership, state export/import, handoff ordering, duplicate handling,
interrupt and timer merge, exit semantics, and failure behavior. It relies on
`memory-consistency.md` for page fences and `wire-ipc-abi.md` for transport
framing. The admitted manifest supplies executor placement and backend profile;
`capability-fault-engines.md` supplies the validated local mechanics.

This specification is normative for new vCPU changes. Current structures
`wvm_kvm_context_t`, `wvm_tcg_context_t`, `wvm_ipc_cpu_run_req`, and
`wvm_ipc_cpu_run_ack` are a code inventory and compatibility container, not a
claim that their field set or host-native layout is already a stable ABI.

## 1. Goal and Non-Goals

The goal is that a remote slice has the same guest-visible meaning as a local
slice: one vCPU executes one ordered interval exactly once, sees the required
memory version and interrupt state, returns an unambiguous exit, and does not
erase events delivered locally while it was away.

The key rule is:

```text
For one {vm_id, vm_incarnation, vcpu_index, handoff_sequence},
the guest instruction interval executes at most once.
```

Non-goals for V1:

- KVM-to-TCG or TCG-to-KVM vCPU handoff inside one running VM.
- Live migration of the authoritative QEMU frontend.
- Treating a fixed sleep, timer signal, or RPC timeout as a semantic vCPU
  synchronization boundary.
- Retrying a timed-out `VCPU_RUN` by sending another executable request.
- Letting a local executor become a direct cross-node vCPU endpoint.

## 2. Authority and State Model

| State or decision | Authoritative owner |
| --- | --- |
| VM identity, incarnation, selected backend, vCPU placement, and route scope | Immutable admitted VM manifest. |
| Current vCPU handoff sequence and ownership state | Origin node runtime's per-VM vCPU coordinator. |
| Memory fence required before handoff | `memory-consistency.md` and originating node runtime. |
| Execution mechanics and imported CPU object | Destination local executor. |
| Guest device model and MMIO/PIO authority | Authoritative QEMU frontend. |
| Cross-node transport | Sidecar/gateway fabric between node runtimes. |

Per-vCPU ownership states are:

```text
LOCAL_OWNED
  -> FENCING_MEMORY
  -> REQUEST_PREPARED
  -> REMOTE_IN_FLIGHT
  -> REMOTE_RUNNING
  -> RETURN_VALIDATING
  -> LOCAL_OWNED

Any state -> FAILED when a nonrecoverable contract error is recorded.
```

Only the owner may submit the next `VCPU_RUN`. `REMOTE_IN_FLIGHT` and
`REMOTE_RUNNING` prohibit another executable handoff for the same vCPU. The
destination executor records the operation before execution so a duplicate can
return cached completion or wait status without running guest instructions
again.

## 3. Handoff Identity and Data Model

The semantic handoff record is:

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

`handoff_sequence` is monotonically increasing per `{VM incarnation, vCPU}`.
It is not the current packet `req_id`, node epoch, route generation, or a timer
value. The semantic deduplication key is `{vm_id, vm_incarnation,
origin_physical_node_id, origin_runtime_instance_id, vcpu_index,
handoff_sequence, operation_id}`. `operation_id` is a nonwrapping 128-bit value
allocated by that origin runtime; a new runtime instance never reuses its
predecessor's identity.

The outer `WVM` envelope owns the semantic digest for the complete canonical
handoff record. The record itself carries a separate digest of
`exported_cpu_context`; this avoids a self-referential payload digest while
still detecting a context change independently of forwarding metadata.

`ForwardingMetadata` is outside the semantic payload digest. A retry keeps the
same deduplication key, context, and semantic payload digest, but may use a new
route snapshot/delivery attempt after G -> G+1 replacement. That reroute must
not create a second executable request.

The current `wvm_ipc_cpu_run_req` has `mode_tcg`, `slave_id`, `vcpu_index`, and
a KVM/TCG context union. The successor must carry the semantic identity above;
existing fields remain compatibility fields until wire/local ABI transition.

### 3.1 Typed Request Encoding

`wavevm_vcpu_handoff` serializes a request as an explicitly big-endian header
followed by `context_bytes` opaque context bytes. The header is fixed at 168
bytes; reserved bytes are zero and rejected otherwise.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 2 | `protocol_version` |
| 2 | 2 | `backend` (`KVM` or `TCG`) |
| 4 | 2 | `context_schema_version` |
| 6 | 2 | `memory_fence_result` |
| 8 | 4 | `vm_id` |
| 12 | 4 | `origin_physical_node_id` |
| 16 | 4 | `vcpu_index` |
| 20 | 2 | `reply_destination_kind` (`FLAT_VNODE` or `FRACTAL_VNODE`) |
| 22 | 2 | reserved zero |
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
| 100 | 4 | reserved zero |
| 104 | 16 | `operation_id` |
| 120 | 8 | `context_valid_fields` |
| 128 | 4 | `context_bytes` |
| 132 | 4 | reserved zero |
| 136 | 32 | SHA-256 of `exported_cpu_context` |
| 168 | variable | `exported_cpu_context` |

The request duplicates the envelope's immutable operation identity. A
destination node runtime rejects a record unless `vm_id`, incarnation,
manifest generation, origin physical/runtime identity, operation ID, and
destination executor equal the admitted envelope. `memory_fence_result` must
be successful before an executor may accept the operation. Context schema
version and valid-field bitmap are mandatory. The current accepted schema is
`WVM_VCPU_CONTEXT_SCHEMA_X86`; a receiver must not infer absent CPU, interrupt,
timer, or device-resume state from zero-filled bytes.

The request also carries the complete return leaf RouteKey. It is semantic
payload, not mutable forwarding metadata: flat destinations require scope zero;
fractal destinations require a nonzero scope; the unspecified vnode rejects.
The destination node runtime resolves this exact key against the same admitted
immutable route snapshot before creating `VCPU_EXIT`. It must not infer a
return path from the sender address, a physical-node ID, a legacy `slave_id`,
or a reverse route lookup.

## 4. Context Contract

The exported context is backend-specific capture data for one common semantic
handoff. It has an explicit context schema version and valid-field bitmap. A
receiver rejects an unsupported schema or missing required field rather than
zeroing it silently.

### 4.1 KVM Context

For KVM, the contract includes at least:

- General registers, instruction pointer, flags, and segment/control state.
- FPU and extended state needed by the selected KVM capability set.
- LAPIC state, vCPU events, MP state, and interrupt injection state.
- Guest TSC, TSC deadline, kernel GS base, and any required clock/MSR values.
- Pending PIO/MMIO completion data and exit context when QEMU device authority
  must complete a previous exit before the next KVM run.
- Exit class, error detail, and valid-field indicators.

The current `wvm_kvm_context_t` already contains registers, copied sregs,
LAPIC, vCPU events, FPU, XCRS, MP state, TSC-related MSRs, and small IO/MMIO
records. It must become an explicitly versioned schema; a raw native
`sizeof(wvm_kvm_context_t)` packet is not a portable contract.

### 4.2 TCG Context

For TCG, the contract includes at least:

- General, control, debug, segment, descriptor-table, and EFER state.
- x87/MMX/SSE/AVX/extended state through a versioned xsave representation.
- LAPIC state, interrupt request/pending/injected state, halted/MP/SIPI state,
  exception state, and nested/intercept fields when selected.
- TSC and APIC timer values represented relative to an explicitly identified
  guest virtual-clock epoch, not copied as an unrelated host/QEMU timestamp.
- Exit class and device completion state.

The current `wvm_tcg_context_t` carries much of this state. Its large fixed
layout and QEMU-internal assumptions require schema versioning and capability
negotiation before heterogeneous builds can claim compatibility.

### 4.3 Backend Compatibility

V1 supports homogeneous backend pairs only:

```text
KVM frontend -> KVM local executor
TCG frontend -> TCG local executor/helper QEMU
```

Mode A and Mode B can be mixed independently of this choice because kernel
acceleration is not an execution backend. A backend mismatch is a capability
failure before the VM starts, never an implicit context conversion.

## 5. Normal Handoff Sequence

1. The origin node runtime confirms that the vCPU is `LOCAL_OWNED`, its manifest
   is current, its forwarding snapshot is accepted, and the selected destination
   supports the admitted backend.
2. The origin captures the required CPU context while excluding another local
   execution owner for that vCPU.
3. It completes the memory handoff fence:

   ```text
   capture dirty pages
     -> submit versioned commits
     -> receive required commit acknowledgements
     -> deliver required local corrections
     -> record memory_fence_id = success
   ```

4. It changes ownership to `REMOTE_IN_FLIGHT`, allocates one operation ID and
   handoff sequence, and sends the request through its local sidecar/gateway.
5. The destination node runtime validates origin identity, semantic operation
   key/digest, manifest identity, forwarding snapshot, backend, handoff
   sequence, and memory-fence success before giving the request to its local
   executor.
6. The executor deduplicates the operation, imports context in the documented
   backend order, executes until a defined exit, captures dirty effects and
   required CPU/device state, and records a completion before transmitting it.
7. The destination resolves the request's explicit reply leaf RouteKey against
   its admitted immutable route snapshot, creates a typed `VCPU_EXIT` with the
   original operation identity, and submits it through its local
   sidecar/gateway boundary.
8. The origin validates result identity, sequence, backend, context schema, and
   returned leaf RouteKey;
   it merges returned state without erasing local events that arrived after the
   send watermark.
9. It completes required returned-memory processing, performs device/MMIO/PIO
   work at QEMU authority when needed, and returns the vCPU to `LOCAL_OWNED`.

Network sends, waits, page fetches, and device operations must not occur while
holding a global VM lock. A vCPU coordinator can lock that vCPU's ownership
record while changing state, then release it before the potentially long remote
execution interval.

## 6. Duplicate, Retry, and Timeout Rules

The destination keeps a bounded, VM-incarnation-scoped completion cache keyed
by the complete semantic deduplication key above. It retains the entry through
the maximum route predecessor/query horizon; a later query receives
`RESULT_EXPIRED`, never permission to execute again.

`vcpu_handoff_record_capacity` is an admitted node-runtime launch-plan limit,
separate from executor worker concurrency. It bounds in-progress and retained
completion records for the local VM incarnation. Capacity exhaustion returns
typed backpressure before any guest interval runs; it must not evict a result
whose route retry/query horizon has not elapsed.

| Condition | Required behavior |
| --- | --- |
| Duplicate request before completion | Return `IN_PROGRESS` or wait/query result; do not execute a second slice. |
| Duplicate request after completion | Replay the cached `VCPU_EXIT` result if the identity and payload digest match. |
| Same operation ID with different context or identity | Reject as protocol corruption. |
| Origin loses response | Query/wait for recorded completion or use a bounded result replay path. |
| Initial delivery loss | Retransmit the identical semantic request in a bounded delivery window; only forwarding metadata may change after route refresh. |
| Execution exceeds watchdog duration | Mark operation uncertain/in-progress according to recorded executor state; never send a second executable run. |
| Destination/process failure before durable completion | Return a failed/degraded vCPU operation; recovery requires a separately specified VM fault policy. |

`IN_PROGRESS`, `BACKPRESSURE`, `STALE`, and `RESULT_EXPIRED` are typed
non-exit statuses. They use exit class `NONE` and carry no CPU context,
memory-fence result, or event watermark. `EXECUTOR_FAILURE` uses
`EXECUTOR_ERROR`; `MEMORY_FAILURE` uses `MEMORY_ERROR`.

The current long `VCPU_RUN` timeout and retry window in `logic_core.c` are
implementation guardrails. They do not make a repeated UDP send semantically
safe unless the destination cache enforces this contract.

## 7. Exit, Device, Interrupt, and Time Semantics

`VCPU_EXIT` must report one typed exit class:

| Exit class | Required owner/action |
| --- | --- |
| `BUDGET` / cooperative preemption | Return CPU context; origin may schedule the next handoff. |
| `HALTED` / wait-for-event | Preserve halted and timer/APIC state; origin must not force runnable merely to make a test progress. |
| `PIO` / `MMIO` | Authoritative QEMU frontend performs device action, records completion data, and only then allows continuation. |
| `INTERRUPT` / IPI / timer | Merge using watermarks and backend-specific state; do not erase local post-send interrupts. |
| `EXCEPTION` / shutdown / reset | Return exact architecture state and map to the authoritative QEMU lifecycle. |
| `MEMORY_ERROR` | Include affected GPA/status; origin enters consistency recovery before another dependent execution interval. |
| `EXECUTOR_ERROR` | Return typed non-success; no fake CPU completion. |

The return envelope retains the request's VM/incarnation, manifest generation,
origin runtime identity, operation ID, route-snapshot key, and semantic result
payload. Its mutable delivery attempt and route hop state are newly created.
Its route leaf must equal the request's explicit reply RouteKey and begin with
hop count zero and a nonzero hop limit resolved from the active snapshot.

Timers and TSC are guest architectural state. KVM uses its selected MSR/LAPIC
mechanics; TCG translates values relative to its virtual-clock epoch. A fixed
sleep, host wall-clock deadline, or signal used by a current implementation may
be a watchdog/escape hatch only. It cannot define the guest's logical handoff
boundary or replace exported timer state.

INIT/SIPI, LAPIC, IPI, NMI, and local interrupt ordering require an explicit
merge policy. The origin records a local interrupt watermark before handoff.
When importing a result it combines returned state with events delivered after
that watermark according to backend rules. It must not replay stale INIT/SIPI
bits that would restart an already initialized AP.

## 8. Concurrency and Backpressure

- Ownership exclusion is per VM/incarnation/vCPU, not a global execution lock.
- Independent vCPUs may hand off concurrently when their memory fences and
  executor queues permit it.
- The local executor manager owns bounded worker queues and reports explicit
  overload. It must not drop a vCPU request or hide it behind unbounded waits.
- Fast QoS is preserved for `VCPU_RUN`, `VCPU_EXIT`, required memory fence
  acknowledgements, and device-completion traffic.
- A short local synchronization operation is permitted for ownership transfer
  or bounded backpressure, but cannot serialize all guest vCPUs permanently.
- Completion-cache eviction must retain an entry at least through the origin's
  documented retry/query horizon or return a clear `RESULT_EXPIRED` error.

## 9. Current Code Mapping and Known Deviations

| Current file or symbol | Current behavior | Required migration direction |
| --- | --- | --- |
| `wavevm-qemu/.../wavevm-cpu.c` | Captures KVM/TCG state, flushes TCG dirty pages, sends local CPU IPC, then imports ACK. | Bind capture/import to explicit handoff sequence, fence result, event watermark, and versioned context schema. |
| `master_core/main_wrapper.c` | Resolves a target then forwards `MSG_VCPU_RUN` through `wvm_rpc_call`. | Node runtime validates manifest/route generation and maintains per-vCPU ownership/correlation. |
| `master_core/logic_core.c` | Uses request contexts and long timeout/retry behavior. | Split delivery retry from execution completion; use a deduplicated result query/replay model. |
| `slave_daemon/slave_hybrid.c` | Caches some VCPU exits, creates KVM vCPUs, imports/exports context, and executes `KVM_RUN`. | Make cache key/lifetime VM-incarnation-scoped and expose typed `IN_PROGRESS`/completion state. |
| `wavevm-qemu/.../wavevm-all.c` | Helper-QEMU path imports, executes, exports, and may serialize some Mode B execution. | Preserve required device/IRQ semantics without making serial execution the universal normal path. |
| `common_include/wavevm_protocol.h` | Defines host-native KVM/TCG context containers. | Add versioned field maps and capability negotiation. |

## 10. Compatibility and Migration

1. Write context-schema and exit-class tests around current KVM and TCG
   exporters/importers before moving fields.
2. Add per-vCPU handoff sequence and completion cache to the node-runtime
   interface while retaining current request IDs as a compatibility key.
3. Route current master-to-slave calls through the local executor ABI without
   changing packet topology.
4. Add typed duplicate/in-progress/result replay before reducing retries or
   changing timeout behavior.
5. Replace host-native context transfer only after all participating endpoints
   negotiate a common schema version.

## 11. Acceptance Tests

- Duplicate `VCPU_RUN` executes one guest interval and returns one cached result.
- Packet loss after execution begins cannot trigger a second `KVM_RUN` or TCG
  slice for the same handoff sequence.
- Replacing a route generation while losing `VCPU_EXIT` preserves the same
  semantic key across result query/reroute and executes one slice only.
- A failed memory fence prevents `VCPU_RUN` transmission.
- KVM and TCG preserve required registers, segments, extended state, LAPIC,
  timer/TSC, MP, interrupt, and halted state across a remote slice.
- An interrupt delivered locally during remote execution survives result import.
- PIO/MMIO completion is performed by the QEMU device authority and supplied to
  the next execution interval exactly once.
- Backend mismatch is rejected at admission/capability negotiation.
- Concurrent independent vCPUs progress without a global handoff lock.
- Executor overload and completion-cache expiry produce bounded typed failures,
  not a false success or indefinite retry loop.

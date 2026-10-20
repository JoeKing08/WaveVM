# WaveVM Capability and Fault Engine Specification

Status: normative implementation specification.

RM-3.1 gate (2026-10-19): accepted — document already defines goal/non-goals,
semantic authority, structures/ABI, state/sequences, concurrency/backpressure,
failure/recovery, compatibility/migration, and acceptance tests per roadmap §3.1.

Scope: host capability discovery, versioned capability profiles, execution and
fault-engine selection, userfaultfd and SIGSEGV/mprotect behavior, KVM dirty
logging, failure handling, and compatibility between Mode A and Mode B. The
memory correctness contract remains in `memory-consistency.md`; the optional
kernel implementation boundary remains in `kernel-accelerator.md`.

This specification is normative for selecting a runtime mechanism. A missing
fast feature may select a slower correct mechanism, but never a semantic
workaround that merely makes a test progress.

## 1. Goal and Non-Goals

The goal is to make capability-dependent behavior explicit before a VM starts:

```text
probe actual host behavior
  -> publish versioned capability profile
  -> resolve one admitted execution/fault profile
  -> prepare per-VM engine state
  -> run the same memory/vCPU semantics
```

WaveVM supports restricted hosts. Root, a custom kernel, `/dev/kvm`,
userfaultfd, or `wavevm.ko` may improve performance, but no one of them is the
unconditional baseline. Mode B provides canonical user-space semantics; Mode A
is an optional implementation of selected local data-plane operations.

### 1.1 Release priority

The minimum usable system requires one correct restricted-host fallback for TCG
and one correct KVM dirty/resync path where KVM is available. The complete
`fault_engine_ops` matrix, UFFD selection, and exhaustive cross-engine
equivalence/failure testing are extended hardening work. They must not become a
reason to delay a correct Mode B launch, and they must not introduce a second
page-consistency authority.

Non-goals for V1:

- Claiming a capability from kernel version, container image name, or a bound
  device path without a real probe.
- Switching fault engine, execution backend, or memory protection mode during
  a live guest interval merely because a timeout occurred.
- Using signal handlers to perform network RPC, blocking locks, allocation, or
  QEMU/global state mutation.
- Treating KVM dirty logging as a complete remote-memory coherence protocol.
- Requiring userfaultfd, root, or a kernel module for all deployments.
- Hiding an unsupported engine behind a test-only environment variable.

## 2. Capability Authority and Profile Model

### 2.1 Capability States

Capability evidence is tied to one physical-node and node-instance lifetime:

```text
UNPROBED -> PROBING -> AVAILABLE
                  -> UNAVAILABLE
                  -> DEGRADED
```

`AVAILABLE` means that the probe completed the operation WaveVM needs, not
only that an API symbol exists. `DEGRADED` means a partial implementation is
known but cannot satisfy one or more declared limits. It is never silently
treated as `AVAILABLE`.

| State | Required meaning |
| --- | --- |
| `UNPROBED` | No valid observation exists for the current node instance. |
| `PROBING` | A bounded probe is running; the feature is not selectable yet. |
| `AVAILABLE` | The required ABI/version/permission/operation probe passed. |
| `UNAVAILABLE` | Probe or policy proves it cannot be used; include a typed reason. |
| `DEGRADED` | Some behavior works but one declared semantic limit prevents use for this profile. |

### 2.2 Capability Record

```text
CapabilityRecord {
    capability_id;
    capability_schema_version;
    physical_node_id;
    node_instance_id;
    provider_instance_id;         // process/module/device instance when relevant
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

`limits` includes values such as supported RAM registration size, maximum
context count, queue depth, supported context schema versions, userfaultfd
features, KVM dirty-log mode, or maximum safely handled fault backlog.
`constraints` records relevant restrictions such as container policy, disabled
unprivileged userfaultfd, incompatible QEMU build, missing permissions, or an
unsupported host architecture.

The membership/control plane publishes the profile; a process may cache it only
with its `node_instance_id`, generation, and expiry/reprobe policy. A profile
from a prior container/VM boot is invalid even when the physical-node ID is
unchanged.

### 2.3 Capability Classes

At minimum V1 profiles capability records for:

| Class | Examples |
| --- | --- |
| Execution backend | KVM usable, TCG usable, required QEMU build/context schema. |
| Fault capture/resolution | userfaultfd API/features, SIGSEGV/mprotect validity, QEMU dirty logging, KVM dirty logging. |
| Optional acceleration | `/dev/wavevm`, kernel ABI, per-VM context support, fast invalidate/dirty/wakeup capabilities. |
| Local transport | Unix socket, shared-memory, eventfd, packet size/fragmentation support. |
| Platform limits | page size, huge-page policy, NUMA data availability, resource limits. |
| Device/storage | selected block/device backend, flush/FUA support, VFIO/GPU restrictions when requested. |

The capability model must describe what is required for a correct path, not
only every performance feature that happens to be present.

## 3. Admitted Execution and Fault Profile

The control plane resolves an immutable profile into the VM manifest:

```text
ExecutionFaultProfile {
    backend;                      // KVM or TCG for this V1 VM
    context_schema_version;
    dirty_capture_engine;
    read_fault_or_resync_engine;
    invalidation_engine;
    optional_kernel_accelerators;
    per_node_capability_digest;
    supported_memory_policies;
    fallback_decision;            // resolved before PREPARED only
}
```

The profile is selected from the intersection of all capabilities needed by the
admitted host, node runtimes, and executors. The same high-level page versions,
directory authority, handoff fences, request identity, and error behavior apply
regardless of the selected engine.

### 3.1 Selection Rules

1. `REQUIRE_KVM` selects KVM only when the host/frontend and every required
   executor path can pass the documented KVM and context-schema probes.
2. `REQUIRE_TCG` selects TCG only when each required helper/executor supports
   the same TCG context schema and a valid memory fault/resync path.
3. `AUTO` is resolved during admission and recorded in the manifest. It does
   not permit a live backend switch.
4. `REQUIRE_KERNEL_ACCEL` fails unless every required attached component has a
   compatible per-VM kernel-context capability. `PREFER` may select Mode B
   before start; it must record that decision.
5. A preferred fault engine may fall back only during admission, after the
   fallback passes its own probe and satisfies the same memory contract.
6. Every selected engine and fallback has an explicit reason and profile digest
   visible to diagnostics and CI.

### 3.1.1 Heterogeneous Compute Clusters

Execution capability is advertised per node and is not a mutually exclusive
node label. A node with usable KVM may advertise both `EXECUTION_KVM` and
`EXECUTION_TCG` when its TCG helper/context probe passes. A node without KVM
normally advertises TCG only. Neither execution capability by itself decides
whether the node may provide guest memory: memory participation is governed by
the node's memory-service capability, capacity, route scope, and negotiated
memory profile.

For one VM incarnation, every vCPU assignment uses the one backend recorded in
the admitted execution profile. A KVM-capable node may therefore contribute
TCG vCPU capacity to a TCG VM, but it executes that VM through its TCG helper;
it does not create a mixed KVM/TCG vCPU plan. Backend selection is a
pre-activation admission decision, not a runtime downgrade or context
conversion.

`AUTO` has deterministic KVM-first semantics:

1. The coordinator first attempts a complete KVM plan whose frontend and every
   required vCPU executor satisfy the KVM capability and context-schema
   requirements.
2. If no complete KVM plan is admissible, it may create a new complete TCG
   plan when the request permits fallback and all selected TCG executors pass
   their probes.
3. The fallback is a new plan and reservation attempt. It must not reuse a
   partially reserved KVM plan, and the selected backend and reason are recorded
   in the candidate/admitted manifest.

`REQUIRE_KVM` never performs this downgrade: if a complete KVM plan cannot be
admitted, the request fails before any process starts. `REQUIRE_TCG` selects
TCG directly. A KVM-to-TCG or TCG-to-KVM transition after `RUNNING` remains
outside V1.

TCG capacity on a KVM-capable node is a separately advertised and accounted
capacity class. It must not be inferred by copying KVM vCPU capacity, and
reservations for KVM and TCG work must still obey the node's shared host CPU
and overhead budget.

### 3.2 Engine Matrix

| Backend/path | Dirty capture | Read fault/resync | Invalidation rule |
| --- | --- | --- | --- |
| TCG Mode B | QEMU dirty tracking plus selected fault engine | userfaultfd when available, otherwise valid SIGSEGV/mprotect path | Range/page protection and explicit versioned push/resync. |
| KVM Mode B | KVM/QEMU dirty logging or equivalent proven capture | Explicit node-runtime/QEMU page fetch before dependent run | Do not use `mprotect(PROT_NONE)` on KVM guest RAM as an EPT-fault trigger. |
| Mode A optional acceleration | Context-bound kernel dirty/invalidate/wakeup only when negotiated | Same user-space authority and typed operation contract | Kernel action is a cache/fast path, never a different page-state rule. |

KVM dirty logging identifies writes. It does not fetch a stale page, establish
directory ownership, resolve a version gap, or make a remote write durable.
Those remain node-runtime/memory-contract operations.

## 4. Fault Engine Contract

Every selectable engine implements a versioned `fault_engine_ops` contract:

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

The exact C ABI can differ by backend, but the operation meanings cannot. Every
call carries or resolves the VM incarnation, manifest generation, RAM range,
and operation/fence identity. An engine has no authority to select a directory,
change a page version, or bypass the local node runtime.

### 4.1 Userfaultfd Engine

The probe must verify the actual `userfaultfd` syscall/policy, requested API
features, registration of a representative RAM range, event delivery, and
cleanup. Reading a sysctl or assuming root is insufficient.

Fault handling runs on a dedicated fault thread or equivalent event loop. It
validates that the address maps to the manifest-bound WaveVM RAM range, then
requests the versioned page/resync through the local node runtime. It must not
hold a QEMU global lock while waiting for network or directory work.

### 4.2 SIGSEGV/mprotect Engine

SIGSEGV/mprotect is permitted only for a demonstrated compatible Mode B TCG
range. The asynchronous signal handler may do only async-signal-safe work such
as recording minimal fault information in a preallocated lock-free buffer and
waking a dedicated handler through an allowed primitive. It must not call
malloc, printf, pthread locks, QEMU APIs, IPC RPC, or network sends.

The handler must verify a manifest-bound RAM range before claiming a WaveVM
fault. A non-WaveVM address, malformed access, or engine-state mismatch is
forwarded to the previously installed handler or normal fault policy; it must
not be swallowed as a remote page request.

### 4.3 KVM Dirty/Resync Engine

KVM guest RAM must not rely on host `mprotect(PROT_NONE)` read/write trapping,
because it can produce EPT violations and incorrect KVM exits. KVM uses a
proven dirty-capture mechanism for writes and explicit QEMU/node-runtime page
fetch/resync for version gaps before a dependent guest interval runs.

The engine must associate dirty log samples with a handoff/flush boundary. It
must not clear a dirty bit or mark a page synchronized until the journal has
entered the memory protocol and the required fence/result is known.

### 4.4 Kernel-Accelerated Engine

The optional kernel engine is selectable only after a manifest-bound
`wvm_kernel_ctx` is prepared. It may accelerate dirty capture, invalidation,
local wakeup, or local packet preparation, but every operation returns the same
typed outcome as Mode B. It cannot issue independent cross-node routing,
invent a memory ACK, or cache a route/page past its manifest/route validity.

## 5. Ordering, Backpressure, and Failure

### 5.1 Ordering

- Dirty capture returns a journal tied to the requesting handoff/fence; it
  cannot be reinterpreted as a later guest interval's write set.
- A page invalidation makes a cached page unusable until the memory contract
  returns a next-version update or authoritative resync.
- `complete_fence(success)` is reached only after the memory specification's
  required directory ACKs and local delivery barriers complete.
- Engine lock ownership is per VM/range/page where practical. No engine may
  use one global fault lock to serialize all VMs or all independent pages.

### 5.2 Bounded Backpressure

Fault queues, dirty journals, and resync requests are bounded. When an engine
is overloaded it blocks only the affected range/vCPU at a documented safe
boundary or returns a typed failure to the lifecycle/runtime; it must not drop
a fault, silently lose a dirty record, or consume unbounded memory.

Control, vCPU handoff, required memory ACK, and fault-resume traffic retain
their declared QoS. A bulk dirty transfer cannot starve a page required to
resume guest execution indefinitely.

### 5.3 Failure Rules

| Condition | Required behavior |
| --- | --- |
| Probe fails before admission | Select a documented compatible fallback if policy permits; otherwise fail before start. |
| Engine preparation fails | Reject/abort lifecycle prepare and clean only that manifest's local state. |
| Fault queue overflow or handler failure | Mark affected operation/range failed or paused; do not silently allow stale execution. |
| Page fetch/version resync fails | Keep page invalid and return typed memory failure; do not restore access to old bytes. |
| Dirty capture uncertainty | Prevent dependent handoff/flush success; preserve/retry journal only through its operation identity. |
| Kernel accelerator disappears | Stop using its fast path, then pause/fail unless a quiesced, manifest-valid transition to Mode B is explicitly implemented. |
| Local child/profile restart with unchanged registered node instance | Invalidate profile/engine context and reprepare against the same manifest before accepting traffic. |
| Registered node-agent or host replacement | New node instance invalidates the admitted member identity; V1 pauses/fails the VM rather than implicitly preparing a replacement or rebinding it. |

V1 does not live-switch engine implementation after `RUNNING`. A future
transition must quiesce all affected vCPUs, complete/fail outstanding fences,
validate the replacement engine against the same manifest, atomically publish
the new profile generation, and resume only after all participants agree.

## 6. Diagnostics and Security Boundaries

Capability records and fault diagnostics are structured and bounded. They must
include VM/incarnation, profile digest, engine, operation ID, page/range where
safe, result/error class, queue depth, and node instance identity. They must
not log page contents, private credentials, unlimited packet dumps, or every
fault indefinitely.

The probe/reporting path may inspect host policy but must not change global host
security settings, enable userfaultfd system-wide, load a module implicitly, or
relax container isolation. Such policy changes are explicit operator actions
outside this specification.

## 7. Current Code Mapping and Known Deviations

| Current file or mechanism | Current behavior | Required migration direction |
| --- | --- | --- |
| `wavevm-qemu/accel/wavevm/wavevm-user-mem.c` | Uses QEMU RAM mappings, SIGSEGV/mprotect paths, version tracking, dirty flush, and KVM-specific active page synchronization. | Split behavior into a manifest-bound fault engine context; preserve KVM's no-`PROT_NONE` rule and move unsafe signal work out of the handler. |
| `wavevm-qemu/accel/wavevm/wavevm-cpu.c` | Couples dirty flush and vCPU handoff preparation. | Consume `DirtyJournal`/fence results from the selected engine under the vCPU handoff contract. |
| QEMU KVM dirty-log code | Supplies native KVM dirty tracking mechanics. | Treat as one capture provider, not page-directory or resync authority. |
| `master_core/kernel_backend.c` and `common_include/wavevm_ioctl.h` | Expose legacy global/module-oriented acceleration controls. | Publish capability evidence and bind all acceleration to per-VM contexts. |
| CI/run scripts | Choose modes through environment and host assumptions. | Record probe results/profile selection and fail early when no correct engine exists. |

## 8. Compatibility and Migration

1. Inventory every current fault handler, mprotect transition, dirty-bit clear,
   KVM dirty-log call, and kernel-assisted memory operation.
2. Add real host probes with a capability report before changing automatic
   selection. Preserve current manual test selection only as an explicit
   compatibility input.
3. Introduce a per-VM engine context and route existing TCG/KVM paths through
   `fault_engine_ops` adapters without changing directory semantics.
4. Make signal handling asynchronous-safe and move page RPC/locking to a
   dedicated fault worker before claiming the SIGSEGV path is production-safe.
5. Add profile digest validation to QEMU/node-runtime/executor startup.
6. Retire guessed KVM, UFFD, or module availability only after a fixture proves
   that unavailable and degraded hosts fail clearly instead of hanging.

## 9. Acceptance Tests

- A capability report differentiates absent KVM, inaccessible KVM, usable KVM,
  absent userfaultfd, policy-blocked userfaultfd, and usable userfaultfd.
- TCG runs with userfaultfd when its full registration/event probe passes and
  with SIGSEGV/mprotect only when that engine's bounded test passes.
- KVM never installs `PROT_NONE` as a guest-RAM access trap; a version gap
  triggers an explicit page fetch before dependent execution resumes.
- Dirty records captured at a handoff either reach the required memory fence or
  cause that handoff to fail; none is silently discarded on queue pressure.
- A fault outside registered WaveVM RAM follows normal QEMU/process handling,
  not a remote page RPC.
- An unavailable kernel module or one that lacks per-VM context support selects
  Mode B for `PREFER` and rejects `REQUIRE_KERNEL_ACCEL` before launch.
- Two VMs with different capability profiles cannot attach to each other's
  fault queues, RAM ranges, page versions, or kernel contexts.
- Capability/engine logs remain bounded under a fault storm and contain enough
  identity/result evidence to distinguish capability, page-consistency, and
  transport failure.

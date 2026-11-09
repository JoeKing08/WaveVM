# WaveVM Refactor Roadmap

Status: normative implementation and maintenance roadmap.
Scope: dependency-ordered runtime capabilities, architectural constraints, and
objective acceptance boundaries. This document records requirements, not code
inventories, implementation progress, audit verdicts, or test results.

Phases 0 through 9 form Minimum. Phases 10 through 13 form Extended. Every
phase delivers executable behavior; writing specifications or producing an
empty skeleton is not a feature phase. Targeted verification accompanies the
capability it checks; the final matrix closes a delivery profile.

## Document Maintenance

These rules govern the architecture baseline, this roadmap, and all subsystem
specifications under docs/specs/:

- State required architecture, authority, interfaces, state transitions,
  concurrency, resource costs, failure behavior, dependencies, and acceptance
  conditions. Keep completion checkboxes, dated approvals, observed code gaps,
  measurements, and audit findings in separate plan or verification records.
- A source mapping identifies a required responsibility, not proof that a file
  implements it. Observed dependency/state matrices remain outside the charter;
  allowed dependencies and required ownership must be justified by the target.
- Existing implementation does not define architectural validity. Follow
  baseline Section 0.1 when resolving conflicts or revising a core decision.
  Missing functionality or a historical compromise alone cannot weaken a rule.
- Revise an owning definition and affected producers, consumers, and acceptance
  conditions together. Reference cross-domain rules rather than copying them.
  Boundary summaries index the full contracts; they do not redefine them.
- State/capability names and conditional admission gates describe required
  behavior, not present completion. Express each gate through the evidence it
  requires, without an audit ID or dated pass/fail declaration.
- Minimum/Extended are temporary scope and dependency boundaries for this
  delivery roadmap, not permanent feature tiers or progress labels. The project
  owner may revise feature scope explicitly; preserve the affected correctness
  and isolation contracts. A completed capability does not change its normative
  meaning. After the owner closes this roadmap and its phases are accepted,
  remove the Minimum/Extended labels and boundary while retaining their
  requirements as system contracts. Track completion separately; future
  capabilities belong in a new roadmap, not in the retired delivery split.
- Normative contract history is tracked in Git. Do not add version suffixes to
  subsystem filenames, symbols, or APIs solely to preserve contract history;
  wire-format version fields follow the wire ABI contract. No parallel protocol
  implementation or compatibility path is required. There is no standing
  requirement to support old configurations, independently launched
  master/slave services, or mixed legacy deployments.

## 1. Architecture and Delivery Goal

Implement one distributed QEMU platform with canonical user-space semantics:

- The cluster control plane owns membership, identities, capacity, placement,
  admission, and overall VM lifecycle.
- One node-runtime binary provides per-VM semantic coordination and local
  executor management. Backend workers and helper QEMU processes obey its
  explicit local executor contract; they are not cross-node endpoints.
- Mode B implements the semantic baseline. Mode A adds optional per-VM kernel
  acceleration without taking over control-plane or runtime authority.
- KVM/TCG and flat/fractal paths satisfy the same operation-level meaning.
- Resource pooling includes explicit accounting, multi-VM isolation, necessary
  parallel execution, and bounded runtime resources.

### 1.1 Delivery Profiles

**Minimum** requires:

- Manifest-bound creation, activation, startup, pause/stop, partial-start
  cleanup, and restart reconciliation by one active coordinator.
- Explicit VM identity/incarnation, QEMU host placement, remote CPU/memory
  allocation, independent resource/name leases, and capability selection.
- Flat and fractal routing with acknowledged immutable snapshots, consistent
  identity rules, and unchanged semantic-operation keys across rerouting.
- KVM guest login or SSH with evidence of remote vCPU and remote memory use.
- Bounded real TCG execution with checked CPU/memory results, independent
  vCPU ownership/progress, handoff/device/atomic ordering, errors, and cleanup.
  See baseline Section 16 and vcpu-handoff Section 8.1. A contract pass is not
  evidence of usable TCG guest OS execution.
- Multiple Mode B VMs and multiple compute-node instances on one physical
  host, including aggregate physical_host_id accounting and explicit endpoint,
  port, socket, shared-memory, log, and temporary-file ownership.
- Per-VM kernel contexts, with two-VM isolation and teardown evidence before
  advertising multi-context Mode A.
- Validated member/gateway join, compute cordon, safe drain, and gateway
  replacement through an acknowledged successor route snapshot.
- Required concurrency, priority, batching, and bounded backpressure for these
  workloads; process survival and listening sockets are not success oracles.

Minimum assumes one active coordinator and bounded single-scope operations.
It requires durable activation decisions, restart replay or compensating
cleanup, and fail-closed required-member loss. It does not require coordinator
HA, transparent recovery of lost compute state, live migration/resharding, or
aggregate multi-scope host transactions. Those exclusions cannot excuse stale
activation, identity bypass, leaks, unsafe removal, or false RUNNING.

**Extended** adds TCG guest boot/login/SSH and sustained distributed multi-vCPU
usability; broader fault engines and failure matrices; recovery, HA, migration,
and live reconfiguration; and hosted host-OS portability. These extend the same
contracts. Full TCG guest usability must be distinguished from Minimum TCG
contract support, including when AUTO chooses TCG before admission.

Host portability first targets the same Linux host appliance under a declared
hypervisor adapter on a non-Linux host or where native deployment is
impractical. It is a host adapter, not a WaveVM guest. Native non-Linux
user-space and kernel ports require separate contracts. Actual appliance
probes determine KVM and Mode A availability independently; neither capability
is inherited from the outer host. Phase 13 owns acceptance.

## 2. Architectural Constraints

- No second semantic authority in an executor, gateway, kernel cache, launch
  script, environment variable, or user-authored route file.
- No VM-specific global singleton or implicit one-node-instance-per-host rule.
- No process layout, file boundary, or inherited data structure is itself a
  target requirement. Independent master/slave production entry points and
  legacy configuration readers must be removed rather than preserved solely
  for compatibility.
- No direct executor-to-executor or frontend-to-remote-executor production
  path. Cross-node work uses both node runtimes and the sidecar/gateway fabric.
- No membership admission from a heartbeat, learned route, or source endpoint.
- No resource removal before allocation drain and acknowledged route retirement
  or replacement. A sole required path cannot be removed successfully.
- No global serialization, disabled queue, extra RPC, bulk copy, or blocking
  forwarding solely to simplify implementation or create module boundaries.
  Necessary synchronization has an explicit scope and cost.
- No silent omission of asynchronous diffs, batching, multiqueue processing,
  or required parallel execution. Meet baseline Section 0.6 through a correct
  implementation or a justified replacement; naming an optimization is not
  evidence that it exists or performs well.
- No test-only production switch, fixed delay as a synchronization proof, or
  success inferred from an alive process.

## 3. Contract and Change Gate

Before changing a public boundary, its owning specification must define the
applicable responsibility, authority and scope, authorized writers/replicas,
allowed implementation dependencies, public inputs/results, ordering and
visibility, resource lifetime, concurrency, and failure semantics. It must
identify producers/consumers and objective verification. Review adjacent
contracts for cross-domain changes; local summaries alone are insufficient.

Use the subsystem boundary summaries as an index, not another duplicated
specification. Keep record encoding in canonical-record-schema, operation
semantics in the owning subsystem, and cross-domain rules at the baseline's
referenced owner. No universal adapter layer, capability wrapper, lifecycle
hook API, or runtime contract-version registry is required.

Verification is proportionate to the change. Use executable contract checks,
public-header/include/symbol rules where enforceable, and targeted concurrency
or failure checks where needed. Static tooling cannot prove all pointer
ownership or temporal behavior. Historical co-change frequency is diagnostic,
not a mandatory score. A full benchmark/fault matrix is not required for every
patch. Hot-path changes require comparable workload/profile conditions and
relevant throughput, latency, resource-cost, or scaling evidence; record results
outside the charter. Keep diagnostics, runtime, and artifacts bounded.

## 4. Phase 0: Implement Identity, Canonical Records, and IPC Foundations

Implement:

- VM/incarnation, node/member-instance, physical-host, local-runtime, vnode,
  Pod/scope, route-generation, and semantic-operation identities with explicit
  allocation, validation, retirement, and non-overlapping version domains.
- Canonical record codecs, digest/self-digest handling, wire framing, typed
  status/completion records, size limits, and bounded reassembly.
- Authenticated control/local registration and operation-origin binding.
  Reject unknown/incompatible formats, raw-ID substitution, invalid lengths,
  and unauthorized roles before state mutation.
- Local executor request/completion primitives with explicit buffer ownership,
  callback context, cancellation, queue limits, and identity retention.

Acceptance: executable round trips and negative cases verify canonical bytes,
identity isolation, bounded decoding, and late/duplicate completion behavior.
No old producer or reader is retained solely for coexistence. A fixture may
supply canonical records but cannot bypass validation.

Owning contracts: identity-routing, wire-ipc-abi, canonical-record-schema.

## 5. Phase 1: Implement the Unified Per-VM Node Runtime

Implement:

- One node-runtime binary with per-VM coordination and local executor roles,
  explicit instance identity, request correlation, worker queues, and lifecycle
  ownership. Delete independent master/slave production launch paths.
- Candidate/activation validation and local prepare/abort/query records.
  Unadmitted or merely PREPARED instances cannot serve guest traffic.
- The typed local executor ABI for workers and helper QEMU processes, including
  manifest/route references, operation identity, status, and lifetime checks.
- Bounded ingress/dispatch/completion queues, priority, backpressure, and
  independent progress. A locally targeted response must reach the requesting
  local channel rather than be mistaken for another runtime's RPC reply.

Acceptance: real registered local requests complete through the runtime and
executor contract; stale identity, role, manifest, and activation failures are
typed rejections. Worker progress and stop do not depend on a global data-plane
lock. Helper processes cannot acquire an independent network authority.

Owning contracts: runtime-manifest-lifecycle, wire-ipc-abi, and operation specs.

## 6. Phase 2: Implement Validated Membership and Route Services

Implement:

- Trusted compute/gateway registration, instance identity, physical_host_id,
  role/capacity declarations, actual capability probes, and health evidence.
  Probe KVM, TCG, memory/fault mechanics, and optional kernel capabilities
  independently; resolve required versus preferred policy explicitly.
- Validation and PENDING/VALIDATING/PREPARED/ACTIVE transitions with bounded
  authenticated control transport. Reachability alone cannot activate a member.
- Flat/fractal topology compilation, immutable route-snapshot
  prepare/ack/publish/retire, exact snapshot digests and persisted survivor
  RequiredAckSet, and VM route-scope create/retire services.
- Independently budgeted member, vnode-domain, gateway-adjacency/route, and
  per-VM admission storage. Size bounded storage for actual records, not the
  maximum ID or a shared fixed global array. A 4096-slot domain budget is not
  a global cluster limit and crossing 4096 alone does not require fractal.
- Sidecar/gateway lookup against complete snapshots, preserving VM identity
  through every hop; the fabric routes to the remote node runtime.

Acceptance: invalid registrations never become schedulable/routable. Missing
routes fail explicitly. Sparse high IDs, actual route lookup above 4096 under
adequate budgets, and multi-Pod totals above a leaf budget are verified
separately from identifier validity. Unsupported capacity is rejected, never
truncated or advertised solely from a wider integer field. Rerouting preserves
semantic-operation identity and never exposes a partial route table.

Owning contracts: cluster-membership-topology-lifecycle, identity-routing,
wire-ipc-abi, canonical-record-schema, capability-fault-engines.

## 7. Phase 3: Implement Memory Consistency and Baseline Fault Paths

Implement:

- Manifest-selected directory authority and per-page bytes, version,
  subscriber/copyset state, valid/stale predicates, and authorized writes.
- Read/fault resolution, versioned dirty/diff commits, push/invalidation,
  duplicate/reordered update handling, full resync, and exact ACK semantics.
- The handoff fence, including all required dirty/subscriber visibility.
  dirty-batch-size=1 is immediate submission, not automatic global coherence.
- A correct restricted-host TCG fault/capture path and KVM dirty/resync path
  when KVM is available. Signal handlers remain async-signal-safe. Neither
  UFFD nor a kernel module is mandatory.
- Per-page/shard concurrency, asynchronous capture/delivery, batching, QoS,
  bounded pressure recovery, and safe buffer/mapping/subscriber lifetimes.

Acceptance: real bytes/versions and successful fence results match the
contract under representative independent-page concurrency, loss/retry, and
version-gap cases. Queued submission is not a commit ACK. No dependent vCPU
executes against unconfirmed memory, and same-host SHM requires actual shared
backing rather than a local-map or hostname inference.

Owning contracts: memory-consistency, capability-fault-engines, wire-ipc-abi.

## 8. Phase 4: Implement QEMU, vCPU Backends, and Device Coordination

Implement:

- Shared QEMU machine/device/address-space integration with backend-specific
  execution mechanics behind the typed local executor interface.
- KVM context/interrupt/timer export/import, dirty/resync integration, and
  guest-visible exits. Avoid host protection behavior that invalidates KVM RAM.
- Real bounded TCG instructions, checked CPU-state transfer and memory access,
  independent vCPU ownership/progress, and device/atomic exit handling.
- Per-vCPU at-most-once handoff with memory fences, interrupt merging, typed
  error/completion, result queries, and bounded uncertain-result handling.
- QEMU-host device authority for MMIO/PIO/interrupts and block completion.
  Remote block primitives, when selected, retain write ordering, flush/FUA,
  idempotency, data-budget limits, and guest-visible errors. This does not
  require distributed ownership of arbitrary devices or remote disks for
  every VM.

Acceptance: actual instructions and remote memory operations produce checked
results; duplicate handoff cannot execute the interval twice. Device exits
return to the authority, and writes/errors/flushes are not fabricated. KVM/TCG
share semantic results while retaining backend-specific mechanics. Independent
work must meet the selected profile's concurrency contract without global
execution exclusion. Sustained TCG guest usability remains Phase 10.

Owning contracts: vcpu-handoff, memory-consistency, storage-device-authority,
wire-ipc-abi, capability-fault-engines.

## 9. Phase 5: Implement Placement, Admission, and VM Lifecycle

Implement:

- A production CLI/API request entry that uses actual eligible membership,
  inventory, capabilities, routes, and constraints. Implement deterministic
  compact/spread scoring and stable tie-breakers.
- Explicit QEMU host selection and overhead, resource quantities independent
  of node/NUMA selection, physical-host aggregate accounting, exclusive
  port/socket/name leases, and structured rejection without overcommit.
- Backend-aware planning: AUTO tries a complete KVM placement, then a new
  complete TCG placement with explicit fallback; REQUIRE_KVM never degrades.
  A VM's vCPUs use one backend. Memory participants need their memory-service
  capability and route, not necessarily KVM.
- VM identity allocation before candidate digests/reservations, prepared route
  scope, atomic prepared reservations, participant prepare, eligibility-fence
  revalidation, one durable activation decision, commit, start, and readiness.
- Idempotent production prepare/activate/abort/query wiring and persisted
  participant ACKs. Prevent stale activation after cordon, health/capability,
  gateway drain, or selected member-instance changes.
- Pause/stop, partial-start compensation, route/subscriber/completion/context
  retirement, named cleanup owners, safe reuse, and coordinator restart
  reconciliation against the durable decision. Activated allocations cannot
  expire as if they were uncommitted prepare leases.

Acceptance: a multi-node SPREAD request traverses the production entry through
actual participant ACKs to RUNNING with remote CPU/memory evidence. Submission
node and QEMU host may differ. Four concurrent creates cannot double-allocate
CPU, memory, names/ports, or overhead. Normal startup failures release exactly
their own resources. Restart replays/cleans up one recorded decision; no
listener, process, or test-owned planner substitutes for readiness.

Quiesce/drain/finalize follows lifecycle Section 6.3. Timeouts do not establish
cancellation or authorize reuse of a still-referenced resource. Comprehensive
crash matrices and coordinator HA belong to Phase 12, not basic reconciliation.

Owning contracts: resource-placement-admission, runtime-manifest-lifecycle,
cluster-membership-topology-lifecycle, and canonical record/wire contracts.

## 10. Phase 6: Complete Multi-VM and Same-Host Instance Isolation

Implement:

- First-class per-VM runtime state, manifest-derived endpoints, SHM and
  mappings, route/request namespaces, logs, temporary paths, process ownership,
  and reservation/lifecycle records across every participating component.
- Multiple registered compute instances on one physical host with explicit
  instance namespaces and aggregate CPU/memory/context/overhead limits.
- VM-scoped drain and cleanup, process-failure attribution, worker/completion
  references, and independent queue progress under shared infrastructure.

Acceptance: two Mode B VMs and two same-host compute instances coexist with
identical raw vnodes/guest ports where permitted. Stopping or failing one does
not clear, truncate, unlink, quiesce, or consume another's state. Concurrent
admission honors physical-host budgets and exclusive leases. No host-global
port, process-kill pattern, or singleton identity stands in for ownership.

Owning contracts: runtime-manifest-lifecycle, resource-placement-admission,
identity-routing, memory-consistency, vcpu-handoff, wire-ipc-abi.

## 11. Phase 7: Complete Dynamic Member and Gateway Lifecycle

Implement:

- Production join/rejoin, cordon, compute drain/removal, gateway replacement,
  and planned versus unplanned failure outcomes through the control plane.
- Eligibility-fence invalidation for unfinished admissions. Joining adds
  capacity for future placement, never silently rewrites an admitted VM.
- Refusal to remove active vCPU, memory/directory, storage, or required control
  dependencies without an accepted transfer protocol.
- Successor routes prepared and acknowledged by the persisted exact survivor
  RequiredAckSet before gateway switch. The departing/failed gateway is
  optional drain evidence, not a required ACK. Retain predecessor generations
  for active operations and bounded result/query horizons.
- Correlated physical-host health exclusion across hosted roles, and role-local
  handling for independent process faults. Aggregate multi-scope host-removal
  transactions remain Extended.

Acceptance: busy compute drain and sole-gateway removal fail safely; a verified
alternate gateway succeeds without black holes, partial snapshots, duplicate
side effects, or changed VM identity. Required-member loss yields documented
paused/degraded/failed behavior, never false health or implicit rebind. Removing
one VM's dependency cannot erase another VM's live route scope or allocation.

Owning contracts: cluster-membership-topology-lifecycle, identity-routing,
runtime-manifest-lifecycle, resource-placement-admission, wire-ipc-abi.

## 12. Phase 8: Implement Per-VM Kernel Acceleration

Implement:

- Explicit context create/attach, permission validation, per-VM identity,
  mappings, route/config caches, page/dirty metadata, operation namespaces,
  queues, and lifetime-safe TX/VMA/work references.
- Only context-tagged shared infrastructure as module-wide state; user-space
  authorities retain placement, routing, lifecycle, and consistency decisions.
- Typed manifest-derived atomic configuration and completions. Remove legacy
  field-by-field truth injection and module-global VM fallbacks.
- Context-specific quiesce/drain/teardown and bounded shared-worker fairness.
  Another context's execution must not wait on unrelated network/VM teardown.

Acceptance: real /dev/wavevm contexts for two VMs preserve independent bytes,
requests, routes, mappings, and completion/failure lifetimes. Stopping a VM or
closing one FD does not clear another context. Query capabilities honestly;
reject a second context until this evidence exists. Mode A has the same
operation-level results as Mode B and a declared acceleration cost model.
Unavailable module capability leaves valid Mode B plans usable.

Owning contracts: kernel-accelerator and its referenced memory/vCPU/IPC,
capability, manifest, and lifecycle definitions.

## 13. Phase 9: Close Minimum Integration and Acceptance

Complete production wiring across the preceding capabilities and generate
bounded, manifest-driven acceptance runs for:

- Flat/fractal KVM guest login or SSH with remote vCPU and memory evidence.
- Flat/fractal bounded real TCG execution with checked CPU/memory results,
  independent vCPU ownership/progress, device/atomic ordering, and cleanup.
- Mode B multi-VM and same-host compute-instance isolation, admission races,
  membership operations, lifecycle/restart reconciliation, and two-VM Mode A
  contexts. Bounded contract workloads may establish isolation but cannot
  replace the KVM guest cells.
- Representative independent-work concurrency and bounded queue/resource use
  for the selected profile. Record declared workloads and hardware conditions;
  comprehensive tuning and scale characterization do not block Minimum.

Every cell records manifest identity/digest, route snapshot, capability profile,
actual resource arguments, remote CPU/memory activity, failure classification,
bounded diagnostics, and cleanup. Success requires the contract's result,
not a stub, open socket, live process, local-only execution, or hidden workaround.
Every run has a fixed timeout and bounded artifacts; cleanup cannot delete an
unrelated VM's processes, files, SHM, routes, or reservations.

Failures are classified as capability, launch, routing, memory, CPU state,
device, lifecycle, or guest acceptance and fixed in the owning production
path. They are not converted into false RUNNING or relaxed success criteria.

**Minimum boundary: after Phase 9.** TCG guest OS login/SSH, sustained TCG
guest usability, complete fault-engine coverage, and operational hardening
continue below. The boundary does not remove shared correctness obligations.

---

## 14. Phase 10: Extended TCG Guest Usability

Implement flat/fractal TCG guest boot/login/SSH and sustained distributed
multi-vCPU execution under the shared memory, device, identity, and lifecycle
contracts. Concurrent remote progress must be the normal path rather than a
token trickle under force_local. Verify per-vCPU fallback bounds, ordering,
cooldown, device bounce, and STOP according to vcpu-handoff Section 8.1.

Acceptance: guest-visible results, remote CPU/memory evidence, concurrency,
bounded fallback, and cleanup satisfy the separate Extended guest gate. A
Minimum instruction contract pass is insufficient. Full native/helper MTTCG
performance work may improve this path, but cannot weaken its semantic or
sustained-progress requirements.

## 15. Phase 11: Extended Fault Engines and Performance Coverage

Implement broader fault_engine_ops coverage for SIGSEGV/mprotect, UFFD, KVM
logging, and kernel dirty capture on supported hosts. Preserve page versions,
engine state, async-signal-safety, and explicit selection. Live engine switching
requires a state-transfer contract, not a timeout-triggered fallback.

Extend verification to mixed accelerator/no-accelerator clusters, cross-engine
equivalence, deterministic loss/duplication/reordering/delay, route replacement,
and QEMU/runtime/executor/gateway faults. Include duplicate handoff, dirty gaps,
block errors, VM-ID reuse, and broader same-host isolation. Baseline ordering
and error correctness remain Minimum; this phase expands the coverage matrix.

Characterize throughput, tail latency, copies/round trips, CPU/memory cost,
fairness, and scaling under declared topology and hardware conditions. Optimize
queues, diffs, batching, placement locality, and backend execution based on
those results, including broader MTTCG work where appropriate. Acceptance must
not depend on a topology-independent performance promise or a mandatory
transport chosen solely by name. Evidence remains in separate records.

## 16. Phase 12: Extended Recovery and Live Reconfiguration

Implement coordinator HA/failover, complete crash-boundary matrices,
transparent recovery, verified replacement and RECOVERY_REBIND, live migration,
automatic replanning/resharding, and active-VM topology/resource changes only
under explicit identity, old-instance fencing, state-transfer, and rollback
contracts. Cross-backend execution handoff and live fault-engine changes also
require their own transfer contracts; implicit conversions are prohibited.

Add aggregate multi-scope host-role transactions and broader failure-domain
handling. Persisted decisions, resource release, route replacement/retirement,
page versions, vCPU sequences, and device ordering remain consistent across
recovery. Acceptance converges to one committed VM or confirmed cleanup with no
orphaned resources or false RUNNING. Basic restart reconciliation and rejection
of stale admission candidates remain Minimum obligations.

## 17. Phase 13: Extended Hosted Host-OS Portability

Implement a declared hypervisor adapter that runs the same Linux host appliance
on a non-Linux host or where native deployment is impractical. Before changing
this boundary, its adapter contract must define trusted physical_host_id and
correlated-failure mapping, networking, capabilities, overhead, and lifecycle.
An endpoint, hostname, or appliance-local observation cannot establish that
mapping. Without trusted mapping, do not claim cross-appliance aggregate
capacity or correlated-host coverage.

Acceptance criteria:

1. On at least one non-Linux host, the adapter starts a Linux host appliance
   carrying control plane, node runtime, gateway/sidecar, and executor; it is
   not a substitute WaveVM guest.
2. Without nested KVM, only TCG execution plans are admitted. Without usable
   wavevm.ko, Mode A is disabled and Mode B selected, while KVM Mode B remains
   valid when its independent probe passes. The appliance completes the same
   manifest-bound control path and guest smoke; unsupported capabilities fail
   or record explicit policy-allowed pre-admission fallback. TCG guest smoke
   here requires Phase 10 acceptance, not just the Minimum instruction gate.
3. KVM and Mode A are advertised only after their respective in-appliance
   probes and context/teardown checks pass. Mode A context requirements do not
   apply to KVM Mode B, and outer-host capabilities are never assumed inherited.
4. Flat/fractal routing, membership, generations, accounting, stop/cleanup,
   identity/incarnation, and lifecycle match native Linux semantics. NAT and
   bridging must preserve reachable manifest endpoints, leases, and mTLS
   identity bindings.
5. Evidence records hypervisor, appliance image/profile, probes, actual
   resource parameters, and typed failures without hidden workarounds. Account
   for outer CPU/memory/hypervisor overhead. Trusted physical_host_id mapping
   prevents appliances on one machine from double-counting capacity or being
   mistaken for independent failure domains.
6. Adapter/capability failure cannot produce false RUNNING. Diagnostics and
   cleanup remain bounded and identity-scoped.

Native non-Linux user-space and native Mode A/kernel ports are separate
Extended capabilities, not implied by hosted portability. Their contracts must
map the same semantic authorities, local execution/IPC lifetimes, capability
reporting, identity, and acceptance behavior to the target OS; unsupported
mechanics fail explicitly rather than changing the VM contract.

**Extended boundary: after Phase 13 and the explicitly selected native-port
contracts.** These labels organize delivery scope, not implementation status.

---

## Implementation Order

Use the following dependency order when implementing from zero or restructuring
an affected path. Each phase requires its relevant public contracts and working
prerequisite capabilities; inventories and empty placeholders cannot satisfy it.

| Phase | Executable capability |
| --- | --- |
| 0 | Identity, canonical records, wire/local IPC foundations. |
| 1 | Unified per-VM node runtime and typed local executor management. |
| 2 | Validated membership, capability probes, route compilation and fabric. |
| 3 | Memory consistency and baseline restricted-host/KVM fault paths. |
| 4 | QEMU integration, KVM/TCG execution, vCPU and device coordination. |
| 5 | Production placement, admission, activation, readiness and lifecycle. |
| 6 | Integrated multi-VM and same-host compute-instance isolation. |
| 7 | Dynamic members, cordon/drain and gateway replacement. |
| 8 | Real per-VM kernel acceleration and context isolation. |
| 9 | Complete Minimum production integration and acceptance matrix. |
| 10 | Extended TCG guest usability. |
| 11 | Extended fault engines, coverage and performance/scaling work. |
| 12 | Extended recovery, HA, migration and live reconfiguration. |
| 13 | Extended hosted portability and separately specified native ports. |

Isolation and concurrency apply from the first affected state/queue, not only
when Phase 6 or Phase 9 is reached. Later phases integrate and verify them at
broader scope. Extended items may proceed independently when their actual
prerequisites are met; numbering does not impose unrelated dependencies, and
hosted TCG guest acceptance still depends on Phase 10.

## Maintenance Review

For an affected production path, identify its owning contract and consumers;
verify identity/authorization, state authority, lifetimes, ordering, failure
semantics, and selected profile. Preserve the node-runtime/fabric boundary and
explicit physical-host resource accounting. Explain any change to queues,
blocking, copies, network hops, batching, fairness, or synchronization scope.
Use bounded verification proportional to those changes. Fix implementation
conflicts or justify a target change under baseline Section 0.1; do not derive
architecture from whichever code happens to exist.

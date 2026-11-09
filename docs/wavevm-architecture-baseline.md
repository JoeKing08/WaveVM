# WaveVM Architecture Baseline

Status: normative architecture baseline for long-term maintenance.
Scope: this document defines architectural authority, boundaries, invariants,
and delivery-profile decisions. Subsystem specifications define their detailed
contracts and acceptance conditions.

The [Document Maintenance](wavevm-refactor-roadmap.md#document-maintenance)
rules govern this baseline and all subsystem specifications. Implementation
progress and verification results belong in separate plan and audit records.

The WaveVM design documentation has three levels:

1. This baseline defines what the system is and which component owns each class
   of decision.
2. `wavevm-refactor-roadmap.md` defines implementation dependency order and
   acceptance boundaries, including requirements for architectural changes.
3. Subsystem specifications define exact structures, state machines, APIs,
   message semantics, lock ordering, failure behavior, and executable tests.

The following subsystem specifications must exist before the corresponding
runtime is substantially rewritten:

- `docs/specs/memory-consistency.md`
- `docs/specs/vcpu-handoff.md`
- `docs/specs/identity-routing.md`
- `docs/specs/wire-ipc-abi.md`
- `docs/specs/canonical-record-schema.md`
- `docs/specs/runtime-manifest-lifecycle.md`
- `docs/specs/resource-placement-admission.md`
- `docs/specs/cluster-membership-topology-lifecycle.md`
- `docs/specs/capability-fault-engines.md`
- `docs/specs/kernel-accelerator.md`
- `docs/specs/storage-device-authority.md`

Existing code is evidence of observed behavior, not a normative definition of
the target. Missing detail requires a decision in the owning specification
before changing that boundary; it is not permission to copy an accidental
implementation constraint or invent a second semantic path.

## 0. Architecture Authority and Maintenance Contracts

### 0.1 Target Authority and Design Changes

Project requirements, correctness and isolation invariants, verified technical
constraints, and reproducible evidence determine the architecture. Existing
file layouts, call graphs, state structures, and historical decisions do not
define or override it. External projects provide evidence and design lessons,
not templates that supersede WaveVM's requirements.

When code and a normative contract disagree:

| Condition | Required response |
| --- | --- |
| Required behavior is missing or incorrect. | Bring the implementation into compliance. |
| Historical compatibility introduced a compromise. | Remove the unnecessary compatibility path; retain one only for an explicitly required deployment obligation. |
| A case has no specified behavior. | Resolve it in the owning specification before choosing implementation semantics. |
| A requirement is contradicted by verified constraints or evidence. | Reconsider the architectural decision and update affected contracts together. |
| The code implements a different design. | Assess that design against the requirements; its existence does not authorize it. |

A core design change must state the triggering requirement or constraint,
supporting evidence, alternatives and trade-offs, affected authorities and
consumers, and how its correctness and performance consequences will be
verified. Implementation convenience and sunk migration cost alone do not
justify weakening correctness, isolation, or required capabilities. The project
owner may explicitly revise optional feature scope and delivery priorities for
budget or maintenance reasons; update the profile boundary and dependent
contracts rather than claiming that an unimplemented requirement was met.

The baseline, roadmap, and subsystem specifications state required behavior
and acceptance conditions only. Observed dependency graphs, code inventories,
implementation gaps, test results, and progress belong in separate records.
An observed dependency matrix must not be copied into an allowed-dependency
contract without architectural justification.

### 0.2 Logical Module Boundaries

Each subsystem must declare its responsibility, non-responsibility, public
interfaces, allowed implementation dependencies, and private state. Consumers
must use public contracts, not private structures, hidden globals, incidental
include order, or accidental link dependencies. Implementation dependency
cycles are prohibited; explicitly contracted request/reply or callback
interaction can be bidirectional without creating such a cycle.

Organize modules around domain responsibilities and state ownership. A file
length, existing directory name, or preferred AI context size does not decide
the boundary. Do not introduce another process, RPC, service, or generic
adapter solely to create modularity. The node-runtime roles remain within
one production node-runtime binary; local worker/helper isolation follows its
execution and fault-containment contract, not historical master/slave launch
paths. QEMU facilities outside distributed coordination should use shared
machine, device, address-space, and backend facilities rather than duplicate
them for each execution mode.

### 0.3 State Authority, Writers, and Replicas

For each important state or resource, identify its key and lifetime scope,
semantic authority, authorized mutation entry points and execution contexts,
readers, replicas, invalidation rules, and reclamation owner. Scope must be
precise: a VM incarnation, page, vCPU, route snapshot, admission transaction,
or kernel context, not merely a component name such as "node runtime."

Semantic authority decides validity and transitions. An authorized writer may
apply those transitions under the authority's contract; a replica or cache
does not acquire authority by storing bytes. Multiple writers, shards, workers,
and queues are permitted when their ordering and conflict rules are explicit.
Single authority does not imply one global thread, lock, or serialization
domain. Delegation must define its scope and how stale writers are fenced.

Non-owners may not mutate authoritative state through exposed pointers or
reconstruct another authority's policy. Snapshots and caches must define their
publication, version validation, expiry/invalidation, and safe reconstruction.
Local cache ownership never authorizes choosing a new page version, placement,
VM identity, or lifecycle outcome.

### 0.4 Cross-Subsystem Interaction Contracts

Cross-boundary contracts must specify applicable identity and authorization,
preconditions, successful completion and visibility, required ordering,
ownership transfer or borrowing, resource lifetimes, execution context,
blocking/reentrancy constraints, and failure/timeout/cancellation semantics.
Asynchronous operations must define late completion, retry identity, reference
retention, and partial or uncertain results. In-process calls, shared memory,
local IPC, network transport, and device memory do not provide interchangeable
visibility guarantees; identify which layer supplies each synchronization
obligation. C atomics alone do not establish cross-node coherence.

Each cross-domain rule has one owning specification and a stable section
reference. Other specifications reference that definition and add their local
obligations without copying or redefining it. The following ownership applies:

| Interaction contract | Owning definition | Required consumers |
| --- | --- | --- |
| Candidate preparation and durable activation | [Runtime lifecycle Section 5.2](specs/runtime-manifest-lifecycle.md#52-create-and-activate-sequence) | Placement/reservations, membership, node runtime, QEMU, executors, gateways, kernel contexts. |
| Quiescence, drain, and final reclamation | [Runtime lifecycle Section 6.3](specs/runtime-manifest-lifecycle.md#63-cross-subsystem-resource-retirement) | IPC, memory, vCPU, storage, routes, kernel contexts, reservation/name owners. |
| Memory visibility at vCPU ownership transfer | [Memory Section 4.6](specs/memory-consistency.md#46-handoff-fence) | vCPU coordinator, frontend, executor, fault engines, kernel acceleration. |
| Route replacement and semantic-operation lifetime | [Identity/routing Section 6.1](specs/identity-routing.md#61-route-replacement-and-operation-lifetime) | Wire/IPC, gateways, membership, lifecycle, memory/vCPU/block operations. |
| Remote execution exits and device authority | [vCPU Section 7](specs/vcpu-handoff.md#7-exit-device-interrupt-and-time-semantics) | Frontend devices, executors, memory, storage, lifecycle. |

Subsystem boundary summaries must index the owning sections for authority,
allowed dependencies, state, cross-domain interactions, concurrency/cost,
failure, and verification. They are navigation aids, not duplicate schemas or
parallel sources of truth. Concrete encodings belong to the wire/schema or
operation specification that owns them. Document history is tracked in Git;
stable references do not require numbered API names, a new runtime registry,
or support for obsolete contracts. A boundary change must identify and update
affected producers, consumers, and verification mappings together.

### 0.5 Lifecycle Coordination and Authorization

The lifecycle coordinator owns overall phase transitions; each subsystem owns
its internal quiescence, in-flight work, references, and resource reclamation.
Quiesce, drain, and finalize are logical obligations, not a mandatory universal
hook API or another VM state machine. Required ACKs, fences, cancellation,
result queries, and cleanup traffic must remain possible during draining.
Reclamation requires the subsystem's completion or fencing proof; a timeout
or a local zero counter is not proof that remote work can no longer act.
Independent cleanup may proceed concurrently within the declared ordering.

Security boundaries must state the authorization source, permitted resource
scope, and revocation or expiry rules. Use capabilities or handles where their
resource delegation and lifetime semantics are needed; do not require a
capability wrapper for every internal call. A transport endpoint, resource ID,
or cached record alone is not proof of authorization.

### 0.6 Performance and Scalability Requirements

The system must implement and maintain the parallel execution, locality,
batching, and bounded resource use required by its resource-pooling goals and
selected delivery profile. Correctness work must supply the necessary
concurrent design, not merely preserve whatever concurrency already exists.
The Minimum/Extended TCG boundary in Section 16 remains applicable; this rule
does not move sustained TCG guest usability into Minimum.

Independent VMs, vCPUs, pages, and operation keys must be able to progress
concurrently where their contracts and available resources permit. Scope
ordering and synchronization to the related resource or transaction; a shared
worker or registry is not permission for a global data-plane critical section.
Any centralized coordination, additional IPC/network hop, bulk copy, blocking
wait, or serialization on a normal hot path requires a reason and a bounded
cost/concurrency model. Necessary topology, isolation, and durability costs
must remain explicit; eliminating a hop never authorizes bypassing an authority.

Performance-sensitive contracts must describe queue ownership and limits,
in-flight concurrency, blocking and callback context, batching/coalescing,
priority/fairness, data copying and locality, and overload behavior. Implement
asynchronous and parallel paths where required; do not merely declare them
possible. Backpressure must be bounded and must neither lose required work nor
starve the control/completion traffic needed to recover.

Concrete mechanisms such as MPSC queues, UDP, asynchronous diffs, or batched
I/O may be corrected or replaced when evidence supports the alternative.
Neither their historical presence nor implementation convenience decides the
choice. Changes that remove an optimization, broaden synchronization, or
alter hot-path queues must explain how the required capabilities are met and
use proportionate before/after evidence under comparable conditions. A guest
boot alone cannot establish parallelism or absence of a performance regression.

Acceptance specifications define relevant throughput, tail-latency, CPU/memory
cost, and scaling checks with workload, topology, capability profile, and
hardware conditions. Measurements and accepted trade-offs belong in separate
verification/design records, not as implementation status here. Do not impose
hardware-independent latency promises, a full benchmark matrix on every edit,
or a requirement to complete all performance tuning before Minimum acceptance.
Essential parallelism and bounded operation remain required within each profile.

Architecture checks should enforce a small set of explicit dependency and
interface rules, supplemented by targeted contract tests and review. Automated
include/symbol checks cannot prove all state ownership or temporal correctness
in C/C++. Historical co-change frequency is diagnostic evidence, not a hard
coupling metric. Local work may use the relevant boundary summaries; changes
that affect shared semantics must also review the neighboring contracts.

## 1. Project Goal

WaveVM is a distributed QEMU platform that presents a single guest VM backed by CPU and memory resources from multiple physical nodes.

The long-term goal is not only to boot a demo guest. The goal is a maintainable distributed virtualization substrate with these properties:

- The guest keeps using a normal virtual machine interface.
- Physical CPU and memory can be pooled across nodes.
- The same high-level semantics apply to KVM and TCG.
- The same high-level semantics apply to flat and fractal topologies.
- The same cluster can host multiple independent VMs.
- A physical host can expose multiple explicitly isolated compute-node
  instances when its aggregate CPU, memory, accelerator, port, and socket
  budgets are sufficient.
- Compute nodes and routing gateways can join, drain, fail, and leave through
  explicit control-plane lifecycle operations.
- Restricted environments can run without a kernel module.
- Kernel help, when available, accelerates the same semantics rather than defining another product.

WaveVM should be treated as a distributed QEMU, not as a collection of test-specific forwarding hacks.

The project has two acceptance horizons:

**Minimum usable system:** a manifest-bound KVM VM can reach guest login or
SSH, use flat or fractal routing, and share a physical host with other Mode B
VMs with isolated resources and identity. TCG remains an execution backend in
Minimum: bounded execution, remote memory, CPU-state handoff, device-authority
exits, and cleanup must satisfy the same semantic contracts. Full TCG guest
boot/login and sustained multi-vCPU guest usability belong to Extended, as
defined in Section 16 and `vcpu-handoff.md` Section 8.1. A TCG contract-test
pass does not establish that a TCG guest OS is usable. Mode A is usable for
multiple VMs only after explicit per-VM kernel contexts and teardown isolation
pass. The minimum system also includes basic node/gateway join, compute
cordon, safe drain, and gateway replacement through acknowledged route snapshots.

**Extended:** full TCG guest boot/login/SSH and sustained distributed
multi-vCPU guest usability, coordinator high availability, automatic migration or
resharding, transparent recovery after loss of required compute state, full
fault-engine plugin coverage, exhaustive network/lifecycle fault injection, and
hosted host-OS portability (a hypervisor adapter running the same Linux host
appliance on a non-Linux physical host; not a WaveVM guest and not a native
non-Linux port). These extend backend coverage or operational resilience; they
are not prerequisites for the Minimum KVM guest and TCG contract-test gates.
See roadmap Section 1.1 and Phases 10 through 13.

The two horizons do not define two products or two semantic paths. Extended
features must preserve the same manifest, identity, routing, memory, and vCPU
contracts established by the minimum system.

## 2. Non-Goals

The following are not acceptable long-term directions:

- Hardcoding node IDs, ports, vm IDs, CPU counts, memory sizes, or route entries to pass one test.
- Adding production-path command-line switches whose only purpose is to hide an implementation bug.
- Making KVM and TCG two unrelated products.
- Making Mode A and Mode B two independent control planes.
- Letting the kernel module own global VM lifecycle semantics.
- Requiring a custom host kernel as a baseline feature.
- Requiring KVM as the only supported execution backend.
- Replacing WaveVM's sidecar/gateway and per-node-runtime model with direct
  QEMU-to-QEMU routing merely because another project does that.
- Treating a heartbeat, route-learning observation, or one gateway control
  datagram as authoritative membership admission or removal.
- Removing a compute node or gateway from an active VM by deleting its route
  before the dependent allocation or traffic has been drained.

## 3. Canonical Architecture

The canonical WaveVM architecture separates control plane from per-VM data
plane:

```text
User CLI / API
    |
    v
User-space cluster control plane
    |  manifest, placement, reservation, lifecycle
    v
For each participating `{vm_incarnation, physical_node_id}`:

QEMU frontend (host node only)
    |
    | local ABI / shared memory / accelerator hooks
    v
User-space node runtime
    |                         |
    | local executor ABI      | sidecar/gateway fabric
    v                         v
KVM workers or TCG helpers    Remote sidecar -> remote node runtime -> executor
```

The user-space control plane owns cluster resource inventory, VM identity and
incarnation allocation, resource planning, host placement, admission, and VM
lifecycle. A node runtime owns the per-VM runtime semantics delegated by the
admitted manifest: VM-scoped routing, page consistency, request correlation,
and CPU/memory dispatch. Both are user-space semantic authorities in
non-overlapping domains.

The names `master` and `slave` describe logical roles inside a node
runtime, not a permanent requirement for two separately deployed services. The
master role is the semantic coordinator and local fabric endpoint. The slave
role is the local executor manager. One node-runtime binary provides both
roles, with explicit worker queues, local ABI, lifecycle, and fault containment;
independent master/slave production launch paths are not supported. A TCG
helper QEMU may remain a separate process because its
QEMU lifecycle and address space require that isolation.

Every remote operation terminates at the remote node runtime before reaching a
local executor. Neither an executor nor a QEMU frontend is a production
cross-node endpoint.

The kernel module, if present, is an accelerator. It must not become a second semantic authority.

## 4. Core Components

### 4.1 User-Space Cluster Control Plane

This is a logical role. Its production entry point may be a control tool and
node launcher; its authority does not require an additional distributed service.

Responsibilities:

- Maintain registered physical capacities and capabilities.
- Own desired and observed membership for compute nodes, sidecars, and
  gateways, including their identity, endpoint, capability, health, and
  lifecycle state.
- Own the cluster topology graph, Pod membership, and flat/fractal topology
  selection. The topology is a cluster decision, not a per-test script flag or
  a guest-visible requirement.
- Generate, prepare, atomically publish, and retire versioned route snapshots
  from that membership and topology state.
- Allocate `vm_id` and VM incarnation.
- Validate a versioned VM request or launch manifest.
- Plan vCPU, memory, host, device, and control-plane overhead placement.
- Reserve resources and coordinate the candidate/activation/commit/retire
  transaction defined by the lifecycle specification.
- Generate the admitted per-node runtime manifests.
- Report structured lifecycle and admission failures.

Non-responsibilities:

- It must not participate in every page fault or vCPU RPC.
- It must not make gateway or kernel caches semantic authorities.
- It must not infer successful VM startup from process survival alone.
- It must not make a node schedulable or a gateway active solely because one
  UDP packet or heartbeat was received.

### 4.2 QEMU Frontend

The frontend integration baseline is QEMU 5.2.0; upgrades must preserve the
guest-visible and distributed-operation contracts.

Responsibilities:

- Present the guest-visible machine, devices, RAM, vCPUs, NUMA layout, disk, and network.
- Implement the WaveVM accelerator glue.
- Export and import vCPU state for remote execution.
- Route remote memory and CPU operations through the local node runtime.
- Keep KVM and TCG differences behind accelerator-specific code.

Non-responsibilities:

- QEMU must not hardcode physical cluster topology.
- QEMU must not become the global control plane.
- QEMU must not directly route around the local node runtime and sidecar/gateway
  fabric for production traffic.

### 4.3 Node Runtime Coordination Role

The user-space node runtime is the canonical authority for one logical VM
instance on one participating physical node. Semantic coordination and local
execution are logical roles within the unified node-runtime boundary, not
independently deployed services.

Responsibilities:

- Consume only the admitted per-node manifest, route snapshot, dispatch
  projection, and capability profile.
- Hold the VM and node identity assigned by the control plane.
- Own CPU route table and memory placement table for that VM.
- Own page directory and version state in Mode B baseline.
- Validate local and remote operations against the admitted identity, manifest,
  route generation, and semantic contract before dispatch.
- Dispatch local CPU, memory, and storage operations through the local
  executor interface.
- Correlate executor completion with the originating QEMU or remote node
  request; an executor response must not be mistaken for an unrelated local
  RPC reply.
- Send all cross-node traffic through the local sidecar/gateway path.
- Provide QEMU IPC endpoint for the local frontend.
- Provide a stable surface for optional accelerators.

Multiplicity and concurrency requirements:

- Every `{vm_incarnation, physical_node_id}` has its own node-runtime state,
  even when one process hosts multiple VM instances on the same physical node.
- The normal data path implements explicit queues, batching, and QoS. Moving an
  executor behind an in-process interface must not turn the node runtime into
  one globally serial executor.

### 4.4 Node Runtime Local Executor Role

The local executor role performs assigned execution and storage work for one VM
instance on one physical node. It is not an independent distributed semantic
authority or a separately deployed master/slave service.

Responsibilities:

- Execute remote vCPU slices under KVM or TCG.
- Own local KVM vCPU objects when KVM is available.
- Spawn helper QEMU TCG instances when using TCG slave execution.
- Apply and return memory updates needed by remote execution.
- Handle storage operations assigned to the physical node.
- Return precise completions and errors through the node runtime's local
  executor interface.

Non-responsibilities:

- The execution runtime must not become the cluster control plane or the
  per-VM routing/directory authority.
- It must not communicate cross-node directly. It returns to its local node
  runtime, which decides whether a sidecar/gateway transmission is required.
- It must not create or truncate another VM's shared memory backing.

Deployment rule:

- KVM executor workers may be in-process worker threads or a separate local
  supervisor.
- TCG helper QEMU processes may remain separate local processes.
- The process choice must not change local request identity, ordering,
  idempotency, queue ownership, or failure reporting.

### 4.5 Node Runtime Boundary

The required boundary is semantic and protocol-oriented, not an unconditional
process boundary:

- The node runtime owns manifest validation, routing and placement lookup,
  request identity, memory/vCPU handoff coordination, and cross-node ingress
  and egress.
- The local execution runtime owns execution mechanics and local resources such
  as KVM vCPU objects or TCG helper processes.
- The local executor ABI must carry VM identity, incarnation, manifest/route
  generation, operation identity, completion status, and enough ordering
  information to satisfy the memory and vCPU contracts. It must be specified
  by the memory, vCPU, and local IPC specifications before it replaces legacy
  master-to-slave messages.
  - Legacy `master_core` to `slave_daemon` IPC is not a supported production
    ABI and must be replaced by the typed
    node-runtime/executor interface.
- Removing a process hop is permitted only after the same role boundary,
  concurrency model, backpressure behavior, and fault behavior have regression
  coverage. It is not permission to bypass the node runtime or to serialize the
  normal path.

### 4.6 Gateway / Sidecar Fabric

The gateway fabric is the only production cross-node network path.

Responsibilities:

- Route packets by composite target identity.
- Support flat and fractal topology.
- Isolate VM traffic by composite ID and explicit route table entries.
- Avoid auto-learning behavior that overwrites static production routes.
- Preserve low-latency handling for synchronous RPC messages such as VCPU_RUN/VCPU_EXIT.
- Deliver cross-node packets to the target node runtime, never directly to an
  arbitrary executor.

Non-responsibilities:

- Gateway must not inspect guest semantics beyond routing and scheduling priority.
- Gateway must not synthesize VM lifecycle decisions.

### 4.7 Optional Kernel Accelerator

The kernel module is not a separate Mode A product. It is an optional data-plane accelerator for the user-space canonical path.

Allowed responsibilities:

- Fast page dirty capture.
- Fast page invalidation or page wakeup.
- Fast local enqueue to a local executor after the node runtime has accepted
  and authorized the operation.
- Fast packet TX/RX when it preserves user-space semantics.
- Optional low-overhead wait queues for blocking memory or vCPU operations.

Forbidden responsibilities:

- Owning global vm_id authority.
- Owning resource planning.
- Owning host placement.
- Owning multi-VM lifecycle.
- Owning a separate copy of cluster topology as the source of truth.
- Owning another independent logic_core state machine unless that state is explicitly per-VM and synchronized by user-space control.

VM-specific state must be owned by explicit kernel contexts. Shared
module-wide transports and workers require context references and safe
lifetimes; they cannot authorize sharing VM identity or semantic state.
Multi-VM capability remains subject to the isolation gate in Section 14.

## 5. Mode Model

### 5.1 Current Terminology

Historically:

- Mode A means `wavevm.ko` is loaded and `/dev/wavevm` is available.
- Mode B means the system runs without the kernel module.

This terminology remains useful for deployment, but it must not imply two independent architectures.

### 5.2 Long-Term Rule

Mode B is the canonical semantic path.

Mode A is Mode B plus optional kernel acceleration.

This means:

```text
Correctness first exists in Mode B.
Mode A may accelerate correctness-preserving operations.
Mode A must never define different correctness semantics.
```

### 5.3 Practical Consequence

Any new feature must first answer:

- What is the Mode B behavior?
- What is the KVM behavior?
- What is the TCG behavior?
- What optional kernel acceleration can speed it up without changing the behavior?

A feature that only works because `wavevm.ko` owns hidden state is not a baseline feature.

## 6. Execution Backends

### 6.1 KVM

KVM is a hardware-accelerated execution backend.

KVM-specific responsibilities:

- Use KVM vCPU ioctls to load and run remote vCPU state.
- Use KVM dirty logging or equivalent mechanisms for guest RAM writes.
- Avoid `mprotect(PROT_NONE)` on KVM RAM paths where it causes EPT violation storms or invalid host mappings.
- Preserve LAPIC, MP state, vCPU events, TSC, and interrupt delivery state across remote execution.

KVM must still obey the same WaveVM CPU route table, memory placement table, and consistency model.

### 6.2 TCG

TCG is the required no-KVM execution backend.

TCG-specific responsibilities:

- Export and import TCG CPU state.
- Preserve guest-visible interrupt state, LAPIC state, and halted/runnable state.
- Maintain remote execution handoff boundaries.
- Handle memory faults and dirty synchronization in user space.
- Avoid assuming a hardware MMU or KVM dirty log exists.

TCG is not an optional toy path. It is required for restricted containers, no-KVM cloud instances, and development environments.

### 6.3 Shared Semantics Between KVM and TCG

KVM and TCG must share these semantics:

- Same guest VM resource definition.
- Same vCPU index to physical-node route mapping.
- Same memory chunk to physical-node placement mapping.
- Same page ownership/version policy.
- Same handoff consistency boundary.
- Same guest-visible machine layout.
- Same error reporting semantics.

Implementation may differ only at the execution and memory-trap layer.

The exact handoff ABI is defined by `docs/specs/vcpu-handoff.md`. That specification
must define field ownership, export/import ordering, vCPU exclusion, interrupt
merging, timeout behavior, and duplicate-request handling before the handoff
path is substantially changed.

Minimum supports a homogeneous execution backend inside one VM:

- KVM frontend to KVM execution runtime.
- TCG frontend to TCG execution runtime.

The cluster itself may be heterogeneous. A physical node with KVM may
advertise both KVM and TCG executor capability when its TCG helper is valid;
a node without KVM normally advertises TCG only. `AUTO` admission prefers a
complete KVM placement and, if that cannot be admitted, creates a new complete
TCG placement and records the fallback before activation. `REQUIRE_KVM` fails
instead of degrading. Guest memory placement is independent of this choice:
KVM and TCG VMs may use memory participants without KVM when their memory
service capability, capacity, and route are valid.

Mode A and Mode B may still be mixed between nodes because kernel acceleration
is independent of the execution backend. KVM-to-TCG or TCG-to-KVM vCPU handoff
is not a Minimum capability. It must fail capability negotiation rather than
attempt an implicit conversion.

## 7. Multi-VM Model

### 7.1 VM Identity

WaveVM uses complete scoped identities for network-visible operations, as
defined by the identity/routing and wire specifications. A historical packed
8-bit VM / 24-bit node identifier cannot represent that contract and must not
be used as a production VM identity.

The identity terms are distinct:

- `vm_id` is a `u32` logical namespace allocated to a VM. It is not a durable
  identity by itself.
- `vm_incarnation` is a generation created for each successful VM creation. It
  prevents delayed traffic from an old VM lifetime entering a new VM that
  reuses the same `vm_id`.
- `physical_node_id` identifies a registered resource-providing host in the
  cluster.
- `physical_host_id` identifies the physical host group for aggregate resource
  accounting and correlated failure. It may contain multiple distinct
  `physical_node_id` resource providers and gateway roles.
- `vnode_id` identifies a DHT/routing slot inside one VM namespace. A physical
  node may own multiple vnodes.
- `primary_vnode` is the designated local vnode in the admitted route scope.
  It is not the physical node ID or a substitute for the complete route key.
- `WVM_INSTANCE_ID` is a local runtime discriminator used to derive socket and
  file names. It may differ between physical nodes participating in the same VM
  and must not be used as a network identity.
- A process instance ID is diagnostic identity for one process lifetime. It is
  not a VM, node, or routing identity.
- A network-visible route key identifies a VM-incarnation-scoped destination;
  production traffic must meet the complete identity and route-scope
  requirements of the wire and identity/routing specifications.

Minimum identity rules:

- Every network route and packet belongs to exactly one VM namespace.
- VM operations carry complete identities. `vm_id=0` is reserved for the
  authenticated cluster-control scope, not raw-ID guest traffic.
- DHT-internal tables may use raw vnode IDs only where the enclosing per-VM
  runtime context makes the namespace unambiguous.
- Physical node IDs and vnode IDs occupy different semantic domains even when
  their numeric values happen to match.
- `WVM_INSTANCE_ID` must never be treated as an alias for `vm_id`.
- Node-agent identity, listener ports, Unix socket paths, shared-memory names,
  logs, and temporary paths must be explicitly parameterized by the
  registered node instance. A host-global default is invalid when two node
  instances share one host.
- Reject a wire path that cannot validate the required incarnation and scope.
  ID reuse requires confirmed retirement and a fresh incarnation; node/page
  epochs must not be repurposed as VM incarnation.

### 7.2 Per-VM Runtime Isolation

Each VM instance must have isolated:

- `vm_id`
- `vm_incarnation`
- `WVM_INSTANCE_ID`
- QEMU IPC socket path
- `WVM_SHM_FILE`
- node-runtime ingress endpoint
- local executor binding
- gateway/sidecar route namespace or route keys
- QEMU monitor/serial/SSH forwarding ports
- log directory
- temp directory
- resource reservation
- page directory state
- vCPU route table
- memory placement table

No two VMs may share the same RAM backing file unless they are explicitly implementing a future shared-memory feature. Accidental SHM sharing is a correctness bug.

The generated runtime manifest is the source of all local names. Components
must not independently derive incompatible socket, SHM, port, or log names from
only a raw node ID. The candidate's local-name salt is derived before its
self-digest from its allocated `manifest_id`, `admission_tx_id`, VM identity,
generation, and physical-node ID; the final manifest digest verifies that
published namespace rather than participating in a hash cycle.

### 7.3 Host Placement

A VM's host node is the physical node that runs the authoritative QEMU frontend for that VM.

Host placement requirements:

- Host placement must be explicit, not inferred from the first vCPU placement
  block.
- The control plane must be able to accept a VM creation request on any physical node and then choose the host node.
- The host node does not have to be the node where the request was submitted.
- Host placement must account for QEMU/control-plane overhead, not only guest vCPU and guest RAM.

### 7.4 Admission Control

Creating a VM must be an atomic admission operation.

The Minimum admission linearization point is a durable activation fence binding
one candidate manifest, eligibility fence, route-scope snapshot, and prepared
reservation set. VM identity/incarnation is allocated before any reservation or
candidate-manifest digest. A reservation or local manifest in `PREPARED` state
is expiring and cannot carry guest traffic; `ACTIVATE` promotes it only after
the durable decision. Coordinator restart replays that decision or aborts an
unactivated candidate. It never infers commitment from a listener, heartbeat,
or process survival.

Admission must check:

- Total requested vCPUs fit in available cluster CPU capacity.
- Total requested memory fits in available cluster memory capacity.
- Per-node reservations do not exceed registered capacities.
- Host node has enough overhead headroom.
- Required ports and SHM names are available.
- Required accelerator capabilities exist if the VM requires them.
- The exact member/gateway/capability/route eligibility fence is still valid at
  every prepare and activation step.
- Rollback is possible if any node fails to start its local components.

Static planning alone is not enough for long-term multi-VM operation.

## 8. Resource Model

### 8.1 Physical Node Registration

Each physical node registers capacity, not a mandatory NUMA boundary for the guest.

Registered capacity includes:

- CPU capacity available to WaveVM.
- Memory capacity available to WaveVM.
- Optional DHT/gateway weight.
- Capabilities such as KVM, TCG, kernel accelerator, storage, GPU, and network features.

The registered capacity is a scheduling input. It is not the same as automatic ownership of every resource by every VM.

Registration is not admission. A registration record additionally identifies
the physical-node identity, boot/process instance, failure domain, reachable
sidecar endpoint, Pod membership, and offered roles such as compute, leaf
sidecar, intermediate gateway, or root gateway. Gateway records explicitly
name their hosting physical node/failure domain. Capacity and role claims become
schedulable only after the membership lifecycle has validated them.

### 8.2 VM Resource Request

A VM should request resources in user-facing terms:

- vCPU count
- memory size
- optional placement policy such as compact or spread
- optional host placement constraints
- optional accelerator requirement
- optional consistency policy
- optional device/storage requirements

Users should not be forced to manually select NUMA nodes for ordinary VM creation.

### 8.3 Placement Policy

Compact policy:

- Prefer fewer physical nodes.
- Reduce cross-node communication.
- Good for latency-sensitive workloads.
- Can concentrate multiple VM hosts unless host placement is separately balanced.

Spread policy:

- Balance resource usage across nodes.
- Increase fault isolation and use more aggregate bandwidth.
- May increase cross-node memory and vCPU traffic.

Neither policy replaces admission control or host placement.

### 8.4 Guest NUMA Presentation

Physical resource placement and guest-visible NUMA topology are separate decisions.

WaveVM may present:

- A flat guest topology for compatibility.
- A NUMA topology matching physical placement.
- A synthetic topology optimized for the guest OS scheduler.

The guest should not be forced into physical-node NUMA unless that is explicitly chosen.

### 8.5 Cluster Membership and Topology Lifecycle

Cluster membership is a control-plane state machine distinct from VM lifecycle,
resource placement, and page/vCPU epochs. The authority is an explicit registry
of compute-node and gateway records plus a desired topology graph. A physical
host may provide both a compute role and a gateway role, but those roles have
separate readiness and drain conditions.

Required member states are:

```text
PENDING -> VALIDATING -> PREPARED -> ACTIVE -> CORDONED -> DRAINING -> REMOVED
Any nonterminal state -> FAILED after a terminal failure decision.

health: HEALTHY | SUSPECT | UNREACHABLE | RECOVERING
```

`PENDING` and `VALIDATING` are not routable or schedulable. `PREPARED` has a
validated identity, capability set, and loaded route snapshot but is not yet
eligible for new placement. `ACTIVE` is the only normal schedulable/routable
state. `CORDONED` blocks new placement while preserving current allocations.
`DRAINING` is a deliberate removal operation. `FAILED` records a failure; it
does not mean that the controller may silently reuse the identity or erase a
VM's dependency on the member.

Joining a compute node requires registration, identity and capability
validation, Pod/vnode assignment, sidecar reachability validation, route
snapshot preparation, a persisted survivor `RequiredAckSet`, and one atomic
publish before the scheduler may use its capacity. Joining a gateway additionally
requires loop-free parent/child reachability, explicit hosting-host/failure
domain registration, and acknowledgement of every required surviving next-hop
rule before it carries production traffic.

Removing a member follows the reverse sequence. A compute node may not leave
while an admitted VM still has vCPUs, memory ownership/directory duties, storage
work, or required control-plane duties allocated there. Minimum rejects that
removal instead of silently rebinding a running VM. A gateway may not leave until a
prepared successor snapshot provides a validated alternate path for every
affected destination, new traffic has moved to that snapshot, and old-snapshot
in-flight traffic has drained or failed through its bounded recovery policy.
Removal of a sole path must fail explicitly.

A health timeout, cordon, gateway drain, capability change, or member-instance
change immediately invalidates unfinished admissions that depend on that member;
it does not by itself delete routes, reclaim capacity, or migrate guest state.
If an alternate gateway path exists, the control plane may publish a replacement
route generation through a persisted required-survivor ACK set. If a VM has no
safe replacement for a failed resource node, the VM enters a documented
degraded, paused, or failed lifecycle outcome; it must not be reported as
healthy. A physical-host failure marks every hosted compute/gateway role
unreachable together; host removal drains all hosted roles before stop.

Cluster membership capacity, per-domain vnode capacity, gateway adjacency and
route capacity, and per-VM admission workspace must have independent resource
budgets. Storage follows actual records within those budgets, not the largest
node ID or the entire representable address space. A deployment may retain a
4096-vnode domain budget without imposing it on the whole cluster.

A flat domain may exceed 4096 vnodes when direct sidecar connectivity and the
declared control-plane and route-consumer budgets permit it. Crossing that
number alone must not force fractal routing. Fractal routing remains available
for network topology and route aggregation: intermediate gateways route by Pod
or prefix, and leaf domains resolve local vnodes. Both topologies use the same
semantic services and snapshot rules. The formal destination field is `u32`
with `0xffffffff` reserved; its address space is not a tested cluster-capacity
claim. Exact addressing, capacity checks, and acceptance tests belong to
`docs/specs/identity-routing.md`. Every consumer must enforce its declared
capacity and be verified before a higher capacity is advertised; increasing a
macro alone cannot establish supported scale.

## 9. Consistency Model

The consistency contract is the user-space directory, monotonically versioned
pages, and subscriber/copyset model specified in
`docs/specs/memory-consistency.md`. Names such as invalidate, downgrade, and
write-back do not by themselves establish a MESI state machine. An explicit
owner or page-state field may be
added only when that specification demonstrates why it is required and defines
its transitions. Documentation and code must not claim stronger coherence than
the accepted contract actually provides.

### 9.1 Required Concepts

WaveVM must define memory consistency in terms of explicit concepts:

- Page state.
- Page owner or directory owner.
- Page version.
- Copyset or subscriber set.
- Dirty state.
- Handoff boundary.
- Acquire/fetch/release behavior.
- Invalidation or downgrade behavior.
- Error and timeout behavior.

These concepts must exist independently of whether KVM, TCG, Mode A, or Mode B is used.

The consistency specification is implementation-blocking. At minimum it must
define page states or equivalent predicates, every message transition,
authority and lock ordering, version/epoch rules, concurrent writers,
subscriber expiry, duplicate/reordered/delayed packets, timeout recovery, and
the exact barriers provided by each dirty synchronization policy.

### 9.2 Handoff Boundary

Remote vCPU execution is a causal boundary.

Before a vCPU state is handed to a remote execution node:

- Required CPU state must be serialized.
- Required interrupt/LAPIC/timer state must be serialized or explicitly retained locally.
- Dirty memory needed for correctness must be visible to the remote node.
- Pending invalidations that affect the remote slice must not be lost.

After remote execution returns:

- Returned CPU state must be merged without erasing locally delivered interrupts.
- Dirty memory updates produced by the remote node must be visible to the authoritative directory path.
- Errors must be propagated to QEMU rather than being hidden as successful execution.

### 9.3 Dirty Memory Policy

Dirty synchronization policy must be explicit.

Examples:

- Strong mode: flush every dirty page boundary or every configured single update.
- Batched mode: flush after N dirty events or a time threshold.
- Handoff mode: flush at vCPU migration/handoff boundaries.
- Lazy push mode: push asynchronously but force fetch on version gap.

A knob such as dirty-batch-size must not accidentally change correctness. It should only change when synchronization occurs under a documented policy.

For Minimum, `dirty-batch-size=1` means that each captured dirty update is submitted
to the consistency path without waiting to accumulate a second dirty update.
It does not by itself mean that every guest store is synchronously visible on
all nodes, and it does not replace acquire, invalidation, acknowledgement, or
handoff barriers. The formal specification must state which acknowledgement
completes that submission before the option may be advertised as strong
consistency.

### 9.4 Fault Handling

Mode B may use `mprotect`/SIGSEGV where that is the best available portable mechanism.

Long-term options:

- Prefer userfaultfd when the environment allows it.
- Keep SIGSEGV/mprotect as fallback for restricted hosts.
- Avoid requiring UFFD as a baseline because some cloud/container environments disable it.

KVM paths must avoid host page protection patterns that break EPT/KVM behavior.

### 9.5 Version Gaps

If a node observes a version gap:

- It may reorder within a bounded window.
- It must fall back to fetch/acquire if the gap cannot be closed.
- It must not blindly apply out-of-order updates that violate page version monotonicity.

## 10. Network and Routing Model

### 10.1 Production Cross-Node Rule

All cross-node production traffic must go through the sidecar/gateway fabric.

Allowed path:

```text
QEMU or local executor
  -> local node runtime
  -> local sidecar -> gateway fabric -> remote sidecar
  -> remote node runtime
  -> destination local executor when needed
```

Forbidden path:

```text
local QEMU or executor -> arbitrary remote executor directly
sidecar/gateway -> remote executor while bypassing the remote node runtime
```

Exception:

- Explicit diagnostic tools may open direct test connections, but they must not become production runtime dependencies.

### 10.2 Routing Table Ownership

Routing table truth belongs to the user-space control plane.

The gateway executes routing. It does not invent placement.

The kernel accelerator may cache routing data, but cached state must be derived from user-space truth and must be safely invalidated or replaced.

Route tables remain necessary implementation state, but they are not a
user-authored VM creation input. At cluster bootstrap an operator supplies
member endpoints, role/capability declarations, Pod membership, and the desired
topology graph. The control plane compiles those records into immutable,
versioned next-hop snapshots and distributes them to node runtimes, sidecars,
and gateways. Production bootstrap consumes canonical topology/member records;
legacy `NODE` and `ROUTE` files are not compatibility inputs.

### 10.3 VM Route Namespace

Minimum route lookup rules are strict:

- Route configuration and runtime tables must preserve the complete composite
  `{vm_id, vnode_id}` key for every nonzero `vm_id`.
- A fractal implementation must preserve the complete VM identity while
  selecting a next hop by Pod/prefix and then a local leaf-vnode mapping. A
  hierarchy reduces per-gateway route scope; it does not create a second VM
  namespace or authorize raw-ID fallback.
- If lookup of a nonzero composite target fails, routing must fail explicitly.
  It must not strip `vm_id` and retry with a raw vnode ID.
- Raw-node fallback is prohibited for production traffic. Authenticated
  cluster-control scope is not an exception for guest routing.
- Flat and fractal gateways must preserve the same VM namespace at every level;
  hierarchy is not a namespace boundary.
- Route-table updates must be generation-based and atomically published. A
  packet is routed using one complete generation, never a partially updated
  table.
- `WVM_NODE_AUTO_ROUTE` is a sentinel, not an identity. Its resolution must
  produce a VM-scoped composite target before cross-node transmission.

Any raw-ID fallback in an implementation must be removed from the production
path; its presence cannot authorize weakening the identity/routing contract.

### 10.4 Static vs Learned Routes

Static configured routes must not be overwritten by auto-learning.

Auto-learning may be used for diagnostics or dynamic discovery only when it cannot invalidate explicit routes.

Learned observations must be scoped by VM namespace and incarnation. They
cannot authorize ID reuse or production route publication.

Heartbeats and endpoint observations are health evidence. They may cause the
control plane to revalidate a member, but they must not directly mutate a
production route table, create a new routable member, or retire an old member.

## 11. Storage and Device Model

Storage and device state are part of the guest-visible machine and must be treated as correctness-critical.

Rules:

- Device authority must be explicit.
- Remote execution must not assume device state magically follows the vCPU.
- MMIO/PIO/APIC/IOAPIC paths must have explicit forwarding or local emulation rules.
- Block write errors must reach the guest path.
- Flush operations must be real flushes unless explicitly configured otherwise for unsafe testing.

Minimum requires the specified QEMU-host device authority and selected block
primitives. Arbitrary distributed device ownership requires its own Extended
contract and must not be implied by those primitives.

## 12. Environment Capability Model

WaveVM should detect host capabilities and choose the best safe path.

Capabilities include:

- KVM availability.
- TCG availability.
- Kernel accelerator availability.
- userfaultfd availability.
- Allowed mprotect behavior.
- Huge pages.
- NUMA information.
- Network transport features.
- Root privileges.

Capability selection rule:

```text
If a faster capability is absent, fall back to a slower correct path.
If no correct path exists, fail early with a clear reason.
```

Do not silently replace a required feature with a workaround that changes semantics.

## 13. Mode A Repositioning

Mode A must not transfer user-space node-runtime semantic authority into the
kernel. Kernel-side acceleration must not become an independent implementation
of those responsibilities.

Target Mode A shape:

```text
User-space node runtime owns semantics.
Kernel module accelerates selected data-plane operations.
```

The kernel accelerator should expose capabilities such as:

- `WVM_CAP_DIRTY_CAPTURE`
- `WVM_CAP_FAST_INVALIDATE`
- `WVM_CAP_FAST_LOCAL_FORWARD`
- `WVM_CAP_WAITQUEUE_WAKEUP`
- `WVM_CAP_FAST_PACKET_TX`

The user-space node runtime decides which capabilities to use.

## 14. Multi-VM and Kernel Accelerator

Minimum chooses an explicit per-VM kernel context, not an implicit per-open context.
One VM may legitimately have several processes and file descriptors using
`/dev/wavevm`, including QEMU, node-runtime roles, and control tooling. Creating an
unrelated VM context for every `open()` would split state that must be shared.

The kernel ABI must therefore provide explicit create/attach semantics:

- A create operation creates one context identified by VM identity and returns
  an unforgeable kernel context handle.
- Additional file descriptors explicitly attach to that context after identity
  and permission validation.
- Every mmap, ioctl, request ID, route cache, mapping, dirty tracker, and page
  metadata lookup is resolved through the attached context.
- Closing one file descriptor releases only its reference. The context is
  destroyed after lifecycle teardown and the final reference.
- Module-global workers may remain only when their queues carry a context
  reference and cannot mix request namespaces.

The exact handle representation, ioctl numbers, permissions, reference model,
and teardown lock order belong in the kernel-accelerator specification.

Target invariants:

- No module-global VM identity.
- No module-global route table as semantic truth.
- No module-global memory mapping pointer that can be overwritten by another VM.

Before multi-context isolation is verified, capability discovery must advertise
`SINGLE_CONTEXT` with a maximum of one context, and admission must reject a
second Mode A VM on that node. Raising the limit requires explicit context
ownership across sleepable and asynchronous paths, safe TX/VMA/destroy
references, full u32 VM identity, and isolation/teardown acceptance evidence.
Module-global VM identity and directory/route fallbacks are prohibited in the
target path. Stub READY results cannot satisfy Minimum KVM guest login/SSH,
TCG execution-contract tests, or remote-resource acceptance criteria.

## 15. Invariants

The following invariants should guide future code changes:

- Mode B is the semantic baseline.
- Kernel code accelerates, it does not define correctness.
- KVM and TCG share high-level semantics.
- Flat and fractal topologies share high-level semantics.
- Multi-VM isolation is required by default.
- A VM creation request is not a placement decision.
- Host placement is explicit, not inferred from node ID ordering.
- Resource capacity does not include hidden control-plane overhead unless accounted for.
- Membership state, topology revision, route generation, VM incarnation, and
  page/CPU epochs are distinct version domains and must never be overloaded.
- A member becomes schedulable or routable only after the control plane commits
  its validated route snapshot. Health evidence alone is insufficient.
- Member removal is drain-first. A running VM's resource allocation is never
  silently reassigned because a node or gateway was removed from a table.
- A gateway removal requires a verified alternate path for every affected
  destination; a sole path cannot be removed successfully.
- Cross-node production traffic uses the gateway fabric.
- Master and slave are node-runtime roles, not mandatory cross-node endpoints
  or mandatory process boundaries. The node runtime remains the only
  guest-semantic cross-node ingress/egress endpoint; executors remain local.
- Test scripts may constrain topology, but production code must not hardcode those constraints.
- Implement and maintain the concurrent and batched normal path required by
  Section 0.6; an absent optimization remains an implementation obligation
  when needed to meet that contract. Correctness repairs must satisfy it.
  They must not silently replace it with global serialization, synchronous
  forwarding, or a permanently disabled queue.
- A local synchronous fallback is allowed only as a bounded backpressure or
  failure path when dropping work would violate guest correctness. Its trigger,
  scope, ordering effect, recovery behavior, and performance cost must be
  specified and tested.
- Queue, worker, batching, and priority changes are performance-sensitive
  architecture changes. They require a stated ownership and backpressure model,
  not only a test that one guest boots.

## 16. Delivery Scope and Deferred Capabilities

The following decisions define the required baseline profile. Subsystem
specifications define their algorithms and ABIs without contradicting them.

- A user-facing CLI or API submits a versioned VM request containing requested
  resources, policy, and constraints. After admission, the control plane
  generates an immutable versioned launch manifest containing resolved
  identities, placement, capabilities, and per-node runtime configuration.
  Handwritten scripts are not the semantic authority for either object.
- The admitted plan contains an explicit `host_node`. The planner chooses it
  from capable nodes; it is neither inferred from the request origin nor from
  the first numeric vnode.
- Host overhead is an explicit per-node reservation separate from guest vCPU
  and RAM. An implementation may begin with conservative configured defaults,
  but it may not pretend the overhead is zero.
- VM startup is coordinated as identity allocation, candidate plan/route scope,
  prepared reservations, prepared participants, one durable activation fence,
  committed local records, start-without-guest-traffic, then `RUNNING` or
  compensating teardown. Creation is all-or-nothing: a partially started VM is not
  reported as running, and every resource created before failure has a named
  cleanup owner.
- The node accepting a create request acts as lifecycle coordinator for that
  operation. It may select a different `host_node` for QEMU. The minimum
  deployment uses one active coordinator and has no coordinator high
  availability or transparent failover. It must persist enough of the
  transaction/activation decision to reconcile a restart deterministically or
  fail closed without leaking a reservation or reporting a false `RUNNING`
  state. Prepared reservations use bounded leases only before activation;
  activated reservations remain held until lifecycle teardown.
- Nonzero VM route namespaces use strict composite keys at every flat or
  fractal gateway level. Raw-ID guest fallback is prohibited, including through
  the reserved cluster-control namespace.
- Flat and leaf-Pod domains have independently budgeted vnode capacity without
  a fixed domain ceiling. The control plane selects flat or fractal
  topology from connectivity, route-aggregation needs, and resource budgets;
  a capacity threshold alone does not force hierarchy. An operator does not
  hand-author one route per VM destination. Global membership and admission
  storage must not inherit a leaf-domain budget. Declared capacities must fit
  every consumer and be verified in both topologies before being advertised;
  neither wide IDs nor hierarchy alone prove supported scale.
- Minimum supports controlled member registration, cordon, and drain only through
  prepared/acknowledged route snapshots with a persisted required-survivor ACK
  set. Adding a member may make capacity available to future VM admissions; it
  does not dynamically add resources to a running VM. Cordon/drain/health or
  instance changes invalidate candidates not yet activated. Removing a member
  with active VM dependencies is rejected in Minimum.
- A member or gateway failure marks affected capacity/routes unavailable and
  triggers documented degraded, paused, or failed VM behavior. A physical-host
  failure marks all hosted roles together. Minimum does not claim automatic live
  resource migration, transparent guest-state recovery, or automatic repair of
  a sole failed gateway path.
- The default guest topology is flat for compatibility. A placement-aware or
  synthetic NUMA topology is an explicit manifest choice and must not alter
  physical placement ownership.
- `dirty-batch-size=1` has the limited submission meaning defined in Section
  9.3. Strong consistency is advertised only after the consistency
  specification defines and the implementation supplies the required ACK and
  handoff barriers.
- Sending `VCPU_RUN` and accepting completion of `VCPU_EXIT` are handoff
  boundaries. The handoff specification determines the exact memory scope and
  barrier sequence; neither backend may skip it as an optimization.
- UFFD is an optional fault engine. SIGSEGV/mprotect remains the restricted-host
  fallback where valid, and KVM dirty logging remains a distinct capability.
- The kernel accelerator uses the explicit per-VM context model from Section
  14. Until its isolation acceptance criteria are met, admission must reject
  a second Mode A VM on the same physical node.
- Each participating physical node has one logical node-runtime instance for
  each `{vm_id, vm_incarnation, physical_node_id}`. One node-runtime binary
  provides master-role coordination and slave-role execution; helper processes
  obey the local executor contract. The manifest, request namespace, queues,
  and lifecycle remain per-instance. Source-directory names do not authorize
  independent master/slave production launch paths or compatibility adapters.
- The authoritative QEMU frontend owns the guest device model. Remote vCPU
  execution returns MMIO/PIO and unsupported device exits to that authority.
  A remote block data service may execute I/O, but ordering, flush completion,
  and guest-visible errors remain governed by the QEMU-host device authority.
- The `u32` VM namespace permits `UINT32_MAX` nonzero logical namespaces.
  Allocation above 255 requires every selected participant to negotiate
  `WVM_CAP_VM_ID_U32`; incompatible participants cannot join that VM's path.
  Mode B has no smaller architectural per-host count; admission is constrained
  by reserved resources and exclusive local names. A nonzero ID is quarantined
  until all route/cache/operation retirement acknowledgements complete and the
  next incarnation is checked. No legacy mixed-deployment path is required.
- **TCG delivery boundary:** Minimum retains real, manifest-bound TCG execution
  tests for CPU context, remote memory reads/commits and fences, independent
  vCPU ownership/progress, device/atomic exits, bounded failures, and STOP.
  Both flat and fractal paths must execute actual guest instructions; a stub,
  listener, local-only substitute, or KVM execution cannot satisfy that gate.
  Full TCG guest OS boot, login/SSH, sustained multi-vCPU guest workload, and
  proof that concurrent remote execution is the normal guest progress path
  belong to Extended. This does not permit accepting incorrect bytes/context,
  suppressing errors, or weakening shared memory and lifecycle contracts.
  Same-host shared RAM requires an actual shared-backing proof; local mapping
  alone does not establish cross-host coherence. The Section 15 fallback
  (`force_local`) remains per-vCPU and bounded whenever used; ownership,
  memory, device, and atomic ordering are not deferred. Section 8.1 of
  `vcpu-handoff.md` defines the separate Minimum contract tests and Extended
  TCG guest acceptance. Until Extended acceptance passes, user-facing backend
  descriptions must distinguish TCG contract support from usable TCG guest OS
  support, including for a policy-selected TCG fallback.

The following capabilities are outside the Minimum profile and belong to
Extended or separately accepted scope:

- Full TCG guest OS boot/login/SSH and sustained distributed multi-vCPU guest
  execution, including concurrent BSP-local + AP-remote progress as the normal
  path rather than a token trickle under local fallback. Acceptance belongs in
  `vcpu-handoff.md` Section 8.1 and roadmap Phase 10 Extended acceptance.
- Full upstream QEMU in-process / cross-process TCG MTTCG performance and
  helper-thread MTTCG (or equivalent barriers) that removes the need for a
  Section 15 bounded local synchronous fallback on the concurrent SHM path
  for stop_machine / text_poke / softlock-class IPI windows. This performance
  work is separate from the Extended usable TCG guest acceptance above.
- Cross-backend KVM-to-TCG or TCG-to-KVM vCPU handoff.
- Live migration of the QEMU frontend or dynamic replanning of a running VM.
- Automatic resharding of an active VM when a compute node joins or leaves.
- Transparent recovery from loss of a required compute node or sole gateway
  without a separately specified replica or migration mechanism.
- Highly available or durable lifecycle coordination after coordinator failure.
- Automatic selection of an optimized synthetic guest NUMA topology.
- Distributed ownership of arbitrary device models beyond the defined remote
  block primitives.
- A tested scale limit lower than the protocol limit, based on measured file
  descriptors, ports, memory overhead, and gateway capacity.

## 17. Relation to GiantVM

GiantVM is a useful architectural reference for distributed KVM DSM concepts, especially page ownership, versioning, copysets, and explicit interrupt/device forwarding.

However, GiantVM is not WaveVM's baseline architecture:

- GiantVM is KVM-only.
- GiantVM requires a custom host kernel.
- GiantVM uses direct QEMU-to-QEMU routing.
- GiantVM does not solve distributed TCG.
- GiantVM does not provide WaveVM's intended mode-B restricted-environment path.

WaveVM may borrow design discipline, not hard dependencies.

## 18. Implementation Dependency Order

The [roadmap](wavevm-refactor-roadmap.md#implementation-order) owns the phase
sequence. It orders executable identity/record/IPC foundations, the unified
node runtime, validated member and route services, memory and vCPU/device
execution, admission and lifecycle integration, multi-instance isolation,
dynamic membership operations, and optional per-VM kernel acceleration before
Minimum acceptance. Extended phases build on those contracts.

Specifications constrain each implementation step; writing a specification,
inventorying existing code, or establishing an empty skeleton is not a runtime
feature phase or evidence of completion. Maintenance of an existing tree uses
the same dependency order to identify affected prerequisites, without requiring
a restart from the beginning of the sequence.

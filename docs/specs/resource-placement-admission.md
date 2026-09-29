# WaveVM Resource Placement and Admission Specification

Status: proposed implementation specification.

Scope: registered allocatable capacity, VM resource requests, deterministic
placement, host selection, reservations, admission, multi-VM isolation, and
release. The runtime manifest owns the admitted result; membership owns which
members are eligible; capability selection owns which execution/fault engines
are valid.

This specification is normative for new planning and admission work. It does
not authorize implicit live migration, dynamic resource borrowing, host CPU
overcommit, or a user-authored route table as a placement mechanism.

## 1. Goal and Non-Goals

The goal is to let an ordinary VM request ask for vCPUs, memory, and policy
without selecting physical nodes or guest NUMA nodes, while the control plane
deterministically chooses and reserves a valid multi-node plan.

```text
registered allocatable inventory + ACTIVE member/capability snapshot
  + VmRequest constraints
  -> deterministic complete PlacementPlan
  -> atomic reservations
  -> immutable AdmittedVmManifest
```

WaveVM pools resource capacity across physical nodes. A registered node is a
resource provider, not a mandatory guest NUMA node and not a unit at which a
VM must consume all resources. One VM may use a fraction of several nodes; one
physical node may host allocations for several VMs when their reservations fit.

Several registered resource providers may share one `physical_host_id`. This
is a supported logical-node subdivision, not permission to double-count host
capacity. The planner first validates each node's independent allocatable
budget, then validates the aggregate host budget for CPU, memory, accelerator
contexts, and host/gateway overhead across every node and gateway record in
that host group. A host-wide conflict is a structured admission rejection.
Each node instance also receives an explicit port/socket/name namespace and
exclusive leases; no planner or runtime may assume that a host has only one
node agent or reuse a host-global default port/path.

Non-goals for V1:

- CPU, memory, or storage overcommit. A configured future overcommit policy
  requires its own accounting, eviction, and guest-visible failure contract.
- Hot-add, hot-remove, automatic rebalancing, or eviction of a running VM.
- Treating raw host core count, installed RAM, or a vnode count as allocatable
  capacity without explicit registration and reserve headroom.
- Altering guest-visible NUMA merely because physical placement changed.
- Selecting a different member after start because it looks reachable or a
  route-learning cache has an entry.

## 2. Authority and Inputs

| State or decision | Authoritative owner | Required input |
| --- | --- | --- |
| Registered physical capacity/capabilities | Membership/control plane record | Validated member registration and health. |
| Allocatable capacity | Control-plane inventory after reserved headroom | Registered capacity minus non-WaveVM and role reservations. |
| Candidate eligibility | Control plane | `ACTIVE` membership, health, route, capability, and constraints. |
| Placement plan and reservation transaction | Admission coordinator | One immutable inventory/membership/capability snapshot. |
| Host node and guest topology choice | Admitted VM manifest | Completed plan and request policy. |
| Runtime queue scheduling | Node runtime and local executor | The admitted plan, not this specification. |

`membership_revision`, topology revision, admission-eligibility revision,
capability profile generation, and inventory revision must be captured with a
placement attempt. The resulting
`AdmissionEligibilityFence` names every required node/gateway role, instance,
capability profile, route scope, and ACK-set digest. The planner must not
combine one node's old capacity with another node's new capability profile and
call the result an atomic plan.

A cordon, health exclusion, gateway drain, selected capability/profile change,
or node/gateway instance change invalidates a fence until its transaction has a
durable activation decision. Thus a reservation prepared before cordon does not
grandfather a new VM onto the cordoned node. Existing committed allocations
remain governed by lifecycle/drain rules rather than being silently replanned.

## 3. Resource and Reservation Model

### 3.1 Capacity Units

V1 uses conservative, integer, non-overcommitted accounting:

| Resource | Unit | Meaning |
| --- | --- | --- |
| Guest CPU | `vcpu_slot` | One registered unit of concurrent guest vCPU execution capacity. It is not automatically equal to a host hardware thread. |
| Guest RAM | bytes | Page-aligned bytes available to WaveVM after host and role headroom. |
| QEMU/node-runtime/executor overhead | bytes and optional `vcpu_slot` | Reserved separately from guest request so it is not hidden inside guest capacity. |
| Storage | backend-specific capacity/IO capability | Must satisfy the device plan; capacity alone does not prove flush semantics. |
| Exclusive local resources | named lease | Ports, socket paths, SHM names, accelerator contexts, GPU/VFIO assignment, and other non-shareable resources. |

An `ExclusiveLease` identifies a local resource by `(lease_kind, lease_name)`.
`lease_generation` records the acquisition/owner epoch and is part of exact
replay equality, but it does not make two uses of the same resource distinct.
Therefore the same lease kind and name conflict even when their generations
differ. The canonical lease list is strictly ordered and unique by
`lease_kind/lease_name`.

For the node-runtime launch plan, placement emits leases for the two listeners
that are actually bound by the current runtime path: the wildcard UDP
node-runtime data listener and the loopback UDP local-executor service
listener. Control-port fields that are only adapter metadata are not treated
as bound resources until an implementation creates a corresponding listener.
The listener port and binding scope come from the controller-selected launch
plan; the planner does not choose a hard-coded port range.

Every `NodeRecord` exposes:

```text
NodeInventory {
    physical_node_id;
    node_instance_id;
    failure_domain_id;
    inventory_revision;
    registered_vcpu_slots;
    registered_memory_bytes;
    reserved_host_cpu_slots;
    reserved_host_memory_bytes;
    reserved_gateway_cpu_slots;
    reserved_gateway_memory_bytes;
    hosted_gateway_role_ids;
    allocatable_vcpu_slots;
    allocatable_memory_bytes;
    storage_capabilities;
    accelerator_and_fault_capabilities;
    exclusive_resource_inventory;
}
```

In addition to the inventory above, a node record exposes `physical_host_id`
and `node_instance_namespace`. The former groups independently schedulable
providers for aggregate accounting and correlated failure. The latter scopes
the node agent's local sockets, shared memory, logs, temporary files, and
instance-specific listener leases. These fields are part of the authoritative
registration/profile input, not values inferred by a launch script.

`allocatable_*` values are explicit fields or deterministic derived values.
They must never be calculated from a remote `nproc`, total RAM, or an arbitrary
vnode count during VM creation. A node serving sidecar/gateway or control-plane
roles must reserve their headroom before it is considered for guest work.
Gateway headroom belongs to the `hosting_physical_node_id` declared by the
corresponding `GatewayRecord`; it must not be charged to an arbitrary endpoint
or omitted because the gateway has a separate logical membership record.

### 3.2 VM Request Normalization

The planner receives the normalized `VmRequest` from
`runtime-manifest-lifecycle.md` and adds only planner-owned derived values:

```text
NormalizedRequest {
    requested_vcpus;
    requested_memory_bytes;
    memory_chunk_bytes;
    placement_policy;             // COMPACT or SPREAD
    host_constraints;
    backend_policy;
    accelerator_policy;
    guest_topology_policy;
    consistency_policy;
    storage_and_device_requirements;
    required_roles_and_capabilities;
}
```

`memory_chunk_bytes` is a cluster-supported power-of-two multiple of 4 KiB,
selected before planning. Every guest RAM byte belongs to exactly one
page-aligned placement chunk. It may be smaller than a physical NUMA domain;
physical NUMA is an optimization input, not the user-visible allocation unit.

Execution backend and memory placement are separate planning dimensions. A
memory chunk may be assigned to any `ACTIVE` participant with the required
memory-service capability, capacity, and manifest-valid route, regardless of
whether that participant has KVM. The vCPU backend still applies to every vCPU
assignment in the VM and is not inferred from the node selected for a memory
chunk.

The planner resolves backend policy before producing the final placement:

1. For `AUTO`, attempt a complete KVM candidate first. Every vCPU assignment
   must use a KVM-capable executor, while memory chunks may use any eligible
   memory participant.
2. If the complete KVM candidate fails, discard its provisional reservations
   and attempt a new complete TCG candidate. TCG-capable executors may be
   nodes without KVM or KVM-capable nodes whose TCG helper is admitted.
3. For `REQUIRE_KVM`, do not attempt the TCG candidate. For `REQUIRE_TCG`,
   plan TCG directly.

The final plan must be homogeneous in vCPU backend. A plan containing both KVM
and TCG vCPU assignments is invalid even when every individual assignment is
locally capable. Backend fallback is therefore a pre-activation replan, not a
partial CPU downgrade after placement.

Backend capacity is part of the captured inventory. A node may expose distinct
KVM and TCG vCPU capacity classes, but both draw from the node's shared host
CPU and overhead budget. The planner must not copy KVM slot counts into TCG
capacity or allow KVM and TCG reservations to overcommit the same host budget.

The planner rejects an unaligned memory request or rounds it only through a
documented API default that is included in the normalized request and manifest.
It does not silently truncate guest RAM.

`host_constraints` restrict every physical resource participant selected for
the new VM, including QEMU host, vCPU executor, memory directory/executor, and
storage owner. V1 interprets `PHYSICAL_NODE`, `FAILURE_DOMAIN`, and
`CAPABILITY` constraints as `subject=id` plus a decimal `value`; all
constraints are conjunctive. `LABEL` is rejected until canonical
`NodeMetadata` records are introduced. The implementation must not consult
shell labels, environment variables, hostname heuristics, or legacy config as
a fallback.

### 3.3 Placement Plan

```text
PlacementPlan {
    plan_digest;
    admission_tx_id;
    eligibility_fence_digest;
    inventory_revision;
    membership_revision;
    topology_revision;
    capability_profile_generation;
    host_node;
    vcpu_assignments[];           // each guest vCPU index exactly once
    memory_chunk_assignments[];   // each guest chunk exactly once
    storage_assignments[];
    reservation_requirements[];
    guest_topology;
    route_scope_requirements;
}
```

Each vCPU assignment contains guest vCPU index, physical executor node,
backend, local executor class/slot, and reservation key. Each memory chunk
assignment contains guest physical range, directory/execution node, page
consistency policy, and reservation key. `reservation_requirements[]` carries
the exact per-node guest/overhead amounts and exclusive leases referenced by
those keys. A placement plan is invalid when it has a gap, overlap, duplicate
guest vCPU index, duplicated reservation key, or participant not eligible in
its captured snapshot.

`host_node` must be selected independently and explicitly. It reserves:

- QEMU frontend CPU and memory overhead.
- Host node-runtime, local IPC, and required sidecar/gateway overhead.
- QEMU monitor/serial/network forwarding and manifest-derived local names.
- The necessary execution/fault/accelerator capability for the selected
  frontend backend.

The host may also execute guest vCPUs or own guest memory, but neither is
implied. A request submitted on one node may be hosted on another eligible
node.

## 4. Eligibility and Validation

A physical node is eligible for an assignment only when all conditions hold:

1. Its required compute, storage, or gateway role is `ACTIVE` and its health
   is acceptable for new placement under the membership specification.
2. Its `node_instance_id`, capacity profile, and endpoint are current in the
   captured snapshot.
3. It has the required execution backend, fault engine, accelerator policy,
   device/storage capability, and ABI compatibility from
   `capability-fault-engines.md`.
4. The topology has a prepared/committed route scope that can reach every
   participant required for the assignment. A current UDP listener alone is
   insufficient.
5. It has sufficient unreserved capacity and all necessary exclusive resources.
6. It satisfies explicit host, affinity, anti-affinity, locality, or security
   constraints in the normalized request.

The planner must also validate the complete set:

- KVM and TCG vCPU placement is homogeneous according to the admitted backend
  plan. A backend mismatch is not repaired by implicit context translation.
- A required kernel accelerator is present on every assigned component that
  needs it; `PREFER` may resolve to the correct Mode B path only before start.
- Every remote memory directory/executor and remote vCPU executor has a
  manifest-valid route through the sidecar/gateway fabric.
- All destination-specific ports, sockets, SHM names, kernel contexts, and
  device leases are distinct from existing reservations.
- The proposed plan does not remove, cordon, or rely on a `DRAINING` member.

Failure returns the first stable typed reason plus a bounded list of rejected
constraints. It must not expose an arbitrary partially successful node list as
an admitted VM.

## 5. Deterministic Placement

The planner takes an immutable snapshot and produces a plan deterministically.
For the same normalized request, snapshot, and policy, it returns the same
plan digest or the same rejection. Node IDs are a stable tie-breaker, not an
instruction that numeric order equals performance.

### 5.1 Candidate Ordering

1. Filter ineligible nodes before scoring.
2. Sort candidates by a stable physical-node identifier.
3. Calculate projected utilization using allocatable units after all already
   chosen assignments and required overhead reservations.
4. Break equal scores with physical-node ID, then local executor class/slot.

### 5.2 Compact Policy

Compact policy minimizes the number of participating physical nodes while
satisfying all constraints. For each assignment it prefers, in order:

1. An already selected eligible node with sufficient remaining capacity.
2. A node that can satisfy the largest remaining compatible resource demand.
3. Lower projected aggregate utilization after assignment.
4. Stable physical-node ID.

The planner reserves host overhead before scoring its guest assignments. It
must not claim compactness by using a node that fits guest RAM but not QEMU or
node-runtime headroom.

### 5.3 Spread Policy

Spread policy balances compatible demand across distinct physical nodes. For
each assignment it prefers, in order:

1. The eligible node with the lowest projected maximum of CPU and memory
   utilization fractions.
2. The node with the fewest assignments for this VM where that does not violate
   resource or locality constraints.
3. Stable physical-node ID.

Spread does not promise fault tolerance when the memory, vCPU, or storage
contract has no replica. It only avoids needless concentration when capacity
and topology permit it.

### 5.4 Planning Failure

The implementation may use bounded backtracking to find a complete legal plan,
but it must bound search time and return `PLACEMENT_CONSTRAINT` or
`INSUFFICIENT_CAPACITY` rather than making an unbounded scheduler call. It may
not reserve or launch a subset of a VM while continuing to search for the rest.

When `AUTO` falls back from KVM to TCG, the returned diagnostic must identify
that KVM was attempted, why no complete KVM candidate was admissible, and that
the committed plan uses TCG. This is a backend-selection result, not a hidden
performance workaround.

## 6. Atomic Reservation and Admission

### 6.1 Reservation Record

```text
ResourceReservation {
    reservation_id;
    plan_digest;
    candidate_manifest_digest;
    admission_tx_id;
    eligibility_fence_digest;
    vm_id;
    vm_incarnation;
    physical_node_id;
    node_instance_id;
    inventory_revision;
    guest_vcpu_slots;
    guest_memory_bytes;
    overhead_vcpu_slots;
    overhead_memory_bytes;
    exclusive_leases;
    state;                        // PREPARED, COMMITTED, RELEASING, RELEASED
    prepared_expiry;
    activation_fence_when_committed;
}
```

`PREPARED` reservations have a bounded expiration and may be reclaimed only if
the holder has not observed a matching durable activation fence. Once activated,
the lifecycle record owns the reservation until normal stop/failure teardown;
an arbitrary lease timeout must not reclaim memory or vCPU capacity from a
still-running guest.

`ResourceReservation` is a node-local derived record, not a nested field of
the self-digested placement plan or candidate manifest. The coordinator first
finalizes those immutable records, then sends a reservation built from one
matching `ReservationRequirement` plus the final plan/candidate/fence digests.
This ordering prevents an otherwise unavoidable hash cycle while preserving
the requirement-to-reservation audit chain.

### 6.2 Reserve/Commit/Abort Sequence

1. The lifecycle coordinator has already allocated VM identity and constructed
   a candidate manifest/eligibility fence before it asks for a reservation.
2. It asks every affected node to `PREPARE_RESERVATION` with transaction ID,
   candidate digest, fence digest, expected node instance, and exact local
   amounts. Each request revalidates member eligibility and capability profile.
3. Nodes atomically check inventory and exclusive leases, record an expiring
   `PREPARED` reservation, and return an idempotent ACK or typed conflict.
4. After route scope and participant preparation complete, the coordinator
   persists the single activation fence defined by
   `runtime-manifest-lifecycle.md`.
5. `COMMIT_RESERVATION` promotes a prepared reservation to `COMMITTED` only
   when transaction, candidate digest, fence digest, and activation fence all
   match. A duplicate replays its recorded result.
6. If no activation decision exists, the coordinator aborts every prepared
   reservation. If activation exists, crash recovery completes activation or
   compensating teardown before release.

### 6.3 Durable Admission Orchestration

The coordinator-owned admission orchestrator is the only composition point for
the create transaction. Transport adapters are callbacks at explicit stage
boundaries; they are not allowed to create a second placement or lifecycle
authority. The normal order is:

```text
CONTROL_PLANE_BEGIN
  -> ROUTE_PLAN (after route_scope_id allocation)
  -> COORDINATOR_PREPARE
  -> durable candidate + PREPARING route
  -> route prepare
  -> durable ROUTE_SCOPE_PREPARED
  -> reservation prepare
  -> durable RESERVATIONS_PREPARED
  -> participant prepare
  -> durable PARTICIPANTS_PREPARED
  -> durable ACTIVATE decision
  -> local/remote reservation and participant commit
  -> durable per-node runtime projections
  -> route commit + durable route activation
  -> durable COMMITTED
  -> identity-bound readiness
  -> STARTING -> RUNNING
```

Every route, reservation, and participant callback is idempotent for the
admission transaction and manifest identity. Route prepare, commit, and abort
use distinct operation IDs derived from the immutable route transaction, stage,
and target member; the `RouteTransaction.operation_id` remains the stable
transaction identifier carried by the canonical record. A failure before the durable
`ACTIVATE` decision records `ABORT`, invokes only prepared-resource cleanup,
and reaches `ABORTED` only after route, participant, reservation, and local
cleanup succeeds. A failure after `ACTIVATE` is not converted into a new
pre-activation abort: the durable state remains `ACTIVATION_DECIDED` (or a
later state) for recovery and compensating teardown. After process loss, the
recovery runner accepts only identity-validated projections reconstructed from
durable candidate/runtime records; it resumes `ACTIVATION_DECIDED` forward and
cleans `ABORTING` toward `ABORTED`, never choosing a new placement or route.

No node independently upgrades a reservation to `COMMITTED` based solely on a
local process start, an old route, or a surviving socket. No process may consume
a `PREPARED` reservation for guest traffic before activation.

### 6.3 Concurrent Admissions

Admission coordination serializes conflicting inventory updates per physical
node but permits disjoint plans and VM lifecycle operations to progress. It
must not hold a cluster-wide mutex while waiting on network replies.

Node-local reservation implementation may use a lock or transaction primitive,
but must validate all amounts and names under the same local atomic operation.
Two concurrent plans that each fit only before the other's reservation cannot
both succeed. A retry uses the original plan digest only when its eligibility
fence is still valid; otherwise it aborts/replans under a new transaction and
fresh VM incarnation.

## 7. Guest Topology and Runtime Scheduling

Guest-visible NUMA is chosen after physical placement:

- `FLAT` is the default compatibility presentation.
- `PLACEMENT_NUMA` may expose a mapping related to physical placement when the
  request explicitly chooses it and all guest-device/RAM ranges are valid.
- `SYNTHETIC_NUMA` is a policy-generated guest layout and requires explicit
  documentation of its CPU/RAM mapping.

No guest topology option changes ownership of a memory page, vCPU, storage
request, or route. A guest vCPU's runtime handoff queue and a node executor's
batching/QoS are owned by the normal runtime. The planner must not turn the
data plane into a globally serial executor to make accounting simpler.

## 8. Failure, Release, and Membership Interaction

| Condition | Required behavior |
| --- | --- |
| Capacity, member, route, or capability changes before activation | Invalidate the eligibility fence, abort/replan, and do not commit stale amounts. |
| Node rejects reservation | Abort all prepared peers and return a typed admission failure. |
| Node/gateway instance changes after prepare | Treat the fence as stale and abort/replan. |
| VM start fails before activation decision | Release only prepared reservations after bounded cleanup. |
| VM start fails after activation decision | Preserve reservations while lifecycle completes activation recovery or compensating teardown; do not silently reuse them. |
| Compute node is cordoned or gateway starts draining | It is excluded from new/unfinished admission; existing committed allocations follow their separate drain policy. |
| Compute node/gateway removal has active dependencies | Membership controller rejects removal in V1; planner cannot use it for a new plan. |
| A running VM exceeds reserved capacity | Report an explicit runtime/admission defect; do not borrow arbitrary capacity or silently degrade another VM. |

Adding a member makes new inventory available only to later admissions. It does
not alter a running manifest or make an existing VM larger. Removing an unused
member may release its inventory after route/membership rules finish; removing
a member with active VM allocations is governed by the drain restrictions in
`cluster-membership-topology-lifecycle.md`.

## 9. Current Code Mapping and Known Deviations

| Current file or mechanism | Current behavior | Required migration direction |
| --- | --- | --- |
| `common_include/wavevm_resources.[ch]` | Defines static CPU/memory resource descriptions and placement helpers. | Become a parser/compatibility adapter for versioned inventory, eligibility fences, complete plans, explicit reservations, and host overhead. |
| `common_include/wavevm_admission.[ch]` | Validates captured V1 inventory, normalized requests, and complete pre-activation reservations without mutating runtime state. | Grow into the coordinator-owned admission model and canonical-record renderer before it drives live reservation RPCs. |
| `common_include/wavevm_admission_orchestrator.[ch]` | Composes durable begin/prepare/activate/commit/abort stages around route, reservation, and participant callbacks. | Connect production control transports and recovery reconciliation; do not bypass the durable coordinator with launch-script policy. |
| `common_include/wavevm_admission_recovery.c` | Reconciles durable `ACTIVATION_DECIDED`, `COMMITTED`, `RUNNING`, and `ABORTING` states using identity-bound projections and idempotent transport callbacks. | Replace fixture-owned reconstruction with the production journal/recovery loader and participant query protocol. |
| `ctl_tool/main.c` | Builds test-oriented node/resource configuration. | Submit normalized VM requests, report deterministic plans/rejections, and drive reservation/lifecycle APIs. |
| `master_core/logic_core.c` | Consumes CPU/memory route state after launch. | Consume only manifest-derived per-VM placement and reject unreserved assignments. |
| `gateway_service/aggregator.c` | Forwards according to static/learned routes. | Consume route snapshots generated for admitted participants; never decide capacity or placement. |
| `artifacts/*/run.sh` and CI fixtures | Manually choose node counts, paths, and topology. | Remain test inputs rendered from request/manifest fixtures, not capacity truth. |

## 10. Compatibility and Migration

1. Inventory current resource units, implicit host selection, local ports,
   socket/SHM names, and any hardcoded per-test placement assumptions.
2. Introduce a read-only inventory snapshot that reproduces existing two-node
   deployments exactly before changing placement behavior.
3. Implement plan validation and manifest rendering before enabling concurrent
   VM admission.
4. Add node-local prepared reservations, activation-fence records, and cleanup
   records while legacy static configuration remains a compatibility input.
5. Make host overhead and exclusive local names visible in admission errors.
6. Enable compact/spread selection only after deterministic fixtures prove that
   a plan covers every vCPU and memory chunk without overlap or hidden default.

## 11. Acceptance Tests

- A request for 32 vCPUs and 64 GiB can use fractions of several registered
  nodes without forcing guest NUMA or requiring the user to name a node.
- A request exceeding aggregate eligible capacity, a node's remaining capacity,
  or host overhead fails before any QEMU/executor starts.
- Four concurrent 20-vCPU/40-GiB requests either receive disjoint complete
  reservations or structured rejections; none shares an exclusive name or
  exceeds capacity.
- Compact and spread fixtures produce stable plan digests across repeated runs
  from the same snapshot and differ only according to their documented scoring.
- A plan's vCPU and memory tables cover all requested guest resources exactly
  once, are page aligned, and name only `ACTIVE` compatible participants.
- An `AUTO` request prefers a complete KVM plan, then produces a new complete
  TCG plan when KVM capacity or capability is insufficient; it never emits a
  mixed-backend vCPU plan.
- A `REQUIRE_KVM` request rejects a cluster where any required vCPU cannot be
  placed on a KVM-capable executor, while its memory may still be placed on an
  eligible non-KVM memory participant.
- A KVM-capable node can serve a TCG vCPU only through its admitted TCG
  executor capacity, with shared host CPU reservations preventing
  overcommitment.
- A reservation conflict or stale node instance aborts every prepared peer and
  leaves no leaked capacity, port, SHM file, or accelerator context.
- Race every admission stage with compute cordon, gateway drain, health
  exclusion, capability change, and node-instance replacement. No new VM
  reaches `RUNNING` through an invalidated eligibility fence.
- Crash/restart the coordinator after every prepare, activation, commit, abort,
  and start message. Each transaction converges to one outcome: a fully
  committed/running VM with all reservations held, or complete compensating
  teardown with all resources released.
- Adding a node affects a later VM request but cannot mutate an already
  admitted VM's host, vCPU/memory plan, or guest topology.
- A mixed Mode A/Mode B cluster is admitted only when every selected component
  supports the manifest's required capability profile; otherwise it fails
  before launch with a clear capability error.

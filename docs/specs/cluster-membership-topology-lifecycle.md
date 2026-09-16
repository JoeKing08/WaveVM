# WaveVM Cluster Membership and Topology Lifecycle Specification

Status: proposed implementation specification.

Scope: cluster membership, physical-node and gateway registration, health,
flat/fractal topology, Pod membership, route-snapshot publication, scheduling
eligibility, controlled drain/removal, and failure outcomes. This specification
does not define page consistency, vCPU state transfer, live migration, or the
exact packet encoding; those are owned by the memory, vCPU, and identity/wire
specifications respectively. VM manifests and resource reservations are owned
by `runtime-manifest-lifecycle.md` and `resource-placement-admission.md`; this
specification supplies their eligible-member and route-snapshot inputs.

This specification is normative for all membership and topology work. Current
`NODE`, `ROUTE`, heartbeat, and legacy gateway control paths are not production
inputs; topology records and authenticated membership control messages are the
only authoritative inputs.

## 1. Goal and Non-Goals

The goal is to make cluster membership a deliberate control-plane operation.
Adding or removing a compute node or gateway must never leave routing, capacity
accounting, VM placement, or guest-visible state in an ambiguous intermediate
state.

The desired result is:

```text
operator desired topology + observed member health
  -> control-plane validation and planning
  -> immutable route snapshot generation
  -> acknowledged publish to node runtimes and gateways
  -> scheduling/routing eligibility
```

Non-goals for V1:

- Automatic live migration, hot-add, or transparent rebalancing of a running
  VM when a member joins or leaves.
- Recovering guest memory, vCPU state, or device state merely by retrying work
  after a required resource node fails.
- Treating a gateway route map as the membership authority.
- Treating a heartbeat, source address, or learned route as a complete member
  registration or removal operation.
- Requiring a specific control-plane database, consensus implementation, or
  authentication mechanism before the state and transitions are specified.

### 1.1 Minimum usable boundary

The minimum usable system includes the ordinary control-plane path for member
join, compute cordon, safe drain, and gateway replacement. A newly joined
member becomes eligible only after identity/capability validation and an
acknowledged route snapshot. Cordon blocks new placement, a compute drain
rejects active VM dependencies, and gateway replacement requires a verified
alternate path before publication.

The minimum system does not include automatic live migration, coordinator high
availability, transparent recovery of lost guest state, or aggregate
multi-scope host transactions. Those are extended hardening work and must not
weaken the fail-closed behavior of the basic operations.

## 2. Authority and Version Domains

| State or decision | Authoritative owner | Allowed consumers/caches |
| --- | --- | --- |
| Desired compute/gateway membership and role assignment | Cluster control plane | Node agents and gateways report observation only. |
| Observed health and endpoint reachability | Registered member agent plus control-plane health monitor | Gateways may report evidence but do not promote it to membership. |
| Host/failure-domain relationship between roles | Cluster control plane | Node and gateway records consume an explicit registered relation. |
| Pod graph and flat/fractal topology policy | Cluster control plane | Gateways consume an immutable topology snapshot. |
| Scheduling eligibility and allocatable capacity | Cluster control plane | Scheduler reads only `ACTIVE` members with healthy validated capacity. |
| Route snapshot and next-hop rules | Cluster control plane | Node runtimes, sidecars, gateways, and optional kernel caches consume one versioned snapshot. |
| Running VM CPU/memory/storage allocation | Admitted VM manifest and lifecycle coordinator | Membership changes may not rewrite it implicitly. |

The following version domains have different meanings and must never be reused
as substitutes for each other:

| Version | Meaning |
| --- | --- |
| `membership_revision` | Monotonic revision of desired member records and their lifecycle state. |
| `topology_revision` | Monotonic revision of the Pod and gateway graph. |
| `admission_eligibility_revision` | Monotonic revision of the member/role/capability set eligible for new activation. |
| `route_scope_id` | One VM-incarnation route namespace or leaf scope. |
| `route_generation` | Immutable next-hop generation within one full route-snapshot key. |
| `vm_incarnation` | One successful VM lifetime; prevents delayed traffic from an old VM entering a reused namespace. |
| Node boot/process instance ID | One member-agent process lifetime; prevents a stale process from claiming a newer registration. |
| Existing node, request, page, and CPU epochs | Semantics defined by their owning subsystem; none imply membership freshness. |

## 3. Data Model

The exact serialized schema belongs to `canonical-record-schema.md`. The
following logical fields are required.

### 3.1 Compute Node Record

```text
NodeRecord {
    physical_node_id;
    node_instance_id;
    failure_domain_id;
    control_endpoint;
    sidecar_endpoint;
    roles;
    pod_id;
    local_vnode_range;
    capacity;
    capabilities;
    desired_membership_state;
    observed_health_state;
    membership_revision;
    topology_revision;
}
```

`physical_node_id` identifies a resource provider. `node_instance_id` changes
when its agent process or host instance is replaced. A physical host can own
multiple local vnodes, but vnode assignment is a routing concern rather than a
claim that each vnode is an independently schedulable machine.

### 3.2 Gateway Record

```text
GatewayRecord {
    gateway_id;
    gateway_instance_id;
    hosting_physical_node_id;
    failure_domain_id;
    endpoint;
    roles;                  // leaf sidecar, intermediate, root, or combined
    pod_id_or_scope;
    parent_gateway_ids;
    child_gateway_ids;
    desired_membership_state;
    observed_health_state;
    membership_revision;
    topology_revision;
}
```

A gateway and a compute node may share one physical host, but their records are
not aliases. `hosting_physical_node_id` and `failure_domain_id` are explicit
registration fields and must not be inferred from endpoint address. A live host
can have a compute-local or gateway-local process failure, while a host failure
is a correlated failure of every hosted role.

### 3.3 Route Snapshot

```text
VmRouteScopeKey {
    vm_id;
    vm_incarnation;
    route_scope_id;
}

RouteSnapshotKey {
    vm_route_scope_key;
    topology_revision;
    route_generation;
    snapshot_digest;
}

RouteSnapshot {
    route_snapshot_key;
    membership_revision;
    flat_or_fractal_scope;
    next_hop_rules;
    required_ack_set;
    required_ack_set_digest;
    predecessor_snapshot_key;
    operation_retention_horizon;
    activation_and_retirement_policy;
}
```

The topology graph is cluster-global, but route snapshots are per VM
incarnation/scope overlays compiled from that graph and the candidate placement
plan. The immutable candidate manifest later binds the prepared snapshot key.
A gateway can therefore hold VM A's draining predecessor while VM B starts,
stops, or advances independently. The snapshot is immutable after preparation.
A gateway may retain the current and draining predecessor snapshots
concurrently, but packet lookup must use one complete snapshot, never a
partially edited map.

`route_generation` is unique only within `RouteSnapshotKey`; receivers must
validate the full key and digest. Scope creation, activation, and retirement
are lifecycle operations, not an implied result of a membership join.

## 4. Member and Health State Machines

Membership state applies independently to compute and gateway records:

| State | Meaning | Schedulable | Routable |
| --- | --- | --- | --- |
| `PENDING` | Registration request exists but identity and endpoint are unverified. | No | No |
| `VALIDATING` | Capabilities, identity, endpoint, and topology constraints are being checked. | No | No |
| `PREPARED` | Required route snapshot is loaded and acknowledged but not committed. | No | No |
| `ACTIVE` | Membership and route generation are committed. | Compute only | Gateway/sidecar only |
| `CORDONED` | No new compute placement; existing allocation remains unchanged. | No | Existing paths only |
| `DRAINING` | Intentional removal is in progress under an explicit drain plan. | No | Only old-generation drain traffic |
| `REMOVED` | Membership is retired and its identity may not be immediately reused. | No | No |
| `FAILED` | Control plane has recorded an unrecoverable or unplanned failure. | No | No, except an explicitly retained draining path cannot be assumed healthy. |

Health is observational, not a replacement for membership state:

| Health | Meaning |
| --- | --- |
| `HEALTHY` | Valid heartbeats and required endpoint/capability checks are current. |
| `SUSPECT` | A bounded monitoring threshold was missed; the member is excluded from new placement while checked. |
| `UNREACHABLE` | A longer threshold or explicit transport failure was reached. |
| `RECOVERING` | The member reappeared but must revalidate its instance identity and current snapshot before use. |

An `ACTIVE` record that becomes `SUSPECT` or `UNREACHABLE` immediately loses
new scheduling eligibility. It does not automatically transition to `REMOVED`,
release its resources, or authorize route learning to replace it.

### 4.1 Admission Linearization

The control plane maintains an `admission_eligibility_revision` over all
members, gateway roles, node/gateway instances, capability profiles, health
exclusions, and route scopes eligible for a new VM activation. A candidate VM
captures this value and its full `AdmissionEligibilityFence` during planning.

The following operations invalidate every dependent candidate that has not
reached its durable activation fence:

- Compute cordon, health exclusion, drain, removal, or node-instance change.
- Gateway drain, failure, removal, topology replacement, or gateway-instance
  change.
- Required capability/profile change or route-scope ACK-set change.

The linearization rule is one control-plane decision order:

```text
membership/topology eligibility change before ACTIVATE
  -> candidate ACTIVATE is rejected as ELIGIBILITY_FENCE_STALE and aborts/replans

durable ActivationRecord(decision=ACTIVATE) before membership/topology change
  -> transaction is a post-decision dependency; drain waits for activation or
     drives compensating teardown before selected-member removal
```

Every reservation, participant prepare, route prepare, `COMMIT_RESERVATION`,
and `ACTIVATE_MANIFEST` request validates the exact fence. A node may not
accept an old reservation merely because its instance still matches. A gateway
in `DRAINING` is eligible only for predecessor-generation drain traffic and
cannot satisfy a new candidate's normal route ACK set.

`AdmissionEligibilityFence` carries `admission_eligibility_revision` as a
separate canonical field in addition to membership and topology revisions.
Health, capability, and pending-drain changes must therefore invalidate an
unfinished candidate even when the registered topology did not change.

## 5. Controlled Operations

### 5.1 Join a Compute Node

1. The node agent registers a stable physical identity, a fresh instance ID,
   endpoints, offered capacity, capabilities, requested roles, and bootstrap
   topology information.
2. The control plane validates identity, endpoint reachability, capability
   claims, exclusive names, Pod capacity, and admission policy.
3. The control plane assigns a Pod and local vnode range without colliding with
   active identities. It records the member as `VALIDATING`.
4. It compiles route snapshot `G+1` for every affected scope, persists the
   survivor `RequiredAckSet`, and distributes a prepare record to that set.
5. Each recipient validates identity, namespace, topology revision, and next
   hops, then acknowledges prepared state without using it for normal traffic.
6. After all persisted required acknowledgements, the control plane commits
   `G+1` and
   marks the compute role `ACTIVE`. The scheduler may then use its capacity for
   future VM admissions.
7. A failed prepare aborts the operation. The candidate remains non-routable
   and non-schedulable, and no partial route remains authoritative.

Adding capacity does not alter the immutable admitted manifest of an already
running VM. Active-VM expansion is a separate future operation requiring its
own memory, vCPU, device, and guest-topology contract.

### 5.2 Join a Gateway

Gateway join follows the same registration and prepare flow, plus these
requirements:

- The control plane validates the intended parent/child graph and rejects a
  cycle or ambiguous next hop.
- It verifies bidirectional reachability for every required link.
- It prepares all affected child, parent, and leaf next-hop rules together.
- It records the gateway's hosting physical node and failure domain, then
  reserves its host-side control/gateway overhead before it becomes eligible.
- The gateway becomes `ACTIVE` only after the committed snapshot gives every
  newly routed destination a complete path to a target node runtime.

A gateway may not claim to be ready merely because its UDP listener is bound.
Readiness includes route-snapshot validation and the required peer acknowledgements.

### 5.3 Cordon and Drain a Compute Node

For a compute member, `CORDONED` immediately advances admission eligibility
and prevents unfinished candidate admission from using the compute role while
allowing existing allocations to finish or be examined. For a gateway member,
it prevents new admission or successor-route selection from naming that
gateway while retaining already committed route snapshots for existing
traffic; it does not rewrite those snapshots. A request to enter `DRAINING` must
enumerate every dependent VM allocation, including vCPU execution, memory
owner/directory duties, storage work, required local control duties, and every
hosted gateway role if the physical host itself is being removed.

V1 permits removal only when that dependency set is empty. If it is nonempty,
the operation is rejected with a structured reason. The controller must not
silently rewrite CPU routes, memory placement, directory ownership, or guest
NUMA layout to make a node appear removable.

### 5.4 Drain and Remove a Gateway

Before a gateway enters `DRAINING`, the controller creates a route transaction
with a verified successor route for every affected destination. The departing
gateway is excluded from the successor's `RequiredAckSet`; it may report an
optional predecessor-drain status, but its silence cannot block successor
commit. New normal traffic changes only after every surviving required source
has prepared the same snapshot key/digest.

The implemented V1 controller primitive is deliberately fail-closed and
bounded to one affected VM route scope. It accepts a drain only when the
departing healthy `ACTIVE` gateway has exactly one registered dependency for
that VM incarnation, the successor has `topology_revision = current + 1`, the
predecessor is a currently activated snapshot for the same scope, the
departing gateway appears exactly once in the optional predecessor-drain set,
and no successor next hop or required ACK names that gateway. Larger
multi-scope drains must be represented as an explicit aggregate transaction;
they must not publish a subset of replacement paths.

The controller first durably records the successor `RouteTransaction`, then
durably reserves its next topology revision in the gateway-drain plan and
advances `admission_eligibility_revision`. Registration, removal, and any
other topology-changing drain are rejected while that reservation is live.
Only ACKs for that one reserved successor may proceed. Its composite commit is
one durable frame that activates the successor and its required ACK states,
marks the gateway `DRAINING`, advances membership/topology/eligibility
revisions, and stamps all records. A crash after the ordinary route prepare
but before the drain plan leaves an orphan future-topology route that cannot
ACK or commit; recovery permits only an explicit abort of that route.

An abort retires the prepared successor and clears the live topology
reservation without changing membership or topology revision. It does not
decrement `admission_eligibility_revision`: the one-step invalidation remains
monotonic so an admission captured while the drain was prepared cannot be
resurrected by a later abort replay.

The predecessor is retained until every operation reference completes or its
documented query/retry horizon expires with a typed result. A fixed arbitrary
timer is not sufficient. If any surviving required ACK holder is unreachable,
the controller either fences that sender and degrades/fails its dependent VM or
leaves the predecessor active; it must not globally publish a route while a
live sender can only use the failed next hop.

If the gateway is the sole validated path to any active destination, removal is
rejected. Deleting the process, socket, or one map entry is not a drain.

### 5.5 Host-Role Drain and Removal

Host removal is a transaction over every compute, sidecar, and gateway role
whose record has the same `hosting_physical_node_id` or failure-domain host
identity. Role records remain separate for ordinary role-local faults, but a
host stop/removal may not act on only one of them:

1. Cordon all compute placement on the host and invalidate unfinished
   admissions using its resources or gateway routes.
2. Enumerate every post-decision or committed compute allocation, local control
   duty, gateway route scope, and predecessor-generation drain on every hosted
   role. A transaction with an activation fence remains a dependency until it
   reaches `COMMITTED` or its compensating teardown is durable everywhere.
3. Prepare/commit successor routes excluding each departing gateway through
   the required-survivor ACK rule.
4. Drain/retire predecessor route generations, then prove no active snapshot
   or normal sender still references the host.
5. Remove compute roles only when their resource dependency sets are empty;
   only then may the host or its remaining roles stop.

### 5.6 Unplanned Failure

An unplanned role failure is handled in this order:

1. Mark the failed role `SUSPECT` or `UNREACHABLE`, advance admission
   eligibility, and exclude it from new scheduling/activation.
2. For an unplanned physical-host failure, atomically mark every hosted role
   suspect/unreachable under one correlated failure observation; do not leave
   a gateway route active merely because its separate GatewayRecord was stale.
3. Determine whether an already validated alternate route or resource replica
   exists for each affected VM dependency.
4. If a safe alternate gateway path exists, publish a replacement route using
   its persisted required-survivor ACK set.
5. If a required resource node or sole path lacks a specified replacement,
   surface the VM's defined degraded, paused, or failed outcome. Do not report
   healthy operation and do not invent a guest-state recovery path.
6. Reappearing members re-enter validation with a fresh instance ID check;
   they do not become `ACTIVE` from a heartbeat alone. A required existing VM
   does not automatically rebind to the new member instance in V1.

## 6. Flat and Fractal Route Scope

`WVM_SLAVE_BITS=12` describes a current 4096-slot implementation limit, not a
permanent flat-domain, leaf-Pod, or cluster capacity. Membership capture and
admission must not size all member records or scratch storage from one domain's
vnode limit. Cluster members, domain vnodes, gateway adjacency/routes, and
per-VM workspaces have independent, explicit resource budgets and bounded
storage sized for actual records. Record/byte limits, including serialized
snapshot limits, remain enforced before publication or activation.

The formal routed-frame prefix uses a `u32` vnode/endpoint and a separate `u64`
destination scope. `0xffffffff` is reserved; the representable vnode range is
`0..0xfffffffe`. This address space is not a physical-host capacity claim.
The detailed budget and sparse-ID contract is in `identity-routing.md` Section
3.1. The logical destination form is:

```text
flat:    { vm namespace, local vnode }
fractal: { vm namespace, pod or prefix, local vnode }
```

In a fractal deployment:

- A leaf sidecar maps only local vnodes to local node-runtime endpoints.
- An intermediate gateway maps an admitted Pod/prefix scope to a child or
  parent next hop.
- A root or upper-level gateway maps destination Pod/prefix to a subtree next
  hop.
- Every layer preserves the same VM namespace and incarnation rules.

The control plane selects `flat`, `fractal`, or a policy such as `auto` from
connectivity, route-aggregation policy, and the independent capacity budgets.
A directly connected flat domain may exceed 4096 when its consumers have
sufficient capacity; neither a high vnode ID nor crossing the old constant
alone forces hierarchy. Conversely, several Pods may each retain a 4096-vnode
budget while the cluster total grows beyond it. Existing global-array checks
must be removed and verified before claiming either behavior works.

Users request VM resources and policy, not hand-authored per-destination
gateway routes. Budget changes do not make new members ACTIVE, alter existing
VM placement, or replace live routes without the normal membership/admission
and prepared snapshot transactions. Missing capacity rejects explicitly rather
than truncating captures, silently changing topology, or publishing part of a
route set.

### 6.1 VM Route-Scope Lifecycle

The lifecycle coordinator creates one or more `VmRouteScopeKey` values after it
has a candidate placement and before resource/participant activation. The
route compiler combines that VM-scoped overlay with the current cluster topology
to produce an initial `RouteSnapshotKey`; the later immutable candidate manifest
binds that key. No operation mutates a global gateway map in place.

For an initial VM scope, the `RequiredAckSet` contains only already-running
surviving sidecars/gateways and any new gateway role. A not-yet-prepared
per-VM node runtime is not a route-transaction survivor; it receives the exact
prepared snapshot through `PREPARE_MANIFEST` and cannot emit normal traffic
until its own activation ACK. This permits route-scope preparation before VM
resource reservation without treating an unstarted QEMU/executor as a missing
gateway ACK source.

```text
scope absent
  -> ROUTE_SCOPE_PREPARED (candidate-only, ACKed but no normal traffic)
  -> ROUTE_SCOPE_ACTIVE (same activation fence as admitted VM)
  -> ROUTE_SCOPE_RETIRING (no new operations, predecessor/query retention)
  -> ROUTE_SCOPE_RETIRED (all scope-specific state released)
```

The reverse sequence is part of VM `RETIRING`. It removes only the stopped VM's
scope after its route-retirement ACKs, subscriber cleanup, and active-operation
references complete. A shared gateway may retain several current and draining
scope snapshots concurrently; raw vnode overlap never authorizes a shared
namespace entry.

## 7. Publication, Concurrency, and Failure Rules

Every route update has one persisted transaction:

```text
RouteTransaction {
    operation_id;
    route_snapshot_key;
    predecessor_snapshot_key;
    required_ack_set[];           // role ID, instance ID, expected endpoint
    required_ack_set_digest;
    optional_departure_drain_set[];
    operation_retention_horizon;
    state;                        // PREPARING, ACTIVATED, RETIRING, RETIRED, ABORTED
}
```

The required ACK set contains only currently eligible survivors that must
install `G+1` before they can emit normal traffic under it, plus any gateway
being activated by the transaction. It excludes a `FAILED`, `REMOVED`, or
departing `DRAINING` gateway, even when that gateway remains in the predecessor
drain set. A departure ACK is optional diagnostic/drain evidence, never a
commit precondition.

Route update semantics are:

```text
persist RouteTransaction and RequiredAckSet
  -> prepare immutable G+1 on every required survivor
  -> collect only persisted-required ACKs on a control path independent of G
  -> atomically activate G+1 at those survivors
  -> retain G while active-operation references or query/retry horizon remain
  -> retire G, then record route scope/generation retirement
```

Each ACK carries operation ID, full route snapshot key/digest, role identity,
role instance identity, and prepared/activated state. Coordinator restart
reuses the persisted ACK set and recorded replies; it must not recompute a
different quorum midway through a transaction. If a required survivor becomes
unreachable, the controller fences its normal traffic and degrades/fails the
affected VM, or aborts while retaining `G`; it must not silently publish an
unusable successor.

Route forwarding metadata may change from G to G+1 only under the retry rule
in `wire-ipc-abi.md`: the inner semantic operation key/digest remains unchanged
and destination deduplication is unaffected. A predecessor is retained by its
active-operation references and the maximum completion-query/retry horizon of
memory, vCPU, and block operations. After that horizon, a query returns a typed
`RESULT_EXPIRED`/failure, never a second guest-visible execution or write.

The control plane serializes conflicting topology and membership operations.
That serialization is control-plane work only. The normal memory/vCPU data path
continues to use local queues, batching, QoS, and immutable route-snapshot
lookups; it must not acquire a global membership lock for every packet.

Snapshot replacement must use safe lifetime ownership such as reference counts
or an equivalent read-copy-update scheme. A gateway must not free a predecessor
snapshot while a receive worker can still use it. The exact mechanism is an
implementation decision, but its reader/writer ordering and teardown behavior
must be tested.

V1 has no automatic durable control-plane failover guarantee. A membership
operation has a bounded prepared lease and operation identity. After coordinator
restart, it reconciles the persisted transaction/ACK set with participants and
either completes one known activation/retirement or aborts it; it must not infer
completion from a member process still being alive.

## 8. Current Code Mapping and Known Deviations

| Current code | Current behavior | Required migration direction |
| --- | --- | --- |
| `common_include/wavevm_resources.c` | Parses static `NODE` records and allocates sequential vnode ranges at startup. | Import as bootstrap input into the control-plane registry; do not make it the long-term authority. |
| `common_include/wavevm_membership_controller.c` and `wavevm_membership_control.c` | The authority persists authenticated node/gateway registration, desired and observed member state, dependency counts, route prepare/ACK/commit/retire decisions, one-scope fail-closed gateway-drain prepare/commit/abort frames, and fenced compute/gateway cordon transitions. The V1 receiver exposes canonical `GatewayDrainRequest` and `MemberCordonRequest` only to transport-authenticated `EXECUTOR` actors accepted by separately configured route-management and membership-management callbacks, and durably replays successful registration, rejoin, drain, and cordon results. | Extend the bounded one-scope drain into an explicit aggregate transaction before permitting multi-scope gateway or host drains. Bind both management authorization callbacks to the real executor/control-plane trust domain rather than test adapters. The coordinator/topology owner captures deep-copied controller records, then combines that immutable membership revision with separately owned capability and reservation evidence. It must not construct runtime membership from `NODE`/`ROUTE` files. |
| `common_include/wavevm_control_transport.[ch]` | Provides a length-prefixed, reliable ordered stream adapter for the authenticated membership receiver. It decodes local V1 envelopes, bounds frame allocation, obtains actor identity only from the transport authentication callback, invokes the one owner dispatch, and writes the fixed 72-byte `CTRL_RESULT` on the same stream. | Bind the adapter to the real control-plane owner and its authenticated stream listener lifecycle. The adapter must remain transport-only: it must not create a second membership authority or infer actor identity from packet fields, source addresses, or payloads. |
| `common_include/wavevm_control_owner.[ch]` | Provides the lifecycle boundary for one protected local Unix stream listener, creates one transport instance per accepted client, and joins client threads during shutdown. It owns no membership or route records; typed `authenticate` and `apply`/`dispatch` callbacks remain the only authority boundary. | Embed this owner in the user-space control-plane service that supplies the durable membership plane and real authentication policy. A remote authenticated stream may use the same transport contract, but it must not bypass the owner or create a second membership cache. |
| `common_include/wavevm_membership_coordinator.c` | Composes authenticated join, compute cordon/drain/remove, and one-scope gateway successor prepare/required-ACK/commit-or-abort operations. Replays committed or removed operations from the controller's durable state and uses a lock-safe member status copy. | Connect this coordinator to the real control-plane transport and manifest/topology planner. Aggregate multiple affected VM scopes and host-role drains before allowing production removal. |
| `gateway_service/aggregator.c` | Parses `ROUTE` groups, learns addresses, and offers an in-place route add/update control path. | Consume prepared immutable snapshots; do not infer membership from packet source or modify live maps as membership operations. |
| `master_core/user_backend.c` | Uses a fixed `WVM_MAX_GATEWAYS` table and sends through a local sidecar. | Keep only local sidecar/derived next-hop state in the node runtime; remove global flat-target assumptions after the route-scope contract exists. |
| `master_core/kernel_backend.c` | Holds module-global route state keyed by current fixed limits. | Convert to versioned per-VM accelerator cache after `kernel-accelerator.md`; it cannot be membership truth. |
| `common_include/wavevm_cluster.c` and `wavevm_admission.[ch]` | Whole-cluster validation, snapshot/plan arrays, and scratch arrays use `WVM_MAX_SLAVES`/`WVM_MAX_GATEWAYS`. | Use caller-owned bounded member, gateway, and admission storage sized for actual records; do not inherit a single domain's vnode budget. |
| Test scripts | Materialize one-off `NODE` and `ROUTE` files. | Generate bounded fixtures from manifests and topology records. |

The current gateway control structure names `DEL_ROUTE`, but the current receive
path handles only add/update. Even a complete delete opcode would still be
insufficient without the state, acknowledgement, drain, and VM-dependency rules
in this specification.

## 9. Compatibility and Migration

1. Remove direct `NODE` and `ROUTE` parsing from production launch paths.
2. Use the control-plane registry as the sole source of versioned desired
   membership state.
3. Generate immutable route snapshots from the registry for flat and fractal
   topology fixtures.
4. Add prepare/ack/commit/retire around gateway snapshot replacement before
   exposing live route updates.
5. Add persisted RequiredAckSet, independent control ACK path, and
   predecessor operation-retention handling before permitting live replacement.
6. Add compute/gateway cordon/drain checks and host-role/failure-domain
   transactions before permitting role or host removal.
7. Replace fixed global route assumptions using the identity/routing and
   kernel-accelerator specifications; do not preserve a legacy flat cache as a
   compatibility target.

Compatibility must fail closed for a missing nonzero VM route. It must not strip
the VM namespace, guess a member from a heartbeat, or treat a route-learning
entry as a substitute for an admitted snapshot.

## 10. Acceptance Tests

The join, cordon, safe drain, route-snapshot publication, and verified gateway
replacement tests form the minimum usable topology gate. Failure races and
multi-scope host recovery are extended hardening and do not block the first
correct member lifecycle.

- A compute-node join remains non-routable and non-schedulable until every
  required route-snapshot prepare acknowledgement succeeds.
- The control owner publishes a protected local stream before accepting clients;
  concurrent clients receive independently correlated typed results, EOF closes
  only that client, and owner stop joins clients and removes the listener.
- A gateway join rejects cyclic, incomplete, or one-way topology links.
- A snapshot update under active traffic never exposes a partially populated
  route map or changes VM namespace.
- A newly active compute node changes only future placement; an existing VM's
  manifest, vCPU routes, memory placement, and guest NUMA presentation remain
  unchanged.
- Cordon blocks new placement without interrupting an allowed existing
  allocation.
- Removal of a compute node with active VM dependencies is rejected in V1.
- Gateway drain succeeds only with a verified alternate path and preserves
  bounded in-flight request behavior.
- Attempting to remove a sole gateway path fails without producing a black hole.
- **Extended:** Kill the departing gateway before/during/after successor prepare. The route
  transaction either commits from its persisted survivor ACK set or returns a
  bounded failure; it never waits for the departed gateway's ACK.
- **Extended:** Race cordon, gateway drain, health failure, and node/gateway instance change
  with every candidate admission stage. No invalidated candidate reaches
  `RUNNING`, while existing committed allocations are not silently replanned.
- **Extended:** A host carrying an idle compute role and a gateway for another VM cannot be
  removed until successor routes and predecessor drains finish. A host failure
  marks all hosted roles unavailable together.
- VM A route-scope retirement and VM B route activation on one gateway retain
  distinct current/predecessor snapshots even with overlapping raw vnode IDs.
- **Extended:** An unplanned compute-node or gateway failure produces the documented VM
  degraded/paused/failed result rather than a false success.
- **Extended:** A reappearing member with a stale instance ID cannot overwrite a newer record
  or become active without revalidation.
- Flat and fractal fixtures retain the same VM namespace and route-generation
  semantics, while each leaf route domain remains within its declared fan-out.
- A flat membership/admission fixture exceeds 4096 with sufficient independent
  workspace and route budgets and compiles/uses routes without a hierarchy
  change. A multi-Pod fixture exceeds that cluster total while every Pod stays
  within its own declared budget and overlapping local vnode IDs remain distinct.
  Both exercise actual capture/admission/route operations, not only record setup.
- Capacity exhaustion during capture or prepare rejects without partial member
  snapshots, route publication, or reservation leaks. Sparse high IDs consume
  only their actual records and are checked separately from occupancy budgets.

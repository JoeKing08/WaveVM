# WaveVM Identity and Routing Specification

Status: normative implementation specification.

The [Document Maintenance](../wavevm-refactor-roadmap.md#document-maintenance)
rules apply to this specification.

Scope: identity allocation, identity lifetime, flat and fractal route scope,
route lookup, route-snapshot ownership, complete destination validation, and
failure behavior for missing or stale routes. This
specification does not define packet framing, payload layout, membership state
transitions, page consistency, or vCPU handoff; those belong to the wire IPC,
membership, memory, and vCPU specifications. VM identity allocation and
retirement are consumed from `runtime-manifest-lifecycle.md`; resource placement
is consumed from `resource-placement-admission.md`.

This document is normative for routing work. Raw-ID fallback, `NODE`/`ROUTE`
production inputs, and gateway-invented membership are prohibited; bounded
storage must follow the declared independent capacity budgets.

## Subsystem Boundary Contract

This summary indexes the owning rules; it does not duplicate their definitions.
Apply [baseline Section 0](../wavevm-architecture-baseline.md#0-architecture-authority-and-maintenance-contracts) to boundary changes.

| Boundary | Required contract |
| --- | --- |
| Responsibility and authority | Own identity/key interpretation, scoped lookup and operation lifetime across route replacement. Lifecycle allocates VM lifetimes; membership publishes routing truth. |
| State and mutation | Runtime route maps are immutable snapshot projections keyed by full scope/generation. Only authorized publication replaces them; lookup never invents an ID, member, or placement. |
| Allowed implementation dependencies | Shared identity types, canonical snapshot records, public snapshot/compiler utilities and transport-facing lookup interfaces. Consume membership projections, not controller private state. |
| Interactions and lifetime | Section 6.1 owns rerouting without duplicate effects. Retirement consumes [lifecycle Section 6.3](runtime-manifest-lifecycle.md#63-cross-subsystem-resource-retirement); preserve old snapshot references through required result/query horizons. |
| Concurrency and cost | Concurrent lookups use complete snapshots. Declare lookup/compilation storage budgets and flat/fractal hop costs; sparse IDs do not justify dense allocation or global lookup serialization. |
| Failure and verification | Sections 6 and 10 require typed missing/stale/capacity errors and identity isolation. A wider field or extra gateway level does not prove supported scale. |

## 1. Goal and Non-Goals

Every network-visible request must identify one VM lifetime, one routing
destination, and one route snapshot without relying on a test topology, source
address, arrival order, or raw node ID coincidence. A stale packet from an old
VM or member lifetime must fail rather than enter a newer one.

The goal is a hierarchy-aware route model where flat and fractal deployments
share the same VM namespace and endpoint semantics while each gateway holds
only the route scope it needs.

Non-goals for Minimum:

- Reusing a `vm_id` immediately while old processes, routes, or packets can
  still exist.
- Inferring a route from a UDP source address or heartbeat.
- Exposing physical topology selection or per-destination routes as ordinary
  VM-user input.
- Treating an identifier's representable range as proof that route tables can
  support the same number of endpoints.
- Supporting a distributed-hash or auto-learning route algorithm as a semantic
  authority without a separately accepted discovery and membership contract.

## 2. Identity Model

The following identifiers are distinct even when numerically equal.

| Identifier | Owner | Lifetime and meaning |
| --- | --- | --- |
| `vm_id` | Cluster control plane | Logical VM namespace is `u32` values `1..UINT32_MAX`. It is not durable on its own. |
| `vm_incarnation` | Cluster control plane | Fresh value per identity allocation, consumed even by an aborted candidate; protects against delayed traffic after `vm_id` reuse. |
| `physical_node_id` | Cluster control plane | Registered resource-provider host. It is not a DHT or route-table index. |
| `node_instance_id` | Registered node agent | Fresh boot/process instance for a physical node registration. |
| `gateway_id` / `gateway_instance_id` | Cluster control plane and gateway agent | Logical gateway role and one gateway process lifetime. |
| `pod_id` | Cluster control plane | Fractal routing domain or prefix scope. It is not guest NUMA identity. |
| `vnode_id` | Cluster control plane | Logical routing slot inside a VM/POD route domain. One physical node can own multiple vnodes. |
| `primary_vnode` | Cluster control plane | Designated local vnode in the admitted route scope; not a substitute for a complete key. |
| `WVM_INSTANCE_ID` | Local runtime manifest | Local namespace discriminator for sockets, SHM, logs, and processes. Never a wire route ID. |
| `process_instance_id` | Component runtime | Diagnostic lifetime for one process. Never a VM identity or route key. |
| `membership_revision` | Cluster membership authority | Desired member-record revision. |
| `topology_revision` | Cluster topology authority | Pod/gateway graph revision. |
| `route_scope_id` | VM lifecycle/control plane | One VM-incarnation route namespace or leaf scope. |
| `route_generation` | Route snapshot authority | Immutable next-hop generation within one route scope. |
| `route_snapshot_digest` | Route compiler | Digest of one full immutable snapshot. |

An 8-bit VM / 24-bit node packed identifier cannot carry VM incarnation,
member-instance identity, topology revision, or route generation. Such helpers
must not replace the complete production key. The zero VM namespace is for
authenticated cluster control, not an exception permitting raw-ID guest routes.

### 2.1 VM Namespace Allocation and Retirement

The allocator persists one record per logical VM namespace:

```text
VmNamespaceRecord {
    vm_id;
    next_vm_incarnation;
    state;                        // FREE, ALLOCATED, ACTIVE, RETIRING,
                                  // QUARANTINED
    retirement_record_digest;
}
```

The required state transitions are:

```text
FREE -> ALLOCATED -> ACTIVE -> RETIRING -> QUARANTINED -> FREE
                 \-> RETIRING                 // aborted candidate
```

`ALLOCATED` occurs before any reservation, candidate-manifest digest, or route
scope is emitted. It allocates a strictly new `vm_incarnation`; retrying an
aborted attempt never revives the old value. `ACTIVE` follows the lifecycle
activation fence, not a route listener or process start.

For the defined wire ABI, `RETIRING -> QUARANTINED` requires all of the following:

- The VM route scopes/current and predecessor snapshots have received required
  retirement acknowledgements and have no active operation references.
- The maximum memory/vCPU/block completion-query and retry horizon has elapsed
  or each remaining operation has a recorded terminal result.
- Node runtimes, executors, QEMU endpoints, kernel contexts, local names, and
  directory subscriber records report manifest-incarnation teardown.

Only then may the allocator return the ID to `FREE`; the next allocation uses a
new incarnation and rejects every old-format/new-format packet that does not
match it.

Old formats without the required incarnation are rejected. Their rejection
must not depend on a global epoch reset or a supported legacy VM deployment.

### 2.2 Identity Width and Participant Capability

The envelope's `vm_id` is a full `u32` namespace. A fixed dense resource-plan
array must not cap or alias that namespace. Identity/admission storage follows
actual records and declared capacity, independently of identifier magnitude.
The allocator may assign
any value in `1..UINT32_MAX` only after every required participant for that VM
(QEMU frontend, node runtimes, executors, sidecars, gateways, and selected
accelerator contexts) has negotiated `WVM_CAP_VM_ID_U32`. A participant
outside the VM's manifest need not negotiate this feature merely because it is
registered in the cluster.

A production VM never traverses a legacy header hop. The control plane records
the required namespace ABI in the candidate manifest and rejects a plan whose
route or local participant lacks it. Mixed old/new VM deployments and dual
identity decoders are not required.

## 3. Canonical Route Key

The semantic route key is:

```text
RouteKey = {
    protocol_version,
    vm_id,
    vm_incarnation,
    route_scope_id,
    destination_scope,
    destination_vnode_or_endpoint,
}

RouteSnapshotKey = {
    vm_id,
    vm_incarnation,
    route_scope_id,
    topology_revision,
    route_generation,
    route_snapshot_digest,
}
```

`destination_scope` is empty for a flat route domain and is a Pod/prefix for a
fractal route domain. The wire carriage is the 24-byte routed-frame
prefix in `wire-ipc-abi.md`: its `destination_kind`,
`destination_scope`, and `destination_vnode_or_endpoint` fields complete this
key. The prefix is forwarding metadata protected by the frame CRC but excluded
from the semantic payload digest.

The logical destination form is:

```text
flat:    { vm_id, vm_incarnation, local_vnode }
fractal: { vm_id, vm_incarnation, pod_or_prefix, local_vnode }
```

Vnode address space and deployed capacity are separate contracts. A domain's
capacity follows explicit bounded storage and transport budgets, not an
identifier bitfield or a fixed array. Fractal topology may aggregate multiple
independently budgeted leaf domains; it is not required merely because an
identifier is numerically large.

### 3.1 Address Space and Capacity Budgets

The formal routed-frame prefix in `wire-ipc-abi.md` carries a `u32`
`destination_vnode_or_endpoint`. Values `0..0xfffffffe` are representable vnode
IDs; `0xffffffff` is reserved and must reject. This gives 4,294,967,295 possible
vnode values per VM-scoped flat or leaf-Pod domain. It is an address-space bound,
not a physical-host count or an achievable deployment size. Range/count
arithmetic must reject overflow and inclusion of the sentinel.

The control plane owns independent capacity budgets for cluster members,
domain vnode counts, gateway adjacency and route records, and per-VM admission
and runtime state. Each consumer also enforces its allocated record/byte limits,
including serialized snapshot and control-message limits. A provider's supported
capacity constrains the admitted plan; an operator cannot enable unsupported
scale merely by raising a policy value. These are deployment resource budgets,
not per-VM hand-authored routes or test-only overrides.

Identity validity and occupancy limits are separate: a sparse high vnode ID
does not consume all lower-numbered entries. Allocate bounded storage for actual
records and retained snapshot generations, with explicit count/capacity checks.
Lookups use complete keys; they must not require node IDs to index a dense global
array. Kernel caches and subscriber sets need the same property, using bounded
sparse or lazily allocated blocks while preserving batching and queue concurrency.
Insufficient capacity must cause an explicit admission/prepare failure without
truncation, partial route publication, or leaked reservations.

A deployment may keep a 4096-vnode domain budget, raise it within supported
resource limits, or use several bounded Pods. Flat routing must remain available
above 4096 when connectivity and consumer budgets permit. Fractal routing is a
topology/aggregation choice, not a mandatory response to crossing that constant.
Multiple Pods may reuse local vnode values because their destination scopes
differ; global membership/admission limits must not inherit one Pod's budget.

## 4. Authority and Route Snapshots

| State or decision | Authoritative owner | Consumer behavior |
| --- | --- | --- |
| VM namespace and incarnation | Control plane / admitted manifest | All consumers validate before accepting an operation. |
| Physical member and gateway graph | Cluster membership/topology control plane | Gateways consume prepared snapshots; they do not infer membership. |
| Pod/vnode assignment | Control plane | Node runtimes and gateways cache the admitted mapping only. |
| VM route-scope lifecycle | VM lifecycle coordinator | It creates/activates/retires one VM-incarnation scope without mutating another VM's entries. |
| Next-hop table | Control plane route-snapshot compiler | Each node runtime, sidecar, gateway, and kernel cache performs lookup against one immutable full snapshot key. |
| Page directory and vCPU placement | Admitted VM manifest plus owning semantic specification | Route lookup transports a selected operation; it never invents placement. |

For every VM route scope, route publication is:

```text
compile G+1 from topology plus the VM-incarnation route scope
  -> persist a RequiredAckSet of eligible surviving senders/gateways
  -> prepare G+1 only on that exact set
  -> validate full snapshot key, identity, namespace, and next-hop reachability
  -> activate G+1 after that set acknowledges
  -> retain G while operation references or query/retry horizon remain
  -> retire G only after scope-specific completion
```

The current and predecessor generations may coexist during drain, but a packet
lookup obtains exactly one complete snapshot. A gateway may not mutate a shared
map in place such that one lookup observes a partial update. The full snapshot
key is needed because a route generation is not globally unique across VM
scopes.

## 5. Flat and Fractal Lookup

The external operation path is identical:

```text
source node runtime -> local sidecar -> gateway fabric
                    -> remote sidecar -> target node runtime
                    -> local directory or executor
```

Only next-hop selection differs.

### 5.1 Flat

A flat route domain maps the complete VM-scoped destination directly to the
target sidecar or node-runtime ingress endpoint. It is selected only when the
required sidecar connectivity and declared domain/consumer budgets fit one
domain. No permanent 4096-vnode ceiling applies. A high numeric vnode ID alone
does not require a gateway or a topology change.

### 5.2 Fractal

In a fractal topology:

- A leaf sidecar maps local leaf vnodes to local node-runtime endpoints and
  uses a parent next hop for nonlocal Pod prefixes.
- An intermediate gateway maps an admitted destination Pod/prefix to a child
  or parent next hop.
- A root or upper-level gateway maps a destination Pod/prefix to a subtree.
- Every level preserves the original VM namespace and incarnation. Hierarchy
  does not authorize a raw-ID lookup or VM-namespace stripping.

The canonical route-rule shape is deliberately stricter than the wire key:
an `EXACT_VNODE` rule denotes one `{scope, vnode}` leaf destination, while a
`PREFIX` rule has a nonzero scope, `destination_vnode_or_endpoint=0`, and a
`GATEWAY` next hop whose member role is `GATEWAY`. A flat snapshot contains
only exact rules with `destination_scope=0`. A fractal exact rule has a
nonzero destination scope. These are control-plane validation rules, so a
gateway never receives an ambiguous snapshot that can only fail at lookup.

The control plane chooses `flat`, `fractal`, or `auto` from connectivity,
route-aggregation policy, independent resource budgets, and active topology.
It must not select hierarchy solely because membership or a vnode ID exceeds
4096. A VM request may express placement policy but does not hand-author its
gateway path. A topology change still requires the normal prepared snapshot
transaction; increasing a capacity budget does not itself change live routes.

## 6. Lookup and Error Semantics

A route consumer validates, in this order:

1. Packet/frame syntax and protocol version.
2. Non-sentinel target identity and valid VM namespace.
3. VM incarnation when the wire carries it; before then, reject unsafe `vm_id`
   reuse by lifecycle policy.
4. Local accepted full route snapshot key and generation.
5. Destination scope and next-hop existence in one snapshot.
6. Gateway role and target node-runtime endpoint consistency.

Required route failures are logical statuses defined in the wire ABI:

| Status | Meaning | Required caller behavior |
| --- | --- | --- |
| `WVM_ROUTE_UNKNOWN` | No route exists for a valid destination in the selected generation. | Fail the operation; do not retry with a raw node ID. |
| `WVM_ROUTE_STALE` | Sender or receiver uses an unavailable/stale snapshot key or VM lifetime. | Refresh forwarding metadata through the control path, then retry only if operation semantics permit. |
| `WVM_ROUTE_NAMESPACE_MISMATCH` | VM identity/incarnation mismatch. | Drop and record a protocol fault; never deliver locally. |
| `WVM_ROUTE_TOPOLOGY_UNAVAILABLE` | Required member or path is unavailable. | Surface the owning operation's degraded/error result. |
| `WVM_ROUTE_LOOP` | Hop budget or route trace proves a forwarding loop. | Drop, report topology fault, and prevent retry amplification. |

`WVM_NODE_AUTO_ROUTE` is a compatibility sentinel, not a destination. It must
be resolved by the local node runtime before production cross-node transmission
and must never be inserted into a route table or passed through hierarchy as an
identity.

### 6.1 Route Replacement and Operation Lifetime

The semantic operation key/digest is independent of mutable forwarding
metadata. On a route refresh, a sender retains the same VM incarnation, origin
identity, operation ID, handoff sequence or block queue sequence, and semantic
payload digest; it may replace only the `RouteSnapshotKey` and delivery-attempt
metadata in the outer envelope.

Destination deduplication therefore cannot mistake rerouting for a new vCPU
execution, memory mutation, or block write. A predecessor snapshot remains
queryable for the maximum operation completion/retry horizon and active
operation references. After retirement a result query returns a typed
`RESULT_EXPIRED` or subsystem failure; it never creates a fresh semantic
operation. Details of envelope separation and completion retention belong to
`wire-ipc-abi.md`.

## 7. Static, Dynamic, and Learned State

Static bootstrap configuration may seed a topology record. It may not be
silently overwritten by route learning. Gateway heartbeats, source endpoint
observations, and view gossip are diagnostic/health evidence only.

Dynamic membership uses the membership specification's registration,
validation, prepare/ack/publish/retire lifecycle. A gateway's `ADD_ROUTE` or
future delete command is only a derived-snapshot installation primitive; it
cannot independently create, remove, or reactivate a member.

## 8. Implementation Touchpoints and Requirements

| File, symbol, or boundary | Required responsibility |
| --- | --- |
| `common_include/wavevm_protocol.h` | Define the canonical route key carrying incarnation and fractal scope. |
| `common_include/wavevm_config.h` | Replace shared fixed limits with independent resource budgets and storage sized for actual records; 4096 is not a permanent flat/leaf ceiling. |
| `common_include/wavevm_cluster.c`, `wavevm_admission.[ch]`, and `wavevm_runtime_dispatch.c` | Separate member/plan capacities from domain occupancy and ID validity; validate complete scoped destinations without dense-ID assumptions. |
| `master_core/user_backend.c` | Cache only local sidecar/derived next-hop state; do not require every destination to fit one local array. |
| `gateway_service/aggregator.c` | Use strict complete keys and immutable snapshot lookup; reject raw-ID production fallback. |
| `common_include/wavevm_resources.c` | Import as bootstrap data into a versioned member/topology registry. |
| `master_core/kernel_backend.c` | Convert to a context-scoped derived accelerator cache after kernel specification acceptance. |

## 9. Compatibility Boundary

No legacy raw-ID route, static route file, dense-index assumption, or dual
decoder is required. Production traffic uses complete VM-incarnation-scoped
keys and admitted snapshots; unsupported identities and missing routes reject
before forwarding. VM-ID reuse follows the retirement contract in Section 2.

## 10. Acceptance Tests

- Two VMs can use the same raw local vnode values without route collision.
- A delayed packet from an old VM incarnation is rejected before reaching a
  node runtime or executor.
- A nonzero VM route miss never strips the VM ID and retries a raw lookup.
- Flat and fractal deployments deliver identical semantic operations to the
  same target node runtime for equivalent admitted manifests.
- **Minimum:** A domain fixture budgeted for 4096 vnodes accepts 4096 admitted entries and
  rejects an additional entry without partial publication. A separate flat
  fixture with sufficient budgets admits more than 4096 entries, compiles the
  snapshot, and resolves/forwards destinations on both sides of the old boundary
  without adding a Pod or gateway layer. Compiler initialization alone is not
  evidence for this test.
- Sparse domain fixtures route IDs `0`, `4096`, `65536`, and `0xfffffffe` using
  bounded storage proportional to their entries; `0xffffffff` and overflowing
  vnode ranges reject. Occupancy limits must not be used as numeric-ID limits.
- Multiple leaf Pods reuse local vnode values and exceed 4096 total members
  while each remains within its own budget. Membership capture, admission,
  compiled routes, and forwarding preserve scope and do not hit a global
  leaf-sized array. An over-budget control workspace or serialized snapshot
  rejects explicitly without truncation or resource leaks.
- A fractal fixture proves that an intermediate gateway holds only prefix
  routes, not every leaf endpoint.
- Route generation replacement under load never yields a partial table, loop,
  or cross-VM delivery.
- Replace G with G+1 while dropping a `VCPU_EXIT`, memory commit ACK, and
  durable block result. Each retry/reroute preserves one semantic operation and
  produces one cached result or one bounded terminal failure.
- Start/stop VM A while VM B shares gateways and raw vnode values. VM A route
  retirement never mutates VM B's current or predecessor snapshot.
- Delayed old-format and wrong-incarnation packets after VM-ID reuse cannot
  reach the new incarnation; no legacy decoder bypasses that check.
- Source-address changes and heartbeat observations cannot overwrite a pinned
  production route or create a member.
- Kernel and user-space derived caches reject a stale VM identity or route
  generation rather than forwarding with a previous VM's state.

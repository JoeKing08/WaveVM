# WaveVM Runtime Manifest and Lifecycle Specification

Status: normative implementation specification.

RM-3.1 gate (2026-10-19): accepted — document already defines goal/non-goals,
semantic authority, structures/ABI, state/sequences, concurrency/backpressure,
failure/recovery, compatibility/migration, and acceptance tests per roadmap §3.1.

Scope: the user-facing VM request, the immutable admitted launch manifest,
per-node runtime manifests, manifest publication, VM lifecycle state, startup,
stop, rollback, and recovery boundaries. Resource selection belongs to
`resource-placement-admission.md`; member and route changes belong to
`cluster-membership-topology-lifecycle.md`; wire identity belongs to
`identity-routing.md` and `wire-ipc-abi.md`.

This specification is normative for all VM lifecycle work. Existing launch
scripts, environment variables, `NODE`/`ROUTE` files, and positional process
arguments are not production inputs; they are test history to be removed or
rewritten as manifest renderers.

## 1. Goal and Non-Goals

The goal is for one successful VM creation to produce one immutable,
versioned, auditable description of the VM actually admitted to the cluster.
Every QEMU frontend, node runtime, executor, sidecar, gateway cache, and
optional kernel accelerator must be able to identify the same VM incarnation,
the same resource plan, and the same local names from that description.

The normal control flow is:

```text
VmRequest
  -> validation + deterministic placement + reservation
  -> AdmittedVmManifest
  -> per-node RuntimeManifest prepare
  -> acknowledged commit/start
  -> RUNNING or one explicit failed/aborted outcome
```

Non-goals for V1:

- Live migration, hot-add, hot-remove, or implicit rebalancing of a running
  VM.
- Editing a running VM's resource, backend, or consistency semantics in place.
- Treating a launcher command line, process environment, or route file as a
  second authority after admission.
- Inferring success from a bound port, a surviving process, or one heartbeat.
- Reusing a `vm_id` immediately after stop before the identity/wire rules allow
  delayed traffic to be rejected by incarnation.
- Turning a node restart into permission to recreate a VM with changed
  placement, backend, or local names.

## 2. Authority and Version Domains

| State or decision | Authoritative owner | Allowed caches/consumers |
| --- | --- | --- |
| User request and request idempotency record | Cluster control plane | CLI/API client may retain a copy. |
| `vm_id` and `vm_incarnation` allocation | Cluster control plane | Every runtime validates it from the admitted manifest. |
| Candidate vCPU, memory, host, storage, device, and local-name plan | Immutable candidate manifest | Prepared reservations and participants only. |
| Admission/activation decision | Lifecycle coordinator's durable transaction record | Participants retain an idempotent local decision record. |
| Resolved vCPU, memory, host, storage, device, and local-name plan | Admitted VM manifest plus activation record | Per-node manifests and process-local caches. |
| Current VM lifecycle state | Lifecycle coordinator in the control plane | Node agents report observed substate only. |
| Route next hops | Versioned route snapshot from membership/topology control plane | Manifest references the required scope/generation; it does not duplicate mutable routes. |
| Page, vCPU, storage-operation, and interrupt state | Their subsystem authorities | Manifest only selects their policy and participants. |

The following values are distinct and must never be overloaded:

| Value | Meaning |
| --- | --- |
| `request_id` | Idempotency key for one user create/update request. |
| `vm_id` | Reusable logical VM namespace only after safe retirement. |
| `vm_incarnation` | One successful VM lifetime within a `vm_id` namespace. |
| `admission_tx_id` | One create/activate/abort transaction for a fresh VM incarnation. |
| `manifest_generation` | Immutable candidate/admitted manifest generation for one incarnation. |
| `activation_fence` | Durable, unique decision that converts one candidate manifest into an admitted allocation. |
| `eligibility_fence` | Exact eligible member, capability, route, and node-instance set accepted by one admission transaction. |
| `membership_revision` / `topology_revision` | Cluster desired-member and topology state. |
| `route_scope_id` | One VM-incarnation route namespace or leaf scope. |
| `route_generation` | Immutable routing snapshot generation within one route-scope identity. |
| `operation_id` | One data-plane or lifecycle operation. |

`route_generation` can advance through a valid gateway replacement without
mutating the VM's resource plan. A topology or route update never changes
`vm_incarnation`, page versions, vCPU handoff sequences, or storage ordering.
The route operation lifetime and its separate forwarding metadata are defined
by `identity-routing.md` and `wire-ipc-abi.md`.

## 3. Manifest Data Model

All manifest forms use the exact canonical, versioned serialization in
`canonical-record-schema.md`, with the envelope in `wire-ipc-abi.md`. JSON,
shell fragments, and environment variables may be debug renderings but are not
independent semantic formats. A candidate manifest is immutable enough to
prepare against, but it is not an admitted allocation until its separately
persisted activation record exists.

### 3.1 User-Facing VM Request

```text
VmRequest {
    api_version;
    request_id;
    display_name;                 // optional, not a route key
    requested_vcpus;              // positive integer
    requested_memory_bytes;       // positive, page-aligned after validation
    execution_backend_policy;     // AUTO, REQUIRE_KVM, or REQUIRE_TCG
    accelerator_policy;           // DISABLED, PREFER, or REQUIRE_KERNEL_ACCEL
    placement_policy;             // COMPACT or SPREAD
    host_constraints;
    guest_topology_policy;        // FLAT, PLACEMENT_NUMA, or SYNTHETIC_NUMA
    consistency_policy;
    storage_and_device_requirements;
    requested_lifecycle_options;  // only documented start/stop policy fields
}
```

The user supplies desired resources and constraints, not physical node IDs,
vnode IDs, gateway ports, socket paths, `WVM_INSTANCE_ID`, raw route entries,
or a guessed QEMU host. An administrative API may expose explicit placement
constraints for diagnosis or policy, but it must still pass normal admission
and cannot bypass reservation or capability validation.

`AUTO` is a request policy, not a runtime fallback permission. Admission first
tries a complete KVM placement, including the frontend and every required vCPU
executor. If that candidate is not admissible, admission may create a new
complete TCG placement when the request permits fallback. The TCG result must
have its own plan digest, reservations, capability profile, and manifest
diagnostic explaining the fallback; a partially reserved KVM candidate is
aborted rather than being mutated in place.

`REQUIRE_KVM` fails when a complete KVM placement cannot be admitted.
`REQUIRE_TCG` selects TCG directly. Once the backend is recorded in the
admitted manifest, a guest does not silently change KVM to TCG, TCG to KVM, or
Mode A to Mode B halfway through a running incarnation.

### 3.2 Candidate and Admitted VM Manifest

```text
CandidateVmManifest {
    schema_version;
    manifest_id;
    manifest_digest;
    vm_id;
    vm_incarnation;
    manifest_generation;
    request_id;
    admission_tx_id;
    eligibility_fence_digest;
    plan_digest;
    namespace_abi;                 // LEGACY or V1_U32
    candidate_created_at;

    guest_machine;
    guest_topology;
    execution_plan;
    consistency_policy;
    storage_and_device_plan;
    host_node;
    vcpu_placements;
    memory_placements;
    required_members;
    required_capability_profiles;
    reservation_requirements;
    route_scope_key;
    prepared_route_snapshot_key;
    derived_local_name_namespace;
    lifecycle_policy;
}

ActivationRecord {
    admission_tx_id;
    candidate_manifest_digest;
    activation_fence;
    coordinator_instance_id;
    required_participant_set_digest;
    required_route_snapshot_keys;
    decision;                     // ACTIVATE or ABORT
    durable_decision_sequence;
    decided_at;
}

AdmittedVmManifest = CandidateVmManifest + ActivationRecord(decision=ACTIVATE)
```

Required semantics:

- `vm_id`, `vm_incarnation`, `admission_tx_id`, and `manifest_generation` are
  assigned before a reservation is emitted. `manifest_generation` begins at
  one for an incarnation. An aborted attempt never reuses its incarnation.
- The candidate manifest is complete, immutable, and digestible before any
  `PREPARE_MANIFEST` participant prepares local VM state. It is not yet an
  admitted allocation and may be aborted while every reservation remains
  `PREPARED`.
- The only transition from candidate to admitted is a durable
  `ActivationRecord(decision=ACTIVATE)`. Participants must not infer activation
  from a surviving process, a reservation ACK, or a route listener.
- `host_node` is explicit. It names the physical node hosting the authoritative
  QEMU frontend, not the API submitter and not the first placement entry.
- `vcpu_placements` covers every guest vCPU exactly once. Each entry includes
  its executor physical node, local executor role/slot, backend, and capacity
  reservation-requirement reference.
- `memory_placements` cover every guest RAM page/chunk exactly once. Each entry
  includes its directory/execution node, range, capacity reservation reference,
  and the applicable page-consistency policy.
- `reservation_requirements` is the immutable per-node/exclusive-resource
  intent shared with the placement plan. Actual `ResourceReservation` records
  are derived after both plan and candidate self-digests are final, then are
  created by `PREPARE_RESERVATION`; embedding them in the candidate would create
  a digest cycle because they bind the candidate digest.
- `guest_topology` is guest-visible and independent of physical placement. A
  flat guest topology is valid even when resources span nodes.
- `required_members` names only members admitted by the exact
  `eligibility_fence`, including physical/role identity, node instance,
  capability profile, and required state. A later member change cannot be
  silently grandfathered into an unactivated candidate.
- `route_scope_key` and `prepared_route_snapshot_key` identify an immutable
  VM-incarnation route scope/snapshot. They never embed an editable per-packet
  route table. Their identity includes scope, topology revision, generation,
  and digest as defined by `identity-routing.md`.
- Per-node runtime manifests are deterministic filtered projections generated
  after the candidate manifest digest is final. They carry the candidate digest,
  but their own digests are not fields of the candidate manifest; otherwise the
  two record classes would form a hash cycle.
- `derived_local_name_namespace` is the sole input for QEMU IPC, shared-memory,
  worker socket, monitor, log, and temporary-name derivation. It prevents two
  VMs on one host from deriving colliding names from only a node ID. Its
  derivation salt is calculated before the candidate self-digest from
  `manifest_id`, `admission_tx_id`, VM identity/generation, and physical-node
  identity; it must not use the final candidate digest because it is itself a
  candidate field.
- The manifest contains no private keys, access tokens, or mutable process
  credentials. Those are supplied through a separately protected local
  credential channel and are not part of the VM identity.

### 3.3 Per-Node Runtime Manifest

Every participating `{vm_incarnation, physical_node_id}` receives a filtered
manifest that includes enough global identity to validate traffic but exposes
only local assignments and required peers:

```text
NodeRuntimeManifest {
    manifest_identity;            // id, digest, VM identity, generation
    admission_tx_id;
    eligibility_fence_digest;
    activation_fence_when_committed;
    physical_node_id;
    expected_node_instance_id;
    local_roles;                  // QEMU host, node runtime, executor, gateway
    local_vcpu_assignments;
    local_memory_assignments;
    local_storage_assignments;
    required_route_snapshot_key;
    local_endpoint_names;
    launch_plan {
        plan_version;
        node_runtime_data_port;
        node_runtime_control_port;
        local_executor_service_port; // loopback-only
        local_executor_control_port; // loopback-only
        executor_worker_count;
        vcpu_handoff_record_capacity;
        sync_batch_size;
        guest_total_memory_bytes;
        guest_machine;
        consistency_policy;
    };
    negotiated_capabilities;
    reservation_lease;
    startup_dependencies;
}
```

The node runtime must reject a local executor, QEMU connection, sidecar input,
or kernel context whose identity, manifest digest, generation, route scope,
eligibility fence, or local role does not match its accepted per-node manifest.
Before an activation record is received it may prepare only local resources; it
must reject guest traffic and may release that prepared state after its lease
expires if it never observes the activation fence.

The control plane durably stores one activated canonical
`NodeRuntimeManifest` projection for every candidate
`ReservationRequirement`, keyed by the candidate digest, physical node ID,
expected node instance ID, and reservation ID. A repeated write is idempotent
only when the canonical bytes match exactly; a second projection for the same
candidate/node with changed identity, reservation, fence, route key, role, or
local assignment is rejected. Recovery retrieves the exact node projection and
never substitutes an equivalent-looking manifest from another physical node.

`COMMITTED` additionally requires the durable projection set to be complete:
every candidate reservation requirement must have exactly one stored
projection whose candidate binding and activation fence match the recorded
`ACTIVATE` decision. A generated in-memory projection, a local process that
survived a restart, or a reservation commit without its matching durable
projection is insufficient.

`launch_plan` is a controller-selected, canonical part of the local
projection. It binds the process-local port leases and executor concurrency
configuration to the same admitted VM identity as the placement. The embedded
machine and consistency configuration must exactly match the candidate manifest;
the embedded total memory must exactly match the candidate's admitted memory
placement total. The local executor service/control ports are loopback-only
implementation endpoints, never cluster-membership or gateway endpoints.

The two currently bound UDP listener ports are materialized as the reservation's
exclusive leases before activation: the node-runtime data listener uses its
wildcard binding scope, while the local-executor service listener uses its
loopback binding scope. A launch-plan control port is not an exclusive lease
unless the corresponding runtime implementation actually binds it. Lease
generation is owner-epoch evidence and does not change resource identity.

`wavevm_node_runtime` accepts only the runtime manifest path and expected node
instance ID. It derives any remaining adapter arguments for the current
master-role and executor-role implementations internally from the accepted
manifest and its dispatch projection. A launcher must not supply independent
RAM, worker count, port, VM ID, static topology, or role-specific argument
groups after admission.

On each physical node, the authenticated local control receiver atomically
publishes the accepted activated projection to the runtime-manifest path and
fsyncs both file and parent directory before returning success. It derives and
atomically publishes a `RuntimeDispatchProjection` at
`<runtime-manifest-path>.dispatch` from that activated manifest, the canonical
node records, and the exact route snapshot. The route snapshot and dispatch
artifact must be present before the final runtime-manifest publication makes a
launch observable. The node runtime loads only that complete manifest, its
matching route snapshot, and its bound dispatch projection; it does not inspect
the coordinator's journal or reconstruct placement or routes from environment
variables. Transport delivery remains a
`PREPARE_MANIFEST`/`ACTIVATE_MANIFEST` responsibility, while this local file
operation is only its crash-safe handoff into the runtime process.

### 3.4 Immutability and Change Classes

The candidate manifest is immutable once distributed for prepare. The admitted
manifest is the same candidate bound to one activation record. The following
changes are not V1 in-place updates and require a stop followed by a new
incarnation unless a later specification defines an acknowledged
reconfiguration protocol:

- vCPU count, CPU placement, or execution backend.
- Memory size, memory placement, directory ownership, or consistency policy.
- QEMU host, guest topology, storage/device authority, or local namespace.
- Required kernel acceleration or fault-engine selection.

The following may evolve without changing the resource plan when their own
specifications' prepare/commit rules succeed:

- A newer route generation that preserves the same VM namespace and endpoint
  semantics.
- Health observations and bounded recovery evidence.
- Diagnostics, logs, and opaque process instance IDs.

## 4. Admission Transaction and VM Lifecycle

One create request owns exactly one `admission_tx_id`. The normal transaction
is deliberately more precise than a generic "prepare/start/commit" sequence:

```text
REQUESTED -> VALIDATING -> IDENTITY_ALLOCATED -> PLANNED
  -> ROUTE_SCOPE_PREPARED -> RESERVATIONS_PREPARED
  -> PARTICIPANTS_PREPARED -> ACTIVATION_DECIDED -> COMMITTED
  -> STARTING -> RUNNING
```

Before `ACTIVATION_DECIDED`, any non-success outcome follows
`ABORTING -> ABORTED`. After that durable decision, recovery must either finish
the activation or run compensating teardown; it must not guess from a timeout
that a committed reservation is safe to reclaim.

| State | Meaning | Allowed next state |
| --- | --- | --- |
| `ABSENT` | No lifecycle or namespace-allocation record exists. | `REQUESTED` |
| `REQUESTED` | Idempotent request is recorded. | `VALIDATING`, `ABORTING` |
| `VALIDATING` | Request and policy validation is in progress. | `IDENTITY_ALLOCATED`, `ABORTING` |
| `IDENTITY_ALLOCATED` | Fresh VM namespace/incarnation and transaction ID are durable but not runnable. | `PLANNED`, `ABORTING` |
| `PLANNED` | Complete deterministic placement and eligibility fence exist. | `ROUTE_SCOPE_PREPARED`, `ABORTING` |
| `ROUTE_SCOPE_PREPARED` | Candidate VM route scope/snapshot and its required ACK set are prepared, never normal-traffic active. | `RESERVATIONS_PREPARED`, `ABORTING` |
| `RESERVATIONS_PREPARED` | Every required resource/exclusive-name lease is held with expiry; no guest traffic is allowed. | `PARTICIPANTS_PREPARED`, `ABORTING` |
| `PARTICIPANTS_PREPARED` | Every required node/QEMU/executor/kernel participant prepared the same candidate manifest and fence. | `ACTIVATION_DECIDED`, `ABORTING` |
| `ACTIVATION_DECIDED` | One durable activation fence exists. Participants must query/replay this decision instead of allowing prepared leases to expire. | `COMMITTED`, `STOPPING` |
| `COMMITTED` | Required participants promoted manifest and reservations to committed state; components may start but guest traffic is still gated. | `STARTING`, `STOPPING` |
| `STARTING` | Components are starting under the committed manifest. | `RUNNING`, `STOPPING`, `FAILED` |
| `RUNNING` | Guest execution is admitted. | `PAUSING`, `STOPPING`, `DEGRADED`, `FAILED` |
| `PAUSING` | New vCPU handoffs are blocked while current work reaches a defined boundary. | `PAUSED`, `STOPPING`, `FAILED` |
| `PAUSED` | Guest execution is quiesced but identity and reservations remain held. | `RUNNING`, `STOPPING`, `FAILED` |
| `DEGRADED` | A required component/path failed; V1 must pause or fail rather than silently rebind it. | `PAUSING`, `STOPPING`, `FAILED` |
| `STOPPING` | Quiesce, flush, and compensating teardown are in progress. | `RETIRING`, `FAILED` |
| `RETIRING` | Route scope, subscriber state, completion caches, local names, contexts, and reservations are being retired. | `STOPPED`, `FAILED` |
| `STOPPED` | Retirement acknowledgements and resource release are recorded; namespace is quarantined by the allocator. | `ABSENT` only after safe namespace reuse |
| `ABORTING` | A pre-activation candidate is being removed. | `ABORTED`, `FAILED` |
| `ABORTED` | Candidate resources and route scope were released without guest traffic. | `ABSENT` after namespace quarantine |
| `FAILED` | A committed VM could not continue safely. | `STOPPING`, `RETIRING`, `STOPPED` |

Only the lifecycle coordinator changes the authoritative state. Node runtimes
publish idempotent observations such as `LOCAL_PREPARED`, `ROUTE_PREPARED`,
`QEMU_READY`, `EXECUTOR_READY`, `ACTIVATED`, `QUIESCED`, and `LOCAL_STOPPED`;
they do not promote the VM to `RUNNING` independently.

The durable admission transaction stores the candidate's complete
`prepared_route_snapshot_key`, including topology revision, route generation,
and snapshot digest. A route scope alone is never a lifecycle authority:
multiple immutable generations can legitimately share one scope. The
coordinator therefore requires the exact persisted route transaction to be
`PREPARING` for `PLANNED -> ROUTE_SCOPE_PREPARED`, `ACTIVATED` for
`ACTIVATION_DECIDED -> COMMITTED`, `RETIRING` for `STOPPING -> RETIRING`,
`RETIRED` for `RETIRING -> STOPPED`, and `ABORTED` for
`ABORTING -> ABORTED`. Recording either activation decision also requires
that exact route transaction to remain `PREPARING`.

## 5. Admission, Activation, and Recovery

### 5.1 Admission Eligibility Fence

Every plan contains an immutable eligibility fence:

```text
AdmissionEligibilityFence {
    admission_tx_id;
    membership_revision;
    topology_revision;
    admission_eligibility_revision;
    inventory_revision;
    capability_profile_generation;
    selected_member_records[];    // role, physical ID, node/gateway instance,
                                  // ACTIVE/healthy eligibility, capability digest
    required_route_scope_key;
    required_ack_set_digest;
    fence_digest;
}
```

`PREPARE_ROUTE_SCOPE`, `PREPARE_RESERVATION`, `PREPARE_MANIFEST`, and the
ordered activation pair `COMMIT_RESERVATION` plus `ACTIVATE_MANIFEST` validate
the same fence. Cordon, health exclusion, gateway drain, required
capability/profile change, node/gateway instance change, or topology change
invalidates every transaction that has not reached `ACTIVATION_DECIDED` and
depends on it. The coordinator aborts/replans those transactions.

An `ACTIVATION_DECIDED` transaction is a post-decision dependency even before
every participant has acknowledged local `COMMITTED` state. Membership drain,
host removal, and failure handling must either wait for it to finish or drive
the documented compensating teardown before removing one of its selected
members. Only after all required promotion ACKs is the VM lifecycle state
`COMMITTED`. Existing `COMMITTED` allocations are not silently replanned; they
follow their own drain/degraded policy.

### 5.2 Create and Activate Sequence

1. Deduplicate `request_id`. A duplicate canonical request returns the
   recorded transaction/result; different semantic fields under the same ID are
   rejected.
2. Validate user policy, then allocate `vm_id`, a fresh `vm_incarnation`, and
   `admission_tx_id` before any reservation or manifest digest is emitted.
3. Capture a membership/topology/inventory/capability snapshot, derive the
   eligibility fence, and calculate a complete deterministic placement plan.
4. Create the VM-incarnation route scope from the placement plan, compile the
   candidate route snapshot,
   persist its `RequiredAckSet`, and prepare it on exactly that survivor set.
   It is not normal-traffic active yet.
5. Construct the immutable candidate manifest and its per-node projections,
   binding the prepared route-snapshot key/digest.
6. Send `PREPARE_RESERVATION` to every selected resource/host/exclusive-name
   owner. Each validates the eligibility fence and stores an expiring
   `PREPARED` reservation keyed by VM identity and transaction ID.
7. Send `PREPARE_MANIFEST` to every required node runtime, QEMU host, executor,
   sidecar/gateway, and optional kernel context. Each validates the candidate
   digest, reservation, capability profile, route snapshot, and fence, then
   prepares only local state without accepting guest traffic.
8. Revalidate the eligibility fence and all recorded prepare acknowledgements.
   Any change before the next step aborts/replans the candidate.
9. Persist one `ActivationRecord(decision=ACTIVATE)` with a new
   `activation_fence` before sending `COMMIT_RESERVATION` or
   `ACTIVATE_MANIFEST` to any participant. This is the single admission
   linearization point.
10. Send idempotent `COMMIT_RESERVATION`, then `ACTIVATE_MANIFEST`, to every
    required participant. Together these are the generic activation action. A
    participant promotes its reservation/manifest only when the transaction,
    digest, fence, and required route snapshot all match its prepared record.
11. Persist every activated per-node runtime-manifest projection, then wait for
    every required activation ACK. Record `COMMITTED` only after the durable
    projection set is complete. Components may start under the admitted
    manifest but must keep guest traffic gated.
12. Start QEMU, node runtimes, and executors. Enter `RUNNING` only when required
    local endpoints and the admitted route/capability checks are ready.

No guest vCPU may run before all required participant readiness checks for its
admitted execution and memory paths have completed. The distributed start
oracle additionally requires observable remote vCPU and remote memory work,
not merely SSH listener creation or process survival.

### 5.3 Abort, Crash Recovery, and Compensating Teardown

Before `ACTIVATION_DECIDED`, a rejection, expiry, or fence invalidation causes
the coordinator to persist `ABORT`, send idempotent abort/teardown to prepared
participants, send `ROUTE_ABORT` for the prepared route scope, and release all prepared
reservations. Prepared records may expire only after they confirm that no
activation fence was observed.

After `ACTIVATION_DECIDED`, coordinator restart follows this query rule:

1. Read the durable transaction and activation record.
2. Query every participant by `admission_tx_id`, candidate digest, and
   activation fence; participants replay their recorded prepare/activate result.
3. If the durable record is `ACTIVATE`, replay missing activation/start actions
   or begin explicit compensating teardown. Do not let a participant reclaim a
   reservation merely because the coordinator was unavailable.
4. If no activation record exists, the transaction is abortable after prepared
   lease expiry and all prepared-route/reservation records are removed.

V1 has no automatic coordinator failover, but coordinator restart must recover
the same durable transaction record. A failure after activation but before any
guest traffic may end in `ABORTED` only after every participant confirms
teardown; a failure after `RUNNING` follows `FAILED -> STOPPING -> RETIRING`.
An aborted incarnation still follows the allocator's quarantine rule and is
never reused for a later retry.

## 6. Pause, Stop, Failure, and Recovery

### 6.1 Pause and Stop

For a normal stop the coordinator:

1. Moves the VM to `PAUSING` or `STOPPING`, blocks new vCPU handoffs and new
   device requests at QEMU authority, and tells node runtimes to reject new
   external work for this incarnation.
2. Waits for in-flight vCPU, memory, and storage operations to reach their
   documented completion, abort, or uncertain-result states. It does not
   discard an outstanding operation merely because a wall-clock deadline fired.
3. Performs required memory fences and storage flushes, then stops QEMU,
   executors, sidecar bindings, and optional kernel contexts in dependency
   order.
4. Deletes local names only after their owner has stopped and detaches every
   manifest-bound file descriptor/mapping.
5. Enters `RETIRING`, removes every directory subscriber for the incarnation,
   retires the VM route scope only after its active-operation references and
   query/retry horizon finish, and collects every required route-retirement ACK.
6. Releases reservations only after route, local-name, context, completion-cache,
   and subscriber teardown records are complete. It then records `STOPPED` and
   hands VM-ID reuse to the namespace allocator in `identity-routing.md`.

Stopping VM A never removes VM B's route scope, predecessor generation,
subscriber records, local names, or reservations, even when both are served by
the same gateway or physical node.

### 6.2 Failure and Restart

A failure after `COMMITTED` is not an aborted launch. The coordinator records
the VM as `DEGRADED`, `PAUSED`, or `FAILED` according to the affected
subsystem's contract and preserves the existing manifest/incarnation while it
collects recovery evidence.

V1 distinguishes failures deliberately:

| Event | V1 outcome |
| --- | --- |
| Noncritical local child restart with unchanged registered node instance | It may restart only against the exact manifest and local role. The new `local_runtime_instance_id` must re-register before serving traffic. |
| Required executor or QEMU process loses state | Pause/fail the VM unless that executor's specification later proves an explicit state-safe local recovery. V1 does not infer safety from process restart. |
| Registered node agent or physical host replacement | New `node_instance_id`; required existing VM enters `PAUSED` or `FAILED`. No automatic rebind occurs. |
| Gateway replacement with a prepared alternate route | Continue only through the membership/route transaction; it does not change the resource member identity captured by the manifest. |

`vm_incarnation` changes only when the control plane creates a new VM lifetime.
A node, node-agent, QEMU, executor, sidecar, or gateway restart creates a new
node/gateway/local-runtime process identity as applicable; it never creates a
new VM incarnation. Restart must not silently switch backend, fault engine,
storage authority, host node, placement, or expected member instance.

Any future restart-in-place for a required member needs a named
`RECOVERY_REBIND` transaction with old/new instance identities, reservation
ownership, capability validation, exact manifest/route references, state
recovery proof for memory/vCPU/storage, and an old-process fencing rule. A
heartbeat or a successful listener bind is not a rebind protocol.

## 7. Concurrency, Idempotency, and Errors

- Lifecycle serialization is per VM incarnation. Unrelated VM admissions and
  local participant preparations may proceed concurrently.
- The coordinator does not hold a global membership, placement, or VM lock
  while making network RPCs or waiting for a process to exit.
- A lifecycle operation carries one operation ID. Participants retain bounded
  completion records long enough for the coordinator's retry/query horizon.
- Every prepare/activate/abort query identifies `admission_tx_id`, candidate
  manifest digest, eligibility-fence digest, and activation fence when one
  exists. A duplicate returns the previously recorded state, never a fresh
  local interpretation.
- Reservation acquisition order is owned by the admission specification;
  manifest code must use its atomic reservation API rather than locking nodes
  ad hoc.
- A stale manifest generation, digest mismatch, wrong node instance, expired
  prepared lease, stale eligibility fence, namespace collision, or capability
  mismatch is a typed rejection.
  It must never be repaired by accepting a nearby node, raw route ID, or
  guessed local path.

Required lifecycle error classes include:

```text
INVALID_REQUEST, UNSUPPORTED_CAPABILITY, INSUFFICIENT_CAPACITY,
PLACEMENT_CONSTRAINT, MEMBER_NOT_ACTIVE, TOPOLOGY_NOT_READY,
ROUTE_GENERATION_UNAVAILABLE, RESERVATION_CONFLICT, NAME_CONFLICT,
MANIFEST_MISMATCH, STALE_INSTANCE, ELIGIBILITY_FENCE_STALE,
ACTIVATION_FENCE_UNKNOWN, PREPARE_REJECTED, START_FAILED, QUIESCE_TIMEOUT,
UNCERTAIN_OPERATION, RESULT_EXPIRED, and TEARDOWN_INCOMPLETE.
```

Timeout is a control-plane observation, not proof that a remote side effect did
not occur. Retrying a prepare, commit, or stop sends the same operation ID and
queries the recorded result before creating a new action.

## 8. Current Code Mapping and Known Deviations

| Current file or mechanism | Current behavior | Required migration direction |
| --- | --- | --- |
| `ctl_tool/main.c` and `common_include/wavevm_resources.[ch]` | Build static resource and route inputs for test deployments. | Parse/validate a request, invoke admission, and emit canonical manifests rather than being the only runtime truth. |
| `artifacts/*/run.sh` and CI scripts | Encode node IDs, ports, mode, QEMU arguments, and launch order. | Generate a test manifest and derived scripts; retain scripts as fixtures rather than policy authority. |
| `master_core/main_wrapper.c` / `user_backend.c` | Consume environment/configuration and create per-process runtime state. | In an admitted launch, consume only the validated per-node manifest, matching route snapshot, and derived dispatch projection before serving local QEMU or fabric traffic. |
| `slave_daemon/slave_hybrid.c` | Starts workers from local flags and socket paths. | Register only manifest-assigned local executor roles and return lifecycle-ready state. |
| `wavevm-qemu/accel/wavevm/` | Reads local WaveVM configuration and connects to local services. | Bind every connection, SHM registration, and accelerator operation to manifest identity/digest. |
| `master_core/kernel_backend.c` | Receives global/module-style configuration through legacy IOCTLs. | Attach only to a prepared per-VM kernel context from `kernel-accelerator.md`. |

## 9. Compatibility and Migration

1. Inventory every environment variable, route file, port, SHM name, and
   launch-script field consumed by QEMU, node runtimes, executors, sidecars,
   gateways, and the kernel module.
2. Use the canonical manifest parser and digest validator in user space. No
   production path renders legacy configuration from it.
3. Make all local names derived from the manifest namespace before accepting a
   second VM on one physical node.
4. Add candidate route-scope, prepared reservation/participant, activation
   fence, commit, abort, and query replies around existing launch order without
   changing memory or vCPU packet semantics first.
5. Gate QEMU/executor acceptance on manifest validation and expose structured
   lifecycle status to the control tool.
6. Remove direct user-authored per-VM `NODE`/`ROUTE` injection. Generated
   manifests and route snapshots are the only production inputs, and fixtures
   must be regenerated from those records.

## 10. Acceptance Tests

The first eight tests below and the final guest-readiness test form the
minimum usable lifecycle gate. Coordinator crash matrices, pre-activation
races, and independent host/process replacement are extended hardening; they
remain required for an operationally hardened deployment but do not block the
first correct distributed VM.

- The same canonical request, member snapshot, and capability set produce the
  same manifest digest and placement plan.
- A two-node flat and a multi-hop fractal fixture start from generated
  manifests with no hidden per-VM route or port input.
- A duplicate create request returns the original result and cannot allocate a
  second VM or reservation.
- One participant rejecting prepare leaves no active QEMU, executor, route
  binding, kernel context, port, SHM file, or resource reservation.
- A process with the wrong manifest digest, incarnation, local role, or node
  instance is rejected before it serves traffic.
- Stop drains or reports every outstanding memory, vCPU, and storage operation
  before releasing the VM namespace and local names.
- Two VMs on one eligible physical node have disjoint local names, reservations,
  route identities, logs, and runtime state.
- A route-generation replacement for an active gateway path does not mutate
  the VM's placement or manifest digest.
- **Extended:** Crash/restart the coordinator after every reservation, participant prepare,
  activation, commit, abort, and start message. The result is exactly one
  running/committed VM with all reservations held, or full compensating teardown
  with no leaked route scope, port, SHM name, context, or capacity.
- **Extended:** Race every pre-activation stage with cordon, gateway drain, health exclusion,
  capability change, and node/gateway instance replacement. A stale eligibility
  fence cannot reach `RUNNING`.
- **Extended:** Restart a noncritical local child, required executor, node agent, and physical
  host independently. V1 permits only the documented local-child re-registration;
  required member identity changes visibly pause/fail rather than rebind.
- **Minimum usable:** VM A route-scope retirement while VM B shares a gateway leaves VM B's current
  and draining routes, local names, reservations, and subscriber state intact.
- **Minimum usable:** Success means a guest reaches its declared readiness condition, plus
  instrumentation proves the admitted remote vCPU and remote memory paths were
  exercised; it does not mean only that processes remained alive.

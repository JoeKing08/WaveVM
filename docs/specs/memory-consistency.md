# WaveVM Memory Consistency Specification

Status: normative implementation specification.

RM-3.1 gate (2026-10-19): accepted — document already defines goal/non-goals,
semantic authority, structures/ABI, state/sequences, concurrency/backpressure,
failure/recovery, compatibility/migration, and acceptance tests per roadmap §3.1.

Scope: one VM incarnation's guest RAM across its QEMU frontend, local node
runtime, local execution runtime, directory nodes, sidecar/gateway fabric, and
optional kernel accelerator. This document defines the semantic contract shared
by KVM and TCG. It does not define block-device durability, vCPU register
handoff, resource placement admission, or host fault-engine selection. Those
boundaries belong to `storage-device-authority.md`, `vcpu-handoff.md`,
`resource-placement-admission.md`, and `capability-fault-engines.md`.

Terminology: `master` and `slave` below name current implementation roles. The
architecture baseline calls them the node runtime's semantic-coordinator role
and local-execution role respectively; they are not required to remain separate
processes. This specification's authority and ordering rules apply regardless
of that deployment choice.

This specification is normative for new work. It records current behavior where
useful, but current behavior is not automatically conforming.

## 1. Goal and Non-Goals

The goal is to make every successful guest-memory read and write explainable by
one VM-scoped directory authority and one monotonically advancing per-page
version. A guest must not observe a successful remote handoff against memory
whose required writes were silently dropped, reordered, or attributed to a
different VM.

This is a directory plus version plus subscriber/copyset protocol. It is not a
claim to implement full hardware MESI, cache-line coherence, transparent live
migration, or durable storage ordering.

V1 unit of coherence is one 4 KiB guest physical page:

```text
page_key = (vm_id, incarnation, gpa aligned to 4096)
```

`vm_id` alone is insufficient after VM deletion and reuse. Until the wire ABI
carries an incarnation, V1 must reject reuse of a `vm_id` while any old runtime
can still send packets. The future `wire-ipc-abi.md` defines the encoding.

## 2. Authority and Ownership

| State or decision | Authoritative owner | Allowed caches |
| --- | --- | --- |
| VM identity, incarnation, memory chunk placement | User-space admitted launch manifest | QEMU, node runtime, executor, gateway, and kernel may cache a versioned snapshot. |
| Directory node for a page | Manifest placement plus directory function | None may infer it from a local test topology. |
| Authoritative page bytes and version | The page's current directory runtime | QEMU RAM, executor RAM, and kernel page metadata are copies only. |
| Subscriber/copyset | Directory runtime | Per-subscriber lifecycle records; an incomplete or stale copyset must not grant write authority. |
| Local QEMU page bytes and local page version | The local QEMU runtime cache | Node-runtime SHM may mirror it but cannot override QEMU's registered RAMBlocks. |
| Dirty-page capture and page invalidation mechanics | KVM, TCG, or optional kernel accelerator | These mechanics do not choose versions, owners, or placement. |

Production cross-node traffic is always:

```text
QEMU or local executor -> local node runtime -> local sidecar -> gateway fabric
                       -> remote sidecar -> remote node runtime
                       -> remote directory or local executor
```

No production path sends directly from one remote executor to another remote
executor. A node runtime may use loopback IPC or an in-process interface to its
local executor.

## 3. Data Model

### 3.1 Version

Each directory page has:

```text
version = (epoch << 32) | counter
```

`counter` advances by exactly one for each accepted page mutation within an
epoch. A page initially materialized by a directory has version
`(current_epoch, 1)`. Version zero means "no valid local copy" and is never a
committable base version.

A version comparison is valid only for the same VM incarnation. A receiver
accepts a normal incremental update only when it is the immediate successor of
its current version. A full authoritative snapshot may replace any older local
version, but only when it came from the current directory.

### 3.2 Directory Page Record

The semantic record is:

```text
directory_page {
    page_key;
    version;
    bytes[4096];
    subscribers[];
    manifest_generation;
}
```

Each entry is:

```text
SubscriberRecord {
    page_key;
    subscription_id;
    subscriber_physical_node_id;
    subscriber_node_instance_id;
    subscriber_runtime_instance_id;
    route_scope_key;
    observed_version;
    delivery_requirement;         // HINT or FENCE_REQUIRED
    state;                        // ACTIVE, STALE, REMOVING, REMOVED
    last_validated_at;
    lease_or_observed_epoch;
}
```

`route_scope_key` is stable subscription identity, not a permanently pinned
forwarding generation. The directory resolves the current accepted snapshot for
that scope immediately before each send and pins it for the send/retry attempt.
`subscribers` is an invalidation/update target set, not an owner set. It may
over-approximate only while each record remains `ACTIVE` and identity-valid. Its
absence must cause an extra read or full resynchronization rather than authorize
a client write. A new node instance or rejoined runtime never inherits an old
subscription; it must request an authoritative full page again.

### 3.3 Client Page States

| State | Meaning | Allowed transition |
| --- | --- | --- |
| `ABSENT` | No valid local bytes/version. | `MEM_READ` or authoritative full push. |
| `CLEAN(v)` | Local bytes match directory version `v`. | Read locally; begin local write capture. |
| `DIRTY(v, journal)` | A local write has been captured against base version `v`. | Submit a commit; no remote vCPU handoff that depends on it until its required fence succeeds. |
| `SUBMITTING(v, req_id)` | A commit is in flight. | Retry idempotently or resolve ACK/error. |
| `RESYNC` | Local bytes are invalid after a gap, rejection, or stale manifest. | Pull authoritative full page; become `CLEAN(new_v)`. |

A client may batch multiple independent dirty pages. It may not coalesce
multiple writes to the same page across a handoff boundary without preserving
their base-version order.

## 4. Canonical Operations

### 4.1 Read / Fault Resolution

1. A local QEMU or executor fault asks its local node runtime for page `gpa`.
2. If the local node is the directory, it copies the current directory bytes
   and version under the page lock.
3. Otherwise the local node runtime sends `MSG_MEM_READ` to the manifest-selected
   directory with a nonzero request ID. Its typed V1 payload contains the
   4-KiB-aligned GPA and the complete reply leaf RouteKey
   `{destination_kind, destination_scope, destination_vnode}`.
4. The directory resolves that reply RouteKey from its admitted immutable route
   snapshot and returns `MSG_MEM_ACK`. A successful typed V1 ACK contains
   `{gpa, version, status=SUCCESS, directory_physical_node_id,
   directory_node_instance_id, data[4096]}`; a terminal status contains no
   page data. The reply preserves the request operation identity and changes
   only forwarding metadata and outer route destination.
5. The requester verifies VM incarnation, complete operation key, GPA,
   directory identity, status, payload size, and checksum before installing
   the page as `CLEAN(version)`.
6. The directory records the requester as an `ACTIVE` subscriber after
   producing the reply snapshot, with current node/runtime identity, route
   snapshot key, observed version, and a `HINT` delivery requirement unless a
   documented fence explicitly requests `FENCE_REQUIRED`.

The request ID identifies one VM-scoped operation. A retried read uses the same
ID. Duplicate replies are harmless after the first matching result.

### 4.2 Normal Dirty Commit

The canonical commit payload is `wvm_diff_log`:

```text
gpa
base_version
offset
size
data
```

The current field named `version` is the `base_version` on submission. The
directory accepts a normal diff only when all conditions hold:

1. The message belongs to the current VM incarnation and manifest generation.
2. The sender epoch equals the directory's accepted epoch for this operation.
3. The target is the current directory for `gpa`.
4. `0 < size <= 4096` and `offset + size <= 4096`.
5. `base_version == directory_page.version`.
6. The request ID has not already completed with a different payload.

On acceptance the directory, under the page lock:

1. Applies the bytes to its page copy.
2. Advances version to `next(base_version)`.
3. Captures the resulting version and any push payloads.
4. Records/refreshes the writer as an identity-valid subscriber.
5. Records an idempotent completion result for the request ID.

It then releases the page lock, dispatches updates to subscribers, and sends a
commit ACK. Network send, QEMU IPC, allocation that may block, and waiting for
another page must not occur while holding the page lock.

The directory retains the idempotent completion record through the maximum
route predecessor completion-query/retry horizon. A rerouted duplicate uses the
same semantic operation key from `wire-ipc-abi.md`; after retention expires it
returns `RESULT_EXPIRED` and never reapplies the diff.

`BACKPRESSURE` means the directory declined before applying bytes. It is not a
completed mutation result: the directory retains the operation ID and semantic
payload digest to reject conflicting reuse, but an identical retry may perform
the apply when capacity returns. Terminal results and successful commits are
the only outcomes replayed from the completion cache.

The canonical commit ACK must contain:

```text
commit_ack {
    gpa;
    result_version;
    status;
    directory_physical_node_id;
    directory_node_instance_id;
}
```

`status=success` means the directory has applied the commit and recorded its
idempotent result. With `WVM_FLAG_NEED_ACK`, it additionally means all local
delivery barriers required by the declared handoff policy have succeeded.

### 4.3 Full Page Writes and Recovery

An authoritative `MSG_PAGE_PUSH_FULL` or `MSG_FORCE_SYNC` is directory to
client recovery traffic. It may overwrite an older local cache because it
carries directory-owned bytes and a directory version.

A client-originated full-page commit is not a general recovery shortcut in V1.
It must still carry a base version and satisfy the normal commit precondition.
In particular, a client must not overwrite a newer directory page merely
because it has a full 4 KiB snapshot.

This deliberately removes the ambiguity in the current "full-page catchup"
behavior. A lost or reordered diff is recovered by `RESYNC`, then a new commit
against the returned version, not by accepting an unproven client snapshot.

### 4.4 Zero Page Commit

A zero page is a normal full-page mutation with explicit zero semantics. It
uses the normal base-version precondition and advances the version once.
`WVM_FLAG_ZERO` changes payload representation only; it must not bypass version
checking or commit acknowledgment.

### 4.5 Subscriber Updates

After an accepted mutation, the directory sends either:

- `MSG_PAGE_PUSH_DIFF` for an ordered bounded diff, or
- `MSG_PAGE_PUSH_FULL` for a full page, zero page, recovery, or a receiver
  that cannot safely apply a diff.

Clients apply a diff only when its version is the next version. Stale and
duplicate updates are idempotent no-ops. A version gap puts the page into
`RESYNC`; the client requests a directory full page before allowing dependent
guest execution to continue.

Subscriber state transitions are:

```text
ACTIVE
  -> STALE       on node/runtime-instance change, membership failure, route-scope
                  retirement, lease/observed-epoch expiry, or failed HINT delivery
  -> REMOVING    on VM STOPPING, explicit unsubscribe, or directory teardown
  -> REMOVED     after no required delivery/query reference remains
```

`HINT` pushes are cache maintenance only. A failed or unreachable HINT marks
the record `STALE`, stops further push retry, and requires the receiver to
resync on a future read/fault. `FENCE_REQUIRED` is valid only when a named
memory/handoff policy includes that subscriber in its barrier. Its delivery ACK
carries the subscription/operation identity; failure prevents the owning fence
from succeeding and follows its bounded retry/query policy. It cannot become an
indefinite retry against a departed node.

A normal committed G to G+1 replacement does not make a healthy subscriber
`STALE`. `ROUTE_COMMIT` first publishes the successor as the current accepted
snapshot for its `VmRouteScopeKey`; future subscriber sends resolve that
successor. A delivery already holding a predecessor snapshot retains that
snapshot reference until its attempt completes, then retries with the same
subscription and semantic operation identity but refreshed forwarding metadata.
For `FENCE_REQUIRED`, the delivery ticket is keyed by subscription and semantic
operation identity, so an ACK after refresh completes the fence once rather
than creating a second requirement. The directory subscriber registry owns this
lookup and snapshot reference; page-lock code never performs a topology update.

On VM `RETIRING`, the lifecycle coordinator requests removal of every
subscriber record for the VM incarnation. On node/gateway failure or route
scope retirement, the membership/route controller marks matching records stale
before a new node can be admitted. Page-lock code captures records to update,
then performs network send/removal outside the page lock.

The current fixed-size reorder window is an optimization only. Collision,
overflow, or expiry must transition to `RESYNC`; it must not silently discard a
page update and leave the page marked valid.

### 4.6 Handoff Fence

Before a `VCPU_RUN` handoff, the local QEMU/node runtime must drain every dirty page
that the remote slice can observe. The required ordering is:

```text
capture dirty pages
  -> submit commits
  -> receive successful required commit ACKs
  -> deliver required local QEMU pushes
  -> send VCPU_RUN
```

This fence is per local QEMU connection and VM incarnation. It is not a global
cluster barrier. Independent pages may remain asynchronous until a handoff,
explicit strong-consistency policy, flush-like device operation, or shutdown
requires a fence.

`dirty-batch-size=1` means every captured dirty page enters the submit/fence
policy immediately. It does not claim a stronger model than the ACK and
handoff barriers actually supplied by this specification.

## 5. Message and IPC Requirements

| Operation | Required wire/local message | QoS | Idempotency requirement |
| --- | --- | --- | --- |
| Fault read | `MSG_MEM_READ` -> `MSG_MEM_ACK` with full payload | Request fast; response policy set by wire ABI | Same request ID returns same or newer authoritative snapshot. |
| Dirty commit | `MSG_COMMIT_DIFF` -> commit ACK | Control/commit priority | Same request ID is deduplicated at the directory. |
| Subscriber update | `MSG_PAGE_PUSH_DIFF` or `MSG_PAGE_PUSH_FULL` | Priority depends on handoff dependency | Applying same version twice is harmless. |
| Recovery | `MSG_FORCE_SYNC` or explicit full read response | High priority correction | Replacing an older local copy is harmless. |
| Handoff fence | Local IPC `COMMIT_DIFF_SYNC` plus explicit commit ACKs | High priority | Fence result is tied to a VM-scoped sequence, not `SYNC_MAGIC` alone. |

`SYNC_MAGIC` currently overloads `MSG_PING` and `MSG_MEM_ACK` as a fence marker.
It is a temporary compatibility mechanism, not the stable ABI. The wire/local
IPC specification must replace it with typed, VM-incarnation-scoped fence
records before multi-VM production support is claimed.

`MSG_MEM_WRITE` is currently used by some KVM dirty-page and emergency paths
but carries no base version. It is legacy compatibility traffic and cannot be
the canonical multi-writer commit mechanism. It must be converted to the
versioned commit contract or restricted to a documented single-writer,
directory-authorized acceleration path.

## 6. Concurrency and Backpressure

### 6.1 Page and Request Locking

- A directory page lock protects that page's bytes, version, and subscriber
  mutation.
- Lock order must be: manifest snapshot read, page lock, then local cache
  bookkeeping. No code may acquire a second page lock while holding the first.
- Route-map, gateway, QEMU-client, and queue locks are never acquired while a
  directory page lock is held.
- Request-completion state has its own lock or atomic protocol and is indexed
  by a full VM-scoped request ID. Slot reuse requires generation validation.

### 6.2 Normal-Path Parallelism

The normal path remains asynchronous and parallel:

- Per-page striped directory locks permit unrelated pages to progress.
- Dirty capture is decoupled from network transmission by bounded producer /
  consumer queues or per-connection journals.
- Gateway and node-runtime QoS queues preserve priority for control, ACK, and handoff
  traffic without globally serializing page data.
- Batched receive and grouped diff transmission remain allowed when they retain
  each page's base-version ordering.

Correctness changes must not replace this normal path with a global mutex,
single global worker, disabled queue, or unconditional synchronous send.

### 6.3 Bounded Backpressure

If a dirty queue is full, allocation fails, or a required fence cannot complete:

1. The page must not be silently dropped.
2. The producer may synchronously submit that one page or pause the dependent
   vCPU/handoff.
3. The fallback must be bounded by timeout and return an explicit error.
4. The result must leave the page either committed or `RESYNC`; it may not
   pretend that a lost page is clean.

The current emergency dirty-page direct-send behavior is an example of the
allowed *shape* of a fallback, but it remains nonconforming until it carries
the canonical versioned commit semantics.

## 7. Failure, Retry, and Recovery

| Condition | Required behavior |
| --- | --- |
| Lost read request/reply | Retry with the same request ID until bounded timeout; do not install a partial payload. |
| Lost commit ACK | Retry the same request ID; directory returns its recorded result without reapplying bytes. |
| Duplicate commit | Return the original result when payload identity matches; reject same ID with different payload. |
| Version mismatch | Directory rejects commit, sends or permits authoritative resync, client enters `RESYNC`. |
| Push gap/queue collision | Client invalidates page validity and performs full resync before dependent execution. |
| Stale epoch or manifest generation | Reject and resync/rejoin under the current manifest; do not reinterpret as a normal retry. |
| Directory unavailable | Fault/commit fails after bounded timeout; dependent guest execution does not continue using an unconfirmed page. |
| Local QEMU push barrier failure | Required commit/handoff reports failure; do not send dependent `VCPU_RUN`. |
| Node/process restart | A node/agent/runtime obtains a new node or local-runtime instance ID, never a new VM incarnation. Existing required VM state pauses/fails under lifecycle policy; old subscriber records become `STALE` and old packets/request IDs are rejected. |

Timeouts are liveness policy, not a reason to relax version checks. Retries
must be bounded and logged with a rate limit.

## 8. Current Code Mapping and Known Deviations

| Current location | Current role | Required direction |
| --- | --- | --- |
| `master_core/logic_core.c` | Directory table, page versions, subscribers, reads, commits, force-sync. | Keep semantic authority in user space; align its paths with this state machine. |
| `master_core/main_wrapper.c` | Local QEMU IPC, commit window, drain before CPU handoff. | Preserve per-connection fence; make commit result/version explicit. |
| `master_core/user_backend.c` | Request table, local executor forwarding, push delivery. | Namespace request records by VM incarnation and preserve full ACK payloads. |
| `wavevm-qemu/accel/wavevm/wavevm-user-mem.c` | TCG/KVM dirty capture, local version cache, reorder window, local fence. | Keep capture mechanics backend-specific; obey the shared commit/fence contract. |
| `slave_daemon/slave_hybrid.c` | KVM dirty harvesting and MPSC sender. | Preserve async MPSC normal path; convert versionless fallback writes. |
| `master_core/kernel_backend.c` | Optional kernel fault/dirty/queue acceleration and a second linked logic core. | Remove semantic authority and module-global VM state; retain only context-scoped acceleration. |

Known nonconforming or incomplete behavior to resolve through targeted patches:

1. Commit ACKs currently use a one-byte success result in some paths and do not
   always return the resulting page version.
2. The directory accepts a full-page version catchup exception that has no
   explicit writer lease or resync proof.
3. `MSG_MEM_WRITE` is versionless and is used by some dirty-page paths.
4. `SYNC_MAGIC` is not VM-incarnation-scoped and overloads unrelated message
   types.
5. The kernel-linked `logic_core` duplicates directory and route semantics.
6. Some current page-lock paths perform push/QEMU notification work before
   releasing the lock.
7. The current subscriber set has no specified expiry or removal policy.

These are migration items, not permission for a broad rewrite. Each fix must
preserve the normal concurrent data path described in Section 6.

## 9. Compatibility and Migration

1. Keep existing fields and message types readable during migration.
2. Add canonical commit ACK payload support before relying on multi-page TCG
   fences for correctness.
3. Make duplicate commit recognition VM-scoped before increasing retry rates.
4. Remove the full-page catchup exception only after recovery via full read or
   `FORCE_SYNC` is covered by regression tests.
5. Convert KVM dirty-page normal and emergency paths from `MSG_MEM_WRITE` to
   versioned commit semantics, or define a narrow directory-authorized fast
   path in `kernel-accelerator.md`.
6. Replace `SYNC_MAGIC` with a typed fence sequence in `wire-ipc-abi.md`.
7. Move kernel copies of page/route/identity state into explicit per-VM
   accelerator contexts as defined by `kernel-accelerator.md`.
8. Add SubscriberRecord identity/lease/removal and per-send route-scope
   resolution before treating subscriber delivery as a handoff-fence dependency
   or enabling VM-ID reuse.

No migration may use hardcoded nodes, test-only production switches, or a
permanent global serialization workaround.

## 10. Acceptance Tests

The specification is accepted for implementation only when automated tests
prove all of the following for both flat and fractal topology:

1. A remote page fault returns the correct 4 KiB page and matching version.
2. Duplicate and delayed read replies cannot replace a newer local page.
3. Two writes to the same page with the same base version yield one accepted
   commit and one explicit resync/rejection.
4. Duplicate commit retry produces one directory mutation and the same result
   version.
5. A dropped/reordered diff causes resync, never a valid stale page.
6. A full authoritative directory push repairs a page gap.
7. A remote vCPU handoff waits for all memory commits required by its local
   causal boundary.
8. Queue saturation does not drop a dirty page; it produces bounded
   backpressure or an explicit failed handoff.
9. Independent pages still make progress concurrently under load.
10. KVM and TCG pass the same semantic tests, with only capture/fault
    mechanics differing.
11. VM A's page, request ID, subscriber update, or force-sync packet cannot
    alter VM B.
12. Test success includes SSH/login plus evidence of remote memory use and
    remote vCPU execution; process survival or listening sockets are
    insufficient.
13. A failed/rejoined subscriber, VM stop, route-scope retirement, and node
   instance replacement leave bounded directory metadata. A rejoined receiver
   obtains a full authoritative page before dependent execution.
14. Replace one healthy gateway generation while a `FENCE_REQUIRED` subscriber
    receives a page update. The subscriber remains active, the delivery may
    refresh only forwarding metadata, and the fence completes exactly once.

Test logs and packet traces must be rate-limited and bounded. A test that fills
an unbounded `/tmp` directory is not an acceptable regression test.

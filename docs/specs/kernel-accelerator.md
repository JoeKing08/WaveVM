# WaveVM Kernel Accelerator Specification

Status: normative implementation specification.

The [Document Maintenance](../wavevm-refactor-roadmap.md#document-maintenance)
rules apply to this specification.

Scope: the optional `wavevm.ko` / `/dev/wavevm` accelerator, per-VM kernel
contexts, IOCTL and mmap boundary, context lifetime, cache publication,
concurrency, failure behavior, and migration from current global module state.
The user-space node runtime remains the semantic authority; memory, vCPU,
identity, manifest, and capability semantics are defined by their corresponding
specifications.

This specification is normative for new Mode A work. It defines an accelerator
for the canonical Mode B semantics, not a second distributed control plane.

## 1. Goal and Non-Goals

The goal is for an available kernel module to accelerate selected local
data-plane operations without changing VM identity, routing authority, page
version rules, vCPU handoff semantics, lifecycle ownership, or error meaning.

```text
candidate/admitted user-space manifest + capability profile
  -> explicit wvm_kernel_ctx create/attach
  -> manifest-derived cache/configuration prepare
  -> optional local acceleration
  -> typed completion through the same node-runtime contract
```

Mode A is therefore:

```text
Mode B canonical runtime + optional per-VM kernel acceleration
```

### 1.1 Release priority

Per-VM context isolation is a minimum usable system gate. A host may decline
Mode A when the module or kernel cannot provide it, but it must not advertise
multi-VM Mode A while state, request IDs, mappings, route caches, or teardown
remain singleton-owned.

The full accelerator specification also describes later hardening such as
complete fault-path migration and exhaustive worker-failure testing. Those
items improve the accelerator but do not make the no-module Mode B baseline a
second-class path.

### 1.2 Context Isolation Admission Gate

Multi-VM Mode A requires explicit context ownership on sleepable paths,
committer send ownership, TX/VMA/destroy reference safety, and full u32 VM
identity. The implementation must satisfy these requirements before raising
the advertised context limit:

- `IOCTL_WVM_QUERY_CAPS` must report the supported context ABI and capability
  bits. Until multi-context isolation is verified, it must advertise
  `WVM_KERNEL_CAP_CONTEXT_BIND` and `WVM_KERNEL_CAP_SINGLE_CONTEXT`, with
  `max_concurrent_contexts = 1`. BIND must enforce the advertised maximum
  with `-ENOSPC`, and admission must reject a second Mode A VM on that node.
- `IOCTL_WVM_BIND_CONTEXT` / `IOCTL_WVM_UNBIND_CONTEXT` must bind an open
  `/dev/wavevm` descriptor to the manifest identity (including
  `node_instance_id`), VM incarnation, manifest generation, capability profile,
  and activation fence.
- Manifest-gated node-runtime, QEMU frontend, and KVM executor descriptors
  for one VM must bind the same admitted context before using the accelerator.
- Each kernel context must own identity, epoch cache, RAM slots, private
  `address_space`/mapping, IRQ wait state, request ID pool/completion table,
  page metadata radix tree, `dir_table`, and `route_context`. Directory and
  route state are derived acceleration caches under user-space authority.
  Module-global VM identity and RX legacy-VM fallback are prohibited;
  directory/route accessors must fail closed without the correct context.
- VMA fault and write-protect callbacks must resolve context from the mapped
  file; async invalidation/dirty-commit work and TX slots must carry an
  explicit context reference. Identity encoding must preserve the full u32
  VM ID without truncation.
- Module-wide UDP sockets and TX rings may be shared plumbing only when
  reference lifetime and request namespace isolation are enforced.
  Dirty-commit queues and GPA shard locks must be per-context.
  `IOCTL_SET_VM_ID` must reject with `-EOPNOTSUPP`; BIND is the production
  context attachment boundary, and field-by-field injection cannot bypass it.

Same-GPA, multi-FD, asynchronous teardown, and failure tests must exercise
these invariants before multi-context capability is advertised. Stub
CREATE-to-RUNNING/READY evidence cannot satisfy the Minimum guest login/SSH
and remote-resource acceptance criteria.

Non-goals for V1:

- Requiring the module, root, or a custom kernel for a correct Mode B VM.
- Making a module-global socket, VM ID, route table, mapping, or request table
  authoritative for all VMs.
- Letting kernel code allocate VM identity, choose placement, admit members,
  create a route, or own a VM lifecycle transition.
- Direct kernel-to-arbitrary-remote-executor traffic that bypasses local and
  remote node runtimes plus the sidecar/gateway fabric.
- Creating a fresh semantic VM context for each `open()` of `/dev/wavevm`.
- Replacing normal asynchronous queues, batching, QoS, and bounded backpressure
  with global synchronous kernel calls just to pass a test.

## 2. Authority and Capability Boundary

| State or decision | Authoritative owner | Kernel role |
| --- | --- | --- |
| VM ID, incarnation, manifest digest/generation, activation fence, lifecycle | User-space control plane and admitted manifest | Validate and cache one accepted snapshot. |
| Route topology and next hops | Control-plane route snapshot | Cache/use one complete derived snapshot only. |
| Page directory, version, copyset, and commit result | User-space node runtime/directory | Accelerate local capture/invalidate/wakeup only. |
| vCPU ownership, handoff sequence, context schema | User-space node runtime/QEMU contract | Optionally accelerate local context transfer/run mechanics. |
| KVM object and TCG helper lifecycle | Local executor/QEMU | Do not create a second executor authority. |
| Kernel context handle and its references | Kernel module | Enforce isolation and lifetime for attached local callers. |

The capability report in `capability-fault-engines.md` is the only basis for
selecting Mode A. A loaded module is not automatically selectable. The report
must include the accelerator ABI version, supported context-schema versions,
per-VM context capability, feature bits, limits, and the current module/device
instance identity.

## 3. Per-VM Context Model

### 3.1 Context Identity

One `wvm_kernel_ctx` represents the kernel acceleration state for exactly one
`{vm_id, vm_incarnation, physical_node_id}`. It is created explicitly from a
prepared per-node runtime manifest and has an opaque kernel-issued context
handle plus an attach capability. The attach capability is not a raw `vm_id`
or a user-chosen integer.

```text
wvm_kernel_ctx {
    context_handle;
    attach_capability;
    refcount;
    state;

    vm_id;
    vm_incarnation;
    admission_tx_id;
    eligibility_fence_digest;
    activation_fence;
    physical_node_id;
    expected_node_instance_id;
    manifest_digest;
    manifest_generation;
    capability_profile_digest;
    route_snapshot_key;

    immutable_config_snapshot;
    ram_mapping_registry;
    page_or_dirty_acceleration_state;
    vcpu_acceleration_state;
    request_and_completion_state;
    local_sidecar_transport_binding;
    workqueues_and_pending_operations;
    attached_fd_and_role_records;
}
```

Every mmap, context-bound IOCTL, page/dirty callback, wait queue, and worker
item must resolve a live context first. Any request, route, page-metadata,
socket, or shared-queue path that cannot prove context isolation prevents
advertising multi-context capability under Section 1.2.

### 3.2 Context State Machine

| State | Meaning | Allowed next state |
| --- | --- | --- |
| `NEW` | Allocated but has no accepted manifest snapshot. | `PREPARING`, `DEAD` |
| `PREPARING` | Candidate manifest/capability/configuration is being validated. | `PREPARED`, `QUIESCING`, `DEAD` |
| `PREPARED` | Exact candidate snapshot and local resources are ready; no guest traffic yet and prepared state may expire without activation. | `ACTIVE`, `QUIESCING`, `DEAD` |
| `ACTIVE` | Matching activation fence promoted the candidate; manifest-bound acceleration may accept operations. | `QUIESCING`, `FAILED` |
| `QUIESCING` | New work is rejected; owned work is drained or given a typed failure. | `DETACHING`, `FAILED` |
| `DETACHING` | Mappings/FDs are being detached after no new work can enter. | `DEAD` |
| `FAILED` | Accelerator cannot safely continue. | `QUIESCING`, `DEAD` |
| `DEAD` | Context is unpublished and final references are released. | none |

Closing one file descriptor removes only that attachment and its reference. It
does not destroy the context while other authorized QEMU, node-runtime,
executor, or control-plane descriptors remain. The lifecycle coordinator
initiates `QUIESCING`/destroy after VM teardown, not whichever process closes
first.

### 3.3 Attachment and Permission Model

`CREATE_CTX` is available only to the local manifest/lifecycle authority or an
explicitly delegated local control endpoint. It verifies the prepared manifest,
expected node instance, eligibility-fence digest, accelerator capability profile,
prepared reservation lease, and node role assignment before returning a handle.

`ATTACH_CTX` requires all of:

- Opaque context handle and attach capability.
- Matching manifest digest/generation and VM incarnation.
- A role permitted by the per-node manifest, such as QEMU frontend, node
  runtime, or a designated local executor.
- Local credential/peer validation defined by the deployment. File-system mode
  bits alone are not sufficient when an unrelated local process could attach.

The exact credential transport may be a protected local control socket,
inherited sealed descriptor, or another explicit local mechanism. It must not
be a hardcoded shared token or a raw global `vm_id` write.

## 4. IOCTL and mmap ABI

The current numeric IOCTL definitions are not the production configuration ABI.
The context ABI uses typed envelopes from `wire-ipc-abi.md`; each
request includes context handle, manifest identity, operation ID, payload
length, flags, and typed result status.

### 4.1 Required ABI Groups

| Group | Operations | Required semantics |
| --- | --- | --- |
| Discovery | `GET_CAPS`, `GET_ABI_VERSION` | Read only; returns module/device instance and capability limits. |
| Context lifecycle | `CREATE_CTX`, `ATTACH_CTX`, `DETACH_CTX`, `QUIESCE_CTX`, `DESTROY_CTX` | Explicit state transitions and refcount rules. |
| Configuration | `PREPARE_MANIFEST`, `COMMIT_CONFIG`, `QUERY_CONFIG` | Accept complete manifest-derived snapshots; no independent truth injection. |
| RAM/mapping | `REGISTER_RAM`, `UNREGISTER_RAM`, `QUERY_MAPPING` | Register only manifest-authorized QEMU RAM ranges and ownership metadata. |
| Acceleration | `CAPTURE_DIRTY`, `FAST_INVALIDATE`, `REMOTE_RUN`, `WAIT_IRQ`, `FAST_LOCAL_FORWARD` | Typed accelerator operation tied to one context/request/fence. |
| Diagnostics | `QUERY_OPERATION`, `QUERY_STATS`, `FAULT_INJECT_TEST_ONLY` | Bounded observability; test injection is build/test gated and cannot alter production semantics. |

`PREPARE_MANIFEST` validates the complete candidate
identity/capability/configuration snapshot but does not use it for guest
traffic. `COMMIT_CONFIG` requires the lifecycle activation fence and atomically
publishes one immutable snapshot after user-space activation. A partial
series of `SET_VM_ID`, `SET_ROUTE`, `SET_GATEWAY`, `SET_MEM_LAYOUT`, or epoch
writes must not be a new production configuration path.

### 4.2 Legacy IOCTL Classification

| Current legacy IOCTL family | Migration role |
| --- | --- |
| `IOCTL_WVM_REMOTE_RUN` | Context-bound acceleration of a validated vCPU handoff; not an independent remote execution protocol. |
| `IOCTL_SET_MEM_LAYOUT` | Compatibility adapter for manifest-authorized RAM registration only. |
| `IOCTL_WAIT_IRQ` | Context-bound local interrupt wait/notification with typed timeout/error result. |
| VM ID, epoch, route, placement, gateway setters | Deprecated field injection. Replace with complete derived manifest/route snapshot prepare/commit. |
| `IOCTL_RPC_SYNC_ACK` | Remove or assign a typed owner before stable ABI exposure; an unhandled numeric command is not a semantic feature. |

No IOCTL may accept a raw route target for nonzero VM traffic and then infer
identity. All route targets retain VM/incarnation scope as defined by
`identity-routing.md`.

### 4.3 mmap Rules

An mmap is valid only for a context-attached, manifest-authorized RAM or
explicit accelerator buffer region. The mapping registry records:

```text
MappingRecord {
    context_handle;
    manifest_digest;
    gpa_range;
    qemu_ramblock_identity;
    host_mapping_identity;
    access_permissions;
    mapping_generation;
    attached_vma_reference;
}
```

The module rejects overlapping mappings that belong to a different VM context
or a stale manifest. VMA close decrements only the mapping/context reference.
Teardown first blocks new mappings and new operations, then drains references,
invalidates/unregisters ranges, and finally frees context memory. A stale user
mapping must never resolve through a newly created VM with the same raw ID.

## 5. Data-Plane Rules

### 5.1 Memory and Dirty Acceleration

The kernel may capture dirty ranges, invalidate a local cache/mapping, or wake
a local waiter only when the operation names a valid context, page/range,
operation ID, and required memory fence. It may not:

- Declare a memory commit successful before the user-space directory records
  the idempotent result required by `memory-consistency.md`.
- Install page bytes from another VM/context.
- Retain a page/route cache after its manifest, incarnation, or generation is
  invalidated.
- Convert a dirty-capture failure into an empty successful journal.

KVM Mode A retains the same prohibition on using host `PROT_NONE` as a guest
RAM trap. Kernel dirty capture is an acceleration provider, not permission to
change KVM's page-resync semantics.

### 5.2 vCPU and Interrupt Acceleration

`REMOTE_RUN` accepts only a node-runtime-validated handoff with a current
`{vm_incarnation, vcpu_index, handoff_sequence, operation_id}` and successful
memory fence. The kernel returns one typed completion or in-progress/result
query state; it cannot execute the same handoff twice after a lost reply.

`WAIT_IRQ` and wakeups are local acceleration primitives. QEMU remains the
guest interrupt/device authority, and the node runtime owns delivery identity,
watermarks, and cross-node transport. A kernel wakeup is not proof that a guest
IRQ has been injected or that a remote device operation completed.

### 5.3 Sidecar/Gateway Boundary

All production cross-node traffic still follows:

```text
local QEMU/executor -> local node runtime -> local sidecar -> gateway fabric
                    -> remote sidecar -> remote node runtime -> executor
```

An optional `FAST_PACKET_TX` or `FAST_LOCAL_FORWARD` accepts a complete,
already validated node-runtime envelope and may only deliver it through the
manifest-bound local sidecar transport binding. It cannot select a remote
executor, create a route, strip VM identity, bypass the remote node runtime, or
turn one kernel socket into global routing truth.

## 6. Concurrency, Locking, and Backpressure

The implementation must use context-scoped queues and references. A module-wide
worker is permitted only when every queued item holds a live context reference
and cannot mix request namespaces.

Required lock order when more than one is needed:

```text
context registry lock
  -> context lifecycle lock
  -> immutable configuration publication/read lock
  -> mapping registry lock
  -> per-vCPU / per-page / per-request lock
```

The registry lock is held only for lookup/publication. Network transmission,
QEMU callbacks, user-space waits, allocation that can block, and workqueue
flushes must occur after releasing locks that would block context teardown or
another VM's independent work.

- Context state is checked before and after acquiring a long-lived operation
  reference.
- Per-page and per-vCPU locks are never used as a module-global VM lock.
- Queues have documented bounds and QoS. Overload returns a typed backpressure
  result or pauses the affected operation at a safe boundary; it must not drop
  vCPU, dirty, IRQ, or memory completion work.
- Config/route snapshot replacement uses one complete immutable object per
  context. Readers use an old or new complete snapshot, never a field-by-field
  mixture.

## 7. Failure, Teardown, and Fallback

| Condition | Required behavior |
| --- | --- |
| Module absent/unavailable before admission | `PREFER` resolves to Mode B if valid; `REQUIRE_KERNEL_ACCEL` rejects before start. |
| Create/attach/configuration validation fails | Reject local lifecycle prepare; no partially configured global state remains. |
| Eligibility or activation fence mismatch | Reject prepared/active operation; no kernel context may promote itself from a listener or process lifetime. |
| Context worker fails or device disappears | Mark context `FAILED`, reject new acceleration, and report typed status to user-space lifecycle. |
| One attached process exits | Drop only its role/FD reference; retain context while other references/lifecycle require it. |
| Quiesce deadline expires | Return outstanding operation identities/status; do not free mappings or reuse context identity while work might reference it. |
| Context destroy | Require lifecycle teardown, no active mapping/operation references, and complete removal from registry before freeing. |
| Route/configuration generation mismatch | Reject operation and request user-space refresh; never use a nearby/global cached entry. |

Mode A failure after a VM begins running is not permission to continue with
undefined state. V1 pauses or fails the affected VM according to the memory and
vCPU contracts. A future hot fallback to Mode B requires a quiesced,
manifest-validated transition that proves no dirty, handoff, or interrupt state
is lost.

Capability discovery and admission must enforce the isolation gate in Section
1.2. Context lifecycle tests establish the accelerator boundary only; the
Minimum guest login/SSH and remote-resource criteria require separate
end-to-end evidence.

## 8. Implementation Touchpoints and Requirements

| File, symbol, or boundary | Required responsibility |
| --- | --- |
| `master_core/kernel_backend.c` | Keep page metadata, route caches, requests, sockets, and shared queues context-owned or explicitly context-tagged; enforce the isolation gate in Section 1.2. |
| `master_core/module-common.[ch]` | Keep only module-wide registries/workers that carry an explicit context reference. |
| `common_include/wavevm_ioctl.h` | Introduce versioned context lifecycle/configuration/operation envelopes while retaining adapters during migration. |
| Module `g_module_transport` (UDP socket + TX rings); per-context `diff_queue`/`dir_locks` | Shared transport slots and workers must carry explicit context references; keep dirty queues and GPA shard locks per-context. |
| `wavevm-qemu/accel/wavevm/` | Create/attach only through the local prepared manifest and validate context identity for each operation. |
| `master_core/logic_core.c` / node runtime | Remain semantic authority; kernel completion returns to this contract rather than inventing a parallel RPC path. |

## 9. Compatibility and Migration

1. Inventory every module-global variable, IOCTL, mmap path, workqueue item,
   wait queue, socket, request cache, and teardown path.
2. Add read-only capability discovery and reject unsupported multi-VM Mode A
   before changing data-plane behavior.
3. Implement explicit create/attach/detach context lifecycle while adapting
   legacy setters to a complete manifest-derived configuration object.
4. Move mappings, page/dirty metadata, vCPU state, route cache, request cache,
   and transport bindings into `wvm_kernel_ctx` one domain at a time.
5. Add context references to every asynchronous callback/work item, then make
   teardown quiesce and drain those references before freeing memory.
6. Replace field-by-field route/placement/VM setters with atomic snapshot
   publication and generation validation.
7. Enable more than one Mode A VM only after isolation, teardown, and
   semantic-equivalence acceptance tests pass.

## 10. Acceptance Tests

- Two Mode A VMs on one physical node have distinct context handles, mappings,
  route caches, page/dirty records, request IDs, wait queues, and local names;
  one VM's traffic cannot affect the other.
- Multiple QEMU/node-runtime descriptors can attach to one context, and closing
  one descriptor does not destroy active state held by the others.
- A wrong incarnation, manifest digest, capability profile, role, or attach
  capability is rejected before mmap or data-plane operation.
- Atomic configuration/route snapshot replacement never exposes a partial
  table to a concurrent reader.
- A lost `REMOTE_RUN` reply returns the documented in-progress/cached result
  without a second execution interval.
- Dirty capture/invalidation produces the same page version and handoff-fence
  outcomes as Mode B for the same workload.
- KVM Mode A does not install host `PROT_NONE` guest-RAM traps and still
  performs explicit version-gap resync before dependent execution.
- Forced worker failure and concurrent detach/destroy do not use freed context
  memory, leak mappings, deadlock unrelated VM contexts, or report false
  completion.
- Cross-node packet instrumentation proves every accelerated remote operation
  entered/exited through the node-runtime and sidecar/gateway path.

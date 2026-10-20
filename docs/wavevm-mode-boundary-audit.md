# WaveVM Mode A/Mode B Boundary Audit

Status: Phase 1 architecture inventory **plus 2026-10-20 gate restore**.
Explicit per-VM kernel contexts (ABI v3 BIND), private `address_space`, and
per-context dir/route scaffolding exist, but the Mode A second-VM gate is
**restored** (fixed `"kernel-context"` lease + QUERY_CAPS SINGLE_CONTEXT max=1)
until A01–A04 isolation correctness closes. Module-wide UDP/TX rings remain
shared plumbing with context-tagged slots (see `kernel-accelerator.md`
§1.2/§8) and are not a second control plane. Guest login/SSH E2E remains goal
§7.

Legacy text below retains the historical inventory of duplicated semantic
state. Where older paragraphs claim the gate is lifted, prefer this header and
`kernel-accelerator.md` §1.2.

---

## 1. Current Execution Shape

Mode B currently uses:

```text
QEMU WaveVM glue
  -> local IPC/shared memory
  -> main_wrapper + logic_core + user_backend
  -> local sidecar/gateway fabric
  -> local or remote slave daemon
```

Mode A currently uses the same QEMU glue but routes selected operations through
`/dev/wavevm`:

```text
QEMU WaveVM glue
  -> /dev/wavevm IOCTL or mapped fault path
  -> kernel_backend + a kernel-linked logic_core
  -> kernel socket / kernel queues
  -> local sidecar/gateway fabric or local slave
```

The Mode A shape has two problems:

1. `logic_core.c` is initialized in both user and kernel contexts, so directory,
   routing, request, epoch, and identity behavior can drift.
2. The kernel module stores VM-scoped state in module globals, so a second
   same-host VM can overwrite state used by the first.

Mode B remains the semantic baseline. Mode A may cache, accelerate, or execute
the same operation, but it must obtain its authority from a per-VM user-space
runtime manifest rather than create a second authority.

### 1.1 Target Node-Runtime Boundary

This inventory uses `master` and `slave` when naming current files and current
IPC. The normative target is one logical node runtime for each participating
`{vm_incarnation, physical_node_id}`:

- The current master role becomes the node runtime's semantic coordinator and
  sidecar/gateway endpoint.
- The current slave role becomes its local executor manager for KVM workers or
  TCG helper QEMU processes.
- These are logical roles, not a requirement that two processes stay alive
  forever. The current process split remains a compatibility deployment until
  a specified local executor ABI and regressions make another deployment safe.
- Cross-node traffic remains `local node runtime -> local sidecar/gateway ->
  remote sidecar/gateway -> remote node runtime`. A gateway must not deliver a
  production packet directly to a remote executor.

This decision does not authorize an immediate process merge. It first removes
duplicated semantic ownership and preserves queues, batching, QoS, explicit
request correlation, and executor fault containment.

### 1.2 Current Membership and Gateway-Update Gap

The current tree has two compatibility mechanisms, neither of which is a
cluster membership implementation:

- Resource plans load static `NODE` records and derive vnode ranges during
  startup.
- `gateway_service/aggregator.c` parses static `ROUTE` files and accepts a
  small control packet that declares `ADD_ROUTE` and `DEL_ROUTE`; the current
  receive loop handles only add/update and mutates the live map in place.

Those paths have no member identity/boot instance, validation, capability
proof, desired-versus-observed state, topology revision, route generation,
prepare acknowledgement, drain, deletion, or active-VM dependency check. They
must remain bounded compatibility/bootstrap inputs. They must not be extended
piecemeal into the future control plane, and gateway route learning must not be
treated as member admission.

## 2. IOCTL Boundary Inventory

| IOCTL | Current caller and kernel behavior | Target ownership | Migration classification |
| --- | --- | --- | --- |
| `IOCTL_SET_GATEWAY` | `main_wrapper.c`, `user_backend.c`, and `ctl_tool` inject a route into module-global `gateway_table`. | Manifest/routing control plane owns routes; kernel keeps a versioned per-VM derived TX cache only. | Replace global table with `wvm_kernel_ctx` cache. |
| `IOCTL_WVM_REMOTE_RUN` | `wavevm-cpu.c` sends a vCPU state container into the kernel, which resolves a CPU route and calls kernel `wvm_rpc_call`. | User-space vCPU handoff semantics; kernel may accelerate a specified handoff. | Retain as optional accelerator ABI after `docs/specs/vcpu-handoff.md`; bind it to a per-VM context and manifest generation. |
| `IOCTL_WAIT_IRQ` | `wavevm-all.c` waits on the bound context's `irq_wait_queue` and `irq_pending`. | Per-VM local interrupt delivery state. | Keep context-scoped; do not share IRQ state between VMs. |
| `IOCTL_SET_MEM_LAYOUT` | QEMU sends RAM ranges; kernel stores them in the bound context's RAM-slot cache for fault validation. | QEMU RAMBlock/memslot registration is authoritative; kernel caches registered ranges for one VM. | Keep as a context-bound compatibility adapter until the versioned RAM ABI replaces it. |
| `IOCTL_UPDATE_MEM_ROUTE` | User space injects legacy memory route slots into the kernel-linked logic core. | Memory consistency/routing semantic authority in user space. | Deprecate after the manifest and memory contract define the canonical placement snapshot. |
| `IOCTL_UPDATE_MEMORY_PLACEMENT` | `main_wrapper.c` injects the 1 GiB placement table into the kernel-linked logic core. | User-space manifest and memory authority. | Replace with a versioned per-VM derived cache, or remove if the kernel fast path can query a narrow local cache. |
| `IOCTL_SET_VM_ID` | Retired in kernel (`-EOPNOTSUPP`); production callers use `IOCTL_WVM_BIND_CONTEXT` only. | VM identity and incarnation belong to the admitted runtime manifest. | Done: setter retired from production path; BIND is sole attach. |
| `IOCTL_UPDATE_EPOCH` | `user_backend.c` copies the current epoch into the bound context's accelerator cache. | User-space consistency authority. | Keep only as an optional per-VM cache update if a kernel fast path needs it. |
| `IOCTL_UPDATE_CPU_ROUTE` | `main_wrapper.c` injects the CPU route table into the kernel-linked logic core. | User-space manifest and vCPU handoff authority. | Replace with a versioned per-VM derived cache or a narrow handoff lookup interface. |

`IOCTL_RPC_SYNC_ACK` is declared in `wavevm_ioctl.h` but has no kernel handler.
It must either gain a specified owner and ABI in a subsystem specification or
be removed before claiming a stable IOCTL ABI.

## 3. Kernel Global-State Inventory

The following state is presently module-global in `kernel_backend.c`. The
classification names the intended target, not a claim that conversion is done.

| Current state | Current role | Target classification |
| --- | --- | --- |
| `g_socket`, `gateway_table`, `service_port`, `local_slave_port` | Kernel UDP transport and route injection. | Per-VM accelerator transport/cache, derived from manifest. |
| context `mapping`, `mapping_sem` | QEMU file mapping used for invalidation. | Per-open or per-VM registered mapping; never module-global. |
| context `mem_slots` | Registered guest RAM ranges. | Per-open or per-VM QEMU registration cache. |
| `g_fast_ring`, `g_slow_ring`, `g_tx_thread`, `g_tx_wq` | Atomic-context TX queues and worker. | Per-VM queues or a shared transport with explicit VM-tagged queue ownership. |
| `g_diff_queue`, `g_diff_lock`, `g_committer_thread`, `g_diff_wq` | Kernel dirty-page capture and commit worker. | Per-VM accelerator queue. Dirty-commit semantics stay in user space. |
| context `page_tree`, `page_tree_lock` | Kernel page pointer/version/reorder metadata. | Per-VM acceleration cache; directory authority stays in user-space memory semantics. |
| context `req_ctx`, `req_ctx_count`, `id_pool` | In-flight RPC tracking and IDs. | Per-VM request state, or an explicitly namespaced shared transport facility. |
| context `irq_wait_queue`, `irq_pending` | Interrupt notification. | Per-VM local IRQ state. |
| context `kernel_epoch`; legacy `g_my_vm_id` mirror | Epoch and identity copies. | Immutable context identity plus derived consistency cache; the mirror is not an authority and must be removed after compatibility migration. |
| Kernel-linked `logic_core` globals | Directory table, CPU and memory routes, peer view, ring, broadcast queues, force-sync state. | User-space semantic authority. Kernel may retain only narrowly defined per-VM acceleration caches. |

## 4. QEMU Boundary Inventory

The QEMU WaveVM accelerator code has one shared guest-visible role across both
modes: maintain QEMU RAM/vCPU/device integration and turn a remote execution
or memory event into a local runtime request.

Mode-specific mechanics currently include:

- `wavevm-cpu.c` performs `IOCTL_WVM_REMOTE_RUN` in kernel mode.
- `wavevm-tcg.c` and user-mode paths use the local user-space IPC/runtime.
- `wavevm-all.c` registers RAM ranges with `IOCTL_SET_MEM_LAYOUT` only when
  the kernel path is active.
- `/dev/wavevm` detection currently influences automatic accelerator mode
  selection.

The intended migration rule is to keep QEMU's guest-facing code shared and
replace the mode branch with a common local-runtime request interface. The
kernel backend then becomes one implementation of acceleration hooks below
that interface, not an alternate distributed control path.

## 5. Required Migration Order

1. Accept `docs/specs/memory-consistency.md`, `docs/specs/vcpu-handoff.md`, and
   `docs/specs/kernel-accelerator.md` before moving semantic logic.
2. Introduce an explicit `wvm_kernel_ctx` lifetime model:
   bind, configure from a manifest generation, start, quiesce, destroy.
3. Move every current module-global VM-scoped item into that context or replace
   it with a context-tagged shared transport object.
4. Make user space publish immutable versioned manifest snapshots. The kernel
   consumes derived snapshots and must reject stale or mismatched VM identity.
5. Move directory, placement, route, epoch, and lifecycle authority out of the
   kernel-linked logic core. Do not delete a kernel fast path until the
   user-space path has equivalent regression coverage.
6. Preserve the asynchronous normal path: fast/slow QoS queues, batched
   receive, and dirty-page sender workers remain normal-path mechanisms.
   Any synchronous fallback is bounded backpressure or failure handling, not
   the default implementation.
7. Replace the current master-to-slave IPC only after the memory, vCPU, and
   local IPC specifications define the node-runtime/executor ABI. Retain the
   current processes as compatibility adapters during that transition.
8. Accept `docs/specs/cluster-membership-topology-lifecycle.md` and the corresponding
   identity/routing rules before replacing static `NODE`/`ROUTE` bootstrap or
   extending gateway control packets. Route-map updates must consume prepared,
   versioned control-plane snapshots rather than infer membership from traffic.

## 6. First Code-Migration Candidate

The first runtime change after the prerequisite specifications are accepted is
not to remove kernel acceleration. It is to introduce a context object around
the existing kernel state without changing the packet protocol:

```text
open/bind manifest -> allocate wvm_kernel_ctx -> configure derived caches
  -> start workers -> QEMU uses context-bound file descriptor
  -> quiesce -> stop workers -> release mappings and caches
```

This is deliberately postponed until the kernel-accelerator specification
defines lifetime, reference ownership, concurrent QEMU access, worker teardown,
and behavior for stale manifests. A global-to-context mechanical rewrite before
that contract would be high risk and would likely create another Mode A
semantic path.

## 7. Verification Required Before Each Migration

- KVM and TCG both retain the same user-space manifest, route namespace, and
  memory/vCPU handoff semantics.
- Flat and fractal topologies route only through the intended sidecar/gateway
  fabric.
- Cross-node delivery reaches the target node runtime before any local executor;
  no QEMU, sidecar, gateway, or executor has an arbitrary remote-executor path.
- A node/gateway join reaches `ACTIVE` only after capability validation and
  route-snapshot acknowledgement. A health observation alone does not create a
  new route or scheduling target.
- A drain/removal attempt cannot black-hole an existing VM: busy compute nodes
  are rejected in V1, and gateway removal requires an acknowledged alternate
  path for every affected destination.
- A second Mode B VM does not share RAM, request IDs, local IPC paths, or
  gateway namespace with the first.
- A second Mode A VM is rejected until per-VM kernel contexts are implemented.
- Normal-path queue/worker/batch behavior remains active under load.
- Bounded backpressure is observable and does not drop guest-visible memory or
  vCPU state.
- Success requires SSH/login and evidence of both remote vCPU execution and
  remote memory use, with bounded logs and artifacts.

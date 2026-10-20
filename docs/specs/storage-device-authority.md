# WaveVM Storage and Device Authority Specification

Status: normative implementation specification.

RM-3.1 gate (2026-10-19): accepted — document already defines goal/non-goals,
semantic authority, structures/ABI, state/sequences, concurrency/backpressure,
failure/recovery, compatibility/migration, and acceptance tests per roadmap §3.1.

Scope: guest-visible device authority, remote block I/O dispatch, read/write
ordering, flush/FUA semantics, idempotency, error mapping, and interaction with
remote vCPU exits. This V1 document specifies remote block primitives; it does
not claim full distributed ownership of arbitrary PCI, VFIO, or GPU devices.
The admitted manifest/resource plan selects storage participants, while
`wire-ipc-abi.md` defines their transport envelope.

## 1. Goal and Non-Goals

The guest sees one QEMU machine and one coherent device model. Remote resource
nodes may execute block data work, but they do not become independent guest
device authorities. A completed write, flush, or error must have the same
guest-visible meaning regardless of the selected physical storage executor.

Non-goals for V1:

- Transparent migration of a live block backend or arbitrary device model.
- Treating `MSG_BLOCK_ACK` without status, ordering, or durable completion as a
  successful guest flush.
- Direct cross-node storage traffic from a local executor to an arbitrary
  remote executor.
- Giving remote VFIO/GPU code authority over guest interrupt routing or device
  lifecycle without a separate device specification.

## 2. Authority and Placement

| State or decision | Authoritative owner |
| --- | --- |
| Guest-visible disk/controller/virtqueue semantics | Authoritative QEMU frontend. |
| VM identity, storage placement, and selected executor | Admitted VM manifest and control plane. |
| Request ordering and completion to guest | QEMU frontend through its node runtime. |
| Physical block data access | Assigned local storage executor only. |
| Network route | Source/destination node runtimes through sidecar/gateway fabric. |
| Device MMIO/PIO exit completion | Authoritative QEMU frontend. |

Remote storage execution follows:

```text
QEMU device authority -> local node runtime -> sidecar/gateway fabric
                      -> remote node runtime -> local storage executor
                      -> remote node runtime -> origin node runtime -> QEMU
```

No remote storage executor sends a guest completion directly to QEMU or a
remote executor.

## 3. Block Request Model

The semantic request is:

```text
BlockRequest {
    protocol_version;
    vm_id;
    vm_incarnation;
    manifest_generation;
    origin_physical_node_id;
    origin_runtime_instance_id;
    operation_id;
    semantic_payload_digest;
    queue_id;
    queue_sequence;
    operation;            // READ, WRITE, FLUSH, DISCARD, WRITE_ZEROES if supported
    lba_512;
    sector_count;
    flags;                // FUA, barrier, no-cache, discard semantics
    data_or_data_reference;
    checksum_or_digest;
}

BlockResult {
    origin_physical_node_id;
    origin_runtime_instance_id;
    operation_id;
    queue_id;
    queue_sequence;
    status;
    durable;              // required for successful FLUSH/FUA
    data_for_read;
    error_class;
}

BlockForwardingMetadata {
    route_snapshot_key;
    delivery_attempt_id;
}
```

`operation_id` is a nonwrapping 128-bit idempotency value allocated by the
origin runtime. The semantic operation key is `{vm_id, vm_incarnation,
origin_physical_node_id, origin_runtime_instance_id, operation_id}`.
`queue_sequence` preserves required guest ordering for a virtqueue or
equivalent ordering domain. A future device specification may define multiple
independent order domains; V1 must not silently reorder writes that the QEMU
frontend has serialized.

`BlockForwardingMetadata` is outside the semantic payload digest. A route
replacement may change it for a retry/query but must retain the same semantic
key, queue sequence, flags, and data digest. The storage executor deduplicates
using the semantic key and must not apply a second write merely because G ->
G+1 changed a forwarding field.

The storage operation cache retains each semantic key/result through the
maximum route predecessor completion-query/retry horizon. After that horizon it
returns `RESULT_EXPIRED`/typed I/O failure and never converts a lost result into
a fresh write or flush.

The current `wvm_block_payload { lba, count, data[] }` and local
`wvm_ipc_block_req { lba, len, is_write, data[] }` are compatibility payloads.
They lack explicit incarnation, queue sequence, FUA/barrier flags, typed status,
and reliable durable-completion semantics.

## 4. Normal Operations

### 4.1 Read

1. QEMU creates a request with one operation ID and queue sequence.
2. The origin node runtime validates storage placement and sends it to the
   selected storage node runtime.
3. The storage executor reads exactly the requested range and returns data plus
   checksum and typed status.
4. QEMU validates identity, sequence, length, and checksum before completing
   the guest request.

A retry keeps the same semantic operation key. Duplicate reads may return the
same data or a result allowed by the selected backend's ordering snapshot; they
must not be misattributed to another VM or request.

### 4.2 Write

1. QEMU assigns one operation ID, queue sequence, LBA/range, flags, and payload
   digest.
2. The storage executor records duplicate-detection state before applying data.
3. It applies the write in the requested order domain and records its completion
   result before replying.
4. A duplicate with matching identity and digest replays the recorded result.
   A duplicate with different bytes or flags is protocol corruption.
5. QEMU completes the guest request only after its specified write-completion
   condition is true.

Write acknowledgement alone is not durable completion unless the backend
contract says it has reached the selected durability boundary.

### 4.3 Flush and FUA

`FLUSH` orders all prior writes in its queue/order domain before the flush and
requires the assigned storage backend to complete its real durable flush before
returning success. `FUA` writes have the same durable requirement for that
write, even if a later flush is absent.

If the backend cannot provide the requested flush/FUA semantics, the operation
fails explicitly. It may not report success merely because data entered a local
buffer or UDP send queue.

### 4.4 Unsupported Operations

Discard, write-zeroes, resize, snapshot, and cache-mode semantics are disabled
unless their flags, ordering, idempotency, recovery, and guest error mapping are
specified. An unsupported request returns a typed unsupported/error result to
the authoritative QEMU frontend.

## 5. Ordering, Retry, and Failure

| Condition | Required behavior |
| --- | --- |
| Duplicate write/flush | Storage executor consults operation cache and replays only matching completion. |
| Result lost after write | Origin queries/retries the same semantic operation key; only forwarding metadata may change and it never generates a second write ID. |
| Out-of-order sequence | Executor holds or rejects according to explicit queue-order policy; it never silently applies an unsafe order. |
| Storage route unavailable | Return typed I/O failure or VM degraded status; no local arbitrary-node fallback. |
| Executor fails before durable completion | Return uncertain/error according to backend capability; do not claim guest completion. |
| Executor fails after recorded durable completion | Replay result after recovery only when operation cache/durability contract proves it. |
| QEMU/device authority fails | VM lifecycle owns failure; remote executors do not continue accepting guest-visible writes independently. |

The device authority may use bounded queues and batching, but it must preserve
each queue/order domain's contract. It cannot globally serialize unrelated
queues merely to simplify correctness, nor drop writes/flushes under overload.

## 6. vCPU and Interrupt Interaction

Remote vCPU execution may produce PIO/MMIO exits related to storage. The remote
executor returns a typed exit to the authoritative QEMU frontend through the
node-runtime path. QEMU performs device emulation and supplies any read result
to the next vCPU interval as defined by `vcpu-handoff.md`.

Remote device/VFIO interrupts are events, not proof of device completion. They
must carry VM identity, source device identity, delivery sequence, and typed
status through the node runtime; QEMU remains responsible for guest IRQ/APIC
delivery and duplicate suppression.

## 7. Current Code Mapping and Known Deviations

| Current file or symbol | Current behavior | Required migration direction |
| --- | --- | --- |
| `wavevm-qemu/.../wavevm-all.c:wvm_send_ipc_block_io` | Serializes local block IPC on one persistent socket and sends `{lba,len,is_write}`. | Add request identity, queue ordering, flags, typed completion, and manifest validation. |
| `slave_daemon/slave_hybrid.c:handle_block_io_phys` | Handles `MSG_BLOCK_READ/WRITE/FLUSH` with simple payload/ACK flow. | Implement operation cache, real backend durability, status/error mapping, and bounds checks under the canonical schema. |
| `common_include/wavevm_protocol.h` | Defines `MSG_BLOCK_*` and minimal `wvm_block_payload`. | Treat as legacy decoder until versioned block payload is negotiated. |
| Gateway/node runtime paths | Forward block packets alongside generic RPC traffic. | Preserve node-runtime authority, queue QoS, and strict VM route identity. |
| VFIO paths | Can emit `MSG_VFIO_IRQ`. | Keep as future device-event source; do not claim V1 distributed device authority. |

## 8. Compatibility and Migration

1. Inventory every QEMU block-hook call and current storage executor path.
2. Add a typed local IPC block envelope and result while decoding the legacy
   payload for existing fixtures.
3. Add per-executor operation cache and queue/order metadata before enabling
   write retry or reconnection behavior.
4. Implement real flush/FUA checks for the selected backend and fail closed
   when unavailable.
5. Route all remote block completions through node runtimes and QEMU authority.
6. Retire implicit `MSG_BLOCK_ACK` success only after contract tests prove
   correct ordering, duplicate handling, and guest error propagation.

## 9. Acceptance Tests

- Read, write, and flush exercise remote storage and return results to the
  authoritative QEMU frontend.
- A duplicate write with the same operation ID applies bytes once; a duplicate
  with different bytes is rejected.
- A lost result after durable write is safely replayed without a duplicate
  backend mutation.
- A route replacement while a durable result is lost preserves one semantic
  write/flush and returns a cached result or bounded `RESULT_EXPIRED` error.
- Flush and FUA success requires an instrumented durable backend completion.
- Storage executor overload and route loss produce bounded guest-visible errors
  rather than hangs or false success.
- Independent queues can progress concurrently while ordered writes within one
  queue preserve their declared sequence.
- MMIO/PIO and IRQ paths retain QEMU device authority and do not bypass the
  node runtime.
- A storage operation from one VM cannot complete another VM's request even
  when raw node/vnode values overlap.

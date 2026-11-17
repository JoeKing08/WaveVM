# Official f10 fractal rerun 2026-11-17 12:24:27 CST

Times are Asia/Shanghai (CST, UTC+8). Official entry only:
`scripts/wavevm f10 --role node-a|node-b --route-topology fractal`
(wvm_ctl serve + wavevm_node_runtime agent + CREATE_VM).
Runtime sha256 `40e96e7531d29c68fa6759bda085adc160546aaffa14abbfec9838edc747f57c`.
HEAD `f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c` = origin/main. No commit, no push.
Typed runtime gate was not enabled. N04 was not weakened.

## Hosts
Both VMs had rebooted after the 11:36 freeze (2404 at 12:13, 2604 ~12:17).
SharedFolder remounted (`vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other`);
`/dev/shm` remounted 6G; Tailscale `100.116.196.65` ↔ `100.114.246.92` up
(~1 ms after warmup). Runtime hash matched on both after reboot (no recopy).
No leftover qemu/runtime/ctl/gateway from 11:36 (`/tmp` arts were gone).

## Official scorer vs honest closeout
Official scorer: VERDICT=PARTIAL (not PASS).
login_ok=1 ssh_ok=1 at 12:25:44 CST. Unique KVM FE started:
`-accel wavevm,backend=kvm,mode=user,split=2`, Cirros disk, serial, smp=3,
hostfwd 2226. CREATE_VM SUCCESS (attempt 0 status=14, attempt 1 status=0).
Scorer tokens: remote=1 remote_defer=131 sent=0 ack_mode0=0 ack_mode1=0
fence_done=0 remote_vcpu_evidence=0 remote_mem_evidence=1 mem_stats_raw=24
remote_mem_peer=15738. `sent=0` is a scorer token mismatch — vm.log has
`[WVM-SEND] cpu=2`.

Honest official F10/A4 closeout: FAIL. Same-run login+SSH held, but there was
no IPC VCPU_RUN RET with ack_status=0 ack_mode=0, and no official
`[WVM-MEM-STATS]` from a forwarded MSG_MEM_WRITE (remote_commits stayed 0).
Do not treat this as F10 CLOSED.

## Send-to-next-hop remoting fix: verified on the wire, RET still missing
The previous local-sidecar loop is gone (`authorize_local failed` count=0).

A vm.log:
- `[WVM-REMOTE-DEFER] cpu=2 userspace observed cs=0x33 dpl=3 rip=0x401810; remoting now allowed`
- `[WVM-REMOTE] cpu=2 dispatch #0 rip=0x401810 cs=0x33 ...`
- `[WVM-SEND] cpu=2 rip=0x401810 ...`

A agent-a.log:
- `[IPC CPU_RUN RX] fd=15 vcpu=2 mode=0`
- `[WVM-ROUTE-SEND] msg=5 vnode=16 dest=100.114.246.92:17220 sidecar=100.116.196.65:17210 lookup=ok-or-default`
  (MSG_VCPU_RUN to B's data port, not A's local sidecar).
- Also 31× MSG_MEM_ACK (msg=3) A→B on the same dest/sidecar pattern.
- No VCPU_RUN RET / ack_status=0 / ack_mode=0 and no `[WVM-MEM-STATS]` on A.

B agent-b.log:
- `[RuntimeGate] KVM page cache installed records=786432 timeout_ms=1000 active=1`
- `[WVM-EXECUTOR-BRIDGE] dispatch enter msg=5 payload=12781 vm=256`
- `[VCPU-RUN] mode=0 vcpu=2 req=1 src=127.0.0.1:17223`
- `[Slave VCPU Init] guest_vcpu=2 fd=11` (KVM run mapping opened)
- `[kvm-import] profile SET_MSRS partial nmsrs=96 ret=13` (skipped i=13 index=0x17b)
- `[WVM-EXECUTOR-BRIDGE] handoff failed execute=0 validate=0
  result={status=2 exit=7 backend=1 vm=256 vcpu=2 ctx=0} error=unknown`
  status=2 is WVM_VCPU_HANDOFF_RESULT_MEMORY_FAILURE;
  exit=7 is WVM_VCPU_EXIT_MEMORY_ERROR.
- `[WVM-ROUTE-SEND] msg=1` (MSG_MEM_READ) B→A dest=100.116.196.65:17210
  sidecar=100.114.246.92:17220 (32 lines).
- `[WVM-MEM-STATS]` origin=811 directory=801 (origin!=directory),
  remote_reads growing to 15738, remote_commits=0. These are remote read
  completions during the failed handoff, not official MSG_MEM_WRITE commits.

## Remaining hole
The first userspace SEND now reaches B. Remote KVM execution returns
MEMORY_FAILURE / MEMORY_ERROR with empty context (ctx=0), so QEMU never gets
a successful RET and official WRITE-commit stats never appear. That is the
next honest F10/A4 gap. Official f10/a4 flat was not run.

Node A finished 12:26:17 CST; node B stopped 12:26:21 CST. Official runner
already tore down qemu/runtime/ctl/gateway on both hosts (no leftovers).

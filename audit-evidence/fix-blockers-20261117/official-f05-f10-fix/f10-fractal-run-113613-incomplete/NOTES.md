# Official f10 fractal 2026-11-17 11:36:13 CST — incomplete (hosts rebooted)

Times are Asia/Shanghai (CST, UTC+8).

## Host outcome
Official `scripts/wavevm f10 --role node-a|node-b --route-topology fractal` started
2026-11-17 11:36:13 CST (A art `/tmp/wavevm-official-f10-fractal-fix-20261117-113613`,
B art `/tmp/wavevm-official-f10-fractal-fix-20261117-113615`).
CREATE_VM SUCCESS at 11:36:27 on A; unique KVM FE observed
(`-accel wavevm,backend=kvm,mode=user,split=2`, Cirros disk, serial, smp=3, hostfwd 2226).
Both VMs became unreachable ~11:48 CST (host/display-class; likely laptop freeze).
After recovery (Joe 「ok了，继续吧」 12:20 CST):
- Ubuntu 2404 rebooted at 12:13 CST; Ubuntu 2604 up from ~12:17–12:18 CST.
- `/tmp` arts on both hosts were gone. No leftover qemu/runtime/ctl/gateway.
- Runtime binaries survived reboot, sha256
  `40e96e7531d29c68fa6759bda085adc160546aaffa14abbfec9838edc747f57c` on both.
- SharedFolder still held the join bundle plus B-side `agent-b.log` / `runner-b.log`
  last written 11:47 CST. Certs/keys and join.env were not copied here.

## Honest score: no official verdict
A-side wrapper/runner/vm.log/agent-a were lost with `/tmp`. login_ok, ssh_ok,
`[WVM-SEND]`, A-side `[WVM-ROUTE-SEND]`, and IPC VCPU_RUN RET cannot be confirmed
from this cell. Official F10/A4 closeout is therefore not scored from this run.

## What B logs do show (not a closeout)
- `[WVM-EXECUTOR-BRIDGE] dispatch enter msg=5` (MSG_VCPU_RUN) then
  `[VCPU-RUN] mode=0 vcpu=2 req=1 src=127.0.0.1:17223` and Slave VCPU Init
  (guest_vcpu=2, KVM fd opened). So a remoted vcpu=2 request did reach B;
  the send-to-next-hop change is consistent with that, but A send logs are gone.
- Immediately after import: `[kvm-import] profile SET_MSRS partial nmsrs=96 ret=13`
  and later `[WVM-EXECUTOR-BRIDGE] handoff failed execute=0 validate=0
  result={status=2 exit=7 backend=1 vm=256 vcpu=2 ctx=0} error=unknown`.
  No `VCPU_RUN RET` / `ack_status=0 ack_mode=0` on B.
- `[WVM-ROUTE-SEND] msg=1 vnode=0 dest=100.116.196.65:17210
  sidecar=100.114.246.92:17220 lookup=ok-or-default` (32 lines). msg=1 is
  MSG_MEM_READ; dest is A, not B's local sidecar.
- `[WVM-MEM-STATS]` with origin=811 directory=801 (origin!=directory),
  remote_reads growing to 14264, remote_commits=0. These are remote read
  completions on B, not proof of official MSG_MEM_WRITE commits.

Saved here: agent-b.log, runner-b.log, B_ART, B_STARTED, B_AGENT_PID only.

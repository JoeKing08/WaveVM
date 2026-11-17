# Official F10 fractal run-135222 (Asia/Shanghai CST)

Date: 2026-11-17
Art A: /tmp/wavevm-official-f10-fractal-fix-20261117-135222
Art B: /tmp/wavevm-official-f10-fractal-fix-20261117-135239
Evidence: /workspaces/WaveVM/audit-evidence/fix-blockers-20261117/official-f05-f10-fix/f10-fractal-run-135222/
Use from-b/agent-b.log (complete 2604 copy). The A-side SharedFolder copy during
early teardown was truncated.
Runtime sha256 (both hosts, 870576 bytes, built 13:51 CST, ACK version fix):
  11255ed14d14740984ff0dd776d1dd4f014139ce3da74a5edfe58b9222c37602
Official entry: scripts/wavevm f10 --role node-a|node-b --route-topology fractal
HEAD: f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c (uncommitted; no push)

## Verdict

Honest official F10/A4 fractal: FAIL (scorer VERDICT=FAIL).
login_ok=0 ssh_ok=0 because QEMU exited mid-boot after a terminal handoff
failure, before the official login/SSH gate. Do not claim F05/F10/Phase 1/
Phase 9 CLOSED or MINIMUM_COMPLETE. Official F05 remains FAIL (run-112120).
Official flat was not run.

CREATE_VM SUCCESS 13:52:40 CST, unique KVM FE observed.
Guest reached early userspace during boot (serial still in Cirros init):
  [WVM-REMOTE-DEFER] cpu=2 userspace observed cs=0x33 dpl=3 rip=0x7fc9c26fcfff; remoting now allowed
  [WVM-SEND] cpu=2 rip=0x7fc9c26fcfff
  dest: [WVM-ROUTE-SEND] msg=5 vnode=16 dest=100.114.246.92:17220 sidecar=100.116.196.65:17210
Then QEMU aborted:
  qemu-system-x86_64: WaveVM vCPU 2 terminal handoff failure status=-14 gpa=0xb079e000
  [System] QEMU frontend pid=18408 stopped status=256
  [official f10 fractal 13:53:34/A] QEMU exited before login

No IPC VCPU_RUN RET, ack_mode0=0, remote_commits=0, no official WRITE mem.

## Directory miss-pull / first-publish: this hole is shown working

A: [WVM-DIR] unique FE backing node=801 instance=802 local=yes
B: [WVM-DIR] unique FE backing node=801 instance=802 local=no
A served B-owned live pages (no "lacks a full page" after the version=1 fix):
  [WVM-DIR] served live FE backing GPA=0xbffa9000 to directory=811
  [WVM-DIR] served live FE backing GPA=0xbffa7000 to directory=811
  [WVM-DIR] served live FE backing GPA=0xbffa6000 to directory=811
  [WVM-DIR] served live FE backing GPA=0xbcd0b000 to directory=811
  [WVM-DIR] served live FE backing GPA=0xb079e000 to directory=811
B first-published them (from-b/agent-b.log):
  [WVM-DIR] first-published live FE page GPA=0xbffa9000 version=0x1
  [WVM-DIR] first-published live FE page GPA=0xbffa7000 version=0x1
  [WVM-DIR] first-published live FE page GPA=0xbffa6000 version=0x1
  [WVM-DIR] first-published live FE page GPA=0xbcd0b000 version=0x1
  [WVM-DIR] first-published live FE page GPA=0xb079e000 version=0x1
First A-half MEM-STATS: gpa=106516480 (0x6580000), origin=811 directory=801,
remote_reads=1 remote_commits=0.

## Remaining hole after first-publish

  [DBG-EXIT] ret=-1 exit=0 rip_after=?  io_port=0x0 io_dir=0 io_sz=0 alarm=0
  [KVM cache] slice commit failed GPA=0xb079e000 reason=KVM memory slice requires resync
  [DBG-ACK] req=1 rip=0x7fc9c26fcfff ... exit=0
  [WVM-EXECUTOR-BRIDGE] handoff failed execute=0 validate=0 result={status=2 exit=7 backend=1 vm=256 vcpu=2 ctx=0} error=unknown

QEMU treats this as a terminal handoff failure and exits. No KVM_RUN success,
no demand-fill, no RET. Not scored as host/display-class RAM death (no OOM
in dmesg; teardown left 4.0Gi available on 2404). Do not launch another
official 3GB cell in this pass.

## Host health after teardown (Asia/Shanghai CST)

2404 13:53:49 CST: up 1:40, load 3.92 / 1.37 / 0.54, available 4.0Gi,
  no leftover wavevm/qemu/wvm_ctl, /dev/shm 6G.
2604 13:54:26 CST: up 1:36, load 2.68 / 2.40 / 1.53, available 3.1Gi,
  no leftover wavevm/qemu. Runtime sha256 matched.

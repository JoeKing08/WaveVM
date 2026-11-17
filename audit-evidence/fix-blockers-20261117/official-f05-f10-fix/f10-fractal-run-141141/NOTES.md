# Official F10 fractal run-141141 (Asia/Shanghai CST)

Date: 2026-11-17
Art A: /tmp/wavevm-official-f10-fractal-fix-20261117-141141
Art B: /tmp/wavevm-official-f10-fractal-fix-20261117-141134
Evidence: /workspaces/WaveVM/audit-evidence/fix-blockers-20261117/official-f05-f10-fix/f10-fractal-run-141141/
Use from-b/agent-b.log for the complete 2604 copy.
Runtime sha256 (both hosts, 874936 bytes, built 14:10 CST, first bare-EFAULT fill):
  6bdd9aa307847b569e521800967c86c1d10d603c32c11c2137c30bc046eff1cf
Official entry: scripts/wavevm f10 --role node-a|node-b --route-topology fractal
HEAD: f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c (uncommitted; no push)

## Verdict

Honest official F10/A4 fractal: FAIL (scorer VERDICT=FAIL).
login_ok=1 at 2026-11-17 14:12:53 CST, ssh_ok=1 at 2026-11-17 14:12:54 CST.
After the 5s vCPU2 affinity burn, remoting started at rip=0x401810, then QEMU
exited on a terminal handoff failure. No RET (ack_mode0=0), no official WRITE
mem (remote_commits=0). Do not claim F05/F10/Phase 1/Phase 9 CLOSED or
MINIMUM_COMPLETE. Official F05 remains FAIL (run-112120). Official flat was
not run.

CREATE_VM SUCCESS 14:11:55 CST, unique KVM FE observed.
  [WVM-REMOTE-DEFER] cpu=2 userspace observed cs=0x33 dpl=3 rip=0x401810; remoting now allowed
  [WVM-SEND] cpu=2 rip=0x401810 rax=0xb7e7a462 rdx=0x46041e ...
  dest: [WVM-ROUTE-SEND] msg=5 vnode=16 dest=100.114.246.92:17220 sidecar=100.116.196.65:17210
Then:
  qemu-system-x86_64: WaveVM vCPU 2 terminal handoff failure status=-14 gpa=0

## First-publish still works

A: [WVM-DIR] unique FE backing node=801 instance=802 local=yes
B: [WVM-DIR] unique FE backing node=801 instance=802 local=no
A served, B first-published B-owned pages including
  0x8f3ce000, 0xbffa9000, 0xbffa7000, 0xbffa6000, 0xbcd0b000, 0x8fb9e000
  all version=0x1.
First MEM-STATS: gpa=113184768 (0x6be4000), origin=811 directory=801,
remote_reads=1 remote_commits=0.

## Post-publish hole confirmed as bare KVM_RUN EFAULT

This host advertises KVM_CAP_MEMORY_FAULT_INFO=1 but a PROT_NONE memslot
access returns ret=-1 errno=14 (EFAULT), exit_reason=0, flags=0, memory_fault
empty (confirmed by a local /dev/kvm probe on both 2404 and 2604, kernel
7.0.0-43-generic, no kvm_mmu_prepare_memory_fault_exit symbol in kvm.ko).
WaveVM therefore never reached the existing KVM_EXIT_MEMORY_FAULT demand-fill
path. The "slice requires resync" line is a consequence of that failed
KVM_RUN (leave marks the slice failed; leftover/zero error_gpa is reported).

This run reached the new bare-EFAULT decoder:
  insn=48 8b 44 24 08 48   ; rex.w mov rax, qword ptr [rsp+8]
  memops=1 new_pages=0
  [KVM cache] bare EFAULT demand-fill failed GPA=0 rc=-14 errno=14 exit=0
  [DBG-EXIT] ret=-1 errno=14 exit=0 ...
  [KVM cache] slice commit failed GPA=0 reason=KVM memory slice requires resync

The decoded operand is the already-prefetched stack page, so the helper
returned -EFAULT without retrying KVM_RUN after re-expose. That retry hole
is addressed in a follow-up runtime build
(0b6aea77b3dbeb78a1e52520a2e1dd552534167b0c142a830d01b05d892c7b95).

QEMU treats any ack.status<0 as terminal (legacy_status=-14 is MEMORY_FAILURE
mapped to -EFAULT) and calls exit(EXIT_FAILURE).

## Host health after teardown (Asia/Shanghai CST)

2404 14:13:14: up 1:59, load 3.83 / 1.84 / 1.07, available 4.0Gi,
  no leftover wavevm/qemu/wvm_ctl. During the 3GB guest, available RAM was
  952Mi (similar to prior official cells).
2604 14:13:16: up 1:55, load 3.67 / 1.87 / 1.37, available 3.1Gi, no leftovers.

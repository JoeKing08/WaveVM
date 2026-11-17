# Official F10 fractal run-141504 (Asia/Shanghai CST)

Date: 2026-11-17
Art A: /tmp/wavevm-official-f10-fractal-fix-20261117-141504
Art B: /tmp/wavevm-official-f10-fractal-fix-20261117-141459
Evidence: /workspaces/WaveVM/audit-evidence/fix-blockers-20261117/official-f05-f10-fix/f10-fractal-run-141504/
Use from-b/agent-b.log for the complete 2604 copy.
Runtime sha256 (both hosts, 874984 bytes, built 14:14 CST, bare-EFAULT retry-after-expose):
  0b6aea77b3dbeb78a1e52520a2e1dd552534167b0c142a830d01b05d892c7b95
Official entry: scripts/wavevm f10 --role node-a|node-b --route-topology fractal
HEAD: f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c (uncommitted; no push)

## Verdict

Honest official F10/A4 fractal: FAIL (scorer VERDICT=FAIL).
login_ok=1 / ssh_ok=1 at 2026-11-17 14:16:13 CST.
After the 5s vCPU2 affinity burn, remoting started at rip=0x401810, then QEMU
exited on a terminal handoff failure. No RET (ack_mode0=0), no official WRITE
mem (remote_commits=0). Do not claim F05/F10/Phase 1/Phase 9 CLOSED or
MINIMUM_COMPLETE. Official F05 remains FAIL (run-112120). Official flat was
not run.

CREATE_VM SUCCESS 14:15:16 CST, unique KVM FE observed.
  [WVM-REMOTE-DEFER] cpu=2 userspace observed cs=0x33 dpl=3 rip=0x401810; remoting now allowed
  [WVM-SEND] cpu=2 rip=0x401810 rax=0x9df17812 rdx=0x2526e ...
  dest: [WVM-ROUTE-SEND] msg=5 vnode=16 dest=100.114.246.92:17220 sidecar=100.116.196.65:17210
Then:
  qemu-system-x86_64: WaveVM vCPU 2 terminal handoff failure status=-14 gpa=0

## First-publish still works

B first-published B-owned pages including
  0xbc4cb000, 0xbffa9000, 0xbffa7000, 0xbffa6000, 0xbcd0b000, 0xaa39e000
  all version=0x1.
First MEM-STATS: gpa=78999552 (0x4b57000), origin=811 directory=801,
remote_reads=1 remote_commits=0.

## Bare EFAULT retry still fails at the already-published stack/RIP pages

The instruction is `48 8b 44 24 08` (rex.w mov rax, qword ptr [rsp+8]).
The decoder recovered the stack linear correctly: lin[0]=0x7ffecac0e958.
Working-set prefetch had already marked those pages CLEAN (new_pages=0).
The follow-up runtime retried KVM_RUN once after re-expose:

  [KVM cache] bare EFAULT demand-fill rip=0x401810 insn=48 8b 44 24 08 48 memops=1 new_pages=0 lin[0]=0x7ffecac0e958
  [KVM cache] bare EFAULT demand-fill rip=0x401810 insn=48 8b 44 24 08 48 memops=1 new_pages=0 lin[0]=0x7ffecac0e958
  [KVM cache] bare EFAULT demand-fill failed GPA=0 rc=-14 errno=14 exit=0
  [DBG-EXIT] ret=-1 errno=14 exit=0 ...
  [KVM cache] slice commit failed GPA=0 reason=KVM memory slice requires resync

So the kernel still returns a bare EFAULT with no GPA after the operand and
instruction pages are (or appear) present. The slice-resync log is a
consequence of that failed KVM_RUN. QEMU maps MEMORY_FAILURE to ack.status=-14
and exits.

No further official 3GB cell was started after this run.

## Host health after teardown (Asia/Shanghai CST)

See the wrap-up health snapshot recorded with the 2404 evidence copy.
During the 3GB guest, 2404 available RAM was 912Mi–1.0Gi.

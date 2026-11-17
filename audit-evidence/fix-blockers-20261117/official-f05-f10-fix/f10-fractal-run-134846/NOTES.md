# Official F10 fractal run-134846 (Asia/Shanghai CST)

Date: 2026-11-17
Art A: /tmp/wavevm-official-f10-fractal-fix-20261117-134846
Art B: /tmp/wavevm-official-f10-fractal-fix-20261117-134909
Evidence: /workspaces/WaveVM/audit-evidence/fix-blockers-20261117/official-f05-f10-fix/f10-fractal-run-134846/
Runtime used for this cell (both hosts, 870576 bytes, built 13:48 CST):
  79c807ba02d28702789e919029692a7adf3090b0ef403432eaf9760e3827a1f0
A follow-up runtime with the ACK version=0 fix (not used by this cell) is
  11255ed14d14740984ff0dd776d1dd4f014139ce3da74a5edfe58b9222c37602
Official entry: scripts/wavevm f10 --role node-a|node-b --route-topology fractal
HEAD: f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c (uncommitted; no push)

## Verdict

Honest official F10/A4 fractal: FAIL (scorer VERDICT=PARTIAL).
Do not claim F05/F10/Phase 1/Phase 9 CLOSED or MINIMUM_COMPLETE.
Official F05 remains FAIL (run-112120). Official flat was not run.

Observed:
- login_ok=1 / ssh_ok=1 at 2026-11-17 13:50:10 CST
- unique KVM FE: -accel wavevm,backend=kvm,mode=user,split=2
- [WVM-SEND] cpu=2 rip=0x401810 (vm.log)
- SEND dest: [WVM-ROUTE-SEND] msg=5 vnode=16 dest=100.114.246.92:17220 sidecar=100.116.196.65:17210
- No IPC VCPU_RUN RET, ack_mode0=0
- No official WRITE mem: remote_commits=0, no MSG_MEM_WRITE
- FE discovery worked:
  A: [WVM-DIR] unique FE backing node=801 instance=802 local=yes
  B: [WVM-DIR] unique FE backing node=801 instance=802 local=no
- Walk continued past A-half pages (first MEM-STATS gpa=100691968 = 0x6007000,
  origin=811 directory=801, remote_reads=1)
- B-owned GPA was requested and A served live FE RAM:
  [WVM-DIR] served live FE backing GPA=0x6d3b3000 to directory=811
- Then: [Typed Ingress] status=2 bytes=220 reason=successful V1 memory ACK lacks a full page
- B: [KVM cache] execution page fetch GPA=0x6d3b3000: V1 local memory fault exceeded completion horizon
  slice commit failed GPA=0x6d3b3000 reason=KVM memory slice requires resync
  [DBG-ACK] exit=65536
  handoff failed status=2 exit=7 ctx=0
- No first-publish on B (ACK never accepted), no KVM_RUN, no demand-fill, no SIGSEGV

## Why the B-owned ACK failed

V1 MEM_ACK SUCCESS requires version!=0 to carry the 4KiB page
(common_include/wavevm_memory.c). The FE backing path set version=0
("not directory-authoritative"), so encode/ingress dropped the page.
That is fixed after this run by a provisional wire version=1; the
directory still overwrites it on first-publish.

## Host health after teardown

2404 after teardown ~13:51:46 CST: available 3.9Gi, no leftover procs.
During login, available dropped to 894Mi (3.1Gi shared guest RAM).
2604 13:51:56 CST: available 3.1Gi, load 2.13 / 1.90 / 1.24, no leftover procs.

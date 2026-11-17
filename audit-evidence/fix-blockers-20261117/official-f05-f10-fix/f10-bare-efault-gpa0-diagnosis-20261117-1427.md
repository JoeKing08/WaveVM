# Official F10 bare-EFAULT GPA=0 diagnosis wrap (2026-11-17 14:27 CST)

Joe (t614u): 「彽亂，收完这轮先停一下吧」. This round stopped after diagnosis.
No new official 3GB F10/A4/F05 cell was started after run-141504. No rebuild, no commit.

## Last official cell (already scored; no successor)

- Evidence: audit-evidence/fix-blockers-20261117/official-f05-f10-fix/f10-fractal-run-141504/ (complete B logs in from-b/)
- Art A: /tmp/wavevm-official-f10-fractal-fix-20261117-141504
- Art B: /tmp/wavevm-official-f10-fractal-fix-20261117-141459
- Runtime on both hosts (unchanged this wrap): sha256 0b6aea77b3dbeb78a1e52520a2e1dd552534167b0c142a830d01b05d892c7b95
  (874984 bytes, 2026-11-17 14:14 CST)
  2404: /workspaces/WaveVM/wavevm_node_runtime
  2604: /home/joeking/WaveVM/wavevm_node_runtime
- login_ok=1 / ssh_ok=1 at 2026-11-17 14:16:13 CST
- SEND: `[WVM-SEND] cpu=2 rip=0x401810 rax=0x9df17812 rdx=0x2526e mp_valid=1 mp=0 lapic=1 vcpu_events=1 tsc=1` dest 100.114.246.92:17220
- first-publish still worked (B directory live FE pages, version=0x1):
  GPA=0xbc4cb000, 0xbffa9000, 0xbffa7000, 0xbffa6000, 0xbcd0b000, 0xaa39e000
- Two same-RIP lines:
  `[KVM cache] bare EFAULT demand-fill rip=0x401810 insn=48 8b 44 24 08 48 memops=1 new_pages=0 lin[0]=0x7ffecac0e958`
- Then: `bare EFAULT demand-fill failed GPA=0 rc=-14 errno=14 exit=0`
  `slice commit failed GPA=0 reason=KVM memory slice requires resync`
  QEMU: `terminal handoff failure status=-14 gpa=0`
- No RET, remote_commits=0. MEM-STATS gpa=78999552 (0x4b57000) origin=811 directory=801 remote_reads=1 remote_commits=0
- Earlier run-141141 (pre-retry runtime 6bdd9aa3...) already showed the same insn/linear with no KVM_RUN retry.

## What is established (code + existing evidence + earlier host probes)

1. Kernel 7.0.0-43-generic advertises CHECK_EXTENSION(KVM_CAP_MEMORY_FAULT_INFO)=1, but KVM_RUN on PROT_NONE returns bare -EFAULT (errno=14), exit_reason=0, flags=0, empty memory_fault. kvm.ko has no kvm_mmu_prepare_memory_fault_exit. Userspace therefore cannot read a fault GPA from KVM.

2. Local /tmp/kvm_efault_diag.c on 2404: when the pages the guest actually needs are exposed, KVM_RUN succeeds (real-mode HLT al=0x5a) even with SHM + MADV_HUGEPAGE + KVM_MEM_LOG_DIRTY_PAGES + PROT_NONE conceal of unused RAM. This kernel can GUP an exposed page. Official EFAULT is therefore not "GUP is broken for every exposed page."

3. run-141504 decoder is correct: `mov rax, [rsp+8]` at rip=0x401810, stack linear 0x7ffecac0e958. Instruction bytes were readable from translated HVA. RIP and operand pages were already CLEAN (new_pages=0). The same-RIP re-expose + one KVM_RUN retry still EFAULT’d with GPA=0. So KVM is accessing some other still-PROT_NONE GPA, not the decoded RIP/stack operand that demand-fill re-exposed.

4. "slice commit failed" / leftover error_gpa is a consequence of leave() after KVM_RUN failure, not the primary hole.

5. `[SLAVE-MEM] GPA=0x401810 unreadable` is a debug red herring (treats RIP as GPA), not evidence of an identity map.

6. first-publish / live-FE materialize / miss-pull remain verified and must be kept. Official WRITE mem must not be claimed from first-publish.

## Code gap (the honest production hole)

`prepare_kvm_execution_snapshot` in slave_daemon/slave_hybrid.c prefetches only:
- RIP span 15 (required)
- RSP span 15 (ENOENT ignored)
- GDT and IDT (ENOENT ignored)

It does **not** prefetch:
- TR / 64-bit TSS (`sregs->tr.base` / limit)
- LDTR
- TSS.RSP0 / RSP1 / RSP2 / IST1–7 stacks
- IDT gate handler pages for a pending exception or LAPIC interrupt

`demand_fill_kvm_bare_efault` only re-ensures the current RIP span and decoded memory operands. After a failed KVM_RUN it GET_REGS, so if the EFAULT happened during *event delivery before the MOV retired*, RIP is still 0x401810 and demand-fill keeps re-exposing the already-CLEAN userspace instruction and `[rsp+8]` page — exactly the 141504 log shape.

QEMU SEND on that run carried `lapic=1 vcpu_events=1` and `mp=0` (RUNNABLE) after Cirros login+SSH. SET_SREGS / SET_LAPIC / SET_VCPU_EVENTS imported without ErrorAck (no `[kvm-import] SET_VCPU_EVENTS` failure line). Event *contents* (pending/injected vector, NMI, exception) were not logged, so a pending delivery is the leading hypothesis, not a proved fact.

Leading hypothesis (unconfirmed by a new cell, per stop request):
KVM_RUN tried to touch a still-PROT_NONE GPA on the architectural / event-delivery path (TSS, kernel stack from TSS.RSP0/IST, and/or the IDT handler for a pending LAPIC/vcpu_events vector) while RIP remained at the userspace MOV. That would produce bare EFAULT with GPA=0 after first-publish and a same-RIP retry.

Remaining uncertainty: existing logs do not print TR.base, CR4, vcpu_events fields, or LAPIC IRR, so the exact faulting GPA/HVA/memslot is still not identified. Other still-open possibilities include a missed page-walk page for a kernel mapping, or a kernel access not covered by the instruction decoder.

## Intended fix (NOT applied this wrap)

Do not invent pages or weaken N04. Keep live-FE, first-publish, and bare-EFAULT demand-fill.

In slave_hybrid.c, extend prepare and bare-EFAULT recovery to also:
- ensure GDT, IDT, TR/TSS, LDTR
- after TSS is present, parse the 64-bit TSS and ensure RSP0/1/2 and IST stacks
- if vcpu_events and/or KVM_GET_LAPIC IRR show pending/injected vectors, parse those IDT gates and ensure handler pages
- log CR0/CR3/CR4/EFER, GDT/IDT/TR GPAs, and event/IRR vectors after bare EFAULT

Only then rebuild wavevm_node_runtime (not QEMU, unless diagnosis later requires it), cp -f via SharedFolder, confirm sha256 on both hosts, and rerun official `scripts/wavevm f10` fractal only if hosts are healthy. Official flat only if fractal honestly has RET + official WRITE mem.

## This wrap

- No tree edits after run-141504. Working tree left as-is (uncommitted prior live-FE / first-publish / bare-EFAULT demand-fill work).
- No runtime/QEMU rebuild. sha256 still 0b6aea77... on both hosts.
- No official cell after 14:15 besides the already-finished 141504.
- HEAD remains f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c. No commit, no push.
- F05 still FAIL (run-112120). F10/A4 not CLOSED. Phase 1/Phase 9 / MINIMUM_COMPLETE not claimed.

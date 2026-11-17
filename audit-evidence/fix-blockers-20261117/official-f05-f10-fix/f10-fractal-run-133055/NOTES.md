# Official F10 fractal run-133055 (Asia/Shanghai CST)

Date: 2026-11-17
Art A: /tmp/wavevm-official-f10-fractal-fix-20261117-133055
Art B: /tmp/wavevm-official-f10-fractal-fix-20261117-133223
Evidence: /workspaces/WaveVM/audit-evidence/fix-blockers-20261117/official-f05-f10-fix/f10-fractal-run-133055/
Runtime sha256 (both hosts, 866304 bytes, built 13:29-13:30 CST):
  03c49b2e28f29e365317250390827fa7d601f2800c45253e39fb72d867a0df23
Previous scored runtime was
  849974c5405831ca4b36a361964b215da7d4f399418d4f10796b0e257c9d9530
Official entry: scripts/wavevm f10 --role node-a|node-b --route-topology fractal
HEAD: f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c (uncommitted; no push this round)

## Verdict

Honest official F10/A4 fractal: FAIL (scorer VERDICT=PARTIAL).
Do not claim F05/F10/Phase 1/Phase 9 CLOSED or MINIMUM_COMPLETE.
Official F05 remains FAIL (run-112120, stay-local in kernel/boot); not scored this pass.
Official f10/a4 flat was not run (fractal has no honest RET and no official WRITE mem).

Observed:
- login_ok=1 at 2026-11-17 13:33:33 CST
- ssh_ok=1 at 2026-11-17 13:33:33 CST
- unique KVM FE: -accel wavevm,backend=kvm,mode=user,split=2
- [WVM-SEND] cpu=2 rip=0x401810 (vm.log)
- SEND dest: [WVM-ROUTE-SEND] msg=5 vnode=16 dest=100.114.246.92:17220 sidecar=100.116.196.65:17210
- No IPC VCPU_RUN RET, ack_mode0=0, ack_status not 0/success
- No official WRITE mem: remote_commits=0, no MSG_MEM_WRITE
- [WVM-MEM-STATS] origin=811 directory=801 gpa=105828352 (0x64ed000) remote_reads=1 remote_commits=0
  (later additional MSG_MEM_READ msg=1 to A occurred; first stats sample still reads=1)
- q_alive=0 is post-teardown, not an A-side crash
- sent=0 is scorer token mismatch; [WVM-SEND] is present in vm.log
- handoff_fail=1
- No KVM_RUN, no demand-fill, no SIGSEGV
- [DBG-ACK] exit=65536 (WVM_EXIT_PREEMPT); handoff failed status=2 exit=7 ctx=0

## 12:47 root cause (this-round diagnosis, confirmed)

Official F10 run-124722 prefetched only CR3/PML4 GPA 0x60cb000 (remote_reads=1),
then join failed with slice resync, no KVM_RUN, no demand-fill.

wvm_handle_local_fault_fastpath() used DIR_FIND_OR_CREATE and returned a
newly invented directory page (zeros, version MAKE_VERSION(epoch, 1))
instead of live unique-FE RAM. Official unique FE had attached the same
WVM_SHM_FILE:

  [WaveVM-SHM] guest RAM attached gpa=0 size=0xc0000000 hva=0x7d41bfe00000

Local KVM execution on A dirties that SHM without versioned directory
commits. The remote executor therefore walked a fake all-zero PML4
(present=0), returned -ENOENT with no execution page fetch log, and
skipped KVM_RUN. The later [KVM cache] slice commit failed GPA=0x60cb000
reason=KVM memory slice requires resync was a consequence, not the first
cause.

A-side conceal_unfetched_kvm_ram() PROT_NONE applies to executor g_phy_ram,
a separate VMA from g_shm_ptr; it was not why the first read succeeded
with zeros.

## This-round production fix (runtime only; QEMU not rebuilt)

- master_core/logic_core.c: userspace fastpath looks up (no implicit zero
  create). On the unique-FE node, materialize / refresh directory bytes
  from live WVM_SHM_FILE and bump version when refreshing an already
  published entry. Non-FE nodes must not treat their local backing store
  as guest RAM. First 16 materializations log:
  [WVM-DIR] materialized live FE RAM GPA=... version=... create|refresh
- master_core/logic_core.h / master_core/main_wrapper.c:
  wvm_frontend_live_ram_page() (gated on QEMU_FRONTEND role + mapped SHM)
- node_runtime/main.c: comment on read_authoritative_local_page updated

Typed runtime gate stays off. N04 not weakened. No fake acks / RET /
[WVM-MEM-STATS]. No PASM. session-backup not touched. No commit/push.

## run-133055: 12:47 hole is addressed; new remaining hole

Live-FE materialize worked on A (BIOS-range [WVM-DIR] logs at boot).
Working-set walk continued past the first CR3 page: B issued multiple
MSG_MEM_READ (msg=1) to dest=100.116.196.65:17210, A replied with
MSG_MEM_ACK (msg=3). First remoted page was GPA 0x64ed000 (in A directory
half). Then:

  [KVM cache] execution page fetch GPA=0xbffa9000: local V1 directory cannot read GPA 0xbffa9000
  [KVM cache] slice commit failed GPA=0xbffa9000 reason=KVM memory slice requires resync

Admitted dispatch (decoded from
  cell/runtime-a/vm-256-1-1.manifest.dispatch):

  GPA [0x0, 0x60000000)        directory=801/802 vnode=0   (Node A)
  GPA [0x60000000, 0xC0000000) directory=811/812 vnode=16  (Node B)

0x64ed000 is in A range (live SHM materialize + remote read works).
0xbffa9000 is in B range. Official spread makes B the directory, so
B calls local read_authoritative_local_page. B is not the unique FE,
has no committed directory image (remote_commits still 0), and correctly
returns -1 instead of inventing zeros. Join/slice resync / status=2
exit=7 follows.

Remaining production gap: unique-FE dirty RAM in a remote directory
range is never published into that directory before remoting. B cannot
serve 0xbffa9000 from live A SHM. Next honest fix is FE dirty-log
commit / first-publish into the admitted directory (or a directory miss
fetch from the unique FE), not another guess-and-rerun.

## Host health after teardown (Asia/Shanghai CST)

2404 13:37:26 CST: up 1:23, load 0.01 / 0.07 / 0.15, available 3.9Gi,
  /dev/shm 6G, SharedFolder mounted, Tailscale 100.116.196.65 up,
  no leftover wavevm/qemu/wvm_ctl. During login, available dropped to
  867Mi (3.1Gi shared guest RAM) then recovered after teardown.
2604 13:37:40 CST: up 1:19, load 0.70 / 1.11 / 0.82, available 3.1Gi,
  /dev/shm 6G, Tailscale 100.114.246.92 up, no leftover wavevm/qemu.
  Runtime sha256 matched on both hosts.

# Official f10 fractal 2026-11-17 12:47:22 CST — FAIL (no RET)

Times are Asia/Shanghai (CST, UTC+8). Official entry:
`scripts/wavevm f10 --role node-a|node-b --route-topology fractal`.
Runtime sha256 `849974c5405831ca4b36a361964b215da7d4f399418d4f10796b0e257c9d9530`
(working-set prefetch + PROT_NONE + KVM_EXIT_MEMORY_FAULT + guarded SLAVE-MEM dump).
HEAD `f9fbe187e8d6cb4d103b9ea5edb6aa0d3250479c` = origin/main. No commit, no push.

CREATE_VM SUCCESS 12:47:35. Unique KVM FE
`-accel wavevm,backend=kvm,mode=user,split=2`. login_ok=1 at 12:48:31,
ssh_ok=1 at 12:48:32. Send-to-next-hop still verified: [WVM-REMOTE] cpu=2,
[WVM-SEND] cpu=2, [IPC CPU_RUN RX] vcpu=2, [WVM-ROUTE-SEND] msg=5 vnode=16
dest=100.114.246.92:17220 sidecar=100.116.196.65:17210.

Official scorer VERDICT=PARTIAL (q_alive=0, sent=0, ack_mode0=0,
handoff_fail=1, remote_mem_evidence=1 from a single remote_reads=1 sample).
Honest official closeout: FAIL. No IPC VCPU_RUN RET / ack_status=0 /
ack_mode=0, no official MSG_MEM_WRITE commits (remote_commits=0).

B: memory_fault_exits=1, unfetched RAM PROT_NONE. No SIGSEGV (SLAVE-MEM
logged "unreadable" for linear 0x401810). Working-set prefetch issued a
single MSG_MEM_READ for CR3/PML4 GPA 0x60cb000 (remote_reads=1), then
prepare/join failed without KVM_RUN or any KVM_EXIT_MEMORY_FAULT
demand-fill. Then `[KVM cache] slice commit failed GPA=0x60cb000
reason=KVM memory slice requires resync` and
`handoff failed execute=0 validate=0 result={status=2 exit=7 ... ctx=0}`.
A had no RET. Node A finished 12:48:38; node B stopped 12:48:41.

# Official f10 fractal 2026-11-17 12:43:21 CST — FAIL (B child SIGSEGV)

Times are Asia/Shanghai (CST, UTC+8). Runtime was
`2b41ccbc6971befb2c66c7fb369ac18e0aabf9a7bb7b534d9583e94e4a7ce508`
(working-set prefetch + PROT_NONE + KVM_EXIT_MEMORY_FAULT, before the
SLAVE-MEM dump guard).

CREATE_VM SUCCESS 12:43:33. Unique KVM FE ok. login_ok=1 ssh_ok=1 at 12:44:40.
Send-to-next-hop still worked: [WVM-SEND], [WVM-ROUTE-SEND] msg=5 to B.
B: memory_fault_exits=1, unfetched RAM PROT_NONE, working-set fetch started
(CR3 page GPA 0x68ff000, remote_reads=1). prepare snapshot reached DBG-RAW.
Then admitted child pid 6342 exited sig=11 (SIGSEGV) because the diagnostic
[SLAVE-MEM] dump dereferenced g_phy_ram + linear RIP (0x401810), which was
still PROT_NONE (identity != translated instruction GPA). Official scorer
VERDICT=PARTIAL; honest closeout FAIL (no RET, no WRITE commits).

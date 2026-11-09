# WaveVM Minimum Cross-Audit (independent)
When: 2026-11-09 ~20:30 CST Asia/Shanghai
Who: Grok Bot cross-auditor (executor subagent) → for relay to Grok Bot agent b52fcc76-…
Repo: machineId 2e4d3ec5-e1b1-4a36-9903-de6309119499 `/workspaces/WaveVM`
Tip HEAD verified: `e47d6a5189b0134ca48d9e9af3e41a3e2e8401f1` (matches claimed e47d6a518)
Workspace: dirty (docs + production fixes + evidence uncommitted); audited WORKING TREE as-is
Method: read-only; opened roadmap §1.1 / Phases 0–9, baseline Minimum usable + §14/§16, goal.txt, MINIMUM_FIX_LIST, self-audit 1957, N01–N07/F05/F10 evidence, and spot-checked production diffs
Authority contrast: Grok self-audit `audit-evidence/fix-blockers-20261109/MINIMUM_GAP_SELF_AUDIT_DIRTY_CHARTER_20261109-1957.txt` — contrast only
MINIMUM_COMPLETE: **NO / NOT_CLAIMABLE**
No code changes, no commit/push, no message to Joe.

---

## 0) Repo / tip verification
| Check | Result |
|---|---|
| `git rev-parse HEAD` | e47d6a5189b0134ca48d9e9af3e41a3e2e8401f1 |
| tip short | e47d6a518 ✓ |
| dirty | yes (~153 status lines; docs+ctl/node/qemu/slave/scripts + untracked evidence/tests) |
| 2604 | not required this round (offline) |

---

## 1) Verdict table — §1.1 / Phase0–9 / MUST-FIX

Format: 项 | Grok裁决 | 你的裁决 | 证据路径 | 一句理由

### 1.A Roadmap §1.1 Minimum bullets

| 项 | Grok裁决 | 你的裁决 | 证据路径 | 一句理由 |
|---|---|---|---|---|
| A1 Manifest lifecycle + one active coordinator (+ durable ACTIVATION_DECIDED / restart replay) | PARTIAL | **同意 PARTIAL**（偏弱） | goal.txt; roadmap §1.1; self-audit A1; **无** 20261109 ACTIVATION_DECIDED live 证据 | N01 lease 定向有证，但冷启动 ACTIVATION_DECIDED 对账/重放/补偿本轮零 live 证明，而 goal 明文属 Minimum |
| A2 Identity/placement/remote CPU·mem/leases/capability | PARTIAL | **同意 PARTIAL** | F10-kvm-narrowed/live-matrix-20261109-183406/; F05 195252 | KVM login 有；remote attribution 仍 0；F05 RET 是 TCG 远端切片，不能盖 KVM g9 |
| A3 Flat+fractal ACK immutable snapshots | PARTIAL | **同意 PARTIAL** | N06-listener-budget/; F05 fract_2node.conf + legacy routes | N06 拒 >64 有定向；F05 仍用 legacy CLI 路由文件，非 Phase-9 typed ACK snapshot 验收格 |
| A4 KVM login/SSH + remote vCPU/mem evidence | PARTIAL (login PASS / remote FAIL) | **同意 PARTIAL**；并 **不同意** fix-list「CLOSED for login/SSH」话术 | F10 …/183406/cells/*/HONESTY.txt, result OVERALL=FAIL_g9_remote_attribution; LIVE_SUMMARY MATRIX_RESULT=FAIL | login/ssh/cpu-smoke=PASS 属实；§1.1 要求 remote 证据，矩阵诚实 FAIL，不能把子项 PASS 写成 CLOSED |
| A5 Bounded real TCG contract (not guest OS) | PARTIAL→stronger (RET evidenced; harness not green) | **同意 PARTIAL**（RET 有证，合同格未闭） | F05 …/195252/master0.log L158 RET; b-side slave1 guest_vcpu=2+UDP MEM_READ×9+TCG ack; f05_fence_only_result q_alive=NO | fence+decode+RET 日志真实；harness ERROR、vm.log 截断、remote/handoff grep=0 → 非 Phase-9 TCG 验收 PASS |
| A6 Multi Mode B VM + same-host compute instances | PARTIAL | **同意 PARTIAL** | N01/N04 NOTES; 本轮无 Phase-9 multi-VM 矩阵重跑 | 隔离门定向有；同宿主多实例验收未本轮重跑 |
| A7 Per-VM kernel ctx; 2-VM Mode A isolation before advertise multi | PARTIAL / fail-closed | **基本同意 PARTIAL** | baseline §14; historical F04-modea-isol/run.log; 本轮无新 Mode A 验收包 | 历史 F04 曾跑双 context；本轮未重验 admission 仍 SINGLE_CONTEXT fail-closed；Phase 8/9 未绿 |
| A8 Join/cordon/drain/gateway successor snapshot | PARTIAL | **同意 PARTIAL** | N05 NOTES+code; Q02 历史; **无** 本轮 live successor/STALE 格 | N05 代码桥存在，但引用证据未证跨进程 fanout（见缺口） |
| A9 Concurrency/backpressure; survival≠success | PARTIAL | **同意 PARTIAL**；诚实规则 **同意** | N01/N06/N07 consoles; F05/F10 诚实 FAIL | 定向预算/背压有；Phase-9 代表性并发 profile 未录 |

### 1.B Baseline “Minimum usable system” one-paragraph gate
| 项 | Grok裁决 | 你的裁决 | 证据路径 | 一句理由 |
|---|---|---|---|---|
| Minimum usable system | FAIL to claim / PARTIAL | **同意：不可宣称 usable** | baseline ~L237; F10 FAIL_g9; F05 harness ERROR | KVM 缺 remote；TCG 合同未绿；join/drain/Mode A 仍 PARTIAL |

### 1.C Phase 0–9 deliverable intent
| 项 | Grok裁决 | 你的裁决 | 证据路径 | 一句理由 |
|---|---|---|---|---|
| P0 Identity/canonical/IPC | PARTIAL | **同意 PARTIAL** | docs/specs/* dirty; 未做本轮 live 重审 | 规格脏树在；未独立重跑 foundation 验收 |
| P1 Unified per-VM node runtime | PARTIAL | **同意 PARTIAL；加强：F05 仍走 legacy master** | scripts/ci_dual_node.sh 启 wavevm_node_master; goal.txt「唯一生产路径=typed」 | F05 主证据路径违反 typed-only 口令 |
| P2 Membership + route | PARTIAL | **同意 PARTIAL** | N06 PASS directed | live successor gap 仍在 |
| P3 Memory consistency + baseline faults | PARTIAL | **同意 PARTIAL；加强：typed MEM_FAULT ENOTCONN** | 195252 NOTES: typed fail ret=-5/-107 → UDP fallback | RET 靠 UDP 回落，CLI master 无 V1 memory service |
| P4 QEMU/vCPU/device | PARTIAL | **同意 PARTIAL** | RET + FE death (port 2226 forward fail; q_alive=NO) | RET 有；FE 存活/清理合同未过 harness |
| P5 Placement/admission/lifecycle | PARTIAL | **同意 PARTIAL** | N01; ACTIVATION_DECIDED 缺口 | 同 A1 |
| P6 Multi-VM / same-host isolation | PARTIAL | **同意 PARTIAL** | N01/N04 | 矩阵未重跑 |
| P7 Dynamic member/gateway | PARTIAL | **同意 PARTIAL** | N05/Q02 | live STALE 未证 |
| P8 Per-VM kernel acceleration | PARTIAL / fail-closed | **同意 PARTIAL** | baseline §14; F04 历史 | 未闭隔离验收即不可广告 multi-context |
| P9 Minimum integration + acceptance matrix | FAIL to claim closed | **同意 FAIL / 未闭** | F10 MATRIX_RESULT=FAIL; F05 fence-only ERROR; MINIMUM_STATUS NOT_CLAIMED | Phase 9 明文要求的 KVM+remote、TCG 合同、lifecycle 格均未绿 |

### 1.D MUST-FIX worklist (MINIMUM_FIX_LIST_20261109.txt)
| 项 | Grok裁决 | 你的裁决 | 证据路径 | 一句理由 |
|---|---|---|---|---|
| N01 admission workspace | PASS directed | **同意 PASS directed**（限 serialize/fail-closed） | N01-admission-workspace/console.txt PASS busy=1; ctl_tool/main.c lease/BACKPRESSURE | 代码+oracle 对齐；非多槽独立 workspace（自承 limits OK） |
| N04 unique KVM FE | PASS directed gate | **同意 PASS directed** | N04 console-runtime-gate.txt PASS; wavevm_runtime_gate.c N04 reject | 异 PID 第二 FE 拒绝有证；完整唯一 FE 生命周期仍绑 F10 |
| N03 QUIESCE/SIGUSR1 | PASS directed | **同意 PASS directed**（证据偏薄） | N03 console.txt; node_runtime SIGUSR1 注册; agent QUIESCING ACK | 代码接线在；无 live dual-node QUIESCE soak；无留下 n03 二进制 |
| N02 coherent same-backing | PASS directed | **同意 PASS directed**（证明强度弱于 baseline 字面） | N02 console.txt unit PASS; wavevm-user-mem.c path-string equality | 缺/异 host/异 path 拒快路属实；**非** inode st_dev/st_ino 级同-backing |
| F05 fence/remote TCG | PARTIAL→RET-evidence; harness ERROR; NOT COMPLETE | **同意 PARTIAL / NOT COMPLETE**；**不同意** NOTES 标题「RET path CLOSED」若被读成 F05 CLOSED | 195252 master0 RET; f05_fence_only_result; NOTES-F05-RET-achieved-harness-ERROR.txt; NOTES_F05.txt **仍停在 19:27 RET incomplete（陈旧）** | RET 行真实；harness ERROR+overlap 195244+legacy 路径 → F05 未 COMPLETE；索引 NOTES 未同步 |
| N05 subscriber cross-proc | PASS directed | **部分不同意 → PARTIAL** | bridge.c 存在且 Makefile 链接；**memory_service.txt 仅 F07 同进程 EVID，无 0x0307/fanout**；无 test_n05* | 生产桥代码像修了 Codex 洞，但引用「定向证据」未覆盖跨进程 fanout；不得与 N01 同级 PASS |
| N06 listener budget | PASS directed | **同意 PASS directed** | N06 console.txt; authority_owner.txt PASS; owner_compile_route_plan refuse | >64 明确拒绝，无静默 clamp |
| N07 block READ budget | PASS directed | **同意 PASS directed** | N07 console winners=1 reserved=4096; block_service.c reserved_result_bytes | 执行前原子预占有证 |
| F10 KVM narrowed | login/SSH CLOSED; remote FAIL / second-host; NOT full PASS | **同意 remote FAIL / NOT full PASS**；**不同意「CLOSED for login/SSH」作为 F10/§1.1 收口措辞** | 183406 HONESTY+SUMMARY; NOTES_F10; fix-list「CLOSED_PENDING_SECOND_HOST」 | 子项 login 绿、矩阵 OVERALL FAIL；§1.1/Phase9 把 remote 绑在同一门上 → F10 仍 OPEN/PARTIAL |
| F01 / Extended | DEFERRED Extended; 不碰 | **同意**（未误把 Extended 当 Minimum） | goal.txt; fix-list §三; matrix cells_extended_opt_in | TCG guest login 正确踢出 Minimum |
| MINIMUM_COMPLETE | NOT_CLAIMED | **同意 NOT_CLAIMED；且不可签** | MINIMUM_STATUS_20261109.txt | Phase 9 未闭 |

---

## 2) Gaps Grok Bot missed or under-weighted

1. **N05 证据错配（重要）**  
   自审/清单写 PASS directed，但 `N05-subscriber-crossproc/memory_service.txt` 只有 F07 同进程 `EVID F07_*`，**零** `0x0307` / bridge fanout / 跨进程 STALE。无 `test_n05*`。应降为 **PARTIAL（代码在、跨进程 oracle 缺）**。

2. **F05 证据路径违反 goal typed-only**  
   `ci_dual_node.sh` 启 `wavevm_node_master` + stub planner `/tmp/wavevm-f05-run/wvm_ctl_plan`；goal/dirty 纲领要求 manifest/typed runtime 唯一生产路径、不保留旧 master/slave 独立入口。自审仅轻描「legacy CLI」，对 Minimum 收口权重不够。

3. **Typed MEM_FAULT 仍 ENOTCONN；RET 依赖 UDP 回落**  
   195252 NOTES 自承 typed MEM_FAULT fail → UDP MEM_READ。Phase 3/9「baseline fault / checked memory results」在生产 typed 服务上仍缺，不能只凭 UDP 切片宣称合同路径闭合。

4. **F05 索引 NOTES 陈旧**  
   `F05-fence-status/NOTES_F05.txt` 仍写 RET incomplete（19:27）；RET 成就只在 ART 内 NOTES。证据树自相矛盾，审计易误读。

5. **「RET path CLOSED」措辞过强**  
   ART NOTES 写 Remote VCPU_RUN RET path CLOSED，但同 ART：`q_alive=NO`、`remote=0`、`handoff=0`、vm.log 仅 3 行、ssh forward `tcp::2226` 失败、与 195244 overlap。RET 日志可采信为 **定向进展**，不是 F05/Phase9 闭合。

6. **VCPU_RUN 仍带 slave_id=4294967295**  
   master0 发送行仍 `-1` slave_id，却收到 RET。残留异常未进自审主表。

7. **Master 重建/二进制可复现性**  
   NOTES：logic_core master rebuild segfault → 回退；运行中依赖 `.f05fix-5s` 系二进制。源码 `WVM_COMMIT_SYNC_TIMEOUT_US=60s` 已改，但「可从脏树干净重建复现 RET」未证明。

8. **F10 / fix-list「CLOSED for login/SSH」与 Phase 9 门不一致**  
   自审 A4 较诚实（PARTIAL）；fix-list/NOTES_F10「CLOSED…」易被读成 F10 半闭合。交叉审计要求统一为 **PARTIAL until remote attribution**。

9. **ACTIVATION_DECIDED 冷启动**  
   自审提到 thin，但 goal 把它升为 Minimum 硬项；MUST-FIX 链（N01…F10）**未单列**该收口项 → 工作序缺口。

10. **N02 同-backing 证明强度**  
    自审 limits 有 path-string；baseline §16 要求 actual shared-backing proof。交叉审计标为定向 PASS、**生产级证明仍欠**。

11. **Mode A：历史 F04 已 multi-context=64，与「fail-closed 直至验收」叙事需对齐**  
    `F04-modea-isol` 显示 max contexts 64 且 dual bind PASS；若生产仍广告/允许 multi 而无本轮验收包，存在「口头 fail-closed / 模块已 multi」张力，自审未点明。

---

## 3) Can MINIMUM_COMPLETE be signed?
**NO.**

Reasons (any one blocks; several apply):
- Phase 9 KVM cells: MATRIX_RESULT=FAIL (`FAIL_g9_remote_attribution`); remote_vcpu=0 remote_mem=0 on flat+fractal.
- Phase 9 TCG contract: fence-only harness ERROR (FE dead); not a clean acceptance PASS despite RET log line.
- §1.1 durable activation / coordinator cold-start replay: not evidenced this tree.
- N05 cross-proc invalidate: not evidenced by cited oracle.
- F05 still on legacy master path + typed memory service hole.
- Grok correctly set MINIMUM_COMPLETE=NOT_CLAIMED — **agree; do not upgrade**.

F01 correctly left as Extended — **no scope error there**.

---

## 4) Short punch-list to close Minimum

1. **F05 harness hygiene**: 单跑、无 overlap；FE 存活至 poll；清 port 2226；更新 `NOTES_F05.txt`；目标 fence-only harness PASS **且** 保留 RET+guest_vcpu+mem 证据。  
2. **F05/P1/P3 production path**: 把跨机 TCG 合同迁到 **typed node_runtime + V1 memory service**（消 ENOTCONN/UDP-only）；淘汰收口证据对 `wavevm_node_master` / stub planner 的依赖。  
3. **F10 remote attribution**: 第二主机（或合法 remote helper）下重跑 flat/fractal KVM；remote_vcpu/mem>0；拒 force_local 冒充；MATRIX 真 PASS。  
4. **N05 真定向/oracle**: 测 ctl bridge → 0x0307 → runtime global invalidate / STALE；替换仅 F07 同进程 console。  
5. **ACTIVATION_DECIDED 冷启动 live**: 持久化激活决策 → kill/restart coordinator → replay/对账/补偿；写入 MUST-FIX 或 Phase-9 格。  
6. **Phase 9 验收包补齐**: Mode B multi-VM/同宿主隔离重跑；join/cordon/drain/successor snapshot live；代表性并发 profile；Mode A 二VM 隔离验收或保持可证 SINGLE_CONTEXT 拒绝。  
7. **可复现构建**: 自源码干净重建 master/qemu/slave，去掉不可复现 binary-patch 依赖后再采证。  
8. **措辞收紧**: fix-list/NOTES 去掉 F10「CLOSED for login/SSH」、F05「RET path CLOSED」类易误读闭合语；统一 PARTIAL until Phase-9 cell green。  
9. **仍禁止**: MINIMUM_COMPLETE、F01/Extended 开工、commit/push（除非 Joe 另开）。

---

## 5) Evidence paths actually opened (sample)
- `goal.txt`, `docs/wavevm-refactor-roadmap.md` (§1.1, Phases 0–9/10), `docs/wavevm-architecture-baseline.md` (Minimum usable, §14, §16)
- `audit-evidence/MINIMUM_FIX_LIST_20261109.txt`
- `audit-evidence/fix-blockers-20261109/MINIMUM_GAP_SELF_AUDIT_DIRTY_CHARTER_20261109-1957.txt`
- `…/N01-admission-workspace/{NOTES,console}`, `N02…`, `N03…`, `N04…`, `N05…/{NOTES,memory_service}`, `N06…`, `N07…`
- `…/F05-fence-status/NOTES_F05.txt`, `…/F05-cross-host/dual-node-tcg-20261109-195252/{master0.log,f05_fence_only_result,vm.log,NOTES-*,b-side-excerpt/*}`, `console-node-a.txt`
- `…/F10-kvm-narrowed/{NOTES_F10,LIVE_SUMMARY,flat_kvm.*,fractal_kvm.*,live-matrix-20261109-183406/...}`
- Production greps: `ctl_tool/main.c`, `wavevm_runtime_gate.c`, `wavevm-user-mem.c`, `block_service.c`, `subscriber_invalidate_bridge.c`, `admission_authority_owner.c`, `ci_dual_node.sh`, `main_wrapper.c` COMMIT timeout

---

## 6) One-line bottom line for Grok Bot agent
Independent cross-audit **broadly agrees** your PARTIAL/NOT_CLAIMED snapshot and Extended deferral of F01, but **downgrades N05 to PARTIAL (wrong oracle)**, **rejects F10/F05 “CLOSED” wording**, and **flags F05 legacy/typed-memory/ACTIVATION_DECIDED/rebuild gaps** as under-weighted — **MINIMUM_COMPLETE still cannot be signed**.

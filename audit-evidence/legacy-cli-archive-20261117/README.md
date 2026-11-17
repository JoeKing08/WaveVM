# Legacy independent CLI archive — 2026-11-17

Timezone: Asia/Shanghai (CST, UTC+8)

This archive is the rollback kit for removing the *independent leftover
entry only*: standalone `wavevm_node_master` / `wavevm_node_slave`
binaries, their build targets (`make legacy-cli`, `legacy-master`,
`slave_daemon/Makefile_Legacy`, `master_core/Makefile_User`), and the
`#ifdef WAVEVM_MASTER_LEGACY_CLI` / `#ifdef WAVEVM_SLAVE_LEGACY_CLI`
startup gates (`WAVEVM_ALLOW_LEGACY_CLI`).

Shared production sources were **not** deleted:
`master_core/main_wrapper.c`, `master_core/logic_core.c`,
`slave_daemon/slave_hybrid.c` and friends remain, because official
`wavevm_node_runtime` still compiles them. The typed MEM_FAULT →
UDP / logic_core fallback was not removed.

This cut does not close F05, F10, Phase 1, Phase 9, or MINIMUM_COMPLETE.

## Contents

- `binaries/` — standalone CLIs and nearby leftover copies, plus the
  `master_legacy_cli.o` / `slave_hybrid_legacy.o` objects used to link them.
- `SHA256SUMS.txt` — hashes of those files at archive time (paths are
  the pre-removal source paths).
- `makefiles/` — copies of the official and leftover Makefiles just
  before this cut.
- `excised-source/` — the exact `#ifdef` standalone-main blocks taken
  out of `main_wrapper.c` (lines 3228–3794) and `slave_hybrid.c`
  (lines 5914–6057) on this dirty tree.

## How to restore (if a later cut goes wrong)

Prefer `git` rollback to the commit that introduced this archive, if
that commit still exists and has not been rewritten:

    git switch -c restore-legacy-cli <that-commit>
    # or inspect files from that commit without changing HEAD

To restore manually from this directory onto a tree that no longer has
the independent CLI:

1. Copy the makefile fragments back:
   - `makefiles/top-Makefile` → repo `Makefile` (or re-add only the
     `legacy-cli` target if the official `all` / `runtime` / `ctl`
     rules have since changed).
   - `makefiles/node_runtime.Makefile` legacy-master rules back into
     `node_runtime/Makefile` (keep official `all` building
     `wavevm_node_runtime` without `-DWAVEVM_MASTER_LEGACY_CLI`).
   - `makefiles/slave_daemon.Makefile_Legacy` → `slave_daemon/Makefile_Legacy`
   - `makefiles/master_core.Makefile_User` → `master_core/Makefile_User`
2. Append the excised blocks to the ends of the shared sources, after
   the last official/shared function and before EOF:
   - `excised-source/main_wrapper.c.WAVEVM_MASTER_LEGACY_CLI-block.c`
     → end of `master_core/main_wrapper.c`
   - `excised-source/slave_hybrid.c.WAVEVM_SLAVE_LEGACY_CLI-block.c`
     → end of `slave_daemon/slave_hybrid.c`
   Official `wavevm_node_runtime` compiles those files *without* the
   `WAVEVM_*_LEGACY_CLI` defines, so the restored `#ifdef` blocks stay
   out of the official binary unless you also rebuild `legacy-cli`.
3. `make legacy-cli` then produces `master_core/wavevm_node_master`
   and `slave_daemon/wavevm_node_slave`. Those binaries still required
   `WAVEVM_ALLOW_LEGACY_CLI=1` at the time of this archive.
4. Optionally compare restored binaries against `binaries/` using
   `SHA256SUMS.txt`. Do not treat a restored legacy CLI as official
   acceptance; official scoring remains `scripts/wavevm`.

Do not copy secrets into this archive. Official entry after this cut:
`scripts/wavevm` → `wvm_ctl serve` + `wavevm_node_runtime agent`.

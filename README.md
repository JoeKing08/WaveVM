# WaveVM

Official production entry is the typed control path:

- `ctl_tool/wvm_ctl` — cluster control plane (`wvm_ctl serve`)
- `wavevm_node_runtime` — unified per-VM node runtime (`wavevm_node_runtime agent`)
- `scripts/wavevm` — official way to start, smoke, and stop that path

Independent `wavevm_node_master` / `wavevm_node_slave` CLIs were removed as a
startable entry. Shared sources still compile into official `wavevm_node_runtime`.
Official tests must not set `WAVEVM_ALLOW_LEGACY_CLI`. `scripts/ci_dual_node.sh`
is a stub and is not official acceptance (it exits 78 if invoked).

## Start / smoke

```sh
make
./scripts/wavevm smoke --state-dir /tmp/wavevm-official-smoke
# long-running control path:
./scripts/wavevm start --state-dir /tmp/wavevm-official
./scripts/wavevm status --state-dir /tmp/wavevm-official
./scripts/wavevm stop --state-dir /tmp/wavevm-official
```

Default smoke is same-host Mode B / require-tcg. When the in-tree QEMU
helper is present it is used so CREATE can reach RUNNING; `--stub` forces
the session-fd stub, which on this tree stays COMMITTED/IN_PROGRESS.
The smoke proves prepare→activate→commit→RUNNING through `wvm_ctl` and
`wavevm_node_runtime`.
It does not claim F05/F10/A4 closed, guest OS login, or Minimum complete.
The typed runtime gate is not flipped by the official entry script.

## Official cross-host acceptance

Use the same official entry. Do not use `scripts/ci_dual_node.sh` or
`WAVEVM_ALLOW_LEGACY_CLI` for scoring.

```sh
# Node A and node B, same cell and topology on both sides:
./scripts/wavevm a4  --role node-a --route-topology fractal
./scripts/wavevm a4  --role node-b --route-topology fractal
# Official F10 is the same KVM login/SSH + remote RET + official remote mem cell:
./scripts/wavevm f10 --role node-a --route-topology flat
# Official bounded TCG fence contract (no TCG guest login gate):
./scripts/wavevm f05 --role node-a --route-topology fractal
# Start no guests:
./scripts/wavevm f05 --role node-a --route-topology fractal --dry-check
```

These invocations do not close F05, F10, Phase 1, Phase 9, or MINIMUM_COMPLETE.
The independent master/slave CLI was removed; official entry is `scripts/wavevm`.

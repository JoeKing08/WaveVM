# WaveVM: GitHub Actions + Tailscale

Official production entry is `scripts/wavevm`, which starts `ctl_tool/wvm_ctl`
and `wavevm_node_runtime`. Independent `wavevm_node_master` / `wavevm_node_slave`
are not a supported production entry.

## 1. Enable the repository workflow

Workflow file:

- `.github/workflows/wavevm-ci.yml`

How to run it:

1. Open the GitHub repository page -> `Actions`.
2. Select `wavevm-ci`.
3. Click `Run workflow`.
4. Leave `run_typed_smoke=true` to exercise the official typed entry.

Outputs:

- `build`: compile official binaries `wavevm_node_runtime` and `wvm_ctl`.
- `typed-entry-smoke`: same-host official entry smoke (`scripts/wavevm smoke`).

Do not upload or advertise `wavevm_node_master` / `wavevm_node_slave` as the
supported production artifacts. Those independent CLIs were removed; official
entry is `scripts/wavevm`.

## 2. GitHub Secrets for later Tailscale work

If a later job should join a Tailscale network, prepare:

- `TS_AUTHKEY`: Tailscale auth key (reusable + short lifetime recommended).
- `TS_TAILNET`: optional tailnet name.

The current `wavevm-ci` workflow does not log into Tailscale by default.

## 3. Remote instances (for later cross-host work)

Cross-host F05/F10 official cells are a separate proof and are not this
typed-entry cutover. Prepare Ubuntu 22.04/24.04 hosts only when that work
resumes:

1. At least 2 vCPU and 4GB RAM.
2. UDP egress, Tailscale installed.
3. `tailscale up --authkey <key> --ssh`
4. Record each host's Tailscale IP.

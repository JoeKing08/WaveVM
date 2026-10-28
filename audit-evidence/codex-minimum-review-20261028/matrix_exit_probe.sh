#!/usr/bin/env bash
set -euo pipefail
repo_root=/workspaces/WaveVM
out_dir=$(mktemp -d /tmp/wavevm-matrix-exit-audit.XXXXXX)
summary="$out_dir/SUMMARY.txt"
have_kvm=1
pass=0 fail=0 skip=0 blocked=0
ran=()
declare -A CELL_TOPO=([flat_tcg]=flat)
declare -A CELL_BACKEND=([flat_tcg]=require-tcg)
declare -A CELL_ACCEL=([flat_tcg]=disabled)
# Model a cell that writes PASS before its cleanup hangs until timeout.
timeout() {
    printf '%s\n' 'OVERALL=PASS' >"$out_dir/cells/flat_tcg/result.txt"
    return 124
}
source <(awk '/^run_cell\(\) \{/ {started=1} started {print} started && /^\}$/ {exit}' \
    "$repo_root/tests/e2e/test_guest_minimum_matrix.sh")
run_cell flat_tcg
cat "$out_dir/flat_tcg.status"
printf 'matrix_counters: pass=%d fail=%d\n' "$pass" "$fail"

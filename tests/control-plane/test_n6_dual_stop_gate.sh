#!/usr/bin/env bash
# N6: isolated dual STOP aggregator — first fail + second ok must FAIL the cell.
set -euo pipefail
evid=$(mktemp -d /tmp/wavevm-n1n6-dual-XXXX)
mkdir -p "$evid"
printf 'cleanup_ok=0\nstop=status=6\nvm_id=1\n' >"$evid/cleanup.ok.vm1"
printf 'cleanup_ok=1\nstop=status=0 recorded_state=17\nvm_id=2\n' >"$evid/cleanup.ok.vm2"
printf 'status=6\n' >"$evid/stop_result.vm1.txt"
printf 'status=0 recorded_state=17\n' >"$evid/stop_result.vm2.txt"
_dual_stop_fail=0
if ! grep -q '^cleanup_ok=1' "$evid/cleanup.ok.vm1" 2>/dev/null; then
  _dual_stop_fail=1
fi
if ! grep -q '^cleanup_ok=1' "$evid/cleanup.ok.vm2" 2>/dev/null; then
  _dual_stop_fail=1
fi
if [[ $_dual_stop_fail -eq 0 ]]; then
  echo "N6 gate incorrectly passed when vm1 cleanup_ok=0" >&2
  exit 1
fi
echo "N6_DUAL_STOP_GATE first_fail_detected=PASS evid=$evid"
# Both ok -> pass
printf 'cleanup_ok=1\n' >"$evid/cleanup.ok.vm1"
_dual_stop_fail=0
grep -q '^cleanup_ok=1' "$evid/cleanup.ok.vm1" || _dual_stop_fail=1
grep -q '^cleanup_ok=1' "$evid/cleanup.ok.vm2" || _dual_stop_fail=1
[[ $_dual_stop_fail -eq 0 ]] || { echo "both-ok should pass" >&2; exit 1; }
echo "N6_DUAL_STOP_GATE both_ok=PASS"
echo "N6_DUAL_STOP_GATE: PASS"

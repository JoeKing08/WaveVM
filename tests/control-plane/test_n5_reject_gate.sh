#!/usr/bin/env bash
# N5: isolated gate — empty / status=14 / status=999 must FAIL; status=6 PASS.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out=/tmp/wavevm-n1n6-20261024/n5_reject_gate.txt
mkdir -p "$(dirname "$out")"
: >"$out"

expect_list=6
check_one() {
  local create_out=$1
  local want_pass=$2
  local got_status=""
  local ok_reject=0
  if [[ "$create_out" =~ status=([0-9]+) ]]; then
    got_status="${BASH_REMATCH[1]}"
  fi
  if [[ -n "$got_status" ]]; then
    IFS=',' read -ra _exp <<< "$expect_list"
    for _e in "${_exp[@]}"; do
      if [[ "$got_status" == "$_e" ]]; then ok_reject=1; break; fi
    done
  fi
  if [[ -z "$create_out" || -z "$got_status" || "$got_status" == "14" ]]; then
    ok_reject=0
  fi
  if [[ $ok_reject -eq 1 ]]; then
    echo "CASE '$create_out' -> PASS_REJECT" | tee -a "$out"
    [[ "$want_pass" == "1" ]] || { echo "unexpected PASS" >&2; return 1; }
  else
    echo "CASE '${create_out:-<empty>}' -> FAIL_REJECT" | tee -a "$out"
    [[ "$want_pass" == "0" ]] || { echo "unexpected FAIL" >&2; return 1; }
  fi
}

check_one "" 0
check_one "status=14 recorded_state=10" 0
check_one "status=999" 0
check_one "status=6 recorded_state=0" 1
check_one "status=0 recorded_state=16" 0  # success is not reject (handled elsewhere)
# status=0 with EXPECT_REJECT is separate path; gate here only for non-success shapes
# For status=0, got_status=0 not in {6} so FAIL_REJECT — correct for this isolated gate.
echo "N5_REJECT_GATE: PASS" | tee -a "$out"

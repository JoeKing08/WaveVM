#!/usr/bin/env bash
set -uo pipefail
repo=/workspaces/WaveVM
evid=/workspaces/WaveVM/audit-evidence/fix-blockers-20261028/s1s4-membership
mkdir -p "$evid"
cd "$repo/tests/control-plane"
export PATH="${HOME}/.local/bin:/home/box/.local/bin:${PATH}"
summary="$evid/SUMMARY.txt"
: > "$summary"
echo "tip=$(cd $repo && git rev-parse HEAD)" | tee -a "$summary"
echo "started=$(date)" | tee -a "$summary"
# Real membership/cordon/drain/gateway — NOT g8 vcpu drain unit
tests=(
  test_cordon_drain_compute.sh
  test_gateway_drain.sh
  test_gateway_drain_prepare_commit.sh
  test_gateway_drain_successor.sh
  test_membership_drain_transport.sh
  test_membership_coordinator.sh
  test_membership_route.sh
  test_membership_controller.sh
  test_create_vm_dual_mode_b.sh
  test_same_host_dual_agent_live.sh
)
# optional placement/spread if present
for extra in test_placement_spread.sh test_physical_host_aggregate.sh; do
  [[ -f $extra ]] && tests+=("$extra")
done
# also check scripts/
for extra in "$repo/scripts/test_placement_spread.sh"; do
  [[ -f $extra ]] && tests+=("$extra")
done

fail=0
pass=0
for t in "${tests[@]}"; do
  base=$(basename "$t" .sh)
  log="$evid/${base}.log"
  echo "=== RUN $t ===" | tee -a "$summary"
  if [[ "$t" == /* ]]; then
    cmd=(bash "$t")
  else
    cmd=(bash "./$t")
  fi
  set +e
  timeout 300 "${cmd[@]}" >"$log" 2>&1
  rc=$?
  set -e
  echo "rc=$rc" | tee -a "$evid/${base}.rc" | tee -a "$summary"
  if [[ $rc -eq 0 ]]; then
    echo "PASS $base" | tee -a "$summary"
    pass=$((pass+1))
  else
    echo "FAIL $base rc=$rc" | tee -a "$summary"
    tail -40 "$log" | tee -a "$summary"
    fail=$((fail+1))
  fi
done
echo "pass=$pass fail=$fail finished=$(date)" | tee -a "$summary"
exit $fail

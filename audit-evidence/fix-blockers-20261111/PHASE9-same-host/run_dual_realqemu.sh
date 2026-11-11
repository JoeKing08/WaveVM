#!/usr/bin/env bash
set -uo pipefail
ROOT=/workspaces/WaveVM
EV=$ROOT/audit-evidence/fix-blockers-20261111/PHASE9-same-host
cd "$ROOT"
LOG=$EV/dual_realqemu_roll.log
echo "DUAL REALQEMU START $(date '+%F %T %Z')" | tee -a "$LOG"
echo "===== START create_vm_dual_mode_b $(date '+%F %T %Z') =====" | tee -a "$LOG"
set +e
timeout --signal=TERM --kill-after=20s 420s \
  bash tests/control-plane/test_create_vm_dual_mode_b.sh \
  >"$EV/create_vm_dual_mode_b.stdout" \
  2>"$EV/create_vm_dual_mode_b.stderr"
rc=$?
set -e
echo "rc=$rc" >"$EV/create_vm_dual_mode_b.rc"
echo "===== create_vm_dual_mode_b rc=$rc $(date '+%H:%M:%S') =====" | tee -a "$LOG"
echo "===== START create_vm_dual_mode_a $(date '+%F %T %Z') =====" | tee -a "$LOG"
set +e
timeout --signal=TERM --kill-after=20s 420s \
  bash tests/control-plane/test_create_vm_dual_mode_a.sh \
  >"$EV/create_vm_dual_mode_a.stdout" \
  2>"$EV/create_vm_dual_mode_a.stderr"
rc=$?
set -e
echo "rc=$rc" >"$EV/create_vm_dual_mode_a.rc"
echo "===== create_vm_dual_mode_a rc=$rc $(date '+%H:%M:%S') =====" | tee -a "$LOG"
echo "DUAL REALQEMU DONE $(date '+%F %T %Z')" | tee -a "$LOG"

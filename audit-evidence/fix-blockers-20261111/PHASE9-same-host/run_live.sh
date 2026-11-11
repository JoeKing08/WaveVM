#!/usr/bin/env bash
set -uo pipefail
ROOT=/workspaces/WaveVM
EV=$ROOT/audit-evidence/fix-blockers-20261111/PHASE9-same-host
mkdir -p "$EV"
cd "$ROOT"
LIVELOG="$EV/live_roll.log"
echo "LIVE START $(date '+%F %T %Z')" | tee -a "$LIVELOG"

run_one() {
  local name="$1"
  local script="$2"
  local timeout_s="${3:-300}"
  echo "===== START $name $(date '+%F %T %Z') =====" | tee -a "$LIVELOG"
  set +e
  timeout --signal=TERM --kill-after=20s "${timeout_s}"s bash "$script" \
    >"$EV/${name}.stdout" 2>"$EV/${name}.stderr"
  local rc=$?
  set -e
  echo "rc=$rc" >"$EV/${name}.rc"
  if [[ $rc -eq 0 ]]; then
    echo "===== PASS $name rc=0 $(date '+%H:%M:%S') =====" | tee -a "$LIVELOG"
  elif [[ $rc -eq 124 || $rc -eq 137 ]]; then
    echo "===== TIMEOUT $name rc=$rc $(date '+%H:%M:%S') =====" | tee -a "$LIVELOG"
  else
    echo "===== FAIL $name rc=$rc $(date '+%H:%M:%S') =====" | tee -a "$LIVELOG"
  fi
  tail -n 40 "$EV/${name}.stdout" >>"$LIVELOG" 2>/dev/null || true
  if [[ -s "$EV/${name}.stderr" ]]; then
    echo "----- stderr tail $name -----" >>"$LIVELOG"
    tail -n 50 "$EV/${name}.stderr" >>"$LIVELOG"
  fi
}

run_one gateway_drain tests/control-plane/test_gateway_drain.sh 360
run_one gateway_drain_prepare_commit tests/control-plane/test_gateway_drain_prepare_commit.sh 420
run_one cordon_drain_compute tests/control-plane/test_cordon_drain_compute.sh 360
run_one create_vm_dual_mode_b tests/control-plane/test_create_vm_dual_mode_b.sh 420
run_one create_vm_dual_mode_a tests/control-plane/test_create_vm_dual_mode_a.sh 420

echo "===== START mode_a_two_vm_isolation $(date '+%F %T %Z') =====" | tee -a "$LIVELOG"
MA_DIR="$EV/mode_a_two_vm"
mkdir -p "$MA_DIR"
{
  echo "date=$(date '+%F %T %Z')"
  ls -l /dev/wavevm 2>&1 || true
  if [[ ! -e /dev/wavevm ]]; then
    echo "NO_DEVICE /dev/wavevm"
    echo "rc=blocked" >"$EV/mode_a_two_vm_isolation.rc"
    echo "===== BLOCKED mode_a_two_vm_isolation no /dev/wavevm =====" | tee -a "$LIVELOG"
  else
    make -C tests/mode-a test_two_vm_isolation test_two_vm_context_bind 2>"$MA_DIR/make.stderr"
    make_rc=$?
    echo "make_rc=$make_rc"
    if [[ $make_rc -ne 0 ]]; then
      echo "rc=compile_fail" >"$EV/mode_a_two_vm_isolation.rc"
      echo "===== FAIL mode_a_two_vm_isolation compile =====" | tee -a "$LIVELOG"
    else
      if /workspaces/WaveVM/tests/mode-a/test_two_vm_isolation >"$MA_DIR/iso.stdout" 2>"$MA_DIR/iso.stderr"; then
        echo "rc=0" >"$EV/mode_a_two_vm_isolation.rc"
        echo "===== PASS mode_a_two_vm_isolation =====" | tee -a "$LIVELOG"
      else
        iso_rc=$?
        echo "direct_rc=$iso_rc"
        cat "$MA_DIR/iso.stderr" || true
        if sudo -n true >/dev/null 2>"$MA_DIR/sudo_n.err"; then
          if sudo -n /workspaces/WaveVM/tests/mode-a/test_two_vm_isolation >"$MA_DIR/iso.stdout" 2>"$MA_DIR/iso.stderr"; then
            echo "rc=0 sudo-n" >"$EV/mode_a_two_vm_isolation.rc"
            echo "===== PASS mode_a_two_vm_isolation (sudo -n) =====" | tee -a "$LIVELOG"
          else
            echo "rc=$?" >"$EV/mode_a_two_vm_isolation.rc"
            echo "===== FAIL mode_a_two_vm_isolation sudo-n =====" | tee -a "$LIVELOG"
          fi
        else
          echo "sudo -n not available; not prompting for password"
          echo "rc=blocked_sudo" >"$EV/mode_a_two_vm_isolation.rc"
          echo "===== BLOCKED mode_a_two_vm_isolation sudo password =====" | tee -a "$LIVELOG"
        fi
      fi
    fi
  fi
} >"$EV/mode_a_two_vm_isolation.stdout" 2>"$EV/mode_a_two_vm_isolation.stderr"

if [[ -x /workspaces/WaveVM/tests/mode-a/test_two_vm_context_bind && -e /dev/wavevm ]]; then
  /workspaces/WaveVM/tests/mode-a/test_two_vm_context_bind \
    >"$MA_DIR/bind.stdout" 2>"$MA_DIR/bind.stderr" || true
fi

echo "LIVE DONE $(date '+%F %T %Z')" | tee -a "$LIVELOG"

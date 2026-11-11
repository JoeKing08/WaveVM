#!/usr/bin/env bash
set -uo pipefail
ROOT=/workspaces/WaveVM
EV=$ROOT/audit-evidence/fix-blockers-20261111/PHASE9-same-host
cd "$ROOT"
LOG=$EV/remaining_roll.log
echo "REMAINING START $(date '+%F %T %Z')" | tee -a "$LOG"

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
tail -n 30 "$EV/create_vm_dual_mode_a.stdout" >>"$LOG" 2>/dev/null || true
tail -n 20 "$EV/create_vm_dual_mode_a.stderr" >>"$LOG" 2>/dev/null || true

echo "===== START mode_a_two_vm_isolation $(date '+%F %T %Z') =====" | tee -a "$LOG"
MA=$EV/mode_a_two_vm
mkdir -p "$MA"
{
  date '+%F %T %Z'
  ls -l /dev/wavevm || echo "NO_DEVICE"
} >"$EV/mode_a_two_vm_isolation.stdout" 2>"$EV/mode_a_two_vm_isolation.stderr"
if [[ ! -e /dev/wavevm ]]; then
  echo "rc=blocked" >"$EV/mode_a_two_vm_isolation.rc"
  echo "===== BLOCKED no /dev/wavevm =====" | tee -a "$LOG"
else
  set +e
  make -C tests/mode-a test_two_vm_isolation test_two_vm_context_bind \
    >"$MA/make.stdout" 2>"$MA/make.stderr"
  mrc=$?
  set -e
  echo "make_rc=$mrc" >>"$EV/mode_a_two_vm_isolation.stdout"
  if [[ $mrc -ne 0 ]]; then
    echo "rc=compile_fail" >"$EV/mode_a_two_vm_isolation.rc"
    echo "===== FAIL compile mode-a tests =====" | tee -a "$LOG"
    cat "$MA/make.stderr" >>"$LOG"
  else
    set +e
    tests/mode-a/test_two_vm_isolation >"$MA/iso.stdout" 2>"$MA/iso.stderr"
    irc=$?
    set -e
    echo "direct_rc=$irc" >>"$EV/mode_a_two_vm_isolation.stdout"
    cat "$MA/iso.stdout" >>"$EV/mode_a_two_vm_isolation.stdout"
    cat "$MA/iso.stderr" >>"$EV/mode_a_two_vm_isolation.stderr"
    if [[ $irc -eq 0 ]]; then
      echo "rc=0" >"$EV/mode_a_two_vm_isolation.rc"
      echo "===== PASS mode_a_two_vm_isolation =====" | tee -a "$LOG"
    else
      set +e
      sudo -n true >/dev/null 2>"$MA/sudo_n.err"
      suc=$?
      set -e
      if [[ $suc -eq 0 ]]; then
        set +e
        sudo -n tests/mode-a/test_two_vm_isolation \
          >"$MA/iso.stdout" 2>"$MA/iso.stderr"
        irc=$?
        set -e
        echo "sudo_n_rc=$irc" >>"$EV/mode_a_two_vm_isolation.stdout"
        cat "$MA/iso.stdout" >>"$EV/mode_a_two_vm_isolation.stdout"
        cat "$MA/iso.stderr" >>"$EV/mode_a_two_vm_isolation.stderr"
        echo "rc=$irc" >"$EV/mode_a_two_vm_isolation.rc"
        echo "===== mode_a_two_vm_isolation sudo-n rc=$irc =====" | tee -a "$LOG"
      else
        echo "sudo -n unavailable; not prompting" \
          >>"$EV/mode_a_two_vm_isolation.stdout"
        echo "rc=blocked_sudo" >"$EV/mode_a_two_vm_isolation.rc"
        echo "===== BLOCKED mode_a_two_vm_isolation sudo =====" | tee -a "$LOG"
      fi
    fi
    if [[ -x tests/mode-a/test_two_vm_context_bind ]]; then
      set +e
      tests/mode-a/test_two_vm_context_bind \
        >"$MA/bind.stdout" 2>"$MA/bind.stderr"
      set -e
      echo "----- context_bind -----" >>"$EV/mode_a_two_vm_isolation.stdout"
      cat "$MA/bind.stdout" >>"$EV/mode_a_two_vm_isolation.stdout"
      cat "$MA/bind.stderr" >>"$EV/mode_a_two_vm_isolation.stderr"
    fi
  fi
fi

echo "REMAINING DONE $(date '+%F %T %Z')" | tee -a "$LOG"

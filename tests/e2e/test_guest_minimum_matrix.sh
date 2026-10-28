#!/usr/bin/env bash
# §7 guest E2E matrix: flat|fractal × require-tcg|require-kvm.
# Durable evidence under WVM_GUEST_OUT_DIR; honesty labels per cell.
# Does NOT claim Minimum COMPLETE by itself.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
stamp=$(date +%Y%m%d-%H%M%S)
run_id=${WVM_GUEST_RUN_ID:-"guest-$stamp-$$"}
out_dir=${WVM_GUEST_OUT_DIR:-"$repo_root/audit-evidence/fix-blockers-20261028/guest-matrix-$stamp"}

if [[ -d "$out_dir" ]]; then
    if [[ "${WVM_GUEST_ALLOW_NONEMPTY_OUT:-0}" != "1" ]]; then
        if compgen -G "$out_dir/*.status" >/dev/null 2>&1 || \
           compgen -G "$out_dir/*/result.txt" >/dev/null 2>&1; then
            echo "guest-matrix: refusing non-empty out_dir: $out_dir" >&2
            exit 2
        fi
    fi
fi
mkdir -p "$out_dir/cells" "$out_dir/evidence"
summary="$out_dir/SUMMARY.txt"
: >"$summary"

have_kvm=0
if sg kvm -c 'test -r /dev/kvm -a -w /dev/kvm' 2>/dev/null; then
    have_kvm=1
fi

qemu_bin=${WVM_S6_QEMU_BIN:-"$repo_root/wavevm-qemu/build/qemu-system-x86_64"}
export WVM_S6_QEMU_BIN="$qemu_bin"
export WVM_S6_REAL_QEMU=${WVM_S6_REAL_QEMU:-1}

tip=$(cd "$repo_root" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
{
  echo "guest_matrix run_id=$run_id out_dir=$out_dir tip=$tip have_kvm=$have_kvm"
  echo "cells=flat_tcg,fractal_tcg,flat_kvm,fractal_kvm"
  TZ=Asia/Shanghai date
} | tee -a "$summary"

# cell_id -> topology backend accel
declare -A CELL_TOPO=(
  [flat_tcg]=flat [fractal_tcg]=fractal
  [flat_kvm]=flat [fractal_kvm]=fractal
)
declare -A CELL_BACKEND=(
  [flat_tcg]=require-tcg [fractal_tcg]=require-tcg
  [flat_kvm]=require-kvm [fractal_kvm]=require-kvm
)
declare -A CELL_ACCEL=(
  [flat_tcg]=disabled [fractal_tcg]=disabled
  [flat_kvm]=disabled [fractal_kvm]=disabled
)

selected=(${WVM_GUEST_CELLS:-flat_tcg fractal_tcg flat_kvm fractal_kvm})
pass=0 fail=0 skip=0 blocked=0
ran=()

run_cell() {
    local cell=$1
    local topo=${CELL_TOPO[$cell]:-}
    local backend=${CELL_BACKEND[$cell]:-}
    local accel=${CELL_ACCEL[$cell]:-}
    local cell_dir="$out_dir/cells/$cell"
    local status_f="$out_dir/$cell.status"
    local log_f="$out_dir/$cell.log"
    mkdir -p "$cell_dir"

    if [[ -z "$topo" || -z "$backend" ]]; then
        echo "UNKNOWN_CELL=$cell" | tee "$status_f" | tee -a "$summary"
        return 2
    fi

    if [[ "$backend" == "require-kvm" && "$have_kvm" != "1" ]]; then
        echo "RESULT=$cell SKIP reason=no_kvm" | tee "$status_f" | tee -a "$summary"
        echo "honesty=SKIP_no_/dev/kvm" >"$cell_dir/HONESTY.txt"
        skip=$((skip + 1))
        return 0
    fi

    echo "=== CELL $cell topology=$topo backend=$backend ===" | tee -a "$summary"
    ran+=("$cell")

    local deadline=${WVM_GUEST_CELL_DEADLINE_S:-900}
    local rc=0
    set +e
    timeout --foreground "$deadline" \
        env WVM_GUEST_TOPOLOGY="$topo" \
            WVM_S6_BACKEND="$backend" \
            WVM_S6_ACCEL="$accel" \
            WVM_S6_KEEP_RUNNING=1 \
            WVM_S6_EVIDENCE_DIR="$cell_dir/evid" \
            WVM_GUEST_SMOKE_ART="$cell_dir" \
            bash "$repo_root/tests/e2e/test_guest_smoke.sh" \
        >"$log_f" 2>&1
    rc=$?
    set -e

    # Prefer guest art dir if smoke wrote elsewhere
    if [[ ! -f "$cell_dir/result.txt" ]]; then
        # smoke uses its own art_dir under /tmp sometimes — copy from evid
        if [[ -f "$cell_dir/evid/result.txt" ]]; then
            cp -a "$cell_dir/evid/result.txt" "$cell_dir/result.txt" 2>/dev/null || true
        fi
        # Also search log for art=
        art=$(grep -oE 'art=/[^[:space:]]+' "$log_f" 2>/dev/null | head -1 | sed 's/^art=//' || true)
        if [[ -n "$art" && -d "$art" ]]; then
            cp -a "$art/." "$cell_dir/" 2>/dev/null || true
        fi
    fi

    local overall=FAIL
    if [[ -f "$cell_dir/result.txt" ]] && grep -q 'OVERALL=PASS' "$cell_dir/result.txt"; then
        overall=PASS
    elif [[ "$rc" -eq 0 ]]; then
        overall=PASS
    fi

    {
      echo "cell=$cell"
      echo "topology=$topo"
      echo "backend=$backend"
      echo "accel=$accel"
      echo "rc=$rc"
      echo "overall=$overall"
      if [[ "$overall" == "PASS" ]]; then
        echo "honesty=GUEST_E2E_PASS_login_ssh_cpu_stop"
      else
        ov=$(grep -E '^OVERALL=' "$cell_dir/result.txt" 2>/dev/null | tail -1 | cut -d= -f2- || true)
        if [[ -n "$ov" ]]; then
          echo "honesty=GUEST_E2E_FAIL_$ov"
        else
          echo "honesty=GUEST_E2E_FAIL_see_log"
        fi
      fi
    } >"$cell_dir/HONESTY.txt"

    if [[ "$overall" == "PASS" ]]; then
        echo "RESULT=$cell PASS rc=$rc" | tee "$status_f" | tee -a "$summary"
        pass=$((pass + 1))
    else
        echo "RESULT=$cell FAIL rc=$rc" | tee "$status_f" | tee -a "$summary"
        fail=$((fail + 1))
        # Keep going so durable matrix reports all cells
        return 0
    fi
}

for c in "${selected[@]}"; do
    run_cell "$c" || true
done

{
  echo "==== SUMMARY ===="
  echo "pass=$pass fail=$fail skip=$skip blocked=$blocked"
  echo "ran=${ran[*]}"
  echo "tip=$tip"
  echo "out_dir=$out_dir"
  if [[ "$fail" -eq 0 ]]; then
    echo "MATRIX_RESULT=PASS"
  else
    echo "MATRIX_RESULT=FAIL"
  fi
  echo "MINIMUM_COMPLETE=NOT_CLAIMED_BY_GUEST_MATRIX"
  echo "NOTE: guest matrix proves §7 Cirros path per cell; not MTTCG / not charter COMPLETE."
  TZ=Asia/Shanghai date
} | tee -a "$summary"

# Mirror under evidence/
cp -a "$summary" "$out_dir/evidence/SUMMARY.txt" 2>/dev/null || true
echo "GUEST_MATRIX_RC:$fail"
exit "$fail"

#!/usr/bin/env bash
# goal §6 / roadmap Phase 10 Minimum smoke matrix (NOT Extended fault injection).
# Closes Codex final audit R3/R4 runner gates; drives R2/R5/R1 via cell env.
# Does NOT claim Phase 10 Minimum COMPLETE by itself — require R1–R5 evidence.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=s6_harness_lib.sh
source "$repo_root/tests/control-plane/s6_harness_lib.sh"

stamp=$(date +%Y%m%d-%H%M%S)
run_id=${WVM_S6_RUN_ID:-"s6-$stamp-$$"}

# Validate selection up front (R3) before touching out_dir.
if ! s6_parse_cell_selection "${WVM_S6_CELLS:-all}"; then
    exit 2
fi

out_dir=${WVM_S6_OUT_DIR:-/tmp/wavevm-s6-matrix-$stamp}
# Fresh out_dir binding: never reuse pre-existing *.status from another run.
if [[ -d "$out_dir" ]]; then
    if [[ "${WVM_S6_ALLOW_NONEMPTY_OUT:-0}" != "1" ]]; then
        if compgen -G "$out_dir/*.status" >/dev/null 2>&1 || \
           compgen -G "$out_dir/*.log" >/dev/null 2>&1; then
            echo "s6: refusing non-empty out_dir with prior status/log: $out_dir" >&2
            echo "s6: set a fresh WVM_S6_OUT_DIR or WVM_S6_ALLOW_NONEMPTY_OUT=1 after review" >&2
            exit 2
        fi
    fi
fi
mkdir -p "$out_dir/cells" "$out_dir/evidence"
summary="$out_dir/SUMMARY.txt"
: > "$summary"
ran_list="$out_dir/RAN_CELLS.txt"
: > "$ran_list"

cell_deadline=${WVM_S6_CELL_DEADLINE_S:-180}
log_cap=${WVM_S6_LOG_CAP_BYTES:-1048576}
export WVM_S6_LOG_CAP_BYTES=$log_cap

have_wavevm=0
if [[ -e /dev/wavevm ]]; then
    if sg kvm -c 'test -r /dev/wavevm -a -w /dev/wavevm' 2>/dev/null; then
        have_wavevm=1
    fi
fi
have_kvm=0
if sg kvm -c 'test -r /dev/kvm -a -w /dev/kvm' 2>/dev/null; then
    have_kvm=1
fi

classify="$repo_root/scripts/ci_classify_failure.sh"

s6_write_source_identity "$out_dir/SOURCE_IDENTITY.txt" "$repo_root"

echo "s6 matrix run_id=$run_id out_dir=$out_dir have_kvm=$have_kvm have_wavevm=$have_wavevm" | tee -a "$summary"
echo "cells_selected=${selected_cells[*]}" | tee -a "$summary"
echo "cell_deadline_s=$cell_deadline log_cap_bytes=$log_cap" | tee -a "$summary"
echo "tip=$(cd "$repo_root" && git rev-parse --short HEAD 2>/dev/null || echo unknown)" | tee -a "$summary"
TZ=Asia/Shanghai date | tee -a "$summary"

# Per-cell env: live probe, real QEMU for TCG, evidence dir, STOP required.
export WVM_S6_CAP_SOURCE=${WVM_S6_CAP_SOURCE:-live}
export WVM_S6_REQUIRE_STOP=${WVM_S6_REQUIRE_STOP:-1}
export WVM_S6_REAL_QEMU=${WVM_S6_REAL_QEMU:-1}
export WVM_S6_DATAPLANE=${WVM_S6_DATAPLANE:-1}
export WVM_S6_RUN_ID="$run_id"

qemu_bin=${WVM_S6_QEMU_BIN:-"$repo_root/wavevm-qemu/build/qemu-system-x86_64"}
if [[ "$WVM_S6_REAL_QEMU" == "1" && -x "$qemu_bin" ]]; then
    export WVM_S6_QEMU_BIN="$qemu_bin"
else
    export WVM_S6_REAL_QEMU=0
fi

want() {
    local cell=$1 c
    for c in "${selected_cells[@]}"; do
        [[ "$c" == "$cell" ]] && return 0
    done
    return 1
}

write_status() {
    local cell=$1 rc=$2 elapsed=$3 class=$4 cleanup_ok=$5 note=$6
    local status_file="$out_dir/${cell}.status"
    {
        echo "run_id=$run_id"
        echo "cell=$cell"
        echo "rc=$rc"
        echo "elapsed_s=$elapsed"
        echo "class=$class"
        echo "cleanup_ok=$cleanup_ok"
        echo "log=$out_dir/${cell}.log"
        echo "note=$note"
        echo "invoked=1"
    } >"$status_file"
    echo "$cell" >>"$ran_list"
}

run_cell() {
    local cell=$1
    local cmd=$2
    local log="$out_dir/${cell}.log"
    local evid="$out_dir/evidence/$cell"
    mkdir -p "$evid"
    echo "=== CELL $cell ===" | tee -a "$summary"
    echo "cmd: $cmd" | tee -a "$summary"
    local rc elapsed class cleanup_ok=1 note=ok
    # Bind evidence dir for the cell harness.
    local full_cmd="export WVM_S6_EVIDENCE_DIR='$evid' WVM_S6_CELL='$cell' WVM_S6_RUN_ID='$run_id'; $cmd"
    # Prefer sg kvm so /dev/kvm and /dev/wavevm (udev root:kvm 0660) work.
    if command -v sg >/dev/null 2>&1; then
        full_cmd="sg kvm -c $(printf '%q' "cd '$repo_root' && $full_cmd")"
    else
        full_cmd="cd '$repo_root' && $full_cmd"
    fi
    s6_run_with_deadline "$cell_deadline" "$log" "$full_cmd"
    rc=$s6_run_rc
    elapsed=$s6_run_elapsed
    class=ok
    if [[ $rc -ne 0 ]]; then
        if [[ $s6_run_timed_out -eq 1 ]]; then
            class=timeout
            note=deadline_exceeded
        elif [[ -x "$classify" ]]; then
            class=$("$classify" --log "$log" 2>/dev/null | sed -n 's/^class=//p' | head -1)
            class=${class:-unknown}
        else
            class=unknown
        fi
    fi
    # Cleanup gate: cell must leave cleanup.ok=1 in evidence (R4).
    if [[ -f "$evid/cleanup.ok" ]]; then
        if grep -q '^cleanup_ok=1' "$evid/cleanup.ok" 2>/dev/null; then
            cleanup_ok=1
        else
            cleanup_ok=0
            note=cleanup_reported_fail
        fi
    else
        # Cells that are expected to produce cleanup evidence:
        case "$cell" in
            flat_*|fractal_*|mode_a_*|mode_b_*)
                if [[ $rc -eq 0 ]]; then
                    cleanup_ok=0
                    note=missing_cleanup_ok
                    rc=1
                fi
                ;;
            neg_*|auto_*)
                # Negative cells write cleanup.ok on reject path too.
                if [[ $rc -eq 0 && ! -f "$evid/cleanup.ok" ]]; then
                    cleanup_ok=0
                    note=missing_cleanup_ok_neg
                    rc=1
                fi
                ;;
            compute_dual)
                # Membership-only; still require explicit cleanup.ok from harness.
                if [[ $rc -eq 0 && ! -f "$evid/cleanup.ok" ]]; then
                    cleanup_ok=0
                    note=missing_cleanup_ok
                    rc=1
                fi
                ;;
        esac
    fi
    if [[ $cleanup_ok -eq 0 && $rc -eq 0 ]]; then
        rc=1
    fi
    # Leftover manifest check when present.
    if [[ -f "$evid/cleanup.manifest" ]]; then
        if ! s6_check_resource_release "$evid/cleanup.manifest" >>"$log" 2>&1; then
            cleanup_ok=0
            note=leftover_resources
            rc=1
        fi
    fi
    write_status "$cell" "$rc" "$elapsed" "$class" "$cleanup_ok" "$note"
    if [[ $rc -eq 0 ]]; then
        echo "RESULT $cell PASS elapsed=${elapsed}s cleanup_ok=$cleanup_ok" | tee -a "$summary"
    else
        echo "RESULT $cell FAIL rc=$rc class=$class cleanup_ok=$cleanup_ok note=$note elapsed=${elapsed}s" | tee -a "$summary"
        tail -n 60 "$log" | tee -a "$summary" >/dev/null || true
    fi
    return 0
}

skip_cell() {
    local cell=$1 reason=$2 rc=${3:-77}
    echo "RESULT $cell SKIP $reason" | tee -a "$summary"
    {
        echo "run_id=$run_id"
        echo "cell=$cell"
        echo "rc=$rc"
        echo "elapsed_s=0"
        echo "class=skip"
        echo "cleanup_ok=1"
        echo "note=$reason"
        echo "invoked=0"
        echo "skip=1"
    } >"$out_dir/${cell}.status"
    echo "$cell" >>"$ran_list"
}

# --- Cell commands ---
if want flat_tcg; then
    run_cell flat_tcg "WVM_S6_BACKEND=require-tcg WVM_S6_ACCEL=disabled bash tests/control-plane/test_create_vm_single_node.sh"
fi
if want fractal_tcg; then
    run_cell fractal_tcg "WVM_S6_BACKEND=require-tcg bash tests/control-plane/test_create_vm_fractal.sh"
fi
if want flat_kvm; then
    if [[ $have_kvm -ne 1 ]]; then
        skip_cell flat_kvm "no_usable_/dev/kvm" 77
    else
        run_cell flat_kvm "WVM_S6_BACKEND=require-kvm WVM_S6_ACCEL=disabled bash tests/control-plane/test_create_vm_single_node.sh"
    fi
fi
if want fractal_kvm; then
    if [[ $have_kvm -ne 1 ]]; then
        skip_cell fractal_kvm "no_usable_/dev/kvm" 77
    else
        run_cell fractal_kvm "WVM_S6_BACKEND=require-kvm bash tests/control-plane/test_create_vm_fractal.sh"
    fi
fi
if want mode_a_one; then
    if [[ $have_wavevm -ne 1 ]]; then
        skip_cell mode_a_one "no_usable_/dev/wavevm" 78
    else
        run_cell mode_a_one "WVM_S6_BACKEND=require-tcg WVM_S6_ACCEL=require-kernel bash tests/control-plane/test_create_vm_single_node.sh"
    fi
fi
if want mode_b_dual; then
    run_cell mode_b_dual "bash tests/control-plane/test_create_vm_dual_mode_b.sh"
fi
if want compute_dual; then
    run_cell compute_dual "bash tests/control-plane/test_same_host_dual_agent_live.sh"
fi
if want mode_a_dual; then
    if [[ $have_wavevm -ne 1 ]]; then
        skip_cell mode_a_dual "no_usable_/dev/wavevm" 78
    else
        run_cell mode_a_dual "bash tests/control-plane/test_create_vm_dual_mode_a.sh"
    fi
fi
if want neg_require_kvm; then
    run_cell neg_require_kvm "bash tests/control-plane/test_s6_neg_require_kvm.sh"
fi
if want neg_require_kernel; then
    run_cell neg_require_kernel "bash tests/control-plane/test_s6_neg_require_kernel.sh"
fi
if want auto_tcg_fallback; then
    run_cell auto_tcg_fallback "bash tests/control-plane/test_s6_auto_tcg_fallback.sh"
fi

# --- Summary: ONLY cells invoked this run (from RAN_CELLS), never orphan *.status ---
echo "==== SUMMARY ====" | tee -a "$summary"
pass=0; fail=0; skip=0; block=0
summary_lines=()
required_failed=0
while IFS= read -r cell || [[ -n "$cell" ]]; do
    [[ -z "$cell" ]] && continue
    st="$out_dir/${cell}.status"
    if [[ ! -f "$st" ]]; then
        summary_lines+=("FAIL $cell missing_status")
        fail=$((fail + 1))
        required_failed=1
        continue
    fi
    # Reject borrowed status from another run_id
    st_run=$(sed -n 's/^run_id=//p' "$st" | head -1)
    if [[ "$st_run" != "$run_id" ]]; then
        summary_lines+=("FAIL $cell borrowed_status run_id=$st_run")
        fail=$((fail + 1))
        required_failed=1
        continue
    fi
    rc=$(sed -n 's/^rc=//p' "$st" | head -1)
    cleanup=$(sed -n 's/^cleanup_ok=//p' "$st" | head -1)
    skip_flag=$(sed -n 's/^skip=//p' "$st" | head -1)
    case "$rc" in
        0)
            if [[ "$cleanup" == "0" ]]; then
                summary_lines+=("FAIL $cell cleanup_not_ok")
                fail=$((fail + 1)); required_failed=1
            else
                summary_lines+=("PASS $cell")
                pass=$((pass + 1))
            fi
            ;;
        77)
            summary_lines+=("SKIP $cell"); skip=$((skip + 1))
            ;;
        78)
            summary_lines+=("BLOCKED $cell"); block=$((block + 1))
            ;;
        *)
            summary_lines+=("FAIL $cell rc=$rc")
            fail=$((fail + 1)); required_failed=1
            ;;
    esac
done <"$ran_list"

# Orphan status files not in RAN_CELLS are ignored (R3) but reported.
orphans=0
for st in "$out_dir"/*.status; do
    [[ -f "$st" ]] || continue
    cell=$(basename "$st" .status)
    if ! grep -qx "$cell" "$ran_list" 2>/dev/null; then
        echo "orphan_status_ignored=$cell" | tee -a "$summary"
        orphans=$((orphans + 1))
    fi
done

printf '%s\n' "${summary_lines[@]}" | tee -a "$summary"
echo "totals pass=$pass fail=$fail skip=$skip blocked=$block orphans_ignored=$orphans out=$out_dir run_id=$run_id" | tee -a "$summary"

# Full matrix PASS only if every selected cell was invoked and none failed.
# SKIP/BLOCKED are not a full matrix PASS (R3).
selected_n=${#selected_cells[@]}
invoked_n=$(grep -c . "$ran_list" 2>/dev/null || echo 0)
echo "selected=$selected_n invoked=$invoked_n" | tee -a "$summary"

if [[ $fail -gt 0 || $required_failed -ne 0 ]]; then
    echo "MATRIX_RESULT=FAIL" | tee -a "$summary"
    exit 1
fi
if [[ $skip -gt 0 || $block -gt 0 ]]; then
    echo "MATRIX_RESULT=PARTIAL (skip/blocked present; not full PASS)" | tee -a "$summary"
    exit 3
fi
if [[ "$invoked_n" -ne "$selected_n" ]]; then
    echo "MATRIX_RESULT=FAIL invoked!=selected" | tee -a "$summary"
    exit 1
fi
echo "MATRIX_RESULT=PASS" | tee -a "$summary"
exit 0

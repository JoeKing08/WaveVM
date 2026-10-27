#!/usr/bin/env bash
# Helpers sourced by §6 cell scripts (create/neg/auto). Optional: no-op if not §6.
# Expects: tmpdir, repo_root, agent_pid, ctl_pid (when stopping).

s6_evidence_dir=${WVM_S6_EVIDENCE_DIR:-}
s6_require_stop=${WVM_S6_REQUIRE_STOP:-0}
s6_cap_source=${WVM_S6_CAP_SOURCE:-fixture}
s6_real_qemu=${WVM_S6_REAL_QEMU:-0}
s6_dataplane=${WVM_S6_DATAPLANE:-0}
s6_qemu_bin=${WVM_S6_QEMU_BIN:-}

s6_seed_extra_flags() {
    case "$s6_cap_source" in
        live) printf '%s' '--live-probe' ;;
        deny-kvm) printf '%s' '--deny-kvm' ;;
        deny-kernel) printf '%s' '--deny-kernel' ;;
        deny-kvm-dirty) printf '%s' '--deny-kvm-dirty' ;;
        fixture|*) printf '%s' '' ;;
    esac
}

s6_compile_seed_extra_srcs() {
    # Extra .c files needed when seed may call live probe.
    printf '%s' "$repo_root/common_include/wavevm_host_probe.c"
}

s6_select_tcg_helper() {
    # Sets WVM_TCG_QEMU_BIN. Real QEMU for TCG dataplane when requested.
    if [[ "$s6_real_qemu" == "1" && -n "$s6_qemu_bin" && -x "$s6_qemu_bin" ]]; then
        export WVM_TCG_QEMU_BIN="$s6_qemu_bin"
        # Uninstalled build tree needs an explicit -L datadir (BIOS etc.).
        if [[ -z "${WVM_TCG_QEMU_DATADIR:-}" ]]; then
            for cand in                 "$(dirname "$s6_qemu_bin")/pc-bios"                 "$repo_root/wavevm-qemu/pc-bios"                 "$repo_root/wavevm-qemu/build/pc-bios"; do
                if [[ -e "$cand/bios-256k.bin" ]]; then
                    export WVM_TCG_QEMU_DATADIR="$cand"
                    break
                fi
            done
        fi
        echo "s6: using real QEMU helper $WVM_TCG_QEMU_BIN datadir=${WVM_TCG_QEMU_DATADIR:-unset}" >&2
    else
        if [[ ! -x "${tmpdir}/tcg_helper_stub" ]]; then
            gcc -Wall -Wextra -Werror -std=c11 \
                "$repo_root/tests/control-plane/tcg_helper_stub.c" \
                -o "$tmpdir/tcg_helper_stub"
        fi
        export WVM_TCG_QEMU_BIN="$tmpdir/tcg_helper_stub"
        echo "s6: using tcg_helper_stub (real_qemu=$s6_real_qemu)" >&2
    fi
}

s6_write_evidence_file() {
    local name=$1
    local content=$2
    [[ -n "$s6_evidence_dir" ]] || return 0
    mkdir -p "$s6_evidence_dir"
    printf '%s\n' "$content" >"$s6_evidence_dir/$name"
}

s6_copy_evidence() {
    local src=$1
    local name=$2
    [[ -n "$s6_evidence_dir" ]] || return 0
    mkdir -p "$s6_evidence_dir"
    if [[ -f "$src" ]]; then
        # Bound copy
        local cap=${WVM_S6_LOG_CAP_BYTES:-1048576}
        local sz
        sz=$(stat -c %s "$src" 2>/dev/null || echo 0)
        if [[ "$sz" -gt "$cap" ]]; then
            {
                echo "truncated_from_bytes=$sz cap=$cap"
                head -c $((cap / 2)) "$src"
                echo
                echo "... omitted ..."
                tail -c $((cap / 2)) "$src"
            } >"$s6_evidence_dir/$name"
        else
            # Dereference logs/evidence: a copied symlink can point at a
            # deleted cell tempdir and make the archive unreadable.
            cp -L "$src" "$s6_evidence_dir/$name"
        fi
    fi
}

# After CREATE SUCCESS: harvest, optional dataplane marker, STOP, cleanup check.
# Args: create_out string. Uses tmpdir, agent_pid, submit_stop_vm binary path.
# Sets s6_finish_rc=0 on success.
s6_finish_running_vm() {
    local create_out=$1
    local submit_stop=${2:-$tmpdir/submit_stop_vm}
    local vm_id vm_inc manifest_gen
    local stop_out
    local cleanup_fail=0
    s6_finish_rc=1

    vm_id=$(sed -n 's/.*vm_id=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
    vm_inc=$(sed -n 's/.*vm_incarnation=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
    manifest_gen=$(sed -n 's/.*manifest_generation=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
    route_scope=$(sed -n 's/.*route_scope_id=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)

    s6_write_evidence_file "create_result.txt" "$create_out"
    s6_write_evidence_file "identity.txt" \
"vm_id=$vm_id
vm_incarnation=$vm_inc
manifest_generation=$manifest_gen
route_scope_id=$route_scope
backend=${WVM_S6_BACKEND:-}
accel=${WVM_S6_ACCEL:-}
cap_source=$s6_cap_source
tcg_helper=${WVM_TCG_QEMU_BIN:-}
run_id=${WVM_S6_RUN_ID:-}
cell=${WVM_S6_CELL:-}"

    local agent_log="$tmpdir/agent.log"
    [[ -f "$agent_log" ]] || agent_log="$tmpdir/agent-a.log"
    local runtime_manifest=""

    # Actual admitted manifest/dispatch/route artifacts, not just grep snippets.
    runtime_manifest=$(grep -oE -- '--manifest[[:space:]]+/[^[:space:]]+\.manifest' \
        "$agent_log" 2>/dev/null | awk '{print $2}' | head -1 || true)
    if [[ -z "$runtime_manifest" && -n "$vm_id" && -n "$vm_inc" && -n "$manifest_gen" ]]; then
        runtime_manifest="$tmpdir/runtime/vm-${vm_id}-${vm_inc}-${manifest_gen}.manifest"
        if [[ ! -f "$runtime_manifest" ]]; then
            runtime_manifest=$(ls -1t "$tmpdir/runtime"/vm-${vm_id}-*.manifest 2>/dev/null | head -1 || true)
        fi
    fi
    if [[ -n "$runtime_manifest" && -f "$runtime_manifest" ]]; then
        s6_copy_evidence "$runtime_manifest" "runtime_manifest"
        s6_copy_evidence "$runtime_manifest.dispatch" "runtime_manifest.dispatch"
        s6_copy_evidence "$runtime_manifest.route" "runtime_manifest.route"
        {
            echo "manifest_path=$runtime_manifest"
            sha256sum "$runtime_manifest" 2>/dev/null || true
            [[ -f "$runtime_manifest.dispatch" ]] && sha256sum "$runtime_manifest.dispatch" 2>/dev/null || true
            [[ -f "$runtime_manifest.route" ]] && sha256sum "$runtime_manifest.route" 2>/dev/null || true
        } >"${s6_evidence_dir:-$tmpdir}/manifest_identity.txt" 2>/dev/null || true
    else
        s6_write_evidence_file "manifest_identity.txt" "manifest_path=MISSING"
    fi
    {
        if [[ -n "${agent_pid:-}" && -r "/proc/$agent_pid/cmdline" ]]; then
            printf 'agent_pid=%s argv=' "$agent_pid"
            tr '\0' ' ' <"/proc/$agent_pid/cmdline" 2>/dev/null || true
            echo
            for child in $(pgrep -P "$agent_pid" 2>/dev/null || true); do
                [[ -r "/proc/$child/cmdline" ]] || continue
                printf 'child_pid=%s argv=' "$child"
                tr '\0' ' ' <"/proc/$child/cmdline" 2>/dev/null || true
                echo
            done
        else
            echo "agent_pid=${agent_pid:-none} argv=unavailable"
        fi
    } >"${s6_evidence_dir:-$tmpdir}/launch_argv.txt" 2>/dev/null || true

    # Capability / probe evidence
    s6_copy_evidence "$tmpdir/evidence/seed-meta.txt" "seed-meta.txt"
    s6_copy_evidence "$tmpdir/evidence/capability-profile.digest" "capability-profile.digest"
    s6_copy_evidence "$tmpdir/evidence/capabilities-801.record" "capabilities-801.record"
    if [[ -f "$tmpdir/node-state/host_capabilities.report" ]]; then
        s6_copy_evidence "$tmpdir/node-state/host_capabilities.report" "host_capabilities.report"
        # Digest binding check: agent probed report exists alongside admission seed.
        s6_write_evidence_file "probe_publish_binding.txt" \
"host_capabilities_report=present
ctl_capabilities_record=present
cap_source=$s6_cap_source
note=admission used ctl capabilities-*.record; agent also published host_capabilities.report"
    fi
    s6_copy_evidence "$agent_log" "agent.log"
    s6_copy_evidence "$tmpdir/ctl.log" "ctl.log"
    if [[ -d "$tmpdir/gw-state" ]]; then
        s6_copy_evidence "$tmpdir/gw-state/route.journal" "gateway_route.journal"
    fi
    # Manifest digest / QEMU args from agent/runtime logs (bounded redacted).
    if [[ -f "$agent_log" ]]; then
        {
            echo "=== backend/topology snippets ==="
            grep -E 'KVM FAST PATH|TCG PROXY|Spawning|execlp qemu|Mode:|backend|negotiated|wavevm_ram|READY|manifest|route_scope|dispatch' \
                "$agent_log" 2>/dev/null | head -n 80 || true
            echo "=== child runtime logs (names) ==="
            find "$tmpdir/runtime" -type f 2>/dev/null | head -n 40 || true
        } >"${s6_evidence_dir:-$tmpdir}/runtime_snippets.txt" 2>/dev/null || true
        # Copy first child log if any
        local child_log
        child_log=$(find "$tmpdir/runtime" -type f \( -name '*.log' -o -name 'stderr*' -o -name 'stdout*' \) 2>/dev/null | head -1 || true)
        if [[ -n "$child_log" ]]; then
            s6_copy_evidence "$child_log" "executor_child.log"
            {
                echo "=== qemu/executor argv / mode ==="
                grep -E 'qemu|KVM FAST|TCG PROXY|WVM_TCG|accel|argv|-m |-smp|wavevm' \
                    "$child_log" 2>/dev/null | head -n 60 || true
            } >>"${s6_evidence_dir:-$tmpdir}/runtime_snippets.txt" 2>/dev/null || true
        fi
    fi

    # Optional dataplane short-exec probe (R1). Best-effort marker file.
    # An intentionally killed VM has no live executor/SHM contract to probe;
    # skip only that VM's dataplane check while preserving STOP evidence.
    if [[ "$s6_dataplane" == "1" && "${WVM_S6_SKIP_DATAPLANE:-0}" == "1" ]]; then
        s6_write_evidence_file "dataplane.txt" "dataplane_probe=SKIP_intentional_kill
production_typed_dispatch=NOT_APPLICABLE
note=VM was intentionally killed before STOP; dataplane probe skipped by design"
    fi
    if [[ "$s6_dataplane" == "1" && "${WVM_S6_SKIP_DATAPLANE:-0}" != "1" ]]; then
        if [[ -x "$repo_root/tests/control-plane/s6_dataplane_probe.sh" ]]; then
            if WVM_S6_EVIDENCE_DIR="$s6_evidence_dir" \
               WVM_S6_TMPDIR="$tmpdir" \
               WVM_S6_CREATE_OUT="$create_out" \
               WVM_S6_AGENT_PID="${agent_pid:-}" \
               WVM_S6_CELL="${WVM_S6_CELL:-}" \
               WVM_S6_BACKEND="${WVM_S6_BACKEND:-}" \
               bash "$repo_root/tests/control-plane/s6_dataplane_probe.sh"; then
                # Prefer probe's own report honesty labels
                if [[ -f "$s6_evidence_dir/dataplane_detail.txt" ]] && \
                   grep -q 'dataplane_probe=PASS_PRODUCTION_TYPED' \
                     "$s6_evidence_dir/dataplane_detail.txt" 2>/dev/null; then
                    s6_write_evidence_file "dataplane.txt" "dataplane_probe=PASS_PRODUCTION_TYPED
dispatch_path=typed_WVM1_ingress_or_gateway
production_typed_dispatch=FIXED
note=live CREATE short-exec via production typed handoff; guest SSH remains §7"
                else
                    s6_write_evidence_file "dataplane.txt" "dataplane_probe=PASS
note=probe exited 0; see dataplane_detail.txt for path honesty"
                fi
            else
                s6_write_evidence_file "dataplane.txt" "dataplane_probe=FAIL
production_typed_dispatch=FAIL
note=see dataplane_detail.txt"
                echo "s6: dataplane probe FAILED" >&2
                return 1
            fi
        else
            s6_write_evidence_file "dataplane.txt" "dataplane_probe=SKIP_no_helper
note=N4/R3: SKIP is not full dataplane PASS"
        fi
    fi

    if [[ "$s6_require_stop" != "1" ]]; then
        s6_write_evidence_file "cleanup.ok" "cleanup_ok=1
note=stop_not_required
honesty=REQUIRE_STOP=0_not_full_STOP_acceptance"
        : >"${s6_evidence_dir:-$tmpdir}/cleanup.manifest"
        s6_finish_rc=0
        return 0
    fi

    if [[ -z "$vm_id" || -z "$vm_inc" || -z "$manifest_gen" ]]; then
        echo "s6: cannot parse CREATE identity for STOP ($create_out)" >&2
        return 1
    fi
    if [[ ! -x "$submit_stop" ]]; then
        # Build submit_stop_vm if missing.
        gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
            -I"$repo_root/common_include" \
            "$repo_root/common_include/wavevm_sha256.c" \
            "$repo_root/common_include/wavevm_canonical.c" \
            "$repo_root/common_include/wavevm_identity.c" \
            "$repo_root/common_include/wavevm_runtime_names.c" \
            "$repo_root/common_include/wavevm_manifest.c" \
            "$repo_root/common_include/wavevm_lifecycle.c" \
            "$repo_root/common_include/wavevm_control.c" \
            "$repo_root/common_include/wavevm_capability.c" \
            "$repo_root/common_include/wavevm_admission.c" \
            "$repo_root/common_include/wavevm_cluster.c" \
            "$repo_root/common_include/wavevm_reservation_runtime.c" \
            "$repo_root/common_include/wavevm_fault_engine.c" \
            "$repo_root/common_include/wavevm_coordinator.c" \
            "$repo_root/common_include/wavevm_envelope.c" \
            "$repo_root/common_include/wavevm_membership_controller.c" \
            "$repo_root/common_include/wavevm_membership_control.c" \
            "$repo_root/common_include/wavevm_control_transport.c" \
            "$repo_root/common_include/wavevm_runtime_profile.c" \
            "$repo_root/tests/control-plane/submit_stop_vm.c" \
            -pthread -o "$tmpdir/submit_stop_vm"
        submit_stop=$tmpdir/submit_stop_vm
    fi

    mapfile -t pre_shm < <(grep -oE '/wavevm_ram_wvm-v'"$vm_id"'[A-Za-z0-9_-]*' "$tmpdir/agent.log" 2>/dev/null | sed "s/['\":.,;)]*$//" | sort -u || true)
    # N6: only children owned by THIS vm_id (cmdline/environ mentions wvm-v$vm_id
    # or matching SHM ns). Do not treat sibling VM children as leftovers.
    pre_children=()
    if [[ -n "${agent_pid:-}" ]]; then
        local _c _ns _hit
        _ns="wvm-v${vm_id}"
        for _c in $(pgrep -P "${agent_pid}" 2>/dev/null | sort -u || true); do
            _hit=0
            if [[ -r "/proc/$_c/cmdline" ]] && tr '\0' ' ' <"/proc/$_c/cmdline" 2>/dev/null | grep -q "$_ns"; then
                _hit=1
            elif [[ -r "/proc/$_c/environ" ]] && tr '\0' '\n' <"/proc/$_c/environ" 2>/dev/null | grep -q "$_ns"; then
                _hit=1
            else
                for name in "${pre_shm[@]}"; do
                    if ls -l "/proc/$_c/fd" 2>/dev/null | grep -q "${name#/}"; then
                        _hit=1
                        break
                    fi
                done
            fi
            if [[ $_hit -eq 1 ]]; then
                pre_children+=("$_c")
            fi
        done
    fi
    pre_paths=()
    local name ns
    for name in "${pre_shm[@]}"; do
        ns=${name#/wavevm_ram_}
        pre_paths+=(
            "/tmp/wvm_user_${ns}.sock"
            "/tmp/${ns}-executor.sock"
            "/tmp/${ns}-worker.sock"
            "/tmp/${ns}-monitor.sock"
            "/tmp/${ns}-ready"
        )
    done

    {
        echo "# cleanup.manifest for vm_id=$vm_id inc=$vm_inc"
        for name in "${pre_shm[@]}"; do
            echo "shm=$name"
        done
        for name in "${pre_paths[@]}"; do
            echo "path=$name"
        done
        for name in "${pre_children[@]}"; do
            echo "pid=$name"
        done
    } >"${s6_evidence_dir:-$tmpdir}/cleanup.manifest"

    if [[ ${#pre_shm[@]} -lt 1 ]]; then
        echo "s6: expected ≥1 SHM for vm_id=$vm_id while RUNNING" >&2
        grep -E 'wavevm_ram|shm' "$tmpdir/agent.log" >&2 || true
        cleanup_fail=1
    fi

    stop_out=$("$submit_stop" "$tmpdir/ctl.sock" "$vm_id" "$vm_inc" "$manifest_gen" 74 || true)
    s6_write_evidence_file "stop_result.txt" "$stop_out"
    echo "s6 STOP: $stop_out"
    # Re-harvest ctl.log after STOP so STOP_VM / orchestrator errors are visible.
    s6_copy_evidence "$tmpdir/ctl.log" "ctl.log"
    if [[ -f "$tmpdir/ctl.log" ]]; then
        grep -E "STOP_VM|orchestrator_stop|ROUTE_RETIRE|0x403|0x602" "$tmpdir/ctl.log"             >"${s6_evidence_dir:-$tmpdir}/stop_ctl_snippets.txt" 2>/dev/null || true
    fi
    if [[ "$stop_out" != status=0* || "$stop_out" != *recorded_state=17* ]]; then
        echo "s6: STOP_VM did not reach SUCCESS/STOPPED (got: $stop_out)" >&2
        cleanup_fail=1
    fi

    # Wait briefly for retire.
    sleep 0.3
    for name in "${pre_shm[@]}"; do
        if [[ -e "/dev/shm/${name#/}" ]]; then
            echo "s6: leftover SHM $name" >&2
            cleanup_fail=1
        fi
    done
    for name in "${pre_paths[@]}"; do
        if [[ -e "$name" ]]; then
            echo "s6: leftover path $name" >&2
            cleanup_fail=1
        fi
    done
    for name in "${pre_children[@]}"; do
        if kill -0 "$name" 2>/dev/null; then
            echo "s6: leftover admitted child pid=$name" >&2
            cleanup_fail=1
        fi
    done

    # Lease abort evidence (best-effort).
    if [[ -f "$tmpdir/ctl.log" ]]; then
        if ! grep -qE 'ABORT_RESERVATION|0x203|stop' "$tmpdir/ctl.log" 2>/dev/null; then
            echo "s6: warn: ctl.log missing obvious STOP/ABORT evidence (continuing if STOP ok)" >&2
        fi
    fi

    if [[ $cleanup_fail -ne 0 ]]; then
        s6_write_evidence_file "cleanup.ok" "cleanup_ok=0
stop=$stop_out
vm_id=$vm_id"
        if [[ -n "${WVM_S6_STOP_TAG:-}" && -n "${s6_evidence_dir:-}" ]]; then
            s6_write_evidence_file "cleanup.ok.${WVM_S6_STOP_TAG}" "cleanup_ok=0
stop=$stop_out
vm_id=$vm_id"
            cp -a "$s6_evidence_dir/stop_result.txt" \
               "$s6_evidence_dir/stop_result.${WVM_S6_STOP_TAG}.txt" 2>/dev/null || true
            cp -a "$s6_evidence_dir/cleanup.manifest" \
               "$s6_evidence_dir/cleanup.manifest.${WVM_S6_STOP_TAG}" 2>/dev/null || true
        fi
        return 1
    fi
    s6_write_evidence_file "cleanup.ok" "cleanup_ok=1
stop=$stop_out
retired_shm=${pre_shm[*]}
vm_id=$vm_id"
    if [[ -n "${WVM_S6_STOP_TAG:-}" && -n "${s6_evidence_dir:-}" ]]; then
        s6_write_evidence_file "cleanup.ok.${WVM_S6_STOP_TAG}" "cleanup_ok=1
stop=$stop_out
retired_shm=${pre_shm[*]}
vm_id=$vm_id"
        cp -a "$s6_evidence_dir/stop_result.txt" \
           "$s6_evidence_dir/stop_result.${WVM_S6_STOP_TAG}.txt" 2>/dev/null || true
        cp -a "$s6_evidence_dir/cleanup.manifest" \
           "$s6_evidence_dir/cleanup.manifest.${WVM_S6_STOP_TAG}" 2>/dev/null || true
    fi
    s6_finish_rc=0
    return 0
}

# For reject/negative cells (N5): tear down THIS cell's pids AND prove no
# partial activation (no wavevm_ram SHM left from this attempt). Empty/odd
s6_finish_reject() {
    local reason=$1
    local cleanup_fail=0
    local leftover
    local reject_state=""
    local reject_status=""
    local early_abort=0
    local abort_error=0
    local reason_ok=1
    s6_write_evidence_file "reject.txt" "$reason"
    {
        echo "# reject path — track agent/ctl + no-partial-activation"
        [[ -n "${agent_pid:-}" ]] && echo "pid=$agent_pid"
        [[ -n "${ctl_pid:-}" ]] && echo "pid=$ctl_pid"
        [[ -n "${gw_pid:-}" ]] && echo "pid=$gw_pid"
    } >"${s6_evidence_dir:-$tmpdir}/cleanup.manifest"
    # Preserve the durable controller state before teardown; process cleanup
    # alone cannot prove that no activation/reservation survived.
    for leftover in admission.journal membership.journal membership-control.journal; do
        if [[ -f "$tmpdir/ctl-state/$leftover" ]]; then
            cp -L "$tmpdir/ctl-state/$leftover"                 "${s6_evidence_dir:-$tmpdir}/$leftover" 2>/dev/null || true
            echo "ctl_state_file=$leftover" >>"${s6_evidence_dir:-$tmpdir}/cleanup.manifest"
        fi
    done
    if [[ ! -s "$tmpdir/ctl-state/admission.journal" ]]; then
        echo "s6_finish_reject: missing durable admission journal" >&2
        cleanup_fail=1
    fi
    if [[ -f "$tmpdir/ctl.log" ]]; then
        reject_state=$(sed -n 's/.*state=\([0-9][0-9]*\).*/\1/p' "$tmpdir/ctl.log" | tail -1)
        reject_status=$(sed -n 's/.*status=\([0-9][0-9]*\).*/\1/p' "$tmpdir/ctl.log" | tail -1)
        if grep -aq 'abort cleanup: lifecycle transition lacks durable route snapshot' "$tmpdir/ctl.log"; then
            early_abort=1
            abort_error=1
        fi
        if [[ -n "${WVM_S6_EXPECT_REJECT_REASON:-}" ]] && \
           ! grep -aEqi -- "${WVM_S6_EXPECT_REJECT_REASON}" "$tmpdir/ctl.log"; then
            reason_ok=0
            echo "s6_finish_reject: expected reason /$WVM_S6_EXPECT_REJECT_REASON/ missing" >&2
        fi
        if grep -aEq 'CREATE_VM.*status=0' "$tmpdir/ctl.log"; then
            echo "s6_finish_reject: rejected cell still logged CREATE_VM status=0" >&2
            cleanup_fail=1
        fi
    else
        echo "s6_finish_reject: missing ctl.log; cannot verify reject compensation" >&2
        cleanup_fail=1
    fi
    {
        echo "reject_state=${reject_state:-unknown}"
        echo "reject_status=${reject_status:-unknown}"
        echo "early_abort_no_durable_route=$early_abort"
        echo "abort_cleanup_error=$abort_error"
        echo "expected_reason_verified=$reason_ok"
        echo "admission_journal_bytes=$(stat -c %s "$tmpdir/ctl-state/admission.journal" 2>/dev/null || echo 0)"
    } >>"${s6_evidence_dir:-$tmpdir}/cleanup.manifest"
    if [[ "$reason_ok" -ne 1 ]]; then
        cleanup_fail=1
    fi
    # The early no-route transaction must reach the real terminal ABORTED
    # state (19), not be mislabeled from ABORTING (18).  A cleanup error is
    # now a failure: no-route rejection has nothing to compensate and must
    # not depend on the old route-gate error as its oracle.
    if [[ "$reject_state" != "19" ]]; then
        echo "s6_finish_reject: reject did not persist ABORTED state=19 (got=${reject_state:-unknown})" >&2
        cleanup_fail=1
    fi
    if [[ "$abort_error" -ne 0 ]]; then
        echo "s6_finish_reject: early abort still reports incomplete cleanup" >&2
        cleanup_fail=1
    fi
    if [[ "$reject_state" == "11" || "$reject_state" == "12" ||
          "$reject_state" == "17" ]]; then
        echo "s6_finish_reject: reject left active state=$reject_state" >&2
        cleanup_fail=1
    fi
    # Snapshot any SHM names that appeared during this cell before teardown.
    mapfile -t _rej_shm < <(grep -oE '/wavevm_ram_[A-Za-z0-9_-]+' "$tmpdir/agent.log" 2>/dev/null | sort -u || true)
    for leftover in "${_rej_shm[@]}"; do
        echo "shm_before_teardown=$leftover" >>"${s6_evidence_dir:-$tmpdir}/cleanup.manifest"
    done
    if [[ -n "${agent_pid:-}" ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
        agent_pid=
    fi
    if [[ -n "${gw_pid:-}" ]]; then
        kill -TERM "$gw_pid" 2>/dev/null || true
        wait "$gw_pid" 2>/dev/null || true
        gw_pid=
    fi
    if [[ -n "${ctl_pid:-}" ]]; then
        kill -TERM "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
        ctl_pid=
    fi
    sleep 0.3
    # Compensation: no SHM from this attempt may remain; tracked pids must be gone.
    for leftover in "${_rej_shm[@]}"; do
        if [[ -e "/dev/shm/${leftover#/}" ]]; then
            echo "s6_finish_reject: leftover SHM after reject $leftover" >&2
            cleanup_fail=1
        fi
    done
    # Also scan for any wavevm_ram still present that our agent log mentioned.
    if compgen -G '/dev/shm/wavevm_ram_*' >/dev/null 2>&1; then
        # Only fail if names intersect this cell's log (avoid cross-test noise).
        for leftover in /dev/shm/wavevm_ram_*; do
            base=${leftover#/dev/shm/}
            if grep -q "/$base" "$tmpdir/agent.log" 2>/dev/null; then
                echo "s6_finish_reject: residual SHM $leftover" >&2
                cleanup_fail=1
            fi
        done
    fi
    if [[ $cleanup_fail -ne 0 ]]; then
        s6_write_evidence_file "cleanup.ok" "cleanup_ok=0
note=reject_path_compensation_failed
reason=$reason
reject_state=${reject_state:-unknown}
early_abort_no_durable_route=$early_abort
abort_cleanup_error=$abort_error
expected_reason_verified=$reason_ok"
        return 1
    fi
    s6_write_evidence_file "cleanup.ok" "cleanup_ok=1
note=reject_path_terminal_aborted
reason=$reason
reject_state=${reject_state:-unknown}
durable_route_snapshot_absent=1
compensation=no_route_no_reservation_required
no_residual_shm=1
expected_reason_verified=$reason_ok"
    return 0
}

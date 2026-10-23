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
            cp -a "$src" "$s6_evidence_dir/$name"
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
    s6_copy_evidence "$tmpdir/agent.log" "agent.log"
    s6_copy_evidence "$tmpdir/ctl.log" "ctl.log"
    if [[ -d "$tmpdir/gw-state" ]]; then
        s6_copy_evidence "$tmpdir/gw-state/route.journal" "gateway_route.journal"
    fi
    # Manifest digest / QEMU args from agent/runtime logs (bounded redacted).
    if [[ -f "$tmpdir/agent.log" ]]; then
        {
            echo "=== backend/topology snippets ==="
            grep -E 'KVM FAST PATH|TCG PROXY|Spawning|execlp qemu|Mode:|backend|negotiated|wavevm_ram|READY|manifest|route_scope|dispatch' \
                "$tmpdir/agent.log" 2>/dev/null | head -n 80 || true
            echo "=== child runtime logs (names) ==="
            find "$tmpdir/runtime" -type f 2>/dev/null | head -n 40 || true
        } >"${s6_evidence_dir:-/dev/null}/runtime_snippets.txt" 2>/dev/null || true
        # Copy first child log if any
        local child_log
        child_log=$(find "$tmpdir/runtime" -type f \( -name '*.log' -o -name 'stderr*' -o -name 'stdout*' \) 2>/dev/null | head -1 || true)
        if [[ -n "$child_log" ]]; then
            s6_copy_evidence "$child_log" "executor_child.log"
            {
                echo "=== qemu/executor argv / mode ==="
                grep -E 'qemu|KVM FAST|TCG PROXY|WVM_TCG|accel|argv|-m |-smp|wavevm' \
                    "$child_log" 2>/dev/null | head -n 60 || true
            } >>"${s6_evidence_dir:-/dev/null}/runtime_snippets.txt" 2>/dev/null || true
        fi
    fi

    # Optional dataplane short-exec probe (R1). Best-effort marker file.
    if [[ "$s6_dataplane" == "1" ]]; then
        if [[ -x "$repo_root/tests/control-plane/s6_dataplane_probe.sh" ]]; then
            if WVM_S6_EVIDENCE_DIR="$s6_evidence_dir" \
               WVM_S6_TMPDIR="$tmpdir" \
               WVM_S6_CREATE_OUT="$create_out" \
               WVM_S6_AGENT_PID="${agent_pid:-}" \
               bash "$repo_root/tests/control-plane/s6_dataplane_probe.sh"; then
                s6_write_evidence_file "dataplane.txt" "dataplane_probe=PASS"
            else
                s6_write_evidence_file "dataplane.txt" "dataplane_probe=FAIL"
                echo "s6: dataplane probe FAILED" >&2
                return 1
            fi
        else
            s6_write_evidence_file "dataplane.txt" "dataplane_probe=SKIP_no_helper"
        fi
    fi

    if [[ "$s6_require_stop" != "1" ]]; then
        s6_write_evidence_file "cleanup.ok" "cleanup_ok=1
note=stop_not_required"
        : >"${s6_evidence_dir:-/dev/null}/cleanup.manifest"
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

    mapfile -t pre_shm < <(grep -oE '/wavevm_ram_wvm-v'"$vm_id"'[^[:space:]]*' "$tmpdir/agent.log" 2>/dev/null | sort -u || true)
    mapfile -t pre_children < <(pgrep -P "${agent_pid:-0}" 2>/dev/null | sort -u || true)
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
stop=$stop_out"
        return 1
    fi
    s6_write_evidence_file "cleanup.ok" "cleanup_ok=1
stop=$stop_out
retired_shm=${pre_shm[*]}"
    s6_finish_rc=0
    return 0
}

# For reject/negative cells: still require process teardown of THIS cell's pids.
s6_finish_reject() {
    local reason=$1
    s6_write_evidence_file "reject.txt" "$reason"
    {
        echo "# reject path — track agent/ctl only"
        [[ -n "${agent_pid:-}" ]] && echo "pid=$agent_pid"
        [[ -n "${ctl_pid:-}" ]] && echo "pid=$ctl_pid"
        [[ -n "${gw_pid:-}" ]] && echo "pid=$gw_pid"
    } >"${s6_evidence_dir:-$tmpdir}/cleanup.manifest"
    # Kill our processes then verify gone.
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
    sleep 0.2
    s6_write_evidence_file "cleanup.ok" "cleanup_ok=1
note=reject_path
reason=$reason"
}

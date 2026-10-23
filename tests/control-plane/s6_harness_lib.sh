#!/usr/bin/env bash
# Shared helpers for goal §6 Minimum matrix (R3/R4/R5).
# Sourced by test_s6_minimum_matrix.sh and cell wrappers.
# shellcheck disable=SC2034

s6_known_cells=(
    flat_tcg fractal_tcg flat_kvm fractal_kvm
    mode_a_one mode_b_dual compute_dual mode_a_dual
    neg_require_kvm neg_require_kernel auto_tcg_fallback
)

s6_is_known_cell() {
    local c=$1 k
    for k in "${s6_known_cells[@]}"; do
        [[ "$k" == "$c" ]] && return 0
    done
    return 1
}

# Parse WVM_S6_CELLS into selected_cells[]. Reject unknown / empty.
# "all" expands to the eight Minimum + three R2 cells when WVM_S6_INCLUDE_NEG=1,
# else the eight Minimum cells only.
s6_parse_cell_selection() {
    local raw=${1:-all}
    selected_cells=()
    if [[ "$raw" == "all" ]]; then
        selected_cells=(flat_tcg fractal_tcg flat_kvm fractal_kvm
            mode_a_one mode_b_dual compute_dual mode_a_dual)
        if [[ "${WVM_S6_INCLUDE_NEG:-1}" == "1" ]]; then
            selected_cells+=(neg_require_kvm neg_require_kernel auto_tcg_fallback)
        fi
        return 0
    fi
    local IFS=','
    local -a parts
    read -r -a parts <<<"$raw"
    local p
    for p in "${parts[@]}"; do
        p=${p// /}
        [[ -z "$p" ]] && continue
        if ! s6_is_known_cell "$p"; then
            echo "s6: unknown cell '$p' (whitelist: ${s6_known_cells[*]})" >&2
            return 2
        fi
        selected_cells+=("$p")
    done
    if [[ ${#selected_cells[@]} -eq 0 ]]; then
        echo "s6: cell selection empty after parse (raw='$raw')" >&2
        return 2
    fi
    return 0
}

# Source identity: HEAD + reproducible hashes of dirty tracked + untracked test sources.
s6_write_source_identity() {
    local out=$1
    local repo=$2
    {
        echo "captured_at_asia_shanghai=$(TZ=Asia/Shanghai date -Iseconds)"
        echo "user=$(id -un) uid=$(id -u) groups=$(id -Gn | tr ' ' ',')"
        echo -n "head="
        git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown
        echo -n "head_short="
        git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown
        echo "dirty_tracked:"
        git -C "$repo" diff --name-only HEAD 2>/dev/null | while read -r f; do
            [[ -z "$f" ]] && continue
            if [[ -f "$repo/$f" ]]; then
                echo "  $(sha256sum "$repo/$f" | awk '{print $1}')  $f"
            else
                echo "  MISSING  $f"
            fi
        done
        echo "untracked_relevant:"
        git -C "$repo" ls-files --others --exclude-standard 2>/dev/null \
            | grep -E '^(tests/control-plane/|scripts/|common_include/|node_runtime/|ctl_tool/|slave_daemon/|gateway_service/|master_core/[^.]|持久化plan\.txt|docs/)' \
            | while read -r f; do
            [[ -z "$f" || ! -f "$repo/$f" ]] && continue
            # Skip build objects
            [[ "$f" == *.o || "$f" == *.ko || "$f" == *.mod || "$f" == *.cmd ]] && continue
            echo "  $(sha256sum "$repo/$f" | awk '{print $1}')  $f"
        done
        echo "devices:"
        echo -n "  /dev/kvm="; ls -la /dev/kvm 2>&1 | tr '\n' ' '; echo
        echo -n "  /dev/wavevm="; ls -la /dev/wavevm 2>&1 | tr '\n' ' '; echo
        echo -n "  wavevm_ko="
        if lsmod | grep -q '^wavevm'; then
            modinfo "$repo/master_core/wavevm.ko" 2>/dev/null | awk -F: '/srcversion/{gsub(/ /,"",$2); print $2; exit}'
            lsmod | awk '/^wavevm/{print " loaded refcnt="$3}'
        else
            echo "not_loaded"
        fi
    } >"$out"
}

# Bound a log file to max bytes (keep head+tail).
s6_bound_log() {
    local log=$1
    local max=${2:-1048576}
    [[ -f "$log" ]] || return 0
    local sz
    sz=$(stat -c %s "$log" 2>/dev/null || echo 0)
    if [[ "$sz" -le "$max" ]]; then
        return 0
    fi
    local half=$((max / 2))
    local tmp
    tmp=$(mktemp)
    {
        echo "=== s6 log truncated: original_bytes=$sz cap=$max ==="
        head -c "$half" "$log"
        echo
        echo "=== ... middle omitted ... ==="
        tail -c "$half" "$log"
    } >"$tmp"
    mv "$tmp" "$log"
}

# Run cmd with total deadline seconds; kill process group on timeout.
# Sets s6_run_rc, s6_run_elapsed, s6_run_timed_out.
s6_run_with_deadline() {
    local deadline=$1
    shift
    local log=$1
    shift
    local start end pgid
    s6_run_timed_out=0
    start=$(date +%s)
    set +e
    # Separate process group so we can kill descendants.
    setsid bash -c "$*" >"$log" 2>&1 &
    local pid=$!
    pgid=$pid
    local waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [[ $waited -ge $deadline ]]; then
            s6_run_timed_out=1
            kill -TERM -"$pgid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
            sleep 1
            kill -KILL -"$pgid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    wait "$pid" 2>/dev/null
    s6_run_rc=$?
    set -e
    if [[ $s6_run_timed_out -eq 1 ]]; then
        s6_run_rc=124
        echo "s6: cell deadline ${deadline}s exceeded" >>"$log"
    fi
    end=$(date +%s)
    s6_run_elapsed=$((end - start))
    s6_bound_log "$log" "${WVM_S6_LOG_CAP_BYTES:-1048576}"
}

# Per-VM/instance leftover check. Args: evidence dir with cleanup.manifest
# Format lines: shm=NAME | path=PATH | pid=PID | sock=PATH
# Returns 0 if all released; 1 if leftovers remain (prints them).
s6_check_resource_release() {
    local manif=$1
    local fail=0
    local line kind val
    [[ -f "$manif" ]] || { echo "s6: missing cleanup manifest $manif" >&2; return 1; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        kind=${line%%=*}
        val=${line#*=}
        case "$kind" in
            shm)
                if [[ -e "/dev/shm/${val#/}" ]]; then
                    echo "leftover_shm=$val" >&2
                    fail=1
                fi
                ;;
            path|sock|ready)
                if [[ -e "$val" ]]; then
                    echo "leftover_path=$val" >&2
                    fail=1
                fi
                ;;
            pid)
                if kill -0 "$val" 2>/dev/null; then
                    echo "leftover_pid=$val" >&2
                    fail=1
                fi
                ;;
            *)
                ;;
        esac
    done <"$manif"
    return $fail
}

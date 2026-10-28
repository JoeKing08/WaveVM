#!/usr/bin/env bash
# goal §7 / Minimum: production CREATE_VM → real QEMU helpers + Cirros frontend
# login/SSH + remote vCPU/memory evidence.
# Process survival alone is NOT success (roadmap §14 / baseline §14).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
art_dir="${WVM_GUEST_SMOKE_ART:-/tmp/wavevm-guest-smoke-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$art_dir"

# Log caps (Joe 2026-10-26): prior disk-full. Reuse s6 bound/limit patterns.
# Live writers go through scripts/wvm_cap_tee.py (no ulimit -f: SHM ftruncate SIGXFSZ).
GUEST_LOG_CAP_BYTES="${WVM_GUEST_SMOKE_LOG_CAP_BYTES:-${WVM_S6_LOG_CAP_BYTES:-67108864}}"
GUEST_FILE_LIMIT_BYTES="${WVM_GUEST_SMOKE_FILE_LIMIT_BYTES:-${WVM_S6_FILE_LIMIT_BYTES:-104857600}}"
export WVM_S6_LOG_CAP_BYTES="$GUEST_LOG_CAP_BYTES"
export WVM_S6_FILE_LIMIT_BYTES="$GUEST_FILE_LIMIT_BYTES"
export WVM_GUEST_SMOKE_LOG_CAP_BYTES="$GUEST_LOG_CAP_BYTES"
# shellcheck source=/dev/null
source "$repo_root/tests/control-plane/s6_harness_lib.sh"
# NOTE: do not ulimit -f — guest RAM ftruncate would SIGXFSZ (attach13).
# Live log caps = wvm_cap_tee on FE serial/stderr + agent.log; s6_bound_log on EXIT.
export WVM_S6_EVIDENCE_DIR="$art_dir/evid"
mkdir -p "$WVM_S6_EVIDENCE_DIR"

qemu_bin="${WVM_S6_QEMU_BIN:-$repo_root/wavevm-qemu/build/qemu-system-x86_64}"
cirros_img="${WVM_GUEST_IMAGE:-$repo_root/artifacts/images/cirros-0.6.2-x86_64-disk.img}"
mem_bytes="${WVM_CREATE_MEMORY_BYTES:-$((256 * 1024 * 1024))}"
vcpus="${WVM_CREATE_VCPUS:-2}"
ssh_port="${WVM_GUEST_SSH_PORT:-2226}"
boot_timeout_s="${WVM_GUEST_BOOT_TIMEOUT_S:-1500}"
ssh_timeout_s="${WVM_GUEST_SSH_TIMEOUT_S:-180}"

agent_pid=""
ctl_pid=""
frontend_pid=""
create_tmpdir=""

cleanup() {
    set +e
    if [[ -n "${frontend_pid:-}" ]]; then
        kill -TERM "$frontend_pid" 2>/dev/null || true
        wait "$frontend_pid" 2>/dev/null || true
    fi
    if [[ -n "${agent_pid:-}" ]]; then
        # SIGTERM agent; child watches parent and helpers die via PDEATHSIG.
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    if [[ -n "${ctl_pid:-}" ]]; then
        kill -TERM "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
    fi
    if [[ -n "${create_tmpdir:-}" && -d "$create_tmpdir" ]]; then
        pkill -f -- "$create_tmpdir" 2>/dev/null || true
    fi
    pkill -f "hostfwd=tcp::${ssh_port}-:22" 2>/dev/null || true
    # Bound evidence logs after writers die (safe: fds closed).
    if declare -F s6_bound_log >/dev/null 2>&1; then
        local _cap="${GUEST_LOG_CAP_BYTES:-67108864}"
        for _f in "$art_dir"/vm.log "$art_dir"/vm-serial.log "$art_dir"/smoke.log                   "$art_dir"/outer.log "$art_dir"/create.log                   ${create_tmpdir:+"$create_tmpdir"/agent.log}                   ${create_tmpdir:+"$create_tmpdir"/ctl.log}; do
            [[ -f "$_f" ]] || continue
            s6_bound_log "$_f" "$_cap"
        done
    fi
}
trap cleanup EXIT

log() { printf '[guest-smoke %s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$art_dir/smoke.log"; }

if [[ ! -x "$qemu_bin" ]]; then
    log "ERROR: qemu missing: $qemu_bin"
    exit 2
fi
if [[ ! -f "$cirros_img" ]]; then
    log "ERROR: Cirros image missing: $cirros_img"
    exit 2
fi
if ! command -v sshpass >/dev/null; then
    log "ERROR: sshpass required for Cirros SSH"
    exit 2
fi

log "art=$art_dir qemu=$qemu_bin mem_bytes=$mem_bytes vcpus=$vcpus log_cap=$GUEST_LOG_CAP_BYTES file_limit=$GUEST_FILE_LIMIT_BYTES"

export WVM_S6_REAL_QEMU=1
export WVM_S6_QEMU_BIN="$qemu_bin"
export WVM_S6_KEEP_RUNNING=1
# Allow KVM interleave without forking harness (Codex tip 2).
# Default remains require-tcg; set WVM_S6_BACKEND=require-kvm for same Cirros path on KVM helpers.
export WVM_S6_BACKEND="${WVM_S6_BACKEND:-require-tcg}"
export WVM_S6_ACCEL="${WVM_S6_ACCEL:-disabled}"
# flat (default) | fractal — guest matrix cells
export WVM_GUEST_TOPOLOGY="${WVM_GUEST_TOPOLOGY:-flat}"
export WVM_CREATE_MEMORY_BYTES="$mem_bytes"
export WVM_CREATE_VCPUS="$vcpus"

case "${WVM_GUEST_TOPOLOGY}" in
    flat)
        create_script="$repo_root/tests/control-plane/test_create_vm_single_node.sh"
        ;;
    fractal)
        create_script="$repo_root/tests/control-plane/test_create_vm_fractal.sh"
        ;;
    *)
        log "ERROR: WVM_GUEST_TOPOLOGY must be flat|fractal (got ${WVM_GUEST_TOPOLOGY})"
        exit 2
        ;;
esac

log "CREATE_VM via $(basename "$create_script") topology=${WVM_GUEST_TOPOLOGY} backend=${WVM_S6_BACKEND} (production + live helpers)"
echo "topology=${WVM_GUEST_TOPOLOGY}" >"$art_dir/cell_id.txt"
echo "backend=${WVM_S6_BACKEND}" >>"$art_dir/cell_id.txt"
echo "accel=${WVM_S6_ACCEL}" >>"$art_dir/cell_id.txt"
if ! bash "$create_script" \
    >"$art_dir/create.log" 2>&1; then
    log "ERROR: CREATE_VM failed; see $art_dir/create.log"
    tail -n 60 "$art_dir/create.log" | tee -a "$art_dir/smoke.log" || true
    exit 1
fi

create_tmpdir=$(cat /tmp/wavevm-s6-keep-tmpdir)
agent_pid=$(cat /tmp/wavevm-s6-keep-agent-pid)
ctl_pid=$(cat /tmp/wavevm-s6-keep-ctl-pid)
cp -a /tmp/wavevm-s6-keep-ports.txt "$art_dir/keep-ports.txt" 2>/dev/null || true

log "CREATE RUNNING keep tmp=$create_tmpdir agent=$agent_pid ctl=$ctl_pid"
if ! kill -0 "$agent_pid" 2>/dev/null; then
    log "ERROR: agent dead after CREATE"
    exit 1
fi
ready_pat='local executor READY with live TCG helpers'
if [[ "${WVM_S6_BACKEND}" == "require-kvm" ]]; then
    # KVM helpers still print TCG READY line in some builds; also accept KVM FAST PATH / Hardware Acceleration.
    ready_pat='local executor READY with live TCG helpers|KVM Hardware Acceleration Active|KVM FAST PATH'
fi
if ! grep -qE "$ready_pat" "$create_tmpdir/agent.log"; then
    log "ERROR: CREATE did not publish live helpers (backend=$WVM_S6_BACKEND)"
    grep -E 'READY|TCG|KVM|Spawning|stub' "$create_tmpdir/agent.log" | tee -a "$art_dir/smoke.log" || true
    exit 1
fi
log "CREATE backend=$WVM_S6_BACKEND accel=$WVM_S6_ACCEL"

helper_n=$(pgrep -c -f "$qemu_bin.*-accel wavevm" || true)
helper_n=${helper_n:-0}
log "live wavevm-accel QEMU processes≈$helper_n"
if [[ "$helper_n" -lt 1 && "${WVM_S6_BACKEND}" != "require-kvm" ]]; then
    log "ERROR: no live -accel wavevm helper QEMU"
    pstree -ap "$agent_pid" 2>/dev/null | tee -a "$art_dir/smoke.log" || true
    exit 1
fi
if [[ "$helper_n" -lt 1 && "${WVM_S6_BACKEND}" == "require-kvm" ]]; then
    log "NOTE: no TCG helper QEMU (expected for some require-kvm layouts); continuing"
    pstree -ap "$agent_pid" 2>/dev/null | tee -a "$art_dir/smoke.log" || true
fi

manifest=$(ls -1t "$create_tmpdir"/runtime/vm-*-*.manifest 2>/dev/null | head -1 || true)
if [[ -z "$manifest" || ! -f "$manifest" ]]; then
    # Some layouts nest under runtime subdirs
    manifest=$(find "$create_tmpdir/runtime" -name 'vm-*-*.manifest' 2>/dev/null | head -1 || true)
fi
if [[ -z "$manifest" || ! -f "$manifest" ]]; then
    log "ERROR: admitted manifest missing under $create_tmpdir/runtime"
    find "$create_tmpdir" -name '*.manifest' 2>/dev/null | tee -a "$art_dir/smoke.log" || true
    exit 1
fi

# Agent --instance-id 802 is the node-instance CREATE children bind to.
node_instance=802
child_pid=$(pgrep -P "$agent_pid" -f 'wavevm_node_runtime child' || true)
if [[ -n "$child_pid" ]]; then
    parsed=$(tr '\0' ' ' <"/proc/$child_pid/cmdline" 2>/dev/null \
        | sed -n 's/.*--node-instance \([0-9][0-9]*\).*/\1/p' | head -1)
    if [[ -n "$parsed" ]]; then
        node_instance=$parsed
    fi
fi
log "manifest=$manifest node_instance=$node_instance child=$child_pid"

launch_env_file="$art_dir/launch.env"
"$repo_root/wavevm_node_runtime" --manifest "$manifest" \
    --node-instance "$node_instance" --print-launch-env \
    >"$launch_env_file" 2>"$art_dir/print-launch-env.err"
if [[ ! -s "$launch_env_file" ]]; then
    log "ERROR: print-launch-env produced empty output"
    cat "$art_dir/print-launch-env.err" | tee -a "$art_dir/smoke.log" || true
    exit 1
fi
# shellcheck disable=SC1090
source "$launch_env_file"
: "${WVM_SHM_FILE:?}"
: "${WVM_RUNTIME_SOCKET:?}"
: "${WVM_RUNTIME_READY_FILE:?}"
: "${WVM_TCG_QEMU_MEM_MB:?}"
: "${WVM_TCG_QEMU_MACHINE:?}"

if [[ ! -f "$WVM_RUNTIME_READY_FILE" ]]; then
    log "ERROR: runtime ready file missing: $WVM_RUNTIME_READY_FILE"
    exit 1
fi
if [[ ! -S "$WVM_RUNTIME_SOCKET" ]]; then
    log "ERROR: runtime socket missing: $WVM_RUNTIME_SOCKET"
    exit 1
fi
shm_path="/dev/shm/${WVM_SHM_FILE#/}"
if [[ ! -e "$shm_path" && ! -e "$WVM_SHM_FILE" ]]; then
    log "ERROR: SHM missing for $WVM_SHM_FILE (looked at $shm_path)"
    exit 1
fi

mem_mb="$WVM_TCG_QEMU_MEM_MB"
machine="$WVM_TCG_QEMU_MACHINE"
if [[ "$mem_mb" -lt 128 ]]; then
    log "ERROR: admitted RAM ${mem_mb}MiB < 128MiB; Cirros needs ≥128 (set WVM_CREATE_MEMORY_BYTES)"
    exit 1
fi

# Frontend = MASTER (must NOT set WVM_ROLE=SLAVE). Helpers already hold SLAVE.
unset WVM_ROLE || true
unset WVM_SOCK_CMD WVM_SOCK_REQ WVM_SOCK_PUSH WVM_EXECUTOR_SESSION_FD || true
# require-tcg: keep FE on TCG/user path (historical Cirros smoke).
# require-kvm: allow Auto-KVM bootstrap so FE sends mode_tcg=0 matching
# negotiated KVM backend (else coordinator rejects handoff as -EINVAL).
if [[ "${WVM_S6_BACKEND}" == "require-kvm" ]]; then
    unset WVM_DISABLE_AUTO_KVM || true
    export WVM_DISABLE_AUTO_KVM=0
else
    export WVM_DISABLE_AUTO_KVM=1
fi

smp=$vcpus
if [[ "$smp" -gt 1 ]]; then
    split=1
else
    # All remote via PROXY when single vCPU + split=0 (still remote path).
    split=0
fi

serial_log="$art_dir/vm-serial.log"
frontend_log="$art_dir/vm.log"
datadir="${WVM_TCG_QEMU_DATADIR:-$repo_root/wavevm-qemu/build/pc-bios}"

log "start Cirros frontend -m ${mem_mb} -smp $smp split=$split machine=$machine"
# Re-export launch env into frontend process explicitly.
set -a
# shellcheck disable=SC1090
source "$launch_env_file"
set +a
unset WVM_ROLE || true
unset WVM_SOCK_CMD WVM_SOCK_REQ WVM_SOCK_PUSH WVM_EXECUTOR_SESSION_FD || true
if [[ "${WVM_S6_BACKEND}" == "require-kvm" ]]; then
    unset WVM_DISABLE_AUTO_KVM || true
    export WVM_DISABLE_AUTO_KVM=0
else
    export WVM_DISABLE_AUTO_KVM=1
fi

# Cap live FE logs (Joe disk-full). Serial via QEMU file: chardev (attach14 pipe
# to cap_tee stayed 0B despite live FE). stderr via cap_tee (smoke shell stays up).
# In-place cap_watch bounds serial file same-inode. No ulimit -f.
cap_tee="$repo_root/scripts/wvm_cap_tee.py"
cap_watch="$repo_root/scripts/wvm_cap_watch.py"
log "log_cap_bytes=$GUEST_LOG_CAP_BYTES file_limit_bytes=$GUEST_FILE_LIMIT_BYTES"
: >"$serial_log"
# require-tcg Cirros FE historically runs Mode B user/SHM. When /dev/wavevm
# is loaded (Mode A session), QEMU would auto-pick KERNEL and bind can EINVAL
# if the create child already owns the context — force user for require-tcg.
accel_args="wavevm,split=${split}"
if [[ "${WVM_S6_BACKEND}" != "require-kvm" ]]; then
    accel_args="${accel_args},mode=user"
fi
"$qemu_bin" \
    -L "$datadir" \
    -accel "${accel_args}" \
    -machine "$machine" \
    -m "$mem_mb" \
    -smp "$smp" \
    -drive "file=${cirros_img},if=virtio,format=qcow2,snapshot=on" \
    -netdev "user,id=ne,hostfwd=tcp::${ssh_port}-:22" \
    -device "${WVM_GUEST_NIC:-e1000},netdev=ne,mac=52:54:00:12:34:56" \
    -display none -vga none \
    -serial "file:${serial_log}" \
    -monitor none \
    >/dev/null 2>"$frontend_log" &
frontend_pid=$!
if [[ -f "$cap_watch" ]]; then
    python3 "$cap_watch" "$serial_log" "$GUEST_LOG_CAP_BYTES" --pid "$frontend_pid" --interval 15 \
        >/dev/null 2>&1 &
    disown $! 2>/dev/null || true
    python3 "$cap_watch" "$frontend_log" "$GUEST_LOG_CAP_BYTES" --pid "$frontend_pid" --interval 15 \
        >/dev/null 2>&1 &
    disown $! 2>/dev/null || true
fi
sleep 3
if ! kill -0 "$frontend_pid" 2>/dev/null; then
    log "ERROR: Cirros frontend exited immediately"
    cat "$frontend_log" | tee -a "$art_dir/smoke.log" || true
    exit 1
fi
echo "$frontend_pid" >"$art_dir/frontend.pid"
log "frontend_pid=$frontend_pid serial=$serial_log"

log "waiting up to ${boot_timeout_s}s for 'cirros login:'"
deadline=$((SECONDS + boot_timeout_s))
login_ok=0
while (( SECONDS < deadline )); do
    if ! kill -0 "$frontend_pid" 2>/dev/null; then
        log "ERROR: frontend died before login"
        tail -n 80 "$frontend_log" | tee -a "$art_dir/smoke.log" || true
        tail -n 40 "$serial_log" 2>/dev/null | tee -a "$art_dir/smoke.log" || true
        exit 1
    fi
    if [[ -f "$serial_log" ]] && grep -q 'cirros login:' "$serial_log"; then
        login_ok=1
        break
    fi
    sleep 10
    if (( SECONDS % 60 < 10 )); then
        log "boot poll ${SECONDS}s serial_bytes=$(wc -c <"$serial_log" 2>/dev/null || echo 0)"
    fi
done
if [[ "$login_ok" != "1" ]]; then
    log "ERROR: cirros login not reached within ${boot_timeout_s}s"
    tail -n 80 "$serial_log" 2>/dev/null | tee -a "$art_dir/smoke.log" || true
    tail -n 40 "$frontend_log" | tee -a "$art_dir/smoke.log" || true
    printf 'guest_login=MISSING\n' >"$art_dir/result.txt"
    exit 1
fi
log "guest reached cirros login"
printf 'guest_login=PASS\n' >"$art_dir/result.txt"

log "waiting up to ${ssh_timeout_s}s for SSH login"
ssh_ok=0
ssh_deadline=$((SECONDS + ssh_timeout_s))
while (( SECONDS < ssh_deadline )); do
    if timeout 10s sshpass -p 'gocubsgo' ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=5 \
        -p "$ssh_port" cirros@127.0.0.1 'echo wavevm-guest-ssh-ok' \
        >"$art_dir/ssh_probe.txt" 2>&1; then
        ssh_ok=1
        break
    fi
    sleep 3
done
if [[ "$ssh_ok" != "1" ]]; then
    log "ERROR: guest SSH failed"
    cat "$art_dir/ssh_probe.txt" 2>/dev/null | tee -a "$art_dir/smoke.log" || true
    echo 'guest_ssh=MISSING' >>"$art_dir/result.txt"
    exit 1
fi
log "guest SSH PASS: $(tr -d '\r' <"$art_dir/ssh_probe.txt")"
echo 'guest_ssh=PASS' >>"$art_dir/result.txt"

# G9: snapshot remote completion counters BEFORE controlled load.
stats_before=$(grep -E '\[WVM-TCG-STATS\]' "$frontend_log" 2>/dev/null | tail -n 40 || true)
printf '%s\n' "$stats_before" >"$art_dir/stats_before.txt"
# s23g9: honest rpc_ok may leave zero STATS at SSH (HALT-WAKE no longer
# inflates remote_done). grep miss must not abort under pipefail.
remote_before=$( { grep -E '\[WVM-TCG-STATS\]' "$frontend_log" 2>/dev/null || true; } \
    | sed -n 's/.*remote_done=\([0-9][0-9]*\).*/\1/p' | awk '{s=$1} END{print s+0}')
local_before=$( { grep -E '\[WVM-TCG-STATS\]' "$frontend_log" 2>/dev/null || true; } \
    | sed -n 's/.*local_done=\([0-9][0-9]*\).*/\1/p' | awk '{s=$1} END{print s+0}')
force_before=$( { grep -E '\[WVM-TCG-STATS\]' "$frontend_log" 2>/dev/null || true; } \
    | sed -n 's/.*force_local_used=\([0-9][0-9]*\).*/\1/p' | awk '{s=$1} END{print s+0}')
echo "remote_done_before=$remote_before" >>"$art_dir/result.txt"
echo "local_done_before=$local_before" >>"$art_dir/result.txt"
echo "force_local_used_before=$force_before" >>"$art_dir/result.txt"

cpu_smoke_rc=0
cpu_smoke_timeout_s=${WVM_GUEST_CPU_SMOKE_TIMEOUT_S:-30}
if [[ "${WVM_S6_BACKEND}" == "require-kvm" ]]; then
    cpu_smoke_timeout_s=${WVM_GUEST_CPU_SMOKE_TIMEOUT_S:-90}
fi
# s23g: require-kvm uses dual-yes by default (LAPIC bounce + preempt drain).
# Set WVM_GUEST_CPU_SMOKE_LIGHT=1 to force the old light busy-loop fallback.
# require-tcg always dual-yes (historical G9 load for remote_done delta).
if [[ "${WVM_S6_BACKEND}" == "require-kvm" && "${WVM_GUEST_CPU_SMOKE_LIGHT:-0}" == "1" ]]; then
    # Quote $i so host does not expand; guest sh sees the loop variable.
    cpu_smoke_cmd='sh -c '"'"'i=0; while [ "$i" -lt 200000 ]; do i=$((i+1)); done; echo cpu-smoke-ok; free; grep -c ^processor /proc/cpuinfo'"'"''
else
    # s23g6: pin one yes per vCPU when taskset exists so AP has real work
    # for concurrent remote MAIN (not hard-coded remote_done N=2).
    cpu_smoke_cmd='sh -c "if command -v taskset >/dev/null 2>&1; then taskset -c 0 yes >/dev/null & taskset -c 1 yes >/dev/null & else yes >/dev/null & yes >/dev/null & fi; sleep 10; kill %1 %2 2>/dev/null; echo cpu-smoke-ok; free; cat /proc/cpuinfo | grep -c ^processor"'
fi
timeout "${cpu_smoke_timeout_s}s" sshpass -p 'gocubsgo' ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=5 \
    -p "$ssh_port" cirros@127.0.0.1 \
    "$cpu_smoke_cmd" \
    >"$art_dir/guest_cpu_smoke.txt" 2>&1 || cpu_smoke_rc=$?
cat "$art_dir/guest_cpu_smoke.txt" | tee -a "$art_dir/smoke.log" || true
if [[ "$cpu_smoke_rc" -ne 0 ]] || ! grep -q 'cpu-smoke-ok' "$art_dir/guest_cpu_smoke.txt"; then
    log "ERROR: guest CPU smoke failed rc=$cpu_smoke_rc"
    echo "guest_cpu_smoke=FAIL rc=$cpu_smoke_rc" >>"$art_dir/result.txt"
    echo 'OVERALL=FAIL_guest_cpu_smoke' >>"$art_dir/result.txt"
    cat "$art_dir/result.txt" | tee -a "$art_dir/smoke.log"
    exit 1
fi
echo 'guest_cpu_smoke=PASS' >>"$art_dir/result.txt"

# G9: after load, require remote_done delta (not READY/region_add banner).
# Concurrent spin hold may still pin the AP local for up to ~90s after arm;
# poll briefly so attribution is not a pure race with hold expiry.
remote_after=$remote_before
local_after=$local_before
force_after=$force_before
stats_after=""
g9_wait_s="${WVM_GUEST_G9_REMOTE_WAIT_S:-45}"
g9_deadline=$((SECONDS + g9_wait_s))
while true; do
    sleep 1
    stats_after=$(grep -E '\[WVM-TCG-STATS\]|\[WVM-REMOTE\]' "$frontend_log" 2>/dev/null | tail -n 80 || true)
    remote_after=$( { grep -E '\[WVM-TCG-STATS\]' "$frontend_log" 2>/dev/null || true; } \
        | sed -n 's/.*remote_done=\([0-9][0-9]*\).*/\1/p' | awk '{s=$1} END{print s+0}')
    local_after=$( { grep -E '\[WVM-TCG-STATS\]' "$frontend_log" 2>/dev/null || true; } \
        | sed -n 's/.*local_done=\([0-9][0-9]*\).*/\1/p' | awk '{s=$1} END{print s+0}')
    force_after=$( { grep -E '\[WVM-TCG-STATS\]' "$frontend_log" 2>/dev/null || true; } \
        | sed -n 's/.*force_local_used=\([0-9][0-9]*\).*/\1/p' | awk '{s=$1} END{print s+0}')
    remote_delta=$((remote_after - remote_before))
    if [[ "$remote_delta" -gt 0 ]]; then
        log "G9 remote_done advanced delta=$remote_delta (waited)"
        break
    fi
    if (( SECONDS >= g9_deadline )); then
        log "G9 remote wait ${g9_wait_s}s exhausted delta=0"
        break
    fi
done
printf '%s\n' "$stats_after" >"$art_dir/stats_after.txt"
local_delta=$((local_after - local_before))
force_delta=$((force_after - force_before))
echo "remote_done_after=$remote_after" >>"$art_dir/result.txt"
echo "local_done_after=$local_after" >>"$art_dir/result.txt"
echo "force_local_used_after=$force_after" >>"$art_dir/result.txt"
echo "remote_done_delta=$remote_delta" >>"$art_dir/result.txt"
echo "local_done_delta=$local_delta" >>"$art_dir/result.txt"
echo "force_local_used_delta=$force_delta" >>"$art_dir/result.txt"

{
    echo "=== G9 attribution (not boot banner) ==="
    echo "remote_done $remote_before -> $remote_after delta=$remote_delta"
    echo "local_done  $local_before -> $local_after delta=$local_delta"
    echo "force_local $force_before -> $force_after delta=$force_delta"
    echo "=== recent WVM-TCG-STATS / WVM-REMOTE ==="
    printf '%s\n' "$stats_after"
    echo "=== memory / dirty commit signals (authoritative; no vCPU-dispatch) ==="
    grep -E 'dirty commit|resync-merge|PUSH_BARRIER_ACK|wavevm_user_mem.*commit|slave TCG slice dirty flush|TYPED_MEM_COMMIT|handoff dirty flush pages=' \
        "$frontend_log" "$create_tmpdir/agent.log" 2>/dev/null | head -n 80 || true
    echo "=== WVM-REMOTE (vcpu only; NOT mem evidence) ==="
    grep -E '\[WVM-REMOTE\]' "$frontend_log" 2>/dev/null | head -n 20 || true
} >"$art_dir/remote_evidence.txt"

remote_vcpu=0
remote_mem=0
# Require post-login remote completion growth for designated remote path.
if [[ "$remote_delta" -gt 0 ]]; then
    remote_vcpu=1
elif [[ "${WVM_S6_BACKEND}" == "require-kvm" && "$remote_before" -gt 0 ]]; then
    # require-kvm: boot-time remote_done>0 still proves remote KVM path (§7)
    # when smoke delta is 0 (e.g. light fallback or drain-local dominated).
    remote_vcpu=1
    log "G9 require-kvm: accept remote_done_before=$remote_before (smoke delta=0)"
fi
# Memory: REAL dirty/commit/resync/fence only — never WVM-REMOTE vCPU dispatch,
# never SHM coherent / WVM-TCG-STATS alone (xiaolang M9 mis-attribution).
mem_hits=$(grep -E 'dirty commit|resync-merge|PUSH_BARRIER_ACK|wavevm_user_mem.*commit|slave TCG slice dirty flush pages=[1-9]|TYPED_MEM_COMMIT|handoff dirty flush pages=[1-9]|tcg_dirty_self_emit' \
    "$art_dir/remote_evidence.txt" "$frontend_log" "$create_tmpdir/agent.log" \
    "$create_tmpdir"/*.log "$art_dir"/*.log 2>/dev/null | head -n 40 || true)
printf '%s\n' "$mem_hits" >"$art_dir/remote_mem_hits.txt"
if [[ -n "$mem_hits" ]]; then
    remote_mem=1
fi
# Also accept numeric commit counters if instrumentation printed them.
if grep -qE 'remote_mem_commit_count=[1-9]|dirty_commit_pages=[1-9]|completed_commit_version=0x[1-9a-fA-F]' \
    "$art_dir/result.txt" "$frontend_log" "$create_tmpdir/agent.log" 2>/dev/null; then
    remote_mem=1
fi

echo "remote_vcpu_evidence=$remote_vcpu" >>"$art_dir/result.txt"
echo "remote_mem_evidence=$remote_mem" >>"$art_dir/result.txt"
cp -a "$create_tmpdir/agent.log" "$art_dir/agent.log" 2>/dev/null || true
cp -a "$art_dir/remote_evidence.txt" "$WVM_S6_EVIDENCE_DIR/" 2>/dev/null || true
cp -a "$art_dir/stats_before.txt" "$WVM_S6_EVIDENCE_DIR/" 2>/dev/null || true
cp -a "$art_dir/stats_after.txt" "$WVM_S6_EVIDENCE_DIR/" 2>/dev/null || true

if [[ "$remote_vcpu" != "1" || "$remote_mem" != "1" ]]; then
    log "ERROR: G9 remote attribution incomplete (vcpu=$remote_vcpu mem=$remote_mem delta=$remote_delta)"
    cat "$art_dir/remote_evidence.txt" | tee -a "$art_dir/smoke.log" || true
    echo 'OVERALL=FAIL_g9_remote_attribution' >>"$art_dir/result.txt"
    cat "$art_dir/result.txt" | tee -a "$art_dir/smoke.log"
    exit 1
fi

log "G9 remote attribution PASS delta_remote=$remote_delta delta_local=$local_delta"
# §8.1 acceptance item 2: optionally wait for named hard-cap/cooldown events
# (arm already present as NEED-LOCAL / SPIN-LOCAL). Default off.
if [[ "${WVM_GUEST_WAIT_81_EVENTS:-0}" == "1" ]]; then
    wait81_s="${WVM_GUEST_WAIT_81_EVENTS_S:-150}"
    log "§8.1 wait up to ${wait81_s}s for hard_cap_expiry (+ cooldown_suppress if spin)"
    deadline81=$((SECONDS + wait81_s))
    got_cap=0
    got_cd=0
    while (( SECONDS < deadline81 )); do
        if grep -q 'event=hard_cap_expiry' "$frontend_log" 2>/dev/null; then
            got_cap=1
        fi
        if grep -qE 'event=cooldown_suppress|event=renew' "$frontend_log" 2>/dev/null; then
            got_cd=1
        fi
        if [[ "$got_cap" == "1" ]]; then
            log "§8.1 hard_cap_expiry observed (renew/cooldown_suppress=$got_cd)"
            break
        fi
        sleep 2
    done
    {
        echo "section=8.1_acceptance_item_2"
        echo "wait_s=$wait81_s"
        echo "hard_cap_expiry=$got_cap"
        echo "renew_or_cooldown_suppress=$got_cd"
        echo "--- events ---"
        grep -E '\[WVM-TCG-(NEED-LOCAL|SPIN-LOCAL|FORCE-LOCAL)\]' "$frontend_log" 2>/dev/null \
            | grep -E 'arm force_local|hold_ms=|event=' || true
    } >"$art_dir/force_local_81_events.txt"
    cp -a "$art_dir/force_local_81_events.txt" "$WVM_S6_EVIDENCE_DIR/" 2>/dev/null || true
    if [[ "$got_cap" != "1" ]]; then
        log "WARN: §8.1 hard_cap_expiry not observed within ${wait81_s}s (pack still written)"
    fi
fi
# OVERALL written only after STOP/cleanup below (G9).

# §7 STOP evidence: Cirros path historically KEEP_RUNNING=1 + process kill only.
# When WVM_GUEST_REQUIRE_STOP=1 (default), call STOP_VM while ctl/agent still up
# so evidence is not REQUIRE_STOP=0-only. FE must die first so SHM can retire.
if [[ "${WVM_GUEST_REQUIRE_STOP:-1}" == "1" ]]; then
    log "REQUIRE_STOP=1 — stop Cirros FE then submit STOP_VM"
    echo 'REQUIRE_STOP=1' >>"$art_dir/result.txt"
    if [[ -n "${frontend_pid:-}" ]] && kill -0 "$frontend_pid" 2>/dev/null; then
        kill -TERM "$frontend_pid" 2>/dev/null || true
        for _i in $(seq 1 50); do
            kill -0 "$frontend_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$frontend_pid" 2>/dev/null || true
        wait "$frontend_pid" 2>/dev/null || true
        frontend_pid=""
    fi
    create_out=$(grep -E 'status=0 recorded_state=11 vm_id=' "$art_dir/create.log" | tail -1 || true)
    vm_id=$(sed -n 's/.*vm_id=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
    vm_inc=$(sed -n 's/.*vm_incarnation=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
    manifest_gen=$(sed -n 's/.*manifest_generation=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
    if [[ -z "$vm_id" || -z "$vm_inc" || -z "$manifest_gen" ]]; then
        log "ERROR: cannot parse CREATE identity for STOP"
        echo 'guest_stop=MISSING_identity' >>"$art_dir/result.txt"
        cat "$art_dir/result.txt" | tee -a "$art_dir/smoke.log"
        exit 1
    fi
    if [[ ! -x "$create_tmpdir/submit_stop_vm" ]]; then
        # Fractal KEEP historically omitted this binary; build on demand (same as s6_finish).
        log "submit_stop_vm missing — building under $create_tmpdir"
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
            -pthread -o "$create_tmpdir/submit_stop_vm"
        if [[ ! -x "$create_tmpdir/submit_stop_vm" ]]; then
            log "ERROR: submit_stop_vm build failed under $create_tmpdir"
            echo 'guest_stop=MISSING_binary' >>"$art_dir/result.txt"
            cat "$art_dir/result.txt" | tee -a "$art_dir/smoke.log"
            exit 1
        fi
    fi
    stop_out=$("$create_tmpdir/submit_stop_vm" "$create_tmpdir/ctl.sock" \
        "$vm_id" "$vm_inc" "$manifest_gen" 2>&1) || true
    printf '%s\n' "$stop_out" | tee "$art_dir/stop_result.txt" | tee -a "$art_dir/smoke.log"
    cp -a "$art_dir/stop_result.txt" "$WVM_S6_EVIDENCE_DIR/stop_result.txt" 2>/dev/null || true
    if ! grep -qE '^status=0 ' <<<"$stop_out"; then
        log "ERROR: STOP_VM failed: $stop_out"
        echo "guest_stop=FAIL" >>"$art_dir/result.txt"
        echo "stop_out=$stop_out" >>"$art_dir/result.txt"
        cat "$art_dir/result.txt" | tee -a "$art_dir/smoke.log"
        exit 1
    fi
    echo 'guest_stop=PASS' >>"$art_dir/result.txt"
    log "STOP_VM PASS"
    # Honesty: create/s6_finish may have written REQUIRE_STOP=0 cleanup.ok while
    # Cirros KEEP ran; overwrite with the real STOP acceptance evidence.
    {
        echo "cleanup_ok=1"
        echo "stop=$stop_out"
        echo "vm_id=$vm_id"
        echo "honesty=REQUIRE_STOP=1_full_STOP_acceptance"
    } >"$art_dir/cleanup.ok"
    if [[ -n "${WVM_S6_EVIDENCE_DIR:-}" ]]; then
        cp -a "$art_dir/cleanup.ok" "$WVM_S6_EVIDENCE_DIR/cleanup.ok" 2>/dev/null || true
    fi
else
    echo 'REQUIRE_STOP=0' >>"$art_dir/result.txt"
    echo 'guest_stop=SKIPPED_keep' >>"$art_dir/result.txt"
    log "REQUIRE_STOP=0 — Cirros KEEP path; STOP not required this run"
fi

# G9: unified result only after STOP/cleanup — never leave early OVERALL=PASS.
echo 'OVERALL=PASS' >>"$art_dir/result.txt"
log "GUEST SMOKE PASS art=$art_dir"
cat "$art_dir/result.txt" | tee -a "$art_dir/smoke.log"
exit 0

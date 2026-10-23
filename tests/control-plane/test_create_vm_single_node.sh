#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# §6 matrix: require-tcg (default) | require-kvm | auto. Guest login/SSH is §7.
s6_backend=${WVM_S6_BACKEND:-require-tcg}
case "$s6_backend" in
    require-tcg|require-kvm|auto) ;;
    *) echo "WVM_S6_BACKEND must be require-tcg|require-kvm|auto (got: $s6_backend)" >&2; exit 2 ;;
esac
s6_accel=${WVM_S6_ACCEL:-disabled}
case "$s6_accel" in
    disabled|require-kernel) ;;
    *) echo "WVM_S6_ACCEL must be disabled|require-kernel (got: $s6_accel)" >&2; exit 2 ;;
esac
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-single.XXXXXX")
ctl_pid=
agent_pid=
# shellcheck source=s6_cell_common.sh
source "$repo_root/tests/control-plane/s6_cell_common.sh"

cleanup() {
    if [[ "${WVM_S6_KEEP_RUNNING:-0}" == "1" ]]; then
        echo "s6: KEEP_RUNNING=1 — leaving agent/ctl up tmpdir=$tmpdir agent_pid=${agent_pid:-} ctl_pid=${ctl_pid:-}" >&2
        echo "$tmpdir" > /tmp/wavevm-s6-keep-tmpdir
        echo "${agent_pid:-}" > /tmp/wavevm-s6-keep-agent-pid
        echo "${ctl_pid:-}" > /tmp/wavevm-s6-keep-ctl-pid
        return 0
    fi
    if [[ -n "${agent_pid:-}" ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    if [[ -n "${ctl_pid:-}" ]]; then
        kill -TERM "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
    fi
    rm -rf -- "$tmpdir"
}
trap cleanup EXIT

export PATH="${HOME}/.local/bin:/home/box/.local/bin:${PATH}"
make -C "$repo_root/ctl_tool" -B -j2 >/dev/null
make -C "$repo_root/node_runtime" -j2 >/dev/null
s6_select_tcg_helper

common_objs=(
    "$repo_root/common_include/wavevm_sha256.c"
    "$repo_root/common_include/wavevm_canonical.c"
    "$repo_root/common_include/wavevm_identity.c"
    "$repo_root/common_include/wavevm_runtime_names.c"
    "$repo_root/common_include/wavevm_manifest.c"
    "$repo_root/common_include/wavevm_control.c"
    "$repo_root/common_include/wavevm_capability.c"
    "$repo_root/common_include/wavevm_lifecycle.c"
    "$repo_root/common_include/wavevm_admission.c"
    "$repo_root/common_include/wavevm_cluster.c"
    "$repo_root/common_include/wavevm_reservation_runtime.c"
    "$repo_root/common_include/wavevm_fault_engine.c"
    "$repo_root/common_include/wavevm_coordinator.c"
    "$repo_root/common_include/wavevm_envelope.c"
    "$repo_root/common_include/wavevm_membership_controller.c"
    "$repo_root/common_include/wavevm_membership_control.c"
    "$repo_root/common_include/wavevm_control_transport.c"
    "$repo_root/common_include/wavevm_runtime_profile.c"
    "$repo_root/common_include/wavevm_host_probe.c"
)

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${common_objs[@]}" \
    "$repo_root/tests/control-plane/seed_create_vm_evidence.c" \
    -pthread -o "$tmpdir/seed_evidence"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_create_vm.c" \
    -pthread -o "$tmpdir/submit_create_vm"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_stop_vm.c" \
    -pthread -o "$tmpdir/submit_stop_vm"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/check_agent_registration.c" \
    -pthread -o "$tmpdir/check_registration"

base_port=$(shuf -i 22000-50000 -n 1)
ctl_port=$base_port
agent_control_port=$((base_port + 1))
agent_data_port=$((base_port + 2))
sidecar_data_port=$((base_port + 3))
sidecar_control_port=$((base_port + 4))
profile_data0=$((base_port + 5))
profile_data1=$((base_port + 6))
profile_svc0=$((base_port + 7))
profile_svc1=$((base_port + 8))

mkdir "$tmpdir/ctl-state" "$tmpdir/node-state" "$tmpdir/runtime" "$tmpdir/evidence"

seed_flags=$(s6_seed_extra_flags)
# shellcheck disable=SC2086
digest=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    "$profile_data0" "$profile_data1" "$profile_svc0" "$profile_svc1" \
    "$agent_control_port" $seed_flags)
echo "s6 seed flags='$seed_flags' digest_prefix=${digest:0:16}..."
[[ ${#digest} -eq 64 ]]

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/ca.key" \
    -out "$tmpdir/ca.crt" >/dev/null 2>&1

make_cert() {
    local name=$1
    local common_name=$2

    openssl req -newkey rsa:2048 -nodes -subj "/CN=$common_name" \
        -keyout "$tmpdir/$name.key" -out "$tmpdir/$name.csr" \
        >/dev/null 2>&1
    openssl x509 -req -days 1 -in "$tmpdir/$name.csr" \
        -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" \
        -CAcreateserial -out "$tmpdir/$name.crt" >/dev/null 2>&1
}

make_cert controller node-runtime:701:702
make_cert node node-runtime:801:802
# Unix CREATE_VM client authenticates as executor; TLS carries node/controller.
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir/principals"

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir/ctl-state" \
    --socket "$tmpdir/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir/principals" --capacity 8 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir/ca.crt" \
    --control-cert "$tmpdir/controller.crt" \
    --control-key "$tmpdir/controller.key" \
    >"$tmpdir/ctl.log" 2>&1 &
ctl_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir/ctl.sock" ]]
kill -0 "$ctl_pid"

# Mode A (require-kernel) needs headroom for per-VM kernel-context leases
# (same floor as test_create_vm_dual_mode_a.sh). Mode B stays compact.
if [[ "$s6_accel" == "require-kernel" ]]; then
    agent_vcpu_slots=8
    agent_memory_bytes=2147483648
    agent_slots=4
    agent_max_vcpus=4
    agent_max_memory_chunks=4
    agent_max_leases=8
else
    agent_vcpu_slots=2
    agent_memory_bytes=1073741824
    agent_slots=2
    agent_max_vcpus=2
    agent_max_memory_chunks=2
    agent_max_leases=2
fi
agent_args=(agent
    --state-dir "$tmpdir/node-state"
    --runtime-dir "$tmpdir/runtime"
    --socket "$tmpdir/node.sock"
    --node-id 801 --instance-id 802 --inventory-revision 1
    --vcpu-slots "$agent_vcpu_slots" --memory-bytes "$agent_memory_bytes"
    --controller-node-id 701 --controller-instance-id 702
    --controller-uid "$(id -u)"
    --slots "$agent_slots" --max-vcpus "$agent_max_vcpus" --max-memory-chunks "$agent_max_memory_chunks"
    --max-storage 1 --max-members 8 --max-leases "$agent_max_leases"
    --control-address 127.0.0.1 --control-port "$agent_control_port"
    --data-port "$agent_data_port"
    --tls-ca "$tmpdir/ca.crt" --tls-cert "$tmpdir/node.crt"
    --tls-key "$tmpdir/node.key"
    --register-controller-address 127.0.0.1
    --register-controller-port "$ctl_port"
    --failure-domain-id 1 --pod-id 1 --vnode-first 1 --vnode-count 16
    --sidecar-address 127.0.0.1 --sidecar-data-port "$sidecar_data_port"
    --sidecar-control-port "$sidecar_control_port" --role-bits 1
    --capability-profile-generation 1
    --capability-profile-digest "$digest"
    --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222
    --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333
    --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444)

# Durable evidence must exist before compute enrollment reaches ACTIVE.
cp "$tmpdir/evidence/capabilities-801.record" "$tmpdir/ctl-state/"
cp "$tmpdir/evidence/runtime-profile-801.record" "$tmpdir/ctl-state/"

env WVM_TCG_QEMU_BIN="$WVM_TCG_QEMU_BIN" WVM_TCG_QEMU_DATADIR="${WVM_TCG_QEMU_DATADIR:-}" WVM_TCG_QEMU_MACHINE="${WVM_TCG_QEMU_MACHINE:-}" WVM_TCG_QEMU_MEM_MB="${WVM_TCG_QEMU_MEM_MB:-}"     "$repo_root/wavevm_node_runtime" "${agent_args[@]}" >"$tmpdir/agent.log" 2>&1 &
agent_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir/node.sock" ]] && kill -0 "$agent_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir/node.sock" ]]
kill -0 "$agent_pid"

# Wait for durable registration+enrollment journals without opening them under the
# live ctl writer (check_registration recovers offline after CREATE).
for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ -s "$tmpdir/ctl-state/membership.journal" ]] &&
       [[ -s "$tmpdir/ctl-state/membership-control.journal" ]] &&
       [[ $(stat -c %s "$tmpdir/ctl-state/membership-control.journal") -gt 64 ]]; then
        break
    fi
    sleep 0.05
done
[[ -s "$tmpdir/ctl-state/membership.journal" ]]
[[ -s "$tmpdir/ctl-state/membership-control.journal" ]]
# Poll until compute membership is ACTIVE (enrollment may retry after
# REGISTER/control-stream race). Fixed 0.5s was timing-sensitive.
# check_registration opens the journal offline — only safe once ctl is idle
# enough; copy snap to avoid racing the live writer when possible.
active_ok=0
for ((attempt = 0; attempt < 200; attempt++)); do
    cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap" 2>/dev/null || true
    if "$tmpdir/check_registration" "$tmpdir/membership.journal.snap"         "$agent_control_port" "$agent_vcpu_slots" "$agent_memory_bytes" >/dev/null 2>&1; then
        active_ok=1
        break
    fi
    sleep 0.05
done
if [[ "$active_ok" -ne 1 ]]; then
    echo "compute member did not reach ACTIVE before CREATE_VM" >&2
    mkdir -p /tmp/wavevm-enroll-diag
    cp -a "$tmpdir/ctl.log" "$tmpdir/agent.log" "$tmpdir/ctl-state" /tmp/wavevm-enroll-diag/ 2>/dev/null || true
    echo "diag copied to /tmp/wavevm-enroll-diag (tmpdir=$tmpdir)" >&2
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    tail -n 80 "$tmpdir/agent.log" >&2 || true
    exit 1
fi
if ! kill -0 "$agent_pid" 2>/dev/null || ! kill -0 "$ctl_pid" 2>/dev/null; then
    echo "ctl or agent exited before CREATE_VM" >&2
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    tail -n 80 "$tmpdir/agent.log" >&2 || true
    exit 1
fi

# Replay CREATE_VM until live ready promotes COMMITTED→RUNNING, or timeout.
create_out=""
for ((attempt = 0; attempt < 80; attempt++)); do
    create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" \
        single-node-create 1 compact 71 "$s6_accel" "$s6_backend" || true)
    echo "attempt=$attempt $create_out"
    if [[ "$create_out" == status=0* ]]; then
        break
    fi
    if [[ "$create_out" != status=14* ]]; then
        break
    fi
    sleep 0.25
done
echo "$create_out"
# Honest RUNNING: SUCCESS(0). IN_PROGRESS(14) means COMMITTED without live ready.
# WVM_S6_EXPECT_REJECT=1: negative cells — non-SUCCESS is the PASS path.
if [[ "$create_out" != status=0* ]]; then
    if [[ "${WVM_S6_EXPECT_REJECT:-0}" == "1" ]]; then
        echo "CREATE_VM rejected as expected (got: $create_out)"
        s6_write_evidence_file "create_result.txt" "$create_out"
        s6_copy_evidence "$tmpdir/evidence/seed-meta.txt" "seed-meta.txt"
        s6_copy_evidence "$tmpdir/agent.log" "agent.log"
        s6_copy_evidence "$tmpdir/ctl.log" "ctl.log"
        s6_finish_reject "expected_reject:$create_out"
        echo "single-node CREATE_VM REJECT: PASS backend=$s6_backend accel=$s6_accel ($create_out)"
        exit 0
    fi
    echo "CREATE_VM did not reach SUCCESS(0)/RUNNING (got: $create_out)" >&2
    echo "--- ctl.log ---" >&2
    cat "$tmpdir/ctl.log" >&2 || true
    echo "--- agent.log ---" >&2
    cat "$tmpdir/agent.log" >&2 || true
    echo "--- child runtime logs ---" >&2
    find "$tmpdir/runtime" -type f \( -name '*.log' -o -name 'stderr*' -o -name 'stdout*' \) \
        -print -exec cat {} \; >&2 2>/dev/null || true
    kill -TERM "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
    agent_pid=
    kill -TERM "$ctl_pid" 2>/dev/null || true
    wait "$ctl_pid" 2>/dev/null || true
    ctl_pid=
    if "$tmpdir/check_registration" "$tmpdir/ctl-state/membership.journal"         "$agent_control_port" "$agent_vcpu_slots" "$agent_memory_bytes"; then
        echo "membership ACTIVE confirmed offline" >&2
    else
        echo "membership NOT ACTIVE offline" >&2
    fi
    exit 1
fi
if [[ "${WVM_S6_EXPECT_REJECT:-0}" == "1" ]]; then
    echo "CREATE_VM unexpectedly SUCCEEDED under EXPECT_REJECT (got: $create_out)" >&2
    s6_finish_reject "unexpected_success:$create_out"
    exit 1
fi

# R4: production STOP + per-resource cleanup evidence BEFORE tearing down agent
s6_finish_running_vm "$create_out" "$tmpdir/submit_stop_vm"

"$tmpdir/check_registration" "$tmpdir/ctl-state/membership.journal"     "$agent_control_port" "$agent_vcpu_slots" "$agent_memory_bytes"

if [[ "${WVM_S6_KEEP_RUNNING:-0}" == "1" ]]; then
    echo "s6: KEEP_RUNNING — skip final agent/ctl teardown" >&2
    echo "$tmpdir" > /tmp/wavevm-s6-keep-tmpdir
    echo "$agent_pid" > /tmp/wavevm-s6-keep-agent-pid
    echo "$ctl_pid" > /tmp/wavevm-s6-keep-ctl-pid
    grep -E 'Listening on|Mode:|SHM File|executor READY' "$tmpdir/agent.log"         > /tmp/wavevm-s6-keep-ports.txt || true
else
    kill -TERM "$agent_pid"
    wait "$agent_pid" || true
    agent_pid=
    kill -TERM "$ctl_pid"
    wait "$ctl_pid" || true
    ctl_pid=
fi

echo "single-node CREATE_VM prepare→activate→commit→RUNNING: PASS backend=$s6_backend accel=$s6_accel ($create_out)"

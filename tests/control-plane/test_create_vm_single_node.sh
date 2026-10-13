#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-single.XXXXXX")
ctl_pid=
agent_pid=

cleanup() {
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
gcc -Wall -Wextra -Werror -std=c11 \
    "$repo_root/tests/control-plane/tcg_helper_stub.c" \
    -o "$tmpdir/tcg_helper_stub"
export WVM_TCG_QEMU_BIN="$tmpdir/tcg_helper_stub"

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

digest=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    "$profile_data0" "$profile_data1" "$profile_svc0" "$profile_svc1" \
    "$agent_control_port")
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

agent_args=(agent
    --state-dir "$tmpdir/node-state"
    --runtime-dir "$tmpdir/runtime"
    --socket "$tmpdir/node.sock"
    --node-id 801 --instance-id 802 --inventory-revision 1
    --vcpu-slots 2 --memory-bytes 1073741824
    --controller-node-id 701 --controller-instance-id 702
    --controller-uid "$(id -u)"
    --slots 2 --max-vcpus 2 --max-memory-chunks 2
    --max-storage 1 --max-members 8 --max-leases 2
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

env WVM_TCG_QEMU_BIN="$tmpdir/tcg_helper_stub"     "$repo_root/wavevm_node_runtime" "${agent_args[@]}" >"$tmpdir/agent.log" 2>&1 &
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
# Give enrollment prepare/commit a moment after journal creation.
sleep 0.5
if ! kill -0 "$agent_pid" 2>/dev/null || ! kill -0 "$ctl_pid" 2>/dev/null; then
    echo "ctl or agent exited before CREATE_VM" >&2
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    tail -n 80 "$tmpdir/agent.log" >&2 || true
    exit 1
fi

# Replay CREATE_VM until live ready promotes COMMITTED→RUNNING, or timeout.
create_out=""
for ((attempt = 0; attempt < 80; attempt++)); do
    create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" || true)
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
if [[ "$create_out" != status=0* ]]; then
    echo "CREATE_VM did not reach SUCCESS(0)/RUNNING (got: $create_out)" >&2
    echo "--- ctl.log ---" >&2
    cat "$tmpdir/ctl.log" >&2 || true
    echo "--- agent.log ---" >&2
    cat "$tmpdir/agent.log" >&2 || true
    echo "--- child runtime logs ---" >&2
    find "$tmpdir/runtime" -type f \( -name '*.log' -o -name 'stderr*' -o -name 'stdout*' \) \
        -print -exec cat {} \; >&2 2>/dev/null || true
    # Stop ctl to allow offline ACTIVE check for diagnosis.
    kill -TERM "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
    agent_pid=
    kill -TERM "$ctl_pid" 2>/dev/null || true
    wait "$ctl_pid" 2>/dev/null || true
    ctl_pid=
    if "$tmpdir/check_registration" "$tmpdir/ctl-state/membership.journal" \
        "$agent_control_port"; then
        echo "membership ACTIVE confirmed offline" >&2
    else
        echo "membership NOT ACTIVE offline" >&2
    fi
    exit 1
fi

kill -TERM "$agent_pid"
wait "$agent_pid" || true
agent_pid=
kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=
"$tmpdir/check_registration" "$tmpdir/ctl-state/membership.journal" \
    "$agent_control_port"

echo "single-node CREATE_VM prepare→activate→commit→RUNNING: PASS ($create_out)"

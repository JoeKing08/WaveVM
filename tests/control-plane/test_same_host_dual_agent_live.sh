#!/usr/bin/env bash
# Live same-host dual wavevm_node_runtime agents (Phase 7).
# Two agents share --physical-host-id with split registered/allocatable capacity,
# distinct ports/namespaces; both REGISTER→ACTIVE; journal passes aggregate.
# Companion to test_same_host_dual_agent.sh (controller enrollment vertical).
# Does not invent HA; Mode A gate stays closed.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-same-host-live.XXXXXX")
ctl_pid=
gw_pid=
agent_a_pid=
agent_b_pid=

cleanup() {
    for pid_var in agent_b_pid agent_a_pid gw_pid ctl_pid; do
        pid=${!pid_var:-}
        if [[ -n "$pid" ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf -- "$tmpdir"
}
trap cleanup EXIT

export PATH="${HOME}/.local/bin:/home/box/.local/bin:${PATH}"
make -C "$repo_root/ctl_tool" -B >/dev/null
make -C "$repo_root/gateway_service" >/dev/null
make -C "$repo_root/node_runtime" -j2 >/dev/null

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/check_same_host_dual_agent.c" \
    -pthread -o "$tmpdir/check_same_host_dual"

base_port=$(shuf -i 22000-50000 -n 1)
ctl_port=$base_port
gw_data_port=$((base_port + 1))
gw_control_port=$((base_port + 2))
gw_legacy_ctrl=$((base_port + 3))
a_control=$((base_port + 4))
a_data=$((base_port + 5))
a_side_data=$((base_port + 6))
a_side_ctrl=$((base_port + 7))
b_control=$((base_port + 8))
b_data=$((base_port + 9))
b_side_data=$((base_port + 10))
b_side_ctrl=$((base_port + 11))

mkdir -p "$tmpdir/ctl-state" "$tmpdir/gw-state/enrollment" \
    "$tmpdir/node-a" "$tmpdir/runtime-a" "$tmpdir/node-b" "$tmpdir/runtime-b"
: > "$tmpdir/gw-empty.conf"

# Real capability evidence before ACTIVE (audit).
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
mkdir -p "$tmpdir/evidence"
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" "${common_objs[@]}" \
    "$repo_root/tests/control-plane/seed_create_vm_evidence.c" \
    -pthread -o "$tmpdir/seed_evidence"
HOST_ID=9001
digest_a=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    $((base_port + 20)) $((base_port + 21)) $((base_port + 22)) $((base_port + 23)) \
    "$a_control" "$HOST_ID")
digest_b=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 811 812 1 1 \
    $((base_port + 24)) $((base_port + 25)) $((base_port + 26)) $((base_port + 27)) \
    "$b_control" "$HOST_ID")
cp "$tmpdir/evidence/"*.record "$tmpdir/ctl-state/"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/ca.key" \
    -out "$tmpdir/ca.crt" >/dev/null 2>&1
make_cert() {
    local name=$1 cn=$2
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$cn" \
        -keyout "$tmpdir/$name.key" -out "$tmpdir/$name.csr" >/dev/null 2>&1
    openssl x509 -req -days 1 -in "$tmpdir/$name.csr" \
        -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" -CAcreateserial \
        -out "$tmpdir/$name.crt" >/dev/null 2>&1
}
make_cert controller node-runtime:701:702
make_cert gateway gateway:901:902
make_cert nodea node-runtime:801:802
make_cert nodeb node-runtime:811:812
printf '%s node-runtime 701 702\n' "$(id -u)" > "$tmpdir/principals"

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir/ctl-state" --socket "$tmpdir/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir/principals" --capacity 16 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir/ca.crt" \
    --control-cert "$tmpdir/controller.crt" \
    --control-key "$tmpdir/controller.key" \
    >"$tmpdir/ctl.log" 2>&1 &
ctl_pid=$!
for ((i = 0; i < 100; i++)); do
    [[ -S "$tmpdir/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/ctl.sock" ]]

# 1) Gateway first (empty-cluster enrollment).
export WVM_GATEWAY_ID=901 WVM_GATEWAY_INSTANCE_ID=902
export WVM_GATEWAY_ROUTE_JOURNAL_PATH="$tmpdir/gw-state/route.journal"
export WVM_GATEWAY_CONTROL_SOCKET="$tmpdir/gw-state/control.sock"
export WVM_GATEWAY_ENROLLMENT_STATE_DIR="$tmpdir/gw-state/enrollment"
export WVM_GATEWAY_CONTROLLER_ROLE=node-runtime
export WVM_GATEWAY_CONTROLLER_ID=701
export WVM_GATEWAY_CONTROLLER_INSTANCE_ID=702
export WVM_GATEWAY_CONTROLLER_PHYSICAL_NODE_ID=701
export WVM_GATEWAY_CONTROLLER_RUNTIME_INSTANCE_ID=702
export WVM_GATEWAY_CONTROL_ADDRESS=127.0.0.1
export WVM_GATEWAY_CONTROL_PORT=$gw_control_port
export WVM_GATEWAY_CONTROL_CA_FILE="$tmpdir/ca.crt"
export WVM_GATEWAY_CONTROL_CERTIFICATE_FILE="$tmpdir/gateway.crt"
export WVM_GATEWAY_CONTROL_PRIVATE_KEY_FILE="$tmpdir/gateway.key"
export WVM_GATEWAY_REGISTER_CONTROLLER_ADDRESS=127.0.0.1
export WVM_GATEWAY_REGISTER_CONTROLLER_PORT=$ctl_port
export WVM_GATEWAY_HOSTING_NODE_ID=801
export WVM_GATEWAY_FAILURE_DOMAIN_ID=1
export WVM_GATEWAY_POD_ID=1
export WVM_GATEWAY_ROLE_BITS=1
export WVM_GATEWAY_SINGLE_RX=1

"$repo_root/gateway_service/wavevm_gateway" \
    "$gw_data_port" 127.0.0.1 9 "$tmpdir/gw-empty.conf" "$gw_legacy_ctrl" \
    >"$tmpdir/gw.log" 2>&1 &
gw_pid=$!
for ((i = 0; i < 200; i++)); do
    if grep -q "REGISTER accepted" "$tmpdir/gw.log" 2>/dev/null; then
        break
    fi
    kill -0 "$gw_pid" 2>/dev/null || { cat "$tmpdir/gw.log" >&2; exit 1; }
    sleep 0.05
done
grep -q "REGISTER accepted" "$tmpdir/gw.log"

start_node() {
    local node_id=$1 instance=$2 control=$3 data=$4 side_d=$5 side_c=$6
    local state=$7 runtime=$8 sock=$9
    local cert=${10}
    local log=${11}
    local digest=${12}
    local vnode_first=${13}

    # Same physical host: identical registered_*; each agent gets half allocatable.
    "$repo_root/wavevm_node_runtime" agent \
        --state-dir "$state" --runtime-dir "$runtime" --socket "$sock" \
        --node-id "$node_id" --instance-id "$instance" --inventory-revision 1 \
        --vcpu-slots 2 --memory-bytes 1073741824 \
        --registered-vcpu-slots 4 --registered-memory-bytes 2147483648 \
        --physical-host-id "$HOST_ID" \
        --controller-node-id 701 --controller-instance-id 702 \
        --controller-uid "$(id -u)" \
        --slots 2 --max-vcpus 2 --max-memory-chunks 2 \
        --max-storage 1 --max-members 8 --max-leases 2 \
        --control-address 127.0.0.1 --control-port "$control" \
        --data-port "$data" \
        --tls-ca "$tmpdir/ca.crt" --tls-cert "$tmpdir/$cert.crt" \
        --tls-key "$tmpdir/$cert.key" \
        --register-controller-address 127.0.0.1 \
        --register-controller-port "$ctl_port" \
        --failure-domain-id 1 --pod-id 1 --vnode-first "$vnode_first" --vnode-count 16 \
        --sidecar-address 127.0.0.1 --sidecar-data-port "$side_d" \
        --sidecar-control-port "$side_c" --role-bits 1 \
        --capability-profile-generation 1 \
        --capability-profile-digest "$digest" \
        --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222 \
        --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333 \
        --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444 \
        >"$log" 2>&1 &
    echo $!
}

agent_a_pid=$(start_node 801 802 "$a_control" "$a_data" "$a_side_data" \
    "$a_side_ctrl" "$tmpdir/node-a" "$tmpdir/runtime-a" "$tmpdir/node-a.sock" \
    nodea "$tmpdir/agent-a.log" "$digest_a" 0)
for ((i = 0; i < 200; i++)); do
    [[ -S "$tmpdir/node-a.sock" ]] && kill -0 "$agent_a_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/node-a.sock" ]]
# Allow node A enrollment (ACK set includes ACTIVE gateway) to finish.
sleep 1.0
if ! kill -0 "$agent_a_pid" 2>/dev/null; then
    echo "node A exited during enrollment" >&2
    cat "$tmpdir/agent-a.log" >&2
    cat "$tmpdir/ctl.log" >&2
    exit 1
fi

agent_b_pid=$(start_node 811 812 "$b_control" "$b_data" "$b_side_data" \
    "$b_side_ctrl" "$tmpdir/node-b" "$tmpdir/runtime-b" "$tmpdir/node-b.sock" \
    nodeb "$tmpdir/agent-b.log" "$digest_b" 16)
for ((i = 0; i < 200; i++)); do
    [[ -S "$tmpdir/node-b.sock" ]] && kill -0 "$agent_b_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/node-b.sock" ]]
# Allow node B enrollment (ACK gateway + node A + self).
sleep 1.5
if ! kill -0 "$agent_b_pid" 2>/dev/null; then
    echo "node B exited during enrollment" >&2
    cat "$tmpdir/agent-b.log" >&2
    cat "$tmpdir/ctl.log" >&2
    exit 1
fi

# Quiesce writers before offline journal open.
kill -TERM "$agent_b_pid" "$agent_a_pid" "$gw_pid" "$ctl_pid" 2>/dev/null || true
wait "$agent_b_pid" 2>/dev/null || true
wait "$agent_a_pid" 2>/dev/null || true
wait "$gw_pid" 2>/dev/null || true
wait "$ctl_pid" 2>/dev/null || true
agent_b_pid=; agent_a_pid=; gw_pid=; ctl_pid=

# Fail-closed over-budget register covered by test_same_host_dual_agent.sh
if ! "$tmpdir/check_same_host_dual" "$tmpdir/ctl-state/membership.journal"; then
    echo "--- ctl ---" >&2; cat "$tmpdir/ctl.log" >&2 || true
    echo "--- gw ---" >&2; cat "$tmpdir/gw.log" >&2 || true
    echo "--- a ---" >&2; cat "$tmpdir/agent-a.log" >&2 || true
    echo "--- b ---" >&2; cat "$tmpdir/agent-b.log" >&2 || true
    exit 1
fi
echo "same-host dual agent live (shared physical_host_id + aggregate): PASS"

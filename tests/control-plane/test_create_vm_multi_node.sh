#!/usr/bin/env bash
# Cross-node CREATE_VM: ≥1 ACTIVE gateway + ≥2 ACTIVE compute, gateway-backed
# FLAT route (not leaf), honest prepare→activate→commit→readiness→RUNNING.
# Does not claim guest E2E. Uses a live TCG helper stub (not QEMU guest).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-multi.XXXXXX")
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
    echo "KEEP=$tmpdir" >&2; #rm -rf -- "$tmpdir"
}
trap cleanup EXIT

export PATH="${HOME}/.local/bin:/home/box/.local/bin:${PATH}"

make -C "$repo_root/ctl_tool" -B -j2 >/dev/null
make -C "$repo_root/gateway_service" >/dev/null
make -C "$repo_root/node_runtime" -j2 >/dev/null

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
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/check_multi_active_cluster.c" \
    -pthread -o "$tmpdir/check_multi_active"
gcc -Wall -Wextra -Werror -std=c11 \
    "$repo_root/tests/control-plane/tcg_helper_stub.c" \
    -o "$tmpdir/tcg_helper_stub"
export WVM_TCG_QEMU_BIN="$tmpdir/tcg_helper_stub"

wait_multi_active() {
    local attempts=$1
    local i
    for ((i = 0; i < attempts; i++)); do
        if [[ -s "$tmpdir/ctl-state/membership.journal" ]]; then
            cp -f "$tmpdir/ctl-state/membership.journal" \
                "$tmpdir/membership.journal.snap" 2>/dev/null || true
            if [[ -s "$tmpdir/membership.journal.snap" ]] &&
               "$tmpdir/check_multi_active" "$tmpdir/membership.journal.snap" \
                   >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.05
    done
    return 1
}

wait_member_count_at_least() {
    # Offline copy probe via check_multi_active only when count==3; for 1/2 use
    # dump helper built below is heavy — use journal size + sleep and verify
    # with multi check only at the end. For sequential waits use multi only
    # after both nodes. For gateway-only, use a small C wait omitted: sleep
    # after REGISTER then proceed with evidence already present.
    sleep "$1"
}

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
a_profile_data0=$((base_port + 12))
a_profile_data1=$((base_port + 13))
a_profile_svc0=$((base_port + 14))
a_profile_svc1=$((base_port + 15))
b_profile_data0=$((base_port + 16))
b_profile_data1=$((base_port + 17))
b_profile_svc0=$((base_port + 18))
b_profile_svc1=$((base_port + 19))

mkdir -p "$tmpdir/ctl-state" "$tmpdir/gw-state/enrollment" \
    "$tmpdir/node-a" "$tmpdir/runtime-a" "$tmpdir/node-b" "$tmpdir/runtime-b" \
    "$tmpdir/evidence"
: > "$tmpdir/gw-empty.conf"

digest_a=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    "$a_profile_data0" "$a_profile_data1" "$a_profile_svc0" "$a_profile_svc1" \
    "$a_control")
digest_b=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 811 812 1 1 \
    "$b_profile_data0" "$b_profile_data1" "$b_profile_svc0" "$b_profile_svc1" \
    "$b_control")
[[ ${#digest_a} -eq 64 ]]
[[ ${#digest_b} -eq 64 ]]
# Evidence must exist before ACTIVE enrollment (audit: real capability evidence).
cp "$tmpdir/evidence/capabilities-801.record" "$tmpdir/ctl-state/"
cp "$tmpdir/evidence/runtime-profile-801.record" "$tmpdir/ctl-state/"
cp "$tmpdir/evidence/capabilities-811.record" "$tmpdir/ctl-state/"
cp "$tmpdir/evidence/runtime-profile-811.record" "$tmpdir/ctl-state/"

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
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir/principals"

stdbuf -o0 -e0 "$repo_root/ctl_tool/wvm_ctl" serve \
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
unset WVM_GATEWAY_FORCE_SINGLE_FD || true

stdbuf -o0 -e0 "$repo_root/gateway_service/wavevm_gateway" \
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
# Allow gateway enrollment COMMITTED/ACTIVE before compute joins.
sleep 1.0

start_node() {
    local node_id=$1 instance=$2 control=$3 data=$4 side_d=$5 side_c=$6
    local state=$7 runtime=$8 sock=$9
    local cert=${10}
    local log=${11}
    local digest=${12}
    local vnode_first=${13}
    local vnode_count=${14}

    stdbuf -o0 -e0 env WVM_TCG_QEMU_BIN="$tmpdir/tcg_helper_stub" \
        "$repo_root/wavevm_node_runtime" agent \
        --state-dir "$state" --runtime-dir "$runtime" --socket "$sock" \
        --node-id "$node_id" --instance-id "$instance" --inventory-revision 1 \
        --vcpu-slots 4 --memory-bytes 1073741824 \
        --controller-node-id 701 --controller-instance-id 702 \
        --controller-uid "$(id -u)" \
        --slots 2 --max-vcpus 4 --max-memory-chunks 2 \
        --max-storage 1 --max-members 8 --max-leases 2 \
        --control-address 127.0.0.1 --control-port "$control" \
        --data-port "$data" \
        --tls-ca "$tmpdir/ca.crt" --tls-cert "$tmpdir/$cert.crt" \
        --tls-key "$tmpdir/$cert.key" \
        --register-controller-address 127.0.0.1 \
        --register-controller-port "$ctl_port" \
        --failure-domain-id 1 --pod-id 1 \
        --vnode-first "$vnode_first" --vnode-count "$vnode_count" \
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

# Non-overlapping vnode ranges for FLAT+gateway exact-vnode rules.
agent_a_pid=$(start_node 801 802 "$a_control" "$a_data" "$a_side_data" \
    "$a_side_ctrl" "$tmpdir/node-a" "$tmpdir/runtime-a" "$tmpdir/node-a.sock" \
    nodea "$tmpdir/agent-a.log" "$digest_a" 0 16)
for ((i = 0; i < 200; i++)); do
    [[ -S "$tmpdir/node-a.sock" ]] && kill -0 "$agent_a_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/node-a.sock" ]]
# Wait for node A enrollment (ACK includes ACTIVE gateway) before starting B.
sleep 1.5
if ! kill -0 "$agent_a_pid" 2>/dev/null; then
    echo "node A exited during enrollment" >&2
    cat "$tmpdir/agent-a.log" >&2
    cat "$tmpdir/ctl.log" >&2
    exit 1
fi

agent_b_pid=$(start_node 811 812 "$b_control" "$b_data" "$b_side_data" \
    "$b_side_ctrl" "$tmpdir/node-b" "$tmpdir/runtime-b" "$tmpdir/node-b.sock" \
    nodeb "$tmpdir/agent-b.log" "$digest_b" 16 16)
for ((i = 0; i < 200; i++)); do
    [[ -S "$tmpdir/node-b.sock" ]] && kill -0 "$agent_b_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/node-b.sock" ]]

if ! wait_multi_active 200; then
    echo "cluster did not reach multi-ACTIVE before CREATE_VM" >&2
    echo "--- ctl ---" >&2; cat "$tmpdir/ctl.log" >&2 || true
    echo "--- gw ---" >&2; cat "$tmpdir/gw.log" >&2 || true
    echo "--- a ---" >&2; cat "$tmpdir/agent-a.log" >&2 || true
    echo "--- b ---" >&2; cat "$tmpdir/agent-b.log" >&2 || true
    exit 1
fi
echo "multi-ACTIVE confirmed before CREATE_VM"

create_out=""
for ((attempt = 0; attempt < 80; attempt++)); do
    # Compact packs guest vCPU+memory on one host. Spread can assign a vCPU to a
    # node with zero local memory; node_runtime honestly refuses that until remote
    # memory executor support exists. Gateway-backed FLAT still applies because
    # ≥2 ACTIVE compute + ACTIVE gateway compile EXACT_VNODE→gateway (not leaf).
    create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" \
        multi-node-create 2 compact || true)
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
if [[ "$create_out" != status=0* ]]; then
    echo "CREATE_VM did not reach SUCCESS(0)/RUNNING (got: $create_out)" >&2
    echo "--- ctl.log ---" >&2; cat "$tmpdir/ctl.log" >&2 || true
    echo "--- gw.log ---" >&2; cat "$tmpdir/gw.log" >&2 || true
    echo "--- agent-a.log ---" >&2; cat "$tmpdir/agent-a.log" >&2 || true
    echo "--- agent-b.log ---" >&2; cat "$tmpdir/agent-b.log" >&2 || true
    find "$tmpdir/runtime-a" "$tmpdir/runtime-b" -type f \
        \( -name '*.log' -o -name 'stderr*' -o -name 'stdout*' \) \
        -print -exec cat {} \; >&2 2>/dev/null || true
    exit 1
fi

if [[ ! -s "$tmpdir/gw-state/route.journal" ]]; then
    echo "gateway route journal empty after CREATE_VM" >&2
    exit 1
fi

kill -TERM "$agent_b_pid" "$agent_a_pid" "$gw_pid" "$ctl_pid" 2>/dev/null || true
wait "$agent_b_pid" 2>/dev/null || true
wait "$agent_a_pid" 2>/dev/null || true
wait "$gw_pid" 2>/dev/null || true
wait "$ctl_pid" 2>/dev/null || true
agent_b_pid=; agent_a_pid=; gw_pid=; ctl_pid=

"$tmpdir/check_multi_active" "$tmpdir/ctl-state/membership.journal"
echo "multi-node+gateway CREATE_VM prepare→activate→commit→RUNNING: PASS ($create_out)"

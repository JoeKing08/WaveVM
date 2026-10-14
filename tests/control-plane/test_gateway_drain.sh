#!/usr/bin/env bash
# Production-path gateway eligibility removal slice (documented CORDON).
#
# Specs followed (no invented protocol):
# - wire-ipc-abi.md §4.2 table: CORDON (0x0102) targets NODE_RUNTIME or GATEWAY
#   → durable CORDONED; DRAIN (0x0103) requires PREPARE+complete successor then
#   COMMIT to DRAINING (换血). DRAIN_COMPUTE (0x0106) rejects gateway targets.
# - wire-ipc-abi.md §4.2.2–4.2.3: drain authorizer vs cordon authorizer;
#   COMMIT without prior PREPARE must fail-closed.
# - canonical-record-schema.md: gateway drain action = PREPARE|COMMIT|ABORT only;
#   MemberCordonRequest may target GATEWAY.
# - architecture-baseline: CORDONED blocks new placement; gateway leave requires
#   prepared successor for every affected destination (换血) — not claimed here.
#
# Asserts: ACTIVE gateway → production CORDON → durable CORDONED; CREATE_VM
# fail-closed when sole GatewayRecord is ineligible; production DRAIN COMMIT
# without PREPARE/successor fail-closes. No guest E2E; no successor 换血 claim.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-gateway-drain.XXXXXX")
ctl_pid=
gw_pid=
agent_pid=

cleanup() {
    if [[ -n "${agent_pid:-}" ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    if [[ -n "${gw_pid:-}" ]]; then
        kill -TERM "$gw_pid" 2>/dev/null || true
        wait "$gw_pid" 2>/dev/null || true
    fi
    if [[ -n "${ctl_pid:-}" ]]; then
        kill -TERM "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
    fi
    rm -rf -- "$tmpdir"
}
trap cleanup EXIT

export PATH="${HOME}/.local/bin:/home/box/.local/bin:/usr/bin:/bin:${PATH}"
make -C "$repo_root/ctl_tool" -B -j2 >/dev/null
make -C "$repo_root/gateway_service" -B >/dev/null
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
    "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_membership_action.c" \
    -pthread -o "$tmpdir/submit_membership_action"
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_gateway_drain_commit.c" \
    -pthread -o "$tmpdir/submit_gateway_drain_commit"
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
    "$repo_root/tests/control-plane/read_membership_fence.c" \
    -pthread -o "$tmpdir/read_membership_fence"
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
    "$repo_root/tests/control-plane/check_gateway_registration.c" \
    -pthread -o "$tmpdir/check_gateway_registration"

base_port=$(shuf -i 22000-50000 -n 1)
ctl_port=$base_port
gw_data_port=$((base_port + 1))
gw_control_port=$((base_port + 2))
gw_legacy_ctrl=$((base_port + 3))
agent_control_port=$((base_port + 4))
agent_data_port=$((base_port + 5))
sidecar_data_port=$((base_port + 6))
sidecar_control_port=$((base_port + 7))
profile_data0=$((base_port + 8))
profile_data1=$((base_port + 9))
profile_svc0=$((base_port + 10))
profile_svc1=$((base_port + 11))

mkdir -p "$tmpdir/ctl-state" "$tmpdir/gw-state/enrollment" \
    "$tmpdir/node-state" "$tmpdir/runtime" "$tmpdir/evidence"
: > "$tmpdir/gw-empty.conf"

digest=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    "$profile_data0" "$profile_data1" "$profile_svc0" "$profile_svc1" \
    "$agent_control_port")
[[ ${#digest} -eq 64 ]]
cp "$tmpdir/evidence/"*.record "$tmpdir/ctl-state/"

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
make_cert gateway gateway:901:902
make_cert node node-runtime:801:802
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
    [[ -S "$tmpdir/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/ctl.sock" ]]

export WVM_GATEWAY_ID=901
export WVM_GATEWAY_INSTANCE_ID=902
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

"$repo_root/gateway_service/wavevm_gateway" \
    "$gw_data_port" 127.0.0.1 9 "$tmpdir/gw-empty.conf" "$gw_legacy_ctrl" \
    >"$tmpdir/gw.log" 2>&1 &
gw_pid=$!

for ((attempt = 0; attempt < 200; attempt++)); do
    if "$tmpdir/check_gateway_registration" \
        "$tmpdir/ctl-state/membership.journal" "$gw_control_port" \
        >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$gw_pid" 2>/dev/null; then
        echo "wavevm_gateway exited early" >&2
        tail -n 80 "$tmpdir/gw.log" >&2 || true
        tail -n 80 "$tmpdir/ctl.log" >&2 || true
        exit 1
    fi
    sleep 0.05
done
if ! "$tmpdir/check_gateway_registration" \
    "$tmpdir/ctl-state/membership.journal" "$gw_control_port"; then
    echo "gateway did not reach ACTIVE" >&2
    exit 1
fi

"$repo_root/wavevm_node_runtime" agent \
    --state-dir "$tmpdir/node-state" \
    --runtime-dir "$tmpdir/runtime" \
    --socket "$tmpdir/node.sock" \
    --node-id 801 --instance-id 802 --inventory-revision 1 \
    --vcpu-slots 2 --memory-bytes 1073741824 \
    --controller-node-id 701 --controller-instance-id 702 \
    --controller-uid "$(id -u)" \
    --slots 2 --max-vcpus 2 --max-memory-chunks 2 \
    --max-storage 1 --max-members 8 --max-leases 2 \
    --control-address 127.0.0.1 --control-port "$agent_control_port" \
    --data-port "$agent_data_port" \
    --tls-ca "$tmpdir/ca.crt" --tls-cert "$tmpdir/node.crt" \
    --tls-key "$tmpdir/node.key" \
    --register-controller-address 127.0.0.1 \
    --register-controller-port "$ctl_port" \
    --failure-domain-id 1 --pod-id 1 --vnode-first 1 --vnode-count 16 \
    --sidecar-address 127.0.0.1 --sidecar-data-port "$sidecar_data_port" \
    --sidecar-control-port "$sidecar_control_port" --role-bits 1 \
    --capability-profile-generation 1 \
    --capability-profile-digest "$digest" \
    --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222 \
    --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333 \
    --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444 \
    >"$tmpdir/agent.log" 2>&1 &
agent_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -S "$tmpdir/node.sock" ]] && kill -0 "$agent_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/node.sock" ]]

wait_member_state() {
    local role_id=$1
    local instance_id=$2
    local want=$3
    local attempts=${4:-200}
    local i line
    for ((i = 0; i < attempts; i++)); do
        if [[ -s "$tmpdir/ctl-state/membership.journal" ]]; then
            cp -f "$tmpdir/ctl-state/membership.journal" \
                "$tmpdir/membership.journal.snap" 2>/dev/null || true
            if [[ -s "$tmpdir/membership.journal.snap" ]]; then
                line=$("$tmpdir/read_membership_fence" \
                    "$tmpdir/membership.journal.snap" \
                    "$role_id" "$instance_id" 2>/dev/null \
                    | grep '^member ' || true)
                if [[ "$line" == *" state=${want} "* ]]; then
                    return 0
                fi
            fi
        fi
        sleep 0.05
    done
    return 1
}

# ACTIVE = 4
if ! wait_member_state 901 902 4 200; then
    echo "gateway member did not stay ACTIVE" >&2
    exit 1
fi
if ! wait_member_state 801 802 4 200; then
    echo "compute member did not reach ACTIVE" >&2
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    tail -n 80 "$tmpdir/agent.log" >&2 || true
    exit 1
fi

cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
fence=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap")
echo "$fence"
mem_rev=$(echo "$fence" | awk '/^revisions /{print $2}')
topo_rev=$(echo "$fence" | awk '/^revisions /{print $3}')
elig_rev=$(echo "$fence" | awk '/^revisions /{print $4}')
[[ -n "$mem_rev" && -n "$topo_rev" && -n "$elig_rev" ]]

# Spec: DRAIN COMMIT without PREPARE/successor must fail-closed (换血 incomplete).
drain_commit_out=$("$tmpdir/submit_gateway_drain_commit" "$tmpdir/ctl.sock" \
    901 902 "$mem_rev" "$topo_rev" "$elig_rev" || true)
echo "drain COMMIT without PREPARE: $drain_commit_out"
if [[ "$drain_commit_out" == status=0* ]]; then
    echo "DRAIN COMMIT without successor PREPARE must fail-closed" >&2
    exit 1
fi
# Gateway must still be ACTIVE after rejected COMMIT.
if ! wait_member_state 901 902 4 20; then
    echo "rejected DRAIN COMMIT must not change gateway state" >&2
    exit 1
fi

# Spec: CORDON (0x0102) may target GATEWAY → durable CORDONED.
# ROLE_TYPE gateway = 2
cordon_out=$("$tmpdir/submit_membership_action" "$tmpdir/ctl.sock" cordon \
    2 901 902 "$mem_rev" "$topo_rev" "$elig_rev")
echo "gateway cordon: $cordon_out"
[[ "$cordon_out" == status=0* ]]
if ! wait_member_state 901 902 5 100; then
    echo "gateway not CORDONED after production CORDON" >&2
    "$tmpdir/read_membership_fence" "$tmpdir/ctl-state/membership.journal" >&2 || true
    exit 1
fi

# Fail-closed: GatewayRecord exists but ineligible → no empty-leaf fallback.
create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" gw-cordon-blocked || true)
echo "create after gateway cordon: $create_out"
if [[ "$create_out" == status=0* || "$create_out" == status=14* ]]; then
    echo "CREATE_VM must fail-closed when sole gateway is CORDONED" >&2
    exit 1
fi

# Post-cordon fence: second cordon must fail (already CORDONED, not ACTIVE).
cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
fence=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap")
mem_rev2=$(echo "$fence" | awk '/^revisions /{print $2}')
topo_rev2=$(echo "$fence" | awk '/^revisions /{print $3}')
elig_rev2=$(echo "$fence" | awk '/^revisions /{print $4}')
again_out=$("$tmpdir/submit_membership_action" "$tmpdir/ctl.sock" cordon \
    2 901 902 "$mem_rev2" "$topo_rev2" "$elig_rev2" 258 || true)
echo "cordon again on CORDONED: $again_out"
if [[ "$again_out" == status=0* ]]; then
    echo "cordon must fail-closed on already-CORDONED gateway with new fence" >&2
    exit 1
fi
"$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap" 901 902 \
    | grep 'state=5 ' >/dev/null
"$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap" 801 802 \
    | grep 'state=4 ' >/dev/null

kill -TERM "$agent_pid"
wait "$agent_pid" || true
agent_pid=
kill -TERM "$gw_pid"
wait "$gw_pid" || true
gw_pid=
kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=

echo "production gateway CORDON + DRAIN fail-closed entry: PASS"
echo "boundary: 换血 PREPARE+ACK+COMMIT covered by test_gateway_drain_prepare_commit.sh"
echo "  (CREATE_VM now wires dependency_acquire). one-scope successor builder in ctl PREPARE path;"
echo "  Mode A / guest E2E not started."

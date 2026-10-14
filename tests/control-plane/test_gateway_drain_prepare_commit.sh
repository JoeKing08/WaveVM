#!/usr/bin/env bash
# Production-path gateway 换血: DRAIN PREPARE(successor topo+1) → peer
# ROUTE_PREPARE ACK → COMMIT → DRAINING, with fail-closed cases.
#
# Specs (no invented actions):
# - canonical-record-schema.md GatewayDrainRequest: PREPARE|COMMIT|ABORT only
# - wire-ipc-abi.md §4.2 / §4.2.2: DRAIN 0x0103 PREPARE complete successor
#   (topology=current+1) → peer route ACK → COMMIT → DRAINING
# - cluster-membership-topology-lifecycle.md §5.4: one-scope V1; exactly one
#   dependency; departing gateway excluded from RequiredAckSet; optional
#   departure drain set names departing gateway once
#
# Fixture: live CREATE_VM registers membership-controller predecessor route
# and dependency_acquire for the selected gateway (no offline seed). Successor
# payload remains caller-supplied (executor), not a topology planner/builder.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-gateway-drain-pc.XXXXXX")
ctl_pid=
gw1_pid=
gw2_pid=
agent_pid=

cleanup() {
    if [[ -n "${agent_pid:-}" ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    if [[ -n "${gw1_pid:-}" ]]; then
        kill -TERM "$gw1_pid" 2>/dev/null || true
        wait "$gw1_pid" 2>/dev/null || true
    fi
    if [[ -n "${gw2_pid:-}" ]]; then
        kill -TERM "$gw2_pid" 2>/dev/null || true
        wait "$gw2_pid" 2>/dev/null || true
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

compile_helper() {
    local name=$1
    shift
    gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
        -I"$repo_root/common_include" \
        "$@" -pthread -o "$tmpdir/$name"
}

compile_helper seed_evidence "${common_objs[@]}" \
    "$repo_root/tests/control-plane/seed_create_vm_evidence.c"
compile_helper submit_create_vm "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_create_vm.c"
compile_helper submit_membership_action "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_membership_action.c"
compile_helper submit_gateway_drain_commit "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_gateway_drain_commit.c"
compile_helper submit_gateway_drain_prepare "${common_objs[@]}" \
    "$repo_root/ctl_tool/gateway_drain_successor.c" \
    "$repo_root/tests/control-plane/submit_gateway_drain_prepare.c"
compile_helper read_membership_fence \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/read_membership_fence.c"
base_port=$(shuf -i 22000-50000 -n 1)
ctl_port=$base_port
gw1_data_port=$((base_port + 1))
gw1_control_port=$((base_port + 2))
gw1_legacy_ctrl=$((base_port + 3))
gw2_data_port=$((base_port + 4))
gw2_control_port=$((base_port + 5))
gw2_legacy_ctrl=$((base_port + 6))
agent_control_port=$((base_port + 7))
agent_data_port=$((base_port + 8))
sidecar_data_port=$((base_port + 9))
sidecar_control_port=$((base_port + 10))
profile_data0=$((base_port + 11))
profile_data1=$((base_port + 12))
profile_svc0=$((base_port + 13))
profile_svc1=$((base_port + 14))

mkdir -p "$tmpdir/ctl-state" "$tmpdir/gw1-state/enrollment" \
    "$tmpdir/gw2-state/enrollment" "$tmpdir/node-state" "$tmpdir/runtime" \
    "$tmpdir/evidence"
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
make_cert gateway1 gateway:901:902
make_cert gateway2 gateway:911:912
make_cert node node-runtime:801:802
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir/principals"

start_ctl() {
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
    local attempt
    for ((attempt = 0; attempt < 100; attempt++)); do
        [[ -S "$tmpdir/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

stop_ctl() {
    if [[ -n "${ctl_pid:-}" ]]; then
        kill -TERM "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
        ctl_pid=
    fi
    rm -f "$tmpdir/ctl.sock"
}

start_ctl

start_gateway() {
    local id=$1
    local inst=$2
    local data_port=$3
    local control_port=$4
    local legacy_ctrl=$5
    local state_dir=$6
    local cert=$7
    local log=$8
    local pid_var=$9

    export WVM_GATEWAY_ID=$id
    export WVM_GATEWAY_INSTANCE_ID=$inst
    export WVM_GATEWAY_ROUTE_JOURNAL_PATH="$state_dir/route.journal"
    export WVM_GATEWAY_CONTROL_SOCKET="$state_dir/control.sock"
    export WVM_GATEWAY_ENROLLMENT_STATE_DIR="$state_dir/enrollment"
    export WVM_GATEWAY_CONTROLLER_ROLE=node-runtime
    export WVM_GATEWAY_CONTROLLER_ID=701
    export WVM_GATEWAY_CONTROLLER_INSTANCE_ID=702
    export WVM_GATEWAY_CONTROLLER_PHYSICAL_NODE_ID=701
    export WVM_GATEWAY_CONTROLLER_RUNTIME_INSTANCE_ID=702
    export WVM_GATEWAY_CONTROL_ADDRESS=127.0.0.1
    export WVM_GATEWAY_CONTROL_PORT=$control_port
    export WVM_GATEWAY_CONTROL_CA_FILE="$tmpdir/ca.crt"
    export WVM_GATEWAY_CONTROL_CERTIFICATE_FILE="$cert.crt"
    export WVM_GATEWAY_CONTROL_PRIVATE_KEY_FILE="$cert.key"
    export WVM_GATEWAY_REGISTER_CONTROLLER_ADDRESS=127.0.0.1
    export WVM_GATEWAY_REGISTER_CONTROLLER_PORT=$ctl_port
    export WVM_GATEWAY_HOSTING_NODE_ID=801
    export WVM_GATEWAY_FAILURE_DOMAIN_ID=1
    export WVM_GATEWAY_POD_ID=1
    export WVM_GATEWAY_ROLE_BITS=1
    export WVM_GATEWAY_SINGLE_RX=1
    unset WVM_GATEWAY_FORCE_SINGLE_FD || true

    "$repo_root/gateway_service/wavevm_gateway" \
        "$data_port" 127.0.0.1 9 "$tmpdir/gw-empty.conf" "$legacy_ctrl" \
        >"$log" 2>&1 &
    eval "$pid_var=$!"
}

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
start_gateway 901 902 "$gw1_data_port" "$gw1_control_port" "$gw1_legacy_ctrl" \
    "$tmpdir/gw1-state" "$tmpdir/gateway1" "$tmpdir/gw1.log" gw1_pid
if ! wait_member_state 901 902 4 200; then
    echo "departing gateway did not reach ACTIVE" >&2
    tail -n 80 "$tmpdir/gw1.log" >&2 || true
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    exit 1
fi
start_gateway 911 912 "$gw2_data_port" "$gw2_control_port" "$gw2_legacy_ctrl" \
    "$tmpdir/gw2-state" "$tmpdir/gateway2" "$tmpdir/gw2.log" gw2_pid
if ! wait_member_state 911 912 4 200; then
    echo "successor gateway did not reach ACTIVE" >&2
    tail -n 80 "$tmpdir/gw2.log" >&2 || true
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
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

if ! wait_member_state 901 902 4 200; then
    echo "departing gateway not ACTIVE" >&2
    exit 1
fi
if ! wait_member_state 911 912 4 200; then
    echo "successor gateway not ACTIVE" >&2
    exit 1
fi
if ! wait_member_state 801 802 4 200; then
    echo "compute member not ACTIVE" >&2
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    exit 1
fi

cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
fence=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap")
mem_rev=$(echo "$fence" | awk '/^revisions /{print $2}')
topo_rev=$(echo "$fence" | awk '/^revisions /{print $3}')
elig_rev=$(echo "$fence" | awk '/^revisions /{print $4}')

# Fail-closed: COMMIT without PREPARE (no successor) — status != 0, still ACTIVE.
drain_commit_out=$("$tmpdir/submit_gateway_drain_commit" "$tmpdir/ctl.sock" \
    901 902 "$mem_rev" "$topo_rev" "$elig_rev" || true)
echo "COMMIT without PREPARE: $drain_commit_out"
if [[ "$drain_commit_out" == status=0* ]]; then
    echo "COMMIT without PREPARE must fail-closed" >&2
    exit 1
fi
if ! wait_member_state 901 902 4 20; then
    echo "rejected COMMIT must not change gateway state" >&2
    exit 1
fi

# Live CREATE_VM → membership route ACTIVATED + dependency_acquire (no offline seed).
create_out=""
for ((attempt = 0; attempt < 80; attempt++)); do
    id_hex=$(printf '%x' $((0x40 + attempt)))
    create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" \
        gw-drain-create 1 compact "$id_hex" || true)
    echo "CREATE_VM attempt=$attempt $create_out"
    if [[ "$create_out" == status=0* ]]; then
        break
    fi
    if [[ "$create_out" != status=14* ]]; then
        break
    fi
    sleep 0.25
done
if [[ "$create_out" != status=0* ]]; then
    echo "CREATE_VM did not reach SUCCESS(0)/RUNNING (got: $create_out)" >&2
    tail -n 120 "$tmpdir/ctl.log" >&2 || true
    tail -n 80 "$tmpdir/agent.log" >&2 || true
    exit 1
fi
vm_id=$(echo "$create_out" | sed -n 's/.* vm_id=\([0-9]*\).*/\1/p')
[[ -n "$vm_id" && "$vm_id" -gt 0 ]]

# Prove CREATE acquired a real dependency on selected gateway 901 (lowest id).
cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
gw_line=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap" \
    901 902 | grep '^member ' || true)
echo "gateway after CREATE: $gw_line"
deps_val=$(echo "$gw_line" | sed -n 's/.* deps=\([0-9]*\).*/\1/p')
if [[ "$deps_val" != "1" ]]; then
    echo "CREATE_VM must leave departing gateway with exactly one dependency (got: $gw_line)" >&2
    "$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap" >&2 || true
    exit 1
fi

fence=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap")
echo "$fence"
mem_rev=$(echo "$fence" | awk '/^revisions /{print $2}')
topo_rev=$(echo "$fence" | awk '/^revisions /{print $3}')
elig_rev=$(echo "$fence" | awk '/^revisions /{print $4}')
# Pre-PREPARE fence retained for COMMIT (§4.2.2).
pre_mem=$mem_rev
pre_topo=$topo_rev
pre_elig=$elig_rev

# Successor built by ctl gateway_drain_successor (caller names SUCC 911 only).
prep_out=$("$tmpdir/submit_gateway_drain_prepare" "$tmpdir/ctl.sock" \
    "$tmpdir/membership.journal.snap" 901 902 911 912)
echo "DRAIN PREPARE: $prep_out"
[[ "$prep_out" == status=0* ]]
op_hex=$(echo "$prep_out" | sed -n 's/.* op=\([0-9a-fA-F]*\)$/\1/p')
[[ ${#op_hex} -eq 32 ]]

# Eligibility advanced only; gateway still ACTIVE until COMMIT.
cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
fence=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap")
elig_after=$(echo "$fence" | awk '/^revisions /{print $4}')
mem_after=$(echo "$fence" | awk '/^revisions /{print $2}')
topo_after=$(echo "$fence" | awk '/^revisions /{print $3}')
[[ "$mem_after" == "$pre_mem" ]]
[[ "$topo_after" == "$pre_topo" ]]
[[ "$elig_after" -eq $((pre_elig + 1)) ]]
if ! wait_member_state 901 902 4 20; then
    echo "after PREPARE gateway must remain ACTIVE until COMMIT" >&2
    exit 1
fi

# Give ctl post-PREPARE peer ROUTE_PREPARE ACK collection a moment.
sleep 0.2

commit_out=$("$tmpdir/submit_gateway_drain_commit" "$tmpdir/ctl.sock" \
    901 902 "$pre_mem" "$pre_topo" "$pre_elig" "$op_hex" || true)
echo "DRAIN COMMIT: $commit_out"
if [[ "$commit_out" != status=0* ]]; then
    echo "COMMIT failed; ctl log:" >&2
    tail -n 120 "$tmpdir/ctl.log" >&2 || true
    exit 1
fi

# DRAINING = 6
if ! wait_member_state 901 902 6 100; then
    echo "gateway not DRAINING after PREPARE+ACK+COMMIT" >&2
    "$tmpdir/read_membership_fence" "$tmpdir/ctl-state/membership.journal" \
        901 902 >&2 || true
    tail -n 100 "$tmpdir/ctl.log" >&2 || true
    exit 1
fi
if ! wait_member_state 911 912 4 20; then
    echo "successor gateway must stay ACTIVE" >&2
    exit 1
fi
if ! wait_member_state 801 802 4 20; then
    echo "compute member must stay ACTIVE" >&2
    exit 1
fi

cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
fence=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap")
echo "$fence"
mem_final=$(echo "$fence" | awk '/^revisions /{print $2}')
topo_final=$(echo "$fence" | awk '/^revisions /{print $3}')
elig_final=$(echo "$fence" | awk '/^revisions /{print $4}')
[[ "$mem_final" -eq $((pre_mem + 1)) ]]
[[ "$topo_final" -eq $((pre_topo + 1)) ]]
[[ "$elig_final" -eq $((pre_elig + 2)) ]]

# Idempotent COMMIT replay with pre-prepare fence.
replay_out=$("$tmpdir/submit_gateway_drain_commit" "$tmpdir/ctl.sock" \
    901 902 "$pre_mem" "$pre_topo" "$pre_elig" "$op_hex" || true)
echo "DRAIN COMMIT replay: $replay_out"
[[ "$replay_out" == status=0* ]]

kill -TERM "$agent_pid"
wait "$agent_pid" || true
agent_pid=
kill -TERM "$gw1_pid"
wait "$gw1_pid" || true
gw1_pid=
kill -TERM "$gw2_pid"
wait "$gw2_pid" || true
gw2_pid=
stop_ctl

echo "production gateway DRAIN PREPARE+peer ACK+COMMIT→DRAINING: PASS"
echo "CREATE_VM dependency_acquire + membership predecessor route: wired"
echo "boundary: one-scope successor builder in ctl (EXECUTOR names successor GW);"
echo "  cold recover republishes membership route+dependency_acquire (mid-flight);"
echo "  drain peer ROUTE_* manifest_generation binds membership dependency;"
echo "  Mode A / guest E2E not started."

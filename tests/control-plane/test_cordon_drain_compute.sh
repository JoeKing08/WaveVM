#!/usr/bin/env bash
# Production-path compute cordon + drain via live wvm_ctl membership receiver.
# Asserts: CORDONED durable state, CREATE_VM fail-closed on cordoned-only cluster,
# drain-compute CORDONED→DRAINING when dependency-free. No guest E2E claim.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-cordon-drain.XXXXXX")
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
    "$repo_root/tests/control-plane/submit_membership_action.c" \
    -pthread -o "$tmpdir/submit_membership_action"
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

cp "$tmpdir/evidence/capabilities-801.record" "$tmpdir/ctl-state/"
cp "$tmpdir/evidence/runtime-profile-801.record" "$tmpdir/ctl-state/"

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
    local want=$1
    local attempts=${2:-200}
    local i snap line
    for ((i = 0; i < attempts; i++)); do
        if [[ -s "$tmpdir/ctl-state/membership.journal" ]]; then
            cp -f "$tmpdir/ctl-state/membership.journal" \
                "$tmpdir/membership.journal.snap" 2>/dev/null || true
            if [[ -s "$tmpdir/membership.journal.snap" ]]; then
                line=$("$tmpdir/read_membership_fence" \
                    "$tmpdir/membership.journal.snap" 801 802 2>/dev/null \
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
if ! wait_member_state 4 200; then
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

# ROLE_TYPE node-runtime = 1
cordon_out=$("$tmpdir/submit_membership_action" "$tmpdir/ctl.sock" cordon \
    1 801 802 "$mem_rev" "$topo_rev" "$elig_rev")
echo "cordon: $cordon_out"
[[ "$cordon_out" == status=0* ]]
if ! wait_member_state 5 100; then
    echo "member not CORDONED after production CORDON" >&2
    "$tmpdir/read_membership_fence" "$tmpdir/ctl-state/membership.journal" >&2 || true
    exit 1
fi

# Fail-closed: sole compute is cordoned → CREATE_VM must not place.
create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" cordon-blocked || true)
echo "create after cordon: $create_out"
# PRECONDITION_FAILED = 3 (see wavevm_control.h); not SUCCESS(0) / IN_PROGRESS(14)
if [[ "$create_out" == status=0* || "$create_out" == status=14* ]]; then
    echo "CREATE_VM must fail-closed on cordoned-only cluster" >&2
    exit 1
fi

cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
fence=$("$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap")
mem_rev=$(echo "$fence" | awk '/^revisions /{print $2}')
topo_rev=$(echo "$fence" | awk '/^revisions /{print $3}')
elig_rev=$(echo "$fence" | awk '/^revisions /{print $4}')

drain_out=$("$tmpdir/submit_membership_action" "$tmpdir/ctl.sock" drain-compute \
    1 801 802 "$mem_rev" "$topo_rev" "$elig_rev")
echo "drain-compute: $drain_out"
[[ "$drain_out" == status=0* ]]
if ! wait_member_state 6 100; then
    echo "member not DRAINING after production DRAIN_COMPUTE" >&2
    exit 1
fi

# Stale fence (pre-drain revisions) must not resurrect ACTIVE/CORDONED.
# Use a distinct operation by bumping reason in a fresh client build path:
# call with wrong revisions → PRECONDITION_FAILED (status != 0) unless exact
# replay of the committed drain fence (which advances all three by +1).
stale_out=$("$tmpdir/submit_membership_action" "$tmpdir/ctl.sock" cordon \
    1 801 802 "$mem_rev" "$topo_rev" "$elig_rev" 258 || true)
echo "stale cordon after drain: $stale_out"
if [[ "$stale_out" == status=0* ]]; then
    echo "stale cordon must not succeed on DRAINING member" >&2
    exit 1
fi
cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap"
"$tmpdir/read_membership_fence" "$tmpdir/membership.journal.snap" 801 802 \
    | grep 'state=6 ' >/dev/null

kill -TERM "$agent_pid"
wait "$agent_pid" || true
agent_pid=
kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=

echo "production cordon/drain-compute entry: PASS"

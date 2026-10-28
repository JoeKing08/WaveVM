#!/usr/bin/env bash
# FRACTAL CREATE_VM control-plane vertical (Step 4 first honest slice).
# Specs: identity-routing.md §5.2; cluster-membership-topology-lifecycle.md §6;
# runtime-manifest-lifecycle.md §5.2 prepare→activate→commit→readiness;
# architecture-baseline flat/fractal selection; admission_route fail-closed
# without gateway for FRACTAL.
# Does not claim guest E2E / KVM /dev/wavevm. Uses TCG helper stub.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# §6 matrix: require-tcg (default) | require-kvm | auto. Guest login/SSH is §7.
s6_backend=${WVM_S6_BACKEND:-require-tcg}
case "$s6_backend" in
    require-tcg|require-kvm|auto) ;;
    *) echo "WVM_S6_BACKEND must be require-tcg|require-kvm|auto (got: $s6_backend)" >&2; exit 2 ;;
esac
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-fractal.XXXXXX")
ctl_pid=
gw_pid=
agent_pid=
# shellcheck source=s6_cell_common.sh
source "$repo_root/tests/control-plane/s6_cell_common.sh"

cleanup() {
    # Match test_create_vm_single_node.sh: KEEP_RUNNING must not tear down the
    # cluster — guest smoke (§7) attaches via /tmp/wavevm-s6-keep-*.
    if [[ "${WVM_S6_KEEP_RUNNING:-0}" == "1" || "${KEEP_RUNNING:-0}" == "1" ]]; then
        echo "s6: KEEP_RUNNING=1 — leaving fractal cluster up tmpdir=$tmpdir agent_pid=${agent_pid:-} ctl_pid=${ctl_pid:-} gw_pid=${gw_pid:-}" >&2
        if [[ -n "${tmpdir:-}" ]]; then
            echo "$tmpdir" > /tmp/wavevm-s6-keep-tmpdir
            echo "${agent_pid:-}" > /tmp/wavevm-s6-keep-agent-pid
            echo "${ctl_pid:-}" > /tmp/wavevm-s6-keep-ctl-pid
            [[ -n "${gw_pid:-}" ]] && echo "$gw_pid" > /tmp/wavevm-s6-keep-gw-pid || true
            if [[ -f "$tmpdir/agent.log" || -f "$tmpdir/agent-a.log" ]]; then
                alog="$tmpdir/agent.log"
                [[ -f "$alog" ]] || alog="$tmpdir/agent-a.log"
                grep -E 'Listening on|Mode:|SHM File|executor READY' "$alog" \
                    > /tmp/wavevm-s6-keep-ports.txt 2>/dev/null || true
            fi
            echo "$tmpdir" > /tmp/wavevm-s6-fractal-keep-tmpdir
            echo "${agent_pid:-}" > /tmp/wavevm-s6-fractal-keep-agent
            echo "${gw_pid:-}" > /tmp/wavevm-s6-fractal-keep-gw
            echo "${ctl_pid:-}" > /tmp/wavevm-s6-fractal-keep-ctl
        fi
        return 0
    fi
    for pid_var in agent_pid gw_pid ctl_pid; do
        pid=${!pid_var:-}
        if [[ -n "$pid" ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ "${WVM_S6_KEEP_TMP:-0}" == "1" ]]; then echo "keeping tmpdir=$tmpdir" >&2; else rm -rf -- "$tmpdir"; fi
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
    "$repo_root/tests/control-plane/check_agent_registration.c" \
    -pthread -o "$tmpdir/check_compute_active"
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
    "$repo_root/tests/control-plane/check_fractal_cluster.c" \
    -pthread -o "$tmpdir/check_fractal"
s6_select_tcg_helper

wait_compute_active() {
    local attempts=$1
    local i
    local expect_slots=${agent_vcpu_slots:-2}
    local expect_mem=${agent_memory_bytes:-1073741824}
    for ((i = 0; i < attempts; i++)); do
        if [[ -s "$tmpdir/ctl-state/membership.journal" ]]; then
            cp -f "$tmpdir/ctl-state/membership.journal" \
                "$tmpdir/membership.journal.snap" 2>/dev/null || true
            if [[ -s "$tmpdir/membership.journal.snap" ]] &&
               "$tmpdir/check_compute_active" "$tmpdir/membership.journal.snap" \
                   "$a_control" "$expect_slots" "$expect_mem" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.05
    done
    return 1
}

wait_fractal_active() {
    local attempts=$1
    local i
    for ((i = 0; i < attempts; i++)); do
        if [[ -s "$tmpdir/ctl-state/membership.journal" ]]; then
            cp -f "$tmpdir/ctl-state/membership.journal" \
                "$tmpdir/membership.journal.snap" 2>/dev/null || true
            if [[ -s "$tmpdir/membership.journal.snap" ]] &&
               "$tmpdir/check_fractal" "$tmpdir/membership.journal.snap" \
                   >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.05
    done
    return 1
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
a_profile_data0=$((base_port + 8))
a_profile_data1=$((base_port + 9))
a_profile_svc0=$((base_port + 10))
a_profile_svc1=$((base_port + 11))
# §6 production typed probe: fractal sends via gateway data port
cat >"$tmpdir/s6_ports.env" <<PORTS
# fractal: typed short-exec goes to gateway data port; node port from manifest.
agent_data_port=$a_data
a_data=$a_data
gw_data_port=$gw_data_port
WVM_S6_GW_DATA_PORT=$gw_data_port
PORTS


mkdir -p "$tmpdir/ctl-state" "$tmpdir/gw-state/enrollment" \
    "$tmpdir/node-a" "$tmpdir/runtime-a" "$tmpdir/evidence"
: > "$tmpdir/gw-empty.conf"

seed_flags=$(s6_seed_extra_flags)
# shellcheck disable=SC2086
digest_a=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    "$a_profile_data0" "$a_profile_data1" "$a_profile_svc0" "$a_profile_svc1" \
    "$a_control" $seed_flags)
echo "s6 seed flags='$seed_flags' digest_prefix=${digest_a:0:16}..."
[[ ${#digest_a} -eq 64 ]]
cp "$tmpdir/evidence/capabilities-801.record" "$tmpdir/ctl-state/"
cp "$tmpdir/evidence/runtime-profile-801.record" "$tmpdir/ctl-state/"

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
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir/principals"

# Cluster control-plane route topology = FRACTAL (documented operator policy).
stdbuf -o0 -e0 "$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir/ctl-state" --socket "$tmpdir/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir/principals" --capacity 16 \
    --route-topology fractal \
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

# Guest smoke (§7) may request ≥2 vCPUs + Cirros-sized RAM via WVM_CREATE_*.
agent_vcpu_slots=2
agent_memory_bytes=1073741824
agent_slots=2
agent_max_vcpus=4
agent_max_memory_chunks=2
if [[ -n "${WVM_CREATE_VCPUS:-}" || -n "${WVM_CREATE_MEMORY_BYTES:-}" ]]; then
    want_vcpus=${WVM_CREATE_VCPUS:-1}
    if [[ "$want_vcpus" -lt 1 ]]; then want_vcpus=1; fi
    if [[ "$agent_vcpu_slots" -lt $((want_vcpus + 2)) ]]; then
        agent_vcpu_slots=$((want_vcpus + 2))
    fi
    if [[ "$agent_max_vcpus" -lt "$want_vcpus" ]]; then
        agent_max_vcpus=$want_vcpus
    fi
    if [[ "$agent_slots" -lt $((want_vcpus + 2)) ]]; then
        agent_slots=$((want_vcpus + 2))
    fi
    if [[ "$agent_max_memory_chunks" -lt 4 ]]; then
        agent_max_memory_chunks=4
    fi
    if [[ -n "${WVM_CREATE_MEMORY_BYTES:-}" ]]; then
        need=$((WVM_CREATE_MEMORY_BYTES + 64*1024*1024))
        if [[ "$agent_memory_bytes" -lt "$need" ]]; then
            agent_memory_bytes=$need
        fi
        if [[ "$agent_memory_bytes" -lt 2147483648 ]]; then
            agent_memory_bytes=2147483648
        fi
    fi
    echo "s6: fractal guest-capacity bump slots=$agent_vcpu_slots max_vcpus=$agent_max_vcpus mem=$agent_memory_bytes" >&2
fi

# Phase A: compute-only ACTIVE → FRACTAL CREATE_VM must fail-closed (no gateway).
stdbuf -o0 -e0 env WVM_TCG_QEMU_BIN="$WVM_TCG_QEMU_BIN" \
    WVM_TCG_QEMU_DATADIR="${WVM_TCG_QEMU_DATADIR:-}" \
    WVM_TCG_QEMU_MACHINE="${WVM_TCG_QEMU_MACHINE:-}" \
    WVM_TCG_QEMU_MEM_MB="${WVM_TCG_QEMU_MEM_MB:-}" \
    "$repo_root/wavevm_node_runtime" agent \
    --state-dir "$tmpdir/node-a" --runtime-dir "$tmpdir/runtime-a" \
    --socket "$tmpdir/node-a.sock" \
    --node-id 801 --instance-id 802 --inventory-revision 1 \
    --vcpu-slots "$agent_vcpu_slots" --memory-bytes "$agent_memory_bytes" \
    --controller-node-id 701 --controller-instance-id 702 \
    --controller-uid "$(id -u)" \
    --slots "$agent_slots" --max-vcpus "$agent_max_vcpus" --max-memory-chunks "$agent_max_memory_chunks" \
    --max-storage 1 --max-members 8 --max-leases 2 \
    --control-address 127.0.0.1 --control-port "$a_control" \
    --data-port "$a_data" \
    --tls-ca "$tmpdir/ca.crt" --tls-cert "$tmpdir/nodea.crt" \
    --tls-key "$tmpdir/nodea.key" \
    --register-controller-address 127.0.0.1 \
    --register-controller-port "$ctl_port" \
    --failure-domain-id 1 --pod-id 7 \
    --vnode-first 1 --vnode-count 16 \
    --sidecar-address 127.0.0.1 --sidecar-data-port "$a_side_data" \
    --sidecar-control-port "$a_side_ctrl" --role-bits 1 \
    --capability-profile-generation 1 \
    --capability-profile-digest "$digest_a" \
    --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222 \
    --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333 \
    --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444 \
    >"$tmpdir/agent-a.log" 2>&1 &
agent_pid=$!
for ((i = 0; i < 200; i++)); do
    [[ -S "$tmpdir/node-a.sock" ]] && kill -0 "$agent_pid" 2>/dev/null && break
    sleep 0.05
done
[[ -S "$tmpdir/node-a.sock" ]]

if ! wait_compute_active 600; then
    echo "compute did not reach ACTIVE before FRACTAL fail-closed probe" >&2
    echo "expected slots=$agent_vcpu_slots mem=$agent_memory_bytes control_port=$a_control" >&2
    if [[ -s "$tmpdir/ctl-state/membership.journal" ]]; then
        cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap" 2>/dev/null || true
        "$tmpdir/check_compute_active" "$tmpdir/membership.journal.snap" \
            "$a_control" "$agent_vcpu_slots" "$agent_memory_bytes" >&2 || true
    fi
    cat "$tmpdir/ctl.log" >&2 || true
    cat "$tmpdir/agent-a.log" >&2 || true
    exit 1
fi
echo "compute-only ACTIVE; probing FRACTAL fail-closed without gateway"

fail_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" \
    fractal-no-gw 1 compact a1 disabled "$s6_backend" || true)
echo "fail-closed probe: $fail_out"
# PRECONDITION_FAILED = 6 (honest fail-closed; not SUCCESS/RUNNING).
if [[ "$fail_out" != status=6* ]]; then
    echo "FRACTAL without gateway must fail-closed with status=6, got: $fail_out" >&2
    cat "$tmpdir/ctl.log" >&2 || true
    exit 1
fi
echo "FRACTAL without gateway fail-closed: PASS"

# Phase B: enroll ACTIVE gateway, then CREATE_VM → RUNNING.
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
export WVM_GATEWAY_POD_ID=7
export WVM_GATEWAY_ROLE_BITS=1
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

if ! wait_fractal_active 600; then
    echo "gateway+compute did not reach FRACTAL ACTIVE before CREATE_VM" >&2
    echo "--- ctl ---" >&2; cat "$tmpdir/ctl.log" >&2 || true
    echo "--- gw ---" >&2; cat "$tmpdir/gw.log" >&2 || true
    echo "--- a ---" >&2; cat "$tmpdir/agent-a.log" >&2 || true
    exit 1
fi
echo "gateway+compute ACTIVE; submitting FRACTAL CREATE_VM"

create_out=""
for ((attempt = 0; attempt < 80; attempt++)); do
    create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" \
        fractal-create 1 compact b2 disabled "$s6_backend" || true)
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
    echo "FRACTAL CREATE_VM did not reach SUCCESS(0)/RUNNING (got: $create_out)" >&2
    echo "--- ctl.log ---" >&2; cat "$tmpdir/ctl.log" >&2 || true
    echo "--- gw.log ---" >&2; cat "$tmpdir/gw.log" >&2 || true
    echo "--- agent-a.log ---" >&2; cat "$tmpdir/agent-a.log" >&2 || true
    find "$tmpdir/runtime-a" -type f \
        \( -name '*.log' -o -name 'stderr*' -o -name 'stdout*' \) \
        -print -exec cat {} \; >&2 2>/dev/null || true
    exit 1
fi

if [[ ! -s "$tmpdir/gw-state/route.journal" ]]; then
    echo "gateway route journal empty after FRACTAL CREATE_VM" >&2
    exit 1
fi

# Alias fractal layout to s6_finish / guest-smoke expected paths
ln -sfn "$tmpdir/agent-a.log" "$tmpdir/agent.log" 2>/dev/null || cp -a "$tmpdir/agent-a.log" "$tmpdir/agent.log"
ln -sfn "$tmpdir/runtime-a" "$tmpdir/runtime" 2>/dev/null || true
ln -sfn "$tmpdir/node-a" "$tmpdir/node-state" 2>/dev/null || true

# Guest E2E (§7): WVM_S6_KEEP_RUNNING=1 leaves cluster up with the same
# /tmp/wavevm-s6-keep-* handshake as test_create_vm_single_node.sh.
# Legacy KEEP_RUNNING=1 kept as alias.
if [[ "${WVM_S6_KEEP_RUNNING:-0}" == "1" || "${KEEP_RUNNING:-0}" == "1" ]]; then
    echo "s6: KEEP_RUNNING — leaving fractal cluster up; tmpdir=$tmpdir" >&2
    echo "$tmpdir" > /tmp/wavevm-s6-keep-tmpdir
    echo "$agent_pid" > /tmp/wavevm-s6-keep-agent-pid
    echo "$ctl_pid" > /tmp/wavevm-s6-keep-ctl-pid
    [[ -n "${gw_pid:-}" ]] && echo "$gw_pid" > /tmp/wavevm-s6-keep-gw-pid || true
    grep -E 'Listening on|Mode:|SHM File|executor READY' "$tmpdir/agent.log"         > /tmp/wavevm-s6-keep-ports.txt || true
    # Compat paths for older fractal probes
    echo "$tmpdir" > /tmp/wavevm-s6-fractal-keep-tmpdir
    echo "$agent_pid" > /tmp/wavevm-s6-fractal-keep-agent
    echo "${gw_pid:-}" > /tmp/wavevm-s6-fractal-keep-gw
    echo "$ctl_pid" > /tmp/wavevm-s6-fractal-keep-ctl
    echo "FRACTAL CREATE_VM prepare→activate→commit→RUNNING: PASS backend=$s6_backend (KEEP_RUNNING)"
    exit 0
fi

# R4: production STOP + cleanup evidence while agent still up
s6_finish_running_vm "$create_out"

"$tmpdir/check_fractal" "$tmpdir/ctl-state/membership.journal"

kill -TERM "$agent_pid" "$gw_pid" "$ctl_pid" 2>/dev/null || true
wait "$agent_pid" 2>/dev/null || true
wait "$gw_pid" 2>/dev/null || true
wait "$ctl_pid" 2>/dev/null || true
agent_pid=; gw_pid=; ctl_pid=

echo "FRACTAL CREATE_VM prepare→activate→commit→RUNNING: PASS backend=$s6_backend ($create_out)"

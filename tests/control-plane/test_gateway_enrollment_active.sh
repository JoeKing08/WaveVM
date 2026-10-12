#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-gateway-enrollment.XXXXXX")
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

make -C "$repo_root/ctl_tool" -B >/dev/null

common_srcs=(
    "$repo_root/common_include/wavevm_sha256.c"
    "$repo_root/common_include/wavevm_canonical.c"
    "$repo_root/common_include/wavevm_identity.c"
    "$repo_root/common_include/wavevm_runtime_names.c"
    "$repo_root/common_include/wavevm_manifest.c"
    "$repo_root/common_include/wavevm_control.c"
    "$repo_root/common_include/wavevm_membership.c"
    "$repo_root/common_include/wavevm_capability.c"
    "$repo_root/common_include/wavevm_lifecycle.c"
    "$repo_root/common_include/wavevm_admission.c"
    "$repo_root/common_include/wavevm_cluster.c"
    "$repo_root/common_include/wavevm_reservation_runtime.c"
    "$repo_root/common_include/wavevm_admission_stage.c"
    "$repo_root/common_include/wavevm_admission_receiver.c"
    "$repo_root/common_include/wavevm_runtime_gate.c"
    "$repo_root/common_include/wavevm_route_runtime.c"
    "$repo_root/common_include/wavevm_route_control.c"
    "$repo_root/common_include/wavevm_route_delivery.c"
    "$repo_root/common_include/wavevm_runtime_dispatch.c"
    "$repo_root/common_include/wavevm_runtime_delivery.c"
    "$repo_root/common_include/wavevm_fault_engine.c"
    "$repo_root/common_include/wavevm_envelope.c"
    "$repo_root/common_include/wavevm_membership_control.c"
    "$repo_root/common_include/wavevm_membership_controller.c"
    "$repo_root/common_include/wavevm_control_transport.c"
    "$repo_root/common_include/wavevm_control_owner.c"
    "$repo_root/common_include/wavevm_admission_node_service.c"
    "$repo_root/common_include/wavevm_tls_control_connector.c"
)

gcc -Wall -Wextra -Werror -std=gnu11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${common_srcs[@]}" \
    "$repo_root/tests/control-plane/gateway_enrollment_agent.c" \
    -pthread -lssl -lcrypto -o "$tmpdir/gateway_enrollment_agent"

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
gw_control_port=$((base_port + 1))
gw_data_port=$((base_port + 2))

mkdir "$tmpdir/ctl-state" "$tmpdir/gw-state"
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
printf '%s node-runtime 701 702\n' "$(id -u)" > "$tmpdir/principals"

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

"$tmpdir/gateway_enrollment_agent" \
    --state-dir "$tmpdir/gw-state" \
    --socket "$tmpdir/gw.sock" \
    --gateway-id 901 --instance-id 902 --hosting-node-id 801 \
    --failure-domain-id 1 --pod-id 1 --role-bits 1 \
    --controller-node-id 701 --controller-instance-id 702 \
    --control-address 127.0.0.1 --control-port "$gw_control_port" \
    --data-port "$gw_data_port" \
    --tls-ca "$tmpdir/ca.crt" --tls-cert "$tmpdir/gateway.crt" \
    --tls-key "$tmpdir/gateway.key" \
    --register-controller-address 127.0.0.1 \
    --register-controller-port "$ctl_port" \
    >"$tmpdir/agent.log" 2>&1 &
agent_pid=$!

for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ -s "$tmpdir/ctl-state/membership.journal" ]] &&
       grep -q "REGISTER accepted" "$tmpdir/agent.log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then
        echo "gateway enrollment agent exited early" >&2
        cat "$tmpdir/agent.log" >&2 || true
        cat "$tmpdir/ctl.log" >&2 || true
        exit 1
    fi
    sleep 0.05
done
[[ -s "$tmpdir/ctl-state/membership.journal" ]]
grep -q "REGISTER accepted" "$tmpdir/agent.log"

# Give ctl a moment to finish synchronous enrollment and journal ACTIVE.
for ((attempt = 0; attempt < 100; attempt++)); do
    if "$tmpdir/check_gateway_registration" \
        "$tmpdir/ctl-state/membership.journal" "$gw_control_port"; then
        echo "gateway mTLS registration and cluster enrollment ACTIVE: PASS"
        exit 0
    fi
    sleep 0.05
done

echo "gateway did not reach ACTIVE enrolled state" >&2
cat "$tmpdir/agent.log" >&2 || true
cat "$tmpdir/ctl.log" >&2 || true
"$tmpdir/check_gateway_registration" \
    "$tmpdir/ctl-state/membership.journal" "$gw_control_port" || true
exit 1

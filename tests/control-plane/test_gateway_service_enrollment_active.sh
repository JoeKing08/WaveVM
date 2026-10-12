#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-gw-service-enroll.XXXXXX")
ctl_pid=
gw_pid=

cleanup() {
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

make -C "$repo_root/ctl_tool" -B >/dev/null
make -C "$repo_root/gateway_service" -B >/dev/null

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

mkdir -p "$tmpdir/ctl-state" "$tmpdir/gw-state/enrollment"
: > "$tmpdir/gw-empty.conf"

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
export WVM_GATEWAY_FORCE_SINGLE_FD=1
# Avoid blocking forever in single-fd worker for this membership test: do not
# force single-fd; let workers run while control listener enrolls.
unset WVM_GATEWAY_FORCE_SINGLE_FD

"$repo_root/gateway_service/wavevm_gateway" \
    "$gw_data_port" 127.0.0.1 9 "$tmpdir/gw-empty.conf" "$gw_legacy_ctrl" \
    >"$tmpdir/gw.log" 2>&1 &
gw_pid=$!

for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ -S "$tmpdir/gw-state/control.sock" ]] &&
       grep -q "REGISTER accepted" "$tmpdir/gw.log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$gw_pid" 2>/dev/null; then
        echo "wavevm_gateway exited early" >&2
        cat "$tmpdir/gw.log" >&2 || true
        cat "$tmpdir/ctl.log" >&2 || true
        exit 1
    fi
    sleep 0.05
done
[[ -S "$tmpdir/gw-state/control.sock" ]]
grep -q "REGISTER accepted" "$tmpdir/gw.log"

for ((attempt = 0; attempt < 100; attempt++)); do
    if "$tmpdir/check_gateway_registration" \
        "$tmpdir/ctl-state/membership.journal" "$gw_control_port"; then
        echo "wavevm_gateway mTLS enrollment ACTIVE: PASS"
        exit 0
    fi
    sleep 0.05
done

echo "wavevm_gateway did not reach ACTIVE" >&2
cat "$tmpdir/gw.log" >&2 || true
cat "$tmpdir/ctl.log" >&2 || true
exit 1

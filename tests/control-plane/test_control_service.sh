#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-control-service.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/ca.key" \
    -out "$tmpdir/ca.crt" >/dev/null 2>&1
for identity in server node other; do
    case "$identity" in
        server) cn=executor:900:901 ;;
        node) cn=node-runtime:17:101 ;;
        other) cn=node-runtime:18:102 ;;
    esac
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$cn" \
        -keyout "$tmpdir/$identity.key" -out "$tmpdir/$identity.csr" \
        >/dev/null 2>&1
    openssl x509 -req -days 1 -in "$tmpdir/$identity.csr" \
        -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" -CAcreateserial \
        -out "$tmpdir/$identity.crt" >/dev/null 2>&1
done

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_membership.c" \
    "$repo_root/common_include/wavevm_capability.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_admission.c" \
    "$repo_root/common_include/wavevm_cluster.c" \
    "$repo_root/common_include/wavevm_reservation_runtime.c" \
    "$repo_root/common_include/wavevm_fault_engine.c" \
    "$repo_root/common_include/wavevm_coordinator.c" \
    "$repo_root/common_include/wavevm_control_plane.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/common_include/wavevm_membership_control.c" \
    "$repo_root/common_include/wavevm_control_transport.c" \
    "$repo_root/common_include/wavevm_tls_control_connector.c" \
    "$repo_root/common_include/wavevm_control_owner.c" \
    "$repo_root/common_include/wavevm_control_service.c" \
    "$repo_root/tests/control-plane/test_control_service.c" \
    -pthread -lssl -lcrypto -o "$tmpdir/test_control_service"
"$tmpdir/test_control_service"
"$tmpdir/test_control_service" "$(shuf -i 20000-40000 -n 1)" \
    "$tmpdir/ca.crt" "$tmpdir/server.crt" "$tmpdir/server.key" \
    "$tmpdir/node.crt" "$tmpdir/node.key" \
    "$tmpdir/other.crt" "$tmpdir/other.key"

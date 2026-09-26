#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-tls-admission-node.XXXXXX")
trap 'rm -rf -- "$tmpdir"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/ca.key" \
    -out "$tmpdir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj /CN=node-runtime:801:802 -keyout "$tmpdir/node.key" \
    -out "$tmpdir/node.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$tmpdir/node.csr" \
    -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" -CAcreateserial \
    -out "$tmpdir/node.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj /CN=node-runtime:701:702 -keyout "$tmpdir/controller.key" \
    -out "$tmpdir/controller.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$tmpdir/controller.csr" \
    -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" -CAcreateserial \
    -out "$tmpdir/controller.crt" >/dev/null 2>&1

port=$(shuf -i 20000-40000 -n 1)
gcc -Wall -Wextra -Wno-error -std=gnu11 \
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
    "$repo_root/common_include/wavevm_admission_stage.c" \
    "$repo_root/common_include/wavevm_runtime_gate.c" \
    "$repo_root/common_include/wavevm_route_runtime.c" \
    "$repo_root/common_include/wavevm_route_control.c" \
    "$repo_root/common_include/wavevm_route_delivery.c" \
    "$repo_root/common_include/wavevm_runtime_dispatch.c" \
    "$repo_root/common_include/wavevm_runtime_delivery.c" \
    "$repo_root/common_include/wavevm_fault_engine.c" \
    "$repo_root/common_include/wavevm_coordinator.c" \
    "$repo_root/common_include/wavevm_control_plane.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/common_include/wavevm_membership_control.c" \
    "$repo_root/common_include/wavevm_control_transport.c" \
    "$repo_root/common_include/wavevm_control_client.c" \
    "$repo_root/common_include/wavevm_control_owner.c" \
    "$repo_root/common_include/wavevm_tls_control_connector.c" \
    "$repo_root/common_include/wavevm_admission_receiver.c" \
    "$repo_root/common_include/wavevm_admission_node_service.c" \
    "$repo_root/common_include/wavevm_admission_stream_transport.c" \
    "$repo_root/tests/control-plane/test_tls_admission_node_service.c" \
    -pthread -lssl -lcrypto -o "$tmpdir/test_tls_admission_node_service"
"$tmpdir/test_tls_admission_node_service" "$port" \
    "$tmpdir/ca.crt" "$tmpdir/node.crt" "$tmpdir/node.key" \
    "$tmpdir/controller.crt" "$tmpdir/controller.key"
echo "TLS admission node service: PASS"

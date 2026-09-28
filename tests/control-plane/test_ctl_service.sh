#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-ctl-service.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/ca.key" \
    -out "$tmpdir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj /CN=executor:900:901 -keyout "$tmpdir/server.key" \
    -out "$tmpdir/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$tmpdir/server.csr" \
    -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" -CAcreateserial \
    -out "$tmpdir/server.crt" >/dev/null 2>&1

make -C "$repo_root/ctl_tool" -B
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/common_include/wavevm_membership_control.c" \
    "$repo_root/tests/control-plane/test_ctl_service.c" \
    -pthread -o "$tmpdir/test_ctl_service"
"$tmpdir/test_ctl_service" "$repo_root/ctl_tool/wvm_ctl"
"$tmpdir/test_ctl_service" "$repo_root/ctl_tool/wvm_ctl" \
    "$(shuf -i 20000-40000 -n 1)" "$tmpdir/ca.crt" \
    "$tmpdir/server.crt" "$tmpdir/server.key"

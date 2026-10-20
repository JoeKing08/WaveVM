#!/usr/bin/env bash
# goal §4 / A14 honest evidence bundle (not stub READY alone).
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root/tests/control-plane"

echo "=== §4 remote memory production path (memory_service) ==="
bash ./test_memory_service.sh

echo "=== §4 typed executor ABI bridge ==="
bash ./test_executor_bridge.sh

echo "=== §4 A14 execute_handoff → remote memory fault/ACK ==="
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-goal4-a14.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" -I"$repo_root/node_runtime" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_memory.c" \
    "$repo_root/common_include/wavevm_runtime_dispatch.c" \
    "$repo_root/common_include/wavevm_route_runtime.c" \
    "$repo_root/common_include/wavevm_vcpu_handoff.c" \
    "$repo_root/common_include/wavevm_x86_context.c" \
    "$repo_root/node_runtime/directory_store.c" \
    "$repo_root/node_runtime/memory_service.c" \
    "$repo_root/tests/control-plane/test_goal4_executor_remote_memory.c" \
    -pthread -o "$tmpdir/test_goal4_a14"
"$tmpdir/test_goal4_a14"

echo "goal §4 / A14 honest evidence bundle PASS"
echo "(tcg_helper_stub remains wiring-only; live guest OS/SSH is goal §7)"

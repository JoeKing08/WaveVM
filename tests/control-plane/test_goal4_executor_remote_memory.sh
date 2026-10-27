#!/usr/bin/env bash
# goal section 4 / A14: production execute_handoff + remote memory via executor_bridge.
# Default A14 = real no-root TCG (real qemu-system-x86_64).
# WVM_GOAL4_COMPONENT_ONLY=1 selects the narrow ABI session stub; never real TCG.
# WVM_GOAL4_KVM=1 selects the real KVM coordinator/vcpu_service path.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root/tests/control-plane"

echo "=== section 4 remote memory production path (memory_service) ==="
bash ./test_memory_service.sh

echo "=== section 4 typed executor ABI bridge ==="
bash ./test_executor_bridge.sh

echo "=== rebuild slave_hybrid.o (production execute_handoff) ==="
make -C "$repo_root/node_runtime" slave_hybrid.o

echo "=== section 4 A14 bridge -> wvm_executor_runtime_execute_handoff -> remote mem ==="
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-goal4-a14.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

nr="$repo_root/node_runtime"
ci="$repo_root/common_include"

gcc -Wall -Wextra -Werror -std=gnu11 -D_DEFAULT_SOURCE \
    -I"$ci" -I"$nr" \
    "$ci/wavevm_sha256.c" \
    "$ci/wavevm_canonical.c" \
    "$ci/wavevm_identity.c" \
    "$ci/wavevm_manifest.c" \
    "$ci/wavevm_control.c" \
    "$ci/wavevm_lifecycle.c" \
    "$ci/wavevm_envelope.c" \
    "$ci/wavevm_memory.c" \
    "$ci/wavevm_local_memory.c" \
    "$ci/wavevm_runtime_dispatch.c" \
    "$ci/wavevm_runtime_gate.c" \
    "$ci/wavevm_runtime_names.c" \
    "$ci/wavevm_route_runtime.c" \
    "$ci/wavevm_vcpu_handoff.c" \
    "$ci/wavevm_vcpu_handoff_cache.c" \
    "$ci/wavevm_x86_context.c" \
    "$ci/wavevm_executor_abi.c" \
    "$ci/wavevm_executor_session.c" \
    "$ci/wavevm_block_chunk_store.c" \
    "$nr/directory_store.c" \
    "$nr/memory_service.c" \
    "$nr/executor_bridge.c" \
    "$nr/vcpu_coordinator.c" \
    "$nr/vcpu_service.c" \
    "$nr/kvm_page_cache.c" \
    "$nr/kvm_execution_fetch.c" \
    "$nr/slave_hybrid.o" \
    "$nr/slave_vfio.o" \
    "$repo_root/tests/control-plane/test_goal4_executor_remote_memory.c" \
    -pthread -lssl -lcrypto \
    -o "$tmpdir/test_goal4_a14"
"$tmpdir/test_goal4_a14"

echo "goal section 4 / A14 production execute_handoff + remote memory PASS"
echo "(tcg_helper_stub remains CP wiring-only; live guest OS/SSH is goal section 7)"

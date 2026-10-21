#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-block-topo.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
export TMPDIR="$tmpdir"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" -I"$repo_root/node_runtime" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_block_wire.c" \
    "$repo_root/common_include/wavevm_block_chunk_store.c" \
    "$repo_root/common_include/wavevm_runtime_dispatch.c" \
    "$repo_root/common_include/wavevm_route_runtime.c" \
    "$repo_root/node_runtime/block_service.c" \
    "$repo_root/node_runtime/block_client.c" \
    "$repo_root/tests/control-plane/test_block_topology.c" \
    -o "$tmpdir/test_block_topology" -lpthread
"$tmpdir/test_block_topology"

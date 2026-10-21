#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-block-service.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
export TMPDIR="$tmpdir"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" -I"$repo_root/node_runtime" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_block_wire.c" \
    "$repo_root/common_include/wavevm_block_chunk_store.c" \
    "$repo_root/node_runtime/block_service.c" \
    "$repo_root/tests/control-plane/test_block_service.c" \
    -o "$tmpdir/test_block_service" -lpthread
"$tmpdir/test_block_service"

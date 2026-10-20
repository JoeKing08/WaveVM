#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-typed-block.XXXXXX")
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_block_chunk_store.c" \
    "$repo_root/tests/control-plane/test_typed_block_authority.c" \
    -o "$tmpdir/test_typed_block_authority" -lpthread
"$tmpdir/test_typed_block_authority"

#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-helper-barrier.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
gcc -Wall -Wextra -std=gnu11 -O2 -msse4.2 \
    -ffunction-sections -fdata-sections -I"$repo_root/common_include" \
    "$repo_root/tests/control-plane/test_helper_barrier.c" \
    -Wl,--gc-sections -pthread -o "$tmpdir/test_helper_barrier"
"$tmpdir/test_helper_barrier"

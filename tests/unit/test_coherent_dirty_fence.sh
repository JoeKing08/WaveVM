#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-dirty-fence.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
{
    sed -n '/^static void wvm_merge_commit_write_set(/,/^}/p' \
        "$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c"
    sed -n '/\/\* WVM coherent pre-image support begin \*/,/\/\* WVM coherent pre-image support end \*/p' \
        "$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c"
    sed -n '/^static int flush_coherent_dirty_bitmap_locked(/,/^int wavevm_user_mem_flush_slave_dirty_sync(/p' \
        "$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c" | sed '$d'
} >"$tmpdir/coherent_dirty.inc"
test -s "$tmpdir/coherent_dirty.inc"
gcc -std=gnu11 -Wall -Wextra -Werror -I"$repo_root/common_include" -I"$tmpdir" \
    "$repo_root/tests/unit/test_coherent_dirty_fence.c" -o "$tmpdir/test_dirty_fence"
"$tmpdir/test_dirty_fence"

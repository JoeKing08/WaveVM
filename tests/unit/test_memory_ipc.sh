#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-memory-ipc.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
sed -n '/^static int memory_ipc_transfer(/,/^static uint64_t memory_ipc_deadline(/p' \
    "$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c" | sed '$d' \
    >"$tmpdir/memory_ipc.inc"
test -s "$tmpdir/memory_ipc.inc"
gcc -std=gnu11 -Wall -Wextra -Werror -I"$tmpdir" \
    "$repo_root/tests/unit/test_memory_ipc.c" -o "$tmpdir/test_memory_ipc"
"$tmpdir/test_memory_ipc"
echo 'memory IPC partial reply / blocked send / disconnect: PASS'

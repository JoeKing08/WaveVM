#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-deferred-fault.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

gcc -Wall -Wextra -Werror -std=c11 \
    "$repo_root/tests/control-plane/test_deferred_fault_queue.c" \
    -o "$tmpdir/test_deferred_fault_queue"
"$tmpdir/test_deferred_fault_queue"
"$repo_root/tests/control-plane/test_sigsegv_handler_no_sync_ipc.sh"

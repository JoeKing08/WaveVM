#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-f06-pool.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

python3 - "$repo_root" "$tmpdir/f06_pool.inc" <<'PY'
import sys, re
from pathlib import Path
text = Path(sys.argv[1], "wavevm-qemu/accel/wavevm/wavevm-user-mem.c").read_text()
# Extract PAGE_POOL_SIZE through writable_page_release_chain (exclusive)
m = re.search(
    r"(#define PAGE_POOL_SIZE 4096\n.*?)^static void writable_page_release_chain\(",
    text, re.M | re.S)
if not m:
    raise SystemExit("pool block not found")
block = m.group(1)
# Drop unused image pool to avoid -Werror=unused-variable in unit harness
block = re.sub(r"static void\* g_image_pool\[PAGE_POOL_SIZE\];.*\n", "", block)
Path(sys.argv[2]).write_text(block)
PY
test -s "$tmpdir/f06_pool.inc"
grep -q 'page_pool_claim' "$tmpdir/f06_pool.inc"
grep -q 'F06 write page pool exhausted' \
    "$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c"

gcc -std=gnu11 -Wall -Wextra -Werror -I"$tmpdir" \
    "$repo_root/tests/unit/test_f06_page_pool.c" -o "$tmpdir/test_f06"
"$tmpdir/test_f06"

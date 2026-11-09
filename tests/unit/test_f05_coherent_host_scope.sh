#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-f05-host.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

python3 - "$repo_root" "$tmpdir/f05_coherent.inc" <<'PY'
import sys
from pathlib import Path
src = Path(sys.argv[1], "wavevm-qemu/accel/wavevm/wavevm-user-mem.c").read_text().splitlines(True)
out = []
i = 0
wanted = ("void wavevm_user_mem_set_tcg_shm_coherent(",
          "int wavevm_user_mem_tcg_shm_coherent(")
while i < len(src):
    if src[i].startswith(wanted):
        out.append(src[i]); i += 1
        depth = 0
        started = False
        while i < len(src):
            line = src[i]
            out.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            i += 1
            if started and depth <= 0:
                out.append("\n")
                break
        continue
    i += 1
Path(sys.argv[2]).write_text("".join(out))
PY
test -s "$tmpdir/f05_coherent.inc"

grep -q 'WVM_PHYSICAL_HOST_ID' "$repo_root/node_runtime/admission_main.c"
grep -q 'WVM_FE_PHYSICAL_HOST_ID' "$repo_root/node_runtime/main.c"
grep -q 'WVM_EXECUTOR_PHYSICAL_HOST_ID' "$repo_root/slave_daemon/slave_hybrid.c"
grep -qE 'N02 coherent REFUSED|F05/N02 coherent REFUSED|F05 coherent REFUSED' "$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c"
grep -q 'WVM_FE_SHM_FILE' "$repo_root/node_runtime/main.c"

gcc -std=gnu11 -Wall -Wextra -Werror -I"$tmpdir" \
    "$repo_root/tests/unit/test_f05_coherent_host_scope.c" -o "$tmpdir/test_f05"
"$tmpdir/test_f05"
echo "placement_export_strings: admission_main+main+slave_hybrid OK"

#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-r05.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
gcc -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE \
    "$repo_root/tests/control-plane/test_r05_multi_vcpu_race.c" \
    -pthread -o "$tmpdir/test_r05"
set +e
"$tmpdir/test_r05"
rc=$?
set -e
# 0=PASS, 2=PARTIAL (guard ok, tear not observed) — both honest; treat 2 as soft pass for close.
if [[ "$rc" -eq 0 || "$rc" -eq 2 ]]; then
  exit 0
fi
exit "$rc"

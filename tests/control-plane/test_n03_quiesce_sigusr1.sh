#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-n03.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
gcc -Wall -Wextra -Werror -std=c11 -D_DEFAULT_SOURCE \
  -I"$ROOT/common_include" \
  "$ROOT/common_include/wavevm_sha256.c" \
  "$ROOT/common_include/wavevm_canonical.c" \
  "$ROOT/common_include/wavevm_identity.c" \
  "$ROOT/common_include/wavevm_manifest.c" \
  "$ROOT/common_include/wavevm_lifecycle.c" \
  "$ROOT/common_include/wavevm_runtime_names.c" \
  "$ROOT/common_include/wavevm_runtime_gate.c" \
  "$ROOT/tests/control-plane/test_n03_quiesce_sigusr1.c" \
  -o "$tmpdir/test_n03_quiesce_sigusr1"
"$tmpdir/test_n03_quiesce_sigusr1"

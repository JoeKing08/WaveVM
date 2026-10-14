#!/usr/bin/env bash
# Placement spread honesty: exclusive lease accounting + fail-closed remote
# memory (resource-placement-admission §4 / §5.3). Mode A gate untouched.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-placement-spread.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_admission.c" \
    "$repo_root/tests/control-plane/test_placement_spread.c" \
    -o "$tmpdir/test_placement_spread"
"$tmpdir/test_placement_spread"

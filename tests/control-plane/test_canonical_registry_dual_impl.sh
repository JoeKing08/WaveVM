#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-canonical-dual.XXXXXX")
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_capability.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/tests/control-plane/test_canonical_registry_dual_impl.c" \
    -o "$tmpdir/test_canonical_registry_dual_impl"
"$tmpdir/test_canonical_registry_dual_impl"

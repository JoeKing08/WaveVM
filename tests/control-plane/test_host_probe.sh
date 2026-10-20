#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-host-probe.XXXXXX")
trap 'rm -rf -- "$tmpdir"' EXIT

gcc -Wall -Wextra -Werror -std=gnu11 -D_GNU_SOURCE \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_host_probe.c" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_fault_engine.c" \
    "$repo_root/common_include/wavevm_capability.c" \
    "$repo_root/tests/control-plane/test_host_probe.c" \
    -o "$tmpdir/test_host_probe"
"$tmpdir/test_host_probe"

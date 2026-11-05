#!/usr/bin/env bash
# Q01 directed evidence: refuse second WaveVM block device_index.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-q01-device.XXXXXX")
trap 'rm -rf -- "$tmpdir"' EXIT

# Match test_storage_placement.sh object set (manifest pulls runtime_names).
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_capability.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/tests/control-plane/test_q01_single_device_index.c" \
    -o "$tmpdir/test_q01_single_device_index"

"$tmpdir/test_q01_single_device_index"

#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-op-identity-wire.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_route_runtime.c" \
    "$repo_root/tests/control-plane/test_rm_p7_op_identity_reroute.c" \
    -pthread -o "$tmpdir/test_rm_p7_op_identity_reroute"
"$tmpdir/test_rm_p7_op_identity_reroute"

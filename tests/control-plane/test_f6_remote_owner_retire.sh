#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-f6.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

# Contract: agent clear_stale must use full name_set_retire (not 4× unlink).
if ! grep -q 'wvm_runtime_name_set_retire' \
    "$repo_root/common_include/wavevm_admission_runtime_agent.c"; then
    echo "F6: agent missing name_set_retire" >&2
    exit 1
fi
if grep -E '^\s*\(void\)unlink\(names\.(runtime|executor|worker|monitor)_socket\)' \
    "$repo_root/common_include/wavevm_admission_runtime_agent.c"; then
    echo "F6: agent still has socket-only unlink path" >&2
    exit 1
fi
# Receiver lifecycle STOP must also retire owner names.
if ! grep -A80 'abort_reason == WVM_ADMISSION_ABORT_REASON_LIFECYCLE_STOP' \
    "$repo_root/common_include/wavevm_admission_receiver.c" |
    grep -q 'wvm_runtime_name_set_retire'; then
    echo "F6: receiver lifecycle STOP missing owner name_set_retire" >&2
    exit 1
fi

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/tests/control-plane/test_f6_remote_owner_retire.c" \
    -lrt -o "$tmpdir/t"
"$tmpdir/t"

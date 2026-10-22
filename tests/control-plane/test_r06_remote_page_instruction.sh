#!/usr/bin/env bash
# R06: remote page bytes -> production fetch -> real KVM instruction result.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root/tests/control-plane"

if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "R06 BLOCKED: /dev/kvm not usable (need read+write)" >&2
  exit 2
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-r06.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

nr="$repo_root/node_runtime"
ci="$repo_root/common_include"

echo "=== rebuild kvm_execution_fetch.o (production R06 fetch) ==="
make -C "$nr" kvm_execution_fetch.o kvm_page_cache.o memory_service.o

echo "=== R06 micro KVM: instruction result depends on remote page ==="
gcc -Wall -Wextra -Werror -std=gnu11 -D_DEFAULT_SOURCE \
    -I"$ci" -I"$nr" \
    "$ci/wavevm_sha256.c" \
    "$ci/wavevm_canonical.c" \
    "$ci/wavevm_identity.c" \
    "$ci/wavevm_manifest.c" \
    "$ci/wavevm_control.c" \
    "$ci/wavevm_lifecycle.c" \
    "$ci/wavevm_envelope.c" \
    "$ci/wavevm_memory.c" \
    "$ci/wavevm_runtime_dispatch.c" \
    "$ci/wavevm_route_runtime.c" \
    "$nr/directory_store.c" \
    "$nr/memory_service.c" \
    "$nr/kvm_page_cache.c" \
    "$nr/kvm_execution_fetch.c" \
    "$repo_root/tests/control-plane/test_r06_remote_page_instruction.c" \
    -pthread -lssl -lcrypto \
    -o "$tmpdir/test_r06"
"$tmpdir/test_r06"

echo "R06 remote-page instruction dependence PASS"

#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-reservation-runtime.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

read -r -a extra_flags <<< "${CFLAGS:-}"
for test in test_reservation_runtime test_reservation_journal; do
    link_flags=()
    if [[ $test == test_reservation_journal ]]; then
        link_flags=(-Wl,--wrap=fsync -Wl,--wrap=write)
    fi
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L "${extra_flags[@]}" \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_admission.c" \
    "$repo_root/common_include/wavevm_reservation_runtime.c" \
    "$repo_root/tests/control-plane/$test.c" \
    -pthread "${link_flags[@]}" -o "$tmpdir/$test"
"$tmpdir/$test" "$tmpdir/reservations.journal"
done

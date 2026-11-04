#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-committed-image.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

gcc -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-format \
    -O2 -ffunction-sections -fdata-sections -pthread \
    "$repo_root/tests/unit/test_directory_committed_image.c" \
    -Wl,--gc-sections -o "$tmpdir/test_directory_committed_image"
"$tmpdir/test_directory_committed_image"

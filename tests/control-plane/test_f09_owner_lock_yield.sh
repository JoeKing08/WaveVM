#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/tests/control-plane/test_f09_owner_lock_yield"
cc -Wall -Werror -O2 -std=gnu11 -D_DEFAULT_SOURCE \
  -o "$BIN" "$ROOT/tests/control-plane/test_f09_owner_lock_yield.c" -pthread
"$BIN"

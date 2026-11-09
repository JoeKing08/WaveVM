#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cc -Wall -Wextra -Werror -std=c11 -D_DEFAULT_SOURCE -pthread \
  -o "$ROOT/tests/control-plane/test_n01_admission_workspace_isolation" \
  "$ROOT/tests/control-plane/test_n01_admission_workspace_isolation.c"
"$ROOT/tests/control-plane/test_n01_admission_workspace_isolation"

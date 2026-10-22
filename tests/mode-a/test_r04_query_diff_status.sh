#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
gcc -Wall -Wextra -Werror -std=gnu11 -D_GNU_SOURCE     "$repo_root/tests/mode-a/test_r04_query_diff_status.c"     -o /tmp/test_r04_query_diff_status
/tmp/test_r04_query_diff_status

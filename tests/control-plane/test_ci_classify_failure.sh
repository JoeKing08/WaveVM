#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cls=$("$repo_root/scripts/ci_classify_failure.sh" --from-stdin <<'LOG'
wvm_ctl: CREATE_VM precondition failed admission_result=-1
STOP_VM did not reach SUCCESS/STOPPED
LOG
)
[[ "$cls" == class=start ]]
cls=$("$repo_root/scripts/ci_classify_failure.sh" --from-stdin <<'LOG'
route-runtime test: lookups never observe half-table next-hop mix
LOG
)
[[ "$cls" == class=route ]]
cls=$("$repo_root/scripts/ci_classify_failure.sh" --from-stdin <<'LOG'
test_guest_smoke: SSH login timeout
LOG
)
[[ "$cls" == class=guest_boot ]]
echo "ci_classify_failure: PASS"

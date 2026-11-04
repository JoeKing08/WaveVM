#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
sample='[WVM-MEM-STATS] vm=7 incarnation=2 manifest=3 origin=1 instance=11 runtime=12 pid=13 directory=2 directory_instance=21 remote_reads=4 remote_commits=2'
count() {
    awk -v vm=7 -v incarnation=2 -v manifest=3 \
        -f "$repo_root/tests/e2e/remote_memory_evidence.awk"
}
[[ $(printf '%s\n%s\n' "$sample" "$sample" | count) == 6 ]]
[[ $(printf '%s\n' "${sample/vm=7/vm=8}" | count) == 0 ]]
[[ $(printf '%s\n' "${sample/incarnation=2/incarnation=1}" | count) == 0 ]]
[[ $(printf '%s\n' "${sample/directory=2 directory_instance=21/directory=1 directory_instance=11}" | count) == 0 ]]
[[ $(printf '%s\n' 'dirty commit failed rc=-5' '=== PUSH_BARRIER_ACK ===' | count) == 0 ]]
echo 'remote memory evidence scope / duplicate samples / failures: PASS'

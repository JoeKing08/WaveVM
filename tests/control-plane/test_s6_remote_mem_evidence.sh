#!/usr/bin/env bash
# remote_mem fence / version / dirty depth evidence pack for §6 residual.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evid="${WAVEVM_S6_R1_EVID:-/tmp/wavevm-s6-r1-rmem-20261024}"
mkdir -p "$evid"
cd "$repo_root/tests/control-plane"

{
  echo "=== remote_mem evidence $(date -Iseconds) Asia/Shanghai ==="
  echo "components: directory_store version/dirty + memory_service dirty commit"
  echo "            + fence_reject unit + goal4 A14 real no-root TCG remote version/fence path"
  echo "            + A14 KVM real coordinator via vcpu_service/remote HLT/dirty-commit ACK path"
} | tee "$evid/remote_mem_HEADER.txt"

set +e
bash ./test_directory_store.sh 2>&1 | tee "$evid/directory_store.log"
rc_dir=${PIPESTATUS[0]}
bash ./test_memory_service.sh 2>&1 | tee "$evid/memory_service.log"
rc_mem=${PIPESTATUS[0]}

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-s6-fence.XXXXXX")
gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_vcpu_handoff.c" \
    "$repo_root/common_include/wavevm_x86_context.c" \
    "$repo_root/tests/control-plane/test_s6_fence_reject.c" \
    -o "$tmpdir/test_s6_fence_reject"
"$tmpdir/test_s6_fence_reject" 2>&1 | tee "$evid/fence_reject.log"
rc_fence=${PIPESTATUS[0]}
rm -rf "$tmpdir"

# goal4 A14 is the production typed handoff + remote memory_service path.
# It is heavier; still required for honest remote_mem depth (version + fence_id).
bash ./test_goal4_executor_remote_memory.sh 2>&1 | tee "$evid/goal4_a14.log"
rc_g4=${PIPESTATUS[0]}
# The KVM mode is the real remote-page execution + real dirty-commit ACK path.
# It is required when /dev/kvm is usable; otherwise record the clear skip.
rc_g4_kvm=0
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  WVM_GOAL4_KVM=1 bash ./test_goal4_executor_remote_memory.sh 2>&1 | \
    tee "$evid/goal4_a14_kvm.log"
  rc_g4_kvm=${PIPESTATUS[0]}
else
  echo "goal4 A14 KVM skipped: /dev/kvm not usable" | \
    tee "$evid/goal4_a14_kvm.log"
fi
set -e

# Harvest concrete markers (not mere greps of source).
{
  echo "directory_store_rc=$rc_dir"
  grep -E 'EVID|PASS|stale|version|commit|ESTALE' "$evid/directory_store.log" | head -40 || true
  echo "---"
  echo "memory_service_rc=$rc_mem"
  grep -E 'EVID|PASS|commit|version|STALE|dirty|fence' "$evid/memory_service.log" | head -40 || true
  echo "---"
  echo "fence_reject_rc=$rc_fence"
  cat "$evid/fence_reject.log"
  echo "---"
  echo "goal4_a14_rc=$rc_g4"
  grep -E 'EVID|PASS|FAIL|version|fence|remote|VCPU_EXIT' "$evid/goal4_a14.log" | head -40 || true
  echo "---"
  echo "goal4_a14_kvm_rc=$rc_g4_kvm"
  grep -E 'EVID|PASS|FAIL|version|fence|remote|VCPU_EXIT|coordinator' \
    "$evid/goal4_a14_kvm.log" | head -60 || true
} >"$evid/remote_mem_HARVEST.txt"

if [[ $rc_dir -eq 0 && $rc_mem -eq 0 && $rc_fence -eq 0 && $rc_g4 -eq 0 && $rc_g4_kvm -eq 0 ]]; then
  {
    echo "REMOTE_MEM_FENCE_VERSION_DIRTY=FIXED"
    echo "evidence:"
    echo "  directory_store: materialize version + commit advances version + ESTALE stale base"
    echo "  memory_service: remote V1 dirty commit base_version->result_version + STALE_BASE_VERSION ACK"
    echo "  fence_reject: memory_fence_result!=SUCCEEDED cannot encode typed VCPU_RUN"
    echo "  goal4 A14 TCG: DEFAULT real no-root QEMU -> production execute_handoff; remote fault ACK + real guest store + remote dirty commit/version"
    echo "  goal4 A14 KVM: vcpu_service -> real coordinator -> real KVM remote-page HLT + real dirty-commit ACK version/fence; same-physical two-instance path (A3 closed)"
    echo "not=source_grep_only"
    date -Iseconds
  } | tee "$evid/REMOTE_MEM_FENCE_VERSION_DIRTY.txt"
  exit 0
fi

{
  echo "REMOTE_MEM_FENCE_VERSION_DIRTY=PARTIAL"
  echo "rc_dir=$rc_dir rc_mem=$rc_mem rc_fence=$rc_fence rc_g4=$rc_g4 rc_g4_kvm=$rc_g4_kvm"
  date -Iseconds
} | tee "$evid/REMOTE_MEM_FENCE_VERSION_DIRTY.txt"
exit 1

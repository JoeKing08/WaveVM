#!/usr/bin/env bash
# WaveVM Minimum Phase-10 failure classifier (goal/roadmap §14 Min acceptance).
# Distinguishes capability / boot-start / route / memory / CPU / guest-boot
# failure classes from harness logs. Does NOT run the §6 matrix or §7 guest.
set -euo pipefail

usage() {
  echo "Usage: $0 [--log FILE] [--from-stdin]" >&2
  echo "  Classifies WaveVM test/control-plane failure text into one class:" >&2
  echo "    capability | start | route | memory | cpu | guest_boot | unknown" >&2
  exit 2
}

log_file=""
from_stdin=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --log) log_file=${2:-}; shift 2 ;;
    --from-stdin) from_stdin=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

if [[ "$from_stdin" -eq 1 ]]; then
  text=$(cat)
elif [[ -n "$log_file" ]]; then
  text=$(cat -- "$log_file")
else
  usage
fi

# Order matters: more specific first. guest_boot stays detectable even though
# §7 is out of Min close scope — classifier must still name that class.
classify() {
  local t=$1
  if echo "$t" | grep -qiE 'guest[_ -]?boot|guest smoke|ssh.*(fail|timeout)|login.*(fail|timeout)|test_guest_smoke'; then
    echo guest_boot; return
  fi
  if echo "$t" | grep -qiE 'QUERY_CAPS|host_probe|capability|UFFD|false.?AVAILABLE|REQUIRE_KVM|probe→publish|CapabilityReport'; then
    echo capability; return
  fi
  if echo "$t" | grep -qiE 'route snapshot|half-table|next-hop|ROUTE_RETIRE|route_generation|stale packet|route-runtime'; then
    echo route; return
  fi
  if echo "$t" | grep -qiE 'memory_service|remote fault|page version|dirty|directory_store|SIGSEGV|fault_engine|mprotect|handoff.*fence'; then
    echo memory; return
  fi
  if echo "$t" | grep -qiE 'vcpu|executor_bridge|executor_session|VCPU_RUN|cpu assignment|requested_vcpu'; then
    echo cpu; return
  fi
  if echo "$t" | grep -qiE 'CREATE_VM|STOP_VM|admission|STARTING|COMMITTED|runtime is starting|orchestrator|participant_abort|admitted child|relaunch|RUNNING'; then
    echo start; return
  fi
  echo unknown
}

cls=$(classify "$text")
echo "class=$cls"
exit 0

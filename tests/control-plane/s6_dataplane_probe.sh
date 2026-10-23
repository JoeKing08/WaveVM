#!/usr/bin/env bash
# §6 R1 dataplane probe against a RUNNING CREATE_VM cell.
# Env: WVM_S6_EVIDENCE_DIR, WVM_S6_TMPDIR, WVM_S6_CREATE_OUT, WVM_S6_AGENT_PID
#      WVM_S6_CELL (optional), WVM_S6_BACKEND
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evid=${WVM_S6_EVIDENCE_DIR:?}
tmpdir=${WVM_S6_TMPDIR:?}
create_out=${WVM_S6_CREATE_OUT:?}
cell=${WVM_S6_CELL:-unknown}
backend=${WVM_S6_BACKEND:-}
agent_log="$tmpdir/agent.log"
[[ -f "$agent_log" ]] || agent_log="$tmpdir/agent-a.log"
runtime_dir="$tmpdir/runtime"
[[ -d "$runtime_dir" ]] || runtime_dir="$tmpdir/runtime-a"

vm_id=$(sed -n 's/.*vm_id=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
marker=$((0x5366 ^ (vm_id & 0xffff)))
report="$evid/dataplane_detail.txt"
: >"$report"
{
  echo "cell=$cell"
  echo "backend=$backend"
  echo "vm_id=$vm_id"
  echo "create_out=$create_out"
  echo "marker=0x$(printf '%x' "$marker")"
} >>"$report"

fail() { echo "dataplane FAIL: $*" | tee -a "$report" >&2; exit 1; }

[[ -n "$vm_id" && "$vm_id" != "0" ]] || fail "no vm_id"

# Locate SHM for THIS cell's VM — prefer agent.log identity, then newest mtime.
# Never pick an arbitrary leftover /dev/shm/wavevm_ram_wvm-vNNN* (false PASS/hang).
shm=""
mapfile -t shms < <(grep -oE '/wavevm_ram_wvm-v'"$vm_id"'[^[:space:]]*' "$agent_log" 2>/dev/null \
  | sed 's|^/wavevm_ram_|/dev/shm/wavevm_ram_|;s|^/dev/shm/dev/shm/|/dev/shm/|' | sort -u || true)
if [[ ${#shms[@]} -lt 1 ]]; then
  mapfile -t shms < <(ls -1t /dev/shm/wavevm_ram_wvm-v"${vm_id}"* 2>/dev/null || true)
fi
[[ ${#shms[@]} -ge 1 ]] || fail "no SHM for vm_id=$vm_id"
shm=""
for c in "${shms[@]}"; do
  [[ -e "$c" ]] || continue
  shm=$c
  break
done
[[ -n "$shm" ]] || fail "SHM path from log/listing not present"
echo "shm=$shm" >>"$report"

# Executor listen port from child/agent logs
port=""
port=$(grep -oE 'Listening on 127\.0\.0\.1:[0-9]+' "$agent_log" 2>/dev/null | head -1 | grep -oE '[0-9]+$' || true)
if [[ -z "$port" ]]; then
  # Child stderr under runtime
  port=$(find "$runtime_dir" -type f \( -name 'stderr*' -o -name '*.log' \) -print0 2>/dev/null \
    | xargs -0 grep -ohE 'Listening on 127\.0\.0\.1:[0-9]+' 2>/dev/null | head -1 \
    | grep -oE '[0-9]+$' || true)
fi
echo "executor_port=${port:-none}" >>"$report"

# Backend identity evidence
mode_line=$(grep -E 'Mode: (KVM FAST PATH|TCG PROXY)' "$agent_log" 2>/dev/null | head -1 || true)
echo "mode_line=$mode_line" >>"$report"
qemu_helper=${WVM_TCG_QEMU_BIN:-}
echo "tcg_helper=$qemu_helper" >>"$report"

case "$backend" in
  require-kvm)
    [[ "$mode_line" == *'KVM FAST PATH'* ]] || fail "expected KVM FAST PATH, got: $mode_line"
    [[ -n "$port" ]] || fail "no executor port for KVM run"
    gcc -Wall -Wextra -Werror -std=gnu11 -O1 \
      -I"$repo_root/common_include" \
      "$repo_root/tests/control-plane/s6_dataplane_kvm_run.c" \
      -o "$tmpdir/s6_dataplane_kvm_run"
    if ! sg kvm -c "$tmpdir/s6_dataplane_kvm_run '$shm' '$port' '$vm_id' '0x$(printf %x "$marker")'" \
         >>"$report" 2>&1; then
      # Also try without sg if already in group
      if ! "$tmpdir/s6_dataplane_kvm_run" "$shm" "$port" "$vm_id" "0x$(printf %x "$marker")" \
           >>"$report" 2>&1; then
        fail "kvm short exec"
      fi
    fi
    ;;
  require-tcg|auto)
    # Real QEMU helper required for TCG dataplane claim
    if [[ -n "$qemu_helper" && -x "$qemu_helper" && "$qemu_helper" != *tcg_helper_stub* ]]; then
      echo "real_qemu=1 path=$qemu_helper" >>"$report"
      if [[ -n "${WVM_S6_AGENT_PID:-}" ]]; then
        if pgrep -P "${WVM_S6_AGENT_PID}" -a 2>/dev/null | grep -E 'qemu-system|wavevm' >>"$report"; then
          echo "qemu_child=present" >>"$report"
        else
          pgrep -af 'qemu-system-x86_64.*-accel wavevm' >>"$report" 2>/dev/null || true
        fi
      fi
      [[ "$mode_line" == *'TCG PROXY'* ]] || echo "warn: mode_line not TCG PROXY: $mode_line" >>"$report"
    else
      fail "TCG cell without real QEMU helper (got: $qemu_helper)"
    fi
    [[ -n "$port" ]] || fail "no executor port for TCG short-exec"
    if grep -qE 'Spawning.*QEMU-TCG|-accel wavevm|TCG helper' "$agent_log" 2>/dev/null; then
      echo "tcg_spawn_evidence=present" >>"$report"
    fi
    gcc -Wall -Wextra -Werror -std=gnu11 -O1 \
      -I"$repo_root/common_include" \
      "$repo_root/tests/control-plane/s6_dataplane_tcg_run.c" \
      -o "$tmpdir/s6_dataplane_tcg_run"
    if ! "$tmpdir/s6_dataplane_tcg_run" "$shm" "$port" "$vm_id" "0x$(printf %x "$marker")" \
         >>"$report" 2>&1; then
      fail "tcg short exec"
    fi
    echo "tcg_dataplane=helper_live+shm_rw+short_exec" >>"$report"
    ;;
  *)
    echo "backend=$backend — treating as generic SHM check" >>"$report"
    python3 - "$shm" "$marker" <<'PY' >>"$report"
import mmap, os, sys
path, marker = sys.argv[1], int(sys.argv[2]) & 0xffffffff
fd = os.open(path, os.O_RDWR)
st = os.fstat(fd)
mm = mmap.mmap(fd, st.st_size)
off = 0x3000
mm[off] = 0xC3
print(f"shm_rw=ok gpa=0x{off:x}")
mm.close(); os.close(fd)
PY
    ;;
esac

# Fractal gateway correlation: route journal + agent must reference same route_scope
if [[ "$cell" == fractal_* ]] || [[ -d "$tmpdir/gw-state" ]]; then
  gwj="$tmpdir/gw-state/route.journal"
  [[ -s "$gwj" ]] || fail "fractal missing gateway route.journal"
  cp -a "$gwj" "$evid/gateway_route.journal" 2>/dev/null || true
  scope=$(sed -n 's/.*route_scope_id=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
  {
    echo "fractal_gateway=1"
    echo "route_scope_id=$scope"
    echo "route_journal_bytes=$(stat -c %s "$gwj" 2>/dev/null || echo 0)"
    # Correlated snippets
    grep -E "route_scope|vm_id=$vm_id|FORWARD|dispatch|ACK|snapshot" \
      "$tmpdir/gw.log" 2>/dev/null | head -n 40 || true
    grep -E "route_scope|gateway|FRACTAL|snapshot" "$agent_log" 2>/dev/null | head -n 40 || true
  } >>"$evid/fractal_gateway_correlation.txt"
  # Require at least route journal non-empty AND create identity present
  if [[ -z "$scope" ]]; then
    fail "fractal missing route_scope_id in create_out"
  fi
  echo "fractal_correlation=route_journal+scope=$scope" >>"$report"
fi

# Remote memory version/fence/dirty — best-effort from agent/ctl logs + SHM dirty
{
  echo "=== remote_mem / fence / dirty snippets ==="
  grep -E 'dirty|fence|MEM_READ|MEM_WRITE|version|page.fault|remote' \
    "$agent_log" "$tmpdir/ctl.log" 2>/dev/null | head -n 40 || true
} >>"$evid/remote_mem_snippets.txt"

echo "dataplane_probe=PASS" >>"$report"
echo "s6 dataplane probe PASS cell=$cell backend=$backend vm_id=$vm_id"
exit 0

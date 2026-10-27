#!/usr/bin/env bash
# §6 R1 dataplane probe against a RUNNING CREATE_VM cell.
# Prefers PRODUCTION typed WVM1 dispatch (node ingress / gateway forward).
# Env: WVM_S6_EVIDENCE_DIR, WVM_S6_TMPDIR, WVM_S6_CREATE_OUT, WVM_S6_AGENT_PID
#      WVM_S6_CELL (optional), WVM_S6_BACKEND, WVM_S6_GW_DATA_PORT (fractal)
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
vm_inc=$(sed -n 's/.*vm_incarnation=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
manifest_gen=$(sed -n 's/.*manifest_generation=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
marker=$((0x5366 ^ (vm_id & 0xffff)))
report="$evid/dataplane_detail.txt"
: >"$report"
{
  echo "cell=$cell"
  echo "backend=$backend"
  echo "vm_id=$vm_id"
  echo "vm_incarnation=$vm_inc"
  echo "manifest_generation=$manifest_gen"
  echo "create_out=$create_out"
  echo "marker=0x$(printf '%x' "$marker")"
} >>"$report"

fail() { echo "dataplane FAIL: $*" | tee -a "$report" >&2; exit 1; }

[[ -n "$vm_id" && "$vm_id" != "0" ]] || fail "no vm_id"

# Locate SHM for THIS cell's VM
shm=""
mapfile -t shms < <(grep -oE '/wavevm_ram_wvm-v'"$vm_id"'[A-Za-z0-9_-]*' "$agent_log" 2>/dev/null \
  | sed "s/['\":.,;)]*$//;s|^/wavevm_ram_|/dev/shm/wavevm_ram_|;s|^/dev/shm/dev/shm/|/dev/shm/|" | sort -u || true)
if [[ ${#shms[@]} -lt 1 ]]; then
  mapfile -t shms < <(ls -1t /dev/shm/wavevm_ram_wvm-v"${vm_id}"* 2>/dev/null || true)
fi
[[ ${#shms[@]} -ge 1 ]] || fail "no SHM for vm_id=$vm_id"
for c in "${shms[@]}"; do
  [[ -e "$c" ]] || continue
  shm=$c
  break
done
[[ -n "$shm" ]] || fail "SHM path from log/listing not present"
echo "shm=$shm" >>"$report"

# Manifest path: child argv, then runtime/vm-ID-INC-GEN.manifest
manifest=""
manifest=$(grep -oE -- "--manifest[[:space:]]+/[^[:space:]]+\.manifest" "$agent_log" 2>/dev/null \
  | grep -E "vm-${vm_id}-" | head -1 | awk '{print $2}' || true)
if [[ -z "$manifest" || ! -f "$manifest" ]]; then
  if [[ -n "$vm_inc" && -n "$manifest_gen" && -f "$runtime_dir/vm-${vm_id}-${vm_inc}-${manifest_gen}.manifest" ]]; then
    manifest="$runtime_dir/vm-${vm_id}-${vm_inc}-${manifest_gen}.manifest"
  else
    manifest=$(ls -1t "$runtime_dir"/vm-"${vm_id}"-*.manifest 2>/dev/null | head -1 || true)
  fi
fi
[[ -n "$manifest" && -f "$manifest" ]] || fail "no admitted manifest for vm_id=$vm_id"
[[ -f "${manifest}.dispatch" ]] || fail "missing ${manifest}.dispatch"
[[ -f "${manifest}.route" ]] || fail "missing ${manifest}.route"
echo "manifest=$manifest" >>"$report"

# Ports: prefer s6_ports.env / env, else parse launch_plan via typed binary after compile
gw_port=${WVM_S6_GW_DATA_PORT:-}
if [[ -f "$tmpdir/s6_ports.env" ]]; then
  # shellcheck disable=SC1090
  source "$tmpdir/s6_ports.env"
  gw_port=${WVM_S6_GW_DATA_PORT:-${gw_data_port:-$gw_port}}
fi
echo "gw_data_port=${gw_port:-none}" >>"$report"

# Backend identity evidence
mode_line=$(grep -E 'Mode: (KVM FAST PATH|TCG PROXY)' "$agent_log" 2>/dev/null | head -1 || true)
echo "mode_line=$mode_line" >>"$report"
qemu_helper=${WVM_TCG_QEMU_BIN:-}
echo "tcg_helper=$qemu_helper" >>"$report"

typed_backend=""
case "$backend" in
  require-kvm)
    [[ "$mode_line" == *'KVM FAST PATH'* ]] || fail "expected KVM FAST PATH, got: $mode_line"
    typed_backend=kvm
    ;;
  require-tcg|auto)
    if [[ -n "$qemu_helper" && -x "$qemu_helper" && "$qemu_helper" != *tcg_helper_stub* ]]; then
      echo "real_qemu=1 path=$qemu_helper" >>"$report"
      if [[ -n "${WVM_S6_AGENT_PID:-}" ]]; then
        pgrep -P "${WVM_S6_AGENT_PID}" -a 2>/dev/null | grep -E 'qemu-system|wavevm' >>"$report" || true
      fi
    else
      fail "TCG cell without real QEMU helper (got: $qemu_helper)"
    fi
    typed_backend=tcg
    ;;
  *)
    fail "unsupported backend=$backend for typed short-exec"
    ;;
esac

# Build production typed helper (same object set as R1 gateway E2E).
typed_bin="$tmpdir/s6_dataplane_typed_run"
gcc -Wall -Wextra -std=gnu11 -D_POSIX_C_SOURCE=200809L -O1 \
  -I"$repo_root/common_include" -I"$repo_root/node_runtime" \
  "$repo_root/common_include/wavevm_sha256.c" \
  "$repo_root/common_include/wavevm_canonical.c" \
  "$repo_root/common_include/wavevm_identity.c" \
  "$repo_root/common_include/wavevm_runtime_names.c" \
  "$repo_root/common_include/wavevm_manifest.c" \
  "$repo_root/common_include/wavevm_lifecycle.c" \
  "$repo_root/common_include/wavevm_membership.c" \
  "$repo_root/common_include/wavevm_capability.c" \
  "$repo_root/common_include/wavevm_admission.c" \
  "$repo_root/common_include/wavevm_cluster.c" \
  "$repo_root/common_include/wavevm_reservation_runtime.c" \
  "$repo_root/common_include/wavevm_fault_engine.c" \
  "$repo_root/common_include/wavevm_coordinator.c" \
  "$repo_root/common_include/wavevm_control.c" \
  "$repo_root/common_include/wavevm_envelope.c" \
  "$repo_root/common_include/wavevm_route_runtime.c" \
  "$repo_root/common_include/wavevm_route_delivery.c" \
  "$repo_root/common_include/wavevm_runtime_gate.c" \
  "$repo_root/common_include/wavevm_runtime_dispatch.c" \
  "$repo_root/common_include/wavevm_vcpu_handoff.c" \
  "$repo_root/common_include/wavevm_x86_context.c" \
  "$repo_root/tests/control-plane/s6_dataplane_typed_run.c" \
  -pthread -o "$typed_bin" || fail "compile s6_dataplane_typed_run"

# Always take node_runtime_data_port from admitted manifest (NOT agent --data-port).
# Agent parent --data-port != child node_runtime ingress; mistaking them was the
# direct_executor_udp / wrong-port class of failures.
ingress_port=""
gcc -Wall -O1 -std=gnu11 -D_POSIX_C_SOURCE=200809L \
  -I"$repo_root/common_include" \
  "$repo_root/common_include/wavevm_sha256.c" \
  "$repo_root/common_include/wavevm_canonical.c" \
  "$repo_root/common_include/wavevm_identity.c" \
  "$repo_root/common_include/wavevm_runtime_names.c" \
  "$repo_root/common_include/wavevm_manifest.c" \
  "$repo_root/common_include/wavevm_lifecycle.c" \
  "$repo_root/common_include/wavevm_membership.c" \
  "$repo_root/common_include/wavevm_capability.c" \
  "$repo_root/common_include/wavevm_admission.c" \
  "$repo_root/common_include/wavevm_cluster.c" \
  "$repo_root/common_include/wavevm_reservation_runtime.c" \
  "$repo_root/common_include/wavevm_fault_engine.c" \
  "$repo_root/common_include/wavevm_coordinator.c" \
  "$repo_root/common_include/wavevm_control.c" \
  "$repo_root/common_include/wavevm_envelope.c" \
  "$repo_root/common_include/wavevm_route_runtime.c" \
  "$repo_root/common_include/wavevm_route_delivery.c" \
  "$repo_root/common_include/wavevm_runtime_gate.c" \
  "$repo_root/tests/control-plane/s6_dump_manifest_ports.c" \
  -pthread -o "$tmpdir/s6_dump_ports" || fail "compile s6_dump_ports"
"$tmpdir/s6_dump_ports" "$manifest" | tee -a "$report"
ingress_port=$(grep -oE 'node_runtime_data_port=[0-9]+' "$report" | tail -1 | cut -d= -f2)

via_gateway=0
send_port=$ingress_port
if [[ "$cell" == fractal_* ]] || [[ -d "$tmpdir/gw-state" ]]; then
  [[ -n "$gw_port" ]] || fail "fractal cell missing gw_data_port (export WVM_S6_GW_DATA_PORT / s6_ports.env)"
  send_port=$gw_port
  via_gateway=1
  echo "fractal_via_gateway=1 gw_data_port=$gw_port node_data_port=$ingress_port" >>"$report"
fi

echo "typed_send_port=$send_port via_gateway=$via_gateway backend=$typed_backend" >>"$report"

run_typed() {
  local mark_hex
  mark_hex=$(printf '0x%x' "$marker")
  if [[ "$typed_backend" == kvm ]] && command -v sg >/dev/null 2>&1 && id -nG 2>/dev/null | grep -qw kvm; then
    if sg kvm -c "'$typed_bin' '$shm' '$manifest' '$send_port' '$typed_backend' '$mark_hex' '0x2000' '$via_gateway'"          >>"$report" 2>&1; then
      return 0
    fi
  fi
  "$typed_bin" "$shm" "$manifest" "$send_port" "$typed_backend"     "$mark_hex" 0x2000 "$via_gateway" >>"$report" 2>&1
}

if ! run_typed; then
  fail "production typed short-exec (WVM1 ingress/gateway)"
fi

# Fractal gateway correlation + forward evidence
if [[ "$via_gateway" == "1" ]]; then
  gwj="$tmpdir/gw-state/route.journal"
  [[ -s "$gwj" ]] || fail "fractal missing gateway route.journal"
  cp -a "$gwj" "$evid/gateway_route.journal" 2>/dev/null || true
  scope=$(sed -n 's/.*route_scope_id=\([0-9][0-9]*\).*/\1/p' <<<"$create_out" | head -1)
  {
    echo "fractal_gateway=1"
    echo "route_scope_id=$scope"
    echo "route_journal_bytes=$(stat -c %s "$gwj" 2>/dev/null || echo 0)"
    grep -E "route_scope|vm_id=$vm_id|FORWARD|V1|rejected|dispatch|ACK|snapshot" \
      "$tmpdir/gw.log" 2>/dev/null | head -n 60 || true
  } >>"$evid/fractal_gateway_correlation.txt"
  [[ -n "$scope" ]] || fail "fractal missing route_scope_id"
  if grep -qiE 'rejected V1|V1 transmit queue is backpressured' "$tmpdir/gw.log" 2>/dev/null; then
    # Not necessarily fatal if later succeeded; record for audit.
    echo "gateway_v1_warn=present" >>"$report"
  fi
  echo "gateway_dataplane_forward=ATTEMPTED_via_gw_port=$gw_port" >>"$report"
  echo "fractal_correlation=route_journal+scope=$scope+typed_via_gateway" >>"$report"
fi

{
  echo "=== remote_mem / fence / dirty snippets ==="
  grep -E 'dirty|fence|MEM_READ|MEM_WRITE|version|page.fault|remote' \
    "$agent_log" "$tmpdir/ctl.log" 2>/dev/null | head -n 40 || true
} >>"$evid/remote_mem_snippets.txt"

{
  echo "dispatch_path=typed_WVM1_ingress$([ "$via_gateway" = 1 ] && echo _via_gateway || true)"
  echo "probe_class=production_typed_short_exec"
  echo "production_typed_dispatch=FIXED"
  echo "gateway_dataplane_forward=$([ "$via_gateway" = 1 ] && echo VIA_GW_DATA_PORT || echo N_A_FLAT)"
  echo "not=direct_executor_udp"
  echo "not=PASS_COMPONENT_SMOKE"
  echo "guest_ssh=§7_not_claimed"
  echo "note=live CREATE short-exec via production typed handoff; EXIT to sidecar; SHM guest store proves exec"
} >>"$report"
echo "dataplane_probe=PASS_PRODUCTION_TYPED" >>"$report"
echo "s6 dataplane probe PASS_PRODUCTION_TYPED cell=$cell backend=$backend vm_id=$vm_id"
exit 0

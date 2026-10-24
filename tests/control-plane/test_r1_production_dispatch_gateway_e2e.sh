#!/usr/bin/env bash
# R1: live wavevm_gateway forwards typed V1 VCPU_RUN/EXIT (fractal scopes).
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evid="${WAVEVM_S6_R1_EVID:-}"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-r1-gw-dispatch.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

make -C "$repo_root/gateway_service" wavevm_gateway >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/ca.key" \
    -out "$tmpdir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj /CN=gateway:27:45 -keyout "$tmpdir/gateway.key" \
    -out "$tmpdir/gateway.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$tmpdir/gateway.csr" \
    -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" -CAcreateserial \
    -out "$tmpdir/gateway.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj /CN=node-runtime:71:72 -keyout "$tmpdir/controller.key" \
    -out "$tmpdir/controller.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$tmpdir/controller.csr" \
    -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" -CAcreateserial \
    -out "$tmpdir/controller.crt" >/dev/null 2>&1

gcc -Wall -Wextra -std=gnu11 -D_POSIX_C_SOURCE=200809L \
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
    "$repo_root/tests/control-plane/test_r1_production_dispatch_gateway_e2e.c" \
    -pthread -o "$tmpdir/test_r1_production_dispatch_gateway_e2e"

set +e
"$tmpdir/test_r1_production_dispatch_gateway_e2e" \
    "$repo_root/gateway_service/wavevm_gateway" "$tmpdir/ca.crt" \
    "$tmpdir/gateway.crt" "$tmpdir/gateway.key" \
    "$tmpdir/controller.crt" "$tmpdir/controller.key" \
    | tee "$tmpdir/stdout.txt"
rc=${PIPESTATUS[0]}
set -e

if [[ -n "$evid" ]]; then
  mkdir -p "$evid"
  cp "$tmpdir/stdout.txt" "$evid/r1_production_dispatch_stdout.txt" 2>/dev/null || true
  if [[ $rc -eq 0 ]]; then
    {
      echo "R1_PRODUCTION_DISPATCH=FIXED"
      echo "path=admitted_fractal_snapshot->WVM1_VCPU_RUN->gateway_forward->executor->WVM1_VCPU_EXIT"
      echo "topology=FRACTAL"
      echo "not=direct_Hybrid_UDP_VCPU_RUN"
      echo "not=PASS_COMPONENT_SMOKE_short_exec"
      echo "guest_ssh=§7_not_claimed"
      date -Iseconds
    } >"$evid/R1_PRODUCTION_DISPATCH.txt"
  else
    {
      echo "R1_PRODUCTION_DISPATCH=PARTIAL"
      echo "rc=$rc"
      date -Iseconds
    } >"$evid/R1_PRODUCTION_DISPATCH.txt"
  fi
fi
exit "$rc"

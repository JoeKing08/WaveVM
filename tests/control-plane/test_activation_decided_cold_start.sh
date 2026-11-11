#!/usr/bin/env bash
# Live ACTIVATION_DECIDED cold-start: persist → process exit → reopen → recover.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-activation-cold.XXXXXX")
persist_dir="$repo_root/audit-evidence/fix-blockers-20261111/ACTIVATION_DECIDED-cold-start"
mkdir -p "$persist_dir"
trap 'rm -rf "$tmpdir"' EXIT

journal="$tmpdir/control.journal"
cc=${CC:-gcc}
read -r -a extra_flags <<< "${CFLAGS:-}"

echo "ACTIVATION: building cold-start helper"
"$cc" -Wall -Wextra -Werror -Wno-unused-function -std=c11 -D_POSIX_C_SOURCE=200809L "${extra_flags[@]}" \
    -I"$repo_root/common_include" -I"$repo_root/tests/control-plane" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_capability.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_admission.c" \
    "$repo_root/common_include/wavevm_cluster.c" \
    "$repo_root/common_include/wavevm_reservation_runtime.c" \
    "$repo_root/common_include/wavevm_admission_stage.c" \
    "$repo_root/common_include/wavevm_admission_receiver.c" \
    "$repo_root/common_include/wavevm_runtime_gate.c" \
    "$repo_root/common_include/wavevm_route_runtime.c" \
    "$repo_root/common_include/wavevm_route_control.c" \
    "$repo_root/common_include/wavevm_route_delivery.c" \
    "$repo_root/common_include/wavevm_runtime_dispatch.c" \
    "$repo_root/common_include/wavevm_runtime_delivery.c" \
    "$repo_root/common_include/wavevm_fault_engine.c" \
    "$repo_root/common_include/wavevm_admission_orchestrator.c" \
    "$repo_root/common_include/wavevm_admission_recovery.c" \
    "$repo_root/common_include/wavevm_coordinator.c" \
    "$repo_root/common_include/wavevm_membership_coordinator.c" \
    "$repo_root/common_include/wavevm_control_plane.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/common_include/wavevm_membership_control.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/ctl_tool/admission_workspace.c" \
    "$repo_root/common_include/wavevm_admission_transport.c" \
    "$repo_root/ctl_tool/admission_readiness.c" \
    "$repo_root/tests/control-plane/test_activation_decided_cold_start.c" \
    -pthread -Wl,--wrap=fsync -Wl,--wrap=write \
    -o "$tmpdir/test_activation_decided_cold_start"

echo "ACTIVATION: persist process"
set +e
"$tmpdir/test_activation_decided_cold_start" persist "$journal" \
    >"$tmpdir/persist.stdout" 2>"$tmpdir/persist.stderr"
persist_rc=$?
set -e
cp -f "$tmpdir/persist.stdout" "$tmpdir/persist.stderr" "$persist_dir/" 2>/dev/null || true
[[ -f "$journal" ]] && cp -f "$journal" "$persist_dir/control.journal" || true

echo "======= persist stdout ======="
cat "$tmpdir/persist.stdout" || true
echo "======= persist stderr ======="
cat "$tmpdir/persist.stderr" || true

if [[ "$persist_rc" -ne 0 ]]; then
    echo "ACTIVATION persist FAIL rc=$persist_rc" >&2
    exit 1
fi
if ! grep -q 'EVID ACTIVATION_DECIDED_persist:' "$tmpdir/persist.stdout"; then
    echo "missing persist evidence" >&2
    exit 1
fi
if [[ ! -s "$journal" ]]; then
    echo "journal was not persisted" >&2
    exit 1
fi

echo "ACTIVATION: recover process (new address space)"
set +e
"$tmpdir/test_activation_decided_cold_start" recover "$journal" \
    >"$tmpdir/recover.stdout" 2>"$tmpdir/recover.stderr"
recover_rc=$?
set -e
cp -f "$tmpdir/recover.stdout" "$tmpdir/recover.stderr" "$persist_dir/" 2>/dev/null || true

echo "======= recover stdout ======="
cat "$tmpdir/recover.stdout" || true
echo "======= recover stderr ======="
cat "$tmpdir/recover.stderr" || true

if ! grep -q 'EVID ACTIVATION_DECIDED_cold_open:' "$tmpdir/recover.stdout"; then
    echo "missing cold-open evidence" >&2
    exit 1
fi

# 0 = replay forwarded to COMMITTED/RUNNING
# 2 = journal survived and recover ran, but did not forward (fail-closed or still DECIDED)
# other = hard fail
if [[ "$recover_rc" -eq 0 ]] && grep -q 'EVID ACTIVATION_DECIDED_replay: forwarded=1' "$tmpdir/recover.stdout"; then
    echo "test_activation_decided_cold_start: PASS"
    exit 0
fi
if [[ "$recover_rc" -eq 2 ]]; then
    echo "test_activation_decided_cold_start: PARTIAL (cold-open yes; replay not forwarded)"
    exit 2
fi
echo "ACTIVATION recover FAIL rc=$recover_rc" >&2
exit 1

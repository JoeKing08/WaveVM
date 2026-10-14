#!/usr/bin/env bash
# Same-host dual node_instance vertical (roadmap Phase 7 / membership §3.1).
# Two compute NodeRecords share physical_host_id with distinct
# node_instance_namespace + listener ports; REGISTER→enroll→ACTIVE both;
# host aggregate forbids double-count; bad second register fail-closed.
# Does NOT invent HA/MIGRATE; does not lift Mode A §12 gate; does not claim
# live dual wavevm_node_runtime process E2E (agent CLI --physical-host-id ready).
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-same-host-dual.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_membership.c" \
    "$repo_root/common_include/wavevm_capability.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_admission.c" \
    "$repo_root/common_include/wavevm_cluster.c" \
    "$repo_root/common_include/wavevm_reservation_runtime.c" \
    "$repo_root/common_include/wavevm_fault_engine.c" \
    "$repo_root/common_include/wavevm_coordinator.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/common_include/wavevm_membership_coordinator.c" \
    "$repo_root/tests/control-plane/test_same_host_dual_agent.c" \
    -pthread -o "$tmpdir/test_same_host_dual_agent"
"$tmpdir/test_same_host_dual_agent"

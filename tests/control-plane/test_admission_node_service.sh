#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-admission-node-service.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
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
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_control.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/common_include/wavevm_control_transport.c" \
    "$repo_root/common_include/wavevm_control_owner.c" \
    "$repo_root/common_include/wavevm_admission_node_service.c" \
    "$repo_root/tests/control-plane/test_admission_node_service.c" \
    -pthread -o "$tmpdir/test_admission_node_service"
"$tmpdir/test_admission_node_service"

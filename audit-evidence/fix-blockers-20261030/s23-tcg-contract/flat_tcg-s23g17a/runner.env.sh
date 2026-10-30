#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/WaveVM
export WVM_GUEST_TOPOLOGY=flat
export WVM_S6_BACKEND=require-tcg
export WVM_S6_ACCEL=disabled
export WVM_CREATE_VCPUS=2
export WVM_CREATE_MEMORY_BYTES=$((256 * 1024 * 1024))
export WVM_GUEST_SSH_PORT=2226
export WVM_GUEST_BOOT_TIMEOUT_S=900
export WVM_GUEST_SSH_TIMEOUT_S=300
export WVM_GUEST_CPU_SMOKE_TIMEOUT_S=90
export WVM_GUEST_REQUIRE_STOP=1
export WVM_GUEST_SMOKE_ART=audit-evidence/fix-blockers-20261030/s23-tcg-contract/flat_tcg-s23g17a
export WVM_S6_QEMU_BIN=/workspaces/WaveVM/wavevm-qemu/build/qemu-system-x86_64
{
  date
  echo "run=flat_tcg-s23g17a B6: stuck-only renew + no mid-hold extend + cooldown only on hard_cap"
  bash tests/e2e/test_guest_smoke.sh
  echo "smoke_exit=$?"
} 2>&1 | tee "$WVM_GUEST_SMOKE_ART/runner.log"

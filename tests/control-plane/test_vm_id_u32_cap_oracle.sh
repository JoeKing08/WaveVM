#!/usr/bin/env bash
# SPEC-canonical-vm-id-u32-cap + BASE-§16-vm-id-u32-quarantine live oracle driver.
# Runs identity U32 allocate/quarantine + coordinator >255 CAP reject evidence.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
echo "=== vm_id u32 cap / quarantine live oracle ==="
echo "1) identity: V1 allocate>=256, incomplete-ACK reject, quarantine, release, restore range"
bash "$repo_root/tests/control-plane/test_identity.sh"
echo "2) coordinator: begin allocates vm_id>=256; prepare rejects missing WVM_CAP_VM_ID_U32"
bash "$repo_root/tests/control-plane/test_coordinator.sh"
echo "vm_id u32 cap oracle: PASS"

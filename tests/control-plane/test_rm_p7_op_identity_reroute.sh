#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bash "$repo_root/tests/control-plane/test_rm_p7_op_identity_reroute_wire.sh"
bash "$repo_root/tests/control-plane/test_vcpu_coordinator.sh"
echo "rm-p7-op-identity-across-reroute: PASS (wire + completion-cache)"

#!/usr/bin/env bash
# R2 negative: REQUIRE_KVM must reject when KVM capability is UNAVAILABLE.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export WVM_S6_CAP_SOURCE=deny-kvm
export WVM_S6_BACKEND=require-kvm
export WVM_S6_ACCEL=disabled
export WVM_S6_EXPECT_REJECT=1
export WVM_S6_EXPECT_REJECT_REASON='no complete KVM dirty/resync capability set is published'
export WVM_S6_REQUIRE_STOP=${WVM_S6_REQUIRE_STOP:-1}
export WVM_S6_REAL_QEMU=${WVM_S6_REAL_QEMU:-0}
export WVM_S6_DATAPLANE=0
bash "$repo_root/tests/control-plane/test_create_vm_single_node.sh"

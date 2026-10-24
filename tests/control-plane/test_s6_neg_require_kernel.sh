#!/usr/bin/env bash
# R2 negative: REQUIRE_KERNEL must reject when kernel-accel capability is UNAVAILABLE.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export WVM_S6_CAP_SOURCE=deny-kernel
export WVM_S6_BACKEND=require-tcg
export WVM_S6_ACCEL=require-kernel
export WVM_S6_EXPECT_REJECT=1
export WVM_S6_EXPECT_REJECT_REASON='required kernel acceleration is unavailable on a member'
export WVM_S6_REQUIRE_STOP=${WVM_S6_REQUIRE_STOP:-1}
export WVM_S6_REAL_QEMU=${WVM_S6_REAL_QEMU:-0}
export WVM_S6_DATAPLANE=0
bash "$repo_root/tests/control-plane/test_create_vm_single_node.sh"

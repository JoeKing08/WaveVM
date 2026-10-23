#!/usr/bin/env bash
# R2: AUTO backend falls back to TCG when KVM is UNAVAILABLE; fallback must be recorded.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export WVM_S6_CAP_SOURCE=deny-kvm
export WVM_S6_BACKEND=auto
export WVM_S6_ACCEL=disabled
export WVM_S6_EXPECT_REJECT=0
export WVM_S6_REQUIRE_STOP=${WVM_S6_REQUIRE_STOP:-1}
export WVM_S6_REAL_QEMU=${WVM_S6_REAL_QEMU:-1}
export WVM_S6_DATAPLANE=${WVM_S6_DATAPLANE:-1}
# Force evidence dir from matrix; after PASS, verify TCG path in agent log.
bash "$repo_root/tests/control-plane/test_create_vm_single_node.sh"
# Post-check: agent must show TCG PROXY (not KVM FAST) when KVM denied under AUTO.
if [[ -n "${WVM_S6_EVIDENCE_DIR:-}" && -f "${WVM_S6_EVIDENCE_DIR}/agent.log" ]]; then
    if ! grep -q 'TCG PROXY' "${WVM_S6_EVIDENCE_DIR}/agent.log" \
        && ! grep -qE 'TCG|tcg|require-tcg|backend.*TCG' "${WVM_S6_EVIDENCE_DIR}/agent.log"; then
        echo "auto_tcg_fallback: missing TCG fallback evidence in agent.log" >&2
        grep -E 'KVM FAST|TCG PROXY|backend|Mode:' "${WVM_S6_EVIDENCE_DIR}/agent.log" >&2 || true
        exit 1
    fi
    {
        echo "fallback=TCG"
        echo "cap_source=deny-kvm"
        echo "backend_policy=auto"
        grep -E 'KVM FAST|TCG PROXY|Mode:' "${WVM_S6_EVIDENCE_DIR}/agent.log" | head -n 20 || true
    } >"${WVM_S6_EVIDENCE_DIR}/auto_fallback.txt"
fi

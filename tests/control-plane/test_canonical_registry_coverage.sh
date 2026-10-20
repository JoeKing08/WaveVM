#!/usr/bin/env bash
# SPEC-canonical-registry — coverage + dual-impl digest conformance gate.
# A15: do NOT invent "52/52 COMPLETE". Report honest dual-pass count + scope.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

echo "=== Canonical registry coverage + dual-impl ==="
bash tests/control-plane/test_canonical_record.sh
dual_out=$(mktemp)
bash tests/control-plane/test_canonical_registry_dual_impl.sh | tee "$dual_out"

types=(1001 1002 1003 1004 1005 1006 1007 1008 1009 100a 100b 100c 100d 100e 100f 1010 1011 1012 1013 1014 1015 1016 1017 1018 1019 101a 101b 101c 101d 101e 101f 1020 1021 1022 1023 1024 1025 1026 1027 1028 1029 102a 102b 102c 102d 102e 102f 1030 1031 1032 1033 1034)
missing=()
for t in "${types[@]}"; do
  if ! grep -RIq --include='*.c' --include='*.h' "0x$t\|0x${t^^}" common_include/ tests/control-plane/; then
    missing+=("0x$t")
  fi
done
echo "Registry type IDs with no in-tree 0xNNNN literal reference:"
if ((${#missing[@]})); then
  printf '  %s\n' "${missing[@]}"
  rm -f "$dual_out"
  exit 1
else
  echo "  (none — every listed ID appears in sources/tests)"
fi

registry_n=${#types[@]}
# Prefer explicit dual-passed counter from the dual-impl binary output.
dual_n=$(grep -Eo 'dual-passed so far: [0-9]+' "$dual_out" | tail -1 | grep -Eo '[0-9]+$' || true)
if [[ -z "${dual_n:-}" ]]; then
  dual_n=$(grep -Eo 'PASS \([0-9]+ type duals' "$dual_out" | grep -Eo '[0-9]+' | head -1 || true)
fi
if [[ -z "${dual_n:-}" ]]; then
  dual_n=0
fi
rm -f "$dual_out"

echo
echo "A15 honest scope:"
echo "  - Literal presence gate: ${registry_n}/${registry_n} registry type IDs referenced in-tree"
echo "  - Dual-impl digest digests passed this run: ${dual_n}/${registry_n}"
echo "  - Schema §5 #1 full dual bytes+digests for EVERY type is NOT claimed unless dual_n==registry_n"
echo "  - Schema §5 #3 probes (duplicate-tag + self-digest zeroing): exercised by dual-impl suite"
if [[ "$dual_n" -eq "$registry_n" ]]; then
  echo "canonical-registry: dual-impl FULL (${dual_n}/${registry_n}) + literal presence + §5 #3 probes"
else
  echo "canonical-registry: PARTIAL dual-impl (${dual_n}/${registry_n}) + literal presence + §5 #3 probes"
  echo "(A15: refusing invented 52/52 COMPLETE wording)"
fi

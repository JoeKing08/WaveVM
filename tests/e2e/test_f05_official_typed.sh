#!/usr/bin/env bash
# Official typed f05 cell. Thin wrapper around test_a4_official_typed.sh
# so scripts/wavevm f05 stays on the same production entry:
#   wvm_ctl serve + wavevm_node_runtime agent + CREATE_VM
# Never starts wavevm_node_master / wavevm_node_slave and never sets
# WAVEVM_ALLOW_LEGACY_CLI. This wrapper does not close the cell.
set -euo pipefail
export WVM_OFFICIAL_CELL=f05
exec bash --noprofile --norc "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test_a4_official_typed.sh" "$@"

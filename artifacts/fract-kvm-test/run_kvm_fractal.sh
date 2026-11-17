#!/usr/bin/env bash
# Independent wavevm_node_master / wavevm_node_slave entry was removed.
# Official entry: scripts/wavevm
# Rollback: git checkout 1d729426a3167a9be14a5f9519582ac7c3bcbb0a -- this file
echo "[WaveVM] This historical runner is not official acceptance." >&2
echo "[WaveVM] Use: scripts/wavevm f05|f10|a4 --role node-a|node-b --route-topology flat|fractal" >&2
exit 78


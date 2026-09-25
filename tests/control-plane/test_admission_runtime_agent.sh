#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-admission-runtime-agent.XXXXXX")
agent_pid=
cleanup() {
    if [[ -n "$agent_pid" ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    rm -rf -- "$tmpdir"
}
trap cleanup EXIT

make -C "$repo_root/node_runtime" -j2 >/dev/null
mkdir "$tmpdir/runtime"
args=(agent
    --state-dir "$tmpdir"
    --runtime-dir "$tmpdir/runtime"
    --socket "$tmpdir/agent.sock"
    --node-id 801 --instance-id 802 --inventory-revision 1
    --vcpu-slots 2 --memory-bytes 1073741824
    --controller-node-id 701 --controller-instance-id 702
    --controller-uid "$(id -u)"
    --slots 2 --max-vcpus 2 --max-memory-chunks 2
    --max-storage 1 --max-members 2 --max-leases 1)

if "$repo_root/wavevm_node_runtime" agent --state-dir "$tmpdir" >/dev/null 2>&1; then
    echo "agent accepted incomplete configuration" >&2
    exit 1
fi
if "$repo_root/wavevm_node_runtime" child --parent-pid 1 \
    --manifest "$tmpdir/absent.manifest" --node-instance 802 >/dev/null 2>&1; then
    echo "child accepted an unrelated agent" >&2
    exit 1
fi

"$repo_root/wavevm_node_runtime" "${args[@]}" &
agent_pid=$!
for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -S "$tmpdir/agent.sock" ]]; then
        break
    fi
    kill -0 "$agent_pid"
    sleep 0.1
done
[[ -S "$tmpdir/agent.sock" && -f "$tmpdir/route.journal" &&
   -f "$tmpdir/reservation.journal" ]]
[[ $(stat -c %a "$tmpdir/agent.sock") == 600 ]]
bash "$repo_root/tests/control-plane/test_admission_node_service.sh" \
    --client "$tmpdir/agent.sock" 801 802
bash "$repo_root/tests/control-plane/test_admission_node_service.sh" \
    --route-client "$tmpdir/agent.sock" 801 802
kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=
[[ ! -e "$tmpdir/agent.sock" ]]

"$repo_root/wavevm_node_runtime" "${args[@]}" &
agent_pid=$!
for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -S "$tmpdir/agent.sock" ]]; then
        break
    fi
    kill -0 "$agent_pid"
    sleep 0.1
done
[[ -S "$tmpdir/agent.sock" ]]
bash "$repo_root/tests/control-plane/test_admission_node_service.sh" \
    --route-client "$tmpdir/agent.sock" 801 802
kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=
[[ ! -e "$tmpdir/agent.sock" ]]

unauthorized_args=("${args[@]}")
for ((index = 0; index < ${#unauthorized_args[@]}; index++)); do
    if [[ ${unauthorized_args[index]} == --controller-uid ]]; then
        unauthorized_args[index + 1]=$(( $(id -u) + 1 ))
        break
    fi
done
"$repo_root/wavevm_node_runtime" "${unauthorized_args[@]}" &
agent_pid=$!
for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -S "$tmpdir/agent.sock" ]]; then
        break
    fi
    kill -0 "$agent_pid"
    sleep 0.1
done
bash "$repo_root/tests/control-plane/test_admission_node_service.sh" \
    --unauthorized-client "$tmpdir/agent.sock" 801 802
kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=
[[ ! -e "$tmpdir/agent.sock" ]]
echo "admission-runtime-agent lifecycle: PASS"

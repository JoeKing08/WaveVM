#!/usr/bin/env bash
set -euo pipefail

runtime="${WAVEVM_NODE_RUNTIME:-wavevm_node_runtime}"
manifest=""
node_instance=""
qemu=""

usage() {
    printf 'Usage: %s --manifest FILE --node-instance N --qemu PATH [-- QEMU_ARGS...]\n' \
        "$0" >&2
}

while (($# > 0)); do
    case "$1" in
        --runtime)
            (($# >= 2)) || { usage; exit 2; }
            runtime=$2
            shift 2
            ;;
        --manifest)
            (($# >= 2)) || { usage; exit 2; }
            manifest=$2
            shift 2
            ;;
        --node-instance)
            (($# >= 2)) || { usage; exit 2; }
            node_instance=$2
            shift 2
            ;;
        --qemu)
            (($# >= 2)) || { usage; exit 2; }
            qemu=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

if [[ -z "$manifest" || -z "$node_instance" || -z "$qemu" ]]; then
    usage
    exit 2
fi

# The runtime emits shell-quoted exports only after validating the manifest,
# route snapshot, dispatch projection, and local identity.
eval "$($runtime --manifest "$manifest" \
    --node-instance "$node_instance" --print-launch-env)"

: "${WVM_RUNTIME_SOCKET:?manifest projection did not provide QEMU socket}"
: "${WVM_RUNTIME_READY_FILE:?manifest projection did not provide readiness fence}"
: "${WVM_SHM_FILE:?manifest projection did not provide SHM name}"
: "${WVM_RUNTIME_MANIFEST_PATH:?manifest projection did not provide manifest}"

runtime_pid=""
qemu_pid=""

cleanup() {
    set +e
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ -n "$runtime_pid" ]] && kill -0 "$runtime_pid" 2>/dev/null; then
        kill "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
    fi
    rm -f "${WVM_RUNTIME_SOCKET:-}"
    rm -f "${WVM_RUNTIME_READY_FILE:-}"
    rm -f "${WVM_LOCAL_EXECUTOR_SOCKET:-}" \
        "${WVM_RUNTIME_WORKER_SOCKET:-}" "${WVM_RUNTIME_MONITOR_SOCKET:-}"
    if [[ "${WVM_SHM_FILE:-}" == /* &&
          "${WVM_SHM_FILE#/}" != */* ]]; then
        rm -f "/dev/shm/${WVM_SHM_FILE#/}"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$runtime" --manifest "$manifest" --node-instance "$node_instance" &
runtime_pid=$!

socket_ready=0
for _ in $(seq 1 200); do
    if [[ -S "$WVM_RUNTIME_SOCKET" ]]; then
        socket_ready=1
        break
    fi
    if ! kill -0 "$runtime_pid" 2>/dev/null; then
        printf 'node runtime exited before QEMU IPC became ready\n' >&2
        exit 1
    fi
    sleep 0.05
done
if ((socket_ready == 0)); then
    printf 'node runtime did not publish manifest-derived QEMU IPC socket\n' >&2
    exit 1
fi

"$qemu" "$@" &
qemu_pid=$!

ready=0
for _ in $(seq 1 200); do
    if [[ -f "$WVM_RUNTIME_READY_FILE" ]]; then
        ready=1
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        printf 'QEMU exited before manifest-bound runtime readiness\n' >&2
        exit 1
    fi
    if ! kill -0 "$runtime_pid" 2>/dev/null; then
        printf 'node runtime exited before manifest-bound runtime readiness\n' >&2
        exit 1
    fi
    sleep 0.05
done
if ((ready == 0)); then
    printf 'QEMU did not complete manifest-bound runtime registration\n' >&2
    exit 1
fi

wait "$qemu_pid"
status=$?
qemu_pid=""
exit "$status"

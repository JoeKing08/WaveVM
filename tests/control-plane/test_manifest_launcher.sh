#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-manifest-launcher.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

runtime="$tmpdir/runtime"
qemu="$tmpdir/qemu"
launcher="$repo_root/scripts/wavevm_manifest_qemu.sh"
pids=()

cleanup() {
    set +e
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$tmpdir"
}
trap cleanup EXIT

printf '%s\n' \
    '#!/usr/bin/env bash' \
    'manifest=""' \
    'print_env=0' \
    'while (($# > 0)); do' \
    '    if [[ "$1" == "--manifest" && $# -ge 2 ]]; then manifest=$2; shift 2' \
    '    elif [[ "$1" == "--print-launch-env" ]]; then print_env=1; shift' \
    '    else shift' \
    '    fi' \
    'done' \
    'suffix=${manifest##*/}' \
    'socket=/tmp/wvm-test-${suffix}.sock' \
    'ready=/tmp/wvm-test-${suffix}.ready' \
    'shm=/wavevm_ram_${suffix}' \
    'if ((print_env)); then' \
    '    printf "export WVM_RUNTIME_SOCKET=%q\\n" "$socket"' \
    '    printf "export WVM_RUNTIME_READY_FILE=%q\\n" "$ready"' \
    '    printf "export WVM_SHM_FILE=%q\\n" "$shm"' \
    '    printf "export WVM_RUNTIME_MANIFEST_PATH=%q\\n" "$manifest"' \
    '    exit 0' \
    'fi' \
    'rm -f "$socket" "$ready"' \
    'export WVM_RUNTIME_SOCKET="$socket" WVM_RUNTIME_READY_FILE="$ready" WVM_SHM_FILE="$shm"' \
    'touch "$WVM_RUNTIME_READY_FILE"' \
    'python3 - "$WVM_RUNTIME_SOCKET" <<"PY"' \
    'import socket, sys, time' \
    'path = sys.argv[1]' \
    'server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)' \
    'server.bind(path)' \
    'server.listen(1)' \
    'time.sleep(30)' \
    'PY' \
    >"$runtime"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf "%s\\n" "$WVM_RUNTIME_SOCKET" >"$QEMU_ENV_OUT"' \
    'printf "%s\\n" "$WVM_SHM_FILE" >>"$QEMU_ENV_OUT"' \
    'printf "%s\\n" "$@" >"$QEMU_ARGS_OUT"' \
    'touch "$WVM_RUNTIME_READY_FILE"' \
    'sleep 0.2' \
    >"$qemu"
chmod 700 "$runtime" "$qemu"

QEMU_ENV_OUT="$tmpdir/env" QEMU_ARGS_OUT="$tmpdir/args" \
    "$launcher" \
    --runtime "$runtime" --manifest "$tmpdir/manifest" \
    --node-instance 7 --qemu "$qemu" -- -machine pc-test -m 128

test "$(sed -n '1p' "$tmpdir/env")" = "/tmp/wvm-test-manifest.sock"
test "$(sed -n '2p' "$tmpdir/env")" = "/wavevm_ram_manifest"
test "$(sed -n '1p' "$tmpdir/args")" = "-machine"
test "$(sed -n '2p' "$tmpdir/args")" = "pc-test"
test "$(sed -n '3p' "$tmpdir/args")" = "-m"
test "$(sed -n '4p' "$tmpdir/args")" = "128"
test ! -e /tmp/wvm-test-manifest.sock
test ! -e /tmp/wvm-test-manifest.ready

manifest_a="$tmpdir/manifest-a"
manifest_b="$tmpdir/manifest-b"
QEMU_ENV_OUT="$tmpdir/env-a" QEMU_ARGS_OUT="$tmpdir/args-a" \
    "$launcher" --runtime "$runtime" --manifest "$manifest_a" \
    --node-instance 7 --qemu "$qemu" -- -machine pc-a &
pids+=("$!")
QEMU_ENV_OUT="$tmpdir/env-b" QEMU_ARGS_OUT="$tmpdir/args-b" \
    "$launcher" --runtime "$runtime" --manifest "$manifest_b" \
    --node-instance 8 --qemu "$qemu" -- -machine pc-b &
pids+=("$!")
wait "${pids[0]}"
wait "${pids[1]}"
pids=()

test "$(sed -n '1p' "$tmpdir/env-a")" = "/tmp/wvm-test-manifest-a.sock"
test "$(sed -n '1p' "$tmpdir/env-b")" = "/tmp/wvm-test-manifest-b.sock"
test "$(sed -n '1p' "$tmpdir/args-a")" = "-machine"
test "$(sed -n '2p' "$tmpdir/args-a")" = "pc-a"
test "$(sed -n '1p' "$tmpdir/args-b")" = "-machine"
test "$(sed -n '2p' "$tmpdir/args-b")" = "pc-b"
test ! -e /tmp/wvm-test-manifest-a.sock
test ! -e /tmp/wvm-test-manifest-b.sock
test ! -e /tmp/wvm-test-manifest-a.ready
test ! -e /tmp/wvm-test-manifest-b.ready

printf 'manifest-launcher tests: PASS\n'

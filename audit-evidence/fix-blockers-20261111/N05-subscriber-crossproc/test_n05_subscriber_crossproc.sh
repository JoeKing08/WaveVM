#!/usr/bin/env bash
# N05 true oracle: ctl bridge -> 0x0307 -> directory global invalidate / STALE.
# Two processes, two link sets (ctl does not link memory_service).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-n05-crossproc.XXXXXX")
trap 'if [[ -n "${dir_pid:-}" ]]; then kill -TERM "$dir_pid" 2>/dev/null || true; wait "$dir_pid" 2>/dev/null || true; fi; rm -rf "$tmpdir"' EXIT

export N05_SOCK="$tmpdir/dir.sock"
export N05_READY="$tmpdir/ready"
export N05_EVID="$tmpdir/evid"
export N05_JOURNAL="$tmpdir/membership.journal"
: >"$N05_JOURNAL"

cc=${CC:-gcc}
common_objs=(
    "$repo_root/common_include/wavevm_sha256.c"
    "$repo_root/common_include/wavevm_canonical.c"
    "$repo_root/common_include/wavevm_identity.c"
    "$repo_root/common_include/wavevm_manifest.c"
    "$repo_root/common_include/wavevm_control.c"
    "$repo_root/common_include/wavevm_lifecycle.c"
    "$repo_root/common_include/wavevm_envelope.c"
    "$repo_root/common_include/wavevm_memory.c"
    "$repo_root/common_include/wavevm_runtime_dispatch.c"
    "$repo_root/common_include/wavevm_route_runtime.c"
)

echo "N05: building directory runtime (links memory_service, no ctl bridge)"
"$cc" -Wall -Wextra -Werror -std=c11 -D_DEFAULT_SOURCE \
    -I"$repo_root/common_include" -I"$repo_root/node_runtime" \
    -I"$repo_root/tests/control-plane" \
    "${common_objs[@]}" \
    "$repo_root/node_runtime/directory_store.c" \
    "$repo_root/node_runtime/memory_service.c" \
    "$repo_root/node_runtime/kernel_memory.c" \
    "$repo_root/tests/control-plane/test_n05_subscriber_crossproc_dir.c" \
    -pthread -o "$tmpdir/test_n05_directory"

echo "N05: building ctl (links subscriber_invalidate_bridge, no memory_service)"
"$cc" -Wall -Wextra -Werror -std=c11 -D_DEFAULT_SOURCE \
    -I"$repo_root/common_include" -I"$repo_root/tests/control-plane" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_membership.c" \
    "$repo_root/common_include/wavevm_capability.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_admission.c" \
    "$repo_root/common_include/wavevm_cluster.c" \
    "$repo_root/common_include/wavevm_reservation_runtime.c" \
    "$repo_root/common_include/wavevm_fault_engine.c" \
    "$repo_root/common_include/wavevm_coordinator.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/common_include/wavevm_membership_coordinator.c" \
    "$repo_root/ctl_tool/subscriber_invalidate_bridge.c" \
    "$repo_root/tests/control-plane/test_n05_subscriber_crossproc_ctl.c" \
    -pthread -o "$tmpdir/test_n05_ctl"

# Confirm the two hook definitions did not end up in the same binary.
if nm -g "$tmpdir/test_n05_ctl" | grep -q ' T wvm_memory_service_global_invalidate_subscriber_instance'; then
    echo "ctl unexpectedly links memory_service global invalidate" >&2
    exit 1
fi
if ! nm -g "$tmpdir/test_n05_ctl" | grep -q ' T wvm_memory_service_membership_failure_invalidate_hook'; then
    echo "ctl missing strong N05 bridge hook" >&2
    exit 1
fi
if ! nm -g "$tmpdir/test_n05_directory" | grep -q ' T wvm_memory_service_global_invalidate_subscriber_instance'; then
    echo "directory missing global invalidate" >&2
    exit 1
fi

echo "N05: starting directory pid-to-be on $N05_SOCK"
"$tmpdir/test_n05_directory" >"$tmpdir/dir.stdout" 2>"$tmpdir/dir.stderr" &
dir_pid=$!

ready=0
for _ in $(seq 1 50); do
    if [[ -f "$N05_READY" ]]; then
        ready=1
        break
    fi
    if ! kill -0 "$dir_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    echo "directory did not become ready" >&2
    echo '======= directory stdout =======' >&2
    cat "$tmpdir/dir.stdout" >&2 || true
    echo '======= directory stderr =======' >&2
    cat "$tmpdir/dir.stderr" >&2 || true
    exit 1
fi

echo "N05: directory ready pid=$dir_pid; running ctl"
set +e
"$tmpdir/test_n05_ctl" >"$tmpdir/ctl.stdout" 2>"$tmpdir/ctl.stderr"
ctl_rc=$?
wait "$dir_pid"
dir_rc=$?
set -e
dir_pid=""

# Keep a copy for evidence even if later asserts fail.
persist="$repo_root/audit-evidence/fix-blockers-20261111/N05-subscriber-crossproc"
mkdir -p "$persist"
cp -f "$tmpdir/dir.stdout" "$tmpdir/dir.stderr" "$tmpdir/ctl.stdout" "$tmpdir/ctl.stderr" "$persist/" 2>/dev/null || true
[[ -f "$N05_EVID" ]] && cp -f "$N05_EVID" "$persist/evid.txt" || true

echo "======= directory stdout ======="
cat "$tmpdir/dir.stdout" || true
echo "======= directory stderr ======="
cat "$tmpdir/dir.stderr" || true
echo "======= ctl stdout ======="
cat "$tmpdir/ctl.stdout" || true
echo "======= ctl stderr ======="
cat "$tmpdir/ctl.stderr" || true
echo "======= evid ======="
cat "$N05_EVID" || true

if [[ "$ctl_rc" -ne 0 || "$dir_rc" -ne 0 ]]; then
    echo "N05 cross-proc oracle FAIL ctl_rc=$ctl_rc dir_rc=$dir_rc" >&2
    exit 1
fi
if ! grep -q 'EVID N05_ACTIVE_to_STALE=1' "$N05_EVID"; then
    echo "missing ACTIVE_to_STALE evidence" >&2
    exit 1
fi
if ! grep -q 'EVID N05_directory_recv: opcode=0x0307' "$N05_EVID"; then
    echo "missing 0x0307 receive evidence" >&2
    exit 1
fi
if ! grep -q 'EVID N05_bridge_fanout: sent=1' "$tmpdir/ctl.stdout"; then
    echo "missing bridge fanout sent=1 evidence" >&2
    exit 1
fi
if ! grep -q 'test_n05_ctl: PASS' "$tmpdir/ctl.stdout"; then
    echo "ctl did not PASS" >&2
    exit 1
fi
echo "test_n05_subscriber_crossproc: PASS"

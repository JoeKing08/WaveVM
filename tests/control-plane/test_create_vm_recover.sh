#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-recover.XXXXXX")
ctl_pid=
agent_pid=

cleanup() {
    if [[ -n "${agent_pid:-}" ]]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
    fi
    if [[ -n "${ctl_pid:-}" ]]; then
        kill -TERM "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
    fi
    rm -rf -- "$tmpdir"
    if [[ -n "${tmpdir_b:-}" ]]; then
        rm -rf -- "$tmpdir_b"
    fi
    if [[ -n "${tmpdir_c:-}" ]]; then
        rm -rf -- "$tmpdir_c"
    fi
    if [[ -n "${tmpdir_d:-}" ]]; then
        rm -rf -- "$tmpdir_d"
    fi
}
trap cleanup EXIT

export PATH="${HOME}/.local/bin:/home/box/.local/bin:${PATH}"
make -C "$repo_root/ctl_tool" -B -j2 >/dev/null
make -C "$repo_root/node_runtime" -j2 >/dev/null
gcc -Wall -Wextra -Werror -std=c11 \
    "$repo_root/tests/control-plane/tcg_helper_stub.c" \
    -o "$tmpdir/tcg_helper_stub"
export WVM_TCG_QEMU_BIN="$tmpdir/tcg_helper_stub"

common_objs=(
    "$repo_root/common_include/wavevm_sha256.c"
    "$repo_root/common_include/wavevm_canonical.c"
    "$repo_root/common_include/wavevm_identity.c"
    "$repo_root/common_include/wavevm_runtime_names.c"
    "$repo_root/common_include/wavevm_manifest.c"
    "$repo_root/common_include/wavevm_control.c"
    "$repo_root/common_include/wavevm_capability.c"
    "$repo_root/common_include/wavevm_lifecycle.c"
    "$repo_root/common_include/wavevm_admission.c"
    "$repo_root/common_include/wavevm_cluster.c"
    "$repo_root/common_include/wavevm_reservation_runtime.c"
    "$repo_root/common_include/wavevm_fault_engine.c"
    "$repo_root/common_include/wavevm_coordinator.c"
    "$repo_root/common_include/wavevm_envelope.c"
    "$repo_root/common_include/wavevm_membership_controller.c"
    "$repo_root/common_include/wavevm_membership_control.c"
    "$repo_root/common_include/wavevm_control_transport.c"
    "$repo_root/common_include/wavevm_runtime_profile.c"
    "$repo_root/common_include/wavevm_host_probe.c"
)

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${common_objs[@]}" \
    "$repo_root/tests/control-plane/seed_create_vm_evidence.c" \
    -pthread -o "$tmpdir/seed_evidence"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${common_objs[@]}" \
    "$repo_root/tests/control-plane/submit_create_vm.c" \
    -pthread -o "$tmpdir/submit_create_vm"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/check_agent_registration.c" \
    -pthread -o "$tmpdir/check_registration"

gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/read_membership_fence.c" \
    -pthread -o "$tmpdir/read_membership_fence"

# Assert CREATE_VM / recover left durable membership dependencies (compute and/or
# gateway). Mid-flight recover republishes via dependency_acquire; RUNNING relies
# on membership journal DEPENDENCY replay — both must leave deps visible offline.
assert_membership_deps() {
    local journal=$1
    local label=$2
    local snap fence total
    snap=$(mktemp "${TMPDIR:-/tmp}/wavevm-deps-snap.XXXXXX")
    cp -f "$journal" "$snap"
    fence=$("$tmpdir/read_membership_fence" "$snap" || true)
    rm -f "$snap"
    total=$(echo "$fence" | sed -n 's/.* deps=\([0-9]*\).*/\1/p' | awk '{s+=$1} END {print s+0}')
    if [[ "$total" -lt 1 ]]; then
        echo "$label: expected durable membership dependency_count >= 1 (got:)" >&2
        echo "$fence" >&2
        return 1
    fi
    echo "$label: membership deps ok (sum=$total)"
}

base_port=$(shuf -i 22000-50000 -n 1)
ctl_port=$base_port
agent_control_port=$((base_port + 1))
agent_data_port=$((base_port + 2))
sidecar_data_port=$((base_port + 3))
sidecar_control_port=$((base_port + 4))
profile_data0=$((base_port + 5))
profile_data1=$((base_port + 6))
profile_svc0=$((base_port + 7))
profile_svc1=$((base_port + 8))

mkdir "$tmpdir/ctl-state" "$tmpdir/node-state" "$tmpdir/runtime" "$tmpdir/evidence"

digest=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    "$profile_data0" "$profile_data1" "$profile_svc0" "$profile_svc1" \
    "$agent_control_port")
[[ ${#digest} -eq 64 ]]

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/ca.key" \
    -out "$tmpdir/ca.crt" >/dev/null 2>&1

make_cert() {
    local name=$1
    local common_name=$2

    openssl req -newkey rsa:2048 -nodes -subj "/CN=$common_name" \
        -keyout "$tmpdir/$name.key" -out "$tmpdir/$name.csr" \
        >/dev/null 2>&1
    openssl x509 -req -days 1 -in "$tmpdir/$name.csr" \
        -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" \
        -CAcreateserial -out "$tmpdir/$name.crt" >/dev/null 2>&1
}

make_cert controller node-runtime:701:702
make_cert node node-runtime:801:802
# Unix CREATE_VM client authenticates as executor; TLS carries node/controller.
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir/principals"

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir/ctl-state" \
    --socket "$tmpdir/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir/principals" --capacity 8 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir/ca.crt" \
    --control-cert "$tmpdir/controller.crt" \
    --control-key "$tmpdir/controller.key" \
    >"$tmpdir/ctl.log" 2>&1 &
ctl_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir/ctl.sock" ]]
kill -0 "$ctl_pid"

agent_args=(agent
    --state-dir "$tmpdir/node-state"
    --runtime-dir "$tmpdir/runtime"
    --socket "$tmpdir/node.sock"
    --node-id 801 --instance-id 802 --inventory-revision 1
    --vcpu-slots 2 --memory-bytes 1073741824
    --controller-node-id 701 --controller-instance-id 702
    --controller-uid "$(id -u)"
    --slots 2 --max-vcpus 2 --max-memory-chunks 2
    --max-storage 1 --max-members 8 --max-leases 2
    --control-address 127.0.0.1 --control-port "$agent_control_port"
    --data-port "$agent_data_port"
    --tls-ca "$tmpdir/ca.crt" --tls-cert "$tmpdir/node.crt"
    --tls-key "$tmpdir/node.key"
    --register-controller-address 127.0.0.1
    --register-controller-port "$ctl_port"
    --failure-domain-id 1 --pod-id 1 --vnode-first 1 --vnode-count 16
    --sidecar-address 127.0.0.1 --sidecar-data-port "$sidecar_data_port"
    --sidecar-control-port "$sidecar_control_port" --role-bits 1
    --capability-profile-generation 1
    --capability-profile-digest "$digest"
    --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222
    --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333
    --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444)

# Durable evidence must exist before compute enrollment reaches ACTIVE.
cp "$tmpdir/evidence/capabilities-801.record" "$tmpdir/ctl-state/"
cp "$tmpdir/evidence/runtime-profile-801.record" "$tmpdir/ctl-state/"

env WVM_TCG_QEMU_BIN="$tmpdir/tcg_helper_stub"     "$repo_root/wavevm_node_runtime" "${agent_args[@]}" >"$tmpdir/agent.log" 2>&1 &
agent_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir/node.sock" ]] && kill -0 "$agent_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir/node.sock" ]]
kill -0 "$agent_pid"

# Wait for durable registration+enrollment journals without opening them under the
# live ctl writer (check_registration recovers offline after CREATE).
for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ -s "$tmpdir/ctl-state/membership.journal" ]] &&
       [[ -s "$tmpdir/ctl-state/membership-control.journal" ]] &&
       [[ $(stat -c %s "$tmpdir/ctl-state/membership-control.journal") -gt 64 ]]; then
        break
    fi
    sleep 0.05
done
[[ -s "$tmpdir/ctl-state/membership.journal" ]]
[[ -s "$tmpdir/ctl-state/membership-control.journal" ]]
# Poll until compute membership is ACTIVE (enrollment may retry after
# REGISTER/control-stream race). Fixed 0.5s was timing-sensitive.
# check_registration opens the journal offline — only safe once ctl is idle
# enough; copy snap to avoid racing the live writer when possible.
active_ok=0
for ((attempt = 0; attempt < 200; attempt++)); do
    cp -f "$tmpdir/ctl-state/membership.journal" "$tmpdir/membership.journal.snap" 2>/dev/null || true
    if "$tmpdir/check_registration" "$tmpdir/membership.journal.snap"         "$agent_control_port" >/dev/null 2>&1; then
        active_ok=1
        break
    fi
    sleep 0.05
done
if [[ "$active_ok" -ne 1 ]]; then
    echo "compute member did not reach ACTIVE before CREATE_VM" >&2
    mkdir -p /tmp/wavevm-enroll-diag
    cp -a "$tmpdir/ctl.log" "$tmpdir/agent.log" "$tmpdir/ctl-state" /tmp/wavevm-enroll-diag/ 2>/dev/null || true
    echo "diag copied to /tmp/wavevm-enroll-diag (tmpdir=$tmpdir)" >&2
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    tail -n 80 "$tmpdir/agent.log" >&2 || true
    exit 1
fi
if ! kill -0 "$agent_pid" 2>/dev/null || ! kill -0 "$ctl_pid" 2>/dev/null; then
    echo "ctl or agent exited before CREATE_VM" >&2
    tail -n 80 "$tmpdir/ctl.log" >&2 || true
    tail -n 80 "$tmpdir/agent.log" >&2 || true
    exit 1
fi

# Replay CREATE_VM until live ready promotes COMMITTED→RUNNING, or timeout.
create_out=""
for ((attempt = 0; attempt < 80; attempt++)); do
    create_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" || true)
    echo "attempt=$attempt $create_out"
    if [[ "$create_out" == status=0* ]]; then
        break
    fi
    if [[ "$create_out" != status=14* ]]; then
        break
    fi
    sleep 0.25
done
echo "$create_out"
# Honest RUNNING: SUCCESS(0). IN_PROGRESS(14) means COMMITTED without live ready.
if [[ "$create_out" != status=0* ]]; then
    echo "CREATE_VM did not reach SUCCESS(0)/RUNNING (got: $create_out)" >&2
    echo "--- ctl.log ---" >&2
    cat "$tmpdir/ctl.log" >&2 || true
    echo "--- agent.log ---" >&2
    cat "$tmpdir/agent.log" >&2 || true
    echo "--- child runtime logs ---" >&2
    find "$tmpdir/runtime" -type f \( -name '*.log' -o -name 'stderr*' -o -name 'stdout*' \) \
        -print -exec cat {} \; >&2 2>/dev/null || true
    # Stop ctl to allow offline ACTIVE check for diagnosis.
    kill -TERM "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
    agent_pid=
    kill -TERM "$ctl_pid" 2>/dev/null || true
    wait "$ctl_pid" 2>/dev/null || true
    ctl_pid=
    if "$tmpdir/check_registration" "$tmpdir/ctl-state/membership.journal" \
        "$agent_control_port"; then
        echo "membership ACTIVE confirmed offline" >&2
    else
        echo "membership NOT ACTIVE offline" >&2
    fi
    exit 1
fi

# --- Step-5: kill coordinator, restart against same durable journals ---
kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir/ctl-state" \
    --socket "$tmpdir/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir/principals" --capacity 8 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir/ca.crt" \
    --control-cert "$tmpdir/controller.crt" \
    --control-key "$tmpdir/controller.key" \
    >"$tmpdir/ctl-restart.log" 2>&1 &
ctl_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
if ! kill -0 "$ctl_pid" 2>/dev/null || [[ ! -S "$tmpdir/ctl.sock" ]]; then
    echo "ctl failed to restart after durable reopen" >&2
    cat "$tmpdir/ctl-restart.log" >&2 || true
    exit 1
fi
if ! grep -q "mid-flight admission recovery scan complete" "$tmpdir/ctl-restart.log"; then
    echo "missing recovery scan log on ctl restart" >&2
    cat "$tmpdir/ctl-restart.log" >&2 || true
    exit 1
fi

# Replay same CREATE against restarted coordinator; agent still live.
replay_out=""
for ((attempt = 0; attempt < 80; attempt++)); do
    replay_out=$("$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" || true)
    echo "replay_attempt=$attempt $replay_out"
    if [[ "$replay_out" == status=0* ]]; then
        break
    fi
    if [[ "$replay_out" != status=14* ]]; then
        break
    fi
    sleep 0.25
done
if [[ "$replay_out" != status=0* ]]; then
    echo "CREATE_VM replay after ctl restart did not reach RUNNING (got: $replay_out)" >&2
    cat "$tmpdir/ctl-restart.log" >&2 || true
    cat "$tmpdir/agent.log" >&2 || true
    exit 1
fi

# Vertical evidence: RUNNING cold start keeps deps via membership journal replay
# (admission recover skips RUNNING; durable DEPENDENCY records must remain).
assert_membership_deps "$tmpdir/ctl-state/membership.journal" \
    "part A after RUNNING ctl restart"

echo "PASS part A: RUNNING→ctl restart→scan→replay RUNNING ($replay_out)"

# --- Part B: COMMITTED mid-flight recover (no live ready helper) ---
kill -TERM "$agent_pid"
wait "$agent_pid" || true
agent_pid=
kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=

tmpdir_b=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-recover-b.XXXXXX")
mkdir "$tmpdir_b/ctl-state" "$tmpdir_b/node-state" "$tmpdir_b/runtime" "$tmpdir_b/evidence"
digest_b=$("$tmpdir/seed_evidence" "$tmpdir_b/evidence" 801 802 1 1 \
    "$profile_data0" "$profile_data1" "$profile_svc0" "$profile_svc1" \
    "$agent_control_port")
[[ ${#digest_b} -eq 64 ]]
cp "$tmpdir/ca.crt" "$tmpdir/ca.key" "$tmpdir/controller.crt" "$tmpdir/controller.key" \
    "$tmpdir/node.crt" "$tmpdir/node.key" "$tmpdir/principals" "$tmpdir_b/" 2>/dev/null || true
# Re-issue node certs into tmpdir_b using same CA
cp "$tmpdir/ca.crt" "$tmpdir/ca.key" "$tmpdir_b/"
cp "$tmpdir/controller.crt" "$tmpdir/controller.key" "$tmpdir_b/"
cp "$tmpdir/node.crt" "$tmpdir/node.key" "$tmpdir_b/"
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir_b/principals"
cp "$tmpdir_b/evidence/capabilities-801.record" "$tmpdir_b/ctl-state/"
cp "$tmpdir_b/evidence/runtime-profile-801.record" "$tmpdir_b/ctl-state/"

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir_b/ctl-state" \
    --socket "$tmpdir_b/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir_b/principals" --capacity 8 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir_b/ca.crt" \
    --control-cert "$tmpdir_b/controller.crt" \
    --control-key "$tmpdir_b/controller.key" \
    >"$tmpdir_b/ctl.log" 2>&1 &
ctl_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir_b/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir_b/ctl.sock" ]]

agent_args_b=(agent
    --state-dir "$tmpdir_b/node-state"
    --runtime-dir "$tmpdir_b/runtime"
    --socket "$tmpdir_b/node.sock"
    --node-id 801 --instance-id 802 --inventory-revision 1
    --vcpu-slots 2 --memory-bytes 1073741824
    --controller-node-id 701 --controller-instance-id 702
    --controller-uid "$(id -u)"
    --slots 2 --max-vcpus 2 --max-memory-chunks 2
    --max-storage 1 --max-members 8 --max-leases 2
    --control-address 127.0.0.1 --control-port "$agent_control_port"
    --data-port "$agent_data_port"
    --tls-ca "$tmpdir_b/ca.crt" --tls-cert "$tmpdir_b/node.crt"
    --tls-key "$tmpdir_b/node.key"
    --register-controller-address 127.0.0.1
    --register-controller-port "$ctl_port"
    --failure-domain-id 1 --pod-id 1 --vnode-first 1 --vnode-count 16
    --sidecar-address 127.0.0.1 --sidecar-data-port "$sidecar_data_port"
    --sidecar-control-port "$sidecar_control_port" --role-bits 1
    --capability-profile-generation 1
    --capability-profile-digest "$digest_b"
    --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222
    --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333
    --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444)

# Missing helper keeps readiness closed → CREATE stays COMMITTED/IN_PROGRESS.
env WVM_TCG_QEMU_BIN="/nonexistent/wavevm-tcg-helper" \
    "$repo_root/wavevm_node_runtime" "${agent_args_b[@]}" >"$tmpdir_b/agent.log" 2>&1 &
agent_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir_b/node.sock" ]] && kill -0 "$agent_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir_b/node.sock" ]]

active_ok=0
for ((attempt = 0; attempt < 200; attempt++)); do
    cp -f "$tmpdir_b/ctl-state/membership.journal" "$tmpdir_b/membership.journal.snap" 2>/dev/null || true
    if "$tmpdir/check_registration" "$tmpdir_b/membership.journal.snap" \
        "$agent_control_port" >/dev/null 2>&1; then
        active_ok=1
        break
    fi
    sleep 0.05
done
[[ "$active_ok" -eq 1 ]]

committed_out=""
for ((attempt = 0; attempt < 40; attempt++)); do
    committed_out=$("$tmpdir/submit_create_vm" "$tmpdir_b/ctl.sock" || true)
    echo "committed_attempt=$attempt $committed_out"
    if [[ "$committed_out" == status=14* ]]; then
        break
    fi
    if [[ "$committed_out" == status=0* ]]; then
        echo "unexpected RUNNING with missing TCG helper" >&2
        exit 1
    fi
    sleep 0.25
done
if [[ "$committed_out" != status=14* ]]; then
    echo "expected COMMITTED/IN_PROGRESS without TCG helper (got: $committed_out)" >&2
    cat "$tmpdir_b/ctl.log" >&2 || true
    cat "$tmpdir_b/agent.log" >&2 || true
    exit 1
fi

kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir_b/ctl-state" \
    --socket "$tmpdir_b/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir_b/principals" --capacity 8 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir_b/ca.crt" \
    --control-cert "$tmpdir_b/controller.crt" \
    --control-key "$tmpdir_b/controller.key" \
    >"$tmpdir_b/ctl-restart.log" 2>&1 &
ctl_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir_b/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
if ! kill -0 "$ctl_pid" 2>/dev/null || [[ ! -S "$tmpdir_b/ctl.sock" ]]; then
    echo "ctl failed to restart for COMMITTED recovery" >&2
    cat "$tmpdir_b/ctl-restart.log" >&2 || true
    exit 1
fi
if ! grep -q "recovering mid-flight admission" "$tmpdir_b/ctl-restart.log"; then
    echo "expected mid-flight COMMITTED recovery log" >&2
    cat "$tmpdir_b/ctl-restart.log" >&2 || true
    exit 1
fi
if ! grep -q "mid-flight admission recovery scan complete" "$tmpdir_b/ctl-restart.log"; then
    echo "COMMITTED recovery did not complete scan" >&2
    cat "$tmpdir_b/ctl-restart.log" >&2 || true
    exit 1
fi
if ! grep -q "republished membership route+dependencies" "$tmpdir_b/ctl-restart.log"; then
    echo "COMMITTED recovery missing membership dependency republish log" >&2
    cat "$tmpdir_b/ctl-restart.log" >&2 || true
    exit 1
fi

# Vertical evidence: COMMITTED recover path re-runs route+dependency_acquire
# (wvm_admission_orchestrator_recover → register_membership_route_and_dependencies).
assert_membership_deps "$tmpdir_b/ctl-state/membership.journal" \
    "part B after COMMITTED mid-flight recover"

# Replay must stay honest IN_PROGRESS (no false RUNNING) while helper is absent.
replay_b=$("$tmpdir/submit_create_vm" "$tmpdir_b/ctl.sock" || true)
echo "committed_replay=$replay_b"
if [[ "$replay_b" == status=0* ]]; then
    echo "fail-closed violated: COMMITTED recover reported RUNNING without ready helper" >&2
    cat "$tmpdir_b/ctl-restart.log" >&2 || true
    exit 1
fi
if [[ "$replay_b" != status=14* ]]; then
    echo "expected IN_PROGRESS after COMMITTED recover (got: $replay_b)" >&2
    cat "$tmpdir_b/ctl-restart.log" >&2 || true
    exit 1
fi

kill -TERM "$agent_pid"
wait "$agent_pid" || true
agent_pid=
kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=
rm -rf -- "$tmpdir_b"

echo "PASS part B: COMMITTED mid-flight ctl restart recover (scan+dependency_acquire republish, stay IN_PROGRESS)"

# --- Part C: same agent, kill admitted child → fail-closed (A12; no false RUNNING) ---
# Codex A12 / goal §1: unexpected required-child death must DEGRADE/FAILED path;
# QUERY_RUNTIME_READY must not relaunch into fake RUNNING. §6.2 relaunch is only
# for noncritical pre-activation cases without has_required_child_failed.
tmpdir_c=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-recover-c.XXXXXX")
mkdir "$tmpdir_c/ctl-state" "$tmpdir_c/node-state" "$tmpdir_c/runtime" "$tmpdir_c/evidence"
digest_c=$("$tmpdir/seed_evidence" "$tmpdir_c/evidence" 801 802 1 1 \
    "$profile_data0" "$profile_data1" "$profile_svc0" "$profile_svc1" \
    "$agent_control_port")
[[ ${#digest_c} -eq 64 ]]
cp "$tmpdir/ca.crt" "$tmpdir/ca.key" "$tmpdir/controller.crt" "$tmpdir/controller.key" \
    "$tmpdir/node.crt" "$tmpdir/node.key" "$tmpdir_c/"
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir_c/principals"
cp "$tmpdir_c/evidence/capabilities-801.record" "$tmpdir_c/ctl-state/"
cp "$tmpdir_c/evidence/runtime-profile-801.record" "$tmpdir_c/ctl-state/"

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir_c/ctl-state" \
    --socket "$tmpdir_c/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir_c/principals" --capacity 8 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir_c/ca.crt" \
    --control-cert "$tmpdir_c/controller.crt" \
    --control-key "$tmpdir_c/controller.key" \
    >"$tmpdir_c/ctl.log" 2>&1 &
ctl_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir_c/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir_c/ctl.sock" ]]

agent_args_c=(agent
    --state-dir "$tmpdir_c/node-state"
    --runtime-dir "$tmpdir_c/runtime"
    --socket "$tmpdir_c/node.sock"
    --node-id 801 --instance-id 802 --inventory-revision 1
    --vcpu-slots 2 --memory-bytes 1073741824
    --controller-node-id 701 --controller-instance-id 702
    --controller-uid "$(id -u)"
    --slots 2 --max-vcpus 2 --max-memory-chunks 2
    --max-storage 1 --max-members 8 --max-leases 2
    --control-address 127.0.0.1 --control-port "$agent_control_port"
    --data-port "$agent_data_port"
    --tls-ca "$tmpdir_c/ca.crt" --tls-cert "$tmpdir_c/node.crt"
    --tls-key "$tmpdir_c/node.key"
    --register-controller-address 127.0.0.1
    --register-controller-port "$ctl_port"
    --failure-domain-id 1 --pod-id 1 --vnode-first 1 --vnode-count 16
    --sidecar-address 127.0.0.1 --sidecar-data-port "$sidecar_data_port"
    --sidecar-control-port "$sidecar_control_port" --role-bits 1
    --capability-profile-generation 1
    --capability-profile-digest "$digest_c"
    --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222
    --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333
    --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444)

"$repo_root/wavevm_node_runtime" "${agent_args_c[@]}" >"$tmpdir_c/agent.log" 2>&1 &
agent_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir_c/node.sock" ]] && kill -0 "$agent_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir_c/node.sock" ]]

active_ok=0
for ((attempt = 0; attempt < 200; attempt++)); do
    cp -f "$tmpdir_c/ctl-state/membership.journal" "$tmpdir_c/membership.journal.snap" 2>/dev/null || true
    if "$tmpdir/check_registration" "$tmpdir_c/membership.journal.snap" \
        "$agent_control_port" >/dev/null 2>&1; then
        active_ok=1
        break
    fi
    sleep 0.05
done
[[ "$active_ok" -eq 1 ]]

# Drive to durable COMMITTED (status=14), kill admitted child, assert no RUNNING.
create_c=""
killed_child=""
saw_fail_closed=0
for ((attempt = 0; attempt < 80; attempt++)); do
    create_c=$("$tmpdir/submit_create_vm" "$tmpdir_c/ctl.sock" || true)
    echo "part_c_attempt=$attempt $create_c"
    if [[ "$create_c" == status=0* ]]; then
        if [[ -n "$killed_child" ]]; then
            echo "fail-closed violated: child kill still reached RUNNING ($create_c)" >&2
            cat "$tmpdir_c/agent.log" >&2 || true
            exit 1
        fi
        # Reached RUNNING before we could kill — continue loop after kill setup below.
        :
    fi
    if [[ "$create_c" == status=14* && -z "$killed_child" ]]; then
        child_pid=""
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
            if [[ "$cmd" == *" child "* ]] || [[ "$cmd" == *" child" ]]; then
                child_pid=$pid
                break
            fi
        done < <(pgrep -P "$agent_pid" || true)
        if [[ -n "$child_pid" ]]; then
            echo "part_c_killing_admitted_child=$child_pid agent=$agent_pid (pre-RUNNING)"
            kill -KILL "$child_pid"
            for ((wait_i = 0; wait_i < 50; wait_i++)); do
                if ! kill -0 "$child_pid" 2>/dev/null; then
                    break
                fi
                sleep 0.05
            done
            if kill -0 "$child_pid" 2>/dev/null; then
                echo "admitted child $child_pid did not die" >&2
                exit 1
            fi
            killed_child=$child_pid
        fi
    fi
    if [[ -n "$killed_child" ]]; then
        # After kill: must not be RUNNING. PRECONDITION_FAILED(6) or sticky
        # IN_PROGRESS(14)/NOT_READY paths are acceptable; SUCCESS(0) is not.
        if [[ "$create_c" == status=0* ]]; then
            echo "fail-closed violated: RUNNING after child kill ($create_c)" >&2
            exit 1
        fi
        if [[ "$create_c" == status=6* || "$create_c" == status=12* || "$create_c" == status=13* ]]; then
            saw_fail_closed=1
            break
        fi
        # status=14 may still appear briefly; keep polling.
    fi
    sleep 0.25
done
if [[ -z "$killed_child" ]]; then
    echo "part C never observed admitted child under COMMITTED to kill" >&2
    cat "$tmpdir_c/agent.log" >&2 || true
    pstree -p "$agent_pid" >&2 || true
    exit 1
fi
if ! kill -0 "$agent_pid" 2>/dev/null; then
    echo "agent died with child; cannot observe fail-closed on live agent" >&2
    exit 1
fi
if [[ "$saw_fail_closed" -ne 1 ]]; then
    # Final probe: one more CREATE must not claim RUNNING.
    create_c=$("$tmpdir/submit_create_vm" "$tmpdir_c/ctl.sock" || true)
    echo "part_c_final $create_c"
    if [[ "$create_c" == status=0* ]]; then
        echo "part C fail-closed violated: final RUNNING ($create_c)" >&2
        cat "$tmpdir_c/ctl.log" >&2 || true
        cat "$tmpdir_c/agent.log" >&2 || true
        exit 1
    fi
    if [[ "$create_c" != status=6* && "$create_c" != status=12* && "$create_c" != status=13* && "$create_c" != status=14* ]]; then
        echo "part C unexpected post-kill status ($create_c)" >&2
        exit 1
    fi
fi
if ! grep -q 'has_required_child_failed' "$tmpdir_c/agent.log"; then
    echo "part C expected agent to mark has_required_child_failed" >&2
    cat "$tmpdir_c/agent.log" >&2 || true
    exit 1
fi
echo "PASS part C: admitted child KILL@$killed_child → fail-closed (no RUNNING; $create_c)"

kill -TERM "$agent_pid"
wait "$agent_pid" || true
agent_pid=
kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=
rm -rf -- "$tmpdir_c"
tmpdir_c=

# --- Part D: agent death (node_instance gone) → no false RUNNING ---
tmpdir_d=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-create-vm-recover-d.XXXXXX")
mkdir "$tmpdir_d/ctl-state" "$tmpdir_d/node-state" "$tmpdir_d/runtime" "$tmpdir_d/evidence"
digest_d=$("$tmpdir/seed_evidence" "$tmpdir_d/evidence" 801 802 1 1 \
    "$profile_data0" "$profile_data1" "$profile_svc0" "$profile_svc1" \
    "$agent_control_port")
[[ ${#digest_d} -eq 64 ]]
cp "$tmpdir/ca.crt" "$tmpdir/ca.key" "$tmpdir/controller.crt" "$tmpdir/controller.key" \
    "$tmpdir/node.crt" "$tmpdir/node.key" "$tmpdir_d/"
printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir_d/principals"
cp "$tmpdir_d/evidence/capabilities-801.record" "$tmpdir_d/ctl-state/"
cp "$tmpdir_d/evidence/runtime-profile-801.record" "$tmpdir_d/ctl-state/"

"$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir_d/ctl-state" \
    --socket "$tmpdir_d/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir_d/principals" --capacity 8 \
    --control-address 127.0.0.1 --control-port "$ctl_port" \
    --control-ca "$tmpdir_d/ca.crt" \
    --control-cert "$tmpdir_d/controller.crt" \
    --control-key "$tmpdir_d/controller.key" \
    >"$tmpdir_d/ctl.log" 2>&1 &
ctl_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir_d/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir_d/ctl.sock" ]]

agent_args_d=(agent
    --state-dir "$tmpdir_d/node-state"
    --runtime-dir "$tmpdir_d/runtime"
    --socket "$tmpdir_d/node.sock"
    --node-id 801 --instance-id 802 --inventory-revision 1
    --vcpu-slots 2 --memory-bytes 1073741824
    --controller-node-id 701 --controller-instance-id 702
    --controller-uid "$(id -u)"
    --slots 2 --max-vcpus 2 --max-memory-chunks 2
    --max-storage 1 --max-members 8 --max-leases 2
    --control-address 127.0.0.1 --control-port "$agent_control_port"
    --data-port "$agent_data_port"
    --tls-ca "$tmpdir_d/ca.crt" --tls-cert "$tmpdir_d/node.crt"
    --tls-key "$tmpdir_d/node.key"
    --register-controller-address 127.0.0.1
    --register-controller-port "$ctl_port"
    --failure-domain-id 1 --pod-id 1 --vnode-first 1 --vnode-count 16
    --sidecar-address 127.0.0.1 --sidecar-data-port "$sidecar_data_port"
    --sidecar-control-port "$sidecar_control_port" --role-bits 1
    --capability-profile-generation 1
    --capability-profile-digest "$digest_d"
    --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222
    --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333
    --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444)

"$repo_root/wavevm_node_runtime" "${agent_args_d[@]}" >"$tmpdir_d/agent.log" 2>&1 &
agent_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$tmpdir_d/node.sock" ]] && kill -0 "$agent_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done
[[ -S "$tmpdir_d/node.sock" ]]

active_ok=0
for ((attempt = 0; attempt < 200; attempt++)); do
    cp -f "$tmpdir_d/ctl-state/membership.journal" "$tmpdir_d/membership.journal.snap" 2>/dev/null || true
    if "$tmpdir/check_registration" "$tmpdir_d/membership.journal.snap" \
        "$agent_control_port" >/dev/null 2>&1; then
        active_ok=1
        break
    fi
    sleep 0.05
done
[[ "$active_ok" -eq 1 ]]

# Drive at least to COMMITTED/IN_PROGRESS (or RUNNING), then kill agent.
create_d=""
for ((attempt = 0; attempt < 40; attempt++)); do
    create_d=$("$tmpdir/submit_create_vm" "$tmpdir_d/ctl.sock" || true)
    echo "part_d_attempt=$attempt $create_d"
    if [[ "$create_d" == status=0* || "$create_d" == status=14* ]]; then
        break
    fi
    sleep 0.25
done
if [[ "$create_d" != status=0* && "$create_d" != status=14* ]]; then
    echo "part D setup CREATE unexpected (got: $create_d)" >&2
    cat "$tmpdir_d/ctl.log" >&2 || true
    cat "$tmpdir_d/agent.log" >&2 || true
    exit 1
fi

echo "part_d_killing_agent=$agent_pid"
kill -KILL "$agent_pid"
wait "$agent_pid" 2>/dev/null || true
agent_pid=
sleep 0.2

# Without live agent at same node_instance_id, CREATE must not claim RUNNING.
false_running=0
for ((attempt = 0; attempt < 20; attempt++)); do
    replay_d=$("$tmpdir/submit_create_vm" "$tmpdir_d/ctl.sock" || true)
    echo "part_d_replay=$attempt $replay_d"
    if [[ "$replay_d" == status=0* ]]; then
        false_running=1
        break
    fi
    sleep 0.15
done
if [[ "$false_running" -eq 1 ]]; then
    echo "fail-closed violated: agent kill still reported RUNNING" >&2
    cat "$tmpdir_d/ctl.log" >&2 || true
    exit 1
fi
echo "PASS part D: agent KILL → no false RUNNING (last=$replay_d)"

kill -TERM "$ctl_pid"
wait "$ctl_pid" || true
ctl_pid=
rm -rf -- "$tmpdir_d"
tmpdir_d=

echo "CREATE_VM coordinator restart recovery + child-kill fail-closed + agent-kill: PASS"

#!/usr/bin/env bash
# Official typed cross-host acceptance on the production entry only:
#   scripts/wavevm a4|f10|f05 --role node-a|node-b --route-topology flat|fractal
#   -> wvm_ctl serve + wavevm_node_runtime agent + CREATE_VM
# a4 and f10 are the same Minimum KVM cell: Cirros login or SSH plus same-run
# official remote vCPU RET and official [WVM-MEM-STATS] (origin!=directory).
# f05 is the bounded TCG fence contract (no TCG guest login gate; F01 stays
# Extended). Never starts wavevm_node_master / wavevm_node_slave and never
# sets WAVEVM_ALLOW_LEGACY_CLI. This file moving or existing does not close
# F05, F10, Phase 1, Phase 9, or MINIMUM_COMPLETE.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ROLE="${WAVEVM_OFFICIAL_ROLE:-${WVM_A4_ROLE:-}}"
case "$ROLE" in
  node-a|a|A) ROLE=A ;;
  node-b|b|B) ROLE=B ;;
  *) echo "ERROR: set WAVEVM_OFFICIAL_ROLE=node-a or node-b" >&2; exit 2 ;;
esac

CELL="${WVM_OFFICIAL_CELL:-a4}"
case "$CELL" in
  a4|f10) CELL_KIND=kvm ;;
  f05) CELL_KIND=tcg ;;
  *) echo "ERROR: WVM_OFFICIAL_CELL must be a4, f10, or f05" >&2; exit 2 ;;
esac

# Default fractal preserves the existing official A4 invocation. Pass
# --route-topology flat (WVM_OFFICIAL_TOPOLOGY=flat) for the flat cell.
TOPOLOGY="${WVM_OFFICIAL_TOPOLOGY:-fractal}"
case "$TOPOLOGY" in
  flat|fractal) ;;
  *) echo "ERROR: WVM_OFFICIAL_TOPOLOGY must be flat or fractal" >&2; exit 2 ;;
esac

PLACEMENT="${WVM_OFFICIAL_PLACEMENT:-spread}"
case "$PLACEMENT" in
  compact|spread) ;;
  *) echo "ERROR: WVM_OFFICIAL_PLACEMENT must be compact or spread" >&2; exit 2 ;;
esac

if [[ "$CELL_KIND" == tcg ]]; then
  EXEC_BACKEND=require-tcg
  ACCEL_POLICY=disabled
else
  EXEC_BACKEND=require-kvm
  ACCEL_POLICY=disabled
fi

TS_A="${WVM_A4_NODE_A_IP:-100.116.196.65}"
TS_B="${WVM_A4_NODE_B_IP:-100.114.246.92}"
SHARED="${WVM_OFFICIAL_SHARED:-${WVM_A4_SHARED:-/mnt/hgfs/SharedFolder/wavevm-official-${CELL}-${TOPOLOGY}}}"
ART="${WVM_OFFICIAL_ART:-${WVM_A4_ART:-/tmp/wavevm-official-${CELL}-${TOPOLOGY}-$(date +%Y%m%d-%H%M%S)}}"
mkdir -p "$ART"

qemu_bin="${WVM_S6_QEMU_BIN:-$repo_root/wavevm-qemu/build-native/qemu-system-x86_64}"
cirros_img="${WVM_GUEST_IMAGE:-$repo_root/devices/images/cirros-0.6.2-x86_64-disk.img}"
if [[ ! -f "$cirros_img" && -f "$repo_root/artifacts/images/cirros-0.6.2-x86_64-disk.img" ]]; then
  cirros_img="$repo_root/artifacts/images/cirros-0.6.2-x86_64-disk.img"
fi
ssh_port="${WVM_GUEST_SSH_PORT:-2226}"
boot_timeout_s="${WVM_GUEST_BOOT_TIMEOUT_S:-1500}"
ssh_timeout_s="${WVM_GUEST_SSH_TIMEOUT_S:-180}"
vcpus="${WVM_CREATE_VCPUS:-3}"
mem_bytes="${WVM_CREATE_MEMORY_BYTES:-$((3072 * 1024 * 1024))}"

CTL_PORT=17101
GW_CTRL=17102
GW_DATA=17103
GW_LEGACY=17104
A_CTRL=17111
A_DATA=17112
A_SIDE_D=17113
A_SIDE_C=17114
B_CTRL=17121
B_DATA=17122
B_SIDE_D=17123
B_SIDE_C=17124

log() { printf '[official %s %s %s/%s] %s\n' "$CELL" "$TOPOLOGY" "$(date +%H:%M:%S)" "$ROLE" "$*" | tee -a "$ART/runner.log"; }
die() { log "ERROR: $*"; exit 1; }

if [[ -n ${WAVEVM_ALLOW_LEGACY_CLI:-} ]]; then
  log "NOTE: unsetting inherited WAVEVM_ALLOW_LEGACY_CLI; typed official entry will not use it"
  unset WAVEVM_ALLOW_LEGACY_CLI
fi

pidof_named() {
  # pidof matches argv0 basename; pgrep -x cannot see comms >15 chars.
  pidof "$@" >/dev/null 2>&1
}

refuse_legacy() {
  if pidof_named wavevm_node_master wavevm_node_slave; then
    ps -eo pid=,args= | awk "/wavevm_node_master( |$)/||/wavevm_node_slave( |$)/" || true
    die "legacy master/slave process is visible; refusing to call this a typed official entry"
  fi
}

official_dry_check() {
  refuse_legacy
  [[ -x $repo_root/wavevm_node_runtime ]] || die "missing wavevm_node_runtime"
  if [[ "$ROLE" == A ]]; then
    [[ -x $repo_root/ctl_tool/wvm_ctl ]] || die "missing ctl_tool/wvm_ctl"
    if [[ -x $repo_root/gateway_service/wavevm_gateway ]]; then
      log "dry-check gateway=$repo_root/gateway_service/wavevm_gateway"
    else
      log "WARNING: missing gateway_service/wavevm_gateway (needed for a live run, not for this dry-check)"
    fi
  fi
  if [[ -x $qemu_bin ]]; then
    log "dry-check qemu=$qemu_bin"
  else
    log "WARNING: QEMU not found at $qemu_bin (needed for a live run, not for this dry-check)"
  fi
  if [[ -f $cirros_img ]]; then
    log "dry-check cirros=$cirros_img"
  else
    log "WARNING: Cirros image not found at $cirros_img (needed for a live run, not for this dry-check)"
  fi
  for src in \
      "$repo_root/tests/control-plane/submit_create_vm.c" \
      "$repo_root/tests/control-plane/submit_stop_vm.c" \
      "$repo_root/tests/control-plane/seed_create_vm_evidence.c" \
      "$repo_root/tests/control-plane/check_multi_active_cluster.c" \
      "$repo_root/tests/control-plane/check_local_active_cluster.c" \
      "$repo_root/tests/control-plane/check_gateway_active_cluster.c"; do
    [[ -f $src ]] || die "missing helper source $src"
  done
  log "DRY-CHECK ok cell=$CELL topology=$TOPOLOGY placement=$PLACEMENT backend=$EXEC_BACKEND accel=$ACCEL_POLICY entry=wvm_ctl+wavevm_node_runtime legacy_cli=0 qemu=$qemu_bin shared=$SHARED"
  echo "DRY-CHECK=PASS"
  echo "cell=$CELL"
  echo "topology=$TOPOLOGY"
  echo "placement=$PLACEMENT"
  echo "backend=$EXEC_BACKEND"
  echo "accel=$ACCEL_POLICY"
  echo "entry=typed_wvm_ctl_node_runtime"
  echo "legacy_cli=0"
  echo "shared=$SHARED"
  echo "qemu=$qemu_bin"
  exit 0
}

if [[ "${WVM_OFFICIAL_DRY_CHECK:-0}" == "1" ]]; then
  official_dry_check
fi

host_u64() {
  python3 -c 'import pathlib; t=pathlib.Path("/etc/machine-id").read_text().strip()[:16]; print(int(t,16))'
}

COMMON_GCC_OBJS=(
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

run_node_b() {
  refuse_legacy
  log "waiting for join bundle in $SHARED"
  local deadline=$((SECONDS + 300))
  while (( SECONDS < deadline )); do
    if [[ -f "$SHARED/READY_FOR_B" && -f "$SHARED/join.env" ]]; then
      break
    fi
    sleep 1
  done
  [[ -f "$SHARED/READY_FOR_B" ]] || die "join bundle not published by node A"
  # shellcheck disable=SC1090
  source "$SHARED/join.env"
  mkdir -p "$ART/certs" "$ART/node-b" "$ART/runtime-b"
  cp -f "$SHARED/certs/"* "$ART/certs/" || die "cannot copy certs from shared folder"
  [[ -x $repo_root/wavevm_node_runtime ]] || die "missing wavevm_node_runtime on B"
  local my_ip
  my_ip=$(tailscale ip -4 2>/dev/null | head -n1 || true)
  my_ip="${my_ip:-$TS_B}"
  log "starting agent B ip=$my_ip ctl=${A_IP}:${CTL_PORT} host=$PHYSICAL_HOST_B"
  stdbuf -o0 -e0 env \
    WVM_TCG_QEMU_BIN="${qemu_bin}" \
    WVM_PHYSICAL_HOST_ID="$PHYSICAL_HOST_B" \
    "$repo_root/wavevm_node_runtime" agent \
      --state-dir "$ART/node-b" --runtime-dir "$ART/runtime-b" \
      --socket "$ART/node-b.sock" \
      --node-id 811 --instance-id 812 --inventory-revision 1 \
      --physical-host-id "$PHYSICAL_HOST_B" \
      --vcpu-slots 4 --memory-bytes "$mem_bytes" \
      --controller-node-id 701 --controller-instance-id 702 \
      --controller-uid "$(id -u)" \
      --slots 4 --max-vcpus 4 --max-memory-chunks 8 \
      --max-storage 1 --max-members 8 --max-leases 2 \
      --control-address "$my_ip" --control-port "$B_CTRL" \
      --data-port "$B_DATA" \
      --tls-ca "$ART/certs/ca.crt" --tls-cert "$ART/certs/nodeb.crt" \
      --tls-key "$ART/certs/nodeb.key" \
      --register-controller-address "$A_IP" \
      --register-controller-port "$CTL_PORT" \
      --failure-domain-id 2 --pod-id 2 \
      --vnode-first 16 --vnode-count 16 \
      --sidecar-address "$my_ip" --sidecar-data-port "$B_SIDE_D" \
      --sidecar-control-port "$B_SIDE_C" --role-bits 1 \
      --capability-profile-generation 1 \
      --capability-profile-digest "$DIGEST_B" \
      --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222 \
      --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333 \
      --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444 \
      >"$ART/agent-b.log" 2>&1 &
  local agent_pid=$!
  echo "$agent_pid" >"$ART/agent-b.pid"
  echo "$agent_pid" >"$SHARED/B_AGENT_PID"
  echo "$ART" >"$SHARED/B_ART"
  local i
  for ((i=0; i<200; i++)); do
    [[ -S "$ART/node-b.sock" ]] && kill -0 "$agent_pid" 2>/dev/null && break
    sleep 0.05
  done
  if [[ ! -S "$ART/node-b.sock" ]]; then
    tail -n 80 "$ART/agent-b.log" >&2 || true
    die "agent B socket did not appear"
  fi
  date '+%Y-%m-%d %H:%M:%S %Z' >"$SHARED/B_STARTED"
  log "agent B up pid=$agent_pid; holding for node A"
  local hold=$((SECONDS + 2400))
  while (( SECONDS < hold )); do
    if [[ -f "$SHARED/DONE" ]]; then
      log "node A signaled DONE"
      break
    fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then
      die "agent B exited early; see $ART/agent-b.log"
    fi
    cp -f "$ART/agent-b.log" "$SHARED/agent-b.log" 2>/dev/null || true
    cp -f "$ART/runner.log" "$SHARED/runner-b.log" 2>/dev/null || true
    sleep 5
  done
  kill -TERM "$agent_pid" 2>/dev/null || true
  wait "$agent_pid" 2>/dev/null || true
  mkdir -p "$SHARED/node-b-logs"
  cp -f "$ART/agent-b.log" "$ART/runner.log" "$SHARED/node-b-logs/" 2>/dev/null || true
  refuse_legacy
  log "node B stopped"
}

common_compile() {
  local tmpdir=$1
  gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${COMMON_GCC_OBJS[@]}" \
    "$repo_root/tests/control-plane/seed_create_vm_evidence.c" \
    -pthread -o "$tmpdir/seed_evidence"
  gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${COMMON_GCC_OBJS[@]}" \
    "$repo_root/tests/control-plane/submit_create_vm.c" \
    -pthread -o "$tmpdir/submit_create_vm"
  gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/check_multi_active_cluster.c" \
    -pthread -o "$tmpdir/check_multi_active"
  gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/check_local_active_cluster.c" \
    -pthread -o "$tmpdir/check_local_active"
  gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "$repo_root/common_include/wavevm_sha256.c" \
    "$repo_root/common_include/wavevm_canonical.c" \
    "$repo_root/common_include/wavevm_identity.c" \
    "$repo_root/common_include/wavevm_runtime_names.c" \
    "$repo_root/common_include/wavevm_manifest.c" \
    "$repo_root/common_include/wavevm_control.c" \
    "$repo_root/common_include/wavevm_lifecycle.c" \
    "$repo_root/common_include/wavevm_envelope.c" \
    "$repo_root/common_include/wavevm_membership_controller.c" \
    "$repo_root/tests/control-plane/check_gateway_active_cluster.c" \
    -pthread -o "$tmpdir/check_gateway_active"
  gcc -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$repo_root/common_include" \
    "${COMMON_GCC_OBJS[@]}" \
    "$repo_root/tests/control-plane/submit_stop_vm.c" \
    -pthread -o "$tmpdir/submit_stop_vm"
}

score_official() {
  local art=$1 out=$2
  python3 - "$art" <<'PY' >"$out"
import os, re, sys, glob
art = sys.argv[1]
rem = sent = ack0 = ack1 = mem_raw = fence_done = push_fail = defer = 0
rd, ld, fl = {}, {}, {}
latest = {}
samples = []
for path in sorted(glob.glob(os.path.join(art, "**", "*.log"), recursive=True)):
    try:
        fh = open(path, errors="replace")
    except OSError:
        continue
    with fh:
        for line in fh:
            if "[WVM-REMOTE-DEFER]" in line:
                defer += 1
                continue
            if "[WVM-REMOTE]" in line and "cpu=2" in line:
                rem += 1
            if "IPC VCPU_RUN] vcpu=2 " in line:
                sent += 1
            if re.search(r"IPC VCPU_RUN RET] vcpu=2.*ack_status=0 ack_mode=0", line):
                ack0 += 1
            if re.search(r"IPC VCPU_RUN RET] vcpu=2.*ack_status=0 ack_mode=1", line):
                ack1 += 1
            if "[IPC FENCE] push-barrier done" in line:
                fence_done += 1
            if "push-fence failed" in line:
                push_fail += 1
            if "[WVM-TCG-STATS]" in line:
                d = dict(re.findall(r"(\w+)=(\S+)", line))
                c = d.get("cpu")
                if c is not None:
                    for key, dst in (("remote_done", rd), ("local_done", ld), ("force_local_used", fl)):
                        if key in d:
                            try: dst[c] = int(d[key])
                            except ValueError: pass
            if "[WVM-MEM-STATS]" in line:
                mem_raw += 1
                d = dict(re.findall(r"(\w+)=(\S+)", line))
                if not (d.get("origin", "").isdigit() and d.get("directory", "").isdigit()
                        and d.get("remote_commits", "").isdigit()):
                    continue
                if d.get("origin") == d.get("directory") and d.get("instance", "") == d.get("directory_instance", ""):
                    continue
                key = (d.get("origin"), d.get("instance"), d.get("runtime"), d.get("pid"))
                latest[key] = int(d.get("remote_reads") or 0) + int(d["remote_commits"])
                if len(samples) < 8:
                    samples.append(os.path.relpath(path, art) + ": " + line.strip()[:320])
rd2 = rd.get("2", 0)
mem_peer = sum(latest.values())
# Official remote vCPU evidence is an honest RET, not a dispatch or DEFER line.
vcpu_kvm = 1 if ack0 > 0 else 0
vcpu_tcg = 1 if ack1 > 0 else 0
mem = 1 if mem_peer > 0 else 0
print("remote=%d" % rem)
print("remote_defer=%d" % defer)
print("sent=%d" % sent)
print("ack_mode0=%d" % ack0)
print("ack_mode1=%d" % ack1)
print("fence_done=%d" % fence_done)
print("push_fail=%d" % push_fail)
print("remote_done_cpu2=%d" % rd2)
print("remote_done_sum=%d" % sum(rd.values()))
print("local_done_sum=%d" % sum(ld.values()))
print("force_local_sum=%d" % sum(fl.values()))
print("mem_stats_raw=%d" % mem_raw)
print("remote_mem_peer=%d" % mem_peer)
print("remote_vcpu_evidence_kvm=%d" % vcpu_kvm)
print("remote_vcpu_evidence_tcg=%d" % vcpu_tcg)
print("remote_vcpu_evidence=%d" % (vcpu_kvm or vcpu_tcg))
print("remote_mem_evidence=%d" % mem)
print("entry=typed_wvm_ctl_node_runtime")
print("legacy_cli=0")
if samples:
    print("mem_samples_begin")
    for s in samples:
        print(s)
    print("mem_samples_end")
PY
}

run_node_a() {
  log "node A starting art=$ART"
  refuse_legacy
  [[ -x $repo_root/ctl_tool/wvm_ctl ]] || die "missing ctl_tool/wvm_ctl"
  [[ -x $repo_root/wavevm_node_runtime ]] || die "missing wavevm_node_runtime"
  [[ -x $repo_root/gateway_service/wavevm_gateway ]] || die "missing wavevm_gateway"
  [[ -x $qemu_bin ]] || die "missing QEMU $qemu_bin"
  [[ -f $cirros_img ]] || die "missing Cirros image $cirros_img"

  local my_ip
  my_ip=$(tailscale ip -4 2>/dev/null | head -n1 || true)
  my_ip="${my_ip:-$TS_A}"
  local host_a host_b
  host_a=$(host_u64)
  host_b="${WVM_A4_NODE_B_HOST_ID:-4799159562654991353}"

  local tmpdir="$ART/cell"
  mkdir -p "$tmpdir/ctl-state" "$tmpdir/gw-state/enrollment" \
    "$tmpdir/node-a" "$tmpdir/runtime-a" "$tmpdir/evidence" "$tmpdir/certs"
  : > "$tmpdir/gw-empty.conf"
  common_compile "$tmpdir"

  local digest_a digest_b
  # Profile port pools must be unique, strictly increasing, and must not
  # collide with node/executor control ports. These advertise in the seeded
  # profile; listen sockets stay on A_*/B_* CLI ports (same as multi_node).
  local a_pdata0=17210 a_pdata1=17211 a_psvc0=17212 a_psvc1=17213 a_pctrl=17214
  local b_pdata0=17220 b_pdata1=17221 b_psvc0=17222 b_psvc1=17223 b_pctrl=17224
  digest_a=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 801 802 1 1 \
    "$a_pdata0" "$a_pdata1" "$a_psvc0" "$a_psvc1" "$a_pctrl" "$host_a") \
    || die "seed evidence A failed"
  digest_b=$("$tmpdir/seed_evidence" "$tmpdir/evidence" 811 812 1 1 \
    "$b_pdata0" "$b_pdata1" "$b_psvc0" "$b_psvc1" "$b_pctrl" "$host_b") \
    || die "seed evidence B failed"
  [[ ${#digest_a} -eq 64 && ${#digest_b} -eq 64 ]] || die "seed digest failed (a=${#digest_a} b=${#digest_b})"
  cp "$tmpdir/evidence/capabilities-801.record" "$tmpdir/ctl-state/"
  cp "$tmpdir/evidence/runtime-profile-801.record" "$tmpdir/ctl-state/"
  cp "$tmpdir/evidence/capabilities-811.record" "$tmpdir/ctl-state/"
  cp "$tmpdir/evidence/runtime-profile-811.record" "$tmpdir/ctl-state/"

  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=WaveVMTestCA -keyout "$tmpdir/certs/ca.key" \
    -out "$tmpdir/certs/ca.crt" >/dev/null 2>&1
  make_cert() {
    local name=$1 cn=$2
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$cn" \
      -keyout "$tmpdir/certs/$name.key" -out "$tmpdir/certs/$name.csr" >/dev/null 2>&1
    openssl x509 -req -days 1 -in "$tmpdir/certs/$name.csr" \
      -CA "$tmpdir/certs/ca.crt" -CAkey "$tmpdir/certs/ca.key" -CAcreateserial \
      -out "$tmpdir/certs/$name.crt" >/dev/null 2>&1
  }
  make_cert controller node-runtime:701:702
  make_cert gateway gateway:901:902
  make_cert nodea node-runtime:801:802
  make_cert nodeb node-runtime:811:812
  printf '%s executor 9001 9002\n' "$(id -u)" > "$tmpdir/principals"

  log "seed+certs ready; publishing join bundle A_IP=$my_ip"
  mkdir -p "$SHARED/certs"
  rm -f "$SHARED/READY_FOR_B" "$SHARED/B_STARTED" "$SHARED/DONE" "$SHARED/join.env"
  cp -f "$tmpdir/certs/"* "$SHARED/certs/" || die "cannot copy certs to shared folder"
  printf "A_IP=%s\nB_IP=%s\nCTL_PORT=%s\nDIGEST_B=%s\nPHYSICAL_HOST_B=%s\nPHYSICAL_HOST_A=%s\n" \
    "$my_ip" "$TS_B" "$CTL_PORT" "$digest_b" "$host_b" "$host_a" \
    >"$SHARED/join.env" || die "cannot write $SHARED/join.env"
  sync "$SHARED/join.env" 2>/dev/null || true
  [[ -s $SHARED/join.env ]] || die "join.env missing after write"
  log "join.env published to $SHARED (A_IP=$my_ip digest_b=${digest_b:0:16}...); READY_FOR_B after gateway enrolls"

  stdbuf -o0 -e0 "$repo_root/ctl_tool/wvm_ctl" serve \
    --state-dir "$tmpdir/ctl-state" --socket "$tmpdir/ctl.sock" \
    --local-node-id 701 --local-instance-id 702 \
    --principals "$tmpdir/principals" --capacity 16 \
    --route-topology "$TOPOLOGY" \
    --control-address 0.0.0.0 --control-port "$CTL_PORT" \
    --control-ca "$tmpdir/certs/ca.crt" \
    --control-cert "$tmpdir/certs/controller.crt" \
    --control-key "$tmpdir/certs/controller.key" \
    >"$tmpdir/ctl.log" 2>&1 &
  ctl_pid=$!
  echo "$ctl_pid" >"$ART/ctl.pid"
  local i
  for ((i=0; i<100; i++)); do
    [[ -S "$tmpdir/ctl.sock" ]] && kill -0 "$ctl_pid" 2>/dev/null && break
    sleep 0.05
  done
  [[ -S "$tmpdir/ctl.sock" ]] || { cat "$tmpdir/ctl.log" >&2; die "ctl socket missing"; }
  log "wvm_ctl serve up pid=$ctl_pid port=$CTL_PORT"

  export WVM_GATEWAY_ID=901 WVM_GATEWAY_INSTANCE_ID=902
  export WVM_GATEWAY_ROUTE_JOURNAL_PATH="$tmpdir/gw-state/route.journal"
  export WVM_GATEWAY_CONTROL_SOCKET="$tmpdir/gw-state/control.sock"
  export WVM_GATEWAY_ENROLLMENT_STATE_DIR="$tmpdir/gw-state/enrollment"
  export WVM_GATEWAY_CONTROLLER_ROLE=node-runtime
  export WVM_GATEWAY_CONTROLLER_ID=701
  export WVM_GATEWAY_CONTROLLER_INSTANCE_ID=702
  export WVM_GATEWAY_CONTROLLER_PHYSICAL_NODE_ID=701
  export WVM_GATEWAY_CONTROLLER_RUNTIME_INSTANCE_ID=702
  export WVM_GATEWAY_CONTROL_ADDRESS="$my_ip"
  export WVM_GATEWAY_DATA_ADDRESS="$my_ip"
  export WVM_GATEWAY_CONTROL_PORT=$GW_CTRL
  export WVM_GATEWAY_CONTROL_CA_FILE="$tmpdir/certs/ca.crt"
  export WVM_GATEWAY_CONTROL_CERTIFICATE_FILE="$tmpdir/certs/gateway.crt"
  export WVM_GATEWAY_CONTROL_PRIVATE_KEY_FILE="$tmpdir/certs/gateway.key"
  export WVM_GATEWAY_REGISTER_CONTROLLER_ADDRESS=127.0.0.1
  export WVM_GATEWAY_REGISTER_CONTROLLER_PORT=$CTL_PORT
  export WVM_GATEWAY_HOSTING_NODE_ID=801
  export WVM_GATEWAY_FAILURE_DOMAIN_ID=1
  export WVM_GATEWAY_POD_ID=1
  export WVM_GATEWAY_ROLE_BITS=1
  export WVM_GATEWAY_SINGLE_RX=1
  unset WVM_GATEWAY_FORCE_SINGLE_FD || true

  stdbuf -o0 -e0 "$repo_root/gateway_service/wavevm_gateway" \
    "$GW_DATA" 127.0.0.1 9 "$tmpdir/gw-empty.conf" "$GW_LEGACY" \
    >"$tmpdir/gw.log" 2>&1 &
  gw_pid=$!
  echo "$gw_pid" >"$ART/gw.pid"
  for ((i=0; i<200; i++)); do
    if grep -q "REGISTER accepted" "$tmpdir/gw.log" 2>/dev/null; then
      break
    fi
    kill -0 "$gw_pid" 2>/dev/null || { cat "$tmpdir/gw.log" >&2; die "gateway exited"; }
    sleep 0.05
  done
  grep -q "REGISTER accepted" "$tmpdir/gw.log" || { cat "$tmpdir/gw.log" >&2; die "gateway REGISTER not accepted"; }
  # REGISTER accepted is not a committed enrollment. run-224323 (A9): agent A
  # started in the same second, gateway ACK was outside its proof, and 901:902
  # stayed PREPARED with no activation id. Wait for gateway COMMITTED+ACTIVE
  # before starting A. READY_FOR_B still waits for gw+A together.
  log "gateway REGISTER accepted pid=$gw_pid advertised control/data=$my_ip; waiting for gateway COMMITTED"
  wait_gw=$((SECONDS + 60))
  while (( SECONDS < wait_gw )); do
    if [[ -s "$tmpdir/ctl-state/membership.journal" ]] && \
       "$tmpdir/check_gateway_active" "$tmpdir/ctl-state/membership.journal" >/dev/null 2>&1; then
      log "gateway 901:902 COMMITTED+ACTIVE"
      break
    fi
    if ! kill -0 "$gw_pid" 2>/dev/null; then
      cat "$tmpdir/gw.log" >&2
      die "gateway exited before enrollment committed"
    fi
    sleep 0.2
  done
  if ! "$tmpdir/check_gateway_active" "$tmpdir/ctl-state/membership.journal" >/dev/null 2>&1; then
    "$tmpdir/check_gateway_active" "$tmpdir/ctl-state/membership.journal" >&2 || true
    tail -n 40 "$tmpdir/ctl.log" >&2 || true
    die "gateway did not reach COMMITTED+ACTIVE before starting agent A"
  fi
  log "gateway up pid=$gw_pid; holding READY_FOR_B until A is COMMITTED"

  export WVM_TCG_QEMU_BIN="$qemu_bin"
  export WVM_TCG_QEMU_DATADIR="${WVM_TCG_QEMU_DATADIR:-$repo_root/wavevm-qemu/build-native/pc-bios}"
  stdbuf -o0 -e0 env WVM_TCG_QEMU_BIN="$qemu_bin" \
    WVM_TCG_QEMU_DATADIR="$WVM_TCG_QEMU_DATADIR" \
    WVM_PHYSICAL_HOST_ID="$host_a" \
    WVM_FE_PHYSICAL_HOST_ID="$host_a" \
    WVM_GUEST_IMAGE="$cirros_img" \
    WVM_GUEST_SERIAL_LOG="$ART/vm-serial.log" \
    WVM_GUEST_FE_LOG="$ART/vm.log" \
    WVM_GUEST_SSH_PORT="$ssh_port" \
    WVM_GUEST_FE_BOOT_NOW=1 \
    WVM_UNIQUE_GUEST_FE=1 \
    WVM_GUEST_SPLIT=2 \
    WVM_GUEST_SMP="$vcpus" \
    WVM_CREATE_VCPUS="$vcpus" \
    "$repo_root/wavevm_node_runtime" agent \
      --state-dir "$tmpdir/node-a" --runtime-dir "$tmpdir/runtime-a" \
      --socket "$tmpdir/node-a.sock" \
      --node-id 801 --instance-id 802 --inventory-revision 1 \
      --physical-host-id "$host_a" \
      --vcpu-slots 6 --memory-bytes "$((mem_bytes + 256*1024*1024))" \
      --controller-node-id 701 --controller-instance-id 702 \
      --controller-uid "$(id -u)" \
      --slots 6 --max-vcpus 6 --max-memory-chunks 8 \
      --max-storage 1 --max-members 8 --max-leases 2 \
      --control-address "$my_ip" --control-port "$A_CTRL" \
      --data-port "$A_DATA" \
      --tls-ca "$tmpdir/certs/ca.crt" --tls-cert "$tmpdir/certs/nodea.crt" \
      --tls-key "$tmpdir/certs/nodea.key" \
      --register-controller-address 127.0.0.1 \
      --register-controller-port "$CTL_PORT" \
      --failure-domain-id 1 --pod-id 1 \
      --vnode-first 0 --vnode-count 16 \
      --sidecar-address "$my_ip" --sidecar-data-port "$A_SIDE_D" \
      --sidecar-control-port "$A_SIDE_C" --role-bits 1 \
      --capability-profile-generation 1 \
      --capability-profile-digest "$digest_a" \
      --storage-capabilities-digest 2222222222222222222222222222222222222222222222222222222222222222 \
      --accelerator-fault-capabilities-digest 3333333333333333333333333333333333333333333333333333333333333333 \
      --exclusive-resource-digest 4444444444444444444444444444444444444444444444444444444444444444 \
      >"$tmpdir/agent-a.log" 2>&1 &
  agent_pid=$!
  echo "$agent_pid" >"$ART/agent-a.pid"
  for ((i=0; i<200; i++)); do
    [[ -S "$tmpdir/node-a.sock" ]] && kill -0 "$agent_pid" 2>/dev/null && break
    sleep 0.05
  done
  [[ -S "$tmpdir/node-a.sock" ]] || { cat "$tmpdir/agent-a.log" >&2; die "agent A socket missing"; }
  log "agent A up pid=$agent_pid; waiting for local gw+A enrollment"

  local wait_local=$((SECONDS + 60))
  while (( SECONDS < wait_local )); do
    if [[ -s "$tmpdir/ctl-state/membership.journal" ]] &&        "$tmpdir/check_local_active" "$tmpdir/ctl-state/membership.journal" >/dev/null 2>&1; then
      log "local gw+A COMMITTED+ACTIVE; publishing READY_FOR_B"
      break
    fi
    if ! kill -0 "$gw_pid" 2>/dev/null; then
      cat "$tmpdir/gw.log" >&2
      die "gateway exited before local enrollment committed"
    fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then
      cat "$tmpdir/agent-a.log" >&2
      die "agent A exited before local enrollment committed"
    fi
    sleep 0.2
  done
  if ! "$tmpdir/check_local_active" "$tmpdir/ctl-state/membership.journal" >/dev/null 2>&1; then
    "$tmpdir/check_local_active" "$tmpdir/ctl-state/membership.journal" >&2 || true
    die "gateway+A did not reach COMMITTED+ACTIVE before inviting B"
  fi
  date '+%Y-%m-%d %H:%M:%S %Z' >"$SHARED/READY_FOR_B" || die "cannot write READY_FOR_B"
  sync "$SHARED/READY_FOR_B" 2>/dev/null || true
  [[ -s $SHARED/READY_FOR_B ]] || die "READY_FOR_B missing after write"
  log "READY_FOR_B published after serialized gw+A enrollment"

  local wait_b=$((SECONDS + 300))
  while (( SECONDS < wait_b )); do
    if [[ -s "$tmpdir/ctl-state/membership.journal" ]]; then
      if "$tmpdir/check_multi_active" "$tmpdir/ctl-state/membership.journal" >/dev/null 2>&1; then
        log "multi-ACTIVE cluster (gw+A+B) ready"
        break
      fi
    fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then
      cat "$tmpdir/agent-a.log" >&2
      die "agent A exited while waiting for B"
    fi
    sleep 1
  done
  if ! "$tmpdir/check_multi_active" "$tmpdir/ctl-state/membership.journal" >/dev/null 2>&1; then
    log "membership dump:"
    "$tmpdir/check_multi_active" "$tmpdir/ctl-state/membership.journal" >&2 || true
    tail -n 40 "$tmpdir/ctl.log" >&2 || true
    tail -n 40 "$tmpdir/agent-a.log" >&2 || true
    die "B did not reach ACTIVE in time (typed cross-host enrollment failed)"
  fi

  log "CREATE_VM $PLACEMENT vcpus=$vcpus mem=$mem_bytes $ACCEL_POLICY $EXEC_BACKEND unique-FE split=2 topology=$TOPOLOGY"
  local create_out="$tmpdir/create.out"
  local create_line="" attempt
  : >"$create_out"
  for ((attempt=0; attempt<80; attempt++)); do
    create_line=$(env WVM_CREATE_MEMORY_BYTES="$mem_bytes" WVM_CREATE_VCPUS="$vcpus" \
      "$tmpdir/submit_create_vm" "$tmpdir/ctl.sock" "official-${CELL}-${TOPOLOGY}" "$vcpus" "$PLACEMENT" 9 "$ACCEL_POLICY" "$EXEC_BACKEND" \
      2>>"$create_out" || true)
    echo "attempt=$attempt $create_line" | tee -a "$create_out" >/dev/null
    log "CREATE_VM attempt=$attempt $create_line"
    if [[ "$create_line" == status=0* ]]; then
      break
    fi
    if [[ "$create_line" != status=14* ]]; then
      break
    fi
    sleep 0.25
  done
  echo "$create_line" >>"$create_out"
  if [[ "$create_line" != status=0* ]]; then
    log "ctl tail:"; tail -n 80 "$tmpdir/ctl.log" || true
    log "agent-a tail:"; tail -n 80 "$tmpdir/agent-a.log" || true
    die "CREATE_VM did not reach SUCCESS(0)/RUNNING (got: $create_line). Typed path cannot yet complete cross-host placement/FE spawn."
  fi
  log "CREATE_VM SUCCESS $create_line"
  if [[ ! -s $tmpdir/gw-state/route.journal ]]; then
    log "WARNING: gateway route journal empty after CREATE_VM"
  fi

  local qemu_deadline=$((SECONDS + 180))
  local qemu_ok=0
  while (( SECONDS < qemu_deadline )); do
    if pgrep -af 'qemu-system-x86_64' | grep -v grep | grep -E 'accel wavevm|wavevm' >/dev/null 2>&1; then
      qemu_ok=1
      break
    fi
    if [[ -f $ART/vm.log ]] && grep -q 'QEMU.*started\|VNC server running\|wavevm' "$ART/vm.log" 2>/dev/null; then
      qemu_ok=1
      break
    fi
    sleep 1
  done
  pgrep -af qemu-system-x86_64 >"$ART/qemu.ps" 2>/dev/null || true
  if [[ $qemu_ok -eq 0 ]]; then
    log "no unique Cirros FE appeared after CREATE_VM commit"
    tail -n 80 "$tmpdir/agent-a.log" || true
    tail -n 80 "$ART/vm.log" 2>/dev/null || true
    die "typed CREATE_VM committed but no QEMU frontend (missing FE spawn piece)"
  fi
  log "QEMU FE observed"

  local login_ok=0 login_at=""
  local ssh_ok=0 ssh_at=""
  if [[ "$CELL" == f05 ]]; then
    log "F05 fence-only poll (no TCG guest login gate; F01 stays Extended)"
    local settle="${WVM_F05_SETTLE_S:-30}"
    local polls="${WVM_F05_POLLS:-24}"
    local sleep_s="${WVM_F05_POLL_SLEEP:-30}"
    log "settle=${settle}s polls=$polls interval=${sleep_s}s"
    sleep "$settle"
    local fi_i q_alive=0 fence_done=0 push_fail=0 remote=0 sent=0 ack1=0
    for ((fi_i=1; fi_i<=polls; fi_i++)); do
      if [[ -f $SHARED/agent-b.log ]]; then
        cp -f "$SHARED/agent-b.log" "$ART/agent-b.log" 2>/dev/null || true
      fi
      if [[ -d $SHARED/node-b-logs ]]; then
        mkdir -p "$ART/node-b-logs"
        cp -f "$SHARED/node-b-logs/." "$ART/node-b-logs/" 2>/dev/null || true
      fi
      score_official "$ART" "$ART/score.txt"
      fence_done=0; push_fail=0; remote=0; sent=0; ack1=0
      # shellcheck disable=SC1090
      eval "$(grep -E '^(remote|sent|ack_mode1|fence_done|push_fail)=' "$ART/score.txt" | sed 's/ack_mode1=/ack1=/')"
      q_alive=0
      pidof_named qemu-system-x86_64 && q_alive=1
      log "F05 poll $fi_i/$polls q_alive=$q_alive fence_done=$fence_done push_fail=$push_fail remote=$remote sent=$sent ack_mode1=$ack1"
      if [[ $fence_done -gt 0 && $push_fail -eq 0 && $remote -gt 0 && $sent -gt 0 && $ack1 -gt 0 && $q_alive -eq 1 ]]; then
        log "F05 fence-only markers observed; stopping poll"
        break
      fi
      if [[ $q_alive -eq 0 ]]; then
        log "QEMU exited during F05 fence-only poll"
        break
      fi
      sleep "$sleep_s"
    done
  else
  # A4/F10: Cirros login/SSH + affinity burn, then official RET+MEM score
  local login_deadline=$((SECONDS + boot_timeout_s))
  while (( SECONDS < login_deadline )); do
    if [[ -f $ART/vm-serial.log ]] && grep -E 'login:|cirros login' "$ART/vm-serial.log" >/dev/null 2>&1; then
      login_ok=1
      login_at=$(date '+%Y-%m-%d %H:%M:%S %Z')
      break
    fi
    if ! pidof_named qemu-system-x86_64; then
      log "QEMU exited before login"
      break
    fi
    sleep 2
  done
  log "login_ok=$login_ok at=${login_at:-none}"

  local ssh_ok=0 ssh_at=""
  if [[ $login_ok -eq 1 ]]; then
    local ssh_deadline=$((SECONDS + ssh_timeout_s))
    while (( SECONDS < ssh_deadline )); do
      if sshpass -p gocubsgo ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 -p "$ssh_port" cirros@127.0.0.1 'echo SSH_OK; uname -a' \
          >"$ART/ssh.out" 2>"$ART/ssh.err"; then
        if grep -q SSH_OK "$ART/ssh.out"; then
          ssh_ok=1
          ssh_at=$(date '+%Y-%m-%d %H:%M:%S %Z')
          break
        fi
      fi
      sleep 3
    done
  fi
  log "ssh_ok=$ssh_ok at=${ssh_at:-none}"

  if [[ $ssh_ok -eq 1 ]]; then
    log "starting 5s vCPU2 affinity burn (sched_setaffinity cpu 2)"
    cat >"$ART/wvm-aff2.c" <<'EOF_AFF'
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
int main(void)
{
    cpu_set_t s;
    struct timespec ts, te;
    CPU_ZERO(&s);
    CPU_SET(2, &s);
    if (sched_setaffinity(0, sizeof(s), &s) != 0) {
        fprintf(stderr, "aff 2 failed errno=%d\n", errno);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts);
    volatile unsigned long i = 0;
    do {
        for (int k = 0; k < 10000000; k++) i++;
        clock_gettime(CLOCK_MONOTONIC, &te);
    } while ((te.tv_sec - ts.tv_sec) + (te.tv_nsec - ts.tv_nsec) / 1e9 < 5.0);
    printf("burn-cpu2-sec=5 iters=%lu\n", i);
    fflush(stdout);
    return 0;
}
EOF_AFF
    if ! gcc -O2 -static -s -o "$ART/wvm-aff2" "$ART/wvm-aff2.c"; then
      log "WARNING: static affinity burn failed to compile"
    else
      timeout 25 sshpass -p gocubsgo ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o LogLevel=ERROR -o ConnectTimeout=8 -p "$ssh_port" cirros@127.0.0.1 \
        'cat > /tmp/wvm-aff2 && chmod +x /tmp/wvm-aff2 && /tmp/wvm-aff2 && echo a4-burn-done' \
        <"$ART/wvm-aff2" >"$ART/burn.out" 2>"$ART/burn.err" || true
      log "vCPU2 burn rc=$? out=$(tr '\n' ' ' <"$ART/burn.out" 2>/dev/null | head -c 200)"
    fi
    sleep 3
  fi
  fi

  if [[ -f $SHARED/agent-b.log ]]; then
    cp -f "$SHARED/agent-b.log" "$ART/agent-b.log" 2>/dev/null || true
  fi
  if [[ -d $SHARED/node-b-logs ]]; then
    mkdir -p "$ART/node-b-logs"
    cp -f "$SHARED/node-b-logs/." "$ART/node-b-logs/" 2>/dev/null || true
  fi
  find "$tmpdir" "$ART" -name '*.log' >"$ART/all-logs.list" 2>/dev/null || true
  score_official "$ART" "$ART/score.txt"
  local remote=0 sent=0 ack0=0 ack1=0 rd2=0 mem_peer=0 mem_raw=0 vcpu_ev=0 mem_ev=0
  local fence_done=0 push_fail=0 remote_defer=0 vcpu_kvm=0 vcpu_tcg=0
  # shellcheck disable=SC1090
  eval "$(grep -E '^(remote|remote_defer|sent|ack_mode0|ack_mode1|remote_done_cpu2|remote_mem_peer|mem_stats_raw|remote_vcpu_evidence|remote_vcpu_evidence_kvm|remote_vcpu_evidence_tcg|remote_mem_evidence|fence_done|push_fail)=' "$ART/score.txt" | sed 's/ack_mode0=/ack0=/;s/ack_mode1=/ack1=/;s/remote_done_cpu2=/rd2=/;s/remote_mem_peer=/mem_peer=/;s/mem_stats_raw=/mem_raw=/;s/remote_vcpu_evidence_kvm=/vcpu_kvm=/;s/remote_vcpu_evidence_tcg=/vcpu_tcg=/;s/remote_vcpu_evidence=/vcpu_ev=/;s/remote_mem_evidence=/mem_ev=/')"
  local ap_shutdown=0 wvm_reset=0 kvm_shutdown=0 handoff_fail=0
  ap_shutdown=$(grep -R -c 'WVM-AP-SHUTDOWN' "$ART" 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}' || echo 0)
  wvm_reset=$(grep -R -c 'WVM-RESET' "$ART" 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}' || echo 0)
  kvm_shutdown=$(grep -c 'KVM_EXIT_SHUTDOWN\|KVM-SHUTDOWN' "$ART/vm.log" 2>/dev/null || echo 0)
  handoff_fail=$(grep -R -c 'terminal handoff failure' "$ART" 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}' || echo 0)
  local q_alive=0
  pidof_named qemu-system-x86_64 && q_alive=1

  local verdict=FAIL
  if [[ "$CELL" == f05 ]]; then
    # Honest TCG fence contract: drained fence + real TCG RET. Login is not a gate.
    if [[ $fence_done -gt 0 && $push_fail -eq 0 && $remote -gt 0 && $sent -gt 0 && $ack1 -gt 0 && $ack0 -eq 0 && $q_alive -eq 1 && $handoff_fail -eq 0 ]]; then
      verdict=PASS
    elif [[ $fence_done -gt 0 && $push_fail -eq 0 ]]; then
      verdict=PARTIAL
    fi
  else
    # Official A4/F10: same-run login+SSH plus honest KVM RET and official remote mem.
    # Dispatch or DEFER alone is not remote vCPU evidence.
    if [[ $login_ok -eq 1 && $ssh_ok -eq 1 && $ack0 -gt 0 && $mem_ev -eq 1 && $ack1 -eq 0 && $q_alive -eq 1 && $handoff_fail -eq 0 ]]; then
      if [[ $ap_shutdown -gt 0 ]]; then
        verdict=PARTIAL
      else
        verdict=PASS
      fi
    elif [[ $login_ok -eq 1 && $ssh_ok -eq 1 && ( $ack0 -gt 0 || $mem_ev -eq 1 ) ]]; then
      verdict=PARTIAL
    fi
  fi

  {
    echo "VERDICT=$verdict"
    echo "cell=$CELL"
    echo "topology=$TOPOLOGY"
    echo "placement=$PLACEMENT"
    echo "backend=$EXEC_BACKEND"
    echo "accel=$ACCEL_POLICY"
    echo "entry=typed_wvm_ctl_node_runtime"
    echo "legacy_cli=0"
    echo "login_ok=$login_ok"
    echo "ssh_ok=$ssh_ok"
    echo "login_at=${login_at:-}"
    echo "ssh_at=${ssh_at:-}"
    echo "q_alive=$q_alive"
    echo "remote=$remote"
    echo "remote_defer=$remote_defer"
    echo "sent=$sent"
    echo "ack_mode0=$ack0"
    echo "ack_mode1=$ack1"
    echo "fence_done=$fence_done"
    echo "push_fail=$push_fail"
    echo "remote_done_cpu2=$rd2"
    echo "remote_mem_peer=$mem_peer"
    echo "mem_stats_raw=$mem_raw"
    echo "remote_vcpu_evidence=$vcpu_ev"
    echo "remote_vcpu_evidence_kvm=$vcpu_kvm"
    echo "remote_vcpu_evidence_tcg=$vcpu_tcg"
    echo "remote_mem_evidence=$mem_ev"
    echo "ap_shutdown=$ap_shutdown"
    echo "wvm_reset=$wvm_reset"
    echo "kvm_shutdown=$kvm_shutdown"
    echo "handoff_fail=$handoff_fail"
    echo "note=moving this test does not close F05, F10, Phase 1, Phase 9, or MINIMUM_COMPLETE"
  } | tee "$ART/verdict.txt"
  cat "$ART/score.txt" >>"$ART/verdict.txt"

  mkdir -p "$SHARED/node-a-logs"
  cp -f "$ART/verdict.txt" "$ART/score.txt" "$ART/runner.log" "$tmpdir/ctl.log" \
    "$tmpdir/agent-a.log" "$ART/vm.log" "$ART/vm-serial.log" "$create_out" \
    "$SHARED/node-a-logs/" 2>/dev/null || true
  date '+%Y-%m-%d %H:%M:%S %Z' >"$SHARED/DONE"

  if [[ -x $tmpdir/submit_stop_vm ]]; then
    "$tmpdir/submit_stop_vm" "$tmpdir/ctl.sock" >/dev/null 2>&1 || true
    sleep 2
  fi
  for p in "$agent_pid" "$gw_pid" "$ctl_pid"; do
    kill -TERM "$p" 2>/dev/null || true
  done
  sleep 1
  pkill -x qemu-system-x86_64 2>/dev/null || true
  for p in "$agent_pid" "$gw_pid" "$ctl_pid"; do
    kill -KILL "$p" 2>/dev/null || true
  done
  refuse_legacy || true
  log "node A finished verdict=$verdict art=$ART"
  [[ $verdict == PASS ]]
}

cleanup_stale() {
  for name in qemu-system-x86_64 wavevm_node_runtime wvm_ctl wavevm_gateway; do
    pids=$(pidof "$name" 2>/dev/null || true)
    if [[ -n $pids ]]; then
      kill -TERM $pids 2>/dev/null || true
    fi
  done
  sleep 1
  for name in qemu-system-x86_64 wavevm_node_runtime wvm_ctl wavevm_gateway; do
    pids=$(pidof "$name" 2>/dev/null || true)
    if [[ -n $pids ]]; then
      kill -KILL $pids 2>/dev/null || true
    fi
  done
}

case "$ROLE" in
  B) run_node_b ;;
  A)
    cleanup_stale
    trap 'date "+%Y-%m-%d %H:%M:%S %Z" >"$SHARED/DONE" 2>/dev/null || true; cleanup_stale' EXIT
    run_node_a
    ;;
esac

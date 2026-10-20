#!/usr/bin/env bash
# Structural oracle: sigsegv_handler must not perform sync page IPC.
# Refs: docs/specs/capability-fault-engines.md section 4.2 / V1 non-goal
# (no network RPC / blocking work in the async signal handler).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
src="$repo_root/wavevm-qemu/accel/wavevm/wavevm-user-mem.c"

if [[ ! -f "$src" ]]; then
  echo "FAIL: missing $src" >&2
  exit 1
fi

python3 - "$src" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
text = src.read_text()

start = text.find("static void sigsegv_handler(int sig, siginfo_t *si, void *ucontext)")
if start < 0:
    print("FAIL: sigsegv_handler not found")
    sys.exit(1)

brace = text.find("{", start)
depth = 0
end = None
for i in range(brace, len(text)):
    ch = text[i]
    if ch == "{":
        depth += 1
    elif ch == "}":
        depth -= 1
        if depth == 0:
            end = i + 1
            break
if end is None:
    print("FAIL: could not bound sigsegv_handler")
    sys.exit(1)

body = text[start:end]
forbidden = [
    "request_page_sync(",
    "request_page_over_ipc(",
    "write_all_fd(",
    "internal_connect_master(",
    "connect(",
    "sendto(",
    "recvfrom(",
    "malloc(",
]
bad = [f for f in forbidden if f in body]
if bad:
    print("FAIL: sigsegv_handler still contains sync/IPC calls:", ", ".join(bad))
    sys.exit(1)

required = [
    "submit_fault_to_worker_or_die(",
]
missing = [r for r in required if r not in body]
if missing:
    print("FAIL: sigsegv_handler missing deferred submit:", ", ".join(missing))
    sys.exit(1)

# Worker must exist and may own the IPC calls.
if "resolve_fault_on_worker(" not in text or "fault_worker_thread_fn" not in text:
    print("FAIL: deferred fault worker symbols missing")
    sys.exit(1)
if "start_fault_worker(" not in text:
    print("FAIL: start_fault_worker missing")
    sys.exit(1)

# Ensure request_page_over_ipc is not reachable only from handler: it may live
# in request_page_sync / resolve_fault_on_worker (non-signal context).
print("PASS: sigsegv_handler has no sync IPC; deferred worker path present")
PY

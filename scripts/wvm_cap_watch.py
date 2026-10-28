#!/usr/bin/env python3
"""Periodically bound DEST to CAP bytes in-place (same inode).

For long-lived writers that outlive the launcher shell (KEEP_RUNNING).
Unlike mv-based truncate, open(path,'r+b')+truncate keeps the writer's fd
valid so growth cannot escape to an unlinked inode (Joe disk-full).
Exits when --pid dies (if given) or after --max-sec.
"""
from __future__ import annotations

import argparse
import os
import sys
import time


def rotate_inplace(path: str, cap: int) -> int:
    try:
        sz = os.path.getsize(path)
    except FileNotFoundError:
        return 0
    if sz <= cap:
        return 0
    head_keep = max(1024, cap // 4)
    tail_keep = max(1024, cap - head_keep)
    with open(path, "rb") as rf:
        head = rf.read(head_keep)
        rf.seek(max(0, sz - tail_keep))
        tail = rf.read()
    marker = f"\n=== wvm_cap_watch rotate was={sz} cap={cap} ===\n".encode()
    with open(path, "r+b") as wf:
        wf.seek(0)
        wf.write(head)
        wf.write(marker)
        wf.write(tail)
        wf.truncate()
        wf.flush()
    return sz


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dest")
    ap.add_argument("cap", nargs="?", type=int, default=0)
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--interval", type=float, default=15.0)
    ap.add_argument("--max-sec", type=float, default=0.0)
    args = ap.parse_args()
    cap = args.cap or int(
        os.environ.get(
            "WVM_S6_LOG_CAP_BYTES",
            os.environ.get("WVM_GUEST_SMOKE_LOG_CAP_BYTES", str(64 * 1024 * 1024)),
        )
    )
    if cap < 4096:
        cap = 4096
    start = time.time()
    while True:
        rotate_inplace(args.dest, cap)
        if args.pid and not os.path.exists(f"/proc/{args.pid}"):
            rotate_inplace(args.dest, cap)
            return 0
        if args.max_sec and (time.time() - start) >= args.max_sec:
            rotate_inplace(args.dest, cap)
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())

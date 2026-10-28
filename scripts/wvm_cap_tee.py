#!/usr/bin/env python3
"""Cap a live stdout/stderr stream to DEST within CAP bytes (head+tail rotate).

Writer holds the pipe, not the dest inode, so rotation never leaves a growing
unlinked file (Joe 2026-10-26 disk-full). Default cap 64MiB.
"""
from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: wvm_cap_tee.py DEST [CAP_BYTES]", file=sys.stderr)
        return 2
    dest = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else int(
        os.environ.get(
            "WVM_GUEST_SMOKE_LOG_CAP_BYTES",
            os.environ.get("WVM_S6_LOG_CAP_BYTES", str(64 * 1024 * 1024)),
        )
    )
    if cap < 4096:
        cap = 4096
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)
    head_keep = max(1024, cap // 4)
    tail_keep = max(1024, cap - head_keep)
    rotated = 0
    out = open(dest, "wb")
    try:
        while True:
            b = sys.stdin.buffer.read(65536)
            if not b:
                break
            out.write(b)
            out.flush()
            size = out.tell()
            if size < cap:
                continue
            out.close()
            with open(dest, "rb") as rf:
                data = rf.read()
            head = data[:head_keep]
            tail = data[-tail_keep:] if len(data) > tail_keep else data
            rotated += 1
            marker = (
                f"\n=== wvm_cap_tee rotate#{rotated} was={len(data)} cap={cap} ===\n"
            ).encode()
            out = open(dest, "wb")
            out.write(head)
            out.write(marker)
            out.write(tail)
            out.flush()
    finally:
        try:
            out.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

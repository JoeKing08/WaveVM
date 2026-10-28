#!/usr/bin/env python3
"""Watch Cirros serial; on size stall dump FE/helper stacks (attach18-style)."""
import os, sys, time, subprocess, signal
from pathlib import Path

def log(msg):
    print(f"[hang-watch {time.strftime('%H:%M:%S')}] {msg}", flush=True)

def pids_matching(substrs):
    out = []
    try:
        ps = subprocess.check_output(["ps", "-eo", "pid,args"], text=True)
    except Exception as e:
        log(f"ps failed: {e}")
        return out
    for line in ps.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid, args = parts[0], parts[1]
        if any(s in args for s in substrs):
            try:
                out.append(int(pid))
            except ValueError:
                pass
    return out

def dump_stacks(dest: Path, tag: str, art: Path):
    dest.mkdir(parents=True, exist_ok=True)
    slot = dest / tag
    slot.mkdir(parents=True, exist_ok=True)
    diag = []
    serial = art / "vm-serial.log"
    size = serial.stat().st_size if serial.exists() else -1
    diag.append(f"tag={tag} serial_bytes={size} ts={time.strftime('%F %T')}")
    # FE = qemu with hostfwd / Cirros; helpers = slave qemu
    pids = pids_matching(["qemu-system-x86_64", "wavevm_node_runtime", "slave_hybrid"])
    diag.append(f"pids={pids}")
    (slot / "pids.txt").write_text("\n".join(map(str, pids)) + "\n")
    for pid in pids:
        stack_path = slot / f"stack.{pid}.txt"
        # prefer eu-stack / gdb; fall back to /proc/pid/stack + wchan
        dumped = False
        for cmd in (
            ["eu-stack", "-p", str(pid)],
            ["gdb", "-batch", "-p", str(pid), "-ex", "thread apply all bt", "-ex", "detach"],
        ):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if r.returncode == 0 and (r.stdout or r.stderr):
                    stack_path.write_text((r.stdout or "") + (r.stderr or ""))
                    dumped = True
                    diag.append(f"pid={pid} via={cmd[0]} ok")
                    break
            except Exception as e:
                diag.append(f"pid={pid} {cmd[0]} err={e}")
        if not dumped:
            bits = []
            for rel in ("stack", "wchan", "status", "comm"):
                p = Path(f"/proc/{pid}/{rel}")
                if p.exists():
                    try:
                        bits.append(f"== {rel} ==\n{p.read_text(errors='replace')}")
                    except Exception as e:
                        bits.append(f"== {rel} == err {e}")
            # userspace backtrace via /proc/pid/task/*/stack if any
            stack_path.write_text("\n".join(bits) if bits else "no dump\n")
            diag.append(f"pid={pid} via=procfs")
    # tail serial
    if serial.exists():
        try:
            data = serial.read_bytes()
            (slot / "serial.tail.txt").write_bytes(data[-8000:])
        except Exception as e:
            diag.append(f"serial tail err={e}")
    (slot / "diagnosis.txt").write_text("\n".join(diag) + "\n")
    (dest / "diagnosis.txt").write_text("\n".join(diag) + "\n")
    log(f"dumped {tag} -> {slot}")

def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} ART_DIR STACK_DIR [stall_s=45] [max_dumps=4]", file=sys.stderr)
        return 2
    art = Path(sys.argv[1])
    stacks = Path(sys.argv[2])
    stall_s = int(sys.argv[3]) if len(sys.argv) > 3 else 45
    max_dumps = int(sys.argv[4]) if len(sys.argv) > 4 else 4
    serial = art / "vm-serial.log"
    stacks.mkdir(parents=True, exist_ok=True)
    log(f"watch serial={serial} stall={stall_s}s max_dumps={max_dumps}")
    last_size = -1
    last_change = time.time()
    dumps = 0
    boot_seen = False
    while dumps < max_dumps:
        time.sleep(5)
        if not serial.exists():
            continue
        try:
            size = serial.stat().st_size
        except OSError:
            continue
        if size != last_size:
            last_size = size
            last_change = time.time()
            if size > 5000:
                boot_seen = True
            continue
        # stagnant
        if not boot_seen or size < 8000:
            continue
        # Login prompt reached: serial naturally stalls; not a boot freeze.
        try:
            if b"cirros login:" in serial.read_bytes():
                log("cirros login seen — stop watching (not a freeze)")
                return 0
        except OSError:
            pass
        if time.time() - last_change < stall_s:
            continue
        dumps += 1
        dump_stacks(stacks, f"hang{dumps}", art)
        last_change = time.time()  # reset so we don't immediately re-dump
    log(f"done dumps={dumps}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

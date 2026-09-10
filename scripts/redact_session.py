#!/usr/bin/env python3
"""Redact credentials from JSON Lines session exports.

The tool preserves the JSON structure, handles plain JSONL and gzip JSONL,
creates a stable input snapshot, and replaces files atomically when
--in-place is requested. A post-redaction scan fails closed if a recognized
credential pattern remains. Large gzip outputs can be split into independently
versioned parts with an integrity manifest for Git hosting.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator


REDACTED = "[REDACTED]"

SIZE_SUFFIXES = {
    "b": 1,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
}

# These are deliberately broad. Losing one command/output string is safer
# than publishing a partial private-key block or an authentication header.
PRIVATE_KEY_RE = re.compile(r"(?i)PRIVATE[ _-]*KEY")
PUBLIC_KEY_RE = re.compile(
    r"(?im)(?<![A-Za-z0-9_-])"
    r"(?:ssh-(?:rsa|ed25519|ecdsa(?:-[A-Za-z0-9-]+)*)|ecdsa-[A-Za-z0-9-]+)"
    r"[ \t]+[A-Za-z0-9+/=]{20,}(?:[ \t]+[^\r\n]*)?"
)

TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github token", re.compile(r"(?i)(?:github_pat_|gh[pousr]_|gh_)\w+")),
    ("gitlab token", re.compile(r"(?i)glpat-[A-Za-z0-9_-]+")),
    ("circleci token", re.compile(r"(?i)CCIPAT_[A-Za-z0-9_-]+")),
    ("tailscale token", re.compile(r"(?i)tskey-(?:api|auth)-[A-Za-z0-9_-]+")),
    ("openai-style api key", re.compile(r"(?i)sk-[A-Za-z0-9_-]{20,}")),
    ("aws access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]+\b")),
    (
        "authorization header",
        re.compile(
            r"(?i)\b(?:authorization|proxy-authorization):[ \t]*"
            r"(?:bearer|basic)[ \t]+\S+"
        ),
    ),
)

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "credential",
    "authorization",
    "bearer",
    "ssh_key",
    "sshkey",
}


def is_sensitive_field(name: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", normalized).strip("_").lower()
    return normalized in SENSITIVE_FIELD_NAMES or any(
        normalized.endswith(f"_{suffix}") for suffix in SENSITIVE_FIELD_NAMES
    )


def redact_string(value: str, literals: tuple[str, ...]) -> tuple[str, int]:
    # A private key may be truncated and contain only one boundary. Replace
    # the complete scalar instead of trying to reconstruct the key block.
    if PRIVATE_KEY_RE.search(value):
        return REDACTED, 1

    result = value
    changes = 0
    result, count = PUBLIC_KEY_RE.subn(REDACTED, result)
    changes += count
    for _label, pattern in TOKEN_PATTERNS:
        result, count = pattern.subn(REDACTED, result)
        changes += count
    for literal in literals:
        if literal and literal in result:
            result = result.replace(literal, REDACTED)
            changes += 1
    return result, changes


def redact_value(
    value: Any, literals: tuple[str, ...], key_context: bool = False
) -> tuple[Any, int]:
    if isinstance(value, str):
        if key_context and value not in ("", REDACTED):
            return REDACTED, 1
        return redact_string(value, literals)
    if isinstance(value, list):
        result_list: list[Any] = []
        count = 0
        for item in value:
            redacted, item_count = redact_value(item, literals, key_context)
            result_list.append(redacted)
            count += item_count
        return result_list, count
    if isinstance(value, dict):
        result_dict: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            key_text = str(key)
            redacted_key = key_text
            key_count = 0
            redacted_item, item_count = redact_value(
                item, literals, key_context or is_sensitive_field(key_text)
            )
            result_dict[redacted_key] = redacted_item
            count += key_count + item_count
        return result_dict, count
    if key_context and value is not None:
        return REDACTED, 1
    return value, 0


def iter_records(path: Path) -> Iterator[tuple[int, Any]]:
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", newline="") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                raise ValueError(f"line {line_number}: blank JSONL record")
            try:
                yield line_number, json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc


def write_jsonl(path: Path, records: Iterator[tuple[int, Any]], literals: tuple[str, ...]) -> int:
    opener = gzip.open if path.name.endswith(".gz") else open
    changes = 0
    with opener(path, "wt", encoding="utf-8", newline="") as target:
        for _line_number, record in records:
            redacted, count = redact_value(record, literals)
            target.write(json.dumps(redacted, ensure_ascii=False, separators=(",", ":")))
            target.write("\n")
            changes += count
        target.flush()
        os.fsync(target.fileno())
    return changes


def scan_output(path: Path) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    for line_number, record in iter_records(path):
        for value in scalar_values(record):
            if PRIVATE_KEY_RE.search(value):
                findings.append((line_number, "private-key marker"))
            if PUBLIC_KEY_RE.search(value):
                findings.append((line_number, "SSH public key"))
            for label, pattern in TOKEN_PATTERNS:
                if pattern.search(value):
                    findings.append((line_number, label))
    return findings


def parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([kmgt]?i?b)?\s*", value, re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError(
            "size must be a positive integer with an optional B, KiB, MiB, GiB, "
            "KB, MB, or GB suffix"
        )
    amount = int(match.group(1))
    suffix = (match.group(2) or "b").lower()
    size = amount * SIZE_SUFFIXES[suffix]
    if size <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return size


def split_archive(archive_path: Path, output_path: Path, part_size: int) -> tuple[Path, int]:
    """Split a verified archive and write a manifest beside its parts."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    part_prefix = f"{output_path.name}.part-"
    part_pattern = re.compile(re.escape(part_prefix) + r"\d{6}$")
    old_parts = {
        path
        for path in output_path.parent.iterdir()
        if path.is_file() and part_pattern.fullmatch(path.name)
    }
    temporary_parts: list[tuple[Path, Path]] = []
    digest = hashlib.sha256()
    total_bytes = 0
    part_count = 0

    try:
        with archive_path.open("rb") as source:
            while True:
                chunk = source.read(part_size)
                if not chunk:
                    break
                digest.update(chunk)
                total_bytes += len(chunk)
                part_count += 1
                final_path = output_path.parent / f"{part_prefix}{part_count:06d}"
                fd, temporary_name = tempfile.mkstemp(
                    prefix=f".{final_path.name}.", suffix=".tmp", dir=output_path.parent
                )
                temporary_path = Path(temporary_name)
                try:
                    with os.fdopen(fd, "wb") as target:
                        target.write(chunk)
                        target.flush()
                        os.fsync(target.fileno())
                except Exception:
                    temporary_path.unlink(missing_ok=True)
                    raise
                temporary_parts.append((temporary_path, final_path))

        if part_count == 0:
            raise ValueError("cannot split an empty archive")

        for temporary_path, final_path in temporary_parts:
            os.replace(temporary_path, final_path)

        manifest_path = Path(f"{output_path}.manifest.json")
        manifest = {
            "format": "wavevm-session-archive-shards",
            "archive": output_path.name,
            "compression": "gzip",
            "part_prefix": part_prefix,
            "part_count": part_count,
            "part_size_bytes": part_size,
            "compressed_size_bytes": total_bytes,
            "sha256": digest.hexdigest(),
            "restore": f"cat {part_prefix}* > {output_path.name}",
        }
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{manifest_path.name}.", suffix=".tmp", dir=output_path.parent
        )
        temporary_manifest = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as target:
                json.dump(manifest, target, indent=2, sort_keys=True)
                target.write("\n")
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary_manifest, manifest_path)
        except Exception:
            temporary_manifest.unlink(missing_ok=True)
            raise

        # A valid manifest makes the new parts recoverable. Only then retire
        # an older whole archive and any surplus parts from a previous split.
        output_path.unlink(missing_ok=True)
        for stale_path in old_parts - {final_path for _temporary, final_path in temporary_parts}:
            stale_path.unlink()
        return manifest_path, part_count
    finally:
        for temporary_path, _final_path in temporary_parts:
            temporary_path.unlink(missing_ok=True)


def scalar_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from scalar_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from scalar_values(item)


def process(
    input_path: Path,
    output_path: Path,
    literals: tuple[str, ...],
    snapshot_dir: Path,
) -> tuple[int, list[tuple[int, str]]]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    source_mode = stat.S_IMODE(input_path.stat().st_mode)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_fd, snapshot_name = tempfile.mkstemp(
        prefix=f".{input_path.name}.", suffix=input_path.suffix, dir=snapshot_dir
    )
    os.close(snapshot_fd)
    snapshot_path = Path(snapshot_name)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=output_path.suffix, dir=output_path.parent
    )
    os.close(fd)
    temporary_path = Path(temporary_name)
    try:
        # Copy first so an actively growing rollout produces one stable backup.
        shutil.copyfile(input_path, snapshot_path)
        changes = write_jsonl(temporary_path, iter_records(snapshot_path), literals)
        findings = scan_output(temporary_path)
        if findings:
            preview = ", ".join(f"line {line}: {kind}" for line, kind in findings[:8])
            raise ValueError(f"post-redaction scan failed ({preview})")
        os.chmod(temporary_path, source_mode)
        os.replace(temporary_path, output_path)
        return changes, []
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    finally:
        snapshot_path.unlink(missing_ok=True)


def load_literals(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    values = tuple(line.rstrip("\r\n") for line in path.read_text(encoding="utf-8").splitlines())
    return tuple(value for value in values if value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="JSONL or JSONL.GZ files")
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="replace each input atomically; otherwise use --output-dir",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="write redacted files here, preserving each input filename",
    )
    parser.add_argument(
        "--secrets-file",
        type=Path,
        help="optional local file with one additional secret literal per line",
    )
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        help="directory for transient input snapshots (default: output directory)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="exact output path; only valid with one input",
    )
    parser.add_argument(
        "--split-size",
        type=parse_size,
        metavar="SIZE",
        help=(
            "after redaction, split the complete gzip archive into parts no larger "
            "than SIZE and write a SHA-256 manifest (for example 45MiB)"
        ),
    )
    args = parser.parse_args()
    if args.in_place and args.output_dir:
        parser.error("--in-place and --output-dir are mutually exclusive")
    if args.in_place and args.output:
        parser.error("--in-place and --output are mutually exclusive")
    if args.output and len(args.inputs) != 1:
        parser.error("--output requires exactly one input")
    if args.split_size is not None and args.in_place:
        parser.error("--split-size cannot be used with --in-place")
    if args.split_size is not None and not (args.output or args.output_dir):
        parser.error("--split-size requires --output or --output-dir")
    if args.split_size is not None:
        split_targets = [args.output] if args.output else [
            args.output_dir / input_path.name for input_path in args.inputs
        ]
        if any(not target.name.endswith(".gz") for target in split_targets):
            parser.error("--split-size requires gzip output paths ending in .gz")
    if not args.in_place and not args.output_dir:
        if not args.output:
            parser.error("choose --in-place, --output, or --output-dir")
    return args


def main() -> int:
    args = parse_args()
    literals = load_literals(args.secrets_file)
    total = 0
    for input_path in args.inputs:
        if not input_path.is_file():
            print(f"error: file not found: {input_path}", file=sys.stderr)
            return 2
        if args.in_place:
            output_path = input_path
        elif args.output:
            output_path = args.output
        else:
            output_path = args.output_dir / input_path.name
        snapshot_dir = args.snapshot_dir or output_path.parent
        archive_path: Path | None = None
        try:
            if args.split_size is None:
                count, _ = process(input_path, output_path, literals, snapshot_dir)
                print(f"{input_path}: redacted {count} JSON value(s) -> {output_path}")
            else:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary_name = tempfile.mkstemp(
                    prefix=f".{output_path.name}.archive.",
                    suffix=".gz",
                    dir=output_path.parent,
                )
                os.close(fd)
                archive_path = Path(temporary_name)
                count, _ = process(input_path, archive_path, literals, snapshot_dir)
                manifest_path, part_count = split_archive(
                    archive_path, output_path, args.split_size
                )
                print(
                    f"{input_path}: redacted {count} JSON value(s) -> "
                    f"{part_count} parts + {manifest_path}"
                )
        except (OSError, ValueError) as exc:
            print(f"error: {input_path}: {exc}", file=sys.stderr)
            return 1
        finally:
            if archive_path is not None:
                archive_path.unlink(missing_ok=True)
        total += count
    print(f"total redacted JSON values: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

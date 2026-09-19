#!/usr/bin/env python3
"""Focused tests for the session backup shard naming and restore command."""

import gzip
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "redact_session.py"
split_archive = runpy.run_path(str(SCRIPT))["split_archive"]


class SplitArchiveTests(unittest.TestCase):
    def test_numeric_shards_restore_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="wavevm-backup-test-") as tmp:
            directory = Path(tmp)
            source = directory / "source.gz"
            output = directory / "session backup.gz"
            payload = bytes(range(256)) * 32
            compressed = gzip.compress(payload)
            source.write_bytes(compressed)
            old = directory / f"{output.name}.part-000001"
            stale = directory / f"{output.name}.999"
            unrelated = directory / f"{output.name}.001.notes"
            for path in (old, stale, unrelated):
                path.write_bytes(b"keep unless an obsolete shard")

            manifest_path, count = split_archive(source, output, 80)
            manifest = json.loads(manifest_path.read_text())
            self.assertGreater(count, 1)
            self.assertEqual(manifest["part_prefix"], f"{output.name}.")
            parts = [directory / f"{output.name}.{i:03d}" for i in range(1, count + 1)]
            restored = b"".join(path.read_bytes() for path in parts)
            self.assertEqual(restored, compressed)
            self.assertEqual(hashlib.sha256(restored).hexdigest(), manifest["sha256"])
            self.assertFalse(old.exists())
            self.assertFalse(stale.exists())
            self.assertTrue(unrelated.exists())
            subprocess.run(manifest["restore"], shell=True, cwd=directory, check=True)
            self.assertEqual(gzip.decompress(output.read_bytes()), payload)

            _, count = split_archive(source, output, len(compressed))
            self.assertEqual(count, 1)
            self.assertFalse(output.exists())
            self.assertTrue(parts[0].exists())
            self.assertTrue(all(not path.exists() for path in parts[1:]))
            self.assertTrue(unrelated.exists())

    def test_too_many_parts_leaves_existing_backup_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="wavevm-backup-test-") as tmp:
            directory = Path(tmp)
            source = directory / "source.gz"
            output = directory / "session.gz"
            existing = directory / "session.gz.001"
            source.write_bytes(b"x" * 1000)
            existing.write_bytes(b"previous backup")
            with self.assertRaisesRegex(ValueError, "999"):
                split_archive(source, output, 1)
            self.assertEqual(existing.read_bytes(), b"previous backup")
            self.assertEqual(set(directory.iterdir()), {source, existing})


if __name__ == "__main__":
    unittest.main()

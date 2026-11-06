"""Reject single-byte Windows ZIP executable corruption, then restore release.

Synthetic PE headers and host ZIP CRC checks; not native executable proof.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

import test_release_archive_validation as fixture


class WindowsMemberCrcRecovery(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ores-win-crc-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for target in fixture.TARS:
            fixture.make_tar(self.root / target, [
                ("atto", b"binary", "file"), ("oreslang", b"binary", "file"),
            ])
        self.rebuild_windows()

    def rebuild_windows(self):
        fixture.make_zip(self.root / fixture.ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])

    def validate(self, expected):
        result = subprocess.run(
            [sys.executable, "-c", fixture.SCRIPT, str(self.root)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode == 0, expected, result.stderr)
        return result

    def test_each_member_detects_content_corruption_without_header_change(self):
        self.validate(True)
        archive_path = self.root / fixture.ZIP
        baseline = archive_path.read_bytes()
        for name in ("atto.exe", "oreslang.exe"):
            with self.subTest(member=name):
                self.rebuild_windows()
                with zipfile.ZipFile(archive_path) as archive:
                    info = archive.getinfo(name)
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                    offset = info.header_offset + 30 + len(name.encode("utf-8")) + len(info.extra)
                    self.assertGreater(info.file_size, 240)
                corrupted = bytearray(archive_path.read_bytes())
                corrupted[offset + 240] ^= 0x01
                archive_path.write_bytes(corrupted)
                failure = self.validate(False)
                self.assertIn("Bad CRC-32", failure.stderr,
                              "failure must be CRC integrity, not invalid PE header")
                self.rebuild_windows()
                self.validate(True)
                self.assertEqual(archive_path.read_bytes(), baseline)


if __name__ == "__main__":
    unittest.main()

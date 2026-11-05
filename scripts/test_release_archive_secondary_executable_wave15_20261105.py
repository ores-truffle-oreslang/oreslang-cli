"""Verify that the release archive gate checks both executable aliases, host-only."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_release_archive_validation import (
    TARS, ZIP, SCRIPT, make_tar, make_zip, synthetic_executable,
)


class SecondaryExecutableValidation(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for archive in TARS:
            self.write_unix(archive, b"binary")
        self.write_windows(b"binary")

    def write_unix(self, archive, second):
        make_tar(self.root / archive, [
            ("atto", b"binary", "file"),
            ("oreslang", second, "file"),
        ])

    def write_windows(self, second):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", second, "file"),
        ])

    def check(self, accepted):
        result = subprocess.run(
            [sys.executable, "-c", SCRIPT, str(self.root)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_valid_both_aliases_for_every_platform(self):
        self.check(True)

    def test_invalid_secondary_header_rejected_on_all_platforms(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                self.write_unix(archive, b"not an executable")
                self.check(False)
                self.write_unix(archive, b"binary")
        with self.subTest(archive=ZIP):
            self.write_windows(b"not an executable")
            self.check(False)

    def test_empty_secondary_executable_rejected_on_all_platforms(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                self.write_unix(archive, b"")
                self.check(False)
                self.write_unix(archive, b"binary")
        self.write_windows(b"")
        self.check(False)

    def test_wrong_cpu_rejected_in_secondary_unix_executable(self):
        for archive, wrong_cpu in (
            (TARS[0], 183),  # ELF AArch64 instead of x86_64
            (TARS[1], 0x0100000c),  # Mach-O arm64 instead of x86_64
            (TARS[2], 0x01000007),  # Mach-O x86_64 instead of arm64
        ):
            with self.subTest(archive=archive):
                header = bytearray(synthetic_executable(archive))
                offset = 18 if archive == TARS[0] else 4
                width = 2 if archive == TARS[0] else 4
                header[offset:offset + width] = wrong_cpu.to_bytes(width, "little")
                self.write_unix(archive, bytes(header))
                self.check(False)
                self.write_unix(archive, b"binary")

    def test_wrong_cpu_rejected_in_secondary_windows_executable(self):
        header = bytearray(synthetic_executable(ZIP))
        header[132:134] = (0xAA64).to_bytes(2, "little")
        self.write_windows(bytes(header))
        self.check(False)


if __name__ == "__main__":
    unittest.main(verbosity=2)

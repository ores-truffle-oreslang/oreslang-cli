"""Source-owned release-publisher format admission matrix.

These binaries are synthetic headers, not runnable native compiler evidence.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

import test_release_archive_validation as fixture


class CrossArchitectureSecondaryMemberFence(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="atto-3506-")
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.build_clean()

    def build_clean(self):
        for target in fixture.TARS:
            fixture.make_tar(self.root / target, [
                ("atto", b"binary", "file"), ("oreslang", b"binary", "file"),
            ])
        fixture.make_zip(self.root / fixture.ZIP, [
            ("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file"),
        ])

    def check(self, success):
        proc = subprocess.run(
            [sys.executable, "-c", fixture.SCRIPT, str(self.root)],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode == 0, success, proc.stderr)

    def test_cross_target_headers_are_denied_even_on_only_secondary_binary(self):
        substitutions = [
            (fixture.TARS[0], fixture.TARS[1]),  # Mach-O inside Linux release
            (fixture.TARS[1], fixture.TARS[0]),  # ELF inside Intel macOS release
            (fixture.TARS[2], fixture.TARS[1]),  # Intel Mach-O inside arm64 release
            (fixture.ZIP, fixture.TARS[0]),      # ELF inside Windows release
        ]
        self.check(True)
        for target, foreign in substitutions:
            with self.subTest(target=target, foreign=foreign):
                bad = fixture.synthetic_executable(foreign)
                if target == fixture.ZIP:
                    fixture.make_zip(self.root / target, [
                        ("atto.exe", b"binary", "file"),
                        ("oreslang.exe", bad, "file"),
                    ])
                else:
                    fixture.make_tar(self.root / target, [
                        ("atto", b"binary", "file"),
                        ("oreslang", bad, "file"),
                    ])
                self.check(False)
                self.build_clean()
                self.check(True)


if __name__ == "__main__":
    unittest.main()

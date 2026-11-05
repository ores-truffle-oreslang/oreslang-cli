"""Host-only synthetic archives: secondary binary must match each target."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class SecondaryTargetFormatAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_must_match_linux_and_both_macos_targets(self):
        cases = [
            (TARS[0], TARS[1]),  # Mach-O in an ELF package
            (TARS[1], TARS[2]),  # arm64 inside x86_64 macOS
            (TARS[2], TARS[1]),  # x86_64 inside arm64 macOS
        ]
        for archive, foreign in cases:
            with self.subTest(archive=archive, foreign=foreign):
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", synthetic_executable(foreign), "file"),
                ])
                self.verify(False)
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", b"binary", "file"),
                ])
                self.verify(True)

    def test_secondary_windows_executable_cannot_hide_a_macho_header(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", synthetic_executable(TARS[1]), "file"),
        ])
        self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

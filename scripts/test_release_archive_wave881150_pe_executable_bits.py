"""Real inline release-publisher test: both Windows aliases require executable COFF bits.

These are host archive-admission tests, not execution of compiled guest binaries.
"""
import unittest

from test_release_archive_validation import (
    ZIP,
    ReleaseArchiveValidation,
    make_zip,
    synthetic_executable,
)


class WindowsExecutableBitsBoundary(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_missing_executable_bit_in_either_alias_fails_then_recovers(self):
        canonical = synthetic_executable(ZIP)
        # Flags whose other bits cannot substitute for IMAGE_FILE_EXECUTABLE_IMAGE.
        for target in ("atto.exe", "oreslang.exe"):
            for flags in (0x0000, 0x0001, 0x0100, 0x2000):
                with self.subTest(target=target, flags=flags):
                    broken = bytearray(canonical)
                    broken[150:152] = flags.to_bytes(2, "little")
                    make_zip(self.root / ZIP, [
                        ("atto.exe", bytes(broken) if target == "atto.exe" else canonical, "file"),
                        ("oreslang.exe", bytes(broken) if target == "oreslang.exe" else canonical, "file"),
                    ])
                    self.verify(False)
                    # Rebuilding both bytes proves the validator's error path does
                    # not leave a poisoned cached admission or modify Unix peers.
                    make_zip(self.root / ZIP, [
                        ("atto.exe", canonical, "file"),
                        ("oreslang.exe", canonical, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Release packager must refuse COFF images lacking executable flag on both aliases.

Synthetic PE headers test source-owned publisher admission only; the fixtures
are not runnable native executables or AttoLang compiler guest evidence.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class WindowsExecutableFlagMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_alias_denies_nonexecutable_coff_and_restores_valid(self):
        original = synthetic_executable(ZIP)
        for member in ("atto.exe", "oreslang.exe"):
            for flags in (0, 0x0020):
                with self.subTest(member=member, flags=flags):
                    bad = bytearray(original)
                    bad[150:152] = flags.to_bytes(2, "little")
                    make_zip(self.root / ZIP, [
                        ("atto.exe", bytes(bad) if member == "atto.exe" else original, "file"),
                        ("oreslang.exe", bytes(bad) if member == "oreslang.exe" else original, "file"),
                    ])
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        ("atto.exe", original, "file"),
                        ("oreslang.exe", original, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Wrong executable flags or PE32 type in the SECOND Windows alias fail closed.

Uses synthetic headers with the real source-free release archive validator.
No executable guest, native compilation, signature or release claim.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class Next5SecondaryPeRecovery(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_windows_executable_flag_and_format_are_independent(self):
        good = synthetic_executable(ZIP)
        bad_flags = bytearray(good)
        bad_flags[150:152] = (0).to_bytes(2, "little")
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", bytes(bad_flags), "file"),
        ])
        archive = self.root / ZIP
        saved = archive.read_bytes()
        self.verify(False)
        self.assertEqual(archive.read_bytes(), saved)

        wrong_optional_type = bytearray(good)
        wrong_optional_type[152:154] = (0x010B).to_bytes(2, "little")
        make_zip(archive, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", bytes(wrong_optional_type), "file"),
        ])
        self.verify(False)
        make_zip(archive, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

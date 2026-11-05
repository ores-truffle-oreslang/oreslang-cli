"""Host-only source release admission for Windows COFF executable flags.

Synthetic format headers are not runnable Windows binaries.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class SecondaryWindowsCoffExecutableAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_pe_without_coff_executable_bit_is_rejected(self):
        valid = synthetic_executable(ZIP)
        invalid = bytearray(valid)
        # Keep DOS/PE signatures, AMD64 machine and PE32+ optional-header magic.
        # Removing IMAGE_FILE_EXECUTABLE_IMAGE alone must revoke admission.
        invalid[150:152] = (0).to_bytes(2, "little")
        self.assertEqual(invalid[128:134], valid[128:134])
        self.assertEqual(invalid[152:154], valid[152:154])

        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", bytes(invalid), "file"),
        ])
        self.verify(False)

        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", valid, "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

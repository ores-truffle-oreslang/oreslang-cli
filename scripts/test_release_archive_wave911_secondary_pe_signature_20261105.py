"""Host-only secondary Windows executable signature admission and recovery.

Synthetic PE headers are structural fixtures, not verified runnable executables.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class SecondaryWindowsPESignatureWave911(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_member_with_broken_pe_signature_fails_then_repairs(self):
        invalid = bytearray(synthetic_executable(ZIP))
        invalid[128:132] = b"NOPE"
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", bytes(invalid), "file"),
        ])
        self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)

    def test_secondary_member_with_wrong_mz_dos_prefix_fails_then_repairs(self):
        invalid = bytearray(synthetic_executable(ZIP))
        invalid[:2] = b"ZZ"
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", bytes(invalid), "file"),
        ])
        self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

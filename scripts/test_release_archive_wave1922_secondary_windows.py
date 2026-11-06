"""Regression: the second Windows executable must carry its own valid PE header.

This exercises source publisher structural checks using synthetic headers, not
native executable or compiled AttoLang guest evidence.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class SecondaryWindowsPEAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def _secondary(self, payload):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", payload, "file"),
        ])

    def test_secondary_foreign_cpu_rejected_independent_of_primary(self):
        invalid = bytearray(synthetic_executable(ZIP))
        invalid[132:134] = (0xAA64).to_bytes(2, "little")  # ARM64, not AMD64
        self._secondary(bytes(invalid))
        self.verify(False)
        self._secondary(b"binary")
        self.verify(True)

    def test_secondary_invalid_pe_signature_rejected_independent_of_primary(self):
        invalid = bytearray(synthetic_executable(ZIP))
        invalid[128:132] = b"NOPE"
        self._secondary(bytes(invalid))
        self.verify(False)
        self._secondary(b"binary")
        self.verify(True)

    def test_secondary_invalid_pe_offset_rejected_independent_of_primary(self):
        invalid = bytearray(synthetic_executable(ZIP))
        invalid[0x3c:0x40] = (0xFFFF).to_bytes(4, "little")
        self._secondary(bytes(invalid))
        self.verify(False)
        self._secondary(b"binary")
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

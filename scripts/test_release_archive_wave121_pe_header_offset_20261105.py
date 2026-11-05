"""Synthetic Windows release archive PE-offset integrity tests.

Executable header checks are source-free release admission, not native code execution.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable
)


class WindowsPortableExecutableOffsetMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_executable_aliases_reject_invalid_pe_offsets(self):
        for member in ("atto.exe", "oreslang.exe"):
            for offset in (0, 63, 233, 0xffffffff):
                with self.subTest(binary=member, offset=offset):
                    wrong = bytearray(synthetic_executable(ZIP))
                    wrong[0x3c:0x40] = offset.to_bytes(4, "little")
                    make_zip(self.root / ZIP, [
                        (name, bytes(wrong) if name == member else b"binary", "file")
                        for name in ("atto.exe", "oreslang.exe")
                    ])
                    self.verify(False)

    def test_valid_canonical_pe_offset_remains_admitted(self):
        make_zip(self.root / ZIP, [
            (name, b"binary", "file") for name in ("atto.exe", "oreslang.exe")
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

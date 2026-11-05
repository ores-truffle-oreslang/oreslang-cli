"""Synthetic ZIP member admission, not a runnable Windows release test."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable
)


class SecondaryWindowsPEHeaderWave58(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_pe_signature_machine_and_magic_must_be_valid(self):
        original = synthetic_executable(ZIP)
        mutations = (
            (0, b"ZZ"),                 # DOS magic
            (128, b"NOPE"),             # PE signature
            (132, b"\x64\xaa"),       # ARM64 COFF, not AMD64
            (152, b"\x0b\x01"),       # PE32 instead of PE32+
        )
        for offset, replacement in mutations:
            with self.subTest(offset=offset):
                corrupted = bytearray(original)
                corrupted[offset:offset + len(replacement)] = replacement
                make_zip(self.root / ZIP, [
                    ("atto.exe", b"binary", "file"),
                    ("oreslang.exe", bytes(corrupted), "file"),
                ])
                self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", original, "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

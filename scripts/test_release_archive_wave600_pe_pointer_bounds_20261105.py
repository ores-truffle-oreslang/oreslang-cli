"""Exercise real inline publisher admission on Windows DOS-to-PE offsets."""
import unittest
from test_release_archive_validation import (
    ZIP, ReleaseArchiveValidation, make_zip, synthetic_executable,
)


class PePointerBoundsWave600(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_valid_archive_remains_accepted(self):
        self.verify(True)

    def test_primary_pe_pointer_outside_header_is_rejected(self):
        for offset in (0, 63, 256, 4096, 0xFFFFFFFF):
            with self.subTest(offset=offset):
                wrong = bytearray(synthetic_executable(ZIP))
                wrong[0x3C:0x40] = offset.to_bytes(4, "little")
                make_zip(self.root / ZIP, [
                    ("atto.exe", bytes(wrong), "file"),
                    ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(False)

    def test_secondary_pe_pointer_outside_header_is_rejected(self):
        wrong = bytearray(synthetic_executable(ZIP))
        wrong[0x3C:0x40] = (0xFFFFFFFF).to_bytes(4, "little")
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", bytes(wrong), "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

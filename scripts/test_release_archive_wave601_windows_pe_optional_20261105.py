"""Source-free PE header-pointer admission; synthetic archive members only."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class SecondaryWindowsPePointerBoundaries(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_pe_pointer_boundary_refuses_invalid_offsets(self):
        original = synthetic_executable(ZIP)
        self.verify(True)
        for offset in (0, 63, 64, 232, 0xFFFFFFFF):
            with self.subTest(offset=offset):
                corrupted = bytearray(original)
                corrupted[0x3C:0x40] = offset.to_bytes(4, "little")
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

"""Host-only DOS-to-PE pointer admission and positive restoration, not native execution."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class WindowsSecondaryPEOffsetWave261106B(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_pe_out_of_bounds_offsets_are_rejected_and_recover(self):
        original = synthetic_executable(ZIP)
        for offset in (0, 32, 63, len(original) - 12, 0xfffffff0):
            with self.subTest(offset=offset):
                damaged = bytearray(original)
                damaged[0x3c:0x40] = offset.to_bytes(4, "little")
                make_zip(self.root / ZIP, [
                    ("atto.exe", b"binary", "file"),
                    ("oreslang.exe", bytes(damaged), "file"),
                ])
                self.verify(False)
                make_zip(self.root / ZIP, [
                    ("atto.exe", b"binary", "file"),
                    ("oreslang.exe", original, "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

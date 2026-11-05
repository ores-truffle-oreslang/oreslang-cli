"""Host-only release publisher negative controls for executable pair headers."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)

class ReleaseArchivePairPeRegression(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_control_archive_set_admitted(self):
        self.verify(True)

    def test_each_windows_executable_refuses_out_of_bounds_pe_offset(self):
        for damaged in ("atto.exe", "oreslang.exe"):
            with self.subTest(damaged=damaged):
                ReleaseArchiveValidation.setUp(self)
                wrong = bytearray(synthetic_executable(ZIP))
                # Keep MZ/PE signature bytes untouched; only the authoritative
                # e_lfanew pointer is redirected beyond the 256-byte payload.
                wrong[0x3c:0x40] = (0x1000).to_bytes(4, "little")
                make_zip(self.root / ZIP, [
                    ("atto.exe", bytes(wrong) if damaged == "atto.exe" else b"binary", "file"),
                    ("oreslang.exe", bytes(wrong) if damaged == "oreslang.exe" else b"binary", "file"),
                ])
                self.verify(False)

if __name__ == "__main__":
    unittest.main()

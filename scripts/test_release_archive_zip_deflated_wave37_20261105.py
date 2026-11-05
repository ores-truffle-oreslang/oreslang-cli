"""Compressed ZIP admission against the actual inline release publisher.

These fake PE headers are source-free host controls, never executable binaries.
"""
import unittest
import zipfile

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, synthetic_executable,
)


class ReleaseDeflatedZipWave37(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def write_deflated(self, *, invalid_second=False):
        archive = self.root / ZIP
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for filename in ("atto.exe", "oreslang.exe"):
                payload = synthetic_executable(ZIP) + b"\x00" * 4096
                if invalid_second and filename == "oreslang.exe":
                    payload = b"INVALID PE" + payload[10:]
                z.writestr(filename, payload, compress_type=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(archive) as z:
            self.assertEqual(sorted(z.namelist()), ["atto.exe", "oreslang.exe"])
            self.assertTrue(all(m.compress_type == zipfile.ZIP_DEFLATED for m in z.infolist()))
            self.assertTrue(all(m.file_size > 256 for m in z.infolist()))

    def test_valid_deflated_windows_release_archive_is_accepted(self):
        self.write_deflated()
        self.verify(True)

    def test_invalid_decompressed_second_executable_is_denied(self):
        self.write_deflated(invalid_second=True)
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

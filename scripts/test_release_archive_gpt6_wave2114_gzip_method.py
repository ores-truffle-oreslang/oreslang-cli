"""Actual source-owned publisher must reject invalid gzip compression methods.

The gzip method byte must remain 8 (DEFLATE), independent of the TAR member
names and CPU/ELF/Mach-O header identities. All fixtures are source-free.
"""
import unittest

from test_release_archive_validation import ReleaseArchiveValidation, TARS


class GzipMethodAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_invalid_method_fails_closed_on_every_unix_target_then_recovers(self):
        for target in TARS:
            archive = self.root / target
            original = archive.read_bytes()
            self.assertEqual(original[:3], b"\x1f\x8b\x08")
            for invalid_method in (0, 9, 255):
                with self.subTest(target=target, method=invalid_method):
                    altered = bytearray(original)
                    altered[2] = invalid_method
                    archive.write_bytes(altered)
                    self.verify(False)
                    self.assertEqual(archive.read_bytes(), bytes(altered),
                                     "verifier must not mutate bad release bytes")
                    archive.write_bytes(original)
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

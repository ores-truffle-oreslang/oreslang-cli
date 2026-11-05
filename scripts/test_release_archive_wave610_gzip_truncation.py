"""The exact release publisher must reject unreadable target archives."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation,
    TARS,
)


class Wave610GzipCorruption(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_all_unix_targets_deny_a_truncated_gzip_stream(self):
        for archive_name in TARS:
            with self.subTest(archive=archive_name):
                archive = self.root / archive_name
                original = archive.read_bytes()
                self.assertGreater(len(original), 24)
                archive.write_bytes(original[:24])
                self.verify(False)
                archive.write_bytes(original)
                self.verify(True)

    def test_invalid_gzip_header_is_rejected_even_if_payload_remains(self):
        archive = self.root / TARS[0]
        original = archive.read_bytes()
        self.assertTrue(original.startswith(b"\x1f\x8b"))
        archive.write_bytes(b"\x00\x00" + original[2:])
        self.verify(False)
        archive.write_bytes(original)
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

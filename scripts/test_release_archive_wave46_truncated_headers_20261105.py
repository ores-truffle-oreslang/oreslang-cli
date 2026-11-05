"""Negative publisher tests: truncated file headers must fail for both CLI aliases."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class TruncatedArchiveBinaryHeaders(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_unix_binary_rejects_truncated_magic_only_header(self):
        for archive in TARS:
            for short_member in ("atto", "oreslang"):
                with self.subTest(archive=archive, binary=short_member):
                    entries = [(member, b"\x7fELF" if member == short_member else b"binary", "file")
                               for member in ("atto", "oreslang")]
                    make_tar(self.root / archive, entries)
                    self.verify(False)

    def test_each_windows_binary_rejects_truncated_dos_header(self):
        for short_member in ("atto.exe", "oreslang.exe"):
            with self.subTest(binary=short_member):
                entries = [(member, b"MZ" if member == short_member else b"binary", "file")
                           for member in ("atto.exe", "oreslang.exe")]
                make_zip(self.root / ZIP, entries)
                self.verify(False)

    def test_full_synthetic_headers_remain_accepted(self):
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

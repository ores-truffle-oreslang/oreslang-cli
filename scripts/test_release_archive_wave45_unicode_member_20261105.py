"""Host-only synthetic release archives: exact member names are authority."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class UnicodeMemberIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_unicode_suffix_cannot_replace_expected_tar_executable(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                make_tar(
                    self.root / archive,
                    [("atto", b"binary", "file"),
                     ("oreslang\u200d", b"binary", "file")],
                )
                self.verify(False)
                make_tar(
                    self.root / archive,
                    [("atto", b"binary", "file"),
                     ("oreslang", b"binary", "file")],
                )
                self.verify(True)

    def test_unicode_suffix_cannot_replace_expected_windows_executable(self):
        make_zip(
            self.root / ZIP,
            [("atto.exe\u200d", b"binary", "file"),
             ("oreslang.exe", b"binary", "file")],
        )
        self.verify(False)
        make_zip(
            self.root / ZIP,
            [("atto.exe", b"binary", "file"),
             ("oreslang.exe", b"binary", "file")],
        )
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

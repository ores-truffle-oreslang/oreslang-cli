"""Host-only release archive filename authority regression, not executable proof."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class ReleaseArchiveNoncanonicalNamesWave46(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_tar_invisible_suffix_cannot_alias_primary_executable(self):
        self.verify(True)
        make_tar(self.root / TARS[0], [
            ("atto\u200b", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_tar_case_shift_cannot_alias_secondary_executable(self):
        self.verify(True)
        make_tar(self.root / TARS[1], [
            ("atto", b"binary", "file"),
            ("Oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_zip_confusable_primary_member_is_not_an_executable(self):
        self.verify(True)
        make_zip(self.root / ZIP, [
            ("att\u043e.exe", b"binary", "file"),  # Cyrillic 'o'
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

"""Source-free release archive identity controls; not a native-release receipt."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip
)


class ReleaseArchiveMemberIdentityWave44(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_archive_names_pass(self):
        self.verify(True)

    def test_windows_unicode_confusable_name_is_rejected(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang\uFF0Eexe", b"binary", "file"),
        ])
        self.verify(False)

    def test_windows_case_alias_is_rejected(self):
        make_zip(self.root / ZIP, [
            ("ATTO.EXE", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)

    def test_unix_relative_name_alias_is_rejected(self):
        make_tar(self.root / TARS[0], [
            ("./atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

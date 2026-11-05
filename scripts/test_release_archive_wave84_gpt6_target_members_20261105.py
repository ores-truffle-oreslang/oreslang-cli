"""Host-only synthetic release target name controls, not binary execution."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class TargetMemberNames(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_tar_members_named_as_parent_relative_alias_are_not_executables(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("./oreslang", b"binary", "file"),
                ])
                self.verify(False)
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", b"binary", "file"),
                ])
                self.verify(True)

    def test_zip_member_path_alias_is_not_a_windows_executable(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("./oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

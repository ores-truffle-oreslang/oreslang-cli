"""Only exact release executable filenames have authority in ZIP bundles."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, ZIP, make_zip


class Wave95WindowsExeNameAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_unmodified_release_targets_remain_admitted(self):
        self.verify(True)

    def test_case_folded_primary_executable_is_not_authoritative(self):
        make_zip(self.root / ZIP, [
            ("ATTO.EXE", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)

    def test_nested_executable_does_not_rebind_primary_name(self):
        make_zip(self.root / ZIP, [
            ("tools/atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)

    def test_extra_case_alias_cannot_hide_behind_valid_members(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
            ("ATTO.EXE", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

"""Source-owned release archive path regressions; synthetic headers are not executable proof."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip,
)


class ZipTopLevelOnlyWave44(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_exact_flat_archive_still_admitted(self):
        self.verify(True)

    def test_extra_zip_directory_is_not_accepted_as_release_payload(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
            ("bin/", b"", "file"),
        ])
        self.verify(False)

    def test_parent_traversal_name_cannot_replace_expected_executable(self):
        make_zip(self.root / ZIP, [
            ("../atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)

    def test_case_changed_member_cannot_impersonate_canonical_executable(self):
        make_zip(self.root / ZIP, [
            ("ATTO.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

"""Source-free release publisher membership regression, not a native binary receipt."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip
)


class ReleaseArchiveMemberPathsWave96(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_member_paths_pass(self):
        self.verify(True)

    def test_primary_member_absolute_or_traversal_aliases_are_rejected(self):
        for alias in (
            "./atto.exe",
            "/atto.exe",
            "C:/atto.exe",
            "nested/../atto.exe",
            "..\\atto.exe",
        ):
            with self.subTest(alias=alias):
                ReleaseArchiveValidation.setUp(self)
                make_zip(self.root / ZIP, [
                    (alias, b"binary", "file"),
                    ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(False)

    def test_secondary_member_traversal_is_rejected(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("nested/../oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

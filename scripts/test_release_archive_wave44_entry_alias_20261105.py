"""Source-owned release-archive authority tests; not runnable-binary proof."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class ReleaseArchiveEntryAliasWave44(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_unmodified_four_target_archives_remain_admitted(self):
        self.verify(True)

    def test_tar_member_using_unicode_lookalike_cannot_replace_atto(self):
        make_tar(self.root / TARS[0], [
            ("ａｔｔｏ", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_tar_extra_nested_path_is_not_a_third_distribution_member(self):
        make_tar(self.root / TARS[1], [
            ("atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
            ("docs/../atto", b"binary", "file"),
        ])
        self.verify(False)

    def test_zip_casefolded_executable_alias_cannot_replace_canonical_name(self):
        make_zip(self.root / ZIP, [
            ("ATTO.EXE", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main(verbosity=2)

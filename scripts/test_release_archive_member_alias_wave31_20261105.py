"""Check archive pathname aliases against the real release publisher admission.

Host-only synthetic binary headers do not attest to native executable behavior.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class ReleaseArchiveMemberAliasWave31(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_control_archives_still_admitted(self):
        self.verify(True)

    def test_tar_dot_slash_path_alias_is_rejected(self):
        make_tar(self.root / TARS[0], [
            ("./atto", b"binary", "file"), ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_tar_absolute_member_alias_is_rejected(self):
        make_tar(self.root / TARS[1], [
            ("/atto", b"binary", "file"), ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_zip_dot_slash_member_alias_is_rejected(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("./oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

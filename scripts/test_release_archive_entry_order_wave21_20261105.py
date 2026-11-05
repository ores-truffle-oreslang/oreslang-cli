"""Host-only publisher archive identity and order regressions."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip


class ArchiveMemberOrderWave21(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_member_order_not_a_source_of_identity_authority(self):
        for archive in TARS:
            make_tar(self.root / archive, [
                ("oreslang", b"binary", "file"),
                ("atto", b"binary", "file"),
            ])
        make_zip(self.root / ZIP, [
            ("oreslang.exe", b"binary", "file"),
            ("atto.exe", b"binary", "file"),
        ])
        self.verify(True)

    def test_tar_dot_prefix_alias_does_not_replace_canonical_name(self):
        make_tar(self.root / TARS[0], [
            ("./atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_tar_subdirectory_member_is_not_an_executable_alias(self):
        make_tar(self.root / TARS[1], [
            ("bin/atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_zip_backslash_member_alias_is_rejected(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("bin\\oreslang.exe", b"binary", "file"),
        ])
        self.verify(False)

    def test_zip_newline_member_alias_is_rejected(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe\n", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Release archive membership names must be exact, not path-normalized aliases."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, make_tar


class TarMemberNameDenial(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_absolute_primary_path_is_not_a_member_identity(self):
        make_tar(self.root / TARS[0], [
            ("/atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_parent_relative_member_path_is_not_a_member_identity(self):
        make_tar(self.root / TARS[0], [
            ("../atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_dot_relative_member_path_is_not_canonical(self):
        make_tar(self.root / TARS[0], [
            ("./atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_hidden_nested_binary_cannot_replace_expected_alias(self):
        make_tar(self.root / TARS[1], [
            ("nested/atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

"""Synthetic TAR-name publication controls; no native execution certification."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, make_tar


class CanonicalUnixArchiveMemberNames(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_dot_and_parent_aliases_never_replace_literal_executable_names(self):
        for archive in TARS:
            for wrong_name in ("./atto", "dir/atto", "dir/../atto"):
                with self.subTest(archive=archive, wrong_name=wrong_name):
                    make_tar(self.root / archive, [
                        (wrong_name, b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

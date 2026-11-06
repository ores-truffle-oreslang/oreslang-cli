"""All Unix release targets must reject unexpected TAR members."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar,
)


class Wave8110TarMemberAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_unix_target_denies_hidden_or_parent_traversing_members(self):
        for target in TARS:
            for hostile in ("./unexpected", "../outside", "nested/foreign"):
                with self.subTest(target=target, member=hostile):
                    path = self.root / target
                    make_tar(path, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                        (hostile, b"foreign", "file"),
                    ])
                    self.verify(False)
                    make_tar(path, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)

    def test_extra_directory_node_is_rejected_even_when_executables_are_valid(self):
        path = self.root / TARS[0]
        make_tar(path, [
            ("atto", b"binary", "file"),
            ("oreslang", b"binary", "file"),
            ("out-of-band/", b"", "directory"),
        ])
        self.verify(False)
        make_tar(path, [("atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

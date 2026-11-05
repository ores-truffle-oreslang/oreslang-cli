"""The secondary executable must pass the same POSIX mode security gate."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, make_tar


class SecondaryModeDenial(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_alias_requires_executable_mode(self):
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"),
            ("oreslang", b"binary", "noexec"),
        ])
        self.verify(False)

    def test_secondary_alias_must_not_have_setuid(self):
        make_tar(self.root / TARS[1], [
            ("atto", b"binary", "file"),
            ("oreslang", b"binary", "setuid"),
        ])
        self.verify(False)

    def test_secondary_alias_must_not_be_group_writable(self):
        make_tar(self.root / TARS[2], [
            ("atto", b"binary", "file"),
            ("oreslang", b"binary", "groupwrite"),
        ])
        self.verify(False)

    def test_secondary_alias_must_not_be_world_writable(self):
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"),
            ("oreslang", b"binary", "worldwrite"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

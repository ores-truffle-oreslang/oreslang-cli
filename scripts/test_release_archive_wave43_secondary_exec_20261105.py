"""Source-owned release archive admission; synthetic headers are not native execution."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar,
)


class SecondaryUnixExecutionPermissions(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_unix_secondary_executable_must_have_execute_permission(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                make_tar(
                    self.root / archive,
                    [("atto", b"binary", "file"),
                     ("oreslang", b"binary", "noexec")],
                )
                self.verify(False)
                make_tar(
                    self.root / archive,
                    [("atto", b"binary", "file"),
                     ("oreslang", b"binary", "file")],
                )
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

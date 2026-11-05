"""Host-only archive member negative controls; synthetic headers are not runnable binaries."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar,
)


class EmptySecondaryExecutable(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_executable_cannot_be_empty_in_any_unix_archive(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", b"", "file"),
                ])
                self.verify(False)
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", b"binary", "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

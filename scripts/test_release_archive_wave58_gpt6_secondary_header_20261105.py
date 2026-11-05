"""Host-only archive admission controls, not native executable proof."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable
)


class SecondaryHeaderRestorationWave58(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_header_corruption_is_rejected_on_each_unix_target(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                valid = synthetic_executable(archive)
                corrupted = b"BAD!" + valid[4:]
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", corrupted, "file"),
                ])
                self.verify(False)
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", valid, "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

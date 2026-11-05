"""Host-only release archive regression: the secondary binary must be safe too."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, make_tar


class SecondaryBinaryModeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_unix_binary_rejects_privileged_or_writable_mode(self):
        for archive in TARS:
            for unsafe_mode in ("setuid", "groupwrite", "worldwrite"):
                with self.subTest(archive=archive, mode=unsafe_mode):
                    make_tar(
                        self.root / archive,
                        [("atto", b"binary", "file"),
                         ("oreslang", b"binary", unsafe_mode)],
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

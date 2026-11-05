"""Synthetic source-owned release publisher mode regression; not native execution."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, make_tar


class SecondaryUnixExecutableModeSecurity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_binary_rejects_privileged_and_writable_mode_bits(self):
        for archive in TARS:
            for unsafe_mode in ("setuid", "groupwrite", "worldwrite"):
                with self.subTest(archive=archive, mode=unsafe_mode):
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", unsafe_mode),
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

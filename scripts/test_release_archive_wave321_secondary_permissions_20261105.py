"""Native release publisher archive-policy matrix: source-owned host tests only."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class SecondaryExecutablePermissionWave321(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_every_unix_secondary_executable_rejects_nonexec_and_writable_modes(self):
        self.verify(True)
        for archive in TARS:
            for invalid_kind in ("noexec", "setuid", "groupwrite", "worldwrite"):
                with self.subTest(archive=archive, mode=invalid_kind):
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", invalid_kind),
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)

    def test_windows_secondary_link_is_rejected_without_poisoning_valid_archive(self):
        self.verify(True)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"atto.exe", "symlink"),
        ])
        self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

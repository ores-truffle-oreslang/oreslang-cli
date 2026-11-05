"""Host-only archive admission tests using synthetic executables, not native release proof."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation,
    TARS,
    ZIP,
    make_tar,
    make_zip,
)


class SecondaryArchiveMemberLength(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_unix_archive_denies_empty_secondary_binary_and_recovers(self):
        for archive in TARS:
            with self.subTest(target=archive):
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

    def test_windows_archive_denies_empty_secondary_binary_and_recovers(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"", "file"),
        ])
        self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

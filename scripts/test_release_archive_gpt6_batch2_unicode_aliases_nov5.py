"""Source-owned TAR member identity checks; synthetic binaries are not executable."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, make_tar


class UnicodeUnixReleaseMemberIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_confusable_member_names_cannot_spoof_required_binary_names(self):
        # Cyrillic 'a' and 'o', and Greek omicron, look deceptively Latin.
        for archive in TARS:
            for alias, actual_name in (
                ("\u0430tto", "atto"),
                ("att\u043e", "atto"),
                ("\u03bfreslang", "oreslang"),
            ):
                with self.subTest(archive=archive, alias=alias):
                    entries = [
                        (alias if name == actual_name else name, b"binary", "file")
                        for name in ("atto", "oreslang")
                    ]
                    make_tar(self.root / archive, entries)
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

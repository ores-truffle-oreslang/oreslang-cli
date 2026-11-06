"""Windows release archive must have exact executable names, never aliases."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, ZIP, make_zip


class Wave2300UnicodeZipAlias(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_valid_archive_roundtrip(self):
        self.verify(True)

    def test_near_alias_cannot_replace_exact_windows_executable(self):
        for alternate in ("atto\u200b.exe", "atto.exe ", "ATTO.EXE", "att\u043e.exe"):
            with self.subTest(alias=alternate):
                make_zip(self.root / ZIP, [
                    (alternate, b"binary", "file"),
                    ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)

    def test_near_alias_cannot_replace_secondary_executable(self):
        for alternate in ("oreslang.EXE", "oreslang.exe ", "oreslang\u200b.exe"):
            with self.subTest(alias=alternate):
                make_zip(self.root / ZIP, [
                    ("atto.exe", b"binary", "file"),
                    (alternate, b"binary", "file"),
                ])
                self.verify(False)
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

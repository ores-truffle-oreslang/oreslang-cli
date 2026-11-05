"""Host-only release archive member identity negative controls.

These synthetic headers are not independently built native binaries.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
    synthetic_executable,
)


class ReleaseMemberUnicodeIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_archives_still_pass(self):
        self.verify(True)

    def test_tar_unicode_aliases_never_satisfy_canonical_member(self):
        for archive in TARS:
            for alias in ("atto\u202e", "a\u200dtto", "atto\u0301"):
                with self.subTest(archive=archive, alias=repr(alias)):
                    make_tar(self.root / archive, [
                        (alias, synthetic_executable(archive), "file"),
                        ("oreslang", synthetic_executable(archive), "file"),
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ("atto", synthetic_executable(archive), "file"),
                        ("oreslang", synthetic_executable(archive), "file"),
                    ])
                    self.verify(True)

    def test_zip_unicode_aliases_never_satisfy_canonical_member(self):
        for alias in ("atto\u202e.exe", "at\u200dto.exe", "atto.exe\u2060"):
            with self.subTest(alias=repr(alias)):
                make_zip(self.root / ZIP, [
                    (alias, synthetic_executable(ZIP), "file"),
                    ("oreslang.exe", synthetic_executable(ZIP), "file"),
                ])
                self.verify(False)
                make_zip(self.root / ZIP, [
                    ("atto.exe", synthetic_executable(ZIP), "file"),
                    ("oreslang.exe", synthetic_executable(ZIP), "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

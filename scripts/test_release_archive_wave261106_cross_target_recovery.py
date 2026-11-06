"""Cross-target executable acceptance negatives for every release member."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
    synthetic_executable,
)


class CrossTargetArchiveRecovery(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_unix_alias_rejects_foreign_target_and_restores(self):
        foreign = {TARS[0]: TARS[1], TARS[1]: TARS[2], TARS[2]: TARS[1]}
        for archive in TARS:
            for modified in ("atto", "oreslang"):
                with self.subTest(archive=archive, modified=modified):
                    entries = [
                        (name, synthetic_executable(foreign[archive])
                         if name == modified else b"binary", "file")
                        for name in ("atto", "oreslang")
                    ]
                    make_tar(self.root / archive, entries)
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"), ("oreslang", b"binary", "file")
                    ])
                    self.verify(True)

    def test_each_windows_alias_rejects_foreign_elf_and_restores(self):
        for modified in ("atto.exe", "oreslang.exe"):
            with self.subTest(modified=modified):
                make_zip(self.root / ZIP, [
                    (name, synthetic_executable(TARS[0])
                     if name == modified else b"binary", "file")
                    for name in ("atto.exe", "oreslang.exe")
                ])
                self.verify(False)
                make_zip(self.root / ZIP, [
                    ("atto.exe", b"binary", "file"),
                    ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

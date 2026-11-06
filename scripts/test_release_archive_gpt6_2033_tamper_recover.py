"""Both release aliases must reject binary format substitution before clean restore.

Synthetic executable headers are host publisher admission tests, not runnable AOT artifacts.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class CrossTargetAliasRecovery(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_unix_archives_reject_cross_target_format_for_each_alias(self):
        foreign = (TARS[1], TARS[2], TARS[0])
        for target, substituted in zip(TARS, foreign):
            for poisoned in ("atto", "oreslang"):
                with self.subTest(archive=target, alias=poisoned):
                    entries = [
                        (name, synthetic_executable(substituted) if name == poisoned
                         else b"binary", "file")
                        for name in ("atto", "oreslang")
                    ]
                    make_tar(self.root / target, entries)
                    self.verify(False)
                    make_tar(self.root / target, [
                        ("atto", b"binary", "file"), ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)

    def test_windows_archives_reject_foreign_elf_for_each_alias_and_recover(self):
        for poisoned in ("atto.exe", "oreslang.exe"):
            with self.subTest(alias=poisoned):
                make_zip(self.root / ZIP, [
                    (name, synthetic_executable(TARS[0]) if name == poisoned
                     else b"binary", "file")
                    for name in ("atto.exe", "oreslang.exe")
                ])
                self.verify(False)
                make_zip(self.root / ZIP, [
                    ("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

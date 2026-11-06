"""Cross-archive release-alias identity and recovery on the real publisher verifier.

Only synthetic binary headers are used. This does not execute native release
artifacts or establish AttoLang compiler / AOT equivalence.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class AliasCrossTargetIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_unix_member_cannot_masquerade_as_other_target(self):
        for archive in TARS:
            allowed = synthetic_executable(archive)
            different = next(name for name in TARS if name != archive)
            foreign = synthetic_executable(different)
            for alias in ("atto", "oreslang"):
                with self.subTest(archive=archive, alias=alias):
                    self.verify(True)
                    make_tar(self.root / archive, [
                        (name, foreign if name == alias else allowed, "file")
                        for name in ("atto", "oreslang")
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        (name, allowed, "file")
                        for name in ("atto", "oreslang")
                    ])
                    self.verify(True)

    def test_windows_aliases_reject_foreign_elf_and_macho_headers(self):
        allowed = synthetic_executable(ZIP)
        for foreign_target in TARS:
            foreign = synthetic_executable(foreign_target)
            for alias in ("atto.exe", "oreslang.exe"):
                with self.subTest(target=foreign_target, alias=alias):
                    self.verify(True)
                    make_zip(self.root / ZIP, [
                        (name, foreign if name == alias else allowed, "file")
                        for name in ("atto.exe", "oreslang.exe")
                    ])
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        (name, allowed, "file")
                        for name in ("atto.exe", "oreslang.exe")
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

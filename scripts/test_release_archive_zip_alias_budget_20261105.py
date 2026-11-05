"""Source-owned release archive checks: reject confusable ZIP member identities."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)

class ZipMemberAliasBoundaries(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_zip_control_remains_admitted(self):
        self.verify(True)

    def test_primary_member_case_and_dot_aliases_cannot_be_admitted(self):
        for alias in ('ATTO.EXE', './atto.exe', 'nested/atto.exe', 'atto.exe/'):
            with self.subTest(alias=alias):
                make_zip(self.root / ZIP, [
                    (alias, synthetic_executable(ZIP), 'file'),
                    ('oreslang.exe', synthetic_executable(ZIP), 'file')])
                self.verify(False)

    def test_unicode_confusable_primary_name_cannot_alias_real_executable(self):
        for alias in ('att\u043e.exe', 'atto\u200b.exe', 'att\u00f3.exe'):
            with self.subTest(alias=alias):
                make_zip(self.root / ZIP, [
                    (alias, synthetic_executable(ZIP), 'file'),
                    ('oreslang.exe', synthetic_executable(ZIP), 'file')])
                self.verify(False)

    def test_secondary_member_path_aliases_are_denied_independently(self):
        for alias in ('./oreslang.exe', '../oreslang.exe', 'bin/oreslang.exe'):
            with self.subTest(alias=alias):
                make_zip(self.root / ZIP, [
                    ('atto.exe', synthetic_executable(ZIP), 'file'),
                    (alias, synthetic_executable(ZIP), 'file')])
                self.verify(False)

if __name__ == '__main__':
    unittest.main()

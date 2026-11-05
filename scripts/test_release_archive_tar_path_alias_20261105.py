"""Release archive negative controls: do not normalize tar member authority."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)

class TarMemberPathBoundaries(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_tar_control_is_accepted(self):
        self.verify(True)

    def test_primary_path_aliases_are_denied_on_all_platforms(self):
        for archive in TARS:
            for alias in ('./atto', '../atto', 'bin/atto', '/atto', 'ATTO'):
                with self.subTest(archive=archive, alias=alias):
                    make_tar(self.root / archive, [
                        (alias, synthetic_executable(archive), 'file'),
                        ('oreslang', synthetic_executable(archive), 'file')])
                    self.verify(False)

    def test_secondary_member_aliases_are_denied(self):
        for alias in ('./oreslang', '../oreslang', 'bin/oreslang', 'oreslang/'):
            with self.subTest(alias=alias):
                make_tar(self.root / TARS[0], [
                    ('atto', synthetic_executable(TARS[0]), 'file'),
                    (alias, synthetic_executable(TARS[0]), 'file')])
                self.verify(False)

    def test_unicode_homograph_member_does_not_satisfy_primary_identity(self):
        make_tar(self.root / TARS[0], [
            ('att\u043e', synthetic_executable(TARS[0]), 'file'),
            ('oreslang', synthetic_executable(TARS[0]), 'file')])
        self.verify(False)

if __name__ == '__main__':
    unittest.main()

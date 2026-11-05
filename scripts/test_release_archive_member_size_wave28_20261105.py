"""Exact release-publisher archive admission tests; host only, no native binaries."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class MemberSizeAndHeaderWave28(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_unmodified_four_target_fixture_is_accepted(self):
        self.verify(True)

    def test_empty_secondary_member_denied_for_every_unix_target(self):
        for archive in TARS:
            with self.subTest(archive=archive):
                make_tar(self.root / archive, [('atto', b'binary', 'file'),
                                               ('oreslang', b'', 'file')])
                self.verify(False)
                make_tar(self.root / archive, [('atto', b'binary', 'file'),
                                               ('oreslang', b'binary', 'file')])

    def test_empty_secondary_windows_member_is_denied(self):
        make_zip(self.root / ZIP, [('atto.exe', b'binary', 'file'),
                                   ('oreslang.exe', b'', 'file')])
        self.verify(False)

    def test_binary_header_length_is_checked_for_both_unix_names(self):
        for archive in TARS:
            too_short = synthetic_executable(archive)[:63 if archive == TARS[0] else 31]
            for member in ('atto', 'oreslang'):
                with self.subTest(archive=archive, member=member):
                    entries = [(name, too_short if name == member else b'binary', 'file')
                               for name in ('atto', 'oreslang')]
                    make_tar(self.root / archive, entries)
                    self.verify(False)
                    make_tar(self.root / archive, [('atto', b'binary', 'file'),
                                                   ('oreslang', b'binary', 'file')])

    def test_windows_pe_header_truncation_denied_for_both_names(self):
        too_short = synthetic_executable(ZIP)[:153]
        for member in ('atto.exe', 'oreslang.exe'):
            with self.subTest(member=member):
                entries = [(name, too_short if name == member else b'binary', 'file')
                           for name in ('atto.exe', 'oreslang.exe')]
                make_zip(self.root / ZIP, entries)
                self.verify(False)
                make_zip(self.root / ZIP, [('atto.exe', b'binary', 'file'),
                                           ('oreslang.exe', b'binary', 'file')])

    def test_alias_member_names_never_substitute_an_exact_executable(self):
        make_tar(self.root / TARS[0], [('atto/', b'binary', 'file'),
                                       ('oreslang', b'binary', 'file')])
        self.verify(False)
        make_tar(self.root / TARS[0], [('atto', b'binary', 'file'),
                                       ('oreslang', b'binary', 'file')])
        make_zip(self.root / ZIP, [('atto.exe', b'binary', 'file'),
                                   ('ORESLANG.EXE', b'binary', 'file')])
        self.verify(False)


if __name__ == '__main__':
    unittest.main()

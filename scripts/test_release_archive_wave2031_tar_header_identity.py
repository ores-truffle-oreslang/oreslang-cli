"""Release alias header identity: each Unix member is independently checked.

Executes the real source-only release publisher verifier with synthetic binary
headers; no native binary execution or compiler/AOT certification is implied.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class Wave2031UnixHeaderIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_every_unix_executable_rejects_header_identity_tamper_and_recovers(self):
        for archive in TARS:
            original = synthetic_executable(archive)
            for binary in ('atto', 'oreslang'):
                altered = bytearray(original)
                if archive == TARS[0]:
                    # x86_64 ELF must be 64-bit little-endian, not ELF32.
                    altered[4] = 1
                else:
                    # A Mach-O executable must retain MH_EXECUTE.
                    altered[12:16] = (1).to_bytes(4, 'little')  # MH_OBJECT
                with self.subTest(archive=archive, executable=binary):
                    self.verify(True)
                    make_tar(self.root / archive, [
                        (name, bytes(altered) if name == binary else b'binary', 'file')
                        for name in ('atto', 'oreslang')
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ('atto', b'binary', 'file'),
                        ('oreslang', b'binary', 'file'),
                    ])
                    self.verify(True)

    def test_explicit_malformed_elf_data_encoding_is_not_an_executable(self):
        archive = TARS[0]
        for binary in ('atto', 'oreslang'):
            altered = bytearray(synthetic_executable(archive))
            altered[5] = 2  # ELF data big-endian, incompatible with target
            with self.subTest(binary=binary):
                make_tar(self.root / archive, [
                    (name, bytes(altered) if name == binary else b'binary', 'file')
                    for name in ('atto', 'oreslang')
                ])
                self.verify(False)
                make_tar(self.root / archive, [
                    ('atto', b'binary', 'file'),
                    ('oreslang', b'binary', 'file'),
                ])
                self.verify(True)


if __name__ == '__main__':
    unittest.main()

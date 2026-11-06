"""All four release formats refuse corrupted magic in either executable alias.

Actual source-owned publisher validation (host only; synthetic headers are not
runnable native binaries or AttoLang compiler parity evidence).
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class MagicMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_alias_each_target_rejects_changed_magic_and_recovers(self):
        for target in (*TARS, ZIP):
            names = ("atto.exe", "oreslang.exe") if target == ZIP else ("atto", "oreslang")
            for alias in names:
                with self.subTest(target=target, alias=alias):
                    archive = self.root / target
                    damaged = bytearray(synthetic_executable(target))
                    # ELF e_ident, Mach-O magic and DOS MZ all start at byte zero.
                    damaged[0] ^= 0x01
                    entries = [(name, bytes(damaged) if name == alias else b"binary", "file")
                               for name in names]
                    if target == ZIP:
                        make_zip(archive, entries)
                    else:
                        make_tar(archive, entries)
                    expected_bad_bytes = archive.read_bytes()
                    self.verify(False)
                    self.assertEqual(archive.read_bytes(), expected_bad_bytes,
                                     "verification must not mutate a rejected archive")
                    restored = [(name, b"binary", "file") for name in names]
                    if target == ZIP:
                        make_zip(archive, restored)
                    else:
                        make_tar(archive, restored)
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

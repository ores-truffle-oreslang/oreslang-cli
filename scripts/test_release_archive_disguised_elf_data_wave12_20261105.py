"""Reject noncanonical ELF identity in each release executable alias.

Source-free archive negative controls; never assert native execution.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class ELFIdentityDenial(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_primary_elf32_disguised_as_x86_64(self):
        bad = bytearray(synthetic_executable(TARS[0]))
        bad[4] = 1  # EI_CLASS must be ELFCLASS64
        make_tar(self.root / TARS[0], [
            ("atto", bytes(bad), "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_primary_big_endian_elf_disguised_as_x86_64(self):
        bad = bytearray(synthetic_executable(TARS[0]))
        bad[5] = 2  # EI_DATA must be little-endian
        make_tar(self.root / TARS[0], [
            ("atto", bytes(bad), "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_secondary_elf32_cannot_hide_behind_valid_primary(self):
        bad = bytearray(synthetic_executable(TARS[0]))
        bad[4] = 1
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"),
            ("oreslang", bytes(bad), "file"),
        ])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

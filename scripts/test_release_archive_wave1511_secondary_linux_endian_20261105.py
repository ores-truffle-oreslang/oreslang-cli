"""Actual source publisher acceptance of secondary ELF class/endian identity.

Synthetic binary headers validate structural admission, not runnable native binaries.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class SecondaryLinuxELFIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_big_endian_elf_rejected_before_valid_restoration(self):
        invalid = bytearray(synthetic_executable(TARS[0]))
        invalid[5] = 2  # ELF EI_DATA big-endian, not the x86_64 little-endian target
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"), ("oreslang", bytes(invalid), "file")
        ])
        self.verify(False)
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"), ("oreslang", b"binary", "file")
        ])
        self.verify(True)

    def test_secondary_elf32_class_rejected_before_valid_restoration(self):
        invalid = bytearray(synthetic_executable(TARS[0]))
        invalid[4] = 1  # ELFCLASS32, not ELFCLASS64
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"), ("oreslang", bytes(invalid), "file")
        ])
        self.verify(False)
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"), ("oreslang", b"binary", "file")
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

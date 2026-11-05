"""Fail-closed executable header bounds for the real source-free release validator.

Synthetic fixture headers do not establish real native binary execution.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
    synthetic_executable,
)


class HeaderBoundaryWave32(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_four_archives_are_admitted(self):
        self.verify(True)

    def test_linux_endianness_and_short_elf_are_rejected(self):
        for mutate in ("big_endian", "short"):
            with self.subTest(mutate=mutate):
                header = bytearray(synthetic_executable(TARS[0]))
                if mutate == "big_endian":
                    header[5] = 2
                else:
                    header = header[:63]
                make_tar(self.root / TARS[0], [
                    ("atto", bytes(header), "file"),
                    ("oreslang", b"binary", "file"),
                ])
                self.verify(False)

    def test_macos_short_header_is_rejected(self):
        make_tar(self.root / TARS[2], [
            ("atto", synthetic_executable(TARS[2])[:31], "file"),
            ("oreslang", b"binary", "file"),
        ])
        self.verify(False)

    def test_windows_pe_offset_must_reference_a_full_header(self):
        for offset in (0, 63, 4095, 0xffffffff):
            with self.subTest(offset=offset):
                header = bytearray(synthetic_executable(ZIP))
                header[0x3c:0x40] = offset.to_bytes(4, "little")
                make_zip(self.root / ZIP, [
                    ("atto.exe", bytes(header), "file"),
                    ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(False)


if __name__ == "__main__":
    unittest.main()

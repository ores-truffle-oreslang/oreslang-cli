"""Reject malformed *secondary* executable headers in all release targets."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
    synthetic_executable,
)


class SecondaryExecutableHeaderWave24(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def replace_unix_secondary(self, archive, binary):
        make_tar(self.root / archive, [
            ("atto", b"binary", "file"),
            ("oreslang", binary, "file"),
        ])

    def replace_windows_secondary(self, binary):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", binary, "file"),
        ])

    def test_valid_original_all_platform_archives(self):
        self.verify(True)

    def test_linux_secondary_wrong_elf_class(self):
        binary = bytearray(synthetic_executable(TARS[0]))
        binary[4] = 1
        self.replace_unix_secondary(TARS[0], bytes(binary))
        self.verify(False)

    def test_linux_secondary_wrong_endian_marker(self):
        binary = bytearray(synthetic_executable(TARS[0]))
        binary[5] = 2
        self.replace_unix_secondary(TARS[0], bytes(binary))
        self.verify(False)

    def test_macos_intel_secondary_short_mach_header(self):
        self.replace_unix_secondary(TARS[1], synthetic_executable(TARS[1])[:16])
        self.verify(False)

    def test_macos_arm_secondary_wrong_executable_type(self):
        binary = bytearray(synthetic_executable(TARS[2]))
        binary[12:16] = (1).to_bytes(4, "little")
        self.replace_unix_secondary(TARS[2], bytes(binary))
        self.verify(False)

    def test_windows_secondary_unbounded_pe_offset(self):
        binary = bytearray(synthetic_executable(ZIP))
        binary[0x3c:0x40] = (4096).to_bytes(4, "little")
        self.replace_windows_secondary(bytes(binary))
        self.verify(False)

    def test_windows_secondary_missing_mz_signature(self):
        binary = bytearray(synthetic_executable(ZIP))
        binary[:2] = b"NO"
        self.replace_windows_secondary(bytes(binary))
        self.verify(False)

    def test_windows_secondary_missing_executable_coff_flag(self):
        binary = bytearray(synthetic_executable(ZIP))
        binary[150:152] = (0).to_bytes(2, "little")
        self.replace_windows_secondary(bytes(binary))
        self.verify(False)


if __name__ == "__main__":
    unittest.main(verbosity=2)

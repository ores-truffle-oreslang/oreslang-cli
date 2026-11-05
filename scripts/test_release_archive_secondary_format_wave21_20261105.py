"""The secondary release executable must independently match the target format."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class SecondaryFormatIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_linux_secondary_wrong_elf_endianness_denied(self):
        wrong = bytearray(synthetic_executable(TARS[0]))
        wrong[5] = 2  # Big-endian ELF hidden in x86_64 little-endian release.
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"), ("oreslang", bytes(wrong), "file")])
        self.verify(False)

    def test_macos_secondary_wrong_mach_o_file_kind_denied(self):
        wrong = bytearray(synthetic_executable(TARS[1]))
        wrong[12:16] = (8).to_bytes(4, "little")  # MH_BUNDLE, not MH_EXECUTE.
        make_tar(self.root / TARS[1], [
            ("atto", b"binary", "file"), ("oreslang", bytes(wrong), "file")])
        self.verify(False)

    def test_windows_secondary_invalid_pe_signature_denied(self):
        wrong = bytearray(synthetic_executable(ZIP))
        wrong[128:132] = b"PX\x00\x00"  # Fake PE signature after MZ.
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"), ("oreslang.exe", bytes(wrong), "file")])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

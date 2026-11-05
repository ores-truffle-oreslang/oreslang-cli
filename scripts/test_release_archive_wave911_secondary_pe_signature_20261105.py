"""Host-only PE DOS e_lfanew boundary and relocation admission for secondary ZIP member.

The structural PE buffers are not executable Windows programs.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class SecondaryWindowsPEOffsetBoundsWave911(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def publish_secondary(self, payload):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", payload, "file"),
        ])

    @staticmethod
    def relocated(offset):
        header = bytearray(synthetic_executable(ZIP))
        canonical_pe_fields = bytes(header[128:154])
        header[0x3c:0x40] = offset.to_bytes(4, "little")
        if 64 <= offset <= len(header) - len(canonical_pe_fields):
            header[offset:offset + len(canonical_pe_fields)] = canonical_pe_fields
        return bytes(header)

    def test_secondary_dos_pointer_accepts_minimum_and_last_complete_pe_header(self):
        # The source verifier reads e_lfanew, not just an assumed PE offset of 128.
        for offset in (64, 230):
            with self.subTest(offset=offset):
                self.publish_secondary(self.relocated(offset))
                self.verify(True)
        self.publish_secondary(b"binary")
        self.verify(True)

    def test_secondary_dos_pointer_outside_complete_header_is_denied(self):
        for offset in (0, 63, 231, 255, 0xffffffff):
            with self.subTest(offset=offset):
                # The old PE marker at offset 128 remains intact, so a validator
                # that ignores e_lfanew could mistakenly admit these malformed files.
                self.publish_secondary(self.relocated(offset))
                self.verify(False)
        self.publish_secondary(b"binary")
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

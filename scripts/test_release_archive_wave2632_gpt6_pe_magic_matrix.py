"""Both Windows executable member aliases must advertise a PE32+ optional header."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class Wave2632PEOptionalMagic(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_member_rejects_pe32_rom_and_zero_magic_then_restores(self):
        valid = synthetic_executable(ZIP)
        for binary in ("atto.exe", "oreslang.exe"):
            for magic in (0x010B, 0x0107, 0x0000):
                with self.subTest(binary=binary, optional_magic=hex(magic)):
                    forged = bytearray(valid)
                    forged[152:154] = magic.to_bytes(2, "little")
                    make_zip(self.root / ZIP, [
                        ("atto.exe", bytes(forged) if binary == "atto.exe" else valid, "file"),
                        ("oreslang.exe", bytes(forged) if binary == "oreslang.exe" else valid, "file"),
                    ])
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        ("atto.exe", valid, "file"),
                        ("oreslang.exe", valid, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

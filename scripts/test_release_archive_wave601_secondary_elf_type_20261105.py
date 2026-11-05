"""Synthetic ELF release-policy negatives, not native executable proof."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class LinuxSecondaryElfTypeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_elf_nonexecutable_types_are_rejected(self):
        original = synthetic_executable(TARS[0])
        self.verify(True)
        for elf_type in (0, 4, 0xFF00):  # ET_NONE, ET_CORE, reserved OS range
            with self.subTest(elf_type=elf_type):
                changed = bytearray(original)
                changed[16:18] = elf_type.to_bytes(2, "little")
                make_tar(self.root / TARS[0], [
                    ("atto", b"binary", "file"),
                    ("oreslang", bytes(changed), "file"),
                ])
                self.verify(False)
        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"),
            ("oreslang", original, "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

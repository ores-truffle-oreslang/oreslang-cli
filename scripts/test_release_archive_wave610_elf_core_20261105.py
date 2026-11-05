"""Actual inline release publisher rejects core-dump ELF masquerading as a binary."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class Wave610ElfExecutableType(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_primary_and_secondary_elf_core_dump_types_are_not_executables(self):
        original = synthetic_executable(TARS[0])
        core_dump = bytearray(original)
        core_dump[16:18] = (4).to_bytes(2, "little")  # ET_CORE, not ET_EXEC/ET_DYN
        for member in ("atto", "oreslang"):
            with self.subTest(member=member):
                make_tar(self.root / TARS[0], [
                    ("atto", bytes(core_dump) if member == "atto" else original, "file"),
                    ("oreslang", bytes(core_dump) if member == "oreslang" else original, "file"),
                ])
                self.verify(False)
        make_tar(self.root / TARS[0], [
            ("atto", original, "file"), ("oreslang", original, "file"),
        ])
        self.verify(True)

    def test_non_pie_executable_type_remains_a_valid_linux_release(self):
        exec_elf = bytearray(synthetic_executable(TARS[0]))
        exec_elf[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
        make_tar(self.root / TARS[0], [
            ("atto", bytes(exec_elf), "file"), ("oreslang", bytes(exec_elf), "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

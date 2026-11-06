"""Both Linux release aliases must reject forged ELF identity bytes, then recover."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class LinuxElfIdentityFence(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_release_aliases_reject_elf32_big_endian_and_core_objects(self):
        target = TARS[0]
        legitimate = synthetic_executable(target)
        self.verify(True)
        variants = (
            ("elf32", 4, b"\x01"),
            ("big_endian", 5, b"\x02"),
            ("elf_core", 16, (4).to_bytes(2, "little")),
        )
        for name, offset, replacement in variants:
            for alias in ("atto", "oreslang"):
                with self.subTest(variant=name, alias=alias):
                    forged = bytearray(legitimate)
                    forged[offset:offset + len(replacement)] = replacement
                    self.assertNotEqual(bytes(forged), legitimate)
                    entries = [
                        (member, bytes(forged) if member == alias else legitimate, "file")
                        for member in ("atto", "oreslang")
                    ]
                    make_tar(self.root / target, entries)
                    self.verify(False)
                    make_tar(self.root / target, [
                        ("atto", legitimate, "file"),
                        ("oreslang", legitimate, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""A short ELF payload must never pass release admission on either CLI alias.

This source-free fixture verifies the original release publisher's exact
target-header guard, not an executable AttoLang native compiler.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation,
    TARS,
    make_tar,
    synthetic_executable,
)


class Wave6116ShortELFHeader(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_alias_rejects_truncated_elf_and_restores_complete_header(self):
        archive = TARS[0]
        complete = synthetic_executable(archive)
        for binary in ("atto", "oreslang"):
            for length in (0, 1, 3, 4, 16, 20, 32, 63):
                with self.subTest(binary=binary, length=length):
                    truncated = complete[:length]
                    make_tar(self.root / archive, [
                        ("atto", truncated if binary == "atto" else complete, "file"),
                        ("oreslang", truncated if binary == "oreslang" else complete, "file"),
                    ])
                    self.verify(False)
            # Lower bound is precisely 64 ELF bytes; valid 64-byte input is
            # enough to prove format, CPU and image type in the source gate.
            header = complete[:64]
            make_tar(self.root / archive, [
                ("atto", header, "file"),
                ("oreslang", header, "file"),
            ])
            self.verify(True)
            make_tar(self.root / archive, [
                ("atto", complete, "file"),
                ("oreslang", complete, "file"),
            ])
            self.verify(True)


if __name__ == "__main__":
    unittest.main()

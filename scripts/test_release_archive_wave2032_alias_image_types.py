"""Actual release publisher rejects executable image kinds for both aliases.

Synthetic headers are structural host admission controls, NOT runnable binaries.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class Wave2032ExecutableImageKindMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_linux_aliases_reject_core_and_relocatable_elf_then_restore(self):
        target = self.root / TARS[0]
        for member in ("atto", "oreslang"):
            for bad_type in (1, 4):  # ET_REL and ET_CORE are not executable images.
                with self.subTest(member=member, e_type=bad_type):
                    wrong = bytearray(synthetic_executable(TARS[0]))
                    wrong[16:18] = bad_type.to_bytes(2, "little")
                    make_tar(target, [
                        ("atto", bytes(wrong) if member == "atto" else b"binary", "file"),
                        ("oreslang", bytes(wrong) if member == "oreslang" else b"binary", "file"),
                    ])
                    self.verify(False)
                    make_tar(target, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)

    def test_each_macho_target_rejects_dylib_for_either_alias_then_restores(self):
        for target_name in TARS[1:]:
            target = self.root / target_name
            for member in ("atto", "oreslang"):
                with self.subTest(target=target_name, member=member):
                    wrong = bytearray(synthetic_executable(target_name))
                    wrong[12:16] = (6).to_bytes(4, "little")  # MH_DYLIB, not MH_EXECUTE.
                    make_tar(target, [
                        ("atto", bytes(wrong) if member == "atto" else b"binary", "file"),
                        ("oreslang", bytes(wrong) if member == "oreslang" else b"binary", "file"),
                    ])
                    self.verify(False)
                    make_tar(target, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)

    def test_both_windows_aliases_require_executable_coff_and_restore(self):
        target = self.root / ZIP
        for member in ("atto.exe", "oreslang.exe"):
            with self.subTest(member=member):
                wrong = bytearray(synthetic_executable(ZIP))
                wrong[150:152] = (0).to_bytes(2, "little")
                make_zip(target, [
                    ("atto.exe", bytes(wrong) if member == "atto.exe" else b"binary", "file"),
                    ("oreslang.exe", bytes(wrong) if member == "oreslang.exe" else b"binary", "file"),
                ])
                self.verify(False)
                make_zip(target, [
                    ("atto.exe", b"binary", "file"),
                    ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

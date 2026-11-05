"""Host-only negative controls for secondary Unix release executable formats.

These are synthetic executable headers and do not prove native artifact execution.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, synthetic_executable,
)


class SecondaryUnixReleaseHeaders(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_valid_two_executable_unix_archives_are_admitted(self):
        self.verify(True)

    def test_linux_secondary_elf_object_is_not_an_executable(self):
        wrong = bytearray(synthetic_executable(TARS[0]))
        wrong[16:18] = (1).to_bytes(2, "little")  # ET_REL object
        make_tar(
            self.root / TARS[0],
            [("atto", b"binary", "file"), ("oreslang", bytes(wrong), "file")],
        )
        self.verify(False)

    def test_linux_secondary_foreign_cpu_is_denied(self):
        wrong = bytearray(synthetic_executable(TARS[0]))
        wrong[18:20] = (183).to_bytes(2, "little")  # AArch64
        make_tar(
            self.root / TARS[0],
            [("atto", b"binary", "file"), ("oreslang", bytes(wrong), "file")],
        )
        self.verify(False)

    def test_macos_secondary_mach_object_is_not_executable(self):
        wrong = bytearray(synthetic_executable(TARS[1]))
        wrong[12:16] = (1).to_bytes(4, "little")  # MH_OBJECT
        make_tar(
            self.root / TARS[1],
            [("atto", b"binary", "file"), ("oreslang", bytes(wrong), "file")],
        )
        self.verify(False)

    def test_macos_secondary_foreign_os_format_is_denied(self):
        make_tar(
            self.root / TARS[2],
            [("atto", b"binary", "file"),
             ("oreslang", synthetic_executable(ZIP), "file")],
        )
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

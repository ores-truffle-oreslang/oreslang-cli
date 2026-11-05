"""Host-only Mach-O identity regressions; no macOS binary is executed."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable
)


class MachOSecondaryIdentityWave242(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_macos_secondary_members_reject_wrong_magic_cpu_and_filetype(self):
        for archive in TARS[1:]:
            original = synthetic_executable(archive)
            other = TARS[2] if archive == TARS[1] else TARS[1]
            wrong_cpu = synthetic_executable(other)[4:8]
            for offset, field in (
                (0, b"\xfe\xed\xfa\xcf"),
                (4, wrong_cpu),
                (12, b"\x01\x00\x00\x00"),
            ):
                with self.subTest(archive=archive, offset=offset):
                    bad = bytearray(original)
                    bad[offset:offset + len(field)] = field
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", bytes(bad), "file"),
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        ("atto", b"binary", "file"),
                        ("oreslang", original, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

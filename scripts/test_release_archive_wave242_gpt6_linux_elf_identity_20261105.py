"""Source-free Linux release archive admission; not runnable binary certification."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable
)


class LinuxElfIdentityWave242(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_elf_header_fields_fail_closed_and_restore(self):
        archive = TARS[0]
        valid = synthetic_executable(archive)
        for offset, field in ((4, b"\x01"), (5, b"\x02"), (18, b"\xb7\x00")):
            with self.subTest(offset=offset):
                bad = bytearray(valid)
                bad[offset:offset + len(field)] = field
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", bytes(bad), "file"),
                ])
                self.verify(False)
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", valid, "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

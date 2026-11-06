"""Windows release PE optional-header size must be bounded for both tools."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class WindowsOptionalSizeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_executable_members_reject_undersized_optional_headers(self):
        valid = synthetic_executable(ZIP)
        for changed_member in ("atto.exe", "oreslang.exe"):
            for invalid_size in (0, 0x6f):
                with self.subTest(member=changed_member, size=invalid_size):
                    bad = bytearray(valid)
                    bad[148:150] = invalid_size.to_bytes(2, "little")
                    make_zip(self.root / ZIP, [
                        (member, bytes(bad) if member == changed_member else valid, "file")
                        for member in ("atto.exe", "oreslang.exe")
                    ])
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        ("atto.exe", valid, "file"),
                        ("oreslang.exe", valid, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

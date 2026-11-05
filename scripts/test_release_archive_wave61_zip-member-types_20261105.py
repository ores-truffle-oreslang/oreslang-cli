"""Host-only ZIP member metadata admission; synthetic PE headers are not runnable proof."""
import stat
import unittest
import zipfile

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, synthetic_executable,
)


class ZipMemberTypeWave61(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def write_member_types(self, symlink_name):
        with zipfile.ZipFile(self.root / ZIP, "w") as archive:
            for name in ("atto.exe", "oreslang.exe"):
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                mode = (stat.S_IFLNK if name == symlink_name else stat.S_IFREG) | 0o755
                member.external_attr = mode << 16
                archive.writestr(member, synthetic_executable(ZIP))

    def test_two_regular_pe_members_remain_admitted(self):
        self.verify(True)

    def test_primary_member_symlink_with_valid_pe_bytes_is_denied(self):
        self.write_member_types("atto.exe")
        self.verify(False)

    def test_secondary_member_symlink_with_valid_pe_bytes_is_denied(self):
        self.write_member_types("oreslang.exe")
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

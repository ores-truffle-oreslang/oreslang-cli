"""Windows release ZIP aliases must be regular files, not special Unix nodes.

Synthetic metadata-only mutations exercise the real inline release verifier.
No compiler or native executable execution is asserted by these host tests.
"""
import stat
import unittest
import zipfile

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class WindowsSpecialMemberTypeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_windows_aliases_reject_special_node_metadata_then_recover(self):
        payload = synthetic_executable(ZIP)
        kinds = (
            ("fifo", stat.S_IFIFO),
            ("socket", stat.S_IFSOCK),
            ("character", stat.S_IFCHR),
            ("block", stat.S_IFBLK),
            ("directory", stat.S_IFDIR),
        )
        for name in ("atto.exe", "oreslang.exe"):
            for kind_name, kind in kinds:
                with self.subTest(name=name, kind=kind_name):
                    with zipfile.ZipFile(self.root / ZIP, "w") as archive:
                        for member_name in ("atto.exe", "oreslang.exe"):
                            info = zipfile.ZipInfo(member_name)
                            info.create_system = 3
                            info.external_attr = (
                                ((kind if member_name == name else stat.S_IFREG)
                                 | 0o755) << 16
                            )
                            archive.writestr(info, payload)
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        ("atto.exe", payload, "file"),
                        ("oreslang.exe", payload, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

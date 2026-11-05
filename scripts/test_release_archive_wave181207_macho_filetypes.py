"""Reject Mach-O library and bundle payloads in both executables, not guest proof."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class MachOFileTypeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_macos_binary_members_reject_dylib_and_bundle_with_restore(self):
        for archive in TARS[1:]:
            valid = synthetic_executable(archive)
            for changed_member in ("atto", "oreslang"):
                for file_type in (6, 8):  # MH_DYLIB / MH_BUNDLE, not MH_EXECUTE
                    with self.subTest(archive=archive, member=changed_member, file_type=file_type):
                        bad = bytearray(valid)
                        bad[12:16] = file_type.to_bytes(4, "little")
                        entries = [
                            (name, bytes(bad) if name == changed_member else valid, "file")
                            for name in ("atto", "oreslang")
                        ]
                        make_tar(self.root / archive, entries)
                        self.verify(False)
                        make_tar(self.root / archive, [
                            ("atto", valid, "file"), ("oreslang", valid, "file"),
                        ])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

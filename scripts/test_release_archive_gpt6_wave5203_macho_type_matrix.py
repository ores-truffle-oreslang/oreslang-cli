"""Both macOS executable aliases must reject loadable nonexecutables.

These are source-owned synthetic header tests of release publisher admission,
not runnable Mach-O executables or AttoLang guest execution.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class Wave5203MachOExecutableType(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_macos_archives_reject_object_and_dylib_for_both_aliases(self):
        for archive_name in TARS[1:]:
            original = synthetic_executable(archive_name)
            for member in ("atto", "oreslang"):
                for bad_type in (1, 6):  # MH_OBJECT, MH_DYLIB
                    with self.subTest(archive=archive_name, member=member, type=bad_type):
                        altered = bytearray(original)
                        altered[12:16] = bad_type.to_bytes(4, "little")
                        make_tar(self.root / archive_name, [
                            ("atto", bytes(altered) if member == "atto" else original, "file"),
                            ("oreslang", bytes(altered) if member == "oreslang" else original, "file"),
                        ])
                        self.verify(False)
            make_tar(self.root / archive_name, [
                ("atto", original, "file"), ("oreslang", original, "file"),
            ])
            self.verify(True)


if __name__ == "__main__":
    unittest.main()

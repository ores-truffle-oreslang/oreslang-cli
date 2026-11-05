"""Exercise real source-free release verifier against cross-target binary spoofing."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class Wave2331PrimaryBinaryTargetIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_every_unix_primary_rejects_wrong_target_format_or_cpu_and_recovers(self):
        for i, name in enumerate(TARS):
            foreign = synthetic_executable(TARS[(i + 1) % len(TARS)])
            for slot in ("atto", "oreslang"):
                with self.subTest(archive=name, member=slot):
                    entries = [
                        (member, foreign if member == slot else b"binary", "file")
                        for member in ("atto", "oreslang")
                    ]
                    make_tar(self.root / name, entries)
                    self.verify(False)
                    make_tar(self.root / name, [
                        ("atto", b"binary", "file"), ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)

    def test_windows_primary_and_secondary_reject_linux_elf_and_recover(self):
        for slot in ("atto.exe", "oreslang.exe"):
            with self.subTest(member=slot):
                make_zip(self.root / ZIP, [
                    (name, synthetic_executable(TARS[0]) if name == slot else b"binary", "file")
                    for name in ("atto.exe", "oreslang.exe")
                ])
                self.verify(False)
                make_zip(self.root / ZIP, [
                    ("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

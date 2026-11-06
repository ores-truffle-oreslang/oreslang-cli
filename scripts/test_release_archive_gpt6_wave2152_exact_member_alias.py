"""Publisher accepts only the two exact executable names on each target.

These are source-free archive/header admission tests, not compiler guest or AOT proof.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)


class ExactReleaseMemberAliasMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_unix_target_rejects_near_aliases_then_rebuilds(self):
        for target in TARS:
            for alias in ("atto", "oreslang"):
                for near in ("./" + alias, alias.upper(), "bin/" + alias):
                    with self.subTest(target=target, alias=alias, near=near):
                        entries = [
                            (near if name == alias else name, b"binary", "file")
                            for name in ("atto", "oreslang")
                        ]
                        make_tar(self.root / target, entries)
                        self.verify(False)
                        make_tar(self.root / target, [
                            ("atto", b"binary", "file"),
                            ("oreslang", b"binary", "file"),
                        ])
                        self.verify(True)

    def test_windows_target_rejects_near_exe_aliases_then_rebuilds(self):
        for alias in ("atto.exe", "oreslang.exe"):
            for near in ("./" + alias, alias.upper(), "bin/" + alias):
                with self.subTest(alias=alias, near=near):
                    entries = [
                        (near if name == alias else name, b"binary", "file")
                        for name in ("atto.exe", "oreslang.exe")
                    ]
                    make_zip(self.root / ZIP, entries)
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        ("atto.exe", b"binary", "file"),
                        ("oreslang.exe", b"binary", "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Release publisher rejects noncanonical archive member path spellings.

Source-owned synthetic archive header tests only; no runnable guest proof.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class ExactArchiveMemberNameAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_unix_aliases_cannot_hide_behind_relative_or_nested_names(self):
        for archive in TARS:
            payload = synthetic_executable(archive)
            for original in ("atto", "oreslang"):
                for forged in ("./" + original, "nested/" + original,
                               original + "/"):
                    with self.subTest(archive=archive, alias=original,
                                      forged=forged):
                        entries = [(forged if name == original else name,
                                    payload, "file")
                                   for name in ("atto", "oreslang")]
                        make_tar(self.root / archive, entries)
                        self.verify(False)
                        make_tar(self.root / archive, [
                            ("atto", payload, "file"),
                            ("oreslang", payload, "file"),
                        ])
                        self.verify(True)

    def test_windows_aliases_require_exact_zip_member_names(self):
        payload = synthetic_executable(ZIP)
        for original in ("atto.exe", "oreslang.exe"):
            for forged in ("./" + original, "nested/" + original,
                           original.upper()):
                with self.subTest(alias=original, forged=forged):
                    make_zip(self.root / ZIP, [
                        (forged if name == original else name, payload, "file")
                        for name in ("atto.exe", "oreslang.exe")
                    ])
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        ("atto.exe", payload, "file"),
                        ("oreslang.exe", payload, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

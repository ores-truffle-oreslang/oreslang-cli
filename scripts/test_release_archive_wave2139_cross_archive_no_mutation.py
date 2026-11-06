"""Cross-target fail-closed release validation is read-only and recovers exactly."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
    synthetic_executable,
)


class CrossArchiveMutationIsolation(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_executable_alias_corruption_rejects_without_mutating_any_archive(self):
        targets = (*TARS, ZIP)
        original = {name: (self.root / name).read_bytes() for name in targets}
        self.verify(True)
        for target in targets:
            for alias_index in (0, 1):
                with self.subTest(target=target, alias=alias_index):
                    if target == ZIP:
                        members = ("atto.exe", "oreslang.exe")
                        malformed = b"NO" + synthetic_executable(target)[2:]
                        items = [(name, malformed if i == alias_index else b"binary", "file")
                                 for i, name in enumerate(members)]
                        make_zip(self.root / target, items)
                    else:
                        members = ("atto", "oreslang")
                        malformed = b"NOPE" + synthetic_executable(target)[4:]
                        items = [(name, malformed if i == alias_index else b"binary", "file")
                                 for i, name in enumerate(members)]
                        make_tar(self.root / target, items)
                    before_validation = {(self.root / name): (self.root / name).read_bytes()
                                         for name in targets}
                    self.verify(False)
                    after_validation = {(self.root / name): (self.root / name).read_bytes()
                                        for name in targets}
                    self.assertEqual(after_validation, before_validation,
                                     "rejected publisher validation must never rewrite archive bytes")
                    (self.root / target).write_bytes(original[target])
                    self.assertEqual(
                        {name: (self.root / name).read_bytes() for name in targets},
                        original,
                        "restoration cannot modify unrelated target archives")
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

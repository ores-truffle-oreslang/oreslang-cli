"""Validate both published Unix aliases against foreign executable formats."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class BothAliasTargetFormatIdentity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_aliases_refuse_foreign_platform_binary_headers_and_recover(self):
        for target in TARS:
            original = synthetic_executable(target)
            foreign = synthetic_executable(TARS[0] if target != TARS[0] else TARS[1])
            for alias in ("atto", "oreslang"):
                with self.subTest(target=target, alias=alias):
                    make_tar(self.root / target, [
                        ("atto", foreign if alias == "atto" else original, "file"),
                        ("oreslang", foreign if alias == "oreslang" else original, "file"),
                    ])
                    self.verify(False)
                    make_tar(self.root / target, [
                        ("atto", original, "file"),
                        ("oreslang", original, "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

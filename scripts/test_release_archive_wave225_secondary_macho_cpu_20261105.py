"""Secondary macOS executables must match the target CPU, not only the primary."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class BothDarwinSecondaryArchitectureTests(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_darwin_targets_reject_other_cpu_in_secondary_member(self):
        targets = ((TARS[1], TARS[2]), (TARS[2], TARS[1]))
        for archive, other_cpu in targets:
            with self.subTest(target=archive, foreign=other_cpu):
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", synthetic_executable(other_cpu), "file"),
                ])
                self.verify(False)
                make_tar(self.root / archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", b"binary", "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

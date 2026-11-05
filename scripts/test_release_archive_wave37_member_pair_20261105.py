"""Host-only archive format checks for both binary member names."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)

class ReleaseArchivePairMachineRegression(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_control_archive_set_admitted(self):
        self.verify(True)

    def test_each_macos_archive_rejects_opposite_cpu_for_either_executable(self):
        for target, foreign in ((TARS[1], TARS[2]), (TARS[2], TARS[1])):
            for damaged in ("atto", "oreslang"):
                with self.subTest(target=target, damaged=damaged):
                    ReleaseArchiveValidation.setUp(self)
                    wrong = synthetic_executable(foreign)
                    make_tar(self.root / target, [
                        ("atto", wrong if damaged == "atto" else b"binary", "file"),
                        ("oreslang", wrong if damaged == "oreslang" else b"binary", "file"),
                    ])
                    self.verify(False)

if __name__ == "__main__":
    unittest.main()

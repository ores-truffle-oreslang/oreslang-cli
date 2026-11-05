"""Source-free release archive presence admission; synthetic headers, not native proof."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP
)


class RequiredReleaseArchives(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_exact_four_target_set_is_admitted(self):
        self.verify(True)

    def test_missing_linux_archive_fails_closed(self):
        (self.root / TARS[0]).unlink()
        self.verify(False)

    def test_missing_intel_macos_archive_fails_closed(self):
        (self.root / TARS[1]).unlink()
        self.verify(False)

    def test_missing_arm_macos_archive_fails_closed(self):
        (self.root / TARS[2]).unlink()
        self.verify(False)

    def test_missing_windows_archive_fails_closed(self):
        (self.root / ZIP).unlink()
        self.verify(False)


if __name__ == '__main__':
    unittest.main()

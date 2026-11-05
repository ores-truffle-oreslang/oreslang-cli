"""Source-free negative tests for release archive symlink admission."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS, ZIP

class ReleaseArchiveSymlinkAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_regular_archive_paths_remain_accepted(self):
        self.verify(True)

    def test_each_release_target_refuses_symlink_even_to_valid_artifact(self):
        for archive in (*TARS, ZIP):
            with self.subTest(archive=archive):
                ReleaseArchiveValidation.setUp(self)
                target = self.root / archive
                backing = self.root / ("backing-" + archive)
                target.rename(backing)
                target.symlink_to(backing.name)
                self.assertTrue(target.is_symlink())
                self.verify(False)

if __name__ == "__main__":
    unittest.main()

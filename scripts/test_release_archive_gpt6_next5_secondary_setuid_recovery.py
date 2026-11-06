"""Secondary alias mode is independently authoritative, not just primary atto.

Exercises the real source-free release archive validator on synthetic binary
headers; does not claim an executable AttoLang guest or signed artifact.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar,
)


class Next5SecondarySetuidRecovery(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_setuid_on_each_tar_target_denies_until_repaired(self):
        for archive_name in TARS:
            with self.subTest(archive=archive_name):
                archive = self.root / archive_name
                make_tar(archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", b"binary", "setuid"),
                ])
                tampered = archive.read_bytes()
                self.verify(False)
                self.assertEqual(archive.read_bytes(), tampered,
                                 "rejection must not mutate supplied archive")
                make_tar(archive, [
                    ("atto", b"binary", "file"),
                    ("oreslang", b"binary", "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

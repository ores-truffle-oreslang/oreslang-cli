"""Valid gzip DEFLATE encoder choices must preserve two reviewed executable members.

Calls the actual inline release verifier from the source checkout. The binary
headers are synthetic structural fixtures, not runnable guest executables.
"""
import gzip
import unittest

from test_release_archive_validation import ReleaseArchiveValidation, TARS


class GzipEncoderIndependence(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_three_unix_targets_accept_stored_fast_and_max_compression(self):
        for archive_name in TARS:
            archive = self.root / archive_name
            original = archive.read_bytes()
            tar_bytes = gzip.decompress(original)
            self.assertGreater(len(tar_bytes), 512)
            for level in (0, 1, 9):
                with self.subTest(target=archive_name, compresslevel=level):
                    alternative = gzip.compress(tar_bytes, compresslevel=level, mtime=0)
                    self.assertTrue(alternative.startswith(b"\x1f\x8b\x08"))
                    self.assertEqual(gzip.decompress(alternative), tar_bytes)
                    archive.write_bytes(alternative)
                    self.verify(True)
                    self.assertEqual(archive.read_bytes(), alternative)
            archive.write_bytes(original)
            self.verify(True)


if __name__ == "__main__":
    unittest.main()

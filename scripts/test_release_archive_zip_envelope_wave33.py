"""Negative controls for publisher ZIP entry and end-of-central-directory boundaries."""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, ZIP

class ReleaseZipEnvelopeBoundaries(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_comment_free_zip_is_accepted(self):
        self.verify(True)

    def test_zip_with_nonzip_executable_prefix_is_rejected(self):
        target = self.root / ZIP
        target.write_bytes(b"MZ-polyglot-prefix" + target.read_bytes())
        self.verify(False)

    def test_zip_with_appended_payload_is_rejected(self):
        target = self.root / ZIP
        target.write_bytes(target.read_bytes() + b"appended-payload")
        self.verify(False)

    def test_zip_with_archive_comment_is_rejected(self):
        # zipfile accepts comments, but this release packager never emits them.
        import zipfile
        target = self.root / ZIP
        with zipfile.ZipFile(target, "a") as z:
            z.comment = b"release-comment"
        self.verify(False)

if __name__ == "__main__":
    unittest.main()

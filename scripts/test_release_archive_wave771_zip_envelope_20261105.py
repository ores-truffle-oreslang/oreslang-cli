"""ZIP release envelope regression: refuse SFX prefix, trailing data, comments.

Synthetic archive fixtures prove static source-owned admission only.
"""
import unittest
import zipfile
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip
)


class ReleaseZipEnvelopeNegativeControls(unittest.TestCase):
    setUp=ReleaseArchiveValidation.setUp
    verify=ReleaseArchiveValidation.verify

    def clean_zip(self):
        make_zip(self.root / ZIP, [
            (name,b"binary","file") for name in ("atto.exe","oreslang.exe")
        ])

    def test_sfx_prefix_is_rejected_and_restoring_archive_recovers(self):
        source=self.root / ZIP
        original=source.read_bytes()
        source.write_bytes(b"MZprefix" + original)
        self.verify(False)
        self.clean_zip()
        self.verify(True)

    def test_post_directory_payload_is_rejected_and_clean_zip_recovers(self):
        source=self.root / ZIP
        source.write_bytes(source.read_bytes() + b"unknown trailing payload")
        self.verify(False)
        self.clean_zip()
        self.verify(True)

    def test_canonical_zip_comment_policy_rejects_comments(self):
        source=self.root / ZIP
        with zipfile.ZipFile(source,"a") as zf:
            zf.comment=b"untrusted comment"
        self.verify(False)
        self.clean_zip()
        self.verify(True)


if __name__=="__main__":
    unittest.main()

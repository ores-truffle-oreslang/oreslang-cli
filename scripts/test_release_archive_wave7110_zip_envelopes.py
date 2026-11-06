"""Release ZIP publisher must require a canonical, comment-free envelope."""
import unittest
import zipfile
from test_release_archive_validation import ReleaseArchiveValidation, ZIP, make_zip


class Wave7110ZipEnvelopeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_comment_trailer_and_self_extracting_prefix_are_rejected(self):
        target = self.root / ZIP
        good = target.read_bytes()
        self.verify(True)
        for mutation in ("comment", "trailer", "prefix"):
            with self.subTest(mutation=mutation):
                target.write_bytes(good)
                if mutation == "comment":
                    with zipfile.ZipFile(target, "a") as archive:
                        archive.comment = b"unreviewed distribution metadata"
                elif mutation == "trailer":
                    with target.open("ab") as output:
                        output.write(b"trailing unsigned content")
                else:
                    target.write_bytes(b"MZ-CARRIER" + good)
                self.verify(False)
                target.write_bytes(good)
                self.verify(True)

    def test_rebuilt_zip_has_same_canonical_contract(self):
        target = self.root / ZIP
        target.write_bytes(b"not a zip")
        self.verify(False)
        make_zip(target, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)


if __name__ == "__main__":
    unittest.main()

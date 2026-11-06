"""Reject every nonregular executable TAR member on each Unix target, both aliases.

Uses source-owned publisher acceptance against structural synthetic binaries,
not compiled AttoLang guest or native executable proof.
"""
import io
import tarfile
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class UnixAliasNodeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_target_and_alias_denies_nonregular_node_without_rewriting_archive(self):
        types = (
            ("symlink", tarfile.SYMTYPE),
            ("hardlink", tarfile.LNKTYPE),
            ("fifo", tarfile.FIFOTYPE),
        )
        for target in TARS:
            for replaced in ("atto", "oreslang"):
                for label, kind in types:
                    with self.subTest(target=target, alias=replaced, kind=label):
                        path = self.root / target
                        with tarfile.open(path, "w:gz") as archive:
                            for alias in ("atto", "oreslang"):
                                item = tarfile.TarInfo(alias)
                                item.mode = 0o755
                                if alias == replaced:
                                    item.type = kind
                                    if label in ("symlink", "hardlink"):
                                        item.linkname = "atto" if alias == "oreslang" else "oreslang"
                                    archive.addfile(item)
                                else:
                                    payload = synthetic_executable(target)
                                    item.size = len(payload)
                                    archive.addfile(item, io.BytesIO(payload))
                        before = path.read_bytes()
                        self.verify(False)
                        self.assertEqual(path.read_bytes(), before,
                                         "rejected artifact must not be rewritten")
                        make_tar(path, [("atto", b"binary", "file"),
                                        ("oreslang", b"binary", "file")])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

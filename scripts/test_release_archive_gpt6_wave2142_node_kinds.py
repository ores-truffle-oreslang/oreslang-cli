"""Actual release publisher rejects special TAR nodes for either executable alias.

Synthetic headers exercise host release admission, not runnable guest binaries.
"""
import io
import tarfile
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class TarNodeKindDenial(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_each_unix_target_rejects_special_alias_nodes_then_restores(self):
        for archive in TARS:
            for alias in ("atto", "oreslang"):
                for kind in ("symlink", "hardlink", "fifo"):
                    with self.subTest(target=archive, alias=alias, kind=kind):
                        path = self.root / archive
                        with tarfile.open(path, "w:gz") as output:
                            for member_name in ("atto", "oreslang"):
                                info = tarfile.TarInfo(member_name)
                                info.mode = 0o755
                                if member_name == alias:
                                    info.type = {
                                        "symlink": tarfile.SYMTYPE,
                                        "hardlink": tarfile.LNKTYPE,
                                        "fifo": tarfile.FIFOTYPE,
                                    }[kind]
                                    if kind != "fifo":
                                        info.linkname = "oreslang" if alias == "atto" else "atto"
                                    output.addfile(info)
                                else:
                                    payload = synthetic_executable(archive)
                                    info.size = len(payload)
                                    output.addfile(info, io.BytesIO(payload))
                        self.verify(False)
                        make_tar(path, [
                            ("atto", b"binary", "file"),
                            ("oreslang", b"binary", "file"),
                        ])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

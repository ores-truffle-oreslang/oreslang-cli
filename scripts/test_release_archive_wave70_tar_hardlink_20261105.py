"""Source-owned host-only rejection of TAR hardlink executable aliases.

All executable payloads are synthetic format headers, not runnable AOT programs.
"""
import io
import tarfile
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class TarHardlinkReleaseAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_canonical_files_still_pass(self):
        self.verify(True)

    def test_hardlinked_secondary_executable_is_not_an_independent_binary(self):
        for archive in TARS:
            with self.subTest(target=archive):
                target = self.root / archive
                with tarfile.open(target, "w:gz") as handle:
                    primary = tarfile.TarInfo("atto")
                    payload = synthetic_executable(archive)
                    primary.size = len(payload)
                    primary.mode = 0o755
                    handle.addfile(primary, io.BytesIO(payload))
                    secondary = tarfile.TarInfo("oreslang")
                    secondary.type = tarfile.LNKTYPE
                    secondary.linkname = "atto"
                    secondary.mode = 0o755
                    handle.addfile(secondary)
                self.verify(False)
                make_tar(target, [
                    ("atto", synthetic_executable(archive), "file"),
                    ("oreslang", synthetic_executable(archive), "file"),
                ])
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

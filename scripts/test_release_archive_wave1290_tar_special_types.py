"""The real publisher rejects directory/FIFO masquerades in either Unix binary slot."""
import io
import tarfile
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class UnixExecutableMemberTypeMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_executable_slots_deny_directory_and_fifo_types_on_every_target(self):
        for archive_name in TARS:
            for target in ("atto", "oreslang"):
                for invalid_type in (tarfile.DIRTYPE, tarfile.FIFOTYPE):
                    with self.subTest(archive=archive_name, target=target, invalid=invalid_type):
                        archive = self.root / archive_name
                        with tarfile.open(archive, "w:gz") as tar:
                            for name in ("atto", "oreslang"):
                                entry = tarfile.TarInfo(name)
                                entry.mode = 0o755
                                if name == target:
                                    entry.type = invalid_type
                                    tar.addfile(entry)
                                else:
                                    payload = synthetic_executable(archive_name)
                                    entry.size = len(payload)
                                    tar.addfile(entry, io.BytesIO(payload))
                        self.verify(False)
                        make_tar(archive, [
                            ("atto", b"binary", "file"),
                            ("oreslang", b"binary", "file"),
                        ])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Host-only negative controls for TAR special-device member admission."""
import io
import tarfile
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class ArchiveSpecialDeviceMemberAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_primary_and_secondary_device_entries_are_rejected_for_each_target(self):
        for archive in TARS:
            for bad_name in ("atto", "oreslang"):
                for kind in (tarfile.CHRTYPE, tarfile.BLKTYPE):
                    with self.subTest(archive=archive, bad_name=bad_name, kind=kind):
                        with tarfile.open(self.root / archive, "w:gz") as tar:
                            for name in ("atto", "oreslang"):
                                member = tarfile.TarInfo(name)
                                member.mode = 0o755
                                if name == bad_name:
                                    member.type = kind
                                    member.devmajor = 1
                                    member.devminor = 3
                                    tar.addfile(member)
                                else:
                                    payload = synthetic_executable(archive)
                                    member.size = len(payload)
                                    tar.addfile(member, io.BytesIO(payload))
                        self.verify(False)
                        make_tar(self.root / archive, [
                            ("atto", b"binary", "file"),
                            ("oreslang", b"binary", "file"),
                        ])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Host-only release TAR policy: no setgid/sticky bits on either executable."""
import io
import tarfile
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, synthetic_executable,
)


class UnixArchiveExecutableModeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def write_tar_with_mode(self, archive, target, mode):
        with tarfile.open(self.root / archive, "w:gz") as out:
            for name in ("atto", "oreslang"):
                payload = synthetic_executable(archive)
                member = tarfile.TarInfo(name)
                member.mode = mode if name == target else 0o755
                member.size = len(payload)
                out.addfile(member, io.BytesIO(payload))

    def test_setgid_and_sticky_modes_rejected_for_both_members_every_target(self):
        for archive in TARS:
            for target in ("atto", "oreslang"):
                for mode in (0o2755, 0o1755, 0o3755):
                    with self.subTest(archive=archive, target=target, mode=oct(mode)):
                        self.write_tar_with_mode(archive, target, mode)
                        self.verify(False)
            # A rejected archive must not make subsequent valid target output fail.
            self.write_tar_with_mode(archive, "atto", 0o755)
            self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Reject Unix release members that carry setgid/sticky privilege bits.

These are synthetic archive-header admission tests; they do not attest native
execution, compiler output, or backend parity.
"""
import io
import tarfile
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class UnixSpecialBitAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def _archive_with_mode(self, archive, member_name, altered_mode):
        binary = synthetic_executable(archive)
        with tarfile.open(self.root / archive, "w:gz") as tar:
            for name in ("atto", "oreslang"):
                info = tarfile.TarInfo(name)
                info.mode = altered_mode if name == member_name else 0o755
                info.size = len(binary)
                tar.addfile(info, io.BytesIO(binary))

    def test_setgid_and_sticky_members_fail_on_each_unix_target(self):
        for archive in TARS:
            for member_name in ("atto", "oreslang"):
                for altered_mode in (0o2755, 0o1755):
                    with self.subTest(archive=archive, member=member_name,
                                      mode=oct(altered_mode)):
                        self._archive_with_mode(archive, member_name,
                                                altered_mode)
                        self.verify(False)
                        make_tar(self.root / archive, [
                            ("atto", b"binary", "file"),
                            ("oreslang", b"binary", "file"),
                        ])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Both Unix CLI aliases must obey the same ELF64 little-endian target gate.

Real inline publisher execution on synthetic host archives, not guest execution.
"""
import unittest

from test_release_archive_validation import (
    TARS, ReleaseArchiveValidation, make_tar, synthetic_executable,
)


class ElfIdentityBoundary(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_either_alias_refuses_wrong_elf_class_or_endian_and_recovers(self):
        archive = TARS[0]
        baseline = synthetic_executable(archive)
        names = ("atto", "oreslang")
        for target in names:
            for identity in (b"\x01\x01", b"\x02\x02", b"\x00\x01", b"\x02\x00"):
                with self.subTest(target=target, identity=identity.hex()):
                    damaged = bytearray(baseline)
                    damaged[4:6] = identity
                    make_tar(self.root / archive, [
                        (name, bytes(damaged) if name == target else baseline, "file")
                        for name in names
                    ])
                    self.verify(False)
                    make_tar(self.root / archive, [
                        (name, baseline, "file") for name in names
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

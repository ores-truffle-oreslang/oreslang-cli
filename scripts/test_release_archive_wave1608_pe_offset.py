"""Exercise the actual release publisher's bounded PE header offset admission.

These are source-free archive fixtures; no compiled compiler/guest claim.
"""
import unittest

from test_release_archive_validation import (
    ZIP, ReleaseArchiveValidation, make_zip, synthetic_executable,
)


class PeOffsetBoundary(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_aliases_refuse_invalid_pe_offsets_and_recover(self):
        baseline = synthetic_executable(ZIP)
        names = ("atto.exe", "oreslang.exe")
        for target in names:
            for offset in (0, 63, 64, 240, 0xffffffff):
                with self.subTest(target=target, offset=offset):
                    damaged = bytearray(baseline)
                    damaged[0x3c:0x40] = offset.to_bytes(4, "little")
                    make_zip(self.root / ZIP, [
                        (name, bytes(damaged) if name == target else baseline, "file")
                        for name in names
                    ])
                    self.verify(False)
                    make_zip(self.root / ZIP, [(name, baseline, "file") for name in names])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

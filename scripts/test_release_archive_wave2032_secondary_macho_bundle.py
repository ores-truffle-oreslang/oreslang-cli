"""Original publisher integration: Mac secondary executable must be MH_EXECUTE.

These are synthetic header admission fixtures, not runnable binaries.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class SecondaryMacBinaryType(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def _replace(self, target, payload):
        make_tar(self.root / target, [
            ("atto", b"binary", "file"),
            ("oreslang", payload, "file"),
        ])

    def test_both_targets_reject_secondary_dylib_and_bundle_then_restore(self):
        for target in (TARS[1], TARS[2]):
            for kind in (6, 8):  # MH_DYLIB and MH_BUNDLE, not MH_EXECUTE
                with self.subTest(target=target, kind=kind):
                    forged = bytearray(synthetic_executable(target))
                    forged[12:16] = kind.to_bytes(4, "little")
                    self._replace(target, bytes(forged))
                    self.verify(False)
                    self._replace(target, b"binary")
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

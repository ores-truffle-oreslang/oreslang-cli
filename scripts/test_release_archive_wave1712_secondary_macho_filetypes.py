"""Reject Mach-O dylib and bundle masquerading as second executable release members.

Executes the real source-owned publisher validator with synthetic Mach-O headers.
The fixtures are structural checks, not runnable native binary proofs.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class SecondaryMachOFileTypeAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_secondary_dylib_and_bundle_denied_for_both_macos_targets(self):
        for target in TARS[1:]:
            for filetype in (6, 8):  # MH_DYLIB and MH_BUNDLE; not MH_EXECUTE
                with self.subTest(target=target, filetype=filetype):
                    impostor = bytearray(synthetic_executable(target))
                    impostor[12:16] = filetype.to_bytes(4, "little")
                    make_tar(self.root / target, [
                        ("atto", b"binary", "file"),
                        ("oreslang", bytes(impostor), "file"),
                    ])
                    self.verify(False)
                    make_tar(self.root / target, [
                        ("atto", b"binary", "file"),
                        ("oreslang", b"binary", "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

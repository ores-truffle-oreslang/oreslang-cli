"""Source publisher Mach-O validation on BOTH aliases and macOS architectures.

Synthetic headers only: tests structural admission, not runnable guest binaries.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class RejectMachOCoreAndPreload(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_macos_core_and_preload_rejected_in_primary_and_secondary_aliases(self):
        for target in (TARS[1], TARS[2]):
            for alias in ("atto", "oreslang"):
                for bad_type in (4, 5):  # MH_CORE / MH_PRELOAD, not MH_EXECUTE
                    with self.subTest(target=target, alias=alias, type=bad_type):
                        forged = bytearray(synthetic_executable(target))
                        forged[12:16] = bad_type.to_bytes(4, "little")
                        entries = [
                            ("atto", bytes(forged) if alias == "atto" else b"binary", "file"),
                            ("oreslang", bytes(forged) if alias == "oreslang" else b"binary", "file"),
                        ]
                        make_tar(self.root / target, entries)
                        self.verify(False)
                        make_tar(self.root / target, [
                            ("atto", b"binary", "file"),
                            ("oreslang", b"binary", "file"),
                        ])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

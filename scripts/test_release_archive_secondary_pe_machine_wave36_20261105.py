"""Host-only executable-header mutation tests for the source release publisher.

Synthetic PE headers are not native binaries or AOT execution evidence.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip, synthetic_executable,
)


class SecondaryPeMachineBoundary(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_valid_primary_and_secondary_pe64_images_are_accepted(self):
        self.verify(True)

    def test_secondary_executable_with_arm64_machine_is_denied(self):
        foreign = bytearray(synthetic_executable(ZIP))
        foreign[132:134] = (0xAA64).to_bytes(2, "little")
        make_zip(
            self.root / ZIP,
            [("atto.exe", b"binary", "file"),
             ("oreslang.exe", bytes(foreign), "file")],
        )
        self.verify(False)

    def test_secondary_executable_with_invalid_pe_signature_is_denied(self):
        foreign = bytearray(synthetic_executable(ZIP))
        foreign[128:132] = b"NOPE"
        make_zip(
            self.root / ZIP,
            [("atto.exe", b"binary", "file"),
             ("oreslang.exe", bytes(foreign), "file")],
        )
        self.verify(False)


if __name__ == "__main__":
    unittest.main()

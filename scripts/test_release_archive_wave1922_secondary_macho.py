"""Source publisher regression: verify BOTH secondary Mach-O formats independently.

Synthetic headers demonstrate admission only, not executable native artifacts.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class SecondaryMachOAdmission(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def _replace_secondary(self, target, payload):
        make_tar(self.root / target, [
            ("atto", b"binary", "file"),
            ("oreslang", payload, "file"),
        ])

    def test_secondary_object_type_rejected_on_each_macos_target(self):
        for target in (TARS[1], TARS[2]):
            with self.subTest(target=target):
                wrong = bytearray(synthetic_executable(target))
                wrong[12:16] = (1).to_bytes(4, "little")  # MH_OBJECT
                self._replace_secondary(target, bytes(wrong))
                self.verify(False)
                self._replace_secondary(target, b"binary")
                self.verify(True)

    def test_secondary_arm64_binary_cannot_masquerade_as_intel_and_vice_versa(self):
        for target, foreign in ((TARS[1], TARS[2]), (TARS[2], TARS[1])):
            with self.subTest(target=target):
                self._replace_secondary(target, synthetic_executable(foreign))
                self.verify(False)
                self._replace_secondary(target, b"binary")
                self.verify(True)


if __name__ == "__main__":
    unittest.main()

"""Source-owned release archive structural admission, not runnable guest binaries."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class UnixImageTypeMatrix2033(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def publish(self, archive, which, payload):
        make_tar(self.root / archive, [
            ("atto", payload if which == "atto" else b"binary", "file"),
            ("oreslang", payload if which == "oreslang" else b"binary", "file"),
        ])

    def test_both_unix_aliases_reject_non_executable_image_types_then_recover(self):
        for archive in TARS:
            for which in ("atto", "oreslang"):
                for invalid in (0, 4) if "linux" in archive else (0, 1):
                    with self.subTest(archive=archive, alias=which, image_type=invalid):
                        payload = bytearray(synthetic_executable(archive))
                        if "linux" in archive:
                            payload[16:18] = invalid.to_bytes(2, "little")
                        else:
                            payload[12:16] = invalid.to_bytes(4, "little")
                        self.publish(archive, which, bytes(payload))
                        self.verify(False)
                        self.publish(archive, which, b"binary")
                        self.verify(True)

    def test_linux_executable_and_pie_types_remain_valid_on_each_alias(self):
        archive = TARS[0]
        for which in ("atto", "oreslang"):
            for image_type in (2, 3):
                with self.subTest(alias=which, image_type=image_type):
                    payload = bytearray(synthetic_executable(archive))
                    payload[16:18] = image_type.to_bytes(2, "little")
                    self.publish(archive, which, bytes(payload))
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

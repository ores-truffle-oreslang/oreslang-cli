"""Exercise actual inline release validator using synthetic Mach-O target headers."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class Wave2143MachOAliasKinds(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_aliases_reject_object_dylib_bundle_and_restore(self):
        for archive in TARS[1:]:
            good = synthetic_executable(archive)
            for alias in ("atto", "oreslang"):
                for bad_type in (1, 6, 8):  # MH_OBJECT, MH_DYLIB, MH_BUNDLE
                    with self.subTest(archive=archive, alias=alias, type=bad_type):
                        bad = bytearray(good)
                        bad[12:16] = bad_type.to_bytes(4, "little")
                        make_tar(self.root / archive, [
                            ("atto", bytes(bad) if alias == "atto" else good, "file"),
                            ("oreslang", bytes(bad) if alias == "oreslang" else good, "file"),
                        ])
                        self.verify(False)
                        make_tar(self.root / archive, [
                            ("atto", good, "file"), ("oreslang", good, "file"),
                        ])
                        self.verify(True)

    def test_wrong_architecture_independent_of_image_type(self):
        for archive, foreign in ((TARS[1], TARS[2]), (TARS[2], TARS[1])):
            for alias in ("atto", "oreslang"):
                with self.subTest(archive=archive, alias=alias):
                    wrong = synthetic_executable(foreign)
                    make_tar(self.root / archive, [
                        ("atto", wrong if alias == "atto" else b"binary", "file"),
                        ("oreslang", wrong if alias == "oreslang" else b"binary", "file"),
                    ])
                    self.verify(False)


if __name__ == "__main__":
    unittest.main()

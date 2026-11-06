"""Exercise the actual release gate on non-executable image kinds in either alias."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class BothAliasExecutableImageKinds(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_core_or_non_executable_image_is_rejected_for_each_alias_then_recovers(self):
        for archive in (*TARS, ZIP):
            valid = synthetic_executable(archive)
            corrupt = bytearray(valid)
            if archive == TARS[0]:
                corrupt[16:18] = (4).to_bytes(2, "little")  # ELF ET_CORE
            elif archive in TARS[1:]:
                corrupt[12:16] = (4).to_bytes(4, "little")  # Mach-O MH_CORE
            else:
                corrupt[150:152] = (0).to_bytes(2, "little")  # PE not executable
            for alias in (("atto.exe", "oreslang.exe") if archive == ZIP else ("atto", "oreslang")):
                with self.subTest(archive=archive, alias=alias):
                    members = [
                        (name, bytes(corrupt) if name == alias else valid, "file")
                        for name in (("atto.exe", "oreslang.exe") if archive == ZIP else ("atto", "oreslang"))
                    ]
                    if archive == ZIP:
                        make_zip(self.root / archive, members)
                    else:
                        make_tar(self.root / archive, members)
                    self.verify(False)
                    repaired = [
                        (name, valid, "file")
                        for name in (("atto.exe", "oreslang.exe") if archive == ZIP else ("atto", "oreslang"))
                    ]
                    if archive == ZIP:
                        make_zip(self.root / archive, repaired)
                    else:
                        make_tar(self.root / archive, repaired)
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

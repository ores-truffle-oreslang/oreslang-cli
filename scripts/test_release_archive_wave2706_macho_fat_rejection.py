"""Source publisher rejects Mach-O FAT wrappers for both public executable aliases.

The release contract publishes thin, target-specific executables. A FAT
container cannot impersonate that identity even if it embeds a valid thin
header, and failing one archive must not poison valid restoration.

Synthetic headers exercise host-side admission, not executable guest code.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class ThinMachOReleaseContract(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_macos_targets_and_aliases_reject_fat_wrapper_then_restore(self):
        for archive in TARS[1:]:
            thin = synthetic_executable(archive)
            for alias in ("atto", "oreslang"):
                for signature in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                    with self.subTest(archive=archive, alias=alias,
                                      signature=signature.hex()):
                        # FAT top-level magic with a valid thin Mach-O embedded
                        # at a nonzero offset; the publisher must reject it.
                        wrapped = signature + (b"\0" * 60) + thin
                        make_tar(self.root / archive, [
                            (name, wrapped if name == alias else b"binary", "file")
                            for name in ("atto", "oreslang")
                        ])
                        self.verify(False)
                        make_tar(self.root / archive, [
                            ("atto", b"binary", "file"),
                            ("oreslang", b"binary", "file"),
                        ])
                        self.verify(True)


if __name__ == "__main__":
    unittest.main()

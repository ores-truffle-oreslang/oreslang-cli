"""Two corrupted release targets must each be repaired before admission.

Runs the real source-owned release validator on synthetic structural binaries.
These fixtures do not claim an executable AttoLang guest binary.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class Wave1607MultiTargetRecovery(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_two_independent_bad_targets_require_both_repairs(self):
        unaffected = {name: (self.root / name).read_bytes() for name in TARS[1:]}

        corrupt_linux = bytearray(synthetic_executable(TARS[0]))
        corrupt_linux[0] = 0  # ELF signature must not be masked by valid aliases
        make_tar(self.root / TARS[0], [
            ("atto", bytes(corrupt_linux), "file"),
            ("oreslang", b"binary", "file"),
        ])

        corrupt_windows = bytearray(synthetic_executable(ZIP))
        corrupt_windows[0] = 0  # PE/MZ signature is independently required
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", bytes(corrupt_windows), "file"),
        ])
        damaged = {name: (self.root / name).read_bytes() for name in (*TARS, ZIP)}
        self.verify(False)
        self.assertEqual(damaged, {
            name: (self.root / name).read_bytes() for name in damaged
        }, "rejecting releases must not rewrite supplied archives")

        make_tar(self.root / TARS[0], [
            ("atto", b"binary", "file"), ("oreslang", b"binary", "file"),
        ])
        self.verify(False)  # Windows target remains compromised

        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file"),
        ])
        self.verify(True)
        self.assertEqual(unaffected, {
            name: (self.root / name).read_bytes() for name in TARS[1:]
        }, "healthy Mach-O targets must remain byte-identical")


if __name__ == "__main__":
    unittest.main()

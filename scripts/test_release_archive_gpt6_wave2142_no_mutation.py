"""The actual release publisher must not alter success or rejected archives.

Synthetic headers verify structural admission, not runnable guest binaries.
"""
import hashlib
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class VerifyReleaseArchiveReadOnly(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def snapshot(self):
        return {name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                for name in (*TARS, ZIP)}

    def replace_binary(self, target, alias, payload):
        name_a = "atto.exe" if target == ZIP else "atto"
        name_b = "oreslang.exe" if target == ZIP else "oreslang"
        entries = [(name_a, payload if alias == "atto" else b"binary", "file"),
                   (name_b, payload if alias == "oreslang" else b"binary", "file")]
        if target == ZIP:
            make_zip(self.root / target, entries)
        else:
            make_tar(self.root / target, entries)

    def test_all_targets_verify_readonly_with_each_bad_alias_then_restore(self):
        baseline = self.snapshot()
        self.verify(True)
        self.assertEqual(self.snapshot(), baseline)
        for target in (*TARS, ZIP):
            for alias in ("atto", "oreslang"):
                with self.subTest(target=target, alias=alias):
                    wrong = bytearray(synthetic_executable(target))
                    wrong[0] = 0  # corrupt ELF, Mach-O or MZ signature, fixed length
                    self.replace_binary(target, alias, bytes(wrong))
                    corrupt_before = self.snapshot()
                    self.verify(False)
                    self.assertEqual(self.snapshot(), corrupt_before)
                    self.replace_binary(target, alias, b"binary")
                    restored_before = self.snapshot()
                    self.verify(True)
                    self.assertEqual(self.snapshot(), restored_before)


if __name__ == "__main__":
    unittest.main()

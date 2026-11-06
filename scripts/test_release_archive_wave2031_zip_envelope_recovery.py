"""Check exact release ZIP envelope rejection and deterministic restoration.

This tests the source-owned release publisher with synthetic executable headers,
not runnable native binaries or an AttoLang compiler guest.
"""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, ZIP, make_zip,
)


class ZIPEnvelopeRecovery(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def _restore(self):
        make_zip(self.root / ZIP, [
            ("atto.exe", b"binary", "file"),
            ("oreslang.exe", b"binary", "file"),
        ])

    def test_sfx_prefixes_are_rejected_and_canonical_zip_recovers(self):
        path = self.root / ZIP
        original = path.read_bytes()
        self.verify(True)
        for prefix in (b"MZ", b"PK\x00\x00", b"\x00" * 32):
            with self.subTest(prefix=prefix):
                path.write_bytes(prefix + original)
                self.verify(False)
                self._restore()
                self.verify(True)
                self.assertEqual(path.read_bytes(), original)

    def test_trailing_overlay_and_eocd_comment_length_are_denied(self):
        path = self.root / ZIP
        original = path.read_bytes()
        for suffix in (b"\x00", b"PK\x05\x06", b"appended executable overlay"):
            with self.subTest(suffix=suffix):
                path.write_bytes(original + suffix)
                self.verify(False)
                self._restore()
                self.verify(True)
                self.assertEqual(path.read_bytes(), original)

        mutated = bytearray(original)
        # The canonical ZIP has a 22-byte end-of-central-directory record.
        self.assertEqual(mutated[-22:-18], b"PK\x05\x06")
        mutated[-2:] = (1).to_bytes(2, "little")
        path.write_bytes(mutated)
        self.verify(False)
        self._restore()
        self.verify(True)
        self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

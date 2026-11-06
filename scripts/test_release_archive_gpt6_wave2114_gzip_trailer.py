"""Verify actual publisher checks gzip CRC32 and ISIZE integrity for all Unix targets.

Mutation fixtures are structural release archives only, not executable guest proof.
"""
import unittest

from test_release_archive_validation import ReleaseArchiveValidation, TARS


class ArchiveTrailerIntegrity(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_crc32_and_uncompressed_size_tampering_are_rejected_without_mutation(self):
        for name in TARS:
            archive = self.root / name
            original = archive.read_bytes()
            self.assertTrue(original.startswith(b"\x1f\x8b"))
            self.assertGreater(len(original), 32)
            for trailer_index in (-8, -4):
                with self.subTest(target=name, offset=trailer_index):
                    damaged = bytearray(original)
                    damaged[trailer_index] ^= 0x80
                    archive.write_bytes(damaged)
                    self.verify(False)
                    self.assertEqual(archive.read_bytes(), bytes(damaged))
                    archive.write_bytes(original)
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

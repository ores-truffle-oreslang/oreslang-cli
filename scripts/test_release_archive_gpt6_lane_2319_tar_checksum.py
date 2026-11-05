"""Release verifier must reject header corruption in both binary members."""
import gzip
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, TARS

class TarHeaderChecksumRegression(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_both_tar_member_headers_fail_closed_then_restore(self):
        self.verify(True)
        for archive_name in TARS:
            target = self.root / archive_name
            pristine = target.read_bytes()
            raw = gzip.decompress(pristine)
            for offset, member_name in ((0, b"atto"), (1024, b"oreslang")):
                with self.subTest(archive=archive_name, member=member_name):
                    self.assertEqual(raw[offset:offset + len(member_name)], member_name)
                    corrupt = bytearray(raw)
                    # Flip an octal checksum digit without touching member contents.
                    digit = corrupt[offset + 148]
                    corrupt[offset + 148] = ord("7") if digit != ord("7") else ord("6")
                    target.write_bytes(gzip.compress(bytes(corrupt), mtime=0))
                    self.verify(False)
                    target.write_bytes(pristine)
                    self.verify(True)

if __name__ == "__main__":
    unittest.main()

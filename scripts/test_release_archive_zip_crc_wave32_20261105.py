"""Exercise the actual no-checkout publisher against corrupted ZIP entry CRCs.

These synthetic headers are not executable compiler or native-release evidence.
"""
import unittest
from test_release_archive_validation import ReleaseArchiveValidation, ZIP


class ReleaseZipCrcWave32(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_control_archive_is_accepted(self):
        self.verify(True)

    def test_crc_corruption_in_each_executable_is_denied(self):
        for entry in (0, 1):
            with self.subTest(entry=entry):
                # Restore clean synthetic archives for each independent attack.
                ReleaseArchiveValidation.setUp(self)
                target = self.root / ZIP
                raw = bytearray(target.read_bytes())
                positions = []
                cursor = 0
                while True:
                    pos = raw.find(b"PK\x01\x02", cursor)
                    if pos == -1:
                        break
                    positions.append(pos)
                    cursor = pos + 4
                self.assertEqual(len(positions), 2)
                raw[positions[entry] + 16] ^= 0x5A
                target.write_bytes(raw)
                self.verify(False)


if __name__ == "__main__":
    unittest.main()

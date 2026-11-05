"""Actual ZIP body corruption, distinct from central-directory CRC mutation."""
import unittest
import zipfile
from test_release_archive_validation import ReleaseArchiveValidation, ZIP

class ReleaseZipPayloadCorruption(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_control_executables_are_accepted(self):
        self.verify(True)

    def test_byte_flip_in_each_executable_body_must_fail_crc(self):
        for name in ("atto.exe", "oreslang.exe"):
            with self.subTest(name=name):
                ReleaseArchiveValidation.setUp(self)
                target = self.root / ZIP
                with zipfile.ZipFile(target) as archive:
                    info = archive.getinfo(name)
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                raw = bytearray(target.read_bytes())
                offset = info.header_offset
                self.assertEqual(raw[offset:offset+4], b"PK\x03\x04")
                filename_length = int.from_bytes(raw[offset+26:offset+28], "little")
                extra_length = int.from_bytes(raw[offset+28:offset+30], "little")
                payload = offset + 30 + filename_length + extra_length
                self.assertEqual(info.file_size, 256)
                # Leave the PE signature/machine/header valid; only CRC can
                # reveal that a body byte was corrupted after packaging.
                raw[payload + 200] ^= 0x5a
                target.write_bytes(raw)
                self.verify(False)

if __name__ == "__main__":
    unittest.main()

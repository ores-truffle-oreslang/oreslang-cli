"""Both Windows release members require independently valid PE headers."""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation,
    ZIP,
    make_zip,
    synthetic_executable,
)


class Wave6207WindowsHeaderMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def test_wrong_pe_signature_or_unbounded_offset_on_either_executable(self):
        for binary in ("atto.exe", "oreslang.exe"):
            for kind in ("signature", "offset", "machine"):
                with self.subTest(binary=binary, mutation=kind):
                    valid = synthetic_executable(ZIP)
                    forged = bytearray(valid)
                    if kind == "signature":
                        forged[128:132] = b"NOPE"
                    elif kind == "offset":
                        forged[0x3c:0x40] = (4090).to_bytes(4, "little")
                    else:
                        forged[132:134] = (0xAA64).to_bytes(2, "little")
                    make_zip(self.root / ZIP, [
                        ("atto.exe", bytes(forged) if binary == "atto.exe" else valid, "file"),
                        ("oreslang.exe", bytes(forged) if binary == "oreslang.exe" else valid, "file"),
                    ])
                    self.verify(False)
                    make_zip(self.root / ZIP, [
                        ("atto.exe", b"binary", "file"),
                        ("oreslang.exe", b"binary", "file"),
                    ])
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

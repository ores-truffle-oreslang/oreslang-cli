"""Exact release-publisher negative controls across all platforms and aliases."""
import unittest

from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip, synthetic_executable,
)


class ArchiveBothMemberFormatMatrix(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def bad_header(self, archive):
        binary = bytearray(synthetic_executable(archive))
        if archive == TARS[0]:
            binary[4] = 1     # ELFCLASS32, must be ELFCLASS64
        elif archive in TARS[1:]:
            binary[12:16] = (8).to_bytes(4, "little")  # MH_BUNDLE, not MH_EXECUTE
        else:
            binary[152:154] = (0x10b).to_bytes(2, "little")  # PE32, not PE32+
        return bytes(binary)

    def test_every_archive_and_binary_member_rejects_format_injection(self):
        for archive in (*TARS, ZIP):
            members = ("atto.exe", "oreslang.exe") if archive == ZIP else ("atto", "oreslang")
            for altered in members:
                with self.subTest(archive=archive, alias=altered):
                    entries = [
                        (name, self.bad_header(archive) if name == altered else b"binary", "file")
                        for name in members
                    ]
                    if archive == ZIP:
                        make_zip(self.root / archive, entries)
                    else:
                        make_tar(self.root / archive, entries)
                    self.verify(False)
                    clean = [(name, b"binary", "file") for name in members]
                    if archive == ZIP:
                        make_zip(self.root / archive, clean)
                    else:
                        make_tar(self.root / archive, clean)
                    self.verify(True)


if __name__ == "__main__":
    unittest.main()

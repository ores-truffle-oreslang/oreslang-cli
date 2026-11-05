#!/usr/bin/env python3
"""Host-only publisher rejection tests for missing/renamed release payloads."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

fixture = Path(__file__).with_name("test_release_archive_validation.py")
spec = importlib.util.spec_from_file_location("release_contract", fixture)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

class MissingReleaseParts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in contract.TARS:
            contract.make_tar(self.root / name,
                              [("atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        contract.make_zip(self.root / contract.ZIP,
                          [("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file")])

    def verify(self, permitted):
        result = subprocess.run([sys.executable, "-c", contract.SCRIPT, str(self.root)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, permitted, result.stderr)

    def test_reference_distribution_passes(self):
        self.verify(True)

    def test_every_missing_platform_archive_is_rejected(self):
        for name in (*contract.TARS, contract.ZIP):
            with self.subTest(archive=name):
                path = self.root / name
                original = path.read_bytes()
                path.unlink()
                try:
                    self.verify(False)
                finally:
                    path.write_bytes(original)
                self.verify(True)

    def test_missing_secondary_tar_executable_is_rejected(self):
        for name in contract.TARS:
            with self.subTest(archive=name):
                contract.make_tar(self.root / name, [("atto", b"binary", "file")])
                self.verify(False)
                contract.make_tar(self.root / name,
                                  [("atto", b"binary", "file"), ("oreslang", b"binary", "file")])

    def test_missing_primary_zip_executable_is_rejected(self):
        contract.make_zip(self.root / contract.ZIP, [("oreslang.exe", b"binary", "file")])
        self.verify(False)

    def test_archive_member_aliases_are_not_case_or_path_insensitive(self):
        contract.make_tar(self.root / contract.TARS[0],
                          [("Atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        self.verify(False)
        contract.make_tar(self.root / contract.TARS[0],
                          [("./atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        self.verify(False)
        contract.make_tar(self.root / contract.TARS[0],
                          [("atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        contract.make_zip(self.root / contract.ZIP,
                          [("dist/atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file")])
        self.verify(False)

if __name__ == "__main__":
    unittest.main()

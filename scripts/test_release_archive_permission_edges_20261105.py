#!/usr/bin/env python3
"""Host-only negative controls for both release executable aliases."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

fixture = Path(__file__).with_name("test_release_archive_validation.py")
spec = importlib.util.spec_from_file_location("release_permissions_contract", fixture)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

class PermissionEdges(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in contract.TARS:
            contract.make_tar(self.root / name,
                              [("atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        contract.make_zip(self.root / contract.ZIP,
                          [("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file")])

    def verify(self, admitted):
        result = subprocess.run([sys.executable, "-c", contract.SCRIPT, str(self.root)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, admitted, result.stderr)

    def test_good_distribution_is_admitted(self):
        self.verify(True)

    def test_secondary_alias_cannot_have_unsafe_mode(self):
        for name, kind in ((contract.TARS[0], "noexec"),
                           (contract.TARS[1], "setuid"),
                           (contract.TARS[2], "groupwrite")):
            with self.subTest(archive=name, kind=kind):
                contract.make_tar(self.root / name,
                                  [("atto", b"binary", "file"), ("oreslang", b"binary", kind)])
                self.verify(False)
                contract.make_tar(self.root / name,
                                  [("atto", b"binary", "file"), ("oreslang", b"binary", "file")])
                self.verify(True)

    def test_primary_zip_alias_cannot_be_a_symlink(self):
        contract.make_zip(self.root / contract.ZIP,
                          [("atto.exe", b"oreslang.exe", "symlink"),
                           ("oreslang.exe", b"binary", "file")])
        self.verify(False)

    def test_primary_archive_binary_must_match_target_architecture(self):
        contract.make_tar(self.root / contract.TARS[0],
                          [("atto", contract.synthetic_executable(contract.TARS[1]), "file"),
                           ("oreslang", b"binary", "file")])
        self.verify(False)

    def test_secondary_alias_binary_must_match_target_architecture(self):
        contract.make_tar(self.root / contract.TARS[1],
                          [("atto", b"binary", "file"),
                           ("oreslang", contract.synthetic_executable(contract.TARS[2]), "file")])
        self.verify(False)

if __name__ == "__main__":
    unittest.main()

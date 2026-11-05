#!/usr/bin/env python3
"""Release header edge cases, using the exact publisher harness (host-only)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

fixture_path = Path(__file__).with_name('test_release_archive_validation.py')
spec = importlib.util.spec_from_file_location('archive_contract', fixture_path)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class ExtraArchiveHeaders(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name in contract.TARS:
            contract.make_tar(self.root / name, [('atto', b'binary', 'file'), ('oreslang', b'binary', 'file')])
        contract.make_zip(self.root / contract.ZIP, [('atto.exe', b'binary', 'file'), ('oreslang.exe', b'binary', 'file')])

    def test_unmodified_reference_archives_admitted(self):
        self.assertEqual(contract.subprocess.run([contract.sys.executable, '-c', contract.SCRIPT, str(self.root)], capture_output=True).returncode, 0)

    def reject_tar(self, name, mutated):
        contract.make_tar(self.root / name, [('atto', bytes(mutated), 'file'), ('oreslang', b'binary', 'file')])
        self.assertNotEqual(contract.subprocess.run([contract.sys.executable, '-c', contract.SCRIPT, str(self.root)], capture_output=True).returncode, 0)

    def reject_zip(self, mutated):
        contract.make_zip(self.root / contract.ZIP, [('atto.exe', bytes(mutated), 'file'), ('oreslang.exe', b'binary', 'file')])
        self.assertNotEqual(contract.subprocess.run([contract.sys.executable, '-c', contract.SCRIPT, str(self.root)], capture_output=True).returncode, 0)

    def test_elf32_masquerading_as_linux_x64_rejected(self):
        h = bytearray(contract.synthetic_executable(contract.TARS[0])); h[4] = 1
        self.reject_tar(contract.TARS[0], h)

    def test_big_endian_elf64_masquerading_as_linux_x64_rejected(self):
        h = bytearray(contract.synthetic_executable(contract.TARS[0])); h[5] = 2
        self.reject_tar(contract.TARS[0], h)

    def test_macho_big_endian_magic_rejected(self):
        h = bytearray(contract.synthetic_executable(contract.TARS[1])); h[:4] = b'\xfe\xed\xfa\xcf'
        self.reject_tar(contract.TARS[1], h)

    def test_pe_offset_outside_bounded_header_rejected(self):
        h = bytearray(contract.synthetic_executable(contract.ZIP)); h[0x3c:0x40] = (4090).to_bytes(4, 'little')
        self.reject_zip(h)

    def test_pe_optional_header_below_minimum_rejected(self):
        h = bytearray(contract.synthetic_executable(contract.ZIP)); h[148:150] = (0x60).to_bytes(2, 'little')
        self.reject_zip(h)


if __name__ == '__main__':
    unittest.main()

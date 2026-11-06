"""Homebrew tap formula preflight rejects invalid data without clobbering output.

Source-owned shell/publisher test. No compiler guest or AOT proof is implied.
"""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FORMULA = ROOT / "packaging/homebrew/generate-formula.sh"
ARM = "Ab" * 32
INTEL = "cD" * 32


class HomebrewPublishPreflight(unittest.TestCase):
    def test_invalid_tag_and_hash_preserve_existing_formula_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "tap formula with spaces.rb"
            sentinel = b"# previously reviewed formula\n"
            dest.write_bytes(sentinel)

            def run(tag, arm=ARM, intel=INTEL):
                return subprocess.run(
                    ["bash", str(FORMULA), tag, arm, intel, str(dest)],
                    capture_output=True, text=True, timeout=8,
                )

            for invalid in ("v1.2", "v1.2.3-rc.1", "v1.2.3+build",
                            "v1.2.3/../../untrusted", "1.2.3", "v1.2.3\nforged"):
                with self.subTest(tag=invalid):
                    self.assertNotEqual(run(invalid).returncode, 0)
                    self.assertEqual(dest.read_bytes(), sentinel)
            for invalid_sha in ("a" * 63, "f" * 65, "g" * 64, "a" * 31 + "\n" + "b" * 32):
                with self.subTest(checksum=invalid_sha):
                    self.assertNotEqual(run("v2.4.6", arm=invalid_sha).returncode, 0)
                    self.assertEqual(dest.read_bytes(), sentinel)
                    self.assertNotEqual(run("v2.4.6", intel=invalid_sha).returncode, 0)
                    self.assertEqual(dest.read_bytes(), sentinel)
            self.assertEqual(list(root.glob(".oreslang-formula.*")), [])

            valid = run("v2.4.6")
            self.assertEqual(valid.returncode, 0, valid.stderr)
            expected = dest.read_bytes()
            self.assertIn(b'version "2.4.6"', expected)
            self.assertIn(('sha256 "' + ARM + '"').encode(), expected)
            self.assertIn(('sha256 "' + INTEL + '"').encode(), expected)
            self.assertIn(b'bin.install "atto", "oreslang", "oreslang-compiler"', expected)
            fingerprint = hashlib.sha256(expected).hexdigest()
            repeated = run("v2.4.6")
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertEqual(dest.read_bytes(), expected)
            self.assertEqual(hashlib.sha256(dest.read_bytes()).hexdigest(), fingerprint)
            self.assertEqual(list(root.glob(".oreslang-formula.*")), [])

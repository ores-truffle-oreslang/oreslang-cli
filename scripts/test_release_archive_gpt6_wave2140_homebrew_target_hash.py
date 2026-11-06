"""Cross-target digest identity and fail-closed metadata for Homebrew generator.

Host-only formula generation is not evidence of native compiler release or install.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

GENERATOR = Path(__file__).resolve().parents[1] / "packaging/homebrew/generate-formula.sh"


class FormulaPerTargetIdentityTest(unittest.TestCase):
    def test_arm_and_intel_urls_bind_to_distinct_validated_digests(self):
        with tempfile.TemporaryDirectory(prefix="atto-formula-2140-") as dirname:
            root = Path(dirname)
            destination = root / "Formula with spaces.rb"
            arm = "a" * 64
            intel = "b" * 64
            result = subprocess.run(
                ["bash", str(GENERATOR), "v12.3.4", arm, intel, str(destination)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            contents = destination.read_text()
            self.assertIn('version "12.3.4"', contents)
            self.assertRegex(
                contents, re.compile(
                    r'oreslang-compiler-macos-arm64\.tar\.gz"\s+sha256 "' + arm + '"'
                ),
            )
            self.assertRegex(
                contents, re.compile(
                    r'oreslang-compiler-macos-x86_64\.tar\.gz"\s+sha256 "' + intel + '"'
                ),
            )
            self.assertEqual(contents.count('sha256 "' + arm + '"'), 1)
            self.assertEqual(contents.count('sha256 "' + intel + '"'), 1)
            original = destination.read_bytes()
            bad = subprocess.run(
                ["bash", str(GENERATOR), "v12.3.4-rc1", arm, intel, str(destination)],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(destination.read_bytes(), original)
            self.assertEqual(list(root.glob(".oreslang-formula.*")), [])


if __name__ == "__main__":
    unittest.main()

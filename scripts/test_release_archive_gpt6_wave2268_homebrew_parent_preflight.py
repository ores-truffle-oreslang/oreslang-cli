"""Host-only release formula destination admission: no compiled guest proof.

Invalid release metadata cannot create even a missing output parent. Valid
pinned stable metadata can publish deterministically to nested paths.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

GENERATOR = Path(__file__).resolve().parents[1] / "packaging/homebrew/generate-formula.sh"
ARM = "a" * 64
INTEL = "b" * 64


class HomebrewParentPreflight(unittest.TestCase):
    def call(self, destination, tag="v12.3.4", arm=ARM, intel=INTEL):
        return subprocess.run(
            ["bash", str(GENERATOR), tag, arm, intel, str(destination)],
            capture_output=True, text=True, check=False,
        )

    def test_invalid_metadata_does_not_create_missing_parent_or_formula(self):
        with tempfile.TemporaryDirectory(prefix="atto-wave2268-") as dirname:
            root = Path(dirname)
            parent = root / "uncreated" / "nested Ω"
            target = parent / "Oreslang Formula.rb"
            for tag, arm, intel in (
                ("v1.2.3-rc.1", ARM, INTEL),
                ("v1.2.3\ncreate", ARM, INTEL),
                ("v12.3.4", "z" * 64, INTEL),
                ("v12.3.4", ARM, "b" * 63),
            ):
                with self.subTest(tag=tag, arm=arm[:5], intel=intel[:5]):
                    result = self.call(target, tag=tag, arm=arm, intel=intel)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(parent.exists(), result.stderr)
                    self.assertFalse(target.exists())
                    self.assertEqual(list(root.rglob(".oreslang-formula.*")), [])

    def test_valid_nested_target_publishes_without_stray_stage_files(self):
        with tempfile.TemporaryDirectory(prefix="atto-wave2268-") as dirname:
            parent = Path(dirname) / "nested Ω"
            target = parent / "Formula with spaces.rb"
            first = self.call(target)
            self.assertEqual(first.returncode, 0, first.stderr)
            contents = target.read_bytes()
            self.assertIn(b'version "12.3.4"', contents)
            self.assertIn(ARM.encode(), contents)
            self.assertIn(INTEL.encode(), contents)
            second = self.call(target)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(target.read_bytes(), contents)
            self.assertEqual(list(parent.glob(".oreslang-formula.*")), [])


if __name__ == "__main__":
    unittest.main()

"""Exercise the real shell formula generator's input and output admission."""
import subprocess
import tempfile
import unittest
from pathlib import Path

GENERATOR = Path(__file__).resolve().parents[1] / "packaging/homebrew/generate-formula.sh"
ARM = "a" * 64
INTEL = "b" * 64


class HomebrewSemverImmutability(unittest.TestCase):
    def call(self, tag, arm, intel, dest):
        return subprocess.run(
            ["bash", str(GENERATOR), tag, arm, intel, str(dest)],
            capture_output=True, text=True, check=False,
        )

    def test_invalid_tag_or_digest_cannot_replace_existing_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / "Oreslang.rb"
            marker = Path(folder) / "never-execute"
            sentinel = b"reviewed formula must remain intact\n"
            for tag, arm, intel in [
                ("v1.2.3-rc1", ARM, INTEL),
                ("v1.2.3\nunsafe", ARM, INTEL),
                ("v1.2.3$(touch " + str(marker) + ")", ARM, INTEL),
                ("1.2.3", ARM, INTEL),
                ("v1.2.3", "a" * 63, INTEL),
                ("v1.2.3", ARM, "g" * 64),
            ]:
                with self.subTest(tag=tag, arm=arm[:6], intel=intel[:6]):
                    dest.write_bytes(sentinel)
                    result = self.call(tag, arm, intel, dest)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(dest.read_bytes(), sentinel)
                    self.assertFalse(marker.exists())
                    self.assertFalse(list(Path(folder).glob(".oreslang-formula.*")))

    def test_accepted_formula_is_reproducible_after_safe_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / "Oreslang.rb"
            dest.write_bytes(b"old formula")
            self.assertEqual(self.call("v1.2.3", ARM, INTEL, dest).returncode, 0)
            first = dest.read_bytes()
            self.assertIn(b'version "1.2.3"', first)
            self.assertIn(ARM.encode(), first)
            self.assertIn(INTEL.encode(), first)
            self.assertEqual(self.call("v1.2.3", ARM, INTEL, dest).returncode, 0)
            self.assertEqual(dest.read_bytes(), first)
            self.assertFalse(list(Path(folder).glob(".oreslang-formula.*")))


if __name__ == "__main__":
    unittest.main()
